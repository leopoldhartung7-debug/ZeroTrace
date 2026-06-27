using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class PUBGCheatForensicScanModule : IScanModule
{
    public string Name => "PUBG-Cheat-Forensik";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string[] CheatFilePatterns =
    {
        "pubg_hack", "pubg_cheat", "pubg_aimbot", "pubg_esp",
        "bg_hack", "battleye_bypass_pubg", "pubg_speed", "pubg_loot_esp",
        "pubg_wallhack", "pubg_bypass", "pubg_inject", "pubg_loader",
        "tslgame_hack", "tslgame_cheat", "pubg_driver",
    };

    private static readonly string[] KernelDriverNames =
    {
        "pubg_driver.sys", "pubg_hack.sys", "battleye_bypass.dll",
        "be_bypass.sys", "battleye_hook.dll", "pubg_be_bypass.sys",
        "bg_kernel.sys", "pubg_kernel.sys", "be_patch.sys",
        "battleye_bypass.sys", "pubg_bypass.sys",
    };

    private static readonly string[] BattleEyeBypassArtifacts =
    {
        "battleye_bypass.dll", "be_bypass.sys", "battleye_hook.dll",
        "pubg_be_bypass", "be_patch.dll", "battleye_bypass.exe",
        "be_bypass.dll", "battleye_spoof.dll", "be_hook.sys",
        "battleye_kill.dll", "anti_battleye", "be_bypass_pubg",
    };

    private static readonly string[] SuspiciousDllNames =
    {
        "battleye_bypass.dll", "be_bypass.dll", "pubg_hook.dll",
        "pubg_inject.dll", "bg_inject.dll", "tslgame_hook.dll",
        "pubg_overlay.dll", "pubg_memory.dll", "bg_esp.dll",
        "pubg_aimbot.dll", "pubg_wallhack.dll", "be_patch.dll",
        "pubg_spoof.dll", "battleye_hook.dll", "pubg_bypass.dll",
    };

    private static readonly string[] LogKeywords =
    {
        "pubg hack", "pubg aimbot", "pubg esp", "battleye bypass pubg",
        "pubg wallhack", "pubg cheat", "loot esp pubg",
        "bg hack", "tslgame hack", "pubg undetected",
        "battleye bypass", "be bypass pubg", "pubg speed hack",
        "pubg radar hack", "pubg fov hack",
    };

    private static readonly string[] DiscordKeywords =
    {
        "pubg hack", "pubg esp", "pubg aimbot", "battleye bypass",
        "bg hack", "pubg cheat", "tslgame hack", "pubg wallhack",
        "be bypass pubg", "pubg loot esp", "pubg undetected",
        "battleye bypass pubg",
    };

    private static readonly string[] KnownCheatToolNames =
    {
        "iloveyou pubg", "aimjunkies pubg", "5ewin", "magicbullet pubg",
        "battleye bypass", "pubg-esp", "pubgesp", "pubg-aimbot",
        "pubgaimbot", "pubg radar", "pubg loot esp", "5e win",
        "pubg soft aim", "softaim pubg", "pubg triggerbot",
        "pubg speed hack", "iloveyou", "aimjunkies",
    };

    private static readonly string[] RegistryCheatPaths =
    {
        @"Software\PUBGCheat",
        @"Software\BGHack",
        @"Software\PUBGHack",
        @"Software\PUBGAimbot",
        @"Software\PUBGESP",
        @"Software\BattlEyeBypass",
        @"Software\BEBypass",
        @"Software\PUBGBypass",
        @"Software\PUBGWallhack",
        @"Software\PUBGLoader",
        @"Software\IloveyouPUBG",
        @"Software\AimjunkiesPUBG",
        @"Software\5eWin",
        @"Software\MagicBulletPUBG",
        @"Software\PUBGSoftAim",
    };

    private static readonly string[] RegistryInstallerPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PUBGCheat",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BGHack",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BattlEyeBypass",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PUBGHack",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IloveyouPUBG",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\5eWin",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PUBGCheat",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\BGHack",
    };

    private static readonly string[] PrefetchCheatExeNames =
    {
        "pubg_hack", "pubg_cheat", "pubg_aimbot", "pubg_esp",
        "bg_hack", "battleye_bypass", "be_bypass", "pubg_loader",
        "pubg_bypass", "iloveyou_pubg", "aimjunkies_pubg",
        "5ewin", "magicbullet_pubg", "pubg_wallhack",
        "pubg_loot_esp", "pubg_speed", "tslgame_hack", "pubg_driver",
        "pubg_inject", "battleye_kill",
    };

    private static readonly string[] UserAssistCheatKeywords =
    {
        "pubg_hack", "pubg_cheat", "pubg_aimbot", "pubg_esp",
        "bg_hack", "battleye_bypass", "be_bypass", "pubg_loader",
        "pubg_bypass", "iloveyou_pubg", "aimjunkies_pubg",
        "5ewin", "magicbullet_pubg", "pubg_wallhack",
        "pubg_speed", "tslgame_hack", "pubg_inject",
    };

    private static readonly string[] SuspiciousScriptKeywords =
    {
        "pubg", "tslgame", "battleye", "playerunknown",
        "battlegrounds", "bg_", "pubgm",
    };

    private static readonly string[] CheatEngineSaveExtensions =
    {
        ".ct", ".cetrainer",
    };

    private static readonly string[] PubgProcessDumpKeywords =
    {
        "TslGame", "PUBG", "pubg", "tslgame", "playerunknown",
        "battlegrounds", "pubg_steam", "pubg.exe",
    };

    private static readonly string[] PubgGameDirNames =
    {
        "PUBG",
        "PlayerUnknown's Battlegrounds",
        "PlayerUnknowns Battlegrounds",
        "TslGame",
        "PUBG Lite",
    };

    private static readonly string[] PubgConfigKeywords =
    {
        "fovangle", "fovoverride", "fov_override",
        "radarscale", "radarenabled", "radar_enabled",
        "norecoil", "no_recoil", "recoil_override",
        "speedhack", "speed_hack", "movespeed",
        "aimassist", "aim_assist", "aimlength",
        "wallhack", "wall_hack", "seethrough",
        "loot_esp", "loothealth", "lootfilter",
        "nospread", "no_spread", "bulletspread",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starte PUBG-Cheat-Forensik-Scan...");

        await Task.WhenAll(
            CheckCheatFilesOnDisk(ctx, ct),
            CheckPubgGameDirectories(ctx, ct),
            CheckBattleEyeBypassArtifacts(ctx, ct),
            CheckKernelDriverArtifacts(ctx, ct),
            CheckRegistryArtifacts(ctx, ct),
            CheckPrefetchArtifacts(ctx, ct),
            CheckUserAssistArtifacts(ctx, ct),
            CheckLogFileArtifacts(ctx, ct),
            CheckDiscordArtifacts(ctx, ct),
            CheckSuspiciousScripts(ctx, ct),
            CheckMemoryDumpArtifacts(ctx, ct),
            CheckCheatEngineTables(ctx, ct),
            CheckPubgConfigArtifacts(ctx, ct),
            CheckRecycleBinArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "PUBG-Cheat-Forensik-Scan abgeschlossen");
    }

    private Task CheckCheatFilesOnDisk(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var searchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath(),
            localAppData,
            appData,
        };

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
                            Title = $"PUBG-Cheat-Datei gefunden: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Datei '{fileName}' entspricht dem bekannten PUBG-Cheat-Dateinamen-Muster '{pattern}'. " +
                                     "Dies ist ein forensisches Artefakt eines PUBG-Cheat-Tools.",
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
                            Title = $"PUBG-Cheat-Verzeichnis: {dirName}",
                            Risk = RiskLevel.High,
                            Location = subDir,
                            FileName = dirName,
                            Reason = $"Verzeichnis '{dirName}' entspricht dem bekannten PUBG-Cheat-Tool '{tool}'. " +
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
                                Title = $"PUBG-Cheat-Datei in Unterverzeichnis: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Datei '{fileName}' in Unterverzeichnis '{dirName}' entspricht dem PUBG-Cheat-Muster '{pattern}'. " +
                                         "Forensisches Artefakt eines PUBG-Cheat-Tools.",
                                Detail = $"Muster: {pattern} | Pfad: {file}"
                            });
                            break;
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckPubgGameDirectories(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var gameDirCandidates = new List<string>();

        foreach (var baseDir in new[] { programFiles, programFilesX86 })
        {
            foreach (var gameName in PubgGameDirNames)
            {
                var candidate = Path.Combine(baseDir, gameName);
                if (Directory.Exists(candidate))
                    gameDirCandidates.Add(candidate);
            }
        }

        var steamAppsDir = Path.Combine(programFiles, "Steam", "steamapps", "common");
        if (Directory.Exists(steamAppsDir))
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(steamAppsDir))
                {
                    var dName = Path.GetFileName(dir);
                    if (dName.Contains("PUBG", StringComparison.OrdinalIgnoreCase) ||
                        dName.Contains("PlayerUnknown", StringComparison.OrdinalIgnoreCase) ||
                        dName.Contains("Battlegrounds", StringComparison.OrdinalIgnoreCase))
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

            string[] dllFiles;
            try
            {
                dllFiles = Directory.GetFiles(gameDir, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dllFile in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(dllFile);

                foreach (var suspDll in SuspiciousDllNames)
                {
                    if (fn.Equals(suspDll, StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains(suspDll.Replace(".dll", ""), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige DLL im PUBG-Spielverzeichnis: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = fn,
                            Reason = $"Verdaechtige DLL '{fn}' im PUBG-Spielverzeichnis gefunden. " +
                                     $"Entspricht bekanntem PUBG-Cheat-DLL-Muster '{suspDll}'. " +
                                     "Cheat-DLLs werden oft direkt in das Spielverzeichnis injiziert.",
                            Detail = $"Spielverzeichnis: {gameDir} | DLL: {fn}"
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
                            Title = $"PUBG-Cheat-DLL im Spielverzeichnis: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = fn,
                            Reason = $"Cheat-DLL '{fn}' direkt im PUBG-Spielverzeichnis gefunden. " +
                                     $"Muster '{pattern}' stimmt mit bekannten PUBG-Cheat-Artefakten ueberein.",
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
                    Title = $"Kernel-Treiber-Datei im PUBG-Spielverzeichnis: {fn}",
                    Risk = RiskLevel.Critical,
                    Location = sysFile,
                    FileName = fn,
                    Reason = $"Kernel-Treiberdatei (.sys) '{fn}' direkt im PUBG-Spielverzeichnis gefunden. " +
                             "Legitime PUBG-Dateien verwenden keine Kernel-Treiber im Spielordner. " +
                             "Starkes Indiz fuer einen Kernel-Level-Cheat.",
                    Detail = $"Spielverzeichnis: {gameDir}"
                });
            }

            var tslBinDir = Path.Combine(gameDir, "TslGame", "Binaries", "Win64");
            if (Directory.Exists(tslBinDir))
            {
                string[] binDllFiles;
                try
                {
                    binDllFiles = Directory.GetFiles(tslBinDir, "*.dll", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var binDll in binDllFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(binDll);

                    foreach (var suspDll in SuspiciousDllNames)
                    {
                        if (fn.Equals(suspDll, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Cheat-DLL im PUBG-Binaries-Verzeichnis: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = binDll,
                                FileName = fn,
                                Reason = $"Bekannte PUBG-Cheat-DLL '{fn}' im TslGame-Binaries-Verzeichnis gefunden. " +
                                         "DLL-Hijacking im Spielverzeichnis ist eine haeufige Cheat-Injektionsmethode.",
                                Detail = $"Binaries: {tslBinDir} | DLL: {fn}"
                            });
                            break;
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckBattleEyeBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var searchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers"),
        };

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
                var fn = Path.GetFileName(file);

                foreach (var beArtifact in BattleEyeBypassArtifacts)
                {
                    if (fn.Equals(beArtifact, StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains(beArtifact.Replace(".dll", "").Replace(".sys", "").Replace(".exe", ""),
                            StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"BattlEye-Bypass-Artefakt gefunden: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei '{fn}' entspricht einem bekannten BattlEye-Bypass-Artefakt '{beArtifact}'. " +
                                     "BattlEye-Bypasses erlauben die Verwendung von PUBG-Cheats trotz aktivem Anti-Cheat.",
                            Detail = $"BattlEye-Bypass-Artefakt: {beArtifact} | Pfad: {file}"
                        });
                        break;
                    }
                }
            }
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var battleEyeDirs = new[]
        {
            Path.Combine(programFiles, "BattlEye"),
            Path.Combine(programFiles, "BEService"),
            Path.Combine(programFiles, "Common Files", "BattlEye"),
        };

        foreach (var beDir in battleEyeDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(beDir)) continue;

            string[] beFiles;
            try
            {
                beFiles = Directory.GetFiles(beDir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var beFile in beFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(beFile);

                bool isSuspicious = false;
                foreach (var beArtifact in BattleEyeBypassArtifacts)
                {
                    if (fn.Contains(beArtifact.Replace(".dll", "").Replace(".sys", ""),
                        StringComparison.OrdinalIgnoreCase))
                    {
                        isSuspicious = true;
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"BattlEye-Bypass im BattlEye-Verzeichnis: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = beFile,
                            FileName = fn,
                            Reason = $"BattlEye-Bypass-Datei '{fn}' im offiziellen BattlEye-Verzeichnis gefunden. " +
                                     "Dies deutet auf eine gezielte Manipulation des Anti-Cheat-Systems hin.",
                            Detail = $"BattlEye-Verzeichnis: {beDir} | Artefakt: {beArtifact}"
                        });
                        break;
                    }
                }

                if (!isSuspicious)
                {
                    foreach (var pattern in CheatFilePatterns)
                    {
                        if (fn.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"PUBG-Cheat-Datei im BattlEye-Verzeichnis: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = beFile,
                                FileName = fn,
                                Reason = $"PUBG-Cheat-Datei '{fn}' im BattlEye-Verzeichnis gefunden (Muster: '{pattern}'). " +
                                         "Cheat-Tools platzieren sich im Anti-Cheat-Verzeichnis um Erkennung zu vermeiden.",
                                Detail = $"Muster: {pattern} | BattlEye-Verzeichnis: {beDir}"
                            });
                            break;
                        }
                    }
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
                            Title = $"PUBG-Cheat-Kernel-Treiber in System32: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = driverFile,
                            FileName = fn,
                            Reason = $"Kernel-Treiber '{fn}' in System32\\drivers entspricht bekanntem PUBG-Cheat-Treiber-Muster '{knownDriver}'. " +
                                     "Kernel-Level-Cheats umgehen BattlEye durch direkten Kernel-Zugriff.",
                            Detail = $"Bekannter Treiber: {knownDriver} | Pfad: {driverFile}"
                        });
                        break;
                    }
                }

                foreach (var beArtifact in BattleEyeBypassArtifacts)
                {
                    var baseArtifact = beArtifact.Replace(".dll", "").Replace(".sys", "").Replace(".exe", "");
                    if (fn.Contains(baseArtifact, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"BattlEye-Bypass-Treiber in System32: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = driverFile,
                            FileName = fn,
                            Reason = $"BattlEye-Bypass-Treiber '{fn}' in System32\\drivers gefunden. " +
                                     $"Entspricht bekanntem Bypass-Artefakt '{beArtifact}'. " +
                                     "Dieser Treiber ermoeglicht das Umgehen des BattlEye-Anti-Cheat-Systems.",
                            Detail = $"BattlEye-Artefakt: {beArtifact} | Pfad: {driverFile}"
                        });
                        break;
                    }
                }
            }
        }

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is null) return;

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
                    foreach (var beArtifact in BattleEyeBypassArtifacts)
                    {
                        var baseArtifact = beArtifact.Replace(".dll", "").Replace(".sys", "").Replace(".exe", "");
                        if (svcName.Contains(baseArtifact, StringComparison.OrdinalIgnoreCase))
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
                        Title = $"PUBG-Cheat-Dienst in Registry: {svcName}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        Reason = $"Windows-Dienst '{svcName}' entspricht einem bekannten PUBG/BattlEye Cheat-Kernel-Treiber. " +
                                 $"Dienst-Typ: {svcType}. Kernel-Treiber-Dienste (Typ 1) koennen BattlEye umgehen.",
                        Detail = $"ImagePath: {imagePath} | Type: {svcType}"
                    });
                }
                catch { }
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
                        Title = $"PUBG-Cheat-Registry-Schluessel: {Path.GetFileName(regPath)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{regPath}",
                        Reason = $"Registry-Schluessel 'HKCU\\{regPath}' deutet auf ein installiertes PUBG-Cheat-Tool hin. " +
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
                        Title = $"PUBG-Cheat-Registry-Schluessel (HKLM): {Path.GetFileName(regPath)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{regPath}",
                        Reason = $"Registry-Schluessel 'HKLM\\{regPath}' deutet auf ein systemweit installiertes PUBG-Cheat-Tool hin.",
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
                    Title = $"PUBG-Cheat-Installer-Eintrag: {displayName}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{installerPath}",
                    Reason = $"Deinstallations-Eintrag '{displayName}' in der Registry deutet auf Installation eines PUBG-Cheat-Tools hin. " +
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
                                Title = $"PUBG-Cheat in MUICache: {Path.GetFileName(valueName)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{muiCachePath}",
                                Reason = $"MUICache-Eintrag deutet auf Ausfuehrung eines PUBG-Cheat-Programms hin: '{valueName}'. " +
                                         "MUICache speichert Programmtitel ausgefuehrter Anwendungen.",
                                Detail = $"Wert: {valueName} | Anzeigename: {displayName}"
                            });
                            break;
                        }
                    }

                    foreach (var beArtifact in BattleEyeBypassArtifacts)
                    {
                        var baseArtifact = beArtifact.Replace(".dll", "").Replace(".sys", "").Replace(".exe", "");
                        if (valueName.Contains(baseArtifact, StringComparison.OrdinalIgnoreCase))
                        {
                            var displayName = muiKey.GetValue(valueName) as string ?? "";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"BattlEye-Bypass in MUICache: {Path.GetFileName(valueName)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{muiCachePath}",
                                Reason = $"MUICache-Eintrag '{valueName}' entspricht dem BattlEye-Bypass-Artefakt '{beArtifact}'. " +
                                         "Das Bypass-Tool wurde auf diesem System ausgefuehrt.",
                                Detail = $"BattlEye-Artefakt: {beArtifact} | Anzeigename: {displayName}"
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
                        Title = $"PUBG-Cheat-Prefetch: {exeName}.exe",
                        Risk = RiskLevel.High,
                        Location = pfFile,
                        FileName = exeName + ".exe",
                        Reason = $"Prefetch-Datei '{pfName}.pf' belegt die Ausfuehrung von '{exeName}.exe', " +
                                 $"welches dem PUBG-Cheat-Muster '{cheatExe}' entspricht. " +
                                 "Prefetch-Eintraege bleiben auch nach dem Loeschen der ausfuehrbaren Datei erhalten.",
                        Detail = lastRun.HasValue
                            ? $"Prefetch-Datum: {lastRun.Value:yyyy-MM-dd HH:mm:ss} | Muster: {cheatExe}"
                            : $"Muster: {cheatExe}"
                    });
                    break;
                }
            }

            foreach (var beArtifact in BattleEyeBypassArtifacts)
            {
                var baseName = beArtifact.Replace(".dll", "").Replace(".sys", "").Replace(".exe", "");
                if (exeName.Contains(baseName, StringComparison.OrdinalIgnoreCase))
                {
                    DateTime? lastRun = null;
                    try { lastRun = File.GetLastWriteTime(pfFile); } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"BattlEye-Bypass-Tool in Prefetch: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = pfFile,
                        FileName = exeName + ".exe",
                        Reason = $"Prefetch-Eintrag '{exeName}' entspricht dem BattlEye-Bypass-Artefakt '{beArtifact}'. " +
                                 "Das Bypass-Tool wurde auf diesem System gestartet.",
                        Detail = lastRun.HasValue
                            ? $"BattlEye-Artefakt: {beArtifact} | Datum: {lastRun.Value:yyyy-MM-dd HH:mm:ss}"
                            : $"BattlEye-Artefakt: {beArtifact}"
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
                        Title = $"Bekanntes PUBG-Cheat-Tool in Prefetch: {exeName}",
                        Risk = RiskLevel.High,
                        Location = pfFile,
                        FileName = exeName + ".exe",
                        Reason = $"Prefetch-Eintrag '{exeName}' entspricht dem bekannten PUBG-Cheat-Tool '{tool}'. " +
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
                                    Title = $"PUBG-Cheat in UserAssist: {keyword}",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                    FileName = Path.GetFileName(decoded),
                                    Reason = $"UserAssist-Eintrag belegt die Ausfuehrung von '{Path.GetFileName(decoded)}' " +
                                             $"({runCount}x ausgefuehrt" +
                                             (lastRun.HasValue ? $", zuletzt {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                             $"). PUBG-Cheat-Schluesselbegriff: '{keyword}'. " +
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
                            foreach (var beArtifact in BattleEyeBypassArtifacts)
                            {
                                var baseName = beArtifact.Replace(".dll", "").Replace(".sys", "").Replace(".exe", "").ToLowerInvariant();
                                if (decoded.Contains(baseName, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"BattlEye-Bypass in UserAssist: {Path.GetFileName(decoded)}",
                                        Risk = RiskLevel.Critical,
                                        Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                        FileName = Path.GetFileName(decoded),
                                        Reason = $"UserAssist-Eintrag '{Path.GetFileName(decoded)}' entspricht dem BattlEye-Bypass-Artefakt '{beArtifact}'. " +
                                                 "Das Bypass-Tool wurde auf diesem System ausgefuehrt.",
                                        Detail = $"BattlEye-Artefakt: {beArtifact} | Dekodiert: {decoded}"
                                    });
                                    matched = true;
                                    break;
                                }
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
                                        Title = $"Bekanntes PUBG-Cheat-Tool in UserAssist: {tool}",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                        FileName = Path.GetFileName(decoded),
                                        Reason = $"UserAssist-Eintrag '{Path.GetFileName(decoded)}' entspricht dem bekannten PUBG-Cheat-Tool '{tool}'. " +
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

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var logSearchRoots = new List<string>
        {
            localAppData,
            appData,
            Path.GetTempPath(),
            Path.Combine(localAppData, "TslGame"),
            Path.Combine(localAppData, "PUBG"),
            Path.Combine(userProfile, "Documents", "PUBG"),
            Path.Combine(userProfile, "AppData", "Local", "TslGame", "Saved", "Logs"),
        };

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
                            Title = $"PUBG-Cheat-Schluesselbegriff in Log: {keyword}",
                            Risk = RiskLevel.Medium,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"Log-Datei '{Path.GetFileName(logFile)}' enthaelt PUBG-Cheat-Schluesselbegriff '{keyword}'. " +
                                     "Dies kann auf die Nutzung oder Installation eines PUBG-Cheats hinweisen.",
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
                            Title = $"PUBG-Cheat-Tool in Log erwaehnt: {tool}",
                            Risk = RiskLevel.Medium,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"Log-Datei '{Path.GetFileName(logFile)}' erwaehnt das bekannte PUBG-Cheat-Tool '{tool}'. " +
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
                                Title = $"PUBG-Cheat-Schluesselbegriff im Discord-Cache: {keyword}",
                                Risk = RiskLevel.Medium,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason = $"Discord-Cache-Datei enthaelt den PUBG-Cheat-Schluesselbegriff '{keyword}'. " +
                                         $"Discord-Client: {client}. " +
                                         "Dies kann auf Mitgliedschaft in PUBG-Cheat-Servern oder Cheat-Diskussionen hinweisen.",
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
                                Title = $"PUBG-Cheat-Skript (Name): {fn}",
                                Risk = RiskLevel.High,
                                Location = scriptFile,
                                FileName = fn,
                                Reason = $"Skriptdatei '{fn}' entspricht dem PUBG-Cheat-Namensmuster '{pattern}'. " +
                                         "Cheat-Tools verwenden Batch- und PowerShell-Skripte zur Installation und Umgehung von BattlEye.",
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

                    bool hasPubgRef = false;
                    foreach (var pubgKeyword in SuspiciousScriptKeywords)
                    {
                        if (content.Contains(pubgKeyword, StringComparison.OrdinalIgnoreCase))
                        {
                            hasPubgRef = true;
                            break;
                        }
                    }

                    if (!hasPubgRef) continue;

                    bool hasCheatKeyword = false;
                    string? matchedCheatKw = null;
                    foreach (var cheatKw in new[] { "bypass", "inject", "hack", "cheat", "esp", "aimbot", "spoof", "patch", "battleye" })
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
                            Title = $"Verdaechtiges Skript mit PUBG- und Cheat-Begriffen: {fn}",
                            Risk = RiskLevel.Medium,
                            Location = scriptFile,
                            FileName = fn,
                            Reason = $"Skriptdatei '{fn}' enthaelt sowohl PUBG/BattlEye-Verweise als auch den Cheat-Begriff '{matchedCheatKw}'. " +
                                     "Verdaechtige Skripte, die auf PUBG-Verzeichnisse abzielen, koennen Cheat-Installer oder BattlEye-Bypass-Tools sein.",
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

                    bool matchesPubg = false;
                    foreach (var procKw in PubgProcessDumpKeywords)
                    {
                        if (fn.Contains(procKw, StringComparison.OrdinalIgnoreCase))
                        {
                            matchesPubg = true;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"PUBG-Prozess-Dump: {fn}",
                                Risk = RiskLevel.High,
                                Location = dumpFile,
                                FileName = fn,
                                Reason = $"Speicher-Dump-Datei '{fn}' enthaelt den PUBG-Prozessnamen '{procKw}'. " +
                                         "Cheat-Tools erstellen oft Speicher-Dumps von TslGame um Offsets und Adressen zu extrahieren.",
                                Detail = $"Prozess-Keyword: {procKw} | Dump: {dumpFile}"
                            });
                            break;
                        }
                    }

                    if (!matchesPubg)
                    {
                        foreach (var pattern in CheatFilePatterns)
                        {
                            if (fn.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"PUBG-Cheat-bezogener Speicher-Dump: {fn}",
                                    Risk = RiskLevel.High,
                                    Location = dumpFile,
                                    FileName = fn,
                                    Reason = $"Speicher-Dump '{fn}' entspricht dem PUBG-Cheat-Muster '{pattern}'. " +
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

                    bool isPubgTable = false;
                    foreach (var procKw in PubgProcessDumpKeywords)
                    {
                        if (fn.Contains(procKw, StringComparison.OrdinalIgnoreCase))
                        {
                            isPubgTable = true;
                            break;
                        }
                    }

                    if (!isPubgTable)
                    {
                        foreach (var pattern in CheatFilePatterns)
                        {
                            if (fn.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                isPubgTable = true;
                                break;
                            }
                        }
                    }

                    if (!isPubgTable)
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

                            foreach (var procKw in PubgProcessDumpKeywords)
                            {
                                if (content.Contains(procKw, StringComparison.OrdinalIgnoreCase))
                                {
                                    isPubgTable = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (isPubgTable)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat-Engine-Tabelle fuer PUBG/TslGame: {fn}",
                            Risk = RiskLevel.High,
                            Location = ctFile,
                            FileName = fn,
                            Reason = $"Cheat-Engine-Tabelle '{fn}' ist mit einem PUBG/TslGame-Prozess verknuepft. " +
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
                         "um Spielprozesse wie PUBG/TslGame zu manipulieren.",
                Detail = $"Pfad: {ceDocPath}"
            });
        }
    }, ct);

    private Task CheckPubgConfigArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var pubgConfigRoots = new[]
        {
            Path.Combine(localAppData, "TslGame"),
            Path.Combine(localAppData, "TslGame", "Saved", "Config"),
            Path.Combine(localAppData, "TslGame", "Saved", "Config", "WindowsNoEditor"),
            Path.Combine(localAppData, "PUBG"),
        };

        foreach (var configRoot in pubgConfigRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(configRoot)) continue;

            string[] configFiles;
            try
            {
                configFiles = Directory.GetFiles(configRoot, "*.ini", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var configFile in configFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                FileInfo fi;
                try { fi = new FileInfo(configFile); } catch { continue; }
                if (fi.Length > 2 * 1024 * 1024) continue;

                string content;
                try
                {
                    using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var matchedKeywords = new List<string>();
                foreach (var configKw in PubgConfigKeywords)
                {
                    if (content.Contains(configKw, StringComparison.OrdinalIgnoreCase))
                        matchedKeywords.Add(configKw);
                }

                if (matchedKeywords.Count == 0) continue;

                var riskLevel = matchedKeywords.Count >= 3 ? RiskLevel.High : RiskLevel.Medium;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtige PUBG-Konfiguration: {Path.GetFileName(configFile)}",
                    Risk = riskLevel,
                    Location = configFile,
                    FileName = Path.GetFileName(configFile),
                    Reason = $"PUBG-Konfigurationsdatei '{Path.GetFileName(configFile)}' enthaelt verdaechtige Schluessel: " +
                             $"{string.Join(", ", matchedKeywords)}. " +
                             $"Cheat-Tools modifizieren PUBG-Konfigurationsdateien fuer FOV-Hacks, Radar-Hacks und Rueckstoss-Eliminierung.",
                    Detail = $"Verdaechtige Schluessel ({matchedKeywords.Count}): {string.Join(", ", matchedKeywords)} | Config: {configFile}"
                });
            }

            string[] jsonConfigFiles;
            try
            {
                jsonConfigFiles = Directory.GetFiles(configRoot, "*.json", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var jsonFile in jsonConfigFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                FileInfo fi;
                try { fi = new FileInfo(jsonFile); } catch { continue; }
                if (fi.Length > 1 * 1024 * 1024) continue;

                string content;
                try
                {
                    using var fs = new FileStream(jsonFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                foreach (var configKw in PubgConfigKeywords)
                {
                    if (content.Contains(configKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige PUBG-JSON-Konfiguration: {Path.GetFileName(jsonFile)}",
                            Risk = RiskLevel.Medium,
                            Location = jsonFile,
                            FileName = Path.GetFileName(jsonFile),
                            Reason = $"PUBG-JSON-Konfigurationsdatei '{Path.GetFileName(jsonFile)}' enthaelt verdaechtigen Konfigurationsschluessel '{configKw}'. " +
                                     "Externe Cheat-Konfigurationen werden oft als JSON-Dateien im Spieldatenverzeichnis gespeichert.",
                            Detail = $"Konfigurationsschluessel: {configKw} | Datei: {jsonFile}"
                        });
                        break;
                    }
                }
            }
        }

        var tslGameSavedDir = Path.Combine(localAppData, "TslGame", "Saved");
        if (Directory.Exists(tslGameSavedDir))
        {
            string[] suspFiles;
            try
            {
                suspFiles = Directory.GetFiles(tslGameSavedDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                suspFiles = Array.Empty<string>();
            }

            foreach (var suspFile in suspFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(suspFile);

                foreach (var pattern in CheatFilePatterns)
                {
                    if (fn.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PUBG-Cheat-Datei im TslGame-Saved-Verzeichnis: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = suspFile,
                            FileName = fn,
                            Reason = $"Cheat-Datei '{fn}' im PUBG TslGame-Saved-Verzeichnis gefunden. " +
                                     $"Muster '{pattern}' entspricht bekanntem PUBG-Cheat-Artefakt. " +
                                     "Cheats werden oft in Spielspeicherordnern versteckt.",
                            Detail = $"Muster: {pattern} | TslGame Saved: {tslGameSavedDir}"
                        });
                        break;
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
                                Title = $"PUBG-Cheat-Datei im Papierkorb: {fileName}",
                                Risk = RiskLevel.High,
                                Location = origPath!,
                                FileName = fileName,
                                Reason = $"Geloeschte Datei '{fileName}' im Papierkorb entspricht dem PUBG-Cheat-Muster '{pattern}'. " +
                                         (deletedTime is not null ? $"Geloescht am: {deletedTime}. " : "") +
                                         "Die Datei ist moeglicherweise wiederherstellbar.",
                                Detail = $"Originalname: {origPath} | Papierkorb: {sidDir}"
                            });
                            break;
                        }
                    }

                    foreach (var beArtifact in BattleEyeBypassArtifacts)
                    {
                        var baseName = beArtifact.Replace(".dll", "").Replace(".sys", "").Replace(".exe", "");
                        if (fileName.Contains(baseName, StringComparison.OrdinalIgnoreCase) ||
                            origPath!.Contains(baseName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"BattlEye-Bypass-Artefakt im Papierkorb: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = origPath!,
                                FileName = fileName,
                                Reason = $"Geloeschte BattlEye-Bypass-Datei '{fileName}' im Papierkorb gefunden. " +
                                         $"Entspricht dem Artefakt '{beArtifact}'. " +
                                         (deletedTime is not null ? $"Geloescht am: {deletedTime}." : ""),
                                Detail = $"BattlEye-Artefakt: {beArtifact} | Original: {origPath}"
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
                                Title = $"Bekanntes PUBG-Cheat-Tool im Papierkorb: {fileName}",
                                Risk = RiskLevel.High,
                                Location = origPath!,
                                FileName = fileName,
                                Reason = $"Geloeschte Datei '{fileName}' im Papierkorb entspricht dem bekannten PUBG-Cheat-Tool '{tool}'. " +
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
