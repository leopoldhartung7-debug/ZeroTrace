using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class MemoryForensicTrailScanModule : IScanModule
{
    public string Name => "Memory Forensics Trail Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    private static readonly string[] CheatProcessNameFragments =
    {
        "aimbot", "aim_bot", "aimassist", "triggerbot", "cheat", "hack",
        "inject", "loader", "bypass", "spoofer", "wallhack", "esp_",
        "_esp", "bhop", "bunnyhop", "noRecoil", "no_recoil", "silent",
        "radar", "overlay", "external", "internal", "modmenu", "mod_menu",
        "menu", "trainer", "executor", "exploit", "dumper", "dump_",
        "_dump", "procdump", "memdump", "paysec", "luac", "lua_",
        "fivem_hack", "gtav_hack", "cs2_cheat", "apex_cheat",
        "valorant_hack", "rust_cheat", "tarkov_cheat", "pubg_cheat",
    };

    private static readonly string[] AntiCheatProcessNames =
    {
        "EasyAntiCheat", "BEService", "bedaisy", "vgc", "vgk",
        "EasyAntiCheat_EOS", "FACEIT", "GameGuard", "nProtect",
        "EasyAntiCheat_Setup", "BEService_x64",
    };

    private static readonly string[] MemoryToolNames =
    {
        "volatility.exe", "volatility3.exe", "vol.exe", "vol3.exe",
        "winpmem.exe", "winpmem_mini.exe", "DumpIt.exe", "RAMMap.exe",
        "RAMMap64.exe", "NotMyFault.exe", "NotMyFault64.exe",
        "mdd.exe", "mdd_1.3.exe", "Redline.exe", "FTK Imager.exe",
        "FTKImager.exe", "osForensics.exe", "Magnet.exe",
        "avml.exe", "pmem.exe", "wincpmem.exe", "lime.ko",
        "AccessData FTK.exe", "belkasoft.exe",
    };

    private static readonly string[] ProcessDumpToolNames =
    {
        "procdump.exe", "procdump64.exe", "procdump.exe",
        "dumper.exe", "game_dump.exe", "memdump.exe", "proc_dump.exe",
        "gtav_dump.exe", "cs2_dump.exe", "apex_dump.exe",
        "game_memory_dump.exe", "mem_dump.exe", "process_dump.exe",
        "miniDumper.exe", "minidumper.exe", "crashdumper.exe",
        "crashdump.exe", "dump_tool.exe", "dump_helper.exe",
    };

    private static readonly string[] GameCrashSubDirs =
    {
        "FiveM", "GrandTheftAutoV", "GTAV", "CS2", "CounterStrike",
        "Valorant", "Apex Legends", "ApexLegends", "Rust",
        "EscapeFromTarkov", "Tarkov", "PUBG", "PlayerUnknowns",
        "Fortnite", "Overwatch", "Rainbow Six", "RainbowSix",
        "Warzone", "CallOfDuty", "COD", "BattlefieldV",
        "Battlefield", "DayZ", "Squad", "Arma3",
    };

    private static readonly string[] PeSieveArtifactNames =
    {
        "pe-sieve_report.json", "pe_sieve_report.json",
        "pe-sieve.log", "pe_sieve.log",
        "hollows_hunter.log", "hollows_hunter_report.json",
    };

    private static readonly string[] VmemExtensions =
    {
        ".vmem", ".vmsn", ".vmss",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        await ScanWindowsMinidumpsAsync(ctx, ct);
        ctx.Report(0.10, "Windows Minidumps", "System-Minidump-Verzeichnis geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanLocalAppDataCrashDumpsAsync(ctx, ct);
        ctx.Report(0.20, "AppData CrashDumps", "Anwendungs-Crashdumps geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanTempDumpFilesAsync(ctx, ct);
        ctx.Report(0.30, "Temp-Dumpfiles", "Dumpfiles in Temp-Verzeichnissen geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanGameCrashDumpsAsync(ctx, ct);
        ctx.Report(0.40, "Spiel-Crashdumps", "Spiel-Crash-Verzeichnisse geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanWerReportQueueAsync(ctx, ct);
        ctx.Report(0.52, "WER ReportQueue", "WER-Fehlerbericht-Warteschlange geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanWerReportArchiveAsync(ctx, ct);
        ctx.Report(0.62, "WER ReportArchive", "WER-Berichtsarchiv geprueft");
        ct.ThrowIfCancellationRequested();

        ScanPagefileAndHibernation(ctx);
        ctx.Report(0.70, "Pagefile/Hibernation", "Auslagerungsdatei und Ruhezustand geprueft");
        ct.ThrowIfCancellationRequested();

        ScanMemoryAnalysisTools(ctx, ct);
        ctx.Report(0.80, "Memory-Tools", "Speicheranalyse-Tools gesucht");
        ct.ThrowIfCancellationRequested();

        await ScanPeSieveArtifactsAsync(ctx, ct);
        ctx.Report(0.88, "PE-Sieve", "PE-Sieve-Artefakte geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanVirtualMemoryDumpsAsync(ctx, ct);
        ctx.Report(0.94, "VM-Speicher-Dumps", "Virtuelle Speicher-Snapshots geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanNonStandardMemoryDumpsAsync(ctx, ct);
        ctx.Report(1.0, "MEMORY.DMP", "Nicht-standardmaessige MEMORY.DMP-Dateien geprueft");
    }

    private async Task ScanWindowsMinidumpsAsync(ScanContext ctx, CancellationToken ct)
    {
        var windir = Environment.GetEnvironmentVariable("SYSTEMROOT")
                     ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var minidumpDir = Path.Combine(windir, "Minidump");

        if (!Directory.Exists(minidumpDir)) return;

        string[] dmpFiles;
        try { dmpFiles = Directory.GetFiles(minidumpDir, "*.dmp"); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        var recentDumps = new List<(string path, DateTime time)>();
        var cheatRelatedDumps = new List<string>();

        foreach (var dmpFile in dmpFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(dmpFile);
            DateTime writeTime;
            try { writeTime = File.GetLastWriteTime(dmpFile); }
            catch { writeTime = DateTime.MinValue; }

            if ((DateTime.Now - writeTime).TotalDays <= 90)
                recentDumps.Add((dmpFile, writeTime));

            bool isCheatRelated = false;
            foreach (var fragment in CheatProcessNameFragments)
            {
                if (fileName.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                {
                    isCheatRelated = true;
                    break;
                }
            }

            if (isCheatRelated)
            {
                cheatRelatedDumps.Add(fileName);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Minidump mit Cheat-Prozessnamen: {fileName}",
                    Risk = RiskLevel.High,
                    Location = dmpFile,
                    FileName = fileName,
                    Reason = $"Im Windows-Minidump-Verzeichnis wurde ein Dump mit dem Namen '{fileName}' " +
                             "gefunden, der einem bekannten Cheat-Prozessnamen entspricht. " +
                             "Dieser Dump kann beweisen, dass ein Cheat-Prozess zur Absturzeit aktiv war " +
                             "und wichtige forensische Spuren enthalten.",
                    Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm} | Pfad: {dmpFile}"
                });
            }

            bool isAntiCheatCrash = false;
            foreach (var acName in AntiCheatProcessNames)
            {
                if (fileName.Contains(acName, StringComparison.OrdinalIgnoreCase))
                {
                    isAntiCheatCrash = true;
                    break;
                }
            }

            if (isAntiCheatCrash)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Anti-Cheat-Prozess-Absturz-Dump gefunden: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = dmpFile,
                    FileName = fileName,
                    Reason = $"Im Minidump-Verzeichnis wurde ein Crashdump mit einem Anti-Cheat-Prozessnamen " +
                             $"'{fileName}' gefunden. Crashes von Anti-Cheat-Prozessen (EAC, BattlEye, Vanguard) " +
                             "sind ein starkes Indiz fuer Bypass-Versuche, da legitime Anti-Cheat-Software " +
                             "selten ohne externen Eingriff abstuerzt.",
                    Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm}"
                });
            }
        }

        if (recentDumps.Count >= 5)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Auffaellig viele aktuelle Minidumps: {recentDumps.Count} in 90 Tagen",
                Risk = RiskLevel.Medium,
                Location = minidumpDir,
                FileName = null,
                Reason = $"Im Windows-Minidump-Verzeichnis wurden {recentDumps.Count} Dumps aus den " +
                         "letzten 90 Tagen gefunden. Eine erhoeht Anzahl von Minidumps kann auf " +
                         "instabile Treiber (z.B. Cheat-Treiber), Kernel-Abstuerze durch DSE-Bypass " +
                         "oder gezielte Speicherdumping-Aktivitaet hinweisen.",
                Detail = $"Aktuellster Dump: {(recentDumps.Count > 0 ? recentDumps.Max(d => d.time).ToString("yyyy-MM-dd HH:mm") : "N/A")}"
            });
        }

        await Task.CompletedTask;
    }

    private async Task ScanLocalAppDataCrashDumpsAsync(ScanContext ctx, CancellationToken ct)
    {
        var crashDumpsDir = Path.Combine(KnownPaths.LocalAppData, "CrashDumps");
        if (!Directory.Exists(crashDumpsDir)) return;

        string[] dmpFiles;
        try { dmpFiles = Directory.GetFiles(crashDumpsDir, "*.dmp", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var dmpFile in dmpFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(dmpFile);
            DateTime writeTime;
            try { writeTime = File.GetLastWriteTime(dmpFile); }
            catch { writeTime = DateTime.MinValue; }

            bool isCheatRelated = false;
            foreach (var fragment in CheatProcessNameFragments)
            {
                if (fileName.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                {
                    isCheatRelated = true;
                    break;
                }
            }

            if (isCheatRelated)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Anwendungs-Crashdump mit Cheat-Bezug: {fileName}",
                    Risk = RiskLevel.High,
                    Location = dmpFile,
                    FileName = fileName,
                    Reason = $"In AppData\\Local\\CrashDumps wurde ein Dump '{fileName}' mit einem " +
                             "cheat-bezogenen Prozessnamen gefunden. Dieser Dump beweist, dass der " +
                             "entsprechende Cheat-Prozess zu einem frueherem Zeitpunkt aktiv war.",
                    Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm}"
                });
            }

            bool isAntiCheatCrash = false;
            foreach (var acName in AntiCheatProcessNames)
            {
                if (fileName.Contains(acName, StringComparison.OrdinalIgnoreCase))
                {
                    isAntiCheatCrash = true;
                    break;
                }
            }

            if (isAntiCheatCrash)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Anti-Cheat-Absturzdump in AppData: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = dmpFile,
                    FileName = fileName,
                    Reason = $"Ein Crashdump des Anti-Cheat-Prozesses '{fileName}' wurde in " +
                             "AppData\\Local\\CrashDumps gefunden. Anti-Cheat-Prozesse stuerzen " +
                             "im normalen Betrieb nicht ab; ein Crash ist ein starkes Signal fuer " +
                             "einen Bypass-Angriff.",
                    Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm}"
                });
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanTempDumpFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var tempRoots = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        foreach (var tempRoot in tempRoots)
        {
            if (!Directory.Exists(tempRoot)) continue;

            string[] dmpFiles;
            try { dmpFiles = Directory.GetFiles(tempRoot, "*.dmp"); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            string[] mdmpFiles;
            try { mdmpFiles = Directory.GetFiles(tempRoot, "*.mdmp"); }
            catch (UnauthorizedAccessException) { mdmpFiles = Array.Empty<string>(); }
            catch { mdmpFiles = Array.Empty<string>(); }

            var allDumps = dmpFiles.Concat(mdmpFiles).ToArray();

            foreach (var dmpFile in allDumps)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(dmpFile);
                DateTime writeTime;
                try { writeTime = File.GetLastWriteTime(dmpFile); }
                catch { writeTime = DateTime.MinValue; }

                bool isCheatRelated = false;
                foreach (var fragment in CheatProcessNameFragments)
                {
                    if (fileName.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                    {
                        isCheatRelated = true;
                        break;
                    }
                }

                if (isCheatRelated)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat-bezogener Dump in Temp-Verzeichnis: {fileName}",
                        Risk = RiskLevel.High,
                        Location = dmpFile,
                        FileName = fileName,
                        Reason = $"Eine Dump-Datei mit cheat-bezogenem Namen '{fileName}' wurde in einem " +
                                 $"Temp-Verzeichnis gefunden. Cheat-Loader legen oft Dumps im Temp-Verzeichnis " +
                                 "ab, wenn sie abstuerzen oder wenn der Nutzer aktiv Speicher-Dumps erstellt.",
                        Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm} | Temp-Root: {tempRoot}"
                    });
                }
                else if ((DateTime.Now - writeTime).TotalDays <= 14)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Aktueller Dump im Temp-Verzeichnis: {fileName}",
                        Risk = RiskLevel.Low,
                        Location = dmpFile,
                        FileName = fileName,
                        Reason = $"Eine kuerzlich erstellte Dump-Datei wurde in einem Temp-Verzeichnis " +
                                 "gefunden. Haeufige oder ungewoehnliche Dumps in Temp-Verzeichnissen " +
                                 "koennen auf Cheat-Tool-Aktivitaet oder gezieltes Speicher-Dumping hinweisen.",
                        Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm}"
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanGameCrashDumpsAsync(ScanContext ctx, CancellationToken ct)
    {
        var appDataRoots = new[]
        {
            KnownPaths.RoamingAppData,
            KnownPaths.LocalAppData,
            KnownPaths.UserProfile + "\\Documents",
        };

        foreach (var appRoot in appDataRoots)
        {
            if (!Directory.Exists(appRoot)) continue;

            foreach (var gameSubDir in GameCrashSubDirs)
            {
                ct.ThrowIfCancellationRequested();

                var gameDir = Path.Combine(appRoot, gameSubDir);
                if (!Directory.Exists(gameDir)) continue;

                var crashSubPaths = new[]
                {
                    Path.Combine(gameDir, "Crashes"),
                    Path.Combine(gameDir, "CrashDumps"),
                    Path.Combine(gameDir, "Crash"),
                    Path.Combine(gameDir, "Minidumps"),
                    Path.Combine(gameDir, "dumps"),
                };

                foreach (var crashPath in crashSubPaths)
                {
                    if (!Directory.Exists(crashPath)) continue;

                    string[] dmpFiles;
                    try
                    {
                        dmpFiles = Directory.GetFiles(crashPath, "*.dmp", SearchOption.AllDirectories)
                                           .Concat(Directory.GetFiles(crashPath, "*.mdmp", SearchOption.AllDirectories))
                                           .ToArray();
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch { continue; }

                    foreach (var dmpFile in dmpFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();

                        var fileName = Path.GetFileName(dmpFile);
                        DateTime writeTime;
                        try { writeTime = File.GetLastWriteTime(dmpFile); }
                        catch { writeTime = DateTime.MinValue; }

                        bool isCheatRelated = false;
                        foreach (var fragment in CheatProcessNameFragments)
                        {
                            if (fileName.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                            {
                                isCheatRelated = true;
                                break;
                            }
                        }

                        if (isCheatRelated)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Spiel-Crashdump mit Cheat-Prozessnamen in {gameSubDir}",
                                Risk = RiskLevel.Critical,
                                Location = dmpFile,
                                FileName = fileName,
                                Reason = $"Im Spiel-Crash-Verzeichnis von '{gameSubDir}' wurde ein Dump " +
                                         $"'{fileName}' gefunden, der einem Cheat-Prozessnamen entspricht. " +
                                         "Dies ist ein direkter forensischer Beweis, dass ein Cheat-Loader " +
                                         "im Kontext dieses Spiels aktiv war.",
                                Detail = $"Spiel: {gameSubDir} | Erstellt: {writeTime:yyyy-MM-dd HH:mm}"
                            });
                        }
                    }

                    if (dmpFiles.Length >= 10)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Ueberdurchschnittlich viele Crashdumps in {gameSubDir}",
                            Risk = RiskLevel.Medium,
                            Location = crashPath,
                            FileName = null,
                            Reason = $"Im Crash-Verzeichnis von '{gameSubDir}' wurden {dmpFiles.Length} Dumps " +
                                     "gefunden. Eine hohe Anzahl von Spielabstuerzen kann auf instabile " +
                                     "Cheat-Software, DLL-Injection-Probleme oder Anti-Cheat-Konflikte hinweisen.",
                            Detail = $"Anzahl Dumps: {dmpFiles.Length} | Verzeichnis: {crashPath}"
                        });
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanWerReportQueueAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanWerDirectoryAsync(ctx, ct,
            Path.Combine(KnownPaths.LocalAppData, "Microsoft", "Windows", "WER", "ReportQueue"),
            "WER ReportQueue");
    }

    private async Task ScanWerReportArchiveAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanWerDirectoryAsync(ctx, ct,
            Path.Combine(KnownPaths.LocalAppData, "Microsoft", "Windows", "WER", "ReportArchive"),
            "WER ReportArchive");

        await ScanWerDirectoryAsync(ctx, ct,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows", "WER", "ReportArchive"),
            "WER ReportArchive (System)");
    }

    private async Task ScanWerDirectoryAsync(ScanContext ctx, CancellationToken ct, string werDir, string sourceName)
    {
        if (!Directory.Exists(werDir)) return;

        string[] werFiles;
        try { werFiles = Directory.GetFiles(werDir, "*.wer", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var werFile in werFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(werFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            DateTime writeTime;
            try { writeTime = File.GetLastWriteTime(werFile); }
            catch { writeTime = DateTime.MinValue; }

            string? appPath = null;
            string? appName = null;

            foreach (var line in content.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("AppPath=", StringComparison.OrdinalIgnoreCase))
                {
                    appPath = trimmed.Substring("AppPath=".Length).Trim();
                    if (!string.IsNullOrEmpty(appPath))
                        appName = Path.GetFileName(appPath);
                    break;
                }
                if (trimmed.StartsWith("AppName=", StringComparison.OrdinalIgnoreCase))
                {
                    appName = trimmed.Substring("AppName=".Length).Trim();
                }
            }

            if (string.IsNullOrEmpty(appName)) continue;

            bool isCheatApp = false;
            foreach (var fragment in CheatProcessNameFragments)
            {
                if (appName.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                {
                    isCheatApp = true;
                    break;
                }
            }

            if (isCheatApp)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"WER-Bericht: Absturz von Cheat-Anwendung: {appName}",
                    Risk = RiskLevel.High,
                    Location = werFile,
                    FileName = Path.GetFileName(werFile),
                    Reason = $"Ein Windows-Fehlerbericht (WER) dokumentiert den Absturz der Anwendung " +
                             $"'{appName}', die einem bekannten Cheat-Prozessnamen entspricht. " +
                             "Der WER-Bericht ist ein forensischer Beweis, dass diese Anwendung " +
                             "zu einem frueheren Zeitpunkt ausgefuehrt wurde.",
                    Detail = $"Quelle: {sourceName} | App: {appPath ?? appName} | Datum: {writeTime:yyyy-MM-dd HH:mm}"
                });
                continue;
            }

            bool isAntiCheatCrash = false;
            foreach (var acName in AntiCheatProcessNames)
            {
                if (appName.Contains(acName, StringComparison.OrdinalIgnoreCase))
                {
                    isAntiCheatCrash = true;
                    break;
                }
            }

            if (isAntiCheatCrash)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"WER-Bericht: Anti-Cheat-Prozess-Absturz: {appName}",
                    Risk = RiskLevel.Critical,
                    Location = werFile,
                    FileName = Path.GetFileName(werFile),
                    Reason = $"Ein WER-Fehlerbericht verzeichnet den Absturz des Anti-Cheat-Prozesses " +
                             $"'{appName}'. Anti-Cheat-Software (EAC, BattlEye, Vanguard, FACEIT) stuerzt " +
                             "im normalen Betrieb nicht ab. Dieser Absturz deutet auf einen " +
                             "Bypass-Angriff oder gezielte Prozess-Terminierung hin.",
                    Detail = $"Quelle: {sourceName} | App: {appPath ?? appName} | Datum: {writeTime:yyyy-MM-dd HH:mm}"
                });
            }
        }
    }

    private void ScanPagefileAndHibernation(ScanContext ctx)
    {
        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))
                         ?? @"C:\";

        var pageFile = Path.Combine(systemDrive, "pagefile.sys");
        var swapFile = Path.Combine(systemDrive, "swapfile.sys");
        var hiberFile = Path.Combine(systemDrive, "hiberfil.sys");

        foreach (var (filePath, fileName, description) in new[]
        {
            (pageFile, "pagefile.sys", "Windows-Auslagerungsdatei"),
            (swapFile, "swapfile.sys", "Windows-Swap-Datei"),
            (hiberFile, "hiberfil.sys", "Windows-Ruhezustand-Datei"),
        })
        {
            if (!File.Exists(filePath)) continue;
            ctx.IncrementFiles();

            DateTime writeTime;
            long fileSize;
            try
            {
                var fi = new FileInfo(filePath);
                writeTime = fi.LastWriteTime;
                fileSize = fi.Length;
            }
            catch { continue; }

            var age = DateTime.Now - writeTime;
            if (age.TotalHours <= 48)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"{fileName} innerhalb der letzten 48 Stunden geaendert",
                    Risk = RiskLevel.Low,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"Die {description} ('{fileName}') wurde innerhalb der letzten 48 Stunden " +
                             "geaendert. Diese Datei enthaelt Speicherinhalte laufender Prozesse. " +
                             "Forensische Tools koennen diese Datei analysieren, um Cheat-Spuren " +
                             "nachzuweisen, auch wenn die Cheat-Software laengst entfernt wurde.",
                    Detail = $"Letzte Aenderung: {writeTime:yyyy-MM-dd HH:mm} | Groesse: {fileSize / (1024 * 1024)} MB"
                });
            }
        }
    }

    private void ScanMemoryAnalysisTools(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents",
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.RoamingAppData,
            KnownPaths.UserProfile + "\\Tools",
            KnownPaths.UserProfile + "\\forensics",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*.exe", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(file);

                foreach (var toolName in MemoryToolNames)
                {
                    if (fileName.Equals(toolName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        DateTime writeTime;
                        try { writeTime = File.GetLastWriteTime(file); }
                        catch { writeTime = DateTime.MinValue; }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Speicheranalyse-Tool gefunden: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Das Speicheranalyse- oder Memory-Forensik-Tool '{fileName}' wurde " +
                                     $"in '{root}' gefunden. Diese Tools (Volatility, WinPmem, DumpIt, etc.) " +
                                     "werden eingesetzt, um physischen RAM zu lesen und zu analysieren. " +
                                     "Im Gaming-Kontext werden sie fuer die Spielspeicher-Analyse und " +
                                     "zum Entwickeln von externen Cheats oder Memory-Read-Exploits benutzt.",
                            Detail = $"Gefunden: {writeTime:yyyy-MM-dd HH:mm}"
                        });
                        break;
                    }
                }

                foreach (var dumpToolName in ProcessDumpToolNames)
                {
                    if (fileName.Equals(dumpToolName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        DateTime writeTime;
                        try { writeTime = File.GetLastWriteTime(file); }
                        catch { writeTime = DateTime.MinValue; }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Prozess-Dump-Tool gefunden: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Das Prozess-Dump-Tool '{fileName}' wurde in '{root}' gefunden. " +
                                     "Tools wie ProcDump und ihre Varianten werden von Cheat-Entwicklern " +
                                     "verwendet, um Spielprozesse zu dumpen, Speicherbereiche zu analysieren " +
                                     "und Offsets fuer Memory-Cheats zu bestimmen.",
                            Detail = $"Gefunden: {writeTime:yyyy-MM-dd HH:mm}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private async Task ScanPeSieveArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents",
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] allFiles;
            try { allFiles = Directory.GetFiles(root, "*.*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in allFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(file);

                foreach (var artifactName in PeSieveArtifactNames)
                {
                    if (fileName.Equals(artifactName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();

                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync();
                        }
                        catch (IOException) { break; }
                        catch (UnauthorizedAccessException) { break; }

                        DateTime writeTime;
                        try { writeTime = File.GetLastWriteTime(file); }
                        catch { writeTime = DateTime.MinValue; }

                        bool hasInjectionEvidence = content.Contains("injected", StringComparison.OrdinalIgnoreCase)
                                                 || content.Contains("implanted", StringComparison.OrdinalIgnoreCase)
                                                 || content.Contains("hollowed", StringComparison.OrdinalIgnoreCase)
                                                 || content.Contains("replaced", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PE-Sieve-Artefakt gefunden: {fileName}",
                            Risk = hasInjectionEvidence ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Ein PE-Sieve-Analysebericht ('{fileName}') wurde gefunden. " +
                                     "PE-Sieve ist ein Tool zur Erkennung von injizierten oder " +
                                     "manipulierten Prozessen (Process Hollowing, DLL Injection). " +
                                     "Der Bericht belegt, dass PE-Sieve auf diesem System ausgefuehrt wurde, " +
                                     "was auf die Analyse von Spielprozessen fuer Cheat-Entwicklung hinweist." +
                                     (hasInjectionEvidence ? " Bericht enthaelt Hinweise auf Injection-Aktivitaet." : ""),
                            Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm} | Injection-Nachweis: {hasInjectionEvidence}"
                        });
                        break;
                    }
                }

                if (fileName.StartsWith("process_", StringComparison.OrdinalIgnoreCase) &&
                    Directory.Exists(file))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Moegliches PE-Sieve-Ausgabeverzeichnis: {fileName}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Das Verzeichnis '{fileName}' entspricht dem Namensschema von PE-Sieve-" +
                                 "Ausgabeverzeichnissen (process_<PID>). PE-Sieve extrahiert gedumpte " +
                                 "Prozessmodule in solche Verzeichnisse.",
                        Detail = null
                    });
                }
            }
        }
    }

    private async Task ScanVirtualMemoryDumpsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents",
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.UserProfile + "\\VMs",
            KnownPaths.UserProfile + "\\Virtual Machines",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] allFiles;
            try { allFiles = Directory.GetFiles(root, "*.*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in allFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);

                if (!VmemExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                long fileSize;
                try { fileSize = new FileInfo(file).Length; }
                catch { fileSize = 0; }

                DateTime writeTime;
                try { writeTime = File.GetLastWriteTime(file); }
                catch { writeTime = DateTime.MinValue; }

                bool isGamingRelated = false;
                foreach (var gameSubDir in GameCrashSubDirs)
                {
                    if (file.Contains(gameSubDir, StringComparison.OrdinalIgnoreCase))
                    {
                        isGamingRelated = true;
                        break;
                    }
                }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"VM-Speicher-Snapshot in Benutzerverzeichnis: {fileName}",
                    Risk = isGamingRelated ? RiskLevel.High : RiskLevel.Medium,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Eine VM-Speicher-Datei ('{ext}') wurde in einem Benutzerverzeichnis gefunden. " +
                             "QEMU/VMware-Speicher-Snapshots (.vmem, .vmsn, .vmss) koennen " +
                             "vollstaendige Speicherabbilder enthalten und werden fuer die " +
                             "Analyse von Spielprozessen oder Anti-Cheat-Mechanismen benutzt." +
                             (isGamingRelated ? " Datei liegt im Kontext eines Spielverzeichnisses." : ""),
                    Detail = $"Groesse: {fileSize / (1024 * 1024)} MB | Erstellt: {writeTime:yyyy-MM-dd HH:mm}"
                });
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanNonStandardMemoryDumpsAsync(ScanContext ctx, CancellationToken ct)
    {
        var systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows))
                         ?? @"C:\";
        var windir = Environment.GetEnvironmentVariable("SYSTEMROOT")
                     ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var standardLocations = new[]
        {
            Path.Combine(windir, "MEMORY.DMP"),
            Path.Combine(windir, "Minidump"),
        };

        var searchRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents",
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.RoamingAppData,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] memDmpFiles;
            try
            {
                memDmpFiles = Directory.GetFiles(root, "MEMORY.DMP", SearchOption.AllDirectories)
                                      .Concat(Directory.GetFiles(root, "memory.dmp", SearchOption.AllDirectories))
                                      .Distinct(StringComparer.OrdinalIgnoreCase)
                                      .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var dmpFile in memDmpFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                bool isStandard = false;
                foreach (var stdLoc in standardLocations)
                {
                    if (dmpFile.StartsWith(stdLoc, StringComparison.OrdinalIgnoreCase))
                    {
                        isStandard = true;
                        break;
                    }
                }

                if (isStandard) continue;

                long fileSize;
                DateTime writeTime;
                try
                {
                    var fi = new FileInfo(dmpFile);
                    fileSize = fi.Length;
                    writeTime = fi.LastWriteTime;
                }
                catch { continue; }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"MEMORY.DMP an nicht-standardmaessigem Speicherort",
                    Risk = RiskLevel.High,
                    Location = dmpFile,
                    FileName = Path.GetFileName(dmpFile),
                    Reason = "Eine MEMORY.DMP-Datei wurde ausserhalb der Windows-Standardspeicherorte " +
                             "(C:\\Windows\\MEMORY.DMP) gefunden. Vollstaendige Speicherdumps an " +
                             "ungewoehnlichen Orten deuten auf gezieltes Speicher-Dumping hin, " +
                             "das fuer die Cheat-Entwicklung oder Anti-Cheat-Analyse eingesetzt wird.",
                    Detail = $"Pfad: {dmpFile} | Groesse: {fileSize / (1024 * 1024)} MB | Erstellt: {writeTime:yyyy-MM-dd HH:mm}"
                });
            }

            string[] gameDirDumps;
            try
            {
                gameDirDumps = Directory.GetFiles(root, "*.dmp", SearchOption.AllDirectories)
                                       .Concat(Directory.GetFiles(root, "*.mdmp", SearchOption.AllDirectories))
                                       .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var dmpFile in gameDirDumps)
            {
                ct.ThrowIfCancellationRequested();

                bool isGameDir = false;
                foreach (var gameSubDir in GameCrashSubDirs)
                {
                    if (dmpFile.Contains(gameSubDir, StringComparison.OrdinalIgnoreCase))
                    {
                        isGameDir = true;
                        break;
                    }
                }

                if (!isGameDir) continue;

                var fileName = Path.GetFileName(dmpFile);

                bool isCheatRelated = false;
                foreach (var fragment in CheatProcessNameFragments)
                {
                    if (fileName.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                    {
                        isCheatRelated = true;
                        break;
                    }
                }

                if (!isCheatRelated) continue;

                ctx.IncrementFiles();
                DateTime writeTime;
                try { writeTime = File.GetLastWriteTime(dmpFile); }
                catch { writeTime = DateTime.MinValue; }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat-Dump im Spiel-Verzeichnis: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = dmpFile,
                    FileName = fileName,
                    Reason = $"Im Spielverzeichnis wurde eine Dump-Datei mit cheat-bezogenem Namen '{fileName}' " +
                             "gefunden. Dumps von Cheat-Prozessen in Spielverzeichnissen sind ein starkes " +
                             "forensisches Signal und belegen die gleichzeitige Aktivitaet von Spiel und Cheat.",
                    Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm}"
                });
            }
        }

        await Task.CompletedTask;
    }
}
