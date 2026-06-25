using System.Diagnostics.Eventing.Reader;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CheatEngineDeepForensicScanModule : IScanModule
{
    public string Name => "Cheat Engine Deep Forensic Scan";
    public double Weight => 4.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string RoamingAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string Downloads =
        Path.Combine(UserProfile, "Downloads");
    private static readonly string ProgramFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32 =
        Path.Combine(WinDir, "System32");
    private static readonly string Temp =
        Path.GetTempPath();

    private static readonly string[] CeExecutableNames =
    {
        "cheatengine-x86_64.exe",
        "cheatengine-x86_64-SSE4-AVX2.exe",
        "cheatengine.exe",
        "cheat engine.exe",
        "ce.exe",
        "CheatEngine.exe",
        "CheatEngine7.exe",
        "CheatEngine75.exe",
        "CheatEngine76.exe",
        "CheatEngine74.exe",
        "cheatengine7.exe",
        "cheatengine74.exe",
        "cheatengine75.exe",
        "cheatengine76.exe",
    };

    private static readonly string[] CeDriverNames =
    {
        "dbk32.sys",
        "dbk64.sys",
    };

    private static readonly string[] CeInjectDllNames =
    {
        "speedhack.dll",
        "speedhacki64.dll",
        "vehdebug-i386.dll",
        "vehdebug-x86_64.dll",
        "luaclient-i386.dll",
        "luaclient-x86_64.dll",
        "allochook-i386.dll",
        "allochook-x86_64.dll",
        "ceserver.dll",
    };

    private static readonly string[] GameRelatedCtNames =
    {
        "gta5.ct", "gta_v.ct", "gtav.ct",
        "fivem.ct", "fivem_hack.ct",
        "altv.ct", "alt_v.ct",
        "valorant.ct", "valorant_hack.ct",
        "rust.ct", "rust_cheat.ct",
        "eft.ct", "escapefromtarkov.ct", "escape from tarkov.ct",
        "cs2.ct", "csgo.ct", "counterstrike.ct", "counter-strike.ct",
        "apex.ct", "apexlegends.ct", "apex_legends.ct",
        "warzone.ct", "cod_warzone.ct", "cod.ct",
        "battlefront.ct", "battlefront2.ct",
        "fortnite.ct",
        "pubg.ct",
        "roblox.ct",
        "minecraft.ct",
        "dayz.ct",
        "arma3.ct", "arma.ct",
        "rdr2.ct", "reddeadredemption2.ct",
    };

    private static readonly string[] CeLuaCheatPatterns =
    {
        "writeprocessmemory",
        "readprocessmemory",
        "getaddress(",
        "aobscan(",
        "aobscanmodule(",
        "inject(",
        "injectdll(",
        "injectcode(",
        "createthread(",
        "bypass",
        "anticheat",
        "anti-cheat",
        "hack",
        "aimbot",
        "esp",
        "wallhack",
        "norecoil",
        "speedhack",
        "godmode",
        "god mode",
        "infinite ammo",
        "infinite health",
        "no clip",
        "noclip",
        "teleport",
        "freeze player",
        "getlocalplayer",
        "getplayerhealth",
        "gta5",
        "fivem",
        "valorant",
        "battleye bypass",
        "eac bypass",
        "easy anti-cheat",
    };

    private static readonly string[] CeAutoAttachTargets =
    {
        "fivem",
        "gta5",
        "gtav",
        "GTA5.exe",
        "FiveM.exe",
        "FiveM_b",
        "valorant",
        "VALORANT-Win64-Shipping",
        "cs2",
        "csgo",
        "RustClient",
        "EscapeFromTarkov",
        "r5apex",
        "ModernWarfare",
        "FortniteClient",
        "TslGame",
        "DayZ",
        "arma3",
        "RDR2",
    };

    private static readonly string[] CeMuiCachePaths =
    {
        "cheatengine-x86_64.exe",
        "cheatengine.exe",
        "CheatEngine.exe",
        "cheat engine.exe",
        "ce.exe",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Cheat Engine Forensic Scan", "Starte Cheat Engine Deep Forensic Scan...");

        await Task.WhenAll(
            CheckCeInstallationFolders(ctx, ct),
            CheckCeDriverFiles(ctx, ct),
            CheckCeTableFiles(ctx, ct),
            CheckCeLuaScripts(ctx, ct),
            CheckCeExecutableVariants(ctx, ct),
            CheckCeRegistryArtifacts(ctx, ct),
            CheckCeDbkDriverService(ctx, ct),
            CheckCeSpeedhackArtifacts(ctx, ct),
            CheckCeProcessArtifacts(ctx, ct),
            CheckCeUserAssist(ctx, ct),
            CheckCeMuiCache(ctx, ct),
            CheckCeAutoAttachScripts(ctx, ct),
            CheckCeMonoScripts(ctx, ct),
            CheckCeEventLog(ctx, ct),
            CheckCeUninstallRecords(ctx, ct),
            CheckCeProgramDataArtifacts(ctx, ct)
        );

        ctx.Report(1.0, "Cheat Engine Forensic Scan", "Cheat Engine Deep Forensic Scan abgeschlossen");
    }

    private Task CheckCeInstallationFolders(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var candidates = new List<string>();

            // Standard Program Files locations for CE installs
            for (int v = 6; v <= 8; v++)
            {
                for (int minor = 0; minor <= 9; minor++)
                {
                    string ver = minor == 0 ? $"{v}" : $"{v}.{minor}";
                    candidates.Add(Path.Combine(ProgramFiles, $"Cheat Engine {ver}"));
                    candidates.Add(Path.Combine(ProgramFilesX86, $"Cheat Engine {ver}"));
                }
            }
            // Generic CE folder names
            candidates.Add(Path.Combine(ProgramFiles, "Cheat Engine"));
            candidates.Add(Path.Combine(ProgramFilesX86, "Cheat Engine"));
            candidates.Add(Path.Combine(LocalAppData, "Programs", "Cheat Engine"));
            candidates.Add(Path.Combine(LocalAppData, "Cheat Engine"));
            candidates.Add(Path.Combine(UserProfile, "Cheat Engine"));
            candidates.Add(Path.Combine(Desktop, "Cheat Engine"));
            candidates.Add(Path.Combine(Downloads, "Cheat Engine"));
            candidates.Add(Path.Combine(Downloads, "CheatEngine"));
            candidates.Add(Path.Combine(Temp, "Cheat Engine"));

            foreach (var dir in candidates)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                // Check for the main CE executable inside the folder
                foreach (var exeName in CeExecutableNames)
                {
                    var exePath = Path.Combine(dir, exeName);
                    if (!File.Exists(exePath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Engine Installationsordner gefunden",
                        Risk = RiskLevel.High,
                        Location = dir,
                        FileName = exeName,
                        Reason = $"Ein Cheat Engine Installationsordner wurde unter '{dir}' gefunden. " +
                                 $"Die CE-Hauptdatei '{exeName}' ist vorhanden. Cheat Engine ist ein " +
                                 "Speichermanipulationswerkzeug, das in fast allen Spielen gegen " +
                                 "die Nutzungsbedingungen verstoesst und als Cheat-Tool eingesetzt wird.",
                        Detail = $"Pfad: {exePath}"
                    });
                }

                // Check for CE driver files in the install folder
                foreach (var drvName in CeDriverNames)
                {
                    var drvPath = Path.Combine(dir, drvName);
                    if (!File.Exists(drvPath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Engine Kernel-Treiber in Installationsordner",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = drvName,
                        Reason = $"Der Cheat Engine Kernel-Treiber '{drvName}' wurde im Ordner '{dir}' " +
                                 "gefunden. Der DBK-Treiber gewaehrt CE Ring-0-Zugriff auf Spielspeicher " +
                                 "und ermoeglicht Kernel-Level-Cheating. Das Vorhandensein dieses Treibers " +
                                 "ist ein starkes Indiz fuer aktive oder kuerzliche CE-Nutzung.",
                        Detail = $"Treiber: {drvPath}"
                    });
                }
            }
        }, ct);

    private Task CheckCeDriverFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Check standard driver locations for CE kernel drivers
            var driverSearchPaths = new[]
            {
                Path.Combine(System32, "drivers"),
                Path.Combine(WinDir, "SysWOW64", "drivers"),
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(WinDir, "Temp"),
                Downloads,
                Desktop,
                Documents,
                Path.Combine(LocalAppData, "Cheat Engine"),
                Path.Combine(RoamingAppData, "Cheat Engine"),
            };

            foreach (var searchPath in driverSearchPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(searchPath)) continue;

                try
                {
                    foreach (var drvName in CeDriverNames)
                    {
                        var drvPath = Path.Combine(searchPath, drvName);
                        if (!File.Exists(drvPath)) continue;

                        ctx.IncrementFiles();
                        bool isInDriversDir = searchPath.Contains("drivers", StringComparison.OrdinalIgnoreCase)
                                              && searchPath.Contains("System32", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Kernel-Treiber: {drvName}",
                            Risk = RiskLevel.Critical,
                            Location = drvPath,
                            FileName = drvName,
                            Reason = $"Der Cheat Engine Kernel-Treiber '{drvName}' wurde unter '{drvPath}' " +
                                     "gefunden. DBK32/DBK64 sind die offiziellen Kernel-Treiber von Cheat Engine " +
                                     "und geben dem CE-Prozess direkten Ring-0-Zugriff auf Spielspeicher. " +
                                     (isInDriversDir
                                         ? "Der Treiber befindet sich im System-Treiberordner, was auf eine " +
                                           "aktive oder vergangene Installation hindeutet."
                                         : "Der Treiber befindet sich ausserhalb des System-Treiberordners, " +
                                           "was auf temporaere Ablage oder manuelle Nutzung hindeutet."),
                            Detail = $"CE-Kernel-Treiber benoetigt Administratorrechte zum Laden."
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Also check for CE DLL injection artifacts in common locations
            var dllSearchPaths = new[]
            {
                System32,
                Path.Combine(WinDir, "SysWOW64"),
                Temp,
                Downloads,
                Desktop,
            };

            foreach (var searchPath in dllSearchPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(searchPath)) continue;

                try
                {
                    foreach (var dllName in CeInjectDllNames)
                    {
                        var dllPath = Path.Combine(searchPath, dllName);
                        if (!File.Exists(dllPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Injections-DLL: {dllName}",
                            Risk = RiskLevel.High,
                            Location = dllPath,
                            FileName = dllName,
                            Reason = $"Die Cheat Engine DLL '{dllName}' wurde unter '{dllPath}' gefunden. " +
                                     "Diese DLLs werden von CE in Zielprozesse injiziert, um Speedhack, " +
                                     "VEH-Debugging und Lua-Scripting zu ermoeglichen. Das Vorhandensein " +
                                     "dieser Dateien ausserhalb des CE-Installationsverzeichnisses deutet " +
                                     "auf einen aktiven DLL-Injektions-Angriff hin.",
                            Detail = $"CE-Injection-DLLs werden normalerweise nur im CE-Installationsordner erwartet."
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckCeTableFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Documents,
                Downloads,
                Desktop,
                Path.Combine(Documents, "Cheat Engine"),
                Path.Combine(Documents, "CheatEngine"),
                Path.Combine(Documents, "CE Tables"),
                Path.Combine(Documents, "Cheat Tables"),
                Path.Combine(UserProfile, "Cheat Tables"),
                Path.Combine(RoamingAppData, "Cheat Engine"),
                Path.Combine(LocalAppData, "Cheat Engine"),
                Temp,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] ctFiles;
                try { ctFiles = Directory.GetFiles(dir, "*.ct", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var ctFile in ctFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(ctFile);
                    bool isGameRelated = GameRelatedCtNames.Any(g =>
                        fileName.Equals(g, StringComparison.OrdinalIgnoreCase));

                    // Try to read the CT file to inspect for game references
                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(ctFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }

                    bool contentHasGameRef = !string.IsNullOrEmpty(content) && CeAutoAttachTargets.Any(t =>
                        content.Contains(t, StringComparison.OrdinalIgnoreCase));

                    var risk = (isGameRelated || contentHasGameRef) ? RiskLevel.High : RiskLevel.Medium;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = isGameRelated
                            ? $"Cheat Engine Table fuer bekanntes Spiel: {fileName}"
                            : $"Cheat Engine Table gefunden: {fileName}",
                        Risk = risk,
                        Location = ctFile,
                        FileName = fileName,
                        Reason = $"Eine Cheat Engine Tabellen-Datei (.CT) wurde unter '{ctFile}' gefunden. " +
                                 "CT-Dateien enthalten Speicheradressen, Lua-Scripts und Cheat-Eintraege " +
                                 "fuer bestimmte Spiele. " +
                                 (isGameRelated
                                     ? $"Der Dateiname '{fileName}' entspricht einem bekannten Online-Spiel, " +
                                       "fuer das CE-basiertes Cheating verbreitet ist."
                                     : "") +
                                 (contentHasGameRef
                                     ? " Der Tabelleninhalt referenziert bekannte Online-Spiel-Prozesse."
                                     : ""),
                        Detail = $"CT-Dateigroesse: {new FileInfo(ctFile).Length} Bytes"
                    });
                }
            }
        }, ct);

    private Task CheckCeLuaScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var luaDirs = new[]
            {
                Path.Combine(RoamingAppData, "Cheat Engine"),
                Path.Combine(LocalAppData, "Cheat Engine"),
                Path.Combine(Documents, "Cheat Engine"),
                Path.Combine(Documents, "CheatEngine"),
                Path.Combine(LocalAppData, "Programs", "Cheat Engine"),
                // ProgramFiles CE installs
                Path.Combine(ProgramFiles, "Cheat Engine 7.5"),
                Path.Combine(ProgramFiles, "Cheat Engine 7.4"),
                Path.Combine(ProgramFiles, "Cheat Engine 7.3"),
                Path.Combine(ProgramFiles, "Cheat Engine 7.2"),
                Path.Combine(ProgramFiles, "Cheat Engine 7.1"),
                Path.Combine(ProgramFiles, "Cheat Engine 7.0"),
                Path.Combine(ProgramFiles, "Cheat Engine 6.8"),
                Path.Combine(ProgramFiles, "Cheat Engine"),
                Path.Combine(ProgramFilesX86, "Cheat Engine 7.5"),
                Path.Combine(ProgramFilesX86, "Cheat Engine 7.4"),
                Path.Combine(ProgramFilesX86, "Cheat Engine"),
            };

            foreach (var dir in luaDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] luaFiles;
                try
                {
                    luaFiles = Directory.GetFiles(dir, "*.lua", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var luaFile in luaFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var lc = content.ToLowerInvariant();
                    var matchedPatterns = CeLuaCheatPatterns
                        .Where(p => lc.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedPatterns.Count == 0) continue;

                    var fileName = Path.GetFileName(luaFile);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Engine Lua-Script mit Cheat-Mustern: {fileName}",
                        Risk = matchedPatterns.Count >= 3 ? RiskLevel.High : RiskLevel.Medium,
                        Location = luaFile,
                        FileName = fileName,
                        Reason = $"Eine Lua-Skript-Datei im Cheat Engine Verzeichnis enthaelt {matchedPatterns.Count} " +
                                 "Cheat-spezifische Muster. CE-Lua-Scripts werden verwendet, um automatisierte " +
                                 "Speichermanipulation, DLL-Injektion, Anti-Cheat-Bypass und spielspezifisches " +
                                 "Cheating zu implementieren.",
                        Detail = $"Gefundene Muster: {string.Join(", ", matchedPatterns.Take(8))}"
                    });
                }
            }
        }, ct);

    private Task CheckCeExecutableVariants(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchLocations = new[]
            {
                Downloads,
                Desktop,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(WinDir, "Temp"),
                Documents,
                Path.Combine(UserProfile, "AppData"),
                Path.Combine(LocalAppData, "Programs"),
                Path.Combine(UserProfile, "OneDrive"),
                Path.Combine(UserProfile, "OneDrive", "Desktop"),
                Path.Combine(UserProfile, "OneDrive", "Downloads"),
            };

            foreach (var dir in searchLocations)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var fileName = Path.GetFileName(file);
                        bool isMatch = CeExecutableNames.Any(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (!isMatch) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Ausfuehrbarer Datei: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Eine Cheat Engine ausfuehrbare Datei '{fileName}' wurde unter " +
                                     $"'{file}' gefunden. Der Speicherort ausserhalb des normalen " +
                                     "Installationsverzeichnisses deutet auf portable Nutzung, " +
                                     "Download oder Tarnung hin. CE-Varianten sind aehnliche " +
                                     "ausfuehrbare Dateien mit leicht abweichenden Namen.",
                            Detail = $"Groesse: {new FileInfo(file).Length} Bytes · Zuletzt geaendert: {File.GetLastWriteTime(file):yyyy-MM-dd HH:mm}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckCeRegistryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // HKCU\Software\Cheat Engine - user settings, recent files, config
            var hkcuCePaths = new[]
            {
                @"Software\Cheat Engine",
                @"Software\Cheat Engine Speedhack",
                @"Software\Classes\Applications\CheatEngine.exe",
                @"Software\Classes\Applications\cheatengine-x86_64.exe",
                @"Software\Classes\.ct",
                @"Software\Classes\CheatEngine.CTfile",
            };

            try
            {
                using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                foreach (var subPath in hkcuCePaths)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var key = hkcu.OpenSubKey(subPath, writable: false);
                        if (key is null) continue;
                        ctx.IncrementRegistryKeys();

                        var valueNames = key.GetValueNames();
                        var recentFiles = valueNames
                            .Where(v => v.Contains("recent", StringComparison.OrdinalIgnoreCase)
                                     || v.Contains("lastfile", StringComparison.OrdinalIgnoreCase)
                                     || v.Contains("mru", StringComparison.OrdinalIgnoreCase))
                            .Select(v => key.GetValue(v)?.ToString())
                            .Where(v => !string.IsNullOrEmpty(v))
                            .ToList();

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Registry-Eintrag: HKCU\\{subPath}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{subPath}",
                            Reason = $"Ein Cheat Engine Registry-Schluessel wurde unter 'HKCU\\{subPath}' " +
                                     "gefunden. CE schreibt Konfigurationsdaten, zuletzt verwendete Dateien " +
                                     "und Einstellungen in die Registry. Dieser Schluessel bleibt nach der " +
                                     "Deinstallation ueblicherweise erhalten.",
                            Detail = recentFiles.Count > 0
                                ? $"Zuletzt verwendete Dateien: {string.Join(", ", recentFiles.Take(5))}"
                                : $"Gefundene Werte: {valueNames.Length}"
                        });
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }

            // HKLM\SOFTWARE\Cheat Engine
            var hklmCePaths = new[]
            {
                @"SOFTWARE\Cheat Engine",
                @"SOFTWARE\WOW6432Node\Cheat Engine",
                @"SOFTWARE\Classes\.ct",
                @"SOFTWARE\Classes\CheatEngine.CTfile",
            };

            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                foreach (var subPath in hklmCePaths)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var key = hklm.OpenSubKey(subPath, writable: false);
                        if (key is null) continue;
                        ctx.IncrementRegistryKeys();

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Registry-Eintrag (System): HKLM\\{subPath}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{subPath}",
                            Reason = $"Ein Cheat Engine Registry-Schluessel wurde unter 'HKLM\\{subPath}' " +
                                     "gefunden. Systemweite CE-Registry-Eintraege deuten auf eine " +
                                     "installierte oder kuerzlich deinstallierte Version von Cheat Engine hin.",
                            Detail = $"Werte gefunden: {key.GetValueNames().Length}"
                        });
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckCeDbkDriverService(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Check registry Services key for DBK kernel driver registrations
            var dbkServiceNames = new[]
            {
                "dbk64",
                "dbk32",
                "DBKDRV",
                "DBKernel",
                "CheatEngine",
                "ce_kernel",
                "cedriver",
            };

            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var services = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
                if (services is null) return;

                foreach (var svcName in services.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;

                    bool isDbk = dbkServiceNames.Any(d =>
                        svcName.Equals(d, StringComparison.OrdinalIgnoreCase)
                        || svcName.Contains(d, StringComparison.OrdinalIgnoreCase));
                    if (!isDbk) continue;

                    try
                    {
                        using var svcKey = services.OpenSubKey(svcName, writable: false);
                        if (svcKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        var imagePath = svcKey.GetValue("ImagePath")?.ToString() ?? string.Empty;
                        var displayName = svcKey.GetValue("DisplayName")?.ToString() ?? svcName;
                        var start = svcKey.GetValue("Start");

                        bool isCeDriver = imagePath.Contains("dbk", StringComparison.OrdinalIgnoreCase)
                                       || imagePath.Contains("cheatengine", StringComparison.OrdinalIgnoreCase)
                                       || imagePath.Contains("ce_", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine DBK Kernel-Treiber Dienst: {svcName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = Path.GetFileName(imagePath),
                            Reason = $"Ein Cheat Engine Kernel-Treiber-Dienst '{svcName}' wurde in der Registry " +
                                     $"unter 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svcName}' gefunden. " +
                                     "Der DBK-Treiber ist der Kernel-Treiber von Cheat Engine und ermoeooglicht " +
                                     "Ring-0-Zugriff auf Spielspeicher. Ein registrierter Dienst deutet auf eine " +
                                     "Installation oder kuerzliche Aktivierung von CE hin.",
                            Detail = $"ImagePath: {imagePath} · DisplayName: {displayName} · Start: {start}"
                        });
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckCeSpeedhackArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // Search for speedhack-related artifacts in common locations
            var speedhackFileNames = new[]
            {
                "speedhack.dll",
                "speedhacki64.dll",
                "speedhack-i386.dll",
                "speedhack-x86_64.dll",
                "ce_speedhack.dll",
                "cespeedhack.dll",
            };

            var searchDirs = new[]
            {
                System32,
                Path.Combine(WinDir, "SysWOW64"),
                Temp,
                Downloads,
                Desktop,
                Documents,
                Path.Combine(LocalAppData, "Temp"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var sh in speedhackFileNames)
                    {
                        if (ct.IsCancellationRequested) return;
                        var path = Path.Combine(dir, sh);
                        if (!File.Exists(path)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Speedhack-DLL gefunden: {sh}",
                            Risk = RiskLevel.High,
                            Location = path,
                            FileName = sh,
                            Reason = $"Eine Cheat Engine Speedhack-DLL '{sh}' wurde unter '{path}' gefunden. " +
                                     "Diese DLL implementiert die Spielgeschwindigkeits-Manipulation von CE, " +
                                     "indem sie Zeit-APIs (GetTickCount, QueryPerformanceCounter etc.) hookt. " +
                                     "Das Vorhandensein im Systemordner deutet auf eine vorherige Injektion hin.",
                            Detail = $"Groesse: {new FileInfo(path).Length} Bytes"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Check for speedhack config files
            var speedhackConfigPaths = new[]
            {
                Path.Combine(RoamingAppData, "Cheat Engine", "speedhack.ini"),
                Path.Combine(LocalAppData, "Cheat Engine", "speedhack.ini"),
                Path.Combine(Documents, "speedhack.ini"),
                Path.Combine(ProgramFiles, "Cheat Engine 7.5", "speedhack.ini"),
                Path.Combine(ProgramFilesX86, "Cheat Engine 7.5", "speedhack.ini"),
            };

            foreach (var cfg in speedhackConfigPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!File.Exists(cfg)) continue;

                ctx.IncrementFiles();
                string content = string.Empty;
                try
                {
                    using var fs = new FileStream(cfg, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat Engine Speedhack Konfigurationsdatei gefunden",
                    Risk = RiskLevel.High,
                    Location = cfg,
                    FileName = Path.GetFileName(cfg),
                    Reason = $"Eine Cheat Engine Speedhack-Konfigurationsdatei wurde unter '{cfg}' gefunden. " +
                             "Diese Datei speichert die Einstellungen fuer den CE-Speedhack, einschliesslich " +
                             "des Geschwindigkeitsfaktors und der anzuhakenden Prozesse.",
                    Detail = content.Length > 0 ? $"Inhalt (Anfang): {content[..Math.Min(200, content.Length)]}" : null
                });
            }
        }, ct);

    private Task CheckCeProcessArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Check currently running processes for CE names
            var processes = ctx.GetProcessSnapshot();
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    ctx.IncrementProcesses();
                    var procName = proc.ProcessName + ".exe";
                    bool isCe = CeExecutableNames.Any(n =>
                        procName.Equals(n, StringComparison.OrdinalIgnoreCase)
                        || proc.ProcessName.Equals(
                            Path.GetFileNameWithoutExtension(n),
                            StringComparison.OrdinalIgnoreCase));
                    if (!isCe) continue;

                    string? imagePath = null;
                    try { imagePath = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Engine AKTIV laufend: {proc.ProcessName}",
                        Risk = RiskLevel.Critical,
                        Location = imagePath ?? proc.ProcessName,
                        FileName = procName,
                        Reason = $"Cheat Engine laeuft AKTUELL als Prozess '{proc.ProcessName}' (PID {proc.Id}). " +
                                 "Ein aktiver CE-Prozess waehrend des Scans ist ein kritisches Indiz fuer " +
                                 "aktives Cheating. CE benoetigt keine Installation und kann direkt aus " +
                                 "beliebigen Verzeichnissen gestartet werden.",
                        Detail = $"PID: {proc.Id} · Pfad: {imagePath ?? "unbekannt"}"
                    });
                }
                catch { }
            }

            // Also check for CE process names in a broader list including renamed variants
            var ceSuspectProcessKeywords = new[]
            {
                "cheatengine",
                "cheat engine",
                "ceserver",
                "ce_server",
            };

            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    var pnLower = proc.ProcessName.ToLowerInvariant();
                    bool isSuspect = ceSuspectProcessKeywords.Any(k =>
                        pnLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (!isSuspect) continue;

                    // Avoid double-reporting exact matches already caught above
                    bool alreadyExact = CeExecutableNames.Any(n =>
                        (proc.ProcessName + ".exe").Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (alreadyExact) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiger Prozess mit CE-Namensschema: {proc.ProcessName}",
                        Risk = RiskLevel.High,
                        Location = proc.ProcessName,
                        FileName = proc.ProcessName + ".exe",
                        Reason = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) enthaelt Cheat Engine " +
                                 "spezifische Schluesselbegriffe im Namen. Koennte ein umbenannter oder " +
                                 "modifizierter CE-Fork sein.",
                        Detail = $"PID: {proc.Id}"
                    });
                }
                catch { }
            }
        }, ct);

    private Task CheckCeUserAssist(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            try
            {
                using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                using var ua = hkcu.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                    writable: false);
                if (ua is null) return;

                foreach (var guid in ua.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var count = ua.OpenSubKey($@"{guid}\Count", writable: false);
                        if (count is null) continue;
                        ctx.IncrementRegistryKeys();

                        foreach (var valueName in count.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            var decoded = Rot13Decode(valueName);
                            if (string.IsNullOrWhiteSpace(decoded)) continue;

                            var decodedLower = decoded.ToLowerInvariant();
                            bool isCeExe = CeExecutableNames.Any(n =>
                                decodedLower.Contains(n.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));
                            bool hasCePath = decodedLower.Contains("cheat engine", StringComparison.OrdinalIgnoreCase)
                                         || decodedLower.Contains("cheatengine", StringComparison.OrdinalIgnoreCase);

                            if (!isCeExe && !hasCePath) continue;

                            // Extract last run time from UserAssist value data
                            string? lastRun = null;
                            try
                            {
                                if (count.GetValue(valueName) is byte[] b && b.Length >= 72)
                                {
                                    var ft = BitConverter.ToInt64(b, 60);
                                    if (ft > 0) lastRun = DateTime.FromFileTime(ft).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
                                }
                            }
                            catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Engine in UserAssist (Ausfuehrungsverlauf)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Der Windows UserAssist-Schluessel zeigt, dass Cheat Engine " +
                                         $"ausgefuehrt wurde. Der dekodierte Eintrag lautet: '{decoded}'. " +
                                         "UserAssist protokolliert GUI-Programm-Starts und bleibt auch " +
                                         "nach Loeschung des Programms erhalten.",
                                Detail = lastRun is not null
                                    ? $"Zuletzt ausgefuehrt: {lastRun}"
                                    : $"Eintrag: {decoded}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckCeMuiCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // MUICache records recently used application display names and persists after deletion
            var muiCachePaths = new[]
            {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"Software\Microsoft\Windows\ShellNoRoam\MUICache",
            };

            try
            {
                using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                foreach (var muiPath in muiCachePaths)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var key = hkcu.OpenSubKey(muiPath, writable: false);
                        if (key is null) continue;
                        ctx.IncrementRegistryKeys();

                        foreach (var valueName in key.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            var vnLower = valueName.ToLowerInvariant();
                            bool isCe = CeMuiCachePaths.Any(n =>
                                vnLower.Contains(n.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase))
                                || vnLower.Contains("cheat engine", StringComparison.OrdinalIgnoreCase)
                                || vnLower.Contains("cheatengine", StringComparison.OrdinalIgnoreCase);
                            if (!isCe) continue;

                            var displayName = key.GetValue(valueName)?.ToString() ?? string.Empty;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Engine in MUICache (Ausfuehrungsverlauf)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{muiPath}",
                                FileName = Path.GetFileName(valueName.Split('.')[0]),
                                Reason = $"Der Windows MUICache-Schluessel zeigt, dass Cheat Engine " +
                                         $"ausgefuehrt wurde. MUICache speichert Anzeigenamen von " +
                                         "ausgefuehrten GUI-Programmen und bleibt nach dem Loeschen " +
                                         "der Dateien erhalten.",
                                Detail = $"Pfad: {valueName} · Anzeigename: {displayName}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckCeAutoAttachScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // Look for CE auto-attach scripts targeting online games
            var scriptExtensions = new[] { "*.lua", "*.txt", "*.ini", "*.cfg" };
            var searchDirs = new[]
            {
                Path.Combine(RoamingAppData, "Cheat Engine"),
                Path.Combine(LocalAppData, "Cheat Engine"),
                Path.Combine(Documents, "Cheat Engine"),
                Path.Combine(Documents, "CheatEngine"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var ext in scriptExtensions)
                {
                    string[] files;
                    try { files = Directory.GetFiles(dir, ext, SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var file in files)
                    {
                        if (ct.IsCancellationRequested) return;

                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        var matchedTargets = CeAutoAttachTargets
                            .Where(t => content.Contains(t, StringComparison.OrdinalIgnoreCase))
                            .ToList();
                        if (matchedTargets.Count == 0) continue;

                        bool hasAttachKeyword = content.Contains("autoattach", StringComparison.OrdinalIgnoreCase)
                                             || content.Contains("auto_attach", StringComparison.OrdinalIgnoreCase)
                                             || content.Contains("attachtoprocess", StringComparison.OrdinalIgnoreCase)
                                             || content.Contains("openprocess", StringComparison.OrdinalIgnoreCase);
                        if (!hasAttachKeyword) continue;

                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"CE Auto-Attach Script fuer Online-Spiel: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Ein Cheat Engine Auto-Attach-Script wurde unter '{file}' gefunden, " +
                                     $"das sich auf folgende Online-Spiele bezieht: {string.Join(", ", matchedTargets)}. " +
                                     "Auto-Attach-Scripts verbinden CE automatisch mit dem Spielprozess " +
                                     "beim Start und fuhren danach Cheat-Operationen aus.",
                            Detail = $"Referenzierte Spiele: {string.Join(", ", matchedTargets)}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckCeMonoScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // CE has Mono/.NET script support - look for associated script files
            var monoExtensions = new[] { "*.csx", "*.cs", "*.py" };
            var ceMonoKeywords = new[]
            {
                "CheatEngine",
                "CEFunctions",
                "mono_runtime",
                "mono_thread",
                "getmonoclasses",
                "getmonomethods",
                "mono_field",
                "inject_mono",
                "unitymono",
            };

            var searchDirs = new[]
            {
                Path.Combine(RoamingAppData, "Cheat Engine"),
                Path.Combine(LocalAppData, "Cheat Engine"),
                Path.Combine(Documents, "Cheat Engine"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var ext in monoExtensions)
                {
                    string[] files;
                    try { files = Directory.GetFiles(dir, ext, SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var file in files)
                    {
                        if (ct.IsCancellationRequested) return;

                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        var matched = ceMonoKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();
                        if (matched.Count == 0) continue;

                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Mono/.NET Script: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Ein Cheat Engine Mono/.NET-Script wurde unter '{file}' gefunden. " +
                                     "CE unterstuetzt das Schreiben von Cheat-Skripten in C# und Python " +
                                     "ueber die Mono-Runtime-Integration, die besonders bei Unity-basierten " +
                                     "Spielen eingesetzt wird.",
                            Detail = $"Mono-Schluesselbegriffe: {string.Join(", ", matched)}"
                        });
                    }
                }
            }

            // Also check for CE extension DLL artifacts
            var ceExtensionDlls = new[]
            {
                "luaclient-i386.dll",
                "luaclient-x86_64.dll",
                "allochook-i386.dll",
                "allochook-x86_64.dll",
                "autorun.lua",
                "ce_mono.dll",
            };

            var dllSearchDirs = new[]
            {
                Path.Combine(ProgramFiles, "Cheat Engine 7.5"),
                Path.Combine(ProgramFiles, "Cheat Engine 7.4"),
                Path.Combine(ProgramFiles, "Cheat Engine"),
                Path.Combine(ProgramFilesX86, "Cheat Engine 7.5"),
                Path.Combine(ProgramFilesX86, "Cheat Engine"),
                Path.Combine(LocalAppData, "Programs", "Cheat Engine"),
                Downloads,
                Desktop,
            };

            foreach (var dir in dllSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var extDll in ceExtensionDlls)
                    {
                        var dllPath = Path.Combine(dir, extDll);
                        if (!File.Exists(dllPath)) continue;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Extension/Lua-DLL: {extDll}",
                            Risk = RiskLevel.High,
                            Location = dllPath,
                            FileName = extDll,
                            Reason = $"Die Cheat Engine Extension-DLL '{extDll}' wurde unter '{dllPath}' gefunden. " +
                                     "Diese DLLs stellen Lua-Scripting, Allokations-Hooks und andere " +
                                     "erweiterte CE-Funktionen bereit.",
                            Detail = $"Groesse: {new FileInfo(dllPath).Length} Bytes"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckCeEventLog(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Check Windows Event Log for CE-related service installs (Event 7045)
            // and application error events that reference CE
            try
            {
                var query = new EventLogQuery("System", PathType.LogName,
                    "*[System[(EventID=7045 or EventID=7034 or EventID=7000)]]")
                { ReverseDirection = true };

                using var reader = new EventLogReader(query);
                int n = 0;
                EventRecord? rec;
                while (n++ < 300 && (rec = reader.ReadEvent()) is not null)
                {
                    if (ct.IsCancellationRequested) { rec.Dispose(); return; }
                    try
                    {
                        var props = rec.Properties;
                        string? svcName = props.Count > 0 ? props[0].Value?.ToString() : null;
                        string? imagePath = props.Count > 1 ? props[1].Value?.ToString() : null;

                        bool isCe = (svcName != null && (
                                         svcName.Contains("dbk", StringComparison.OrdinalIgnoreCase)
                                         || svcName.Contains("cheatengine", StringComparison.OrdinalIgnoreCase)
                                         || svcName.Contains("cheat engine", StringComparison.OrdinalIgnoreCase)))
                                 || (imagePath != null && (
                                         imagePath.Contains("dbk", StringComparison.OrdinalIgnoreCase)
                                         || imagePath.Contains("cheatengine", StringComparison.OrdinalIgnoreCase)));
                        if (!isCe) continue;

                        var when = rec.TimeCreated?.ToLocalTime();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Dienst im Event-Log (ID {rec.Id})",
                            Risk = RiskLevel.High,
                            Location = "Windows Event Log: System",
                            Reason = $"Das Windows System-Event-Log zeigt einen CE-bezogenen Dienst-Eintrag. " +
                                     $"Event-ID {rec.Id}: Dienst '{svcName}'. " +
                                     "Event-Log-Eintraege bleiben auch nach der Deinstallation erhalten.",
                            Detail = $"Zeit: {when?.ToString("yyyy-MM-dd HH:mm") ?? "?"} · " +
                                     $"ImagePath: {imagePath ?? "?"} · Dienst: {svcName ?? "?"}"
                        });
                    }
                    catch { }
                    finally { rec.Dispose(); }
                }
            }
            catch { }

            // Check Application event log for CE crashes or errors
            try
            {
                var appQuery = new EventLogQuery("Application", PathType.LogName,
                    "*[System[(Level=2)]]") { ReverseDirection = true };
                using var appReader = new EventLogReader(appQuery);
                int n = 0;
                EventRecord? rec;
                while (n++ < 500 && (rec = appReader.ReadEvent()) is not null)
                {
                    if (ct.IsCancellationRequested) { rec.Dispose(); return; }
                    try
                    {
                        var source = rec.ProviderName ?? string.Empty;
                        var msg = rec.FormatDescription() ?? string.Empty;
                        bool isCe = source.Contains("cheatengine", StringComparison.OrdinalIgnoreCase)
                                 || msg.Contains("cheatengine", StringComparison.OrdinalIgnoreCase)
                                 || msg.Contains("cheat engine", StringComparison.OrdinalIgnoreCase)
                                 || msg.Contains("dbk64", StringComparison.OrdinalIgnoreCase)
                                 || msg.Contains("dbk32", StringComparison.OrdinalIgnoreCase);
                        if (!isCe) continue;

                        var when = rec.TimeCreated?.ToLocalTime();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Engine Fehler-Eintrag im Application-Log",
                            Risk = RiskLevel.Medium,
                            Location = "Windows Event Log: Application",
                            Reason = $"Das Windows Application-Event-Log enthaelt einen Fehler-Eintrag " +
                                     $"mit Cheat Engine Bezug (Quelle: '{source}'). Fehler-Logs zeigen " +
                                     "Abstuerze oder Fehler bei der CE-Nutzung an.",
                            Detail = $"Zeit: {when?.ToString("yyyy-MM-dd HH:mm") ?? "?"} · " +
                                     $"Quelle: {source}"
                        });
                    }
                    catch { }
                    finally { rec.Dispose(); }
                }
            }
            catch { }
        }, ct);

    private Task CheckCeUninstallRecords(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Check Add/Remove Programs (Uninstall registry) for CE entries
            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            var ceUninstallKeywords = new[]
            {
                "cheat engine",
                "cheatengine",
                "ce ",
            };

            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                foreach (var uninstPath in uninstallPaths)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var uninstRoot = hklm.OpenSubKey(uninstPath, writable: false);
                        if (uninstRoot is null) continue;

                        foreach (var keyName in uninstRoot.GetSubKeyNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            try
                            {
                                using var entry = uninstRoot.OpenSubKey(keyName, writable: false);
                                if (entry is null) continue;
                                ctx.IncrementRegistryKeys();

                                var displayName = entry.GetValue("DisplayName")?.ToString() ?? string.Empty;
                                var publisher = entry.GetValue("Publisher")?.ToString() ?? string.Empty;
                                var installDate = entry.GetValue("InstallDate")?.ToString() ?? string.Empty;
                                var installLocation = entry.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                                var uninstallStr = entry.GetValue("UninstallString")?.ToString() ?? string.Empty;

                                bool isCe = ceUninstallKeywords.Any(k =>
                                    displayName.Contains(k, StringComparison.OrdinalIgnoreCase)
                                    || keyName.Contains(k, StringComparison.OrdinalIgnoreCase));
                                if (!isCe) continue;

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Cheat Engine Installations-Eintrag: {displayName}",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKLM\{uninstPath}\{keyName}",
                                    Reason = $"Ein Cheat Engine Eintrag in der Deinstallations-Registry " +
                                             $"wurde gefunden: '{displayName}'. Dies zeigt, dass Cheat Engine " +
                                             "offiziell installiert wurde oder war. Uninstall-Eintraege " +
                                             "bleiben manchmal auch nach der Deinstallation erhalten.",
                                    Detail = $"Publisher: {publisher} · Installiert: {installDate} · " +
                                             $"Pfad: {installLocation}"
                                });
                            }
                            catch (UnauthorizedAccessException) { }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }

            // Also check HKCU uninstall keys (per-user installs)
            try
            {
                using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                using var uninstRoot = hkcu.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", writable: false);
                if (uninstRoot is null) return;

                foreach (var keyName in uninstRoot.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var entry = uninstRoot.OpenSubKey(keyName, writable: false);
                        if (entry is null) continue;
                        ctx.IncrementRegistryKeys();

                        var displayName = entry.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        bool isCe = ceUninstallKeywords.Any(k =>
                            displayName.Contains(k, StringComparison.OrdinalIgnoreCase)
                            || keyName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (!isCe) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Benutzer-Installations-Eintrag: {displayName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{keyName}",
                            Reason = $"Ein Cheat Engine Benutzer-Installations-Eintrag '{displayName}' " +
                                     "wurde in der HKCU-Uninstall-Registry gefunden. Per-Benutzer-Installs " +
                                     "benoetigen keine Adminrechte und hinterlassen Spuren im HKCU-Hive.",
                            Detail = $"Key: {keyName}"
                        });
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckCeProgramDataArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // Check ProgramData for CE artifacts (shared machine-wide data)
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var ceProgramDataDirs = new[]
            {
                Path.Combine(programData, "Cheat Engine"),
                Path.Combine(programData, "CheatEngine"),
            };

            foreach (var dir in ceProgramDataDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat Engine ProgramData-Verzeichnis gefunden",
                    Risk = RiskLevel.High,
                    Location = dir,
                    Reason = $"Ein Cheat Engine Datenverzeichnis wurde unter '{dir}' (ProgramData) gefunden. " +
                             "Maschinenweite CE-Daten in ProgramData deuten auf eine systemweite Installation hin.",
                    Detail = $"Verzeichnis existiert: {dir}"
                });

                // Scan for CT files and configs in ProgramData CE folder
                try
                {
                    foreach (var ctFile in Directory.GetFiles(dir, "*.ct", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine Table in ProgramData: {Path.GetFileName(ctFile)}",
                            Risk = RiskLevel.High,
                            Location = ctFile,
                            FileName = Path.GetFileName(ctFile),
                            Reason = $"Eine Cheat Engine CT-Tabelle wurde in ProgramData unter '{ctFile}' gefunden. " +
                                     "CT-Dateien in maschinenweiten Verzeichnissen koennen von allen Benutzern " +
                                     "des Systems verwendet werden.",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Check for CE crash dumps referencing games
            var crashDumpDirs = new[]
            {
                Path.Combine(LocalAppData, "CrashDumps"),
                Path.Combine(programData, "Microsoft", "Windows", "WER", "ReportQueue"),
                Path.Combine(programData, "Microsoft", "Windows", "WER", "ReportArchive"),
            };

            foreach (var dumpDir in crashDumpDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dumpDir)) continue;

                string[] dmpFiles;
                try { dmpFiles = Directory.GetFiles(dumpDir, "cheatengine*.dmp", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var dmp in dmpFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Engine Crash-Dump: {Path.GetFileName(dmp)}",
                        Risk = RiskLevel.Medium,
                        Location = dmp,
                        FileName = Path.GetFileName(dmp),
                        Reason = $"Ein Cheat Engine Crash-Dump wurde unter '{dmp}' gefunden. " +
                                 "Crash-Dumps entstehen, wenn CE abstauerzt und bleiben auch " +
                                 "nach der Deinstallation erhalten.",
                        Detail = $"Groesse: {new FileInfo(dmp).Length} Bytes · Erstellt: {File.GetCreationTime(dmp):yyyy-MM-dd HH:mm}"
                    });
                }
            }

            // Check for CE recent files list in AppData
            var ceRecentFiles = new[]
            {
                Path.Combine(RoamingAppData, "Cheat Engine", "recentfiles.ini"),
                Path.Combine(RoamingAppData, "Cheat Engine", "recent.ini"),
                Path.Combine(LocalAppData, "Cheat Engine", "recentfiles.ini"),
            };

            foreach (var recentFile in ceRecentFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (!File.Exists(recentFile)) continue;

                ctx.IncrementFiles();
                string content = string.Empty;
                try
                {
                    using var fs = new FileStream(recentFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat Engine Zuletzt-Verwendete-Dateien Liste",
                    Risk = RiskLevel.High,
                    Location = recentFile,
                    FileName = Path.GetFileName(recentFile),
                    Reason = $"Eine Cheat Engine 'Zuletzt verwendete Dateien'-Liste wurde unter " +
                             $"'{recentFile}' gefunden. Diese Datei zeigt, welche CT-Tabellen und " +
                             "Targets zuletzt in CE geladen wurden.",
                    Detail = content.Length > 0
                        ? $"Inhalt (Anfang): {content[..Math.Min(300, content.Length)]}"
                        : null
                });
            }

            // Check for CE config files and settings
            var ceConfigFiles = new[]
            {
                Path.Combine(RoamingAppData, "Cheat Engine", "settings.ini"),
                Path.Combine(RoamingAppData, "Cheat Engine", "cheatengine.ini"),
                Path.Combine(LocalAppData, "Cheat Engine", "settings.ini"),
                Path.Combine(RoamingAppData, "Cheat Engine", "autorun.lua"),
                Path.Combine(LocalAppData, "Cheat Engine", "autorun.lua"),
            };

            foreach (var cfgFile in ceConfigFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (!File.Exists(cfgFile)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat Engine Konfigurationsdatei: {Path.GetFileName(cfgFile)}",
                    Risk = RiskLevel.High,
                    Location = cfgFile,
                    FileName = Path.GetFileName(cfgFile),
                    Reason = $"Eine Cheat Engine Konfigurationsdatei wurde unter '{cfgFile}' gefunden. " +
                             "CE-Konfigurationsdateien speichern Einstellungen, Treiberpfade und " +
                             "Autostart-Lua-Scripts, die auf aktive CE-Nutzung hinweisen.",
                    Detail = $"Zuletzt geaendert: {File.GetLastWriteTime(cfgFile):yyyy-MM-dd HH:mm}"
                });
            }
        }, ct);

    private static string Rot13Decode(string s)
    {
        var a = s.ToCharArray();
        for (int i = 0; i < a.Length; i++)
        {
            char c = a[i];
            if (c is >= 'A' and <= 'Z') a[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c is >= 'a' and <= 'z') a[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(a);
    }
}
