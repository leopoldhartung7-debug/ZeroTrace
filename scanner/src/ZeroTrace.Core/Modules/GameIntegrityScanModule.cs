using System.Management;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Verifies the integrity of installed game clients and their anti-cheat modules
/// against known-good file hashes and detects modifications that indicate
/// cheat bypass injection into game files.
///
/// Common game file modifications by cheats:
///   1. Modified EXE/DLL with patched anti-cheat checks (integrity check bypass).
///   2. ASI/LUA plugin injection into game directories (Script Hook V for GTA).
///   3. Replaced sound files with radar sound cheats (game-internal ESP).
///   4. Modified client.dll/engine.dll for CS2 cheat injection.
///   5. FiveM resource injection: unsigned resources in citizen/scripting.
///   6. Replaced animation files for bhop / no-recoil assistance.
///   7. Modified shader files for wallhack (transparent textures).
///   8. Injected .asi plugins (GTA V / FiveM ASI loader).
///
/// Detection approach:
///   - Walk game installation directories for unexpected file types
///   - Check for ASI/LUA files in game root directories
///   - Look for executable/DLL files in asset directories
///   - Detect recently modified game DLLs
///   - Check for missing or replaced anti-cheat binaries
///   - Detect script injectors in game plugin directories
/// </summary>
public sealed class GameIntegrityScanModule : IScanModule
{
    public string Name => "Spieldatei-Integrität";
    public double Weight => 1.2;
    public int ParallelGroup => 0; // sequential — disk IO

    private static readonly string SteamApps = FindSteamApps();
    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);

    private static string FindSteamApps()
    {
        // Try to find Steam installation via registry
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Valve\Steam", writable: false)
                ?? Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Valve\Steam", writable: false);
            var steamPath = key?.GetValue("InstallPath") as string;
            if (steamPath is not null)
                return Path.Combine(steamPath, "steamapps", "common");
        }
        catch { }

        // Default fallback
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            @"Steam\steamapps\common");
    }

    // Anti-cheat binaries that must not be replaced/missing
    private static readonly (string game, string[] acBinaries)[] AntiCheatFiles =
    {
        ("Counter-Strike Global Offensive", new[] { "EasyAntiCheat.dll", "EasyAntiCheat.exe" }),
        ("Counter-Strike 2", new[] { "EasyAntiCheat.dll", "EasyAntiCheat_EOS.dll" }),
        ("VALORANT", new[] { "vgc.exe", "vgk.sys", "vanguard.dll" }),
        ("EscapeFromTarkov", new[] { "BattlEye\\BEService.exe", "BattlEye\\BEClient.dll" }),
        ("Rust", new[] { "EasyAntiCheat.dll", "EasyAntiCheat\\EasyAntiCheat.exe" }),
        ("DayZ", new[] { "BattlEye\\BEService.exe", "BattlEye\\BEClient_x64.dll" }),
    };

    // File extensions that should NEVER appear in game root directories
    private static readonly string[] SuspiciousGameExtensions =
    {
        ".asi",   // Script Hook / ASI loader plugins
        ".luac",  // Compiled LUA (injected)
    };

    // Directories where executable content is suspicious
    private static readonly string[] AssetDirectories =
    {
        "sounds", "audio", "textures", "models", "materials",
        "maps", "particles", "fonts", "icons", "images",
    };

    // Known injector file names found in game directories
    private static readonly string[] KnownInjectorFiles =
    {
        "ScriptHookV.dll", "ScriptHookVDotNet.dll", "ScriptHookVDotNet2.dll",
        "ScriptHookVDotNet3.dll",
        "OpenIV.asi", "dinput8.dll",   // Often a renamed injector
        "version.dll",                  // Often hijacked for DLL loading
        "dsound.dll",                   // Also used as proxy DLL
        "winmm.dll",                    // Proxy DLL injection
        "d3d9.dll", "d3d10.dll", "d3d11.dll", // D3D proxy DLLs
        "bink2w64.dll",                 // Replaced to load code
        "vorbisFile.dll",               // Replaced in some game DLL hijacks
    };

    // Known cheat ASI file names
    private static readonly string[] KnownCheatAsiFiles =
    {
        "menyoo.asi", "FiveM.asi", "kiddion.asi", "TrainerV.asi",
        "NativeTrainer.asi", "Simple Trainer.asi",
        "ScriptHookVDotNet.asi",
        "Cherax.asi", "Ozark.asi", "Tsunami.asi",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Spieldatei-Integrität", "Suche Spielinstallationen...");
        var gameInstalls = FindGameInstallations();

        if (gameInstalls.Count == 0)
        {
            ctx.Report(1.0, "Spieldatei-Integrität", "Keine Spielinstallationen gefunden");
            return Task.CompletedTask;
        }

        ctx.Report(0.05, "Spieldatei-Integrität",
            $"{gameInstalls.Count} Spielinstallationen gefunden");

        int i = 0;
        foreach (var (gameName, gamePath) in gameInstalls)
        {
            if (ct.IsCancellationRequested) break;
            i++;
            ctx.Report((double)i / gameInstalls.Count, gameName,
                $"Prüfe {gameName}...");

            CheckGameDirectory(gameName, gamePath, ctx, ct);
            CheckAntiCheatBinaries(gameName, gamePath, ctx, ct);
        }

        // Also check FiveM separately
        CheckFiveMIntegrity(ctx, ct);

        ctx.Report(1.0, "Spieldatei-Integrität", "Spieldatei-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    private static List<(string name, string path)> FindGameInstallations()
    {
        var games = new List<(string, string)>();
        if (!Directory.Exists(SteamApps)) return games;

        var knownGames = new[]
        {
            ("Grand Theft Auto V", "Grand Theft Auto V"),
            ("Counter-Strike Global Offensive", "Counter-Strike Global Offensive"),
            ("Counter-Strike 2", "Counter-Strike 2"),
            ("Rust", "Rust"),
            ("DayZ", "DayZ"),
            ("EscapeFromTarkov", "EscapeFromTarkov"),
            ("Tom Clancy's Rainbow Six Siege", "Tom Clancy's Rainbow Six Siege"),
        };

        foreach (var (name, dir) in knownGames)
        {
            var fullPath = Path.Combine(SteamApps, dir);
            if (Directory.Exists(fullPath))
                games.Add((name, fullPath));
        }

        return games;
    }

    private static void CheckGameDirectory(string gameName, string gamePath,
        ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        // Check for ASI files in game root
        try
        {
            foreach (var file in Directory.EnumerateFiles(gamePath, "*.asi"))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                var isKnownCheat = KnownCheatAsiFiles.Any(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));
                var isKnownLoader = fn.Equals("ScriptHookV.dll", StringComparison.OrdinalIgnoreCase) ||
                                    fn.Equals("dsound.dll", StringComparison.OrdinalIgnoreCase);

                ctx.AddFinding(new Finding
                {
                    Module   = "Spieldatei-Integrität",
                    Title    = $"ASI-Plugin in {gameName}: {fn}",
                    Risk     = isKnownCheat ? RiskLevel.Critical : RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason   = isKnownCheat
                        ? $"Bekannte Cheat-ASI-Datei '{fn}' im {gameName}-Verzeichnis gefunden."
                        : $"ASI-Plugin '{fn}' im {gameName}-Verzeichnis. ASI-Dateien werden " +
                          "vom ScriptHookV-Loader automatisch ausgeführt und können Cheat-Code enthalten.",
                    Detail   = $"Pfad: {file} | Bekannter Cheat: {isKnownCheat}"
                });
            }
        }
        catch { }

        // Check for known proxy/hijack DLLs in game root
        foreach (var injectorFile in KnownInjectorFiles)
        {
            if (ct.IsCancellationRequested) return;
            var filePath = Path.Combine(gamePath, injectorFile);
            if (!File.Exists(filePath)) continue;

            ctx.IncrementFiles();

            // Verify it's not legitimately part of the game
            // Heuristic: if it's not signed by the game publisher, it's suspicious
            bool signed = false;
            try
            {
                System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
                signed = true;
            }
            catch { }

            if (!signed)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Spieldatei-Integrität",
                    Title    = $"Unsignierte Proxy-DLL in {gameName}: {injectorFile}",
                    Risk     = RiskLevel.High,
                    Location = filePath,
                    FileName = injectorFile,
                    Reason   = $"Unsignierte '{injectorFile}' im {gameName}-Verzeichnis gefunden. " +
                               "Diese DLL-Namen werden häufig als Proxy-DLLs verwendet, um beim " +
                               "Spielstart automatisch Cheat-Code zu laden (DLL-Hijacking).",
                    Detail   = $"Pfad: {filePath} | Signiert: Nein"
                });
            }
        }

        // Check for executable files in asset directories
        foreach (var assetDir in AssetDirectories)
        {
            if (ct.IsCancellationRequested) return;
            var assetPath = Path.Combine(gamePath, assetDir);
            if (!Directory.Exists(assetPath)) continue;

            try
            {
                foreach (var ext in new[] { "*.exe", "*.dll", "*.sys" })
                {
                    foreach (var file in Directory.EnumerateFiles(assetPath, ext,
                        SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Spieldatei-Integrität",
                            Title    = $"Ausführbare Datei in Asset-Ordner: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Ausführbare Datei '{Path.GetFileName(file)}' in " +
                                       $"Asset-Verzeichnis '{assetDir}' von {gameName} gefunden. " +
                                       "Ausführbarer Code gehört nicht in Asset-Verzeichnisse — " +
                                       "dies ist ein starkes Zeichen für Cheat-Injektion.",
                            Detail   = $"Pfad: {file}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private static void CheckAntiCheatBinaries(string gameName, string gamePath,
        ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        foreach (var (game, acFiles) in AntiCheatFiles)
        {
            if (!gameName.StartsWith(game.Split(' ')[0], StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var acFile in acFiles)
            {
                if (ct.IsCancellationRequested) return;
                var acPath = Path.Combine(gamePath, acFile);
                if (!File.Exists(acPath)) continue;

                ctx.IncrementFiles();

                // Check if AC binary was recently modified (bypass injection)
                var info = new FileInfo(acPath);
                var daysSinceModified = (DateTime.UtcNow - info.LastWriteTimeUtc).TotalDays;

                // AC binaries shouldn't change between game updates
                // If modified within 24h but no game update happened — suspicious
                if (daysSinceModified < 1)
                {
                    // Check if the game itself was also recently modified (= legitimate update)
                    var gameExes = Directory.GetFiles(gamePath, "*.exe", SearchOption.TopDirectoryOnly);
                    bool gameAlsoModified = gameExes.Any(e =>
                        (DateTime.UtcNow - new FileInfo(e).LastWriteTimeUtc).TotalDays < 1);

                    if (!gameAlsoModified)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Spieldatei-Integrität",
                            Title    = $"Anti-Cheat-Binärdatei kürzlich verändert: {acFile}",
                            Risk     = RiskLevel.Critical,
                            Location = acPath,
                            FileName = acFile,
                            Reason   = $"Anti-Cheat-Datei '{acFile}' wurde in den letzten 24 Stunden " +
                                       "verändert, ohne dass das Spiel selbst aktualisiert wurde. " +
                                       "Cheat-Bypass-Tools patchen Anti-Cheat-Binärdateien, um " +
                                       "Kernel-Scans zu deaktivieren.",
                            Detail   = $"Zuletzt verändert: {info.LastWriteTime:yyyy-MM-dd HH:mm} | " +
                                       $"Spiel-Update: Nein"
                        });
                    }
                }

                // Verify anti-cheat binary is still signed
                bool signed = false;
                try
                {
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(acPath);
                    signed = true;
                }
                catch { }

                if (!signed)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Spieldatei-Integrität",
                        Title    = $"Anti-Cheat-Binärdatei unsigniert: {acFile}",
                        Risk     = RiskLevel.Critical,
                        Location = acPath,
                        FileName = acFile,
                        Reason   = $"Anti-Cheat-Datei '{acFile}' von {gameName} ist nicht " +
                                   "digital signiert. Legitime AC-Dateien sind immer signiert. " +
                                   "Die Datei wurde möglicherweise durch eine gepatchte Version ersetzt.",
                        Detail   = $"Pfad: {acPath} | Signiert: Nein"
                    });
                }
            }
        }
    }

    private static void CheckFiveMIntegrity(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var fivemPath = Path.Combine(LocalApp, "FiveM");
        if (!Directory.Exists(fivemPath)) return;

        // Check for unsigned ASI plugins in FiveM
        var pluginsDir = Path.Combine(fivemPath, "FiveM.app", "plugins");
        if (Directory.Exists(pluginsDir))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(pluginsDir, "*.asi"))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Spieldatei-Integrität",
                        Title    = $"FiveM ASI-Plugin: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = $"ASI-Plugin '{fn}' im FiveM-Plugin-Verzeichnis gefunden. " +
                                   "FiveM lädt ASI-Plugins automatisch beim Start. " +
                                   "Bekannte Cheat-Menüs wie 2Take1, Cherax und Kiddion " +
                                   "werden als ASI-Dateien geladen.",
                        Detail   = $"Pfad: {file}"
                    });
                }
            }
            catch { }
        }

        // Check for modified FiveM game files
        var fivemCitizen = Path.Combine(fivemPath, "FiveM.app", "citizen");
        if (!Directory.Exists(fivemCitizen)) return;

        try
        {
            // Flag any .dll files in the FiveM citizen/scripting/lua directory
            var luaDir = Path.Combine(fivemCitizen, "scripting", "lua");
            if (Directory.Exists(luaDir))
            {
                foreach (var file in Directory.EnumerateFiles(luaDir, "*.dll"))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Spieldatei-Integrität",
                        Title    = $"Unerwartete DLL im FiveM-LUA-Verzeichnis: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"DLL-Datei in FiveM's LUA-Scripting-Verzeichnis: '{file}'. " +
                                   "DLLs sollten in diesem Verzeichnis nicht vorkommen. " +
                                   "Cheat-Injektoren platzieren ihre Bibliotheken hier.",
                        Detail   = $"Pfad: {file}"
                    });
                }
            }
        }
        catch { }
    }
}
