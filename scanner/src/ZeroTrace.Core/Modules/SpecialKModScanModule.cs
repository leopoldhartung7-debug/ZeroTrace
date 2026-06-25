using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Special K ("SK") game modification framework artifacts.
///
/// Special K is a DirectX/OpenGL/Vulkan wrapper that sits between the game and the
/// graphics API. While primarily marketed as a performance/compatibility tool, it:
///   - Injects into every game's rendering pipeline via d3d9.dll / dxgi.dll / dinput8.dll
///   - Provides a scripting interface (Lua scripts) that can implement ESP/wallhack
///   - Has been documented as a vector for cheat injection because it bypasses signature
///     checks that target raw injectors
///   - Enables texture replacement (replacing solid walls with transparent textures =
///     wallhack effect without traditional memory-read ESP)
///   - Its "Global Injector" mode auto-injects into ALL games at launch
///
/// Ocean and detect.ac flag Special K because:
///   - The combination of Special K + competitive game = injection opportunity
///   - SK's Lua scripting can implement game-object reading without raw memory access
///   - SK profiles with suspicious texture replacements for competitive games
///
/// ReShade is similarly flagged — its depth buffer access enables distance-based ESP.
///
/// Detection:
///   - %PROGRAMDATA%\SK_Res\Global\  — SK global injector data
///   - %LOCALAPPDATA%\...\SpecialK\  — per-user SK data
///   - SK registry keys
///   - dxgi.dll / d3d9.dll / dinput8.dll in GAME directories (SK injects via these)
///   - ReShade.ini in game directories
/// </summary>
public sealed class SpecialKModScanModule : IScanModule
{
    public string Name => "Special K / ReShade Game-Mod-Injection Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    // Competitive game directories where SK/ReShade DLLs should NOT exist
    private static readonly string[] CompetitiveGamePaths =
    {
        @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive",
        @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike 2",
        @"C:\Program Files\Riot Games\VALORANT",
        @"C:\Program Files\Riot Games\League of Legends",
        @"D:\Steam\steamapps\common\Counter-Strike 2",
        @"D:\Steam\steamapps\common\Counter-Strike Global Offensive",
        @"D:\Riot Games\VALORANT",
    };

    private static readonly string[] InjectableDllNames =
    {
        "dxgi.dll", "d3d9.dll", "d3d11.dll", "d3d12.dll",
        "dinput.dll", "dinput8.dll", "opengl32.dll",
        "winmm.dll", "version.dll",
    };

    // SK-specific file names
    private static readonly string[] SkFileNames =
    {
        "SpecialK32.dll", "SpecialK64.dll",
        "SKIFsvc32.exe", "SKIFsvc64.exe",
        "SKIF.exe",
        "sk_inject.exe",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanSkInstallation(ctx, ct);
        ScanSkRegistry(ctx, ct);
        ScanCompetitiveGameDirs(ctx, ct);
        ScanReShadeInGames(ctx, ct);
    }

    private void ScanSkInstallation(ScanContext ctx, CancellationToken ct)
    {
        string progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string local    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string profile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var skDirs = new[]
        {
            System.IO.Path.Combine(progData, "SK_Res"),
            System.IO.Path.Combine(local,    "Programs", "SK"),
            System.IO.Path.Combine(profile,  "AppData", "Roaming", "SpecialK"),
        };

        foreach (string dir in skDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Special K Installationsverzeichnis gefunden: {dir}",
                Risk     = RiskLevel.Medium,
                Location = dir,
                FileName = System.IO.Path.GetFileName(dir),
                Reason   = "Special K (SK) Framework-Verzeichnis gefunden. SK ist ein DirectX-Wrapper " +
                           "der in alle Spiele injiziert und für Cheat-Injection (ESP/Wallhack via " +
                           "Lua-Scripting, Textur-Ersatz) missbraucht werden kann. Besonders in " +
                           "Kombination mit kompetitiven Spielen ist dies ein starkes Signal.",
                Detail   = $"Verzeichnis: {dir}"
            });
        }

        // Check for SK executables
        foreach (string skFile in SkFileNames)
        {
            ct.ThrowIfCancellationRequested();
            // Check running processes
            var processes = ctx.GetProcessSnapshot();
            foreach (var proc in processes)
            {
                try
                {
                    if (proc.ProcessName.Equals(
                        System.IO.Path.GetFileNameWithoutExtension(skFile),
                        StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementProcesses();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Special K-Prozess aktiv: {proc.ProcessName} (PID {proc.Id})",
                            Risk     = RiskLevel.High,
                            Location = $"Prozess: {proc.ProcessName} (PID {proc.Id})",
                            FileName = proc.ProcessName + ".exe",
                            Reason   = $"Special K-Prozess '{proc.ProcessName}' läuft aktiv. SK injiziert " +
                                       "in alle gestarteten Spiele. Ocean und detect.ac flaggen aktive " +
                                       "SK-Prozesse als direktes Injection-Indiz.",
                            Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id}"
                        });
                        break;
                    }
                }
                catch { }
            }
        }
    }

    private void ScanSkRegistry(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            // SK registers itself in various places
            string[] skRegPaths =
            {
                @"SOFTWARE\Kaldaien\Special K",
                @"SOFTWARE\WOW6432Node\Kaldaien\Special K",
                @"SOFTWARE\Special K",
            };

            foreach (string path in skRegPaths)
            {
                ct.ThrowIfCancellationRequested();
                using var key = Registry.LocalMachine.OpenSubKey(path, false)
                             ?? Registry.CurrentUser.OpenSubKey(path, false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Special K Registry-Eintrag gefunden",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKLM\{path}",
                    FileName = "Special K",
                    Reason   = "Special K ist im Registry registriert. Dies bestätigt eine SK-Installation " +
                               "auf diesem System.",
                    Detail   = $"Registry: {path}"
                });
                break;
            }
        }
        catch { }
    }

    private void ScanCompetitiveGameDirs(ScanContext ctx, CancellationToken ct)
    {
        // Also find game dirs from Steam
        var allGameDirs = new List<string>(CompetitiveGamePaths);
        FindSteamGameDirs(allGameDirs, ct);

        foreach (string gameDir in allGameDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(gameDir)) continue;

            try
            {
                foreach (string dll in InjectableDllNames)
                {
                    string dllPath = System.IO.Path.Combine(gameDir, dll);
                    if (!System.IO.File.Exists(dllPath)) continue;

                    ctx.IncrementFiles();
                    var info = new System.IO.FileInfo(dllPath);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Injection-DLL im Spielverzeichnis: {dll} in {System.IO.Path.GetFileName(gameDir)}",
                        Risk     = RiskLevel.Critical,
                        Location = dllPath,
                        FileName = dll,
                        Reason   = $"DLL '{dll}' im Spielverzeichnis '{System.IO.Path.GetFileName(gameDir)}' " +
                                   "gefunden. Wenn dxgi.dll/d3d9.dll/dinput8.dll im Spielverzeichnis liegt " +
                                   "und nicht von Microsoft signiert ist, wird sie statt der System-DLL " +
                                   "geladen — klassische DLL-Hijacking-Injection für Cheats, Special K " +
                                   "und ReShade. Ocean und detect.ac flaggen dies als Critical.",
                        Detail   = $"DLL: {dllPath} | Größe: {info.Length / 1024}KB | " +
                                   $"Geändert: {info.LastWriteTime:yyyy-MM-dd HH:mm}"
                    });
                }
            }
            catch { }
        }
    }

    private void FindSteamGameDirs(List<string> dirs, CancellationToken ct)
    {
        // Find competitive games in all Steam library paths
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string steamRoot = System.IO.Path.Combine(progFiles86, "Steam", "steamapps", "common");

        if (!System.IO.Directory.Exists(steamRoot)) return;

        string[] competitiveGames =
        {
            "Counter-Strike 2", "Counter-Strike Global Offensive",
            "VALORANT", "Apex Legends", "Fortnite",
            "Rainbow Six Siege", "Rust", "DayZ",
            "EscapeFromTarkov", "Escape From Tarkov",
            "PUBG", "Battlebit Remastered",
        };

        try
        {
            foreach (string gameDir in System.IO.Directory.EnumerateDirectories(steamRoot))
            {
                ct.ThrowIfCancellationRequested();
                string name = System.IO.Path.GetFileName(gameDir);
                if (competitiveGames.Any(g => name.Contains(g, StringComparison.OrdinalIgnoreCase)))
                    dirs.Add(gameDir);
            }
        }
        catch { }
    }

    private void ScanReShadeInGames(ScanContext ctx, CancellationToken ct)
    {
        // ReShade leaves ReShade.ini and reshade-shaders dir in game folders
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string steamRoot = System.IO.Path.Combine(progFiles86, "Steam", "steamapps", "common");

        if (!System.IO.Directory.Exists(steamRoot)) return;

        try
        {
            foreach (string gameDir in System.IO.Directory.EnumerateDirectories(steamRoot))
            {
                ct.ThrowIfCancellationRequested();
                string reshadIni = System.IO.Path.Combine(gameDir, "ReShade.ini");
                string reshadeDir = System.IO.Path.Combine(gameDir, "reshade-shaders");

                if (!System.IO.File.Exists(reshadIni) && !System.IO.Directory.Exists(reshadeDir))
                    continue;

                string gameName = System.IO.Path.GetFileName(gameDir);

                // Check if this is a competitive game
                string[] competitiveKeywords = { "counter-strike", "valorant", "apex", "fortnite",
                    "siege", "rust", "tarkov", "pubg", "battlebit", "dayz" };
                bool isCompetitive = competitiveKeywords.Any(kw =>
                    gameName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"ReShade in {gameName} Verzeichnis{(isCompetitive ? " [Kompetitives Spiel!]" : "")}",
                    Risk     = isCompetitive ? RiskLevel.High : RiskLevel.Medium,
                    Location = System.IO.File.Exists(reshadIni) ? reshadIni : reshadeDir,
                    FileName = gameName,
                    Reason   = $"ReShade im Spielverzeichnis '{gameName}' gefunden. ReShade hat Zugriff " +
                               "auf den Tiefen-Buffer der Grafikkarte, der wallhack-ähnliche Sichtbarkeit " +
                               "durch Wände ermöglicht (Depth Buffer ESP). In kompetitiven Spielen " +
                               "ist ReShade häufig verboten oder ein Cheat-Indiz.",
                    Detail   = $"Spielverzeichnis: {gameDir} | ReShade.ini: {System.IO.File.Exists(reshadIni)} | " +
                               $"reshade-shaders: {System.IO.Directory.Exists(reshadeDir)} | " +
                               $"Kompetitiv: {isCompetitive}"
                });
            }
        }
        catch { }
    }
}
