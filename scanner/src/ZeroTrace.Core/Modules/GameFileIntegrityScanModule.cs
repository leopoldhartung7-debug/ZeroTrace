using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans competitive game installation directories for modified/replaced files.
///
/// Cheats sometimes modify game files directly rather than injecting:
///   - Texture replacement (transparent wall textures = wallhack)
///   - Model replacement (making enemies brighter/larger)
///   - Audio replacement (footstep enhancement)
///   - Config file modification (enabling developer console, removing limits)
///   - DLL replacement (dinput8.dll, dxgi.dll = injection shim)
///
/// Additional checks:
///   - Presence of unexpected DLLs in game directories
///   - Game config files with cheat-enabling settings
///   - Symbolic links in game directories (used to redirect DLL loads)
///
/// Ocean and detect.ac scan game directories because:
///   - Modified game files are a reliable signal (games verify file integrity,
///     but only at startup; mods applied after verification window pass)
///   - Unexpected DLLs in game dirs = DLL hijacking
///   - Cheat config strings in game config files
/// </summary>
public sealed class GameFileIntegrityScanModule : IScanModule
{
    public string Name => "Spielverzeichnis Integrität und Cheat-Datei Scan";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    // Extensions not normally found in game install directories
    private static readonly string[] SuspiciousGameFileExtensions =
    {
        ".asi",     // ASI loader (popular injection shim for GTA series)
        ".xex",     // Xbox game format — not on PC games
    };

    // File names that are suspicious in game directories
    private static readonly string[] SuspiciousFileNames =
    {
        // ASI loaders (used for GTA cheats)
        "dinput8.dll", "dsound.dll", "winmm.dll", "version.dll",
        "binkw32.dll", "binkw64.dll",
        // Cheat DLL names (documented)
        "cheat.dll", "hack.dll", "aimbot.dll", "esp.dll",
        "injector.dll", "loader.dll",
        // Specific known cheat DLLs
        "overlay.dll", "trainer.dll",
        // ScriptHook (GTA V)
        "ScriptHookV.dll", "ScriptHookVDotNet.dll",
        "ScriptHookVDotNet2.dll", "ScriptHookVDotNet3.dll",
        // ASI loader
        "asiloader.dll", "asi_loader.dll",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "sv_cheats", "mat_wireframe", "r_drawothermodels",
        "cl_sidespeed 30000", "sv_noclipspeed",
        "aimbot", "wallhack", "esp", "triggerbot",
        "norecoil", "no_recoil", "bhop",
        "spinbot", "rapidfire",
        "rage", "legit", "semi-rage",
        "fov_cs_debug", "cl_showfps 5",
        "bind", "cheat", "hack",
    };

    // Known competitive game directories to scan
    private static readonly string[] GameSubPaths =
    {
        // CS2
        @"Counter-Strike 2\game\csgo",
        @"Counter-Strike 2\game\bin",
        // CSGO
        @"Counter-Strike Global Offensive\csgo",
        @"Counter-Strike Global Offensive\bin",
        // Rust
        @"Rust",
        // GTA V
        @"Grand Theft Auto V",
        @"Grand Theft Auto V\scripts",
        // Red Dead Redemption 2
        @"Red Dead Redemption 2",
        // RDR2
        @"RDR2",
        // EFT
        @"Escape from Tarkov",
        @"EscapeFromTarkov",
        // Battlefield
        @"Battlefield 2042",
        @"Battlefield V",
        // DayZ
        @"DayZ",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string steamRoot = System.IO.Path.Combine(progFiles86, "Steam", "steamapps", "common");

        // Also check alternative Steam paths
        var steamRoots = new List<string> { steamRoot };
        foreach (char drive in "DEF")
        {
            string alt = $@"{drive}:\Steam\steamapps\common";
            if (System.IO.Directory.Exists(alt)) steamRoots.Add(alt);
            alt = $@"{drive}:\SteamLibrary\steamapps\common";
            if (System.IO.Directory.Exists(alt)) steamRoots.Add(alt);
        }

        foreach (string root in steamRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(root)) continue;

            foreach (string subPath in GameSubPaths)
            {
                ct.ThrowIfCancellationRequested();
                string gameDir = System.IO.Path.Combine(root, subPath);
                if (!System.IO.Directory.Exists(gameDir)) continue;

                ScanGameDirectory(ctx, gameDir, System.IO.Path.GetFileName(
                    System.IO.Path.GetDirectoryName(gameDir) ?? subPath), ct);
            }
        }

        // Also scan Riot Valorant directory
        string riotGames = @"C:\Riot Games\VALORANT\live";
        if (System.IO.Directory.Exists(riotGames))
            ScanGameDirectory(ctx, riotGames, "VALORANT", ct);
    }

    private void ScanGameDirectory(ScanContext ctx, string dir, string gameName, CancellationToken ct)
    {
        try
        {
            // Check for suspicious file names in the game dir (top level only for speed)
            foreach (string file in System.IO.Directory.EnumerateFiles(dir,
                         "*", System.IO.SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                string fileName = System.IO.Path.GetFileName(file);
                string fileNameLower = fileName.ToLowerInvariant();
                string ext = System.IO.Path.GetExtension(fileNameLower);

                ctx.IncrementFiles();

                // Check suspicious extensions
                if (SuspiciousGameFileExtensions.Contains(ext))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtige Datei-Erweiterung in {gameName}: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Datei '{fileName}' mit verdächtiger Erweiterung '{ext}' im " +
                                   $"Spielverzeichnis von '{gameName}'. ASI-Dateien sind Injection-" +
                                   "Shims für Cheats und Trainer. Ocean und detect.ac scannen " +
                                   "Spielverzeichnisse auf nicht-standard Dateitypen.",
                        Detail   = $"Datei: {file} | Erweiterung: {ext} | Spiel: {gameName}"
                    });
                    continue;
                }

                // Check suspicious file names
                foreach (string suspName in SuspiciousFileNames)
                {
                    if (!fileNameLower.Equals(suspName.ToLowerInvariant())) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtige DLL in {gameName}: {fileName}",
                        Risk     = fileNameLower.Contains("cheat") || fileNameLower.Contains("hack") ||
                                   fileNameLower.Contains("aimbot") || fileNameLower.Contains("esp")
                            ? RiskLevel.Critical : RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Datei '{fileName}' im Spielverzeichnis von '{gameName}'. " +
                                   "Diese Datei ist entweder ein bekannter Cheat-DLL-Name oder ein " +
                                   "DLL-Hijacking-Shim (dinput8.dll/dsound.dll), der statt der System-" +
                                   "DLL geladen wird und Cheat-Code injiziert.",
                        Detail   = $"Datei: {file} | Spiel: {gameName}"
                    });
                    break;
                }

                // Scan config files for cheat keywords
                if (ext is ".cfg" or ".ini" or ".json" or ".xml" or ".txt")
                {
                    try
                    {
                        var info = new System.IO.FileInfo(file);
                        if (info.Length > 2 * 1024 * 1024) continue;

                        string text = System.IO.File.ReadAllText(file);
                        string lower = text.ToLowerInvariant();

                        foreach (string kw in CheatConfigKeywords)
                        {
                            if (!lower.Contains(kw.ToLowerInvariant())) continue;

                            int idx = lower.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                            int start = Math.Max(0, idx - 30);
                            int end = Math.Min(text.Length, idx + kw.Length + 60);
                            string snippet = text.Substring(start, end - start)
                                                 .Replace('\n', ' ').Trim();

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Cheat-Konfiguration in {gameName}: '{kw}' in {fileName}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Spiel-Config '{fileName}' in '{gameName}' enthält Cheat-" +
                                           $"Schlüsselwort '{kw}'. Direkte Cheat-Konfigurationen in " +
                                           "Spieldateien belegen aktive Cheat-Nutzung.",
                                Detail   = $"Datei: {file} | Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                            });
                            break;
                        }
                    }
                    catch { }
                }

                // Check for symbolic links in game dirs (used to redirect DLL loads)
                try
                {
                    var fi = new System.IO.FileInfo(file);
                    if ((fi.Attributes & System.IO.FileAttributes.ReparsePoint) != 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Symbolischer Link im Spielverzeichnis: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Symbolischer Link '{fileName}' im Spielverzeichnis von " +
                                       $"'{gameName}'. Sym-Links in Spielverzeichnissen werden verwendet, " +
                                       "um DLL-Loads auf alternative (Cheat-)Versionen umzuleiten.",
                            Detail   = $"Datei (Symlink): {file} | Spiel: {gameName}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }
}
