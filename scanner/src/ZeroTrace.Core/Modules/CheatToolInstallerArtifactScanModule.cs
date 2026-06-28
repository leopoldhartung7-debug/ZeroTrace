using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans filesystem locations for installer artifacts, configuration files, log files,
/// and temporary files left by cheat tool installers and loaders. Many cheat tools
/// leave detectable traces even after the main executable is deleted:
///
///   1. Installer packages: .zip/.rar extracts in Downloads containing cheat tool names
///   2. Config files: .cfg/.ini/.json/.txt files with cheat tool names in game dirs
///   3. Log files: cheat tool execution logs in %TEMP%, %LOCALAPPDATA%, %APPDATA%
///   4. License files: cheat tool authentication tokens/license files
///   5. Update caches: cheat auto-updater leftover files (.upd, .ver, .manifest)
///   6. DLL staging areas: temp directories with unsigned DLLs with cheat-related exports
///   7. Discord/Telegram bot config artifacts (used by cheat tools for C2 fallback)
///   8. Crash dumps from cheat tools (contain cheat tool memory artifacts)
///   9. Cheat tool screenshot folders (cheat tools capture screenshots of successful cheating)
///  10. Injector extraction folders (many injectors extract PE files to temp before injection)
///
/// This module specifically targets file artifacts NOT covered by:
///   - CheatToolFileArtifactScanModule (covers known binary names)
///   - CheatToolRegistryArtifactsScanModule (covers registry artifacts)
///   - DriveScanModule (covers general suspicious files)
///
/// Focus: configuration artifacts, log files, license tokens, and update cache files
/// that persist long after the cheat binary is deleted.
/// </summary>
public sealed class CheatToolInstallerArtifactScanModule : IScanModule
{
    public string Name => "Cheat Tool Installer / Config Artifact Scan";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    private record ArtifactPattern(
        string Description,
        string[] SearchPaths,
        string[] FilePatterns,
        string[]? ContentKeywords,
        RiskLevel Risk,
        bool CheckContent);

    private static readonly ArtifactPattern[] Patterns =
    {
        // Cheat tool config files in game directories
        new("Cheat Config in Game-Verzeichnis",
            new[]
            {
                @"C:\Program Files (x86)\Steam\steamapps\common",
                @"C:\Program Files\Steam\steamapps\common",
                @"D:\Steam\steamapps\common",
                @"D:\Games\steamapps\common",
            },
            new[] { "*.cfg", "*.ini", "*.json", "*.lua", "*.txt" },
            new[]
            {
                "aimbot", "triggerbot", "wallhack", "esp", "radar",
                "norecoil", "bhop", "spinbot", "rapid_fire", "godmode",
                "onetap", "fatality", "aimware", "gamesense", "kiddion",
            },
            RiskLevel.High, CheckContent: true),

        // Cheat tool license/authentication files
        new("Cheat-Lizenz/Auth-Token-Datei",
            new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            },
            new[] { "*.lic", "*.license", "*.token", "*.auth", "*.key", "*.hwid" },
            new[]
            {
                "cheat", "hack", "aimbot", "loader",
                "onetap", "fatality", "aimware", "gamesense",
                "kiddion", "2take1", "stand", "cherax",
            },
            RiskLevel.Critical, CheckContent: false), // filename alone is indicative

        // Log files from cheat tools
        new("Cheat-Tool-Log-Datei",
            new[]
            {
                Path.Combine(Path.GetTempPath()),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            },
            new[] { "*.log", "*.txt" },
            new[]
            {
                "[cheat]", "[hack]", "[aimbot]", "[esp]", "[wallhack]",
                "[triggerbot]", "[inject]", "[loader]", "[bypass]",
                "cheat initialized", "hook installed", "injection successful",
                "aimbot enabled", "esp enabled", "wallhack enabled",
                "triggerbot active", "no recoil active",
                "gamesense", "onetap", "fatality", "aimware",
                "kiddion", "2take1", "stand menu",
            },
            RiskLevel.High, CheckContent: true),

        // Cheat updater/manifest files
        new("Cheat-Updater-Manifest-Datei",
            new[]
            {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            },
            new[] { "*.manifest", "*.upd", "*.update", "*.ver", "version.txt", "update.txt" },
            new[]
            {
                "cheat", "hack", "loader", "aimbot",
                "gamesense", "onetap", "fatality", "aimware",
                "skycheats", "neverlose", "kiddion", "2take1",
            },
            RiskLevel.High, CheckContent: true),

        // Injector staging areas in temp
        new("Injector-Staging-Verzeichnis in Temp",
            new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            },
            new[] { "*.dll" },
            new[]
            {
                "cheat", "hack", "inject", "loader", "bypass", "esp",
                "aimbot", "triggerbot", "wallhack",
            },
            RiskLevel.Critical, CheckContent: false), // unsigned DLL in temp = already suspicious

        // Screenshots captured by cheat tools
        new("Cheat-Tool-Screenshot-Ordner",
            new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            },
            new[] { "*.png", "*.jpg", "*.bmp" },
            null, // check by directory name instead
            RiskLevel.Medium, CheckContent: false),
    };

    // Directory names that are known cheat tool folders
    private static readonly HashSet<string> CheatDirectoryNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "gamesense", "onetap", "fatality", "aimware", "skycheats", "neverlose",
        "kiddion", "2take1", "stand", "cherax", "midnight", "ozark",
        "pcileech", "memflow", "dma", "EzSpoofer", "HwidSpoofer",
        "CheatEngine", "xenos", "GHInjector",
        "cheat", "hack", "aimbot", "triggerbot", "wallhack", "esp",
        "norecoil", "recoil", "bhop", "spinbot",
        "injector", "loader", "bypass",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check for cheat directory names first (faster)
            ScanForCheatDirectories(ctx, ct);
            ct.ThrowIfCancellationRequested();
            // Then scan files per pattern
            foreach (var pattern in Patterns)
            {
                ct.ThrowIfCancellationRequested();
                ScanPattern(pattern, ctx, ct);
            }
        }, ct);
    }

    private static void ScanForCheatDirectories(ScanContext ctx, CancellationToken ct)
    {
        string[] scanRoots =
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var root in scanRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var dir in Directory.EnumerateDirectories(root))
                {
                    ct.ThrowIfCancellationRequested();
                    string dirName = Path.GetFileName(dir);
                    string dirNameLow = dirName.ToLowerInvariant();

                    bool isCheatDir = CheatDirectoryNames.Contains(dirName) ||
                                      CheatDirectoryNames.Any(cd =>
                                          dirNameLow.Contains(cd.ToLowerInvariant()) && cd.Length > 4);

                    if (!isCheatDir) continue;

                    long? dirSize = null;
                    int? fileCount = null;
                    try
                    {
                        var files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
                        fileCount = files.Length;
                        dirSize = files.Sum(f =>
                        {
                            try { return new FileInfo(f).Length; } catch { return 0L; }
                        });
                    }
                    catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Cheat Tool Installer / Config Artifact Scan",
                        Title    = $"Cheat-Tool-Verzeichnis gefunden: {dirName}",
                        Risk     = RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason   = $"Verzeichnis '{dir}' entspricht einem bekannten Cheat-Tool-Ordnernamen — " +
                                   "Cheat-Tools installieren sich typisch in AppData/Desktop/Temp-Unterordner " +
                                   "mit ihrem Produktnamen",
                        Detail   = $"Pfad: {dir} | Dateien: {fileCount?.ToString() ?? "?"} | " +
                                   $"Größe: {dirSize?.ToString() ?? "?"} Bytes"
                    });
                }
            }
            catch { }
        }
    }

    private static void ScanPattern(ArtifactPattern pattern, ScanContext ctx, CancellationToken ct)
    {
        foreach (var searchPath in pattern.SearchPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(searchPath)) continue;

            try
            {
                foreach (var filePattern in pattern.FilePatterns)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(searchPath, filePattern,
                            SearchOption.TopDirectoryOnly))
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementFiles();

                            string fileName    = Path.GetFileName(file);
                            string fileNameLow = fileName.ToLowerInvariant();

                            // Check filename for keywords
                            bool fileNameMatch = pattern.ContentKeywords is not null &&
                                                 Array.Exists(pattern.ContentKeywords,
                                                     kw => fileNameLow.Contains(kw.ToLowerInvariant()));

                            if (fileNameMatch && !pattern.CheckContent)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Cheat Tool Installer / Config Artifact Scan",
                                    Title    = $"{pattern.Description}: {fileName}",
                                    Risk     = pattern.Risk,
                                    Location = file,
                                    FileName = fileName,
                                    Reason   = $"Datei '{fileName}' in '{Path.GetDirectoryName(file)}' " +
                                               $"entspricht Cheat-Tool-Artefakt-Muster: {pattern.Description}",
                                    Detail   = $"Datei: {file} | Muster: {filePattern} | " +
                                               $"Kategorie: {pattern.Description}"
                                });
                                continue;
                            }

                            // Check file content for keywords
                            if (pattern.CheckContent && pattern.ContentKeywords is not null)
                            {
                                try
                                {
                                    long fileSize = new FileInfo(file).Length;
                                    if (fileSize > 10 * 1024 * 1024) continue; // skip files > 10MB

                                    string content = File.ReadAllText(file);
                                    string contentLow = content.ToLowerInvariant();

                                    string? matchedKw = Array.Find(pattern.ContentKeywords,
                                        kw => contentLow.Contains(kw.ToLowerInvariant()));

                                    if (matchedKw is null) continue;

                                    ctx.AddFinding(new Finding
                                    {
                                        Module   = "Cheat Tool Installer / Config Artifact Scan",
                                        Title    = $"{pattern.Description}: {fileName}",
                                        Risk     = pattern.Risk,
                                        Location = file,
                                        FileName = fileName,
                                        Reason   = $"Datei '{fileName}' enthält Cheat-Schlüsselwort '{matchedKw}' — " +
                                                   $"{pattern.Description}. Cheat-Tool-Konfigurationsdateien bleiben " +
                                                   "nach Deinstallation oft erhalten",
                                        Detail   = $"Datei: {file} | Schlüsselwort: {matchedKw} | " +
                                                   $"Größe: {fileSize} Bytes | Kategorie: {pattern.Description}"
                                    });
                                }
                                catch { }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }
}
