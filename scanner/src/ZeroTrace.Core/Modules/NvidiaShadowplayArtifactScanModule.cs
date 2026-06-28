using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Nvidia GeForce Experience / Shadowplay clip and screenshot artifacts for
/// cheat-related naming patterns.
///
/// Shadowplay automatically names clips and screenshots based on game name + timestamp
/// (e.g. "Counter-Strike 2 2024.01.15 - 22.31.45.mp4"). Users who cheat often:
///   - Record "proof" clips with cheat overlays visible
///   - Share clips with cheat highlights (aimlock, wallhack-based play)
///   - Have clips named by cheat software (e.g. "ESP_clip_01.mp4")
///
/// Ocean and detect.ac scan clip file names because:
///   - Clip files named with cheat keywords are a direct evidence trail
///   - GFE log files contain session data that persists even after clips are deleted
///   - GeForce Experience stores overlay configuration that reveals cheat software
///
/// Locations:
///   %USERPROFILE%\Videos\          — Shadowplay default clip location
///   %USERPROFILE%\Videos\Desktop\  — Desktop recording
///   %APPDATA%\NVIDIA\NvBackend\    — GFE settings and log
///   %PROGRAMDATA%\NVIDIA\          — System-wide GFE data
///   %LOCALAPPDATA%\NVIDIA\         — Per-user NV data
/// </summary>
public sealed class NvidiaShadowplayArtifactScanModule : IScanModule
{
    public string Name => "Nvidia GeForce Experience / Shadowplay Cheat-Artefakt Scan";
    public double Weight => 0.45;
    public int ParallelGroup => 4;

    private static readonly string[] CheatClipKeywords =
    {
        "aimbot", "aim_bot", "aimlock", "aim_lock",
        "wallhack", "wall_hack", "wh_clip",
        "esp_clip", "esp clip",
        "rage", "rage hack", "ragehack",
        "cheat", "hack", "cheater",
        "spinbot", "spin_bot",
        "triggerbot", "trigger_bot",
        "no_recoil", "norecoil",
        "bhop", "bunny",
        "injector", "inject",
        "undetected", "ud_clip",
        "gamesense", "onetap", "fatality",
        "skeet", "neverlose",
        "2take1", "kiddion",
    };

    private static readonly string[] VideoExtensions =
    {
        ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string profile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appdata  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string local    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        // Clip locations
        ScanClipDirectory(ctx, System.IO.Path.Combine(profile, "Videos"), 2, ct);
        ScanClipDirectory(ctx, System.IO.Path.Combine(profile, "Desktop"), 1, ct);
        ScanClipDirectory(ctx, System.IO.Path.Combine(profile, "Documents"), 1, ct);

        // GFE settings / logs (text scan for cheat keywords)
        ScanGfeConfig(ctx, System.IO.Path.Combine(appdata, "NVIDIA", "NvBackend"), ct);
        ScanGfeConfig(ctx, System.IO.Path.Combine(local, "NVIDIA", "NvBackend"), ct);
        ScanGfeConfig(ctx, System.IO.Path.Combine(progData, "NVIDIA", "NvBackend"), ct);

        // Also scan common alternate clip save paths
        foreach (char drive in "CDEF")
        {
            ct.ThrowIfCancellationRequested();
            string clipPath = $@"{drive}:\Users\{Environment.UserName}\Videos";
            if (System.IO.Directory.Exists(clipPath))
                ScanClipDirectory(ctx, clipPath, 2, ct);
        }
    }

    private void ScanClipDirectory(ScanContext ctx, string dir, int maxDepth, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(dir)) return;
        try
        {
            var option = maxDepth > 1
                ? System.IO.SearchOption.AllDirectories
                : System.IO.SearchOption.TopDirectoryOnly;

            int fileCount = 0;
            foreach (string file in System.IO.Directory.EnumerateFiles(dir, "*", option))
            {
                ct.ThrowIfCancellationRequested();
                if (++fileCount > 5000) break;

                string ext = System.IO.Path.GetExtension(file).ToLowerInvariant();
                if (!VideoExtensions.Contains(ext)) continue;

                string fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();
                ctx.IncrementFiles();

                foreach (string kw in CheatClipKeywords)
                {
                    if (!fileName.Contains(kw)) continue;

                    var info = new System.IO.FileInfo(file);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Clip-Dateiname: '{kw}' in {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"Video-Clip '{System.IO.Path.GetFileName(file)}' enthält Cheat-Schlüsselwort " +
                                   $"'{kw}' im Dateinamen. Clip-Namen mit Cheat-Bezeichnungen deuten auf " +
                                   "bewusstes Aufzeichnen von Cheat-Gameplay hin. Ocean und detect.ac " +
                                   "scannen Clip-Dateinamen als forensische Quelle.",
                        Detail   = $"Datei: {file} | Schlüsselwort: '{kw}' | " +
                                   $"Größe: {info.Length / 1024}KB | " +
                                   $"Geändert: {info.LastWriteTime:yyyy-MM-dd HH:mm}"
                    });
                    break; // one finding per clip file
                }
            }
        }
        catch { }
    }

    private void ScanGfeConfig(ScanContext ctx, string dir, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(dir)) return;
        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(dir, "*",
                         System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                string ext = System.IO.Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".json" && ext != ".log" && ext != ".xml" && ext != ".db") continue;

                var info = new System.IO.FileInfo(file);
                if (info.Length == 0 || info.Length > 10 * 1024 * 1024) continue;

                ctx.IncrementFiles();
                try
                {
                    string text = System.IO.File.ReadAllText(file).ToLowerInvariant();
                    string fileName = System.IO.Path.GetFileName(file);

                    foreach (string kw in CheatClipKeywords)
                    {
                        if (!text.Contains(kw)) continue;

                        int idx = text.IndexOf(kw, StringComparison.Ordinal);
                        int start = Math.Max(0, idx - 40);
                        int end = Math.Min(text.Length, idx + kw.Length + 80);
                        string snippet = text.Substring(start, end - start)
                                             .Replace('\n', ' ').Trim();

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat-Schlüsselwort in GFE-Config: '{kw}'",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"GeForce Experience Konfigurationsdatei '{fileName}' enthält " +
                                       $"Cheat-Schlüsselwort '{kw}'. GFE-Logs können Clip-Pfade, " +
                                       "Overlay-Konfigurationen und Sitzungsdaten speichern, die " +
                                       "Cheat-Software-Nutzung widerspiegeln.",
                            Detail   = $"Datei: {file} | Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                        });
                        break;
                    }
                }
                catch { }
            }
        }
        catch { }
    }
}
