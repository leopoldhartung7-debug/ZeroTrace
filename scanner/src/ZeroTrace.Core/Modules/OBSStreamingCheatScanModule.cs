using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans OBS Studio configuration for cheat-related streaming setup artifacts.
///
/// OBS is frequently used in cheat setups:
///   - Streaming with cheats and hiding cheat overlays from stream output (window capture
///     vs game capture — a cheat user configures OBS to capture only the game window
///     WITHOUT the cheat overlay visible)
///   - Screen-sharing cheats: a second monitor shows wallhack ESP and OBS captures only
///     the main monitor
///   - Script plugins that automate cheat-related actions
///   - Recording game sessions while cheating (private local recording)
///
/// Ocean and detect.ac check OBS config because:
///   - scene-collections and profiles reveal which monitors/windows are captured
///   - Script plugins may reference cheat tools
///   - Source names like "ESP Overlay" or "Radar" are dead giveaways
///
/// Files scanned:
///   %APPDATA%\obs-studio\basic\scenes\*.json          — scene collections
///   %APPDATA%\obs-studio\basic\profiles\              — profile configs
///   %APPDATA%\obs-studio\global.ini                   — global OBS settings
///   %APPDATA%\obs-studio\logs\                        — recent session logs
/// </summary>
public sealed class OBSStreamingCheatScanModule : IScanModule
{
    public string Name => "OBS Studio Cheat-Setup Scan";
    public double Weight => 0.45;
    public int ParallelGroup => 4;

    private static readonly string[] CheatSceneSourceKeywords =
    {
        // ESP / wallhack overlay source names
        "esp", "radar", "wallhack", "cheat overlay", "cheat_overlay",
        "aimbot", "aim_overlay", "no_recoil",
        // Cheat loader windows that OBS might capture by window title
        "gamesense", "onetap", "fatality", "neverlose", "skeet",
        "2take1", "kiddion", "cherax", "ozark",
        "cheat loader", "cheat_loader", "hack loader",
        "injector", "cheat menu", "cheatmenu",
        // DMA-related sources
        "dma", "radar window", "radar_window",
        "external cheat", "external esp",
        // Script names
        "cheat", "hack", "bypass",
    };

    private static readonly string[] CheatPluginNames =
    {
        "obs-cheat", "cheat-plugin", "esp-plugin",
        "radar-plugin", "overlay-cheat",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string obsRoot = System.IO.Path.Combine(appdata, "obs-studio");
        if (!System.IO.Directory.Exists(obsRoot)) return;

        // Scene collections
        ScanDirectory(ctx, System.IO.Path.Combine(obsRoot, "basic", "scenes"),
            "*.json", "OBS Szenen-Collection", ct);

        // Profiles
        ScanDirectory(ctx, System.IO.Path.Combine(obsRoot, "basic", "profiles"),
            "*.ini", "OBS Profil", ct);

        // Global config
        ScanFile(ctx, System.IO.Path.Combine(obsRoot, "global.ini"), "OBS global.ini", ct);

        // Logs (recent activity — look for cheat window titles captured)
        ScanLogsDir(ctx, System.IO.Path.Combine(obsRoot, "logs"), ct);

        // Plugin data
        ScanDirectory(ctx, System.IO.Path.Combine(obsRoot, "plugin_config"),
            "*", "OBS Plugin-Config", ct);

        // Scripts
        ScanDirectory(ctx, System.IO.Path.Combine(obsRoot, "scripts"),
            "*.py", "OBS Python-Script", ct);
        ScanDirectory(ctx, System.IO.Path.Combine(obsRoot, "scripts"),
            "*.lua", "OBS Lua-Script", ct);
    }

    private void ScanDirectory(ScanContext ctx, string dir, string pattern,
        string label, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(dir)) return;
        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(dir, pattern,
                         System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var info = new System.IO.FileInfo(file);
                if (info.Length == 0 || info.Length > 10 * 1024 * 1024) continue;
                ctx.IncrementFiles();
                ScanFile(ctx, file, label, ct);
            }
        }
        catch { }
    }

    private void ScanFile(ScanContext ctx, string path, string label, CancellationToken ct)
    {
        if (!System.IO.File.Exists(path)) return;
        try
        {
            string text = System.IO.File.ReadAllText(path);
            string lower = text.ToLowerInvariant();
            string fileName = System.IO.Path.GetFileName(path);

            foreach (string kw in CheatSceneSourceKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!lower.Contains(kw)) continue;

                int idx = lower.IndexOf(kw, StringComparison.Ordinal);
                int start = Math.Max(0, idx - 50);
                int end = Math.Min(text.Length, idx + kw.Length + 80);
                string snippet = text.Substring(start, end - start)
                                     .Replace('\n', ' ').Replace('\r', ' ').Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Artefakt in OBS Konfiguration: '{kw}' in {fileName}",
                    Risk     = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason   = $"OBS-Konfigurationsdatei '{fileName}' ({label}) enthält Cheat-Schlüsselwort " +
                               $"'{kw}'. OBS-Szenenkonfigurationen mit ESP-Overlay-Quellen, Radar-Fenstern " +
                               "oder Cheat-Loader-Fenstertiteln sind direkte Belege für Cheat-Nutzung " +
                               "beim Streaming/Recording. Ocean und detect.ac scannen OBS als Quelle.",
                    Detail   = $"Quelle: {label} | Datei: {fileName} | " +
                               $"Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                });
                return;
            }
        }
        catch { }
    }

    private void ScanLogsDir(ScanContext ctx, string logsDir, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(logsDir)) return;
        try
        {
            // Only scan the 5 most recent log files
            var logs = System.IO.Directory.GetFiles(logsDir, "*.txt")
                            .OrderByDescending(f => System.IO.File.GetLastWriteTime(f))
                            .Take(5);

            foreach (string log in logs)
            {
                ct.ThrowIfCancellationRequested();
                var info = new System.IO.FileInfo(log);
                if (info.Length == 0 || info.Length > 20 * 1024 * 1024) continue;
                ctx.IncrementFiles();
                ScanFile(ctx, log, "OBS Log", ct);
            }
        }
        catch { }
    }
}
