using ZeroTrace.Core.Models;
using System.Text;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects screen recording software configured to hide cheat overlays or used
/// in suspicious ways that correlate with cheat usage during competitive play.
///
/// Anti-cheat context:
///
///   - OBS Studio: Can exclude specific window captures. Cheaters configure OBS to
///     capture the game via "Game Capture" which skips overlay windows — ESP/radar
///     overlays are not recorded even when streaming to Twitch/YouTube. Also used
///     to "prove" innocence with selectively recorded gameplay missing the overlay.
///
///   - NVIDIA ShadowPlay/GeForce Experience: shadowplay.cfg / GfxUI entries reveal
///     which applications are excluded from highlight recording. Cheaters add cheat
///     tool directories to the exclusion list. Also check for highlight clip names
///     with cheat-tool-related substrings.
///
///   - Action! by Mirillis: competitor to OBS, same exclusion pattern. Used to create
///     fake "clean" gameplay proof.
///
///   - Bandicam: similarly configurable to exclude specific windows.
///
///   - XSplit: separate window/process exclusion per scene.
///
///   - Virtual Camera outputs routing to analysis prevention: virtual camera
///     software (ManyCam, VirtualCam plugin) can introduce lag/filter on the
///     output stream to make real-time ESP analysis harder.
///
/// Ocean / detect.ac scan recording software configs because:
///   - The presence of professional streaming software with game-overlay exclusions
///     on a competitive gaming PC is suspicious when combined with cheat artifacts
///   - Clip file names in Shadowplay/ReLive reveal cheat tool window names
///   - OBS scene files with cheat-tool window sources indicate the player was
///     recording the cheat overlay intentionally (analyzing ESP data)
/// </summary>
public sealed class ScreenRecordingCheatArtifactScanModule : IScanModule
{
    public string Name => "Screen-Recording Cheat-Artefakt-Scan (OBS/Shadowplay/Bandicam/XSplit)";
    public double Weight => 0.45;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywords =
    {
        "aimbot", "wallhack", "esp", "cheat", "hack", "triggerbot", "bhop",
        "spinbot", "no_recoil", "gamesense", "onetap", "fatality", "aimware",
        "neverlose", "skeet", "2take1", "kiddion", "cherax", "ozark", "stand",
        "radar", "overlay", "maphack", "speedhack", "godmode",
    };

    private static readonly string[] AntiCheatDomains =
    {
        "battleye", "easyanticheat", "eac", "vanguard", "faceit", "esea",
        "steampowered", "valve", "riot", "xigncode",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string myVideos     = Environment.GetFolderPath(Environment.SpecialFolder.MyVideos);

        // 1. OBS Studio — scene collection JSON files
        ScanObsScenes(ctx, ct, appData, localAppData);

        // 2. Action! by Mirillis — recording configuration
        ScanActionRecorder(ctx, ct, appData);

        // 3. Bandicam — configuration files
        ScanBandicam(ctx, ct, appData);

        // 4. XSplit — scene/source files
        ScanXSplit(ctx, ct, appData, localAppData);

        // 5. AMD ReLive / Radeon Software clip names
        ScanAmdRelive(ctx, ct, userProfile, myVideos);

        // 6. Medal.tv / Outplayed — gaming clip capture apps
        ScanMedalTv(ctx, ct, localAppData, appData);

        // 7. Replay/Highlight directories — scan ALL clip directories for cheat window names
        ScanVideoClipDirectories(ctx, ct, userProfile, myVideos);
    }

    private void ScanObsScenes(ScanContext ctx, CancellationToken ct, string appData, string localAppData)
    {
        // OBS scene collections: %APPDATA%\obs-studio\basic\scenes\*.json
        // Portable: next to obs64.exe/obs.json
        var obsDirs = new[]
        {
            Path.Combine(appData, "obs-studio", "basic", "scenes"),
            Path.Combine(appData, "obs-studio", "basic"),
        };

        foreach (var dir in obsDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var jsonFile in SafeGetFiles(dir, "*.json"))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    string content = File.ReadAllText(jsonFile).ToLowerInvariant();

                    // Check for cheat-keyword window sources
                    string? match = CheatKeywords.FirstOrDefault(kw => content.Contains(kw));
                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OBS Szene-Datei enthält Cheat-Keyword '{match}': {Path.GetFileName(jsonFile)}",
                            Risk     = RiskLevel.High,
                            Location = jsonFile,
                            FileName = Path.GetFileName(jsonFile),
                            Reason   = $"OBS-Szene-Konfiguration '{Path.GetFileName(jsonFile)}' enthält Cheat-Keyword '{match}'. " +
                                       "Cheater konfigurieren OBS-Szenen mit Cheat-Overlay-Fenstern als Quellen " +
                                       "oder benennen Quellen nach Cheat-Tools. Ocean/detect.ac scannen OBS-Szenen " +
                                       "als primäre forensische Quelle für Stream-Setup-Analyse.",
                            Detail   = $"Datei: {jsonFile} | Keyword: {match}"
                        });
                    }

                    // Check for window capture sources with suspicious names
                    if (content.Contains("\"window_capture\"") || content.Contains("\"game_capture\""))
                    {
                        // Look for excluded windows containing AC domain names
                        string? acMatch = AntiCheatDomains.FirstOrDefault(d => content.Contains(d));
                        if (acMatch != null && content.Contains("exclude"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"OBS Szene schließt Anti-Cheat-Fenster aus: '{acMatch}'",
                                Risk     = RiskLevel.High,
                                Location = jsonFile,
                                FileName = Path.GetFileName(jsonFile),
                                Reason   = $"OBS-Szene '{Path.GetFileName(jsonFile)}' enthält eine Ausschlussliste " +
                                           $"für Fenster mit Anti-Cheat-Bezug ('{acMatch}'). Cheater konfigurieren " +
                                           "OBS so, dass AC-Overlay/Warnung-Fenster nicht mit aufgezeichnet werden.",
                                Detail   = $"Datei: {jsonFile} | AC-Keyword: {acMatch}"
                            });
                        }
                    }
                }
                catch { }
            }
        }

        // OBS global.ini — check for virtual camera or suspicious output settings
        string globalIni = Path.Combine(appData, "obs-studio", "global.ini");
        if (File.Exists(globalIni))
        {
            ctx.IncrementFiles();
            try
            {
                string content = File.ReadAllText(globalIni).ToLowerInvariant();
                // Virtual camera enabled in combination with game recording = suspicious
                if (content.Contains("virtualcamerasource") && content.Contains("enabled=true"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "OBS Virtual Camera aktiv (Stream-Manipulation möglich)",
                        Risk     = RiskLevel.Low,
                        Location = globalIni,
                        FileName = "global.ini",
                        Reason   = "OBS Virtual Camera ist aktiviert. Kann zur Manipulation von Proof-of-Gameplay-" +
                                   "Streams verwendet werden, indem vorab aufgezeichnete cheatfreie Inhalte " +
                                   "statt des Live-Spiels übertragen werden.",
                        Detail   = $"Datei: {globalIni}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanActionRecorder(ScanContext ctx, CancellationToken ct, string appData)
    {
        string actionDir = Path.Combine(appData, "Mirillis", "Action");
        if (!Directory.Exists(actionDir)) return;

        foreach (var iniFile in SafeGetFiles(actionDir, "*.ini"))
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            try
            {
                string content = File.ReadAllText(iniFile).ToLowerInvariant();
                string? match = CheatKeywords.FirstOrDefault(kw => content.Contains(kw));
                if (match != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Action! (Mirillis) Konfiguration enthält Cheat-Keyword '{match}'",
                        Risk     = RiskLevel.Medium,
                        Location = iniFile,
                        FileName = Path.GetFileName(iniFile),
                        Reason   = $"Action! Recorder-Konfiguration enthält Cheat-Keyword '{match}'. " +
                                   "Action! kann konfiguriert werden um bestimmte Fenster von der Aufzeichnung " +
                                   "auszuschließen — Cheater verwenden dies um ESP-Overlays zu verbergen.",
                        Detail   = $"Datei: {iniFile} | Keyword: {match}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanBandicam(ScanContext ctx, CancellationToken ct, string appData)
    {
        string bandDir = Path.Combine(appData, "Bandicam");
        if (!Directory.Exists(bandDir)) return;

        foreach (var file in SafeGetFiles(bandDir, "*.ini").Concat(SafeGetFiles(bandDir, "*.cfg")))
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            try
            {
                string content = File.ReadAllText(file).ToLowerInvariant();
                string? match = CheatKeywords.FirstOrDefault(kw => content.Contains(kw));
                if (match != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bandicam Konfiguration enthält Cheat-Keyword '{match}'",
                        Risk     = RiskLevel.Medium,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Bandicam-Konfiguration enthält Cheat-Keyword '{match}'. " +
                                   "Deutet auf Bandicam-Konfiguration hin, die Cheat-Fenster ausschließt.",
                        Detail   = $"Datei: {file} | Keyword: {match}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanXSplit(ScanContext ctx, CancellationToken ct, string appData, string localAppData)
    {
        var xsplitDirs = new[]
        {
            Path.Combine(appData, "SplitMediaLabs", "XSplit Broadcaster"),
            Path.Combine(localAppData, "SplitMediaLabs"),
        };

        foreach (var dir in xsplitDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var xmlFile in SafeGetFiles(dir, "*.xml").Concat(SafeGetFiles(dir, "*.xbs")))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    string content = File.ReadAllText(xmlFile).ToLowerInvariant();
                    string? match = CheatKeywords.FirstOrDefault(kw => content.Contains(kw));
                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"XSplit Szene enthält Cheat-Keyword '{match}': {Path.GetFileName(xmlFile)}",
                            Risk     = RiskLevel.Medium,
                            Location = xmlFile,
                            FileName = Path.GetFileName(xmlFile),
                            Reason   = $"XSplit-Szene '{Path.GetFileName(xmlFile)}' enthält Cheat-Keyword '{match}'. " +
                                       "XSplit-Szenen können Cheat-Overlay-Fenster als Quellen beinhalten.",
                            Detail   = $"Datei: {xmlFile} | Keyword: {match}"
                        });
                    }
                }
                catch { }
            }
        }
    }

    private void ScanAmdRelive(ScanContext ctx, CancellationToken ct, string userProfile, string myVideos)
    {
        // AMD ReLive clips: Videos\ReLive\
        var reliveDir = Path.Combine(myVideos, "ReLive");
        if (!Directory.Exists(reliveDir)) return;

        foreach (var file in SafeGetFiles(reliveDir, "*.mp4").Concat(SafeGetFiles(reliveDir, "*.mkv")))
        {
            ct.ThrowIfCancellationRequested();
            string fname = Path.GetFileName(file).ToLowerInvariant();
            string? match = CheatKeywords.FirstOrDefault(kw => fname.Contains(kw));
            if (match != null)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"AMD ReLive Clip-Name enthält Cheat-Keyword '{match}': {Path.GetFileName(file)}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason   = $"AMD ReLive Video-Clip '{Path.GetFileName(file)}' enthält Cheat-Keyword '{match}' " +
                               "im Dateinamen. Der Dateiname wird aus dem aktiven Fenstertitel generiert — " +
                               "ein Clip mit Cheat-Keyword wurde während eines Cheat-Tools aufgezeichnet.",
                    Detail   = $"Datei: {file} | Keyword: {match}"
                });
            }
        }
    }

    private void ScanMedalTv(ScanContext ctx, CancellationToken ct, string localAppData, string appData)
    {
        // Medal.tv: %APPDATA%\Medal\clips\ or %LOCALAPPDATA%\Medal
        var medalDirs = new[]
        {
            Path.Combine(appData, "Medal"),
            Path.Combine(localAppData, "Medal"),
        };

        foreach (var dir in medalDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var file in SafeGetFiles(dir, "*.json"))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    string content = File.ReadAllText(file).ToLowerInvariant();
                    string? match = CheatKeywords.FirstOrDefault(kw => content.Contains(kw));
                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Medal.tv Konfiguration/Clip-Metadaten mit Cheat-Keyword '{match}'",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Medal.tv Datei '{Path.GetFileName(file)}' enthält Cheat-Keyword '{match}'. " +
                                       "Medal.tv speichert Clip-Metadaten und Spiel-Erkennung in JSON-Dateien.",
                            Detail   = $"Datei: {file} | Keyword: {match}"
                        });
                    }
                }
                catch { }
            }
        }
    }

    private void ScanVideoClipDirectories(ScanContext ctx, CancellationToken ct, string userProfile, string myVideos)
    {
        // Scan common clip output directories for cheat-keyword filenames
        var clipDirs = new[]
        {
            Path.Combine(myVideos, "Captures"),        // Xbox Game Bar
            Path.Combine(myVideos, "Desktop"),
            Path.Combine(userProfile, "Videos"),
            Path.Combine(userProfile, "Desktop"),
        };

        string[] videoExts = { ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv" };

        foreach (var dir in clipDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                var files = Directory.GetFiles(dir)
                    .Where(f => videoExts.Contains(Path.GetExtension(f).ToLowerInvariant()));
                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    string fname = Path.GetFileName(file).ToLowerInvariant();
                    string? match = CheatKeywords.FirstOrDefault(kw => fname.Contains(kw));
                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Video-Clip-Dateiname enthält Cheat-Keyword '{match}': {Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Video-Clip '{Path.GetFileName(file)}' enthält Cheat-Keyword '{match}' " +
                                       "im Dateinamen. Clip-Software benennt Aufnahmen nach dem aktiven Fenstertitel — " +
                                       "dieser Clip wurde während eines aktiven Cheat-Tools erstellt.",
                            Detail   = $"Datei: {file} | Keyword: {match}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private IEnumerable<string> SafeGetFiles(string dir, string pattern)
    {
        try { return Directory.GetFiles(dir, pattern); }
        catch { return Array.Empty<string>(); }
    }
}
