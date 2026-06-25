using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans peripheral macro software config files for no-recoil and cheat macro patterns.
///
/// Macro-based no-recoil cheats are extremely common and hard to detect in-game because
/// they operate at the hardware/USB HID layer. Ocean and detect.ac scan macro software
/// profiles because:
///
///   - Razer Synapse, Logitech G Hub, SteelSeries GG, Corsair iCUE, HyperX NGenuity
///     all store macro scripts as readable JSON/XML/LUA files on disk
///   - No-recoil scripts have distinctive patterns: rapid mouse movements in fixed
///     intervals matching specific weapon recoil patterns
///   - AutoHotKey (.ahk) scripts referencing game windows with recoil compensation
///     are a well-known cheating vector
///
/// Detects:
///   Razer Synapse 3:  %APPDATA%\Razer\Synapse3\Profiles\*.json  (SYNAPSE_PROFILE)
///   Logitech G Hub:   %LOCALAPPDATA%\LGHUB\settings.db          (SQLite blob scan)
///   SteelSeries GG:   %APPDATA%\SteelSeries GG\gamesense\*
///   Corsair iCUE:     %APPDATA%\Corsair\Corsair Utility Engine\profiles\*.cueprofil
///   HyperX NGenuity:  %APPDATA%\HyperX NGenuity\*
///   AutoHotKey:       %USERPROFILE%\*.ahk  %APPDATA%\*.ahk  Common paths
/// </summary>
public sealed class MacroSoftwareCheatScanModule : IScanModule
{
    public string Name => "Macro-Software Cheat-Script Scan (Razer/Logitech/SteelSeries)";
    public double Weight => 0.55;
    public int ParallelGroup => 4;

    private static readonly string[] CheatMacroKeywords =
    {
        // No-recoil / recoil compensation keywords in scripts
        "norecoil", "no_recoil", "no-recoil", "recoilscript",
        "antirecoil", "anti_recoil", "anti-recoil",
        "recoil compensation", "recoilcomp",
        "spray control", "spraycontrol", "spray_control",
        // Triggerbot keywords
        "triggerbot", "trigger_bot", "trigger bot", "autoshoot",
        "auto_shoot", "auto shoot", "autofire",
        // Bhop / movement
        "bhop", "bunny hop", "bunnyhop", "bhopscript",
        "auto jump", "autojump", "space_jump",
        // Rapid fire
        "rapidfire", "rapid_fire", "rapid fire", "fastfire",
        // Game-specific recoil references
        "AK47 recoil", "AK recoil", "M4 recoil", "FAMAS recoil",
        "Vandal recoil", "Phantom recoil",
        // AHK references
        "SendInput", "MouseMove", "Click", "Sleep",
        // Cheat loader references
        "cheat.exe", "hack.exe", "loader.exe", "injector",
    };

    private static readonly string[] AhkCheatPatterns =
    {
        "MouseMove", "Click", "Sleep", "Loop", "Send",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string local   = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Razer Synapse 3
        ScanDirectory(ctx, System.IO.Path.Combine(appdata, "Razer", "Synapse3", "Profiles"),
            "*.json", 2, "Razer Synapse 3 Profil", ct);
        ScanDirectory(ctx, System.IO.Path.Combine(appdata, "Razer", "Synapse3"),
            "*.json", 3, "Razer Synapse 3", ct);

        // Logitech G Hub settings.db (SQLite — byte-grep it)
        ScanFile(ctx, System.IO.Path.Combine(local, "LGHUB", "settings.db"),
            "Logitech G Hub settings.db", ct);

        // SteelSeries GG
        ScanDirectory(ctx, System.IO.Path.Combine(appdata, "SteelSeries GG"),
            "*.json", 3, "SteelSeries GG", ct);
        ScanDirectory(ctx, System.IO.Path.Combine(appdata, "SteelSeries Engine 3"),
            "*.json", 3, "SteelSeries Engine 3", ct);

        // Corsair iCUE
        ScanDirectory(ctx, System.IO.Path.Combine(appdata, "Corsair", "Corsair Utility Engine", "profiles"),
            "*.cueprofil", 2, "Corsair iCUE", ct);
        ScanDirectory(ctx, System.IO.Path.Combine(appdata, "Corsair", "ICUE4", "profiles"),
            "*.icp", 2, "Corsair iCUE 4", ct);

        // HyperX NGenuity
        ScanDirectory(ctx, System.IO.Path.Combine(appdata, "HyperX NGenuity"),
            "*.json", 3, "HyperX NGenuity", ct);

        // AutoHotKey scripts — common locations
        ScanAutoHotKey(ctx, profile, ct);
        ScanAutoHotKey(ctx, appdata, ct);
        ScanAutoHotKey(ctx, System.IO.Path.Combine(profile, "Desktop"), ct);
        ScanAutoHotKey(ctx, System.IO.Path.Combine(profile, "Documents"), ct);

        // Generic: startup folder AHK scripts
        ScanAutoHotKey(ctx, System.IO.Path.Combine(
            appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"), ct);
    }

    private void ScanDirectory(ScanContext ctx, string dir, string pattern,
        int maxDepth, string label, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(dir)) return;
        try
        {
            var option = maxDepth > 1
                ? System.IO.SearchOption.AllDirectories
                : System.IO.SearchOption.TopDirectoryOnly;

            foreach (string file in System.IO.Directory.EnumerateFiles(dir, pattern, option))
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
            var info = new System.IO.FileInfo(path);
            if (info.Length == 0 || info.Length > 32 * 1024 * 1024) return;
            ctx.IncrementFiles();

            byte[] raw = System.IO.File.ReadAllBytes(path);
            string text = System.Text.Encoding.UTF8.GetString(raw).ToLowerInvariant();
            string fileName = System.IO.Path.GetFileName(path);

            foreach (string kw in CheatMacroKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!text.Contains(kw.ToLowerInvariant())) continue;

                int idx = text.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                int start = Math.Max(0, idx - 30);
                int end = Math.Min(text.Length, idx + kw.Length + 60);
                string snippet = text.Substring(start, end - start)
                                     .Replace('\0', ' ')
                                     .Replace('\n', ' ')
                                     .Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Makro in {label}: '{kw}' in {fileName}",
                    Risk     = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason   = $"Makro-Software-Profil '{fileName}' ({label}) enthält Cheat-Makro-Muster " +
                               $"'{kw}'. Makrobasiertes No-Recoil / Triggerbot operiert auf HID-Ebene " +
                               "und ist in-game nicht erkennbar. Ocean und detect.ac scannen Makro-" +
                               "Profile als forensische Quelle, da legitime Gamer selten solche " +
                               "Schlüsselwörter in Profilen verwenden.",
                    Detail   = $"Quelle: {label} | Datei: {fileName} | " +
                               $"Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                });
                return;
            }
        }
        catch { }
    }

    private void ScanAutoHotKey(ScanContext ctx, string dir, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(dir)) return;
        try
        {
            foreach (string ahk in System.IO.Directory.EnumerateFiles(dir, "*.ahk",
                         System.IO.SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                var info = new System.IO.FileInfo(ahk);
                if (info.Length == 0 || info.Length > 2 * 1024 * 1024) continue;
                ctx.IncrementFiles();

                string text = System.IO.File.ReadAllText(ahk);
                string lower = text.ToLowerInvariant();
                string fileName = System.IO.Path.GetFileName(ahk);

                // AHK no-recoil: rapid Sleep + MouseMove/Click loops are the hallmark pattern
                bool hasLoop  = lower.Contains("loop");
                bool hasSleep = lower.Contains("sleep");
                bool hasMouse = lower.Contains("mousemove") || lower.Contains("click");
                bool hasCheatKw = CheatMacroKeywords.Any(k => lower.Contains(k.ToLowerInvariant()));

                if (hasCheatKw || (hasLoop && hasSleep && hasMouse))
                {
                    string reason = hasCheatKw ? "Cheat-Schlüsselwort gefunden" :
                        "Loop+Sleep+MouseMove-Muster (typisches No-Recoil-AHK-Muster)";

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtiges AutoHotKey-Script: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = ahk,
                        FileName = fileName,
                        Reason   = $"AutoHotKey-Script '{fileName}' enthält {reason}. " +
                                   "AHK-basierte No-Recoil-Cheats nutzen Loop+Sleep+MouseMove, " +
                                   "um Waffenrückstoß zu kompensieren — vollständig unterhalb der " +
                                   "Anti-Cheat-Erfassungsebene. Ocean und detect.ac flaggen AHK-" +
                                   "Scripts mit diesem Muster als starkes Cheat-Signal.",
                        Detail   = $"Datei: {ahk} | Muster: {reason}"
                    });
                }
            }
        }
        catch { }
    }
}
