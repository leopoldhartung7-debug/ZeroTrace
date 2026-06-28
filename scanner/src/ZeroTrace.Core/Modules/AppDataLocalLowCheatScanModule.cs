using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans %USERPROFILE%\AppData\LocalLow for cheat tool artifacts.
///
/// LocalLow is a low-integrity counterpart to LocalAppData used by IE and other
/// low-integrity processes. It is often overlooked by manual cleanup attempts
/// because Windows Explorer hides AppData entirely from the navigation pane.
/// Cheat tools deliberately store license tokens, logs, and configuration here
/// because:
///   - Standard "delete AppData\Cheat" cleanup misses LocalLow
///   - LocalLow survives many uninstall routines and reset-game scripts
///   - Anti-cheat scanners that only walk Roaming/Local miss it
///
/// Ocean and detect.ac specifically enumerate LocalLow — this module matches
/// that coverage with the same cheat-suite keyword and signature file lists
/// used by the main AppData scanner.
/// </summary>
public sealed class AppDataLocalLowCheatScanModule : IScanModule
{
    public string Name => "AppData\\LocalLow Cheat Artifact Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    private static readonly HashSet<string> CheatDirectoryNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        // CS / Source cheat suites
        "gamesense", "onetap", "fatality", "aimware", "limeware", "ev0lve",
        "neverlose", "skeet", "primordial", "weave.gg", "intellect",
        // GTA V menus
        "kiddion", "2take1", "stand", "cherax", "midnight", "ozark",
        "menyoo", "scripthookv",
        // EFT
        "skycheats", "skytap", "magicbullet", "tarkov_aimbot",
        // CoD / Warzone
        "engineowning", "iniuria", "vapeflux", "interwebz",
        // Apex
        "apexlegit", "spectre.gg",
        // Valorant
        "tronix", "lethal.gg",
        // Universal
        "CheatEngine", "Cheat Engine", "xenos", "Extreme Injector",
        "Process Hacker", "x64dbg", "x32dbg", "ollydbg",
        // Hardware/DMA
        "pcileech", "memprocfs", "memflow",
        // HWID
        "spoofer", "hwid_changer", "permspoofer", "tempspoofer",
    };

    private static readonly string[] CheatFileExtensions =
    {
        ".asi", ".luac", ".lic", ".license", ".token", ".manifest",
    };

    private static readonly string[] CheatFilenameKeywords =
    {
        "cheat", "hack", "aimbot", "wallhack", "esp_", "trigger_",
        "spoofer", "loader.exe", "inject.exe", "bypass.exe",
        "license_key", "auth_token", "cheat.cfg", "hack.cfg",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(profile)) return;

        string locallow = System.IO.Path.Combine(profile, "AppData", "LocalLow");
        if (!System.IO.Directory.Exists(locallow)) return;

        // Top-level directories
        try
        {
            foreach (string dir in System.IO.Directory.EnumerateDirectories(locallow))
            {
                ct.ThrowIfCancellationRequested();
                string dirName = System.IO.Path.GetFileName(dir);

                if (CheatDirectoryNames.Contains(dirName) ||
                    CheatDirectoryNames.Any(k => dirName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Verzeichnis in AppData\\LocalLow: {dirName}",
                        Risk     = RiskLevel.Critical,
                        Location = dir,
                        FileName = dirName,
                        Reason   = $"Verzeichnis '{dirName}' in AppData\\LocalLow entspricht bekanntem " +
                                   "Cheat-Tool. LocalLow wird von Standard-Cleanup-Scripts oft übersehen — " +
                                   "Cheat-Tools nutzen das gezielt für License-Tokens und Config-Dateien.",
                        Detail   = $"Pfad: {dir}"
                    });
                    continue;
                }

                ScanDirectoryRecursive(ctx, dir, dirName, 0, ct);
            }
        }
        catch { }
    }

    private void ScanDirectoryRecursive(ScanContext ctx, string dir,
        string rootName, int depth, CancellationToken ct)
    {
        if (depth > 3) return;
        ct.ThrowIfCancellationRequested();

        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(dir))
            {
                ct.ThrowIfCancellationRequested();
                string fname = System.IO.Path.GetFileName(file).ToLowerInvariant();
                string ext   = System.IO.Path.GetExtension(file).ToLowerInvariant();

                bool extHit = CheatFileExtensions.Contains(ext);
                string? kwHit = null;
                foreach (string kw in CheatFilenameKeywords)
                {
                    if (fname.Contains(kw)) { kwHit = kw; break; }
                }

                if (!extHit && kwHit is null) continue;
                ctx.IncrementFiles();

                var risk = (extHit && kwHit is not null) ? RiskLevel.Critical
                         : kwHit is not null ? RiskLevel.High
                         : RiskLevel.Medium;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Artefakt in AppData\\LocalLow: {System.IO.Path.GetFileName(file)}",
                    Risk     = risk,
                    Location = file,
                    FileName = System.IO.Path.GetFileName(file),
                    Reason   = $"Datei '{System.IO.Path.GetFileName(file)}' im LocalLow-Unterordner " +
                               $"'{rootName}' entspricht Cheat-Artefakt-Muster" +
                               (kwHit is not null ? $" (Keyword: {kwHit})" : "") +
                               (extHit ? $" (Erweiterung: {ext})" : "") +
                               ". LocalLow wird von Standard-Anti-Cheat-Scannern oft übersehen.",
                    Detail   = $"Pfad: {file} | Ordner: {rootName}" +
                               (kwHit is not null ? $" | Keyword: {kwHit}" : "")
                });
            }

            foreach (string sub in System.IO.Directory.EnumerateDirectories(dir))
                ScanDirectoryRecursive(ctx, sub, rootName, depth + 1, ct);
        }
        catch { }
    }
}
