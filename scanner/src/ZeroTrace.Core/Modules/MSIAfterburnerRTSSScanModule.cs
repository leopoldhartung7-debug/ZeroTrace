using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects MSI Afterburner and RivaTuner Statistics Server overlay abuse for cheating.
///
/// MSI Afterburner + RTSS are the most common GPU overlay tools. The RTSS overlay
/// injects into all DirectX/Vulkan processes using a kernel-level driver. Cheaters abuse
/// this because:
///   - RTSS's injection mechanism can be used to load arbitrary DLLs into game processes
///   - Some cheat loaders piggyback on RTSS's injection (lower suspicion than raw injection)
///   - Afterburner's OSD (On-Screen Display) profiles can hide cheat overlay windows
///   - RTSS provides a legitimate-looking reason for a kernel hook driver to be loaded
///
/// Ocean and detect.ac check Afterburner/RTSS because:
///   - RTSS profiles with custom plugins pointing to non-Afterburner paths = suspicious
///   - Afterburner macro buttons configured to launch cheat executables
///   - RTSS process-specific OSD configs that disable display for certain processes
///     (used to hide ESP overlay from streams by turning off RTSS for OBS but keeping it
///     active in-game)
///
/// Files scanned:
///   %ProgramFiles(x86)%\MSI Afterburner\                — Afterburner profiles
///   %ProgramFiles(x86)%\RivaTuner Statistics Server\    — RTSS profiles + plugins
///   %APPDATA%\MSI Afterburner\Profiles\                 — user profiles
/// </summary>
public sealed class MSIAfterburnerRTSSScanModule : IScanModule
{
    public string Name => "MSI Afterburner / RTSS Overlay Cheat-Abuse Scan";
    public double Weight => 0.45;
    public int ParallelGroup => 3;

    private static readonly string[] SuspiciousProfileKeywords =
    {
        // Macro/plugin paths pointing outside Afterburner
        "cheat", "hack", "injector", "loader",
        "aimbot", "wallhack", "esp",
        // RTSS plugin DLL names from known cheat projects
        "rtssplugin_cheat", "overlay_plugin",
        // Afterburner macro targets
        ".exe\" cheat", "cheat.exe", "hack.exe",
        // Known cheat injection via RTSS
        "gamesense", "onetap", "fatality",
        "neverlose", "skeet",
        // Process-specific exclusions (hiding overlay for streaming)
        "obs64.exe", "obs32.exe",   // when combined with active game OSD = suspicious
    };

    private static readonly string[] RtssPluginPathPatterns =
    {
        // RTSS plugins outside the RTSS install dir are suspicious
        "\\appdata\\", "\\temp\\", "\\downloads\\",
        "\\desktop\\", "\\users\\public\\",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string appdata     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // MSI Afterburner install dir
        ScanDirectory(ctx,
            System.IO.Path.Combine(progFiles86, "MSI Afterburner"),
            "Afterburner", ct);

        // RTSS install dir
        ScanDirectory(ctx,
            System.IO.Path.Combine(progFiles86, "RivaTuner Statistics Server"),
            "RTSS", ct);

        // User profile overrides
        ScanDirectory(ctx,
            System.IO.Path.Combine(appdata, "MSI Afterburner"),
            "Afterburner Profil (User)", ct);

        // Registry: RTSS plugin list
        ScanRtssPluginRegistry(ctx, ct);
    }

    private void ScanDirectory(ScanContext ctx, string dir, string label, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(dir)) return;
        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(dir, "*",
                         System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                string ext = System.IO.Path.GetExtension(file).ToLowerInvariant();
                if (ext is not (".cfg" or ".ini" or ".xml" or ".json" or ".dll" or ".txt")) continue;

                var info = new System.IO.FileInfo(file);
                if (info.Length == 0 || info.Length > 5 * 1024 * 1024) continue;

                ctx.IncrementFiles();

                // For .dll files — flag if they're in suspicious subdirs
                if (ext == ".dll")
                {
                    string pathLower = file.ToLowerInvariant();
                    if (!pathLower.Contains("rivatuner") &&
                        !pathLower.Contains("msi afterburner") &&
                        !pathLower.Contains("afterburner"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Externe DLL in {label}-Verzeichnis: {System.IO.Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = System.IO.Path.GetFileName(file),
                            Reason   = $"DLL '{System.IO.Path.GetFileName(file)}' befindet sich im {label}-Verzeichnis, " +
                                       "gehört aber nicht zur Standard-Installation. RTSS-Plugin-DLLs aus " +
                                       "unbekannten Quellen können für Cheat-DLL-Injection missbraucht werden, " +
                                       "da RTSS einen legitimen Kernel-Inject-Mechanismus bereitstellt.",
                            Detail   = $"Pfad: {file} | Label: {label}"
                        });
                    }
                    continue;
                }

                try
                {
                    string text = System.IO.File.ReadAllText(file);
                    string lower = text.ToLowerInvariant();
                    string fileName = System.IO.Path.GetFileName(file);

                    foreach (string kw in SuspiciousProfileKeywords)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!lower.Contains(kw.ToLowerInvariant())) continue;

                        int idx = lower.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                        int start = Math.Max(0, idx - 40);
                        int end = Math.Min(text.Length, idx + kw.Length + 80);
                        string snippet = text.Substring(start, end - start)
                                             .Replace('\n', ' ').Replace('\r', ' ').Trim();

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtiger Eintrag in {label}: '{kw}' in {fileName}",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"{label}-Konfigurationsdatei '{fileName}' enthält verdächtigen " +
                                       $"Eintrag '{kw}'. Afterburner-Makros oder RTSS-Plugin-Pfade mit " +
                                       "Cheat-Referenzen sind Indizien für Overlay-Cheat-Nutzung.",
                            Detail   = $"Quelle: {label} | Datei: {fileName} | " +
                                       $"Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                        });
                        return;
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanRtssPluginRegistry(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var rtssKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Unwinder\RTSS\Plugins", writable: false)
                ?? Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Unwinder\RTSS\Plugins", writable: false);

            if (rtssKey is null) return;

            foreach (string pluginName in rtssKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var pluginKey = rtssKey.OpenSubKey(pluginName, writable: false);
                    if (pluginKey is null) continue;

                    string? path = pluginKey.GetValue("FileName") as string
                                ?? pluginKey.GetValue("Path") as string
                                ?? pluginKey.GetValue("") as string;

                    if (string.IsNullOrEmpty(path)) continue;

                    string pathLower = path.ToLowerInvariant();
                    foreach (string pattern in RtssPluginPathPatterns)
                    {
                        if (!pathLower.Contains(pattern)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"RTSS-Plugin aus verdächtigem Pfad: {pluginName}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\SOFTWARE\...\RTSS\Plugins\{pluginName}",
                            FileName = pluginName,
                            Reason   = $"RTSS-Plugin '{pluginName}' ist in einem unüblichen Pfad " +
                                       $"('{path}') registriert. Legitime RTSS-Plugins befinden " +
                                       "sich im RTSS-Installationsverzeichnis. Plugins aus AppData, " +
                                       "Temp oder Desktop deuten auf Cheat-DLL-Injection über den " +
                                       "RTSS-Mechanismus hin.",
                            Detail   = $"Plugin: {pluginName} | Pfad: {path} | Muster: '{pattern}'"
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
