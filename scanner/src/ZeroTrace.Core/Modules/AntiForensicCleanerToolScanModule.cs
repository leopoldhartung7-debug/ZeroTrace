using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects anti-forensic tool artifacts: CCleaner with cheat-directory cleaning rules,
/// BleachBit/PrivaZer/Eraser installations, O&O ShutUp10 telemetry blocking, and Prefetch
/// evidence of cleaner execution before AC review. Cheaters run these tools before submitting
/// to AC reviews — artifacts prove intentional evidence destruction. Primary Ocean/detect.ac signal.
/// </summary>
public sealed class AntiForensicCleanerToolScanModule : IScanModule
{
    public string Name => "AntiForensicCleanerTool";
    public double Weight => 0.55;
    public int ParallelGroup => 4;

    private static readonly string[] CheatRelatedPathFragments = {
        "aimbot", "cheat", "hack", "esp", "inject", "bypass", "spoofer",
        "kiddion", "onetap", "gamesense", "2take1", "cherax", "memprocfs",
        "pcileech", "norecoil", "triggerbot", "wallhack", "bhop",
        "unknowncheats", "mpgh", "hvh", "softaim", "aimware", "fatality",
        "neverlose", "supremacy", "interium", "skeet", "csgohack"
    };

    private static readonly string[] CleanerPrefetchNames = {
        "CCLEANER64.EXE", "CCLEANER.EXE", "CCLEANERPORTABLE.EXE",
        "BLEACHBIT.EXE", "BLEACHBIT-CONSOLE.EXE",
        "PRIVAZER.EXE", "ERASER.EXE",
        "FILESHREDDER.EXE", "ULTRASHREDDER.EXE",
        "WISECARE365.EXE", "GLARYUTILITIES5.EXE",
        "OOSU10.EXE", "O&OSHUTUP10.EXE",
        "SPYBOTANTIBEACON.EXE", "W10PRIVACY.EXE",
        "WINDOWS10PRIVACY.EXE", "PRIVACYREPAIRER.EXE"
    };

    private static readonly string[] ShredderDirNames = {
        "Eraser", "PrivaZer", "FileShredder", "UltraShredder",
        "Secure Eraser", "Wise Care 365", "Glary Utilities",
        "BleachBit"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanCcleaner(ctx, ct);
            ScanBleachBit(ctx, ct);
            ScanPrivazerEraser(ctx, ct);
            ScanShutUp10AndPrivacyTools(ctx, ct);
            ScanFileShredderArtifacts(ctx, ct);
            ScanPrefetchForCleanerExecution(ctx, ct);
        }, ct);
    }

    private static bool ContainsCheatPath(string text)
    {
        var lower = text.ToLowerInvariant();
        foreach (var fragment in CheatRelatedPathFragments)
            if (lower.Contains(fragment)) return true;
        return false;
    }

    // ─── CCleaner ────────────────────────────────────────────────────────────

    private static void ScanCcleaner(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        using var cclKey = Registry.CurrentUser.OpenSubKey(@"Software\Piriform\CCleaner");
        if (cclKey == null) return;

        ctx.IncrementRegistryKeys(1);

        int customFilesCount = 0;
        for (int i = 1; i <= 100; i++)
        {
            ct.ThrowIfCancellationRequested();
            var val = cclKey.GetValue($"CustomFiles{i}") as string
                   ?? cclKey.GetValue($"CustomFolder{i}") as string;
            if (val == null) break;
            customFilesCount++;

            if (ContainsCheatPath(val))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "AntiForensicCleanerTool",
                    Title = "CCleaner: Cheat-Verzeichnis als Reinigungsziel konfiguriert",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\Piriform\CCleaner",
                    Reason = $"CCleaner hat einen cheat-bezogenen Pfad als benutzerdefiniertes Reinigungsziel: '{val}'. " +
                             "Cheater konfigurieren CCleaner um Cheat-Dateien automatisch zu loeschen.",
                    Detail = $"CustomEntry={val}"
                });
            }
        }

        var autoRun = cclKey.GetValue("AutoRun") as string;
        var monitorDrives = cclKey.GetValue("MonitorDrives") as string;
        if ((autoRun == "1" || monitorDrives == "1") && customFilesCount > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = "AntiForensicCleanerTool",
                Title = "CCleaner mit automatischer Bereinigung und benutzerdefinierten Zielpfaden",
                Risk = RiskLevel.Medium,
                Location = @"HKCU\Software\Piriform\CCleaner",
                Reason = "CCleaner ist fuer automatische Bereinigung konfiguriert (AutoRun/MonitorDrives) " +
                         "mit benutzerdefinierten Zielen — Anti-Forensik-Konfiguration.",
                Detail = $"AutoRun={autoRun} MonitorDrives={monitorDrives} CustomEntries={customFilesCount}"
            });
        }

        // CCleaner installation record
        using var uninstKey = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CCleaner");
        using var uninstKey64 = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\CCleaner");
        if (uninstKey != null || uninstKey64 != null)
        {
            ctx.IncrementRegistryKeys(1);
            ctx.AddFinding(new Finding
            {
                Module = "AntiForensicCleanerTool",
                Title = "CCleaner installiert (Anti-Forensik-Tool)",
                Risk = RiskLevel.Low,
                Location = @"HKLM\SOFTWARE\...\Uninstall\CCleaner",
                Reason = "CCleaner ist installiert. Cheater verwenden es haeufig zur Spurenbeseitigung vor AC-Reviews. " +
                         "Im Kontext anderer Funde erhoehtes Risiko.",
                Detail = "CCleaner in Add/Remove Programs registry"
            });
        }
    }

    // ─── BleachBit ───────────────────────────────────────────────────────────

    private static void ScanBleachBit(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var bleachDir = Path.Combine(appData, "BleachBit");

        if (!Directory.Exists(bleachDir)) return;

        ctx.AddFinding(new Finding
        {
            Module = "AntiForensicCleanerTool",
            Title = "BleachBit Anti-Forensik-Tool installiert",
            Risk = RiskLevel.Medium,
            Location = bleachDir,
            Reason = "BleachBit (Datei-Shredder mit sicherer Ueberschreibung) ist installiert. " +
                     "Verwendet von Cheatern zur sicheren Vernichtung forensischer Beweise.",
            Detail = $"BleachBitDir={bleachDir}"
        });

        var configFile = Path.Combine(bleachDir, "bleachbit.ini");
        if (!File.Exists(configFile)) return;

        try
        {
            ctx.IncrementFiles(1);
            var content = File.ReadAllText(configFile, Encoding.UTF8);
            if (ContainsCheatPath(content))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "AntiForensicCleanerTool",
                    Title = "BleachBit: Cheat-bezogene Pfade in Konfiguration",
                    Risk = RiskLevel.High,
                    Location = configFile,
                    FileName = "bleachbit.ini",
                    Reason = "BleachBit-Konfiguration enthaelt cheat-bezogene Pfade als Reinigungsziele — " +
                             "gezielte Vernichtung von Cheat-Forensikbeweisen konfiguriert.",
                    Detail = $"Config={configFile}"
                });
            }
        }
        catch { }
    }

    // ─── PrivaZer / Eraser ───────────────────────────────────────────────────

    private static void ScanPrivazerEraser(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        using var pvKey = Registry.CurrentUser.OpenSubKey(@"Software\PrivaZer");
        if (pvKey != null)
        {
            ctx.IncrementRegistryKeys(1);
            ctx.AddFinding(new Finding
            {
                Module = "AntiForensicCleanerTool",
                Title = "PrivaZer Anti-Forensik-Tool konfiguriert",
                Risk = RiskLevel.Medium,
                Location = @"HKCU\Software\PrivaZer",
                Reason = "PrivaZer (Tiefenreiniger mit sicherer Ueberschreibung) Konfiguration gefunden. " +
                         "Verwendet von Cheatern zur Vernichtung von Cheat-Artefakten und BAM/Shimcache-Eintraegen.",
                Detail = "PrivaZer registry artifact"
            });
        }

        using var eraserKey  = Registry.CurrentUser.OpenSubKey(@"Software\Eraser\Eraser 6");
        using var eraserKey2 = Registry.CurrentUser.OpenSubKey(@"Software\Heidi Computers\Eraser 5");
        if (eraserKey != null || eraserKey2 != null)
        {
            ctx.IncrementRegistryKeys(1);
            ctx.AddFinding(new Finding
            {
                Module = "AntiForensicCleanerTool",
                Title = "Eraser Datei-Shredder gefunden",
                Risk = RiskLevel.Medium,
                Location = @"HKCU\Software\Eraser",
                Reason = "Eraser (sicherer Datei-Shredder mit DoD-Standard) gefunden. " +
                         "Wird von Cheatern verwendet um Cheat-Tools spurlos zu vernichten.",
                Detail = "Eraser registry key present"
            });
        }

        // Check for shredder tool directories in Program Files
        var programFiles   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var progFilesX86   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        foreach (var baseDir in new[] { programFiles, progFilesX86 })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;
            foreach (var shredDir in ShredderDirNames)
            {
                var fullPath = Path.Combine(baseDir, shredDir);
                if (Directory.Exists(fullPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "AntiForensicCleanerTool",
                        Title = $"Datei-Bereinigungstool '{shredDir}' installiert",
                        Risk = RiskLevel.Low,
                        Location = fullPath,
                        Reason = $"'{shredDir}' Verzeichnis gefunden. Im Kontext anderer Funde deutet dies auf " +
                                 "Anti-Forensik-Massnahmen zur Beweisvernichtung hin.",
                        Detail = $"Dir={fullPath}"
                    });
                }
            }
        }
    }

    // ─── O&O ShutUp10 / Windows10Privacy / Spybot Anti-Beacon ───────────────

    private static void ScanShutUp10AndPrivacyTools(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var appData  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var shutupDir = Path.Combine(appData, "O&O", "O&O ShutUp10");

        if (Directory.Exists(shutupDir))
        {
            ctx.AddFinding(new Finding
            {
                Module = "AntiForensicCleanerTool",
                Title = "O&O ShutUp10 Telemetrie-Blocker konfiguriert",
                Risk = RiskLevel.Medium,
                Location = shutupDir,
                Reason = "O&O ShutUp10 Konfigurationsverzeichnis gefunden. Kann Anti-Cheat-Telemetrie-Uebertragungen " +
                         "blockieren und diagnostische Pfade deaktivieren die von AC-Systemen verwendet werden.",
                Detail = $"ShutUp10Dir={shutupDir}"
            });
        }

        using var w10pKey = Registry.CurrentUser.OpenSubKey(@"Software\Windows10Privacy");
        if (w10pKey != null)
        {
            ctx.IncrementRegistryKeys(1);
            ctx.AddFinding(new Finding
            {
                Module = "AntiForensicCleanerTool",
                Title = "Windows10Privacy Telemetrie-Deaktivierung konfiguriert",
                Risk = RiskLevel.Medium,
                Location = @"HKCU\Software\Windows10Privacy",
                Reason = "Windows10Privacy-Konfiguration gefunden — kann AC-relevante Windows-Dienste und " +
                         "Telemetriepfade deaktivieren.",
                Detail = "Windows10Privacy registry key"
            });
        }

        using var spyKey = Registry.CurrentUser.OpenSubKey(@"Software\Safer-Networking\Spybot - Anti-Beacon");
        if (spyKey != null)
        {
            ctx.IncrementRegistryKeys(1);
            ctx.AddFinding(new Finding
            {
                Module = "AntiForensicCleanerTool",
                Title = "Spybot Anti-Beacon Telemetrie-Blocker gefunden",
                Risk = RiskLevel.Low,
                Location = @"HKCU\Software\Safer-Networking",
                Reason = "Spybot Anti-Beacon kann Windows-Diagnose-Telemetrie deaktivieren die von Anti-Cheats verwendet wird.",
                Detail = "Spybot Anti-Beacon registry key"
            });
        }

        // O&O AppBuster / Privacy Repairer
        using var ooKey = Registry.CurrentUser.OpenSubKey(@"Software\O&O Software");
        if (ooKey != null)
        {
            ctx.IncrementRegistryKeys(1);
            ctx.AddFinding(new Finding
            {
                Module = "AntiForensicCleanerTool",
                Title = "O&O Privacy-Tool-Suite konfiguriert",
                Risk = RiskLevel.Low,
                Location = @"HKCU\Software\O&O Software",
                Reason = "O&O Software Privacy-Suite Konfiguration. Diese Toolsuite kann Telemetrie-Dienste " +
                         "deaktivieren die fuer Anti-Cheat-Integritaetspruefungen relevant sind.",
                Detail = "O&O Software registry key"
            });
        }
    }

    // ─── File shredder temp files ─────────────────────────────────────────────

    private static void ScanFileShredderArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var tempPath = Path.GetTempPath();

        string[] shredExtensions = { ".shrd", ".shredded", ".erased", ".erazed", ".obliterated", ".zap" };

        try
        {
            foreach (var file in Directory.GetFiles(tempPath, "*", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (Array.IndexOf(shredExtensions, ext) >= 0)
                {
                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = "AntiForensicCleanerTool",
                        Title = "Datei-Shredder Temp-Datei gefunden",
                        Risk = RiskLevel.Low,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Shredder-Temp-Datei (Ext='{ext}') im Temp-Verzeichnis — Hinweis auf kuerzliche " +
                                 "Shredder-Aktivitaet zur Beweisvernichtung.",
                        Detail = $"Path={file}"
                    });
                }
            }
        }
        catch { }
    }

    // ─── Prefetch evidence of cleaner execution ───────────────────────────────

    private static void ScanPrefetchForCleanerExecution(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var pfFile in Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                var baseName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();

                foreach (var cleaner in CleanerPrefetchNames)
                {
                    var cleanerBase = Path.GetFileNameWithoutExtension(cleaner).ToUpperInvariant();
                    if (baseName.StartsWith(cleanerBase, StringComparison.Ordinal))
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "AntiForensicCleanerTool",
                            Title = $"Anti-Forensik-Tool ausgefuehrt (Prefetch): {cleaner}",
                            Risk = RiskLevel.Medium,
                            Location = pfFile,
                            FileName = Path.GetFileName(pfFile),
                            Reason = $"Prefetch-Datei beweist Ausfuehrung von '{cleaner}' — Anti-Forensik-Bereinigungstool. " +
                                     "Cheater fuehren Cleaners vor AC-Ueberpruefungen aus um Beweise zu vernichten.",
                            Detail = $"PrefetchFile={pfFile}"
                        });
                        break;
                    }
                }
            }
        }
        catch { /* Prefetch may require elevation */ }
    }
}
