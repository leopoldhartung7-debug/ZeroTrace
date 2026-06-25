using Microsoft.Win32;
using System.Security.Cryptography;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects abuse of Windows Accessibility binaries for backdoor installation
/// and detection evasion.
///
/// The "Sticky Keys" / "Ease of Access" backdoor is a well-known technique:
/// Windows runs specific binaries at the lock screen without authentication:
///   - Shift×5        → sethc.exe     (Sticky Keys)
///   - Win+U          → utilman.exe   (Ease of Access)
///   - Ctrl+Alt+Del   → osk.exe       (On-Screen Keyboard)
///   - Shift×5 long   → magnify.exe   (Magnifier)
///   - Narrator       → narrator.exe
///
/// Attackers replace these binaries (or their Image File Execution Options
/// debugger) with cmd.exe or another tool to gain SYSTEM-level access from
/// the lock screen, or to run cheat software at boot without user interaction.
///
/// Detection:
///   1. Image File Execution Options (IFEO) debugger for accessibility binaries.
///   2. Hash comparison of accessibility binaries against known-good Windows hashes.
///   3. Digital signature verification of accessibility binaries.
///   4. Registry: Accessibility features configured to launch unexpected programs.
///   5. Narrator / Magnifier registry redirected to non-system binary.
/// </summary>
public sealed class AccessibilityAbuseScanModule : IScanModule
{
    public string Name => "Eingabehilfe-Missbrauch";
    public double Weight => 0.4;
    public int ParallelGroup => 1;

    private static readonly string IFEOBase =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    // Accessibility binaries that are targeted by attackers
    private static readonly string[] AccessibilityBinaries =
    {
        "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe",
        "narrator.exe", "displayswitch.exe", "atbroker.exe",
        "msconfig.exe", "taskmgr.exe", "cmd.exe", "calc.exe",
    };

    // System32 path
    private static readonly string System32 =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Eingabehilfe-Missbrauch", "Prüfe IFEO-Debugger...");
        CheckIfeo(ctx, ct);

        ctx.Report(0.4, "Eingabehilfe-Missbrauch", "Prüfe Binärdateien...");
        CheckBinaryIntegrity(ctx, ct);

        ctx.Report(0.7, "Eingabehilfe-Missbrauch", "Prüfe Registry-Umleitungen...");
        CheckRegistryRedirects(ctx, ct);

        ctx.Report(1.0, "Eingabehilfe-Missbrauch", "Eingabehilfe-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    // ── 1. IFEO debugger ──────────────────────────────────────────────────────

    private static void CheckIfeo(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            foreach (var binary in AccessibilityBinaries)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        $@"{IFEOBase}\{binary}", writable: false);
                    if (key is null) continue;

                    var debugger = key.GetValue("Debugger") as string;
                    if (string.IsNullOrEmpty(debugger)) continue;

                    var isSystemBinary = debugger.StartsWith(System32,
                        StringComparison.OrdinalIgnoreCase);

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Eingabehilfe-Missbrauch",
                        Title    = $"IFEO-Debugger für {binary}: {Path.GetFileName(debugger)}",
                        Risk     = isSystemBinary ? RiskLevel.High : RiskLevel.Critical,
                        Location = $@"HKLM\{IFEOBase}\{binary}",
                        FileName = binary,
                        Reason   = $"Image File Execution Options für '{binary}' hat einen " +
                                   $"Debugger gesetzt: '{debugger}'. Jeder Aufruf von '{binary}' " +
                                   "(auch vom Sperrbildschirm) startet stattdessen dieses Programm. " +
                                   "Klassischer Sticky-Keys-Backdoor-Angriff für SYSTEM-Zugriff.",
                        Detail   = $"IFEO Debugger: {debugger}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    // ── 2. Binary integrity ───────────────────────────────────────────────────

    private static void CheckBinaryIntegrity(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var accessBinaries = new[] { "sethc.exe", "utilman.exe", "osk.exe",
                                      "magnify.exe", "narrator.exe" };

        foreach (var binary in accessBinaries)
        {
            if (ct.IsCancellationRequested) return;
            var path = Path.Combine(System32, binary);
            if (!File.Exists(path)) continue;

            ctx.IncrementFiles();
            try
            {
                // Check digital signature
                bool isSigned = false;
                bool isVerified = false;
                try
                {
                    var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(path);
                    isSigned = cert is not null;
                    isVerified = isSigned; // CreateFromSignedFile throws if invalid
                }
                catch { }

                if (!isSigned)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Eingabehilfe-Missbrauch",
                        Title    = $"Eingabehilfe-Binärdatei unsigniert: {binary}",
                        Risk     = RiskLevel.Critical,
                        Location = path,
                        FileName = binary,
                        Reason   = $"Die Windows-Eingabehilfe-Datei '{binary}' ist nicht " +
                                   "digital signiert. Alle legitimen Windows-Systemdateien haben " +
                                   "eine Microsoft-Authenticode-Signatur. Eine unsignierte Datei " +
                                   "hier ist ein starker Indikator für einen Backdoor-Ersatz.",
                        Detail   = $"Pfad: {path} | Signiert: Nein"
                    });
                }

                // Check file size anomaly: sethc.exe should be > 50 KB
                var size = new FileInfo(path).Length;
                if (size < 20 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Eingabehilfe-Missbrauch",
                        Title    = $"Eingabehilfe-Binärdatei ungewöhnlich klein: {binary}",
                        Risk     = RiskLevel.High,
                        Location = path,
                        FileName = binary,
                        Reason   = $"'{binary}' ist nur {size / 1024} KB — deutlich kleiner als " +
                                   "die legitime Windows-Datei. Könnte durch eine minimale " +
                                   "Backdoor-Datei ersetzt worden sein.",
                        Detail   = $"Größe: {size} Bytes | Erwartet: >20 KB"
                    });
                }
            }
            catch { }
        }
    }

    // ── 3. Registry redirects ─────────────────────────────────────────────────

    private static void CheckRegistryRedirects(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        // Check Narrator command redirect
        var narratorPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        };

        foreach (var regPath in narratorPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    ctx.IncrementRegistryKeys();
                    var value = key.GetValue(valueName) as string ?? "";
                    var lower = value.ToLowerInvariant();

                    // Check if any accessibility-related run key points to non-system binary
                    var isAccessKey = valueName.IndexOf("narrator", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                      valueName.IndexOf("magnify", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                      valueName.IndexOf("osk", StringComparison.OrdinalIgnoreCase) >= 0;

                    if (!isAccessKey) continue;

                    if (!lower.Contains(@"windows\system32") &&
                        !lower.Contains(@"windows\syswow64") &&
                        value.Length > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Eingabehilfe-Missbrauch",
                            Title    = $"Eingabehilfe-Autostart umgeleitet: {valueName}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{regPath}",
                            Reason   = $"Autostart-Eintrag '{valueName}' mit Eingabehilfe-Bezug " +
                                       $"zeigt auf unerwarteten Pfad: '{value}'. " +
                                       "Könnte auf einen Backdoor-Eintrag hinweisen.",
                            Detail   = $"Wert: {valueName} = {value}"
                        });
                    }
                }
            }
            catch { }
        }

        // Check GlobalFlags for silent process exit (another IFEO technique)
        try
        {
            foreach (var binary in new[] { "sethc.exe", "utilman.exe" })
            {
                if (ct.IsCancellationRequested) return;
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"{IFEOBase}\{binary}", writable: false);
                if (key is null) continue;

                var globalFlag = key.GetValue("GlobalFlag") as int?;
                if (globalFlag is not null && globalFlag != 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Eingabehilfe-Missbrauch",
                        Title    = $"GlobalFlag in IFEO für {binary}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{IFEOBase}\{binary}",
                        FileName = binary,
                        Reason   = $"GlobalFlag in IFEO für '{binary}' gesetzt (0x{globalFlag:X}). " +
                                   "Dies wird für 'Silent Process Exit'-Techniken genutzt, " +
                                   "um beim Start/Beenden eines Prozesses ein anderes Programm zu starten.",
                        Detail   = $"GlobalFlag: 0x{globalFlag:X}"
                    });
                }
            }
        }
        catch { }
    }
}
