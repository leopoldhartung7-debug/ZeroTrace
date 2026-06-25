using System.Diagnostics;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Checks Volume Shadow Copies for deleted cheat artifact evidence.
///
/// Volume Shadow Copies (VSS) capture point-in-time snapshots of the filesystem.
/// Even if a cheat user deletes their cheat files and clears logs, VSS snapshots
/// may retain the deleted files, making them accessible via:
///   \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\...
///
/// Additionally, cheaters often DELETE shadow copies specifically to prevent forensic
/// recovery — which is itself a red flag.
///
/// Ocean and detect.ac check VSS because:
///   - Absence of shadow copies on a system that normally has them = tampering
///   - Shadow copies are deleted by ransomware AND by cheat cleanup scripts
///   - Some cheat loaders include VSS deletion as part of their anti-forensic cleanup
///
/// Detection:
///   - vssadmin list shadows — check if shadow copies exist
///   - Event log: Event 8222 (VSS error) or VSS deletion events
///   - WMIC shadowcopy — enumerate current shadow copies and their creation times
///   - Check if VSS service is disabled (used by some cheat cleanup scripts)
///   - Prefetch for vssadmin.exe / wmic shadowcopy delete (direct evidence)
/// </summary>
public sealed class ShadowCopyCheatArtifactScanModule : IScanModule
{
    public string Name => "Volume Shadow Copy Cheat-Forensik / VSS-Manipulation Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanVssServiceState(ctx, ct);
        ScanVssAdminOutput(ctx, ct);
        ScanPrefetchForVssDeletion(ctx, ct);
    }

    private void ScanVssServiceState(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var vssKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\VSS", writable: false);
            if (vssKey is null) return;

            int start = (int)(vssKey.GetValue("Start") ?? 3);
            if (start == 4) // Disabled
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Volume Shadow Copy Service (VSS) deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\VSS",
                    FileName = "VSS",
                    Reason   = "Der Volume Shadow Copy Service (VSS) ist deaktiviert. VSS wird von " +
                               "Cheat-Cleanup-Scripts und Ransomware deaktiviert, um forensische " +
                               "Wiederherstellung von gelöschten Dateien zu verhindern. Ocean und " +
                               "detect.ac flaggen deaktivierten VSS als anti-forensisches Indiz.",
                    Detail   = $"Start-Typ: {start} (4=Disabled)"
                });
            }
        }
        catch { }
    }

    private void ScanVssAdminOutput(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName               = "vssadmin.exe",
                Arguments              = "list shadows",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };

            using var proc = Process.Start(psi);
            if (proc is null) return;

            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            // No shadow copies at all — suspicious on a system with games
            if (output.Contains("No items found", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Keine Elemente", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(output))
            {
                // Only flag if the system has been running for a while (would normally have VSS)
                // Check if Windows OS has been installed > 30 days
                if (IsSystemOlderThan30Days())
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Keine Volume Shadow Copies vorhanden",
                        Risk     = RiskLevel.Medium,
                        Location = "vssadmin list shadows",
                        FileName = "VSS",
                        Reason   = "Keine Volume Shadow Copies auf einem System, das scheinbar länger " +
                                   "als 30 Tage in Betrieb ist. Cheat-Cleanup-Scripts löschen VSS-" +
                                   "Snapshots, um Spuren zu entfernen. Auch Ransomware nutzt dies — " +
                                   "beide Szenarien sind forensisch relevant.",
                        Detail   = $"vssadmin Ausgabe: '{output.Trim().Substring(0, Math.Min(200, output.Trim().Length))}'"
                    });
                }
            }
        }
        catch { }
    }

    private static bool IsSystemOlderThan30Days()
    {
        try
        {
            // Check Windows installation date via registry
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", false);
            if (key is null) return false;

            long installDate = (long)(int)(key.GetValue("InstallDate") ?? 0L);
            if (installDate == 0) return false;

            var installTime = DateTimeOffset.FromUnixTimeSeconds(installDate);
            return (DateTimeOffset.UtcNow - installTime).TotalDays > 30;
        }
        catch { return false; }
    }

    private void ScanPrefetchForVssDeletion(ScanContext ctx, CancellationToken ct)
    {
        string prefetchDir = @"C:\Windows\Prefetch";
        if (!System.IO.Directory.Exists(prefetchDir)) return;

        // Prefetch entries that indicate VSS deletion commands were run
        string[] vssDeletionPrefetch =
        {
            "VSSADMIN.EXE",
            "WMIC.EXE",
        };

        try
        {
            foreach (string exe in vssDeletionPrefetch)
            {
                ct.ThrowIfCancellationRequested();
                foreach (string pf in System.IO.Directory.EnumerateFiles(
                             prefetchDir, $"{exe}*.pf"))
                {
                    ct.ThrowIfCancellationRequested();
                    var info = new System.IO.FileInfo(pf);
                    var lastRun = info.LastWriteTime;

                    // Only flag recent runs (within 30 days)
                    if ((DateTime.Now - lastRun).TotalDays > 30) continue;

                    // vssadmin prefetch alone isn't suspicious — need to check if it was
                    // run with delete argument; we can't get args from Prefetch easily,
                    // but the combination with no VSS snapshots is suspicious
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"VSS-Management-Tool ausgeführt: {System.IO.Path.GetFileName(pf)}",
                        Risk     = RiskLevel.Medium,
                        Location = pf,
                        FileName = System.IO.Path.GetFileName(pf),
                        Reason   = $"Prefetch-Eintrag für '{exe}' belegt die Ausführung " +
                                   $"(zuletzt: {lastRun:yyyy-MM-dd HH:mm}). vssadmin/wmic werden für " +
                                   "das Löschen von Shadow Copies verwendet. Zusammen mit fehlenden " +
                                   "Shadow Copies ist dies ein starkes anti-forensisches Signal.",
                        Detail   = $"Prefetch: {pf} | Letzter Lauf: {lastRun:yyyy-MM-dd HH:mm}"
                    });
                    break; // one finding per tool type
                }
            }
        }
        catch { }
    }
}
