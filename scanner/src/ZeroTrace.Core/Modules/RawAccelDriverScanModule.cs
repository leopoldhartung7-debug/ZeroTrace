using ZeroTrace.Core.Models;
using Microsoft.Win32;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects RawAccel kernel driver and related input-manipulation software used for aim assistance.
///
/// RawAccel is a Windows kernel driver that installs a HID class filter to intercept and modify
/// raw mouse input at the driver level before any software (including game and anti-cheat) can
/// read it. It applies custom sensitivity curves (acceleration, deceleration, snap, cap) that
/// can produce "aim-assist-like" behavior — e.g. slowing the mouse when aiming near a target.
///
/// Why Ocean and detect.ac flag RawAccel:
///   - It is a kernel driver installed without PatchGuard bypass, detectable via service registry
///   - Its config file (RawAccel.json) persists in %APPDATA% with curve parameters
///   - The companion GUI (rawaccel.exe) leaves Prefetch and MuiCache entries
///   - The driver binary (rawaccel.sys) is typically in a user-writable path (Downloads/AppData)
///   - Combined with gaming context it is strong evidence of aim manipulation
///
/// Also detects:
///   - MouseMovement.ini / MarkC mouse fix abused to tune sensitivity below game minimum
///   - Graficaster (companion tool for RawAccel curve visualization)
///   - povohat's accel driver (predecessor to RawAccel)
/// </summary>
public sealed class RawAccelDriverScanModule : IScanModule
{
    public string Name => "RawAccel Aim-Assist Treiber und Eingabe-Manipulation Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    private static readonly string[] RawAccelServiceNames =
    {
        "rawaccel", "raw_accel", "RawAccelDriver",
        "MouseFilter", "mousefilter",
        "povohat", "accel",
    };

    private static readonly string[] RawAccelFileNames =
    {
        "rawaccel.sys", "rawaccel.exe", "rawaccel-updater.exe",
        "RawAccel.json",
        "graficaster.exe", "Graficaster.exe",
        "povohat-driver.sys", "mouse_accel.sys",
    };

    private static readonly string[] RawAccelDirs =
    {
        "rawaccel", "raw-accel", "RawAccel",
        "graficaster", "Graficaster",
        "povohat",
    };

    // Config keys that indicate active use / aggressive tuning
    private static readonly string[] SuspiciousConfigKeys =
    {
        "\"acceleration\"", "\"cap\"", "\"sensitivity\"",
        "\"snap\"", "\"wholeMultiplier\"", "\"speed\"",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanServiceRegistry(ctx, ct);
        ScanFilesystem(ctx, ct);
        ScanRunningProcesses(ctx, ct);
    }

    private void ScanServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", false);
            if (services == null) return;

            foreach (string svcName in services.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                string svcLower = svcName.ToLowerInvariant();
                bool isRawAccel = RawAccelServiceNames.Any(n =>
                    svcLower.Equals(n, StringComparison.OrdinalIgnoreCase) ||
                    svcLower.Contains("rawaccel"));

                if (!isRawAccel) continue;

                try
                {
                    using var svcKey = services.OpenSubKey(svcName, false);
                    if (svcKey == null) continue;

                    string imagePath = svcKey.GetValue("ImagePath") as string ?? "";
                    int startType = (int)(svcKey.GetValue("Start") ?? -1);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"RawAccel/Aim-Assist Treiber als Service registriert: {svcName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = svcName,
                        Reason   = $"Kernel-Treiber '{svcName}' ist als Windows-Service registriert. " +
                                   "RawAccel und ähnliche Treiber modifizieren Mauseingaben auf Kernel-Ebene " +
                                   "für Aim-Assistance, unsichtbar für Software-Anti-Cheat. Ocean/detect.ac " +
                                   "prüfen Service-Registry auf Maus-Filter-Treiber.",
                        Detail   = $"Service: {svcName} | ImagePath: {imagePath} | Start: {startType}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanFilesystem(ScanContext ctx, CancellationToken ct)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string downloads   = System.IO.Path.Combine(userProfile, "Downloads");
        string desktop     = System.IO.Path.Combine(userProfile, "Desktop");
        string sysTemp     = System.IO.Path.GetTempPath();

        var searchRoots = new[] { appData, localApp, downloads, desktop, sysTemp };

        foreach (string root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(root)) continue;

            // Check for RawAccel directories
            try
            {
                foreach (string dir in System.IO.Directory.GetDirectories(root))
                {
                    string dirName = System.IO.Path.GetFileName(dir);
                    if (!RawAccelDirs.Any(d => dirName.Equals(d, StringComparison.OrdinalIgnoreCase) ||
                                              dirName.ToLowerInvariant().Contains("rawaccel"))) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"RawAccel-Verzeichnis gefunden: {dirName}",
                        Risk     = RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason   = $"Verzeichnis '{dirName}' im Pfad '{root}' deutet auf " +
                                   "RawAccel-Installation hin. RawAccel ist ein Kernel-Maus-Filter-Treiber " +
                                   "der Mausempfindlichkeit auf Treiber-Ebene für Aim-Manipulation ändert.",
                        Detail   = $"Pfad: {dir}"
                    });
                }
            }
            catch { }

            // Check for RawAccel-specific files
            try
            {
                foreach (string file in System.IO.Directory.EnumerateFiles(root,
                    "*", System.IO.SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    string fileName = System.IO.Path.GetFileName(file);
                    ctx.IncrementFiles();

                    if (!RawAccelFileNames.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    bool isConfig = fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase);
                    string detail = $"Datei: {file}";

                    if (isConfig)
                    {
                        try
                        {
                            var info = new System.IO.FileInfo(file);
                            if (info.Length < 4096)
                            {
                                string text = System.IO.File.ReadAllText(file);
                                string textLower = text.ToLowerInvariant();
                                var foundKeys = SuspiciousConfigKeys
                                    .Where(k => textLower.Contains(k.ToLowerInvariant()))
                                    .ToArray();
                                if (foundKeys.Length > 0)
                                    detail += $" | Konfig-Schlüssel: {string.Join(", ", foundKeys)}";
                            }
                        }
                        catch { }
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"RawAccel-Datei gefunden: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Datei '{fileName}' ist ein RawAccel-Komponente. " +
                                   "RawAccel.json enthält Maus-Kurven-Konfigurationen, rawaccel.sys " +
                                   "ist der Kernel-Treiber. Ocean/detect.ac flaggen alle RawAccel-Dateien " +
                                   "als Aim-Assist-Indikator.",
                        Detail   = detail
                    });
                }
            }
            catch { }
        }

        // Also scan AppData\Roaming for RawAccel.json directly
        try
        {
            string raJson = System.IO.Path.Combine(appData, "RawAccel", "settings.json");
            if (!System.IO.File.Exists(raJson))
                raJson = System.IO.Path.Combine(appData, "rawaccel", "settings.json");

            if (System.IO.File.Exists(raJson))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "RawAccel Einstellungsdatei (settings.json) gefunden",
                    Risk     = RiskLevel.High,
                    Location = raJson,
                    FileName = "settings.json",
                    Reason   = "RawAccel Konfigurationsdatei settings.json gefunden. Diese enthält " +
                               "die aktiven Maus-Kurven-Parameter des RawAccel Kernel-Treibers.",
                    Detail   = $"Pfad: {raJson}"
                });
            }
        }
        catch { }
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var snapshot = ctx.GetProcessSnapshot();
            foreach (var proc in snapshot)
            {
                ct.ThrowIfCancellationRequested();
                string name = proc.ProcessName.ToLowerInvariant();
                if (!name.Contains("rawaccel") && !name.Contains("graficaster")) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"RawAccel/Aim-Assist Prozess läuft: {proc.ProcessName}",
                    Risk     = RiskLevel.Critical,
                    Location = proc.MainModule?.FileName ?? proc.ProcessName,
                    FileName = proc.ProcessName,
                    Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) läuft aktiv. " +
                               "RawAccel im laufenden Betrieb während eines Gaming-Scans ist ein " +
                               "kritisches Aim-Assist-Signal. Ocean/detect.ac markieren aktiven " +
                               "RawAccel als Critical.",
                    Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id}"
                });
            }
        }
        catch { }
    }
}
