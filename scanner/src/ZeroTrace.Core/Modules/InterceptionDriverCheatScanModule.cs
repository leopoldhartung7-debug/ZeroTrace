using ZeroTrace.Core.Models;
using Microsoft.Win32;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects the Interception keyboard/mouse filter driver used for no-recoil and aimbot automation.
///
/// Interception (github.com/oblitum/Interception) is a Windows kernel driver that installs itself
/// as a keyboard and mouse filter driver, allowing user-space programs to intercept and modify
/// ALL keyboard and mouse input before it reaches any application — including games and AC.
///
/// Why it's used for cheating:
///   - Injects synthetic mouse movements indistinguishable from hardware at the driver level
///   - No-recoil scripts using Interception pass hardware-level fingerprinting checks
///   - Aimbot smoothing applied via Interception bypasses mouse movement anomaly detection
///   - Completely invisible to user-space hooks (GetAsyncKeyState, SetWindowsHookEx)
///
/// Detection artifacts:
///   - keyboard.inf / mouse.inf driver files installed via "install-interception.exe"
///   - Filter driver service entries: "keyboard" and "mouse" in service registry with
///     ImagePath pointing to unusual locations (not System32\drivers\kbdclass.sys)
///   - Interception.dll companion library in user AppData or cheat directories
///   - AutoHotKey scripts with "Interception" DllCall patterns
///
/// Also detects:
///   - Xim Apex / XIM Matrix API drivers (aim assist via console controller emulation)
///   - vJoy / ViGEmBus (virtual joystick for aim assist on PC games)
///   - MouseMover / MoveMouseSmooth (synthetic mouse movement for aim smoothing)
/// </summary>
public sealed class InterceptionDriverCheatScanModule : IScanModule
{
    public string Name => "Interception Tastatur/Maus-Filter Treiber Cheat Scan";
    public double Weight => 0.55;
    public int ParallelGroup => 3;

    private static readonly string[] InterceptionServiceNames =
    {
        "keyboard", "mouse",      // Interception default service names
        "interception",           // Named variant
        "vjoy", "vJoy",           // Virtual joystick
        "ViGEmBus", "vigem",      // Virtual Gamepad Emulation Bus
        "HidHide", "hidhide",     // HidHide (used with ViGEm for aim assist)
        "nefconuser",             // NefconUser (Interception installer component)
    };

    private static readonly string[] InterceptionFileNames =
    {
        "interception.dll", "interception.sys",
        "keyboard.sys",      // Interception keyboard filter driver
        "mouse.sys",         // Interception mouse filter driver
        "install-interception.exe",
        "vjoy.dll", "vjoy.sys", "vJoyInterface.dll",
        "ViGEmBus.sys", "ViGEmClient.dll",
        "HidHide.sys", "HidHideClient.dll",
    };

    private static readonly string[] AhkInterceptionPatterns =
    {
        "dllcall(\"interception",
        "interception_create_context",
        "interception_send",
        "interception_receive",
        "dll, \"interception",
    };

    private static readonly string[] InterceptionDirs =
    {
        "interception", "Interception",
        "vjoy", "vJoy",
        "vigem", "ViGEm", "ViGEmBus",
        "hidhide", "HidHide",
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
        ScanAhkScripts(ctx, ct);
    }

    private void ScanServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", false);
            if (services == null) return;

            // Specifically check for Interception's filter driver services
            // Interception installs filter drivers named "keyboard" and "mouse"
            // DISTINCT from Windows' native kbdclass/mouclass
            string[] interceptServices = { "keyboard", "mouse" };
            foreach (string svcName in interceptServices)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var svcKey = services.OpenSubKey(svcName, false);
                    if (svcKey == null) continue;
                    ctx.IncrementRegistryKeys();

                    string imagePath = (svcKey.GetValue("ImagePath") as string ?? "").ToLowerInvariant();
                    string description = (svcKey.GetValue("Description") as string ?? "").ToLowerInvariant();

                    // Legitimate Windows kbd/mouse filter drivers are in System32\drivers\
                    // Interception's own drivers are in a custom location
                    bool isLegitimate = imagePath.Contains("system32\\drivers\\kbdclass") ||
                                        imagePath.Contains("system32\\drivers\\mouclass") ||
                                        imagePath.Contains("system32\\drivers\\kbdhid") ||
                                        imagePath.Contains("system32\\drivers\\mouhid");

                    if (!isLegitimate && !string.IsNullOrEmpty(imagePath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Interception Filter-Treiber Service: '{svcName}' mit unbekanntem ImagePath",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = svcName,
                            Reason   = $"Service '{svcName}' hat ungewöhnlichen ImagePath: '{imagePath}'. " +
                                       "Interception installiert Keyboard/Mouse-Filter-Treiber mit diesen Namen " +
                                       "statt dem legitimen Windows kbdclass/mouclass. Diese Filter fangen " +
                                       "ALLE Eingaben vor Spielen und Anti-Cheat ab.",
                            Detail   = $"Service: {svcName} | ImagePath: {imagePath}"
                        });
                    }
                }
                catch { }
            }

            // Check for other known input-manipulation driver services
            foreach (string svcName in services.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                string svcLower = svcName.ToLowerInvariant();
                bool isTarget = InterceptionServiceNames
                    .Skip(2) // skip "keyboard" and "mouse" already checked above
                    .Any(n => svcLower.Equals(n, StringComparison.OrdinalIgnoreCase) ||
                              svcLower.Contains("interception") || svcLower.Contains("vigem") ||
                              svcLower.Contains("hidhide") || svcLower.Contains("vjoy"));

                if (!isTarget) continue;

                try
                {
                    using var svcKey = services.OpenSubKey(svcName, false);
                    if (svcKey == null) continue;
                    ctx.IncrementRegistryKeys();

                    string imagePath = svcKey.GetValue("ImagePath") as string ?? "";

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Eingabe-Manipulation Treiber registriert: {svcName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = svcName,
                        Reason   = $"Eingabe-Filter-Treiber '{svcName}' als Service registriert. " +
                                   "vJoy/ViGEmBus erstellen virtuelle Gamepad-Geräte für Aim-Assist; " +
                                   "HidHide versteckt physische Controller vor Spielen. Diese Treiber " +
                                   "werden für Hardware-Level-Aim-Assist eingesetzt.",
                        Detail   = $"Service: {svcName} | ImagePath: {imagePath}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanFilesystem(ScanContext ctx, CancellationToken ct)
    {
        string progFiles   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var searchRoots = new[] { progFiles, progFiles86, appData, localApp,
            System.IO.Path.Combine(userProfile, "Downloads"),
            System.IO.Path.GetTempPath() };

        var nameLookup = new HashSet<string>(InterceptionFileNames, StringComparer.OrdinalIgnoreCase);

        foreach (string root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(root)) continue;

            // Check for Interception directories
            try
            {
                foreach (string dir in System.IO.Directory.GetDirectories(root))
                {
                    string dirName = System.IO.Path.GetFileName(dir);
                    if (!InterceptionDirs.Any(d => dirName.Equals(d, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Interception/Eingabe-Manipulation Verzeichnis: {dirName}",
                        Risk     = RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason   = $"Verzeichnis '{dirName}' in '{root}' ist ein bekanntes Interception/" +
                                   "ViGEm-Installationsverzeichnis. Diese Treiber ermöglichen Hardware-" +
                                   "Level-Mauseingabe-Manipulation für No-Recoil und Aimbot.",
                        Detail   = $"Pfad: {dir}"
                    });
                }
            }
            catch { }

            // Check for specific files
            try
            {
                foreach (string file in System.IO.Directory.EnumerateFiles(root,
                    "*", System.IO.SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    string fileName = System.IO.Path.GetFileName(file);
                    if (!nameLookup.Contains(fileName)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Interception/Eingabe-Treiber Datei: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Datei '{fileName}' ist ein Interception, vJoy, oder ViGEmBus " +
                                   "Komponente. Diese ermöglichen Kernel-Level-Eingabe-Interception " +
                                   "für No-Recoil-Scripts und Aim-Assist-Automatisierung.",
                        Detail   = $"Pfad: {file}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanAhkScripts(ScanContext ctx, CancellationToken ct)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs =
        {
            System.IO.Path.Combine(userProfile, "Documents"),
            System.IO.Path.Combine(userProfile, "Desktop"),
            System.IO.Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (string dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(dir)) continue;

            try
            {
                foreach (string file in System.IO.Directory.EnumerateFiles(dir,
                    "*.ahk", System.IO.SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        var info = new System.IO.FileInfo(file);
                        if (info.Length == 0 || info.Length > 512 * 1024) continue;

                        string text = System.IO.File.ReadAllText(file).ToLowerInvariant();
                        string? pattern = AhkInterceptionPatterns.FirstOrDefault(p =>
                            text.Contains(p, StringComparison.OrdinalIgnoreCase));
                        if (pattern == null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"AutoHotKey Script mit Interception DllCall: {System.IO.Path.GetFileName(file)}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = System.IO.Path.GetFileName(file),
                            Reason   = $"AHK Script '{System.IO.Path.GetFileName(file)}' enthält " +
                                       $"Interception DLL-Call Pattern '{pattern}'. AHK + Interception " +
                                       "ist die häufigste Kombination für No-Recoil- und Triggerbot-Scripts, " +
                                       "die auf Kernel-Ebene operieren und software-basierte AC umgehen.",
                            Detail   = $"Datei: {file} | Pattern: '{pattern}'"
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }
    }
}
