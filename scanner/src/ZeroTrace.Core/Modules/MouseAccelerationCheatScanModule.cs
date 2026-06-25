using System.Runtime.InteropServices;
using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects mouse parameter manipulation used to implement no-recoil and aim assistance
/// at the HID (Human Interface Device) driver level — outside the game process.
///
/// HID-level no-recoil works by:
///   1. Modifying Windows mouse acceleration curves to inject counter-movement:
///      When the game generates weapon recoil (upward screen movement), the cheat
///      intercepts mouse events via HID filter driver or raw input hook and adds
///      downward micro-adjustments that exactly cancel the recoil pattern.
///
///   2. SmoothMouseXCurve / SmoothMouseYCurve registry values:
///      Windows stores bezier curve control points for mouse acceleration as 10-byte
///      arrays per axis under HKCU\Control Panel\Mouse. These curves define how
///      physical mouse movement maps to cursor movement. Unusual values indicate
///      a cheat tool has modified these to implement aim snapping or recoil control.
///
///   3. MouseSensitivity set to 0 or extremes:
///      Some cheat tools set mouse sensitivity to 0 to disable Windows acceleration
///      entirely and implement their own raw-input-based movement, or to 20 (maximum)
///      for aimbot snap sensitivity.
///
///   4. RawInput device filter registrations (RIDEV_INPUTSINK) from non-game processes:
///      Raw input registrations persist across focus changes (RIDEV_INPUTSINK flag).
///      Non-game processes with RIDEV_INPUTSINK on mouse input are suspicious.
///
///   5. HID filter drivers:
///      Upper/lower filter drivers installed on the HID mouse device stack
///      (HKLM\SYSTEM\CurrentControlSet\Control\Class\{745a17a0...}\UpperFilters)
///      that aren't part of known legitimate HID drivers.
/// </summary>
public sealed class MouseAccelerationCheatScanModule : IScanModule
{
    public string Name => "Mouse Acceleration / HID-Level No-Recoil Cheat Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    [DllImport("user32.dll")]
    private static extern bool SystemParametersInfo(uint uiAction, uint uiParam,
        nint pvParam, uint fWinIni);

    private const uint SPI_GETMOUSE            = 0x0003;
    private const uint SPI_GETMOUSESPEED       = 0x0070;
    private const uint SPI_GETMOUSEVANISHPOINT = 0x1020;

    // Registry paths for mouse settings
    private const string MouseControlPanelKey = @"Control Panel\Mouse";
    private const string MouseInputKey = @"SYSTEM\CurrentControlSet\Services\mouclass\Parameters";
    private const string HidMouseClassKey = @"SYSTEM\CurrentControlSet\Control\Class\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}";

    // Known legitimate HID filter drivers
    private static readonly HashSet<string> LegitHidFilters = new(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft
        "kbdclass", "mouclass", "HidUsb", "HidBth", "hidbth", "HidIr",
        "mouhid", "kbdhid", "HidInterrupt", "HidLowVoltage",
        // Razer
        "RzDev", "RazerHid", "RazerHidFilter", "RzFilter",
        // Logitech
        "LGSHidFilter", "LGHidFilter", "LGHID",
        // SteelSeries
        "SSHidFilter",
        // Corsair
        "CuHidFilter",
        // Accessibility
        "accessibilityfilter",
        // Input recording (legit)
        "NtInputRecord",
    };

    // Suspicious HID filter driver name patterns
    private static readonly string[] SuspiciousHidFilterPatterns =
    {
        "cheat", "hack", "norecoi", "aim", "spoof",
        "inject", "bypass", "hook", "filter", "intercept",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckMouseRegistrySettings(ctx, ct);
            ct.ThrowIfCancellationRequested();
            CheckHidFilterDrivers(ctx, ct);
            ct.ThrowIfCancellationRequested();
            CheckMouseDriverParameters(ctx, ct);
        }, ct);
    }

    private static void CheckMouseRegistrySettings(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var mouseKey = Registry.CurrentUser.OpenSubKey(MouseControlPanelKey);
            if (mouseKey is null) return;

            ctx.IncrementRegistryKeys();

            // Check MouseSensitivity (valid range 1-20, default 10)
            string? sensitivity = mouseKey.GetValue("MouseSensitivity") as string;
            if (sensitivity is not null && int.TryParse(sensitivity, out int sens))
            {
                if (sens == 0 || sens > 19)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Mouse Acceleration / HID-Level No-Recoil Cheat Detection",
                        Title    = $"Ungewöhnliche Maussensitivität: {sens}",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKCU\{MouseControlPanelKey}\MouseSensitivity",
                        FileName = "MouseSensitivity",
                        Reason   = $"Maussensitivität auf {sens} gesetzt (Normal: 1-20, Standard: 10) — " +
                                   "Wert 0 oder Extremwerte werden von No-Recoil-Cheats gesetzt die Windows-" +
                                   "Beschleunigung deaktivieren und eigene Bewegungskorrektur implementieren",
                        Detail   = $"MouseSensitivity: {sens}"
                    });
                }
            }

            // Check MouseSpeed (0=no acceleration, 1=standard, 2=double precision)
            string? speed = mouseKey.GetValue("MouseSpeed") as string;
            if (speed is not null && int.TryParse(speed, out int spd))
            {
                if (spd < 0 || spd > 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Mouse Acceleration / HID-Level No-Recoil Cheat Detection",
                        Title    = $"Ungültiger MouseSpeed-Wert: {spd}",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKCU\{MouseControlPanelKey}\MouseSpeed",
                        FileName = "MouseSpeed",
                        Reason   = $"MouseSpeed auf {spd} gesetzt (gültig: 0-2) — " +
                                   "ungültige Werte können von Cheat-Tools hinterlassen werden",
                        Detail   = $"MouseSpeed: {spd}"
                    });
                }
            }

            // Check SmoothMouseXCurve / SmoothMouseYCurve
            // These are 40-byte arrays (5 x 8-byte points) defining bezier curves
            // Normal curves are zero (disabled) or the Windows default progression
            byte[]? xCurve = mouseKey.GetValue("SmoothMouseXCurve") as byte[];
            byte[]? yCurve = mouseKey.GetValue("SmoothMouseYCurve") as byte[];

            if (xCurve is not null || yCurve is not null)
            {
                bool isModified = false;

                // The default Windows SmoothMouseXCurve: all zeros or standard MS values
                // Any non-zero, non-default value is suspicious
                byte[] defaultXCurve =
                {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x40, 0x66, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,
                };

                byte[] allZero = new byte[40];

                if (xCurve is not null && xCurve.Length == 40)
                {
                    isModified = !xCurve.SequenceEqual(defaultXCurve) && !xCurve.SequenceEqual(allZero);
                }

                if (isModified)
                {
                    string hexCurve = xCurve is not null
                        ? BitConverter.ToString(xCurve.Take(20).ToArray())
                        : "";

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Mouse Acceleration / HID-Level No-Recoil Cheat Detection",
                        Title    = "Modifizierte Maus-Beschleunigungskurve (SmoothMouseXCurve)",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\{MouseControlPanelKey}\SmoothMouseXCurve",
                        FileName = "SmoothMouseXCurve",
                        Reason   = "Windows Maus-Beschleunigungskurve (SmoothMouseXCurve) enthält nicht-Standard-Werte — " +
                                   "HID-Level-No-Recoil-Cheats modifizieren diese Bezier-Kurven um Waffenrückstoß " +
                                   "durch Anti-Bewegungs-Kompensation auf Treiber-Ebene zu eliminieren",
                        Detail   = $"Kurve (erste 20 Bytes hex): {hexCurve}"
                    });
                }
            }

            // Check MouseThreshold values (acceleration threshold)
            string? thresh1 = mouseKey.GetValue("MouseThreshold1") as string;
            string? thresh2 = mouseKey.GetValue("MouseThreshold2") as string;

            if (thresh1 is not null && int.TryParse(thresh1, out int t1) && t1 < 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Mouse Acceleration / HID-Level No-Recoil Cheat Detection",
                    Title    = $"Negativer MouseThreshold1-Wert: {t1}",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKCU\{MouseControlPanelKey}\MouseThreshold1",
                    FileName = "MouseThreshold1",
                    Reason   = $"MouseThreshold1 auf negativen Wert {t1} gesetzt — ungültig und " +
                               "könnte von Cheat-Tool zum Deaktivieren der Beschleunigung hinterlassen sein",
                    Detail   = $"MouseThreshold1: {t1} | MouseThreshold2: {thresh2}"
                });
            }
        }
        catch { }
    }

    private static void CheckHidFilterDrivers(ScanContext ctx, CancellationToken ct)
    {
        // Check for suspicious HID filter drivers on mouse device class
        try
        {
            using var hidClass = Registry.LocalMachine.OpenSubKey(HidMouseClassKey);
            if (hidClass is null) return;

            ctx.IncrementRegistryKeys();

            // Check UpperFilters and LowerFilters at the class level
            CheckFilterList(hidClass, "UpperFilters", HidMouseClassKey, ctx);
            CheckFilterList(hidClass, "LowerFilters", HidMouseClassKey, ctx);

            // Also check individual device instances
            foreach (var subName in hidClass.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                if (!char.IsDigit(subName[0])) continue; // instance numbers are digit strings

                try
                {
                    using var instKey = hidClass.OpenSubKey(subName);
                    if (instKey is null) continue;
                    ctx.IncrementRegistryKeys();
                    CheckFilterList(instKey, "UpperFilters", $@"{HidMouseClassKey}\{subName}", ctx);
                    CheckFilterList(instKey, "LowerFilters", $@"{HidMouseClassKey}\{subName}", ctx);
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CheckFilterList(RegistryKey key, string valueName,
        string keyPath, ScanContext ctx)
    {
        try
        {
            var filters = key.GetValue(valueName) as string[];
            if (filters is null) return;

            foreach (var filter in filters)
            {
                if (string.IsNullOrWhiteSpace(filter)) continue;
                if (LegitHidFilters.Contains(filter)) continue;

                string filterLow = filter.ToLowerInvariant();
                string? suspPattern = Array.Find(SuspiciousHidFilterPatterns,
                    p => filterLow.Contains(p));

                bool isSuspiciousName = suspPattern is not null;

                // Any non-legit filter in the HID mouse class is suspicious
                ctx.AddFinding(new Finding
                {
                    Module   = "Mouse Acceleration / HID-Level No-Recoil Cheat Detection",
                    Title    = $"Nicht-legitimer HID-Maustreiber-Filter: {filter}",
                    Risk     = isSuspiciousName ? RiskLevel.Critical : RiskLevel.High,
                    Location = $@"HKLM\{keyPath}\{valueName}",
                    FileName = filter,
                    Reason   = $"HID-Maus-Filter-Treiber '{filter}' in {valueName} der Maus-Geräteklasse " +
                               "ist nicht als legitimer Peripherie-Treiber bekannt — " +
                               "No-Recoil-Cheats installieren sich als HID-Upper/Lower-Filter um alle " +
                               "Mausbewegungen abzufangen und anti-recoil Korrekturen einzuspritzen " +
                               "bevor die Daten das Spiel erreichen",
                    Detail   = $"Filter: {filter} | Typ: {valueName} | Pfad: {keyPath} | " +
                               $"Cheat-Muster: {suspPattern ?? "unbekannt"}"
                });
            }
        }
        catch { }
    }

    private static void CheckMouseDriverParameters(ScanContext ctx, CancellationToken ct)
    {
        // Check mouclass Parameters for unusual settings
        try
        {
            using var moClass = Registry.LocalMachine.OpenSubKey(MouseInputKey);
            if (moClass is null) return;

            ctx.IncrementRegistryKeys();

            // MouseDataQueueSize: normally 100, set to 0 or very large = suspicious
            object? queueSize = moClass.GetValue("MouseDataQueueSize");
            if (queueSize is int qs && (qs == 0 || qs > 10000))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Mouse Acceleration / HID-Level No-Recoil Cheat Detection",
                    Title    = $"Ungewöhnliche MouseDataQueueSize: {qs}",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKLM\{MouseInputKey}\MouseDataQueueSize",
                    FileName = "MouseDataQueueSize",
                    Reason   = $"mouclass-Parameter MouseDataQueueSize auf {qs} gesetzt " +
                               "(Normal: 100) — ungewöhnliche Werte können von Cheat-Treibern " +
                               "zur Manipulation des Maus-Input-Puffers hinterlassen werden",
                    Detail   = $"MouseDataQueueSize: {qs}"
                });
            }
        }
        catch { }
    }
}
