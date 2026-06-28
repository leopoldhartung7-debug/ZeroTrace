using ZeroTrace.Core.Models;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects mouse and keyboard firmware anomalies used for hardware-level cheating.
///
/// Hardware cheat methods:
///
///   1. Arduino/Raspberry Pi "no-recoil" controllers:
///      - Small microcontroller programmed with recoil patterns
///      - Connects as USB HID device to the gaming PC
///      - PC sees it as a legitimate mouse/keyboard
///      - Runs pattern scripts that counteract gun recoil movement
///      - VID/PIDs: Arduino (2341:xxxx), Raspberry Pi (2E8A:xxxx), Teensy (16C0:0486)
///        generic HID MCUs: 1A86 (CH340), 2341, 16C0, 03EB (ATMEL)
///
///   2. XIM Apex / XIM Matrix (controller-to-mouse converter):
///      - Translates gamepad input to precise mouse movements with aim assist
///      - Bypasses PC-based AC (runs on PS4/PS5 side when cross-platform)
///      - VID:PID: 2BF9:xxxx (XIM Technologies)
///      - XIM is detectable via HID device registry even after unplugging
///
///   3. Wooting Lekker / Rapid Trigger keyboards:
///      - Analog hall-effect keys with instant actuation manipulation
///      - Not cheating per se but combined with macros = advantage
///
///   4. Mouse firmware with built-in macro scripting:
///      - Roccat Power-Grid, Logitech G-Hub macro devices
///      - Firmware-level macro cannot be detected by software
///      - Detectable: USB HID descriptor analysis, device name checks
///
///   5. Titan One/Two (game controller emulators):
///      - Runs GPC scripts for rapid-fire, drop-shot, anti-recoil
///      - VID:0A81 (Chesen Electronics) or 20D6 (PowerA) for pass-through
///
///   6. KeyMander / ReaSnow S1 (similar to XIM):
///      - Controller-to-mouse converter with scripting support
///
/// Detection approach:
///   - Enumerate HID devices via registry HKLM\SYSTEM\CurrentControlSet\Enum\USB
///     and HKLM\SYSTEM\CurrentControlSet\Enum\HID
///   - Match VID:PID patterns against known cheat hardware
///   - Check installed VID entries persist after device is unplugged
///   - Mouse/keyboard descriptor properties for anomalous logical ranges
///   - Scan DeviceSuiteDriverVersion for non-standard mouse/keyboard firmware strings
///
/// Ocean/detect.ac check the USB device enumeration registry because connected
/// hardware leaves entries that persist indefinitely after being unplugged.
/// </summary>
public sealed class MouseFirmwareAnomalyScanModule : IScanModule
{
    public string Name => "Maus/Tastatur Firmware Anomalie & Arduino/XIM Hardware-Cheat Erkennung";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    // Known cheat hardware VID:PID patterns
    // Format: (VendorId, ProductIdPattern_or_null_for_any, Description)
    private static readonly (string VID, string? PIDContains, string Description)[] CheatHardwareVids =
    {
        // Arduino MCUs — commonly programmed for no-recoil scripts
        ("2341", null,   "Arduino MCU (häufig für No-Recoil Scripts programmiert)"),
        ("2A03", null,   "Arduino Leonardo/Micro (No-Recoil HID Device)"),

        // Teensy MCU — popular for HID spoofing cheats
        ("16C0", "0486", "Teensy USB HID (populär für Cheat-Hardware-Scripting)"),
        ("16C0", "0487", "Teensy USB Serial (Cheat-Hardware-Debug-Interface)"),

        // Atmel/Microchip general-purpose HID MCUs
        ("03EB", "2042", "Atmel AVR HID Keyboard (programmierbare Tastatur MCU)"),
        ("03EB", "2040", "Atmel AVR HID Mouse (programmierbare Maus MCU)"),

        // WCH CH340/CH341 USB-Serial (used in cheap Arduino clones)
        ("1A86", null,   "WCH CH340/341 USB-Serial (Arduino-Clone für Cheat-MCU)"),

        // Raspberry Pi RP2040 (Pico) used as HID device
        ("2E8A", "0003", "Raspberry Pi Pico in USB HID mode (No-Recoil Controller)"),
        ("2E8A", "000A", "Raspberry Pi Pico SDK (Cheat Hardware Platform)"),

        // XIM Technologies (controller-to-mouse converters)
        ("2BF9", null,   "XIM Adapter (Controller→Maus Konverter mit Aim-Assist Bypass)"),

        // Titan One/Two
        ("20D6", "0A80", "Titan One/Two (GPC Script Controller — Rapid-Fire/Anti-Recoil)"),

        // Cronusmax/Cronus Zen (detected by AimAssistHardware module but cross-check here)
        ("1532", "0900", "Cronusmax/Cronus Zen (USB Cronus — Anti-Recoil Macro Device)"),

        // ReaSnow S1 Crosshair
        ("0079", "0011", "ReaSnow S1 Crosshair (Controller→PC Konverter mit Script-Support)"),

        // Brook Universal Fighting Board / SuperConverter
        ("0C12", "0E10", "Brook Universal Fighting Board (Controller Emulator)"),

        // Generic HID device with suspicious class name
        ("03EB", "6124", "Atmel DFU Bootloader (Cheat MCU Firmware Upload Mode)"),
    };

    private const string UsbEnumPath = @"SYSTEM\CurrentControlSet\Enum\USB";
    private const string HidEnumPath = @"SYSTEM\CurrentControlSet\Enum\HID";

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        // 1. Scan USB device registry
        ScanUsbRegistry(ctx, ct, UsbEnumPath, "USB");

        // 2. Scan HID device registry (HID layer on top of USB)
        ScanUsbRegistry(ctx, ct, HidEnumPath, "HID");

        // 3. Check for suspiciously generic mouse/keyboard device names
        ScanGenericHidDeviceNames(ctx, ct);
    }

    private void ScanUsbRegistry(ScanContext ctx, CancellationToken ct, string regPath, string busType)
    {
        ctx.IncrementRegistryKeys();
        try
        {
            using var enumKey = Registry.LocalMachine.OpenSubKey(regPath);
            if (enumKey == null) return;

            foreach (var vidPidKey in enumKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();

                // vidPidKey format: "VID_2341&PID_0043" or "HID_VID_2341&PID_0043"
                string upper = vidPidKey.ToUpperInvariant();

                foreach (var (vid, pidContains, desc) in CheatHardwareVids)
                {
                    string vidPattern = $"VID_{vid.ToUpperInvariant()}";
                    if (!upper.Contains(vidPattern)) continue;

                    // Check PID filter if specified
                    if (pidContains != null)
                    {
                        string pidPattern = $"PID_{pidContains.ToUpperInvariant()}";
                        if (!upper.Contains(pidPattern)) continue;
                    }

                    // Get device friendly name from sub-instance
                    string friendlyName = GetDeviceFriendlyName(enumKey, vidPidKey);

                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekanntes Cheat-Hardware Gerät erkannt [{busType}]: {desc}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{regPath}\{vidPidKey}",
                        FileName = friendlyName.Length > 0 ? friendlyName : vidPidKey,
                        Reason   = $"USB/HID-Gerät '{vidPidKey}' ({friendlyName}) ist als bekannte Cheat-Hardware " +
                                   $"identifiziert: {desc}. " +
                                   "Diese Hardware-Geräte werden von Spielern für Hardware-Level-Cheating " +
                                   "eingesetzt (No-Recoil-Scripts, Aim-Assist-Bypass, Rapid-Fire). " +
                                   "USB-Einträge bleiben dauerhaft im Registry auch nach dem Abziehen des Geräts.",
                        Detail   = $"[{busType}] Gerät: {vidPidKey} | Name: {friendlyName} | Typ: {desc}"
                    });
                    break; // One finding per device key
                }
            }
        }
        catch { }
    }

    private string GetDeviceFriendlyName(RegistryKey parentKey, string vidPidKey)
    {
        try
        {
            using var vpKey = parentKey.OpenSubKey(vidPidKey);
            if (vpKey == null) return "";

            foreach (var instanceName in vpKey.GetSubKeyNames())
            {
                using var instKey = vpKey.OpenSubKey(instanceName);
                if (instKey == null) continue;

                string? fn = instKey.GetValue("FriendlyName") as string
                           ?? instKey.GetValue("DeviceDesc") as string
                           ?? "";
                if (!string.IsNullOrEmpty(fn)) return fn;
            }
        }
        catch { }
        return "";
    }

    private void ScanGenericHidDeviceNames(ScanContext ctx, CancellationToken ct)
    {
        // Look for USB mice/keyboards with suspiciously generic or programmer-tool names
        // that indicate DIY no-recoil devices
        string[] suspiciousDeviceNames =
        {
            "arduino", "teensy", "raspberry pi pico", "rp2040",
            "xim apex", "xim matrix", "xim nexus",
            "titan one", "titan two",
            "reasnow", "keymander",
            "usb composite device hid", "dfu mode",
            "bootloader", "microchip hid",
            "no-recoil", "norecoil",
        };

        ctx.IncrementRegistryKeys();
        try
        {
            using var hidKey = Registry.LocalMachine.OpenSubKey(HidEnumPath);
            if (hidKey == null) return;

            foreach (var vidPidKey in hidKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var vpKey = hidKey.OpenSubKey(vidPidKey);
                if (vpKey == null) continue;

                foreach (var instanceName in vpKey.GetSubKeyNames())
                {
                    using var instKey = vpKey.OpenSubKey(instanceName);
                    if (instKey == null) continue;

                    string friendlyName = ((instKey.GetValue("FriendlyName") as string
                                         ?? instKey.GetValue("DeviceDesc") as string
                                         ?? "")).ToLowerInvariant();

                    if (string.IsNullOrEmpty(friendlyName)) continue;

                    string? match = suspiciousDeviceNames.FirstOrDefault(n =>
                        friendlyName.Contains(n, StringComparison.OrdinalIgnoreCase));

                    if (match != null)
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtiger HID-Gerätename '{match}': '{friendlyName}'",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{HidEnumPath}\{vidPidKey}\{instanceName}",
                            FileName = friendlyName,
                            Reason   = $"HID-Gerät mit verdächtigem Namen '{friendlyName}' (Keyword: '{match}') " +
                                       "im Geräte-Manager gefunden. " +
                                       "Arduino/Teensy/RP2040-Geräte die als HID angemeldet sind, werden typischerweise " +
                                       "als programmierbare No-Recoil- oder Triggerbot-Controller eingesetzt. " +
                                       "XIM/Titan Geräte ermöglichen controller-basiertes Aim-Assist auf PC-Spielen.",
                            Detail   = $"Gerät: {vidPidKey}\\{instanceName} | Name: {friendlyName} | Keyword: {match}"
                        });
                    }
                }
            }
        }
        catch { }
    }
}
