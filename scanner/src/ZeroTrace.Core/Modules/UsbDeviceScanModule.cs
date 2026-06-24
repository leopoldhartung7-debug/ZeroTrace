using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Inspects the Windows USB device history (HKLM\SYSTEM\...\Enum\USB) for
/// hardware that is commonly used as a physical ("hardware") cheat device:
/// Arduino, Teensy, Raspberry Pi, and compatible microcontrollers. These are
/// used as HID-emulating triggerbot, rapid-fire, or macro devices that avoid
/// software-based anti-cheat entirely. The registry retains a history of ALL
/// ever-connected USB devices — even unplugged ones. Read-only.
/// </summary>
public sealed class UsbDeviceScanModule : IScanModule
{
    public string Name => "USB-Geraete";
    public double Weight => 0.3;
    public int ParallelGroup => 1; // registry-read only

    // Known VID prefixes for microcontroller / Arduino-ecosystem boards.
    // These appear in the sub-key name "VID_XXXX&PID_YYYY".
    private static readonly string[] SuspiciousVids =
    {
        "VID_2341", // Arduino LLC (genuine)
        "VID_16C0", // Van Ooijen Technische Informatica (Teensy)
        "VID_2E8A", // Raspberry Pi Foundation
        "VID_1B4F", // SparkFun Electronics
        "VID_239A", // Adafruit Industries
        "VID_0483", // STMicroelectronics (STM32 in DFU / HID mode)
        "VID_1A86", // QinHeng Electronics CH340/CH341 (clone Arduino boards)
        "VID_2886", // Seeed Studio (Seeeduino)
    };

    // Keyword fragments matched against FriendlyName / DeviceDesc / Mfg values.
    private static readonly string[] SuspiciousKeywords =
    {
        "arduino", "teensy", "raspberry pi", "rpi pico", "seeeduino",
        "digispark", "pro micro", "leonardo", "micro-usb hid", "atmega32u4",
        "stm32", "nucleo", "bluepill", "maple", "keyboardio"
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        try { CheckUsbHistory(ctx, ct); }
        catch { }
        ctx.Report(1.0, "USB", "USB-Geraete-Verlauf geprueft");
        return Task.CompletedTask;
    }

    private void CheckUsbHistory(ScanContext ctx, CancellationToken ct)
    {
        using var usbKey = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Enum\USB");
        if (usbKey is null) return;

        foreach (var vidPid in usbKey.GetSubKeyNames())
        {
            if (ct.IsCancellationRequested) return;

            bool vidMatch = SuspiciousVids.Any(v =>
                vidPid.StartsWith(v, StringComparison.OrdinalIgnoreCase));

            using var vpKey = usbKey.OpenSubKey(vidPid);
            if (vpKey is null) continue;

            foreach (var serial in vpKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                using var devKey = vpKey.OpenSubKey(serial);
                if (devKey is null) continue;
                ctx.IncrementRegistryKeys();

                var friendly = devKey.GetValue("FriendlyName")?.ToString() ?? "";
                var desc = devKey.GetValue("DeviceDesc")?.ToString() ?? "";
                var mfg = devKey.GetValue("Mfg")?.ToString() ?? "";
                var combined = (friendly + " " + desc + " " + mfg).ToLowerInvariant();

                bool kwMatch = SuspiciousKeywords.Any(k => combined.Contains(k));
                if (!vidMatch && !kwMatch) continue;

                var displayName = !string.IsNullOrWhiteSpace(friendly) ? friendly
                    : !string.IsNullOrWhiteSpace(desc) ? desc : vidPid;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Hardware-Cheat-Geraet im USB-Verlauf: {displayName}",
                    Risk = RiskLevel.High,
                    Recommendation = Recommendation.Review,
                    Location = $@"HKLM\SYSTEM\...\Enum\USB\{vidPid}\{serial}",
                    Reason = $"Im USB-Geraete-Verlauf wurde '{displayName}' gefunden. " +
                             "Microcontroller-Boards (Arduino, Teensy, Raspberry Pi Pico u.a.) " +
                             "werden als HID-Emulator fuer Hardware-Triggerbots, Rapid-Fire- " +
                             "und Makro-Geraete missbraucht, die von Software-Anti-Cheat " +
                             "nicht erkannt werden. Der Eintrag bleibt nach dem Abstecken erhalten.",
                    Detail = $"VID/PID: {vidPid} · Beschreibung: {displayName}" +
                             (!string.IsNullOrWhiteSpace(mfg) ? $" · Hersteller: {mfg}" : "")
                });
            }
        }
    }
}
