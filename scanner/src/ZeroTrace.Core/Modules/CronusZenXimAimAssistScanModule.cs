using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects USB aim-assist hardware connected to the system: Cronus Zen, Cronus Max,
/// XIM Apex, XIM Matrix, MaxAim DI, ReaSnow S1, Brook Universal Fighting Board,
/// Titan Two — all of which intercept controller input to implement no-recoil,
/// auto-aim, and rapid-fire on console-style games and CS/Apex on PC.
///
/// Most aim-assist devices register themselves as composite HID devices (Mouse+Keyboard+
/// Game Controller) and identify with vendor-specific USB VID/PID pairs. The pairs
/// persist in the Windows enumeration registry hive
/// (HKLM\SYSTEM\CurrentControlSet\Enum\USB) and HKLM\SYSTEM\...\Enum\HID even after
/// the device is unplugged.
///
/// Ocean and detect.ac maintain VID/PID lists for these devices — this module
/// implements the same check at the kernel-enumeration layer, no driver required.
/// </summary>
public sealed class CronusZenXimAimAssistScanModule : IScanModule
{
    public string Name => "Aim-Assist Hardware Detection (Cronus Zen / XIM / MaxAim)";
    public double Weight => 0.75;
    public int ParallelGroup => 3;

    // (vid, pid, hardwareName, riskHint)
    private static readonly (string Vid, string Pid, string Name)[] AimAssistDevices =
    {
        // Cronus Zen / Max / Plus
        ("2508", "0019", "Cronus Zen"),
        ("2508", "0001", "Cronus Max Plus"),
        ("2508", "0002", "Cronus Max v3"),
        ("2508", "0003", "CronusMax/PlusPro"),
        ("2508", "001A", "Cronus Zen v2"),
        // XIM technologies
        ("054C", "05C4", "XIM Apex (PS4 passthrough)"), // Common PS4 passthrough disguise
        ("16D0", "0CDD", "XIM Apex"),
        ("16D0", "0D04", "XIM Matrix"),
        ("16D0", "0CDC", "XIM4"),
        // MaxAim DI
        ("054C", "0BA0", "MaxAim DI"),
        // Titan One / Titan Two
        ("1A86", "0E04", "Titan Two"),
        ("1A86", "0E03", "Titan One"),
        // ReaSnow S1 / Cross Hair Pro
        ("258A", "1006", "ReaSnow S1"),
        ("258A", "1007", "ReaSnow Cross Hair Pro"),
        // Brook Universal Fighting Board
        ("0C12", "0E22", "Brook Universal Fighting Board"),
        // KeyMander 2 (HORI/IOGEAR)
        ("0926", "8888", "KeyMander 2"),
        ("0926", "2222", "KeyMander 1"),
        // Mayflash MAGIC-NS adapter (often used with cheating peripherals)
        ("0079", "1843", "Mayflash MAGIC-NS"),
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanEnumKey(ctx, @"SYSTEM\CurrentControlSet\Enum\USB", "USB", ct);
        ScanEnumKey(ctx, @"SYSTEM\CurrentControlSet\Enum\HID", "HID", ct);
    }

    private void ScanEnumKey(ScanContext ctx, string keyPath, string bus, CancellationToken ct)
    {
        using RegistryKey? root = Registry.LocalMachine.OpenSubKey(keyPath);
        if (root is null) return;

        foreach (string deviceKey in root.GetSubKeyNames())
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();

            // Device keys look like: VID_2508&PID_0019  or  HID\VID_..._PID_...
            string upper = deviceKey.ToUpperInvariant();

            foreach (var dev in AimAssistDevices)
            {
                string vidTag = $"VID_{dev.Vid}";
                string pidTag = $"PID_{dev.Pid}";
                if (!upper.Contains(vidTag) || !upper.Contains(pidTag)) continue;

                // Enumerate child instance subkeys for ConnectedDate / FirstInstallDate
                string detail = $"USB-ID: {deviceKey}";
                try
                {
                    using RegistryKey? devKey = root.OpenSubKey(deviceKey);
                    if (devKey is not null)
                    {
                        var instances = devKey.GetSubKeyNames();
                        if (instances.Length > 0) detail += $" | Instanzen: {instances.Length}";

                        foreach (string inst in instances)
                        {
                            using RegistryKey? instKey = devKey.OpenSubKey(inst);
                            string? friendly = instKey?.GetValue("FriendlyName") as string;
                            string? mfg      = instKey?.GetValue("Mfg") as string;
                            string? deviceDesc = instKey?.GetValue("DeviceDesc") as string;

                            if (!string.IsNullOrEmpty(friendly)) detail += $" | FriendlyName: {friendly}";
                            if (!string.IsNullOrEmpty(deviceDesc)) detail += $" | Desc: {deviceDesc}";
                            if (!string.IsNullOrEmpty(mfg)) detail += $" | Mfg: {mfg}";
                        }
                    }
                }
                catch { }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Aim-Assist-Hardware erkannt ({bus}): {dev.Name}",
                    Risk     = RiskLevel.Critical,
                    Location = $@"HKLM\{keyPath}\{deviceKey}",
                    FileName = dev.Name,
                    Reason   = $"USB-Gerät mit VID={dev.Vid}, PID={dev.Pid} entspricht " +
                               $"'{dev.Name}' — ein bekanntes Aim-Assist-/Recoil-Reduction-Gerät. " +
                               "Diese Hardware sitzt zwischen Controller und PC, manipuliert " +
                               "Eingabesignale und implementiert No-Recoil, Auto-Aim und Rapid-Fire " +
                               "auf einer Ebene, die Software-Anti-Cheats nicht erreichen. Die " +
                               "USB-Enumeration persistiert auch nach dem Abstecken des Geräts.",
                    Detail   = detail
                });
                break;
            }
        }
    }
}
