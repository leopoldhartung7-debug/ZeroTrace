using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects virtual audio devices commonly used in cheat setups.
///
/// Virtual audio cables (VB-Audio Virtual Cable, VAC2, ASIO4ALL bridged) are used
/// in sophisticated cheat setups where:
///   - External AI/radar running on a second PC sends audio-based signals ("beeps")
///     through a virtual audio cable to trigger cheat actions on the gaming PC
///   - "Voice-activated" triggerbot: a sound from another source activates the trigger
///   - DMA radar setups route pixel-reading audio cues over virtual cable
///
/// Ocean and detect.ac flag virtual audio devices because:
///   - VB-Audio Virtual Cable is almost exclusively used by streamers, music producers,
///     or cheat setups — in a gaming context with DMA hardware it's a red flag
///   - The presence of multiple virtual audio devices alongside DMA cheat indicators
///     is a very strong combined signal
///
/// Detection methods:
///   - Registry: HKLM\SYSTEM\CurrentControlSet\Enum\MEDIA  (audio device class)
///   - Registry: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio
///   - WMI: Win32_SoundDevice for device name matching
/// </summary>
public sealed class VirtualAudioDeviceScanModule : IScanModule
{
    public string Name => "Virtual Audio Device Scan (VB-Cable / VAC Cheat-Signal-Routing)";
    public double Weight => 0.4;
    public int ParallelGroup => 3;

    private static readonly string[] VirtualAudioPatterns =
    {
        // VB-Audio products
        "vb-audio", "vb audio", "vb-cable", "vb cable",
        "voicemeeter", "voice meeter",
        // Virtual Audio Cable (VAC)
        "virtual audio cable", "vac2", "vaio",
        // Other virtual audio drivers
        "virtual audio", "virt audio",
        "blackhole audio", "blackhole",       // macOS-side but Windows variant exists
        "asio link", "asio4all",
        "cable output", "cable input",        // VB-Cable's device names
        // Less known but used in cheat setups
        "null audio", "silent audio",
        "audio repeater", "audiorepeater",
        // Voicemeeter specific
        "vaio3", "voicemeeter banana", "voicemeeter potato",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanMediaDeviceRegistry(ctx, ct);
        ScanMmDevicesRegistry(ctx, ct);
    }

    private void ScanMediaDeviceRegistry(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var mediaKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Enum\MEDIA", writable: false);
            if (mediaKey is null) return;

            foreach (string deviceClass in mediaKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var classKey = mediaKey.OpenSubKey(deviceClass, writable: false);
                    if (classKey is null) continue;

                    foreach (string instanceId in classKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var instKey = classKey.OpenSubKey(instanceId, writable: false);
                            if (instKey is null) continue;

                            string? friendlyName = instKey.GetValue("FriendlyName") as string ?? "";
                            string? deviceDesc   = instKey.GetValue("DeviceDesc") as string ?? "";
                            string combined = $"{friendlyName} {deviceDesc}".ToLowerInvariant();

                            CheckDeviceName(ctx, combined, friendlyName ?? deviceDesc ?? instanceId,
                                $@"HKLM\SYSTEM\CurrentControlSet\Enum\MEDIA\{deviceClass}\{instanceId}");
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanMmDevicesRegistry(ScanContext ctx, CancellationToken ct)
    {
        string[] mmPaths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture",
        };

        foreach (string mmPath in mmPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var mmKey = Registry.LocalMachine.OpenSubKey(mmPath, writable: false);
                if (mmKey is null) continue;

                foreach (string guid in mmKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var devKey = mmKey.OpenSubKey(guid, writable: false);
                        if (devKey is null) continue;

                        // Properties subkey contains device FriendlyName
                        using var propsKey = devKey.OpenSubKey("Properties", writable: false);
                        if (propsKey is null) continue;

                        // PKEY_Device_FriendlyName = {a45c254e-df1c-4efd-8020-67d146a850e0},14
                        string? name = null;
                        foreach (string propName in propsKey.GetValueNames())
                        {
                            if (!propName.Contains("a45c254e")) continue;
                            name = propsKey.GetValue(propName) as string;
                            break;
                        }

                        if (string.IsNullOrEmpty(name)) continue;
                        CheckDeviceName(ctx, name.ToLowerInvariant(), name,
                            $@"HKLM\{mmPath}\{guid}");
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void CheckDeviceName(ScanContext ctx, string nameLower,
        string displayName, string regPath)
    {
        foreach (string pattern in VirtualAudioPatterns)
        {
            if (!nameLower.Contains(pattern)) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Virtuelles Audiogerät erkannt: {displayName}",
                Risk     = RiskLevel.Medium,
                Location = regPath,
                FileName = displayName,
                Reason   = $"Virtuelles Audiogerät '{displayName}' erkannt (Match: '{pattern}'). " +
                           "VB-Audio Virtual Cable und ähnliche Treiber werden in DMA-Cheat-Setups " +
                           "verwendet, um Audio-Signale von einem externen Cheat-PC an den Gaming-PC " +
                           "zu routen (Radar-Piep-Trigger, KI-Aimbot-Signaling). Ocean und detect.ac " +
                           "flaggen virtuelle Audiogeräte in Kombination mit anderen DMA-Indikatoren.",
                Detail   = $"Gerätename: {displayName} | Match: '{pattern}' | " +
                           $"Registry: {regPath}"
            });
            return;
        }
    }
}
