using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects suspicious input device filter drivers and virtual HID devices used for
/// aimbot/triggerbot/no-recoil macro automation. Cheat tools use kernel-mode input
/// filter drivers (Interception, nopRecoil, Logitech filter exploit) or virtual HID
/// devices (vJoy, VirtualHere, ViGEm) to inject hardware-level mouse/keyboard events
/// that bypass software-level input hooks used by anti-cheat. The module inspects:
///   - HKLM\SYSTEM\CurrentControlSet\Services for known cheat input filter driver names
///   - HKLM\SYSTEM\CurrentControlSet\Enum\HID for virtual HID device registrations
///   - HKLM\SYSTEM\CurrentControlSet\Control\Class\{HID class} for filter driver entries
///   - Known macro/automation device service names (Logitech GHUB filter abuse, Razer)
/// </summary>
public sealed class InputDeviceFilterScanModule : IScanModule
{
    public string Name => "Input Device Filter Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private static readonly string[] SuspiciousInputDriverNames =
    {
        // Interception — kernel input filter framework widely abused by no-recoil cheats
        "interception", "mouclass_filter", "kbdclass_filter",
        // Virtual joystick/gamepad devices used to spoof mouse as controller
        "vjoy", "vjoybus", "vjoymouse",
        // ViGEm Bus — virtual controller (also used for aimbot injection)
        "vigembus", "vigemdrv",
        // Virtual mouse/keyboard injection tools
        "vmouse", "vkeyboard", "vmkeyboard", "vmouclass",
        // Logitech GHUB filter kernel driver (abused for no-recoil)
        "logi_hlp_driver", "logi_hl_driver", "logihlp",
        // Nopaste/RecoilHelper drivers
        "nopRecoil", "norecoil", "norecoildrv",
        // Generic suspicious input filter names
        "inputfilter", "mousehook", "kbhook", "kbfilter", "mousefilter",
        // SteelSeries/Razer kernel cheats
        "ssfilter", "razerinput", "rzinputdrv",
        // Known cheat-specific input driver names
        "inputRedirector", "hackInput", "aimbot", "triggerbot",
        // Artificial latency reducers sometimes abused
        "mouselatency", "inputboost",
    };

    private static readonly string[] SuspiciousHidDeviceNames =
    {
        "vjoy", "vigembus", "vigemdrv", "virtualhere", "vhid",
        "vmouse", "vkeybd", "fakemouse", "fakekbd",
        "norecoil", "inputredirect",
    };

    // GUID for HID class — used to check UpperFilters/LowerFilters
    private const string HidClassGuid = @"SYSTEM\CurrentControlSet\Control\Class\{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}";
    private const string ServicesKey  = @"SYSTEM\CurrentControlSet\Services";
    private const string HidEnumKey   = @"SYSTEM\CurrentControlSet\Enum\HID";

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckInputFilterServices(ctx, ct);
            CheckHidClassFilters(ctx, ct);
            CheckHidDeviceRegistry(ctx, ct);
        }, ct);
    }

    private void CheckInputFilterServices(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(ServicesKey);
            if (servicesKey is null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                string svcLower = svcName.ToLowerInvariant();

                if (!Array.Exists(SuspiciousInputDriverNames, n => svcLower.Contains(n))) continue;

                try
                {
                    using var svcKey = servicesKey.OpenSubKey(svcName);
                    if (svcKey is null) continue;

                    ctx.IncrementRegistryKeys();
                    string? imagePath = svcKey.GetValue("ImagePath") as string;
                    string? displayName = svcKey.GetValue("DisplayName") as string;
                    int? start = svcKey.GetValue("Start") as int?;
                    int? type  = svcKey.GetValue("Type") as int?;

                    bool isKernelDriver = type is 1; // SERVICE_KERNEL_DRIVER
                    bool isEnabled = start is 0 or 1 or 2; // Boot/System/Auto

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtiger Input-Filter-Dienst: {svcName}",
                        Risk     = isKernelDriver && isEnabled ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"HKLM\{ServicesKey}\{svcName}",
                        FileName = imagePath is not null ? Path.GetFileName(imagePath) : svcName,
                        Reason   = $"Dienst '{svcName}' ({displayName ?? "kein Anzeigename"}) ist ein verdächtiger " +
                                   (isKernelDriver ? "Kernel-" : "") + "Input-Filter-Treiber — " +
                                   "wird für Hardware-Level Maus/Tastatur-Injektion bei No-Recoil/Aimbot verwendet",
                        Detail   = $"Service: {svcName} | Typ: 0x{type:X} | Start: {start} | " +
                                   $"Aktiviert: {isEnabled} | Kernel: {isKernelDriver} | Pfad: {imagePath}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckHidClassFilters(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var hidClass = Registry.LocalMachine.OpenSubKey(HidClassGuid);
            if (hidClass is null) return;

            ctx.IncrementRegistryKeys();

            // Check UpperFilters and LowerFilters for the HID class
            foreach (var filterKey in new[] { "UpperFilters", "LowerFilters" })
            {
                ct.ThrowIfCancellationRequested();
                var filters = hidClass.GetValue(filterKey) as string[];
                if (filters is null) continue;

                foreach (var filter in filters)
                {
                    string filterLower = filter.ToLowerInvariant();
                    if (!Array.Exists(SuspiciousInputDriverNames, n => filterLower.Contains(n))) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtiger HID-Klassen-Filter: {filter}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{HidClassGuid}",
                        FileName = filter,
                        Reason   = $"HID-Geräteklasse hat verdächtigen {filterKey}-Treiber '{filter}' — " +
                                   "wird in alle HID-Geräte geladen und kann Maus/Tastatur-Eingaben abfangen oder injizieren",
                        Detail   = $"Klasse: HID | {filterKey}: {filter} | Schlüssel: {HidClassGuid}"
                    });
                }
            }
        }
        catch { }
    }

    private void CheckHidDeviceRegistry(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var hidEnum = Registry.LocalMachine.OpenSubKey(HidEnumKey);
            if (hidEnum is null) return;

            foreach (var deviceId in hidEnum.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                string deviceLower = deviceId.ToLowerInvariant();

                if (!Array.Exists(SuspiciousHidDeviceNames, n => deviceLower.Contains(n))) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdächtiges virtuelles HID-Gerät: {deviceId}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{HidEnumKey}\{deviceId}",
                    FileName = deviceId,
                    Reason   = $"Virtuelles HID-Gerät '{deviceId}' in Geräteverwaltung — " +
                               "wird von Cheat-Tools genutzt um synthetische Maus/Tastatur-Ereignisse " +
                               "auf Hardware-Ebene zu erzeugen (umgeht Software-Input-Hooks von Anti-Cheat)",
                    Detail   = $"HID-Gerät-ID: {deviceId} | Typ: Virtuelles HID-Gerät"
                });
            }
        }
        catch { }
    }
}
