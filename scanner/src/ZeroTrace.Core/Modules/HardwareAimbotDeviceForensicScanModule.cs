using System.Runtime.Versioning;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class HardwareAimbotDeviceForensicScanModule : IScanModule
{
    public string Name => "Hardware Aimbot Device Forensic";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // KMBOX VID/PID patterns (KMBOX B/B+/Net use CH340 serial chip)
    // -------------------------------------------------------------------------
    private static readonly string[] KmboxVidPids =
    {
        "VID_1A86&PID_7523",  // KMBOX B/B+ — QinHeng CH340
        "VID_1A86&PID_7522",  // QinHeng CH340C variant
        "VID_1A86&PID_55D4",  // QinHeng CH9102 (KMBOX Net)
        "VID_1A86&PID_5523",  // CH341 variant used in some KMBOX revisions
        "VID_067B&PID_2303",  // Prolific PL2303 — older KMBOX clones
    };

    private static readonly string[] KmboxExecutables =
    {
        "kmbox.exe",
        "kmboxnet.exe",
        "kmbox_net.exe",
        "kmboxb.exe",
        "kmbox_manager.exe",
        "kmboxpro.exe",
    };

    private static readonly string[] KmboxKeywords =
    {
        "kmbox", "km box", "kmboxnet", "km-box",
    };

    // -------------------------------------------------------------------------
    // XIM device keywords and VID patterns
    // -------------------------------------------------------------------------
    private static readonly string[] XimVidPids =
    {
        "VID_2341&PID_8036",  // XIM Apex (Arduino Zero/M0 base)
        "VID_2341&PID_804D",  // XIM Matrix
        "VID_2341&PID_0036",
        "VID_16D0&PID_0BA3",  // MassStorage / XIM bootloader
        "VID_04D8&PID_EE56",  // XIM Nexus
    };

    private static readonly string[] XimExecutables =
    {
        "xim manager.exe",
        "ximmanager.exe",
        "xim apex manager.exe",
        "xim4manager.exe",
        "ximedge.exe",
    };

    private static readonly string[] XimKeywords =
    {
        "xim apex", "xim manager", "xim nexus", "xim matrix", "ximapex",
        "xim4", "xim link",
    };

    // -------------------------------------------------------------------------
    // Cronus Zen/Max VID patterns and keywords
    // -------------------------------------------------------------------------
    private static readonly string[] CronusVidPids =
    {
        "VID_0A89&PID_0003",  // Cronus Zen
        "VID_0A89&PID_0006",  // Cronus Max / Zen variant
        "VID_0A89&PID_0001",  // CronusMAX Plus
        "VID_0A89",            // generic Cronus vendor
    };

    private static readonly string[] CronusExecutables =
    {
        "cronuszen.exe",
        "cronus zen.exe",
        "cronuspro.exe",
        "zenplus.exe",
        "cronusmaxplus.exe",
    };

    private static readonly string[] CronusKeywords =
    {
        "cronus zen", "cronuszen", "cronus max", "cronusmax", "cronus pro",
        "gpc script", "gamepack", "anti-recoil script", "rapid fire script",
    };

    private static readonly string[] GpcAnticheatPatterns =
    {
        "anti_recoil", "antirecoil", "rapid_fire", "rapidfire", "auto_aim",
        "autoaim", "aimbot", "triggerbot", "bhop", "bunny_hop", "anti-recoil",
        "rapid fire", "no recoil", "norecoil",
    };

    // -------------------------------------------------------------------------
    // Titan One/Two VID patterns
    // -------------------------------------------------------------------------
    private static readonly string[] TitanVidPids =
    {
        "VID_04D8&PID_F528",  // Titan One (ConsoleTuner)
        "VID_04D8&PID_FEAA",  // Titan Two
        "VID_04D8&PID_0082",
        "VID_04D8",            // generic Microchip / ConsoleTuner
    };

    private static readonly string[] TitanExecutables =
    {
        "consoletuner.exe",
        "titan one.exe",
        "titan two.exe",
        "titantwo.exe",
        "gtuner.exe",
        "gtuner pro.exe",
        "gtuner iv.exe",
    };

    private static readonly string[] TitanKeywords =
    {
        "titan one", "titan two", "titantwo", "gtuner", "consoletuner",
        "titan firmware",
    };

    // -------------------------------------------------------------------------
    // ReaSnow S1 VID patterns
    // -------------------------------------------------------------------------
    private static readonly string[] ReasnowVidPids =
    {
        "VID_16C0&PID_0A56",  // ReaSnow S1
        "VID_16C0&PID_27DB",
    };

    private static readonly string[] ReasnowExecutables =
    {
        "reasnow.exe",
        "reasnow s1.exe",
        "reasnowtool.exe",
        "reasnow cross hair.exe",
    };

    private static readonly string[] ReasnowKeywords =
    {
        "reasnow", "reasnow s1", "reasnow crosshair",
    };

    // -------------------------------------------------------------------------
    // Brook UFB/Wingman VID patterns
    // -------------------------------------------------------------------------
    private static readonly string[] BrookVidPids =
    {
        "VID_0C12&PID_0EF8",  // Brook UFB
        "VID_0C12&PID_0E10",  // Brook Wingman XE
        "VID_0C12&PID_0E15",  // Brook Wingman SD
        "VID_0C12&PID_0EF6",
        "VID_0C12",            // generic Brook vendor
    };

    private static readonly string[] BrookKeywords =
    {
        "brook ufb", "wingman", "brook wingman", "brook accessory", "brook ps",
        "brook xbox", "super converter",
    };

    // -------------------------------------------------------------------------
    // Arduino / Teensy / RP2040 HID firmware patterns
    // -------------------------------------------------------------------------
    private static readonly string[] HidFirmwareKeywords =
    {
        "mouse.move", "mouse.click", "keyboard.press", "keyboard.write",
        "#include <mouse.h>", "#include <keyboard.h>", "usb_hid", "hid.mouse",
        "MouseReport", "KeyboardReport", "boot_keyboard", "boot_mouse",
        "TinyUSB", "tinyusb", "usbd_hid",
    };

    private static readonly string[] ArduinoKeywords =
    {
        "teensy loader", "teensyduino", "avrdude", "arduino ide", "arduino cli",
    };

    private static readonly string[] PythonHidImports =
    {
        "import hid", "from hid import", "import usb_hid", "from usb_hid",
        "import analogio", "import usb.core",
    };

    // -------------------------------------------------------------------------
    // vJoy virtual joystick driver patterns
    // -------------------------------------------------------------------------
    private static readonly string[] VjoyKeywords =
    {
        "vjoy", "vjoyconf", "vjoycpl", "vjoyinterface",
    };

    private static readonly string[] VjoyDriverFiles =
    {
        "vjoy.sys",
        "vjoyinterface.dll",
        "vjoyconf.exe",
    };

    // -------------------------------------------------------------------------
    // ViGEmBus virtual gamepad patterns
    // -------------------------------------------------------------------------
    private static readonly string[] VigemKeywords =
    {
        "vigembus", "vigem bus", "vigemclient", "vigem client",
        "ds4windows", "rewasd", "joystick gremlin",
    };

    private static readonly string[] VigemDriverFiles =
    {
        "vigembus.sys",
        "vigemclient.dll",
        "vigembus.inf",
    };

    // -------------------------------------------------------------------------
    // reWASD patterns
    // -------------------------------------------------------------------------
    private static readonly string[] RewasdExecutables =
    {
        "rewasd.exe",
        "rewasdservice.exe",
        "rewasdtray.exe",
        "rewasdengine.exe",
    };

    private static readonly string[] RewasdKeywords =
    {
        "rewasd", "re.wasd", "controller remapper", "gamepad remapper",
    };

    // -------------------------------------------------------------------------
    // Logitech G-Hub macro abuse patterns
    // -------------------------------------------------------------------------
    private static readonly string[] GhubRecoilLuaPatterns =
    {
        "MoveMouseRelative", "MoveMouseTo", "anti.recoil", "antirecoil",
        "anti_recoil", "recoil compensation", "rapid.fire", "rapidfire",
        "rapid_fire", "triggerbot", "aimbot", "no.recoil",
        "sleep(", "Sleep(", "PressMouseButton", "ReleaseMouseButton",
    };

    private static readonly string[] GhubSuspiciousScriptNames =
    {
        "recoil", "antirecoil", "aimbot", "triggerbot", "rapidfire",
        "norecoil", "no_recoil", "autofire", "macro_aim",
    };

    // -------------------------------------------------------------------------
    // Razer Synapse macro abuse patterns
    // -------------------------------------------------------------------------
    private static readonly string[] RazerMacroKeywords =
    {
        "no_recoil", "norecoil", "anti_recoil", "antirecoil", "rapid_fire",
        "rapidfire", "aimbot", "triggerbot", "autofire", "spray_transfer",
        "recoil_compensation",
    };

    // -------------------------------------------------------------------------
    // HORI TAC Pro / Target Strike VID patterns
    // -------------------------------------------------------------------------
    private static readonly string[] HoriVidPids =
    {
        "VID_0F0D&PID_006E",  // HORI TAC Pro
        "VID_0F0D&PID_0084",  // HORI Target Strike
        "VID_0F0D&PID_0066",
        "VID_0F0D",            // generic HORI vendor
    };

    private static readonly string[] HoriKeywords =
    {
        "hori tac", "tac pro", "target strike", "hori horipad",
        "hori fighting commander", "tacsettings",
    };

    // -------------------------------------------------------------------------
    // Hardware aimbot purchase/download search terms
    // -------------------------------------------------------------------------
    private static readonly string[] PurchaseSearchTerms =
    {
        "kmbox buy", "kmbox purchase", "xim apex order", "xim apex buy",
        "cronus zen cheat", "cronus zen buy", "hardware aimbot", "hardware cheat",
        "controller bypass", "mouse emulator cheat", "aimbot hardware",
        "hid emulator buy", "keyboard emulator buy", "kmbox net buy",
        "titan two buy", "reasnow buy", "brook wingman cheat",
        "vjoy aimbot", "vigem aimbot", "rewasd aimbot",
    };

    private static readonly string[] PurchaseDownloadNames =
    {
        "kmbox_software", "kmbox_tool", "kmbox_net",
        "xim_manager", "xim_apex_setup", "ximmanager_setup",
        "cronus_utility", "cronus_zen_setup", "cronuszen_installer",
        "titan_one_setup", "titan_two_setup", "gtuner_setup",
        "reasnow_setup", "reasnow_tool",
        "hardware_aimbot", "hid_aimbot",
    };

    // -------------------------------------------------------------------------
    // HID filter driver class GUIDs
    // -------------------------------------------------------------------------
    private static readonly string[] HidClassGuids =
    {
        "{4d36e96b-e325-11ce-bfc1-08002be10318}",  // HID keyboard
        "{4d36e96c-e325-11ce-bfc1-08002be10318}",  // HID mouse
        "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}",  // HID generic
    };

    private static readonly string[] LegitimateFilterDrivers =
    {
        "kbdclass", "mouclass", "kbfiltr", "moufiltr", "hidusb",
        "usbhid", "hidparse", "hidkmdf", "wdmaudio", "portcls",
    };

    // -------------------------------------------------------------------------
    // Firmware file patterns
    // -------------------------------------------------------------------------
    private static readonly string[] FirmwareExtensions =
    {
        ".hex", ".bin", ".uf2", ".ino",
    };

    private static readonly string[] FirmwareHidKeywords =
    {
        "Mouse.move", "Mouse.click", "Mouse.press", "Mouse.release",
        "Keyboard.press", "Keyboard.write", "Keyboard.release",
        "usb_hid", "HID_USAGE_DESKTOP_MOUSE", "HID_USAGE_DESKTOP_KEYBOARD",
        "DESCRIPTOR_TYPE_HID", "TinyUSB", "BootMouse", "BootKeyboard",
        "AbsoluteMouse", "SingleAbsoluteMouse",
    };

    private static readonly string[] PicoHidKeywords =
    {
        "import hid", "from hid", "import usb_hid", "from usb_hid",
        "hid.Mouse", "hid.Keyboard", "usb_hid.devices",
    };

    // -------------------------------------------------------------------------
    // Registry artifact keywords for UserAssist / MuiCache
    // -------------------------------------------------------------------------
    private static readonly string[] UserAssistToolKeywords =
    {
        "kmbox", "xim apex", "ximmanager", "cronuszen", "cronus zen",
        "gtuner", "consoletuner", "reasnow", "vjoyconf", "vigembus",
        "rewasd", "ds4windows", "joystick gremlin", "titantwo", "titan two",
        "kmboxnet",
    };

    // -------------------------------------------------------------------------
    // Discord cache hardware aimbot keywords
    // -------------------------------------------------------------------------
    private static readonly string[] DiscordHardwareKeywords =
    {
        "kmbox", "km box", "xim apex", "ximapex", "cronus zen", "cronuszen",
        "hardware spoof", "controller bypass", "hardware aimbot",
        "hid emulator", "mouse emulator", "titan two", "titantwo",
        "vjoy cheat", "vigem cheat", "rewasd cheat", "brook wingman cheat",
        "reasnow", "hardware cheat",
    };

    private static readonly string[] DiscordDeviceManualNames =
    {
        "kmbox_manual", "kmbox_guide", "xim_guide", "cronus_guide",
        "hardware_aimbot_guide", "controller_bypass_manual",
        "kmbox_tutorial", "xim_tutorial",
    };

    // =========================================================================
    // RunAsync — fans out to all 18 sub-checks concurrently
    // =========================================================================

    public Task RunAsync(ScanContext ctx, CancellationToken ct) =>
        Task.WhenAll(
            CheckKmboxArtifacts(ctx, ct),
            CheckXimArtifacts(ctx, ct),
            CheckCronusArtifacts(ctx, ct),
            CheckTitanArtifacts(ctx, ct),
            CheckReasnowArtifacts(ctx, ct),
            CheckBrookArtifacts(ctx, ct),
            CheckArduinoHidFirmware(ctx, ct),
            CheckVjoyArtifacts(ctx, ct),
            CheckVigemArtifacts(ctx, ct),
            CheckRewasdArtifacts(ctx, ct),
            CheckGhubMacroAbuse(ctx, ct),
            CheckRazerMacroAbuse(ctx, ct),
            CheckHoriArtifacts(ctx, ct),
            CheckPurchaseDownloadArtifacts(ctx, ct),
            CheckHidFilterDriverAbuse(ctx, ct),
            CheckFirmwareFiles(ctx, ct),
            CheckRegistryToolTraces(ctx, ct),
            CheckDiscordHardwareAimbotArtifacts(ctx, ct)
        );

    // =========================================================================
    // Sub-check 1 — KMBOX B/B+/Net registry and file artifacts
    // =========================================================================

    private Task CheckKmboxArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // USB registry trace
            try
            {
                using var usbKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Enum\USB");
                if (usbKey is not null)
                {
                    foreach (var vidPid in usbKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        bool match = KmboxVidPids.Any(k =>
                            vidPid.StartsWith(k, StringComparison.OrdinalIgnoreCase));
                        if (!match) continue;

                        using var vpKey = usbKey.OpenSubKey(vidPid);
                        if (vpKey is null) continue;
                        foreach (var serial in vpKey.GetSubKeyNames())
                        {
                            using var devKey = vpKey.OpenSubKey(serial);
                            if (devKey is null) continue;
                            ctx.IncrementRegistryKeys();
                            var friendly = devKey.GetValue("FriendlyName")?.ToString() ?? "";
                            var desc = devKey.GetValue("DeviceDesc")?.ToString() ?? "";
                            var display = string.IsNullOrWhiteSpace(friendly) ? desc : friendly;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "KMBOX USB Device in Registry",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\{vidPid}\{serial}",
                                Reason = $"KMBOX hardware aimbot device detected via USB VID/PID '{vidPid}' in USB enumeration registry. " +
                                         "KMBOX B/B+/Net are dedicated hardware mouse-emulation devices used to bypass software anti-cheat " +
                                         "by injecting aimbot movements at the hardware level. This registry key persists after device removal.",
                                Detail = $"VID/PID: {vidPid} | FriendlyName: {display} | Serial: {serial}"
                            });
                        }
                    }
                }
            }
            catch { }

            // INF driver file traces
            string infDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF");
            if (Directory.Exists(infDir))
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(infDir, "*.inf"))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            bool hasKmbox = KmboxKeywords.Any(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            bool hasVid = KmboxVidPids.Any(v =>
                                content.Contains(v, StringComparison.OrdinalIgnoreCase));
                            if (hasKmbox || hasVid)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "KMBOX Driver INF File",
                                    Risk = RiskLevel.High,
                                    Location = infDir,
                                    FileName = Path.GetFileName(f),
                                    Reason = "A Windows INF driver file contains KMBOX-related content, indicating the KMBOX hardware aimbot " +
                                             "driver was installed on this system.",
                                    Detail = $"File: {f}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // Executable traces in Downloads and Temp
            var searchPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "KMBOX"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "KMBOX"),
            };

            foreach (var dir in searchPaths)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        if (KmboxExecutables.Any(e =>
                            fname.Equals(e, StringComparison.OrdinalIgnoreCase)) ||
                            KmboxKeywords.Any(k =>
                            fname.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "KMBOX Software Executable",
                                Risk = RiskLevel.Critical,
                                Location = dir,
                                FileName = fname,
                                Reason = "KMBOX hardware aimbot management software found on disk. KMBOX executables are used " +
                                         "to configure and flash the KMBOX hardware device with aimbot movement scripts.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);

    // =========================================================================
    // Sub-check 2 — XIM Apex/Matrix/Nexus artifacts
    // =========================================================================

    private Task CheckXimArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // USB registry
            try
            {
                using var usbKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Enum\USB");
                if (usbKey is not null)
                {
                    foreach (var vidPid in usbKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!XimVidPids.Any(v =>
                            vidPid.StartsWith(v, StringComparison.OrdinalIgnoreCase))) continue;

                        using var vpKey = usbKey.OpenSubKey(vidPid);
                        if (vpKey is null) continue;
                        foreach (var serial in vpKey.GetSubKeyNames())
                        {
                            using var devKey = vpKey.OpenSubKey(serial);
                            ctx.IncrementRegistryKeys();
                            var friendly = devKey?.GetValue("FriendlyName")?.ToString() ?? "";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "XIM Device USB Registry Trace",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\{vidPid}",
                                Reason = "XIM Apex/Matrix/Nexus USB device detected in Windows device enumeration registry. " +
                                         "XIM devices are hardware adapters that emulate mouse/keyboard inputs to bypass " +
                                         "game controller detection and enable aim assistance via hardware.",
                                Detail = $"VID/PID: {vidPid} | Serial: {serial} | Name: {friendly}"
                            });
                        }
                    }
                }
            }
            catch { }

            // XIM Manager in Program Files / AppData
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            foreach (var baseDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        var ext = Path.GetExtension(f);

                        // XIM executable
                        if (XimExecutables.Any(e => fname.Equals(e, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "XIM Manager Application Found",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "XIM Manager application found. This software is used exclusively to configure XIM " +
                                         "hardware adapter devices which bypass game input detection for aimbot use.",
                                Detail = $"Path: {f}"
                            });
                        }

                        // .xim config files
                        if (ext.Equals(".xim", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "XIM Configuration File",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "A .xim configuration file was found. These files store XIM hardware adapter configuration " +
                                         "profiles, including aim-assist curves and game-specific input mappings.",
                                Detail = $"Path: {f}"
                            });
                        }

                        // XIM keyword in filename
                        if (XimKeywords.Any(k => fname.Contains(k, StringComparison.OrdinalIgnoreCase)) &&
                            !ext.Equals(".xim", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "XIM-Related File",
                                Risk = RiskLevel.Medium,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "File with XIM hardware aimbot device keyword found on disk.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }

            // Read a dummy await to satisfy async requirement
            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 3 — Cronus Zen/Max artifacts and GPC scripts
    // =========================================================================

    private Task CheckCronusArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // USB registry
            try
            {
                using var usbKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Enum\USB");
                if (usbKey is not null)
                {
                    foreach (var vidPid in usbKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!CronusVidPids.Any(v =>
                            vidPid.StartsWith(v, StringComparison.OrdinalIgnoreCase))) continue;

                        using var vpKey = usbKey.OpenSubKey(vidPid);
                        if (vpKey is null) continue;
                        foreach (var serial in vpKey.GetSubKeyNames())
                        {
                            ctx.IncrementRegistryKeys();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cronus Zen/Max USB Registry Trace",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\{vidPid}",
                                Reason = "Cronus Zen or CronusMAX USB device detected. Cronus devices are macro hardware " +
                                         "controllers that inject rapid-fire, anti-recoil, and aimbot inputs at the hardware " +
                                         "level, circumventing software anti-cheat detection.",
                                Detail = $"VID/PID: {vidPid} | Serial: {serial}"
                            });
                        }
                    }
                }
            }
            catch { }

            // Executable and GPC script search
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            foreach (var baseDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        var ext = Path.GetExtension(f);

                        if (CronusExecutables.Any(e =>
                            fname.Equals(e, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cronus Zen Software Found",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "Cronus Zen software detected. This application is used exclusively to configure " +
                                         "Cronus hardware cheat devices with GPC macro scripts.",
                                Detail = $"Path: {f}"
                            });
                        }

                        if (ext.Equals(".gpc", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementFiles();
                            try
                            {
                                using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                string content = await sr.ReadToEndAsync(ct);
                                var hitPattern = GpcAnticheatPatterns.FirstOrDefault(p =>
                                    content.Contains(p, StringComparison.OrdinalIgnoreCase));
                                var risk = hitPattern is not null ? RiskLevel.Critical : RiskLevel.High;
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = hitPattern is not null
                                        ? "GPC Script with Anti-Recoil/Rapid-Fire Pattern"
                                        : "GPC Script File Found",
                                    Risk = risk,
                                    Location = Path.GetDirectoryName(f) ?? baseDir,
                                    FileName = fname,
                                    Reason = hitPattern is not null
                                        ? $"GPC script contains pattern '{hitPattern}' indicating anti-recoil, rapid-fire, " +
                                          "or aimbot macro functionality for Cronus Zen/Titan hardware."
                                        : "GPC script file found — these scripts run on Cronus Zen/Max or Titan hardware " +
                                          "cheat devices to automate aiming and firing inputs.",
                                    Detail = $"Path: {f} | Matched: {hitPattern ?? "GPC extension"}"
                                });
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }, ct);

    // =========================================================================
    // Sub-check 4 — Titan One/Two artifacts
    // =========================================================================

    private Task CheckTitanArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // USB registry
            try
            {
                using var usbKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Enum\USB");
                if (usbKey is not null)
                {
                    foreach (var vidPid in usbKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!TitanVidPids.Any(v =>
                            vidPid.StartsWith(v, StringComparison.OrdinalIgnoreCase))) continue;

                        using var vpKey = usbKey.OpenSubKey(vidPid);
                        if (vpKey is null) continue;
                        foreach (var serial in vpKey.GetSubKeyNames())
                        {
                            ctx.IncrementRegistryKeys();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Titan One/Two USB Registry Trace",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\{vidPid}",
                                Reason = "Titan One or Titan Two (ConsoleTuner) USB device found in Windows registry. " +
                                         "These devices execute GPC macro scripts at the hardware level to provide " +
                                         "anti-recoil, rapid-fire, and aim assist without software detection.",
                                Detail = $"VID/PID: {vidPid} | Serial: {serial}"
                            });
                        }
                    }
                }
            }
            catch { }

            // Software files
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            foreach (var baseDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        if (TitanExecutables.Any(e =>
                            fname.Equals(e, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Titan One/Two Software (GTuner/ConsoleTuner)",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "GTuner or ConsoleTuner software found. This is used exclusively to program " +
                                         "Titan One/Two hardware cheat devices with GPC macro scripts.",
                                Detail = $"Path: {f}"
                            });
                        }
                        else if (TitanKeywords.Any(k =>
                            fname.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Titan Hardware Cheat Related File",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "File with Titan One/Two hardware cheat device keyword found.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }

            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 5 — ReaSnow S1 artifacts
    // =========================================================================

    private Task CheckReasnowArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // USB registry
            try
            {
                using var usbKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Enum\USB");
                if (usbKey is not null)
                {
                    foreach (var vidPid in usbKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!ReasnowVidPids.Any(v =>
                            vidPid.StartsWith(v, StringComparison.OrdinalIgnoreCase))) continue;

                        using var vpKey = usbKey.OpenSubKey(vidPid);
                        if (vpKey is null) continue;
                        foreach (var serial in vpKey.GetSubKeyNames())
                        {
                            ctx.IncrementRegistryKeys();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "ReaSnow S1 USB Registry Trace",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\{vidPid}",
                                Reason = "ReaSnow S1 hardware aimbot adapter detected in USB device history. " +
                                         "The ReaSnow S1 converts controller input with aim-assist algorithms at " +
                                         "the hardware level to bypass software anti-cheat.",
                                Detail = $"VID/PID: {vidPid} | Serial: {serial}"
                            });
                        }
                    }
                }
            }
            catch { }

            // Software and config files
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };

            foreach (var baseDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        if (ReasnowExecutables.Any(e =>
                            fname.Equals(e, StringComparison.OrdinalIgnoreCase)) ||
                            ReasnowKeywords.Any(k =>
                            fname.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "ReaSnow S1 Software/Config File",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "ReaSnow S1 hardware aimbot software or configuration file found on disk.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }

            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 6 — Brook UFB/Wingman artifacts
    // =========================================================================

    private Task CheckBrookArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // USB registry
            try
            {
                using var usbKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Enum\USB");
                if (usbKey is not null)
                {
                    foreach (var vidPid in usbKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!BrookVidPids.Any(v =>
                            vidPid.StartsWith(v, StringComparison.OrdinalIgnoreCase))) continue;

                        using var vpKey = usbKey.OpenSubKey(vidPid);
                        if (vpKey is null) continue;
                        foreach (var serial in vpKey.GetSubKeyNames())
                        {
                            using var devKey = vpKey.OpenSubKey(serial);
                            ctx.IncrementRegistryKeys();
                            var desc = devKey?.GetValue("DeviceDesc")?.ToString() ?? "";
                            bool isWingman = BrookKeywords.Any(k =>
                                desc.Contains(k, StringComparison.OrdinalIgnoreCase));
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = isWingman
                                    ? "Brook Wingman/UFB Device Detected"
                                    : "Brook USB Accessory in Registry (VID_0C12)",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\{vidPid}",
                                Reason = "Brook UFB or Wingman accessory USB device found in Windows device history. " +
                                         "Brook Wingman adapters are used to connect controllers with input remapping " +
                                         "capabilities that can enable aim-assist bypass on PC games.",
                                Detail = $"VID/PID: {vidPid} | DeviceDesc: {desc} | Serial: {serial}"
                            });
                        }
                    }
                }
            }
            catch { }

            // AppData configuration files
            var appDataDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Brook"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Brook"),
            };
            foreach (var dir in appDataDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Brook Accessory Software AppData Directory",
                    Risk = RiskLevel.High,
                    Location = dir,
                    Reason = "Brook accessory software configuration directory found in AppData.",
                    Detail = $"Directory: {dir}"
                });
            }

            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 7 — Arduino/Teensy/RP2040 HID aimbot firmware
    // =========================================================================

    private Task CheckArduinoHidFirmware(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // Arduino IDE / Teensy Loader in Program Files
            var programDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs"),
            };

            foreach (var baseDir in programDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        if (ArduinoKeywords.Any(k =>
                            fname.Contains(k, StringComparison.OrdinalIgnoreCase)) ||
                            fname.Equals("teensy.exe", StringComparison.OrdinalIgnoreCase) ||
                            fname.Equals("teensy_loader_cli.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Arduino/Teensy Development Tool Found",
                                Risk = RiskLevel.Medium,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "Arduino IDE or Teensy Loader found. These tools can be used to flash HID emulation " +
                                         "firmware onto microcontroller boards, which are then used as hardware aimbot devices. " +
                                         "Presence alone is not conclusive — check for .ino/.hex files with HID patterns.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }

            // .ino sketch files with Mouse.move / Keyboard.press
            var sketchDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents", "Arduino"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents", "Teensy"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            foreach (var dir in sketchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(dir, "*.ino", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            var hit = HidFirmwareKeywords.FirstOrDefault(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is not null)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Arduino Sketch with HID Mouse/Keyboard Code",
                                    Risk = RiskLevel.Critical,
                                    Location = Path.GetDirectoryName(f) ?? dir,
                                    FileName = Path.GetFileName(f),
                                    Reason = $"Arduino sketch file contains HID input injection code (matched '{hit}'). " +
                                             "This indicates firmware designed to emulate mouse/keyboard as a hardware aimbot device.",
                                    Detail = $"Path: {f} | Pattern: {hit}"
                                });
                            }
                        }
                        catch { }
                    }

                    // Raspberry Pi Pico Python scripts
                    foreach (var f in Directory.EnumerateFiles(dir, "*.py", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            var hit = PicoHidKeywords.FirstOrDefault(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is not null)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Raspberry Pi Pico HID Python Script",
                                    Risk = RiskLevel.Critical,
                                    Location = Path.GetDirectoryName(f) ?? dir,
                                    FileName = Path.GetFileName(f),
                                    Reason = $"Python script imports HID library (matched '{hit}'). " +
                                             "This is consistent with CircuitPython/MicroPython RP2040 aimbot firmware.",
                                    Detail = $"Path: {f} | Pattern: {hit}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // avrdude artifact check
            string? avrDude = null;
            foreach (var dir in programDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    var found = Directory.EnumerateFiles(dir, "avrdude.exe", SearchOption.AllDirectories)
                        .FirstOrDefault();
                    if (found is not null) { avrDude = found; break; }
                }
                catch { }
            }
            if (avrDude is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "avrdude Flash Tool Found",
                    Risk = RiskLevel.Medium,
                    Location = Path.GetDirectoryName(avrDude) ?? string.Empty,
                    FileName = "avrdude.exe",
                    Reason = "avrdude is an AVR microcontroller flash programmer. It is used to flash HID aimbot " +
                             "firmware onto Arduino/Teensy-class boards. Presence with .hex files is highly suspicious.",
                    Detail = $"Path: {avrDude}"
                });
            }
        }, ct);

    // =========================================================================
    // Sub-check 8 — vJoy virtual joystick driver artifacts
    // =========================================================================

    private Task CheckVjoyArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // Driver file in System32\drivers
            string driversDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
            foreach (var fname in VjoyDriverFiles)
            {
                var fullPath = Path.Combine(driversDir, fname);
                if (File.Exists(fullPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "vJoy Driver File in System32",
                        Risk = RiskLevel.High,
                        Location = driversDir,
                        FileName = fname,
                        Reason = "vJoy virtual joystick driver file found in System32\\drivers. vJoy creates a virtual " +
                                 "HID joystick device and is used to forward manipulated aimbot input to games, " +
                                 "bypassing direct input monitoring.",
                        Detail = $"Path: {fullPath}"
                    });
                }
            }

            // Registry: vJoy device in Device Manager
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var enumKey = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum");
                if (enumKey is not null)
                {
                    foreach (var bus in enumKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!bus.Contains("vjoy", StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "vJoy Device in Device Manager Registry",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Enum\{bus}",
                            Reason = "vJoy virtual joystick device entry found in Windows device enumeration.",
                            Detail = $"Key: {bus}"
                        });
                    }
                }
            }
            catch { }

            // Services registry check
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var svcKey = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\vjoy");
                if (svcKey is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var imagePath = svcKey.GetValue("ImagePath")?.ToString();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "vJoy Service Registry Entry",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\vjoy",
                        Reason = "vJoy virtual joystick driver service registered in Windows Services registry.",
                        Detail = $"ImagePath: {imagePath ?? "N/A"}"
                    });
                }
            }
            catch { }

            // Program Files SDK DLLs
            var pfDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            };
            foreach (var baseDir in pfDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*vjoy*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "vJoy SDK/Application File",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(f) ?? baseDir,
                            FileName = Path.GetFileName(f),
                            Reason = "vJoy SDK or application file found in Program Files. vJoy is used to " +
                                     "inject synthetic joystick inputs for aimbot applications.",
                            Detail = $"Path: {f}"
                        });
                    }
                }
                catch { }
            }

            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 9 — ViGEmBus virtual gamepad artifacts
    // =========================================================================

    private Task CheckVigemArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // Driver file check
            string driversDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
            foreach (var fname in VigemDriverFiles)
            {
                var driverPath = Path.Combine(driversDir, fname);
                if (File.Exists(driverPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ViGEmBus Driver File Found",
                        Risk = RiskLevel.High,
                        Location = driversDir,
                        FileName = fname,
                        Reason = "ViGEmBus virtual gamepad bus driver file found. ViGEmBus creates virtual Xbox/DS4 " +
                                 "controllers used by reWASD, DS4Windows, and similar tools to inject synthetic " +
                                 "controller input that can bypass standard HID monitoring.",
                        Detail = $"Path: {driverPath}"
                    });
                }
            }

            // Services registry
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var svcKey = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\ViGEmBus");
                if (svcKey is not null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ViGEmBus Service Installed",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\ViGEmBus",
                        Reason = "ViGEmBus virtual gamepad bus driver service registered. This driver is a dependency " +
                                 "for reWASD, DS4Windows, and Joystick Gremlin — tools used for controller input remapping " +
                                 "that can enable hardware-level aimbot injection.",
                        Detail = svcKey.GetValue("ImagePath")?.ToString() ?? "ImagePath not found"
                    });
                }
            }
            catch { }

            // Program Files scan for ViGEm-linked apps
            var pfDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };
            foreach (var baseDir in pfDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        if (VigemKeywords.Any(k =>
                            fname.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "ViGEmBus-Related Application File",
                                Risk = RiskLevel.Medium,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "File associated with ViGEmBus virtual gamepad ecosystem found (DS4Windows, reWASD, Joystick Gremlin).",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }

            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 10 — reWASD controller remapping artifacts
    // =========================================================================

    private Task CheckRewasdArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // reWASD installation directory
            var rewasdDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "reWASD"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "reWASD"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "reWASD"),
            };

            foreach (var dir in rewasdDirs)
            {
                if (Directory.Exists(dir))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "reWASD Installation Directory Found",
                        Risk = RiskLevel.High,
                        Location = dir,
                        Reason = "reWASD controller remapping software installation directory found. reWASD can remap " +
                                 "controller inputs and inject synthetic HID inputs, potentially bypassing aim input detection.",
                        Detail = $"Directory: {dir}"
                    });
                }
            }

            // Executable check
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };

            foreach (var baseDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        if (RewasdExecutables.Any(e =>
                            fname.Equals(e, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "reWASD Executable Found",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "reWASD process remapper executable found. This tool installs a USB filter driver " +
                                         "and virtual HID bus to intercept and remap controller inputs at the driver level.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }

            // .rewasd config files
            var configDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            };

            foreach (var baseDir in configDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*.rewasd", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "reWASD Configuration File",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(f) ?? baseDir,
                            FileName = Path.GetFileName(f),
                            Reason = "reWASD controller remapping configuration file found.",
                            Detail = $"Path: {f}"
                        });
                    }
                }
                catch { }
            }

            // USB filter driver registry check
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var svcKey = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\reWASD");
                if (svcKey is not null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "reWASD USB Filter Driver Service",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\reWASD",
                        Reason = "reWASD USB filter driver registered as a Windows service. This intercepts HID device " +
                                 "communications at the kernel level.",
                        Detail = svcKey.GetValue("ImagePath")?.ToString() ?? "ImagePath not found"
                    });
                }
            }
            catch { }

            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 11 — Logitech G-Hub macro script abuse
    // =========================================================================

    private Task CheckGhubMacroAbuse(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrWhiteSpace(localAppData)) return;

            var ghubScriptDir = Path.Combine(localAppData, "LGHUB", "script");
            if (!Directory.Exists(ghubScriptDir)) return;

            try
            {
                foreach (var f in Directory.EnumerateFiles(ghubScriptDir, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(f);

                    bool suspiciousName = GhubSuspiciousScriptNames.Any(n =>
                        fname.Contains(n, StringComparison.OrdinalIgnoreCase));

                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch { }

                    var hitPattern = GhubRecoilLuaPatterns.FirstOrDefault(p =>
                        content.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (hitPattern is not null || suspiciousName)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = suspiciousName && hitPattern is not null
                                ? "G-Hub Lua Script: Suspicious Name + Recoil/Aimbot Pattern"
                                : hitPattern is not null
                                    ? "G-Hub Lua Script with Anti-Recoil/Aimbot Code"
                                    : "G-Hub Lua Script with Suspicious Name",
                            Risk = hitPattern is not null ? RiskLevel.Critical : RiskLevel.High,
                            Location = ghubScriptDir,
                            FileName = fname,
                            Reason = hitPattern is not null
                                ? $"Logitech G-Hub Lua script contains pattern '{hitPattern}' consistent with " +
                                  "anti-recoil, aim compensation, or triggerbot macro code."
                                : $"Logitech G-Hub Lua script has a suspicious name suggesting aimbot or recoil " +
                                  "control functionality.",
                            Detail = $"Path: {f} | Pattern: {hitPattern ?? "suspicious name"}"
                        });
                    }
                }
            }
            catch { }

            // script.json with rapid-fire macros
            var scriptJsonPaths = new[]
            {
                Path.Combine(localAppData, "LGHUB", "script.json"),
                Path.Combine(localAppData, "LGHUB", "current", "script.json"),
            };

            foreach (var jsonPath in scriptJsonPaths)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(jsonPath)) continue;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsonPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    var hit = GhubRecoilLuaPatterns.FirstOrDefault(p =>
                        content.Contains(p, StringComparison.OrdinalIgnoreCase));
                    if (hit is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "G-Hub script.json with Rapid-Fire/Recoil Pattern",
                            Risk = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(jsonPath) ?? localAppData,
                            FileName = "script.json",
                            Reason = $"Logitech G-Hub script.json contains macro pattern '{hit}' indicating rapid-fire " +
                                     "or anti-recoil macro bindings in a G-Hub profile.",
                            Detail = $"Path: {jsonPath} | Pattern: {hit}"
                        });
                    }
                }
                catch { }
            }
        }, ct);

    // =========================================================================
    // Sub-check 12 — Razer Synapse macro script abuse
    // =========================================================================

    private Task CheckRazerMacroAbuse(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            string? appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrWhiteSpace(appData)) return;

            var razerDirs = new[]
            {
                Path.Combine(appData, "Razer"),
                Path.Combine(appData, "Razer", "Synapse3"),
                Path.Combine(appData, "Razer", "Synapse"),
                Path.Combine(appData, "Razer", "Razer Synapse 3"),
            };

            foreach (var razerDir in razerDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(razerDir)) continue;

                try
                {
                    foreach (var f in Directory.EnumerateFiles(razerDir, "*.json", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            var hit = RazerMacroKeywords.FirstOrDefault(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is not null)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Razer Synapse Macro with Anti-Recoil/Aimbot Pattern",
                                    Risk = RiskLevel.Critical,
                                    Location = Path.GetDirectoryName(f) ?? razerDir,
                                    FileName = Path.GetFileName(f),
                                    Reason = $"Razer Synapse macro file contains pattern '{hit}' consistent with " +
                                             "no-recoil, rapid-fire, or aimbot macro configuration.",
                                    Detail = $"Path: {f} | Pattern: {hit}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // Chroma App with aimbot-keyword script names
            var chromaAppDir = Path.Combine(appData, "Razer", "ChromaAppInfo");
            if (Directory.Exists(chromaAppDir))
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(chromaAppDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        if (RazerMacroKeywords.Any(k =>
                            fname.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Razer Chroma App with Aimbot Keyword",
                                Risk = RiskLevel.High,
                                Location = chromaAppDir,
                                FileName = fname,
                                Reason = "Razer Chroma application entry with aimbot/recoil keyword in name.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);

    // =========================================================================
    // Sub-check 13 — HORI TAC Pro / Target Strike artifacts
    // =========================================================================

    private Task CheckHoriArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // USB registry
            try
            {
                using var usbKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Enum\USB");
                if (usbKey is not null)
                {
                    foreach (var vidPid in usbKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!HoriVidPids.Any(v =>
                            vidPid.StartsWith(v, StringComparison.OrdinalIgnoreCase))) continue;

                        using var vpKey = usbKey.OpenSubKey(vidPid);
                        if (vpKey is null) continue;
                        foreach (var serial in vpKey.GetSubKeyNames())
                        {
                            using var devKey = vpKey.OpenSubKey(serial);
                            ctx.IncrementRegistryKeys();
                            var friendly = devKey?.GetValue("FriendlyName")?.ToString() ?? "";
                            var isTacPro = HoriKeywords.Any(k =>
                                friendly.Contains(k, StringComparison.OrdinalIgnoreCase));
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = isTacPro
                                    ? "HORI TAC Pro/Target Strike Device Detected"
                                    : "HORI USB Device (VID_0F0D) in Registry",
                                Risk = isTacPro ? RiskLevel.Critical : RiskLevel.Medium,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Enum\USB\{vidPid}",
                                Reason = isTacPro
                                    ? $"HORI TAC Pro or Target Strike hardware detected ('{friendly}'). " +
                                      "These are dedicated hardware devices with built-in aim-assist that bypass " +
                                      "software anti-cheat by operating at the USB HID level."
                                    : $"HORI USB device with VID_0F0D found. Some HORI devices include the TAC Pro " +
                                      "and Target Strike which provide hardware-level aim assistance.",
                                Detail = $"VID/PID: {vidPid} | FriendlyName: {friendly} | Serial: {serial}"
                            });
                        }
                    }
                }
            }
            catch { }

            // HORI configuration software search
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            };

            foreach (var baseDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(f);
                        if (HoriKeywords.Any(k =>
                            fname.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "HORI TAC Pro/Target Strike Configuration File",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(f) ?? baseDir,
                                FileName = fname,
                                Reason = "HORI TAC Pro or Target Strike configuration software or file found.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }

            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 14 — Hardware aimbot purchase/download artifacts
    // =========================================================================

    private Task CheckPurchaseDownloadArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // Downloads folder for known archive/installer names
            string downloadsDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

            if (Directory.Exists(downloadsDir))
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(downloadsDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileNameWithoutExtension(f);
                        if (PurchaseDownloadNames.Any(n =>
                            fname.Contains(n, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Hardware Aimbot Software Download",
                                Risk = RiskLevel.Critical,
                                Location = downloadsDir,
                                FileName = Path.GetFileName(f),
                                Reason = "Downloaded file with hardware aimbot device software name found. " +
                                         "This indicates acquisition of hardware aimbot device management software.",
                                Detail = $"Path: {f}"
                            });
                        }

                        // Also check for purchase-intent keywords in filenames
                        if (PurchaseSearchTerms.Any(t =>
                            fname.Contains(t.Replace(" ", "_"), StringComparison.OrdinalIgnoreCase) ||
                            fname.Contains(t.Replace(" ", "-"), StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Hardware Aimbot Purchase-Related Download",
                                Risk = RiskLevel.High,
                                Location = downloadsDir,
                                FileName = Path.GetFileName(f),
                                Reason = "File in Downloads directory with hardware aimbot purchase-related keyword.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }

            // Browser history check using SQLite (Chromium) — search for purchase terms
            string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            string? appData = Environment.GetEnvironmentVariable("APPDATA");

            var historyDbs = new List<string>();
            if (!string.IsNullOrWhiteSpace(localAppData))
            {
                var chromiumRoots = new[]
                {
                    Path.Combine(localAppData, "Google", "Chrome", "User Data"),
                    Path.Combine(localAppData, "Microsoft", "Edge", "User Data"),
                    Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data"),
                };
                foreach (var root in chromiumRoots)
                {
                    if (!Directory.Exists(root)) continue;
                    try
                    {
                        foreach (var profile in Directory.GetDirectories(root))
                        {
                            var db = Path.Combine(profile, "History");
                            if (File.Exists(db)) historyDbs.Add(db);
                        }
                    }
                    catch { }
                }
            }

            foreach (var dbPath in historyDbs)
            {
                ct.ThrowIfCancellationRequested();
                string? tempPath = null;
                try
                {
                    tempPath = Path.Combine(Path.GetTempPath(),
                        "zt_hwab_hist_" + Guid.NewGuid().ToString("N") + ".db");
                    File.Copy(dbPath, tempPath, overwrite: true);

                    using var fs = new FileStream(tempPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string rawContent = await sr.ReadToEndAsync(ct);

                    var hit = PurchaseSearchTerms.FirstOrDefault(t =>
                        rawContent.Contains(t, StringComparison.OrdinalIgnoreCase));
                    if (hit is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History: Hardware Aimbot Purchase Search",
                            Risk = RiskLevel.High,
                            Location = dbPath,
                            FileName = "History",
                            Reason = $"Browser history contains search term '{hit}' indicating research into or " +
                                     "purchase of hardware aimbot devices.",
                            Detail = $"History DB: {dbPath} | Term: {hit}"
                        });
                    }
                }
                catch { }
                finally
                {
                    if (tempPath is not null)
                        try { File.Delete(tempPath); } catch { }
                }
            }
        }, ct);

    // =========================================================================
    // Sub-check 15 — HID filter driver abuse (UpperFilters/LowerFilters)
    // =========================================================================

    private Task CheckHidFilterDriverAbuse(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            const string classBase = @"SYSTEM\CurrentControlSet\Control\Class";

            foreach (var guid in HidClassGuids)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                    using var classKey = baseKey.OpenSubKey(Path.Combine(classBase, guid), writable: false);
                    if (classKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var filterType in new[] { "UpperFilters", "LowerFilters" })
                    {
                        var filters = classKey.GetValue(filterType) as string[];
                        if (filters is null || filters.Length == 0) continue;

                        foreach (var driver in filters)
                        {
                            if (string.IsNullOrWhiteSpace(driver)) continue;
                            bool isLegit = LegitimateFilterDrivers.Any(l =>
                                driver.Equals(l, StringComparison.OrdinalIgnoreCase));
                            if (isLegit) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious HID {filterType}: {driver}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{classBase}\{guid}",
                                Reason = $"Non-Microsoft HID {filterType} driver '{driver}' found in device class " +
                                         $"'{guid}'. HID filter drivers intercept all input from keyboards or mice " +
                                         "at the kernel level. This technique is used by hardware aimbot controllers " +
                                         "(reWASD, vJoy, custom HID filters) to inject synthetic aim inputs.",
                                Detail = $"FilterType: {filterType} | Driver: {driver} | Class GUID: {guid}"
                            });
                        }
                    }
                }
                catch { }
            }

            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 16 — Hardware aimbot firmware files (.hex/.bin/.uf2)
    // =========================================================================

    private Task CheckFirmwareFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            var searchDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };

            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var ext = Path.GetExtension(f);
                        var fname = Path.GetFileName(f);

                        if (!FirmwareExtensions.Any(e =>
                            ext.Equals(e, StringComparison.OrdinalIgnoreCase))) continue;

                        ctx.IncrementFiles();

                        // .uf2 files are always Raspberry Pi Pico / RP2040 firmware images
                        if (ext.Equals(".uf2", StringComparison.OrdinalIgnoreCase))
                        {
                            bool aimbotName = FirmwareHidKeywords.Any(k =>
                                fname.Contains(k, StringComparison.OrdinalIgnoreCase)) ||
                                KmboxKeywords.Any(k =>
                                fname.Contains(k, StringComparison.OrdinalIgnoreCase));

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = aimbotName
                                    ? "RP2040/Pico Firmware with Aimbot Keyword in Name"
                                    : "RP2040/Pico UF2 Firmware File",
                                Risk = aimbotName ? RiskLevel.Critical : RiskLevel.Medium,
                                Location = Path.GetDirectoryName(f) ?? dir,
                                FileName = fname,
                                Reason = aimbotName
                                    ? "UF2 firmware image for Raspberry Pi Pico/RP2040 with aimbot-related name. " +
                                      "These files are flashed onto RP2040 boards to create HID aimbot devices."
                                    : "UF2 firmware image found. RP2040 firmware images in user directories may indicate " +
                                      "custom hardware device flashing activity.",
                                Detail = $"Path: {f}"
                            });
                            continue;
                        }

                        // .hex / .bin — check content for HID descriptors
                        try
                        {
                            var fi = new FileInfo(f);
                            if (fi.Length > 2 * 1024 * 1024) continue; // skip > 2 MB binary blobs

                            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            var hit = FirmwareHidKeywords.FirstOrDefault(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is not null)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Firmware File with HID Mouse/Keyboard Descriptor",
                                    Risk = RiskLevel.Critical,
                                    Location = Path.GetDirectoryName(f) ?? dir,
                                    FileName = fname,
                                    Reason = $"Firmware file ({ext}) contains HID input emulation code/descriptor " +
                                             $"(matched '{hit}'). This firmware is designed to make a microcontroller " +
                                             "appear as a mouse/keyboard HID device for aimbot input injection.",
                                    Detail = $"Path: {f} | Pattern: {hit}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }, ct);

    // =========================================================================
    // Sub-check 17 — Registry traces (UserAssist, MuiCache, Run/RunOnce, installer)
    // =========================================================================

    private Task CheckRegistryToolTraces(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            // UserAssist — ROT13 encoded application execution history
            const string userAssistPath =
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
            try
            {
                using var uaKey = Registry.CurrentUser.OpenSubKey(userAssistPath);
                if (uaKey is not null)
                {
                    foreach (var guidKey in uaKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        using var countKey = uaKey.OpenSubKey(Path.Combine(guidKey, "Count"));
                        if (countKey is null) continue;

                        foreach (var valueName in countKey.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();
                            var decoded = Rot13(valueName);
                            var hit = UserAssistToolKeywords.FirstOrDefault(k =>
                                decoded.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"UserAssist: Hardware Aimbot Tool Executed — {hit}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\{userAssistPath}\{guidKey}\Count",
                                Reason = $"Windows UserAssist registry records execution of hardware aimbot tool matching '{hit}'. " +
                                         "UserAssist persists a ROT13-encoded history of executed programs even after deletion.",
                                Detail = $"Decoded entry: {decoded}"
                            });
                        }
                    }
                }
            }
            catch { }

            // MuiCache — stores display names of executed applications
            const string muiCachePath =
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
            try
            {
                using var muiKey = Registry.CurrentUser.OpenSubKey(muiCachePath);
                if (muiKey is not null)
                {
                    foreach (var valueName in muiKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        var hit = UserAssistToolKeywords.FirstOrDefault(k =>
                            valueName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"MuiCache: Hardware Aimbot Tool Execution Trace — {hit}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{muiCachePath}",
                            Reason = $"Windows MuiCache records a previous execution of hardware aimbot tool matching '{hit}'. " +
                                     "This trace persists even after the application is uninstalled.",
                            Detail = $"MuiCache entry: {valueName}"
                        });
                    }
                }
            }
            catch { }

            // Run/RunOnce autostart for aimbot tools
            var runKeys = new[]
            {
                (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run"),
                (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
                (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            };

            foreach (var (hive, keyPath) in runKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                    using var runKey = baseKey.OpenSubKey(keyPath);
                    if (runKey is null) continue;

                    foreach (var valueName in runKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        var value = runKey.GetValue(valueName)?.ToString() ?? "";
                        var combined = valueName + " " + value;
                        var hit = UserAssistToolKeywords.FirstOrDefault(k =>
                            combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Run Autostart: Hardware Aimbot Tool — {hit}",
                            Risk = RiskLevel.Critical,
                            Location = $@"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}",
                            Reason = $"Hardware aimbot tool matching '{hit}' found in Windows autostart Run key.",
                            Detail = $"ValueName: {valueName} | Command: {value}"
                        });
                    }
                }
                catch { }
            }

            // Uninstall key traces (installer artifacts)
            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            foreach (var uninstallPath in uninstallPaths)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                    using var uKey = baseKey.OpenSubKey(uninstallPath);
                    if (uKey is null) continue;

                    foreach (var appKey in uKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        using var app = uKey.OpenSubKey(appKey);
                        if (app is null) continue;
                        ctx.IncrementRegistryKeys();

                        var displayName = app.GetValue("DisplayName")?.ToString() ?? "";
                        var publisher = app.GetValue("Publisher")?.ToString() ?? "";
                        var combined = displayName + " " + publisher;

                        var hit = UserAssistToolKeywords.FirstOrDefault(k =>
                            combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Installed/Uninstalled Hardware Aimbot Tool: {displayName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{uninstallPath}\{appKey}",
                            Reason = $"Hardware aimbot tool matching '{hit}' found in Windows installer registry. " +
                                     "This indicates the tool was installed on this system (may have been uninstalled).",
                            Detail = $"DisplayName: {displayName} | Publisher: {publisher}"
                        });
                    }
                }
                catch { }
            }

            await Task.CompletedTask;
        }, ct);

    // =========================================================================
    // Sub-check 18 — Discord cache hardware aimbot artifacts
    // =========================================================================

    private Task CheckDiscordHardwareAimbotArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ct.ThrowIfCancellationRequested();

            string? appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrWhiteSpace(appData)) return;

            var discordClients = new[] { "discord", "discordptb", "discordcanary" };

            foreach (var client in discordClients)
            {
                ct.ThrowIfCancellationRequested();
                var clientRoot = Path.Combine(appData, client);
                if (!Directory.Exists(clientRoot)) continue;

                // Cache directories to scan
                var cacheDirs = new[]
                {
                    Path.Combine(clientRoot, "Cache", "Cache_Data"),
                    Path.Combine(clientRoot, "Cache"),
                    Path.Combine(clientRoot, "Local Storage", "leveldb"),
                    Path.Combine(clientRoot, "Session Storage"),
                };

                foreach (var cacheDir in cacheDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!Directory.Exists(cacheDir)) continue;

                    try
                    {
                        foreach (var f in Directory.EnumerateFiles(cacheDir).Take(100))
                        {
                            ct.ThrowIfCancellationRequested();
                            var fi = new FileInfo(f);
                            if (fi.Length > 4 * 1024 * 1024) continue;

                            ctx.IncrementFiles();
                            try
                            {
                                using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs, detectEncodingFromByteOrderMarks: false,
                                    fallbackEncoding: System.Text.Encoding.Latin1);
                                string content = await sr.ReadToEndAsync(ct);

                                var hit = DiscordHardwareKeywords.FirstOrDefault(k =>
                                    content.Contains(k, StringComparison.OrdinalIgnoreCase));
                                if (hit is not null)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Discord Cache: Hardware Aimbot Keyword '{hit}'",
                                        Risk = RiskLevel.High,
                                        Location = cacheDir,
                                        FileName = Path.GetFileName(f),
                                        Reason = $"Discord client cache contains reference to hardware aimbot keyword '{hit}'. " +
                                                 "This indicates discussions or community activity related to hardware aimbot devices " +
                                                 "in the user's Discord history.",
                                        Detail = $"Client: {client} | Cache: {cacheDir} | File: {Path.GetFileName(f)} | Keyword: {hit}"
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }

            // Downloads: hardware aimbot manuals and guides
            string downloadsDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (Directory.Exists(downloadsDir))
            {
                try
                {
                    foreach (var f in Directory.EnumerateFiles(downloadsDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileNameWithoutExtension(f);
                        if (DiscordDeviceManualNames.Any(n =>
                            fname.Contains(n, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Hardware Aimbot Manual/Guide Download",
                                Risk = RiskLevel.High,
                                Location = downloadsDir,
                                FileName = Path.GetFileName(f),
                                Reason = "Downloaded file matching a hardware aimbot device manual or guide name pattern.",
                                Detail = $"Path: {f}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);

    // =========================================================================
    // Helpers
    // =========================================================================

    private static string Rot13(string input)
    {
        var sb = new System.Text.StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (c >= 'a' && c <= 'z')
                sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z')
                sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }
}
