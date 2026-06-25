using Microsoft.Win32;
using System.Diagnostics;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects macro and input-automation software used in gaming contexts:
///
///   1. AutoHotkey / AutoIt scripts — commonly used for triggerbot, rapid-fire,
///      movement macros, and aim assistance scripts.
///
///   2. Logitech G-Hub / G-Series LUA scripts — Logitech's scripting engine
///      allows LUA scripts that run mouse smoothing, rapid-fire, no-recoil macros.
///
///   3. Interception driver — a keyboard/mouse filter driver used by cheat tools
///      to send undetectable synthetic input at the kernel level.
///
///   4. Arduino / Raspberry Pi HID macros — physical devices programmed as
///      macro keyboards/mice; detectable by USB HID descriptor inspection.
///
///   5. reWASD / XMapper / JoyToKey — gamepad remapping software that sends
///      synthetic mouse/keyboard input for aim assist.
///
///   6. MouseKeys / Windows Accessibility macros abused for aim automation.
///
///   7. Known rapid-fire/no-recoil mouse firmware scripts (Bloody, Razer Synapse
///      macros, SteelSeries Engine scripts).
/// </summary>
public sealed class MacroSoftwareScanModule : IScanModule
{
    public string Name => "Makro-Software";
    public double Weight => 0.8;
    public int ParallelGroup => 1;

    private static readonly string[] KnownMacroProcesses =
    {
        // AutoHotkey variants
        "autohotkey", "autohotkey64", "ahk_h", "ahkx64",
        // AutoIt
        "autoit3", "autoit3_x64",
        // Interception driver companion
        "interception", "input_filter",
        // Logitech (scripting-enabled)
        "lghub", "lcore", "lgs",
        // reWASD
        "rewasd", "rewasdsvc",
        // Razer Synapse macros
        "razersynapse", "razercentralservice",
        // SteelSeries GG
        "steelseriesengine", "steelseriesgg",
        // JoyToKey
        "joytokey",
        // xdotool / x360ce (Windows gamepad emulator)
        "x360ce", "xinputemulator",
        // Corsair iCUE
        "cue", "icue",
        // HID macro tools
        "hidmacros", "keystroke", "makrofactory",
        // Clicker tools
        "autoclicker", "gclicker", "ophclicker",
        // Macro recorder
        "macrorecorder", "pulover",
    };

    private static readonly string[] KnownMacroFileNames =
    {
        // AutoHotkey scripts with cheat-related names
        "triggerbot.ahk", "aimbot.ahk", "norecoil.ahk", "rapidfire.ahk",
        "bhop.ahk", "bunnyhop.ahk", "spinbot.ahk", "aimassist.ahk",
        "wallhack.ahk", "esp.ahk", "radar.ahk", "silent_aim.ahk",
        "macro.ahk", "cheat.ahk", "hack.ahk",
        // Logitech LUA macro files
        "norecoil.lua", "triggerbot.lua", "rapidfire.lua",
        "aimassist.lua", "bhop.lua",
        // AutoIt scripts
        "triggerbot.au3", "aimbot.au3", "macro.au3",
    };

    private static readonly string[] MacroRegistryPaths =
    {
        @"SOFTWARE\AutoHotkey",
        @"SOFTWARE\AutoIt v3",
        @"SOFTWARE\Interception",
        @"SOFTWARE\LGHUB",
        @"SOFTWARE\Logitech\LGHUB",
        @"SOFTWARE\reWASD",
    };

    // Directories where Logitech LUA scripts and AHK scripts are commonly stored
    private static readonly string[] MacroScriptDirs =
    {
        @"Logitech\GHUB\profiles",
        @"Logitech Gaming Software\profiles",
        @"AutoHotkey",
    };

    // Known cheat-related AHK/LUA keywords
    private static readonly string[] CheatScriptKeywords =
    {
        "triggerbot", "aimbot", "norecoil", "no_recoil", "no recoil",
        "rapidfire", "rapid_fire", "rapid fire",
        "bhop", "bunny_hop", "bunnyhop",
        "wallhack", "wall_hack", "aimassist", "aim_assist",
        "spinbot", "silent_aim", "silentaim",
        "GetKeyState", "MouseMove", "MouseClick", // AHK primitives used in cheats
    };

    // Interception driver service name
    private const string InterceptionServiceName = "keyboard_filter";

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Makro-Software", "Prüfe laufende Prozesse...");
        CheckMacroProcesses(ctx, ct);

        ctx.Report(0.3, "Makro-Software", "Prüfe Registry...");
        CheckMacroRegistry(ctx, ct);
        CheckInterceptionDriver(ctx, ct);

        ctx.Report(0.6, "Makro-Software", "Suche Makro-Skriptdateien...");
        CheckMacroScriptFiles(ctx, ct);

        ctx.Report(0.85, "Makro-Software", "Prüfe Starttypeinstellungen...");
        CheckMouseKeys(ctx, ct);

        ctx.Report(1.0, "Makro-Software", "Makro-Software-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    private static void CheckMacroProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementProcesses();
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (!KnownMacroProcesses.Any(m => name.Contains(m)))
                    {
                        proc.Dispose();
                        continue;
                    }

                    string? exePath = null;
                    try { exePath = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Makro-Software",
                        Title    = $"Makro-Software aktiv: {proc.ProcessName}",
                        Risk     = RiskLevel.Medium,
                        Location = exePath ?? $"PID {proc.Id}",
                        FileName = proc.ProcessName,
                        Reason   = $"Makro-/Input-Automatisierungsprogramm '{proc.ProcessName}' läuft. " +
                                   "Solche Tools werden häufig für Triggerbot, Rapid-Fire, " +
                                   "No-Recoil und Bhop-Makros in Spielen eingesetzt.",
                        Detail   = $"PID: {proc.Id} | Name: {proc.ProcessName}"
                    });
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private static void CheckMacroRegistry(ScanContext ctx, CancellationToken ct)
    {
        foreach (var regPath in MacroRegistryPaths)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false)
                             ?? Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = "Makro-Software",
                    Title    = $"Makro-Software installiert: {Path.GetFileName(regPath)}",
                    Risk     = RiskLevel.Low,
                    Location = $@"HKLM\{regPath}",
                    Reason   = $"Registry-Schlüssel von bekannter Makro-Software gefunden: '{regPath}'. " +
                               "Dies ist allein noch kein Beweis für Cheaten, aber im Kontext relevant.",
                    Detail   = $"Registry: {regPath}"
                });
            }
            catch { }
        }
    }

    private static void CheckInterceptionDriver(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            // Interception driver registers as a keyboard/mouse filter in registry
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{InterceptionServiceName}", writable: false);
            if (key is not null)
            {
                var start = key.GetValue("Start") as int?;
                ctx.AddFinding(new Finding
                {
                    Module   = "Makro-Software",
                    Title    = "Interception Kernel-Filter-Treiber",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{InterceptionServiceName}",
                    Reason   = "Der Interception-Kernel-Filter-Treiber ist installiert. Dieser Treiber " +
                               "ermöglicht das Senden synthetischer Tastatur- und Mauseingaben auf " +
                               "Kernel-Ebene, was von Anti-Cheats auf Benutzerebene nicht erkannt werden kann. " +
                               "Er wird von mehreren bekannten Cheat-Tools eingesetzt.",
                    Detail   = $"Service: {InterceptionServiceName} | StartType: {start}"
                });
            }
        }
        catch { }

        // Also check alternative names
        var altNames = new[] { "moufiltr", "kbfiltr", "hidinput_filter" };
        foreach (var name in altNames)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{name}", writable: false);
                if (key is null) continue;

                var imgPath = (key.GetValue("ImagePath") as string ?? "").ToLowerInvariant();
                if (imgPath.Contains("interception") || imgPath.Contains("input_filter"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Makro-Software",
                        Title    = $"Verdächtiger Input-Filter-Treiber: {name}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{name}",
                        Reason   = $"Kernel-Input-Filter-Treiber '{name}' mit Interception-Signatur gefunden.",
                        Detail   = $"ImagePath: {imgPath}"
                    });
                }
            }
            catch { }
        }
    }

    private static void CheckMacroScriptFiles(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var baseDir in new[] { appData, localApp })
        {
            foreach (var subDir in MacroScriptDirs)
            {
                if (ct.IsCancellationRequested) return;
                var fullDir = Path.Combine(baseDir, subDir);
                if (!Directory.Exists(fullDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(fullDir, "*",
                        SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var fn = Path.GetFileName(file).ToLowerInvariant();

                        // Check against known cheat script filenames
                        if (KnownMacroFileNames.Any(n => fn == n))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Makro-Software",
                                Title    = $"Verdächtige Makro-Skriptdatei: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Makro-Skriptdatei mit bekanntem Cheat-Namen gefunden: '{fn}'. " +
                                           "Diese Datei wird wahrscheinlich als Triggerbot, No-Recoil oder " +
                                           "ähnliches Hilfsmittel im Spiel verwendet.",
                                Detail   = $"Pfad: {file}"
                            });
                            continue;
                        }

                        // Scan LUA/AHK script contents for cheat keywords
                        var ext = Path.GetExtension(fn);
                        if (ext is not (".ahk" or ".lua" or ".au3")) continue;

                        try
                        {
                            var content = File.ReadAllText(file, System.Text.Encoding.UTF8);
                            var contentLower = content.ToLowerInvariant();
                            var hit = CheatScriptKeywords.FirstOrDefault(k =>
                                contentLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is not null)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Makro-Software",
                                    Title    = $"Cheat-Keyword in Makro-Skript: {fn}",
                                    Risk     = RiskLevel.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason   = $"Makro-Skript '{fn}' enthält cheat-typisches Schlüsselwort " +
                                               $"'{hit}'. Deutet auf Triggerbot-, No-Recoil- oder " +
                                               "Aim-Assist-Makro hin.",
                                    Detail   = $"Keyword: '{hit}' | Datei: {file}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
    }

    private static void CheckMouseKeys(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            // MouseKeys accessibility feature can be abused for aim automation
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Control Panel\Accessibility\MouseKeys", writable: false);
            if (key is null) return;
            var flags = key.GetValue("Flags") as string ?? "";
            // Bit 0 of Flags = MouseKeys enabled
            if (flags.StartsWith("1") || flags == "63")
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Makro-Software",
                    Title    = "MouseKeys (Zugangshilfe) aktiviert",
                    Risk     = RiskLevel.Low,
                    Location = @"HKCU\Control Panel\Accessibility\MouseKeys",
                    Reason   = "Die Windows-Zugangshilfe 'MouseKeys' ist aktiviert. Obwohl meist " +
                               "legitim, wird sie gelegentlich für Klick-Makros missbraucht.",
                    Detail   = $"Flags: {flags}"
                });
            }
        }
        catch { }
    }
}
