using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class AimbotMouseSignatureScanModule : IScanModule
{
    public string Name => "Aimbot & Mouse Behavior Artifact Detection";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    private static readonly string[] AimbotExeNames =
    {
        "aimbot.exe", "aim_bot.exe", "aimassist.exe", "aim_assist.exe",
        "triggerbot.exe", "trigger_bot.exe", "noRecoil.exe", "no_recoil.exe",
        "recoil_script.exe", "bhop.exe", "bunny_hop.exe", "bunnyhop.exe",
        "autoaim.exe", "auto_aim.exe", "legit_aimbot.exe", "rage_aimbot.exe",
        "silent_aim.exe", "silentaim.exe", "aim_hack.exe", "aimhack.exe",
        "triggerbot_cs2.exe", "triggerbot_csgo.exe", "csgo_aimbot.exe",
        "cs2_aimbot.exe", "valorant_aimbot.exe", "apex_aimbot.exe",
        "fortnite_aimbot.exe", "pubg_aimbot.exe", "rust_aimbot.exe",
        "external_aim.exe", "internal_aim.exe", "memoryaimbot.exe",
        "mem_aim.exe", "aimbot_v2.exe", "aimbot_v3.exe", "aimbot_lite.exe",
        "aimbot_pro.exe", "aim_trainer_hack.exe", "triggerkey.exe",
        "aim_key.exe", "aimkey.exe", "flick_aim.exe", "flick_aimbot.exe",
        "humanizer_aim.exe", "humanize_aim.exe", "smooth_aim.exe",
        "smoothaim.exe", "prediction_aim.exe", "boneaimbot.exe",
        "bone_aim.exe", "headaim.exe", "head_aim.exe", "chestaimbot.exe",
        "headshotbot.exe", "headshot_bot.exe", "aimbot_loader.exe",
        "aimbot_injector.exe", "aim_injector.exe",
    };

    private static readonly string[] AimbotDllNames =
    {
        "aimbot.dll", "aim.dll", "triggerbot.dll", "noRecoil.dll",
        "bhop.dll", "autoaim.dll", "aim_assist.dll", "silentaim.dll",
        "silent_aim.dll", "aimhack.dll", "aim_hack.dll",
        "no_recoil.dll", "recoil_control.dll", "aimbot_lib.dll",
        "aimbot_core.dll", "aim_core.dll", "triggerkey.dll",
    };

    private static readonly string[] AimbotConfigKeys =
    {
        "fov", "smoothing", "aim_key", "trigger_key", "bone_target",
        "aim_speed", "prediction", "aimbot_enabled", "legit_mode",
        "rage_mode", "silent_aim", "aim_fov", "triggerbot_enabled",
        "trigger_delay", "trigger_chance", "recoil_control",
        "recoil_x", "recoil_y", "spray_control", "bhop_enabled",
        "bunny_hop", "auto_strafe", "aim_bone", "target_bone",
        "aim_smooth", "smooth_factor", "fov_size", "triggerbot_fov",
        "aimbot_fov", "max_distance", "visibility_check",
        "auto_fire", "auto_aim", "draw_fov", "draw_crosshair",
        "aimbot_hotkey", "trigger_hotkey", "esp_enabled", "wallhack",
    };

    private static readonly string[] PythonAimbotFileNames =
    {
        "aimbot.py", "triggerbot.py", "aim.py", "mouse_control.py",
        "aim_assist.py", "trigger.py", "noRecoil.py", "no_recoil.py",
        "bhop.py", "bunnyhop.py", "autoaim.py", "silent_aim.py",
        "aim_bot.py", "aimhack.py", "recoil_control.py",
        "spray_control.py", "mouse_aim.py", "game_aim.py",
        "screen_aim.py", "pixel_aim.py", "color_aim.py",
        "yolo_aim.py", "nn_aim.py", "ai_aim.py", "aim_ai.py",
    };

    private static readonly string[] PythonAimbotImports =
    {
        "import cv2", "import pyautogui", "import win32api",
        "import win32con", "from win32api", "from win32con",
        "import pydirectinput", "import mouse", "from mouse import",
        "import mss", "from mss import", "import keyboard",
        "ctypes.windll", "user32.mouse_event", "SendInput",
        "mouse_event", "SetCursorPos", "GetCursorPos",
        "MOUSEINPUT", "INPUT_MOUSE", "mouse.move", "pyautogui.moveTo",
        "pyautogui.click", "pydirectinput.moveTo",
    };

    private static readonly string[] RecoilAhkFileNames =
    {
        "no_recoil.ahk", "recoil_control.ahk", "spray_control.ahk",
        "macro.ahk", "rapidfire.ahk", "rapid_fire.ahk",
        "no_spray.ahk", "anti_recoil.ahk", "antirecoil.ahk",
        "logitech_no_recoil.ahk", "csgo_no_recoil.ahk",
        "cs2_no_recoil.ahk", "valorant_no_recoil.ahk",
        "rapid_fire.ahk", "auto_fire.ahk", "auto_click.ahk",
        "recoil.ahk", "spray.ahk", "bhop.ahk", "bunnyhop.ahk",
        "bhop_script.ahk", "movement.ahk", "strafe.ahk",
        "triggerbot.ahk", "trigger.ahk", "aimbot.ahk",
    };

    private static readonly string[] AhkRecoilPatterns =
    {
        "MouseMove", "DllCall(\"mouse_event\"", "Send {Click",
        "MouseClick", "Click,", "WinActivate", "PixelGetColor",
        "PixelSearch", "ImageSearch", "DllCall(\"SendInput",
        "GetCursorPos", "SetCursorPos", "BlockInput",
        "Sleep, 1", "Sleep,1", "Loop, {", "Loop {",
    };

    private static readonly string[] ArduinoAimbotFileNames =
    {
        "mouse_move.ino", "aimbot.ino", "hid_aimbot.ino",
        "mouse_control.ino", "aim_control.ino", "game_aim.ino",
        "triggerbot.ino", "recoil_control.ino", "no_recoil.ino",
        "bhop.ino", "hid_mouse.ino", "usb_mouse.ino",
        "arduino_aimbot.ino", "mouse_emulator.ino",
        "rapid_fire.ino", "auto_fire.ino", "autofire.ino",
    };

    private static readonly string[] ArduinoAimbotPatterns =
    {
        "Mouse.move(", "Mouse.click(", "Mouse.begin()",
        "Mouse.press(", "Mouse.release(", "#include <Mouse.h>",
        "Mouse.h>", "Keyboard.press(", "Keyboard.release(",
        "HID().SendReport(", "usb_hid.SendReport(",
    };

    private static readonly string[] CronusGpcFilePatterns =
    {
        "anti_recoil", "antirecoil", "no_recoil", "norecoil",
        "aimbot", "aim_bot", "auto_aim", "triggerbot",
        "rapid_fire", "rapidfire", "bhop", "bunnyhop",
        "recoil_control", "spray_control", "aim_assist",
    };

    private static readonly string[] LogitechLuaRecoilPatterns =
    {
        "OnEvent(", "recoil", "anti_recoil", "MoveMouseRelative(",
        "MoveMouseTo(", "PressMouseButton(", "ReleaseMouseButton(",
        "Sleep(", "GetRunningTime(", "OutputLogMessage(",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        ScanAimbotExecutables(ctx, ct);
        ctx.Report(0.10, "Aimbot-Executables", "Aimbot-Ausfuehrdateien gesucht");
        ct.ThrowIfCancellationRequested();

        ScanAimbotDlls(ctx, ct);
        ctx.Report(0.18, "Aimbot-DLLs", "Aimbot-DLLs gesucht");
        ct.ThrowIfCancellationRequested();

        await ScanAimbotConfigFilesAsync(ctx, ct);
        ctx.Report(0.26, "Aimbot-Konfigurationen", "Aimbot-Konfigurationsdateien geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanPythonAimbotScriptsAsync(ctx, ct);
        ctx.Report(0.36, "Python-Aimbots", "Python-Aimbot-Skripte geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanAhkRecoilScriptsAsync(ctx, ct);
        ctx.Report(0.46, "AHK-Recoil-Skripte", "AutoHotkey Recoil-Skripte geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanArduinoAimbotSketchesAsync(ctx, ct);
        ctx.Report(0.55, "Arduino-Aimbots", "Arduino-Aimbot-Skizzen geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanRaspberryPicoAimbotAsync(ctx, ct);
        ctx.Report(0.62, "Raspberry-Pi-Aimbots", "Raspberry-Pi-Pico-Aimbot-Skripte geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanCronusZenArtifactsAsync(ctx, ct);
        ctx.Report(0.70, "Cronus-Zen", "Cronus-Zen/Max-Artefakte geprueft");
        ct.ThrowIfCancellationRequested();

        ScanXimApexArtifacts(ctx);
        ctx.Report(0.76, "Xim-Apex", "Xim-Adapter-Konfigurationen geprueft");
        ct.ThrowIfCancellationRequested();

        ScanTitanTwoArtifacts(ctx);
        ctx.Report(0.82, "Titan-Two", "Titan-Two-Konfigurationen geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanLogitechGHubScriptsAsync(ctx, ct);
        ctx.Report(0.90, "Logitech-G-Hub", "Logitech-G-Hub-Lua-Skripte geprueft");
        ct.ThrowIfCancellationRequested();

        ScanSteelSeriesArtifacts(ctx);
        ctx.Report(0.95, "SteelSeries", "SteelSeries-Engine-Artefakte geprueft");
        ct.ThrowIfCancellationRequested();

        ScanAimbotRegistryArtifacts(ctx);
        ctx.Report(1.0, "Registry-Artefakte", "Aimbot-Registry-Spuren geprueft");
    }

    private void ScanAimbotExecutables(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*.exe", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(file);

                foreach (var aimbotName in AimbotExeNames)
                {
                    if (fileName.Equals(aimbotName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        DateTime writeTime;
                        try { writeTime = File.GetLastWriteTime(file); }
                        catch { writeTime = DateTime.MinValue; }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Aimbot-Executable gefunden: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Die Datei '{fileName}' entspricht dem bekannten Namen einer Aimbot- " +
                                     "oder Triggerbot-Software. Aimbot-Programme manipulieren die Mauseingabe " +
                                     "oder die Spiellogik, um automatisch auf Gegner zu zielen, " +
                                     "und verstoessen gegen die Nutzungsbedingungen aller kompetitiven Spiele.",
                            Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm} | Pfad: {file}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private void ScanAimbotDlls(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(file);

                foreach (var dllName in AimbotDllNames)
                {
                    if (fileName.Equals(dllName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        DateTime writeTime;
                        try { writeTime = File.GetLastWriteTime(file); }
                        catch { writeTime = DateTime.MinValue; }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Aimbot-DLL gefunden: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Die DLL '{fileName}' entspricht dem bekannten Namen einer Aimbot- " +
                                     "oder Recoil-Control-DLL. Solche DLLs werden meist per DLL-Injection " +
                                     "in den Spielprozess eingeschleust, um Spielfunktionen zu manipulieren.",
                            Detail = $"Erstellt: {writeTime:yyyy-MM-dd HH:mm}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private async Task ScanAimbotConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configExtensions = new[] { ".json", ".ini", ".cfg", ".yaml", ".yml", ".toml", ".xml", ".conf" };
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*.*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();

                var ext = Path.GetExtension(file);
                if (!configExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                var fileName = Path.GetFileName(file);

                bool hasAimbotNameHint = fileName.Contains("aimbot", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Contains("triggerbot", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Contains("noRecoil", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Contains("no_recoil", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Contains("cheat", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Equals("config.json", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Equals("settings.json", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Equals("config.cfg", StringComparison.OrdinalIgnoreCase);

                if (!hasAimbotNameHint) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                var matchedKeys = new List<string>();
                int matchCount = 0;

                foreach (var key in AimbotConfigKeys)
                {
                    if (content.Contains(key, StringComparison.OrdinalIgnoreCase))
                    {
                        matchedKeys.Add(key);
                        matchCount++;
                        if (matchCount >= 5) break;
                    }
                }

                if (matchCount >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Aimbot-Konfigurationsdatei: {fileName} ({matchCount} Schluessel)",
                        Risk = matchCount >= 5 ? RiskLevel.Critical : RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Die Datei '{fileName}' enthaelt {matchCount} typische Aimbot-/Cheat-" +
                                 $"Konfigurationsschluessel ({string.Join(", ", matchedKeys.Take(5))}). " +
                                 "Konfigurationsdateien mit diesen Schluesseln gehoeren zu Aimbot- oder " +
                                 "Cheat-Software und koennen Aimbot-Parameter wie FOV, Smoothing und " +
                                 "Bone-Targeting enthalten.",
                        Detail = $"Gefundene Schluessel: {string.Join(", ", matchedKeys)}"
                    });
                }
            }
        }
    }

    private async Task ScanPythonAimbotScriptsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] pyFiles;
            try { pyFiles = Directory.GetFiles(root, "*.py", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var pyFile in pyFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(pyFile);

                bool isKnownAimbotName = false;
                foreach (var knownName in PythonAimbotFileNames)
                {
                    if (fileName.Equals(knownName, StringComparison.OrdinalIgnoreCase))
                    {
                        isKnownAimbotName = true;
                        break;
                    }
                }

                bool hasAimbotNameHint = isKnownAimbotName
                                      || fileName.Contains("aimbot", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Contains("triggerbot", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Contains("no_recoil", StringComparison.OrdinalIgnoreCase)
                                      || fileName.Contains("aim_assist", StringComparison.OrdinalIgnoreCase);

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(pyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int importMatches = 0;
                var foundImports = new List<string>();
                foreach (var import in PythonAimbotImports)
                {
                    if (content.Contains(import, StringComparison.OrdinalIgnoreCase))
                    {
                        importMatches++;
                        foundImports.Add(import);
                        if (importMatches >= 4) break;
                    }
                }

                bool hasMouseControl = content.Contains("mouse_event", StringComparison.OrdinalIgnoreCase)
                                    || content.Contains("SendInput", StringComparison.OrdinalIgnoreCase)
                                    || content.Contains("mouse.move", StringComparison.OrdinalIgnoreCase)
                                    || content.Contains("moveTo(", StringComparison.OrdinalIgnoreCase)
                                    || content.Contains("MoveMouseRelative", StringComparison.OrdinalIgnoreCase);

                bool hasScreenCapture = content.Contains("mss", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("screenshot", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("ImageGrab", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("PIL.Image", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("cv2.imshow", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("cv2.cvtColor", StringComparison.OrdinalIgnoreCase);

                if (isKnownAimbotName && importMatches >= 1 && hasMouseControl)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Python-Aimbot-Skript gefunden: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = pyFile,
                        FileName = fileName,
                        Reason = $"Das Python-Skript '{fileName}' kombiniert einen bekannten Aimbot-Namen " +
                                 "mit verdaechtigen Bibliotheksimporten und Maussteuerungs-Aufrufen. " +
                                 "Python-Aimbots verwenden oft OpenCV (Bilderkennung), " +
                                 "PyAutoGUI/pydirectinput (Maussteuerung) und mss/Pillow (Bildschirmaufnahme) " +
                                 "um Gegner zu erkennen und automatisch darauf zu zielen.",
                        Detail = $"Imports: {string.Join(", ", foundImports.Take(4))} | Maussteuerung: {hasMouseControl} | Bildschirmaufnahme: {hasScreenCapture}"
                    });
                }
                else if (hasAimbotNameHint && importMatches >= 2 && hasMouseControl && hasScreenCapture)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Moegliches Python-Aimbot-Skript: {fileName}",
                        Risk = RiskLevel.High,
                        Location = pyFile,
                        FileName = fileName,
                        Reason = $"Das Python-Skript '{fileName}' enthaelt verdaechtige Kombinationen von " +
                                 "Bibliotheksimporten fuer Bildschirmaufnahme, Bilderkennung und " +
                                 "Maussteuerung. Diese Kombination ist typisch fuer AI-basierte Aimbots, " +
                                 "die den Bildschirm analysieren und die Maus automatisch bewegen.",
                        Detail = $"Imports: {string.Join(", ", foundImports.Take(4))} | Maussteuerung: {hasMouseControl} | Screen: {hasScreenCapture}"
                    });
                }
            }
        }
    }

    private async Task ScanAhkRecoilScriptsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] ahkFiles;
            try { ahkFiles = Directory.GetFiles(root, "*.ahk", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var ahkFile in ahkFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(ahkFile);

                bool isKnownRecoilScript = false;
                foreach (var knownName in RecoilAhkFileNames)
                {
                    if (fileName.Equals(knownName, StringComparison.OrdinalIgnoreCase))
                    {
                        isKnownRecoilScript = true;
                        break;
                    }
                }

                bool hasAimbotHint = isKnownRecoilScript
                                  || fileName.Contains("aimbot", StringComparison.OrdinalIgnoreCase)
                                  || fileName.Contains("triggerbot", StringComparison.OrdinalIgnoreCase)
                                  || fileName.Contains("recoil", StringComparison.OrdinalIgnoreCase)
                                  || fileName.Contains("no_recoil", StringComparison.OrdinalIgnoreCase)
                                  || fileName.Contains("bhop", StringComparison.OrdinalIgnoreCase)
                                  || fileName.Contains("rapidfire", StringComparison.OrdinalIgnoreCase)
                                  || fileName.Contains("rapid_fire", StringComparison.OrdinalIgnoreCase);

                if (!hasAimbotHint) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(ahkFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int patternMatches = 0;
                var foundPatterns = new List<string>();
                foreach (var pattern in AhkRecoilPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        patternMatches++;
                        foundPatterns.Add(pattern);
                        if (patternMatches >= 5) break;
                    }
                }

                bool hasGameTargeting = content.Contains("WinActivate", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("WinExist", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("PixelSearch", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("ImageSearch", StringComparison.OrdinalIgnoreCase);

                if (patternMatches >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AHK-Recoil/Aimbot-Skript gefunden: {fileName}",
                        Risk = hasGameTargeting ? RiskLevel.Critical : RiskLevel.High,
                        Location = ahkFile,
                        FileName = fileName,
                        Reason = $"Das AutoHotkey-Skript '{fileName}' enthaelt Mausbewegungsbefehle in " +
                                 "verdaechtigen Kombinationen. AHK-Skripte werden fuer Recoil-Control " +
                                 "(Rueckstoss-Kompensation), Bunny-Hopping und Triggerbot-Funktionen " +
                                 "in kompetitiven Spielen eingesetzt." +
                                 (hasGameTargeting ? " Skript enthaelt spielspezifisches Targeting." : ""),
                        Detail = $"Muster: {string.Join(", ", foundPatterns.Take(4))} | Spiel-Targeting: {hasGameTargeting}"
                    });
                }
                else if (isKnownRecoilScript)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekanntes AHK-Recoil-Skript: {fileName}",
                        Risk = RiskLevel.High,
                        Location = ahkFile,
                        FileName = fileName,
                        Reason = $"Der Dateiname '{fileName}' entspricht einem bekannten AutoHotkey-Skript " +
                                 "fuer Recoil-Control oder Aimbot-Funktionen. Solche Skripte manipulieren " +
                                 "die Mauseingabe, um den Rueckstoss in Egoshootern zu kompensieren.",
                        Detail = null
                    });
                }
            }
        }
    }

    private async Task ScanArduinoAimbotSketchesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents\\Arduino",
            KnownPaths.UserProfile + "\\Documents",
            KnownPaths.UserProfile + "\\Arduino",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] inoFiles;
            try { inoFiles = Directory.GetFiles(root, "*.ino", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var inoFile in inoFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(inoFile);

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(inoFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                bool isKnownAimbotSketch = false;
                foreach (var knownName in ArduinoAimbotFileNames)
                {
                    if (fileName.Equals(knownName, StringComparison.OrdinalIgnoreCase))
                    {
                        isKnownAimbotSketch = true;
                        break;
                    }
                }

                int patternMatches = 0;
                var foundPatterns = new List<string>();
                foreach (var pattern in ArduinoAimbotPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        patternMatches++;
                        foundPatterns.Add(pattern);
                        if (patternMatches >= 4) break;
                    }
                }

                bool hasMouseMove = content.Contains("Mouse.move(", StringComparison.OrdinalIgnoreCase);
                bool hasSerial = content.Contains("Serial.read(", StringComparison.OrdinalIgnoreCase)
                              || content.Contains("Serial.available(", StringComparison.OrdinalIgnoreCase);

                if (isKnownAimbotSketch || (patternMatches >= 2 && hasMouseMove))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Arduino-HID-Aimbot-Sketch gefunden: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = inoFile,
                        FileName = fileName,
                        Reason = $"Das Arduino-Sketch '{fileName}' enthaelt USB-HID-Maussteuerungs-Code " +
                                 "(Mouse.move(), Mouse.click()). Arduino-basierte Aimbots " +
                                 "emulieren eine USB-Maus auf Hardware-Ebene und sind dadurch " +
                                 "fuer Software-basierte Anti-Cheat-Loesungen sehr schwer zu erkennen, " +
                                 "da sie keine verdaechtige Software im System installieren.",
                        Detail = $"Muster: {string.Join(", ", foundPatterns.Take(4))} | Serial-Kontrolle: {hasSerial}"
                    });
                }
                else if (patternMatches >= 1 && hasMouseMove)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Arduino-Maus-HID-Sketch mit Aimbot-Verdacht: {fileName}",
                        Risk = RiskLevel.High,
                        Location = inoFile,
                        FileName = fileName,
                        Reason = $"Das Arduino-Sketch '{fileName}' enthaelt USB-Maus-HID-Code. " +
                                 "Arduino-Sketches mit Maussteuerung werden fuer Hardware-Aimbots verwendet.",
                        Detail = $"Muster: {string.Join(", ", foundPatterns.Take(4))}"
                    });
                }
            }
        }
    }

    private async Task ScanRaspberryPicoAimbotAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents",
            KnownPaths.UserProfile + "\\Pico",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] pyFiles;
            try { pyFiles = Directory.GetFiles(root, "*.py", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var pyFile in pyFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(pyFile);

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(pyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                bool hasUsbHid = content.Contains("usb_hid", StringComparison.OrdinalIgnoreCase)
                              || content.Contains("import adafruit_hid", StringComparison.OrdinalIgnoreCase)
                              || content.Contains("from adafruit_hid", StringComparison.OrdinalIgnoreCase)
                              || content.Contains("Mouse(usb_hid", StringComparison.OrdinalIgnoreCase);

                bool hasMouseMove = content.Contains("mouse.move(", StringComparison.OrdinalIgnoreCase)
                                 || content.Contains(".move(", StringComparison.OrdinalIgnoreCase);

                bool hasGameContext = content.Contains("aim", StringComparison.OrdinalIgnoreCase)
                                   || content.Contains("recoil", StringComparison.OrdinalIgnoreCase)
                                   || content.Contains("triggerbot", StringComparison.OrdinalIgnoreCase)
                                   || content.Contains("enemy", StringComparison.OrdinalIgnoreCase)
                                   || content.Contains("target", StringComparison.OrdinalIgnoreCase);

                bool hasSerial = content.Contains("import serial", StringComparison.OrdinalIgnoreCase)
                              || content.Contains("uart", StringComparison.OrdinalIgnoreCase);

                if (hasUsbHid && hasMouseMove && hasGameContext)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Raspberry-Pi-Pico-Aimbot-Skript gefunden: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = pyFile,
                        FileName = fileName,
                        Reason = $"Das MicroPython-Skript '{fileName}' kombiniert USB-HID-Bibliotheken " +
                                 "(adafruit_hid/usb_hid) mit Mausbewegungscode und spielbezogenem Kontext. " +
                                 "Raspberry-Pi-Pico-Aimbots werden als USB-HID-Geraete angemeldet und " +
                                 "sind fuer Software-Anti-Cheat nicht erkennbar.",
                        Detail = $"USB-HID: {hasUsbHid} | Mausbewegung: {hasMouseMove} | Spiel-Kontext: {hasGameContext} | Serial: {hasSerial}"
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanCronusZenArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var cronusAppDataPaths = new[]
        {
            Path.Combine(KnownPaths.RoamingAppData, "CronusZen"),
            Path.Combine(KnownPaths.LocalAppData, "CronusZen"),
            Path.Combine(KnownPaths.RoamingAppData, "CronusMax"),
            Path.Combine(KnownPaths.LocalAppData, "CronusMax"),
            Path.Combine(KnownPaths.RoamingAppData, "Cronus"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CronusZen"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "CronusZen"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cronus"),
        };

        foreach (var cronusPath in cronusAppDataPaths)
        {
            if (!Directory.Exists(cronusPath)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Cronus-Zen/Max-Softwareverzeichnis gefunden",
                Risk = RiskLevel.High,
                Location = cronusPath,
                FileName = Path.GetFileName(cronusPath),
                Reason = "Ein Cronus-Zen- oder Cronus-Max-Softwareverzeichnis wurde gefunden. " +
                         "Cronus-Geraete sind USB-Adapter, die Controller-Eingaben manipulieren " +
                         "und Anti-Recoil, Aimbot und Rapid-Fire-Funktionen auf Hardware-Ebene " +
                         "bereitstellen. Sie sind in den meisten kompetitiven Spielen verboten.",
                Detail = $"Pfad: {cronusPath}"
            });
        }

        var gpcSearchRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents",
        };

        foreach (var root in gpcSearchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] gpcFiles;
            try { gpcFiles = Directory.GetFiles(root, "*.gpc", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var gpcFile in gpcFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(gpcFile);
                string content;
                try
                {
                    using var fs = new FileStream(gpcFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                bool hasCheatContent = false;
                string? matchedPattern = null;
                foreach (var pattern in CronusGpcFilePatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        hasCheatContent = true;
                        matchedPattern = pattern;
                        break;
                    }
                }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cronus-GPC-Skriptdatei gefunden: {fileName}",
                    Risk = hasCheatContent ? RiskLevel.Critical : RiskLevel.High,
                    Location = gpcFile,
                    FileName = fileName,
                    Reason = $"Eine Cronus-GPC-Skriptdatei ('{fileName}') wurde gefunden. GPC-Dateien " +
                             "enthalten Cronus-Zen/Max-Skripte fuer Controller-Automatisierung. " +
                             "Solche Skripte werden fuer Aimbot, Anti-Recoil, Rapid-Fire und " +
                             "andere unfaire Vorteile in kompetitiven Spielen eingesetzt." +
                             (hasCheatContent ? $" Skript enthaelt Muster '{matchedPattern}'." : ""),
                    Detail = matchedPattern is not null ? $"Erkanntes Muster: {matchedPattern}" : null
                });
            }
        }
    }

    private void ScanXimApexArtifacts(ScanContext ctx)
    {
        var ximPaths = new[]
        {
            Path.Combine(KnownPaths.RoamingAppData, "XIM APEX"),
            Path.Combine(KnownPaths.LocalAppData, "XIM APEX"),
            Path.Combine(KnownPaths.RoamingAppData, "XimMax"),
            Path.Combine(KnownPaths.LocalAppData, "XimMax"),
            Path.Combine(KnownPaths.RoamingAppData, "XIM"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "XIM APEX"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "XIM APEX"),
        };

        foreach (var ximPath in ximPaths)
        {
            if (!Directory.Exists(ximPath)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Xim-Apex/XimMax-Softwareverzeichnis gefunden",
                Risk = RiskLevel.High,
                Location = ximPath,
                FileName = Path.GetFileName(ximPath),
                Reason = "Ein Xim-Apex- oder XimMax-Konfigurationsverzeichnis wurde gefunden. " +
                         "Xim-Adapter uebersetzen Maus- und Tastatureingaben auf Controller-Protokolle " +
                         "und bieten dabei Aimbot-aehnliche Mausbeschleunigungsfunktionen (ST-Kurven). " +
                         "Diese Geraete sind in den meisten Turnierspielen verboten.",
                Detail = $"Pfad: {ximPath}"
            });
        }

        var ximConfigFiles = new[]
        {
            Path.Combine(KnownPaths.RoamingAppData, "XIM APEX", "config.xim"),
            Path.Combine(KnownPaths.RoamingAppData, "XIM APEX", "profiles.xim"),
        };

        foreach (var configFile in ximConfigFiles)
        {
            if (!File.Exists(configFile)) continue;
            ctx.IncrementFiles();

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Xim-Apex-Konfigurationsdatei: {Path.GetFileName(configFile)}",
                Risk = RiskLevel.High,
                Location = configFile,
                FileName = Path.GetFileName(configFile),
                Reason = "Eine Xim-Apex-Konfigurationsdatei wurde gefunden, die Mausempfindlichkeitskurven " +
                         "und Spielprofile enthaelt. Xim-Konfigurationen koennen auf die Zielhilfe " +
                         "(Aim-Assist) des Controllers abgestimmt sein und damit unfaire Vorteile bieten.",
                Detail = null
            });
        }
    }

    private void ScanTitanTwoArtifacts(ScanContext ctx)
    {
        var titanPaths = new[]
        {
            Path.Combine(KnownPaths.RoamingAppData, "Titan Two"),
            Path.Combine(KnownPaths.LocalAppData, "Titan Two"),
            Path.Combine(KnownPaths.RoamingAppData, "ConsoleTuner"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Titan Two"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Titan Two"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ConsoleTuner"),
        };

        foreach (var titanPath in titanPaths)
        {
            if (!Directory.Exists(titanPath)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Titan-Two-Softwareverzeichnis gefunden",
                Risk = RiskLevel.High,
                Location = titanPath,
                FileName = Path.GetFileName(titanPath),
                Reason = "Ein Titan-Two-Konfigurationsverzeichnis (ConsoleTuner) wurde gefunden. " +
                         "Titan Two ist ein fortgeschrittenes Eingabe-Konvertergeraet, das GPC-Skripte " +
                         "fuer Aimbot, Anti-Recoil, Rapid-Fire und andere Automatisierungen unterstuetzt " +
                         "und in kompetitiven Spielen als Betrugsgeraet gilt.",
                Detail = $"Pfad: {titanPath}"
            });
        }

        var titanScriptRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Documents",
        };

        foreach (var root in titanScriptRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] gpcFiles;
            try { gpcFiles = Directory.GetFiles(root, "*.gpc", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var gpcFile in gpcFiles)
            {
                if (gpcFile.Contains("Titan", StringComparison.OrdinalIgnoreCase) ||
                    gpcFile.Contains("ConsoleTuner", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Titan-Two-GPC-Skript gefunden: {Path.GetFileName(gpcFile)}",
                        Risk = RiskLevel.High,
                        Location = gpcFile,
                        FileName = Path.GetFileName(gpcFile),
                        Reason = "Eine GPC-Skriptdatei im Titan-Two-Kontext wurde gefunden. " +
                                 "Diese Skripte programmieren das Titan-Two-Geraet fuer Spielautomatisierungen.",
                        Detail = null
                    });
                }
            }
        }
    }

    private async Task ScanLogitechGHubScriptsAsync(ScanContext ctx, CancellationToken ct)
    {
        var ghubScriptPaths = new[]
        {
            Path.Combine(KnownPaths.LocalAppData, "LGHUB"),
            Path.Combine(KnownPaths.RoamingAppData, "LGHUB"),
            Path.Combine(KnownPaths.LocalAppData, "Logitech Gaming Software"),
            Path.Combine(KnownPaths.RoamingAppData, "Logitech Gaming Software"),
        };

        foreach (var ghubPath in ghubScriptPaths)
        {
            if (!Directory.Exists(ghubPath)) continue;

            string[] luaFiles;
            try { luaFiles = Directory.GetFiles(ghubPath, "*.lua", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var luaFile in luaFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(luaFile);
                string content;
                try
                {
                    using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int matches = 0;
                var foundPatterns = new List<string>();
                foreach (var pattern in LogitechLuaRecoilPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        matches++;
                        foundPatterns.Add(pattern);
                        if (matches >= 4) break;
                    }
                }

                bool hasRecoilContent = content.Contains("recoil", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("anti_recoil", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("spray", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("MoveMouseRelative", StringComparison.OrdinalIgnoreCase);

                bool hasRapidFire = content.Contains("rapid", StringComparison.OrdinalIgnoreCase)
                                 || content.Contains("autofire", StringComparison.OrdinalIgnoreCase)
                                 || content.Contains("auto_fire", StringComparison.OrdinalIgnoreCase);

                if (matches >= 2 && (hasRecoilContent || hasRapidFire))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Logitech-G-Hub-Recoil/Aimbot-Skript: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = luaFile,
                        FileName = fileName,
                        Reason = $"Das Logitech-G-Hub-Lua-Skript '{fileName}' enthaelt Code fuer " +
                                 "Recoil-Kompensation oder Rapid-Fire-Automatisierung. " +
                                 "Logitech-G-Hub-Skripte mit MoveMouseRelative()-Aufrufen koennen " +
                                 "Anti-Recoil-Makros implementieren, die in kompetitiven Spielen verboten sind.",
                        Detail = $"Muster: {string.Join(", ", foundPatterns.Take(4))} | Recoil: {hasRecoilContent} | RapidFire: {hasRapidFire}"
                    });
                }
            }
        }
    }

    private void ScanSteelSeriesArtifacts(ScanContext ctx)
    {
        var ssePaths = new[]
        {
            Path.Combine(KnownPaths.RoamingAppData, "SteelSeries"),
            Path.Combine(KnownPaths.LocalAppData, "SteelSeries"),
            Path.Combine(KnownPaths.RoamingAppData, "SteelSeries Engine 3"),
            Path.Combine(KnownPaths.LocalAppData, "SteelSeries Engine 3"),
        };

        foreach (var ssePath in ssePaths)
        {
            if (!Directory.Exists(ssePath)) continue;

            string[] scriptFiles;
            try { scriptFiles = Directory.GetFiles(ssePath, "*.json", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var scriptFile in scriptFiles)
            {
                var fileName = Path.GetFileName(scriptFile);
                if (!fileName.Contains("macro", StringComparison.OrdinalIgnoreCase)
                    && !fileName.Contains("action", StringComparison.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"SteelSeries-Engine-Makrodatei gefunden: {fileName}",
                    Risk = RiskLevel.Medium,
                    Location = scriptFile,
                    FileName = fileName,
                    Reason = $"Eine SteelSeries-Engine-Makrodatei ('{fileName}') wurde gefunden. " +
                             "SteelSeries-Makros koennen Mausbewegungen und Klicksequenzen automatisieren. " +
                             "Im Gaming-Kontext werden solche Makros fuer Recoil-Control und Rapid-Fire benutzt.",
                    Detail = null
                });
            }
        }
    }

    private void ScanAimbotRegistryArtifacts(ScanContext ctx)
    {
        try
        {
            using var hkcu = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (hkcu is not null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var valName in hkcu.GetValueNames())
                {
                    var val = hkcu.GetValue(valName)?.ToString();
                    if (string.IsNullOrEmpty(val)) continue;

                    bool isAimbot = false;
                    string? matchedName = null;
                    foreach (var aimbotName in AimbotExeNames)
                    {
                        if (val.Contains(aimbotName, StringComparison.OrdinalIgnoreCase))
                        {
                            isAimbot = true;
                            matchedName = aimbotName;
                            break;
                        }
                    }

                    if (isAimbot)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Aimbot-Autostart in Registry gefunden: {valName}",
                            Risk = RiskLevel.Critical,
                            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                            Reason = $"Der Autostart-Registrierungseintrag '{valName}' verweist auf eine " +
                                     $"Aimbot-Ausfuehrdatei ('{matchedName}'). Aimbot-Software mit " +
                                     "Autostart-Eintrag wird automatisch beim Windows-Start geladen.",
                            Detail = $"Wert: {val}"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        try
        {
            using var muiCache = Registry.CurrentUser.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
            if (muiCache is not null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var valName in muiCache.GetValueNames())
                {
                    if (!valName.Contains("\\")) continue;

                    bool isAimbot = false;
                    string? matchedName = null;
                    foreach (var aimbotName in AimbotExeNames)
                    {
                        if (valName.Contains(aimbotName, StringComparison.OrdinalIgnoreCase))
                        {
                            isAimbot = true;
                            matchedName = aimbotName;
                            break;
                        }
                    }

                    if (isAimbot)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Aimbot-Ausfuehrungsspur in MUICache: {matchedName}",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\...\MuiCache",
                            FileName = matchedName,
                            Reason = $"In der Windows-MUICache wurde ein Eintrag fuer '{matchedName}' gefunden. " +
                                     "MUICache speichert ausfuehrbare Dateien, die der Benutzer ausgefuehrt hat, " +
                                     "auch wenn die Datei inzwischen geloescht wurde. Dies ist ein forensischer " +
                                     "Nachweis, dass der Aimbot auf diesem System ausgefuehrt wurde.",
                            Detail = $"Pfad: {valName}"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        try
        {
            using var userAssist = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (userAssist is not null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var guidName in userAssist.GetSubKeyNames())
                {
                    try
                    {
                        using var count = userAssist.OpenSubKey(guidName + "\\Count");
                        if (count is null) continue;
                        ctx.IncrementRegistryKeys();

                        foreach (var valName in count.GetValueNames())
                        {
                            if (string.IsNullOrEmpty(valName)) continue;
                            string decoded;
                            try { decoded = Rot13Decode(valName); }
                            catch { decoded = valName; }

                            bool isAimbot = false;
                            string? matchedName = null;
                            foreach (var aimbotName in AimbotExeNames)
                            {
                                if (decoded.Contains(aimbotName, StringComparison.OrdinalIgnoreCase))
                                {
                                    isAimbot = true;
                                    matchedName = aimbotName;
                                    break;
                                }
                            }

                            if (isAimbot)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Aimbot-Ausfuehrungsspur in UserAssist: {matchedName}",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKCU\...\UserAssist\{guidName}\Count",
                                    FileName = matchedName,
                                    Reason = $"In der Windows-UserAssist-Registry wurde ein Eintrag fuer " +
                                             $"'{matchedName}' (dekodiert: {decoded}) gefunden. " +
                                             "UserAssist protokolliert ausgefuehrte Programme mit Zeitstempeln " +
                                             "und Ausfuehrungsanzahl. Dies belegt, dass der Aimbot ausgefuehrt wurde.",
                                    Detail = $"Dekodierter Pfad: {decoded}"
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private static string Rot13Decode(string input)
    {
        var chars = input.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c >= 'A' && c <= 'Z')
                chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c >= 'a' && c <= 'z')
                chars[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(chars);
    }

    private static string[] GetUserSearchRoots()
    {
        return new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents",
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.RoamingAppData,
            KnownPaths.UserProfile + "\\AppData\\Roaming",
            KnownPaths.UserProfile + "\\Games",
            Path.Combine(KnownPaths.LocalAppData, "Programs"),
        };
    }
}
