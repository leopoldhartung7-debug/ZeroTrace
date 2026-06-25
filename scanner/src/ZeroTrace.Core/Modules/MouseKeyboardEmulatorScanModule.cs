using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class MouseKeyboardEmulatorScanModule : IScanModule
{
    public string Name => "Mouse-Keyboard-Emulator";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    private static readonly string[] InterceptionDriverNames =
    {
        "keyboard_filter.sys", "mouse_filter.sys", "interception.sys",
        "kbfiltr.sys", "moufiltr.sys",
    };

    private static readonly string[] InterceptionServiceNames =
    {
        "Interception", "keyboard_filter", "mouse_filter", "kbfiltr", "moufiltr",
    };

    private static readonly string[] ArduinoEmulatorProcessNames =
    {
        "arduino", "arduino_debug", "kmboxnet", "kmbox", "xim", "xim4", "xim_apex",
        "titan", "titan_two", "rewasd", "joytokey", "antimicro",
    };

    private static readonly string[] SoftwareAimbotProcessNames =
    {
        "pixelaimbot", "triggerbot", "coloraimbot", "colorbot", "screenaim",
        "aimassist", "mousemover", "autoclicker", "ghub_aimbot", "lgs_script",
        "aimbot_ai", "ai_aimbot", "trigger_ai", "yolo_aimbot", "neural_aimbot", "aimaim",
    };

    private static readonly string[] AiAimbotExecutableNames =
    {
        "aimbot_ai.exe", "ai_aimbot.exe", "trigger_ai.exe", "yolo_aimbot.exe",
        "neural_aimbot.exe", "aimaim.exe",
    };

    private static readonly string[] ArduinoAimbotFileNames =
    {
        "arduino_aimbot.ino", "aimbot.ino", "triggerbot.ino",
        "recoil.ino", "bhop.ino",
    };

    private static readonly string[] ArduinoConfigFileNames =
    {
        "kmbox_config.json",
    };

    private static readonly string[] LghubRecoilKeywords =
    {
        "moveMouseRelative", "pressMouseButton", "repeatMouseClick",
        "recoil", "rapidfire", "triggerbot", "sensitivity", "norecoil",
    };

    private static readonly string[] RazerSynapseCheatKeywords =
    {
        "aimbot", "recoil", "rapidfire", "triggerbot", "bhop", "bunny",
        "norecoil", "no_recoil",
    };

    private static readonly string[] AhkCheatKeywords =
    {
        "recoil", "aimbot", "triggerbot",
    };

    private static readonly string[] AhkAutomationPrimitives =
    {
        "Click", "MouseMove", "PixelSearch", "ImageSearch",
    };

    private static readonly string[] AiAimbotDirectoryMarkers =
    {
        "bettercam", "dxcam", "yolov5", "yolov8",
    };

    private static readonly string[] AiAimbotPythonKeywords =
    {
        "bettercam", "dxcam", "ultralytics", "onnxruntime",
        "win32api.mouse_event", "pynput.mouse", "pyautogui.moveTo",
    };

    private static readonly string[] AiAimbotPythonDetectKeywords =
    {
        "predict", "detect",
    };

    private static readonly string[] EmulatorRegistryPaths =
    {
        @"SOFTWARE\Interception",
        @"SOFTWARE\KMBOX",
        @"SOFTWARE\reWASD",
        @"SOFTWARE\JoyToKey",
    };

    private static readonly string[] SuspiciousOnnxDirNames =
    {
        "aimbot", "esp", "detect", "cheat", "hack",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Mouse-Keyboard-Emulator", "Checking Interception driver artifacts...");
        await CheckInterceptionDriverAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.15, "Mouse-Keyboard-Emulator", "Checking Logitech GHUB Lua script abuse...");
        await ScanLogitech(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.28, "Mouse-Keyboard-Emulator", "Checking Razer Synapse macro abuse...");
        await ScanRazerSynapse(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.38, "Mouse-Keyboard-Emulator", "Checking SteelSeries Engine abuse...");
        await ScanSteelSeriesEngine(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.46, "Mouse-Keyboard-Emulator", "Checking Arduino/KMBOX emulator files...");
        await ScanArduinoEmulatorFiles(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.55, "Mouse-Keyboard-Emulator", "Checking running emulator processes...");
        CheckEmulatorProcesses(ctx, ct);

        ctx.Report(0.65, "Mouse-Keyboard-Emulator", "Checking AHK aimbot scripts...");
        await ScanAhkScripts(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.75, "Mouse-Keyboard-Emulator", "Checking AI aimbot files...");
        await ScanAiAimbotFiles(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.88, "Mouse-Keyboard-Emulator", "Checking emulator registry keys...");
        CheckEmulatorRegistry(ctx, ct);

        ctx.Report(1.0, "Mouse-Keyboard-Emulator", "Mouse/keyboard emulator scan complete.");
    }

    private static async Task CheckInterceptionDriverAsync(ScanContext ctx, CancellationToken ct)
    {
        var driversDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");

        if (Directory.Exists(driversDir))
        {
            foreach (var driverName in InterceptionDriverNames)
            {
                if (ct.IsCancellationRequested) return;
                var driverPath = Path.Combine(driversDir, driverName);
                ctx.IncrementFiles();

                if (File.Exists(driverPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Mouse-Keyboard-Emulator",
                        Title = $"Interception/input filter driver found: {driverName}",
                        Risk = RiskLevel.Critical,
                        Location = driverPath,
                        FileName = driverName,
                        Reason = $"Kernel-mode input filter driver '{driverName}' found in the Windows driver directory. " +
                                 "The Interception driver framework allows aimbots and triggerbots to send synthetic " +
                                 "mouse and keyboard input at the kernel level, bypassing user-mode anti-cheat hooks.",
                        Detail = $"Path: {driverPath}",
                    });
                }
            }
        }

        foreach (var svcName in InterceptionServiceNames)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();

            try
            {
                using var svcKey = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svcName}", writable: false);
                if (svcKey is null) continue;

                var imgPath = (svcKey.GetValue("ImagePath") as string ?? string.Empty);
                var startType = svcKey.GetValue("Start") as int?;

                ctx.AddFinding(new Finding
                {
                    Module = "Mouse-Keyboard-Emulator",
                    Title = $"Interception input filter service registered: {svcName}",
                    Risk = RiskLevel.Critical,
                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                    Reason = $"Registry service entry '{svcName}' is registered as a kernel input filter driver. " +
                             "This service is used by aimbot software to intercept and synthesize mouse/keyboard " +
                             "events at the kernel level, producing input that appears hardware-generated to anti-cheat systems.",
                    Detail = $"ImagePath: {imgPath} | StartType: {startType}",
                });
            }
            catch { }
        }

        var interceptionDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Interception");
        ctx.IncrementFiles();
        if (Directory.Exists(interceptionDir))
        {
            ctx.AddFinding(new Finding
            {
                Module = "Mouse-Keyboard-Emulator",
                Title = "Interception program directory found",
                Risk = RiskLevel.High,
                Location = interceptionDir,
                Reason = "The 'Interception' program directory exists under Program Files. " +
                         "The Interception library is the most widely-used kernel-mode input injection framework " +
                         "in PC game cheating tools.",
                Detail = $"Directory: {interceptionDir}",
            });
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private static async Task ScanLogitech(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var lghubLuaDir = Path.Combine(appData, "LGHUB", "applications");
        await ScanLuaDirectoryAsync(ctx, ct, lghubLuaDir, "Logitech GHUB", LghubRecoilKeywords).ConfigureAwait(false);

        var lgsDir = Path.Combine(appData, "Logitech", "Logitech Gaming Software", "profiles");
        await ScanLuaDirectoryAsync(ctx, ct, lgsDir, "Logitech Gaming Software", LghubRecoilKeywords).ConfigureAwait(false);
    }

    private static async Task ScanLuaDirectoryAsync(ScanContext ctx, CancellationToken ct,
        string dir, string sourceName, string[] keywords)
    {
        if (!Directory.Exists(dir)) return;

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
        }
        catch { return; }

        foreach (var filePath in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(filePath);
            var ext = Path.GetExtension(fileName).ToLowerInvariant();
            if (ext is not (".lua" or ".xml" or ".json")) continue;

            try
            {
                using var sr = new StreamReader(filePath);
                string content = await sr.ReadToEndAsync().ConfigureAwait(false);

                foreach (var keyword in keywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Mouse-Keyboard-Emulator",
                            Title = $"{sourceName} cheat macro script: {fileName}",
                            Risk = RiskLevel.Medium,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"{sourceName} script '{fileName}' contains the keyword '{keyword}', " +
                                     "which is associated with recoil control, rapid-fire, or triggerbot macros " +
                                     "running inside the gaming peripheral software's scripting engine.",
                            Detail = $"Keyword: {keyword} | Path: {filePath}",
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private static async Task ScanRazerSynapse(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var synapseDir = Path.Combine(appData, "Razer", "Synapse3", "Profiles");

        if (!Directory.Exists(synapseDir)) return;

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(synapseDir, "*.json", SearchOption.AllDirectories);
        }
        catch { return; }

        foreach (var filePath in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            try
            {
                using var sr = new StreamReader(filePath);
                string content = await sr.ReadToEndAsync().ConfigureAwait(false);

                foreach (var keyword in RazerSynapseCheatKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        var fileName = Path.GetFileName(filePath);
                        ctx.AddFinding(new Finding
                        {
                            Module = "Mouse-Keyboard-Emulator",
                            Title = $"Razer Synapse cheat macro profile: {fileName}",
                            Risk = RiskLevel.Medium,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"Razer Synapse profile '{fileName}' contains the keyword '{keyword}', " +
                                     "which is strongly associated with aimbot, recoil control, or triggerbot " +
                                     "macros programmed into the Synapse macro engine.",
                            Detail = $"Keyword: {keyword} | Path: {filePath}",
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private static async Task ScanSteelSeriesEngine(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var ssDir = Path.Combine(appData, "SteelSeries", "SteelSeries Engine 3", "gamesense");

        if (!Directory.Exists(ssDir)) return;

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(ssDir, "*", SearchOption.AllDirectories);
        }
        catch { return; }

        var cheatTerms = new[] { "aimbot", "triggerbot", "recoil", "rapidfire", "bhop", "norecoil", "hack" };

        foreach (var filePath in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext is not (".lua" or ".json" or ".js")) continue;

            try
            {
                using var sr = new StreamReader(filePath);
                string content = await sr.ReadToEndAsync().ConfigureAwait(false);

                foreach (var term in cheatTerms)
                {
                    if (content.Contains(term, StringComparison.OrdinalIgnoreCase))
                    {
                        var fileName = Path.GetFileName(filePath);
                        ctx.AddFinding(new Finding
                        {
                            Module = "Mouse-Keyboard-Emulator",
                            Title = $"SteelSeries Engine suspicious event handler: {fileName}",
                            Risk = RiskLevel.Medium,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"SteelSeries GameSense event handler '{fileName}' contains the keyword '{term}', " +
                                     "which is associated with cheat macros running through peripheral software scripting.",
                            Detail = $"Keyword: {term} | Path: {filePath}",
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private static async Task ScanArduinoEmulatorFiles(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
            }
            catch { continue; }

            foreach (var filePath in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(filePath);

                foreach (var known in ArduinoAimbotFileNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Mouse-Keyboard-Emulator",
                            Title = $"Arduino aimbot sketch file: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"Arduino sketch file '{fileName}' is a known aimbot or triggerbot program " +
                                     "designed to be flashed to a USB HID-emulating microcontroller (Arduino, Pro Micro, etc.) " +
                                     "to produce hardware-level mouse input that cannot be detected by software anti-cheat.",
                            Detail = $"Path: {filePath}",
                        });
                        goto nextFile;
                    }
                }

                foreach (var known in ArduinoConfigFileNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Mouse-Keyboard-Emulator",
                            Title = $"KMBOX emulator config file: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"KMBOX network mouse emulator config file '{fileName}' found. " +
                                     "KMBOX devices emulate a physical mouse/keyboard over USB or network, " +
                                     "allowing aimbot software to send input that appears hardware-generated.",
                            Detail = $"Path: {filePath}",
                        });
                        goto nextFile;
                    }
                }

                nextFile:;
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private static void CheckEmulatorProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementProcesses();

            var name = proc.ProcessName.ToLowerInvariant();

            foreach (var known in ArduinoEmulatorProcessNames)
            {
                if (name.Equals(known, StringComparison.OrdinalIgnoreCase)
                    || name.Contains(known, StringComparison.OrdinalIgnoreCase))
                {
                    string? exePath = null;
                    try { exePath = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = "Mouse-Keyboard-Emulator",
                        Title = $"Hardware emulator process running: {proc.ProcessName}",
                        Risk = RiskLevel.High,
                        Location = exePath ?? $"PID {proc.Id}",
                        FileName = proc.ProcessName + ".exe",
                        Reason = $"Process '{proc.ProcessName}' (PID {proc.Id}) is a known Arduino, KMBOX, or " +
                                 "input remapping tool used to send aimbot mouse movement to games via emulated " +
                                 "hardware devices or software input injection.",
                        Detail = $"PID: {proc.Id} | Path: {exePath ?? "unknown"}",
                    });
                    break;
                }
            }

            foreach (var known in SoftwareAimbotProcessNames)
            {
                if (name.Equals(known, StringComparison.OrdinalIgnoreCase)
                    || name.Contains(known, StringComparison.OrdinalIgnoreCase))
                {
                    string? exePath = null;
                    try { exePath = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = "Mouse-Keyboard-Emulator",
                        Title = $"Software aimbot/emulator process running: {proc.ProcessName}",
                        Risk = RiskLevel.Critical,
                        Location = exePath ?? $"PID {proc.Id}",
                        FileName = proc.ProcessName + ".exe",
                        Reason = $"Process '{proc.ProcessName}' (PID {proc.Id}) matches a known software aimbot " +
                                 "or input emulator name. These tools use screen capture and mouse movement APIs to " +
                                 "perform automated aiming without kernel access.",
                        Detail = $"PID: {proc.Id} | Path: {exePath ?? "unknown"}",
                    });
                    break;
                }
            }
        }
    }

    private static async Task ScanAhkScripts(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> ahkFiles;
            try
            {
                ahkFiles = Directory.EnumerateFiles(root, "*.ahk", SearchOption.AllDirectories);
            }
            catch { continue; }

            foreach (var filePath in ahkFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    using var sr = new StreamReader(filePath);
                    string content = await sr.ReadToEndAsync().ConfigureAwait(false);

                    bool hasCheatKeyword = AhkCheatKeywords.Any(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    bool hasAutomationPrimitive = AhkAutomationPrimitives.Any(p =>
                        content.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (hasCheatKeyword && hasAutomationPrimitive)
                    {
                        var fileName = Path.GetFileName(filePath);
                        var matchedCheat = AhkCheatKeywords.FirstOrDefault(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;
                        var matchedPrimitive = AhkAutomationPrimitives.FirstOrDefault(p =>
                            content.Contains(p, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                        ctx.AddFinding(new Finding
                        {
                            Module = "Mouse-Keyboard-Emulator",
                            Title = $"AHK aimbot/triggerbot script: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"AutoHotkey script '{fileName}' combines a cheat keyword ('{matchedCheat}') " +
                                     $"with an input automation primitive ('{matchedPrimitive}'). " +
                                     "This pattern is characteristic of AHK aimbot, triggerbot, or recoil control scripts.",
                            Detail = $"Cheat keyword: {matchedCheat} | Input primitive: {matchedPrimitive}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
    }

    private static async Task ScanAiAimbotFiles(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> allFiles;
            try
            {
                allFiles = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
            }
            catch { continue; }

            foreach (var filePath in allFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(filePath);
                var ext = Path.GetExtension(fileName).ToLowerInvariant();
                var dirName = Path.GetDirectoryName(filePath) ?? string.Empty;
                var dirLeaf = Path.GetFileName(dirName).ToLowerInvariant();

                foreach (var known in AiAimbotExecutableNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Mouse-Keyboard-Emulator",
                            Title = $"AI aimbot executable: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"File '{fileName}' is a known AI-based aimbot executable. " +
                                     "AI aimbots use YOLO or similar neural networks to detect enemy players on screen " +
                                     "and synthesize mouse movements to aim at them.",
                            Detail = $"Path: {filePath}",
                        });
                        goto nextFile;
                    }
                }

                if (ext == ".onnx")
                {
                    bool suspectDir = SuspiciousOnnxDirNames.Any(n =>
                        dirLeaf.Contains(n, StringComparison.OrdinalIgnoreCase)
                        || dirName.Contains(n, StringComparison.OrdinalIgnoreCase));

                    bool suspectRoot = root.Equals(
                        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                        StringComparison.OrdinalIgnoreCase)
                        || root.Contains("Downloads", StringComparison.OrdinalIgnoreCase);

                    if (suspectDir || suspectRoot)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Mouse-Keyboard-Emulator",
                            Title = $"ONNX model in suspicious location: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"ONNX neural network model file '{fileName}' found in a suspicious location " +
                                     $"('{dirLeaf}'). AI aimbots bundle ONNX model files (usually YOLOv5/v8 trained " +
                                     "on game footage) to detect enemy positions and automate mouse aiming.",
                            Detail = $"Directory: {dirName}",
                        });
                        goto nextFile;
                    }
                }

                if (ext == ".py")
                {
                    try
                    {
                        using var sr = new StreamReader(filePath);
                        string content = await sr.ReadToEndAsync().ConfigureAwait(false);

                        bool hasAiLib = AiAimbotPythonKeywords.Any(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool hasDetect = AiAimbotPythonDetectKeywords.Any(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (hasAiLib && hasDetect)
                        {
                            var matchedLib = AiAimbotPythonKeywords.FirstOrDefault(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                            ctx.AddFinding(new Finding
                            {
                                Module = "Mouse-Keyboard-Emulator",
                                Title = $"AI aimbot Python script: {fileName}",
                                Risk = RiskLevel.High,
                                Location = filePath,
                                FileName = fileName,
                                Reason = $"Python script '{fileName}' uses AI/ML library '{matchedLib}' combined " +
                                         "with object detection (predict/detect). This pattern is characteristic of " +
                                         "screen-capture AI aimbots that use neural networks to track enemies and " +
                                         "move the mouse automatically.",
                                Detail = $"AI library: {matchedLib} | Path: {filePath}",
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                    goto nextFile;
                }

                if (ext == ".exe")
                {
                    bool suspectName = AiAimbotDirectoryMarkers.Any(m =>
                        fileName.Contains(m, StringComparison.OrdinalIgnoreCase));
                    if (suspectName) goto nextFile;

                    bool isDesktopOrDownloads =
                        dirName.Equals(Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                            StringComparison.OrdinalIgnoreCase)
                        || dirName.Contains("Downloads", StringComparison.OrdinalIgnoreCase);

                    if (isDesktopOrDownloads)
                    {
                        DateTime created;
                        try { created = File.GetCreationTime(filePath); }
                        catch { goto nextFile; }

                        long fileSize;
                        try { fileSize = new FileInfo(filePath).Length; }
                        catch { goto nextFile; }

                        long sizeInMb = fileSize / (1024 * 1024);
                        bool recentlyCreated = (DateTime.Now - created).TotalDays < 90;
                        bool sizeMatches = sizeInMb >= 15 && sizeInMb <= 80;

                        if (recentlyCreated && sizeMatches)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Mouse-Keyboard-Emulator",
                                Title = $"Suspicious PyInstaller-sized EXE on Desktop/Downloads: {fileName}",
                                Risk = RiskLevel.Medium,
                                Location = filePath,
                                FileName = fileName,
                                Reason = $"Executable '{fileName}' ({sizeInMb} MB) was created within the last 90 days " +
                                         "and is sized 15-80 MB, matching the typical size of AI aimbot tools packaged " +
                                         "with PyInstaller (which bundles Python runtime + ONNX model into a single EXE).",
                                Detail = $"Size: {sizeInMb} MB | Created: {created:yyyy-MM-dd}",
                            });
                        }
                    }
                }

                nextFile:;
            }
        }
    }

    private static void CheckEmulatorRegistry(ScanContext ctx, CancellationToken ct)
    {
        foreach (var regPath in EmulatorRegistryPaths)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false)
                             ?? Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                var keyName = regPath.Split('\\').Last();
                ctx.AddFinding(new Finding
                {
                    Module = "Mouse-Keyboard-Emulator",
                    Title = $"Input emulator registry key present: {keyName}",
                    Risk = RiskLevel.Medium,
                    Location = $@"HKCU\{regPath}",
                    Reason = $"Registry key '{regPath}' found for input emulation software '{keyName}'. " +
                             "This software is commonly used to proxy aimbot mouse movements through hardware-emulating " +
                             "devices or kernel-mode drivers to evade anti-cheat detection.",
                    Detail = $"Registry: HKCU\\{regPath}",
                });
            }
            catch { }
        }
    }
}
