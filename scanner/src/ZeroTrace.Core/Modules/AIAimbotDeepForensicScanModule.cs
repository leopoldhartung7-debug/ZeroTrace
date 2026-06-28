using Microsoft.Win32;
using System.Runtime.Versioning;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class AIAimbotDeepForensicScanModule : IScanModule
{
    public string Name => "AI Aimbot Deep Forensic";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] AimbotScriptFileNames =
    [
        "aimbot.py", "triggerbot.py", "aim_assist.py", "object_detect.py",
        "aim_bot.py", "trigger_bot.py", "aimassist.py", "objectdetect.py",
        "detection.py", "detect.py", "aim.py", "trigger.py",
        "aimbot_v2.py", "aimbot_v3.py", "aimbot2.py", "aimbot3.py",
        "yolo_aimbot.py", "yolov8_aim.py", "ai_aimbot.py", "nn_aimbot.py",
        "bettercam_aimbot.py", "dxcam_aimbot.py", "mss_aimbot.py",
        "screen_aimbot.py", "screen_aim.py", "screen_detect.py",
        "aimbot_main.py", "main_aimbot.py", "run_aimbot.py",
        "cheat.py", "hack.py", "esp.py", "wallhack.py",
        "autoaim.py", "auto_aim.py", "humanizer.py",
    ];

    private static readonly string[] AimbotPythonImports =
    [
        "ultralytics", "bettercam", "dxcam", "mss", "cv2",
        "torch", "tensorflow", "keras", "onnxruntime", "onnx",
        "pymem", "win32api", "pynput", "pyautogui", "pygetwindow",
        "interception", "mouse", "keyboard",
    ];

    private static readonly string[] OnnxModelFileNames =
    [
        "best.onnx", "yolov8n.onnx", "aimbot.onnx", "model.onnx",
        "yolov5n.onnx", "yolov8s.onnx", "yolov8m.onnx",
        "yolo.onnx", "detect.onnx", "aim.onnx",
        "player_detect.onnx", "head_detect.onnx", "enemy.onnx",
        "fortnite.onnx", "valorant.onnx", "apex.onnx", "warzone.onnx",
        "csgo.onnx", "cs2.onnx", "pubg.onnx", "r6.onnx",
        "player.onnx", "body.onnx", "head.onnx",
        "weights.onnx", "final.onnx", "trained.onnx",
    ];

    private static readonly string[] AiAimbotLibraries =
    [
        "ultralytics", "bettercam", "dxcam", "mss",
        "pymem", "interception-python", "interception",
        "pynput", "pyautogui", "mouse", "keyboard",
        "onnxruntime-gpu", "onnxruntime", "onnx",
        "torch", "torchvision", "tensorflow", "keras",
        "opencv-python", "opencv-python-headless",
        "Pillow", "numpy", "scipy", "pywin32",
    ];

    private static readonly string[] AimbotExeNames =
    [
        "aimbot.exe", "triggerbot.exe", "aim_bot.exe", "aim_assist.exe",
        "esp_overlay.exe", "aimassist.exe", "trigger_bot.exe",
        "ai_aimbot.exe", "yolo_aimbot.exe", "object_detect.exe",
        "detection.exe", "screen_aim.exe", "autoaim.exe",
        "bettercam_aim.exe", "dxcam_aim.exe", "cheat.exe",
        "aimbot_v2.exe", "aimbot_v3.exe", "aim.exe",
        "nn_aim.exe", "ai_aim.exe", "aimhack.exe",
        "valorant_aimbot.exe", "fortnite_aimbot.exe", "apex_aimbot.exe",
        "warzone_aimbot.exe", "csgo_aimbot.exe", "pubg_aimbot.exe",
        "r6_aimbot.exe", "tarkov_aimbot.exe", "cs2_aimbot.exe",
    ];

    private static readonly string[] AimbotConfigKeys =
    [
        "confidence_threshold", "target_class", "fov_radius",
        "triggerbot_delay", "head_smoothness", "aim_smoothing",
        "mouse_speed", "detection_fps", "screen_region",
        "aim_bone", "head_bone", "neck_bone", "target_bone",
        "smooth_factor", "smoothness", "prediction_factor",
        "auto_shoot", "auto_fire", "trigger_delay",
        "triggerbot_confidence", "aim_confidence",
        "fov_size", "fov_color", "draw_fov",
        "esp_enabled", "esp_boxes", "esp_health", "esp_names",
        "screen_width", "screen_height", "capture_fps",
        "model_path", "onnx_path", "weights_path",
        "classes", "class_names", "target_classes",
        "cuda_device", "directml_device", "cpu_threads",
    ];

    private static readonly string[] CheatVenvNames =
    [
        "aimbot", "cheat", "hack", "triggerbot", "aim",
        "yolo", "detect", "esp", "overlay", "wallhack",
        "aimassist", "autoaim", "aimer", "target",
        "screen", "capture", "cv", "neural", "nn",
    ];

    private static readonly string[] AimbotRegistryRunKeywords =
    [
        "aimbot", "triggerbot", "aim_bot", "aim_assist",
        "yolo_aim", "ai_aimbot", "object_detect",
        "bettercam_aim", "dxcam_aim", "screen_aim",
        "python_aimbot", "py_aimbot", "py_aim",
    ];

    private static readonly string[] AimbotPrefetchNames =
    [
        "AIMBOT.EXE", "TRIGGERBOT.EXE", "AIM_BOT.EXE",
        "AIM_ASSIST.EXE", "ESP_OVERLAY.EXE", "AI_AIMBOT.EXE",
        "OBJECT_DETECT.EXE", "DETECTION.EXE", "SCREEN_AIM.EXE",
        "AIMASSIST.EXE", "AUTOAIM.EXE", "YOLO_AIMBOT.EXE",
    ];

    private static readonly string[] MouseSmoothingLibraries =
    [
        "win32api", "pynput", "pyautogui", "interception",
        "mouse", "keyboard", "ctypes", "windll",
        "SendInput", "mouse_event", "SetCursorPos",
        "MOUSEEVENTF_MOVE", "INPUT_MOUSE",
    ];

    private static readonly string[] AimbotLogKeywords =
    [
        "detected", "detection", "target", "enemy", "player",
        "head", "body", "confidence", "shooting", "fired",
        "aim", "lock", "tracking", "lost target", "acquired",
        "trigger", "clicked", "mouse moved", "fov",
    ];

    private static readonly string[] BrowserAimbotSearchTerms =
    [
        "ultralytics aimbot", "bettercam aimbot", "yolov8 aimbot",
        "ai aimbot fortnite", "object detection cheat",
        "yolov8 aimbot gta", "ai aimbot valorant", "ai aimbot apex",
        "python aimbot", "python triggerbot", "dxcam aimbot",
        "onnx aimbot", "yolo cheat", "neural network aimbot",
        "screen capture aimbot", "ai triggerbot", "mss aimbot",
        "ultralytics cheat", "bettercam triggerbot",
        "yolov8 object detection game", "opencv aimbot",
        "pytorch aimbot", "tensorflow aimbot",
    ];

    private static readonly string[] AimbotDownloadNames =
    [
        "ai_aimbot", "yolo_cheat", "object_detection_hack",
        "aimbot_ai", "neural_aimbot", "yolov8_aimbot",
        "ai_triggerbot", "python_aimbot", "bettercam_aimbot",
        "dxcam_aimbot", "mss_aimbot", "screen_aimbot",
        "ai_cheat", "yolo_aim", "ultralytics_aimbot",
        "aimbot_pytorch", "aimbot_tensorflow", "aimbot_onnx",
        "fortnite_ai_aimbot", "valorant_ai_aimbot", "apex_ai_aimbot",
        "warzone_ai_aimbot", "csgo_ai_aimbot", "pubg_ai_aimbot",
    ];

    private static readonly string[] AimbotInstallerKeywords =
    [
        "pip install ultralytics", "pip install bettercam",
        "pip install dxcam", "pip install mss",
        "pip install pymem", "pip install pynput",
        "pip install onnxruntime", "pip install torch",
        "pip install tensorflow", "pip install opencv",
        "pip install pyautogui", "pip install interception",
        "install ultralytics", "install bettercam",
        "python aimbot.py", "python triggerbot.py",
        "python aim_assist.py", "python object_detect.py",
        "start aimbot.py", "run aimbot.py",
        "python.exe aimbot", "pythonw aimbot",
    ];

    private static readonly string[] CudaAimbotFileNames =
    [
        "cudart64_110.dll", "cudart64_111.dll", "cudart64_112.dll",
        "cublas64_11.dll", "cublasLt64_11.dll",
        "cudnn64_8.dll", "cudnn_ops_infer64_8.dll",
        "DirectML.dll", "directml.dll",
        "cufft64_10.dll", "curand64_10.dll",
        "nvcuda.dll", "nvrtc64_112.dll",
    ];

    private static readonly string[] DatasetArtifactFolders =
    [
        "images/train", "images/val", "images/test",
        "labels/train", "labels/val", "labels/test",
        "datasets", "training_data", "dataset",
        "annotations", "labelImg",
    ];

    private static readonly string[] DiscordAimbotKeywords =
    [
        "aimbot", "triggerbot", "yolov8", "ultralytics",
        "bettercam", "dxcam", "python aim", "ai cheat",
        "object detect", "neural aim", "buy aimbot",
        "aimbot purchase", "aimbot key", "aimbot license",
        "ai triggerbot", "screen capture cheat",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "AI Aimbot Deep Forensic Scan gestartet");

        await Task.WhenAll(
            CheckAimbotScriptFiles(ctx, ct),
            CheckOnnxModelFiles(ctx, ct),
            CheckAiAimbotLibraries(ctx, ct),
            CheckAimbotExecutables(ctx, ct),
            CheckScreenCaptureLibraryArtifacts(ctx, ct),
            CheckAimbotConfigFiles(ctx, ct),
            CheckCudaDirectMlArtifacts(ctx, ct),
            CheckDatasetArtifacts(ctx, ct),
            CheckAimbotVirtualEnvironments(ctx, ct),
            CheckPyInstallerNuitkaArtifacts(ctx, ct),
            CheckAimbotRegistryTraces(ctx, ct),
            CheckAimbotPrefetchEntries(ctx, ct),
            CheckMouseSmoothingArtifacts(ctx, ct),
            CheckAimbotLogFiles(ctx, ct),
            CheckAimbotBrowserHistory(ctx, ct),
            CheckDiscordTelegramArtifacts(ctx, ct),
            CheckAimbotDownloadArtifacts(ctx, ct),
            CheckAimbotInstallerScripts(ctx, ct)
        );

        ctx.Report(1.0, Name, "AI Aimbot Deep Forensic Scan abgeschlossen");
    }

    private Task CheckAimbotScriptFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                userProfile,
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(dir, "*.py", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);

                    bool isKnownAimbotScript = AimbotScriptFileNames.Any(n =>
                        fn.Equals(n, StringComparison.OrdinalIgnoreCase));

                    if (!isKnownAimbotScript) continue;

                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (Exception) { continue; }

                    var importHits = AimbotPythonImports
                        .Where(lib => content.Contains(lib, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (importHits.Count >= 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot Python-Skript: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Python-Skript '{fn}' entspricht einem bekannten AI-Aimbot-Dateinamen " +
                                     $"und enthaelt {importHits.Count} AI/Screen-Capture-Bibliothek-Importe. " +
                                     "AI-Aimbots nutzen Echtzeit-Objekterkennung (YOLO, OpenCV) zur automatischen Zielanvisierung.",
                            Detail = $"Importe gefunden: {string.Join(", ", importHits.Take(8))} | Pfad: {file}"
                        });
                    }
                    else
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot Python-Skript (Name): {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Python-Skript '{fn}' entspricht einem bekannten AI-Aimbot-Dateinamen " +
                                     "in einem Benutzerverzeichnis.",
                            Detail = $"Pfad: {file}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckOnnxModelFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                userProfile,
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(dir, "*.onnx", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    bool isKnownAimbotModel = OnnxModelFileNames.Any(n =>
                        fn.Equals(n, StringComparison.OrdinalIgnoreCase));

                    var fnLower = fn.ToLowerInvariant();
                    bool hasAimbotKeyword =
                        fnLower.Contains("aim") || fnLower.Contains("cheat") ||
                        fnLower.Contains("hack") || fnLower.Contains("detect") ||
                        fnLower.Contains("yolo") || fnLower.Contains("enemy") ||
                        fnLower.Contains("player") || fnLower.Contains("head") ||
                        fnLower.Contains("body") || fnLower.Contains("target");

                    if (isKnownAimbotModel || hasAimbotKeyword)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot ONNX-Modelldatei: {fn}",
                            Risk = isKnownAimbotModel ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = isKnownAimbotModel
                                ? $"ONNX-Modelldatei '{fn}' entspricht bekanntem AI-Aimbot-Modellnamen. " +
                                  "AI-Aimbots laden ONNX-Modelle (YOLO-basiert) zur Echtzeit-Spielererkennung."
                                : $"ONNX-Modelldatei '{fn}' enthaelt aimbot-relevante Bezeichner im Dateinamen. " +
                                  "Solche Modelle werden fuer automatische Zielanvisierung in Spielen eingesetzt.",
                            Detail = $"Groesse: {GetFileSizeKb(file)} KB | Pfad: {file}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckAiAimbotLibraries(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            var pythonVersionDirs = new List<string>();
            try
            {
                var pythonBase = Path.Combine(localAppData, "Programs", "Python");
                if (Directory.Exists(pythonBase))
                    pythonVersionDirs.AddRange(Directory.GetDirectories(pythonBase));
            }
            catch { }

            var sitePackagesRoots = new List<string>();
            foreach (var pyDir in pythonVersionDirs)
            {
                var sp = Path.Combine(pyDir, "Lib", "site-packages");
                if (Directory.Exists(sp)) sitePackagesRoots.Add(sp);
            }

            var extraSitePackages = new[]
            {
                Path.Combine(userProfile, "AppData", "Roaming", "Python"),
                Path.Combine(localAppData, "Programs", "Python"),
            };

            foreach (var extra in extraSitePackages)
            {
                if (!Directory.Exists(extra)) continue;
                try
                {
                    foreach (var sub in Directory.GetDirectories(extra, "*", SearchOption.AllDirectories))
                    {
                        if (sub.Contains("site-packages", StringComparison.OrdinalIgnoreCase))
                            sitePackagesRoots.Add(sub);
                    }
                }
                catch { }
            }

            foreach (var sp in sitePackagesRoots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(sp)) continue;
                ct.ThrowIfCancellationRequested();

                foreach (var lib in AiAimbotLibraries)
                {
                    var libDir = Path.Combine(sp, lib);
                    var libDirNorm = Path.Combine(sp, lib.Replace("-", "_"));
                    var libDirNorm2 = Path.Combine(sp, lib.Replace("-", "").ToLowerInvariant());

                    bool found = Directory.Exists(libDir) || Directory.Exists(libDirNorm) || Directory.Exists(libDirNorm2);

                    if (!found)
                    {
                        try
                        {
                            found = Directory.GetDirectories(sp).Any(d =>
                                Path.GetFileName(d).StartsWith(lib.Replace("-", "_"), StringComparison.OrdinalIgnoreCase) ||
                                Path.GetFileName(d).StartsWith(lib.Replace("-", ""), StringComparison.OrdinalIgnoreCase));
                        }
                        catch { }
                    }

                    if (found)
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot Python-Bibliothek installiert: {lib}",
                            Risk = RiskLevel.High,
                            Location = sp,
                            FileName = lib,
                            Reason = $"AI-Aimbot-relevante Bibliothek '{lib}' in Python site-packages gefunden. " +
                                     $"'{lib}' wird von AI-Aimbot-Skripten fuer Objekterkennung, " +
                                     "Screen-Capture oder Mausbewegung verwendet.",
                            Detail = $"site-packages: {sp}"
                        });
                    }
                }

                var reqFiles = new[] { "requirements.txt", "requirements_aimbot.txt", "req.txt" };
                foreach (var reqFile in reqFiles)
                {
                    var reqPath = Path.Combine(sp, "..", reqFile);
                    try { reqPath = Path.GetFullPath(reqPath); } catch { continue; }
                    if (!File.Exists(reqPath)) continue;

                    string reqContent;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(reqPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        reqContent = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (Exception) { continue; }

                    var reqHits = AiAimbotLibraries
                        .Where(lib => reqContent.Contains(lib, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (reqHits.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot requirements.txt: {Path.GetFileName(reqPath)}",
                            Risk = RiskLevel.High,
                            Location = reqPath,
                            FileName = Path.GetFileName(reqPath),
                            Reason = $"requirements.txt enthaelt {reqHits.Count} AI-Aimbot-Bibliotheken. " +
                                     "Solche Anforderungsdateien gehoeren typischerweise zu AI-Aimbot-Projekten.",
                            Detail = $"Bibliotheken: {string.Join(", ", reqHits.Take(8))}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckAimbotExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.GetTempPath(),
                Path.Combine(userProfile, "AppData", "Local", "Temp"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);

                    bool isKnownAimbotExe = AimbotExeNames.Any(n =>
                        fn.Equals(n, StringComparison.OrdinalIgnoreCase));

                    if (!isKnownAimbotExe)
                    {
                        var fnLower = fn.ToLowerInvariant();
                        isKnownAimbotExe =
                            (fnLower.Contains("aimbot") || fnLower.Contains("triggerbot") || fnLower.Contains("aim_bot")) &&
                            (fnLower.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));
                    }

                    if (isKnownAimbotExe)
                    {
                        ctx.IncrementFiles();

                        bool hasOnnxSibling = false;
                        bool hasPySibling = false;
                        try
                        {
                            var parentDir = Path.GetDirectoryName(file) ?? string.Empty;
                            if (Directory.Exists(parentDir))
                            {
                                hasOnnxSibling = Directory.GetFiles(parentDir, "*.onnx").Length > 0;
                                hasPySibling = Directory.GetFiles(parentDir, "*.py").Any(f =>
                                    AimbotScriptFileNames.Any(n =>
                                        Path.GetFileName(f).Equals(n, StringComparison.OrdinalIgnoreCase)));
                            }
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot Executable: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"AI-Aimbot-Executable '{fn}' gefunden. " +
                                     "PyInstaller oder Nuitka kompilierte Aimbots tarnen Python-AI-Aimbots als EXE-Dateien. " +
                                     (hasOnnxSibling ? "ONNX-Modell im selben Verzeichnis gefunden. " : "") +
                                     (hasPySibling ? "Aimbot-Python-Quellcode im selben Verzeichnis gefunden." : ""),
                            Detail = $"Groesse: {GetFileSizeKb(file)} KB | ONNX: {hasOnnxSibling} | .py: {hasPySibling} | Pfad: {file}"
                        });
                    }
                }
            }

            var processes = ctx.GetProcessSnapshot();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();
                var pname = proc.ProcessName + ".exe";

                bool isAimbotProc = AimbotExeNames.Any(n =>
                    pname.Equals(n, StringComparison.OrdinalIgnoreCase));

                if (!isAimbotProc)
                {
                    var pnameLower = pname.ToLowerInvariant();
                    isAimbotProc = pnameLower.Contains("aimbot") || pnameLower.Contains("triggerbot");
                }

                if (isAimbotProc)
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AI-Aimbot-Prozess aktiv: {pname}",
                        Risk = RiskLevel.Critical,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Bekannter AI-Aimbot-Prozess '{pname}' ist aktuell aktiv. " +
                                 "Ein laufendes AI-Aimbot-Tool kann in Echtzeit Spieler erkennen und automatisch zielen.",
                        Detail = $"PID: {proc.Id}"
                    });
                }
            }
        }, ct);

    private Task CheckScreenCaptureLibraryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            var cacheCheckDirs = new[]
            {
                Path.Combine(localAppData, "bettercam"),
                Path.Combine(localAppData, "dxcam"),
                Path.Combine(appData, "bettercam"),
                Path.Combine(appData, "dxcam"),
                Path.Combine(localAppData, "mss"),
            };

            foreach (var cacheDir in cacheCheckDirs)
            {
                if (!Directory.Exists(cacheDir)) continue;
                ct.ThrowIfCancellationRequested();

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Screen-Capture-Bibliothek Cache/Konfig: {Path.GetFileName(cacheDir)}",
                    Risk = RiskLevel.High,
                    Location = cacheDir,
                    FileName = Path.GetFileName(cacheDir),
                    Reason = $"Cache/Konfigurationsverzeichnis der Screen-Capture-Bibliothek '{Path.GetFileName(cacheDir)}' gefunden. " +
                             "bettercam und dxcam sind hochperformante Windows-Screen-Capture-Bibliotheken, " +
                             "die fast ausschliesslich von AI-Aimbots fuer GPU-beschleunigte Spielbildschirmerfassung verwendet werden.",
                    Detail = $"Pfad: {cacheDir}"
                });
            }

            var cheatNamedVenvDirs = new List<string>();
            var searchRoots = new[]
            {
                userProfile,
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                ct.ThrowIfCancellationRequested();

                try
                {
                    foreach (var dir in Directory.GetDirectories(root))
                    {
                        var dirName = Path.GetFileName(dir).ToLowerInvariant();
                        if (CheatVenvNames.Any(n => dirName.Equals(n, StringComparison.OrdinalIgnoreCase) ||
                                                    dirName.Contains(n, StringComparison.OrdinalIgnoreCase)))
                        {
                            var venvPython = Path.Combine(dir, "Scripts", "python.exe");
                            var venvActivate = Path.Combine(dir, "Scripts", "activate");
                            var venvActivateBat = Path.Combine(dir, "Scripts", "activate.bat");

                            if (File.Exists(venvPython) || File.Exists(venvActivate) || File.Exists(venvActivateBat))
                                cheatNamedVenvDirs.Add(dir);
                        }
                    }
                }
                catch { }
            }

            foreach (var venvDir in cheatNamedVenvDirs)
            {
                ct.ThrowIfCancellationRequested();
                var venvName = Path.GetFileName(venvDir);

                var screenLibsFound = new List<string>();
                foreach (var lib in new[] { "bettercam", "dxcam", "mss" })
                {
                    var libPath = Path.Combine(venvDir, "Lib", "site-packages", lib);
                    if (Directory.Exists(libPath)) screenLibsFound.Add(lib);
                }

                if (screenLibsFound.Count > 0)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Screen-Capture-Lib in Cheat-venv: {venvName}",
                        Risk = RiskLevel.Critical,
                        Location = venvDir,
                        FileName = venvName,
                        Reason = $"Python-Virtual-Environment '{venvName}' mit cheat-relevantem Namen enthaelt " +
                                 $"Screen-Capture-Bibliotheken: {string.Join(", ", screenLibsFound)}. " +
                                 "Dies ist ein klares Indiz fuer ein AI-Aimbot-Entwicklungs- oder Ausfuehrungsumfeld.",
                        Detail = $"Bibliotheken: {string.Join(", ", screenLibsFound)} | venv: {venvDir}"
                    });
                }
                else
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiges Python-venv (Cheat-Name): {venvName}",
                        Risk = RiskLevel.Medium,
                        Location = venvDir,
                        FileName = venvName,
                        Reason = $"Python-Virtual-Environment mit verdaechtigem Namen '{venvName}' gefunden.",
                        Detail = $"venv-Pfad: {venvDir}"
                    });
                }
            }
        }, ct);

    private Task CheckAimbotConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                userProfile,
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };

            var configExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { ".json", ".yaml", ".yml", ".ini", ".cfg", ".toml", ".conf" };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!configExtensions.Contains(ext)) continue;

                    var fn = Path.GetFileName(file);
                    var fnLower = fn.ToLowerInvariant();

                    bool hasCheatName =
                        fnLower.Contains("aimbot") || fnLower.Contains("triggerbot") ||
                        fnLower.Contains("aim_bot") || fnLower.Contains("cheat") ||
                        fnLower.Contains("hack") || fnLower.Contains("esp") ||
                        fnLower.Contains("yolo") || fnLower.Contains("detect");

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (Exception) { continue; }

                    var configHits = AimbotConfigKeys
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (configHits.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot Konfigurationsdatei: {fn}",
                            Risk = hasCheatName ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Konfigurationsdatei '{fn}' enthaelt {configHits.Count} AI-Aimbot-spezifische " +
                                     $"Einstellungsschluessel wie '{configHits[0]}', '{(configHits.Count > 1 ? configHits[1] : "")}'. " +
                                     "Solche Konfigurationen steuern Aimbot-Verhalten (FOV, Smoothing, Confidence-Threshold).",
                            Detail = $"Schluessel: {string.Join(", ", configHits.Take(10))}"
                        });
                    }
                    else if (configHits.Count >= 1 && hasCheatName)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige Aimbot-Konfiguration: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei '{fn}' mit aimbot-relevantem Namen enthaelt AI-Aimbot-Konfigurationsschluessel: " +
                                     $"'{configHits[0]}'.",
                            Detail = $"Schluessel: {string.Join(", ", configHits)}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckCudaDirectMlArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                var cudaFound = new List<string>();
                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);

                    bool isCudaFile = CudaAimbotFileNames.Any(n =>
                        fn.Equals(n, StringComparison.OrdinalIgnoreCase));

                    if (isCudaFile) cudaFound.Add(fn);
                }

                if (cudaFound.Count >= 2)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CUDA/DirectML-Dateien in Cheat-Verzeichnis: {Path.GetFileName(dir)}",
                        Risk = RiskLevel.High,
                        Location = dir,
                        FileName = Path.GetFileName(dir),
                        Reason = $"{cudaFound.Count} CUDA/DirectML-DLLs im Verzeichnis '{dir}' gefunden. " +
                                 "AI-Aimbots legen GPU-Beschleunigungs-DLLs (CUDA, cuDNN, DirectML) " +
                                 "neben der Aimbot-Executable ab, um GPU-basierte Inferenz zu ermoeglichen.",
                        Detail = $"DLLs: {string.Join(", ", cudaFound.Take(8))}"
                    });
                }

                bool directMlPresent = files.Any(f =>
                    Path.GetFileName(f).Equals("DirectML.dll", StringComparison.OrdinalIgnoreCase));

                if (directMlPresent)
                {
                    bool aimbotExePresent = false;
                    try
                    {
                        aimbotExePresent = Directory.GetFiles(dir, "*.exe").Any(f =>
                            AimbotExeNames.Any(n =>
                                Path.GetFileName(f).Equals(n, StringComparison.OrdinalIgnoreCase)));
                    }
                    catch { }

                    if (aimbotExePresent)
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "DirectML.dll neben Aimbot-EXE",
                            Risk = RiskLevel.Critical,
                            Location = dir,
                            FileName = "DirectML.dll",
                            Reason = "DirectML.dll befindet sich im selben Verzeichnis wie eine bekannte Aimbot-Executable. " +
                                     "DirectML ermoegliche GPU-beschleunigte Inferenz ohne CUDA — " +
                                     "typisches Deployment-Muster fuer AI-Aimbots auf AMD/Intel-GPUs.",
                            Detail = $"Verzeichnis: {dir}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckDatasetArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                userProfile,
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                ct.ThrowIfCancellationRequested();

                string[] allDirs;
                try { allDirs = Directory.GetDirectories(root, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var dir in allDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var dirName = Path.GetFileName(dir).ToLowerInvariant();

                    bool hasDatasetStructure = false;
                    var foundSubfolders = new List<string>();

                    foreach (var dataFolder in DatasetArtifactFolders)
                    {
                        var subPath = Path.Combine(dir, dataFolder.Replace("/", Path.DirectorySeparatorChar.ToString()));
                        if (Directory.Exists(subPath))
                        {
                            hasDatasetStructure = true;
                            foundSubfolders.Add(dataFolder);
                        }
                    }

                    if (hasDatasetStructure)
                    {
                        ctx.IncrementFiles();
                        int imageCount = 0;
                        try { imageCount = Directory.GetFiles(dir, "*.jpg", SearchOption.AllDirectories).Length +
                                          Directory.GetFiles(dir, "*.png", SearchOption.AllDirectories).Length; }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot-Trainingsdatensatz: {Path.GetFileName(dir)}",
                            Risk = RiskLevel.High,
                            Location = dir,
                            FileName = Path.GetFileName(dir),
                            Reason = $"Verzeichnis '{Path.GetFileName(dir)}' enthaelt YOLO-Datensatzstruktur " +
                                     $"({string.Join(", ", foundSubfolders.Take(4))}). " +
                                     "Solche Strukturen werden zum Training von AI-Aimbot-Modellen (YOLO/Ultralytics) " +
                                     "auf Spieler-Screenshots verwendet.",
                            Detail = $"Gefundene Ordner: {string.Join(", ", foundSubfolders)} | " +
                                     $"Bilder ca.: {imageCount} | Pfad: {dir}"
                        });
                    }

                    if (dirName.Contains("labelimg") || dirName.Contains("label_img") || dirName.Contains("labeling"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"LabelImg Annotation-Tool-Verzeichnis: {Path.GetFileName(dir)}",
                            Risk = RiskLevel.Medium,
                            Location = dir,
                            FileName = Path.GetFileName(dir),
                            Reason = "LabelImg oder aehnliches Annotations-Tool-Verzeichnis gefunden. " +
                                     "labelImg wird zum Annotieren von Spielerbildern fuer AI-Aimbot-Training verwendet.",
                            Detail = $"Pfad: {dir}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckAimbotVirtualEnvironments(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchRoots = new[]
            {
                userProfile,
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };

            var condaEnvRoots = new List<string>();
            var condaBase = Environment.GetEnvironmentVariable("CONDA_PREFIX") ??
                            Path.Combine(userProfile, "miniconda3", "envs");
            if (Directory.Exists(condaBase)) condaEnvRoots.Add(condaBase);

            var condaBase2 = Path.Combine(userProfile, "anaconda3", "envs");
            if (Directory.Exists(condaBase2)) condaEnvRoots.Add(condaBase2);

            var condaBase3 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "AppData", "Local", "miniconda3", "envs");
            if (Directory.Exists(condaBase3)) condaEnvRoots.Add(condaBase3);

            foreach (var condaEnvRoot in condaEnvRoots)
            {
                if (!Directory.Exists(condaEnvRoot)) continue;
                ct.ThrowIfCancellationRequested();

                string[] envDirs;
                try { envDirs = Directory.GetDirectories(condaEnvRoot); }
                catch { continue; }

                foreach (var envDir in envDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var envName = Path.GetFileName(envDir).ToLowerInvariant();

                    if (CheatVenvNames.Any(n => envName.Equals(n, StringComparison.OrdinalIgnoreCase) ||
                                               envName.Contains(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Conda-Umgebung mit Aimbot-Name: {Path.GetFileName(envDir)}",
                            Risk = RiskLevel.High,
                            Location = envDir,
                            FileName = Path.GetFileName(envDir),
                            Reason = $"Conda-Environment '{Path.GetFileName(envDir)}' mit verdaechtigem Namen gefunden. " +
                                     "AI-Aimbot-Entwickler nutzen dedizierte Conda-Umgebungen fuer ihre Cheat-Projekte.",
                            Detail = $"Conda-envs: {condaEnvRoot}"
                        });
                    }
                }
            }

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                ct.ThrowIfCancellationRequested();

                string[] topDirs;
                try { topDirs = Directory.GetDirectories(root, "*", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (var dir in topDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var dirName = Path.GetFileName(dir).ToLowerInvariant();

                    if (!CheatVenvNames.Any(n => dirName.Equals(n, StringComparison.OrdinalIgnoreCase) ||
                                                 dirName.Contains(n, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    var pyExe = Path.Combine(dir, "Scripts", "python.exe");
                    var activateBat = Path.Combine(dir, "Scripts", "activate.bat");
                    var pyvenvCfg = Path.Combine(dir, "pyvenv.cfg");

                    if (File.Exists(pyExe) || File.Exists(activateBat) || File.Exists(pyvenvCfg))
                    {
                        ctx.IncrementFiles();

                        var sp = Path.Combine(dir, "Lib", "site-packages");
                        var aimbotLibsFound = new List<string>();
                        if (Directory.Exists(sp))
                        {
                            foreach (var lib in AiAimbotLibraries)
                            {
                                try
                                {
                                    if (Directory.GetDirectories(sp).Any(d =>
                                        Path.GetFileName(d).StartsWith(lib.Replace("-", "_"),
                                            StringComparison.OrdinalIgnoreCase)))
                                        aimbotLibsFound.Add(lib);
                                }
                                catch { }
                            }
                        }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot Python-venv: {Path.GetFileName(dir)}",
                            Risk = aimbotLibsFound.Count > 0 ? RiskLevel.Critical : RiskLevel.High,
                            Location = dir,
                            FileName = Path.GetFileName(dir),
                            Reason = $"Python-Virtual-Environment mit Aimbot-relevantem Namen '{Path.GetFileName(dir)}' gefunden. " +
                                     (aimbotLibsFound.Count > 0
                                         ? $"Enthaelt AI-Aimbot-Bibliotheken: {string.Join(", ", aimbotLibsFound.Take(6))}."
                                         : "Enthaelt Python-Laufzeitumgebung."),
                            Detail = $"venv: {dir}" + (aimbotLibsFound.Count > 0
                                ? $" | Libs: {string.Join(", ", aimbotLibsFound)}"
                                : "")
                        });
                    }
                }
            }
        }, ct);

    private Task CheckPyInstallerNuitkaArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                userProfile,
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] specFiles;
                try { specFiles = Directory.GetFiles(dir, "*.spec", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var specFile in specFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(specFile);
                    var fnLower = fn.ToLowerInvariant();

                    bool isAimbotSpec =
                        fnLower.Contains("aimbot") || fnLower.Contains("triggerbot") ||
                        fnLower.Contains("aim_bot") || fnLower.Contains("cheat") ||
                        fnLower.Contains("aim") || fnLower.Contains("detect");

                    if (!isAimbotSpec) continue;

                    ctx.IncrementFiles();

                    string specContent = string.Empty;
                    try
                    {
                        using var fs = new FileStream(specFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        specContent = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { }
                    catch (Exception) { }

                    bool hasAimbotImports = AimbotPythonImports.Any(lib =>
                        specContent.Contains(lib, StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PyInstaller-Spec fuer AI-Aimbot: {fn}",
                        Risk = RiskLevel.High,
                        Location = specFile,
                        FileName = fn,
                        Reason = $"PyInstaller-Spec-Datei '{fn}' mit Aimbot-Bezeichner gefunden. " +
                                 "Solche .spec-Dateien werden verwendet, um Python-AI-Aimbot-Skripte " +
                                 "in eigenstaendige EXE-Dateien zu verpacken (PyInstaller/Nuitka)." +
                                 (hasAimbotImports ? " Enthaelt AI-Aimbot-Bibliotheksreferenzen." : ""),
                        Detail = $"Pfad: {specFile}"
                    });

                    var parentDir = Path.GetDirectoryName(specFile) ?? string.Empty;
                    var distDir = Path.Combine(parentDir, "dist");
                    var buildDir = Path.Combine(parentDir, "build");

                    if (Directory.Exists(distDir))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PyInstaller dist/-Verzeichnis (Aimbot): {Path.GetFileName(parentDir)}",
                            Risk = RiskLevel.High,
                            Location = distDir,
                            FileName = "dist",
                            Reason = $"PyInstaller dist/-Ausgabeverzeichnis neben Aimbot-Spec-Datei '{fn}' gefunden. " +
                                     "Enthalt die kompilierte Aimbot-EXE.",
                            Detail = $"Pfad: {distDir}"
                        });
                    }

                    if (Directory.Exists(buildDir))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PyInstaller build/-Verzeichnis (Aimbot): {Path.GetFileName(parentDir)}",
                            Risk = RiskLevel.Medium,
                            Location = buildDir,
                            FileName = "build",
                            Reason = $"PyInstaller build/-Verzeichnis neben Aimbot-Spec-Datei '{fn}'. " +
                                     "Temporaere Build-Artefakte vom Aimbot-Packaging-Prozess.",
                            Detail = $"Pfad: {buildDir}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckAimbotRegistryTraces(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var runKeyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            foreach (var runPath in runKeyPaths)
            {
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(runPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var value = key.GetValue(valueName) as string ?? string.Empty;

                        bool nameHit = AimbotRegistryRunKeywords.Any(k =>
                            valueName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool valueHit = AimbotRegistryRunKeywords.Any(k =>
                            value.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool pythonAimbotHit = value.Contains("python", StringComparison.OrdinalIgnoreCase) &&
                                              AimbotScriptFileNames.Any(s =>
                                                  value.Contains(s, StringComparison.OrdinalIgnoreCase));

                        if (nameHit || valueHit || pythonAimbotHit)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"AI-Aimbot Autostart-Registry (HKCU): {valueName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\{runPath}",
                                FileName = valueName,
                                Reason = $"Registry-Autostart-Eintrag '{valueName}' enthaelt AI-Aimbot-Schluesselbegriffe. " +
                                         "Der Aimbot wird bei jeder Windows-Anmeldung automatisch gestartet.",
                                Detail = $"Wert: {value}"
                            });
                        }
                    }
                }
                catch { }

                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(runPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var value = key.GetValue(valueName) as string ?? string.Empty;

                        bool nameHit = AimbotRegistryRunKeywords.Any(k =>
                            valueName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool valueHit = AimbotRegistryRunKeywords.Any(k =>
                            value.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (nameHit || valueHit)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"AI-Aimbot Autostart-Registry (HKLM): {valueName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{runPath}",
                                FileName = valueName,
                                Reason = $"Registry-Autostart-Eintrag '{valueName}' (HKLM) enthaelt AI-Aimbot-Schluesselbegriffe.",
                                Detail = $"Wert: {value}"
                            });
                        }
                    }
                }
                catch { }
            }

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                using var ua = baseKey.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
                if (ua == null) return;

                foreach (var guid in ua.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    using var count = ua.OpenSubKey($@"{guid}\Count");
                    if (count == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in count.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var decoded = Rot13Decode(valueName);
                        if (string.IsNullOrWhiteSpace(decoded)) continue;

                        bool isAimbotExe = AimbotExeNames.Any(n =>
                            decoded.Contains(n, StringComparison.OrdinalIgnoreCase));
                        bool isPythonAimbot = decoded.Contains("python", StringComparison.OrdinalIgnoreCase) &&
                                             AimbotScriptFileNames.Any(s =>
                                                 decoded.Contains(s, StringComparison.OrdinalIgnoreCase));

                        if (isAimbotExe || isPythonAimbot)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"AI-Aimbot UserAssist-Spur: {Path.GetFileName(decoded)}",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"UserAssist-Eintrag beweist Ausfuehrung von '{decoded}'. " +
                                         "UserAssist protokolliert GUI-Programmstarts, auch nach Dateiloeschung.",
                                Detail = $"Dekodierter Pfad: {decoded}"
                            });
                        }
                    }
                }
            }
            catch { }

            var muiCachePaths = new[]
            {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            };

            foreach (var muiPath in muiCachePaths)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                    using var key = baseKey.OpenSubKey(muiPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        bool isAimbotTool = AimbotExeNames.Any(n =>
                            valueName.Contains(n.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));

                        bool isAimbotKeyword =
                            (valueName.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                             valueName.Contains("triggerbot", StringComparison.OrdinalIgnoreCase) ||
                             valueName.Contains("aim_bot", StringComparison.OrdinalIgnoreCase));

                        if (isAimbotTool || isAimbotKeyword)
                        {
                            var displayName = key.GetValue(valueName) as string ?? string.Empty;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"AI-Aimbot MUICache-Spur: {Path.GetFileName(valueName)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{muiPath}",
                                FileName = Path.GetFileName(valueName),
                                Reason = $"MUICache-Eintrag deutet auf ausgefuehrtes AI-Aimbot-Tool hin: '{valueName}'. " +
                                         "MUICache protokolliert ausgefuehrte Anwendungen auch nach Loeschung.",
                                Detail = $"Name: {displayName} | Pfad: {valueName}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckAimbotPrefetchEntries(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var prefetchDir = Path.Combine(
                Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
                "Prefetch");

            if (!Directory.Exists(prefetchDir)) return;

            string[] prefetchFiles;
            try { prefetchFiles = Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { return; }
            catch (Exception) { return; }

            foreach (var pfFile in prefetchFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(pfFile).ToUpperInvariant();

                bool isAimbotPrefetch = AimbotPrefetchNames.Any(n =>
                    fn.StartsWith(n, StringComparison.OrdinalIgnoreCase));

                bool isPythonCheatDir = fn.StartsWith("PYTHON.EXE", StringComparison.OrdinalIgnoreCase) ||
                                        fn.StartsWith("PYTHONW.EXE", StringComparison.OrdinalIgnoreCase);

                if (isAimbotPrefetch)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AI-Aimbot Prefetch-Eintrag: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = pfFile,
                        FileName = fn,
                        Reason = $"Windows-Prefetch-Datei '{fn}' belegt, dass ein AI-Aimbot-Executable " +
                                 "auf diesem System gestartet wurde. Prefetch-Eintraege bleiben erhalten, " +
                                 "auch nachdem die Originaldatei geloescht wurde.",
                        Detail = $"Prefetch: {pfFile}"
                    });
                }

                if (isPythonCheatDir)
                {
                    var fnOrig = Path.GetFileName(pfFile);
                    bool looksLikeAimbotContext = fnOrig.Contains("AIMBOT", StringComparison.OrdinalIgnoreCase) ||
                                                  fnOrig.Contains("TRIGGERBOT", StringComparison.OrdinalIgnoreCase) ||
                                                  fnOrig.Contains("AIM_BOT", StringComparison.OrdinalIgnoreCase);

                    if (looksLikeAimbotContext)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Python Prefetch im Aimbot-Kontext: {fnOrig}",
                            Risk = RiskLevel.High,
                            Location = pfFile,
                            FileName = fnOrig,
                            Reason = $"Python-Interpreter-Prefetch '{fnOrig}' deutet auf Ausfuehrung " +
                                     "eines Python-Aimbot-Skripts hin (Aimbot-Kontext im Dateinamen).",
                            Detail = $"Prefetch: {pfFile}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckMouseSmoothingArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                userProfile,
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] pyFiles;
                try { pyFiles = Directory.GetFiles(dir, "*.py", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var file in pyFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    var fnLower = fn.ToLowerInvariant();

                    bool isAimbotRelated =
                        AimbotScriptFileNames.Any(n => fn.Equals(n, StringComparison.OrdinalIgnoreCase)) ||
                        fnLower.Contains("aim") || fnLower.Contains("smooth") ||
                        fnLower.Contains("mouse") || fnLower.Contains("trigger") ||
                        fnLower.Contains("humanize") || fnLower.Contains("move");

                    if (!isAimbotRelated) continue;

                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (Exception) { continue; }

                    var smoothingHits = MouseSmoothingLibraries
                        .Where(lib => content.Contains(lib, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    bool hasInterception = content.Contains("interception", StringComparison.OrdinalIgnoreCase);
                    bool hasSmoothing = content.Contains("smooth", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("bezier", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("lerp", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("humanize", StringComparison.OrdinalIgnoreCase);

                    if (smoothingHits.Count >= 2 && hasSmoothing)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Maus-Smoothing AI-Aimbot-Artefakt: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Python-Skript '{fn}' verwendet Maus-Smoothing-Bibliotheken ({string.Join(", ", smoothingHits.Take(4))}) " +
                                     "kombiniert mit Smoothing-Algorithmen. AI-Aimbots nutzen Maus-Smoothing, " +
                                     "um menschliche Mausbewegung zu simulieren und Anti-Cheat-Systeme zu umgehen.",
                            Detail = $"Bibliotheken: {string.Join(", ", smoothingHits)} | Pfad: {file}"
                        });
                    }

                    if (hasInterception && (smoothingHits.Count >= 1 || hasSmoothing))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Interception-Library fuer Kernel-Mauseingabe: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Python-Skript '{fn}' verwendet die Interception-Bibliothek (Kernel-Treiber-basierte Mauseingabe). " +
                                     "interception-python umgeht User-Mode-Eingabefilter und wird von fortgeschrittenen " +
                                     "AI-Aimbots fuer nicht-erkennbare Mausbewegungen eingesetzt.",
                            Detail = $"Pfad: {file}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckAimbotLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var knownLogNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "detection_log.txt", "aim_log.txt", "fps_log.txt",
                "aimbot_log.txt", "trigger_log.txt", "cheat_log.txt",
                "detection.log", "aimbot.log", "aim.log", "triggerbot.log",
                "target_log.txt", "enemy_log.txt", "kills_log.txt",
            };

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                userProfile,
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] logFiles;
                try
                {
                    var txtFiles = Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly);
                    var logExt = Directory.GetFiles(dir, "*.log", SearchOption.TopDirectoryOnly);
                    logFiles = txtFiles.Concat(logExt).ToArray();
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(logFile);

                    bool isKnownLog = knownLogNames.Contains(fn);
                    var fnLower = fn.ToLowerInvariant();
                    bool hasLogKeyword =
                        fnLower.Contains("detection") || fnLower.Contains("aimbot") ||
                        fnLower.Contains("aim_log") || fnLower.Contains("trigger_log") ||
                        fnLower.Contains("target") || fnLower.Contains("enemy");

                    if (!isKnownLog && !hasLogKeyword) continue;

                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (Exception) { continue; }

                    var logHits = AimbotLogKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (logHits.Count >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot Log-Datei: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = logFile,
                            FileName = fn,
                            Reason = $"Log-Datei '{fn}' enthaelt {logHits.Count} AI-Aimbot-Erkennungsschluesselbegriffe " +
                                     $"wie '{logHits[0]}', '{(logHits.Count > 1 ? logHits[1] : "")}'. " +
                                     "Solche Logs werden von Aimbot-Skripten generiert, die Erkennungszeitpunkte, " +
                                     "Konfidenzwerte und Schussereignisse protokollieren.",
                            Detail = $"Schluessel: {string.Join(", ", logHits.Take(8))} | Groesse: {GetFileSizeKb(logFile)} KB"
                        });
                    }
                    else if (logHits.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige Log-Datei (Aimbot-Kontext): {fn}",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = fn,
                            Reason = $"Log-Datei '{fn}' enthaelt {logHits.Count} Aimbot-relevante Begriffe.",
                            Detail = $"Schluessel: {string.Join(", ", logHits)}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckAimbotBrowserHistory(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

            var historyPaths = new List<string>();

            var chromiumProfiles = new[]
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data"),
                Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data"),
                Path.Combine(localAppData, "Chromium", "User Data"),
                Path.Combine(localAppData, "Opera Software", "Opera Stable"),
                Path.Combine(localAppData, "Vivaldi", "User Data"),
            };

            foreach (var profileBase in chromiumProfiles)
            {
                if (!Directory.Exists(profileBase)) continue;
                try
                {
                    var defaultHistory = Path.Combine(profileBase, "Default", "History");
                    if (File.Exists(defaultHistory)) historyPaths.Add(defaultHistory);

                    foreach (var profileDir in Directory.GetDirectories(profileBase, "Profile *"))
                    {
                        var h = Path.Combine(profileDir, "History");
                        if (File.Exists(h)) historyPaths.Add(h);
                    }
                }
                catch { }
            }

            var firefoxBase = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(firefoxBase))
            {
                try
                {
                    foreach (var profileDir in Directory.GetDirectories(firefoxBase))
                    {
                        var places = Path.Combine(profileDir, "places.sqlite");
                        if (File.Exists(places)) historyPaths.Add(places);
                    }
                }
                catch { }
            }

            foreach (var histFile in historyPaths)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(histFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, detectEncodingFromByteOrderMarks: false,
                        encoding: System.Text.Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (Exception) { continue; }

                var searchHits = BrowserAimbotSearchTerms
                    .Where(term => content.Contains(term, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (searchHits.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Browser-Verlauf: AI-Aimbot-Suchen ({Path.GetFileName(Path.GetDirectoryName(histFile) ?? "")})",
                        Risk = RiskLevel.High,
                        Location = histFile,
                        FileName = Path.GetFileName(histFile),
                        Reason = $"Browser-Verlauf enthaelt {searchHits.Count} AI-Aimbot-bezogene Suchanfragen " +
                                 $"wie '{searchHits[0]}'. Deutet auf aktive Suche nach AI-Aimbot-Tools hin.",
                        Detail = $"Suchanfragen: {string.Join(", ", searchHits.Take(6))}"
                    });
                }
                else if (searchHits.Count >= 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Browser-Verlauf: AI-Aimbot-Suche",
                        Risk = RiskLevel.Medium,
                        Location = histFile,
                        FileName = Path.GetFileName(histFile),
                        Reason = $"Browser-Verlauf enthaelt AI-Aimbot-Suchanfrage: '{searchHits[0]}'.",
                        Detail = $"Pfad: {histFile}"
                    });
                }
            }
        }, ct);

    private Task CheckDiscordTelegramArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var discordCachePaths = new[]
            {
                Path.Combine(appData, "discord", "Cache"),
                Path.Combine(appData, "discordptb", "Cache"),
                Path.Combine(appData, "discordcanary", "Cache"),
                Path.Combine(localAppData, "Discord", "Cache"),
            };

            foreach (var cacheDir in discordCachePaths)
            {
                if (!Directory.Exists(cacheDir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] cacheFiles;
                try { cacheFiles = Directory.GetFiles(cacheDir, "f_*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                int discordAimbotHits = 0;
                var hitTerms = new List<string>();

                foreach (var cacheFile in cacheFiles.Take(200))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, detectEncodingFromByteOrderMarks: false,
                            encoding: System.Text.Encoding.Latin1);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (Exception) { continue; }

                    bool hasPython = content.Contains("python", StringComparison.OrdinalIgnoreCase);
                    var foundTerms = DiscordAimbotKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (foundTerms.Count >= 1 && (hasPython || foundTerms.Count >= 2))
                    {
                        discordAimbotHits++;
                        foreach (var t in foundTerms)
                        {
                            if (!hitTerms.Contains(t, StringComparer.OrdinalIgnoreCase))
                                hitTerms.Add(t);
                        }
                    }
                }

                if (discordAimbotHits >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Discord-Cache: AI-Aimbot-Kommunikation",
                        Risk = RiskLevel.High,
                        Location = cacheDir,
                        FileName = Path.GetFileName(cacheDir),
                        Reason = $"Discord-Cache-Verzeichnis enthaelt {discordAimbotHits} Dateien mit AI-Aimbot-bezogenen " +
                                 $"Schluesselbegriffen ({string.Join(", ", hitTerms.Take(6))}). " +
                                 "Deutet auf Kommunikation in AI-Aimbot-Servern oder Kauf-Gespraeche hin.",
                        Detail = $"Cache: {cacheDir} | Treffer-Dateien: {discordAimbotHits}"
                    });
                }
            }

            var telegramPaths = new[]
            {
                Path.Combine(appData, "Telegram Desktop", "tdata"),
                Path.Combine(localAppData, "Telegram Desktop", "tdata"),
            };

            foreach (var tdataPath in telegramPaths)
            {
                if (!Directory.Exists(tdataPath)) continue;
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                long tdataSize = 0;
                try
                {
                    tdataSize = Directory.GetFiles(tdataPath, "*", SearchOption.AllDirectories)
                        .Sum(f => { try { return new FileInfo(f).Length; } catch { return 0L; } });
                }
                catch { }

                if (tdataSize > 1024 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Telegram tdata vorhanden (AI-Aimbot-Kontext)",
                        Risk = RiskLevel.Low,
                        Location = tdataPath,
                        FileName = "tdata",
                        Reason = "Telegram-Sitzungsdaten gefunden. Telegram-Kanaele werden haeufig fuer " +
                                 "den Vertrieb von AI-Aimbot-Software und Kaufabwicklung genutzt.",
                        Detail = $"tdata-Groesse: {tdataSize / 1024 / 1024} MB | Pfad: {tdataPath}"
                    });
                }
            }
        }, ct);

    private Task CheckAimbotDownloadArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var downloadsDir = Path.Combine(userProfile, "Downloads");
            var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

            var searchDirs = new[] { downloadsDir, desktopDir };
            var archiveExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { ".zip", ".rar", ".7z", ".tar", ".gz", ".tar.gz" };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    var fnLower = fn.ToLowerInvariant();
                    var ext = Path.GetExtension(file);

                    bool isArchive = archiveExtensions.Contains(ext);
                    if (!isArchive) continue;

                    bool isAimbotArchive = AimbotDownloadNames.Any(n =>
                        fnLower.Contains(n, StringComparison.OrdinalIgnoreCase));

                    if (!isAimbotArchive)
                    {
                        isAimbotArchive =
                            (fnLower.Contains("aimbot") || fnLower.Contains("triggerbot") ||
                             fnLower.Contains("aim_bot") || fnLower.Contains("aim bot")) &&
                            (fnLower.Contains("ai") || fnLower.Contains("yolo") ||
                             fnLower.Contains("python") || fnLower.Contains("neural") ||
                             fnLower.Contains("detect") || fnLower.Contains("object"));
                    }

                    if (isAimbotArchive)
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot Download-Archiv: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Archivdatei '{fn}' entspricht bekannten AI-Aimbot-Download-Mustern. " +
                                     "AI-Aimbots werden haeufig als ZIP/RAR-Archive mit YOLO-Modellen, " +
                                     "Python-Skripten und Anforderungsdateien verteilt.",
                            Detail = $"Groesse: {GetFileSizeKb(file)} KB | Pfad: {file}"
                        });
                    }
                }

                string[] dirs;
                try { dirs = Directory.GetDirectories(dir, "*", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (var subDir in dirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var subDirName = Path.GetFileName(subDir).ToLowerInvariant();

                    bool isAimbotDir = AimbotDownloadNames.Any(n =>
                        subDirName.Contains(n, StringComparison.OrdinalIgnoreCase));

                    if (!isAimbotDir)
                    {
                        isAimbotDir =
                            (subDirName.Contains("aimbot") || subDirName.Contains("triggerbot")) &&
                            (subDirName.Contains("yolo") || subDirName.Contains("python") ||
                             subDirName.Contains("ai") || subDirName.Contains("detect"));
                    }

                    if (isAimbotDir)
                    {
                        bool hasGitDir = Directory.Exists(Path.Combine(subDir, ".git"));
                        bool hasReadme = File.Exists(Path.Combine(subDir, "README.md")) ||
                                         File.Exists(Path.Combine(subDir, "readme.md")) ||
                                         File.Exists(Path.Combine(subDir, "README.txt"));
                        bool hasPyFiles = false;
                        try { hasPyFiles = Directory.GetFiles(subDir, "*.py").Length > 0; }
                        catch { }

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot GitHub-Klon: {Path.GetFileName(subDir)}",
                            Risk = RiskLevel.Critical,
                            Location = subDir,
                            FileName = Path.GetFileName(subDir),
                            Reason = $"Verzeichnis '{Path.GetFileName(subDir)}' entspricht einem AI-Aimbot-Repository-Klon. " +
                                     (hasGitDir ? "Enthaelt .git-Verzeichnis (GitHub-Klon). " : "") +
                                     (hasPyFiles ? "Enthaelt Python-Skripte." : ""),
                            Detail = $"git: {hasGitDir} | README: {hasReadme} | .py: {hasPyFiles} | Pfad: {subDir}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckAimbotInstallerScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Documents"),
                userProfile,
            };

            var scriptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { ".bat", ".cmd", ".ps1", ".psm1", ".ahk" };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (Exception) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!scriptExtensions.Contains(ext)) continue;

                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (Exception) { continue; }

                    var installerHits = AimbotInstallerKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (installerHits.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AI-Aimbot Installations-/Startskript: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Skriptdatei '{fn}' enthaelt {installerHits.Count} AI-Aimbot-Installations-/Start-Anweisungen " +
                                     $"wie '{installerHits[0]}'. " +
                                     "Solche Skripte installieren AI-Aimbot-Bibliotheken via pip und starten anschliessend " +
                                     "das Aimbot-Skript.",
                            Detail = $"Anweisungen: {string.Join(", ", installerHits.Take(8))}"
                        });
                    }
                    else if (installerHits.Count >= 1)
                    {
                        var fnLower = fn.ToLowerInvariant();
                        bool hasAimbotName =
                            fnLower.Contains("aimbot") || fnLower.Contains("install") ||
                            fnLower.Contains("setup") || fnLower.Contains("start") ||
                            fnLower.Contains("run") || fnLower.Contains("launch");

                        if (hasAimbotName)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Verdaechtiges Skript mit Aimbot-Anweisung: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Skript '{fn}' enthaelt AI-Aimbot-Anweisung: '{installerHits[0]}'.",
                                Detail = $"Pfad: {file}"
                            });
                        }
                    }

                    if (ext.Equals(".ahk", StringComparison.OrdinalIgnoreCase))
                    {
                        bool hasPythonLaunch = content.Contains("python", StringComparison.OrdinalIgnoreCase) &&
                                              AimbotScriptFileNames.Any(s =>
                                                  content.Contains(s, StringComparison.OrdinalIgnoreCase));

                        bool hasAhkAimbotKeyword =
                            content.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("triggerbot", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("aim_bot", StringComparison.OrdinalIgnoreCase);

                        if (hasPythonLaunch || (hasAhkAimbotKeyword && installerHits.Count >= 1))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"AHK-Autostart fuer Python-Aimbot: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fn,
                                Reason = $"AutoHotkey-Skript '{fn}' startet Python-Aimbot-Skripte. " +
                                         "AHK wird verwendet, um Python-Aimbots per Hotkey oder beim Systemstart " +
                                         "automatisch zu starten.",
                                Detail = $"Pfad: {file}"
                            });
                        }
                    }
                }
            }
        }, ct);

    private static long GetFileSizeKb(string path)
    {
        try { return new FileInfo(path).Length / 1024; }
        catch { return 0; }
    }

    private static string Rot13Decode(string s)
    {
        var a = s.ToCharArray();
        for (int i = 0; i < a.Length; i++)
        {
            char c = a[i];
            if (c is >= 'A' and <= 'Z') a[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c is >= 'a' and <= 'z') a[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(a);
    }
}
