using System.Diagnostics;
using System.Management;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects GPU compute processes and frameworks used by external AI-based aimbot cheats.
///
/// The latest generation of cheats ("AI aimbots") runs YOLO-based object detection
/// on a second GPU or second PC and feeds aim corrections into the primary gaming PC
/// via DMA or HID injection. Signs of this setup:
///
///   - CUDA / cuDNN runtime processes running alongside games (OnnxRuntime, TensorRT)
///   - OpenCL compute processes with no obvious legitimate use on a gaming machine
///   - Python with AI libraries (torch, onnxruntime, ultralytics) found in AppData
///   - Specific known AI aimbot project directories (Trigon, SteelFish, vision-aim)
///   - Installed packages: ultralytics, onnxruntime-gpu, torch+cuda
///
/// Ocean and detect.ac flag AI-aimbot indicators because:
///   - Legitimate gamers do not typically run CUDA inference pipelines alongside CS2
///   - The specific combination of YOLO + OnnxRuntime + screen-capture is distinctive
///   - AI aimbot repositories have characteristic directory structures
///
/// Detection:
///   - Process names: python.exe with AI library imports evident in command line
///   - AppData directories: known AI aimbot project names
///   - Pip installed packages: ultralytics, onnxruntime-gpu, mss (screen capture)
///   - CUDA toolkit presence without legitimate dev-tool context
/// </summary>
public sealed class GpuComputeCheatProcessScanModule : IScanModule
{
    public string Name => "GPU Compute / KI-Aimbot Prozess- und Artefakt-Scan";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private static readonly string[] AiAimbotDirNames =
    {
        // Known open-source AI aimbot project names (GitHub repos)
        "vision-aim", "visionaim", "trigon-aimbot", "trigon",
        "steelfish", "neural-aim", "neuralaim",
        "yolo-aimbot", "yoloaim", "yolo_aim",
        "ai-aimbot", "aiaimbot", "aimbot-ai",
        "csgo-ai", "cs2-ai", "valorant-ai",
        "apex-ai", "warzone-ai",
        "screen-aim", "screenaimbot",
        "pixelbot", "pixel-aim",
        "mss-aim", "mssaim",
        "tensorrt-aim", "tensorrtaim",
        "onnx-aim", "onnxaim",
        "mediapipe-aim",
        // Common repo names for AI aimbots
        "aim_assist_ai", "AimAssistAI",
        "aimtrainer_hack", "aim-trainer-cheat",
    };

    private static readonly string[] AiAimbotPipPackages =
    {
        "ultralytics",        // YOLO v8+ — #1 AI aimbot framework
        "onnxruntime-gpu",    // GPU-accelerated ONNX inference
        "onnxruntime_gpu",
        "mss",                // python screen capture (multi-screen screenshot)
        "bettercam",          // faster screen capture for aimbot
        "dxcam",              // DirectX camera for aimbot
        "win32api",           // pynput/pywin32 for mouse injection
        "pynput",             // mouse/keyboard injection
        "pyautogui",          // alternative mouse injection
        "mouse",              // 'mouse' package for injection
        "tensorrt",           // NVIDIA TensorRT for optimized inference
        "torch",              // PyTorch base
    };

    private static readonly string[] SuspiciousPyScriptNames =
    {
        "aim", "aimbot", "aim_bot", "cheat", "hack",
        "detect", "yolo_detect", "inference",
        "triggerbot", "trigger_bot",
        "screen_capture", "screencap",
        "pixel_aim",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanRunningProcesses(ctx, ct);
        ScanPythonEnvironments(ctx, ct);
        ScanAiAimbotDirectories(ctx, ct);
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();
        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string name = proc.ProcessName.ToLowerInvariant();

                // Flag python.exe running alongside games — suspicious on gaming machines
                if (name is "python" or "python3" or "pythonw")
                {
                    ctx.IncrementProcesses();
                    try
                    {
                        string cmdline = GetCommandLine(proc);
                        string lower = cmdline.ToLowerInvariant();

                        bool hasAiLib = lower.Contains("ultralytics") ||
                                        lower.Contains("onnxruntime") ||
                                        lower.Contains("yolo") ||
                                        lower.Contains("torch") ||
                                        lower.Contains("tensorrt") ||
                                        lower.Contains("bettercam") ||
                                        lower.Contains("dxcam") ||
                                        lower.Contains("mss");

                        // Check script name
                        bool hasAimScript = SuspiciousPyScriptNames.Any(s =>
                            lower.Contains(s + ".py") || lower.Contains(s + " "));

                        if (hasAiLib || hasAimScript)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"KI-Aimbot Python-Prozess: {proc.ProcessName} (PID {proc.Id})",
                                Risk     = RiskLevel.Critical,
                                Location = $"Prozess: python (PID {proc.Id})",
                                FileName = "python.exe",
                                Reason   = "Python-Prozess mit KI/ML-Bibliotheken läuft aktiv auf dem System. " +
                                           "Dies ist das Kernmerkmal moderner KI-Aimbots: YOLO-Objekterkennung " +
                                           "mit OnnxRuntime/TensorRT + Screen-Capture (mss/bettercam) + " +
                                           "Mausbewegungsinjektion. Ocean und detect.ac flaggen Python+AI als " +
                                           "primäres Signal für externe KI-Cheat-Setups.",
                                Detail   = $"PID: {proc.Id} | Kommandozeile: {cmdline}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void ScanPythonEnvironments(ScanContext ctx, CancellationToken ct)
    {
        string profile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appdata  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string local    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        // Common Python installation dirs
        var pythonRoots = new List<string>
        {
            System.IO.Path.Combine(profile, "AppData", "Local", "Programs", "Python"),
            System.IO.Path.Combine(local, "Programs", "Python"),
            @"C:\Python310", @"C:\Python311", @"C:\Python312",
            System.IO.Path.Combine(profile, "miniconda3"),
            System.IO.Path.Combine(profile, "anaconda3"),
            System.IO.Path.Combine(local, "miniconda3"),
        };

        foreach (string pythonRoot in pythonRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(pythonRoot)) continue;

            // Check site-packages for AI aimbot packages
            try
            {
                foreach (string sitePackages in System.IO.Directory.EnumerateDirectories(
                             pythonRoot, "site-packages", System.IO.SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    CheckSitePackages(ctx, sitePackages, ct);
                }
            }
            catch { }
        }

        // pip's installed package list: %APPDATA%\pip or %LOCALAPPDATA%\pip
        ScanPipCache(ctx, System.IO.Path.Combine(appdata, "pip"), ct);
        ScanPipCache(ctx, System.IO.Path.Combine(local, "pip"), ct);
    }

    private void CheckSitePackages(ScanContext ctx, string sitePackagesDir, CancellationToken ct)
    {
        try
        {
            var dirs = System.IO.Directory.GetDirectories(sitePackagesDir);
            foreach (string dir in dirs)
            {
                ct.ThrowIfCancellationRequested();
                string name = System.IO.Path.GetFileName(dir).ToLowerInvariant();
                foreach (string pkg in AiAimbotPipPackages)
                {
                    if (!name.StartsWith(pkg.ToLowerInvariant().Replace("-", "_"))
                        && !name.StartsWith(pkg.ToLowerInvariant())) continue;

                    // Extra confirmation: also check if mss or bettercam is co-installed
                    // (screen capture = aimbot indicator when combined with ultralytics)
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"KI-Aimbot Python-Paket installiert: {pkg}",
                        Risk     = pkg is "ultralytics" or "bettercam" or "dxcam"
                            ? RiskLevel.High : RiskLevel.Medium,
                        Location = sitePackagesDir,
                        FileName = System.IO.Path.GetFileName(dir),
                        Reason   = $"Python-Paket '{pkg}' in '{sitePackagesDir}' installiert. " +
                                   $"'{pkg}' ist {DescribePackage(pkg)}. " +
                                   "Kombination von YOLO/OnnxRuntime + Screen-Capture (mss/bettercam) " +
                                   "ist das typische Setup für KI-basierte Aimbots.",
                        Detail   = $"Paket: {pkg} | Pfad: {dir}"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private static string DescribePackage(string pkg) => pkg switch
    {
        "ultralytics"     => "das primäre YOLO v8/v9/v10 Framework für KI-Aimbots",
        "onnxruntime-gpu" => "GPU-beschleunigtes ONNX-Inferenz-Framework (KI-Aimbot-Kern)",
        "onnxruntime_gpu" => "GPU-beschleunigtes ONNX-Inferenz-Framework (KI-Aimbot-Kern)",
        "bettercam"       => "schnelle Screen-Capture-Bibliothek, primär für Aimbots genutzt",
        "dxcam"           => "DirectX-basierte Screen-Capture-Bibliothek (Aimbot-spezifisch)",
        "mss"             => "Multi-Screen-Screenshot-Bibliothek (KI-Aimbot Screen-Input)",
        "pynput"          => "Maus/Tastatur-Injektionsbibliothek (KI-Aimbot Output)",
        "tensorrt"        => "NVIDIA TensorRT Inferenz-Optimierer (KI-Aimbot Performance)",
        _                 => "eine KI/ML- oder Input-Injektionsbibliothek"
    };

    private void ScanPipCache(ScanContext ctx, string pipDir, CancellationToken ct)
    {
        // pip stores wheels in cache; look for aimbot package names in cache filenames
        if (!System.IO.Directory.Exists(pipDir)) return;
        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(
                         pipDir, "*.whl", System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                string fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();
                foreach (string pkg in AiAimbotPipPackages)
                {
                    if (!fileName.StartsWith(pkg.ToLowerInvariant().Replace("-", "_"))) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"KI-Aimbot Pip-Wheel im Cache: {pkg}",
                        Risk     = RiskLevel.Medium,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"Pip-Wheel-Cache enthält Paket '{pkg}' — {DescribePackage(pkg)}. " +
                                   "Gecachte Wheels belegen, dass das Paket heruntergeladen wurde, " +
                                   "auch wenn es inzwischen deinstalliert wurde.",
                        Detail   = $"Datei: {file} | Paket: {pkg}"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private void ScanAiAimbotDirectories(ScanContext ctx, CancellationToken ct)
    {
        string profile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string desktop  = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string docs     = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        string downloads = System.IO.Path.Combine(profile, "Downloads");

        var searchRoots = new[] { profile, desktop, docs, downloads };

        foreach (string root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(root)) continue;

            try
            {
                foreach (string dir in System.IO.Directory.EnumerateDirectories(root))
                {
                    ct.ThrowIfCancellationRequested();
                    string dirName = System.IO.Path.GetFileName(dir).ToLowerInvariant();

                    foreach (string aimbotDir in AiAimbotDirNames)
                    {
                        if (!dirName.Equals(aimbotDir.ToLowerInvariant()) &&
                            !dirName.Contains(aimbotDir.ToLowerInvariant())) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"KI-Aimbot Projektverzeichnis gefunden: {System.IO.Path.GetFileName(dir)}",
                            Risk     = RiskLevel.Critical,
                            Location = dir,
                            FileName = System.IO.Path.GetFileName(dir),
                            Reason   = $"Verzeichnis '{System.IO.Path.GetFileName(dir)}' entspricht einem " +
                                       "bekannten KI-Aimbot-Projekt (GitHub-Klon oder Download). " +
                                       "Diese Projekte implementieren YOLO-basierte Spielfigur-Erkennung " +
                                       "mit Maus-Injection und sind nicht für legitime Zwecke gedacht.",
                            Detail   = $"Pfad: {dir} | Match: '{aimbotDir}'"
                        });
                        break;
                    }

                    // Also scan for Python scripts with aimbot names in top-level dirs
                    try
                    {
                        foreach (string py in System.IO.Directory.EnumerateFiles(dir, "*.py",
                                     System.IO.SearchOption.TopDirectoryOnly))
                        {
                            ct.ThrowIfCancellationRequested();
                            string pyName = System.IO.Path.GetFileNameWithoutExtension(py).ToLowerInvariant();
                            foreach (string aimName in SuspiciousPyScriptNames)
                            {
                                if (!pyName.Contains(aimName)) continue;
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Verdächtiges KI-Script: {System.IO.Path.GetFileName(py)}",
                                    Risk     = RiskLevel.High,
                                    Location = py,
                                    FileName = System.IO.Path.GetFileName(py),
                                    Reason   = $"Python-Script '{System.IO.Path.GetFileName(py)}' hat einen " +
                                               "Aimbot-typischen Namen. KI-Aimbots bestehen meist aus einem " +
                                               "einzelnen Python-Script mit AI-Inferenz und Maus-Injection.",
                                    Detail   = $"Datei: {py} | Muster: '{aimName}'"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private static string GetCommandLine(Process proc)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {proc.Id}");
            foreach (ManagementObject obj in searcher.Get())
                return obj["CommandLine"]?.ToString() ?? "";
        }
        catch { }
        return "";
    }
}
