using System.IO;
using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ScreenCaptureCheatScanModule : IScanModule
{
    public string Name => "Screen-Capture-Cheat";
    public double Weight => 0.55;
    public int ParallelGroup => 4;

    private static readonly HashSet<string> KnownAiAimbotExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "screenaim.exe", "screenaimbot.exe", "pixel_aimbot.exe", "coloraimbot.exe",
        "color_aimbot.exe", "colorbot.exe", "color_trigger.exe", "colortrigger.exe",
        "pixeltrigger.exe", "pixel_triggerbot.exe", "ai_aimbot.exe", "aimbot_ai.exe",
        "yolo_aimbot.exe", "neural_aimbot.exe", "tensoraimbot.exe", "rtss_aimbot.exe",
        "dxcam_aimbot.exe", "bettercam_aimbot.exe", "mss_aimbot.exe",
        "wincap_aimbot.exe", "obs_aimbot.exe",
    };

    private static readonly HashSet<string> KnownAiAimbotDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "screencap_hook.dll", "dxgi_capture.dll", "desktop_duplication.dll",
    };

    private static readonly HashSet<string> KnownDxCapProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "dxcam.exe", "bettercam.exe", "screencap.exe", "desktopdup.exe",
    };

    private static readonly HashSet<string> SuspiciousDxCaptureDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "dxgi_hook.dll", "desktop_dup.dll", "screen_capture_hook.dll",
    };

    private static readonly string[] ScreenCaptureLibraries =
    {
        "bettercam", "dxcam", "mss", "ImageGrab", "d3dshot", "desktop_duplication",
    };

    private static readonly string[] AiInferenceLibraries =
    {
        "ultralytics", "onnxruntime", "tensorflow", "torch", "cv2", "yolo", "detect", "predict",
    };

    private static readonly string[] MouseControlLibraries =
    {
        "win32api.mouse_event", "pynput.mouse", "pyautogui.moveTo",
        "mouse.move", "ctypes", "mouse_event",
    };

    private static readonly string[] AimbotDirKeywords =
    {
        "aimbot", "aim", "trigger", "cheat", "hack", "detect", "cs2", "valorant", "fivem", "gta",
    };

    private static readonly string[] TriggerBotConfigFileNames =
    {
        "triggerbot.cfg", "trigger_config.json", "color_config.json",
        "pixel_config.json", "aim_color.json",
    };

    private static readonly string[] TriggerBotConfigKeywords =
    {
        "triggerColor", "targetColor", "fovRange", "reaction_time",
        "delay_ms", "trigger_delay", "activation_key", "hotkey",
    };

    private static readonly string[] PipeSitePackageNames =
    {
        "dxcam", "bettercam", "mss", "d3dshot",
    };

    private static readonly string[] AiInferenceSitePackageNames =
    {
        "onnxruntime", "ultralytics", "torch",
    };

    private static readonly string[] ColorTriggerKeywords =
    {
        "GetPixel", "pixel_color",
    };

    private static readonly string[] ColorTriggerMouseKeywords =
    {
        "mouse_event", "moveTo",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanKnownAiAimbotFiles(ctx, ct);
            ScanPythonAiAimbotScripts(ctx, ct);
            ScanOnnxModelFiles(ctx, ct);
            ScanDxCamBetterCamArtifacts(ctx, ct);
            ScanTriggerBotConfigs(ctx, ct);
            ScanDesktopDuplicationAbuse(ctx, ct);
        }, ct);
    }

    private static void ScanKnownAiAimbotFiles(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var baseDir in searchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    if (!KnownAiAimbotExeNames.Contains(fname)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "Screen-Capture-Cheat",
                        Title = $"AI screen-capture aimbot EXE found: {fname}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fname,
                        Reason = $"Known AI screen-capture aimbot executable '{fname}' found on disk. " +
                                 "This tool captures the screen, runs object detection, and moves the mouse to aim at enemies.",
                        Detail = $"Path={file}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    if (!KnownAiAimbotDllNames.Contains(fname)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "Screen-Capture-Cheat",
                        Title = $"AI aimbot screen-capture DLL found: {fname}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fname,
                        Reason = $"Known screen-capture cheat DLL '{fname}' found on disk. " +
                                 "This DLL is used to hook screen capture or DirectX for AI-based aimbot tools.",
                        Detail = $"Path={file}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void ScanPythonAiAimbotScripts(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var baseDir in searchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            string[] pyFiles;
            try
            {
                pyFiles = Directory.GetFiles(baseDir, "*.py", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var pyFile in pyFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(pyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();
                }
                catch (IOException) { continue; }

                AnalyzePythonAimbotScript(ctx, pyFile, content, ct);
            }
        }
    }

    private static void AnalyzePythonAimbotScript(ScanContext ctx, string pyFile, string content, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var lower = content.ToLowerInvariant();
        var fname = Path.GetFileName(pyFile);

        var groupAMatches = new List<string>();
        var groupBMatches = new List<string>();
        var groupCMatches = new List<string>();

        foreach (var lib in ScreenCaptureLibraries)
        {
            if (lower.Contains(lib.ToLowerInvariant()))
                groupAMatches.Add(lib);
        }

        foreach (var lib in AiInferenceLibraries)
        {
            if (lower.Contains(lib.ToLowerInvariant()))
                groupBMatches.Add(lib);
        }

        foreach (var lib in MouseControlLibraries)
        {
            if (lower.Contains(lib.ToLowerInvariant()))
                groupCMatches.Add(lib);
        }

        var groupsMatched = (groupAMatches.Count > 0 ? 1 : 0)
                          + (groupBMatches.Count > 0 ? 1 : 0)
                          + (groupCMatches.Count > 0 ? 1 : 0);

        if (groupsMatched >= 3)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Screen-Capture-Cheat",
                Title = $"Python AI aimbot script confirmed: {fname}",
                Risk = RiskLevel.Critical,
                Location = pyFile,
                FileName = fname,
                Reason = $"Python script '{fname}' contains all three indicator groups for an AI screen-capture aimbot: " +
                         $"screen-capture ({string.Join(", ", groupAMatches)}), " +
                         $"AI inference ({string.Join(", ", groupBMatches)}), " +
                         $"mouse control ({string.Join(", ", groupCMatches)}). " +
                         "This combination is the signature of automated AI-based game cheating.",
                Detail = $"File={pyFile} GroupA={string.Join("|", groupAMatches)} " +
                         $"GroupB={string.Join("|", groupBMatches)} GroupC={string.Join("|", groupCMatches)}",
            });
            return;
        }

        if (groupsMatched >= 2)
        {
            var allMatches = groupAMatches.Concat(groupBMatches).Concat(groupCMatches).ToList();
            ctx.AddFinding(new Finding
            {
                Module = "Screen-Capture-Cheat",
                Title = $"Python AI aimbot script (2 of 3 groups): {fname}",
                Risk = RiskLevel.High,
                Location = pyFile,
                FileName = fname,
                Reason = $"Python script '{fname}' contains {groupsMatched} of 3 indicator groups for an AI aimbot. " +
                         $"Matched libraries: {string.Join(", ", allMatches)}. " +
                         "Missing the third group but the combination is still suspicious.",
                Detail = $"File={pyFile} Groups={groupsMatched} Matches={string.Join("|", allMatches)}",
            });
            return;
        }

        var hasColorTriggerCapture = ColorTriggerKeywords.Any(k => lower.Contains(k.ToLowerInvariant()));
        var hasColorTriggerMouse = ColorTriggerMouseKeywords.Any(k => lower.Contains(k.ToLowerInvariant()));

        if (hasColorTriggerCapture && hasColorTriggerMouse)
        {
            var captureKw = ColorTriggerKeywords.FirstOrDefault(k => lower.Contains(k.ToLowerInvariant())) ?? "";
            var mouseKw = ColorTriggerMouseKeywords.FirstOrDefault(k => lower.Contains(k.ToLowerInvariant())) ?? "";

            ctx.AddFinding(new Finding
            {
                Module = "Screen-Capture-Cheat",
                Title = $"Python color triggerbot script: {fname}",
                Risk = RiskLevel.High,
                Location = pyFile,
                FileName = fname,
                Reason = $"Python script '{fname}' contains pixel/color reading ({captureKw}) combined with " +
                         $"mouse movement automation ({mouseKw}). " +
                         "This pattern is characteristic of a color-based triggerbot that shoots when a target color appears on screen.",
                Detail = $"File={pyFile} ColorRead={captureKw} MouseControl={mouseKw}",
            });
        }
    }

    private static void ScanOnnxModelFiles(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var baseDir in searchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            string[] onnxFiles;
            try
            {
                onnxFiles = Directory.GetFiles(baseDir, "*.onnx", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var onnxFile in onnxFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var dir = Path.GetDirectoryName(onnxFile) ?? string.Empty;
                var dirLower = dir.ToLowerInvariant();
                var fname = Path.GetFileName(onnxFile);

                var isSuspiciousDir = AimbotDirKeywords.Any(k => dirLower.Contains(k));
                var isDownloadsOrDesktop =
                    dirLower.Equals(
                        Environment.GetFolderPath(Environment.SpecialFolder.Desktop).ToLowerInvariant(),
                        StringComparison.OrdinalIgnoreCase) ||
                    dirLower.Equals(
                        Path.Combine(
                            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                            "Downloads").ToLowerInvariant(),
                        StringComparison.OrdinalIgnoreCase);

                if (isSuspiciousDir)
                {
                    var matchedKeyword = AimbotDirKeywords.First(k => dirLower.Contains(k));
                    ctx.AddFinding(new Finding
                    {
                        Module = "Screen-Capture-Cheat",
                        Title = $"ONNX AI model in cheat-named directory: {fname}",
                        Risk = RiskLevel.Critical,
                        Location = onnxFile,
                        FileName = fname,
                        Reason = $"ONNX neural network model '{fname}' found in a directory containing cheat keyword '{matchedKeyword}'. " +
                                 "ONNX models in cheat-named directories are the inference models used by AI aimbot tools " +
                                 "to detect enemies on screen.",
                        Detail = $"File={onnxFile} Dir={dir} Keyword={matchedKeyword}",
                    });
                }
                else if (isDownloadsOrDesktop)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Screen-Capture-Cheat",
                        Title = $"ONNX AI model in Downloads/Desktop: {fname}",
                        Risk = RiskLevel.High,
                        Location = onnxFile,
                        FileName = fname,
                        Reason = $"ONNX neural network model '{fname}' found in Downloads or Desktop without legitimate context. " +
                                 "ONNX models in user download directories are frequently the detection models used by AI aimbots.",
                        Detail = $"File={onnxFile} Dir={dir}",
                    });
                }
            }
        }
    }

    private static void ScanDxCamBetterCamArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var knownCaptureDirs = new[]
        {
            Path.Combine(appData, "dxcam"),
            Path.Combine(appData, "bettercam"),
            Path.Combine(localAppData, "dxcam"),
        };

        foreach (var captureDir in knownCaptureDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(captureDir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Screen-Capture-Cheat",
                Title = $"Screen capture tool AppData directory: {Path.GetFileName(captureDir)}",
                Risk = RiskLevel.Medium,
                Location = captureDir,
                Reason = $"AppData directory for screen capture library '{Path.GetFileName(captureDir)}' found. " +
                         "DXcam and BetterCam are high-performance screen capture libraries primarily used by AI aimbot tools.",
                Detail = $"Dir={captureDir}",
            });
        }

        ScanPythonSitePackagesForAiAimbotCombination(ctx, ct);
    }

    private static void ScanPythonSitePackagesForAiAimbotCombination(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        string[] pythonVersionDirs;
        try
        {
            pythonVersionDirs = Directory.GetDirectories(appData, "Python3*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var pyVersionDir in pythonVersionDirs)
        {
            ct.ThrowIfCancellationRequested();
            var sitePackages = Path.Combine(pyVersionDir, "site-packages");
            if (!Directory.Exists(sitePackages)) continue;

            string[] installedPackageDirs;
            try
            {
                installedPackageDirs = Directory.GetDirectories(sitePackages);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            var installedNames = installedPackageDirs
                .Select(d => Path.GetFileName(d).ToLowerInvariant())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var capturePackages = PipeSitePackageNames
                .Where(p => installedNames.Contains(p.ToLowerInvariant()))
                .ToList();

            var aiPackages = AiInferenceSitePackageNames
                .Where(p => installedNames.Contains(p.ToLowerInvariant()))
                .ToList();

            if (capturePackages.Count == 0 || aiPackages.Count == 0) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Screen-Capture-Cheat",
                Title = "AI aimbot Python package combination installed",
                Risk = RiskLevel.High,
                Location = sitePackages,
                Reason = $"Python site-packages at '{sitePackages}' contains both screen-capture packages " +
                         $"({string.Join(", ", capturePackages)}) and AI inference packages ({string.Join(", ", aiPackages)}). " +
                         "This combination of packages in the same Python environment is the standard setup for AI screen-capture aimbots.",
                Detail = $"SitePackages={sitePackages} Capture={string.Join("|", capturePackages)} AI={string.Join("|", aiPackages)}",
            });
        }
    }

    private static void ScanTriggerBotConfigs(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var baseDir in searchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            foreach (var triggerFileName in TriggerBotConfigFileNames)
            {
                var fullPath = Path.Combine(baseDir, triggerFileName);
                if (!File.Exists(fullPath)) continue;

                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();
                }
                catch (IOException) { continue; }

                var lower = content.ToLowerInvariant();
                var matchedKeywords = TriggerBotConfigKeywords
                    .Where(k => lower.Contains(k.ToLowerInvariant()))
                    .ToList();

                if (matchedKeywords.Count == 0) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Screen-Capture-Cheat",
                    Title = $"Triggerbot configuration file: {triggerFileName}",
                    Risk = RiskLevel.Medium,
                    Location = fullPath,
                    FileName = triggerFileName,
                    Reason = $"Triggerbot configuration file '{triggerFileName}' found containing keywords: " +
                             $"{string.Join(", ", matchedKeywords)}. " +
                             "This file configures a triggerbot that automatically fires when the target color appears on screen.",
                    Detail = $"File={fullPath} Keywords={string.Join("|", matchedKeywords)}",
                });
            }

            ScanDirectoryForTriggerBotConfigs(ctx, baseDir, ct);
        }
    }

    private static void ScanDirectoryForTriggerBotConfigs(ScanContext ctx, string baseDir, CancellationToken ct)
    {
        string[] allFiles;
        try
        {
            allFiles = Directory.GetFiles(baseDir, "*.json", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(baseDir, "*.cfg", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(baseDir, "*.ini", SearchOption.TopDirectoryOnly))
                .ToArray();
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in allFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fname = Path.GetFileName(file).ToLowerInvariant();

            if (!fname.Contains("trigger") && !fname.Contains("color") && !fname.Contains("pixel")) continue;

            string content;
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = sr.ReadToEnd();
            }
            catch (IOException) { continue; }

            var lower = content.ToLowerInvariant();
            var matchedKeywords = TriggerBotConfigKeywords
                .Where(k => lower.Contains(k.ToLowerInvariant()))
                .ToList();

            if (matchedKeywords.Count < 2) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Screen-Capture-Cheat",
                Title = $"Triggerbot config by filename+content: {Path.GetFileName(file)}",
                Risk = RiskLevel.Medium,
                Location = file,
                FileName = Path.GetFileName(file),
                Reason = $"File '{Path.GetFileName(file)}' has a trigger/color/pixel-related name and contains " +
                         $"triggerbot configuration keywords: {string.Join(", ", matchedKeywords)}. " +
                         "This is consistent with a pixel-scanning triggerbot configuration.",
                Detail = $"File={file} Keywords={string.Join("|", matchedKeywords)}",
            });
        }
    }

    private static void ScanDesktopDuplicationAbuse(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        ScanForSuspiciousDxDlls(ctx, ct);
        ScanForDxCaptureProcesses(ctx, ct);
    }

    private static void ScanForSuspiciousDxDlls(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var winSystem32 = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
        var winSysWow64 = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

        var nonStandardLocations = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
        };

        foreach (var searchDir in nonStandardLocations)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(searchDir)) continue;

            string[] dllFiles;
            try
            {
                dllFiles = Directory.GetFiles(searchDir, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dllFile in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fname = Path.GetFileName(dllFile);
                if (!SuspiciousDxCaptureDlls.Contains(fname)) continue;

                var isNonStandard = !dllFile.StartsWith(winSystem32, StringComparison.OrdinalIgnoreCase) &&
                                    !dllFile.StartsWith(winSysWow64, StringComparison.OrdinalIgnoreCase);
                if (!isNonStandard) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Screen-Capture-Cheat",
                    Title = $"Desktop Duplication API hook DLL in non-standard location: {fname}",
                    Risk = RiskLevel.Medium,
                    Location = dllFile,
                    FileName = fname,
                    Reason = $"Screen-capture hook DLL '{fname}' found in a non-standard location outside System32. " +
                             "This DLL type is used to hook the DirectX Desktop Duplication API for screen-capture-based aimbots.",
                    Detail = $"File={dllFile}",
                });
            }
        }
    }

    private static void ScanForDxCaptureProcesses(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var snapshot = ctx.GetProcessSnapshot();

        foreach (var proc in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            var procExe = proc.ProcessName + ".exe";
            if (!KnownDxCapProcessNames.Contains(procExe) &&
                !KnownAiAimbotExeNames.Contains(procExe)) continue;

            string procPath;
            try { procPath = proc.MainModule?.FileName ?? string.Empty; }
            catch { procPath = string.Empty; }

            var isAiAimbot = KnownAiAimbotExeNames.Contains(procExe);
            ctx.AddFinding(new Finding
            {
                Module = "Screen-Capture-Cheat",
                Title = $"Screen-capture cheat process running: {proc.ProcessName}",
                Risk = isAiAimbot ? RiskLevel.High : RiskLevel.Medium,
                Location = string.IsNullOrEmpty(procPath) ? $"PID {proc.Id}" : procPath,
                FileName = procExe,
                Reason = isAiAimbot
                    ? $"Known AI aimbot process '{proc.ProcessName}' (PID {proc.Id}) is actively running. " +
                      "This tool uses screen capture to aim at enemies using computer vision."
                    : $"Known Desktop Duplication screen-capture process '{proc.ProcessName}' (PID {proc.Id}) is running. " +
                      "This process captures screen frames via DXGI Desktop Duplication and may be part of an AI aimbot setup.",
                Detail = $"PID={proc.Id} Name={proc.ProcessName} Path={procPath}",
            });
        }
    }
}
