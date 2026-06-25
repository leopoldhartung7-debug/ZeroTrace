using System.Diagnostics;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AntiScreenshotEvasionScanModule : IScanModule
{
    public string Name => "Anti-Screenshot & Screen Evasion Scan";
    public double Weight => 3.2;
    public int ParallelGroup => 4;

    private const string ModuleName = "AntiScreenshotEvasion";

    // ── Known anti-screenshot / DWM hook DLL names ───────────────────────────

    private static readonly HashSet<string> KnownEvasionDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "dwmhook.dll",
        "dwm_hook.dll",
        "dwmbypass.dll",
        "dwm_bypass.dll",
        "dwmpatch.dll",
        "dwm_patch.dll",
        "dwminject.dll",
        "dwmapi_hook.dll",
        "dwmapi_bypass.dll",
        "screenhide.dll",
        "screen_hide.dll",
        "screenhider.dll",
        "screenbypass.dll",
        "screen_bypass.dll",
        "capturebypass.dll",
        "capture_bypass.dll",
        "screencapturehide.dll",
        "antiscreenshot.dll",
        "anti_screenshot.dll",
        "antiscreen.dll",
        "screenshot_bypass.dll",
        "screenshot_hide.dll",
        "screenshothide.dll",
        "screenshotbypass.dll",
        "overlaystealth.dll",
        "overlay_stealth.dll",
        "stealthoverlay.dll",
        "stealth_overlay.dll",
        "hiddenoverlay.dll",
        "hidden_overlay.dll",
        "invisibleoverlay.dll",
        "invisible_overlay.dll",
        "renderstealth.dll",
        "render_stealth.dll",
        "dxgihook.dll",
        "dxgi_hook.dll",
        "dxgibypass.dll",
        "dxgi_bypass.dll",
        "presenthook.dll",
        "present_hook.dll",
        "d3d11hook.dll",
        "d3d12hook.dll",
        "d3d11_hook.dll",
        "d3d12_hook.dll",
        "dx11hook.dll",
        "dx12hook.dll",
        "dx11_screenhide.dll",
        "dx12_screenhide.dll",
        "shadowplayhide.dll",
        "nvfreestyle_bypass.dll",
        "nvcapture_bypass.dll",
        "obs_bypass.dll",
        "obs_hook_bypass.dll",
        "obs_game_capture_bypass.dll",
        "obscapture_bypass.dll",
        "obshide.dll",
        "gamecapture_bypass.dll",
        "game_capture_bypass.dll",
        "gdihook.dll",
        "gdi32hook.dll",
        "gdi_hook.dll",
        "printwndbypass.dll",
        "printwindow_bypass.dll",
        "bitbltbypass.dll",
        "bitblt_bypass.dll",
        "screensafe.dll",
        "screen_safe.dll",
        "eacbypass_screen.dll",
        "eac_screenshot_bypass.dll",
        "vac_screenshot_bypass.dll",
        "be_screenshot_bypass.dll",
        "faceit_bypass_screen.dll",
        "fivem_screenshot_bypass.dll",
        "ragemp_screenshot_bypass.dll",
        "altv_screenshot_bypass.dll",
        "kernelhide.dll",
        "kernel_hide.dll",
        "windowhider.dll",
        "window_hider.dll",
        "hidefromcapture.dll",
        "excludefromcapture.dll",
        "wda_bypass.dll",
        "displayaffinity_bypass.dll",
    };

    // ── Known anti-screenshot executable names ────────────────────────────────

    private static readonly HashSet<string> KnownEvasionExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "screen_bypass.exe",
        "screenbypass.exe",
        "screenhide.exe",
        "stealth_render.exe",
        "stealthrender.exe",
        "antiscreenshot.exe",
        "anti_screenshot.exe",
        "screensafe.exe",
        "overlaystealth.exe",
        "stealthoverlay.exe",
        "invisibleoverlay.exe",
        "hiddenoverlay.exe",
        "dxgibypass.exe",
        "capturebypass.exe",
        "screenshot_bypass.exe",
        "screenshothider.exe",
        "screenshot_hider.exe",
        "renderbypass.exe",
        "render_bypass.exe",
        "dwmbypass.exe",
        "dwm_bypass.exe",
        "gdihide.exe",
        "bitblt_bypass.exe",
        "obs_bypass.exe",
        "gamecapture_bypass.exe",
        "nvbypass.exe",
        "nv_bypass.exe",
        "windowhider.exe",
        "window_hider.exe",
        "kernelhide.exe",
        "fivem_scbypass.exe",
        "ragemp_scbypass.exe",
        "eac_bypass_screen.exe",
        "be_bypass_screen.exe",
    };

    // ── Modified DWM / system DLL names (placed in app directories) ───────────

    private static readonly HashSet<string> HijackedSystemDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "dwmapi.dll",
        "dxgi.dll",
        "d3d11.dll",
        "d3d12.dll",
        "d3d9.dll",
        "d3d10.dll",
        "d3d10_1.dll",
        "dcomp.dll",
        "user32.dll",
        "gdi32.dll",
        "gdi32full.dll",
        "win32u.dll",
        "ntdll.dll",
        "kernel32.dll",
        "shcore.dll",
    };

    // ── OBS bypass file indicators ────────────────────────────────────────────

    private static readonly string[] ObsBypassFileNames =
    {
        "obs-game-capture.dll",
        "obs-game-capture-bypass.dll",
        "obs_game_capture.dll",
        "obs_hook.dll",
        "obs-hook.dll",
        "get-graphics-offsets32.exe",
        "get-graphics-offsets64.exe",
        "inject-helper32.exe",
        "inject-helper64.exe",
        "graphics-hook32.dll",
        "graphics-hook64.dll",
    };

    // ── Content signatures: anti-screenshot code patterns ─────────────────────

    private static readonly string[] AntiScreenshotCodeSignatures =
    {
        "SetWindowDisplayAffinity",
        "WDA_EXCLUDEFROMCAPTURE",
        "WDA_MONITOR",
        "GetWindowDisplayAffinity",
        "DwmSetWindowAttribute",
        "DWMWA_CLOAK",
        "DWMWA_CLOAKED",
        "DwmEnableBlurBehindWindow",
        "DWM_BB_ENABLE",
        "IDXGISwapChain::Present",
        "IDXGIOutput::GetGammaControl",
        "IDXGISwapChain1::Present1",
        "IDXGISurface",
        "RenderTargetView",
        "screenshot_safe",
        "screenshot_bypass",
        "anti_screenshot",
        "AntiScreenshot",
        "hide_from_screenshot",
        "HideFromScreenshot",
        "exclude_from_capture",
        "ExcludeFromCapture",
        "capture_bypass",
        "bypass_screenshot",
        "BypassScreenshot",
        "BitBlt.*bypass",
        "PrintWindow.*bypass",
        "bypass.*PrintWindow",
        "bypass.*BitBlt",
        "GetDC.*bypass",
        "ReleaseDC.*bypass",
        "EnumWindows.*hide",
        "hide.*EnumWindows",
        "SetWindowsHookEx.*WH_CALLWNDPROC",
        "WM_PRINT",
        "WM_PRINTCLIENT",
        "NtUserSetWindowDisplayAffinity",
        "ZwUserSetWindowDisplayAffinity",
        "stealth.*overlay",
        "overlay.*stealth",
        "invisible.*overlay",
        "overlay.*invisible",
        "obs_game_capture.*bypass",
        "bypass.*obs",
        "obs.*bypass",
        "hook.*obs",
        "OBS_CAPTURE",
        "shadowplay.*bypass",
        "bypass.*shadowplay",
        "nvidia.*bypass",
        "bypass.*nvidia",
        "nvcontainer.*bypass",
        "GammaRamp.*bypass",
        "screenshot.*safe",
        "safe.*screenshot",
        "no.*screenshot",
        "block.*screenshot",
        "capture.*block",
        "WDA_EXCLUDEFROMCAPTURE",
        "fivem.*screenshot.*bypass",
        "ragemp.*screenshot",
        "altv.*screenshot",
        "eac.*screenshot.*bypass",
        "battleye.*screenshot.*bypass",
        "faceit.*screenshot.*bypass",
        "kernel.*hide.*window",
        "hide.*window.*kernel",
    };

    // ── Registry paths for screen capture blacklist / WDA settings ────────────

    private static readonly string[] ScreenCaptureRegistryPaths =
    {
        @"SOFTWARE\Microsoft\Windows\DWM",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
        @"SOFTWARE\NVIDIA Corporation\Global\ShadowPlay",
        @"SOFTWARE\NVIDIA Corporation\NvTray",
        @"SOFTWARE\NVIDIA Corporation\Global\Freestyle",
        @"SOFTWARE\OBS-Studio",
        @"SOFTWARE\obs-studio",
    };

    // ── Known screenshot capture process names ────────────────────────────────

    private static readonly HashSet<string> ScreenshotCaptureProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "obs64",
        "obs32",
        "obs",
        "streamlabs obs",
        "streamlabs",
        "xsplit",
        "nvcapture",
        "nvcontainer",
        "shadowplay",
        "fraps",
        "bandicam",
        "dxtory",
        "action",
        "screencapture",
        "snagit",
        "faststone capture",
        "lightshot",
        "gyazo",
        "greenshot",
        "sharex",
        "medal",
        "overwolf",
    };

    // ── File system search directories ────────────────────────────────────────

    private static readonly string[] EvasionSearchRoots;

    static AntiScreenshotEvasionScanModule()
    {
        var roots = new List<string>();

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var localLow = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "AppData", "LocalLow");
        var temp = Path.GetTempPath();
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads");
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        roots.Add(appData);
        roots.Add(localAppData);
        roots.Add(localLow);
        roots.Add(temp);
        roots.Add(desktop);
        roots.Add(downloads);
        roots.Add(docs);

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        roots.Add(Path.Combine(programFiles, "Steam", "steamapps", "common"));
        roots.Add(Path.Combine(programFilesX86, "Steam", "steamapps", "common"));
        roots.Add(Path.Combine(programFiles, "Rockstar Games"));
        roots.Add(Path.Combine(appData, "FiveM"));
        roots.Add(Path.Combine(localAppData, "FiveM"));
        roots.Add(Path.Combine(appData, "RageMP"));
        roots.Add(Path.Combine(appData, "altv"));
        roots.Add(Path.Combine(localAppData, "Programs"));

        EvasionSearchRoots = roots.Where(r => !string.IsNullOrEmpty(r)).ToArray();
    }

    // ── FiveM / RageMP anti-screenshot config names ───────────────────────────

    private static readonly string[] FiveMScreenBypassModuleNames =
    {
        "screenshot_bypass",
        "anti_screenshot",
        "screen_bypass",
        "screenshothide",
        "bypass_eac_screen",
        "bypass_cfx_screen",
        "cfx_screenshot_bypass",
        "fivem_screen",
        "noscreen",
        "no_screenshot",
        "screensafe",
        "scbypass",
        "sc_bypass",
        "fivem_anti_ac_screen",
        "ragemp_noscreen",
        "ragemp_bypass",
        "altv_bypass",
        "altv_screen",
    };

    // ── Config/script content signatures ─────────────────────────────────────

    private static readonly string[] ConfigScreenEvasionSignatures =
    {
        "screenshot",
        "screen_bypass",
        "screenshot_bypass",
        "anti_screenshot",
        "stealth_mode",
        "stealth_render",
        "capture_bypass",
        "hide_overlay",
        "invisible_overlay",
        "obs_bypass",
        "shadowplay_bypass",
        "wda_excludefromcapture",
        "WDA_EXCLUDEFROMCAPTURE",
        "SetWindowDisplayAffinity",
        "dwm_bypass",
        "dwm_hook",
        "dxgi_bypass",
        "present_hook",
        "gdi_bypass",
        "bitblt_bypass",
        "printwindow_bypass",
        "no_capture",
        "bypass_capture",
        "safe_screenshot",
        "screenshot_safe",
        "kernel_hide",
        "exclude_from_capture",
        "HideFromCapture",
    };

    // ─────────────────────────────────────────────────────────────────────────

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.00, ModuleName, "Scanning running processes for screen evasion tools...");
        ScanRunningProcesses(ctx, ct);

        ctx.Report(0.10, ModuleName, "Scanning for anti-screenshot DLLs and executables...");
        await ScanFileSystemForEvasionToolsAsync(ctx, ct);

        ctx.Report(0.30, ModuleName, "Scanning game directories for DWM/DXGI hook DLLs...");
        await ScanGameDirectoriesForHookDllsAsync(ctx, ct);

        ctx.Report(0.48, ModuleName, "Scanning for hijacked system DLLs in application directories...");
        await ScanForHijackedSystemDllsAsync(ctx, ct);

        ctx.Report(0.58, ModuleName, "Scanning for OBS game capture bypass artifacts...");
        await ScanObsBypassArtifactsAsync(ctx, ct);

        ctx.Report(0.65, ModuleName, "Scanning FiveM/RageMP/AltV anti-screenshot modules...");
        await ScanFiveMScreenBypassAsync(ctx, ct);

        ctx.Report(0.72, ModuleName, "Scanning registry for screen capture suppression settings...");
        ScanRegistryForScreenCaptureManipulation(ctx, ct);

        ctx.Report(0.80, ModuleName, "Scanning cheat config files for screenshot evasion settings...");
        await ScanConfigFilesForEvasionAsync(ctx, ct);

        ctx.Report(0.88, ModuleName, "Checking for screenshot capture process injection evidence...");
        ScanForCaptureProcessInjection(ctx, ct);

        ctx.Report(0.94, ModuleName, "Scanning prefetch for anti-screenshot tool execution...");
        ScanPrefetchForEvasionTools(ctx, ct);

        ctx.Report(1.00, ModuleName, "Anti-screenshot evasion scan complete.");
    }

    // ── Running process scan ──────────────────────────────────────────────────

    private static void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var snapshot = ctx.GetProcessSnapshot();
        foreach (var proc in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            string procExeName = proc.ProcessName + ".exe";
            if (!KnownEvasionExeNames.Contains(procExeName))
                continue;

            string location = string.Empty;
            try { location = proc.MainModule?.FileName ?? string.Empty; } catch { }

            ctx.AddFinding(new Finding
            {
                Module = ModuleName,
                Title = $"Anti-screenshot evasion tool running: {proc.ProcessName}",
                Risk = RiskLevel.Critical,
                Location = location,
                FileName = procExeName,
                Reason = $"Process '{proc.ProcessName}' (PID {proc.Id}) is a known anti-screenshot evasion tool. " +
                         "These tools hook DWM, DXGI, or GDI to hide cheat overlays from screenshot-based " +
                         "anti-cheat detection by rendering cheats invisible to capture APIs.",
                Detail = $"PID={proc.Id}",
            });
        }

        var captureProcs = snapshot
            .Where(p => ScreenshotCaptureProcessNames.Contains(p.ProcessName))
            .ToList();

        if (captureProcs.Count == 0) return;

        foreach (var captureProc in captureProcs)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var proc in snapshot)
            {
                ct.ThrowIfCancellationRequested();
                if (proc.Id == captureProc.Id) continue;

                string procExeName = proc.ProcessName + ".exe";
                if (!KnownEvasionExeNames.Contains(procExeName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"Anti-screenshot tool active alongside screen capture software: {proc.ProcessName}",
                    Risk = RiskLevel.Critical,
                    Location = string.Empty,
                    FileName = procExeName,
                    Reason = $"Anti-screenshot tool '{proc.ProcessName}' (PID {proc.Id}) is running at the same time " +
                             $"as screen capture software '{captureProc.ProcessName}' (PID {captureProc.Id}). " +
                             "This combination strongly indicates active screen capture evasion during a streaming or " +
                             "recording session, a common pattern for cheating while avoiding visual detection.",
                    Detail = $"EvasionProcess={proc.ProcessName} PID={proc.Id} CaptureProcess={captureProc.ProcessName} CapturePID={captureProc.Id}",
                });
            }
        }
    }

    // ── File system scan for evasion tools ────────────────────────────────────

    private static async Task ScanFileSystemForEvasionToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in EvasionSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                if (KnownEvasionExeNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Anti-screenshot bypass executable: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"'{fileName}' is a known anti-screenshot evasion tool. Found at '{file}'. " +
                                 "This type of tool hooks rendering APIs or the DWM compositor to render cheat overlays " +
                                 "in a layer invisible to screenshot capture tools, defeating screenshot-based anti-cheat.",
                        Detail = $"Path={file}",
                    });
                    continue;
                }

                if (KnownEvasionDllNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Anti-screenshot DLL artifact: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"'{fileName}' is a known anti-screenshot hook DLL. Found at '{file}'. " +
                                 "This DLL intercepts DWM/DXGI/GDI rendering calls to exclude cheat overlay windows " +
                                 "from screen capture APIs, making cheats invisible to screenshots and recordings.",
                        Detail = $"Path={file}",
                    });
                    continue;
                }

                var fileNameLower = fileName.ToLowerInvariant();
                if ((fileNameLower.Contains("screenshot") || fileNameLower.Contains("screen")) &&
                    (fileNameLower.Contains("bypass") || fileNameLower.Contains("hide") ||
                     fileNameLower.Contains("stealth") || fileNameLower.Contains("safe") ||
                     fileNameLower.Contains("evade") || fileNameLower.Contains("block")))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Suspicious anti-screenshot file name: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"'{fileName}' has a name pattern strongly indicating an anti-screenshot evasion tool. " +
                                 $"Found at '{file}'.",
                        Detail = $"Path={file}",
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    // ── Game directory hook DLL scan ──────────────────────────────────────────

    private static async Task ScanGameDirectoriesForHookDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var gameRoots = new[]
        {
            Path.Combine(programFiles, "Steam", "steamapps", "common"),
            Path.Combine(programFilesX86, "Steam", "steamapps", "common"),
            Path.Combine(programFiles, "Epic Games"),
            Path.Combine(programFilesX86, "Epic Games"),
            Path.Combine(programFiles, "Rockstar Games"),
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(appData, "RageMP"),
            Path.Combine(appData, "altv-client"),
        };

        foreach (var gameRoot in gameRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(gameRoot)) continue;

            IEnumerable<string> dlls;
            try
            {
                dlls = Directory.EnumerateFiles(gameRoot, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dll in dlls)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var dllName = Path.GetFileName(dll);

                if (!KnownEvasionDllNames.Contains(dllName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"Anti-screenshot DLL in game directory: {dllName}",
                    Risk = RiskLevel.Critical,
                    Location = dll,
                    FileName = dllName,
                    Reason = $"Anti-screenshot hook DLL '{dllName}' found inside game directory '{gameRoot}'. " +
                             "Placing this DLL inside a game directory causes Windows to load it via DLL search-order " +
                             "hijacking at game startup, enabling automatic invisible-overlay rendering without " +
                             "explicit injection.",
                    Detail = $"GameRoot={gameRoot} DllPath={dll}",
                });
            }
        }

        await Task.CompletedTask;
    }

    // ── Hijacked system DLL scan ──────────────────────────────────────────────

    private static async Task ScanForHijackedSystemDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var syswow64 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);

        var appDirs = new List<string>();

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var steamCommon = Path.Combine(programFilesX86, "Steam", "steamapps", "common");
        var steamCommon64 = Path.Combine(programFiles, "Steam", "steamapps", "common");
        var rockstar = Path.Combine(programFiles, "Rockstar Games");
        var rockstarX86 = Path.Combine(programFilesX86, "Rockstar Games");
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var root in new[] { steamCommon, steamCommon64, rockstar, rockstarX86 })
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var d in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
                    appDirs.Add(d);
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        foreach (var fixedDir in new[] {
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(appData, "RageMP"),
            Path.Combine(appData, "altv-client") })
        {
            if (Directory.Exists(fixedDir))
                appDirs.Add(fixedDir);
        }

        foreach (var appDir in appDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(appDir)) continue;

            foreach (var systemDllName in HijackedSystemDllNames)
            {
                ct.ThrowIfCancellationRequested();
                var candidatePath = Path.Combine(appDir, systemDllName);
                if (!File.Exists(candidatePath)) continue;

                ctx.IncrementFiles();

                var systemPath = Path.Combine(system32, systemDllName);
                var sysWowPath = Path.Combine(syswow64, systemDllName);

                bool isSystemDllPresent = File.Exists(systemPath) || File.Exists(sysWowPath);

                if (!isSystemDllPresent)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"System DLL shadowing in application directory: {systemDllName}",
                        Risk = RiskLevel.Critical,
                        Location = candidatePath,
                        FileName = systemDllName,
                        Reason = $"'{systemDllName}' was found in game/application directory '{appDir}' but does not exist " +
                                 "in System32. This file shadows the legitimate Windows system DLL, causing all " +
                                 "applications in this directory to load the malicious version. Anti-screenshot cheats " +
                                 "commonly shadow dwmapi.dll, dxgi.dll, or d3d11.dll to intercept rendering and hide " +
                                 "overlays from screen capture.",
                        Detail = $"ShadowPath={candidatePath} ExpectedSystemPath={systemPath}",
                    });
                    continue;
                }

                long appFileSize = 0;
                long sysFileSize = 0;
                try { appFileSize = new FileInfo(candidatePath).Length; } catch { }
                try { sysFileSize = new FileInfo(systemPath).Length; } catch { }

                if (appFileSize > 0 && sysFileSize > 0 && appFileSize != sysFileSize)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Modified system DLL in application directory (size mismatch): {systemDllName}",
                        Risk = RiskLevel.Critical,
                        Location = candidatePath,
                        FileName = systemDllName,
                        Reason = $"'{systemDllName}' exists in both the game directory ('{candidatePath}', {appFileSize} bytes) " +
                                 $"and System32 ('{systemPath}', {sysFileSize} bytes), but the sizes differ. " +
                                 "Windows loads the application-directory copy first (DLL search order), " +
                                 "meaning this modified DLL intercepts all rendering calls. Anti-screenshot cheats " +
                                 "use this technique to modify dwmapi.dll or dxgi.dll to hide overlays.",
                        Detail = $"AppDllSize={appFileSize} SystemDllSize={sysFileSize} AppPath={candidatePath} SysPath={systemPath}",
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    // ── OBS bypass artifact scan ──────────────────────────────────────────────

    private static async Task ScanObsBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var obsDirectories = new List<string>();

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        obsDirectories.Add(Path.Combine(programFiles, "obs-studio"));
        obsDirectories.Add(Path.Combine(programFilesX86, "obs-studio"));
        obsDirectories.Add(Path.Combine(appData, "obs-studio"));

        try
        {
            using var obsKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\OBS-Studio")
                            ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\obs-studio");
            if (obsKey != null)
            {
                ctx.IncrementRegistryKeys();
                var installDir = obsKey.GetValue("InstallDir") as string ?? string.Empty;
                if (!string.IsNullOrEmpty(installDir) && Directory.Exists(installDir))
                    obsDirectories.Add(installDir);
            }
        }
        catch (Exception) { }

        foreach (var obsDir in obsDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(obsDir)) continue;

            IEnumerable<string> obsFiles;
            try
            {
                obsFiles = Directory.EnumerateFiles(obsDir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var obsFile in obsFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var obsFileName = Path.GetFileName(obsFile);

                bool isBypassFile = false;
                foreach (var bypassName in ObsBypassFileNames)
                {
                    if (obsFileName.Equals(bypassName, StringComparison.OrdinalIgnoreCase))
                    {
                        isBypassFile = true;
                        break;
                    }
                }

                if (!isBypassFile) continue;

                string content;
                try
                {
                    using var fs = new FileStream(obsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                bool hasEvasionSig = false;
                foreach (var sig in AntiScreenshotCodeSignatures)
                {
                    if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        hasEvasionSig = true;
                        break;
                    }
                }

                if (hasEvasionSig)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Modified OBS capture file with evasion signatures: {obsFileName}",
                        Risk = RiskLevel.Critical,
                        Location = obsFile,
                        FileName = obsFileName,
                        Reason = $"OBS file '{obsFileName}' found at '{obsFile}' contains anti-screenshot evasion code. " +
                                 "A modified obs-game-capture.dll or graphics-hook DLL can be patched to skip " +
                                 "capturing specific windows or render targets, making cheat overlays invisible in " +
                                 "OBS recordings while appearing normally on screen.",
                        Detail = $"Path={obsFile}",
                    });
                }
            }
        }

        var obsPluginDirs = new[]
        {
            Path.Combine(programFiles, "obs-studio", "obs-plugins"),
            Path.Combine(programFilesX86, "obs-studio", "obs-plugins"),
        };

        foreach (var pluginDir in obsPluginDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(pluginDir)) continue;

            IEnumerable<string> pluginFiles;
            try
            {
                pluginFiles = Directory.EnumerateFiles(pluginDir, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var pluginFile in pluginFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var pluginName = Path.GetFileName(pluginFile).ToLowerInvariant();

                if (!pluginName.Contains("bypass") && !pluginName.Contains("hide") &&
                    !pluginName.Contains("stealth") && !pluginName.Contains("block") &&
                    !pluginName.Contains("exclude") && !pluginName.Contains("filter"))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"Suspicious OBS plugin with screen evasion name: {Path.GetFileName(pluginFile)}",
                    Risk = RiskLevel.High,
                    Location = pluginFile,
                    FileName = Path.GetFileName(pluginFile),
                    Reason = $"OBS plugin '{Path.GetFileName(pluginFile)}' has a name suggesting it modifies " +
                             "OBS capture behavior to hide or filter certain windows from recording. " +
                             "Cheat tools use custom OBS plugins to exclude cheat overlay windows from " +
                             "screen capture while allowing everything else to be recorded normally.",
                    Detail = $"PluginPath={pluginFile}",
                });
            }
        }
    }

    // ── FiveM / RageMP / AltV screen bypass scan ──────────────────────────────

    private static async Task ScanFiveMScreenBypassAsync(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var fivemRoots = new[]
        {
            Path.Combine(appData, "FiveM", "FiveM.app", "plugins"),
            Path.Combine(appData, "FiveM", "FiveM.app", "citizen", "resources"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "plugins"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "citizen", "resources"),
            Path.Combine(appData, "RageMP", "dotnet", "scripts"),
            Path.Combine(appData, "RageMP", "plugins"),
            Path.Combine(appData, "altv-client", "resources"),
            Path.Combine(localAppData, "altv", "resources"),
        };

        foreach (var fivemRoot in fivemRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(fivemRoot)) continue;

            IEnumerable<string> resourceFiles;
            try
            {
                resourceFiles = Directory.EnumerateFiles(fivemRoot, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in resourceFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file).ToLowerInvariant();

                bool nameMatch = false;
                foreach (var bypassName in FiveMScreenBypassModuleNames)
                {
                    if (fileName.Contains(bypassName, StringComparison.OrdinalIgnoreCase))
                    {
                        nameMatch = true;
                        break;
                    }
                }

                if (nameMatch)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"FiveM/RageMP/AltV anti-screenshot module: {Path.GetFileName(file)}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"File '{Path.GetFileName(file)}' in the FiveM/RageMP/AltV resource directory " +
                                 "matches a known anti-screenshot bypass module name. FiveM cheats commonly " +
                                 "include NUI/resource modules that hook the screenshot APIs used by CFX/EAC " +
                                 "to capture evidence of cheating.",
                        Detail = $"Path={file} Root={fivemRoot}",
                    });
                    continue;
                }

                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".lua" && ext != ".js" && ext != ".cfg" && ext != ".json" && ext != ".ini")
                    continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int matchCount = 0;
                var matches = new List<string>();
                foreach (var sig in ConfigScreenEvasionSignatures)
                {
                    if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        matchCount++;
                        matches.Add(sig);
                    }
                }

                if (matchCount >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"FiveM/RageMP script with screenshot evasion signatures: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Script '{Path.GetFileName(file)}' in game resource directory contains {matchCount} " +
                                 $"screenshot evasion indicators: {string.Join(", ", matches.Take(5))}.",
                        Detail = $"Path={file} Matches={string.Join("|", matches)}",
                    });
                }
            }
        }
    }

    // ── Registry scan for screen capture manipulation ─────────────────────────

    private static void ScanRegistryForScreenCaptureManipulation(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            using var dwmKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\DWM");
            if (dwmKey != null)
            {
                ctx.IncrementRegistryKeys();

                var enableAero = dwmKey.GetValue("EnableAeroPeek");
                var alwaysHideThumb = dwmKey.GetValue("AlwaysHideThumb");
                var disableThumbs = dwmKey.GetValue("EnableThumbnail");

                if (alwaysHideThumb is int aht && aht == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = "DWM AlwaysHideThumb enabled (hides windows from taskbar/Aero Peek)",
                        Risk = RiskLevel.Low,
                        Location = @"HKCU\SOFTWARE\Microsoft\Windows\DWM",
                        Reason = "DWM AlwaysHideThumb=1 hides window thumbnails from the taskbar. " +
                                 "Anti-screenshot tools sometimes set this to reduce the visibility of " +
                                 "cheat overlay windows in Windows UI.",
                        Detail = "AlwaysHideThumb=1",
                    });
                }
            }
        }
        catch (Exception) { }

        ct.ThrowIfCancellationRequested();

        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            foreach (var runKey in runKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = hive.OpenSubKey(runKey);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var val = key.GetValue(valueName) as string ?? string.Empty;
                        var valLower = val.ToLowerInvariant();
                        var nameLower = valueName.ToLowerInvariant();

                        bool evasionMatch = false;
                        foreach (var evasionExe in KnownEvasionExeNames)
                        {
                            if (valLower.Contains(evasionExe.ToLowerInvariant()))
                            {
                                evasionMatch = true;
                                break;
                            }
                        }
                        if (!evasionMatch)
                        {
                            foreach (var evasionDll in KnownEvasionDllNames)
                            {
                                if (valLower.Contains(evasionDll.ToLowerInvariant()))
                                {
                                    evasionMatch = true;
                                    break;
                                }
                            }
                        }
                        if (!evasionMatch)
                        {
                            evasionMatch = nameLower.Contains("screenshot") || nameLower.Contains("screenbypass") ||
                                          nameLower.Contains("screenhide") || nameLower.Contains("stealthrender") ||
                                          nameLower.Contains("overlaystealth");
                        }

                        if (!evasionMatch) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Anti-screenshot tool persisted in registry Run key: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"{(hive == Registry.CurrentUser ? "HKCU" : "HKLM")}\{runKey}",
                            Reason = $"Registry Run key '{valueName}' = '{val}' references an anti-screenshot evasion tool. " +
                                     "This ensures the screen capture bypass loads automatically at every Windows startup, " +
                                     "providing persistent evasion of screenshot-based anti-cheat systems.",
                            Detail = $"RunKey={valueName} Value={val}",
                        });
                    }
                }
                catch (Exception) { }
            }
        }

        ct.ThrowIfCancellationRequested();

        try
        {
            using var shadowPlayKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\NVIDIA Corporation\Global\ShadowPlay\ShadowPlayShortcuts");
            if (shadowPlayKey != null)
            {
                ctx.IncrementRegistryKeys();
                var capEnabled = shadowPlayKey.GetValue("Enable");
                if (capEnabled is int capVal && capVal == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = "NVIDIA ShadowPlay/Share capture disabled via registry",
                        Risk = RiskLevel.Medium,
                        Location = @"HKCU\SOFTWARE\NVIDIA Corporation\Global\ShadowPlay\ShadowPlayShortcuts",
                        Reason = "NVIDIA ShadowPlay capture is disabled in the registry. While this can be user preference, " +
                                 "disabling GPU-level capture is a tactic used by cheaters to prevent NVIDIA's hardware-level " +
                                 "screen capture from recording cheat overlays that might evade software screenshot bypass.",
                        Detail = "ShadowPlay Capture Enable=0",
                    });
                }
            }
        }
        catch (Exception) { }
    }

    // ── Config file scan for screen evasion settings ──────────────────────────

    private static async Task ScanConfigFilesForEvasionAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
        };

        var configExts = new[] { "*.ini", "*.cfg", "*.json", "*.xml", "*.txt", "*.config", "*.lua", "*.js" };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            foreach (var ext in configExts)
            {
                IEnumerable<string> cfgFiles;
                try
                {
                    cfgFiles = Directory.EnumerateFiles(root, ext, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var cfgFile in cfgFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var cfgFileName = Path.GetFileName(cfgFile).ToLowerInvariant();
                    bool nameRelevant = cfgFileName.Contains("cheat") || cfgFileName.Contains("hack") ||
                                       cfgFileName.Contains("inject") || cfgFileName.Contains("bypass") ||
                                       cfgFileName.Contains("screen") || cfgFileName.Contains("overlay") ||
                                       cfgFileName.Contains("stealth") || cfgFileName.Contains("loader");
                    if (!nameRelevant) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    int matchCount = 0;
                    var matches = new List<string>();
                    foreach (var sig in ConfigScreenEvasionSignatures)
                    {
                        if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            matches.Add(sig);
                        }
                    }

                    if (matchCount >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Cheat config with screenshot evasion settings: {Path.GetFileName(cfgFile)}",
                            Risk = RiskLevel.High,
                            Location = cfgFile,
                            FileName = Path.GetFileName(cfgFile),
                            Reason = $"Configuration file '{Path.GetFileName(cfgFile)}' contains {matchCount} screenshot " +
                                     $"evasion indicators: {string.Join(", ", matches.Take(5))}. " +
                                     "This suggests the cheat tool is configured with explicit anti-screenshot or " +
                                     "stealth rendering features enabled.",
                            Detail = $"Path={cfgFile} Signatures={string.Join("|", matches)}",
                        });
                    }
                }
            }
        }
    }

    // ── Capture process injection evidence ────────────────────────────────────

    private static void ScanForCaptureProcessInjection(ScanContext ctx, CancellationToken ct)
    {
        var snapshot = ctx.GetProcessSnapshot();

        foreach (var proc in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            if (!ScreenshotCaptureProcessNames.Contains(proc.ProcessName)) continue;

            try
            {
                var modules = proc.Modules;
                foreach (System.Diagnostics.ProcessModule? mod in modules)
                {
                    if (mod is null) continue;
                    ct.ThrowIfCancellationRequested();

                    var modName = Path.GetFileName(mod.FileName ?? string.Empty);

                    if (KnownEvasionDllNames.Contains(modName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Anti-screenshot DLL injected into screen capture process: {modName}",
                            Risk = RiskLevel.Critical,
                            Location = mod.FileName ?? proc.ProcessName,
                            FileName = modName,
                            Reason = $"Anti-screenshot DLL '{modName}' is loaded inside screen capture process " +
                                     $"'{proc.ProcessName}' (PID {proc.Id}). Injecting into screenshot software " +
                                     "allows cheats to intercept or modify capture calls from within the capture " +
                                     "process itself, preventing cheat overlays from appearing in recordings.",
                            Detail = $"InjectedDll={modName} TargetProcess={proc.ProcessName} PID={proc.Id} DllPath={mod.FileName}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }

    // ── Prefetch scan for evasion tool execution ──────────────────────────────

    private static void ScanPrefetchForEvasionTools(ScanContext ctx, CancellationToken ct)
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        IEnumerable<string> prefetchFiles;
        try
        {
            prefetchFiles = Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var pfFile in prefetchFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var pfName = Path.GetFileName(pfFile).ToLowerInvariant();

            foreach (var evasionExe in KnownEvasionExeNames)
            {
                var baseName = Path.GetFileNameWithoutExtension(evasionExe).ToLowerInvariant();
                if (!pfName.StartsWith(baseName, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"Anti-screenshot tool execution evidence in Prefetch: {Path.GetFileName(pfFile)}",
                    Risk = RiskLevel.High,
                    Location = pfFile,
                    FileName = Path.GetFileName(pfFile),
                    Reason = $"Windows Prefetch file '{Path.GetFileName(pfFile)}' proves that anti-screenshot " +
                             $"evasion tool '{evasionExe}' was executed on this machine. Prefetch files are " +
                             "created by Windows the first time a program runs and persist even after the " +
                             "program is deleted, providing forensic evidence of execution.",
                    Detail = $"PrefetchFile={pfFile} EvasionTool={evasionExe}",
                });
                break;
            }
        }
    }
}
