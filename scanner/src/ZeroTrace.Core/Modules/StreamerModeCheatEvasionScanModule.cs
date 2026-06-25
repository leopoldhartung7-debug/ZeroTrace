using Microsoft.Win32;
using System.Diagnostics;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class StreamerModeCheatEvasionScanModule : IScanModule
{
    public string Name => "Streamer Mode Cheat Evasion Detection";
    public double Weight => 3.8;
    public int ParallelGroup => 4;

    private static readonly string[] WindowHidingExecutables =
    {
        "window_hider.exe", "hide_window.exe", "stealth_overlay.exe",
        "dxhook_hide.exe", "obs_bypass.exe", "shadowplay_bypass.exe",
        "capture_bypass.exe", "screen_bypass.exe", "anti_obs.exe",
        "anti_screenshot.exe", "anti_screen.exe", "anti_capture.exe",
        "obs_killer.exe", "obs_spoofer.exe", "nvidia_bypass.exe",
        "geforce_bypass.exe", "discord_overlay_bypass.exe", "discord_hide.exe",
        "xsplit_bypass.exe", "streamlabs_bypass.exe", "capture_block.exe",
        "screen_block.exe", "obs_block.exe", "record_bypass.exe",
        "stream_bypass.exe", "screenshot_bypass.exe", "scrcpy_bypass.exe",
        "capture_hide.exe", "overlay_hide.exe", "obs_hide.exe",
        "twitch_bypass.exe", "youtube_bypass.exe", "fullscreen_bypass.exe",
        "wgc_bypass.exe", "dxgi_bypass.exe", "dx_bypass.exe",
        "obs_evade.exe", "capture_evade.exe", "screen_evade.exe",
    };

    private static readonly string[] DwmBypassDlls =
    {
        "dwm_bypass.dll", "dwm_hook.dll", "dwm_patch.dll",
        "dwm_inject.dll", "dwm_stealth.dll", "dcomp_bypass.dll",
        "compositor_bypass.dll", "dwm_hide.dll",
    };

    private static readonly string[] ProxyDllNames =
    {
        "d3d9.dll", "d3d11.dll", "dxgi.dll", "d3d12.dll",
        "d3d8.dll", "ddraw.dll", "opengl32.dll", "dinput.dll",
        "dinput8.dll", "dsound.dll", "winmm.dll",
    };

    private static readonly string[] ObsHookDllNames =
    {
        "graphics-hook64.dll", "graphics-hook32.dll",
        "get-graphics-offsets64.exe", "get-graphics-offsets32.exe",
        "obs-vulkan64.dll", "obs-vulkan32.dll",
        "ObsVulkanCapture.dll",
    };

    private static readonly string[] AntiCaptureScriptNames =
    {
        "cleanup.bat", "selfdelete.bat", "remove_traces.ps1",
        "cleanup.ps1", "clean.bat", "clear_traces.bat",
        "wipe.bat", "nuke.bat", "delete_cheat.bat",
        "remove_cheat.ps1", "uninstall.bat", "stealth_clean.bat",
        "after_stream.bat", "stream_cleanup.bat", "cleanup_overlay.bat",
        "remove_overlay.bat", "del_dll.bat", "clean_overlay.ps1",
        "post_stream.ps1", "auto_clean.bat",
    };

    private static readonly string[] StreamerModeConfigKeywords =
    {
        "streamer_mode = true", "streamer_mode=true",
        "obs_bypass = true", "obs_bypass=true",
        "hide_from_capture = true", "hide_from_capture=true",
        "anti_screenshot = true", "anti_screenshot=true",
        "anti_record = true", "anti_record=true",
        "window_hide = true", "window_hide=true",
        "dx_overlay = true", "dx_overlay=true",
        "capture_bypass = true", "capture_bypass=true",
        "\"streamer_mode\": true", "\"streamer_mode\":true",
        "\"obs_bypass\": true", "\"obs_bypass\":true",
        "\"hide_from_capture\": true", "\"hide_from_capture\":true",
        "\"anti_screenshot\": true", "\"anti_screenshot\":true",
        "\"anti_record\": true", "\"anti_record\":true",
        "\"window_hide\": true", "\"window_hide\":true",
        "\"dx_overlay\": true", "\"dx_overlay\":true",
        "streamer = 1", "streamer=1",
        "obs_invisible", "capture_invisible", "hide_overlay",
        "WGC_BYPASS", "wgc_bypass", "exclude_from_capture",
        "SetWindowDisplayAffinity", "WDA_EXCLUDEFROMCAPTURE",
    };

    private static readonly string[] CleanupScriptKeywords =
    {
        "del ", "rm ", "Remove-Item", "rmdir", "rd /s",
        "erase ", "DEL /F", "del /f",
        ".dll", ".exe", "overlay", "cheat", "inject",
        "loader", "bypass", "hook", "d3d", "dxgi",
    };

    private static readonly string[] AutostartRegistryPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    };

    private static readonly string[] GameDirectoryFragments =
    {
        "steamapps", "steam", "origin", "epicgames", "ubisoft",
        "riot games", "battlenet", "activision", "ea games",
        "games", "game", "csgo", "cs2", "apex", "valorant",
        "fortnite", "pubg", "tarkov", "rust", "gta",
        "warzone", "cod", "battlefield", "rainbow six",
    };

    private static readonly string[] ObsRelatedProcesses =
    {
        "obs64", "obs32", "obs", "obs-browser-page",
        "obspluginproxy", "shadowplay", "nvcapturesvc",
        "nvcontainer", "nvidia share", "geforceexperience",
        "xsplit", "xsplit broadcaster", "streamlabs",
        "streamlabs obs", "slobs", "discord", "lightstream",
        "galax share", "medal", "outplayed", "plays",
        "amd link", "radeon relive", "riva statistics",
    };

    private static readonly string[] WindowTitleSpoofingKeywords =
    {
        "chrome", "google chrome", "firefox", "edge", "notepad",
        "calculator", "explorer", "microsoft edge", "file explorer",
        "task manager", "word", "excel", "control panel",
        "settings", "paint", "photos", "store",
    };

    private static readonly string[] RegistryDwmKeys =
    {
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AEFM",
        @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers\DCI",
        @"SOFTWARE\Microsoft\Windows\Dwm",
    };

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string Downloads =
        Path.Combine(UserProfile, "Downloads");
    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static readonly string ProgramFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    private static readonly string TempPath =
        Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar);

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Scanning for window hiding and OBS bypass executables...");
        await ScanWindowHidingExecutablesAsync(ctx, ct);

        ctx.Report(0.14, Name, "Scanning for DWM hook and bypass DLLs...");
        await ScanDwmBypassDllsAsync(ctx, ct);

        ctx.Report(0.25, Name, "Scanning for proxy DLLs in game directories...");
        await ScanProxyDllsInGameDirsAsync(ctx, ct);

        ctx.Report(0.36, Name, "Scanning cheat configs for streamer mode flags...");
        await ScanCheatConfigsForStreamerModeAsync(ctx, ct);

        ctx.Report(0.48, Name, "Scanning for anti-forensics cleanup scripts...");
        await ScanCleanupScriptsAsync(ctx, ct);

        ctx.Report(0.58, Name, "Checking OBS hook DLL integrity and misplacement...");
        await ScanObsHookDllsAsync(ctx, ct);

        ctx.Report(0.67, Name, "Checking registry for anti-screenshot and DWM bypass artifacts...");
        ScanRegistryArtifacts(ctx, ct);

        ctx.Report(0.76, Name, "Scanning autostart entries for window title spoofing...");
        ScanAutostartWindowTitleSpoofing(ctx, ct);

        ctx.Report(0.85, Name, "Checking running processes for anti-capture tools...");
        ScanRunningProcesses(ctx, ct);

        ctx.Report(0.93, Name, "Scanning AppData for hidden cheat component directories...");
        await ScanAppDataForHiddenCheatDirsAsync(ctx, ct);

        ctx.Report(1.0, Name, "Streamer mode cheat evasion scan complete");
    }

    private async Task ScanWindowHidingExecutablesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
            Documents,
            UserProfile,
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                IEnumerable<string> exeFiles;
                try
                {
                    exeFiles = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var filePath in exeFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(filePath);

                    var match = WindowHidingExecutables.FirstOrDefault(n =>
                        n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
                    if (match is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Window hiding / OBS bypass tool: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"Executable '{fileName}' is a known streamer-mode bypass or window " +
                                 "hiding tool. These tools prevent OBS, ShadowPlay, Discord overlay, " +
                                 "and other capture software from recording the cheat's overlay or UI. " +
                                 "They exploit DirectX/DXGI capture gaps or DWM exclusion APIs to make " +
                                 "the cheat invisible to screen recordings while still showing on the " +
                                 "player's monitor.",
                        Detail = $"Path: {filePath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }

            await Task.Yield();
        }

        await ScanSubdirsForWindowHidingToolsAsync(ctx, ct);
    }

    private async Task ScanSubdirsForWindowHidingToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var baseDir in new[] { AppDataRoaming, AppDataLocal })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    IEnumerable<string> files;
                    try
                    {
                        files = Directory.EnumerateFiles(subdir, "*.exe", SearchOption.TopDirectoryOnly);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var filePath in files)
                    {
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(filePath);

                        var match = WindowHidingExecutables.FirstOrDefault(n =>
                            n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Window hiding tool in AppData: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"Screen capture bypass tool '{fileName}' found in AppData directory " +
                                     $"'{Path.GetFileName(subdir)}'. Cheats install capture bypass components " +
                                     "in application directories to load them automatically alongside " +
                                     "the cheat when the game is launched.",
                            Detail = $"Path: {filePath}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                await Task.Yield();
            }
        }
    }

    private async Task ScanDwmBypassDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
            Documents,
            UserProfile,
            Path.Combine(AppDataLocal, "Temp"),
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                IEnumerable<string> dllFiles;
                try
                {
                    dllFiles = Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var filePath in dllFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(filePath);

                    var dwmMatch = DwmBypassDlls.FirstOrDefault(n =>
                        n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
                    if (dwmMatch is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Desktop Window Manager bypass DLL: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"DLL '{fileName}' is a Desktop Window Manager (DWM) hook or bypass " +
                                 "library. DWM manages the Windows visual compositor that OBS and " +
                                 "other capture tools use to record the screen. Hooking DWM allows " +
                                 "a cheat overlay to render directly to the GPU framebuffer without " +
                                 "passing through the compositor, making it completely invisible to " +
                                 "OBS, Discord, ShadowPlay, and any software-based capture tool.",
                        Detail = $"Path: {filePath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }

            await Task.Yield();
        }
    }

    private async Task ScanProxyDllsInGameDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        var gameDirRoots = new List<string>();

        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed) continue;

                foreach (var fragment in new[] { "Games", "SteamLibrary", "Steam", "Epic Games" })
                {
                    var candidate = Path.Combine(drive.RootDirectory.FullName, fragment);
                    if (Directory.Exists(candidate)) gameDirRoots.Add(candidate);
                }
            }
        }
        catch (IOException) { }

        var steamAppsDir = Path.Combine(AppDataLocal, "Steam");
        if (!Directory.Exists(steamAppsDir))
            steamAppsDir = @"C:\Program Files (x86)\Steam\steamapps\common";
        if (Directory.Exists(steamAppsDir)) gameDirRoots.Add(steamAppsDir);

        var programFilesGameDirs = new[]
        {
            Path.Combine(ProgramFiles, "Steam", "steamapps", "common"),
            Path.Combine(ProgramFilesX86, "Steam", "steamapps", "common"),
            Path.Combine(ProgramFiles, "Epic Games"),
            Path.Combine(ProgramFilesX86, "Epic Games"),
            Path.Combine(ProgramFiles, "Ubisoft", "Ubisoft Game Launcher", "games"),
            Path.Combine(ProgramFiles, "Riot Games"),
        };
        gameDirRoots.AddRange(programFilesGameDirs.Where(Directory.Exists));

        foreach (var rootDir in gameDirRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(rootDir)) continue;

            IEnumerable<string> gameDirs;
            try
            {
                gameDirs = Directory.EnumerateDirectories(rootDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var gameDir in gameDirs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await ScanGameDirForProxyDllsAsync(ctx, gameDir, ct);
                }
                catch (UnauthorizedAccessException) { }
                await Task.Yield();
            }
        }
    }

    private async Task ScanGameDirForProxyDllsAsync(
        ScanContext ctx, string gameDir, CancellationToken ct)
    {
        IEnumerable<string> dllFiles;
        try
        {
            dllFiles = Directory.EnumerateFiles(gameDir, "*.dll", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var filePath in dllFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(filePath);
            var proxyMatch = ProxyDllNames.FirstOrDefault(n =>
                n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
            if (proxyMatch is null) continue;

            string content = string.Empty;
            bool hasProxyExports = false;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, System.Text.Encoding.Latin1);
                var buf = new char[4096];
                int read = await sr.ReadAsync(buf, 0, buf.Length);
                content = new string(buf, 0, read);
                hasProxyExports = content.Contains("Direct3DCreate", StringComparison.OrdinalIgnoreCase)
                               || content.Contains("CreateDXGIFactory", StringComparison.OrdinalIgnoreCase)
                               || content.Contains("RealDirect3D", StringComparison.OrdinalIgnoreCase)
                               || content.Contains("Proxy", StringComparison.OrdinalIgnoreCase)
                               || content.Contains("hook", StringComparison.OrdinalIgnoreCase)
                               || content.Contains("overlay", StringComparison.OrdinalIgnoreCase)
                               || content.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                               || content.Contains("capture", StringComparison.OrdinalIgnoreCase)
                               || content.Contains("EXCLUDE", StringComparison.OrdinalIgnoreCase);
            }
            catch (IOException) { }

            var gameDirName = Path.GetFileName(gameDir);

            if (hasProxyExports)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"DirectX proxy DLL with bypass/hook strings in game dir: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"System DLL '{fileName}' found in game directory '{gameDirName}' with " +
                             "bypass/hook/overlay strings. DLL hijacking with DirectX/DXGI proxy DLLs " +
                             "is a primary technique for injecting cheat overlays that evade screen " +
                             "capture. When the game loads d3d11.dll or dxgi.dll, it loads the cheat " +
                             "proxy instead of the system version, enabling invisible rendering.",
                    Detail = $"Game dir: {gameDir} | Suspicious strings detected in DLL"
                });
            }
            else
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"System DLL in game directory (possible proxy): {fileName}",
                    Risk = RiskLevel.High,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"System DirectX/audio DLL '{fileName}' found in game directory " +
                             $"'{gameDirName}'. Games should load these DLLs from System32, not from " +
                             "their own directory. A copy here indicates DLL hijacking — the standard " +
                             "technique for deploying cheat overlays. Some legitimate mods use this " +
                             "method too, so manual review is needed.",
                    Detail = $"Game dir: {gameDir}"
                });
            }
        }
    }

    private async Task ScanCheatConfigsForStreamerModeAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
            Documents,
            UserProfile,
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                await ScanDirForStreamerConfigsAsync(ctx, dir, SearchOption.TopDirectoryOnly, ct);
            }
            catch (UnauthorizedAccessException) { }
        }

        foreach (var baseDir in new[] { AppDataRoaming, AppDataLocal })
        {
            if (!Directory.Exists(baseDir)) continue;
            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await ScanDirForStreamerConfigsAsync(ctx, subdir, SearchOption.TopDirectoryOnly, ct);
                }
                catch (UnauthorizedAccessException) { }
                await Task.Yield();
            }
        }
    }

    private async Task ScanDirForStreamerConfigsAsync(
        ScanContext ctx, string directory, SearchOption option, CancellationToken ct)
    {
        IEnumerable<string> configFiles;
        try
        {
            configFiles = Directory.EnumerateFiles(directory, "*.json", option)
                .Concat(Directory.EnumerateFiles(directory, "*.cfg", option))
                .Concat(Directory.EnumerateFiles(directory, "*.ini", option))
                .Concat(Directory.EnumerateFiles(directory, "*.txt", option));
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var filePath in configFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            var matchedKeywords = StreamerModeConfigKeywords
                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchedKeywords.Count == 0) continue;

            var fileName = Path.GetFileName(filePath);
            var risk = matchedKeywords.Count >= 3 ? RiskLevel.Critical : RiskLevel.High;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Streamer mode / capture bypass config: {fileName}",
                Risk = risk,
                Location = filePath,
                FileName = fileName,
                Reason = $"Config file '{fileName}' contains {matchedKeywords.Count} streamer mode " +
                         $"or capture bypass flags: {string.Join(", ", matchedKeywords.Take(5))}. " +
                         "Cheats with built-in streamer mode implement specific hooks to exclude " +
                         "their windows from OBS/ShadowPlay/Discord capture. These flags are only " +
                         "meaningful in cheat software — legitimate applications do not need to " +
                         "hide themselves from screen capture.",
                Detail = $"Matched config flags: {string.Join(", ", matchedKeywords)}"
            });
        }
    }

    private async Task ScanCleanupScriptsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
            Documents,
            UserProfile,
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                await ScanDirForCleanupScriptsAsync(ctx, dir, SearchOption.TopDirectoryOnly, ct);
            }
            catch (UnauthorizedAccessException) { }
        }

        foreach (var baseDir in new[] { AppDataRoaming, AppDataLocal })
        {
            if (!Directory.Exists(baseDir)) continue;
            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await ScanDirForCleanupScriptsAsync(ctx, subdir, SearchOption.TopDirectoryOnly, ct);
                }
                catch (UnauthorizedAccessException) { }
                await Task.Yield();
            }
        }
    }

    private async Task ScanDirForCleanupScriptsAsync(
        ScanContext ctx, string directory, SearchOption option, CancellationToken ct)
    {
        IEnumerable<string> scriptFiles;
        try
        {
            scriptFiles = Directory.EnumerateFiles(directory, "*.bat", option)
                .Concat(Directory.EnumerateFiles(directory, "*.ps1", option))
                .Concat(Directory.EnumerateFiles(directory, "*.cmd", option));
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var filePath in scriptFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(filePath);

            bool isKnownCleanupName = AntiCaptureScriptNames.Any(n =>
                n.Equals(fileName, StringComparison.OrdinalIgnoreCase));

            string content;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            var matchedCleanupKw = CleanupScriptKeywords
                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (!isKnownCleanupName && matchedCleanupKw.Count < 4) continue;

            bool deletesCheatFiles = content.Contains(".dll", StringComparison.OrdinalIgnoreCase)
                || content.Contains(".exe", StringComparison.OrdinalIgnoreCase);
            bool mentionsCheatTerms = new[] { "cheat", "overlay", "inject", "hook", "bypass", "loader", "d3d", "dxgi" }
                .Any(t => content.Contains(t, StringComparison.OrdinalIgnoreCase));

            if (!isKnownCleanupName && !mentionsCheatTerms) continue;

            var risk = isKnownCleanupName && mentionsCheatTerms && deletesCheatFiles
                ? RiskLevel.Critical
                : mentionsCheatTerms && deletesCheatFiles
                    ? RiskLevel.High
                    : RiskLevel.Medium;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Anti-forensics cleanup script: {fileName}",
                Risk = risk,
                Location = filePath,
                FileName = fileName,
                Reason = $"Script '{fileName}' appears to be a post-streaming cheat cleanup script. " +
                         (isKnownCleanupName
                             ? "The filename matches known cheat cleanup script patterns. "
                             : "") +
                         (mentionsCheatTerms
                             ? "The script references cheat-related terms (overlay, inject, hook, bypass). "
                             : "") +
                         (deletesCheatFiles
                             ? "The script deletes DLL or EXE files. "
                             : "") +
                         "Streamer cheat users frequently run cleanup scripts after streaming sessions " +
                         "to remove overlay DLLs, cheat executables, and other traces before " +
                         "submitting to anti-cheat investigations.",
                Detail = $"Cheat terms matched: {string.Join(", ", matchedCleanupKw.Take(6))}"
            });
        }
    }

    private async Task ScanObsHookDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var obsInstallDirs = new List<string>();

        var commonObsPaths = new[]
        {
            Path.Combine(ProgramFiles, "obs-studio"),
            Path.Combine(ProgramFilesX86, "obs-studio"),
            Path.Combine(AppDataRoaming, "obs-studio"),
            Path.Combine(AppDataLocal, "Programs", "obs-studio"),
        };

        obsInstallDirs.AddRange(commonObsPaths.Where(Directory.Exists));

        string? obsHookDir = null;
        foreach (var obsDir in obsInstallDirs)
        {
            var candidate = Path.Combine(obsDir, "bin", "64bit");
            if (Directory.Exists(candidate)) { obsHookDir = candidate; break; }
            candidate = Path.Combine(obsDir, "data", "obs-plugins", "win-capture");
            if (Directory.Exists(candidate)) { obsHookDir = candidate; break; }
        }

        var searchDirs = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
            UserProfile,
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                IEnumerable<string> dllFiles;
                try
                {
                    dllFiles = Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var filePath in dllFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(filePath);

                    var obsHookMatch = ObsHookDllNames.FirstOrDefault(n =>
                        n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
                    if (obsHookMatch is null) continue;

                    bool isInObsDir = obsHookDir is not null &&
                        filePath.StartsWith(obsHookDir, StringComparison.OrdinalIgnoreCase);
                    if (isInObsDir) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"OBS hook DLL in non-OBS location: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"OBS capture hook DLL '{fileName}' found outside OBS installation " +
                                 $"directory in '{dir}'. OBS game capture hooks (graphics-hook64/32.dll) " +
                                 "are injected into game processes by OBS to capture their frames. " +
                                 "A copy in a non-OBS location may indicate someone extracted and " +
                                 "modified OBS hooks to tamper with the capture pipeline, or is " +
                                 "using OBS hook DLLs as a bypass technique.",
                        Detail = $"Expected in OBS dir: {obsHookDir ?? "not found"} | Found at: {filePath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }

            await Task.Yield();
        }

        await CheckObsProcessInspectionBypassConfigsAsync(ctx, ct);
    }

    private async Task CheckObsProcessInspectionBypassConfigsAsync(ScanContext ctx, CancellationToken ct)
    {
        var obsAntiDetectKeywords = new[]
        {
            "obs.exe", "obs64.exe", "obs32.exe", "shadowplay.exe",
            "nvcapturesvc.exe", "discord.exe",
            "\"kill_obs\"", "\"close_obs\"", "kill_capture",
            "terminate_obs", "suspend_obs", "pause_obs",
            "\"obs_detected\"", "obs_check", "capture_check",
            "\"excluded_processes\"", "process_blacklist",
        };

        var searchDirs = new[]
        {
            TempPath, AppDataRoaming, AppDataLocal, Desktop, Downloads,
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> configFiles;
            try
            {
                configFiles = Directory.EnumerateFiles(dir, "*.json", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.EnumerateFiles(dir, "*.cfg", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.EnumerateFiles(dir, "*.ini", SearchOption.TopDirectoryOnly));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var filePath in configFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                var matched = obsAntiDetectKeywords
                    .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matched.Count < 2) continue;

                var fileName = Path.GetFileName(filePath);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"OBS/capture process detection in cheat config: {fileName}",
                    Risk = RiskLevel.High,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"Config file '{fileName}' references {matched.Count} OBS/capture process " +
                             $"detection keywords: {string.Join(", ", matched.Take(5))}. " +
                             "Some cheats scan the process list for OBS, ShadowPlay, and Discord " +
                             "and either refuse to run or switch to a capture-invisible mode when " +
                             "recording software is detected. These entries in a config file " +
                             "indicate anti-capture process scanning logic.",
                    Detail = $"OBS-related terms: {string.Join(", ", matched)}"
                });
            }

            await Task.Yield();
        }
    }

    private static void ScanRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        CheckSetWindowDisplayAffinityRegistry(ctx, ct);
        CheckDwmRegistryTampering(ctx, ct);
        CheckScreensaverPolicyRegistry(ctx, ct);
    }

    private static void CheckSetWindowDisplayAffinityRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string windowsKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var key = baseKey.OpenSubKey(windowsKey, writable: false);
            if (key is null) return;

            ctx.IncrementRegistryKeys();
            var loadedDlls = key.GetValue("LoadAppInit_DLLs");
            var appInitDlls = key.GetValue("AppInit_DLLs")?.ToString() ?? "";

            if (loadedDlls is int loaded && loaded == 1 && !string.IsNullOrWhiteSpace(appInitDlls))
            {
                var lowerDlls = appInitDlls.ToLowerInvariant();
                bool containsBypassDll = new[] { "bypass", "hook", "overlay", "capture", "hide", "stealth", "obs" }
                    .Any(kw => lowerDlls.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (containsBypassDll)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Streamer Mode Cheat Evasion Detection",
                        Title = "Suspicious AppInit_DLLs with bypass/hook keyword",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{windowsKey}\AppInit_DLLs",
                        Reason = "AppInit_DLLs registry value is enabled and contains a DLL with " +
                                 "bypass/hook/overlay in its name. AppInit_DLLs are loaded into every " +
                                 "process using user32.dll — a mechanism abused by capture bypass tools " +
                                 "to inject DWM hooks system-wide. Legitimate software rarely uses " +
                                 "AppInit_DLLs on modern Windows.",
                        Detail = $"AppInit_DLLs: {appInitDlls}"
                    });
                }
            }
        }
        catch { }
    }

    private static void CheckDwmRegistryTampering(ScanContext ctx, CancellationToken ct)
    {
        foreach (var regPath in RegistryDwmKeys)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var key = baseKey.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                var valueNames = key.GetValueNames();

                var suspectValues = valueNames.Where(v =>
                    v.Contains("hook", StringComparison.OrdinalIgnoreCase)
                    || v.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                    || v.Contains("disable", StringComparison.OrdinalIgnoreCase)
                    || v.Contains("capture", StringComparison.OrdinalIgnoreCase)
                    || v.Contains("exclude", StringComparison.OrdinalIgnoreCase)).ToList();

                if (suspectValues.Count == 0) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Streamer Mode Cheat Evasion Detection",
                    Title = $"Suspicious DWM registry value: {string.Join(", ", suspectValues.Take(3))}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{regPath}",
                    Reason = $"DWM/compositor registry key '{regPath}' contains suspicious values: " +
                             $"{string.Join(", ", suspectValues)}. Desktop Window Manager registry " +
                             "tampering can disable or redirect DWM capture hooks used by OBS and " +
                             "other screen recording software.",
                    Detail = $"Suspicious value names: {string.Join(", ", suspectValues)}"
                });
            }
            catch { }
        }
    }

    private static void CheckScreensaverPolicyRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string policyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        ct.ThrowIfCancellationRequested();
        ctx.IncrementRegistryKeys();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var key = baseKey.OpenSubKey(policyKey, writable: false);
            if (key is null) return;

            var disableScreenSaver = key.GetValue("DisableScreenSaver");
            var noDispScrSavPage = key.GetValue("NoDispScrSavPage");

            if ((disableScreenSaver is int dss && dss == 1)
                || (noDispScrSavPage is int ndsp && ndsp == 1))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Streamer Mode Cheat Evasion Detection",
                    Title = "Screen saver disabled via system policy",
                    Risk = RiskLevel.Low,
                    Location = $@"HKLM\{policyKey}",
                    Reason = "System policy has disabled the screen saver via registry. While this " +
                             "is benign alone, some cheat anti-forensics setups use policy tampering " +
                             "in combination with screenshot hooks. Flagged as a low-priority " +
                             "contextual indicator to review alongside other streamer mode findings.",
                    Detail = $"DisableScreenSaver: {disableScreenSaver} | NoDispScrSavPage: {noDispScrSavPage}"
                });
            }
        }
        catch { }
    }

    private static void ScanAutostartWindowTitleSpoofing(ScanContext ctx, CancellationToken ct)
    {
        foreach (var regPath in AutostartRegistryPaths)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                    using var key = baseKey.OpenSubKey(regPath, writable: false);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        var valueData = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        if (string.IsNullOrEmpty(valueData)) continue;

                        var lowerName = valueName.ToLowerInvariant();
                        var lowerData = valueData.ToLowerInvariant();

                        bool nameLooksLegit = WindowTitleSpoofingKeywords
                            .Any(t => lowerName.Contains(t, StringComparison.OrdinalIgnoreCase));

                        bool dataIsSuspicious = (lowerData.Contains("temp", StringComparison.OrdinalIgnoreCase)
                                || lowerData.Contains("appdata", StringComparison.OrdinalIgnoreCase)
                                || lowerData.Contains("downloads", StringComparison.OrdinalIgnoreCase))
                            && (lowerData.EndsWith(".exe") || lowerData.Contains(".exe\""));

                        bool dataHasSuspectDirName = new[]
                            { "cheat", "loader", "inject", "hack", "bypass", "aimbot", "esp", "payload" }
                            .Any(t => lowerData.Contains(t, StringComparison.OrdinalIgnoreCase));

                        if (nameLooksLegit && dataIsSuspicious)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Streamer Mode Cheat Evasion Detection",
                                Title = $"Autostart entry with spoofed name: {valueName}",
                                Risk = RiskLevel.High,
                                Location = $@"{(hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU")}\{regPath}\{valueName}",
                                Reason = $"Autostart registry entry '{valueName}' uses a name that resembles " +
                                         "a legitimate Windows application (Chrome, Notepad, etc.) but " +
                                         "points to an executable in a user-writable directory. " +
                                         "Window title spoofing is used by cheats to disguise their " +
                                         "windows in task lists and screen recordings, making them appear " +
                                         "as benign applications to casual observers.",
                                Detail = $"Value name: {valueName} | Points to: {valueData}"
                            });
                        }
                        else if (dataHasSuspectDirName && dataIsSuspicious)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Streamer Mode Cheat Evasion Detection",
                                Title = $"Autostart entry pointing to cheat-named path: {valueName}",
                                Risk = RiskLevel.High,
                                Location = $@"{(hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU")}\{regPath}\{valueName}",
                                Reason = $"Autostart entry '{valueName}' references a path with cheat-related " +
                                         "terms in a user directory. Cheat loaders with streamer mode " +
                                         "frequently add themselves to autostart to initialize capture " +
                                         "bypass hooks before OBS or the game launches.",
                                Detail = $"Data: {valueData}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
    }

    private static void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();

                try
                {
                    var procName = proc.ProcessName + ".exe";
                    var match = WindowHidingExecutables.FirstOrDefault(n =>
                        n.Equals(procName, StringComparison.OrdinalIgnoreCase));

                    if (match is not null)
                    {
                        string path = string.Empty;
                        try { path = proc.MainModule?.FileName ?? string.Empty; } catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = "Streamer Mode Cheat Evasion Detection",
                            Title = $"Window hiding tool currently running: {procName}",
                            Risk = RiskLevel.Critical,
                            Location = string.IsNullOrEmpty(path) ? $"PID {proc.Id}" : path,
                            FileName = procName,
                            Reason = $"Screen capture bypass tool '{procName}' is actively running. " +
                                     "An active window hider or OBS bypass tool means the cheat " +
                                     "is currently concealing itself from screen capture software. " +
                                     "This is a live evasion attempt against streaming and " +
                                     "anti-cheat screen recording.",
                            Detail = $"PID: {proc.Id} | Path: {path}"
                        });
                    }

                    var lowerProcName = proc.ProcessName.ToLowerInvariant();
                    bool isAntiCaptureTool =
                        lowerProcName.Contains("obs_bypass", StringComparison.OrdinalIgnoreCase)
                        || lowerProcName.Contains("obs_killer", StringComparison.OrdinalIgnoreCase)
                        || lowerProcName.Contains("obs_spoof", StringComparison.OrdinalIgnoreCase)
                        || lowerProcName.Contains("capture_bypass", StringComparison.OrdinalIgnoreCase)
                        || lowerProcName.Contains("screen_bypass", StringComparison.OrdinalIgnoreCase)
                        || lowerProcName.Contains("anti_obs", StringComparison.OrdinalIgnoreCase)
                        || lowerProcName.Contains("anti_capture", StringComparison.OrdinalIgnoreCase)
                        || lowerProcName.Contains("anti_screen", StringComparison.OrdinalIgnoreCase);

                    if (isAntiCaptureTool && match is null)
                    {
                        string path = string.Empty;
                        try { path = proc.MainModule?.FileName ?? string.Empty; } catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = "Streamer Mode Cheat Evasion Detection",
                            Title = $"Anti-capture tool process by name pattern: {procName}",
                            Risk = RiskLevel.Critical,
                            Location = string.IsNullOrEmpty(path) ? $"PID {proc.Id}" : path,
                            FileName = procName,
                            Reason = $"Running process '{procName}' has a name consistent with an " +
                                     "OBS bypass or screen capture avoidance tool. The process name " +
                                     "contains keywords (obs_bypass, anti_capture, screen_bypass, etc.) " +
                                     "that are specific to cheat evasion tools. This process is likely " +
                                     "actively hiding cheat components from recording software.",
                            Detail = $"PID: {proc.Id}"
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private async Task ScanAppDataForHiddenCheatDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        var streamerEvadeKeywords = new[]
        {
            "obs_bypass", "capture_bypass", "screen_bypass", "window_hide",
            "stealth_overlay", "anti_obs", "anti_capture", "dwm_hook",
            "obs_evade", "capture_evade", "shadowplay_bypass", "nvcapture_bypass",
            "dxgi_bypass", "wgc_bypass", "dx_overlay",
        };

        foreach (var baseDir in new[] { AppDataRoaming, AppDataLocal })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(subdir);

                bool isEvadeDirName = streamerEvadeKeywords.Any(kw =>
                    dirName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (isEvadeDirName)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Streamer evasion directory: {dirName}",
                        Risk = RiskLevel.Critical,
                        Location = subdir,
                        FileName = dirName,
                        Reason = $"Directory '{dirName}' in AppData has a name matching capture bypass " +
                                 "or streamer evasion patterns. Cheat tools with OBS/capture bypass " +
                                 "features create dedicated directories to store their evasion " +
                                 "components, hooks, and configuration. The directory name itself " +
                                 "is a strong indicator of streamer evasion software.",
                        Detail = $"Directory: {subdir}"
                    });
                }

                try
                {
                    IEnumerable<string> files;
                    try
                    {
                        files = Directory.EnumerateFiles(subdir, "*.dll", SearchOption.TopDirectoryOnly)
                            .Concat(Directory.EnumerateFiles(subdir, "*.exe", SearchOption.TopDirectoryOnly));
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var filePath in files)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(filePath);

                        var dwmMatch = DwmBypassDlls.FirstOrDefault(n =>
                            n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
                        if (dwmMatch is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DWM bypass DLL in AppData subdirectory: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason = $"DWM bypass library '{fileName}' found in AppData " +
                                         $"subdirectory '{dirName}'. This DLL is used to hook the " +
                                         "Desktop Window Manager to make cheat overlays invisible " +
                                         "to OBS, ShadowPlay, and other capture tools.",
                                Detail = $"Parent dir: {dirName} | Path: {filePath}"
                            });
                        }

                        var proxyMatch = ProxyDllNames.FirstOrDefault(n =>
                            n.Equals(fileName, StringComparison.OrdinalIgnoreCase));
                        if (proxyMatch is not null && isEvadeDirName)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DirectX proxy DLL in evasion directory: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason = $"System DLL '{fileName}' found in a capture evasion directory " +
                                         $"'{dirName}'. This is a proxy DLL prepared for deployment into " +
                                         "a game directory to intercept DirectX calls and add an overlay " +
                                         "that bypasses screen capture.",
                                Detail = $"Evasion dir: {subdir}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }

                await Task.Yield();
            }
        }
    }
}
