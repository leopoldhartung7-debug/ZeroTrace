using System.Diagnostics;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class SpeedHackTimerScanModule : IScanModule
{
    public string Name => "Speed Hack & Timer Manipulation Scan";
    public double Weight => 3.6;
    public int ParallelGroup => 4;

    private const string ModuleName = "SpeedHackTimer";

    // ── Known speed hack executable names ───────────────────────────────────

    private static readonly HashSet<string> KnownSpeedHackExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "speedhack.exe",
        "speedhack32.exe",
        "speedhack64.exe",
        "gamespeed.exe",
        "timerhack.exe",
        "timewarp.exe",
        "timeflow.exe",
        "timemaster.exe",
        "gamespeedchanger.exe",
        "speedmultiplier.exe",
        "speedbooster.exe",
        "speedmaster.exe",
        "fasthack.exe",
        "fasthacker.exe",
        "winhack.exe",
        "winspeeder.exe",
        "game_speed.exe",
        "speed_cheat.exe",
        "cheat_speed.exe",
        "speedtool.exe",
        "gamespeedtool.exe",
        "velocityhack.exe",
        "speedhackpro.exe",
        "speedinjector.exe",
        "timehack.exe",
        "timecheat.exe",
        "artmoneyspeed.exe",
        "artmoney.exe",
        "artmoney32.exe",
        "artmoney64.exe",
        "pspeed.exe",
        "xspeed.exe",
        "omnispeed.exe",
        "speedometer.exe",
        "turbospeed.exe",
        "maxspeed.exe",
        "ultraspeed.exe",
        "cheatspeed.exe",
        "hackspeed.exe",
        "gta5speedhack.exe",
        "fivem_speed.exe",
        "mcspeed.exe",
        "robloxspeed.exe",
        "rblxspeed.exe",
    };

    // ── Known speed hack DLL names ───────────────────────────────────────────

    private static readonly HashSet<string> KnownSpeedHackDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "speedhack32.dll",
        "speedhack64.dll",
        "speedhack.dll",
        "gamespeed.dll",
        "timewarp.dll",
        "timeflow.dll",
        "timeroverride.dll",
        "timerpatch.dll",
        "timerreplace.dll",
        "gethookdll.dll",
        "tickcounthook.dll",
        "queryperf.dll",
        "qpchook.dll",
        "rdtsckeystone.dll",
        "speedmultiplier.dll",
        "speedhookdll.dll",
        "speedhack_x64.dll",
        "speedhack_x86.dll",
        "cetrainer_speed.dll",
        "trainer_speed.dll",
        "gamespeedchanger.dll",
        "omnispeed.dll",
        "pspeed.dll",
        "speedinjector.dll",
        "artmoney_speed.dll",
        "timepatch.dll",
        "clockhook.dll",
        "clockpatch.dll",
        "gettickcounthook.dll",
        "ntdll_speed_hook.dll",
        "kernel32_speed_hook.dll",
        "d3d_speed.dll",
        "dx_speed.dll",
        "robloxspeed.dll",
        "minecraftspeed.dll",
        "fivemspeed.dll",
        "winhook.dll",
        "speedwrapper.dll",
        "speedlib.dll",
        "libspeed.dll",
        "speedhax.dll",
    };

    // ── Cheat Engine speed-hack-related file name patterns ───────────────────

    private static readonly string[] CheatEngineSpeedPatterns =
    {
        "cheatengine",
        "ce_speed",
        "ce-speed",
        "cetrainer",
        "ce_trainer",
        "cespeed",
        "speedhack_ce",
        "ce_speedhack",
        "tutorial-i386",
        "tutorial-x86_64",
    };

    // ── File content signatures for speed hack source/config ─────────────────

    private static readonly string[] FileContentSpeedHackSignatures =
    {
        "SpeedHackEnable",
        "speedhack_enabled",
        "speed_multiplier",
        "game_speed_multiplier",
        "speedhack=",
        "speed_hack=",
        "speedfactor=",
        "speed_factor=",
        "gamespeed=",
        "game_speed=",
        "timescale=",
        "time_scale=",
        "timeScale",
        "SetSpeed(",
        "SetGameSpeed(",
        "SetSpeedHack(",
        "EnableSpeedHack(",
        "DisableSpeedHack(",
        "SpeedHackFactor",
        "SpeedHackMultiplier",
        "SpeedMultiplier",
        "timeBeginPeriod(1)",
        "timeBeginPeriod(0)",
        "NtSetTimerResolution",
        "ZwSetTimerResolution",
        "SetThreadExecutionState",
        "SetWaitableTimerEx",
        "QueryPerformanceCounter",
        "GetTickCount64",
        "timeGetTime",
        "GetTickCountHook",
        "QPC_hook",
        "qpc_hook",
        "tick_count_hook",
        "TickCountHook",
        "VirtualProtect.*GetTickCount",
        "patch_gettickcount",
        "hook_gettickcount",
        "hook_queryperformancecounter",
        "WriteProcessMemory.*timer",
        "wpm.*timer",
        "game_loop_speed",
        "physics_speed",
        "simulation_speed",
        "dt_multiplier",
        "delta_time_multiplier",
        "frame_time_multiplier",
        "fivem.*speed",
        "fivem.*fps.*unlock",
        "gta.*speed.*hack",
        "minecraft.*speed",
        "roblox.*speed",
        "bhop.*speed",
        "bunny.*hop.*speed",
        "autohop",
        "speed_bhop",
        "bhop_speed",
        "move_speed",
        "walk_speed_hack",
        "run_speed_hack",
        "swim_speed",
        "fly_speed_hack",
        "no_slowdown",
        "remove_slowdown",
        "bypass_slowdown",
        "ctypes.*VirtualProtect",
        "ctypes.*WriteProcessMemory",
        "ctypes.*GetTickCount",
        "win32api.*timer",
        "win32api.*speed",
        "SetSuspendState.*speed",
        "SleepEx.*0.*speed",
        "timeBeginPeriod",
        "winmm.*BeginPeriod",
    };

    // ── AutoHotkey / AutoIt speed hack script signatures ─────────────────────

    private static readonly string[] AutoHotkeySpeedHackSignatures =
    {
        "SetTimer",
        "speed_hack",
        "SpeedHack",
        "game_speed",
        "Loop.*Send.*{Space}",
        "bhop",
        "bunny",
        "autohop",
        "WheelDown::Send {Space}",
        "WheelUp::Send {Space}",
        "SpeedMultiplier",
        "speed_multiplier",
        "fast_walk",
        "speedrun",
    };

    // ── Registry keys for multimedia timer resolution ─────────────────────────

    private static readonly (string Key, string Value)[] TimerResolutionRegistryTargets =
    {
        (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile", "SystemResponsiveness"),
        (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Priority"),
        (@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games", "Scheduling Category"),
        (@"SYSTEM\CurrentControlSet\Services\NtFsd", "Start"),
        (@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "LargeSystemCache"),
    };

    // ── Registry Run keys that may persist speed hack tools ──────────────────

    private static readonly string[] RunKeyPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    };

    // ── ArtMoney speed feature registry artifacts ─────────────────────────────

    private static readonly string[] ArtMoneyRegistryPaths =
    {
        @"SOFTWARE\ArtMoney",
        @"SOFTWARE\Art Money",
        @"SOFTWARE\WOW6432Node\ArtMoney",
    };

    // ── Process Hacker speed manipulation plugin registry paths ──────────────

    private static readonly string[] ProcessHackerPluginPaths =
    {
        @"SOFTWARE\ProcessHacker",
        @"SOFTWARE\Process Hacker 2",
        @"SOFTWARE\Process Hacker 3",
        @"SOFTWARE\NTKernelResources\WinPmem",
    };

    // ── Known speed hack search directories ──────────────────────────────────

    private static readonly string[] SpeedHackSearchRoots;

    static SpeedHackTimerScanModule()
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
        roots.Add(Path.Combine(localAppData, "Programs"));
        roots.Add(Path.Combine(appData, "CheatEngine"));
        roots.Add(Path.Combine(localAppData, "CheatEngine"));
        roots.Add(Path.Combine(appData, "ArtMoney"));
        roots.Add(Path.Combine(localAppData, "Temp"));
        roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"));

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        roots.Add(programFiles);
        roots.Add(programFilesX86);

        SpeedHackSearchRoots = roots.Where(r => !string.IsNullOrEmpty(r)).ToArray();
    }

    // ── Python ctypes speed hack script indicators ───────────────────────────

    private static readonly string[] PythonSpeedHackIndicators =
    {
        "import ctypes",
        "VirtualProtect",
        "WriteProcessMemory",
        "GetTickCount",
        "QueryPerformanceCounter",
        "timeBeginPeriod",
        "NtSetTimerResolution",
        "speed_multiplier",
        "game_speed",
        "SpeedHack",
        "timer_resolution",
        "winmm",
        "ntdll",
        "ctypes.windll.winmm",
        "ctypes.windll.ntdll",
        "ctypes.windll.kernel32.GetTickCount",
    };

    // ─────────────────────────────────────────────────────────────────────────

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.00, ModuleName, "Scanning running processes for speed hack tools...");
        ScanRunningProcesses(ctx, ct);

        ctx.Report(0.10, ModuleName, "Scanning file system for speed hack executables...");
        await ScanFileSystemAsync(ctx, ct);

        ctx.Report(0.45, ModuleName, "Scanning for speed hack DLLs in game directories...");
        await ScanGameDirectoriesForDllsAsync(ctx, ct);

        ctx.Report(0.60, ModuleName, "Scanning AutoHotkey/AutoIt scripts for speed hack patterns...");
        await ScanScriptFilesAsync(ctx, ct);

        ctx.Report(0.70, ModuleName, "Scanning Python scripts for timer manipulation...");
        await ScanPythonScriptsAsync(ctx, ct);

        ctx.Report(0.78, ModuleName, "Scanning registry for timer resolution abuse...");
        ScanTimerResolutionRegistry(ctx, ct);

        ctx.Report(0.83, ModuleName, "Scanning registry Run keys for speed hack persistence...");
        ScanRunKeysForSpeedHack(ctx, ct);

        ctx.Report(0.88, ModuleName, "Scanning for ArtMoney speed feature artifacts...");
        ScanArtMoneyArtifacts(ctx, ct);

        ctx.Report(0.92, ModuleName, "Scanning for Process Hacker plugin speed manipulation...");
        ScanProcessHackerArtifacts(ctx, ct);

        ctx.Report(0.96, ModuleName, "Scanning for Cheat Engine speed hack trainer files...");
        await ScanCheatEngineTrainersAsync(ctx, ct);

        ctx.Report(1.00, ModuleName, "Speed hack scan complete.");
    }

    // ── Process scan ─────────────────────────────────────────────────────────

    private static void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var snapshot = ctx.GetProcessSnapshot();
        foreach (var proc in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            string procName = proc.ProcessName + ".exe";
            if (!KnownSpeedHackExeNames.Contains(procName))
                continue;

            string location = string.Empty;
            try { location = proc.MainModule?.FileName ?? string.Empty; } catch { }

            ctx.AddFinding(new Finding
            {
                Module = ModuleName,
                Title = $"Speed hack process running: {proc.ProcessName}",
                Risk = RiskLevel.Critical,
                Location = location,
                FileName = procName,
                Reason = $"Process '{proc.ProcessName}' (PID {proc.Id}) is a known speed hack tool that manipulates game timing " +
                         "by hooking GetTickCount, QueryPerformanceCounter, or patching the game loop timer.",
                Detail = $"PID={proc.Id} Name={proc.ProcessName}",
            });
        }

        foreach (var proc in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            string lowerName = proc.ProcessName.ToLowerInvariant();

            bool ceMatch = false;
            foreach (var pattern in CheatEngineSpeedPatterns)
            {
                if (lowerName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ceMatch = true;
                    break;
                }
            }
            if (!ceMatch) continue;

            string location = string.Empty;
            try { location = proc.MainModule?.FileName ?? string.Empty; } catch { }

            ctx.AddFinding(new Finding
            {
                Module = ModuleName,
                Title = $"Cheat Engine variant with speed hack capability running: {proc.ProcessName}",
                Risk = RiskLevel.High,
                Location = location,
                FileName = proc.ProcessName + ".exe",
                Reason = $"Process '{proc.ProcessName}' matches Cheat Engine naming patterns. " +
                         "Cheat Engine includes a built-in speed hack feature that manipulates game timing globally by " +
                         "intercepting Windows timer APIs.",
                Detail = $"PID={proc.Id}",
            });
        }
    }

    // ── File system scan ─────────────────────────────────────────────────────

    private static async Task ScanFileSystemAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in SpeedHackSearchRoots)
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

                if (KnownSpeedHackExeNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Speed hack executable found: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"'{fileName}' is a known speed hack tool. Found at '{file}'. " +
                                 "Speed hacks manipulate Windows timer APIs to make the game think less time has passed, " +
                                 "granting movement speed, fire rate, reload speed, and cooldown reduction advantages.",
                        Detail = $"Path={file}",
                    });
                    continue;
                }

                if (KnownSpeedHackDllNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Speed hack DLL found: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"'{fileName}' is a known speed hack injection DLL. Found at '{file}'. " +
                                 "This DLL hooks or replaces timer functions (GetTickCount, QueryPerformanceCounter) " +
                                 "inside the game process to manipulate timing.",
                        Detail = $"Path={file}",
                    });
                    continue;
                }

                if (fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    var lowerFileName = fileName.ToLowerInvariant();
                    if (lowerFileName.Contains("speedhack") || lowerFileName.Contains("speed_hack") ||
                        lowerFileName.Contains("timewarp") || lowerFileName.Contains("timehack") ||
                        lowerFileName.Contains("gamespeed") || lowerFileName.Contains("game_speed") ||
                        lowerFileName.Contains("timeflow") || lowerFileName.Contains("timemaster") ||
                        (lowerFileName.Contains("speed") && lowerFileName.Contains("hack")) ||
                        (lowerFileName.Contains("speed") && lowerFileName.Contains("cheat")))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Suspicious speed hack binary name: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"'{fileName}' has a name pattern consistent with speed hack tools. " +
                                     "Found at '{file}'.",
                            Detail = $"Path={file}",
                        });
                    }
                }
            }

            IEnumerable<string> subDirs;
            try
            {
                subDirs = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var subDir in subDirs)
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(subDir).ToLowerInvariant();
                if (!dirName.Contains("speedhack") && !dirName.Contains("speed_hack") &&
                    !dirName.Contains("timewarp") && !dirName.Contains("gamespeed") &&
                    !dirName.Contains("timemaster") && !dirName.Contains("timeflow") &&
                    !dirName.Contains("timerhack") && !dirName.Contains("cheatengine") &&
                    !dirName.Contains("artmoney"))
                    continue;

                IEnumerable<string> subFiles;
                try
                {
                    subFiles = Directory.EnumerateFiles(subDir, "*.*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var subFile in subFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var subFileName = Path.GetFileName(subFile);

                    if (KnownSpeedHackExeNames.Contains(subFileName) || KnownSpeedHackDllNames.Contains(subFileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Speed hack artifact in suspicious directory: {subFileName}",
                            Risk = RiskLevel.Critical,
                            Location = subFile,
                            FileName = subFileName,
                            Reason = $"Speed hack binary '{subFileName}' found inside directory '{subDir}' " +
                                     "which has a name consistent with speed hack or timer manipulation tools.",
                            Detail = $"Dir={subDir} File={subFile}",
                        });
                    }
                }
            }

            await ScanDirectoryForConfigsAsync(ctx, root, ct);
        }
    }

    // ── Game directory DLL scan ───────────────────────────────────────────────

    private static async Task ScanGameDirectoriesForDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var gameRoots = new List<string>();

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var knownGamePaths = new[]
        {
            Path.Combine(programFiles, "Steam", "steamapps", "common"),
            Path.Combine(programFilesX86, "Steam", "steamapps", "common"),
            Path.Combine(programFiles, "Epic Games"),
            Path.Combine(programFilesX86, "Epic Games"),
            Path.Combine(programFiles, "Rockstar Games"),
            Path.Combine(programFilesX86, "Rockstar Games"),
            Path.Combine(programFiles, "FiveM"),
            Path.Combine(programFilesX86, "FiveM"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FiveM"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FiveM"),
            Path.Combine(programFiles, "Minecraft"),
            Path.Combine(programFilesX86, "Minecraft Launcher"),
        };

        foreach (var gp in knownGamePaths)
        {
            if (Directory.Exists(gp))
                gameRoots.Add(gp);
        }

        foreach (var gameRoot in gameRoots)
        {
            ct.ThrowIfCancellationRequested();

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
                if (!KnownSpeedHackDllNames.Contains(dllName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"Speed hack DLL injected into game directory: {dllName}",
                    Risk = RiskLevel.Critical,
                    Location = dll,
                    FileName = dllName,
                    Reason = $"Known speed hack DLL '{dllName}' was found inside a game directory at '{dll}'. " +
                             "Placing a timer-hook DLL in the game directory causes it to load automatically at game " +
                             "startup via DLL search order hijacking, enabling persistent speed manipulation.",
                    Detail = $"GameRoot={gameRoot} DllPath={dll}",
                });
            }
        }

        await Task.CompletedTask;
    }

    // ── Script file scan ──────────────────────────────────────────────────────

    private static async Task ScanScriptFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var scriptExts = new[] { "*.ahk", "*.au3" };
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            foreach (var ext in scriptExts)
            {
                IEnumerable<string> scriptFiles;
                try
                {
                    scriptFiles = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var scriptFile in scriptFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    int matchCount = 0;
                    var matchedSigs = new List<string>();
                    foreach (var sig in AutoHotkeySpeedHackSignatures)
                    {
                        if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            matchedSigs.Add(sig);
                        }
                    }

                    if (matchCount >= 2)
                    {
                        string ext2 = Path.GetExtension(scriptFile).ToLowerInvariant();
                        string tool = ext2 == ".ahk" ? "AutoHotkey" : "AutoIt";
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"{tool} speed hack script detected: {Path.GetFileName(scriptFile)}",
                            Risk = RiskLevel.High,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = $"{tool} script '{Path.GetFileName(scriptFile)}' contains {matchCount} speed hack " +
                                     $"indicators including: {string.Join(", ", matchedSigs.Take(5))}. " +
                                     $"{tool} scripts can automate speed hacks via keyboard/mouse input loops, " +
                                     "bhop/bunny hop automation, or timer manipulation.",
                            Detail = $"Path={scriptFile} Matches={string.Join("|", matchedSigs)}",
                        });
                    }
                }
            }
        }
    }

    // ── Python script scan ────────────────────────────────────────────────────

    private static async Task ScanPythonScriptsAsync(ScanContext ctx, CancellationToken ct)
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

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> pyFiles;
            try
            {
                pyFiles = Directory.EnumerateFiles(root, "*.py", SearchOption.AllDirectories);
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
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                int matchCount = 0;
                var matchedSigs = new List<string>();
                foreach (var sig in PythonSpeedHackIndicators)
                {
                    if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        matchCount++;
                        matchedSigs.Add(sig);
                    }
                }

                if (matchCount >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Python speed/timer hack script: {Path.GetFileName(pyFile)}",
                        Risk = RiskLevel.High,
                        Location = pyFile,
                        FileName = Path.GetFileName(pyFile),
                        Reason = $"Python script '{Path.GetFileName(pyFile)}' contains {matchCount} indicators of " +
                                 $"timer manipulation via ctypes: {string.Join(", ", matchedSigs.Take(5))}. " +
                                 "Python scripts using ctypes can call VirtualProtect/WriteProcessMemory to patch " +
                                 "GetTickCount or QueryPerformanceCounter in a running game process.",
                        Detail = $"Path={pyFile} Signatures={string.Join("|", matchedSigs)}",
                    });
                }
            }
        }
    }

    // ── Timer resolution registry scan ────────────────────────────────────────

    private static void ScanTimerResolutionRegistry(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        using var sysProfile = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile");

        if (sysProfile != null)
        {
            ctx.IncrementRegistryKeys();
            var sysResponsiveness = sysProfile.GetValue("SystemResponsiveness");
            if (sysResponsiveness is int srVal && srVal == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = "Multimedia SystemResponsiveness set to 0 (timer manipulation artifact)",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                    Reason = "SystemResponsiveness=0 dedicates 100% of CPU scheduling to foreground tasks. " +
                             "Speed hack tools set this value to minimize timer interrupt jitter, " +
                             "making fine-grained timer manipulation (1ms resolution) more reliable.",
                    Detail = "SystemResponsiveness=0",
                });
            }
        }

        using var gamesProfile = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games");

        if (gamesProfile != null)
        {
            ctx.IncrementRegistryKeys();
            var priority = gamesProfile.GetValue("Priority");
            var schedulingCat = gamesProfile.GetValue("Scheduling Category") as string;
            var sfioThrottled = gamesProfile.GetValue("SFIO Throttle") as string;
            var gpuPriority = gamesProfile.GetValue("GPU Priority");
            var affinitySet = gamesProfile.GetValue("Affinity");

            if (priority is int prioVal && prioVal >= 6)
            {
                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = "Multimedia Games task priority elevated to maximum (timer abuse indicator)",
                    Risk = RiskLevel.Low,
                    Location = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                    Reason = $"Games task Priority={prioVal} (max=6). Speed hack tools raise this to ensure " +
                             "their timer-hooking threads get maximum CPU scheduling priority over the game's own timer threads.",
                    Detail = $"Priority={prioVal} SchedulingCategory={schedulingCat} SFIOThrottle={sfioThrottled}",
                });
            }
        }

        ct.ThrowIfCancellationRequested();

        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            foreach (var (keyPath, valueName) in TimerResolutionRegistryTargets)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = hive.OpenSubKey(keyPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                }
                catch (Exception) { }
            }
        }

        using var timerResKey = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Session Manager\kernel");
        if (timerResKey != null)
        {
            ctx.IncrementRegistryKeys();
            var globalTimerRes = timerResKey.GetValue("GlobalTimerResolutionRequests");
            if (globalTimerRes is int gtrVal && gtrVal == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = "GlobalTimerResolutionRequests enabled (forced 1ms timer resolution)",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
                    Reason = "GlobalTimerResolutionRequests=1 enforces 1ms system timer resolution globally, " +
                             "even for processes that called timeBeginPeriod(1). Speed hack tools set this " +
                             "to make timer hooking precise — particularly for manipulating GetTickCount and " +
                             "QueryPerformanceCounter to spoof elapsed game time.",
                    Detail = "GlobalTimerResolutionRequests=1",
                });
            }
        }
    }

    // ── Run key scan ─────────────────────────────────────────────────────────

    private static void ScanRunKeysForSpeedHack(ScanContext ctx, CancellationToken ct)
    {
        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            foreach (var runKeyPath in RunKeyPaths)
            {
                ct.ThrowIfCancellationRequested();
                using var runKey = hive.OpenSubKey(runKeyPath);
                if (runKey == null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in runKey.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var val = runKey.GetValue(valueName) as string ?? string.Empty;
                    var valLower = val.ToLowerInvariant();
                    var nameLower = valueName.ToLowerInvariant();

                    bool nameMatch = nameLower.Contains("speedhack") || nameLower.Contains("speed_hack") ||
                                     nameLower.Contains("gamespeed") || nameLower.Contains("timewarp") ||
                                     nameLower.Contains("timeflow") || nameLower.Contains("artmoney");

                    bool valueMatch = false;
                    foreach (var dllName in KnownSpeedHackDllNames)
                    {
                        if (valLower.Contains(dllName.ToLowerInvariant()))
                        {
                            valueMatch = true;
                            break;
                        }
                    }
                    if (!valueMatch)
                    {
                        foreach (var exeName in KnownSpeedHackExeNames)
                        {
                            if (valLower.Contains(exeName.ToLowerInvariant()))
                            {
                                valueMatch = true;
                                break;
                            }
                        }
                    }

                    if (nameMatch || valueMatch)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Speed hack tool persisted in registry Run key: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"{(hive == Registry.CurrentUser ? "HKCU" : "HKLM")}\{runKeyPath}",
                            Reason = $"Registry Run key '{valueName}' = '{val}' references a speed hack tool. " +
                                     "This causes the speed hack to launch automatically at every Windows startup, " +
                                     "ensuring persistent timer manipulation even after game restarts.",
                            Detail = $"Key={valueName} Value={val}",
                        });
                    }
                }
            }
        }
    }

    // ── ArtMoney artifact scan ────────────────────────────────────────────────

    private static void ScanArtMoneyArtifacts(ScanContext ctx, CancellationToken ct)
    {
        foreach (var amPath in ArtMoneyRegistryPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(amPath)
                             ?? Registry.CurrentUser.OpenSubKey(amPath);
                if (key == null) continue;

                ctx.IncrementRegistryKeys();

                var speedEnabled = key.GetValue("SpeedHackEnabled")
                                ?? key.GetValue("EnableSpeedHack")
                                ?? key.GetValue("SpeedEnabled");

                if (speedEnabled != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = "ArtMoney speed hack feature enabled in registry",
                        Risk = RiskLevel.High,
                        Location = amPath,
                        Reason = "ArtMoney's built-in speed hack feature is enabled. ArtMoney is a memory editor that " +
                                 "includes a speed hack component that manipulates the Windows multimedia timer to slow " +
                                 "or accelerate game speed, giving advantages in timing-dependent game mechanics.",
                        Detail = $"SpeedEnabled={speedEnabled}",
                    });
                }
                else
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = "ArtMoney installation detected (speed hack capability)",
                        Risk = RiskLevel.Medium,
                        Location = amPath,
                        Reason = "ArtMoney is installed. While primarily a memory editor, ArtMoney includes a built-in " +
                                 "speed hack that manipulates Windows timer resolution and GetTickCount return values " +
                                 "to control game speed. Its presence alongside gaming activity is suspicious.",
                        Detail = $"RegistryPath={amPath}",
                    });
                }
            }
            catch (Exception) { }
        }

        var artMoneyAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "ArtMoney");

        if (Directory.Exists(artMoneyAppData))
        {
            ctx.IncrementFiles();
            IEnumerable<string> amFiles;
            try
            {
                amFiles = Directory.EnumerateFiles(artMoneyAppData, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var amFile in amFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var amFileName = Path.GetFileName(amFile).ToLowerInvariant();
                if (amFileName.Contains("speed") || amFileName.Contains("timer") || amFileName.Contains("hack"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"ArtMoney speed hack configuration file: {Path.GetFileName(amFile)}",
                        Risk = RiskLevel.High,
                        Location = amFile,
                        FileName = Path.GetFileName(amFile),
                        Reason = "ArtMoney configuration file referencing speed/timer functionality found in " +
                                 "ArtMoney's application data directory. Indicates active configuration of " +
                                 "ArtMoney's speed hack feature.",
                        Detail = $"Path={amFile}",
                    });
                }
            }
        }
    }

    // ── Process Hacker artifact scan ──────────────────────────────────────────

    private static void ScanProcessHackerArtifacts(ScanContext ctx, CancellationToken ct)
    {
        foreach (var phPath in ProcessHackerPluginPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(phPath)
                             ?? Registry.CurrentUser.OpenSubKey(phPath);
                if (key == null) continue;

                ctx.IncrementRegistryKeys();

                var pluginsDir = key.GetValue("PluginsDirectory") as string ?? string.Empty;

                if (!string.IsNullOrEmpty(pluginsDir) && Directory.Exists(pluginsDir))
                {
                    IEnumerable<string> plugins;
                    try
                    {
                        plugins = Directory.EnumerateFiles(pluginsDir, "*.dll", SearchOption.TopDirectoryOnly);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var plugin in plugins)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var pluginName = Path.GetFileName(plugin).ToLowerInvariant();
                        if (pluginName.Contains("speed") || pluginName.Contains("timer") ||
                            pluginName.Contains("suspend") || pluginName.Contains("inject"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = ModuleName,
                                Title = $"Process Hacker speed/timer manipulation plugin: {Path.GetFileName(plugin)}",
                                Risk = RiskLevel.High,
                                Location = plugin,
                                FileName = Path.GetFileName(plugin),
                                Reason = $"Process Hacker plugin '{Path.GetFileName(plugin)}' found in plugins directory. " +
                                         "Process Hacker plugins with speed/timer/suspend capability can freeze game threads " +
                                         "selectively or manipulate process timing to achieve speed hack effects.",
                                Detail = $"PluginPath={plugin} PHKey={phPath}",
                            });
                        }
                    }
                }
            }
            catch (Exception) { }
        }
    }

    // ── Cheat Engine trainer scan ─────────────────────────────────────────────

    private static async Task ScanCheatEngineTrainersAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        var trainerExtensions = new[] { "*.CT", "*.ct", "*.cetrainer" };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            foreach (var ext in trainerExtensions)
            {
                IEnumerable<string> trainerFiles;
                try
                {
                    trainerFiles = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var trainerFile in trainerFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(trainerFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    int matchCount = 0;
                    var matches = new List<string>();
                    foreach (var sig in FileContentSpeedHackSignatures)
                    {
                        if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            matches.Add(sig);
                            if (matchCount >= 10) break;
                        }
                    }

                    if (matchCount >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Cheat Engine trainer with speed hack entries: {Path.GetFileName(trainerFile)}",
                            Risk = RiskLevel.High,
                            Location = trainerFile,
                            FileName = Path.GetFileName(trainerFile),
                            Reason = $"Cheat Engine table/trainer '{Path.GetFileName(trainerFile)}' contains " +
                                     $"{matchCount} speed hack signatures including: {string.Join(", ", matches.Take(5))}. " +
                                     "CE trainers with speed hack entries use Cheat Engine's built-in speedhack " +
                                     "feature or script timer manipulation via LUA scripting.",
                            Detail = $"Path={trainerFile} Signatures={string.Join("|", matches)}",
                        });
                    }
                }
            }
        }
    }

    // ── Config file scan helper ───────────────────────────────────────────────

    private static async Task ScanDirectoryForConfigsAsync(ScanContext ctx, string root, CancellationToken ct)
    {
        var configExtensions = new[] { "*.ini", "*.cfg", "*.json", "*.xml", "*.txt", "*.config" };

        foreach (var ext in configExtensions)
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
                bool nameRelevant = cfgFileName.Contains("speed") || cfgFileName.Contains("timer") ||
                                    cfgFileName.Contains("hack") || cfgFileName.Contains("cheat") ||
                                    cfgFileName.Contains("trainer") || cfgFileName.Contains("artmoney");

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
                foreach (var sig in FileContentSpeedHackSignatures)
                {
                    if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        matchCount++;
                        matches.Add(sig);
                        if (matchCount >= 10) break;
                    }
                }

                if (matchCount >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Speed hack configuration file detected: {Path.GetFileName(cfgFile)}",
                        Risk = RiskLevel.High,
                        Location = cfgFile,
                        FileName = Path.GetFileName(cfgFile),
                        Reason = $"Configuration file '{Path.GetFileName(cfgFile)}' contains {matchCount} speed hack " +
                                 $"indicators: {string.Join(", ", matches.Take(5))}. " +
                                 "This file configures speed hack behavior (multiplier values, targeted timer functions, " +
                                 "or game-specific speed settings).",
                        Detail = $"Path={cfgFile} Matches={string.Join("|", matches)}",
                    });
                }
            }
        }
    }
}
