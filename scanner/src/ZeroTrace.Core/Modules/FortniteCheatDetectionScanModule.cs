using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FortniteCheatDetectionScanModule : IScanModule
{
    public string Name => "Fortnite Cheat Detection";
    public double Weight => 4.4;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Known Fortnite cheat executable / DLL names (80+ variants)
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> KnownCheatFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // fortnite_ prefix EXE variants
        "fortnite_aimbot.exe",
        "fortnite_hack.exe",
        "fortnite_cheat.exe",
        "fortnite_esp.exe",
        "fortnite_wallhack.exe",
        "fortnite_radar.exe",
        "fortnite_buildbot.exe",
        "fortnite_triggerbot.exe",
        "fortnite_speed.exe",
        "fortnite_no_recoil.exe",
        "fortnite_trainer.exe",
        "fortnite_external.exe",
        "fortnite_internal.exe",
        "fortnite_silent_aim.exe",
        "fortnite_spoofer.exe",
        "fortnite_injector.exe",
        "fortnite_loader.exe",
        "fortnite_bypass.exe",
        "fortnite_unlocker.exe",
        "fortnite_god.exe",
        "fortnite_menu.exe",
        "fortnite_mod.exe",
        "fortnite_exploit.exe",
        "fortnite_macro.exe",
        // fn_ prefix EXE variants
        "fn_hack.exe",
        "fn_cheat.exe",
        "fn_aimbot.exe",
        "fn_esp.exe",
        "fn_wallhack.exe",
        "fn_radar.exe",
        "fn_buildbot.exe",
        "fn_triggerbot.exe",
        "fn_speed.exe",
        "fn_no_recoil.exe",
        "fn_silent_aim.exe",
        "fn_spoofer.exe",
        "fn_injector.exe",
        "fn_loader.exe",
        "fn_bypass.exe",
        "fn_mod.exe",
        // compound EXE names
        "fortniteexploit.exe",
        "fortnitecheats.exe",
        "fortnitebot.exe",
        "fortnitegod.exe",
        "fortnitebuild.exe",
        "fortnitecrack.exe",
        "fortniteunlock.exe",
        "fortnitemenu.exe",
        "fortniteloader.exe",
        "fortniteinjector.exe",
        "fortnitespoofer.exe",
        "fortnitebypass.exe",
        "fortnitetrainer.exe",
        "fortniteaimbot.exe",
        "fortniteesp.exe",
        "fortnitewallhack.exe",
        // input device / build macro tools
        "rapid_build.exe",
        "build_macro.exe",
        "build_bot.exe",
        "rapid_fire.exe",
        "triggerbot.exe",
        "buildbot.exe",
        "rapidbuild.exe",
        "fn_rapid_fire.exe",
        "fn_build_macro.exe",
        // DLL variants
        "fortnite_hack.dll",
        "fortnite_cheat.dll",
        "fortnite_aimbot.dll",
        "fortnite_esp.dll",
        "fortnite_internal.dll",
        "fortnite_external.dll",
        "fortnite_injector.dll",
        "fn_hack.dll",
        "fn_cheat.dll",
        "fn_aimbot.dll",
        "fn_esp.dll",
        "fn_internal.dll",
        "fn_external.dll",
        "fn_bypass.dll",
        "fortnitehack.dll",
        "fortniteaimbot.dll",
        "fortniteesp.dll",
        "fortniteinternal.dll",
        // known brand loaders / menus targeting Fortnite
        "layla_fn.exe",
        "synapse_fn.exe",
        "phantom_fn.exe",
        "strike_fn.exe",
        "nexus_fn.exe",
    };

    // -------------------------------------------------------------------------
    // Cheat config / settings keywords found inside JSON / INI / CFG files
    // -------------------------------------------------------------------------
    private static readonly string[] CheatConfigKeywords =
    {
        "aimbot_settings",
        "esp_settings",
        "build_bot",
        "trigger_bot",
        "no_recoil",
        "speed_hack",
        "player_esp",
        "through_walls",
        "silent_aim",
        "bone_aimbot",
        "fov_circle",
        "prediction_enabled",
        "rapid_build",
        "instant_build",
        "auto_build",
        "material_hack",
        "no_spread",
    };

    // -------------------------------------------------------------------------
    // Known Fortnite cheat community / brand name strings found inside files
    // -------------------------------------------------------------------------
    private static readonly string[] KnownCheatCommunityStrings =
    {
        "skycheats fortnite",
        "aimware fortnite",
        "gamesense fortnite",
        "interwebz fn",
        "streamline fn",
        "layla fortnite",
        "synapse fortnite",
        "phantom fortnite",
        "strike cheats fn",
        "nexus fn cheat",
        "fn external cheat",
        "fortnite external",
        "fortnite internal cheat",
        "fn aimbot loader",
        "fn esp loader",
    };

    // -------------------------------------------------------------------------
    // Fortnite-specific data / config directory paths
    // -------------------------------------------------------------------------
    private static readonly string LocalApp =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string ProgramFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

    private static readonly string ProgramFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

    // -------------------------------------------------------------------------
    // Build macro / rapid fire script extensions worth scanning inside
    // -------------------------------------------------------------------------
    private static readonly string[] ScriptExtensions =
    {
        ".ahk", ".au3", ".lua", ".py", ".bat", ".ps1",
    };

    // -------------------------------------------------------------------------
    // Registry paths that carry execution evidence
    // -------------------------------------------------------------------------
    private static readonly string[] RunKeyPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    };

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------
    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Fortnite cheat artifact scan...");

        return Task.WhenAll(
            CheckKnownCheatFiles(ctx, ct),
            CheckEacBypassArtifacts(ctx, ct),
            CheckFortniteDataDirectories(ctx, ct),
            CheckCheatConfigFiles(ctx, ct),
            CheckInputMacroTools(ctx, ct),
            CheckRegistryMuiCache(ctx, ct),
            CheckRegistryUserAssist(ctx, ct),
            CheckRegistryRunKeys(ctx, ct)
        );
    }

    // -------------------------------------------------------------------------
    // Sub-check: known cheat EXE / DLL names on all fixed drives
    // -------------------------------------------------------------------------
    private Task CheckKnownCheatFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.05, Name, "Scanning drives for known Fortnite cheat files...");

            var searchRoots = new List<string>();

            // All fixed drives
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (ct.IsCancellationRequested) return;
                if (drive.DriveType != DriveType.Fixed) continue;
                try { if (!drive.IsReady) continue; } catch { continue; }
                searchRoots.Add(drive.RootDirectory.FullName);
            }

            // Additionally prioritise common cheat drop locations
            var commonDirs = new[]
            {
                Path.Combine(LocalApp,  "Temp"),
                Path.Combine(AppData,   "Temp"),
                Path.Combine(LocalApp,  "Programs"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            foreach (var dir in commonDirs)
            {
                if (Directory.Exists(dir) && !searchRoots.Any(r =>
                        dir.StartsWith(r, StringComparison.OrdinalIgnoreCase)))
                    searchRoots.Add(dir);
            }

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                await ScanDirectoryForCheatFiles(root, ctx, ct);
            }
        }, ct);
    }

    private static async Task ScanDirectoryForCheatFiles(string root, ScanContext ctx, CancellationToken ct)
    {
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) return;
            var dir = stack.Pop();

            string[] files = Array.Empty<string>();
            try
            {
                files = Directory.GetFiles(dir);
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                var fn = Path.GetFileName(file);
                if (!KnownCheatFileNames.Contains(fn)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module   = "Fortnite Cheat Detection",
                    Title    = $"Known Fortnite cheat file: {fn}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fn,
                    Reason   = $"File '{fn}' matches a known Fortnite cheat executable or DLL name. " +
                               "This file is associated with aimbot, ESP, wallhack, build-bot or " +
                               "trigger-bot functionality targeting Fortnite / EpicGames.",
                    Detail   = $"Full path: {file}",
                });
            }

            string[] subdirs = Array.Empty<string>();
            try
            {
                subdirs = Directory.GetDirectories(dir);
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            foreach (var sub in subdirs)
                stack.Push(sub);
        }

        await Task.CompletedTask;
    }

    // -------------------------------------------------------------------------
    // Sub-check: EasyAntiCheat bypass artifacts specific to Fortnite
    // -------------------------------------------------------------------------
    private Task CheckEacBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.15, Name, "Checking EasyAntiCheat integrity for Fortnite...");

            // EAC installs under %ProgramFiles%\EasyAntiCheat and
            // %ProgramFiles%\Epic Games\Fortnite\Engine\Binaries\...
            var eacRoots = new[]
            {
                Path.Combine(ProgramFiles,    "EasyAntiCheat"),
                Path.Combine(ProgramFilesX86, "EasyAntiCheat"),
                Path.Combine(ProgramFiles,    "Epic Games", "Fortnite"),
                Path.Combine(ProgramFilesX86, "Epic Games", "Fortnite"),
            };

            // Core EAC binaries that must be present and signed for Fortnite
            var eacCriticalFiles = new[]
            {
                "EasyAntiCheat.exe",
                "EasyAntiCheat.sys",
                "EasyAntiCheat_EOS.sys",
                "EasyAntiCheat_EOS.exe",
                "EasyAntiCheat_launcher.exe",
            };

            foreach (var eacRoot in eacRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(eacRoot)) continue;

                // Check each expected EAC binary
                foreach (var binaryName in eacCriticalFiles)
                {
                    if (ct.IsCancellationRequested) return;

                    // Search recursively up to 4 levels
                    string? found = null;
                    try
                    {
                        found = Directory.GetFiles(eacRoot, binaryName, SearchOption.AllDirectories)
                                         .FirstOrDefault();
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    if (found is null)
                    {
                        // Missing EAC binary is a red flag — bypass tools delete them
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Fortnite Cheat Detection",
                            Title    = $"EAC binary missing in Fortnite directory: {binaryName}",
                            Risk     = RiskLevel.High,
                            Location = eacRoot,
                            FileName = binaryName,
                            Reason   = $"EasyAntiCheat binary '{binaryName}' is absent from the " +
                                       $"Fortnite EAC directory '{eacRoot}'. EAC bypass tools " +
                                       "commonly delete or replace these files to disable kernel-level " +
                                       "anti-cheat protection.",
                            Detail   = $"Expected location: {Path.Combine(eacRoot, binaryName)}",
                        });
                    }
                    else
                    {
                        ctx.IncrementFiles();

                        // Check if it is unusually small (stub/placeholder)
                        try
                        {
                            var fi = new FileInfo(found);
                            if (fi.Length < 10_240) // less than 10 KB is implausible for EAC
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Fortnite Cheat Detection",
                                    Title    = $"Suspiciously small EAC binary: {binaryName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = found,
                                    FileName = binaryName,
                                    Reason   = $"EasyAntiCheat binary '{binaryName}' exists but is only " +
                                               $"{fi.Length} bytes — far smaller than a legitimate EAC binary. " +
                                               "Cheat bypass tools replace EAC binaries with stub files that " +
                                               "do nothing, disabling kernel-level scanning.",
                                    Detail   = $"File size: {fi.Length} bytes | Path: {found}",
                                });
                            }
                        }
                        catch (IOException) { }
                    }
                }

                // Look for known EAC bypass DLLs / patches dropped alongside legitimate EAC
                var bypassNames = new[]
                {
                    "EasyAntiCheat_patch.dll",
                    "EasyAntiCheat_bypass.dll",
                    "eac_bypass.dll",
                    "eac_patch.exe",
                    "eac_hook.dll",
                    "eac_disable.exe",
                    "eac_loader.exe",
                    "anticheat_bypass.exe",
                    "anticheatsdk_bypass.dll",
                };

                foreach (var bypassName in bypassNames)
                {
                    if (ct.IsCancellationRequested) return;
                    string? bypassFile = null;
                    try
                    {
                        bypassFile = Directory.GetFiles(eacRoot, bypassName, SearchOption.AllDirectories)
                                              .FirstOrDefault();
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    if (bypassFile is null) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Fortnite Cheat Detection",
                        Title    = $"EAC bypass artifact in Fortnite directory: {bypassName}",
                        Risk     = RiskLevel.Critical,
                        Location = bypassFile,
                        FileName = bypassName,
                        Reason   = $"Known EasyAntiCheat bypass file '{bypassName}' found inside the " +
                                   $"Fortnite EAC directory. This file is used to neutralise Fortnite's " +
                                   "kernel-level anti-cheat, enabling cheats that would otherwise be " +
                                   "detected and banned.",
                        Detail   = $"Path: {bypassFile}",
                    });
                }
            }

            await Task.CompletedTask;
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: Fortnite data directories — %LOCALAPPDATA%\EpicGamesLauncher,
    //            %LOCALAPPDATA%\FortniteGame, %APPDATA%\EpicGamesLauncher
    // -------------------------------------------------------------------------
    private Task CheckFortniteDataDirectories(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.25, Name, "Inspecting Fortnite data directories...");

            var dataDirs = new[]
            {
                Path.Combine(LocalApp, "EpicGamesLauncher"),
                Path.Combine(LocalApp, "FortniteGame"),
                Path.Combine(AppData,  "EpicGamesLauncher"),
                Path.Combine(LocalApp, "EpicGames"),
            };

            // File extensions that are suspicious inside these data directories
            var suspiciousExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".exe", ".dll", ".sys", ".drv", ".asi",
            };

            // EXE/DLL names that are legitimate in the Epic Games launcher tree
            var legitimateEpicFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "EpicGamesLauncher.exe",
                "EpicWebHelper.exe",
                "EpicOnlineServices.exe",
                "UnrealCEFSubProcess.exe",
                "EpicGamesLauncher.dll",
                "EpicOnlineServices.dll",
                "EOSSDK-Win64-Shipping.dll",
                "EOSSDK-Win32-Shipping.dll",
                "EpicGames.Aria2.dll",
            };

            foreach (var dataDir in dataDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dataDir)) continue;

                // Scan for suspicious executables in cache / temp subdirs
                var suspectSubdirs = new[] { "Saved", "Temp", "Cache", "Logs" };
                foreach (var sub in suspectSubdirs)
                {
                    if (ct.IsCancellationRequested) return;
                    var subPath = Path.Combine(dataDir, sub);
                    if (!Directory.Exists(subPath)) continue;

                    string[] files = Array.Empty<string>();
                    try { files = Directory.GetFiles(subPath, "*", SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    foreach (var file in files)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fn = Path.GetFileName(file);
                        var ext = Path.GetExtension(file);

                        if (!suspiciousExtensions.Contains(ext)) continue;
                        if (legitimateEpicFiles.Contains(fn)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Fortnite Cheat Detection",
                            Title    = $"Suspicious executable in Fortnite data directory: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Executable file '{fn}' found inside the Fortnite data " +
                                       $"directory '{subPath}'. Executables in launcher cache, log or " +
                                       "temp subdirectories are abnormal and may indicate a cheat dropper " +
                                       "or injector that placed itself alongside Epic Games files to avoid " +
                                       "detection.",
                            Detail   = $"Directory: {sub} | Full path: {file}",
                        });
                    }
                }

                // Look for cheat config files dropped into the Fortnite data tree
                await ScanDirectoryForCheatConfigs(dataDir, ctx, ct, maxDepth: 6);
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: cheat config / settings files with known cheat keywords
    // -------------------------------------------------------------------------
    private Task CheckCheatConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.35, Name, "Scanning for Fortnite cheat configuration files...");

            // Common cheat config file names
            var cheatConfigNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "aimbot_settings.json",
                "aimbot_settings.ini",
                "aimbot_settings.cfg",
                "esp_settings.json",
                "esp_settings.ini",
                "fortnite_config.json",
                "fortnite_config.ini",
                "fortnite_settings.json",
                "fn_config.json",
                "fn_config.ini",
                "fn_settings.json",
                "cheat_config.json",
                "cheat_config.ini",
                "cheat_settings.json",
                "hack_config.json",
                "loader_config.json",
                "config.json",
                "settings.json",
                "settings.ini",
                "config.ini",
            };

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.Combine(LocalApp, "Temp"),
                Path.Combine(AppData,  "Temp"),
                Path.Combine(LocalApp, "EpicGamesLauncher"),
                Path.Combine(LocalApp, "FortniteGame"),
                Path.Combine(AppData,  "EpicGamesLauncher"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files = Array.Empty<string>();
                try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    bool isNamedCheatConfig = cheatConfigNames.Contains(fn);
                    bool isTextFile = ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                                   || ext.Equals(".ini",  StringComparison.OrdinalIgnoreCase)
                                   || ext.Equals(".cfg",  StringComparison.OrdinalIgnoreCase)
                                   || ext.Equals(".txt",  StringComparison.OrdinalIgnoreCase);

                    if (!isNamedCheatConfig && !isTextFile) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    // Check for cheat config keywords
                    var hitKeyword = CheatConfigKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (hitKeyword is null)
                    {
                        // Also check for known community strings
                        hitKeyword = KnownCheatCommunityStrings.FirstOrDefault(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    }

                    if (hitKeyword is null && !isNamedCheatConfig) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Fortnite Cheat Detection",
                        Title    = hitKeyword is not null
                            ? $"Fortnite cheat config keyword found: {fn}"
                            : $"Suspicious Fortnite cheat config file: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = hitKeyword is not null
                            ? $"Config file '{fn}' contains the cheat keyword '{hitKeyword}', which is " +
                              "characteristic of Fortnite aimbot, ESP, build-bot, trigger-bot or speed-hack " +
                              "configuration files."
                            : $"File '{fn}' has a name matching a known Fortnite cheat configuration " +
                              "file pattern and may contain cheat settings.",
                        Detail   = hitKeyword is not null
                            ? $"Keyword: '{hitKeyword}' | Path: {file}"
                            : $"Path: {file}",
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Helper: scan a directory tree for cheat config files (used by multiple checks)
    // -------------------------------------------------------------------------
    private static async Task ScanDirectoryForCheatConfigs(
        string root, ScanContext ctx, CancellationToken ct, int maxDepth = 4)
    {
        var stack = new Stack<(string dir, int depth)>();
        stack.Push((root, 0));

        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) return;
            var (dir, depth) = stack.Pop();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir); }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                var ext = Path.GetExtension(file);
                if (!ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                 && !ext.Equals(".ini",  StringComparison.OrdinalIgnoreCase)
                 && !ext.Equals(".cfg",  StringComparison.OrdinalIgnoreCase))
                    continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var hitKeyword = CheatConfigKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase))
                    ?? KnownCheatCommunityStrings.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (hitKeyword is null) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module   = "Fortnite Cheat Detection",
                    Title    = $"Fortnite cheat config in Epic data directory: {Path.GetFileName(file)}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason   = $"File '{Path.GetFileName(file)}' in the Fortnite / Epic Games data tree " +
                               $"contains the cheat keyword '{hitKeyword}'. This suggests a cheat tool " +
                               "dropped its configuration alongside legitimate game files.",
                    Detail   = $"Keyword: '{hitKeyword}' | Path: {file}",
                });
            }

            if (depth >= maxDepth) continue;
            string[] subdirs = Array.Empty<string>();
            try { subdirs = Directory.GetDirectories(dir); }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            foreach (var sub in subdirs)
                stack.Push((sub, depth + 1));
        }
    }

    // -------------------------------------------------------------------------
    // Sub-check: input device macro tools for Fortnite build / trigger macros
    // -------------------------------------------------------------------------
    private Task CheckInputMacroTools(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.50, Name, "Scanning for Fortnite input macro tools and scripts...");

            var scriptSearchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.Combine(AppData, "AutoHotkey"),
                Path.Combine(LocalApp, "Programs"),
            };

            // Macro script content keywords specific to Fortnite build / combat macros
            var fortniteScriptKeywords = new[]
            {
                "rapid_build",
                "build_macro",
                "build_bot",
                "fortnite",
                "fn_macro",
                "rapidbuild",
                "buildbot",
                "instant_edit",
                "triggerbot",
                "rapid_fire",
                "no_recoil",
                "silent_aim",
                "aimbot",
                "fn_triggerbot",
                "fortnite_build",
                "wall_replace",
                "edit_turbo",
            };

            foreach (var dir in scriptSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files = Array.Empty<string>();
                try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    bool isScript = ScriptExtensions.Any(e =>
                        ext.Equals(e, StringComparison.OrdinalIgnoreCase));
                    if (!isScript) continue;

                    // Check filename first (fast path)
                    bool fileNameHit = fn.Contains("fortnite", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("build_macro", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("rapid_build", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("triggerbot", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("aimbot", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("no_recoil", StringComparison.OrdinalIgnoreCase);

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hitKeyword = fortniteScriptKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (hitKeyword is null && !fileNameHit) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Fortnite Cheat Detection",
                        Title    = $"Fortnite macro / input automation script: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = hitKeyword is not null
                            ? $"Script '{fn}' contains the keyword '{hitKeyword}', indicating a " +
                              "Fortnite build macro, rapid-fire tool, triggerbot or no-recoil script. " +
                              "Automated inputs violate Fortnite's terms of service."
                            : $"Script '{fn}' has a name referencing Fortnite macros or automation. " +
                              "Such scripts are used for automated building, triggerbots and aim assistance.",
                        Detail   = hitKeyword is not null
                            ? $"Keyword: '{hitKeyword}' | Path: {file}"
                            : $"Path: {file}",
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: MUICache — records the last-displayed name of executed apps
    // -------------------------------------------------------------------------
    private Task CheckRegistryMuiCache(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.60, Name, "Checking MUICache for Fortnite cheat execution evidence...");

            var muiPaths = new[]
            {
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache",
            };

            foreach (var muiPath in muiPaths)
            {
                if (ct.IsCancellationRequested) return;

                RegistryKey? key = null;
                try
                {
                    key = Registry.CurrentUser.OpenSubKey(muiPath, writable: false);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) break;
                        ctx.IncrementRegistryKeys();

                        var valueNameLower = valueName.ToLowerInvariant();
                        var fn = Path.GetFileName(valueName);

                        // Check against known cheat file names
                        if (!KnownCheatFileNames.Contains(fn))
                        {
                            // Also check for cheat keywords in the path
                            bool hasCheatKeyword =
                                valueNameLower.Contains("fortnite_hack", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("fortnite_cheat", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("fn_hack", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("fn_cheat", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("fn_aimbot", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("fortnitehack", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("fortniteaimbot", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("fortniteloader", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("fortniteinjector", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("build_bot", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("buildbot", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("rapid_build", StringComparison.OrdinalIgnoreCase)
                             || valueNameLower.Contains("triggerbot", StringComparison.OrdinalIgnoreCase);

                            if (!hasCheatKeyword) continue;
                        }

                        var displayName = key.GetValue(valueName) as string ?? string.Empty;

                        ctx.AddFinding(new Finding
                        {
                            Module   = "Fortnite Cheat Detection",
                            Title    = $"MUICache: Fortnite cheat execution evidence: {fn}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{muiPath}",
                            FileName = fn,
                            Reason   = $"MUICache entry '{valueName}' references a known or suspected " +
                                       "Fortnite cheat tool. MUICache records applications that were " +
                                       "launched by the user, providing evidence of prior execution even " +
                                       "if the file has since been deleted.",
                            Detail   = $"MUICache value: '{valueName}' | Display name: '{displayName}'",
                        });
                    }
                }
                catch { }
                finally { key?.Dispose(); }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: UserAssist (ROT13-encoded execution history in HKCU)
    // -------------------------------------------------------------------------
    private Task CheckRegistryUserAssist(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.70, Name, "Checking UserAssist for Fortnite cheat execution history...");

            var userAssistGuid = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            RegistryKey? uaRoot = null;
            try
            {
                uaRoot = Registry.CurrentUser.OpenSubKey(userAssistGuid, writable: false);
                if (uaRoot is null) return;

                foreach (var guidName in uaRoot.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;

                    RegistryKey? countKey = null;
                    try
                    {
                        countKey = uaRoot.OpenSubKey(Path.Combine(guidName, "Count"), writable: false);
                        if (countKey is null) continue;

                        foreach (var valueName in countKey.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) break;
                            ctx.IncrementRegistryKeys();

                            // Decode ROT13
                            var decoded = Rot13Decode(valueName);
                            var decodedLower = decoded.ToLowerInvariant();
                            var fn = Path.GetFileName(decoded);

                            bool isKnownCheat = KnownCheatFileNames.Contains(fn);
                            bool hasCheatKeyword = !isKnownCheat && (
                                   decodedLower.Contains("fortnite_hack", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("fortnite_cheat", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("fn_hack", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("fn_cheat", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("fn_aimbot", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("fortnitehack", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("fortniteaimbot", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("fortniteloader", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("fortniteinjector", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("build_bot", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("rapid_build", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("triggerbot", StringComparison.OrdinalIgnoreCase));

                            if (!isKnownCheat && !hasCheatKeyword) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = "Fortnite Cheat Detection",
                                Title    = $"UserAssist: Fortnite cheat execution record: {fn}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKCU\{userAssistGuid}\{guidName}\Count",
                                FileName = fn,
                                Reason   = $"UserAssist entry (ROT13-decoded: '{decoded}') indicates that a " +
                                           "known or suspected Fortnite cheat application was executed by the " +
                                           "user. UserAssist tracks GUI application launches and persists even " +
                                           "after the cheat tool has been deleted.",
                                Detail   = $"ROT13 raw: '{valueName}' | Decoded: '{decoded}'",
                            });
                        }
                    }
                    catch { }
                    finally { countKey?.Dispose(); }
                }
            }
            catch { }
            finally { uaRoot?.Dispose(); }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: Run / RunOnce startup registry keys
    // -------------------------------------------------------------------------
    private Task CheckRegistryRunKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.82, Name, "Checking Run/RunOnce keys for Fortnite cheat persistence...");

            var hives = new[] { Registry.LocalMachine, Registry.CurrentUser };

            foreach (var hive in hives)
            {
                foreach (var runPath in RunKeyPaths)
                {
                    if (ct.IsCancellationRequested) return;

                    RegistryKey? key = null;
                    try
                    {
                        key = hive.OpenSubKey(runPath, writable: false);
                        if (key is null) continue;

                        foreach (var valueName in key.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) break;
                            ctx.IncrementRegistryKeys();

                            var value = key.GetValue(valueName) as string ?? string.Empty;
                            var valueLower = value.ToLowerInvariant();
                            var fn = Path.GetFileName(value.Trim('"').Split(' ')[0]);

                            bool isKnownCheat = KnownCheatFileNames.Contains(fn);
                            bool hasCheatKeyword = !isKnownCheat && (
                                   valueLower.Contains("fortnite_hack", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("fortnite_cheat", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("fn_hack", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("fn_cheat", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("fn_aimbot", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("fortnitehack", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("fortniteaimbot", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("fortniteinjector", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("build_bot", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("rapid_build", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("triggerbot", StringComparison.OrdinalIgnoreCase));

                            if (!isKnownCheat && !hasCheatKeyword) continue;

                            var hivePrefix = ReferenceEquals(hive, Registry.LocalMachine)
                                ? "HKLM" : "HKCU";

                            ctx.AddFinding(new Finding
                            {
                                Module   = "Fortnite Cheat Detection",
                                Title    = $"Run key: Fortnite cheat autostart entry: {valueName}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"{hivePrefix}\{runPath}",
                                FileName = fn,
                                Reason   = $"Autostart registry entry '{valueName}' in '{hivePrefix}\\{runPath}' " +
                                           $"points to a suspected Fortnite cheat tool: '{value}'. " +
                                           "Run/RunOnce keys cause the cheat tool to launch automatically " +
                                           "at Windows startup, establishing cheat persistence.",
                                Detail   = $"Value name: '{valueName}' | Command: '{value}'",
                            });
                        }
                    }
                    catch { }
                    finally { key?.Dispose(); }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Helper: ROT13 decode for UserAssist
    // -------------------------------------------------------------------------
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
}
