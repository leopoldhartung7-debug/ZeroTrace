using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RainbowSixSiegeCheatScanModule : IScanModule
{
    public string Name => "Rainbow Six Siege Cheat Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Known Rainbow Six Siege cheat executable / DLL names (80+ variants)
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> KnownCheatFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // r6_ prefix EXE variants
        "r6_hack.exe",
        "r6_cheat.exe",
        "r6_aimbot.exe",
        "r6_esp.exe",
        "r6_wallhack.exe",
        "r6_radar.exe",
        "r6_no_recoil.exe",
        "r6_no_spread.exe",
        "r6_triggerbot.exe",
        "r6_speed.exe",
        "r6_god.exe",
        "r6_silent_aim.exe",
        "r6_spoofer.exe",
        "r6_injector.exe",
        "r6_loader.exe",
        "r6_bypass.exe",
        "r6_trainer.exe",
        "r6_external.exe",
        "r6_internal.exe",
        "r6_menu.exe",
        "r6_drone.exe",
        "r6_rapid_fire.exe",
        "r6_macro.exe",
        // r6siege_ prefix EXE variants
        "r6siege_hack.exe",
        "r6siege_cheat.exe",
        "r6siege_aimbot.exe",
        "r6siege_esp.exe",
        "r6siege_wallhack.exe",
        "r6siege_no_recoil.exe",
        "r6siege_triggerbot.exe",
        "r6siege_trainer.exe",
        "r6siege_spoofer.exe",
        "r6siege_injector.exe",
        "r6siege_loader.exe",
        "r6siege_bypass.exe",
        "r6siege_external.exe",
        "r6siege_internal.exe",
        // siege_ prefix EXE variants
        "siege_hack.exe",
        "siege_cheat.exe",
        "siege_aimbot.exe",
        "siege_esp.exe",
        "siege_wallhack.exe",
        "siege_no_recoil.exe",
        "siege_triggerbot.exe",
        "siege_trainer.exe",
        "siege_spoofer.exe",
        "siege_injector.exe",
        "siege_loader.exe",
        "siege_bypass.exe",
        "siege_external.exe",
        "siege_internal.exe",
        "siege_drone.exe",
        "siege_camera.exe",
        "siege_radar.exe",
        "siege_speed.exe",
        "siege_god.exe",
        // rainbowsix_ / rainbow6_ prefix EXE variants
        "rainbowsix_hack.exe",
        "rainbowsix_cheat.exe",
        "rainbowsix_aimbot.exe",
        "rainbowsix_esp.exe",
        "rainbowsix_wallhack.exe",
        "rainbowsix_loader.exe",
        "rainbowsix_injector.exe",
        "rainbow6_hack.exe",
        "rainbow6_cheat.exe",
        "rainbow6_aimbot.exe",
        "rainbow6_esp.exe",
        "rainbow6_wallhack.exe",
        "rainbow6_loader.exe",
        // drone / camera / thermal hack tools
        "drone_hack.exe",
        "camera_hack.exe",
        "thermal_hack.exe",
        "drone_esp.exe",
        "camera_esp.exe",
        // rapid fire / macro tools
        "r6_rapid_fire.exe",
        "r6_macro.exe",
        "rapid_fire.ahk",
        "no_recoil.ahk",
        "r6_no_recoil.ahk",
        "r6_triggerbot.ahk",
        "siege_macro.ahk",
        // DLL variants
        "r6_hack.dll",
        "r6_cheat.dll",
        "r6_aimbot.dll",
        "r6_esp.dll",
        "r6_internal.dll",
        "r6_external.dll",
        "r6_injector.dll",
        "r6_bypass.dll",
        "r6siege_hack.dll",
        "r6siege_cheat.dll",
        "r6siege_aimbot.dll",
        "r6siege_esp.dll",
        "siege_hack.dll",
        "siege_cheat.dll",
        "siege_aimbot.dll",
        "siege_esp.dll",
        "siege_internal.dll",
        "siege_bypass.dll",
        "rainbowsix_hack.dll",
        "rainbowsix_cheat.dll",
        // known brand loaders / menus targeting R6S
        "gamesense_r6.exe",
        "aimware_r6.exe",
        "skycheats_r6.exe",
        "interwebz_r6.exe",
        "streamline_r6.exe",
        "layla_r6.exe",
        "synapse_r6.exe",
    };

    // -------------------------------------------------------------------------
    // Cheat config / settings keywords found inside JSON / INI / CFG files
    // -------------------------------------------------------------------------
    private static readonly string[] CheatConfigKeywords =
    {
        "aimbot",
        "esp",
        "wallhack",
        "no_recoil",
        "laser_sight",
        "drone_esp",
        "through_smoke",
        "see_through_gadget",
        "no_spread",
        "silent_aim",
        "bone_aimbot",
        "fov_circle",
        "prediction_enabled",
        "operator_esp",
        "thermal_vision",
        "through_wall",
        "camera_hack",
        "rapid_fire",
        "triggerbot",
    };

    // -------------------------------------------------------------------------
    // Known R6S cheat community / brand name strings found inside files
    // -------------------------------------------------------------------------
    private static readonly string[] KnownCheatCommunityStrings =
    {
        "gamesense r6",
        "aimware r6",
        "skycheats r6",
        "interwebz r6",
        "streamline r6",
        "layla r6",
        "r6 external cheat",
        "r6 internal cheat",
        "siege aimbot loader",
        "siege esp loader",
        "rainbow six siege hack",
        "rainbow six siege cheat",
        "r6s aimbot",
        "r6s wallhack",
        "r6s no recoil",
    };

    // -------------------------------------------------------------------------
    // Ubisoft Connect DLL names that cheat tools replace with stubs
    // -------------------------------------------------------------------------
    private static readonly string[] UbisoftIntegrityDlls =
    {
        "uplay_r2.dll",
        "ubi_services.dll",
        "upc_r2.dll",
        "uplaypc_r2.dll",
        "uplay_r2_loader.dll",
        "ubisoft_connect.dll",
    };

    // -------------------------------------------------------------------------
    // R6S data / config directory base paths
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
    // Script extensions to scan for macro content
    // -------------------------------------------------------------------------
    private static readonly string[] ScriptExtensions =
    {
        ".ahk", ".au3", ".lua", ".py", ".bat", ".ps1",
    };

    // -------------------------------------------------------------------------
    // Registry Run/RunOnce paths
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
        ctx.Report(0.0, Name, "Starting Rainbow Six Siege cheat artifact scan...");

        return Task.WhenAll(
            CheckKnownCheatFiles(ctx, ct),
            CheckBattleEyeBypassArtifacts(ctx, ct),
            CheckR6SDataDirectories(ctx, ct),
            CheckCheatConfigFiles(ctx, ct),
            CheckDroneCameraHackTools(ctx, ct),
            CheckRapidFireMacroTools(ctx, ct),
            CheckUbisoftConnectIntegrity(ctx, ct),
            CheckRegistryMuiCache(ctx, ct),
            CheckRegistryUserAssist(ctx, ct),
            CheckRegistryRunKeys(ctx, ct),
            CheckRegistryUninstallRecords(ctx, ct)
        );
    }

    // -------------------------------------------------------------------------
    // Sub-check: known cheat EXE / DLL names on all fixed drives
    // -------------------------------------------------------------------------
    private Task CheckKnownCheatFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.05, Name, "Scanning drives for known R6S cheat files...");

            var searchRoots = new List<string>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (ct.IsCancellationRequested) return;
                if (drive.DriveType != DriveType.Fixed) continue;
                try { if (!drive.IsReady) continue; } catch { continue; }
                searchRoots.Add(drive.RootDirectory.FullName);
            }

            // High-priority drop locations
            var priorityDirs = new[]
            {
                Path.Combine(LocalApp,  "Temp"),
                Path.Combine(AppData,   "Temp"),
                Path.Combine(LocalApp,  "Programs"),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            foreach (var dir in priorityDirs)
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
                    Module   = "Rainbow Six Siege Cheat Detection",
                    Title    = $"Known R6S cheat file: {fn}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fn,
                    Reason   = $"File '{fn}' matches a known Rainbow Six Siege cheat executable or DLL name. " +
                               "This file is associated with aimbot, ESP, wallhack, no-recoil, drone ESP " +
                               "or trigger-bot functionality targeting Rainbow Six Siege / Ubisoft.",
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
    // Sub-check: BattlEye bypass artifacts specific to R6S
    // -------------------------------------------------------------------------
    private Task CheckBattleEyeBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.13, Name, "Checking BattlEye integrity for Rainbow Six Siege...");

            // R6S game directory candidates
            var r6GameRoots = new[]
            {
                Path.Combine(ProgramFiles,    "Ubisoft", "Ubisoft Game Launcher", "games",
                             "Tom Clancy's Rainbow Six Siege"),
                Path.Combine(ProgramFilesX86, "Ubisoft", "Ubisoft Game Launcher", "games",
                             "Tom Clancy's Rainbow Six Siege"),
                Path.Combine(ProgramFiles,    "Rainbow Six Siege"),
                Path.Combine(ProgramFilesX86, "Rainbow Six Siege"),
            };

            // BattlEye expected files within the game's BattlEye subdirectory
            var beExpectedFiles = new[]
            {
                "BEClient.dll",
                "BEClient_x64.dll",
                "BEService.exe",
                "BEService_x64.exe",
                "BattlEye.dll",
                "Battleye_launcher.exe",
            };

            // Known BattlEye bypass file names dropped into R6S directories
            var beBypassNames = new[]
            {
                "BEClient_bypass.dll",
                "BEClient_stub.dll",
                "BEClient_patch.dll",
                "BEService_bypass.exe",
                "BEService_stub.exe",
                "battleye_bypass.dll",
                "battleye_patch.dll",
                "be_bypass.dll",
                "be_hook.dll",
                "anticheat_bypass.exe",
                "be_disable.exe",
            };

            foreach (var gameRoot in r6GameRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(gameRoot)) continue;

                var beDir = Path.Combine(gameRoot, "BattlEye");

                // Check that BattlEye directory exists at all
                if (!Directory.Exists(beDir))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Rainbow Six Siege Cheat Detection",
                        Title    = "BattlEye directory missing from R6S installation",
                        Risk     = RiskLevel.Critical,
                        Location = gameRoot,
                        FileName = "BattlEye",
                        Reason   = "The BattlEye anti-cheat directory is absent from the Rainbow Six Siege " +
                                   $"installation at '{gameRoot}'. BattlEye bypass tools sometimes remove or " +
                                   "rename the entire BattlEye directory to prevent the anti-cheat from loading.",
                        Detail   = $"Expected: {beDir}",
                    });
                    continue;
                }

                // Check each expected BE file
                foreach (var binaryName in beExpectedFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var binaryPath = Path.Combine(beDir, binaryName);

                    if (!File.Exists(binaryPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Rainbow Six Siege Cheat Detection",
                            Title    = $"BattlEye binary missing in R6S: {binaryName}",
                            Risk     = RiskLevel.High,
                            Location = beDir,
                            FileName = binaryName,
                            Reason   = $"BattlEye file '{binaryName}' is absent from the R6S BattlEye " +
                                       $"directory '{beDir}'. BattlEye bypass tools delete or replace these " +
                                       "files to disable kernel-level anti-cheat protection.",
                            Detail   = $"Expected: {binaryPath}",
                        });
                        continue;
                    }

                    ctx.IncrementFiles();

                    // Check for stub files (implausibly small)
                    try
                    {
                        var fi = new FileInfo(binaryPath);
                        if (fi.Length < 8_192)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Rainbow Six Siege Cheat Detection",
                                Title    = $"Suspiciously small BattlEye binary: {binaryName}",
                                Risk     = RiskLevel.Critical,
                                Location = binaryPath,
                                FileName = binaryName,
                                Reason   = $"BattlEye file '{binaryName}' exists but is only {fi.Length} bytes. " +
                                           "Legitimate BattlEye binaries are significantly larger. " +
                                           "Bypass tools replace them with stub files that do nothing, " +
                                           "disabling anti-cheat scanning for Rainbow Six Siege.",
                                Detail   = $"File size: {fi.Length} bytes | Path: {binaryPath}",
                            });
                        }
                    }
                    catch (IOException) { }
                }

                // Check whether BEService is disabled in registry
                try
                {
                    ctx.IncrementRegistryKeys();
                    using var beServiceKey = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\BEService", writable: false);
                    if (beServiceKey is not null)
                    {
                        var startType = beServiceKey.GetValue("Start") as int?;
                        if (startType.HasValue && startType.Value == 4) // 4 = Disabled
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Rainbow Six Siege Cheat Detection",
                                Title    = "BattlEye service (BEService) is disabled",
                                Risk     = RiskLevel.Critical,
                                Location = @"HKLM\SYSTEM\CurrentControlSet\Services\BEService",
                                Reason   = "The BattlEye service 'BEService' is configured as Disabled " +
                                           "(Start=4) in the registry. BattlEye bypass tools disable this " +
                                           "service to prevent the kernel-level anti-cheat from running " +
                                           "when Rainbow Six Siege is launched.",
                                Detail   = $"Start type: {startType} (4 = Disabled)",
                            });
                        }
                    }
                }
                catch { }

                // Look for known BE bypass DLLs / patches inside the game tree
                foreach (var bypassName in beBypassNames)
                {
                    if (ct.IsCancellationRequested) return;
                    string? bypassFile = null;
                    try
                    {
                        bypassFile = Directory.GetFiles(gameRoot, bypassName, SearchOption.AllDirectories)
                                              .FirstOrDefault();
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    if (bypassFile is null) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Rainbow Six Siege Cheat Detection",
                        Title    = $"BattlEye bypass artifact in R6S directory: {bypassName}",
                        Risk     = RiskLevel.Critical,
                        Location = bypassFile,
                        FileName = bypassName,
                        Reason   = $"Known BattlEye bypass file '{bypassName}' found inside the " +
                                   $"Rainbow Six Siege game directory. This file is used to neutralise " +
                                   "BattlEye's kernel-level anti-cheat, enabling cheats that would " +
                                   "otherwise be detected and result in a ban.",
                        Detail   = $"Path: {bypassFile}",
                    });
                }
            }

            await Task.CompletedTask;
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: R6S data directories —
    //   %LOCALAPPDATA%\Ubisoft Game Launcher
    //   %APPDATA%\Ubisoft
    //   %LOCALAPPDATA%\Rainbow Six Siege
    // -------------------------------------------------------------------------
    private Task CheckR6SDataDirectories(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.24, Name, "Inspecting R6S and Ubisoft data directories...");

            var dataDirs = new[]
            {
                Path.Combine(LocalApp, "Ubisoft Game Launcher"),
                Path.Combine(LocalApp, "Ubisoft"),
                Path.Combine(LocalApp, "Rainbow Six Siege"),
                Path.Combine(AppData,  "Ubisoft"),
                Path.Combine(AppData,  "Ubisoft Game Launcher"),
            };

            var suspiciousExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".exe", ".dll", ".sys", ".drv", ".asi",
            };

            // DLL/EXE names that are legitimately part of Ubisoft Connect
            var legitimateUbisoftFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "UbisoftGameLauncher.exe",
                "UplayWebCore.exe",
                "UbisoftConnect.exe",
                "upc.exe",
                "uplay_r2.dll",
                "ubi_services.dll",
                "upc_r2.dll",
                "uplaypc_r2.dll",
                "EOSSDK-Win64-Shipping.dll",
                "EOSSDK-Win32-Shipping.dll",
            };

            foreach (var dataDir in dataDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dataDir)) continue;

                // Check cache / temp / log subdirectories for dropped executables
                var suspectSubdirs = new[] { "cache", "temp", "logs", "tmp", "data" };
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
                        if (legitimateUbisoftFiles.Contains(fn)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Rainbow Six Siege Cheat Detection",
                            Title    = $"Suspicious executable in Ubisoft/R6S data directory: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Executable file '{fn}' found inside the Ubisoft/R6S data " +
                                       $"directory '{subPath}'. Executables in launcher cache, log or " +
                                       "temp subdirectories are abnormal and may indicate a cheat dropper " +
                                       "or injector placed alongside Ubisoft Connect files to evade detection.",
                            Detail   = $"Directory: {sub} | Full path: {file}",
                        });
                    }
                }

                // Scan for cheat config files inside the Ubisoft / R6S data tree
                await ScanDirectoryForCheatConfigs(dataDir, ctx, ct, maxDepth: 5);
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: R6S cheat configuration files
    // -------------------------------------------------------------------------
    private Task CheckCheatConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.35, Name, "Scanning for R6S cheat configuration files...");

            var cheatConfigNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "r6_config.json",
                "r6_config.ini",
                "siege_config.json",
                "siege_config.ini",
                "r6siege_config.json",
                "r6siege_config.ini",
                "r6_settings.json",
                "siege_settings.json",
                "r6_aimbot.json",
                "r6_esp.json",
                "r6_wallhack.json",
                "r6_cheat.json",
                "r6_cheat.ini",
                "cheat_config.json",
                "cheat_config.ini",
                "hack_config.json",
                "loader_config.json",
                "aimbot_settings.json",
                "aimbot_settings.ini",
                "esp_settings.json",
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
                Path.Combine(LocalApp, "Ubisoft Game Launcher"),
                Path.Combine(LocalApp, "Rainbow Six Siege"),
                Path.Combine(AppData,  "Ubisoft"),
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

                    var hitKeyword = CheatConfigKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (hitKeyword is null)
                    {
                        hitKeyword = KnownCheatCommunityStrings.FirstOrDefault(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    }

                    if (hitKeyword is null && !isNamedCheatConfig) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Rainbow Six Siege Cheat Detection",
                        Title    = hitKeyword is not null
                            ? $"R6S cheat config keyword found: {fn}"
                            : $"Suspicious R6S cheat config file: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = hitKeyword is not null
                            ? $"Config file '{fn}' contains the cheat keyword '{hitKeyword}', which is " +
                              "characteristic of Rainbow Six Siege aimbot, ESP, wallhack, no-recoil, " +
                              "drone ESP, laser-sight or through-smoke configuration files."
                            : $"File '{fn}' has a name matching a known R6S cheat configuration " +
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
    // Helper: scan a directory tree for cheat config content
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
                    Module   = "Rainbow Six Siege Cheat Detection",
                    Title    = $"R6S cheat config in Ubisoft data directory: {Path.GetFileName(file)}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason   = $"File '{Path.GetFileName(file)}' in the R6S / Ubisoft data tree " +
                               $"contains the cheat keyword '{hitKeyword}'. This suggests a cheat tool " +
                               "dropped its configuration alongside legitimate Ubisoft files.",
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
    // Sub-check: drone / camera / thermal hack artifacts
    // -------------------------------------------------------------------------
    private Task CheckDroneCameraHackTools(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.47, Name, "Scanning for R6S drone/camera hack tools...");

            var droneCameraHackNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "drone_hack.exe",
                "camera_hack.exe",
                "thermal_hack.exe",
                "drone_esp.exe",
                "camera_esp.exe",
                "r6_drone_hack.exe",
                "r6_camera_hack.exe",
                "siege_drone_hack.exe",
                "siege_camera_hack.exe",
                "drone_wallhack.exe",
                "thermal_vision.exe",
                "r6_thermal.exe",
                "siege_thermal.exe",
                "drone_bypass.exe",
                "operator_esp.exe",
                "r6_operator_esp.exe",
                "siege_operator.exe",
            };

            var droneCameraKeywords = new[]
            {
                "drone_esp",
                "camera_hack",
                "thermal_vision",
                "operator_esp",
                "see_through_gadget",
                "through_smoke",
                "camera_esp",
                "drone_hack",
                "drone_wallhack",
                "see_drones",
                "show_operators",
            };

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.Combine(LocalApp, "Temp"),
                Path.Combine(AppData,  "Temp"),
                Path.Combine(LocalApp, "Programs"),
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

                    if (droneCameraHackNames.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Rainbow Six Siege Cheat Detection",
                            Title    = $"R6S drone/camera hack file: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' matches a known Rainbow Six Siege drone ESP, " +
                                       "camera hack or thermal vision cheat tool. These tools give " +
                                       "players unfair visibility through cameras, drones and gadgets.",
                            Detail   = $"Full path: {file}",
                        });
                        continue;
                    }

                    bool isScript = ScriptExtensions.Any(e =>
                        ext.Equals(e, StringComparison.OrdinalIgnoreCase));
                    if (!isScript) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hitKeyword = droneCameraKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hitKeyword is null) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Rainbow Six Siege Cheat Detection",
                        Title    = $"R6S drone/camera hack keyword in script: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Script '{fn}' contains the keyword '{hitKeyword}', indicating a " +
                                   "Rainbow Six Siege drone ESP, camera hack, thermal vision or " +
                                   "through-smoke cheat tool.",
                        Detail   = $"Keyword: '{hitKeyword}' | Path: {file}",
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: rapid fire / no-recoil macro tools
    // -------------------------------------------------------------------------
    private Task CheckRapidFireMacroTools(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.57, Name, "Scanning for R6S rapid fire and no-recoil macro tools...");

            var rapidFireKeywords = new[]
            {
                "rapid_fire",
                "no_recoil",
                "no recoil",
                "rapidfire",
                "norecoil",
                "r6_macro",
                "siege_macro",
                "triggerbot",
                "trigger_bot",
                "r6_triggerbot",
                "siege_triggerbot",
                "rapid fire",
                "no_spread",
                "no spread",
                "rainbow six",
                "r6siege",
                "siege_fire",
                "r6_fire",
            };

            var scriptDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.Combine(AppData, "AutoHotkey"),
                Path.Combine(AppData, "Logitech", "GHUB", "profiles"),
                Path.Combine(AppData, "Logitech Gaming Software", "profiles"),
                Path.Combine(LocalApp, "Programs"),
                Path.Combine(LocalApp, "Temp"),
            };

            foreach (var dir in scriptDirs)
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

                    bool fileNameHit = fn.Contains("r6", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("siege", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("rainbow", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("no_recoil", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("rapid_fire", StringComparison.OrdinalIgnoreCase)
                                    || fn.Contains("triggerbot", StringComparison.OrdinalIgnoreCase);

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hitKeyword = rapidFireKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (hitKeyword is null && !fileNameHit) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Rainbow Six Siege Cheat Detection",
                        Title    = $"R6S rapid fire / no-recoil macro: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = hitKeyword is not null
                            ? $"Script '{fn}' contains the keyword '{hitKeyword}', indicating a " +
                              "Rainbow Six Siege rapid fire, no-recoil or triggerbot macro. " +
                              "Automated inputs violate Ubisoft's terms of service and BattlEye policies."
                            : $"Script '{fn}' has a name referencing R6S macros or automation. " +
                              "Such scripts are used for rapid fire, no-recoil and triggerbots.",
                        Detail   = hitKeyword is not null
                            ? $"Keyword: '{hitKeyword}' | Path: {file}"
                            : $"Path: {file}",
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: Ubisoft Connect integrity — modified uplay_r2.dll / ubi_services.dll
    // -------------------------------------------------------------------------
    private Task CheckUbisoftConnectIntegrity(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.65, Name, "Checking Ubisoft Connect DLL integrity...");

            var ubisoftRoots = new[]
            {
                Path.Combine(ProgramFiles,    "Ubisoft", "Ubisoft Game Launcher"),
                Path.Combine(ProgramFilesX86, "Ubisoft", "Ubisoft Game Launcher"),
                Path.Combine(ProgramFiles,    "Ubisoft Connect"),
                Path.Combine(ProgramFilesX86, "Ubisoft Connect"),
            };

            var r6GameRoots = new[]
            {
                Path.Combine(ProgramFiles,    "Ubisoft", "Ubisoft Game Launcher", "games",
                             "Tom Clancy's Rainbow Six Siege"),
                Path.Combine(ProgramFilesX86, "Ubisoft", "Ubisoft Game Launcher", "games",
                             "Tom Clancy's Rainbow Six Siege"),
                Path.Combine(ProgramFiles,    "Rainbow Six Siege"),
                Path.Combine(ProgramFilesX86, "Rainbow Six Siege"),
            };

            var allRoots = ubisoftRoots.Concat(r6GameRoots).ToArray();

            foreach (var root in allRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                foreach (var dllName in UbisoftIntegrityDlls)
                {
                    if (ct.IsCancellationRequested) return;

                    string? dllPath = null;
                    try
                    {
                        dllPath = Directory.GetFiles(root, dllName, SearchOption.AllDirectories)
                                           .FirstOrDefault();
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    if (dllPath is null) continue;
                    ctx.IncrementFiles();

                    try
                    {
                        var fi = new FileInfo(dllPath);

                        // A legitimate uplay_r2.dll is typically > 1 MB; stub is tiny
                        if (fi.Length < 65_536)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Rainbow Six Siege Cheat Detection",
                                Title    = $"Suspiciously small Ubisoft Connect DLL: {dllName}",
                                Risk     = RiskLevel.Critical,
                                Location = dllPath,
                                FileName = dllName,
                                Reason   = $"Ubisoft Connect library '{dllName}' at '{dllPath}' is only " +
                                           $"{fi.Length} bytes. Legitimate versions are hundreds of kilobytes " +
                                           "or larger. Cheat tools replace these DLLs with stub versions that " +
                                           "bypass authentication and anti-cheat checks.",
                                Detail   = $"File size: {fi.Length} bytes | Path: {dllPath}",
                            });
                        }

                        // Recently modified outside a game update window is suspicious
                        var daysSinceModified = (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays;
                        if (daysSinceModified < 1)
                        {
                            var launcherExes = new[] { "UbisoftGameLauncher.exe", "UbisoftConnect.exe", "upc.exe" };
                            bool launcherAlsoUpdated = false;
                            foreach (var exeName in launcherExes)
                            {
                                var exePath = Path.Combine(root, exeName);
                                if (!File.Exists(exePath)) continue;
                                try
                                {
                                    launcherAlsoUpdated =
                                        (DateTime.UtcNow - new FileInfo(exePath).LastWriteTimeUtc).TotalDays < 1;
                                    if (launcherAlsoUpdated) break;
                                }
                                catch (IOException) { }
                            }

                            if (!launcherAlsoUpdated)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Rainbow Six Siege Cheat Detection",
                                    Title    = $"Ubisoft Connect DLL modified outside update: {dllName}",
                                    Risk     = RiskLevel.High,
                                    Location = dllPath,
                                    FileName = dllName,
                                    Reason   = $"Ubisoft Connect DLL '{dllName}' was modified within the " +
                                               "last 24 hours but the launcher executable was not updated " +
                                               "at the same time. Cheat bypass tools patch or replace these " +
                                               "DLLs to disable signature verification and bypass BattlEye.",
                                    Detail   = $"Last modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm} | " +
                                               "Launcher update: No",
                                });
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: MUICache — records names of launched executables
    // -------------------------------------------------------------------------
    private Task CheckRegistryMuiCache(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.73, Name, "Checking MUICache for R6S cheat execution evidence...");

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

                        var fn = Path.GetFileName(valueName);
                        if (!KnownCheatFileNames.Contains(fn))
                        {
                            var valueNameLower = valueName.ToLowerInvariant();
                            bool hasCheatKeyword =
                                   valueNameLower.Contains("r6_hack", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("r6_cheat", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("siege_hack", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("siege_cheat", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("r6_aimbot", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("siege_aimbot", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("r6siege_hack", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("rainbowsix_hack", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("r6_esp", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("drone_hack", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("camera_hack", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("r6_loader", StringComparison.OrdinalIgnoreCase)
                                || valueNameLower.Contains("r6_injector", StringComparison.OrdinalIgnoreCase);

                            if (!hasCheatKeyword) continue;
                        }

                        var displayName = key.GetValue(valueName) as string ?? string.Empty;

                        ctx.AddFinding(new Finding
                        {
                            Module   = "Rainbow Six Siege Cheat Detection",
                            Title    = $"MUICache: R6S cheat execution evidence: {fn}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{muiPath}",
                            FileName = fn,
                            Reason   = $"MUICache entry '{valueName}' references a known or suspected " +
                                       "Rainbow Six Siege cheat tool. MUICache records applications that " +
                                       "were launched by the user, providing evidence of prior execution " +
                                       "even if the file has since been deleted.",
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
    // Sub-check: UserAssist (ROT13-encoded execution history)
    // -------------------------------------------------------------------------
    private Task CheckRegistryUserAssist(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.80, Name, "Checking UserAssist for R6S cheat execution history...");

            const string userAssistGuid =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

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

                            var decoded = Rot13Decode(valueName);
                            var decodedLower = decoded.ToLowerInvariant();
                            var fn = Path.GetFileName(decoded);

                            bool isKnownCheat = KnownCheatFileNames.Contains(fn);
                            bool hasCheatKeyword = !isKnownCheat && (
                                   decodedLower.Contains("r6_hack", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("r6_cheat", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("siege_hack", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("siege_cheat", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("r6_aimbot", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("siege_aimbot", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("r6siege_hack", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("rainbowsix_hack", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("r6_loader", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("r6_injector", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("drone_hack", StringComparison.OrdinalIgnoreCase)
                                || decodedLower.Contains("camera_hack", StringComparison.OrdinalIgnoreCase));

                            if (!isKnownCheat && !hasCheatKeyword) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = "Rainbow Six Siege Cheat Detection",
                                Title    = $"UserAssist: R6S cheat execution record: {fn}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKCU\{userAssistGuid}\{guidName}\Count",
                                FileName = fn,
                                Reason   = $"UserAssist entry (ROT13-decoded: '{decoded}') indicates that " +
                                           "a known or suspected Rainbow Six Siege cheat application was " +
                                           "executed by the user. UserAssist tracks GUI application launches " +
                                           "and persists even after the cheat tool has been deleted.",
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
    // Sub-check: Run / RunOnce startup keys
    // -------------------------------------------------------------------------
    private Task CheckRegistryRunKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.87, Name, "Checking Run/RunOnce keys for R6S cheat persistence...");

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
                                   valueLower.Contains("r6_hack", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("r6_cheat", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("siege_hack", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("siege_cheat", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("r6_aimbot", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("siege_aimbot", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("r6siege_hack", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("rainbowsix_hack", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("r6_loader", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("r6_injector", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("drone_hack", StringComparison.OrdinalIgnoreCase)
                                || valueLower.Contains("camera_hack", StringComparison.OrdinalIgnoreCase));

                            if (!isKnownCheat && !hasCheatKeyword) continue;

                            var hivePrefix = ReferenceEquals(hive, Registry.LocalMachine) ? "HKLM" : "HKCU";

                            ctx.AddFinding(new Finding
                            {
                                Module   = "Rainbow Six Siege Cheat Detection",
                                Title    = $"Run key: R6S cheat autostart entry: {valueName}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"{hivePrefix}\{runPath}",
                                FileName = fn,
                                Reason   = $"Autostart registry entry '{valueName}' in '{hivePrefix}\\{runPath}' " +
                                           $"points to a suspected R6S cheat tool: '{value}'. " +
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
    // Sub-check: Uninstall records for known R6S cheat software
    // -------------------------------------------------------------------------
    private Task CheckRegistryUninstallRecords(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.93, Name, "Checking uninstall records for R6S cheat software...");

            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            var cheatUninstallKeywords = new[]
            {
                "r6 hack",
                "r6 cheat",
                "r6 aimbot",
                "r6 esp",
                "siege hack",
                "siege cheat",
                "siege aimbot",
                "siege esp",
                "rainbow six hack",
                "rainbow six cheat",
                "r6siege hack",
                "r6siege cheat",
                "r6_hack",
                "r6_cheat",
                "r6_aimbot",
                "siege_hack",
                "siege_cheat",
                "drone hack",
                "drone esp",
                "camera hack",
                "r6 bypass",
                "siege bypass",
                "battleye bypass",
                "gamesense r6",
                "aimware r6",
                "skycheats r6",
                "interwebz r6",
                "streamline r6",
            };

            var hives = new[] { Registry.LocalMachine, Registry.CurrentUser };

            foreach (var hive in hives)
            {
                foreach (var uninstallPath in uninstallPaths)
                {
                    if (ct.IsCancellationRequested) return;

                    RegistryKey? uninstallKey = null;
                    try
                    {
                        uninstallKey = hive.OpenSubKey(uninstallPath, writable: false);
                        if (uninstallKey is null) continue;

                        foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                        {
                            if (ct.IsCancellationRequested) break;
                            ctx.IncrementRegistryKeys();

                            RegistryKey? appKey = null;
                            try
                            {
                                appKey = uninstallKey.OpenSubKey(subKeyName, writable: false);
                                if (appKey is null) continue;

                                var displayName    = appKey.GetValue("DisplayName")    as string ?? string.Empty;
                                var publisher      = appKey.GetValue("Publisher")      as string ?? string.Empty;
                                var installLocation= appKey.GetValue("InstallLocation")as string ?? string.Empty;
                                var displayNameLower = displayName.ToLowerInvariant();

                                var hitKeyword = cheatUninstallKeywords.FirstOrDefault(k =>
                                    displayNameLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                                if (hitKeyword is null)
                                {
                                    var locationLower = installLocation.ToLowerInvariant();
                                    hitKeyword = cheatUninstallKeywords.FirstOrDefault(k =>
                                        locationLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                                }

                                if (hitKeyword is null) continue;

                                var hivePrefix = ReferenceEquals(hive, Registry.LocalMachine) ? "HKLM" : "HKCU";

                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Rainbow Six Siege Cheat Detection",
                                    Title    = $"Uninstall record: R6S cheat software: {displayName}",
                                    Risk     = RiskLevel.High,
                                    Location = $@"{hivePrefix}\{uninstallPath}\{subKeyName}",
                                    Reason   = $"Uninstall registry entry '{displayName}' matches R6S cheat " +
                                               $"software keyword '{hitKeyword}'. Even if the software was " +
                                               "uninstalled, the registry record confirms it was previously " +
                                               "installed on this system.",
                                    Detail   = $"DisplayName: '{displayName}' | Publisher: '{publisher}' | " +
                                               $"InstallLocation: '{installLocation}' | Key: {subKeyName}",
                                });
                            }
                            catch { }
                            finally { appKey?.Dispose(); }
                        }
                    }
                    catch { }
                    finally { uninstallKey?.Dispose(); }
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
