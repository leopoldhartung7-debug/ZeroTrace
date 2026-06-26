using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class SteamCheatWorkshopScanModule : IScanModule
{
    public string Name => "Steam Workshop Cheat Distribution Forensic Scan";
    public double Weight => 3.6;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // -------------------------------------------------------------------------
    // Known Steam cheat launcher executables (65+)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> KnownSteamCheatLaunchers = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam_cheat.exe",
        "steam_inject.exe",
        "steam_hack.exe",
        "steam_loader.exe",
        "steam_bypass.exe",
        "steam_dumper.exe",
        "steam_crack.exe",
        "steam_patch.exe",
        "steam_overlay_cheat.exe",
        "gameinject.exe",
        "gameoverlay_cheat.exe",
        "steamapi_bypass.exe",
        "steamapi_inject.exe",
        "steamapi_hack.exe",
        "vac_bypass.exe",
        "vac_bypass_v2.exe",
        "vac_bypass_v3.exe",
        "vac_dump.exe",
        "steam_vac_bypass.exe",
        "steam_vac_dump.exe",
        "steamcmd_cheat.exe",
        "steam_workshop_dl.exe",
        "workshop_dl.exe",
        "workshop_bypass.exe",
        "workshop_crack.exe",
        "workshop_inject.exe",
        "workshop_loader.exe",
        "steamapi_loader.exe",
        "steamclient_patch.exe",
        "steamclient_hook.exe",
        "steam_emu.exe",
        "steam_emulator.exe",
        "goldberg_emu.exe",
        "skidrow_steam.exe",
        "reloaded_steam.exe",
        "bypass_steam.exe",
        "crack_steam.exe",
        "patch_steam.exe",
        "hook_steam.exe",
        "inject_steam.exe",
        "dump_steam.exe",
        "steam_game_inject.exe",
        "game_inject_steam.exe",
        "steamhook.exe",
        "steaminject.exe",
        "steambypass.exe",
        "steamhack.exe",
        "steamcrack.exe",
        "steamdump.exe",
        "workshopcheat.exe",
        "workshophack.exe",
        "workshopinject.exe",
        "vacbypass.exe",
        "vacbypasser.exe",
        "vacdump.exe",
        "vacdumper.exe",
        "steamvac.exe",
        "steam_api_bypass.exe",
        "steam_overlay_inject.exe",
        "steam_game_cheat.exe",
        "steam_cheat_loader.exe",
        "game_cheat_steam.exe",
        "steam_aimbot.exe",
        "steam_wallhack.exe",
        "steam_cheat_v2.exe",
    };

    // -------------------------------------------------------------------------
    // Known Steam cheat download archives (50+)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> KnownSteamCheatArchives = new(StringComparer.OrdinalIgnoreCase)
    {
        "vac_bypass.zip",
        "vac_bypass.rar",
        "steam_inject.zip",
        "steam_hack.zip",
        "steam_cheat.zip",
        "steam_bypass.zip",
        "workshop_cheat.zip",
        "workshop_hack.zip",
        "steamapi_bypass.zip",
        "goldberg_emu.zip",
        "steam_emu.zip",
        "steam_crack.zip",
        "steam_patch.zip",
        "steam_loader.zip",
        "steam_loader.rar",
        "vacbypass_tool.zip",
        "vac_undetected.zip",
        "vac_bypass_v2.zip",
        "steam_dumper.zip",
        "steam_overlay_cheat.zip",
        "steamapi_hack.zip",
        "workshop_bypass.zip",
        "workshop_loader.zip",
        "steamclient_patch.zip",
        "steamclient_hook.zip",
        "steam_hook.zip",
        "steam_inject_v2.zip",
        "steam_api_bypass.zip",
        "goldberg_emu.rar",
        "ali213_emu.zip",
        "skidrow_steam.zip",
        "reloaded_steam.zip",
        "cream_api.zip",
        "cream_api.rar",
        "steam_workshop_dl.zip",
        "workshop_crack.zip",
        "workshop_inject.zip",
        "steam_cheat_loader.zip",
        "game_cheat_steam.zip",
        "steam_aimbot.zip",
        "steam_wallhack.zip",
        "vac_cracker.zip",
        "vac_cracker.rar",
        "steamemulator_pack.zip",
        "steam_emu_pack.zip",
        "steam_bypass_pack.zip",
        "vac_bypass_pack.zip",
        "steam_cheat_pack.zip",
        "steam_inject_pack.zip",
        "workshop_cheat_pack.zip",
    };

    // -------------------------------------------------------------------------
    // Steam API bypass file indicators (fake/patched steam_api.dll etc.)
    // -------------------------------------------------------------------------

    private static readonly string[] SteamApiBypassContentKeywords = new[]
    {
        "goldberg", "skidrow", "reloaded", "cracked", "bypassed",
    };

    private static readonly HashSet<string> SteamApiBypassFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam_api.dll",
        "steam_api64.dll",
        "steamclient.dll",
        "steamclient64.dll",
    };

    // Config files used by Steam emulators and bypass tools
    private static readonly HashSet<string> SteamEmuConfigFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam_interfaces.txt",
        "ALI213.ini",
        "cream_api.ini",
        "goldberg.ini",
        "steam_settings.ini",
        "CreamAPI.ini",
        "SmokelessRUMBLE.ini",
        "hotfix.ini",
    };

    // -------------------------------------------------------------------------
    // Cheat overlay DLL names used in Steam game injection
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> CheatOverlayDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "gameoverlayrenderer.dll",
        "gameoverlayrenderer64.dll",
        "gamehook.dll",
        "overlay_inject.dll",
        "overlay_cheat.dll",
        "overlay_hack.dll",
        "steam_overlay_cheat.dll",
        "game_overlay_inject.dll",
        "d3d9_hook.dll",
        "d3d11_hook.dll",
        "d3d12_hook.dll",
        "opengl_hook.dll",
        "vulkan_hook.dll",
        "overlay_loader.dll",
        "cheat_overlay.dll",
        "hack_overlay.dll",
    };

    // -------------------------------------------------------------------------
    // VAC ban bypass tool documentation files
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> VacBypassDocFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "vac_ban_bypass.txt",
        "unban_guide.txt",
        "ban_bypass.pdf",
        "vac_bypass_guide.txt",
        "vac_unban.txt",
        "steam_unban.txt",
        "vac_removal.txt",
        "bypass_vac.txt",
        "unbanned.txt",
        "anti_vac.txt",
        "vac_bypass_readme.txt",
        "vac_bypass.md",
        "steam_ban_bypass.txt",
        "game_ban_bypass.txt",
    };

    // -------------------------------------------------------------------------
    // VAC bypass script filenames (.ps1, .bat, .py)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> VacBypassScriptNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "vac_bypass.ps1",
        "vacbypass.ps1",
        "vac_bypass.bat",
        "vacbypass.bat",
        "vac_bypass.py",
        "vacbypass.py",
        "bypass_vac.ps1",
        "bypass_vac.bat",
        "bypass_vac.py",
        "steam_bypass.ps1",
        "steam_bypass.bat",
        "steam_bypass.py",
        "anti_vac.ps1",
        "anti_vac.bat",
        "steam_cheat_setup.bat",
        "steam_cheat_setup.ps1",
        "install_bypass.bat",
        "install_bypass.ps1",
        "vac_hook.bat",
        "vac_hook.ps1",
    };

    // -------------------------------------------------------------------------
    // Steam cheat config file keywords
    // -------------------------------------------------------------------------

    private static readonly string[] SteamCheatConfigKeywords = new[]
    {
        "bypass", "crack", "vac", "cheat", "inject",
    };

    // -------------------------------------------------------------------------
    // Workshop directory suspicious file extensions
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> SuspiciousWorkshopExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".dll",
        ".exe",
        ".sys",
    };

    // -------------------------------------------------------------------------
    // Workshop item folder cheat keyword fragments
    // -------------------------------------------------------------------------

    private static readonly string[] WorkshopCheatFolderKeywords = new[]
    {
        "cheat", "hack", "aimbot", "wallhack", "esp", "bypass", "inject",
        "triggerbot", "bhop", "spinbot", "rapidfire", "nofall", "godmode",
        "noclip", "trainer", "exploit", "loader", "stealer",
    };

    // -------------------------------------------------------------------------
    // Steam log suspicious patterns
    // -------------------------------------------------------------------------

    private static readonly string[] SteamLogSuspiciousPatterns = new[]
    {
        "vac ban",
        "game ban",
        "workshop cheat",
        "inject detected",
        "bypass detected",
        "cheat detected",
        "suspicious activity",
        "vac network",
        "game network ban",
        "ban issued",
        "vacnetwork",
        "ban detected",
        "cheating detected",
        "anti-cheat",
        "anticheat",
        "violation detected",
        "untrusted",
        "banned from",
        "permanent ban",
        "cooldown",
        "overwatch ban",
        "trust factor",
        "low trust",
        "untrusted account",
        "vac authentication error",
        "steam guard blocked",
        "account restricted",
        "vac enabled game",
        "vac session timed out",
        "game server ban",
    };

    // -------------------------------------------------------------------------
    // Fake Steam emulator registry keys (Goldberg, ALI213, RLD)
    // -------------------------------------------------------------------------

    private static readonly string[] FakeSteamEmuRegistryPaths = new[]
    {
        @"SOFTWARE\Goldberg Emulator",
        @"SOFTWARE\Ali213",
        @"SOFTWARE\ALI213",
        @"SOFTWARE\RLD Games",
        @"SOFTWARE\SKIDROW",
        @"SOFTWARE\CODEX",
        @"SOFTWARE\Cream API",
        @"SOFTWARE\SmokelessRUMBLE",
        @"SOFTWARE\CPY",
        @"SOFTWARE\DARKSiDERS",
        @"SOFTWARE\3DM",
        @"SOFTWARE\Goldberg Steam Emu",
    };

    // -------------------------------------------------------------------------
    // Steam cheat launcher names in UserAssist (ROT13 encoded in registry)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> SteamCheatUserAssistNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam_cheat.exe",
        "steam_inject.exe",
        "steam_hack.exe",
        "steam_loader.exe",
        "steam_bypass.exe",
        "vac_bypass.exe",
        "vac_bypass_v2.exe",
        "steam_vac_bypass.exe",
        "goldberg_emu.exe",
        "steam_emu.exe",
        "workshop_bypass.exe",
        "steamapi_bypass.exe",
        "steamclient_patch.exe",
        "steam_overlay_cheat.exe",
        "vacbypass.exe",
        "vacbypasser.exe",
        "steamhook.exe",
        "steaminject.exe",
        "steambypass.exe",
        "workshopcheat.exe",
        "workshophack.exe",
        "workshopinject.exe",
        "steam_dumper.exe",
        "vac_dump.exe",
        "steam_crack.exe",
        "steam_patch.exe",
        "bypass_steam.exe",
        "crack_steam.exe",
        "patch_steam.exe",
        "hook_steam.exe",
        "inject_steam.exe",
        "steam_game_inject.exe",
        "steamvac.exe",
        "steam_api_bypass.exe",
        "steam_cheat_loader.exe",
    };

    // -------------------------------------------------------------------------
    // Steam cheat MUICache names (30+)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> SteamCheatMuiCacheNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam_cheat.exe",
        "steam_inject.exe",
        "steam_hack.exe",
        "steam_loader.exe",
        "steam_bypass.exe",
        "vac_bypass.exe",
        "steam_vac_bypass.exe",
        "goldberg_emu.exe",
        "workshop_bypass.exe",
        "steamapi_bypass.exe",
        "steamclient_patch.exe",
        "steam_overlay_cheat.exe",
        "vacbypass.exe",
        "steamhook.exe",
        "steaminject.exe",
        "steambypass.exe",
        "workshopcheat.exe",
        "workshophack.exe",
        "steam_dumper.exe",
        "vac_dump.exe",
        "steam_crack.exe",
        "steam_patch.exe",
        "bypass_steam.exe",
        "steam_game_inject.exe",
        "steamvac.exe",
        "steam_api_bypass.exe",
        "steam_cheat_loader.exe",
        "vac_bypass_v2.exe",
        "vac_bypass_v3.exe",
        "steam_emu.exe",
    };

    // -------------------------------------------------------------------------
    // Directory helpers
    // -------------------------------------------------------------------------

    private static string DesktopDir =>
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

    private static string DownloadsDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

    private static string UserTempDir => Path.GetTempPath();

    private static string WindowsTempDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");

    private static string LocalAppDataDir =>
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static string RoamingAppDataDir =>
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    // Default Steam install path
    private static readonly string DefaultSteamDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Steam");

    private static readonly string DefaultSteamAppsDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Steam", "steamapps");

    private static readonly string DefaultWorkshopContentDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Steam", "steamapps", "workshop", "content");

    // -------------------------------------------------------------------------
    // Resolve Steam directory (registry or default)
    // -------------------------------------------------------------------------

    private static string ResolveSteamDir()
    {
        try
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                using var key = hive.OpenSubKey(@"SOFTWARE\Valve\Steam", writable: false)
                             ?? hive.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam", writable: false);
                if (key == null) continue;
                var path = key.GetValue("SteamPath")?.ToString()
                        ?? key.GetValue("InstallPath")?.ToString();
                if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                    return path;
            }
        }
        catch { }
        return DefaultSteamDir;
    }

    // -------------------------------------------------------------------------
    // RunAsync — all 11 checks in parallel
    // -------------------------------------------------------------------------

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Steam Workshop cheat distribution forensic scan...");

        return Task.WhenAll(
            CheckSteamCheatLauncherExecutables(ctx, ct),
            CheckSteamApiBypassArtifacts(ctx, ct),
            CheckSteamWorkshopCheatItems(ctx, ct),
            CheckSteamLocalConfigCheat(ctx, ct),
            CheckSteamCheatDownloadArtifacts(ctx, ct),
            CheckSteamOverlayCheatArtifacts(ctx, ct),
            CheckSteamCheatRegistryArtifacts(ctx, ct),
            CheckSteamCheatConfigFiles(ctx, ct),
            CheckSteamCheatLogFiles(ctx, ct),
            CheckVACBanArtifacts(ctx, ct),
            CheckSteamInstallerCheatRecords(ctx, ct)
        );
    }

    // -------------------------------------------------------------------------
    // Check 1: Steam cheat launcher executables
    // -------------------------------------------------------------------------

    private Task CheckSteamCheatLauncherExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamDir = ResolveSteamDir();
            var searchDirs = new[]
            {
                DesktopDir,
                DownloadsDir,
                UserTempDir,
                WindowsTempDir,
                LocalAppDataDir,
                RoamingAppDataDir,
                steamDir,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    if (!KnownSteamCheatLaunchers.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known Steam Cheat Launcher: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Executable '{fn}' matches a known Steam cheat launcher or VAC bypass tool. " +
                                 "These tools exploit Steam's API, inject into game processes via Steam overlays, " +
                                 "or bypass Valve Anti-Cheat (VAC) by intercepting Steam authentication calls.",
                        Detail = $"Path: {file} | Directory: {dir}"
                    });
                }

                await Task.Yield();
            }

            // Also check AppData subdirectories one level deep
            foreach (var baseDir in new[] { LocalAppDataDir, RoamingAppDataDir })
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                string[] subDirs;
                try { subDirs = Directory.GetDirectories(baseDir); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var sub in subDirs)
                {
                    if (ct.IsCancellationRequested) return;

                    string[] subFiles;
                    try
                    {
                        subFiles = Directory.GetFiles(sub, "*.exe", SearchOption.TopDirectoryOnly);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in subFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fn = Path.GetFileName(file);
                        if (!KnownSteamCheatLaunchers.Contains(fn)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Steam Cheat Launcher in AppData Subdirectory: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known Steam cheat launcher '{fn}' found in an AppData subdirectory. " +
                                     "This staging location is commonly used to hide Steam bypass tools and " +
                                     "VAC evasion software from superficial directory scans.",
                            Detail = $"Path: {file}"
                        });
                    }

                    await Task.Yield();
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 2: Steam API bypass artifacts (patched/fake steam_api.dll etc.)
    // -------------------------------------------------------------------------

    private Task CheckSteamApiBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamDir = ResolveSteamDir();
            var steamAppsDir = Path.Combine(steamDir, "steamapps");

            if (!Directory.Exists(steamAppsDir)) return;

            // Enumerate game directories under steamapps\common
            var commonDir = Path.Combine(steamAppsDir, "common");
            if (!Directory.Exists(commonDir)) return;

            string[] gameDirs;
            try { gameDirs = Directory.GetDirectories(commonDir); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var gameDir in gameDirs)
            {
                if (ct.IsCancellationRequested) return;

                // Look for steam_api.dll, steam_api64.dll, steamclient.dll, steamclient64.dll
                foreach (var apiFileName in SteamApiBypassFileNames)
                {
                    if (ct.IsCancellationRequested) return;

                    string[] candidates;
                    try
                    {
                        candidates = Directory.GetFiles(gameDir, apiFileName,
                            SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var apiFile in candidates)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        // Read first 256KB to check for bypass keywords in file content
                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(apiFile, FileMode.Open,
                                FileAccess.Read, FileShare.ReadWrite);
                            int readLen = (int)Math.Min(262144L, fs.Length);
                            if (readLen > 0)
                            {
                                var buf = new byte[readLen];
                                int bytesRead = 0;
                                while (bytesRead < readLen)
                                {
                                    int n = await fs.ReadAsync(buf, bytesRead, readLen - bytesRead, ct);
                                    if (n == 0) break;
                                    bytesRead += n;
                                }
                                content = System.Text.Encoding.ASCII.GetString(buf, 0, bytesRead);
                            }
                        }
                        catch (UnauthorizedAccessException) { continue; }
                        catch (IOException) { continue; }

                        var matchedKeyword = SteamApiBypassContentKeywords.FirstOrDefault(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (matchedKeyword == null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Patched/Fake Steam API DLL in Game Directory: {Path.GetFileName(apiFile)}",
                            Risk = RiskLevel.High,
                            Location = apiFile,
                            FileName = Path.GetFileName(apiFile),
                            Reason = $"Steam API file '{Path.GetFileName(apiFile)}' in a game directory contains " +
                                     $"the keyword '{matchedKeyword}', which is a watermark found in well-known " +
                                     "Steam emulators (Goldberg, Skidrow, Reloaded, ALI213). These replace the " +
                                     "legitimate Steam API to bypass DRM, authentication, and potentially VAC.",
                            Detail = $"Path: {apiFile} | Matched keyword: {matchedKeyword} | " +
                                     $"Game dir: {Path.GetFileName(gameDir)}"
                        });
                    }
                }

                // Check for Steam emulator config files in the game directory
                foreach (var emuConfig in SteamEmuConfigFiles)
                {
                    if (ct.IsCancellationRequested) return;

                    string[] configMatches;
                    try
                    {
                        configMatches = Directory.GetFiles(gameDir, emuConfig,
                            SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var cfgFile in configMatches)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Steam Emulator Config in Game Directory: {Path.GetFileName(cfgFile)}",
                            Risk = RiskLevel.High,
                            Location = cfgFile,
                            FileName = Path.GetFileName(cfgFile),
                            Reason = $"Steam emulator configuration file '{Path.GetFileName(cfgFile)}' found in a " +
                                     "Steam game directory. Files like ALI213.ini, cream_api.ini, and " +
                                     "steam_interfaces.txt are used to configure cracked/bypassed Steam API " +
                                     "DLLs that circumvent DRM and potentially VAC checks.",
                            Detail = $"Path: {cfgFile} | Game dir: {Path.GetFileName(gameDir)}"
                        });
                    }
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 3: Steam Workshop cheat items
    // -------------------------------------------------------------------------

    private Task CheckSteamWorkshopCheatItems(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // Steam Workshop content path
            var steamDir = ResolveSteamDir();
            var workshopDir = Path.Combine(steamDir, "steamapps", "workshop", "content");

            if (!Directory.Exists(workshopDir)) return;

            // Enumerate app ID directories (each game has its own)
            string[] appDirs;
            try { appDirs = Directory.GetDirectories(workshopDir); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var appDir in appDirs)
            {
                if (ct.IsCancellationRequested) return;

                // Enumerate workshop item directories
                string[] itemDirs;
                try { itemDirs = Directory.GetDirectories(appDir); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var itemDir in itemDirs)
                {
                    if (ct.IsCancellationRequested) return;

                    var itemDirName = Path.GetFileName(itemDir).ToLowerInvariant();
                    bool dirHasCheatKeyword = WorkshopCheatFolderKeywords.Any(k =>
                        itemDirName.Contains(k, StringComparison.OrdinalIgnoreCase));

                    // Enumerate all files in this workshop item
                    string[] itemFiles;
                    try
                    {
                        itemFiles = Directory.GetFiles(itemDir, "*",
                            SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in itemFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        var fn = Path.GetFileName(file);

                        // Flag .dll, .exe, .sys files in workshop content
                        if (SuspiciousWorkshopExtensions.Contains(ext))
                        {
                            var risk = ext == ".sys" ? RiskLevel.Critical : RiskLevel.High;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Binary in Steam Workshop Item: {fn}",
                                Risk = risk,
                                Location = file,
                                FileName = fn,
                                Reason = $"A {ext.ToUpperInvariant()} file was found inside a Steam Workshop " +
                                         $"content directory (App: {Path.GetFileName(appDir)}, Item: " +
                                         $"{Path.GetFileName(itemDir)}). Workshop items should not contain " +
                                         "executable, DLL, or driver files. This strongly suggests a cheat or " +
                                         "injector is being distributed via Steam Workshop.",
                                Detail = $"Path: {file} | App: {Path.GetFileName(appDir)} | " +
                                         $"Item: {Path.GetFileName(itemDir)}"
                            });
                        }
                        // Flag if item directory name contains cheat keywords
                        else if (dirHasCheatKeyword)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Workshop Item Directory Contains Cheat Keyword: {Path.GetFileName(itemDir)}",
                                Risk = RiskLevel.Medium,
                                Location = itemDir,
                                FileName = fn,
                                Reason = $"Steam Workshop item directory '{Path.GetFileName(itemDir)}' for app " +
                                         $"'{Path.GetFileName(appDir)}' has a name containing a cheat-related " +
                                         "keyword. Cheats are sometimes distributed as Workshop items with " +
                                         "misleading or explicit names.",
                                Detail = $"Item dir: {itemDir} | File: {file}"
                            });
                            break; // One finding per item directory to avoid spam
                        }
                    }

                    await Task.Yield();
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 4: Steam local config cheat indicators
    // -------------------------------------------------------------------------

    private Task CheckSteamLocalConfigCheat(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamDir = ResolveSteamDir();

            // Check localconfig.vdf, loginusers.vdf, config.vdf for suspicious content
            var vdfFiles = new[]
            {
                Path.Combine(steamDir, "userdata"),
                Path.Combine(RoamingAppDataDir, "Steam"),
                Path.Combine(steamDir, "config"),
            };

            var suspiciousVdfKeywords = new[]
            {
                "cheat", "hack", "bypass", "inject", "vac_bypass", "workshop_cheat",
                "aimbot", "wallhack", "triggerbot",
            };

            foreach (var baseDir in vdfFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                string[] configFiles;
                try
                {
                    configFiles = Directory.GetFiles(baseDir, "*.vdf", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var vdfFile in configFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(vdfFile, FileMode.Open,
                            FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    var matchedKeyword = suspiciousVdfKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (matchedKeyword == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Steam Config File Contains Cheat Keyword: {Path.GetFileName(vdfFile)}",
                        Risk = RiskLevel.Medium,
                        Location = vdfFile,
                        FileName = Path.GetFileName(vdfFile),
                        Reason = $"Steam configuration file '{Path.GetFileName(vdfFile)}' contains the keyword " +
                                 $"'{matchedKeyword}', which may indicate a cheat-related workshop subscription, " +
                                 "a modified launch option, or evidence of cheat tool integration with Steam.",
                        Detail = $"Path: {vdfFile} | Keyword: {matchedKeyword}"
                    });
                }

                await Task.Yield();
            }

            // Check steamapps directory for suspicious app manifests (acf files with cheat app names)
            var steamAppsDir = Path.Combine(steamDir, "steamapps");
            if (ct.IsCancellationRequested || !Directory.Exists(steamAppsDir)) return;

            string[] acfFiles;
            try { acfFiles = Directory.GetFiles(steamAppsDir, "*.acf", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var acfFile in acfFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(acfFile, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                var matchedKw = suspiciousVdfKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (matchedKw == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious Steam App Manifest: {Path.GetFileName(acfFile)}",
                    Risk = RiskLevel.Medium,
                    Location = acfFile,
                    FileName = Path.GetFileName(acfFile),
                    Reason = $"Steam app manifest '{Path.GetFileName(acfFile)}' contains keyword '{matchedKw}'. " +
                             "This may indicate a cheat application installed via Steam or a modified game " +
                             "manifest referencing cheat-related content.",
                    Detail = $"Path: {acfFile} | Keyword: {matchedKw}"
                });
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 5: Steam cheat download artifacts
    // -------------------------------------------------------------------------

    private Task CheckSteamCheatDownloadArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[] { DownloadsDir, DesktopDir };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);

                    // Exact match
                    if (KnownSteamCheatArchives.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Steam Cheat Archive in Downloads/Desktop: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Archive '{fn}' matches a known Steam cheat or VAC bypass toolkit " +
                                     "distribution package. These archives are downloaded from cheat distribution " +
                                     "forums and contain tools for bypassing Steam's anti-cheat systems.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    // Heuristic keyword match on archive names
                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    if (ext != ".zip" && ext != ".rar" && ext != ".7z") continue;

                    bool hasSteamCheatKeyword =
                        fn.Contains("vac_bypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("vacbypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steam_cheat", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steamcheat", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steam_inject", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steam_hack", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steam_bypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steambypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("goldberg_emu", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steam_emu", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("cream_api", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("workshop_cheat", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("workshop_bypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steamapi_bypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steam_crack", StringComparison.OrdinalIgnoreCase);

                    if (!hasSteamCheatKeyword) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious Steam Cheat-Related Archive: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Archive '{fn}' contains keywords associated with Steam cheat and VAC bypass " +
                                 "tool distributions. The filename pattern matches packages commonly shared on " +
                                 "cheat forums to circumvent Steam's anti-cheat mechanisms.",
                        Detail = $"Path: {file}"
                    });
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 6: Steam overlay cheat artifacts
    // -------------------------------------------------------------------------

    private Task CheckSteamOverlayCheatArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamDir = ResolveSteamDir();
            var steamAppsCommonDir = Path.Combine(steamDir, "steamapps", "common");

            if (!Directory.Exists(steamAppsCommonDir)) return;

            string[] gameDirs;
            try { gameDirs = Directory.GetDirectories(steamAppsCommonDir); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var gameDir in gameDirs)
            {
                if (ct.IsCancellationRequested) return;

                // Check for known cheat overlay DLL names in game directories
                foreach (var overlayDll in CheatOverlayDlls)
                {
                    if (ct.IsCancellationRequested) return;

                    string[] matches;
                    try
                    {
                        matches = Directory.GetFiles(gameDir, overlayDll,
                            SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var match in matches)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        // Skip the real Steam overlay DLLs in the Steam install dir itself
                        if (match.StartsWith(steamDir, StringComparison.OrdinalIgnoreCase)
                            && !match.StartsWith(steamAppsCommonDir, StringComparison.OrdinalIgnoreCase))
                            continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Overlay DLL in Steam Game Directory: {Path.GetFileName(match)}",
                            Risk = RiskLevel.High,
                            Location = match,
                            FileName = Path.GetFileName(match),
                            Reason = $"Overlay DLL '{Path.GetFileName(match)}' found in Steam game directory " +
                                     $"'{Path.GetFileName(gameDir)}'. This file name is associated with cheat " +
                                     "injection via the Steam overlay mechanism. Cheats inject into game " +
                                     "processes by hooking or replacing the overlay renderer DLL.",
                            Detail = $"Path: {match} | Game: {Path.GetFileName(gameDir)}"
                        });
                    }
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 7: Steam cheat registry artifacts
    // -------------------------------------------------------------------------

    private Task CheckSteamCheatRegistryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // 7a — HKCU\Software\Valve\Steam — check for suspicious modifications
            try
            {
                using var steamKey = Registry.CurrentUser.OpenSubKey(
                    @"Software\Valve\Steam", writable: false);
                if (steamKey != null)
                {
                    ctx.IncrementRegistryKeys();

                    // Check for workshop-bypass-related values
                    foreach (var valName in steamKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        bool isSuspicious =
                            valName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("crack", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("inject", StringComparison.OrdinalIgnoreCase);

                        if (!isSuspicious) continue;

                        var valData = steamKey.GetValue(valName)?.ToString() ?? "";

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious Value in Steam Registry Key: {valName}",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKCU\Software\Valve\Steam",
                            Reason = $"Registry value '{valName}' under the Steam configuration key contains " +
                                     "keywords suggesting a cheat tool modification to the Steam client " +
                                     "or its settings.",
                            Detail = $"Value: {valName} = {valData}"
                        });
                    }
                }
            }
            catch (IOException) { }

            // 7b — UserAssist — ROT13 scan for Steam cheat launcher names
            try
            {
                using var uaRoot = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                    writable: false);
                if (uaRoot != null)
                {
                    foreach (var guidName in uaRoot.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        using var countKey = uaRoot.OpenSubKey($@"{guidName}\Count", writable: false);
                        if (countKey == null) continue;

                        foreach (var valName in countKey.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementRegistryKeys();

                            var decoded = Rot13Decode(valName);
                            var fn = Path.GetFileName(decoded);

                            if (!SteamCheatUserAssistNames.Contains(fn)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Steam Cheat Launcher in UserAssist: {fn}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\" +
                                           $@"{guidName}\Count",
                                FileName = fn,
                                Reason = $"UserAssist entry decodes (ROT13) to '{fn}', a known Steam cheat " +
                                         "launcher or VAC bypass tool. UserAssist records GUI execution history " +
                                         "with run counts and timestamps — this provides forensic evidence of " +
                                         "the tool being executed even after deletion.",
                                Detail = $"Encoded: {valName} | Decoded: {decoded}"
                            });
                        }
                    }
                }
            }
            catch (IOException) { }

            // 7c — MUICache — Steam cheat execution evidence
            var muiCachePaths = new[]
            {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"Software\Microsoft\Windows\ShellNoRoam\MUICache",
            };

            foreach (var muiPath in muiCachePaths)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var muiKey = Registry.CurrentUser.OpenSubKey(muiPath, writable: false);
                    if (muiKey == null) continue;

                    foreach (var valName in muiKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var fn = Path.GetFileName(valName);
                        if (!SteamCheatMuiCacheNames.Contains(fn)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Steam Cheat Tool in MUICache: {fn}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{muiPath}",
                            FileName = fn,
                            Reason = $"MUICache entry '{fn}' references a known Steam cheat launcher or VAC " +
                                     "bypass tool. MUICache stores the full path of all executed applications, " +
                                     "providing forensic evidence of execution even after file deletion.",
                            Detail = $"MUICache entry: {valName}"
                        });
                    }
                }
                catch (IOException) { }
            }

            // 7d — HKLM\Software — fake Steam emulator installation keys
            foreach (var emuKeyPath in FakeSteamEmuRegistryPaths)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var emuKey = Registry.LocalMachine.OpenSubKey(emuKeyPath, writable: false)
                                    ?? Registry.CurrentUser.OpenSubKey(emuKeyPath, writable: false);
                    if (emuKey == null) continue;

                    ctx.IncrementRegistryKeys();

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Steam Emulator Registry Key Found: {Path.GetFileName(emuKeyPath)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{emuKeyPath}",
                        Reason = $"Registry key '{emuKeyPath}' is associated with a known Steam emulator " +
                                 "(Goldberg, ALI213, SKIDROW, CODEX, etc.). These emulators replace the " +
                                 "legitimate Steam API to bypass DRM and potentially VAC authentication.",
                        Detail = $"Key: {emuKeyPath}"
                    });
                }
                catch (IOException) { }
            }

            // 7e — Run/RunOnce — Steam cheat auto-start entries
            var runKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            foreach (var runKeyPath in runKeys)
            {
                if (ct.IsCancellationRequested) return;
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    try
                    {
                        using var runKey = hive.OpenSubKey(runKeyPath, writable: false);
                        if (runKey == null) continue;

                        foreach (var valName in runKey.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementRegistryKeys();

                            var valData = runKey.GetValue(valName)?.ToString() ?? "";
                            var fn = Path.GetFileName(valData.Trim('"').Split(' ')[0]);

                            if (!KnownSteamCheatLaunchers.Contains(fn)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Steam Cheat Tool Auto-Start Entry: {valName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{runKeyPath}",
                                FileName = fn,
                                Reason = $"Auto-start registry entry '{valName}' references the known Steam " +
                                         $"cheat tool '{fn}'. The tool is configured to launch automatically " +
                                         "at system startup, a common persistence technique for cheat loaders.",
                                Detail = $"Key: {runKeyPath} | Value: {valName} | Data: {valData}"
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 8: Steam cheat config files in game dirs and Downloads
    // -------------------------------------------------------------------------

    private Task CheckSteamCheatConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamDir = ResolveSteamDir();
            var steamAppsCommon = Path.Combine(steamDir, "steamapps", "common");

            var baseDirs = new List<string> { DownloadsDir, DesktopDir };
            if (Directory.Exists(steamAppsCommon)) baseDirs.Add(steamAppsCommon);

            var allConfigNames = SteamEmuConfigFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var baseDir in baseDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(baseDir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;

                    var fn = Path.GetFileName(file);
                    if (!allConfigNames.Contains(fn)) continue;

                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open,
                            FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    var matchedKeyword = SteamCheatConfigKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (matchedKeyword == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Steam Cheat/Emulator Config File: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Steam emulator/cheat configuration file '{fn}' was found and contains the " +
                                 $"keyword '{matchedKeyword}'. Files like ALI213.ini, cream_api.ini, and " +
                                 "goldberg.ini configure cracked Steam API libraries that bypass DRM and VAC.",
                        Detail = $"Path: {file} | Keyword: {matchedKeyword}"
                    });
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 9: Steam cheat log files
    // -------------------------------------------------------------------------

    private Task CheckSteamCheatLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamDir = ResolveSteamDir();

            var logDirs = new[]
            {
                Path.Combine(RoamingAppDataDir, "Steam", "logs"),
                Path.Combine(steamDir, "logs"),
            };

            foreach (var logDir in logDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(logDir)) continue;

                string[] logFiles;
                try
                {
                    logFiles = Directory.GetFiles(logDir, "*.txt", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var logFile in logFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open,
                            FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    var matchedPattern = SteamLogSuspiciousPatterns.FirstOrDefault(p =>
                        content.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (matchedPattern == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Steam Log Contains Cheat/Ban Pattern: {Path.GetFileName(logFile)}",
                        Risk = RiskLevel.Medium,
                        Location = logFile,
                        FileName = Path.GetFileName(logFile),
                        Reason = $"Steam log file '{Path.GetFileName(logFile)}' contains the pattern " +
                                 $"'{matchedPattern}'. Steam log files record anti-cheat events, VAC " +
                                 "authentication, bans, and suspicious activity detected by Valve's systems. " +
                                 "The presence of these patterns may indicate prior cheat detection or ban events.",
                        Detail = $"Path: {logFile} | Pattern: {matchedPattern}"
                    });
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 10: VAC ban artifacts and bypass tools
    // -------------------------------------------------------------------------

    private Task CheckVACBanArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[] { DownloadsDir, DesktopDir, UserTempDir };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);

                    // Check for VAC bypass documentation files
                    if (VacBypassDocFiles.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VAC Ban Bypass Documentation Found: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Documentation file '{fn}' associated with VAC ban bypass techniques " +
                                     "was found. These files contain instructions, scripts, or guides for " +
                                     "evading Valve Anti-Cheat bans, circumventing game bans, or removing " +
                                     "bans via account manipulation techniques.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    // Check for VAC bypass script files by name
                    if (VacBypassScriptNames.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VAC Bypass Script Found: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Script file '{fn}' matches a known VAC bypass automation script name. " +
                                     "These scripts automate steps for bypassing Valve Anti-Cheat, such as " +
                                     "modifying Steam process memory, patching VAC modules, or configuring " +
                                     "tools to evade VAC network scans.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    // Heuristic: any script with vac_bypass, vacbypass, steam_bypass in name
                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    if (ext != ".ps1" && ext != ".bat" && ext != ".py") continue;

                    bool hasVacBypassName =
                        fn.Contains("vac_bypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("vacbypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("steam_bypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("vac_remove", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("unban_steam", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("vac_patch", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("vac_crack", StringComparison.OrdinalIgnoreCase);

                    if (!hasVacBypassName) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"VAC Bypass Script (Heuristic): {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Script '{fn}' has a filename strongly suggesting VAC (Valve Anti-Cheat) " +
                                 "bypass functionality. The filename pattern matches automation scripts used " +
                                 "to circumvent Steam's anti-cheat detection mechanisms.",
                        Detail = $"Path: {file}"
                    });
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 11: Steam installer cheat records (uninstall keys, emulator evidence)
    // -------------------------------------------------------------------------

    private Task CheckSteamInstallerCheatRecords(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // 11a — HKLM Uninstall keys for Steam cheat installer entries
            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            var cheatInstallerKeywords = new[]
            {
                "vac bypass", "steam cheat", "steam hack", "steam inject",
                "goldberg emulator", "ali213", "cream api", "steamemu",
                "steam bypass", "workshop cheat", "workshop bypass",
                "steam api bypass", "steamapi bypass", "steam crack",
                "steam loader", "vacbypass", "vac_bypass",
            };

            foreach (var uninstallPath in uninstallPaths)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var uninstallKey = Registry.LocalMachine.OpenSubKey(
                        uninstallPath, writable: false);
                    if (uninstallKey == null) continue;

                    foreach (var appKey in uninstallKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        try
                        {
                            using var appSubKey = uninstallKey.OpenSubKey(appKey, writable: false);
                            if (appSubKey == null) continue;

                            var displayName = appSubKey.GetValue("DisplayName")?.ToString() ?? "";
                            var publisher = appSubKey.GetValue("Publisher")?.ToString() ?? "";
                            ctx.IncrementRegistryKeys();

                            var combined = displayName + " " + publisher;

                            var matchedKw = cheatInstallerKeywords.FirstOrDefault(k =>
                                combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (matchedKw == null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Steam Cheat Tool Installer Record: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{appKey}",
                                Reason = $"Uninstall entry '{displayName}' (publisher: '{publisher}') contains " +
                                         $"keyword '{matchedKw}' associated with Steam cheat or emulator tools. " +
                                         "This provides evidence that a Steam cheat tool was formally installed " +
                                         "on this system.",
                                Detail = $"DisplayName: {displayName} | Publisher: {publisher} | " +
                                         $"Key: {uninstallPath}\\{appKey}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
                catch (IOException) { }
            }

            // 11b — Goldberg / ALI213 emulator installation file evidence
            var goldbergPaths = new[]
            {
                Path.Combine(LocalAppDataDir, "goldberg_steam_emu"),
                Path.Combine(RoamingAppDataDir, "goldberg_steam_emu"),
                Path.Combine(LocalAppDataDir, "Goldberg Emulator"),
                Path.Combine(RoamingAppDataDir, "Goldberg Emulator"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "goldberg_steam_emu"),
            };

            foreach (var gbPath in goldbergPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(gbPath)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Goldberg Steam Emulator Installation Directory Found",
                    Risk = RiskLevel.High,
                    Location = gbPath,
                    Reason = "The Goldberg Steam Emulator data directory was found. Goldberg Emulator is a " +
                             "well-known Steam DRM bypass tool that replaces the legitimate Steam API to allow " +
                             "games to run without Steam authentication, potentially enabling VAC bypass.",
                    Detail = $"Path: {gbPath}"
                });
            }

            // 11c — ALI213 emulator data directory
            var ali213Paths = new[]
            {
                Path.Combine(LocalAppDataDir, "Ali213"),
                Path.Combine(RoamingAppDataDir, "Ali213"),
                Path.Combine(LocalAppDataDir, "ALI213"),
                Path.Combine(RoamingAppDataDir, "ALI213"),
            };

            foreach (var aliPath in ali213Paths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(aliPath)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "ALI213 Steam Emulator Installation Directory Found",
                    Risk = RiskLevel.High,
                    Location = aliPath,
                    Reason = "The ALI213 Steam Emulator data directory was found. ALI213 is a Steam bypass " +
                             "emulator used to circumvent Steam DRM and authentication. Its presence indicates " +
                             "the system has been configured to run cracked Steam games.",
                    Detail = $"Path: {aliPath}"
                });
            }

            // 11d — Cream API presence in game directories
            var steamDir = ResolveSteamDir();
            var steamAppsCommon = Path.Combine(steamDir, "steamapps", "common");

            if (ct.IsCancellationRequested || !Directory.Exists(steamAppsCommon)) return;

            string[] gameDirs;
            try { gameDirs = Directory.GetDirectories(steamAppsCommon); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var gameDir in gameDirs)
            {
                if (ct.IsCancellationRequested) return;

                // Check for CreamAPI.ini or cream_api.ini as definitive evidence
                foreach (var creamFile in new[] { "CreamAPI.ini", "cream_api.ini", "CreamAPI.dll" })
                {
                    string[] matches;
                    try
                    {
                        matches = Directory.GetFiles(gameDir, creamFile,
                            SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var match in matches)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cream API (Steam DRM Bypass) in Game Directory: {Path.GetFileName(match)}",
                            Risk = RiskLevel.High,
                            Location = match,
                            FileName = Path.GetFileName(match),
                            Reason = $"Cream API file '{Path.GetFileName(match)}' found in Steam game directory " +
                                     $"'{Path.GetFileName(gameDir)}'. Cream API is a Steam DRM bypass that " +
                                     "unlocks DLC without purchase by spoofing Steam ownership calls. It " +
                                     "replaces or augments the steam_api.dll to bypass license checks.",
                            Detail = $"Path: {match} | Game: {Path.GetFileName(gameDir)}"
                        });
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // ROT13 decoder for UserAssist registry values
    // -------------------------------------------------------------------------

    private static string Rot13Decode(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c >= 'a' && c <= 'z')
                sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z')
                sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }
}
