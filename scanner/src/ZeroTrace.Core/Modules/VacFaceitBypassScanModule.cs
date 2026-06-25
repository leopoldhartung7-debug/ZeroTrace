using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

// VAC and FACEIT Anti-Cheat bypass detection module.
// Detects Steam emulators bypassing VAC, VAC bypass DLLs, -insecure launch options,
// FACEIT service tampering, FACEIT bypass tools, Steam API fake DLLs,
// PS history targeting VAC/FACEIT, gameoverlayrenderer64 modifications,
// CS2-specific bypass configs, workshop VPK executable content,
// VAC trust factor tools, fake playtime inflators, and injector payloads in cfg\.
public sealed class VacFaceitBypassScanModule : IScanModule
{
    public string Name => "VAC / FACEIT Bypass Detection";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Steam emulator config file names — bypass VAC by faking the Steam API
    // -------------------------------------------------------------------------
    private static readonly string[] SteamEmulatorConfigFiles =
    [
        "SmartSteamEmu.ini",
        "SmartSteamEmu64.ini",
        "DLLInjector.ini",
        "cream_api.ini",
        "CreamAPI.ini",
        "ALI213.ini",
        "Profile.ini",
        "steam_emu.ini",
        "SteamFake.ini",
        "SteamEmu.ini",
        "goldberg_steam_emu.ini",
        "local_save.txt",
    ];

    // -------------------------------------------------------------------------
    // Steam emulator directory names
    // -------------------------------------------------------------------------
    private static readonly string[] SteamEmulatorDirNames =
    [
        "steam_settings",
        "goldberg_emu",
        "SmartSteamEmu",
        "CreamAPI",
        "ALI213",
        "GreenLuma",
        "SteamEmu",
        "Goldberg_Steam_Emu",
        "steam_emu_settings",
        "cream_api",
    ];

    // -------------------------------------------------------------------------
    // VAC bypass DLL names that appear next to steam.exe
    // -------------------------------------------------------------------------
    private static readonly string[] VacBypassDllNames =
    [
        "steam_api64_bypass.dll",
        "steamapi_bypass.dll",
        "vcruntime_bypass.dll",
        "vac_bypass.dll",
        "VAC_Bypass.dll",
        "vac_hook.dll",
        "steam_bypass.dll",
        "steam64_fake.dll",
        "steamclient_bypass.dll",
        "steamclient64_bypass.dll",
        "steam_api_fake.dll",
        "vac_disable.dll",
        "novac.dll",
        "vac_off.dll",
    ];

    // -------------------------------------------------------------------------
    // FACEIT bypass tool file names
    // -------------------------------------------------------------------------
    private static readonly string[] FaceitBypassFileNames =
    [
        "faceit_bypass.exe",
        "faceit_spoofer.exe",
        "FC_Bypass.dll",
        "faceit_unloader.exe",
        "faceit_killer.exe",
        "FaceitBypass.exe",
        "FC_bypass.exe",
        "faceit_disable.exe",
        "faceit_hook.dll",
        "faceit_hook.exe",
        "FaceitHook.dll",
        "faceit_fake.exe",
        "FACEIT_Bypass.dll",
        "faceit_bypass_v2.dll",
        "fc_spoofer.exe",
        "faceit_patch.exe",
        "faceit_unload.exe",
    ];

    // -------------------------------------------------------------------------
    // FACEIT bypass GitHub repository folder names
    // -------------------------------------------------------------------------
    private static readonly string[] FaceitBypassRepoDirs =
    [
        "faceit-bypass",
        "faceit-ac-bypass",
        "faceit-cheat",
        "FC-Bypass",
        "FaceitBypass",
        "faceit_bypass",
        "faceit-unloader",
        "faceit-spoofer",
        "faceit_ac_bypass",
        "FACEIT-Bypass",
    ];

    // -------------------------------------------------------------------------
    // VAC bypass GitHub repository folder names
    // -------------------------------------------------------------------------
    private static readonly string[] VacBypassRepoDirs =
    [
        "VAC-Bypass",
        "vac-bypass",
        "vac_bypass",
        "VACBypass",
        "vac-emulator",
        "vac_emulator",
        "VACEmulator",
        "novac",
        "no-vac",
        "vac-disable",
    ];

    // -------------------------------------------------------------------------
    // PowerShell history patterns targeting VAC or FACEIT
    // -------------------------------------------------------------------------
    private static readonly (string Pattern, RiskLevel Risk, string Title)[] PsHistoryPatterns =
    [
        ("taskkill /im faceit",           RiskLevel.Critical, "FACEIT Process Killed via taskkill"),
        ("taskkill /f /im faceit",        RiskLevel.Critical, "FACEIT Force-Killed via taskkill"),
        ("sc stop faceit",                RiskLevel.Critical, "FACEIT Service Stopped via sc.exe"),
        ("sc delete faceit",              RiskLevel.Critical, "FACEIT Service Deleted via sc.exe"),
        ("net stop faceit",               RiskLevel.High,     "FACEIT Service Stopped via net stop"),
        ("sc stop VAC",                   RiskLevel.High,     "VAC Service Referenced in sc stop Command"),
        ("taskkill /im faceit-client",    RiskLevel.Critical, "FACEIT Client Process Killed"),
        ("faceit-client-container",       RiskLevel.Medium,   "FACEIT Client Container Referenced"),
        ("vac_bypass",                    RiskLevel.High,     "vac_bypass Keyword in PS History"),
        ("faceit_bypass",                 RiskLevel.High,     "faceit_bypass Keyword in PS History"),
    ];

    // =========================================================================
    // Entry point
    // =========================================================================
    public async Task RunAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await CheckFaceitServiceRegistryAsync(ctx, ct);
        await ScanSteamEmulatorsAsync(ctx, ct);
        await ScanVacBypassDllsNextToSteamAsync(ctx, ct);
        await CheckSteamShortcutsInsecureFlagAsync(ctx, ct);
        await ScanFaceitBypassFilesAsync(ctx, ct);
        await CheckFaceitKillArtifactsAsync(ctx, ct);
        await CheckBypassRepoDirsAsync(ctx, ct);
        await ScanSteamApiFakeDllsAsync(ctx, ct);
        await CheckPowerShellHistoryAsync(ctx, ct);
        await CheckGameoverlayRendererAsync(ctx, ct);
        await CheckCs2InsecureLaunchOptionsAsync(ctx, ct);
        await CheckCs2AutoexecAsync(ctx, ct);
        await ScanWorkshopVpkFilesAsync(ctx, ct);
        await ScanVacTrustManipulationToolsAsync(ctx, ct);
        await ScanCfgDirectoryForPayloadsAsync(ctx, ct);
    }

    // =========================================================================
    // 1. FACEIT Anti-Cheat service registry checks
    // =========================================================================
    private async Task CheckFaceitServiceRegistryAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string[] serviceKeys =
            [
                @"SYSTEM\CurrentControlSet\Services\faceit",
                @"SYSTEM\CurrentControlSet\Services\FaceitService",
                @"SYSTEM\CurrentControlSet\Services\faceit-client-container",
            ];

            foreach (string keyPath in serviceKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null)
                        continue;

                    object? startVal = key.GetValue("Start");
                    if (startVal is int startInt && startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "FACEIT Anti-Cheat Service Disabled in Registry",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"The {Path.GetFileName(keyPath)} service Start value is 4 (Disabled). A bypass tool may have disabled the FACEIT Anti-Cheat service.",
                            Detail   = $"Start = {startInt} (Disabled)",
                        });
                    }

                    object? imagePathVal = key.GetValue("ImagePath");
                    if (imagePathVal is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                    {
                        if (IsInSuspiciousUserPath(imagePath))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "FACEIT Service ImagePath in User-Writable Location",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                Reason   = "The FACEIT service ImagePath references a Temp, Downloads, or AppData directory. The service binary may have been redirected by a bypass tool.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                }
            }
        }, ct);
    }

    // =========================================================================
    // 2. Steam emulators bypassing VAC
    // =========================================================================
    private async Task ScanSteamEmulatorsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] searchRoots = BuildUserScanDirectories();

        // Also check common Steam and game install locations
        List<string> extendedRoots = [..searchRoots];
        extendedRoots.Add(@"C:\Program Files (x86)\Steam");
        extendedRoots.Add(@"C:\Program Files (x86)\Steam\steamapps\common");
        extendedRoots.Add(@"C:\Program Files\Steam");

        foreach (string dir in extendedRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> allFiles;
            try
            {
                allFiles = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in allFiles)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    string fileName = Path.GetFileName(filePath);
                    ctx.IncrementFiles();

                    foreach (string emuFile in SteamEmulatorConfigFiles)
                    {
                        if (fileName.Equals(emuFile, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Steam Emulator Config File Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File \"{fileName}\" is a Steam emulator configuration file. Steam emulators bypass VAC by faking the Steam API without connecting to Valve servers.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        await ScanSteamEmulatorDirsAsync(ctx, ct);
    }

    private async Task ScanSteamEmulatorDirsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] searchRoots =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            ];

            foreach (string root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
                    continue;

                IEnumerable<string> subDirs;
                try
                {
                    subDirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string subDir in subDirs)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        string dirName = Path.GetFileName(subDir);

                        foreach (string emuDir in SteamEmulatorDirNames)
                        {
                            if (dirName.Equals(emuDir, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "Steam Emulator Directory Detected",
                                    Risk     = RiskLevel.Critical,
                                    Location = subDir,
                                    Reason   = $"Directory \"{dirName}\" matches a known Steam emulator folder name. Steam emulators bypass VAC by replacing the Steam API without connecting to Valve servers.",
                                    Detail   = $"Matched pattern: {emuDir}",
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 3. VAC bypass DLLs next to steam.exe
    // =========================================================================
    private async Task ScanVacBypassDllsNextToSteamAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string[] steamExePaths =
            [
                @"C:\Program Files (x86)\Steam\steam.exe",
                @"C:\Program Files\Steam\steam.exe",
            ];

            foreach (string steamExe in steamExePaths)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(steamExe))
                    continue;

                string steamDir = Path.GetDirectoryName(steamExe) ?? string.Empty;
                if (string.IsNullOrEmpty(steamDir))
                    continue;

                IEnumerable<string> dllFiles;
                try
                {
                    dllFiles = Directory.EnumerateFiles(steamDir, "*.dll", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string dllPath in dllFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        string fileName = Path.GetFileName(dllPath);

                        foreach (string bad in VacBypassDllNames)
                        {
                            if (fileName.Equals(bad, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "VAC Bypass DLL Found Next to steam.exe",
                                    Risk     = RiskLevel.Critical,
                                    Location = dllPath,
                                    FileName = fileName,
                                    Reason   = $"DLL \"{fileName}\" is a known VAC bypass file and is located in the Steam installation directory next to steam.exe. This DLL intercepts Steam API calls to disable VAC.",
                                    Detail   = $"Steam directory: {steamDir}",
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 4. Steam shortcut files with -insecure launch flag
    // =========================================================================
    private async Task CheckSteamShortcutsInsecureFlagAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] steamShortcutDirs =
        [
            @"C:\Program Files (x86)\Steam\userdata",
            @"C:\Program Files\Steam\userdata",
        ];

        foreach (string shortcutRoot in steamShortcutDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(shortcutRoot))
                continue;

            IEnumerable<string> shortcutFiles;
            try
            {
                shortcutFiles = Directory.EnumerateFiles(shortcutRoot, "shortcuts.vdf", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string shortcutPath in shortcutFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectShortcutFileAsync(ctx, shortcutPath, ct);
            }
        }
    }

    private async Task InspectShortcutFileAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string shortcutPath,
        CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(shortcutPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        ct.ThrowIfCancellationRequested();

        if (content.Contains("-insecure", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Steam Shortcut Contains -insecure Launch Flag",
                Risk     = RiskLevel.High,
                Location = shortcutPath,
                FileName = Path.GetFileName(shortcutPath),
                Reason   = "A Steam shortcuts.vdf file contains the '-insecure' flag. This flag disables VAC protection for the launched game, allowing unsigned code and cheats to run without triggering VAC.",
                Detail   = ExtractMatchingLine(content, "-insecure"),
            });
        }
    }

    // =========================================================================
    // 5. FACEIT bypass tool files
    // =========================================================================
    private async Task ScanFaceitBypassFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs = BuildUserScanDirectories();

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    string fileName = Path.GetFileName(filePath);
                    ctx.IncrementFiles();

                    foreach (string bad in FaceitBypassFileNames)
                    {
                        if (fileName.Equals(bad, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Known FACEIT Bypass Tool File Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File \"{fileName}\" matches a known FACEIT Anti-Cheat bypass tool name.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 6. FACEIT kill artifacts — evidence that faceit-client-container was stopped
    // =========================================================================
    private async Task CheckFaceitKillArtifactsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check for service deletion artifacts in the event log via registry remnants
            string[] deletedServicePaths =
            [
                @"SYSTEM\CurrentControlSet\Services\faceit",
                @"SYSTEM\CurrentControlSet\Services\FaceitService",
            ];

            foreach (string keyPath in deletedServicePaths)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null)
                        continue;

                    // If the service key exists but has no ImagePath or DisplayName,
                    // it may be a remnant after forcible deletion/modification
                    object? displayName = key.GetValue("DisplayName");
                    object? imagePath   = key.GetValue("ImagePath");

                    if (displayName is null && imagePath is null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "FACEIT Service Registry Key Has No ImagePath or DisplayName",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = "The FACEIT service registry key exists but has neither ImagePath nor DisplayName values, which is anomalous. The service may have been partially deleted or stripped by a bypass tool.",
                            Detail   = $"Key: HKLM\\{keyPath}",
                        });
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                }
            }

            // Check for FACEIT client container kill artifact files
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string faceitDir    = Path.Combine(localAppData, "Programs", "FACEIT Client");

            if (!Directory.Exists(faceitDir))
                return;

            // Look for crash dumps or forcible-exit artifacts
            IEnumerable<string> dumpFiles;
            try
            {
                dumpFiles = Directory.EnumerateFiles(faceitDir, "*.dmp", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                return;
            }

            foreach (string dumpPath in dumpFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    var fi = new FileInfo(dumpPath);
                    // A fresh dump (< 1 hour old) is suspicious
                    if ((DateTime.UtcNow - fi.LastWriteTimeUtc).TotalHours < 1.0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Recent FACEIT Client Crash Dump Found",
                            Risk     = RiskLevel.Medium,
                            Location = dumpPath,
                            FileName = Path.GetFileName(dumpPath),
                            Reason   = "A very recent FACEIT client crash dump was found. FACEIT bypass tools frequently cause the client to crash by forcibly terminating it.",
                            Detail   = $"Last write: {fi.LastWriteTimeUtc:u}",
                        });
                    }
                }
                catch (IOException)
                {
                }
            }
        }, ct);
    }

    // =========================================================================
    // 7. VAC and FACEIT bypass GitHub repository directories
    // =========================================================================
    private async Task CheckBypassRepoDirsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] searchRoots =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            ];

            foreach (string root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
                    continue;

                IEnumerable<string> subDirs;
                try
                {
                    subDirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string subDir in subDirs)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        string dirName = Path.GetFileName(subDir);

                        foreach (string repoName in FaceitBypassRepoDirs)
                        {
                            if (dirName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "FACEIT Bypass Repository Directory Found",
                                    Risk     = RiskLevel.High,
                                    Location = subDir,
                                    Reason   = $"Directory \"{dirName}\" matches a known FACEIT bypass GitHub repository name. The user likely cloned or possesses bypass source code.",
                                    Detail   = $"Matched pattern: {repoName}",
                                });
                                break;
                            }
                        }

                        foreach (string repoName in VacBypassRepoDirs)
                        {
                            if (dirName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "VAC Bypass Repository Directory Found",
                                    Risk     = RiskLevel.High,
                                    Location = subDir,
                                    Reason   = $"Directory \"{dirName}\" matches a known VAC bypass GitHub repository name. The user likely cloned or possesses bypass source code.",
                                    Detail   = $"Matched pattern: {repoName}",
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 8. Fake Steam API DLLs next to game executables
    // =========================================================================
    private async Task ScanSteamApiFakeDllsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] gameLibraries =
        [
            @"C:\Program Files (x86)\Steam\steamapps\common",
            @"C:\Program Files\Steam\steamapps\common",
        ];

        string[] fakeDllPatterns =
        [
            "steam_api64_bypass.dll",
            "steamapi_bypass.dll",
            "vcruntime_bypass.dll",
            "steam_api_fake.dll",
            "steamclient_bypass.dll",
        ];

        foreach (string library in gameLibraries)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(library))
                continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(library, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string dllPath in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    string fileName = Path.GetFileName(dllPath);

                    foreach (string pattern in fakeDllPatterns)
                    {
                        if (fileName.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Fake Steam API DLL in Game Directory",
                                Risk     = RiskLevel.Critical,
                                Location = dllPath,
                                FileName = fileName,
                                Reason   = $"DLL \"{fileName}\" is a known fake or bypass Steam API file. These DLLs intercept Steam API calls to bypass VAC without connecting to Valve servers.",
                                Detail   = $"Game directory: {Path.GetDirectoryName(dllPath)}",
                            });
                            break;
                        }
                    }

                    // Also flag any steam_api*.dll in a game directory that has 'bypass' or 'fake' in the name
                    if (fileName.StartsWith("steam_api", StringComparison.OrdinalIgnoreCase)
                        && (fileName.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                            || fileName.Contains("fake", StringComparison.OrdinalIgnoreCase)
                            || fileName.Contains("hack", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Suspicious steam_api DLL Name in Game Directory",
                            Risk     = RiskLevel.High,
                            Location = dllPath,
                            FileName = fileName,
                            Reason   = $"DLL \"{fileName}\" starts with 'steam_api' but contains a suspicious suffix ('bypass', 'fake', or 'hack'). This may be a fake Steam API planted to bypass VAC.",
                            Detail   = $"Game directory: {Path.GetDirectoryName(dllPath)}",
                        });
                    }
                }
                catch (IOException)
                {
                }
            }
        }
    }

    // =========================================================================
    // 9. PowerShell history targeting VAC or FACEIT
    // =========================================================================
    private async Task CheckPowerShellHistoryAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string historyPath = Path.Combine(
            appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (!File.Exists(historyPath))
            return;

        ctx.IncrementFiles();

        string content;
        try
        {
            using var fs = new FileStream(historyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var (pattern, risk, title) in PsHistoryPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"VAC/FACEIT Command in PS History: {title}",
                    Risk     = risk,
                    Location = historyPath,
                    FileName = Path.GetFileName(historyPath),
                    Reason   = $"PowerShell history contains the pattern \"{pattern}\", indicating an attempt to interfere with VAC or FACEIT Anti-Cheat.",
                    Detail   = ExtractMatchingLine(content, pattern),
                });
                break;
            }
        }

        // Additional combined check: GreenLuma referenced in PS history
        if (content.Contains("GreenLuma", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "GreenLuma Steam Emulator Referenced in PS History",
                Risk     = RiskLevel.High,
                Location = historyPath,
                FileName = Path.GetFileName(historyPath),
                Reason   = "PowerShell history references 'GreenLuma', a Steam emulator that bypasses VAC by faking game ownership and disabling VAC checks.",
                Detail   = ExtractMatchingLine(content, "GreenLuma"),
            });
        }
    }

    // =========================================================================
    // 10. Modified gameoverlayrenderer64.dll in game directories
    // =========================================================================
    private async Task CheckGameoverlayRendererAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // The legitimate gameoverlayrenderer64.dll lives only in the Steam installation
            string[] legitSteamDirs =
            [
                @"C:\Program Files (x86)\Steam",
                @"C:\Program Files\Steam",
            ];

            // Search game directories for a modified copy
            string[] gameLibraries =
            [
                @"C:\Program Files (x86)\Steam\steamapps\common",
                @"C:\Program Files\Steam\steamapps\common",
            ];

            string steamInstallDir = string.Empty;
            foreach (string dir in legitSteamDirs)
            {
                if (Directory.Exists(dir))
                {
                    steamInstallDir = dir;
                    break;
                }
            }

            foreach (string library in gameLibraries)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(library))
                    continue;

                IEnumerable<string> overlayDlls;
                try
                {
                    overlayDlls = Directory.EnumerateFiles(
                        library, "gameoverlayrenderer64.dll", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string dllPath in overlayDlls)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        // A copy inside a game subdirectory (not inside the Steam root) is suspicious
                        bool inSteamRoot = !string.IsNullOrEmpty(steamInstallDir)
                            && dllPath.StartsWith(steamInstallDir, StringComparison.OrdinalIgnoreCase);

                        // The file should be in Steam root bin/ folder, not in a game directory
                        bool inGameDir = dllPath.StartsWith(library, StringComparison.OrdinalIgnoreCase);

                        if (inGameDir && !inSteamRoot)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "gameoverlayrenderer64.dll Found in Game Directory (Possible Modification)",
                                Risk     = RiskLevel.High,
                                Location = dllPath,
                                FileName = "gameoverlayrenderer64.dll",
                                Reason   = "gameoverlayrenderer64.dll was found inside a game directory rather than the Steam installation folder. A modified overlay renderer is used to hook VAC memory scanning calls.",
                                Detail   = $"Game directory: {Path.GetDirectoryName(dllPath)}",
                            });
                        }
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 11. CS2 -insecure launch options and gameinfo.gi modifications
    // =========================================================================
    private async Task CheckCs2InsecureLaunchOptionsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] cs2Dirs =
        [
            @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive",
            @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike 2",
        ];

        foreach (string cs2Dir in cs2Dirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cs2Dir))
                continue;

            // Check for gameinfo.gi modifications
            IEnumerable<string> gameInfoFiles;
            try
            {
                gameInfoFiles = Directory.EnumerateFiles(cs2Dir, "gameinfo.gi", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string gameInfoPath in gameInfoFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectGameInfoFileAsync(ctx, gameInfoPath, ct);
            }
        }

        // Check Steam local config for -insecure launch option for CS2
        await CheckSteamLocalConfigForInsecureAsync(ctx, ct);
    }

    private async Task InspectGameInfoFileAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string gameInfoPath,
        CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(gameInfoPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        ct.ThrowIfCancellationRequested();

        // Look for added search paths pointing to outside the game directory (cheat DLL search path injection)
        if (content.Contains("Game\t\t|gameinfo_path", StringComparison.OrdinalIgnoreCase)
            && content.Contains(@"..\..", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "CS2 gameinfo.gi Contains Suspicious External Search Path",
                Risk     = RiskLevel.High,
                Location = gameInfoPath,
                FileName = "gameinfo.gi",
                Reason   = "gameinfo.gi contains an external path traversal in a Game search path entry. This technique is used to load cheat DLLs by adding them to the game's VPK search path.",
                Detail   = ExtractMatchingLine(content, @"..\..")
            });
        }
    }

    private async Task CheckSteamLocalConfigForInsecureAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] steamUserDataRoots =
        [
            @"C:\Program Files (x86)\Steam\userdata",
            @"C:\Program Files\Steam\userdata",
        ];

        foreach (string udRoot in steamUserDataRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(udRoot))
                continue;

            IEnumerable<string> localConfigFiles;
            try
            {
                localConfigFiles = Directory.EnumerateFiles(udRoot, "localconfig.vdf", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string configPath in localConfigFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException)
                {
                    continue;
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                if (content.Contains("-insecure", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Steam localconfig.vdf Contains -insecure Launch Option",
                        Risk     = RiskLevel.High,
                        Location = configPath,
                        FileName = Path.GetFileName(configPath),
                        Reason   = "Steam localconfig.vdf contains the '-insecure' launch option. This disables VAC for the configured game, allowing cheats to run without triggering VAC bans.",
                        Detail   = ExtractMatchingLine(content, "-insecure"),
                    });
                }
            }
        }
    }

    // =========================================================================
    // 12. CS2 autoexec.cfg with sv_cheats 1 in online context
    // =========================================================================
    private async Task CheckCs2AutoexecAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] cs2CfgRoots =
        [
            @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\cfg",
            @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike 2\game\csgo\cfg",
        ];

        foreach (string cfgRoot in cs2CfgRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cfgRoot))
                continue;

            IEnumerable<string> cfgFiles;
            try
            {
                cfgFiles = Directory.EnumerateFiles(cfgRoot, "*.cfg", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string cfgPath in cfgFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectCfgFileAsync(ctx, cfgPath, ct);
            }
        }
    }

    private async Task InspectCfgFileAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string cfgPath,
        CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(cfgPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        ct.ThrowIfCancellationRequested();

        string fileName = Path.GetFileName(cfgPath);

        if (content.Contains("sv_cheats", StringComparison.OrdinalIgnoreCase)
            && content.Contains("1", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"CS2/CSGO cfg File Contains sv_cheats 1",
                Risk     = RiskLevel.Medium,
                Location = cfgPath,
                FileName = fileName,
                Reason   = $"CS2/CSGO config file \"{fileName}\" contains 'sv_cheats 1'. Setting sv_cheats in an autoexec or startup cfg is used to enable cheat commands in online play through console variable manipulation.",
                Detail   = ExtractMatchingLine(content, "sv_cheats"),
            });
        }

        // Check for injector commands in cfg files (exec + payload pattern)
        string[] injectorCmds =
        [
            "exec payload",
            "exec inject",
            "exec cheat",
            "exec hack",
            "exec loader",
        ];

        foreach (string cmd in injectorCmds)
        {
            if (content.Contains(cmd, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"CS2 cfg File Contains Suspicious exec Command",
                    Risk     = RiskLevel.High,
                    Location = cfgPath,
                    FileName = fileName,
                    Reason   = $"CS2 config file contains the suspicious command \"{cmd}\". This pattern is used to execute a separate payload or cheat configuration file at game startup.",
                    Detail   = ExtractMatchingLine(content, cmd),
                });
                return;
            }
        }
    }

    // =========================================================================
    // 13. Workshop VPK files with executable content
    // =========================================================================
    private async Task ScanWorkshopVpkFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] workshopRoots =
        [
            @"C:\Program Files (x86)\Steam\steamapps\workshop\content",
            @"C:\Program Files\Steam\steamapps\workshop\content",
        ];

        foreach (string workshopRoot in workshopRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(workshopRoot))
                continue;

            IEnumerable<string> vpkFiles;
            try
            {
                vpkFiles = Directory.EnumerateFiles(workshopRoot, "*.vpk", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string vpkPath in vpkFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectVpkFileAsync(ctx, vpkPath, ct);
            }
        }
    }

    private async Task InspectVpkFileAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string vpkPath,
        CancellationToken ct)
    {
        // Read first 4KB of the VPK to check for embedded PE content
        byte[] buffer = new byte[4096];
        int bytesRead;

        try
        {
            using var fs = new FileStream(vpkPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            bytesRead = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (bytesRead < 4)
            return;

        // Check for embedded PE MZ header inside the VPK (executable content)
        for (int i = 0; i < bytesRead - 1; i++)
        {
            if (buffer[i] == 0x4D && buffer[i + 1] == 0x5A)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Workshop VPK File Contains Embedded PE Executable",
                    Risk     = RiskLevel.Critical,
                    Location = vpkPath,
                    FileName = Path.GetFileName(vpkPath),
                    Reason   = "A Workshop VPK file contains an embedded PE (MZ) header, indicating executable content inside a mod archive. This is used to smuggle cheat code past VAC's workshop file validation.",
                    Detail   = $"MZ signature found at offset {i}",
                });
                return;
            }
        }

        // Also flag VPK files with suspicious names
        string fileName = Path.GetFileName(vpkPath);
        string[] suspVpkNames =
        [
            "cheat",
            "hack",
            "inject",
            "bypass",
            "aimbot",
            "wallhack",
            "esp",
        ];

        foreach (string suspect in suspVpkNames)
        {
            if (fileName.Contains(suspect, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Suspicious Workshop VPK File Name",
                    Risk     = RiskLevel.High,
                    Location = vpkPath,
                    FileName = fileName,
                    Reason   = $"Workshop VPK file name contains '{suspect}', which is associated with cheat content distributed through the Steam Workshop.",
                    Detail   = $"Full path: {vpkPath}",
                });
                return;
            }
        }
    }

    // =========================================================================
    // 14. VAC trust factor manipulation tools and fake playtime inflators
    // =========================================================================
    private async Task ScanVacTrustManipulationToolsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs = BuildUserScanDirectories();

        string[] trustManipFileNames =
        [
            "playtime_booster.exe",
            "steam_playtime.exe",
            "fake_playtime.exe",
            "idle_master.exe",
            "IdleMaster.exe",
            "steam_idle.exe",
            "trust_booster.exe",
            "vac_trust.exe",
            "account_booster.exe",
            "playtime_farmer.exe",
            "steam_farmer.exe",
            "game_idler.exe",
            "hours_boost.exe",
            "steam_hours.exe",
        ];

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    string fileName = Path.GetFileName(filePath);
                    ctx.IncrementFiles();

                    foreach (string bad in trustManipFileNames)
                    {
                        if (fileName.Equals(bad, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "VAC Trust Factor Manipulation Tool Detected",
                                Risk     = RiskLevel.Medium,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File \"{fileName}\" matches a known VAC trust factor manipulation or fake playtime inflator tool. These tools artificially boost Steam account metrics to improve VAC trust scores.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 15. CSGO/CS2 cfg\ directory with injector payloads
    // =========================================================================
    private async Task ScanCfgDirectoryForPayloadsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] cfgRoots =
        [
            @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\cfg",
            @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike 2\game\csgo\cfg",
        ];

        string[] payloadKeywords =
        [
            "inject",
            "payload",
            "loader",
            "cheat",
            "hack",
            "aimbot",
            "wallhack",
            "esp",
            "bypass",
            "triggerbot",
        ];

        foreach (string cfgRoot in cfgRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cfgRoot))
                continue;

            IEnumerable<string> allFiles;
            try
            {
                allFiles = Directory.EnumerateFiles(cfgRoot, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in allFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    string fileName = Path.GetFileName(filePath);

                    // Flag non-.cfg files in the cfg directory — these are anomalous
                    string ext = Path.GetExtension(filePath);
                    if (!ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Non-cfg File in CS2 cfg\\ Directory",
                            Risk     = RiskLevel.Medium,
                            Location = filePath,
                            FileName = fileName,
                            Reason   = $"File \"{fileName}\" with extension '{ext}' was found in the CS2 cfg\\ directory. Only .cfg files should be present; other files may be injector payloads or cheat configs.",
                            Detail   = $"cfg directory: {cfgRoot}",
                        });
                        continue;
                    }

                    // Inspect .cfg content for payload keywords
                    await InspectCfgPayloadAsync(ctx, filePath, payloadKeywords, cfgRoot, ct);
                }
                catch (IOException)
                {
                }
            }
        }
    }

    private async Task InspectCfgPayloadAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string cfgPath,
        string[] keywords,
        string cfgRoot,
        CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(cfgPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        ct.ThrowIfCancellationRequested();

        string fileName = Path.GetFileName(cfgPath);

        foreach (string keyword in keywords)
        {
            if (fileName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Suspicious cfg File Name in CS2 cfg\\ Directory",
                    Risk     = RiskLevel.High,
                    Location = cfgPath,
                    FileName = fileName,
                    Reason   = $"cfg file name \"{fileName}\" contains the keyword '{keyword}', suggesting it is a cheat or injector configuration placed in the CS2 cfg directory.",
                    Detail   = $"cfg root: {cfgRoot}",
                });
                return;
            }
        }
    }

    // =========================================================================
    // Private utility helpers
    // =========================================================================

    private static string[] BuildUserScanDirectories()
    {
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string desktop      = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string userProfile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloads    = Path.Combine(userProfile, "Downloads");
        string systemTemp   = Path.GetTempPath();
        string localTemp    = Path.Combine(localAppData, "Temp");

        return
        [
            desktop,
            downloads,
            systemTemp,
            localTemp,
            appData,
            localAppData,
        ];
    }

    private static bool IsInSuspiciousUserPath(string path)
    {
        string[] fragments =
        [
            @"\Temp\",
            @"\Downloads\",
            @"\AppData\",
        ];

        foreach (string fragment in fragments)
        {
            if (path.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        string[] endings =
        [
            @"\Temp",
            @"\Downloads",
            @"\AppData",
        ];

        foreach (string ending in endings)
        {
            if (path.EndsWith(ending, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string ExtractMatchingLine(string content, string pattern)
    {
        foreach (string line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return line.Trim();
        }

        return string.Empty;
    }
}
