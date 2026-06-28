using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class GtaVModMenuCheatScanModule : IScanModule
{
    public string Name => "GTA-V-ModMenu-Cheat";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    // ─── GTA V static install path candidates ────────────────────────────────

    private static readonly string[] StaticGtaVPaths =
    {
        @"C:\Program Files\Rockstar Games\Grand Theft Auto V",
        @"C:\Program Files (x86)\Rockstar Games\Grand Theft Auto V",
        @"D:\Rockstar Games\Grand Theft Auto V",
        @"D:\Grand Theft Auto V",
        @"C:\Games\Grand Theft Auto V",
        @"C:\Program Files\Epic Games\GTAV",
    };

    // ─── Known cheat DLL names (Critical when present in GTA V install dir) ──

    private static readonly HashSet<string> KnownCheatDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "menyoo.dll", "lambda.dll", "orbital.dll", "cherax.dll",
        "2take1.dll", "stand.dll", "midnight.dll", "brute.dll",
        "nova.dll", "phantom.dll", "kiddion.dll",
    };

    // ─── Proxy / wrapper DLLs (Medium unless paired with other indicators) ───

    private static readonly HashSet<string> AmbiguousProxyDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "dinput8.dll", "dsound.dll", "version.dll",
    };

    // ─── Name fragments that flag an ASI as a cheat ──────────────────────────

    private static readonly string[] CheatAsiPatterns =
    {
        "menyoo", "lambda", "kiddion", "stand", "cherax", "orbital",
        "2take1", "brute", "midnight", "nova", "phantom", "trainer",
        "modmenu", "godmode", "money", "esp", "aimbot", "cheat", "hack",
    };

    // ─── ScriptHookV log keywords that upgrade risk to High ──────────────────

    private static readonly string[] ScriptHookLogCheatNames =
    {
        "menyoo", "lambda", "stand", "cherax", "kiddion",
        "orbital", "2take1", "brute", "midnight", "nova", "phantom",
    };

    // ─── Config-file cheat feature keywords ──────────────────────────────────

    private static readonly string[] ConfigCheatKeywords =
    {
        "godMode", "godmode", "neverWanted", "neverwanted",
        "moneyDrop", "moneydrop", "vehicleSpawn", "vehiclespawn",
        "teleport", "invisible", "aimbot", "esp", "wallhack",
        "noclip", "infiniteAmmo", "infiniteammo", "superJump",
        "superSpeed", "rapidFire", "undetected", "bypass", "antiban",
    };

    // ─── Known mod menu EXE names (used by Section 3 and Section 4) ──────────

    private static readonly HashSet<string> KnownModMenuExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "menyoo.exe", "menyoopc.exe", "kiddion.exe", "kiddionsmb.exe",
        "kiddions_mb.exe", "modest_menu.exe", "lambdamenu.exe",
        "lambda_menu.exe", "orbital_menu.exe", "cherax.exe",
        "2take1.exe", "2take1menu.exe", "brute.exe", "brutemenu.exe",
        "midnight.exe", "midnight_menu.exe", "stand_menu.exe", "stand.exe",
        "nova_menu.exe", "phantom_gta.exe", "wexternal.exe",
        "gtao_cheats.exe", "online_cheats.exe",
    };

    // ─── GTA Online script cheat keywords (Section 6) ────────────────────────

    private static readonly string[] ScriptCheatKeywords =
    {
        "MoneyDrop", "CasinoHack", "MoneyGlitch", "RP_Boost",
        "casino_cheat", "GtaOnline", "gta_online",
    };

    // ─── Prefetch name prefixes (Section 7) ──────────────────────────────────

    private static readonly string[] PrefetchPatterns =
    {
        "MENYOO", "KIDDION", "LAMBDAMENU", "2TAKE1", "CHERAX",
        "ORBITAL", "STAND", "MIDNIGHT", "BRUTE", "NOVA", "WEXTERNAL",
    };

    // ─── GTA V commandline.txt anti-detect flags (Section 5) ─────────────────

    private static readonly string[] CommandlineAntiDetectFlags =
    {
        "-nocheatdetect", "-noanticheat", "-novac",
        "sv_cheats", "-novrnotification",
    };

    // ─── Rockstar / GTA V log cheat keywords (Section 5) ─────────────────────

    private static readonly string[] RockstarLogCheatKeywords =
    {
        "ScriptHookV", "menyoo", "kiddion", "stand", "cherax",
        "lambda", "2take1", "orbital", "brute", "midnight", "nova", "phantom",
    };

    // ─── Entry point ─────────────────────────────────────────────────────────

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(async () =>
        {
            // Section 1: GTA V install directory scan
            var gtaVDirs = FindGtaVInstallDirectories(ctx, ct);
            foreach (var dir in gtaVDirs)
            {
                ct.ThrowIfCancellationRequested();
                await ScanGtaVInstallDirectoryAsync(ctx, dir, ct).ConfigureAwait(false);
            }

            ctx.Report(0.20, "GTA V install dir", "GTA V install directories scanned");

            // Section 2: known mod menu AppData directories
            await ScanModMenuAppDataDirectoriesAsync(ctx, ct).ConfigureAwait(false);
            ctx.Report(0.42, "Mod menu AppData", "Mod menu AppData directories scanned");

            // Section 3: known mod menu executables on disk
            await ScanKnownModMenuExecutablesAsync(ctx, ct).ConfigureAwait(false);
            ctx.Report(0.58, "Mod menu EXEs", "Known mod menu executables scanned");

            // Section 4: running process detection
            ScanRunningProcesses(ctx, ct);
            ctx.Report(0.65, "Running processes", "Running processes checked");

            // Section 5: Rockstar Social Club / R* config tamper
            await ScanRockstarConfigAndLogsAsync(ctx, ct).ConfigureAwait(false);
            ctx.Report(0.75, "Rockstar config", "Rockstar config and logs scanned");

            // Section 6: GTAO money/casino cheat scripts
            await ScanGtaoScriptFilesAsync(ctx, ct).ConfigureAwait(false);
            ctx.Report(0.88, "GTAO scripts", "GTA Online cheat script files scanned");

            // Section 7: Prefetch scan
            ScanPrefetchDirectory(ctx, ct);
            ctx.Report(1.0, "Prefetch", "Prefetch artifacts scanned");

        }, ct);
    }

    // ─── Section 1 helper: find GTA V install directories ────────────────────

    private static List<string> FindGtaVInstallDirectories(ScanContext ctx, CancellationToken ct)
    {
        var found = new List<string>();

        foreach (var path in StaticGtaVPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (Directory.Exists(path) &&
                !found.Contains(path, StringComparer.OrdinalIgnoreCase))
            {
                found.Add(path);
            }
        }

        // Check Steam registry for GTA V install dir (App ID 271590)
        try
        {
            using var steamAppsKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Valve\Steam\Apps\271590");
            if (steamAppsKey != null)
            {
                ctx.IncrementRegistryKeys();
                var installDir = steamAppsKey.GetValue("InstallDir") as string;
                if (!string.IsNullOrEmpty(installDir) &&
                    Directory.Exists(installDir) &&
                    !found.Contains(installDir, StringComparer.OrdinalIgnoreCase))
                {
                    found.Add(installDir);
                }
            }
        }
        catch (Exception) { }

        return found;
    }

    // ─── Section 1: scan one GTA V install directory ─────────────────────────

    private static async Task ScanGtaVInstallDirectoryAsync(
        ScanContext ctx, string gtaDir, CancellationToken ct)
    {
        bool hasOtherCheatIndicator = false;
        bool hasScriptHookV = false;
        bool hasAsiLoader = false;

        string[] rootFiles;
        try
        {
            rootFiles = Directory.GetFiles(gtaDir, "*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (DirectoryNotFoundException) { return; }
        catch (IOException) { return; }

        foreach (var file in rootFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fileName = Path.GetFileName(file);
            var fileNameLower = fileName.ToLowerInvariant();
            var ext = Path.GetExtension(fileNameLower);

            // Known cheat DLLs → Critical
            if (KnownCheatDlls.Contains(fileName))
            {
                hasOtherCheatIndicator = true;
                ctx.AddFinding(new Finding
                {
                    Module = "GTA-V-ModMenu-Cheat",
                    Title = $"GTA V: Known cheat DLL in install directory: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known GTA V mod menu DLL '{fileName}' found directly in GTA V install directory. " +
                             "This DLL is injected into GTA V at startup to enable cheat features " +
                             "such as god mode, money drops, and aimbot.",
                    Detail = $"Path={file} GtaVDir={gtaDir}",
                });
                continue;
            }

            // Ambiguous proxy DLLs → Medium (unless paired with other indicators later)
            if (AmbiguousProxyDlls.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "GTA-V-ModMenu-Cheat",
                    Title = $"GTA V: Proxy/ASI loader DLL present: {fileName}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Proxy wrapper DLL '{fileName}' found in GTA V directory. " +
                             "This DLL is commonly used as an ASI loader to inject mod menus and cheat plugins. " +
                             "Not conclusive on its own but indicates a modified GTA V installation.",
                    Detail = $"Path={file} GtaVDir={gtaDir}",
                });
                continue;
            }

            // ScriptHookV.dll — will be assessed after checking the log
            if (string.Equals(fileNameLower, "scripthookv.dll", StringComparison.OrdinalIgnoreCase))
            {
                hasScriptHookV = true;
                continue;
            }

            // ASI loader log files signal an active ASI loader
            if (string.Equals(fileNameLower, "scripthookv.log", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(fileNameLower, "asiloader.log", StringComparison.OrdinalIgnoreCase))
            {
                hasAsiLoader = true;
                continue;
            }

            // ASI files
            if (ext == ".asi")
            {
                hasAsiLoader = true;
                var baseNameLower = Path.GetFileNameWithoutExtension(fileNameLower);
                var matchedPattern = string.Empty;

                foreach (var pattern in CheatAsiPatterns)
                {
                    if (baseNameLower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        matchedPattern = pattern;
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(matchedPattern))
                {
                    hasOtherCheatIndicator = true;
                    ctx.AddFinding(new Finding
                    {
                        Module = "GTA-V-ModMenu-Cheat",
                        Title = $"GTA V: Cheat-named ASI file in install directory: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"ASI plugin '{fileName}' in GTA V directory matches known cheat pattern '{matchedPattern}'. " +
                                 "ASI files are the primary delivery format for GTA V mod menus and cheat plugins.",
                        Detail = $"Path={file} MatchedPattern={matchedPattern} GtaVDir={gtaDir}",
                    });
                }
                else
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "GTA-V-ModMenu-Cheat",
                        Title = $"GTA V: ASI loader plugin present: {fileName}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = fileName,
                        Reason = $"ASI file '{fileName}' found in GTA V directory. " +
                                 "ASI files require an ASI loader (dinput8/dsound/version proxy) and " +
                                 "are used to load mods, scripts, and cheat menus into GTA V.",
                        Detail = $"Path={file} GtaVDir={gtaDir}",
                    });
                }
            }
        }

        // Evaluate ScriptHookV — check its log for cheat references
        if (hasScriptHookV)
        {
            var scriptHookPath = Path.Combine(gtaDir, "ScriptHookV.dll");
            var scriptHookLogPath = Path.Combine(gtaDir, "ScriptHookV.log");
            bool logHasCheat = false;
            var logCheatName = string.Empty;

            if (File.Exists(scriptHookLogPath))
            {
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(
                        scriptHookLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8,
                        detectEncodingFromByteOrderMarks: true, bufferSize: 4096, leaveOpen: false);
                    string? line;
                    while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) != null)
                    {
                        ct.ThrowIfCancellationRequested();
                        foreach (var name in ScriptHookLogCheatNames)
                        {
                            if (line.Contains(name, StringComparison.OrdinalIgnoreCase))
                            {
                                logHasCheat = true;
                                logCheatName = name;
                                break;
                            }
                        }
                        if (logHasCheat) break;
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            if (logHasCheat)
            {
                hasOtherCheatIndicator = true;
                ctx.AddFinding(new Finding
                {
                    Module = "GTA-V-ModMenu-Cheat",
                    Title = $"GTA V: ScriptHookV.log references cheat tool '{logCheatName}'",
                    Risk = RiskLevel.High,
                    Location = scriptHookLogPath,
                    FileName = "ScriptHookV.log",
                    Reason = $"ScriptHookV.log contains a reference to known GTA V cheat tool '{logCheatName}'. " +
                             "ScriptHookV is required by most mod menus; this log entry confirms active cheat use.",
                    Detail = $"GtaVDir={gtaDir} CheatName={logCheatName} LogPath={scriptHookLogPath}",
                });
            }
            else
            {
                var riskLevel = (hasOtherCheatIndicator || hasAsiLoader)
                    ? RiskLevel.High
                    : RiskLevel.Medium;

                ctx.AddFinding(new Finding
                {
                    Module = "GTA-V-ModMenu-Cheat",
                    Title = "GTA V: ScriptHookV.dll present in install directory",
                    Risk = riskLevel,
                    Location = scriptHookPath,
                    FileName = "ScriptHookV.dll",
                    Reason = "ScriptHookV.dll found in GTA V install directory. " +
                             "ScriptHookV is required by almost every GTA V mod menu and cheat tool. " +
                             "While single-player modding is legitimate, it is also the prerequisite " +
                             "for all script-based cheats in GTA Online.",
                    Detail = $"GtaVDir={gtaDir} OtherCheatIndicator={hasOtherCheatIndicator} AsiLoader={hasAsiLoader}",
                });
            }
        }

        // Scan scripts\ directory for cheat-named DLLs
        var scriptsDir = Path.Combine(gtaDir, "scripts");
        if (Directory.Exists(scriptsDir))
        {
            await ScanGtaVScriptsDirAsync(ctx, scriptsDir, ct).ConfigureAwait(false);
        }

        // Menyoo-specific: menyooStuff\ inside GTA V dir
        var menyooStuffDir = Path.Combine(gtaDir, "menyooStuff");
        if (Directory.Exists(menyooStuffDir))
        {
            ctx.AddFinding(new Finding
            {
                Module = "GTA-V-ModMenu-Cheat",
                Title = "GTA V: Menyoo mod menu data directory found inside GTA V folder",
                Risk = RiskLevel.Critical,
                Location = menyooStuffDir,
                FileName = "menyooStuff",
                Reason = "The 'menyooStuff' directory inside the GTA V install folder is created by " +
                         "Menyoo PC mod menu. Its presence proves Menyoo was installed and used.",
                Detail = $"GtaVDir={gtaDir} MenyooStuffDir={menyooStuffDir}",
            });
        }
    }

    private static async Task ScanGtaVScriptsDirAsync(
        ScanContext ctx, string scriptsDir, CancellationToken ct)
    {
        string[] dllFiles;
        try
        {
            dllFiles = Directory.GetFiles(scriptsDir, "*.dll", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var dll in dllFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fileName = Path.GetFileName(dll);
            var baseNameLower = Path.GetFileNameWithoutExtension(dll).ToLowerInvariant();
            var matchedPattern = string.Empty;

            foreach (var pattern in CheatAsiPatterns)
            {
                if (baseNameLower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    matchedPattern = pattern;
                    break;
                }
            }

            if (string.IsNullOrEmpty(matchedPattern)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "GTA-V-ModMenu-Cheat",
                Title = $"GTA V scripts\\: Cheat-named DLL found: {fileName}",
                Risk = RiskLevel.High,
                Location = dll,
                FileName = fileName,
                Reason = $"DLL '{fileName}' in GTA V scripts\\ directory matches cheat pattern '{matchedPattern}'. " +
                         "The scripts\\ folder is used by ScriptHookV.NET to load cheat scripts automatically at startup.",
                Detail = $"Path={dll} MatchedPattern={matchedPattern} Dir={scriptsDir}",
            });
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // ─── Section 2: known mod menu AppData directories ────────────────────────

    private static async Task ScanModMenuAppDataDirectoriesAsync(
        ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // Each tuple: (directory path, menu name, HKCU registry key or null, base risk)
        var menuEntries = new (string Dir, string MenuName, string? RegKey, RiskLevel Risk)[]
        {
            (Path.Combine(appData,      "Kiddion's Modest Menu"), "Kiddion's Modest Menu", null,                RiskLevel.High),
            (Path.Combine(localAppData, "Kiddion"),               "Kiddion's Modest Menu", null,                RiskLevel.High),
            (Path.Combine(localAppData, "Kiddion's Modest Menu"), "Kiddion's Modest Menu", null,                RiskLevel.High),
            (Path.Combine(appData,      "2Take1"),                "2Take1 Menu",           @"Software\2Take1",  RiskLevel.Critical),
            (Path.Combine(localAppData, "2Take1"),                "2Take1 Menu",           @"Software\2Take1",  RiskLevel.Critical),
            (Path.Combine(appData,      "Stand"),                 "Stand Menu",            @"Software\Stand",   RiskLevel.Critical),
            (Path.Combine(localAppData, "Stand"),                 "Stand Menu",            @"Software\Stand",   RiskLevel.Critical),
            (Path.Combine(appData,      "Orbital"),               "Orbital Menu",          null,                RiskLevel.Critical),
            (Path.Combine(localAppData, "Orbital"),               "Orbital Menu",          null,                RiskLevel.Critical),
            (Path.Combine(appData,      "Cherax"),                "Cherax Menu",           @"Software\Cherax",  RiskLevel.Critical),
            (Path.Combine(localAppData, "Cherax"),                "Cherax Menu",           @"Software\Cherax",  RiskLevel.Critical),
            (Path.Combine(appData,      "Midnight"),              "Midnight Menu",         null,                RiskLevel.Critical),
            (Path.Combine(localAppData, "Midnight"),              "Midnight Menu",         null,                RiskLevel.Critical),
            (Path.Combine(appData,      "Brute"),                 "Brute Menu",            null,                RiskLevel.Critical),
            (Path.Combine(localAppData, "Brute"),                 "Brute Menu",            null,                RiskLevel.Critical),
            (Path.Combine(appData,      "Nova"),                  "Nova Menu",             null,                RiskLevel.Critical),
            (Path.Combine(appData,      "Menyoo PC"),             "Menyoo PC",             null,                RiskLevel.Critical),
            (Path.Combine(appData,      "MenyooStuff"),           "Menyoo PC",             null,                RiskLevel.Critical),
            (Path.Combine(appData,      "Lambda Menu"),           "Lambda Menu",           null,                RiskLevel.Critical),
            (Path.Combine(appData,      "Eulen"),                 "Eulen GTA",             null,                RiskLevel.Critical),
            (Path.Combine(appData,      "Lynx"),                  "Lynx GTA",              null,                RiskLevel.Critical),
        };

        var seenRegKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (dir, menuName, regKey, baseRisk) in menuEntries)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "GTA-V-ModMenu-Cheat",
                Title = $"GTA V Mod Menu: {menuName} AppData directory found",
                Risk = baseRisk,
                Location = dir,
                FileName = Path.GetFileName(dir),
                Reason = $"AppData directory for '{menuName}' GTA V mod menu found at: {dir}. " +
                         "The presence of this directory confirms the cheat tool was installed and used " +
                         "on this system.",
                Detail = $"MenuName={menuName} Dir={dir}",
            });

            await ScanMenuConfigFilesAsync(ctx, dir, menuName, ct).ConfigureAwait(false);

            if (regKey != null && seenRegKeys.Add(regKey))
            {
                ScanMenuRegistryKey(ctx, regKey, menuName);
            }
        }
    }

    private static async Task ScanMenuConfigFilesAsync(
        ScanContext ctx, string dir, string menuName, CancellationToken ct)
    {
        string[] configPatterns = { "*.json", "*.ini", "*.cfg", "*.xml", "*.yaml", "*.toml" };

        foreach (var pattern in configPatterns)
        {
            string[] files;
            try
            {
                files = Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var matchedKw = await FindKeywordInFileAsync(file, ConfigCheatKeywords, ct)
                    .ConfigureAwait(false);
                if (matchedKw == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "GTA-V-ModMenu-Cheat",
                    Title = $"GTA V Mod Menu: {menuName} config contains cheat feature '{matchedKw}'",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = $"Configuration file for '{menuName}' contains cheat feature keyword '{matchedKw}'. " +
                             "This confirms active configuration of cheat features such as god mode, " +
                             "money drops, aimbot, or vehicle spawning.",
                    Detail = $"MenuName={menuName} File={file} Keyword={matchedKw}",
                });
            }
        }
    }

    private static void ScanMenuRegistryKey(ScanContext ctx, string keyPath, string menuName)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(keyPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            ctx.AddFinding(new Finding
            {
                Module = "GTA-V-ModMenu-Cheat",
                Title = $"GTA V Mod Menu: {menuName} registry key present",
                Risk = RiskLevel.High,
                Location = $@"HKCU\{keyPath}",
                Reason = $"Registry key for '{menuName}' found at HKCU\\{keyPath}. " +
                         "This registry artifact was created by the cheat tool and confirms " +
                         "its installation or prior execution.",
                Detail = $"MenuName={menuName} RegKey=HKCU\\{keyPath}",
            });
        }
        catch (Exception) { }
    }

    // ─── Section 3: known mod menu executables on disk ────────────────────────

    private static async Task ScanKnownModMenuExecutablesAsync(
        ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Path.GetTempPath(),
            appData,
            localAppData,
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            // Top-level EXEs
            await ScanDirForModMenuExesAsync(ctx, root, ct).ConfigureAwait(false);

            // One level of subdirectories
            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var sub in subDirs)
            {
                ct.ThrowIfCancellationRequested();
                await ScanDirForModMenuExesAsync(ctx, sub, ct).ConfigureAwait(false);
            }
        }
    }

    private static async Task ScanDirForModMenuExesAsync(
        ScanContext ctx, string dir, CancellationToken ct)
    {
        string[] exeFiles;
        try
        {
            exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var exe in exeFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fileName = Path.GetFileName(exe);
            if (!KnownModMenuExeNames.Contains(fileName)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "GTA-V-ModMenu-Cheat",
                Title = $"GTA V Mod Menu EXE found on disk: {fileName}",
                Risk = RiskLevel.Critical,
                Location = exe,
                FileName = fileName,
                Reason = $"Known GTA V mod menu / cheat tool executable '{fileName}' found on disk. " +
                         "This file is a recognized cheat tool providing god mode, money drops, " +
                         "vehicle spawning, griefing, or aimbot capabilities in GTA Online.",
                Detail = $"Path={exe}",
            });
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // ─── Section 4: running process detection ────────────────────────────────

    private static void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var snapshot = ctx.GetProcessSnapshot();

        foreach (var proc in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            var procNameExe = proc.ProcessName + ".exe";
            if (!KnownModMenuExeNames.Contains(procNameExe)) continue;

            string procPath;
            try { procPath = proc.MainModule?.FileName ?? string.Empty; }
            catch { procPath = string.Empty; }

            ctx.AddFinding(new Finding
            {
                Module = "GTA-V-ModMenu-Cheat",
                Title = $"GTA V Mod Menu ACTIVELY RUNNING: {proc.ProcessName}",
                Risk = RiskLevel.Critical,
                Location = string.IsNullOrEmpty(procPath) ? $"PID {proc.Id}" : procPath,
                FileName = procNameExe,
                Reason = $"Known GTA V mod menu process '{proc.ProcessName}' (PID {proc.Id}) is currently running. " +
                         "This constitutes direct evidence of an active cheat session in GTA V or GTA Online.",
                Detail = $"PID={proc.Id} Name={proc.ProcessName} Path={procPath}",
            });
        }
    }

    // ─── Section 5: Rockstar Social Club / R* config tamper ──────────────────

    private static async Task ScanRockstarConfigAndLogsAsync(
        ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var rockstarGtaVDir = Path.Combine(appData, "Rockstar Games", "GTA V");

        if (Directory.Exists(rockstarGtaVDir))
        {
            // commandline.txt anti-detect flags
            var commandlinePath = Path.Combine(rockstarGtaVDir, "commandline.txt");
            if (File.Exists(commandlinePath))
            {
                ctx.IncrementFiles();
                await ScanCommandlineTxtAsync(ctx, commandlinePath, ct).ConfigureAwait(false);
            }

            // .log files referencing cheat tools
            await ScanRockstarLogFilesAsync(ctx, rockstarGtaVDir, ct).ConfigureAwait(false);
        }

        // Social Club registry: EnableInGameOverlay = 0
        ScanSocialClubRegistry(ctx);
    }

    private static async Task ScanCommandlineTxtAsync(
        ScanContext ctx, string filePath, CancellationToken ct)
    {
        try
        {
            using var fs = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true, bufferSize: 4096, leaveOpen: false);
            string? line;
            while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) != null)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var flag in CommandlineAntiDetectFlags)
                {
                    if (!line.Contains(flag, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "GTA-V-ModMenu-Cheat",
                        Title = $"GTA V commandline.txt: anti-detect flag '{flag}'",
                        Risk = RiskLevel.Medium,
                        Location = filePath,
                        FileName = "commandline.txt",
                        Reason = $"GTA V commandline.txt contains anti-cheat detection bypass flag '{flag}'. " +
                                 "This flag is inserted by cheaters to reduce the detection surface " +
                                 "of cheat tools running alongside GTA V.",
                        Detail = $"File={filePath} Flag={flag} Line={TruncateLine(line)}",
                    });
                    break; // one finding per line
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }

    private static async Task ScanRockstarLogFilesAsync(
        ScanContext ctx, string dir, CancellationToken ct)
    {
        string[] logFiles;
        try
        {
            logFiles = Directory.GetFiles(dir, "*.log", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var logFile in logFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            try
            {
                using var fs = new FileStream(
                    logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: true, bufferSize: 8192, leaveOpen: false);
                string? line;
                while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) != null)
                {
                    ct.ThrowIfCancellationRequested();
                    var matchedKw = string.Empty;
                    foreach (var kw in RockstarLogCheatKeywords)
                    {
                        if (line.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            matchedKw = kw;
                            break;
                        }
                    }

                    if (string.IsNullOrEmpty(matchedKw)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "GTA-V-ModMenu-Cheat",
                        Title = $"GTA V Rockstar log references cheat tool '{matchedKw}'",
                        Risk = RiskLevel.High,
                        Location = logFile,
                        FileName = Path.GetFileName(logFile),
                        Reason = $"Rockstar Games GTA V log file contains a reference to known cheat tool '{matchedKw}'. " +
                                 "This log entry confirms that the cheat tool interacted with or was loaded " +
                                 "alongside GTA V.",
                        Detail = $"LogFile={logFile} Keyword={matchedKw} Line={TruncateLine(line)}",
                    });
                    break; // one finding per log file
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void ScanSocialClubRegistry(ScanContext ctx)
    {
        const string scSettingsKey = @"Software\Rockstar Games\Social Club\Settings";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(scSettingsKey);
            if (key == null) return;
            ctx.IncrementRegistryKeys();

            var overlayValue = key.GetValue("EnableInGameOverlay");
            if (overlayValue is int overlayInt && overlayInt == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "GTA-V-ModMenu-Cheat",
                    Title = "GTA V: Rockstar Social Club in-game overlay disabled in registry",
                    Risk = RiskLevel.Low,
                    Location = $@"HKCU\{scSettingsKey}",
                    Reason = "EnableInGameOverlay is set to 0 in Rockstar Social Club registry settings. " +
                             "Cheaters commonly disable the Social Club overlay to reduce detection surface " +
                             "and prevent conflicts between the overlay and their mod menu.",
                    Detail = $"RegKey=HKCU\\{scSettingsKey} Value=EnableInGameOverlay=0",
                });
            }
        }
        catch (Exception) { }
    }

    // ─── Section 6: GTAO money/casino cheat scripts ───────────────────────────

    private static async Task ScanGtaoScriptFilesAsync(
        ScanContext ctx, CancellationToken ct)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        string[] scriptExtensions = { "*.bat", "*.ahk", "*.py" };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            foreach (var ext in scriptExtensions)
            {
                await ScanDirForGtaoScriptsAsync(ctx, dir, ext, ct).ConfigureAwait(false);
            }

            // One level of subdirectories
            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var sub in subDirs)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var ext in scriptExtensions)
                {
                    await ScanDirForGtaoScriptsAsync(ctx, sub, ext, ct).ConfigureAwait(false);
                }
            }
        }
    }

    private static async Task ScanDirForGtaoScriptsAsync(
        ScanContext ctx, string dir, string pattern, CancellationToken ct)
    {
        string[] files;
        try
        {
            files = Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            await ScanGtaoScriptFileAsync(ctx, file, ct).ConfigureAwait(false);
        }
    }

    private static async Task ScanGtaoScriptFileAsync(
        ScanContext ctx, string filePath, CancellationToken ct)
    {
        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        var fileName = Path.GetFileName(filePath);
        string content;

        try
        {
            using var fs = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true, bufferSize: 8192, leaveOpen: false);

            // Cap at ~200 KB to avoid hanging on huge files
            var sb = new StringBuilder();
            var lineCount = 0;
            string? line;
            while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) != null &&
                   lineCount < 5000)
            {
                sb.AppendLine(line);
                lineCount++;
            }
            content = sb.ToString();
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        // Check for GTA Online cheat keywords
        var matchedKw = string.Empty;
        foreach (var kw in ScriptCheatKeywords)
        {
            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
            {
                matchedKw = kw;
                break;
            }
        }

        if (!string.IsNullOrEmpty(matchedKw))
        {
            ctx.AddFinding(new Finding
            {
                Module = "GTA-V-ModMenu-Cheat",
                Title = $"GTA Online cheat script: {fileName} (keyword: {matchedKw})",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"Script file '{fileName}' contains GTA Online cheat keyword '{matchedKw}'. " +
                         "This script likely automates money drops, casino cheats, RP boosting, " +
                         "or griefing in GTA Online.",
                Detail = $"Path={filePath} Keyword={matchedKw} Extension={ext}",
            });
            return;
        }

        // AHK files: flag if they contain GTA + aimbot/godmode/money combo
        if (ext == ".ahk")
        {
            bool hasGta = content.Contains("GTA", StringComparison.OrdinalIgnoreCase);
            bool hasCheatTerm = content.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("godmode", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("money", StringComparison.OrdinalIgnoreCase);

            if (hasGta && hasCheatTerm)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "GTA-V-ModMenu-Cheat",
                    Title = $"GTA V AutoHotkey cheat script found: {fileName}",
                    Risk = RiskLevel.High,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"AutoHotkey script '{fileName}' contains GTA-related cheat terms " +
                             "(GTA + aimbot/godmode/money). This script likely automates cheat " +
                             "actions in GTA V or GTA Online.",
                    Detail = $"Path={filePath} HasGTA={hasGta} HasCheatTerm={hasCheatTerm}",
                });
            }
        }
    }

    // ─── Section 7: Prefetch scan ─────────────────────────────────────────────

    private static void ScanPrefetchDirectory(ScanContext ctx, CancellationToken ct)
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        foreach (var prefix in PrefetchPatterns)
        {
            ct.ThrowIfCancellationRequested();

            string[] pfFiles;
            try
            {
                pfFiles = Directory.GetFiles(prefetchDir, prefix + "*.pf",
                    SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var pf in pfFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var pfName = Path.GetFileName(pf);
                var lastRun = DateTime.MinValue;
                try { lastRun = File.GetLastWriteTimeUtc(pf); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = "GTA-V-ModMenu-Cheat",
                    Title = $"GTA V Mod Menu: Prefetch artifact '{pfName}'",
                    Risk = RiskLevel.Medium,
                    Location = pf,
                    FileName = pfName,
                    Reason = $"Windows Prefetch file '{pfName}' proves prior execution of a GTA V mod menu " +
                             $"tool matching pattern '{prefix}'. Prefetch files are persistent forensic " +
                             "artifacts that survive deletion of the cheat tool itself.",
                    Detail = lastRun != DateTime.MinValue
                        ? $"Path={pf} Pattern={prefix} LastRun={lastRun:yyyy-MM-dd HH:mm:ss} UTC"
                        : $"Path={pf} Pattern={prefix}",
                });
            }
        }
    }

    // ─── Shared helpers ───────────────────────────────────────────────────────

    private static async Task<string?> FindKeywordInFileAsync(
        string filePath, string[] keywords, CancellationToken ct)
    {
        try
        {
            using var fs = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true, bufferSize: 4096, leaveOpen: false);
            string? line;
            while ((line = await sr.ReadLineAsync(ct).ConfigureAwait(false)) != null)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var kw in keywords)
                {
                    if (line.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        return kw;
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        return null;
    }

    private static string TruncateLine(string line)
    {
        var trimmed = line.Trim();
        return trimmed.Length > 220 ? trimmed[..220] + "..." : trimmed;
    }
}
