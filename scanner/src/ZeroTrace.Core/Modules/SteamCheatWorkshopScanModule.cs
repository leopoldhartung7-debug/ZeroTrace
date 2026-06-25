using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class SteamCheatWorkshopScanModule : IScanModule
{
    public string Name => "Steam Workshop Cheat Artifact Forensic Scan";
    public double Weight => 3.6;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string ProgramFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    private static readonly string ProgramFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    // Well-known Steam AppIDs for games that are common cheat targets
    private const string AppIdGta5       = "271590";
    private const string AppIdCs2        = "730";
    private const string AppIdGmod       = "4000";
    private const string AppIdTf2        = "440";
    private const string AppIdRust       = "252490";
    private const string AppIdDayZ       = "221100";
    private const string AppIdArma3      = "107410";
    private const string AppIdPubg       = "578080";
    private const string AppIdRainbow6   = "359550";
    private const string AppIdApexLeg    = "1172470";
    private const string AppIdDota2      = "570";
    private const string AppIdUnturned   = "304930";

    private static readonly string[] CheatLaunchOptions =
    {
        "-insecure", "-bypass", "-hack", "-dev",
        "-nobreakpad", "-nosteamcontroller",
        "-condebug", "-novid -insecure",
        "-sw -insecure", "-unsafe",
        "-allowdebug", "-norestrictions",
        "+sv_cheats 1", "+sv_lan 1",
        "-textmode", "-nohltv",
        "-allowdebugger", "-debugger",
        "-nocheatcheck", "-noanticheat",
        "-disable_anticheat", "-bypass_anticheat",
        "-eac_disable", "-be_disable",
        "-easy_anticheat_launcher=0",
    };

    private static readonly string[] CheatWorkshopFolderNames =
    {
        "cheat", "hack", "aimbot", "wallhack", "esp", "bhop", "bunnyhop",
        "triggerbot", "no-recoil", "norecoil", "spinbot", "speedhack",
        "inject", "injector", "loader", "bypass", "spoofer",
        "kiddion", "2take1", "cherax", "ozark", "tsunami",
        "yimmenu", "lambda", "absolute", "spectre", "susano",
        "neverlose", "onetap", "gamesense", "aimware", "fatality",
        "nixware", "lumina", "fecurity", "vac_bypass", "eac_bypass",
        "cheatengine", "modmenu", "mod menu", "private menu",
        "internal cheat", "external cheat", "rage cheat", "legit cheat",
        "hvh", "head vs head", "closet cheat", "stream proof",
    };

    private static readonly string[] SuspiciousWorkshopExtensions =
    {
        ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".wsf",
        ".scr", ".com", ".pif",
    };

    private static readonly string[] CheatAsiFileNames =
    {
        "cheat.asi", "hack.asi", "injector.asi", "loader.asi",
        "trainer.asi", "bypass.asi", "menu.asi", "modmenu.asi",
        "ScriptHookVDotNet.asi", "dsound.asi", "dinput8.asi",
        "NativeTrainer.asi", "EnhancedNativeTrainer.asi",
        "LegacyMenuAPI.asi", "GTA5Mods.asi",
        "aimbot.asi", "wallhack.asi", "esp.asi",
        "rage.asi", "internal.asi", "external.asi",
        "kiddion.asi", "cherax.asi", "2take1.asi",
        "tsunami.asi", "ozark.asi", "yimmenu.asi",
    };

    private static readonly string[] CheatGarryModE2Patterns =
    {
        "aimbot", "wallhack", "esp", "triggerbot", "bhop", "bunnyhop",
        "godmode", "noclip cheat", "speedhack", "fly hack",
        "propkill", "crash server", "lag exploit", "crash exploit",
        "kill all", "explode all", "freeze all", "kick all",
        "admin bypass", "ulx bypass", "ulib bypass",
        "prop spam", "entity spam", "crash lua",
        "sv_cheats", "sv_allowcslua",
    };

    private static readonly string[] SuspiciousSteamBinDlls =
    {
        "gameoverlayrenderer.dll", "gameoverlayrenderer64.dll",
        "steamclient.dll", "steamclient64.dll",
        "tier0_s.dll", "vstdlib_s.dll",
    };

    private static readonly string[] KnownSteamCheatOverlayDlls =
    {
        "cheat_overlay.dll", "hack_overlay.dll", "esp_overlay.dll",
        "aimbot_overlay.dll", "radar_overlay.dll", "menu_overlay.dll",
        "cheatoverlay.dll", "hackoverlay.dll", "overlay_cheat.dll",
        "inject_overlay.dll", "bypass_overlay.dll",
        "steam_api_hook.dll", "steam_bypass.dll", "steam_emu.dll",
        "steamemu.dll", "steam_api_bypass.dll",
        "goldberg_steam_emu.dll", "ALICEfix.dll",
        "SmartSteamEmu.dll", "SmartSteamEmu64.dll",
        "CreamAPI.dll", "cream_api.dll",
        "SteamFix.dll", "steam_fix.dll",
        "orbital_emulator.dll",
    };

    private static readonly string[] CheatStackTracePatterns =
    {
        "cheat", "hack", "aimbot", "wallhack", "esp", "inject",
        "loader", "bypass", "spoofer", "kiddion", "cherax",
        "2take1", "neverlose", "onetap", "gamesense", "aimware",
        "fatality", "nixware", "fecurity", "lumina",
        "memprocfs", "pcileech", "dma",
        "xenos", "extremeinjector", "manualmap",
        "ScriptHookV", "ScriptHookVDotNet",
        "eac_bypass", "battleye_bypass", "vac_bypass",
        "anti_anticheat", "anticheat_bypass",
    };

    private static readonly string[] UserDataCheatCloudPatterns =
    {
        "cheat", "hack", "aimbot", "wallhack", "esp",
        "triggerbot", "bhop", "bunnyhop", "no_recoil", "norecoil",
        "bypass", "inject", "loader", "spoofer",
        "sv_cheats", "noclip", "godmode",
        "kiddion", "cherax", "2take1", "ozark",
        "neverlose", "onetap", "gamesense", "aimware", "fatality",
        "aim_key", "esp_key", "triggerkey", "bhop_key",
        "fov_aimbot", "smooth_aimbot", "silent_aim",
        "prediction", "backtrack", "spread_correction",
        "resolver", "anti_aim", "desync",
        "rage_bot", "legit_bot", "hvh_config",
        "skinchanger", "skin_changer", "inventory_changer",
    };

    private static readonly string[] SteamCheatRunKeys =
    {
        "CheatLoader", "HackLoader", "SteamBypass", "SteamHook",
        "SteamCheat", "GameHack", "AimBot", "WallHack",
        "EspLoader", "InjectLoader", "BypassLoader",
        "SpooferLoader", "HwidSpoofer", "SerialSpoofer",
        "VacBypass", "EacBypass", "BattleyeBypass",
        "SteamEmu", "SmartSteamEmu", "GoldbergEmu",
        "CreamAPI", "Skidrow", "Codex",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Steam Workshop cheat artifact scan");

        await Task.WhenAll(
            CheckWorkshopContentFolder(ctx, ct),
            CheckWorkshopDllArtifacts(ctx, ct),
            CheckGta5WorkshopItems(ctx, ct),
            CheckCs2WorkshopItems(ctx, ct),
            CheckGmodE2Scripts(ctx, ct),
            CheckTf2WorkshopItems(ctx, ct),
            CheckSteamLocalConfig(ctx, ct),
            CheckSteamUserData(ctx, ct),
            CheckSteamRegistryLaunchArgs(ctx, ct),
            CheckSteamLibrarySystemDlls(ctx, ct),
            CheckSteamBinOverlayDlls(ctx, ct),
            CheckSteamCrashDumps(ctx, ct),
            CheckUserAssistSteamCheats(ctx, ct),
            CheckMuiCacheSteamCheats(ctx, ct),
            CheckSteamRunKeys(ctx, ct)
        );

        ctx.Report(1.0, Name, "Steam Workshop cheat artifact scan complete");
    }

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if      (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    private static string? GetSteamPath()
    {
        try
        {
            var path = Registry.GetValue(
                @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;
            if (!string.IsNullOrEmpty(path)) return path;

            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Valve\Steam", writable: false)
                ?? Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Valve\Steam", writable: false);
            return key?.GetValue("InstallPath") as string;
        }
        catch { return null; }
    }

    private static string? GetWorkshopPath(string? steamPath)
    {
        if (string.IsNullOrEmpty(steamPath)) return null;
        var workshopPath = Path.Combine(steamPath, "steamapps", "workshop", "content");
        return Directory.Exists(workshopPath) ? workshopPath : null;
    }

    private static IEnumerable<string> GetAllSteamLibraries(string? steamPath)
    {
        if (string.IsNullOrEmpty(steamPath)) yield break;
        yield return steamPath;

        var libraryFolders = Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
        if (!File.Exists(libraryFolders)) yield break;

        string[] lines;
        try { lines = File.ReadAllLines(libraryFolders); }
        catch { yield break; }

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith('"')) continue;
            var parts = trimmed.Split('"', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            var value = parts[parts.Length - 1];
            if (value.Contains('\\') || value.Contains('/'))
            {
                if (Directory.Exists(value)) yield return value;
            }
        }
    }

    private Task CheckWorkshopContentFolder(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var steamPath = GetSteamPath();
            var workshopBase = GetWorkshopPath(steamPath);
            if (workshopBase is null) return;

            try
            {
                foreach (var appIdDir in Directory.EnumerateDirectories(workshopBase))
                {
                    if (ct.IsCancellationRequested) return;
                    var appId = Path.GetFileName(appIdDir);

                    try
                    {
                        foreach (var itemDir in Directory.EnumerateDirectories(appIdDir))
                        {
                            if (ct.IsCancellationRequested) return;
                            var itemId = Path.GetFileName(itemDir);

                            try
                            {
                                foreach (var file in Directory.EnumerateFiles(itemDir, "*", SearchOption.AllDirectories))
                                {
                                    if (ct.IsCancellationRequested) return;
                                    ctx.IncrementFiles();

                                    var ext = Path.GetExtension(file).ToLowerInvariant();
                                    if (!SuspiciousWorkshopExtensions.Contains(ext)) continue;

                                    var nameLower = Path.GetFileName(file).ToLowerInvariant();
                                    var hasSuspiciousName = CheatWorkshopFolderNames.Any(k =>
                                        nameLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                                    if (ext == ".exe" || ext == ".bat" || ext == ".cmd" || ext == ".ps1")
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                            Title = $"Workshop item contains unexpected executable: {Path.GetFileName(file)}",
                                            Risk = hasSuspiciousName ? RiskLevel.Critical : RiskLevel.High,
                                            Location = file,
                                            FileName = Path.GetFileName(file),
                                            Reason = $"Steam Workshop item {itemId} (AppID {appId}) contains " +
                                                     $"an executable file '{Path.GetFileName(file)}'. " +
                                                     "Workshop items should not contain standalone executables. " +
                                                     "This is a known vector for distributing cheat loaders " +
                                                     "via Steam Workshop subscriptions.",
                                            Detail = $"Workshop item: {itemDir} | AppID: {appId} | File: {file}"
                                        });
                                    }
                                }
                            }
                            catch (UnauthorizedAccessException) { }

                            var itemDirName = Path.GetFileName(itemDir).ToLowerInvariant();
                            foreach (var cheatName in CheatWorkshopFolderNames)
                            {
                                if (itemDirName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                        Title = $"Workshop item folder with cheat name: {Path.GetFileName(itemDir)}",
                                        Risk = RiskLevel.High,
                                        Location = itemDir,
                                        FileName = Path.GetFileName(itemDir),
                                        Reason = $"Steam Workshop item directory '{Path.GetFileName(itemDir)}' " +
                                                 $"(AppID {appId}) has a name matching cheat keyword '{cheatName}'. " +
                                                 "Cheat tools are sometimes distributed through Workshop items " +
                                                 "using misleading or explicit names.",
                                        Detail = $"Item dir: {itemDir} | Keyword: {cheatName} | AppID: {appId}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckWorkshopDllArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var steamPath = GetSteamPath();
            var workshopBase = GetWorkshopPath(steamPath);
            if (workshopBase is null) return;

            var legitimateModDllPatterns = new[]
            {
                "addon", "mod", "plugin", "extension", "resource",
                "soundfix", "fix", "patch", "improvement",
            };

            try
            {
                foreach (var appIdDir in Directory.EnumerateDirectories(workshopBase))
                {
                    if (ct.IsCancellationRequested) return;
                    var appId = Path.GetFileName(appIdDir);

                    try
                    {
                        foreach (var itemDir in Directory.EnumerateDirectories(appIdDir))
                        {
                            if (ct.IsCancellationRequested) return;
                            var itemId = Path.GetFileName(itemDir);

                            try
                            {
                                foreach (var dll in Directory.EnumerateFiles(itemDir, "*.dll", SearchOption.AllDirectories))
                                {
                                    if (ct.IsCancellationRequested) return;
                                    ctx.IncrementFiles();

                                    var dllName = Path.GetFileName(dll).ToLowerInvariant();
                                    var relPath = dll.Substring(itemDir.Length).ToLowerInvariant();

                                    bool isLegitMod = legitimateModDllPatterns.Any(p =>
                                        dllName.Contains(p, StringComparison.OrdinalIgnoreCase));
                                    bool isCheatName = CheatWorkshopFolderNames.Any(k =>
                                        dllName.Contains(k, StringComparison.OrdinalIgnoreCase));
                                    bool isInRootOrBin = relPath.Count(c => c == Path.DirectorySeparatorChar) <= 2
                                        || relPath.Contains(@"\bin\", StringComparison.OrdinalIgnoreCase);

                                    if (isCheatName)
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                            Title = $"Workshop DLL with cheat name: {Path.GetFileName(dll)}",
                                            Risk = RiskLevel.Critical,
                                            Location = dll,
                                            FileName = Path.GetFileName(dll),
                                            Reason = $"Steam Workshop item {itemId} (AppID {appId}) contains DLL " +
                                                     $"'{Path.GetFileName(dll)}' whose name matches a known cheat keyword. " +
                                                     "Workshop DLLs with cheat names are characteristic of cheat " +
                                                     "injection libraries distributed through Workshop subscriptions.",
                                            Detail = $"Workshop item: {itemDir} | DLL: {dll} | AppID: {appId}"
                                        });
                                    }
                                    else if (isInRootOrBin && !isLegitMod)
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                            Title = $"Workshop item: unexpected DLL in bin/root location ({Path.GetFileName(dll)})",
                                            Risk = RiskLevel.Medium,
                                            Location = dll,
                                            FileName = Path.GetFileName(dll),
                                            Reason = $"Steam Workshop item {itemId} (AppID {appId}) contains DLL " +
                                                     $"'{Path.GetFileName(dll)}' in a root or bin-level directory " +
                                                     "where non-addon DLLs are not expected. " +
                                                     "This location is used by cheat loaders to ensure automatic loading.",
                                            Detail = $"Workshop item: {itemDir} | DLL: {dll} | RelPath: {relPath}"
                                        });
                                    }
                                }
                            }
                            catch (UnauthorizedAccessException) { }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckGta5WorkshopItems(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var steamPath = GetSteamPath();
            var workshopBase = GetWorkshopPath(steamPath);
            if (workshopBase is null) return;

            var gta5WorkshopDir = Path.Combine(workshopBase, AppIdGta5);
            if (!Directory.Exists(gta5WorkshopDir)) return;

            try
            {
                foreach (var itemDir in Directory.EnumerateDirectories(gta5WorkshopDir))
                {
                    if (ct.IsCancellationRequested) return;
                    var itemId = Path.GetFileName(itemDir);

                    try
                    {
                        foreach (var asi in Directory.EnumerateFiles(itemDir, "*.asi", SearchOption.AllDirectories))
                        {
                            ctx.IncrementFiles();
                            var asiName = Path.GetFileName(asi);
                            bool isKnownCheatAsi = CheatAsiFileNames.Any(k =>
                                asiName.Equals(k, StringComparison.OrdinalIgnoreCase));
                            bool hasCheatName = CheatWorkshopFolderNames.Any(k =>
                                asiName.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (isKnownCheatAsi || hasCheatName)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"GTA5 Workshop: cheat ASI plugin ({asiName})",
                                    Risk = RiskLevel.Critical,
                                    Location = asi,
                                    FileName = asiName,
                                    Reason = $"GTA V Workshop item {itemId} contains ASI plugin '{asiName}' " +
                                             "which matches a known cheat or suspicious ASI file name. " +
                                             "ASI files are loaded by ScriptHookV and are the primary delivery " +
                                             "mechanism for GTA V cheats including kiddion's Modest Menu, " +
                                             "2Take1, Cherax, and similar tools.",
                                    Detail = $"Workshop item: {itemDir} | ASI: {asi} | AppID: {AppIdGta5}"
                                });
                            }
                            else
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"GTA5 Workshop: unexpected ASI plugin ({asiName})",
                                    Risk = RiskLevel.Medium,
                                    Location = asi,
                                    FileName = asiName,
                                    Reason = $"GTA V Workshop item {itemId} contains ASI plugin '{asiName}'. " +
                                             "ASI files are loaded by ScriptHookV and can execute arbitrary code. " +
                                             "Legitimate mods rarely distribute as Workshop-sourced ASI files.",
                                    Detail = $"Workshop item: {itemDir} | ASI: {asi}"
                                });
                            }
                        }

                        foreach (var dll in Directory.EnumerateFiles(itemDir, "*.dll", SearchOption.AllDirectories))
                        {
                            ctx.IncrementFiles();
                            var dllName = Path.GetFileName(dll).ToLowerInvariant();
                            if (dllName.Contains("scripthook", StringComparison.OrdinalIgnoreCase) ||
                                dllName.Contains("dinput8", StringComparison.OrdinalIgnoreCase) ||
                                dllName.Contains("dsound", StringComparison.OrdinalIgnoreCase) ||
                                dllName.Contains("d3d", StringComparison.OrdinalIgnoreCase) ||
                                dllName.Contains("winmm", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"GTA5 Workshop: proxy/hook DLL artifact ({Path.GetFileName(dll)})",
                                    Risk = RiskLevel.High,
                                    Location = dll,
                                    FileName = Path.GetFileName(dll),
                                    Reason = $"GTA V Workshop item {Path.GetFileName(itemDir)} contains DLL " +
                                             $"'{Path.GetFileName(dll)}' that matches a known DLL hijacking proxy name. " +
                                             "Cheats use proxy DLLs (dinput8.dll, dsound.dll, winmm.dll) to load " +
                                             "without an ASI loader, making detection harder.",
                                    Detail = $"Workshop item: {itemDir} | DLL: {dll}"
                                });
                            }
                        }

                        var itemDirLower = Path.GetFileName(itemDir).ToLowerInvariant();
                        foreach (var cheatName in CheatWorkshopFolderNames)
                        {
                            if (itemDirLower.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"GTA5 Workshop: cheat-named item folder ({itemDirLower})",
                                    Risk = RiskLevel.High,
                                    Location = itemDir,
                                    FileName = Path.GetFileName(itemDir),
                                    Reason = $"GTA V Workshop subscription folder '{Path.GetFileName(itemDir)}' " +
                                             $"matches cheat keyword '{cheatName}'. " +
                                             "This is consistent with a subscribed cheat distributed as a Workshop item.",
                                    Detail = $"Item: {itemDir} | Keyword: {cheatName} | AppID: {AppIdGta5}"
                                });
                                break;
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckCs2WorkshopItems(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var steamPath = GetSteamPath();
            var workshopBase = GetWorkshopPath(steamPath);
            if (workshopBase is null) return;

            var cs2WorkshopDir = Path.Combine(workshopBase, AppIdCs2);
            if (!Directory.Exists(cs2WorkshopDir)) return;

            var suspiciousCs2Extensions = new[] { ".exe", ".dll", ".bat", ".ps1", ".cmd", ".vbs" };
            var cs2CheatPatterns = new[]
            {
                "aimbot", "wallhack", "esp", "bhop", "triggerbot",
                "norecoil", "no_recoil", "spinbot", "bypass",
                "neverlose", "onetap", "gamesense", "aimware", "fatality",
                "nixware", "fecurity", "lumina", "interium", "skeet",
                "vac_bypass", "eac_bypass", "cheat", "hack", "inject",
                "rage", "hvh", "resolver", "backtrack", "spread",
                "prediction", "anti_aim", "desync",
            };

            try
            {
                foreach (var itemDir in Directory.EnumerateDirectories(cs2WorkshopDir))
                {
                    if (ct.IsCancellationRequested) return;
                    var itemId = Path.GetFileName(itemDir);

                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(itemDir, "*", SearchOption.AllDirectories))
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();

                            var ext = Path.GetExtension(file).ToLowerInvariant();
                            if (!suspiciousCs2Extensions.Contains(ext)) continue;

                            var nameLower = Path.GetFileName(file).ToLowerInvariant();
                            var isCheat = cs2CheatPatterns.Any(p =>
                                nameLower.Contains(p, StringComparison.OrdinalIgnoreCase));

                            ctx.AddFinding(new Finding
                            {
                                Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                Title = $"CS2 Workshop: suspicious executable in item ({Path.GetFileName(file)})",
                                Risk = isCheat ? RiskLevel.Critical : RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"CS2 Workshop item {itemId} contains executable or DLL " +
                                         $"'{Path.GetFileName(file)}'. " +
                                         "CS2 Workshop items should only contain maps, models, and game assets. " +
                                         "Executables or DLLs in Workshop content are a strong indicator " +
                                         "of cheat distribution via Workshop subscription.",
                                Detail = $"Workshop item: {itemDir} | File: {file} | IsCheatNamed: {isCheat}"
                            });
                        }

                        var vcfFiles = Directory.EnumerateFiles(itemDir, "*.cfg", SearchOption.AllDirectories);
                        foreach (var cfg in vcfFiles)
                        {
                            ctx.IncrementFiles();
                            string content;
                            try
                            {
                                using var fs = new FileStream(cfg, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                content = sr.ReadToEnd();
                            }
                            catch (IOException) { continue; }
                            catch (UnauthorizedAccessException) { continue; }

                            if (content.Contains("sv_cheats", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("sv_lan", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("exec cheat", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"CS2 Workshop: config with cheat console vars ({Path.GetFileName(cfg)})",
                                    Risk = RiskLevel.Medium,
                                    Location = cfg,
                                    FileName = Path.GetFileName(cfg),
                                    Reason = $"CS2 Workshop config file '{Path.GetFileName(cfg)}' in item {itemId} " +
                                             "contains cheat-enabling console variables (sv_cheats, sv_lan). " +
                                             "Workshop configs with these variables may be used to enable " +
                                             "server-side cheats or to configure cheat functionality.",
                                    Detail = $"Config: {cfg} | Workshop item: {itemDir}"
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckGmodE2Scripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamPath = GetSteamPath();
            var workshopBase = GetWorkshopPath(steamPath);
            if (workshopBase is null) return;

            var gmodWorkshopDir = Path.Combine(workshopBase, AppIdGmod);
            if (!Directory.Exists(gmodWorkshopDir)) return;

            try
            {
                foreach (var itemDir in Directory.EnumerateDirectories(gmodWorkshopDir))
                {
                    if (ct.IsCancellationRequested) return;
                    var itemId = Path.GetFileName(itemDir);

                    try
                    {
                        foreach (var e2File in Directory.EnumerateFiles(itemDir, "*.txt", SearchOption.AllDirectories)
                            .Concat(Directory.EnumerateFiles(itemDir, "*.e2", SearchOption.AllDirectories))
                            .Concat(Directory.EnumerateFiles(itemDir, "*.lua", SearchOption.AllDirectories)))
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();

                            var fi = new FileInfo(e2File);
                            if (fi.Length > 2 * 1024 * 1024) continue;

                            string content;
                            try
                            {
                                using var fs = new FileStream(e2File, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                content = await sr.ReadToEndAsync(ct);
                            }
                            catch (IOException) { continue; }
                            catch (UnauthorizedAccessException) { continue; }

                            foreach (var pattern in CheatGarryModE2Patterns)
                            {
                                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                        Title = $"Garry's Mod Workshop: E2/Lua cheat script ({Path.GetFileName(e2File)})",
                                        Risk = RiskLevel.High,
                                        Location = e2File,
                                        FileName = Path.GetFileName(e2File),
                                        Reason = $"Garry's Mod Workshop item {itemId} contains script " +
                                                 $"'{Path.GetFileName(e2File)}' with cheat-related content matching " +
                                                 $"'{pattern}'. E2 (Expression2) and Lua scripts in GMod can " +
                                                 "implement aimbots, prop kills, server crash exploits, " +
                                                 "godmode, and admin bypass cheats.",
                                        Detail = $"Script: {e2File} | Pattern: {pattern} | Item: {itemDir}"
                                    });
                                    break;
                                }
                            }

                            if (content.Contains("RunString", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("CompileString", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("loadstring", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"Garry's Mod Workshop: dynamic code execution in script ({Path.GetFileName(e2File)})",
                                    Risk = RiskLevel.Medium,
                                    Location = e2File,
                                    FileName = Path.GetFileName(e2File),
                                    Reason = $"Garry's Mod Workshop script '{Path.GetFileName(e2File)}' uses " +
                                             "dynamic code execution functions (RunString/CompileString/loadstring). " +
                                             "These are used to execute obfuscated cheat payloads loaded at runtime, " +
                                             "evading static analysis of Workshop content.",
                                    Detail = $"Script: {e2File} | Item: {itemDir}"
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckTf2WorkshopItems(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var steamPath = GetSteamPath();
            var workshopBase = GetWorkshopPath(steamPath);
            if (workshopBase is null) return;

            var tf2WorkshopDir = Path.Combine(workshopBase, AppIdTf2);
            if (!Directory.Exists(tf2WorkshopDir)) return;

            try
            {
                foreach (var itemDir in Directory.EnumerateDirectories(tf2WorkshopDir))
                {
                    if (ct.IsCancellationRequested) return;
                    var itemId = Path.GetFileName(itemDir);

                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(itemDir, "*.dll", SearchOption.AllDirectories)
                            .Concat(Directory.EnumerateFiles(itemDir, "*.exe", SearchOption.AllDirectories)))
                        {
                            ctx.IncrementFiles();
                            var name = Path.GetFileName(file);
                            ctx.AddFinding(new Finding
                            {
                                Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                Title = $"TF2 Workshop: unexpected executable/DLL in item ({name})",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = name,
                                Reason = $"Team Fortress 2 Workshop item {itemId} contains '{name}', " +
                                         "an executable or DLL file. TF2 Workshop items should only " +
                                         "contain cosmetics, maps, and game content — not binaries. " +
                                         "Executables in TF2 Workshop items are a known cheat delivery vector.",
                                Detail = $"Workshop item: {itemDir} | File: {file} | AppID: {AppIdTf2}"
                            });
                        }

                        foreach (var vtf in Directory.EnumerateFiles(itemDir, "*.vtf", SearchOption.AllDirectories))
                        {
                            ctx.IncrementFiles();
                            var vtfName = Path.GetFileName(vtf).ToLowerInvariant();
                            if (vtfName.Contains("wallhack", StringComparison.OrdinalIgnoreCase) ||
                                vtfName.Contains("transparent", StringComparison.OrdinalIgnoreCase) ||
                                vtfName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                vtfName.Contains("glow", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"TF2 Workshop: suspicious VTF texture name ({Path.GetFileName(vtf)})",
                                    Risk = RiskLevel.Medium,
                                    Location = vtf,
                                    FileName = Path.GetFileName(vtf),
                                    Reason = $"TF2 Workshop item {itemId} contains VTF texture " +
                                             $"'{Path.GetFileName(vtf)}' with a suspicious name. " +
                                             "Modified textures are used in TF2 to create wallhacks " +
                                             "(transparent walls) and visual cheats that bypass VAC.",
                                    Detail = $"Workshop item: {itemDir} | VTF: {vtf}"
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckSteamLocalConfig(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamPath = GetSteamPath();
            if (steamPath is null) return;

            var userdataDir = Path.Combine(steamPath, "userdata");
            if (!Directory.Exists(userdataDir)) return;

            try
            {
                foreach (var userDir in Directory.EnumerateDirectories(userdataDir))
                {
                    if (ct.IsCancellationRequested) return;
                    var configDir = Path.Combine(userDir, "config");
                    if (!Directory.Exists(configDir)) continue;

                    var localConfig = Path.Combine(configDir, "localconfig.vdf");
                    if (!File.Exists(localConfig)) continue;

                    ctx.IncrementFiles();
                    string content;
                    try
                    {
                        using var fs = new FileStream(localConfig, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var opt in CheatLaunchOptions)
                    {
                        if (content.Contains(opt, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                Title = $"Steam localconfig.vdf: cheat launch option ({opt})",
                                Risk = opt.Equals("-insecure", StringComparison.OrdinalIgnoreCase)
                                    ? RiskLevel.Critical : RiskLevel.High,
                                Location = localConfig,
                                FileName = "localconfig.vdf",
                                Reason = $"Steam local config file '{localConfig}' contains cheat-related " +
                                         $"launch option '{opt}'. " +
                                         "Launch options like -insecure disable VAC, while -nobreakpad disables " +
                                         "crash reporting to prevent forensic analysis. These options are set " +
                                         "by cheat loaders and are left behind as artifacts.",
                                Detail = $"Config: {localConfig} | Option: {opt}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }

            var globalConfig = Path.Combine(steamPath, "config", "config.vdf");
            if (File.Exists(globalConfig))
            {
                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(globalConfig, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { return; }
                catch (UnauthorizedAccessException) { return; }

                foreach (var opt in CheatLaunchOptions)
                {
                    if (content.Contains(opt, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Steam Workshop Cheat Artifact Forensic Scan",
                            Title = $"Steam config.vdf: cheat launch option ({opt})",
                            Risk = RiskLevel.High,
                            Location = globalConfig,
                            FileName = "config.vdf",
                            Reason = $"Steam global config file contains cheat-related launch option '{opt}'. " +
                                     "Global config launch options apply to all games and are a persistent " +
                                     "artifact of cheat tool configuration.",
                            Detail = $"Config: {globalConfig} | Option: {opt}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckSteamUserData(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamPath = GetSteamPath();
            if (steamPath is null) return;

            var userdataDir = Path.Combine(steamPath, "userdata");
            if (!Directory.Exists(userdataDir)) return;

            try
            {
                foreach (var userDir in Directory.EnumerateDirectories(userdataDir))
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        foreach (var gameDir in Directory.EnumerateDirectories(userDir))
                        {
                            if (ct.IsCancellationRequested) return;
                            var remoteDir = Path.Combine(gameDir, "remote");
                            if (!Directory.Exists(remoteDir)) continue;

                            try
                            {
                                foreach (var file in Directory.EnumerateFiles(remoteDir, "*", SearchOption.AllDirectories))
                                {
                                    if (ct.IsCancellationRequested) return;
                                    ctx.IncrementFiles();

                                    var fi = new FileInfo(file);
                                    if (fi.Length > 2 * 1024 * 1024) continue;

                                    var nameLower = Path.GetFileName(file).ToLowerInvariant();
                                    if (UserDataCheatCloudPatterns.Any(p =>
                                        nameLower.Contains(p, StringComparison.OrdinalIgnoreCase)))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                            Title = $"Steam userdata: cheat config cloud-synced ({Path.GetFileName(file)})",
                                            Risk = RiskLevel.High,
                                            Location = file,
                                            FileName = Path.GetFileName(file),
                                            Reason = $"Steam remote storage (cloud sync) file '{Path.GetFileName(file)}' " +
                                                     $"in userdata for game '{Path.GetFileName(gameDir)}' " +
                                                     "matches a cheat configuration name pattern. " +
                                                     "Cheat configurations are sometimes cloud-synced via Steam " +
                                                     "remote storage, leaving them as persistent artifacts.",
                                            Detail = $"File: {file} | GameID: {Path.GetFileName(gameDir)} | User: {Path.GetFileName(userDir)}"
                                        });
                                        continue;
                                    }

                                    var ext = Path.GetExtension(file).ToLowerInvariant();
                                    if (ext == ".cfg" || ext == ".ini" || ext == ".json" || ext == ".txt")
                                    {
                                        string content;
                                        try
                                        {
                                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                            using var sr = new StreamReader(fs);
                                            content = await sr.ReadToEndAsync(ct);
                                        }
                                        catch (IOException) { continue; }
                                        catch (UnauthorizedAccessException) { continue; }

                                        foreach (var pattern in UserDataCheatCloudPatterns)
                                        {
                                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                            {
                                                ctx.AddFinding(new Finding
                                                {
                                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                                    Title = $"Steam userdata: cloud config with cheat content ({Path.GetFileName(file)})",
                                                    Risk = RiskLevel.High,
                                                    Location = file,
                                                    FileName = Path.GetFileName(file),
                                                    Reason = $"Steam cloud-synced config file '{Path.GetFileName(file)}' " +
                                                             $"contains cheat-related content matching '{pattern}'. " +
                                                             "Cheat settings (aimbot sensitivity, ESP keys, rage bot config) " +
                                                             "are often stored in game config files that sync via Steam Cloud.",
                                                    Detail = $"File: {file} | Pattern: {pattern} | Game: {Path.GetFileName(gameDir)}"
                                                });
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            catch (UnauthorizedAccessException) { }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckSteamRegistryLaunchArgs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string steamKey = @"Software\Valve\Steam";
            const string steamKeyLm = @"SOFTWARE\Valve\Steam";
            const string steamKeyLmWow = @"SOFTWARE\WOW6432Node\Valve\Steam";

            var suspiciousSteamValues = new[]
            {
                ("SteamExe", "steam executable path"),
                ("SteamPath", "steam install path"),
                ("LastGameNameUsed", "last game"),
            };

            var suspiciousFlagsInArgs = new[]
            {
                "-dev", "-insecure", "-nobreakpad", "-allowdebug",
                "-nocheatcheck", "-norestrictions", "-unsafe",
                "+sv_cheats", "+sv_lan", "-bypass", "-hack",
                "-disable_anticheat", "-eac_disable", "-be_disable",
            };

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(steamKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    foreach (var valueName in key.GetValueNames())
                    {
                        ctx.IncrementRegistryKeys();
                        var val = key.GetValue(valueName) as string ?? "";
                        var valLower = val.ToLowerInvariant();
                        var nameLower = valueName.ToLowerInvariant();

                        if (nameLower.Contains("launch", StringComparison.OrdinalIgnoreCase) ||
                            nameLower.Contains("args", StringComparison.OrdinalIgnoreCase) ||
                            nameLower.Contains("param", StringComparison.OrdinalIgnoreCase))
                        {
                            foreach (var flag in suspiciousFlagsInArgs)
                            {
                                if (valLower.Contains(flag, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                        Title = $"Steam registry: cheat launch flag ({flag})",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKCU\{steamKey}",
                                        Reason = $"Steam registry value '{valueName}' contains cheat-related " +
                                                 $"launch argument '{flag}'. " +
                                                 "Registry-stored launch flags are set by cheat loaders to " +
                                                 "ensure games start in an insecure or debuggable state.",
                                        Detail = $"Key: HKCU\\{steamKey} | Value: {valueName} | Content: {val}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            foreach (var lmKey in new[] { steamKeyLm, steamKeyLmWow })
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(lmKey, writable: false);
                    if (key is null) continue;
                    ctx.IncrementRegistryKeys();

                    var installPath = key.GetValue("InstallPath") as string ?? "";
                    if (!string.IsNullOrEmpty(installPath))
                    {
                        var steamExe = Path.Combine(installPath, "Steam.exe");
                        if (File.Exists(steamExe))
                        {
                            // Check if steam exe is in an unusual location (could indicate fake Steam)
                            if (!installPath.Contains("Steam", StringComparison.OrdinalIgnoreCase) &&
                                !installPath.Contains("Valve", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = "Steam installed in non-standard location (possible fake Steam)",
                                    Risk = RiskLevel.Medium,
                                    Location = steamExe,
                                    FileName = "Steam.exe",
                                    Reason = $"Steam is registered as installed at '{installPath}' which does not " +
                                             "contain 'Steam' or 'Valve' in the path. " +
                                             "Cheat loaders sometimes bundle a modified Steam client " +
                                             "or redirect Steam to a fake installation path.",
                                    Detail = $"Registry: HKLM\\{lmKey} | InstallPath: {installPath}"
                                });
                            }
                        }
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckSteamLibrarySystemDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var steamPath = GetSteamPath();
            if (steamPath is null) return;

            var steamApiHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "steam_api.dll", "known-good-hash-placeholder" },
                { "steam_api64.dll", "known-good-hash-placeholder" },
            };

            var suspiciousSteamApiNames = new[]
            {
                "steam_api.dll", "steam_api64.dll",
                "steamclient.dll", "steamclient64.dll",
            };

            var knownSteamApiReplacements = new[]
            {
                "goldberg_steam_emu", "steamemu", "smartsteamemu",
                "creamapi", "cream_api", "skidrow", "codex",
                "orbital_emulator", "rld", "rld!",
                "steam_bypass", "steam_emu", "nosteam",
                "gog_galaxy", "steamless",
            };

            foreach (var library in GetAllSteamLibraries(steamPath))
            {
                if (ct.IsCancellationRequested) return;
                var commonDir = Path.Combine(library, "steamapps", "common");
                if (!Directory.Exists(commonDir)) continue;

                try
                {
                    foreach (var gameDir in Directory.EnumerateDirectories(commonDir))
                    {
                        if (ct.IsCancellationRequested) return;
                        try
                        {
                            foreach (var apiName in suspiciousSteamApiNames)
                            {
                                var apiPath = Path.Combine(gameDir, apiName);
                                if (!File.Exists(apiPath)) continue;
                                ctx.IncrementFiles();

                                var fi = new FileInfo(apiPath);

                                string? contentSample = null;
                                try
                                {
                                    var bytes = new byte[Math.Min(4096, fi.Length)];
                                    using var fs = new FileStream(apiPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                    int read = fs.Read(bytes, 0, bytes.Length);
                                    contentSample = Encoding.Latin1.GetString(bytes, 0, read);
                                }
                                catch (IOException) { }
                                catch (UnauthorizedAccessException) { }

                                if (contentSample is not null)
                                {
                                    foreach (var replacement in knownSteamApiReplacements)
                                    {
                                        if (contentSample.Contains(replacement, StringComparison.OrdinalIgnoreCase))
                                        {
                                            ctx.AddFinding(new Finding
                                            {
                                                Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                                Title = $"Replaced steam_api.dll: Steam emulator detected ({replacement})",
                                                Risk = RiskLevel.Critical,
                                                Location = apiPath,
                                                FileName = apiName,
                                                Reason = $"'{apiName}' in game '{Path.GetFileName(gameDir)}' " +
                                                         $"contains strings matching Steam emulator '{replacement}'. " +
                                                         "Replacing steam_api.dll with an emulator bypasses Steam " +
                                                         "authentication, VAC, and game ownership checks. " +
                                                         "This is used to play cracked games and to bypass " +
                                                         "Steam-based anti-cheat integrations.",
                                                Detail = $"Path: {apiPath} | Emulator: {replacement} | Game: {Path.GetFileName(gameDir)}"
                                            });
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckSteamBinOverlayDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var steamPath = GetSteamPath();
            if (steamPath is null) return;

            var binDirs = new[]
            {
                Path.Combine(steamPath, "bin"),
                Path.Combine(steamPath, "bin", "cef"),
                Path.Combine(steamPath, "GameOverlayUI"),
                Path.Combine(steamPath, "public"),
                steamPath,
            };

            foreach (var binDir in binDirs)
            {
                if (!Directory.Exists(binDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(binDir, "*.dll"))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var name = Path.GetFileName(file);

                        foreach (var suspDll in KnownSteamCheatOverlayDlls)
                        {
                            if (name.Equals(suspDll, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"Steam bin: known cheat overlay DLL ({name})",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = name,
                                    Reason = $"Known cheat or Steam emulator DLL '{name}' found in Steam " +
                                             $"binary directory '{binDir}'. " +
                                             "Placing cheat DLLs in Steam's own directories allows them to " +
                                             "load with Steam's process trust and can bypass DLL verification.",
                                    Detail = $"Path: {file} | Matched: {suspDll}"
                                });
                                break;
                            }
                        }

                        if (name.StartsWith("gameoverlayrenderer", StringComparison.OrdinalIgnoreCase))
                        {
                            var fi = new FileInfo(file);
                            if (fi.Length < 100 * 1024)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"Steam overlay DLL suspiciously small (possible replacement): {name}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = name,
                                    Reason = $"Steam overlay DLL '{name}' is unusually small ({fi.Length} bytes). " +
                                             "The legitimate Steam overlay renderer is several megabytes. " +
                                             "A small replacement may be a stub that loads a cheat overlay " +
                                             "while pretending to be the Steam overlay.",
                                    Detail = $"Path: {file} | Size: {fi.Length} bytes"
                                });
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckSteamCrashDumps(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamPath = GetSteamPath();
            if (steamPath is null) return;

            var crashDumpDirs = new[]
            {
                Path.Combine(steamPath, "dumps"),
                Path.Combine(steamPath, "logs"),
                Path.Combine(LocalAppData, "Steam", "minidumps"),
                Path.Combine(LocalAppData, "Microsoft", "Windows", "WER", "ReportArchive"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Microsoft", "Windows", "WER", "ReportArchive"),
            };

            foreach (var dumpDir in crashDumpDirs)
            {
                if (!Directory.Exists(dumpDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dumpDir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext != ".dmp" && ext != ".log" && ext != ".txt" && ext != ".wer") continue;

                        var fi = new FileInfo(file);
                        if (fi.Length > 8 * 1024 * 1024) continue;

                        string content;
                        try
                        {
                            if (ext == ".dmp")
                            {
                                var bytes = new byte[Math.Min(65536, fi.Length)];
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                int read = fs.Read(bytes, 0, bytes.Length);
                                content = Encoding.Latin1.GetString(bytes, 0, read);
                            }
                            else
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                content = await sr.ReadToEndAsync(ct);
                            }
                        }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        foreach (var pattern in CheatStackTracePatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                    Title = $"Steam crash dump: cheat tool stack trace artifact ({pattern})",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Steam crash dump or log file '{Path.GetFileName(file)}' " +
                                             $"contains cheat-related string '{pattern}'. " +
                                             "Crash dumps capture the full stack trace at the time of a crash, " +
                                             "preserving evidence of cheat DLLs and modules even after they " +
                                             "are deleted. This is a high-value forensic artifact.",
                                    Detail = $"Dump: {file} | Pattern: {pattern} | Size: {fi.Length} bytes"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckUserAssistSteamCheats(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string UserAssistBase =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            var steamCheatExecutables = new[]
            {
                "cheatloader", "hackloader", "steambypass", "steamhook",
                "steamcheat", "gamehack", "aimbot", "wallhack",
                "esploader", "injectloader", "bypassloader",
                "spooferloader", "hwidspoofer", "serialspoofer",
                "vacbypass", "eacbypass", "battleyebypass",
                "steamemu", "smartsteamemu", "goldbergemu",
                "creamapi", "cream_api", "skidrow", "codex",
                "kiddion", "2take1", "cherax", "ozark", "tsunami",
                "neverlose", "onetap", "gamesense", "aimware", "fatality",
                "nixware", "fecurity", "lumina", "injector",
                "xenos", "extremeinjector", "manualmap",
                "scripthookv", "scripthookvdotnet",
                "memprocfs", "pcileech",
                "workshop_cheat", "workshop_hack", "workshop_loader",
                "steam_workshop_cheat",
            };

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(UserAssistBase, writable: false);
                if (baseKey is null) return;

                foreach (var guidName in baseKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                        if (countKey is null) continue;

                        foreach (var encodedName in countKey.GetValueNames())
                        {
                            ctx.IncrementRegistryKeys();
                            var decoded = Rot13Decode(encodedName).ToLowerInvariant();

                            foreach (var exe in steamCheatExecutables)
                            {
                                if (decoded.Contains(exe, StringComparison.OrdinalIgnoreCase))
                                {
                                    int runCount = 0;
                                    DateTime? lastRun = null;
                                    try
                                    {
                                        var data = countKey.GetValue(encodedName) as byte[];
                                        if (data is { Length: >= 16 })
                                        {
                                            runCount = BitConverter.ToInt32(data, 4);
                                            var ft = BitConverter.ToInt64(data, 8);
                                            if (ft > 0) lastRun = DateTime.FromFileTimeUtc(ft);
                                        }
                                    }
                                    catch { }

                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                        Title = $"UserAssist: Steam cheat tool executed ({exe})",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKCU\{UserAssistBase}\{guidName}\Count",
                                        FileName = Path.GetFileName(decoded),
                                        Reason = $"UserAssist registry shows execution of '{Path.GetFileName(decoded)}' " +
                                                 $"matching Steam cheat tool '{exe}' " +
                                                 $"({runCount} runs" +
                                                 (lastRun.HasValue ? $", last: {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                                 "). UserAssist entries persist after the binary is deleted, " +
                                                 "making this a reliable forensic execution artifact.",
                                        Detail = $"Decoded: {decoded} | Tool: {exe} | Runs: {runCount} | " +
                                                 $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckMuiCacheSteamCheats(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string MuiCacheKey =
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

            var steamCheatToolNames = new[]
            {
                "kiddion", "2take1", "cherax", "ozark", "tsunami",
                "yimmenu", "lambda menu", "absolute menu", "spectre menu",
                "susano", "hyperion", "nexus menu", "scarlet", "celestial",
                "neverlose", "onetap", "gamesense", "aimware", "fatality",
                "nixware", "fecurity", "lumina", "interium", "skeet",
                "steambypass", "steamemu", "smartsteamemu", "goldbergemu",
                "creamapi", "cream_api", "orbital_emulator",
                "scripthookv", "scripthookvdotnet", "asiloader",
                "cheat_loader", "hack_loader", "bypass_loader",
                "steamhook", "gamehack", "workshop_loader",
                "eac_bypass", "battleye_bypass", "vac_bypass",
                "memprocfs", "pcileech", "dma_software",
                "xenos", "extremeinjector", "manualmap",
                "cheatengine", "x64dbg",
            };

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(MuiCacheKey, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    var dotIdx = valueName.LastIndexOf('.');
                    var cleanPath = (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                        ? valueName[..dotIdx] : valueName;

                    var combined = (cleanPath + " " + (key.GetValue(valueName) as string ?? ""))
                        .ToLowerInvariant();

                    foreach (var toolName in steamCheatToolNames)
                    {
                        if (combined.Contains(toolName, StringComparison.OrdinalIgnoreCase))
                        {
                            bool fileExists = File.Exists(cleanPath);
                            ctx.AddFinding(new Finding
                            {
                                Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                Title = $"MuiCache: Steam cheat tool executed ({toolName})",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{MuiCacheKey}",
                                FileName = Path.GetFileName(cleanPath),
                                Reason = $"MuiCache entry indicates execution of '{Path.GetFileName(cleanPath)}' " +
                                         $"matching Steam cheat tool '{toolName}'. " +
                                         (fileExists ? "File still present on disk." :
                                             "File has been deleted but execution is proven by MuiCache artifact.") +
                                         " MuiCache is populated when Windows displays a binary's friendly name " +
                                         "and persists indefinitely.",
                                Detail = $"Path: {cleanPath} | Tool: {toolName} | Exists: {fileExists}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckSteamRunKeys(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var runKeyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            foreach (var runKeyPath in runKeyPaths)
            {
                if (ct.IsCancellationRequested) return;

                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    try
                    {
                        using var key = hive.OpenSubKey(runKeyPath, writable: false);
                        if (key is null) continue;

                        foreach (var valueName in key.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementRegistryKeys();

                            var val = key.GetValue(valueName) as string ?? "";
                            var nameLower = valueName.ToLowerInvariant();
                            var valLower = val.ToLowerInvariant();
                            var combined = nameLower + " " + valLower;

                            foreach (var cheatRunKey in SteamCheatRunKeys)
                            {
                                if (combined.Contains(cheatRunKey, StringComparison.OrdinalIgnoreCase))
                                {
                                    var hiveName = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                        Title = $"Run key: Steam cheat loader autostart ({cheatRunKey})",
                                        Risk = RiskLevel.Critical,
                                        Location = $@"{hiveName}\{runKeyPath}",
                                        FileName = Path.GetFileName(val.Split(' ')[0].Trim('"')),
                                        Reason = $"Registry autorun key '{valueName}' = '{val}' in " +
                                                 $"'{hiveName}\\{runKeyPath}' matches Steam cheat loader " +
                                                 $"name '{cheatRunKey}'. " +
                                                 "Cheat loaders and Steam emulators set autorun keys to " +
                                                 "start before games launch, ensuring they are in place " +
                                                 "before anti-cheat initializes.",
                                        Detail = $"Key: {hiveName}\\{runKeyPath} | Name: {valueName} | Value: {val} | Match: {cheatRunKey}"
                                    });
                                    break;
                                }
                            }

                            if (valLower.Contains("steam", StringComparison.OrdinalIgnoreCase))
                            {
                                foreach (var flag in CheatLaunchOptions)
                                {
                                    if (valLower.Contains(flag, StringComparison.OrdinalIgnoreCase))
                                    {
                                        var hiveName = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = "Steam Workshop Cheat Artifact Forensic Scan",
                                            Title = $"Run key: Steam started with cheat flag ({flag})",
                                            Risk = RiskLevel.High,
                                            Location = $@"{hiveName}\{runKeyPath}",
                                            FileName = "Steam.exe",
                                            Reason = $"Autorun registry entry '{valueName}' starts Steam " +
                                                     $"with cheat-related flag '{flag}'. " +
                                                     "Cheat loaders modify Steam autostart entries to inject " +
                                                     "launch arguments that disable VAC, enable developer " +
                                                     "mode, or suppress crash reporting.",
                                            Detail = $"Key: {hiveName}\\{runKeyPath} | Value: {val} | Flag: {flag}"
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
        }, ct);
}
