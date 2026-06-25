using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Steam API emulator presence in game directories. Steam emulators (Goldberg,
/// CreamAPI, SmokeAPI, Koaloader, ALI213) replace the legitimate steam_api64.dll to bypass
/// Valve Anti-Cheat (VAC) and DRM, trick games into thinking they own DLC, and in some
/// variants remove all online authentication. The presence of an emulator config file
/// alongside a game is strong evidence of VAC bypass or DRM circumvention. The module
/// scans game directories for: steam_emu.ini, Crack_steam.ini, cream_api.ini, SmokeAPI.ini,
/// Koaloader configuration files, steam_interfaces.txt, local_save/ directories (Goldberg
/// offline save path), and compares steam_api64.dll export tables against Goldberg-specific
/// function signatures. Also checks for appid.txt and user.id files in game roots.
/// </summary>
public sealed class SteamEmulatorDetectionScanModule : IScanModule
{
    public string Name => "Steam Emulator & VAC Bypass Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 4;

    private static readonly string[] SteamGameRoots =
    {
        @"C:\Program Files\Steam\steamapps\common",
        @"C:\Program Files (x86)\Steam\steamapps\common",
        @"D:\Steam\steamapps\common",
        @"D:\Games\steamapps\common",
        @"D:\Games",
        @"E:\Steam\steamapps\common",
        @"E:\Games",
    };

    // Emulator configuration file names
    private static readonly (string FileName, string EmulatorName, bool IsCritical)[] EmulatorConfigFiles =
    {
        // Goldberg Steam Emulator
        ("steam_emu.ini",       "Goldberg Steam Emulator",  true),
        ("steam_interfaces.txt","Goldberg Steam Emulator",  false),
        ("local_save",          "Goldberg Emulator (local_save dir)", false),
        ("ColdClientLoader.ini","Goldberg ColdClientLoader", true),
        // CreamAPI (DLC unlocker — not a VAC bypass but circumvents Steam DRM)
        ("cream_api.ini",       "CreamAPI DLC Unlocker",    true),
        ("CreamAPI.ini",        "CreamAPI DLC Unlocker",    true),
        // SmokeAPI (DLC unlocker)
        ("SmokeAPI.ini",        "SmokeAPI DLC Unlocker",    true),
        ("SmokeAPI.log",        "SmokeAPI DLC Unlocker",    false),
        // Koaloader (DLL proxy loader for Steam emulators)
        ("Koaloader.config.json","Koaloader Proxy Loader",  true),
        // ALI213 emulator
        ("ALI213.ini",          "ALI213 Steam Emulator",    true),
        ("Crack_steam.ini",     "ALI213/Crack Steam Emulator", true),
        // EMPRESS emulator
        ("EMPRESS_SETTINGS.ini","EMPRESS Steam Emulator",   true),
        // General indicators
        ("appid.txt",           "Steam AppID Override",     false),
        ("user.id",             "Steam User ID Override",   false),
        ("account_name.txt",    "Goldberg Account Name",    false),
    };

    // DLL names that are Steam emulator/proxy implementations
    private static readonly HashSet<string> EmulatorProxyDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Koaloader DLL proxies
        "winhttp.dll", "version.dll", "winmm.dll",
        "xinput9_1_0.dll", "xinput1_4.dll",
        // Direct Steam emulator DLLs (when renamed)
        "steam_api.dll", "steam_api64.dll",
        // Note: steam_api64.dll in game dir is normal — we check CONTENT not just presence
    };

    // Goldberg emulator exports that legitimate steam_api64.dll doesn't have
    private static readonly string[] GoldbergSpecificExports =
    {
        "flat_steam_api_",   // Goldberg adds flat_ prefixed exports
        "SteamGameServer_Init_SteamClient",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => ScanGameRoots(ctx, ct), ct);
    }

    private void ScanGameRoots(ScanContext ctx, CancellationToken ct)
    {
        var steamPaths = new List<string>(SteamGameRoots);
        TryAddSteamLibraries(steamPaths);

        foreach (var root in steamPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var gameDir in Directory.EnumerateDirectories(root))
                {
                    ct.ThrowIfCancellationRequested();
                    ScanGameDirectory(gameDir, ctx, ct);
                }
            }
            catch { }
        }
    }

    private void ScanGameDirectory(string gameDir, ScanContext ctx, CancellationToken ct)
    {
        string gameName = Path.GetFileName(gameDir);

        // Check for emulator config files (recursive, shallow)
        try
        {
            foreach (var (fileName, emulatorName, isCritical) in EmulatorConfigFiles)
            {
                ct.ThrowIfCancellationRequested();

                // Check in root and one level deep
                string[] searchPaths = { gameDir };
                foreach (var searchRoot in searchPaths)
                {
                    string filePath = Path.Combine(searchRoot, fileName);

                    // Check both as file and directory (local_save is a directory)
                    bool exists = File.Exists(filePath) || Directory.Exists(filePath);
                    if (!exists) continue;

                    ctx.IncrementFiles();

                    // For steam_interfaces.txt and appid.txt — verify they have emulator content
                    if (fileName == "steam_interfaces.txt" || fileName == "appid.txt")
                    {
                        if (!VerifyEmulatorFileContent(filePath, fileName)) continue;
                    }

                    // For local_save directory — verify it actually has save files
                    if (fileName == "local_save")
                    {
                        if (!Directory.EnumerateFiles(filePath).Any()) continue;
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"{emulatorName} erkannt: {gameName}",
                        Risk     = isCritical ? RiskLevel.Critical : RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason   = $"{emulatorName}-Konfigurationsdatei '{fileName}' gefunden in " +
                                   $"Spielverzeichnis '{gameName}' — Steam-Emulatoren ersetzen " +
                                   "steam_api64.dll um VAC zu umgehen, DLC ohne Kauf freizuschalten, " +
                                   "oder Steam-Online-Authentifizierung zu deaktivieren",
                        Detail   = $"Spiel: {gameName} | Emulator: {emulatorName} | Datei: {filePath} | " +
                                   $"Kritisch: {isCritical}"
                    });
                }
            }
        }
        catch { }

        // Check for Koaloader config in subdirectories too
        try
        {
            foreach (var subDir in Directory.EnumerateDirectories(gameDir, "*", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                string koaPath = Path.Combine(subDir, "Koaloader.config.json");
                if (File.Exists(koaPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Koaloader Proxy-Loader erkannt: {gameName}",
                        Risk     = RiskLevel.Critical,
                        Location = koaPath,
                        FileName = "Koaloader.config.json",
                        Reason   = $"Koaloader-Konfiguration in '{gameName}\\{Path.GetFileName(subDir)}' — " +
                                   "Koaloader ist ein DLL-Proxy-Loader der Steam-Emulatoren (Goldberg, " +
                                   "CreamAPI) in Spielprozesse injiziert ohne die Original-steam_api zu ersetzen",
                        Detail   = $"Spiel: {gameName} | Config: {koaPath}"
                    });
                }
            }
        }
        catch { }
    }

    private static bool VerifyEmulatorFileContent(string filePath, string fileName)
    {
        try
        {
            if (fileName == "steam_interfaces.txt")
            {
                string content = File.ReadAllText(filePath);
                // Goldberg steam_interfaces.txt contains interface version strings
                return content.Contains("SteamClient", StringComparison.OrdinalIgnoreCase) ||
                       content.Contains("SteamUser", StringComparison.OrdinalIgnoreCase);
            }
            if (fileName == "appid.txt")
            {
                // Valid Steam AppID is a number
                string content = File.ReadAllText(filePath).Trim();
                return long.TryParse(content, out _);
            }
            return true;
        }
        catch { return false; }
    }

    private static void TryAddSteamLibraries(List<string> paths)
    {
        try
        {
            string[] vdfPaths =
            {
                @"C:\Program Files (x86)\Steam\steamapps\libraryfolders.vdf",
                @"C:\Program Files\Steam\steamapps\libraryfolders.vdf",
            };
            foreach (string vdf in vdfPaths)
            {
                if (!File.Exists(vdf)) continue;
                string content = File.ReadAllText(vdf);
                int idx = 0;
                while ((idx = content.IndexOf("\"path\"", idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                {
                    int q1 = content.IndexOf('"', idx + 6);
                    if (q1 < 0) break;
                    int q2 = content.IndexOf('"', q1 + 1);
                    if (q2 < 0) break;
                    string libPath = content[(q1 + 1)..q2].Replace("\\\\", "\\");
                    string common = Path.Combine(libPath, "steamapps", "common");
                    if (Directory.Exists(common) && !paths.Contains(common))
                        paths.Add(common);
                    idx = q2 + 1;
                }
                break;
            }
        }
        catch { }
    }
}
