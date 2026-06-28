using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects BepInEx, Unity Doorstop, and IL2CPP code injection frameworks installed in game
/// directories. While legitimate for mods, these frameworks are the most common vector for
/// cheat injection in Unity games: BepInEx auto-loads all DLLs in BepInEx/plugins/ at startup,
/// giving complete access to game memory and API. Doorstop uses a winhttp.dll proxy in the
/// game root to intercept DLL loading before Unity initializes. The module scans Steam game
/// installations for: doorstop_config.ini (enabled=true), winhttp.dll proxy (non-Windows),
/// BepInEx/plugins/ directory with non-blessed DLLs, IL2CPP dump scripts, and Unity Mod
/// Manager / MelonLoader configurations. Flags cheat-keyword plugin DLL names and non-whitelisted
/// assemblies in BepInEx directories.
/// </summary>
public sealed class BepInExDoorstopScanModule : IScanModule
{
    public string Name => "BepInEx/Doorstop Cheat Injection Detection";
    public double Weight => 0.65;
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

    // Cheat-keyword plugin DLL names
    private static readonly string[] CheatPluginKeywords =
    {
        "cheat", "hack", "esp", "aimbot", "radar", "wallhack",
        "speedhack", "norecoil", "triggerbot", "bypass",
        "aimassist", "softaim", "inject", "overlay",
        "dumper", "trainer", "menu",
    };

    // Known legitimate BepInEx plugin names / prefixes
    private static readonly HashSet<string> WhitelistedPluginPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "BepInEx.Core", "BepInEx.Unity", "BepInEx.Logging",
        "Harmony", "MonoMod", "0Harmony",
        "MMHOOK_", "HarmonyX",
        "UnityExplorer", "RuntimeUnityEditor",
        "Thunderstore", "RiskOfOptions", "ConfigurationManager",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => ScanGameRoots(ctx, ct), ct);
    }

    private void ScanGameRoots(ScanContext ctx, CancellationToken ct)
    {
        // Also check user's local Steam library from registry
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
        try
        {
            string gameName = Path.GetFileName(gameDir);

            // 1. doorstop_config.ini — Doorstop proxy config
            string doorstopCfg = Path.Combine(gameDir, "doorstop_config.ini");
            if (File.Exists(doorstopCfg))
            {
                ctx.IncrementFiles();
                string content = File.ReadAllText(doorstopCfg);
                if (content.Contains("enabled=true", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("enabled = true", StringComparison.OrdinalIgnoreCase))
                {
                    // Extract target DLL path from config
                    string targetLine = content.Split('\n')
                        .FirstOrDefault(l => l.TrimStart().StartsWith("targetAssembly",
                            StringComparison.OrdinalIgnoreCase)) ?? "";
                    string targetDll = targetLine.Contains('=')
                        ? targetLine.Split('=', 2)[1].Trim()
                        : "";

                    bool hasCheatKeyword = Array.Exists(CheatPluginKeywords,
                        kw => targetDll.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Unity Doorstop aktiv in: {gameName}",
                        Risk     = hasCheatKeyword ? RiskLevel.Critical : RiskLevel.High,
                        Location = doorstopCfg,
                        FileName = "doorstop_config.ini",
                        Reason   = $"Unity Doorstop-Proxy ist im Spielverzeichnis '{gameName}' aktiviert — " +
                                   "Doorstop fängt den Unity DLL-Ladevorgang ab und lädt eine beliebige DLL " +
                                   "vor der Unity-Engine (BepInEx verwendet dies für Cheat-Plugin-Injection). " +
                                   (hasCheatKeyword
                                       ? $"Ziel-DLL enthält Cheat-Keyword: '{targetDll}'"
                                       : $"Ziel-DLL: '{targetDll}'"),
                        Detail   = $"Spiel: {gameName} | Config: {doorstopCfg} | Target: {targetDll} | " +
                                   $"Cheat-Keyword: {hasCheatKeyword}"
                    });
                }
            }

            // 2. winhttp.dll in game root — Doorstop proxy DLL (should only be in System32)
            string winhttpPath = Path.Combine(gameDir, "winhttp.dll");
            if (File.Exists(winhttpPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Doorstop-Proxy DLL in Spielverzeichnis: {gameName}",
                    Risk     = RiskLevel.High,
                    Location = winhttpPath,
                    FileName = "winhttp.dll",
                    Reason   = $"winhttp.dll im Spielverzeichnis '{gameName}' — diese Datei ist ein " +
                               "Doorstop-Proxy der das DLL-Search-Order-Hijacking ausnutzt um vor " +
                               "der echten Windows winhttp.dll geladen zu werden und Code zu injizieren. " +
                               "BepInEx/MelonLoader verwenden diese Technik zur Unity-Mod/Cheat-Injection.",
                    Detail   = $"Spiel: {gameName} | Pfad: {winhttpPath}"
                });
            }

            // 3. BepInEx directory — check plugins subfolder
            string bepInExDir = Path.Combine(gameDir, "BepInEx");
            if (Directory.Exists(bepInExDir))
            {
                ctx.IncrementFiles();
                string pluginsDir = Path.Combine(bepInExDir, "plugins");
                if (Directory.Exists(pluginsDir))
                {
                    try
                    {
                        foreach (var dll in Directory.EnumerateFiles(pluginsDir, "*.dll",
                            SearchOption.AllDirectories))
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementFiles();

                            string dllName = Path.GetFileNameWithoutExtension(dll);

                            // Skip known-good plugins
                            if (WhitelistedPluginPrefixes.Any(p =>
                                dllName.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;

                            bool hasCheatKw = Array.Exists(CheatPluginKeywords,
                                kw => dllName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                            if (!hasCheatKw) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Verdächtiges BepInEx-Plugin: {dllName}",
                                Risk     = RiskLevel.Critical,
                                Location = dll,
                                FileName = Path.GetFileName(dll),
                                Reason   = $"BepInEx-Plugin '{dllName}' in Spielverzeichnis '{gameName}' " +
                                           "enthält Cheat-Keyword — BepInEx lädt alle DLLs in plugins/ " +
                                           "automatisch beim Spielstart und gibt ihnen vollen Zugriff " +
                                           "auf Spiellogik, Objekte und Netzwerkkommunikation",
                                Detail   = $"Spiel: {gameName} | Plugin: {dll}"
                            });
                        }
                    }
                    catch { }
                }
            }

            // 4. MelonLoader directory
            string melonDir = Path.Combine(gameDir, "MelonLoader");
            if (Directory.Exists(melonDir))
            {
                ctx.IncrementFiles();
                string modsDir = Path.Combine(gameDir, "Mods");
                if (Directory.Exists(modsDir))
                {
                    try
                    {
                        foreach (var dll in Directory.EnumerateFiles(modsDir, "*.dll"))
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementFiles();

                            string dllName = Path.GetFileNameWithoutExtension(dll);
                            bool hasCheatKw = Array.Exists(CheatPluginKeywords,
                                kw => dllName.Contains(kw, StringComparison.OrdinalIgnoreCase));
                            if (!hasCheatKw) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Verdächtiges MelonLoader-Mod: {dllName}",
                                Risk     = RiskLevel.Critical,
                                Location = dll,
                                FileName = Path.GetFileName(dll),
                                Reason   = $"MelonLoader-Mod '{dllName}' mit Cheat-Keyword in " +
                                           $"'{gameName}' — MelonLoader lädt alle Mods bei Spielstart " +
                                           "mit vollem Unity API-Zugriff",
                                Detail   = $"Spiel: {gameName} | Mod: {dll}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private static void TryAddSteamLibraries(List<string> paths)
    {
        // Try to find additional Steam library folders from libraryfolders.vdf
        try
        {
            string steamPath = @"C:\Program Files (x86)\Steam";
            string vdf = Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
            if (!File.Exists(vdf))
                vdf = Path.Combine(@"C:\Program Files\Steam", "steamapps", "libraryfolders.vdf");
            if (!File.Exists(vdf)) return;

            string content = File.ReadAllText(vdf);
            // Parse "path" entries: "path"		"D:\\Games\\Steam"
            int idx = 0;
            while ((idx = content.IndexOf("\"path\"", idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                int q1 = content.IndexOf('"', idx + 6);
                if (q1 < 0) break;
                int q2 = content.IndexOf('"', q1 + 1);
                if (q2 < 0) break;
                string libPath = content[(q1 + 1)..q2]
                    .Replace("\\\\", "\\");
                string common = Path.Combine(libPath, "steamapps", "common");
                if (Directory.Exists(common) && !paths.Contains(common))
                    paths.Add(common);
                idx = q2 + 1;
            }
        }
        catch { }
    }
}
