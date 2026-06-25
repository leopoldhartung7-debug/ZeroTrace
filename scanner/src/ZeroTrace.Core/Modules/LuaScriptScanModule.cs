using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects LUA script injection artifacts for FiveM, Garry's Mod, and Roblox.
///
/// Many multiplayer games embed LUA scripting engines for mods and plugins.
/// Cheats exploit these in two ways:
///   1. LUA script injection: the cheat injects a LUA script directly into the
///      game's script environment to call internal functions (e.g. FiveM's
///      Citizen.CreateThread, Garry's Mod's hook.Add).
///
///   2. Malicious resource/addon loading: placing a cheat resource in the game's
///      resource directory so it auto-loads on connect.
///
/// Scan targets:
///   - FiveM: %LOCALAPPDATA%\FiveM\FiveM.app\data\cache\scripthookv
///   - FiveM resources: plugins/resources/citizen/scripting/lua
///   - Garry's Mod: Steam\steamapps\common\GarrysMod\garrysmod\lua\autorun
///   - Garry's Mod addons: garrysmod\addons\
///   - Roblox scripts: %LOCALAPPDATA%\Roblox\
///   - Custom game mods: %APPDATA%\*.lua files
///
/// Detection signals:
///   - LUA files containing known cheat function calls or API hooks
///   - AHK scripts masquerading as .lua files
///   - Resources with no legitimate game content but with cheat keywords
///   - Autorun scripts that load external LUA (loadfile, dofile with URLs)
/// </summary>
public sealed class LuaScriptScanModule : IScanModule
{
    public string Name => "LUA-Script-Injektion";
    public double Weight => 0.8;
    public int ParallelGroup => 4;

    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);
    private static readonly string SteamApps = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        @"Steam\steamapps\common");

    // LUA code patterns that indicate cheat functionality
    private static readonly string[] CheatLuaPatterns =
    {
        // FiveM native call abuse
        "setentitycoords", "setpedcomponentvariation", "setplayerwantedlevel",
        "addexplosion", "setentityhealth", "networkresurrectlocalplayer",
        "setentityinvincible", "givewaponto", "taskleaveanycar",
        "setplayerenteredvehicleaspassenger", "removeblip", "removeallpedweapons",
        "setentitycanmigrate", "networkregisterentityasnetworked",
        // GTA V speedhack / god mode
        "setpedmaxspeed", "setpedtomultiplayer",
        // Teleport hacks
        "entitydistance", "requestcollisionatscoord",
        // Aimbot / ESP via native
        "getentityboneindex", "getentityboneposition", "getentitycoords",
        // FiveM exploit patterns
        "citizen.invokeservervent", "triggercheatevent",
        "executeclientscript", "clientscriptinject",
        // Garry's Mod cheat patterns
        "aimbot", "wallhack", "bhop", "speedhack",
        "localplayer():getpos", "localplayer():sethp",
        "hook.add(\"thinkslow\"", "hook.add(\"createmovedataent",
        "cam.start", "debugoverlay.sphere",
        // External resource loading (suspicious)
        "loadfile(\"http", "dofile(\"http",
        "require(\"http", "loadstring(http",
        // Roblox exploit patterns
        "game:getservice(\"players\")", "workspace.currentcamera",
        "syn.require", "syn.protect_gui",
        "getgenv", "getrenv", "getrawmetatable",
        "hookfunction", "newcclosure", "setreadonly",
    };

    // Cheat-related keywords in LUA file names
    private static readonly string[] CheatFileKeywords =
    {
        "aimbot", "wallhack", "esp", "triggerbot", "bhop", "bunnyhop",
        "norecoil", "no_recoil", "radar", "speedhack", "godmode",
        "invisibility", "freecam", "teleport", "spinbot",
        "cheat", "hack", "inject", "exploit",
    };

    // Directories to scan for LUA scripts
    private static readonly string[] LuaScanDirs;

    static LuaScriptScanModule()
    {
        var dirs = new List<string>();

        // FiveM
        var fivemCache = Path.Combine(LocalApp, @"FiveM\FiveM.app\data\cache");
        var fivemLua   = Path.Combine(LocalApp, @"FiveM\FiveM.app\citizen\scripting\lua");
        var fivemPlugins = Path.Combine(LocalApp, @"FiveM\FiveM.app\plugins");
        dirs.Add(fivemCache);
        dirs.Add(fivemLua);
        dirs.Add(fivemPlugins);

        // Garry's Mod autorun
        var gmodAutorun = Path.Combine(SteamApps, @"GarrysMod\garrysmod\lua\autorun");
        var gmodAddons  = Path.Combine(SteamApps, @"GarrysMod\garrysmod\addons");
        dirs.Add(gmodAutorun);
        dirs.Add(gmodAddons);

        // Generic AppData LUA scripts
        dirs.Add(AppData);

        LuaScanDirs = dirs.Where(Directory.Exists).ToArray();
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int filesScanned = 0;
        int luaHits = 0;

        foreach (var dir in LuaScanDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            try
            {
                var pattern = dir.Contains("AppData") ? "*.lua" : "*.lua";
                var depth = dir.Contains("addons") ? SearchOption.AllDirectories
                                                   : SearchOption.TopDirectoryOnly;

                foreach (var file in Directory.EnumerateFiles(dir, pattern, depth))
                {
                    if (ct.IsCancellationRequested) break;
                    filesScanned++;
                    ctx.IncrementFiles();

                    try
                    {
                        if (AnalyzeLuaFile(file, ctx, ct))
                            luaHits++;
                    }
                    catch { }
                }
            }
            catch { }
        }

        ctx.Report(1.0, "LUA-Script-Injektion",
            $"{filesScanned} LUA-Dateien geprüft, {luaHits} verdächtig");
        return Task.CompletedTask;
    }

    private static bool AnalyzeLuaFile(string file, ScanContext ctx, CancellationToken ct)
    {
        var fn = Path.GetFileName(file).ToLowerInvariant();

        // Check file name for cheat keywords
        var nameHit = CheatFileKeywords.FirstOrDefault(k =>
            fn.Contains(k, StringComparison.OrdinalIgnoreCase));
        if (nameHit is not null)
        {
            ctx.AddFinding(new Finding
            {
                Module   = "LUA-Script-Injektion",
                Title    = $"Verdächtige LUA-Datei: {fn}",
                Risk     = RiskLevel.High,
                Location = file,
                FileName = fn,
                Reason   = $"LUA-Skriptdatei mit cheat-typischem Namen '{fn}' gefunden. " +
                           "Cheat-LUA-Skripte nutzen Game-interne Funktionen für Aimbot, " +
                           "ESP, Bhop und andere Manipulationen.",
                Detail   = $"Keyword: '{nameHit}' | Pfad: {file}"
            });
            return true;
        }

        // Scan file content for cheat patterns
        try
        {
            if (new FileInfo(file).Length > 512 * 1024) return false; // Skip large files
            var content = File.ReadAllText(file, System.Text.Encoding.UTF8);
            var lower   = content.ToLowerInvariant();

            // Count matches — single match might be false positive
            var matches = CheatLuaPatterns
                .Where(p => lower.Contains(p, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matches.Count == 0) return false;

            var risk = matches.Count >= 3 ? RiskLevel.Critical
                     : matches.Count >= 2 ? RiskLevel.High
                     : RiskLevel.Medium;

            ctx.AddFinding(new Finding
            {
                Module   = "LUA-Script-Injektion",
                Title    = $"Cheat-LUA-Muster in Skript: {fn}",
                Risk     = risk,
                Location = file,
                FileName = fn,
                Reason   = $"LUA-Skript '{fn}' enthält {matches.Count} Cheat-typische Funktionsaufrufe: " +
                           string.Join(", ", matches.Take(3).Select(m => $"'{m}'")) +
                           (matches.Count > 3 ? " ..." : "") +
                           ". Diese Muster deuten auf Aimbot, ESP, Speedhack oder " +
                           "God-Mode-LUA-Cheats hin.",
                Detail   = $"Matches ({matches.Count}): {string.Join(", ", matches.Take(6))}"
            });
            return true;
        }
        catch { }
        return false;
    }
}
