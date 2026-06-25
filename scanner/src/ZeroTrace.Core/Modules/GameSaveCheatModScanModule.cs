using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans game save directories and mod folders for cheat modification artifacts.
///
/// Games store save files, mods, and user-generated content in well-known locations.
/// Cheats targeting specific games often modify or add files in these directories:
///
///   GTA V / GTA Online:
///     %USERPROFILE%\Documents\Rockstar Games\GTA V\Profiles\[profile]\
///       stats.sav — modded stats (infinite money, max rank)
///       playerdata.dat — modded player data
///       scripts\ — ScriptHook scripts (mod menu files)
///
///   Red Dead Redemption 2:
///     %USERPROFILE%\Documents\Rockstar Games\Red Dead Redemption 2\Profiles\[profile]\
///       systemsettings.xml — modified game settings
///       *.rpf files — modified game archives
///
///   FiveM (GTA RP client):
///     %LOCALAPPDATA%\FiveM\FiveM.app\plugins\
///       Lua cheat plugins for FiveM servers
///
///   Minecraft:
///     %APPDATA%\.minecraft\mods\
///       .jar files with cheat mod names (wurst, liquidbounce, meteor, impact, sigma)
///       OptiFine is legitimate but combined with other signals is worth noting
///
///   CS2 / CSGO:
///     %USERPROFILE%\Documents\CSGOLocal\ or steam userdata
///       autoexec.cfg with sv_cheats, r_drawothermodels
///
///   Roblox:
///     %LOCALAPPDATA%\Roblox\  — exploit executor artifacts
///
/// Ocean and detect.ac scan game save/mod directories because:
///   - Modded save files are direct evidence of cheat tool use
///   - Cheat scripts in mod folders confirm installation
///   - Some cheat tools use game's own mod system for stealth persistence
/// </summary>
public sealed class GameSaveCheatModScanModule : IScanModule
{
    public string Name => "Spiel-Save und Mod-Verzeichnis Cheat-Modifikation Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    private static readonly string[] MinecraftCheatMods =
    {
        "wurst", "liquidbounce", "meteor", "impact", "sigma",
        "aristois", "xaero", "baritone", "future", "inertia",
        "ares", "oneplus", "rusherhack", "hyperium",
        "wolfram", "nocom", "exploit", "hack", "cheat",
    };

    private static readonly string[] FiveMCheatPlugins =
    {
        "bypass", "hack", "cheat", "radar", "esp", "aimbot",
        "inject", "spoof", "trainer", "money", "god",
    };

    private static readonly string[] GtaCheatFiles =
    {
        "ScriptHookV.dll", "ScriptHookVDotNet.dll",
        "ScriptHookVDotNet2.dll", "ScriptHookVDotNet3.dll",
        "dinput8.dll",        // ASI loader proxy
        "kiddion_mod.asi",
        "standalone.asi",
        "menyoo.asi", "Menyoo.asi",
        "enhanced_native_trainer.asi",
        "moneyglitch.asi",
    };

    private static readonly string[] GtaCheatScripts =
    {
        "kiddion", "2take1", "cherax", "ozark", "stand",
        "menyoo", "trainer", "god_mode", "godmode",
        "money", "teleport", "noclip", "speed",
        "modmenu", "mod_menu",
    };

    private static readonly string[] RobloxExploitDirs =
    {
        "synapse x", "synapsex", "SynapseX",
        "krnl", "KRNL", "Krnl",
        "jjsploit", "JJSploit",
        "fluxus", "Fluxus",
        "exploits", "executor", "exploit",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanMinecraftMods(ctx, ct);
        ScanFiveMPlugins(ctx, ct);
        ScanGtaVMods(ctx, ct);
        ScanRoblox(ctx, ct);
    }

    private void ScanMinecraftMods(ScanContext ctx, CancellationToken ct)
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string minecraftMods = System.IO.Path.Combine(appData, ".minecraft", "mods");

        if (!System.IO.Directory.Exists(minecraftMods)) return;

        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(minecraftMods,
                "*.jar", System.IO.SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string fileName = System.IO.Path.GetFileName(file);
                string fileNameLower = fileName.ToLowerInvariant();

                string? match = MinecraftCheatMods.FirstOrDefault(mod =>
                    fileNameLower.Contains(mod, StringComparison.OrdinalIgnoreCase));
                if (match == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Minecraft Cheat-Mod gefunden: {fileName}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Minecraft Mod '{fileName}' enthält bekannten Cheat-Mod-Namen '{match}'. " +
                               "Wurst, LiquidBounce, Meteor, Impact und Sigma sind vollständige " +
                               "Cheat-Clients mit KillAura, ESP, Fly-Hack und Speed-Hack. " +
                               "Gefunden in .minecraft\\mods — aktiv installiert.",
                    Detail   = $"Datei: {file} | Mod: '{match}'"
                });
            }
        }
        catch { }
    }

    private void ScanFiveMPlugins(ScanContext ctx, CancellationToken ct)
    {
        string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string[] fiveMDirs =
        {
            System.IO.Path.Combine(localApp, "FiveM", "FiveM.app", "plugins"),
            System.IO.Path.Combine(localApp, "FiveM", "FiveM.app", "citizen", "scripting", "lua"),
            System.IO.Path.Combine(localApp, "FiveM", "FiveM.app", "data", "cache"),
        };

        foreach (string dir in fiveMDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(dir)) continue;

            try
            {
                foreach (string file in System.IO.Directory.EnumerateFiles(dir,
                    "*", System.IO.SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string fileName = System.IO.Path.GetFileName(file);
                    string fileNameLower = fileName.ToLowerInvariant();

                    string? match = FiveMCheatPlugins.FirstOrDefault(kw =>
                        fileNameLower.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (match == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"FiveM Cheat-Plugin gefunden: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"FiveM Plugin '{fileName}' enthält Cheat-Keyword '{match}'. " +
                                   "FiveM plugins/ Verzeichnis lädt Lua/DLL-Scripts für FiveM-Server. " +
                                   "Cheat-Scripts für FiveM ermöglichen ESP, Bypass, und Trainerfunktionen " +
                                   "auf Roleplay-Servern.",
                        Detail   = $"Datei: {file} | Keyword: '{match}'"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanGtaVMods(ScanContext ctx, CancellationToken ct)
    {
        // GTA V mod directories
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] gtaDirs =
        {
            // Script directories
            System.IO.Path.Combine(userProfile, "Documents", "Rockstar Games",
                "GTA V", "scripts"),
            System.IO.Path.Combine(userProfile, "Documents", "GTAV", "scripts"),
        };

        // Also check GTA V install directory for ASI mods
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string gtaInstall = System.IO.Path.Combine(progFiles86, "Steam", "steamapps",
            "common", "Grand Theft Auto V");
        if (System.IO.Directory.Exists(gtaInstall))
        {
            // Check for ASI loader + cheat ASI files in game root
            try
            {
                foreach (string file in System.IO.Directory.EnumerateFiles(gtaInstall,
                    "*.asi", System.IO.SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    string fileName = System.IO.Path.GetFileName(file);

                    bool isKnownCheat = GtaCheatFiles.Any(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                    bool hasCheatKeyword = GtaCheatScripts.Any(kw =>
                        fileName.ToLowerInvariant().Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (!isKnownCheat && !hasCheatKeyword) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"GTA V Cheat-ASI/Script im Spielverzeichnis: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"GTA V Cheat-Datei '{fileName}' im Spielverzeichnis gefunden. " +
                                   "ASI-Dateien werden über dinput8.dll ASI Loader injiziert. " +
                                   "Kiddion's Modest Menu, 2Take1, Menyoo und ähnliche Mod Menus " +
                                   "nutzen diesen Mechanismus für GTA Online Cheats.",
                        Detail   = $"Datei: {file}"
                    });
                }
            }
            catch { }
        }

        // Scan script directories
        foreach (string dir in gtaDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(dir)) continue;

            try
            {
                foreach (string file in System.IO.Directory.EnumerateFiles(dir,
                    "*", System.IO.SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    string fileName = System.IO.Path.GetFileName(file);
                    string fileNameLower = fileName.ToLowerInvariant();

                    string? match = GtaCheatScripts.FirstOrDefault(kw =>
                        fileNameLower.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (match == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"GTA V Cheat-Script: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"GTA V Script '{fileName}' enthält Cheat-Keyword '{match}'. " +
                                   "GTA V Script-Verzeichnis ist der primäre Ablageort für " +
                                   "Mod-Menu-Scripts und Trainer-Lua-Dateien.",
                        Detail   = $"Datei: {file} | Keyword: '{match}'"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanRoblox(ScanContext ctx, CancellationToken ct)
    {
        string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string robloxRoot = System.IO.Path.Combine(localApp, "Roblox");

        if (!System.IO.Directory.Exists(robloxRoot)) return;

        try
        {
            foreach (string dir in System.IO.Directory.GetDirectories(robloxRoot))
            {
                string dirName = System.IO.Path.GetFileName(dir);
                if (!RobloxExploitDirs.Any(n =>
                    dirName.Equals(n, StringComparison.OrdinalIgnoreCase) ||
                    dirName.ToLowerInvariant().Contains("exploit") ||
                    dirName.ToLowerInvariant().Contains("executor"))) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Roblox Exploit-Executor Verzeichnis: {dirName}",
                    Risk     = RiskLevel.High,
                    Location = dir,
                    FileName = dirName,
                    Reason   = $"Roblox Exploit-Executor Verzeichnis '{dirName}' in Roblox AppData. " +
                               "Roblox-Exploit-Executors (Synapse X, KRNL, JJSploit, Fluxus) " +
                               "injizieren Lua-Scripts in Roblox um Exploits auszuführen. " +
                               "Ocean/detect.ac scannen Roblox AppData für Executor-Artefakte.",
                    Detail   = $"Pfad: {dir}"
                });
            }
        }
        catch { }

        // Also check for known Roblox exploit files
        try
        {
            string autoexec = System.IO.Path.Combine(robloxRoot, "autoexec");
            if (System.IO.Directory.Exists(autoexec))
            {
                foreach (string file in System.IO.Directory.EnumerateFiles(autoexec,
                    "*.lua", System.IO.SearchOption.TopDirectoryOnly))
                {
                    ctx.IncrementFiles();
                    string fileName = System.IO.Path.GetFileName(file);

                    try
                    {
                        var info = new System.IO.FileInfo(file);
                        if (info.Length == 0 || info.Length > 512 * 1024) continue;

                        string text = System.IO.File.ReadAllText(file).ToLowerInvariant();
                        bool hasExploitCode = text.Contains("game:getservice") ||
                                              text.Contains("getfenv") ||
                                              text.Contains("loadstring") ||
                                              text.Contains("getrenv") ||
                                              text.Contains("hookfunction");

                        if (!hasExploitCode) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Roblox Exploit-Autorun Script: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Roblox Autoexec-Script '{fileName}' enthält Exploit-API-Aufrufe " +
                                       "(getservice, loadstring, hookfunction). Autoexec-Scripts werden " +
                                       "bei jedem Roblox-Start automatisch ausgeführt — persistente " +
                                       "Exploit-Injektion ohne manuellen Start.",
                            Detail   = $"Datei: {file}"
                        });
                    }
                    catch { }
                }
            }
        }
        catch { }
    }
}
