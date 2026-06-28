using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep FiveM-specific cheat detection beyond the base FiveMScanModule:
/// known cheat client directories/DLLs (Eulen, Lynx, Hamster, Impulse, Infinity, Desudo, Baddie),
/// FiveM bypass tools, Cfx.re anticheat bypass artifacts, Lua/NUI injection scripts in
/// CitizenFX resource paths, FiveM log scanning for suspicious resource loads, and
/// running FiveM cheat processes. FiveM cheat market is one of the largest — primary target.
/// </summary>
public sealed class FiveMDeepCheatScanModule : IScanModule
{
    public string Name => "FiveMDeepCheat";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    // ─── Known FiveM cheat client EXE/DLL names ──────────────────────────────
    private static readonly string[] FiveMCheatExeNames = {
        // Eulen — most popular FiveM cheat subscription
        "eulen.exe", "eulenclient.exe", "eulenloader.exe", "eulen-loader.exe",
        // Lynx — FiveM executor/menu
        "lynx.exe", "lynxclient.exe", "lynx-loader.exe", "lynxloader.exe",
        // Hamster — FiveM cheat
        "hamster.exe", "hamsterclient.exe", "hamsterloader.exe",
        // Impulse — FiveM menu
        "impulse.exe", "impulse-fivem.exe", "impulseloader.exe",
        // Infinity — FiveM cheat
        "infinity.exe", "infinity-menu.exe", "infinityclient.exe",
        // Desudo — FiveM menu
        "desudo.exe", "desudo-menu.exe",
        // Baddie — FiveM cheat
        "baddie.exe", "baddie-client.exe",
        // Generic FiveM bypass/loaders
        "fivem-bypass.exe", "cfx-bypass.exe", "citizenfx-bypass.exe",
        "fivem-cheat.exe", "fivem-hack.exe", "fivem-mod.exe",
        "rp-bypass.exe", "antiban.exe", "fivemloader.exe",
        "resourceinjector.exe", "fivem-injector.exe",
    };

    private static readonly string[] FiveMCheatDllNames = {
        "eulen.dll", "eulenclient.dll", "eulenhook.dll",
        "lynx.dll", "lynxclient.dll", "lynxhook.dll",
        "hamster.dll", "impulse.dll", "infinity.dll",
        "desudo.dll", "baddie.dll",
        "fivemcheat.dll", "fivemhook.dll", "fivemmod.dll",
        "cfxbypass.dll", "citizenbypass.dll",
        "resourcehook.dll", "nuihook.dll",
    };

    // ─── Known FiveM cheat vendor/tool directory names ───────────────────────
    private static readonly string[] FiveMCheatDirNames = {
        "Eulen", "EulenClient", "Eulen-Client", "Eulen Menu",
        "Lynx", "LynxClient", "Lynx-FiveM",
        "Hamster", "HamsterClient",
        "Impulse", "ImpulseFiveM", "Impulse-FiveM",
        "Infinity", "InfinityMenu", "Infinity-Menu",
        "Desudo", "DesudoMenu",
        "Baddie", "BaddieClient",
        "FiveM-Cheat", "FiveM-Hack", "FiveMCheat",
        "CFX-Bypass", "CitizenBypass", "FiveM-Bypass",
        "ResourceInjector", "NUI-Injector",
    };

    // ─── FiveM Lua resource cheat patterns ───────────────────────────────────
    private static readonly string[] LuaCheatPatterns = {
        "getentitycoords",       // entity position reading
        "setvehiclemaxspeed",    // speed hack
        "setplayerinvincible",   // god mode
        "noclip",                // noclip
        "spawnvehicle",          // vehicle spawner
        "addweapontoentity",     // weapon spawner
        "createobject",          // object spawner
        "setentityinvincible",   // entity god mode
        "disablepolicespawning", // cop ban
        "setmaxwantedlevel",     // wanted level hack
        "setblipsprite",         // ESP blip hacking
        "getplayerped",
        "teleport",              // teleport hack
        "setentitycoords",       // entity teleport (combined with entity spawn = cheat)
        "requestanimdict",       // anim bypass
        "ped_component_variation", // model changer (combined with others)
        "networksession",        // session manipulation
        "explosionat",           // explosion spawner
        "headshotmodifier",      // aimbot modifier
        "setentityheading",      // targeting assist
    };

    // ─── FiveM NUI/JS cheat patterns ─────────────────────────────────────────
    private static readonly string[] NuiCheatPatterns = {
        "invokeNative",          // native call from NUI (should not be possible)
        "GetPlayerPed",
        "SetEntityInvincible",
        "SetPlayerInvincible",
        "exploit",
        "bypass",
        "inject",
        "godmode",
        "noclip",
        "esp",
        "aimbot",
        "speedhack",
        "teleport",
        "xmlhttprequest.*fivem",  // XHR to FiveM internals
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanFiveMCheatDirectories(ctx, ct);
            ScanFiveMProcesses(ctx, ct);
            ScanCitizenFxDirectory(ctx, ct);
            ScanFiveMResourcesForCheats(ctx, ct);
            ScanFiveMLogs(ctx, ct);
            ScanFiveMBypassRegistry(ctx, ct);
        }, ct);
    }

    // ─── Check common user dirs for FiveM cheat dirs/files ──────────────────

    private static void ScanFiveMCheatDirectories(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        foreach (var baseDir in searchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            // Check known cheat directories
            foreach (var cheatDir in FiveMCheatDirNames)
            {
                var fullPath = Path.Combine(baseDir, cheatDir);
                if (!Directory.Exists(fullPath)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "FiveMDeepCheat",
                    Title = $"FiveM Cheat-Verzeichnis gefunden: {cheatDir}",
                    Risk = RiskLevel.Critical,
                    Location = fullPath,
                    Reason = $"Bekanntes FiveM-Cheat-Verzeichnis '{cheatDir}' gefunden. " +
                             "Dies ist ein bekanntes Cheat-Tool fuer FiveM / Cfx.re GTA V Server.",
                    Detail = $"Dir={fullPath}"
                });
            }

            // Check for known cheat EXEs
            try
            {
                foreach (var exe in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(exe).ToLowerInvariant();
                    if (Array.IndexOf(FiveMCheatExeNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "FiveMDeepCheat",
                            Title = $"FiveM Cheat-EXE gefunden: {Path.GetFileName(exe)}",
                            Risk = RiskLevel.Critical,
                            Location = exe,
                            FileName = fname,
                            Reason = $"Bekanntes FiveM-Cheat-Programm '{fname}' gefunden.",
                            Detail = $"Path={exe}"
                        });
                    }
                }

                foreach (var dll in Directory.GetFiles(baseDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(dll).ToLowerInvariant();
                    if (Array.IndexOf(FiveMCheatDllNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "FiveMDeepCheat",
                            Title = $"FiveM Cheat-DLL gefunden: {Path.GetFileName(dll)}",
                            Risk = RiskLevel.Critical,
                            Location = dll,
                            FileName = fname,
                            Reason = $"Bekannte FiveM-Cheat-DLL '{fname}' gefunden — wahrscheinlich Injector oder Hook-DLL.",
                            Detail = $"Path={dll}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    // ─── Running FiveM cheat processes ───────────────────────────────────────

    private static void ScanFiveMProcesses(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var procs = ctx.GetProcessSnapshot();

        foreach (var proc in procs)
        {
            ct.ThrowIfCancellationRequested();
            var pname = (proc.Name + ".exe").ToLowerInvariant();
            if (Array.IndexOf(FiveMCheatExeNames, pname) >= 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "FiveMDeepCheat",
                    Title = $"FiveM Cheat-Prozess laeuft: {proc.Name}",
                    Risk = RiskLevel.Critical,
                    Location = proc.MainModule ?? proc.Name,
                    FileName = proc.Name,
                    Reason = $"Aktiver FiveM-Cheat-Prozess '{proc.Name}' erkannt.",
                    Detail = $"PID={proc.Id} Name={proc.Name}"
                });
            }

            // Also check path for FiveM cheat directories
            var path = (proc.MainModule ?? string.Empty).ToLowerInvariant();
            if (path.Contains("eulen") || path.Contains("lynx") || path.Contains("hamster") ||
                path.Contains("impulse") || path.Contains("desudo") || path.Contains("baddie") ||
                path.Contains("fivem-cheat") || path.Contains("cfx-bypass"))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "FiveMDeepCheat",
                    Title = $"Prozess aus FiveM-Cheat-Verzeichnis laeuft: {proc.Name}",
                    Risk = RiskLevel.Critical,
                    Location = proc.MainModule ?? proc.Name,
                    FileName = proc.Name,
                    Reason = $"Prozess '{proc.Name}' laeuft aus einem FiveM-Cheat-Verzeichnis.",
                    Detail = $"PID={proc.Id} Path={proc.MainModule}"
                });
            }
        }
    }

    // ─── CitizenFX / FiveM data directory scan ───────────────────────────────

    private static void ScanCitizenFxDirectory(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // Main FiveM data paths
        var fivemPaths = new[]
        {
            Path.Combine(appData,  "CitizenFX"),
            Path.Combine(localApp, "FiveM"),
            Path.Combine(localApp, "DigitalEntitlements"),  // Cfx.re license store
        };

        foreach (var fivemPath in fivemPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(fivemPath)) continue;

            // Check for cheat DLLs directly in CitizenFX
            try
            {
                foreach (var dll in Directory.GetFiles(fivemPath, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(dll).ToLowerInvariant();
                    if (Array.IndexOf(FiveMCheatDllNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "FiveMDeepCheat",
                            Title = $"FiveM Cheat-DLL im CitizenFX-Verzeichnis: {Path.GetFileName(dll)}",
                            Risk = RiskLevel.Critical,
                            Location = dll,
                            FileName = fname,
                            Reason = $"Cheat-DLL '{fname}' direkt im FiveM/CitizenFX-Datenverzeichnis — typisches Injection-Ziel.",
                            Detail = $"Path={dll}"
                        });
                    }
                }
            }
            catch { }

            // Check citizen\scripting for injected scripts
            var scriptingDir = Path.Combine(fivemPath, "FiveM.app", "citizen", "scripting");
            if (Directory.Exists(scriptingDir))
                ScanLuaDirectory(ctx, scriptingDir, ct);

            // Check NUI devtools enabled (FiveM NUI exploit)
            var fivemAppData = Path.Combine(fivemPath, "FiveM.app", "data");
            ScanFiveMAppData(ctx, fivemAppData, ct);
        }
    }

    private static void ScanFiveMAppData(ScanContext ctx, string dataDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!Directory.Exists(dataDir)) return;

        // Check for known cheat config files
        string[] cheatConfigFiles = {
            "eulen_config.json", "lynx_config.json", "hamster.cfg",
            "impulse.json", "infinity.cfg", "desudo.cfg",
            "cheat_config.json", "menu_config.json",
        };

        foreach (var cfg in cheatConfigFiles)
        {
            var fullPath = Path.Combine(dataDir, cfg);
            if (!File.Exists(fullPath)) continue;
            ctx.IncrementFiles(1);
            ctx.AddFinding(new Finding
            {
                Module = "FiveMDeepCheat",
                Title = $"FiveM Cheat-Konfigurationsdatei: {cfg}",
                Risk = RiskLevel.Critical,
                Location = fullPath,
                FileName = cfg,
                Reason = $"Cheat-Konfigurationsdatei '{cfg}' im FiveM-Datenverzeichnis gefunden.",
                Detail = $"Path={fullPath}"
            });
        }

        // Check NUI devtools (used for NUI injection)
        var nuiDevtools = Path.Combine(dataDir, "nui-devtools.json");
        if (File.Exists(nuiDevtools))
        {
            ctx.IncrementFiles(1);
            try
            {
                var content = File.ReadAllText(nuiDevtools);
                if (content.Contains("remote-debugging-port") || content.Contains("devtools"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "FiveMDeepCheat",
                        Title = "FiveM NUI DevTools aktiviert (NUI-Injection-Vorbereitung)",
                        Risk = RiskLevel.High,
                        Location = nuiDevtools,
                        FileName = "nui-devtools.json",
                        Reason = "FiveM NUI Chrome DevTools sind aktiviert. Wird von Cheats genutzt um " +
                                 "JavaScript-Code in FiveM NUI-Pages einzuschleusen.",
                        Detail = $"Config={nuiDevtools}"
                    });
                }
            }
            catch { }
        }
    }

    // ─── FiveM server resource cheat scan ────────────────────────────────────

    private static void ScanFiveMResourcesForCheats(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // FiveM caches downloaded server resources here
        var resourceCaches = new[]
        {
            Path.Combine(appData, "CitizenFX", "FiveM.app", "data", "cache", "priv"),
            Path.Combine(appData, "CitizenFX", "FiveM.app", "data", "server-cache"),
            Path.Combine(appData, "CitizenFX", "FiveM.app", "data", "game-storage"),
        };

        foreach (var cacheDir in resourceCaches)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cacheDir)) continue;
            ScanLuaDirectory(ctx, cacheDir, ct);
        }

        // Check user-installed resources (if running a local FiveM server)
        var serverResourceDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "FXServer", "resources");
        if (Directory.Exists(serverResourceDir))
            ScanLuaDirectory(ctx, serverResourceDir, ct);
    }

    private static void ScanLuaDirectory(ScanContext ctx, string dir, CancellationToken ct)
    {
        try
        {
            foreach (var luaFile in Directory.GetFiles(dir, "*.lua", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles(1);

                string content;
                try
                {
                    const int maxBytes = 128 * 1024;
                    using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var buf = new byte[(int)Math.Min(maxBytes, fs.Length)];
                    var read = fs.Read(buf, 0, buf.Length);
                    content = Encoding.UTF8.GetString(buf, 0, read).ToLowerInvariant();
                }
                catch { continue; }

                var matched = new List<string>();
                foreach (var pattern in LuaCheatPatterns)
                {
                    if (content.Contains(pattern.ToLowerInvariant()))
                    {
                        matched.Add(pattern);
                        if (matched.Count >= 4) break;
                    }
                }

                if (matched.Count >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "FiveMDeepCheat",
                        Title = $"FiveM Lua-Cheat-Skript: {Path.GetFileName(luaFile)}",
                        Risk = RiskLevel.High,
                        Location = luaFile,
                        FileName = Path.GetFileName(luaFile),
                        Reason = $"Lua-Skript enthaelt {matched.Count} Cheat-API-Aufrufe: {string.Join(", ", matched)}. " +
                                 "Typische FiveM Godmode/Teleport/ESP-Cheat-Kombination.",
                        Detail = $"File={luaFile} Patterns={string.Join("|", matched)}"
                    });
                }
            }
        }
        catch { }
    }

    // ─── FiveM log scanning ───────────────────────────────────────────────────

    private static readonly string[] FiveMLogCheatKeywords = {
        "eulen", "lynx", "hamster", "impulse", "infinity", "desudo", "baddie",
        "inject", "bypass", "cheat", "hack", "exploit",
        "cfx-bypass", "citizenbypass", "resourceinjector",
        "nui-devtools", "devtools-port",
        "script hook", "scripthookv"
    };

    private static void ScanFiveMLogs(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var logDir  = Path.Combine(appData, "CitizenFX");

        if (!Directory.Exists(logDir)) return;

        try
        {
            foreach (var logFile in Directory.GetFiles(logDir, "*.log", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles(1);

                try
                {
                    const int maxBytes = 512 * 1024;
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    // Read last portion of large logs
                    var readStart = Math.Max(0, fs.Length - maxBytes);
                    fs.Seek(readStart, SeekOrigin.Begin);
                    var buf = new byte[Math.Min(maxBytes, fs.Length)];
                    var read = fs.Read(buf, 0, buf.Length);
                    var content = Encoding.UTF8.GetString(buf, 0, read).ToLowerInvariant();

                    foreach (var kw in FiveMLogCheatKeywords)
                    {
                        if (content.Contains(kw))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "FiveMDeepCheat",
                                Title = $"FiveM-Log: Cheat-Keyword '{kw}' gefunden",
                                Risk = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"FiveM-Logdatei enthaelt Cheat-Keyword '{kw}' — Hinweis auf Cheat-Tool-Aktivitaet.",
                                Detail = $"LogFile={logFile} Keyword={kw}"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    // ─── Registry artifacts from FiveM cheat installers ──────────────────────

    private static void ScanFiveMBypassRegistry(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // Known registry keys left by FiveM cheat tools
        string[] cheatRegKeys = {
            @"Software\Eulen",
            @"Software\EulenClient",
            @"Software\LynxClient",
            @"Software\HamsterFiveM",
            @"Software\ImpulseFiveM",
            @"Software\InfinityMenu",
            @"Software\DesudoMenu",
            @"Software\CFX-Bypass",
            @"Software\FiveMCheat",
        };

        foreach (var keyPath in cheatRegKeys)
        {
            ct.ThrowIfCancellationRequested();
            using var key = Registry.CurrentUser.OpenSubKey(keyPath)
                         ?? Registry.LocalMachine.OpenSubKey(keyPath);
            if (key == null) continue;

            ctx.IncrementRegistryKeys(1);
            ctx.AddFinding(new Finding
            {
                Module = "FiveMDeepCheat",
                Title = $"FiveM Cheat-Registry-Artefakt: {keyPath}",
                Risk = RiskLevel.Critical,
                Location = $@"HKCU\{keyPath}",
                Reason = $"Registry-Schluessel von bekanntem FiveM-Cheat-Tool gefunden: '{keyPath}'. " +
                         "Beweist Installation oder Ausfuehrung dieses Cheats.",
                Detail = $"RegKey={keyPath}"
            });
        }

        // Check Add/Remove Programs for FiveM cheats
        string[] uninstPaths = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };
        string[] cheatUninstNames = {
            "eulen", "lynx", "hamster", "impulse", "infinity", "desudo",
            "fivem cheat", "fivem hack", "cfx bypass", "citizenfx bypass"
        };

        foreach (var uninstPath in uninstPaths)
        {
            ct.ThrowIfCancellationRequested();
            using var uninstKey = Registry.LocalMachine.OpenSubKey(uninstPath)
                               ?? Registry.CurrentUser.OpenSubKey(uninstPath);
            if (uninstKey == null) continue;

            foreach (var subName in uninstKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var sub = uninstKey.OpenSubKey(subName);
                if (sub == null) continue;

                var displayName = (sub.GetValue("DisplayName") as string ?? string.Empty).ToLowerInvariant();
                foreach (var cheatName in cheatUninstNames)
                {
                    if (displayName.Contains(cheatName))
                    {
                        ctx.IncrementRegistryKeys(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "FiveMDeepCheat",
                            Title = $"FiveM Cheat in Add/Remove Programs: {sub.GetValue("DisplayName")}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{uninstPath}\{subName}",
                            Reason = $"FiveM-Cheat-Software '{displayName}' in Programmen gefunden — beweist Installation.",
                            Detail = $"DisplayName={displayName}"
                        });
                        break;
                    }
                }
            }
        }
    }
}
