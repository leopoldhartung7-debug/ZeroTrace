using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects alt:V Multiplayer GTA V cheat artifacts: known cheat client directories and EXEs,
/// malicious alt:V resource scripts (client-side .js/.mjs with native-call cheat patterns),
/// alt:V bypass tools (signature bypass, server-side check bypass), cheat-keyword DLLs in
/// the alt:V data directory, and registry/installed-program artifacts from cheat tools.
/// alt:V uses a Chromium V8 JS runtime for client-side scripts — making script-based cheats
/// trivially portable.
/// </summary>
public sealed class AltVCheatDetectionScanModule : IScanModule
{
    public string Name => "AltVCheatDetection";
    public double Weight => 0.55;
    public int ParallelGroup => 4;

    // ─── Known alt:V cheat EXE names ─────────────────────────────────────────
    private static readonly string[] AltVCheatExeNames = {
        // Known alt:V cheat clients / mod menus
        "altv-cheat.exe", "altvcheat.exe", "altv-hack.exe", "altvhack.exe",
        "altv-bypass.exe", "altvbypass.exe",
        "altv-menu.exe", "altvmenu.exe",
        "altv-loader.exe", "altvloader.exe",
        "altv-injector.exe", "altvinjector.exe",
        // Common cheat names in alt:V context
        "phantom-altv.exe", "spectre-altv.exe", "stealth-altv.exe",
        "gtav-altv-hack.exe",
        // Resource exploitation tools
        "resource-exploit.exe", "sync-exploit.exe",
    };

    private static readonly string[] AltVCheatDllNames = {
        "altv-cheat.dll", "altvcheat.dll", "altv-hook.dll", "altvhook.dll",
        "altv-bypass.dll", "altvbypass.dll",
        "altv-aimbot.dll", "altv-esp.dll",
        "phantom-altv.dll", "spectre-altv.dll",
    };

    private static readonly string[] AltVCheatDirNames = {
        "AltV-Cheat", "AltVCheat", "AltV-Hack", "AltVHack",
        "AltV-Bypass", "AltVBypass",
        "AltV-Menu", "AltVMenu",
        "Phantom-AltV", "Spectre-AltV",
        "AltV-Injector", "AltVInjector",
    };

    // ─── alt:V client-side JavaScript cheat patterns ─────────────────────────
    // alt:V uses alt-client JS API with natives via alt.natives.*
    private static readonly string[] AltVJsCheatPatterns = {
        "alt.natives.setplayerinvincible",      // god mode
        "alt.natives.setvehiclemaxspeed",       // speed hack
        "alt.natives.setentitycoords",          // teleport
        "alt.natives.addweapontoentity",        // weapon spawner
        "alt.natives.setentityinvincible",      // entity god mode
        "alt.natives.createvehicle",            // vehicle spawner
        "alt.natives.explosion",                // explosion spawner
        "alt.natives.setmaxwantedlevel",        // wanted level
        "alt.natives.disablepolicespawning",    // police ban
        "alt.onserver",                         // server event hook (ESP data exfil)
        "alt.emit",                             // local event (cheat IPC)
        "noclip",
        "aimbot",
        "wallhack",
        "esp",
        "godmode",
        "speedhack",
        "bypass",
        "exploit",
        "inject",
        "radar",
        "alt.game.invoke",                      // raw native call bypass
        "getentitycoords",                      // position reading (ESP)
        "getplayerped",
        "setentityheading",                     // targeting assist
    };

    // ─── alt:V resource manifest cheat indicators ────────────────────────────
    private static readonly string[] AltVManifestCheatKeywords = {
        "cheat", "hack", "aimbot", "esp", "wallhack", "bypass",
        "exploit", "godmode", "speedhack", "noclip", "radar"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanAltVCheatDirectories(ctx, ct);
            ScanAltVProcesses(ctx, ct);
            ScanAltVDataDirectory(ctx, ct);
            ScanAltVResourceScripts(ctx, ct);
            ScanAltVRegistry(ctx, ct);
        }, ct);
    }

    // ─── Common user dirs ─────────────────────────────────────────────────────

    private static void ScanAltVCheatDirectories(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.GetTempPath(),
        };

        foreach (var baseDir in searchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            foreach (var cheatDir in AltVCheatDirNames)
            {
                var fullPath = Path.Combine(baseDir, cheatDir);
                if (!Directory.Exists(fullPath)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "AltVCheatDetection",
                    Title = $"alt:V Cheat-Verzeichnis gefunden: {cheatDir}",
                    Risk = RiskLevel.Critical,
                    Location = fullPath,
                    Reason = $"Bekanntes alt:V-Cheat-Verzeichnis '{cheatDir}' gefunden.",
                    Detail = $"Dir={fullPath}"
                });
            }

            try
            {
                foreach (var exe in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(exe).ToLowerInvariant();
                    if (Array.IndexOf(AltVCheatExeNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "AltVCheatDetection",
                            Title = $"alt:V Cheat-EXE: {Path.GetFileName(exe)}",
                            Risk = RiskLevel.Critical,
                            Location = exe,
                            FileName = fname,
                            Reason = $"Bekanntes alt:V-Cheat-Programm '{fname}' gefunden.",
                            Detail = $"Path={exe}"
                        });
                    }
                }

                foreach (var dll in Directory.GetFiles(baseDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(dll).ToLowerInvariant();
                    if (Array.IndexOf(AltVCheatDllNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "AltVCheatDetection",
                            Title = $"alt:V Cheat-DLL: {Path.GetFileName(dll)}",
                            Risk = RiskLevel.Critical,
                            Location = dll,
                            FileName = fname,
                            Reason = $"Bekannte alt:V-Cheat-DLL '{fname}' gefunden.",
                            Detail = $"Path={dll}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    // ─── Running alt:V cheat processes ───────────────────────────────────────

    private static void ScanAltVProcesses(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var procs = ctx.GetProcessSnapshot();

        foreach (var proc in procs)
        {
            ct.ThrowIfCancellationRequested();
            var pname = (proc.Name + ".exe").ToLowerInvariant();
            if (Array.IndexOf(AltVCheatExeNames, pname) >= 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "AltVCheatDetection",
                    Title = $"alt:V Cheat-Prozess aktiv: {proc.Name}",
                    Risk = RiskLevel.Critical,
                    Location = proc.MainModule ?? proc.Name,
                    FileName = proc.Name,
                    Reason = $"Aktiver alt:V-Cheat-Prozess '{proc.Name}' erkannt.",
                    Detail = $"PID={proc.Id}"
                });
            }

            var path = (proc.MainModule ?? string.Empty).ToLowerInvariant();
            if (path.Contains("altv-cheat") || path.Contains("altvcheat") ||
                path.Contains("altv-bypass") || path.Contains("altv-hack"))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "AltVCheatDetection",
                    Title = $"Prozess aus alt:V-Cheat-Pfad: {proc.Name}",
                    Risk = RiskLevel.Critical,
                    Location = proc.MainModule ?? proc.Name,
                    FileName = proc.Name,
                    Reason = $"'{proc.Name}' laeuft aus einem alt:V-Cheat-Verzeichnis.",
                    Detail = $"PID={proc.Id} Path={proc.MainModule}"
                });
            }
        }
    }

    // ─── alt:V data directory scan ────────────────────────────────────────────

    private static void ScanAltVDataDirectory(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // alt:V stores data in %AppData%\altv or %LocalAppData%\altv
        var altVDirs = new[]
        {
            Path.Combine(appData,  "altv"),
            Path.Combine(appData,  "alt-v"),
            Path.Combine(appData,  "altv-client"),
            Path.Combine(localApp, "altv"),
            Path.Combine(localApp, "alt-v"),
        };

        foreach (var altVDir in altVDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(altVDir)) continue;

            // Scan for cheat DLLs in alt:V data root
            try
            {
                foreach (var dll in Directory.GetFiles(altVDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(dll).ToLowerInvariant();

                    if (Array.IndexOf(AltVCheatDllNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "AltVCheatDetection",
                            Title = $"Cheat-DLL im alt:V-Verzeichnis: {fname}",
                            Risk = RiskLevel.Critical,
                            Location = dll,
                            FileName = fname,
                            Reason = $"Cheat-DLL '{fname}' im alt:V-Datenverzeichnis — wird bei alt:V-Start geladen.",
                            Detail = $"Path={dll}"
                        });
                    }

                    // Check for cheat keywords in DLL filename
                    foreach (var kw in new[] { "cheat", "hack", "aimbot", "esp", "bypass", "inject" })
                    {
                        if (fname.Contains(kw))
                        {
                            ctx.IncrementFiles(1);
                            ctx.AddFinding(new Finding
                            {
                                Module = "AltVCheatDetection",
                                Title = $"Verdaechtige DLL im alt:V-Verzeichnis: {fname}",
                                Risk = RiskLevel.High,
                                Location = dll,
                                FileName = fname,
                                Reason = $"DLL mit Cheat-Keyword '{kw}' im alt:V-Verzeichnis gefunden.",
                                Detail = $"Path={dll} Keyword={kw}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }

            // Check for bypass configuration files
            string[] bypassFiles = {
                "bypass.json", "altv-bypass.cfg", "sig-bypass.json",
                "cheat.cfg", "hack.json", "altv-cheat.cfg"
            };
            foreach (var bypassFile in bypassFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fullPath = Path.Combine(altVDir, bypassFile);
                if (!File.Exists(fullPath)) continue;
                ctx.IncrementFiles(1);
                ctx.AddFinding(new Finding
                {
                    Module = "AltVCheatDetection",
                    Title = $"alt:V Cheat-Konfigurationsdatei: {bypassFile}",
                    Risk = RiskLevel.Critical,
                    Location = fullPath,
                    FileName = bypassFile,
                    Reason = $"Cheat/Bypass-Konfigurationsdatei '{bypassFile}' im alt:V-Verzeichnis.",
                    Detail = $"Path={fullPath}"
                });
            }

            // Check resources/logs subdirectory
            var resourcesDir = Path.Combine(altVDir, "resources");
            if (Directory.Exists(resourcesDir))
                ScanAltVResourceDirectory(ctx, resourcesDir, ct);
        }
    }

    // ─── alt:V resource script scan ──────────────────────────────────────────

    private static void ScanAltVResourceScripts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var resourceDirs = new[]
        {
            Path.Combine(appData,  "altv",   "resources"),
            Path.Combine(appData,  "alt-v",  "resources"),
            Path.Combine(localApp, "altv",   "resources"),
            Path.Combine(appData,  "altv",   "cache"),
        };

        foreach (var dir in resourceDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;
            ScanAltVResourceDirectory(ctx, dir, ct);
        }
    }

    private static void ScanAltVResourceDirectory(ScanContext ctx, string dir, CancellationToken ct)
    {
        try
        {
            // Scan JS/MJS scripts
            foreach (var ext in new[] { "*.js", "*.mjs" })
            {
                foreach (var jsFile in Directory.GetFiles(dir, ext, SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles(1);
                    AnalyzeAltVScript(ctx, jsFile, AltVJsCheatPatterns, ct);
                }
            }

            // Scan resource.cfg / resource.toml manifests for cheat keywords
            foreach (var manifestExt in new[] { "resource.cfg", "resource.toml", "manifest.json" })
            {
                foreach (var manifest in Directory.GetFiles(dir, manifestExt, SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles(1);
                    try
                    {
                        var content = File.ReadAllText(manifest, Encoding.UTF8).ToLowerInvariant();
                        foreach (var kw in AltVManifestCheatKeywords)
                        {
                            if (content.Contains(kw))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "AltVCheatDetection",
                                    Title = $"Cheat-Keyword in alt:V Resource-Manifest: {Path.GetFileName(manifest)}",
                                    Risk = RiskLevel.High,
                                    Location = manifest,
                                    FileName = Path.GetFileName(manifest),
                                    Reason = $"alt:V Resource-Manifest enthaelt Cheat-Keyword '{kw}'.",
                                    Detail = $"File={manifest} Keyword={kw}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private static void AnalyzeAltVScript(ScanContext ctx, string filePath,
        string[] patterns, CancellationToken ct)
    {
        string content;
        try
        {
            const int maxBytes = 256 * 1024;
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buf  = new byte[(int)Math.Min(maxBytes, fs.Length)];
            var read = fs.Read(buf, 0, buf.Length);
            content  = Encoding.UTF8.GetString(buf, 0, read).ToLowerInvariant();
        }
        catch { return; }

        var matched = new List<string>();
        foreach (var pattern in patterns)
        {
            ct.ThrowIfCancellationRequested();
            if (content.Contains(pattern.ToLowerInvariant()))
            {
                matched.Add(pattern);
                if (matched.Count >= 4) break;
            }
        }

        if (matched.Count < 2) return;

        ctx.AddFinding(new Finding
        {
            Module = "AltVCheatDetection",
            Title = $"alt:V Cheat-Clientskript: {Path.GetFileName(filePath)}",
            Risk = matched.Count >= 3 ? RiskLevel.Critical : RiskLevel.High,
            Location = filePath,
            FileName = Path.GetFileName(filePath),
            Reason = $"alt:V-Skript enthaelt {matched.Count} Cheat-API-Pattern: {string.Join(", ", matched)}. " +
                     "Native-Calls deuten auf ESP/Aimbot/Teleport-Cheat hin.",
            Detail = $"File={filePath} Patterns={string.Join("|", matched)}"
        });
    }

    // ─── Registry artifacts ───────────────────────────────────────────────────

    private static void ScanAltVRegistry(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        string[] cheatRegKeys = {
            @"Software\AltVCheat",
            @"Software\AltV-Cheat",
            @"Software\AltVBypass",
            @"Software\AltV-Bypass",
            @"Software\PhantomAltV",
            @"Software\SpectreAltV",
        };

        foreach (var keyPath in cheatRegKeys)
        {
            ct.ThrowIfCancellationRequested();
            using var key = Registry.CurrentUser.OpenSubKey(keyPath);
            if (key == null) continue;

            ctx.IncrementRegistryKeys(1);
            ctx.AddFinding(new Finding
            {
                Module = "AltVCheatDetection",
                Title = $"alt:V Cheat-Registry-Artefakt: {keyPath}",
                Risk = RiskLevel.Critical,
                Location = $@"HKCU\{keyPath}",
                Reason = $"Registry-Schluessel von bekanntem alt:V-Cheat: '{keyPath}'.",
                Detail = $"RegKey={keyPath}"
            });
        }

        // Add/Remove Programs check
        string[] uninstCheatNames = {
            "altv cheat", "alt:v cheat", "altv hack", "altv bypass",
            "phantom altv", "spectre altv"
        };

        foreach (var uninstPath in new[] {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" })
        {
            ct.ThrowIfCancellationRequested();
            using var uninstKey = Registry.LocalMachine.OpenSubKey(uninstPath);
            if (uninstKey == null) continue;

            foreach (var subName in uninstKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var sub = uninstKey.OpenSubKey(subName);
                if (sub == null) continue;

                var displayName = (sub.GetValue("DisplayName") as string ?? string.Empty).ToLowerInvariant();
                foreach (var cheatName in uninstCheatNames)
                {
                    if (displayName.Contains(cheatName))
                    {
                        ctx.IncrementRegistryKeys(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "AltVCheatDetection",
                            Title = $"alt:V Cheat in Add/Remove Programs: {sub.GetValue("DisplayName")}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{uninstPath}\{subName}",
                            Reason = $"alt:V-Cheat '{displayName}' in installierten Programmen — beweist Installation.",
                            Detail = $"DisplayName={displayName}"
                        });
                        break;
                    }
                }
            }
        }
    }
}
