using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects RageMP (RAGE Multiplayer) GTA V cheat artifacts: known cheat client directories/EXEs
/// (Evolution, Hamster-RAGEMP, custom mod clients), malicious .NET assemblies in the RageMP
/// dotnet/assemblies directory, suspicious client-side JavaScript packages, RageMP bypass tools,
/// and registry/installed-software artifacts from cheat installers.
/// RageMP is one of the major GTA V multiplayer platforms alongside FiveM.
/// </summary>
public sealed class RageMpCheatDetectionScanModule : IScanModule
{
    public string Name => "RageMpCheatDetection";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    // ─── Known RageMP cheat EXE names ────────────────────────────────────────
    private static readonly string[] RageMpCheatExeNames = {
        // Evolution — most well-known RageMP cheat
        "evolution.exe", "evolution-ragemp.exe", "evolutionclient.exe",
        // Hamster for RageMP
        "hamster-ragemp.exe", "hamsterragemp.exe",
        // Generic RageMP cheats
        "ragemp-cheat.exe", "ragemp-hack.exe", "ragemp-bypass.exe",
        "rage-cheat.exe", "ragemenu.exe", "rage-menu.exe",
        // RageMP mod loaders / injectors
        "ragemp-loader.exe", "rageinjector.exe", "rage-injector.exe",
        "gtav-ragemp-hack.exe",
        // Known generic cheat names in RageMP context
        "nighthawk.exe",    // reported RageMP cheat
        "epsilon.exe",      // reported RageMP cheat
        "phantom.exe",
        "spectre-ragemp.exe",
        "stealth-ragemp.exe",
    };

    private static readonly string[] RageMpCheatDllNames = {
        "evolution.dll", "evolutionhook.dll",
        "hamster-ragemp.dll", "hamsterragemp.dll",
        "ragemp-cheat.dll", "ragehook.dll", "ragemphook.dll",
        "nighthawk.dll", "epsilon.dll", "phantom.dll",
        "ragebypass.dll", "rage-bypass.dll",
    };

    private static readonly string[] RageMpCheatDirNames = {
        "Evolution", "EvolutionRageMP", "Evolution-RageMP",
        "HamsterRageMP", "Hamster-RageMP",
        "RageMP-Cheat", "RAGEMP-Hack", "RageHack",
        "Nighthawk", "Epsilon", "Phantom",
        "RageMP-Bypass", "Rage-Bypass",
    };

    // ─── Suspicious .NET assembly patterns (RageMP loads .NET DLLs) ──────────
    private static readonly string[] SuspiciousDotNetPatterns = {
        "aimbot", "wallhack", "esp", "noclip", "godmode",
        "teleport", "speedhack", "injector", "bypass",
        "exploit", "cheat", "hack", "radar",
        "getentitycoords", "setplayerinvincible",
    };

    // ─── RageMP clientside JavaScript cheat patterns ─────────────────────────
    private static readonly string[] JsCheatPatterns = {
        "mp.game.invoke",             // native invocation
        "mp.players.forEach",         // player enumeration (ESP)
        "setplayerinvincible",        // god mode native
        "setvehiclemaxspeed",         // speed hack
        "setentitycoords",            // teleport
        "noclip",
        "aimbot",
        "esp",
        "speedhack",
        "godmode",
        "exploit",
        "bypass",
        "mp.events.add.*tick",        // per-tick hook (common in ESP/aimbot)
        "getentitycoords",
        "setentityheading",           // aimbot entity targeting
        "explosion",                  // explosion spawner
        "addweapontoentity",
        "getplayerped",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanRageMpCheatDirectories(ctx, ct);
            ScanRageMpProcesses(ctx, ct);
            ScanRageMpDataDirectory(ctx, ct);
            ScanRageMpDotNetAssemblies(ctx, ct);
            ScanRageMpClientScripts(ctx, ct);
            ScanRageMpRegistry(ctx, ct);
        }, ct);
    }

    // ─── Common directories for RageMP cheat files ───────────────────────────

    private static void ScanRageMpCheatDirectories(ScanContext ctx, CancellationToken ct)
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

            foreach (var cheatDir in RageMpCheatDirNames)
            {
                var fullPath = Path.Combine(baseDir, cheatDir);
                if (!Directory.Exists(fullPath)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "RageMpCheatDetection",
                    Title = $"RageMP Cheat-Verzeichnis gefunden: {cheatDir}",
                    Risk = RiskLevel.Critical,
                    Location = fullPath,
                    Reason = $"Bekanntes RageMP-Cheat-Verzeichnis '{cheatDir}' gefunden.",
                    Detail = $"Dir={fullPath}"
                });
            }

            try
            {
                foreach (var exe in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(exe).ToLowerInvariant();
                    if (Array.IndexOf(RageMpCheatExeNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "RageMpCheatDetection",
                            Title = $"RageMP Cheat-EXE: {Path.GetFileName(exe)}",
                            Risk = RiskLevel.Critical,
                            Location = exe,
                            FileName = fname,
                            Reason = $"Bekanntes RageMP-Cheat-Programm '{fname}' gefunden.",
                            Detail = $"Path={exe}"
                        });
                    }
                }

                foreach (var dll in Directory.GetFiles(baseDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(dll).ToLowerInvariant();
                    if (Array.IndexOf(RageMpCheatDllNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "RageMpCheatDetection",
                            Title = $"RageMP Cheat-DLL: {Path.GetFileName(dll)}",
                            Risk = RiskLevel.Critical,
                            Location = dll,
                            FileName = fname,
                            Reason = $"Bekannte RageMP-Cheat-DLL '{fname}' gefunden.",
                            Detail = $"Path={dll}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    // ─── Running RageMP cheat processes ──────────────────────────────────────

    private static void ScanRageMpProcesses(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var procs = ctx.GetProcessSnapshot();

        foreach (var proc in procs)
        {
            ct.ThrowIfCancellationRequested();
            var pname = (proc.Name + ".exe").ToLowerInvariant();
            if (Array.IndexOf(RageMpCheatExeNames, pname) >= 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "RageMpCheatDetection",
                    Title = $"RageMP Cheat-Prozess aktiv: {proc.Name}",
                    Risk = RiskLevel.Critical,
                    Location = proc.MainModule ?? proc.Name,
                    FileName = proc.Name,
                    Reason = $"Aktiver RageMP-Cheat-Prozess '{proc.Name}' erkannt.",
                    Detail = $"PID={proc.Id}"
                });
            }

            var path = (proc.MainModule ?? string.Empty).ToLowerInvariant();
            foreach (var cheatDir in RageMpCheatDirNames)
            {
                if (path.Contains(cheatDir.ToLowerInvariant()))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "RageMpCheatDetection",
                        Title = $"Prozess aus RageMP-Cheat-Verzeichnis: {proc.Name}",
                        Risk = RiskLevel.Critical,
                        Location = proc.MainModule ?? proc.Name,
                        FileName = proc.Name,
                        Reason = $"'{proc.Name}' laeuft aus RageMP-Cheat-Verzeichnis '{cheatDir}'.",
                        Detail = $"PID={proc.Id} Path={proc.MainModule}"
                    });
                    break;
                }
            }
        }
    }

    // ─── RageMP %AppData%\RAGEMP directory ───────────────────────────────────

    private static void ScanRageMpDataDirectory(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData    = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var rageMpDir  = Path.Combine(appData, "RAGEMP");
        var rageMpDir2 = Path.Combine(appData, "ragemp");

        foreach (var dir in new[] { rageMpDir, rageMpDir2 })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            // Check for cheat files in RageMP root
            try
            {
                foreach (var file in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(file).ToLowerInvariant();

                    if (Array.IndexOf(RageMpCheatDllNames, fname) >= 0 ||
                        Array.IndexOf(RageMpCheatExeNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "RageMpCheatDetection",
                            Title = $"RageMP Cheat-Datei im RAGEMP-Verzeichnis: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fname,
                            Reason = $"Cheat-Datei '{fname}' direkt im RageMP-Datenverzeichnis gefunden.",
                            Detail = $"Path={file}"
                        });
                    }
                }
            }
            catch { }

            // packages subdirectory — client-side packages
            var packagesDir = Path.Combine(dir, "packages");
            if (Directory.Exists(packagesDir))
                ScanRageMpPackages(ctx, packagesDir, ct);
        }
    }

    private static void ScanRageMpPackages(ScanContext ctx, string packagesDir, CancellationToken ct)
    {
        try
        {
            foreach (var pkgDir in Directory.GetDirectories(packagesDir, "*", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                var pkgName = Path.GetFileName(pkgDir).ToLowerInvariant();

                // Suspicious package names
                bool isSuspicious = false;
                string[] cheatPkgKeywords = {
                    "cheat", "hack", "aimbot", "esp", "bypass", "exploit",
                    "godmode", "speedhack", "noclip", "radar",
                    "evolution", "hamster", "nighthawk", "epsilon"
                };
                foreach (var kw in cheatPkgKeywords)
                {
                    if (pkgName.Contains(kw)) { isSuspicious = true; break; }
                }

                if (isSuspicious)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "RageMpCheatDetection",
                        Title = $"Verdaechtiges RageMP-Package: {Path.GetFileName(pkgDir)}",
                        Risk = RiskLevel.Critical,
                        Location = pkgDir,
                        Reason = $"RageMP-Package-Verzeichnis mit Cheat-Keyword '{pkgName}' gefunden.",
                        Detail = $"PackageDir={pkgDir}"
                    });
                }
            }
        }
        catch { }
    }

    // ─── RageMP .NET assembly directory ──────────────────────────────────────

    private static void ScanRageMpDotNetAssemblies(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var asmDir  = Path.Combine(appData, "RAGEMP", "dotnet", "assemblies");

        if (!Directory.Exists(asmDir)) return;

        try
        {
            foreach (var dll in Directory.GetFiles(asmDir, "*.dll", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles(1);
                var fname = Path.GetFileName(dll).ToLowerInvariant();

                // Check for known cheat DLL names
                if (Array.IndexOf(RageMpCheatDllNames, fname) >= 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "RageMpCheatDetection",
                        Title = $"Cheat-.NET-Assembly in RageMP: {Path.GetFileName(dll)}",
                        Risk = RiskLevel.Critical,
                        Location = dll,
                        FileName = fname,
                        Reason = $"Bekannte Cheat-DLL '{fname}' im RageMP .NET-Assembly-Verzeichnis.",
                        Detail = $"Path={dll}"
                    });
                    continue;
                }

                // Check filename for cheat keywords
                foreach (var pattern in SuspiciousDotNetPatterns)
                {
                    if (fname.Contains(pattern))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "RageMpCheatDetection",
                            Title = $"Verdaechtige .NET-Assembly in RageMP: {Path.GetFileName(dll)}",
                            Risk = RiskLevel.High,
                            Location = dll,
                            FileName = fname,
                            Reason = $".NET-Assembly mit Cheat-Keyword '{pattern}' im RageMP-Assembly-Verzeichnis gefunden. " +
                                     "RageMP laedt alle DLLs hier automatisch in den GTA-V-Prozess.",
                            Detail = $"Path={dll} Keyword={pattern}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }

    // ─── RageMP client-side script scan ──────────────────────────────────────

    private static void ScanRageMpClientScripts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var scriptDirs = new[]
        {
            Path.Combine(appData, "RAGEMP", "bin", "scripts"),
            Path.Combine(appData, "RAGEMP", "scripts"),
            Path.Combine(appData, "RAGEMP", "client_packages"),
        };

        foreach (var scriptDir in scriptDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(scriptDir)) continue;

            try
            {
                foreach (var jsFile in Directory.GetFiles(scriptDir, "*.js", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles(1);
                    AnalyzeJsCheatScript(ctx, jsFile, ct);
                }
            }
            catch { }
        }
    }

    private static void AnalyzeJsCheatScript(ScanContext ctx, string filePath, CancellationToken ct)
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
        foreach (var pattern in JsCheatPatterns)
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
            Module = "RageMpCheatDetection",
            Title = $"RageMP Cheat-Clientskript: {Path.GetFileName(filePath)}",
            Risk = matched.Count >= 3 ? RiskLevel.Critical : RiskLevel.High,
            Location = filePath,
            FileName = Path.GetFileName(filePath),
            Reason = $"RageMP clientseitiges JavaScript enthaelt {matched.Count} Cheat-API-Pattern: {string.Join(", ", matched)}.",
            Detail = $"File={filePath} Patterns={string.Join("|", matched)}"
        });
    }

    // ─── Registry artifacts ───────────────────────────────────────────────────

    private static void ScanRageMpRegistry(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        string[] cheatRegKeys = {
            @"Software\Evolution",
            @"Software\EvolutionRageMP",
            @"Software\HamsterRageMP",
            @"Software\RageMPCheat",
            @"Software\NightHawk",
            @"Software\EpsilonRageMP",
        };

        foreach (var keyPath in cheatRegKeys)
        {
            ct.ThrowIfCancellationRequested();
            using var key = Registry.CurrentUser.OpenSubKey(keyPath);
            if (key == null) continue;

            ctx.IncrementRegistryKeys(1);
            ctx.AddFinding(new Finding
            {
                Module = "RageMpCheatDetection",
                Title = $"RageMP Cheat-Registry-Artefakt: {keyPath}",
                Risk = RiskLevel.Critical,
                Location = $@"HKCU\{keyPath}",
                Reason = $"Registry-Schluessel von bekanntem RageMP-Cheat-Tool: '{keyPath}'.",
                Detail = $"RegKey={keyPath}"
            });
        }

        // Add/Remove Programs
        string[] uninstCheatNames = {
            "evolution", "evolution ragemp", "hamster ragemp",
            "ragemp cheat", "rage multiplayer cheat", "nighthawk"
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
                            Module = "RageMpCheatDetection",
                            Title = $"RageMP Cheat in Add/Remove Programs: {sub.GetValue("DisplayName")}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{uninstPath}\{subName}",
                            Reason = $"RageMP-Cheat '{displayName}' in installierten Programmen — beweist Installation.",
                            Detail = $"DisplayName={displayName}"
                        });
                        break;
                    }
                }
            }
        }
    }
}
