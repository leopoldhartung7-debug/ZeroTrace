using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects game replay/demo manipulation artifacts: truncated or stub CS2 demos,
/// VALORANT match replay absence, demo-blocking tools, and launch options disabling
/// demo recording. Demo forensics is a primary Ocean/detect.ac detection source.
/// </summary>
public sealed class GameReplayManipulationScanModule : IScanModule
{
    public string Name => "GameReplayManipulation";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywords = {
        "aimbot", "cheat", "hack", "wallhack", "esp", "spinbot", "bhop",
        "triggerbot", "inject", "bypass", "norecoil", "silent", "hvh"
    };

    private static readonly string[] DemoBlockerExeNames = {
        "demoblocker.exe", "nodemo.exe", "demoblock.exe", "cleandemo.exe",
        "demo_delete.exe", "demo_cleaner.exe", "block_demo.exe",
        "csgo_cleaner.exe", "cs2_cleaner.exe"
    };

    private static readonly string[] DemoBlockLaunchFlags = {
        "-nodemo", "+demo_forcerecord 0", "-norecord", "+tv_enable 0",
        "+record_off", "-noprofiledemos"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanCsGoDemoDirectory(ctx, ct);
            ScanValorantReplays(ctx, ct);
            ScanDemoBlockingTools(ctx, ct);
            ScanSteamLaunchOptionsForDemoBlock(ctx, ct);
            ScanFaceitClient(ctx, ct);
        }, ct);
    }

    private static void ScanCsGoDemoDirectory(ScanContext ctx, CancellationToken ct)
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var cs2DemoDir  = Path.Combine(profile, "Documents", "Counter-Strike 2", "CSGO", "demos");
        var csgoDemoDir = Path.Combine(profile, "Documents", "CSGO", "demos");

        foreach (var demoDir in new[] { cs2DemoDir, csgoDemoDir })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(demoDir)) continue;

            try
            {
                var demFiles = Directory.GetFiles(demoDir, "*.dem", SearchOption.TopDirectoryOnly);
                ctx.IncrementFiles(demFiles.Length);

                foreach (var dem in demFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var info = new FileInfo(dem);
                        if (info.Length < 2048) // real demos are 50-500 MB; <2 KB = stub/blocked
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "GameReplayManipulation",
                                Title = "CS2 Demo-Datei zu klein (moeglicherweise blockiert)",
                                Risk = RiskLevel.High,
                                Location = dem,
                                FileName = Path.GetFileName(dem),
                                Reason = $"Demo-Datei ist nur {info.Length} Bytes. Normale Demos sind 50-500 MB. " +
                                         "Stub-Dateien entstehen wenn Demo-Recording aktiv blockiert wurde.",
                                Detail = $"Path={dem} Size={info.Length}"
                            });
                        }
                    }
                    catch { }
                }

                if (demFiles.Length == 0)
                {
                    var ageInDays = (DateTime.UtcNow - Directory.GetCreationTimeUtc(demoDir)).TotalDays;
                    if (ageInDays > 7)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "GameReplayManipulation",
                            Title = "CS2 Demo-Verzeichnis leer trotz aktivem Spielprofil",
                            Risk = RiskLevel.Medium,
                            Location = demoDir,
                            Reason = $"Demo-Verzeichnis existiert seit {(int)ageInDays} Tagen und enthaelt keine Demos " +
                                     "— deutet auf Demo-Loesch-Skript oder Demo-Blocker hin.",
                            Detail = $"DemoDir={demoDir} AgeInDays={ageInDays:F0}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private static void ScanValorantReplays(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var replayDir = Path.Combine(localApp, "VALORANT", "Saved", "Demos");

        if (!Directory.Exists(replayDir)) return;

        try
        {
            var replays = Directory.GetFiles(replayDir, "*.rec", SearchOption.TopDirectoryOnly);
            ctx.IncrementFiles(replays.Length);

            foreach (var replay in replays)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var info = new FileInfo(replay);
                    if (info.Length < 4096)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "GameReplayManipulation",
                            Title = "VALORANT Replay zu klein (moeglicherweise blockiert)",
                            Risk = RiskLevel.Medium,
                            Location = replay,
                            FileName = Path.GetFileName(replay),
                            Reason = $"Replay-Datei ist nur {info.Length} Bytes — defekte oder blockierte Aufzeichnung.",
                            Detail = $"Path={replay} Size={info.Length}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void ScanDemoBlockingTools(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.GetTempPath()
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(file).ToLowerInvariant();
                    if (Array.IndexOf(DemoBlockerExeNames, fname) >= 0)
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "GameReplayManipulation",
                            Title = "Demo-Blocking-Tool gefunden",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fname,
                            Reason = "Bekanntes Demo-Blocking-Tool gefunden. Verhindert CS2/CSGO-Demo-Aufzeichnung — " +
                                     "verwendet um Demo-Beweise nach Matches zu vernichten.",
                            Detail = $"Path={file}"
                        });
                    }
                }
            }
            catch { }
        }

        // Check running processes
        var procs = ctx.GetProcessSnapshot();
        foreach (var proc in procs)
        {
            ct.ThrowIfCancellationRequested();
            var pname = (proc.ProcessName + ".exe").ToLowerInvariant();
            if (Array.IndexOf(DemoBlockerExeNames, pname) >= 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "GameReplayManipulation",
                    Title = "Demo-Blocking-Tool laeuft aktiv",
                    Risk = RiskLevel.Critical,
                    Location = proc.MainModule?.FileName ?? proc.ProcessName,
                    FileName = proc.ProcessName,
                    Reason = "Aktiver Demo-Blocking-Prozess verhindert Spielbeweisaufzeichnung.",
                    Detail = $"PID={proc.Id} Name={proc.ProcessName}"
                });
            }
        }
    }

    private static void ScanSteamLaunchOptionsForDemoBlock(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // CS2 / CSGO AppID = 730
        const string cs2AppId = "730";
        var launchKeyPath = $@"SOFTWARE\Valve\Steam\Apps\{cs2AppId}";

        using var key = Registry.CurrentUser.OpenSubKey(launchKeyPath);
        if (key == null) return;

        ctx.IncrementRegistryKeys(1);
        var opts = key.GetValue("LaunchOptions") as string ?? string.Empty;

        foreach (var flag in DemoBlockLaunchFlags)
        {
            if (opts.Contains(flag, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "GameReplayManipulation",
                    Title = "CS2 Demo-Aufzeichnung per Launch-Option deaktiviert",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{launchKeyPath}!LaunchOptions",
                    Reason = $"Launch-Option '{flag}' deaktiviert Demo-Aufzeichnung. Cheater setzen diese Flags " +
                             "um nach Matches keine Demo-Beweise zu hinterlassen.",
                    Detail = $"LaunchOptions={opts}"
                });
                break;
            }
        }

        foreach (var kw in CheatKeywords)
        {
            if (opts.Contains(kw, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "GameReplayManipulation",
                    Title = "Cheat-Keyword in CS2 Launch-Optionen",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{launchKeyPath}!LaunchOptions",
                    Reason = $"Cheat-Keyword '{kw}' in CS2 Start-Optionen gefunden.",
                    Detail = $"LaunchOptions={opts}"
                });
                break;
            }
        }
    }

    private static void ScanFaceitClient(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var faceitDir = Path.Combine(localApp, "FACEIT");

        if (!Directory.Exists(faceitDir)) return;

        var demoDir = Path.Combine(faceitDir, "demos");
        if (Directory.Exists(demoDir))
        {
            try
            {
                var demos = Directory.GetFiles(demoDir, "*.dem", SearchOption.TopDirectoryOnly);
                ctx.IncrementFiles(demos.Length);

                foreach (var d in demos)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var info = new FileInfo(d);
                        if (info.Length < 2048)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "GameReplayManipulation",
                                Title = "FACEIT Demo blockiert/beschaedigt",
                                Risk = RiskLevel.High,
                                Location = d,
                                FileName = Path.GetFileName(d),
                                Reason = $"FACEIT Demo ist nur {info.Length} Bytes — blockierte oder korrupte Aufzeichnung.",
                                Detail = $"Path={d} Size={info.Length}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // Suspicious executables inside FACEIT dir
        var bypassFiles = new[] { "bypass.exe", "patch.exe", "loader.exe", "inject.exe" };
        try
        {
            foreach (var f in Directory.GetFiles(faceitDir, "*.exe", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(f).ToLowerInvariant();
                if (Array.IndexOf(bypassFiles, fn) >= 0)
                {
                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = "GameReplayManipulation",
                        Title = "Verdaechtige EXE im FACEIT-Verzeichnis",
                        Risk = RiskLevel.Critical,
                        Location = f,
                        FileName = fn,
                        Reason = $"Verdaechtige Datei '{fn}' im FACEIT-Client-Verzeichnis — potentieller AC-Bypass oder Injector.",
                        Detail = $"Path={f}"
                    });
                }
            }
        }
        catch { }
    }
}
