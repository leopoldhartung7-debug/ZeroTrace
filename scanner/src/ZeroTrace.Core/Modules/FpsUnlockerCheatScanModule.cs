using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects FPS unlocker tools and game-speed manipulation software.
///
/// FPS unlockers and speed hacks are cheating tools that:
///   - Unlock frame rates beyond game limits (giving timing advantages in tick-rate games)
///   - Modify game clock/timer speed to create "speed hack" effects
///   - Inject into game timer APIs (timeBeginPeriod, QueryPerformanceCounter)
///   - Some also serve as injection vectors for additional cheat modules
///
/// Well-known tools in this category:
///   - Roblox FPS Unlocker (rbxfpsunlocker) — hooks Roblox's frame limiter
///   - Cheat Engine speed hack — multiplies timer frequency
///   - Universal FPS Unlocker tools
///   - BlurBusters UFO test combined with frame time manipulation
///
/// Additionally scans for game integrity bypass tools:
///   - Roblox exploit executors (Synapse X, KRNL, Script-Ware, Fluxus, JJSploit)
///     These inject custom Lua/Luau VMs into Roblox to run game scripts
///   - CSGO/CS2 server-side cheat tools
///
/// Ocean and detect.ac include FPS unlockers and exploit executors because:
///   - Roblox exploit executors are documented AC targets
///   - FPS unlockers often use the same injection technique as game cheats
///
/// Detection:
///   - Installed software registry
///   - Prefetch entries
///   - Known file paths (executors extract to AppData)
///   - Running processes
/// </summary>
public sealed class FpsUnlockerCheatScanModule : IScanModule
{
    public string Name => "FPS Unlocker / Game Exploit Executor Scan (Roblox, Speed Hack)";
    public double Weight => 0.45;
    public int ParallelGroup => 3;

    private static readonly string[] FpsUnlockerKeywords =
    {
        // FPS unlocker names
        "rbxfpsunlocker", "roblox fps unlocker", "fps unlocker",
        "fpsunlocker", "fpsunlock",
        "reshade fps", "fpscap",
        // Speed hackers
        "speed hack", "speedhack", "gamespeedhack",
        "cheat engine speed", "ce speed",
        // Roblox exploit executors
        "synapse x", "synapsex",
        "krnl", "krnl.exe",
        "scriptware", "script-ware",
        "fluxus",
        "jjsploit",
        "oxygen u", "oxygenu",
        "protosmasher",
        "sirhurt",
        "electron", "electronhub",     // Roblox exploit hub
        "visenya",
        "calamari",
        // Generic executor keywords
        "lua executor", "luau executor",
        "roblox executor", "roblox exploit",
        "roblox hack", "roblox cheat",
        // CS2/CSGO server
        "csgo server hack", "cs2 server hack",
        // Misc game specific
        "among us hack", "among us cheat",
        "minecraft hacked client",
    };

    private static readonly string[] SuspiciousExecutables =
    {
        "rbxfpsunlocker", "fpsunlocker",
        "synapsex", "synapse",
        "krnl",
        "jjsploit",
        "fluxus",
        "scriptware",
        "oxygenu",
    };

    private static readonly string[] SuspiciousAppdataPaths =
    {
        // Synapse X
        "synapse x", "sxlib",
        // KRNL
        "krnl",
        // JJSploit
        "jjsploit",
        // Fluxus
        "fluxus",
        // Generic executor directories
        "exploits", "executors",
        "roblox\\exploit", "roblox exploit",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanInstalledSoftware(ctx, ct);
        ScanRunningProcesses(ctx, ct);
        ScanPrefetch(ctx, ct);
        ScanAppdataDirectories(ctx, ct);
    }

    private void ScanInstalledSoftware(ScanContext ctx, CancellationToken ct)
    {
        string[] paths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (string path in paths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path, false)
                             ?? Registry.CurrentUser.OpenSubKey(path, false);
                if (key is null) continue;

                foreach (string sub in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var subKey = key.OpenSubKey(sub, false);
                        string? name = subKey?.GetValue("DisplayName") as string ?? "";
                        if (string.IsNullOrEmpty(name)) continue;

                        string lower = name.ToLowerInvariant();
                        foreach (string kw in FpsUnlockerKeywords)
                        {
                            if (!lower.Contains(kw.ToLowerInvariant())) continue;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"FPS Unlocker / Exploit Executor installiert: {name}",
                                Risk     = IsHighRisk(kw) ? RiskLevel.Critical : RiskLevel.High,
                                Location = $@"Registry: {path}\{sub}",
                                FileName = name,
                                Reason   = $"Software '{name}' enthält Match '{kw}' — {DescribeTool(kw)}. " +
                                           "Ocean und detect.ac flaggen diese Tool-Kategorie als direktes " +
                                           "Cheat-Indiz.",
                                Detail   = $"Software: {name} | Match: '{kw}'"
                            });
                            break;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();
        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            string name = proc.ProcessName.ToLowerInvariant();
            foreach (string exe in SuspiciousExecutables)
            {
                if (!name.Contains(exe)) continue;
                ctx.IncrementProcesses();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Exploit Executor / FPS Unlocker läuft: {proc.ProcessName} (PID {proc.Id})",
                    Risk     = RiskLevel.Critical,
                    Location = $"Prozess: {proc.ProcessName} (PID {proc.Id})",
                    FileName = proc.ProcessName + ".exe",
                    Reason   = $"Exploit Executor / FPS Unlocker '{proc.ProcessName}' läuft aktiv. " +
                               "Dies ist ein direktes Cheat-Indiz.",
                    Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | Match: '{exe}'"
                });
                break;
            }
        }
    }

    private void ScanPrefetch(ScanContext ctx, CancellationToken ct)
    {
        string prefetchDir = @"C:\Windows\Prefetch";
        if (!System.IO.Directory.Exists(prefetchDir)) return;
        try
        {
            foreach (string pf in System.IO.Directory.EnumerateFiles(prefetchDir, "*.pf"))
            {
                ct.ThrowIfCancellationRequested();
                string pfName = System.IO.Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();
                foreach (string exe in SuspiciousExecutables)
                {
                    if (!pfName.StartsWith(exe)) continue;
                    var info = new System.IO.FileInfo(pf);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Exploit Executor in Prefetch: {System.IO.Path.GetFileName(pf)}",
                        Risk     = RiskLevel.High,
                        Location = pf,
                        FileName = System.IO.Path.GetFileName(pf),
                        Reason   = $"Prefetch-Eintrag für '{exe}' (zuletzt: {info.LastWriteTime:yyyy-MM-dd HH:mm}). " +
                                   "Prefetch belegt die frühere Ausführung auch nach Deinstallation.",
                        Detail   = $"Prefetch: {pf} | Match: '{exe}' | Letzter Lauf: {info.LastWriteTime:yyyy-MM-dd HH:mm}"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private void ScanAppdataDirectories(ScanContext ctx, CancellationToken ct)
    {
        string appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string local   = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (string root in new[] { appdata, local })
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(root)) continue;

            try
            {
                foreach (string dir in System.IO.Directory.EnumerateDirectories(root))
                {
                    ct.ThrowIfCancellationRequested();
                    string dirName = System.IO.Path.GetFileName(dir).ToLowerInvariant();
                    foreach (string pat in SuspiciousAppdataPaths)
                    {
                        if (!dirName.Contains(pat.ToLowerInvariant())) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Exploit Executor Verzeichnis in AppData: {System.IO.Path.GetFileName(dir)}",
                            Risk     = RiskLevel.Critical,
                            Location = dir,
                            FileName = System.IO.Path.GetFileName(dir),
                            Reason   = $"Verzeichnis '{System.IO.Path.GetFileName(dir)}' in AppData entspricht " +
                                       $"einem bekannten Exploit-Executor-Pfad (Match: '{pat}'). " +
                                       "Roblox-Exploit-Executors und FPS Unlocker entpacken ihre " +
                                       "Komponenten typischerweise in AppData.",
                            Detail   = $"Pfad: {dir} | Match: '{pat}'"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }

    private static bool IsHighRisk(string kw) =>
        kw.Contains("synapse") || kw.Contains("krnl") || kw.Contains("executor") ||
        kw.Contains("exploit") || kw.Contains("jjsploit") || kw.Contains("scriptware") ||
        kw.Contains("fluxus");

    private static string DescribeTool(string kw)
    {
        if (kw.Contains("synapse")) return "Synapse X ist der bekannteste Roblox-Exploit-Executor";
        if (kw.Contains("krnl")) return "KRNL ist ein kostenloser Roblox-Exploit-Executor";
        if (kw.Contains("jjsploit")) return "JJSploit ist ein Roblox-Exploit-Executor";
        if (kw.Contains("fluxus")) return "Fluxus ist ein Roblox-Exploit-Executor";
        if (kw.Contains("fps unlocker") || kw.Contains("rbxfps")) return "FPS Unlocker für kompetitive Spiele";
        if (kw.Contains("speed hack")) return "Speed-Hack manipuliert Spieluhr/-timer";
        return "ein bekanntes Cheat- oder Exploit-Tool";
    }
}
