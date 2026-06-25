using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects cheat-specific "game booster" / process killer tools commonly bundled with
/// or used alongside cheat software.
///
/// Many cheat packages include their own "optimizer" or "booster" that:
///   - Kills anti-cheat background services before loading the cheat
///   - Modifies process priorities to give the cheat process more CPU time
///   - Terminates Windows Defender / security tools temporarily
///   - Runs the user in a stripped-down Windows environment to reduce AC footprint
///
/// Additionally, certain process-management tools are specifically popular in the cheat
/// community for bypassing anti-cheat initialization:
///   - Process Hacker / System Informer (used to inspect/kill AC processes)
///   - MemReduct (memory editor, used with cheats)
///   - RAMMap / VMMap (memory analysis, used alongside memory cheats)
///   - Special K ("SK") — game modifier often abused for cheat injection
///   - ReShade — post-processing that can expose ESP-like shaders
///
/// Ocean and detect.ac flag these tools because legitimate competitive players
/// don't need process killers or AC-termination scripts.
///
/// Detection:
///   - Installed software registry (HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall)
///   - Process image in known locations
///   - Prefetch entries
///   - Known cheat-bundled "optimizer" executable names
/// </summary>
public sealed class GameBoosterCheatToolScanModule : IScanModule
{
    public string Name => "Cheat-Tool / Game-Booster / AC-Killer Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    private static readonly HashSet<string> SuspiciousToolNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        // Process inspection / manipulation (heavily used to kill AC)
        "Process Hacker", "ProcessHacker",
        "System Informer", "SystemInformer",
        "Process Lasso", "ProcessLasso",       // process priority manipulator

        // Memory editors
        "MemReduct", "Mem Reduct",
        "Cheat Engine",                         // direct detection
        "CheatEngine",

        // Special K (DirectX wrapper / game modifier)
        "Special K",

        // ReShade (can enable ESP-style depth buffer access)
        "ReShade",

        // HWID changers / cloners
        "HWID Changer", "HWIDChanger",
        "HWID Spoofer", "HWIDSpoofer",
        "Serial Number Changer",
        "SMBIOS Editor",
        "HWID Generator",

        // VPN/proxy tools commonly used to bypass IP bans
        "Mullvad", "ProtonVPN",                // note: legitimate use exists; lower risk
        "Hide.me",

        // Specific cheat-bundled optimizer names (community-documented)
        "Valorant Optimizer",
        "CS Optimizer",
        "Game Firewall",                        // AC bypass via WFP filter
        "Anti Anti Cheat",
        "BattlEye Bypass",
        "EAC Bypass",
        "VAC Bypass",
        "VACFix",
        "EACFix",
        "BEFix",

        // Crack/keygen utilities often co-distributed with cheats
        "KMS Activator", "KMSAuto",
        "Windows Activator",
    };

    private static readonly string[] SuspiciousExecutableNames =
    {
        "processhacker", "systeminformer", "processlasso",
        "memreduct", "cheatengine",
        "hwidchanger", "hwidspoofer", "smbioseditor",
        "vacbypass", "eacbypass", "battleeyebypass",
        "vacfix", "eacfix", "befix",
        "antilag", "ac_killer", "ackiller",
        "game_optimizer_cheat", "cheat_optimizer",
        "ac_bypasser", "acbypasser",
        "taskmanager_killer", "acservice_killer",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanInstalledSoftwareRegistry(ctx, Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", ct);
        ScanInstalledSoftwareRegistry(ctx, Registry.LocalMachine,
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", ct);
        ScanInstalledSoftwareRegistry(ctx, Registry.CurrentUser,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", ct);

        ScanRunningProcesses(ctx, ct);
        ScanPrefetchArtifacts(ctx, ct);
    }

    private void ScanInstalledSoftwareRegistry(ScanContext ctx, RegistryKey hive,
        string path, CancellationToken ct)
    {
        try
        {
            using var key = hive.OpenSubKey(path, writable: false);
            if (key is null) return;

            foreach (string subName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var sub = key.OpenSubKey(subName, writable: false);
                    if (sub is null) continue;

                    string? displayName = sub.GetValue("DisplayName") as string ?? "";
                    string? publisher   = sub.GetValue("Publisher") as string ?? "";
                    string? installLoc  = sub.GetValue("InstallLocation") as string ?? "";

                    if (string.IsNullOrEmpty(displayName)) continue;

                    foreach (string toolName in SuspiciousToolNames)
                    {
                        if (!displayName.Contains(toolName, StringComparison.OrdinalIgnoreCase))
                            continue;

                        // Adjust risk: some tools (ProcessHacker) have legitimate use;
                        // others (VACBypass, EACFix) are unambiguously cheat tools.
                        bool unambiguous = toolName.Contains("Bypass", StringComparison.OrdinalIgnoreCase)
                            || toolName.Contains("Fix", StringComparison.OrdinalIgnoreCase)
                            || toolName.Contains("Spoofer", StringComparison.OrdinalIgnoreCase)
                            || toolName.Contains("Changer", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtiges Tool installiert: {displayName}",
                            Risk     = unambiguous ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"{hive.Name}\{path}\{subName}",
                            FileName = displayName,
                            Reason   = $"Software '{displayName}' ist installiert und wird häufig " +
                                       "in Cheat-Setups zum Umgehen von Anti-Cheat-Systemen, Manipulieren " +
                                       "von Prozessen oder Ändern von Hardware-IDs verwendet. " +
                                       "Ocean und detect.ac flaggen diese Tool-Kategorie als direktes " +
                                       "Cheat-Indiz.",
                            Detail   = $"Programmname: {displayName} | Hersteller: {publisher} | " +
                                       $"Installationspfad: {installLoc} | Match: '{toolName}'"
                        });
                        break;
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();
        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string name = proc.ProcessName.ToLowerInvariant();
                foreach (string exe in SuspiciousExecutableNames)
                {
                    if (!name.Contains(exe)) continue;
                    ctx.IncrementProcesses();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtiger Prozess läuft: {proc.ProcessName} (PID {proc.Id})",
                        Risk     = RiskLevel.High,
                        Location = $"Prozess: {proc.ProcessName} (PID {proc.Id})",
                        FileName = proc.ProcessName + ".exe",
                        Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) entspricht einem bekannten " +
                                   "Cheat-Tool, AC-Bypass-Utility oder HWID-Manipulations-Tool. " +
                                   "Das aktive Laufen neben einem Spiel ist ein starkes Signal.",
                        Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | Match: '{exe}'"
                    });
                    break;
                }
            }
            catch { }
        }
    }

    private void ScanPrefetchArtifacts(ScanContext ctx, CancellationToken ct)
    {
        string prefetchDir = @"C:\Windows\Prefetch";
        if (!System.IO.Directory.Exists(prefetchDir)) return;
        try
        {
            foreach (string pf in System.IO.Directory.EnumerateFiles(prefetchDir, "*.pf"))
            {
                ct.ThrowIfCancellationRequested();
                string pfName = System.IO.Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();

                foreach (string exe in SuspiciousExecutableNames)
                {
                    if (!pfName.StartsWith(exe)) continue;

                    var info = new System.IO.FileInfo(pf);
                    var lastRun = info.LastWriteTime;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Tool-Ausführung in Prefetch: {System.IO.Path.GetFileName(pf)}",
                        Risk     = RiskLevel.High,
                        Location = pf,
                        FileName = System.IO.Path.GetFileName(pf),
                        Reason   = $"Prefetch-Eintrag '{System.IO.Path.GetFileName(pf)}' belegt die " +
                                   $"Ausführung von '{exe}' (zuletzt: {lastRun:yyyy-MM-dd HH:mm}). " +
                                   "Prefetch-Einträge persistieren 30 Tage und überleben normale " +
                                   "Programmdeinstallation — forensischer Beweis für frühere Nutzung.",
                        Detail   = $"Prefetch-Datei: {pf} | Letzter Lauf: {lastRun:yyyy-MM-dd HH:mm} | Match: '{exe}'"
                    });
                    break;
                }
            }
        }
        catch { }
    }
}
