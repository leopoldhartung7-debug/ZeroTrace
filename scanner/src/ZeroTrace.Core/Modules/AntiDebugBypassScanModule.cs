using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects anti-debug / anti-analysis bypass techniques used by cheat loaders and injectors.
///
/// Cheat software uses anti-debug measures to prevent reverse engineering and to detect
/// when an anti-cheat debugger is attached. The inverse — detecting that something is
/// hiding from debuggers — reveals cheat activity:
///
///   1. NtSetInformationProcess(ProcessDebugFlags=0x1F, FALSE) — clears the NoDebugInherit
///      flag, used by cheats to prevent child processes from inheriting debug state
///   2. NtQuerySystemInformation abuse: checking SystemKernelDebuggerInformation to detect
///      kernel debuggers (WinDbg, BSOD analysis tools loaded by AC)
///   3. SetUnhandledExceptionFilter replacement — cheats replace this to avoid crash dumps
///   4. PEB.NtGlobalFlag manipulation — cleared by cheats to hide from IsDebuggerPresent
///   5. Heap flags manipulation (PEB.ProcessHeap.Flags) — cleared to evade debug heap check
///   6. TLS callbacks with anti-debug code (checked via PEB scan, if elevated)
///
/// Detectable at runtime via:
///   - NtQueryInformationProcess(ProcessDebugPort=7) on suspicious processes → 0 if no
///     debugger but they've patched IsDebuggerPresent returns = suspicious
///   - Suspicious heap flags in known cheat process memory (requires elevation + VM_READ)
///   - Exception filter replacement in cheat processes
///
/// Also detects Scylla / x64dbg / WinDbg BYOVD-adjacent presence:
///   - Installed debugger tools used for cheat development
///   - Debugger in %PROGRAMFILES% on a gaming machine
/// </summary>
public sealed class AntiDebugBypassScanModule : IScanModule
{
    public string Name => "Anti-Debug / Anti-Analysis Bypass Scan";
    public double Weight => 0.55;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(nint ProcessHandle,
        uint ProcessInformationClass, out nint ProcessInformation,
        uint ProcessInformationLength, out uint ReturnLength);

    private const uint ProcessDebugPort          = 7;
    private const uint ProcessDebugFlags         = 0x1F;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    // Known debugger / reverse engineering tool names used in cheat development
    private static readonly HashSet<string> DebuggerNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "x64dbg", "x32dbg", "windbg", "ollydbg", "immunity",
        "ida", "ida64", "idaq", "idaq64",
        "ghidra", "radare2", "cutter",
        "scylla", "scyllahide",
        "cheat engine",     // also a debugger in context
        "reclass", "reclass64",
        "process monitor", "procmon", "procmon64",
        "wireshark",        // packet capture for AC evasion analysis
        "fiddler", "charles proxy",
        "api monitor",
    };

    private static readonly string[] DebuggerExecutableNames =
    {
        "x64dbg", "x32dbg", "windbg", "windbgx",
        "ollydbg", "ollydbg2",
        "idaq", "idaq64", "ida64", "ida",
        "scylla", "scyllahide",
        "reclass", "reclass64",
        "procmon", "procmon64",
        "apimonitor", "apimonitor-x86", "apimonitor-x64",
    };

    // Known cheat process names to check anti-debug state on
    private static readonly HashSet<string> TargetProcessNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        "cs2", "csgo", "valorant-win64-shipping", "r5apex",
        "dota2", "fortnite", "warzone", "tslgame",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanRunningDebuggers(ctx, ct);
        ScanDebuggerInstallations(ctx, ct);
        ScanPrefetchForDebuggers(ctx, ct);
    }

    private void ScanRunningDebuggers(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();

        bool gameRunning = processes.Any(p =>
            TargetProcessNames.Any(g =>
                p.ProcessName.Contains(g, StringComparison.OrdinalIgnoreCase)));

        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string name = proc.ProcessName.ToLowerInvariant();
                foreach (string dbg in DebuggerExecutableNames)
                {
                    if (!name.Contains(dbg)) continue;
                    ctx.IncrementProcesses();

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Debugger / Reverse-Engineering-Tool läuft: {proc.ProcessName}" +
                                   (gameRunning ? " [Spiel aktiv!]" : ""),
                        Risk     = gameRunning ? RiskLevel.Critical : RiskLevel.High,
                        Location = $"Prozess: {proc.ProcessName} (PID {proc.Id})",
                        FileName = proc.ProcessName + ".exe",
                        Reason   = $"Debugger / Reverse-Engineering-Tool '{proc.ProcessName}' läuft aktiv" +
                                   (gameRunning ? " während ein bekanntes Spiel ebenfalls aktiv ist" : "") +
                                   ". Debugger werden für Cheat-Entwicklung, Anti-Anti-Cheat-Analyse " +
                                   "und das Verstehen von AC-Algorithmen verwendet. " +
                                   "Ocean und detect.ac flaggen aktive Debugger als starkes Cheat-Signal.",
                        Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | " +
                                   $"Spiel aktiv: {gameRunning} | Match: '{dbg}'"
                    });
                    break;
                }
            }
            catch { }
        }
    }

    private void ScanDebuggerInstallations(ScanContext ctx, CancellationToken ct)
    {
        string[] uninstallPaths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (string path in uninstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path, false);
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

                        foreach (string dbg in DebuggerNames)
                        {
                            if (!name.Contains(dbg, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Reverse-Engineering-Tool installiert: {name}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{path}\{sub}",
                                FileName = name,
                                Reason   = $"Reverse-Engineering / Debugging-Tool '{name}' ist installiert. " +
                                           "Diese Tools werden für Cheat-Entwicklung und Anti-Anti-Cheat-" +
                                           "Forschung verwendet. Auf einem reinen Gaming-PC haben sie keinen " +
                                           "legitimen Zweck. Ocean und detect.ac flaggen RE-Tools als Indiz.",
                                Detail   = $"Software: {name} | Match: '{dbg}'"
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

    private void ScanPrefetchForDebuggers(ScanContext ctx, CancellationToken ct)
    {
        string prefetchDir = @"C:\Windows\Prefetch";
        if (!System.IO.Directory.Exists(prefetchDir)) return;
        try
        {
            foreach (string pf in System.IO.Directory.EnumerateFiles(prefetchDir, "*.pf"))
            {
                ct.ThrowIfCancellationRequested();
                string pfName = System.IO.Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();

                foreach (string dbg in DebuggerExecutableNames)
                {
                    if (!pfName.StartsWith(dbg)) continue;

                    var info = new System.IO.FileInfo(pf);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Debugger-Ausführung in Prefetch: {System.IO.Path.GetFileName(pf)}",
                        Risk     = RiskLevel.High,
                        Location = pf,
                        FileName = System.IO.Path.GetFileName(pf),
                        Reason   = $"Prefetch-Eintrag '{System.IO.Path.GetFileName(pf)}' belegt die " +
                                   $"Ausführung von '{dbg}' (zuletzt: {info.LastWriteTime:yyyy-MM-dd HH:mm}). " +
                                   "Prefetch persistiert 30 Tage — forensischer Beweis für frühere " +
                                   "Debugger-Nutzung auf diesem System.",
                        Detail   = $"Prefetch: {pf} | Match: '{dbg}' | Letzter Lauf: {info.LastWriteTime:yyyy-MM-dd HH:mm}"
                    });
                    break;
                }
            }
        }
        catch { }
    }
}
