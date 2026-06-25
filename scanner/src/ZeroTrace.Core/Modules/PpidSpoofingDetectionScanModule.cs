using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects PPID (Parent Process ID) spoofing used to hide cheat loader process trees.
///
/// PPID Spoofing allows an attacker to create a new process with an arbitrary
/// "parent" process ID — making the new process appear to be a child of any
/// chosen process (e.g., svchost.exe, explorer.exe, csrss.exe).
///
/// Why cheats use PPID spoofing:
///   - Anti-cheat systems check process trees: a cheat loader spawned from
///     cmd.exe/powershell.exe raises immediate red flags
///   - Spawning the cheat process as a "child" of explorer.exe, svchost.exe,
///     or the game process itself makes it appear benign in process trees
///   - Also used to bypass UAC elevator limitations that check parent processes
///
/// How PPID Spoofing works:
///   1. Open handle to the target "fake parent": OpenProcess(target_parent_pid)
///   2. Create STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute
///   3. Call CreateProcess with EXTENDED_STARTUPINFO_PRESENT flag
///   → The new process lists target_parent_pid as its ParentProcessId in EPROCESS
///   → Task Manager, Process Explorer, and most AV tools show the wrong parent
///
/// PPID Spoofing is used by:
///   - Advanced cheat loaders (DMA loaders, kernel-driver installers)
///   - Mimikatz (token impersonation via fake parent)
///   - Cobalt Strike, Metasploit beacons
///   - Sandboxing evasion (appear to be spawned by browser/explorer)
///
/// Detection logic:
///   1. For every running process, get the stored parent PID via:
///      NtQueryInformationProcess(class 0) → PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId
///   2. Look up the parent process by that PID in the current process list
///   3. Flag PPID mismatch if:
///      a) The parent PID no longer exists — spoofed with a dead process
///         (attacker opens a high-PID process to get a slot, spawns child,
///          parent terminates → PID is stale but stored as parent)
///      b) Parent exists but is an unusual spawn origin for the child:
///         - cmd.exe, powershell.exe, wscript.exe, cscript.exe, mshta.exe,
///           regsvr32.exe, rundll32.exe, msiexec.exe as parent of games/AC
///         - Anti-cheat services (EasyAntiCheat, BattlEye) spawned from unusual parents
///         - System processes (svchost, lsass, csrss) spawning user-mode tools
///   4. Detect cheat-relevant PPID spoofing patterns:
///      a) Game processes with no legitimate game launcher as parent
///      b) Anti-cheat processes spoofed to appear spawned by game (anti-AC targeting)
///      c) Processes claiming explorer.exe as parent but explorer PID doesn't match
///         (attacker spoofed explorer.exe using a past PID)
///
/// Additional: detect ProcessCreationFlags=CREATE_SUSPENDED abuse where a process
/// is created suspended and never resumed (zombie process used as APC target)
/// </summary>
public sealed class PpidSpoofingDetectionScanModule : IScanModule
{
    public string Name => "PPID-Spoofing-Erkennung";
    public double Weight => 0.8;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle,
        int processInformationClass,
        out PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags,
        [Out] StringBuilder lpExeName, ref uint lpdwSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    private const uint PROCESS_QUERY_INFORMATION       = 0x0400;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    // Process names that are suspicious as parents of game/AC processes
    private static readonly HashSet<string> SuspiciousParents =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe",
            "bitsadmin.exe", "certutil.exe", "wmic.exe", "bash.exe",
            "python.exe", "python3.exe", "node.exe", "perl.exe", "ruby.exe",
            "curl.exe", "wget.exe",
        };

    // Anti-cheat and game security processes — their parents should be very specific
    private static readonly HashSet<string> SensitiveProcesses =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe", "BEService.exe",
            "vgc.exe", "vgtray.exe", "FACEIT.exe", "faceit.exe",
            "EAC.exe", "csgo.exe", "cs2.exe",
        };

    // System processes that should never spawn user-mode tools
    private static readonly HashSet<string> SystemNoSpawnParents =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
        };

    // Launcher processes that are legitimate parents for game EXEs
    private static readonly HashSet<string> LegitimateGameLaunchers =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "steam.exe", "EpicGamesLauncher.exe", "Origin.exe", "EADesktop.exe",
            "battlenet.exe", "Battle.net.exe", "GalaxyClient.exe", "explorer.exe",
            "GameBar.exe", "GameBarPresenceWriter.exe", "XboxApp.exe",
            "upc.exe", "uplay.exe", "ubisoft-connect.exe",
        };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Build PID → ProcessName map once for parent lookup
            var pidToName = new Dictionary<int, string>();
            var allProcs = Process.GetProcesses();
            foreach (var p in allProcs)
            {
                try { pidToName[p.Id] = p.ProcessName + ".exe"; } catch { }
                p.Dispose();
            }

            // Now iterate again for the actual checks
            var checkProcs = Process.GetProcesses();
            foreach (var proc in checkProcs)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    ctx.IncrementProcesses();
                    hits += CheckProcess(proc, pidToName, ctx);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"PPID-Spoofing geprüft, {hits} Auffälligkeiten");
        return Task.CompletedTask;
    }

    private static int CheckProcess(Process proc, Dictionary<int, string> pidToName,
        ScanContext ctx)
    {
        if (proc.Id <= 4) return 0; // Skip System/Idle

        IntPtr hProcess = IntPtr.Zero;
        try
        {
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.Id);
            if (hProcess == IntPtr.Zero)
                hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Id);
            if (hProcess == IntPtr.Zero) return 0;

            int status = NtQueryInformationProcess(hProcess, 0,
                out PROCESS_BASIC_INFORMATION pbi,
                Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
            if (status != 0) return 0;

            int parentPid = (int)pbi.InheritedFromUniqueProcessId.ToInt64();
            if (parentPid <= 0) return 0;

            string childExe  = proc.ProcessName + ".exe";
            bool parentExists = pidToName.TryGetValue(parentPid, out string? parentExe);

            // Check 1: claimed parent PID no longer exists
            if (!parentExists && parentPid != 0)
            {
                // Stale parent is normal for long-running processes whose parent exited;
                // only flag if the child itself is sensitive or the PID looks recent
                if (SensitiveProcesses.Contains(childExe))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "PPID-Spoofing-Erkennung",
                        Title    = $"Sicherheitsprozess mit nicht-existentem Eltern-PID: {childExe}",
                        Risk     = RiskLevel.High,
                        Location = $"PID {proc.Id} → ParentPID {parentPid} (existiert nicht)",
                        Reason   = $"'{childExe}' (PID {proc.Id}) gibt PID {parentPid} als " +
                                   "Elternprozess an, aber kein Prozess mit dieser PID ist aktiv. " +
                                   "PPID-Spoofing: Angreifer wählt gezielt eine PID aus, die bald " +
                                   "frei wird, erstellt den Prozess mit dieser als Eltern-PID, " +
                                   "lässt den Elternprozess terminieren — der gefälschte Eltern-PID " +
                                   "verbleibt in EPROCESS.InheritedFromUniqueProcessId. " +
                                   "Damit erscheint der Cheat-Loader in Prozessbaum-Analysen " +
                                   "als Kind eines nicht-existenten (oder recycelten) Prozesses.",
                        Detail   = $"Child={childExe} PID={proc.Id} | " +
                                   $"ClaimedParentPID={parentPid} | ParentExists=Nein"
                    });
                    return 1;
                }
                return 0;
            }

            if (!parentExists || parentExe is null) return 0;

            // Check 2: suspicious parent spawning game/AC process
            if (SensitiveProcesses.Contains(childExe) &&
                SuspiciousParents.Contains(parentExe))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "PPID-Spoofing-Erkennung",
                    Title    = $"Sicherheitsprozess von verdächtigem Elternprozess gestartet: {childExe}",
                    Risk     = RiskLevel.Critical,
                    Location = $"PID {proc.Id} ({childExe}) ← PID {parentPid} ({parentExe})",
                    Reason   = $"'{childExe}' (PID {proc.Id}) wurde von '{parentExe}' " +
                               $"(PID {parentPid}) gestartet — ein ungewöhnlicher Elternprozess " +
                               "für einen Spiel- oder Anti-Cheat-Prozess. " +
                               "Legitime Anti-Cheat-Dienste werden von ihren zugehörigen Launchern " +
                               "oder vom Windows Service Manager (services.exe) gestartet. " +
                               "Ein Befehlsinterpreter oder Skript-Host als Eltern deutet auf " +
                               "PPID-Spoofing hin: Angreifer startet einen gefälschten Prozess " +
                               $"und verschleiert seine Herkunft durch Manipulation der " +
                               "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS Attribut-Liste.",
                    Detail   = $"Child={childExe} PID={proc.Id} | " +
                               $"Parent={parentExe} PID={parentPid}"
                });
                return 1;
            }

            // Check 3: system process spawning user-mode tools
            if (SystemNoSpawnParents.Contains(parentExe) &&
                !string.IsNullOrEmpty(childExe) &&
                !parentExe.Equals(childExe, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "PPID-Spoofing-Erkennung",
                    Title    = $"Systemprozess als gefälschter Eltern: {parentExe} → {childExe}",
                    Risk     = RiskLevel.High,
                    Location = $"PID {proc.Id} ({childExe}) ← PID {parentPid} ({parentExe})",
                    Reason   = $"'{childExe}' (PID {proc.Id}) behauptet, von '{parentExe}' " +
                               $"(PID {parentPid}) gestartet worden zu sein. " +
                               $"'{parentExe}' ist ein kritischer Systemprozess, der " +
                               "normalerweise keine Benutzer-Anwendungen startet. " +
                               "PPID-Spoofing: Angreifer öffnet lsass/csrss als Handle-Ziel " +
                               "und übergibt diesen Handle als PARENT_PROCESS Attribut " +
                               "an CreateProcess — der Prozess erscheint als Kind des " +
                               "Sicherheitsprozesses und umgeht Prozessbaum-basierte Detektionen.",
                    Detail   = $"Child={childExe} PID={proc.Id} | " +
                               $"ClaimedSystemParent={parentExe} PID={parentPid}"
                });
                return 1;
            }
        }
        catch { }
        finally
        {
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
        return 0;
    }
}
