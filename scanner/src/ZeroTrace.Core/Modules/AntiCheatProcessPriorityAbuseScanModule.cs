using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects manipulation of anti-cheat process CPU priority and core affinity.
///
/// Cheat tools lower the priority of anti-cheat processes (EasyAntiCheat, BattlEye,
/// Vanguard, FACEIT) to IDLE or BELOW_NORMAL using SetPriorityClass — this causes
/// Windows to heavily throttle AC scanning threads, extending the interval between
/// detection checks. Additionally, cheats pin AC processes to a single CPU core
/// (SetProcessAffinityMask) while the game and cheat occupy the remaining cores.
///
/// This is a process-level attack that requires no code injection — any process with
/// PROCESS_SET_INFORMATION access can call SetPriorityClass and SetProcessAffinityMask
/// on another process. The changes are visible in the process object and readable via
/// kernel32 queries.
///
/// Complements TokenPrivilegeScanModule (privilege abuse) and APC injection
/// detection with a non-memory-manipulation evasion technique.
/// </summary>
public sealed class AntiCheatProcessPriorityAbuseScanModule : IScanModule
{
    public string Name => "Anti-Cheat Process Priority/Affinity Manipulation Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetPriorityClass(nint hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessAffinityMask(nint hProcess,
        out nint lpProcessAffinityMask, out nint lpSystemAffinityMask);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint IDLE_PRIORITY_CLASS         = 0x0040;
    private const uint BELOW_NORMAL_PRIORITY_CLASS = 0x4000;

    private static readonly HashSet<string> AntiCheatProcessNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        // EasyAntiCheat
        "easyanticheat", "easyanticheat_eac", "easyanticheat_launcher",
        "eac_launcher",
        // BattlEye
        "beservice", "beservice_x64", "beservice_x86",
        "battleye", "be_service",
        // Vanguard (Riot)
        "vgc", "vgk", "vanguard", "vanguard-tray",
        // FACEIT
        "faceitclient", "faceit", "faceit.anticheat",
        // ESEA
        "esea", "esea_client",
        // XIGNCODE3
        "xhscan", "xcorona", "xcorona_x64",
        // GameGuard
        "nprotect", "gameguard", "npggnt",
        // Valve VAC (runs inside steam.exe so not a standalone process, but include gamescanner)
        "steamservice",
        // Other common AC
        "anticheatsdk", "ac_client", "anticheat_agent",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        int cpuCount = Environment.ProcessorCount;

        Process[] allProcs;
        try { allProcs = Process.GetProcesses(); }
        catch { return; }

        foreach (Process proc in allProcs)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string name      = proc.ProcessName;
                string nameLower = name.ToLowerInvariant();

                bool isAc = AntiCheatProcessNames.Any(ac =>
                    nameLower == ac ||
                    nameLower.StartsWith(ac + "_") ||
                    nameLower.StartsWith(ac + "."));

                if (!isAc) continue;

                ctx.IncrementProcesses();

                nint hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Id);
                if (hProc == nint.Zero) continue;

                try
                {
                    CheckPriority(ctx, hProc, name, proc.Id);
                    CheckAffinity(ctx, hProc, name, proc.Id, cpuCount);
                }
                finally { CloseHandle(hProc); }
            }
            catch { }
            finally { try { proc.Dispose(); } catch { } }
        }
    }

    private static void CheckPriority(ScanContext ctx, nint hProc, string name, int pid)
    {
        uint priority = GetPriorityClass(hProc);
        if (priority == 0) return;

        if (priority == IDLE_PRIORITY_CLASS)
        {
            ctx.AddFinding(new Finding
            {
                Module   = "Anti-Cheat Process Priority/Affinity Manipulation Detection",
                Title    = $"Anti-Cheat-Prozess mit IDLE-Priorität: {name}",
                Risk     = RiskLevel.Critical,
                Location = $"Prozess: {name} (PID {pid})",
                FileName = name + ".exe",
                Reason   = $"Anti-Cheat-Prozess '{name}' (PID {pid}) läuft mit IDLE-Prozesspriorität " +
                           "(0x40). Cheat-Tools rufen SetPriorityClass(IDLE_PRIORITY_CLASS) auf AC-Prozesse " +
                           "auf, um Windows zu zwingen, AC-Scan-Threads stark zu drosseln — dadurch " +
                           "verlängern sich Erkennungsintervalle erheblich. Normale AC-Prozesse laufen " +
                           "immer mit NORMAL- oder HIGH-Priorität.",
                Detail   = $"Prozess: {name} | PID: {pid} | Prioritätsklasse: IDLE (0x{IDLE_PRIORITY_CLASS:X})"
            });
        }
        else if (priority == BELOW_NORMAL_PRIORITY_CLASS)
        {
            ctx.AddFinding(new Finding
            {
                Module   = "Anti-Cheat Process Priority/Affinity Manipulation Detection",
                Title    = $"Anti-Cheat-Prozess mit BELOW_NORMAL-Priorität: {name}",
                Risk     = RiskLevel.High,
                Location = $"Prozess: {name} (PID {pid})",
                FileName = name + ".exe",
                Reason   = $"Anti-Cheat-Prozess '{name}' (PID {pid}) läuft mit unter-normaler " +
                           "Priorität (BELOW_NORMAL_PRIORITY_CLASS=0x4000). SetPriorityClass kann " +
                           "ohne Administrator-Rechte auf fremde Prozesse angewendet werden — " +
                           "Cheat-Loader reduzieren die AC-Priorität systematisch.",
                Detail   = $"Prozess: {name} | PID: {pid} | Prioritätsklasse: BELOW_NORMAL (0x{BELOW_NORMAL_PRIORITY_CLASS:X})"
            });
        }
    }

    private static void CheckAffinity(ScanContext ctx, nint hProc, string name, int pid, int cpuCount)
    {
        if (!GetProcessAffinityMask(hProc, out nint procMask, out nint sysMask)) return;
        if (sysMask == 0 || cpuCount < 4) return; // Only flag on systems with 4+ cores

        int procCores = CountBits(procMask);
        int sysCores  = CountBits(sysMask);

        if (procCores > 1 || sysCores < 4) return;

        ctx.AddFinding(new Finding
        {
            Module   = "Anti-Cheat Process Priority/Affinity Manipulation Detection",
            Title    = $"Anti-Cheat-Prozess auf einzelnen CPU-Kern gepinnt: {name}",
            Risk     = RiskLevel.High,
            Location = $"Prozess: {name} (PID {pid})",
            FileName = name + ".exe",
            Reason   = $"Anti-Cheat-Prozess '{name}' (PID {pid}) ist auf {procCores} CPU-Kern " +
                       $"beschränkt (von {sysCores} verfügbaren Kernen). SetProcessAffinityMask " +
                       "ist eine bekannte Cheat-Technik: AC wird auf Core 0 isoliert, während " +
                       "Cheat-Threads auf allen anderen Kernen ungestört laufen. " +
                       "Kein legitimes Spiel oder AC-Programm setzt diese Einschränkung.",
            Detail   = $"Prozess: {name} | PID: {pid} | " +
                       $"Prozess-Affinität: 0x{procMask:X} ({procCores} Kern(e)) | " +
                       $"System-Affinität: 0x{sysMask:X} ({sysCores} Kern(e))"
        });
    }

    private static int CountBits(nint value)
    {
        ulong v = (ulong)value;
        int count = 0;
        while (v != 0) { count += (int)(v & 1); v >>= 1; }
        return count;
    }
}
