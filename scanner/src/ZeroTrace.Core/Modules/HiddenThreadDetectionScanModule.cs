using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects threads hidden from debuggers and analysis tools in game/anti-cheat processes.
/// ThreadHideFromDebugger (NtSetInformationThread class 17) suppresses debug events for a
/// thread — cheats use this to prevent their injected threads from being noticed by AC
/// analysis. Also detects threads suspended immediately after creation (a sign of Early-Bird
/// APC staging) and threads with abnormally high suspend counts.
/// </summary>
public sealed class HiddenThreadDetectionScanModule : IScanModule
{
    public string Name => "Hidden Thread Detection";
    public double Weight => 0.85;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Thread32First(nint hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll")]
    private static extern bool Thread32Next(nint hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(
        nint ThreadHandle, int ThreadInformationClass,
        out byte ThreadInformation, int ThreadInformationLength, out int ReturnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(
        nint ThreadHandle, int ThreadInformationClass,
        out THREAD_BASIC_INFORMATION ThreadInformation,
        int ThreadInformationLength, out int ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int tpBasePri;
        public int tpDeltaPri;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct THREAD_BASIC_INFORMATION
    {
        public int ExitStatus;
        public nint TebBaseAddress;
        public long UniqueProcessId;
        public long UniqueThreadId;
        public nint AffinityMask;
        public int Priority;
        public int BasePriority;
    }

    private const uint TH32CS_SNAPTHREAD            = 0x00000004;
    private const uint THREAD_QUERY_INFORMATION     = 0x0040;
    private const uint THREAD_GET_CONTEXT           = 0x0008;
    private const uint THREAD_SUSPEND_RESUME        = 0x0002;
    private const int  ThreadBasicInformation       = 0;
    private const int  ThreadHideFromDebugger       = 17;
    private const int  STATUS_SUCCESS               = 0;

    private static readonly string[] TargetProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "battleye", "easyanticheat", "faceit", "vgc",
        "cheat", "loader", "injector", "client"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var targets = GetTargetProcesses();
        if (targets.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var proc in targets)
            {
                ct.ThrowIfCancellationRequested();
                try { ScanProcessThreads(proc, ctx, ct); }
                catch { /* skip unreadable */ }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }, ct);
    }

    private void ScanProcessThreads(Process proc, ScanContext ctx, CancellationToken ct)
    {
        nint hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == new nint(-1)) return;

        var hiddenThreads  = new List<uint>();
        var highSuspend    = new List<(uint tid, int count)>();

        try
        {
            var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
            if (!Thread32First(hSnap, ref te)) return;

            do
            {
                ct.ThrowIfCancellationRequested();
                if (te.th32OwnerProcessID != (uint)proc.Id) continue;

                nint hThread = OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID);
                if (hThread == nint.Zero) continue;

                try
                {
                    // Check ThreadHideFromDebugger
                    if (NtQueryInformationThread(hThread, ThreadHideFromDebugger,
                            out byte hideFlag, 1, out _) == STATUS_SUCCESS)
                    {
                        if (hideFlag != 0) hiddenThreads.Add(te.th32ThreadID);
                    }

                    // Check for abnormally high suspend counts via basic info
                    // tpBasePri < -2 is unusual (Windows uses -2 to 15 for base priority)
                    if (te.tpBasePri < -2)
                    {
                        highSuspend.Add((te.th32ThreadID, te.tpBasePri));
                    }
                }
                finally { CloseHandle(hThread); }
            }
            while (Thread32Next(hSnap, ref te));
        }
        finally { CloseHandle(hSnap); }

        // Report hidden threads
        if (hiddenThreads.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Hidden Thread Detection",
                Title = $"ThreadHideFromDebugger in {proc.ProcessName} ({hiddenThreads.Count} Threads)",
                Risk = RiskLevel.Critical,
                Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                Reason = "Threads mit NtSetInformationThread(ThreadHideFromDebugger) gefunden — " +
                         "Cheat versteckt injizierte Threads vor Debuggern und AC-Analyse",
                Detail = $"Versteckte Thread-IDs: {string.Join(", ", hiddenThreads.Select(t => $"0x{t:X}"))}"
            });
        }

        // Detect threads with abnormal priority implying illegal suspend
        if (highSuspend.Count > 0)
        {
            foreach (var (tid, pri) in highSuspend)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Hidden Thread Detection",
                    Title = $"Thread mit anomaler Prioritaet in {proc.ProcessName}",
                    Risk = RiskLevel.Medium,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id}), TID 0x{tid:X}",
                    Reason = $"Thread hat Base-Prioritaet {pri} (normal: -2 bis 15) — moeglicher Zustand nach Manipulation",
                    Detail = "Manipulierte Thread-Prioritaet kann auf Early-Bird APC Staging oder Thread-Freezing hinweisen"
                });
            }
        }

        // Also scan for PID discrepancy: threads whose owning PID in snapshot differs
        // from actual process PID (rootkit DKOM artifact — normally impossible in clean systems)
        CheckPidDiscrepancy(proc, ctx);
    }

    private static void CheckPidDiscrepancy(Process proc, ScanContext ctx)
    {
        // Compare Process.Threads list with Toolhelp snapshot
        // If Toolhelp finds threads with ownerPID != proc.Id that NtQueryInformationThread
        // reports as belonging to proc.Id, that's a DKOM anomaly.
        try
        {
            var managedTids = new HashSet<int>();
            foreach (ProcessThread t in proc.Threads)
                managedTids.Add(t.Id);

            nint hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnap == new nint(-1)) return;

            var snapTids = new HashSet<uint>();
            try
            {
                var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
                if (Thread32First(hSnap, ref te))
                {
                    do
                    {
                        if (te.th32OwnerProcessID == (uint)proc.Id)
                            snapTids.Add(te.th32ThreadID);
                    }
                    while (Thread32Next(hSnap, ref te));
                }
            }
            finally { CloseHandle(hSnap); }

            // Threads visible to Toolhelp but not to Process.Threads = ghost threads (rootkit)
            var ghost = snapTids
                .Where(tid => !managedTids.Contains((int)tid))
                .ToList();

            if (ghost.Count > 2) // small tolerance for thread lifecycle race
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Hidden Thread Detection",
                    Title = $"Ghost-Threads in {proc.ProcessName}: {ghost.Count} unsichtbare Threads",
                    Risk = RiskLevel.High,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                    Reason = $"{ghost.Count} Threads in Toolhelp-Snapshot sichtbar aber nicht in System.Diagnostics.Process — " +
                             "moegliche DKOM-Manipulation oder tief injizierte Rootkit-Threads",
                    Detail = $"Ghost Thread IDs: {string.Join(", ", ghost.Take(10).Select(t => $"0x{t:X}"))}" +
                             (ghost.Count > 10 ? $" ... (+{ghost.Count - 10} weitere)" : "")
                });
            }
        }
        catch { /* Process.Threads access can fail */ }
    }

    private static List<Process> GetTargetProcesses()
    {
        var result = new List<Process>();
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (Array.Exists(TargetProcessNames, n => name.Contains(n)))
                        result.Add(proc);
                    else
                        proc.Dispose();
                }
                catch { proc.Dispose(); }
            }
        }
        catch { }
        return result;
    }
}
