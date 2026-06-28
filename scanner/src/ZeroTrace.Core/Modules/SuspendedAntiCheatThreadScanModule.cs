using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects anti-cheat process threads that have been suspended by an external process.
///
/// A well-known bypass technique: a cheat loader enumerates all threads of the running
/// anti-cheat service (EasyAntiCheat, BattlEye, Vanguard, FACEIT) and calls
/// SuspendThread() on each one. The AC process remains in memory (not terminated),
/// so the game server still sees its heartbeat/network presence — but every scanning
/// routine inside the AC process is frozen. When the AC is about to perform a check
/// the cheat resumes the threads briefly, then suspends again.
///
/// NtQuerySystemInformation(SystemProcessInformation=5) returns per-thread
/// SYSTEM_THREAD_INFORMATION structs including the ThreadState and WaitReason fields.
/// A thread in Waiting state with WaitReason = Suspended (5) was externally suspended.
/// If ALL threads of a known AC process are suspended while a game is active, this is
/// a strong indicator of the freeze-bypass technique.
///
/// Requires no elevation — the system call returns state for all threads.
/// Distinct from HardwareBreakpointScanModule (DR0–DR3 in game threads) and
/// ApcInjectionScanModule (APC-queued shellcode in game threads).
/// </summary>
public sealed class SuspendedAntiCheatThreadScanModule : IScanModule
{
    public string Name => "Suspended Anti-Cheat Thread Detection (Freeze Bypass)";
    public double Weight => 0.75;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(uint SystemInformationClass,
        nint SystemInformation, uint SystemInformationLength, out uint ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_PROCESS_INFORMATION
    {
        public uint   NextEntryOffset;
        public uint   NumberOfThreads;
        public long   WorkingSetPrivateSize;
        public uint   HardFaultCount;
        public uint   NumberOfThreadsHighWatermark;
        public ulong  CycleTime;
        public long   CreateTime;
        public long   UserTime;
        public long   KernelTime;
        public ushort ImageNameLength;
        public ushort ImageNameMaximumLength;
        public nint   ImageNameBuffer;
        public int    BasePriority;
        public nint   UniqueProcessId;
        public nint   InheritedFromUniqueProcessId;
        public uint   HandleCount;
        public uint   SessionId;
        public nint   UniqueProcessKey;
        public nint   PeakVirtualSize;
        public nint   VirtualSize;
        public uint   PageFaultCount;
        public nint   PeakWorkingSetSize;
        public nint   WorkingSetSize;
        public nint   QuotaPeakPagedPoolUsage;
        public nint   QuotaPagedPoolUsage;
        public nint   QuotaPeakNonPagedPoolUsage;
        public nint   QuotaNonPagedPoolUsage;
        public nint   PagefileUsage;
        public nint   PeakPagefileUsage;
        public nint   PrivatePageCount;
        public long   ReadOperationCount;
        public long   WriteOperationCount;
        public long   OtherOperationCount;
        public long   ReadTransferCount;
        public long   WriteTransferCount;
        public long   OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_THREAD_INFORMATION
    {
        public long  KernelTime;
        public long  UserTime;
        public long  CreateTime;
        public uint  WaitTime;
        public nint  StartAddress;
        public nint  UniqueProcessId;
        public nint  UniqueThreadId;
        public int   Priority;
        public int   BasePriority;
        public uint  ContextSwitches;
        public uint  ThreadState;
        public uint  WaitReason;
    }

    private const uint SystemProcessInformation = 5;
    private const uint ThreadStateWaiting = 5;  // KTHREAD_STATE::Waiting
    private const uint WaitReasonSuspended = 5; // KWAIT_REASON::Suspended

    private static readonly HashSet<string> AntiCheatProcessNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        "easyanticheat", "easyanticheat_eac", "easyanticheat_launcher", "eac_launcher",
        "beservice", "beservice_x64", "beservice_x86", "battleye", "be_service",
        "vgc", "vgk", "vanguard", "vanguard-tray",
        "faceitclient", "faceit",
        "esea", "esea_client",
        "xhscan", "xcorona", "xcorona_x64",
        "nprotect", "gameguard", "npggnt",
        "anticheatsdk", "anticheat_agent",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        uint bufSize = 1024 * 512;
        nint buf = Marshal.AllocHGlobal((int)bufSize);

        try
        {
            int status = NtQuerySystemInformation(SystemProcessInformation, buf, bufSize, out uint needed);

            // STATUS_INFO_LENGTH_MISMATCH — retry with correct size
            if (status == unchecked((int)0xC0000004u) && needed > 0)
            {
                Marshal.FreeHGlobal(buf);
                bufSize = needed + 4096;
                buf = Marshal.AllocHGlobal((int)bufSize);
                status = NtQuerySystemInformation(SystemProcessInformation, buf, bufSize, out _);
            }

            if (status != 0) return;

            int procInfoSize = Marshal.SizeOf<SYSTEM_PROCESS_INFORMATION>();
            int threadSize   = Marshal.SizeOf<SYSTEM_THREAD_INFORMATION>();

            nint cur = buf;

            while (true)
            {
                ct.ThrowIfCancellationRequested();

                var proc = Marshal.PtrToStructure<SYSTEM_PROCESS_INFORMATION>(cur);

                string? imageName = null;
                if (proc.ImageNameBuffer != nint.Zero && proc.ImageNameLength > 0)
                {
                    try
                    {
                        imageName = Marshal.PtrToStringUni(proc.ImageNameBuffer,
                            proc.ImageNameLength / 2);
                    }
                    catch { }
                }

                if (imageName is not null)
                {
                    string nameNoExt = System.IO.Path.GetFileNameWithoutExtension(imageName);
                    bool isAc = AntiCheatProcessNames.Any(ac =>
                        string.Equals(nameNoExt, ac, StringComparison.OrdinalIgnoreCase));

                    if (isAc && proc.NumberOfThreads > 0)
                    {
                        ctx.IncrementProcesses();
                        AnalyzeAcThreads(ctx, cur + procInfoSize,
                            (int)proc.NumberOfThreads, threadSize, imageName,
                            (int)proc.UniqueProcessId);
                    }
                }

                if (proc.NextEntryOffset == 0) break;
                cur += (int)proc.NextEntryOffset;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static void AnalyzeAcThreads(ScanContext ctx, nint threadBase,
        int count, int threadSize, string imageName, int pid)
    {
        int suspended = 0;
        int total     = 0;

        for (int i = 0; i < count; i++)
        {
            try
            {
                var t = Marshal.PtrToStructure<SYSTEM_THREAD_INFORMATION>(threadBase + i * threadSize);
                total++;
                if (t.ThreadState == ThreadStateWaiting && t.WaitReason == WaitReasonSuspended)
                    suspended++;
            }
            catch { }
        }

        if (total == 0) return;

        double ratio = (double)suspended / total;

        // All threads suspended = critical; majority suspended = high
        if (suspended == total)
        {
            ctx.AddFinding(new Finding
            {
                Module   = "Suspended Anti-Cheat Thread Detection (Freeze Bypass)",
                Title    = $"Alle Threads des Anti-Cheat-Prozesses suspendiert: {imageName}",
                Risk     = RiskLevel.Critical,
                Location = $"Prozess: {imageName} (PID {pid})",
                FileName = imageName,
                Reason   = $"ALLE {total} Threads des Anti-Cheat-Prozesses '{imageName}' (PID {pid}) " +
                           "sind im Zustand SUSPENDED. Dies ist das klassische 'Thread-Freeze-Bypass'-Muster: " +
                           "ein Cheat-Loader ruft SuspendThread() auf jeden AC-Thread auf, um alle " +
                           "Erkennungsroutinen einzufrieren. Der AC-Prozess bleibt alive (Server sieht " +
                           "Heartbeat), aber keine Scan-Funktion kann ausgeführt werden.",
                Detail   = $"Prozess: {imageName} | PID: {pid} | " +
                           $"Suspendierte Threads: {suspended}/{total} (100%) | " +
                           "Technik: SuspendThread() auf alle AC-Threads von externem Prozess"
            });
        }
        else if (suspended >= 2 && ratio >= 0.5)
        {
            ctx.AddFinding(new Finding
            {
                Module   = "Suspended Anti-Cheat Thread Detection (Freeze Bypass)",
                Title    = $"Mehrheit der Anti-Cheat-Threads suspendiert: {imageName}",
                Risk     = RiskLevel.High,
                Location = $"Prozess: {imageName} (PID {pid})",
                FileName = imageName,
                Reason   = $"{suspended} von {total} Threads des Anti-Cheat-Prozesses '{imageName}' " +
                           $"(PID {pid}) sind suspendiert ({ratio * 100:F0}%). Cheat-Tools suspendieren " +
                           "selektiv Worker-Threads und Scanner-Threads des ACs, lassen aber den " +
                           "Heartbeat-Thread laufen. Partiell suspendierte AC-Prozesse sind " +
                           "kein normaler Betriebszustand.",
                Detail   = $"Prozess: {imageName} | PID: {pid} | " +
                           $"Suspendierte Threads: {suspended}/{total} ({ratio * 100:F0}%)"
            });
        }
    }
}
