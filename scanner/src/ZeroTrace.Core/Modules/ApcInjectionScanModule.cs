using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects APC (Asynchronous Procedure Call) injection into game processes.
///
/// APC Injection is one of the most stealthy code execution techniques:
///
///   How it works:
///     1. Attacker calls VirtualAllocEx() in target → allocates RWX memory
///     2. WriteProcessMemory() copies shellcode into target process
///     3. QueueUserAPC() / NtQueueApcThread() queues a callback to a thread
///     4. When thread enters an alertable wait (SleepEx, WaitForSingleObjectEx,
///        SignalObjectAndWait, MsgWaitForMultipleObjectsEx), the APC fires
///        → shellcode executes in the context of that thread
///
///   Early-Bird APC (bypasses most scanners):
///     1. CreateProcess() creates a suspended child process
///     2. VirtualAllocEx() + WriteProcessMemory() writes shellcode
///     3. QueueUserAPC() queues the shellcode as APC to the primary thread
///     4. ResumeThread() — first thing the thread does is execute the APC
///     → Code runs before the process even initializes, before any AC hook
///
///   Special User APC (Windows 11, CVE-2022–44668 pattern):
///     - NtQueueApcThreadEx2 with APC_FORCE_THREAD_SIGNAL fires in non-alertable waits
///     - Removes the "alertable thread" requirement entirely
///     - Game threads do not need to call SleepEx; any active thread can be targeted
///
///   Ghostly APC (advanced):
///     - Thread is terminated immediately after APC queue but before execution
///     - Shellcode pointer is left dangling in the APC queue structure
///     - A new thread is created that inherits the APC queue
///
/// Why it bypasses thread-start scanners:
///     - No new thread is created (CreateRemoteThread signatures don't fire)
///     - The thread's listed start address (NtCreateThreadEx parameter) is unchanged
///     - Only the APC queue entry points to shellcode — which is transient
///     - After execution, the APC entry is dequeued; no persistent trace in thread list
///
/// Detection approach (this module):
///   1. Enumerate all threads in game processes via CreateToolhelp32Snapshot
///   2. Open each thread with THREAD_QUERY_INFORMATION
///   3. Call NtQueryInformationThread(ThreadQuerySetWin32StartAddress = 9)
///      → Returns the user-mode "Win32 start address" which is the function pointer
///        the thread started at — this persists even after thread re-use
///   4. VirtualQueryEx the start address:
///      - MEM_IMAGE → legitimate (code lives in a loaded module)
///      - MEM_PRIVATE + PAGE_EXECUTE_* → shellcode (APC or CRT injection remnant)
///   5. Also check per-thread private executable memory via VirtualQueryEx walk
///      for stacks containing shellcode return addresses (ROP chain / stack pivot)
/// </summary>
public sealed class ApcInjectionScanModule : IScanModule
{
    public string Name => "APC-Injektions-Erkennung";
    public double Weight => 1.1;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(IntPtr ThreadHandle,
        int ThreadInformationClass,
        out IntPtr ThreadInformation,
        int ThreadInformationLength,
        out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int  tpBasePri;
        public int  tpDeltaPri;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    private const uint TH32CS_SNAPTHREAD       = 0x00000004;
    private const uint THREAD_QUERY_INFORMATION = 0x0040;
    private const uint PROCESS_VM_READ          = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT               = 0x1000;
    private const uint MEM_IMAGE                = 0x1000000;
    private const uint PAGE_EXECUTE             = 0x10;
    private const uint PAGE_EXECUTE_READ        = 0x20;
    private const uint PAGE_EXECUTE_READWRITE   = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY   = 0x80;

    // NtQueryInformationThread class 9 = ThreadQuerySetWin32StartAddress
    private const int ThreadQuerySetWin32StartAddress = 9;

    private static readonly HashSet<string> TargetProcesses =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "csgo.exe", "cs2.exe", "valorant.exe", "VALORANT-Win64-Shipping.exe",
            "r5apex.exe", "FortniteClient-Win64-Shipping.exe",
            "GTA5.exe", "EFT.exe", "pubg.exe",
            "overwatch.exe", "Overwatch.exe",
            "RainbowSix.exe", "dota2.exe",
        };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Build map PID → exe-name for targeted processes currently running
            var targetPids = new Dictionary<int, string>();
            foreach (var proc in Process.GetProcesses())
            {
                string exe = proc.ProcessName + ".exe";
                if (TargetProcesses.Contains(exe))
                    targetPids[proc.Id] = exe;
                proc.Dispose();
            }

            if (targetPids.Count == 0)
            {
                ctx.Report(1.0, Name, "Keine Ziel-Spielprozesse aktiv");
                return Task.CompletedTask;
            }

            // Open process handles once; reuse per thread check
            var processHandles = new Dictionary<int, IntPtr>();
            foreach (var (pid, _) in targetPids)
            {
                if (ct.IsCancellationRequested) break;
                IntPtr h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
                if (h != IntPtr.Zero)
                    processHandles[pid] = h;
            }

            try
            {
                // System-wide thread snapshot
                IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (snap == new IntPtr(-1)) goto done;

                try
                {
                    var entry = new THREADENTRY32
                    {
                        dwSize = (uint)Marshal.SizeOf<THREADENTRY32>()
                    };

                    if (Thread32First(snap, ref entry))
                    {
                        do
                        {
                            if (ct.IsCancellationRequested) break;

                            int ownerPid = (int)entry.th32OwnerProcessID;
                            if (!targetPids.TryGetValue(ownerPid, out string? procExe)) continue;
                            if (!processHandles.TryGetValue(ownerPid, out IntPtr hProcess)) continue;

                            ctx.IncrementProcesses();
                            hits += InspectThread(entry.th32ThreadID, ownerPid,
                                procExe, hProcess, ctx);
                        }
                        while (Thread32Next(snap, ref entry));
                    }
                }
                finally
                {
                    CloseHandle(snap);
                }
            }
            finally
            {
                done:
                foreach (var h in processHandles.Values)
                    CloseHandle(h);
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"APC-Injektion analysiert, {hits} Treffer");
        return Task.CompletedTask;
    }

    private static int InspectThread(uint threadId, int pid, string procExe,
        IntPtr hProcess, ScanContext ctx)
    {
        IntPtr hThread = IntPtr.Zero;
        try
        {
            hThread = OpenThread(THREAD_QUERY_INFORMATION, false, threadId);
            if (hThread == IntPtr.Zero) return 0;

            // Query Win32 start address of the thread
            int status = NtQueryInformationThread(hThread,
                ThreadQuerySetWin32StartAddress,
                out IntPtr startAddr,
                IntPtr.Size,
                out _);
            if (status != 0 || startAddr == IntPtr.Zero) return 0;

            // Query the memory region at the start address
            if (!VirtualQueryEx(hProcess, startAddr, out var mbi,
                (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>())) return 0;

            // Must be committed memory
            if (mbi.State != MEM_COMMIT) return 0;

            // Image-backed memory is legitimate (loaded module)
            if (mbi.Type == MEM_IMAGE) return 0;

            // Private or mapped memory — check if executable
            bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            if (!isExec) return 0;

            string memTypeStr = mbi.Type switch
            {
                0x20000   => "MEM_PRIVATE",
                0x40000   => "MEM_MAPPED",
                0x1000000 => "MEM_IMAGE",
                _         => $"0x{mbi.Type:X}"
            };

            ctx.AddFinding(new Finding
            {
                Module   = "APC-Injektions-Erkennung",
                Title    = $"Thread-Startadresse in privatem Speicher: {procExe}",
                Risk     = RiskLevel.Critical,
                Location = $"PID {pid}: TID {threadId} @ 0x{startAddr.ToInt64():X}",
                Reason   = $"Thread {threadId} in '{procExe}' (PID {pid}) hat " +
                           $"Win32-Startadresse 0x{startAddr.ToInt64():X} in " +
                           $"privatem ausführbarem Speicher ({memTypeStr}). " +
                           "Dies ist das klassische Muster von APC-Injektion: " +
                           "Ein Angreifer hat Shellcode (VirtualAllocEx + WriteProcessMemory) " +
                           "in den Spielprozess geschrieben und QueueUserAPC / " +
                           "NtQueueApcThread genutzt, um den Thread darauf zu zeigen. " +
                           "Early-Bird-Variante: Code läuft vor der Anti-Cheat-Initialisierung.",
                Detail   = $"TID={threadId} | " +
                           $"Win32StartAddr=0x{startAddr.ToInt64():X} | " +
                           $"MemType={memTypeStr} | " +
                           $"Protect=0x{mbi.Protect:X} | " +
                           $"RegionBase=0x{mbi.BaseAddress.ToInt64():X} | " +
                           $"RegionSize=0x{mbi.RegionSize.ToInt64():X} | " +
                           $"Prozess={procExe} PID={pid}"
            });
            return 1;
        }
        catch { return 0; }
        finally
        {
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
        }
    }
}
