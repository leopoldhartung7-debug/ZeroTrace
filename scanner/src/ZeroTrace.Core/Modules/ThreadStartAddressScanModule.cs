using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans threads in game processes for start addresses that point to injected
/// code rather than legitimate module entry points.
///
/// When a cheat DLL is injected via CreateRemoteThread or other injection
/// techniques, the created thread's start address often points to:
///   1. The middle of a private (non-module-backed) memory region (shellcode)
///   2. A trampoline inside ntdll.dll (RtlUserThreadStart) while the actual
///      code is in an unbacked region
///   3. An address that falls within a memory region with PAGE_EXECUTE_READWRITE
///      (RWX) protection — a hallmark of injected shellcode
///
/// Detection via NtQueryInformationThread (ThreadQuerySetWin32StartAddress = 9):
///   Returns the original CreateThread/CreateRemoteThread start function pointer.
///   Compare this against the known module map — if it falls in unmapped memory
///   or private RWX regions, the thread is injected.
///
/// P/Invoke: NtQueryInformationThread, NtQueryVirtualMemory,
///           OpenThread, OpenProcess, Thread32First/Next
/// </summary>
public sealed class ThreadStartAddressScanModule : IScanModule
{
    public string Name => "Thread-Startadress-Analyse";
    public double Weight => 1.1;
    public int ParallelGroup => 0;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(
        IntPtr threadHandle, int threadInfoClass,
        ref IntPtr threadInfo, uint threadInfoLength, out uint returnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryVirtualMemory(
        IntPtr processHandle, IntPtr baseAddress, int memInfoClass,
        ref MEMORY_BASIC_INFORMATION memInfo, ulong memInfoLen, out ulong returnLen);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint access, bool inherit, uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);

    [DllImport("kernel32.dll")]
    private static extern bool Thread32First(IntPtr snap, ref THREADENTRY32 te);

    [DllImport("kernel32.dll")]
    private static extern bool Thread32Next(IntPtr snap, ref THREADENTRY32 te);

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
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint THREAD_QUERY_INFORMATION = 0x0040;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint TH32CS_SNAPTHREAD = 0x00000004;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const int ThreadQuerySetWin32StartAddress = 9;

    private static readonly HashSet<string> GameProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "GTA5", "FiveM", "FiveM_b2802_GTAProcess",
        "cs2", "csgo",
        "EscapeFromTarkov",
        "r5apex", "r5apex_dx12",
        "VALORANT-Win64-Shipping",
        "RainbowSix",
        "TslGame",
        "RustClient",
        "Fortnite",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int threadsChecked = 0;
        int hits = 0;

        var procs = System.Diagnostics.Process.GetProcesses();
        foreach (var proc in procs)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using (proc)
                {
                    if (!GameProcessNames.Contains(proc.ProcessName)) continue;
                    ctx.IncrementProcesses();

                    string path = "";
                    try { path = proc.MainModule?.FileName ?? ""; } catch { }

                    var hProc = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
                    if (hProc == IntPtr.Zero) continue;

                    try
                    {
                        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, (uint)proc.Id);
                        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) continue;

                        try
                        {
                            var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };
                            if (!Thread32First(snap, ref te)) continue;

                            do
                            {
                                if (ct.IsCancellationRequested) break;
                                if (te.th32OwnerProcessID != (uint)proc.Id) continue;

                                threadsChecked++;

                                var hThread = OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID);
                                if (hThread == IntPtr.Zero) continue;

                                try
                                {
                                    var startAddr = IntPtr.Zero;
                                    int status = NtQueryInformationThread(
                                        hThread, ThreadQuerySetWin32StartAddress,
                                        ref startAddr, (uint)IntPtr.Size, out _);

                                    if (status != 0 || startAddr == IntPtr.Zero) continue;

                                    // Query the memory region at the start address
                                    var mbi = new MEMORY_BASIC_INFORMATION();
                                    ulong mbiSize = (ulong)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                                    int qStatus = NtQueryVirtualMemory(
                                        hProc, startAddr, 0, ref mbi, mbiSize, out _);

                                    if (qStatus != 0) continue;

                                    bool isPrivate = mbi.Type == MEM_PRIVATE;
                                    bool isRwx = mbi.Protect == PAGE_EXECUTE_READWRITE ||
                                                 mbi.Protect == PAGE_EXECUTE_WRITECOPY ||
                                                 mbi.AllocationProtect == PAGE_EXECUTE_READWRITE;

                                    if (isPrivate && isRwx)
                                    {
                                        hits++;
                                        ctx.AddFinding(new Finding
                                        {
                                            Module   = Name,
                                            Title    = $"Shellcode-Thread in {proc.ProcessName} (PID {proc.Id})",
                                            Risk     = RiskLevel.Critical,
                                            Location = path,
                                            FileName = proc.ProcessName + ".exe",
                                            Reason   = $"Thread #{te.th32ThreadID} in Spielprozess '{proc.ProcessName}' " +
                                                       $"startet bei Adresse 0x{startAddr.ToInt64():X16} in " +
                                                       "privatem RWX-Speicher (keine Modul-Backing). " +
                                                       "Dies ist das klassische Muster eines injizierten " +
                                                       "Shellcode-Threads (CreateRemoteThread + VirtualAllocEx).",
                                            Detail   = $"TID: {te.th32ThreadID} | StartAddr: 0x{startAddr.ToInt64():X} | " +
                                                       $"MemType: Private | Protect: 0x{mbi.Protect:X} | " +
                                                       $"AllocProtect: 0x{mbi.AllocationProtect:X}"
                                        });
                                    }
                                    else if (isPrivate && !isRwx)
                                    {
                                        // Private non-RWX: thread in private code region (less suspicious
                                        // but still worth flagging in game processes)
                                        hits++;
                                        ctx.AddFinding(new Finding
                                        {
                                            Module   = Name,
                                            Title    = $"Thread in privatem Code-Bereich: {proc.ProcessName}",
                                            Risk     = RiskLevel.High,
                                            Location = path,
                                            FileName = proc.ProcessName + ".exe",
                                            Reason   = $"Thread #{te.th32ThreadID} in '{proc.ProcessName}' " +
                                                       $"startet in privatem Speicher (kein DLL/EXE-Modul-Backing) " +
                                                       $"bei 0x{startAddr.ToInt64():X16}. " +
                                                       "Kann auf manuelles DLL-Mapping (nicht via LoadLibrary) hinweisen.",
                                            Detail   = $"TID: {te.th32ThreadID} | StartAddr: 0x{startAddr.ToInt64():X} | " +
                                                       $"Protect: 0x{mbi.Protect:X} | Type: 0x{mbi.Type:X}"
                                        });
                                    }
                                }
                                finally
                                {
                                    CloseHandle(hThread);
                                }
                            }
                            while (Thread32Next(snap, ref te));
                        }
                        finally
                        {
                            CloseHandle(snap);
                        }
                    }
                    finally
                    {
                        CloseHandle(hProc);
                    }
                }
            }
            catch { }
        }

        ctx.Report(1.0, Name, $"{threadsChecked} Threads in Spielprozessen geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }
}
