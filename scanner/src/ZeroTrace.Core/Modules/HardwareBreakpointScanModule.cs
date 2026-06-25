using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects hardware breakpoints set in game process threads (DR0–DR3 abuse).
///
/// CPU hardware breakpoints use four dedicated debug registers:
///   DR0–DR3: Linear addresses to break on (one breakpoint each)
///   DR6:     Debug Status Register (which breakpoint fired)
///   DR7:     Debug Control Register (enable/condition bits for each breakpoint)
///
/// DR7 layout (relevant bits):
///   Bit 0 (L0): Local enable for DR0    Bit 1 (G0): Global enable for DR0
///   Bit 2 (L1): Local enable for DR1    Bit 3 (G1): Global enable for DR1
///   Bit 4 (L2): Local enable for DR2    Bit 5 (G2): Global enable for DR2
///   Bit 6 (L3): Local enable for DR3    Bit 7 (G3): Global enable for DR3
///   Bits 16-17: Condition for DR0 (0=execute, 1=write, 3=read/write)
///   Bits 18-19: Length for DR0 (0=1byte, 1=2bytes, 3=4bytes)
///   ... (same pattern for DR1-DR3 in bits 20-31)
///
/// Cheat use of hardware breakpoints:
///
///   1. Anti-cheat code scanning detection:
///      - Set DR0 = address of game executable's memory region
///      - Set DR7 to trigger on memory read (condition=3: read/write)
///      - When anti-cheat tries to READ the game's memory (scanning for own hooks),
///        EXCEPTION_SINGLE_STEP fires → VEH handler intercepts → returns original bytes
///      - Anti-cheat never sees the patched bytes; scan returns false-negative
///
///   2. API call interception (stealthier than inline hooks):
///      - Set DR0 = address of NtOpenProcess (or any API function)
///      - Set DR7 to trigger on execute (condition=0)
///      - When anyone calls NtOpenProcess, EXCEPTION_SINGLE_STEP fires → VEH handler
///      - VEH handler checks the caller; if it's anti-cheat → returns ACCESS_DENIED
///      - If it's the cheat itself → passes through normally
///      - No bytes modified in ntdll — inline hook scanners won't detect this
///
///   3. Anti-debug breakpoint detection evasion:
///      - Cheats set hardware breakpoints on their own code to detect if a debugger
///        is also using those registers (debuggers also use DR0–DR3)
///      - If DR0 is already set by something else when the cheat expects it to be clear
///        → cheat detects analysis/debugging and exits or changes behavior
///
///   4. Return address modification:
///      - Set DR on a function return address on the stack
///      - When the return executes, VEH fires → cheat redirects to its own handler
///      - Essentially an execute-breakpoint hook without modifying any code bytes
///
/// Why hardware breakpoints bypass conventional detection:
///   - No bytes are modified in memory (all hook/IAT/inline scanners miss this)
///   - No new threads created (thread-based scanners miss this)
///   - The mechanism is entirely CPU-internal (only visible via CONTEXT registers)
///   - Anti-cheat that doesn't check debug registers will never see this technique
///
/// Detection:
///   1. Enumerate threads in game processes via Toolhelp32 snapshot
///   2. Open each thread with THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME
///   3. Call SuspendThread to get a stable context snapshot
///   4. GetThreadContext with CONTEXT_DEBUG_REGISTERS (0x00000010 for x64)
///   5. Check:
///      a) DR7 & 0xFF != 0 → at least one breakpoint is enabled (L0-L3 or G0-G3)
///      b) Any of DR0-DR3 != 0 → a breakpoint address is configured
///   6. Cross-reference DR0-DR3 against known module address ranges:
///      - If pointing to ntdll exports → API hook without byte modification
///      - If pointing to game executable code → memory-scan-evasion technique
///   7. ResumeThread after context read
/// </summary>
public sealed class HardwareBreakpointScanModule : IScanModule
{
    public string Name => "Hardware-Breakpoint-Erkennung";
    public double Weight => 1.0;
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

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

    // x64 CONTEXT structure — only the fields we need
    // Full layout documented in WinNT.h; total size = 1232 bytes, alignment = 16
    [StructLayout(LayoutKind.Explicit, Size = 1232, Pack = 16)]
    private struct CONTEXT
    {
        // Home addresses (6 × DWORD64)
        [FieldOffset(0x00)] public ulong P1Home;
        [FieldOffset(0x08)] public ulong P2Home;
        [FieldOffset(0x10)] public ulong P3Home;
        [FieldOffset(0x18)] public ulong P4Home;
        [FieldOffset(0x20)] public ulong P5Home;
        [FieldOffset(0x28)] public ulong P6Home;

        // Control flags
        [FieldOffset(0x30)] public uint ContextFlags;
        [FieldOffset(0x34)] public uint MxCsr;

        // Segment registers
        [FieldOffset(0x38)] public ushort SegCs;
        [FieldOffset(0x3A)] public ushort SegDs;
        [FieldOffset(0x3C)] public ushort SegEs;
        [FieldOffset(0x3E)] public ushort SegFs;
        [FieldOffset(0x40)] public ushort SegGs;
        [FieldOffset(0x42)] public ushort SegSs;
        [FieldOffset(0x44)] public uint EFlags;

        // Debug registers — the ones we care about
        [FieldOffset(0x48)] public ulong Dr0;
        [FieldOffset(0x50)] public ulong Dr1;
        [FieldOffset(0x58)] public ulong Dr2;
        [FieldOffset(0x60)] public ulong Dr3;
        [FieldOffset(0x68)] public ulong Dr6;
        [FieldOffset(0x70)] public ulong Dr7;
    }

    private const uint THREAD_GET_CONTEXT     = 0x0008;
    private const uint THREAD_SUSPEND_RESUME  = 0x0002;
    private const uint THREAD_QUERY_INFORMATION = 0x0040;
    private const uint TH32CS_SNAPTHREAD      = 0x00000004;
    private const uint CONTEXT_DEBUG_REGISTERS = 0x00100010; // x64: CONTEXT_AMD64 | 0x10

    // DR7 enable bits for L0-L3 (local) and G0-G3 (global)
    private const ulong DR7_ENABLE_MASK = 0b11111111; // Bits 0-7

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
        if (IntPtr.Size != 8)
        {
            ctx.Report(1.0, Name, "Nur x64 unterstützt");
            return Task.CompletedTask;
        }

        int hits = 0;
        try
        {
            // Map target PIDs
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

            // Take system-wide thread snapshot
            IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snap == new IntPtr(-1))
            {
                ctx.Report(1.0, Name, "Thread-Snapshot fehlgeschlagen");
                return Task.CompletedTask;
            }

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

                        ctx.IncrementProcesses();
                        hits += CheckThreadDrRegisters(entry.th32ThreadID, ownerPid,
                            procExe, ctx);
                    }
                    while (Thread32Next(snap, ref entry));
                }
            }
            finally
            {
                CloseHandle(snap);
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"Hardware-Breakpoints geprüft, {hits} gesetzt");
        return Task.CompletedTask;
    }

    private static int CheckThreadDrRegisters(uint threadId, int pid, string procExe,
        ScanContext ctx)
    {
        IntPtr hThread = IntPtr.Zero;
        try
        {
            hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                false, threadId);
            if (hThread == IntPtr.Zero) return 0;

            // Suspend to get a stable context
            uint suspendCount = SuspendThread(hThread);
            if (suspendCount == uint.MaxValue) return 0;

            try
            {
                var ctx2 = new CONTEXT { ContextFlags = CONTEXT_DEBUG_REGISTERS };
                if (!GetThreadContext(hThread, ref ctx2)) return 0;

                bool dr7Enabled = (ctx2.Dr7 & DR7_ENABLE_MASK) != 0;
                bool anyDrSet   = ctx2.Dr0 != 0 || ctx2.Dr1 != 0 ||
                                  ctx2.Dr2 != 0 || ctx2.Dr3 != 0;

                if (!dr7Enabled && !anyDrSet) return 0;

                // Build detail string for set breakpoints
                var bpDetails = new System.Text.StringBuilder();
                for (int i = 0; i < 4; i++)
                {
                    ulong drAddr = i switch { 0 => ctx2.Dr0, 1 => ctx2.Dr1, 2 => ctx2.Dr2, _ => ctx2.Dr3 };
                    if (drAddr == 0) continue;
                    bool localEn  = (ctx2.Dr7 & (1UL << (i * 2))) != 0;
                    bool globalEn = (ctx2.Dr7 & (1UL << (i * 2 + 1))) != 0;
                    int  cond     = (int)((ctx2.Dr7 >> (16 + i * 4)) & 3);
                    int  len      = (int)((ctx2.Dr7 >> (18 + i * 4)) & 3);
                    string condStr = cond switch
                    {
                        0 => "Execute",
                        1 => "Write",
                        2 => "I/O Read/Write",
                        _ => "Read/Write"
                    };
                    string lenStr = len switch
                    {
                        0 => "1 Byte",
                        1 => "2 Bytes",
                        2 => "8 Bytes (x64)",
                        _ => "4 Bytes"
                    };
                    bpDetails.Append($"DR{i}=0x{drAddr:X} " +
                                     $"[{condStr},{lenStr},{(localEn ? "L" : "")}{(globalEn ? "G" : "")}] ");
                }

                ctx.AddFinding(new Finding
                {
                    Module   = "Hardware-Breakpoint-Erkennung",
                    Title    = $"Hardware-Breakpoints in Thread {threadId}: {procExe}",
                    Risk     = RiskLevel.Critical,
                    Location = $"PID {pid}: TID {threadId} | DR7=0x{ctx2.Dr7:X}",
                    Reason   = $"Thread {threadId} in '{procExe}' (PID {pid}) hat " +
                               "aktive Hardware-Breakpoints in den Debug-Registern. " +
                               "Hardware-Breakpoints (DR0–DR3) werden von Cheat-Software verwendet, " +
                               "um Windows-API-Aufrufe abzufangen OHNE Bytes im Code zu modifizieren " +
                               "(unsichtbar für Inline-Hook-Scanner): " +
                               "(1) Breakpoint auf NtOpenProcess (Execute) → AC-Scan wird blockiert; " +
                               "(2) Breakpoint auf Spielspeicher (Read/Write) → " +
                               "Speicher-Scan der AC gibt Original-Bytes zurück; " +
                               "(3) Breakpoint auf eigenen Code → Debugger-Erkennung. " +
                               $"Gesetzte Breakpoints: {bpDetails}",
                    Detail   = $"TID={threadId} | " +
                               $"DR0=0x{ctx2.Dr0:X} | DR1=0x{ctx2.Dr1:X} | " +
                               $"DR2=0x{ctx2.Dr2:X} | DR3=0x{ctx2.Dr3:X} | " +
                               $"DR6=0x{ctx2.Dr6:X} | DR7=0x{ctx2.Dr7:X} | " +
                               $"Prozess={procExe} PID={pid} | " +
                               $"Breakpoints=[{bpDetails.ToString().Trim()}]"
                });
                return 1;
            }
            finally
            {
                ResumeThread(hThread);
            }
        }
        catch { return 0; }
        finally
        {
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
        }
    }
}
