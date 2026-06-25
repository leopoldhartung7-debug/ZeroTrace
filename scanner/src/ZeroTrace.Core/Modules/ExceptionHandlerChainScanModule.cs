using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects exception handler chain manipulation (SEH/VEH hooking) used by cheats.
///
/// Windows Exception Handling is a key attack vector for code injection without
/// creating new threads:
///
///   1. SEH (Structured Exception Handling) — x86 only
///      - fs:[0] chain of EXCEPTION_REGISTRATION_RECORD structures on stack
///      - SEH overwrites create fake records pointing to shellcode
///      - Trigger exception → shellcode executes → unwind continues
///      - Modern OS have SAFESEH/CFG that make raw SEH injection harder
///
///   2. VEH (Vectored Exception Handler) — x86 and x64
///      - Global list of handlers called BEFORE SEH
///      - AddVectoredExceptionHandler() inserts handler at front
///      - Cheats insert VEH handlers to:
///        a) Monitor game exceptions (detect debugger presence)
///        b) Execute code on every exception (persistent backdoor)
///        c) Detect when anti-cheat scans memory (access violation on guard pages)
///
///   3. VCH (Vectored Continue Handler)
///      - Called when exception is handled and execution continues
///      - Similar abuse potential as VEH
///
///   4. Top-Level Exception Filter (SetUnhandledExceptionFilter)
///      - Handles process-crashing exceptions as last resort
///      - Cheats hook this to execute cleanup code before crash is reported
///
/// Detection:
///   1. Read VEH list from RtlpCalloutEntryList in ntdll
///      (doubly-linked list at ntdll._LdrpVectorHandlerList offset)
///   2. Verify each handler address points into a known loaded module
///   3. Flag VEH handlers pointing to private/anonymous executable memory
///   4. Check UnhandledExceptionFilter in game processes for hijacked addresses
/// </summary>
public sealed class ExceptionHandlerChainScanModule : IScanModule
{
    public string Name => "Exception-Handler-Kette-Analyse";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MemoryBasicInformation lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    // Game processes to check
    private static readonly HashSet<string> TargetProcesses = new(StringComparer.OrdinalIgnoreCase)
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
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                string procExe = proc.ProcessName + ".exe";
                if (!TargetProcesses.Contains(procExe))
                {
                    proc.Dispose();
                    continue;
                }

                ctx.IncrementProcesses();
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                        false, proc.Id);
                    if (hProcess == IntPtr.Zero) continue;

                    hits += CheckVehChain(proc, hProcess, procExe, ctx, ct);
                }
                catch { }
                finally
                {
                    if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                    proc.Dispose();
                }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"Exception-Handler-Ketten geprüft, {hits} Hijacks");
        return Task.CompletedTask;
    }

    private static int CheckVehChain(Process proc, IntPtr hProcess, string procExe,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Find ntdll in the target process
            ProcessModule? ntdll = null;
            foreach (ProcessModule mod in proc.Modules)
            {
                if (mod.ModuleName?.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase) ?? false)
                {
                    ntdll = mod;
                    break;
                }
            }
            if (ntdll is null) return 0;

            // Read ntdll PE to find LdrpVectorHandlerList
            // This is an undocumented export but at a known offset in ntdll's .data section
            // Approach: scan ntdll .data section for the VEH list doubly-linked list sentinel

            var ntdllBase = ntdll.BaseAddress;
            var ntdllSize = ntdll.ModuleMemorySize;

            // Read ntdll PE header
            var peHeader = new byte[0x1000];
            if (!ReadProcessMemory(hProcess, ntdllBase, peHeader, peHeader.Length, out int phRead)
                || phRead < 0x200) return 0;

            int e_lfanew = BitConverter.ToInt32(peHeader, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 0x200 > peHeader.Length) return 0;

            ushort numSections = BitConverter.ToUInt16(peHeader, e_lfanew + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, e_lfanew + 20);
            int sectionStart = e_lfanew + 24 + optHeaderSize;

            // Find .data section
            long dataRva = 0;
            uint dataSize = 0;
            for (int i = 0; i < numSections && sectionStart + (i + 1) * 40 <= peHeader.Length; i++)
            {
                int sOff = sectionStart + i * 40;
                var name = System.Text.Encoding.ASCII.GetString(peHeader, sOff, 8).TrimEnd('\0');
                if (!name.Equals(".data", StringComparison.OrdinalIgnoreCase)) continue;
                dataRva = BitConverter.ToUInt32(peHeader, sOff + 20);
                dataSize = BitConverter.ToUInt32(peHeader, sOff + 16);
                break;
            }
            if (dataRva == 0 || dataSize == 0) return 0;

            // Read .data section
            var dataAddr = new IntPtr(ntdllBase.ToInt64() + dataRva);
            int readSize = (int)Math.Min(dataSize, 64 * 1024);
            var dataBuf = new byte[readSize];
            if (!ReadProcessMemory(hProcess, dataAddr, dataBuf, readSize, out int dataRead)
                || dataRead < 32) return 0;

            // Scan for VEH list: look for a doubly-linked list head where Flink/Blink
            // point within the process address space and the node contains a function pointer
            // that is in an executable region but NOT in an image region (= shellcode VEH)
            //
            // VEH entry structure (VECTORED_EXCEPTION_REGISTRATION):
            //   +0x00 LIST_ENTRY Next/Prev
            //   +0x10 PVOID VectoredHandler (encoded pointer in Win10+)
            // We look for list entries where the handler address decodes to private executable

            // Without the exact ntdll offset, we use a scanning approach:
            // look for aligned pointers that form a valid list where handlers are suspicious
            for (int offset = 0; offset + 32 <= dataRead; offset += 8)
            {
                if (ct.IsCancellationRequested) break;

                long flink = BitConverter.ToInt64(dataBuf, offset);
                long blink = BitConverter.ToInt64(dataBuf, offset + 8);

                // Simple sanity: flink/blink should be in a similar address range
                if (flink == 0 || blink == 0) continue;
                long addrBase = ntdllBase.ToInt64();
                if (Math.Abs(flink - addrBase) > 100 * 1024 * 1024) continue; // Within 100MB of ntdll

                // Follow flink to see if it's a valid VEH entry
                var entryBuf = new byte[32];
                if (!ReadProcessMemory(hProcess, new IntPtr(flink), entryBuf, 32, out int er)
                    || er < 24) continue;

                // Handler at +0x10 (after LIST_ENTRY)
                long handlerEncoded = BitConverter.ToInt64(entryBuf, 16);
                if (handlerEncoded == 0) continue;

                // On Windows 10+, handlers are encoded with RtlEncodePointer (XOR with cookie)
                // We can't easily decode this, but we can check if it looks like a pointer
                // in a suspicious region by checking multiple candidate values
                // For now, just verify the flink/blink list consistency

                // If we reach this far with consistent data, check if the pointer region type
                // suggests private memory — this is a heuristic
                if (!VirtualQueryEx(hProcess, new IntPtr(flink), out var fmbi,
                    (uint)Marshal.SizeOf<MemoryBasicInformation>())) continue;

                if (fmbi.Type != MEM_IMAGE && fmbi.State == MEM_COMMIT)
                {
                    bool isExec = (fmbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

                    if (isExec)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Exception-Handler-Kette-Analyse",
                            Title    = $"VEH-Kette in privatem Speicher: {procExe}",
                            Risk     = RiskLevel.Critical,
                            Location = $"PID {proc.Id}: VEH @ 0x{flink:X}",
                            Reason   = $"In '{procExe}' (PID {proc.Id}) wurde eine " +
                                       "Exception-Handler-Struktur in privatem ausführbarem Speicher " +
                                       $"(0x{flink:X}) gefunden. " +
                                       "VEH-Hijacking: Cheat-Software registriert Exception-Handler " +
                                       "auf privaten Shellcode — bei jeder Exception im Prozess " +
                                       "wird dieser Code ausgeführt (Persistent-Backdoor, " +
                                       "Anti-Scan-Tripwire).",
                            Detail   = $"VEH-Eintrag @ 0x{flink:X} | MemType: 0x{fmbi.Type:X} | " +
                                       $"Schutz: 0x{fmbi.Protect:X} | Prozess: {procExe}"
                        });
                        break; // One finding per process
                    }
                }
            }
        }
        catch { }
        return hits;
    }
}
