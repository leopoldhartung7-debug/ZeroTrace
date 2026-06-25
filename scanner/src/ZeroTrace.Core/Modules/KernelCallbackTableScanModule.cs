using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects KernelCallbackTable hijacking in processes — a stealthy code injection technique.
///
/// The KernelCallbackTable (KCT) is a pointer table in the PEB (Process Environment Block)
/// at offset PEB+0x58 (x64). It holds pointers to functions that the Win32k kernel subsystem
/// calls back into user-mode for window messaging (WM_* messages).
///
/// KCT Hijacking (used by Lazarus Group, FinFisher, and advanced cheats):
///   1. Read PEB.KernelCallbackTable pointer
///   2. Allocate a new table (copy of original)
///   3. Replace one entry (e.g., __fnCOPYDATA at index 0x3C) with shellcode pointer
///   4. Write new table address to PEB.KernelCallbackTable
///   5. Send WM_COPYDATA message to any window — kernel calls the hijacked entry
///   6. Shellcode executes in target process context
///
/// Advantages for cheats:
///   - No new threads created (bypasses thread-start-address scanners)
///   - Execution triggered by legitimate window message (hard to detect)
///   - Code runs in existing process threads (appears legitimate)
///   - No PE injection required (pure ROP/shellcode execution)
///
/// Detection:
///   1. Read PEB.KernelCallbackTable pointer
///   2. Verify each entry points into a known loaded module's code section
///   3. Flag entries pointing to private/anonymous memory
///   4. Compare against clean KCT from another identical system (hash-based)
/// </summary>
public sealed class KernelCallbackTableScanModule : IScanModule
{
    public string Name => "KernelCallbackTable-Hijacking-Erkennung";
    public double Weight => 1.0;
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

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle,
        int processInformationClass, out ProcessBasicInformationStruct processInformation,
        int processInformationLength, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformationStruct
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

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

    // Win32 processes (have a KCT in their PEB)
    private static readonly HashSet<string> Win32Processes = new(StringComparer.OrdinalIgnoreCase)
    {
        "csgo.exe", "cs2.exe", "valorant.exe", "VALORANT-Win64-Shipping.exe",
        "r5apex.exe", "FortniteClient-Win64-Shipping.exe",
        "GTA5.exe", "EFT.exe", "pubg.exe",
        "explorer.exe", "taskhostw.exe", "RuntimeBroker.exe",
    };

    // KCT offset in PEB (x64)
    private const int PEB_KCT_OFFSET_X64 = 0x58;
    // Number of KCT entries to verify
    private const int KCT_ENTRY_COUNT = 0x80;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            bool is64Bit = IntPtr.Size == 8;
            if (!is64Bit) return Task.CompletedTask; // Only implemented for x64

            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                string procExe = proc.ProcessName + ".exe";
                if (!Win32Processes.Contains(procExe))
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

                    hits += CheckKernelCallbackTable(proc, hProcess, procExe, ctx);
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

        ctx.Report(1.0, Name, $"KernelCallbackTable in Prozessen geprüft, {hits} Hijacks");
        return Task.CompletedTask;
    }

    private static int CheckKernelCallbackTable(Process proc, IntPtr hProcess,
        string procExe, ScanContext ctx)
    {
        int hits = 0;
        try
        {
            // Get PEB address
            int status = NtQueryInformationProcess(hProcess, 0, out var pbi,
                Marshal.SizeOf<ProcessBasicInformationStruct>(), out _);
            if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero) return 0;

            // Read PEB to get KernelCallbackTable pointer
            var pebBuf = new byte[0x100];
            if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, pebBuf, pebBuf.Length, out int r)
                || r < PEB_KCT_OFFSET_X64 + 8) return 0;

            IntPtr kctPtr = new(BitConverter.ToInt64(pebBuf, PEB_KCT_OFFSET_X64));
            if (kctPtr == IntPtr.Zero) return 0;

            // Read the KCT (array of function pointers)
            int kctSize = KCT_ENTRY_COUNT * 8; // 8 bytes per pointer on x64
            var kctBuf = new byte[kctSize];
            if (!ReadProcessMemory(hProcess, kctPtr, kctBuf, kctSize, out int kctRead)
                || kctRead < 16) return 0;

            int entriesRead = kctRead / 8;

            // Verify that the KCT itself is in mapped image memory (not private/anonymous)
            if (!VirtualQueryEx(hProcess, kctPtr, out var kctMbi,
                (uint)Marshal.SizeOf<MemoryBasicInformation>())) return 0;

            if (kctMbi.Type != MEM_IMAGE)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "KernelCallbackTable-Hijacking-Erkennung",
                    Title    = $"KernelCallbackTable in privatem Speicher: {procExe}",
                    Risk     = RiskLevel.Critical,
                    Location = $"PID {proc.Id}: PEB.KCT @ 0x{kctPtr.ToInt64():X}",
                    Reason   = $"PEB.KernelCallbackTable von '{procExe}' (PID {proc.Id}) zeigt auf " +
                               "nicht-Image-Speicher (MEM_PRIVATE oder MEM_MAPPED). " +
                               "Beim KCT-Hijacking wird eine gefälschte Funktionstabelle " +
                               "im privaten Speicher erstellt und die PEB-KCT auf sie umgezeigt. " +
                               "Shellcode in der neuen Tabelle wird bei WM_* Nachrichten aufgerufen.",
                    Detail   = $"KCT @ 0x{kctPtr.ToInt64():X} | MemType: 0x{kctMbi.Type:X} " +
                               $"(erwartet: 0x{MEM_IMAGE:X}=IMAGE)"
                });
                return hits;
            }

            // Check each KCT entry: all must point into MEM_IMAGE regions
            for (int i = 0; i < entriesRead; i++)
            {
                long entryPtr = BitConverter.ToInt64(kctBuf, i * 8);
                if (entryPtr == 0) continue;

                var entryAddr = new IntPtr(entryPtr);
                if (!VirtualQueryEx(hProcess, entryAddr, out var entryMbi,
                    (uint)Marshal.SizeOf<MemoryBasicInformation>())) continue;

                if (entryMbi.State == MEM_COMMIT && entryMbi.Type != MEM_IMAGE)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "KernelCallbackTable-Hijacking-Erkennung",
                        Title    = $"KCT-Eintrag {i} zeigt auf privaten Speicher: {procExe}",
                        Risk     = RiskLevel.Critical,
                        Location = $"PID {proc.Id}: KCT[{i}] @ 0x{entryPtr:X}",
                        Reason   = $"KernelCallbackTable-Eintrag [{i}] in '{procExe}' " +
                                   $"zeigt auf Adresse 0x{entryPtr:X} im " +
                                   $"privaten Speicher (MemType: 0x{entryMbi.Type:X}). " +
                                   "Alle KCT-Einträge sollten in Modul-Image-Regionen zeigen (win32u.dll, user32.dll). " +
                                   "Privater Speicher bedeutet, ein Angreifer hat diesen Eintrag " +
                                   "auf Shellcode umgeleitet (KCT-Hijacking-Payload).",
                        Detail   = $"KCT[{i}] = 0x{entryPtr:X} | MemType: 0x{entryMbi.Type:X} | " +
                                   $"Prozess: {procExe} PID={proc.Id}"
                    });
                    break; // One finding per process is enough
                }
            }
        }
        catch { }
        return hits;
    }
}
