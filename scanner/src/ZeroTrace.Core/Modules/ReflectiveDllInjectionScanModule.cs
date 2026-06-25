using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Reflective DLL Injection in game processes.
///
/// Reflective DLL Injection (RDI), developed by Stephen Fewer (2008) and widely used
/// by cheat developers, loads a DLL entirely from memory without using the Windows
/// loader. The DLL never appears in the module list, never touches the filesystem
/// after injection, and evades most module-enumeration based scanners.
///
/// How Reflective DLL Injection works:
///   1. Attacker reads a DLL from disk or network into a byte array
///   2. The DLL contains a "reflective loader" export (ReflectiveLoader):
///      - Locates its own image base using position-independent code
///      - Applies relocations and resolves imports manually
///      - Calls DllMain with DLL_PROCESS_ATTACH
///      → The entire loading process happens in user-mode, bypassing LoadLibrary
///   3. The mapped DLL's memory region is:
///      - Type: MEM_PRIVATE (not MEM_IMAGE — OS loader didn't map it)
///      - Contains a valid MZ/PE header at the allocation base
///      - Contains import tables, export tables, section headers
///      - NOT listed in Process.Modules or any toolhelp32 module snapshot
///
/// Variants:
///   - Manual Map (CheatEngine, minhook, external overlays):
///     Custom loader applies relocations and resolves imports without the reflective
///     loader export. Module headers may be wiped post-load (module stomping).
///   - PE-backed Shellcode (payloads with PE headers for RTTI / imports):
///     Shellcode compiled as a DLL for convenience; the PE structure is valid
///     but the code is standalone (no DllMain).
///   - Memory-mapped injection (via MapViewOfFile2 + shared sections):
///     PE mapped via NtMapViewOfSection from a custom section — appears as
///     MEM_MAPPED (not MEM_PRIVATE), but not in the module list.
///
/// Why conventional scanners miss it:
///   - Process.Modules / Module32First only lists OS-loaded modules
///   - CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) returns only PEB LDR modules
///   - The injected region has no filename — GetMappedFileName returns empty
///   - PE header may be zeroed after injection (module stomping variant)
///
/// Detection algorithm (this module):
///   1. Collect all known module base-address ranges from Process.Modules
///   2. Walk all virtual memory regions via VirtualQueryEx:
///      Scan for regions where State=MEM_COMMIT, Type≠MEM_IMAGE,
///      Protection is executable (PAGE_EXECUTE_*)
///   3. Read the first 0x1000 bytes of each suspicious private executable region
///   4. Check for:
///      a) MZ signature at offset 0 (valid PE start)
///      b) Valid PE header at e_lfanew (PE\0\0 signature)
///      c) Reasonable SizeOfImage (> 4 KB, < 256 MB)
///      d) Region NOT covered by any known Process.Modules entry
///   5. Also detect mapped (MEM_MAPPED) executables not in module list:
///      These are section-mapped DLLs injected via NtMapViewOfSection
///   6. Flag the base address, size, and protection of each suspicious PE region
/// </summary>
public sealed class ReflectiveDllInjectionScanModule : IScanModule
{
    public string Name => "Reflektive-DLL-Injektions-Erkennung";
    public double Weight => 1.2;
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
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetMappedFileNameW(IntPtr hProcess, IntPtr lpv,
        [Out] char[] lpFilename, uint nSize);

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

    private const uint PROCESS_VM_READ            = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION  = 0x0400;
    private const uint MEM_COMMIT                 = 0x1000;
    private const uint MEM_IMAGE                  = 0x1000000;
    private const uint MEM_MAPPED                 = 0x40000;
    private const uint MEM_PRIVATE                = 0x20000;
    private const uint PAGE_EXECUTE               = 0x10;
    private const uint PAGE_EXECUTE_READ          = 0x20;
    private const uint PAGE_EXECUTE_READWRITE     = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY     = 0x80;

    // Minimum PE size to consider a region suspicious (avoid false positives on tiny stubs)
    private const long MinPeSizeBytes = 4 * 1024;         // 4 KB
    // Maximum PE size to consider (avoid parsing garbage data)
    private const long MaxPeSizeBytes = 256 * 1024 * 1024; // 256 MB

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

                    hits += ScanProcessForReflectiveDlls(proc, hProcess, procExe, ctx, ct);
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

        ctx.Report(1.0, Name, $"Reflektive DLL-Injektion analysiert, {hits} Treffer");
        return Task.CompletedTask;
    }

    private static int ScanProcessForReflectiveDlls(Process proc, IntPtr hProcess,
        string procExe, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Build set of known module address ranges
            var knownRanges = new List<(long Start, long End)>();
            try
            {
                foreach (ProcessModule m in proc.Modules)
                {
                    try
                    {
                        long start = m.BaseAddress.ToInt64();
                        knownRanges.Add((start, start + m.ModuleMemorySize));
                    }
                    catch { }
                }
            }
            catch { }

            // Walk virtual address space
            var mbi = new MEMORY_BASIC_INFORMATION();
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            IntPtr addr = IntPtr.Zero;

            while (!ct.IsCancellationRequested)
            {
                if (!VirtualQueryEx(hProcess, addr, out mbi, mbiSize)) break;
                if (mbi.RegionSize == IntPtr.Zero) break;

                long regionBase = mbi.BaseAddress.ToInt64();
                long regionSize = mbi.RegionSize.ToInt64();

                // Move to next region before any early continues
                try { addr = new IntPtr(regionBase + regionSize); } catch { break; }

                // We want committed, executable, non-image memory
                if (mbi.State != MEM_COMMIT) continue;
                if (mbi.Type == MEM_IMAGE) continue;

                bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                if (!isExec) continue;

                // Size filter
                if (regionSize < MinPeSizeBytes || regionSize > MaxPeSizeBytes) continue;

                // Skip regions covered by a known loaded module
                bool covered = false;
                foreach (var (start, end) in knownRanges)
                {
                    if (regionBase >= start && regionBase < end) { covered = true; break; }
                }
                if (covered) continue;

                // Read the first 0x1000 bytes to check for PE header
                var headerBuf = new byte[0x1000];
                if (!ReadProcessMemory(hProcess, mbi.BaseAddress, headerBuf, headerBuf.Length,
                    out int hRead) || hRead < 64) continue;

                // Check for MZ signature
                if (headerBuf[0] != 'M' || headerBuf[1] != 'Z') continue;

                // Read e_lfanew (PE header offset)
                int e_lfanew = BitConverter.ToInt32(headerBuf, 0x3C);
                if (e_lfanew < 0 || e_lfanew + 24 > hRead) continue;

                // Validate PE signature
                if (headerBuf[e_lfanew]     != 'P' || headerBuf[e_lfanew + 1] != 'E' ||
                    headerBuf[e_lfanew + 2] != 0   || headerBuf[e_lfanew + 3] != 0) continue;

                // Check machine type (must be x86 or x64)
                ushort machine = BitConverter.ToUInt16(headerBuf, e_lfanew + 4);
                if (machine != 0x8664 && machine != 0x14C) continue;

                // Sanity-check SizeOfImage from optional header
                // SizeOfImage is at OptionalHeader + 0x38 for both x86 and x64
                int optOff = e_lfanew + 24;
                if (optOff + 0x3C > hRead) continue;
                uint sizeOfImage = BitConverter.ToUInt32(headerBuf, optOff + 0x38);
                if (sizeOfImage < MinPeSizeBytes || sizeOfImage > MaxPeSizeBytes) continue;

                // Try GetMappedFileName — if it returns something, it's a mapped file (less suspicious)
                var fnBuf = new char[512];
                uint fnLen = GetMappedFileNameW(hProcess, mbi.BaseAddress, fnBuf, (uint)fnBuf.Length);
                string mappedName = fnLen > 0 ? new string(fnBuf, 0, (int)fnLen) : "";

                string memTypeStr = mbi.Type == MEM_PRIVATE ? "MEM_PRIVATE" :
                                    mbi.Type == MEM_MAPPED  ? "MEM_MAPPED"  : $"0x{mbi.Type:X}";
                RiskLevel risk = mbi.Type == MEM_PRIVATE ? RiskLevel.Critical : RiskLevel.High;

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Reflektive-DLL-Injektions-Erkennung",
                    Title    = $"PE-Abbild in privatem Speicher: {procExe} @ 0x{regionBase:X}",
                    Risk     = risk,
                    Location = $"PID {proc.Id}: 0x{regionBase:X}–0x{regionBase + regionSize:X}",
                    Reason   = $"'{procExe}' (PID {proc.Id}) hat ein gültiges PE-Abbild " +
                               $"(MZ+PE Signatur, {sizeOfImage / 1024} KB SizeOfImage) " +
                               $"in {memTypeStr} bei 0x{regionBase:X} " +
                               (string.IsNullOrEmpty(mappedName)
                                   ? "(kein Dateiname — anonym)."
                                   : $"(mapped von '{mappedName}').") + " " +
                               "Das Modul ist NICHT in der Prozess-Modulliste registriert. " +
                               "Reflektive DLL-Injektion mappt DLLs ohne Windows-Loader: " +
                               "kein Eintrag in PEB.LDR, kein Eintrag in Toolhelp32-Modul-Snapshot. " +
                               "Einsatzgebiete: Cheat-DLLs (ESP, Aimbot, Memory-Read), " +
                               "Overlay-Injection, externe Radar-Komponenten.",
                    Detail   = $"BaseAddr=0x{regionBase:X} | Size={regionSize / 1024}KB | " +
                               $"SizeOfImage={sizeOfImage / 1024}KB | MemType={memTypeStr} | " +
                               $"Protect=0x{mbi.Protect:X} | MappedFile='{mappedName}' | " +
                               $"Machine=0x{machine:X} | Prozess={procExe} PID={proc.Id}"
                });

                if (hits >= 5) break; // Cap per process
            }
        }
        catch { }
        return hits;
    }
}
