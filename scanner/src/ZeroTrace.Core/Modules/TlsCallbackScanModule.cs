using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects malicious TLS (Thread Local Storage) callback abuse in game processes.
///
/// TLS (Thread Local Storage) callbacks are defined in a PE's TLS directory and
/// are automatically invoked by the Windows loader for every thread at attach and
/// detach. Crucially, they execute BEFORE the DLL entry point (DllMain) and
/// BEFORE the executable's main() / WinMain(). This makes them ideal for
/// pre-initialization code injection.
///
/// How the PE TLS mechanism works:
///   PE Optional Header → DataDirectory[9] → IMAGE_TLS_DIRECTORY:
///   ┌─────────────────────────────────────────────────────────────────┐
///   │ StartAddressOfRawData  — VA of TLS data template               │
///   │ EndAddressOfRawData    — end of template                       │
///   │ AddressOfIndex         — VA of DWORD for per-thread TLS index  │
///   │ AddressOfCallBacks     — VA of null-terminated callback array  │ ← abuse target
///   │ SizeOfZeroFill         — zero-init bytes after template        │
///   │ Characteristics        — alignment flags                       │
///   └─────────────────────────────────────────────────────────────────┘
///   The AddressOfCallBacks array is a VA list terminated by a null pointer.
///   Windows loader iterates it and calls each entry with (hModule, reason, reserved).
///
/// Cheat / malware abuse scenarios:
///
///   1. Injected DLL with malicious TLS:
///      - Cheat DLL registers a TLS callback that runs payload at attach
///      - Code executes before DllMain — anti-cheat InitDll hooks may not be in place yet
///      - Can be used to restore hooked ntdll functions before the AC reads them
///
///   2. TLS callback table tampering (most dangerous):
///      - Anti-cheat DLL has legitimate TLS callbacks for self-integrity checks
///      - Attacker overwrites AddressOfCallBacks in the mapped PE header to NULL
///        → Neuters the AC's initialization code completely
///      - Or replaces a callback pointer with shellcode address → hijacks AC init
///
///   3. Manually-mapped modules with synthetic TLS:
///      - PE is not loaded by the loader (reflective DLL injection, manual map)
///      - A custom loader constructs a TLS directory in private memory
///      - Callbacks point to shellcode in private/anonymous executable regions
///
///   4. Process hollowing with patched TLS:
///      - Hollow a legitimate process, transplant a different PE image
///      - The transplanted PE's TLS callbacks contain cheat init code
///
/// Detection:
///   1. Enumerate all loaded modules in game processes via Process.Modules
///   2. Read each module's PE header from process memory (ReadProcessMemory)
///   3. Locate TLS directory via DataDirectory[9] (index 9 = IMAGE_DIRECTORY_ENTRY_TLS)
///   4. Read IMAGE_TLS_DIRECTORY64 / IMAGE_TLS_DIRECTORY32 structure
///   5. Walk AddressOfCallBacks null-terminated pointer array
///   6. VirtualQueryEx every callback address:
///      - MEM_IMAGE → legitimate (callback in mapped module code section)
///      - MEM_PRIVATE / MEM_MAPPED → shellcode or tampered callback
///   7. Flag TLS directories themselves pointing outside MEM_IMAGE (synthetic TLS)
/// </summary>
public sealed class TlsCallbackScanModule : IScanModule
{
    public string Name => "TLS-Callback-Missbrauch-Erkennung";
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
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

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

    private const uint PROCESS_VM_READ          = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint MEM_COMMIT               = 0x1000;
    private const uint MEM_IMAGE                = 0x1000000;

    // IMAGE_DIRECTORY_ENTRY_TLS = index 9 in DataDirectory
    private const int IMAGE_DIRECTORY_ENTRY_TLS = 9;

    // Maximum TLS callbacks to inspect per module (guard against corrupt/malicious PE)
    private const int MaxCallbacksPerModule = 64;

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

                    hits += ScanProcessTls(proc, hProcess, procExe, ctx, ct);
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

        ctx.Report(1.0, Name, $"TLS-Callbacks analysiert, {hits} Missbrauch erkannt");
        return Task.CompletedTask;
    }

    private static int ScanProcessTls(Process proc, IntPtr hProcess,
        string procExe, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (ProcessModule mod in proc.Modules)
            {
                if (ct.IsCancellationRequested) break;
                try { hits += CheckModuleTls(proc, hProcess, procExe, mod, ctx); }
                catch { }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckModuleTls(Process proc, IntPtr hProcess, string procExe,
        ProcessModule mod, ScanContext ctx)
    {
        try
        {
            var modBase = mod.BaseAddress;

            // Read PE header (first 0x1000 bytes covers header and data directories)
            var header = new byte[0x1000];
            if (!ReadProcessMemory(hProcess, modBase, header, header.Length, out int hRead)
                || hRead < 0x200) return 0;

            // Validate MZ signature
            if (header[0] != 'M' || header[1] != 'Z') return 0;

            int e_lfanew = BitConverter.ToInt32(header, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 0x108 > hRead) return 0;

            // Validate PE signature
            if (header[e_lfanew]     != 'P' || header[e_lfanew + 1] != 'E' ||
                header[e_lfanew + 2] != 0   || header[e_lfanew + 3] != 0)
                return 0;

            // Determine architecture
            ushort machine = BitConverter.ToUInt16(header, e_lfanew + 4);
            bool is64 = machine == 0x8664;
            if (!is64 && machine != 0x14C) return 0;

            // Locate DataDirectory[TLS] in OptionalHeader
            // x64 OptionalHeader: IMAGE_NT_HEADERS64.OptionalHeader starts at e_lfanew+24
            //   Magic(2) + MajorLinkerVer(1) + MinorLinkerVer(1) + SizeOfCode(4) +
            //   SizeOfInitializedData(4) + SizeOfUninitializedData(4) + AddressOfEntryPoint(4) +
            //   BaseOfCode(4) [no BaseOfData in x64] + ImageBase(8) + SectionAlignment(4) +
            //   FileAlignment(4) + MajorOSVer(2) + MinorOSVer(2) + MajorImageVer(2) +
            //   MinorImageVer(2) + MajorSubsystemVer(2) + MinorSubsystemVer(2) +
            //   Win32VersionValue(4) + SizeOfImage(4) + SizeOfHeaders(4) + CheckSum(4) +
            //   Subsystem(2) + DllCharacteristics(2) + SizeOfStackReserve(8) +
            //   SizeOfStackCommit(8) + SizeOfHeapReserve(8) + SizeOfHeapCommit(8) +
            //   LoaderFlags(4) + NumberOfRvaAndSizes(4) = 0x70 bytes before DataDirectory
            // x86: same but without 4 extra bytes for BaseOfData and 8→4 byte fields
            //   total = 0x60 bytes before DataDirectory
            int optHeaderStart = e_lfanew + 24;
            int ddStart = optHeaderStart + (is64 ? 0x70 : 0x60);
            int tlsDdOffset = ddStart + IMAGE_DIRECTORY_ENTRY_TLS * 8;
            if (tlsDdOffset + 8 > hRead) return 0;

            uint tlsRva  = BitConverter.ToUInt32(header, tlsDdOffset);
            uint tlsSize = BitConverter.ToUInt32(header, tlsDdOffset + 4);
            if (tlsRva == 0 || tlsSize < 4) return 0;

            // Read IMAGE_TLS_DIRECTORY from the process
            // x64 IMAGE_TLS_DIRECTORY64 layout (40 bytes total):
            //   StartAddressOfRawData  ULONGLONG  +0
            //   EndAddressOfRawData    ULONGLONG  +8
            //   AddressOfIndex         ULONGLONG  +16
            //   AddressOfCallBacks     ULONGLONG  +24  ← we need this
            //   SizeOfZeroFill         DWORD      +32
            //   Characteristics        DWORD      +36
            // x86 IMAGE_TLS_DIRECTORY32 layout (24 bytes):
            //   StartAddressOfRawData  DWORD      +0
            //   EndAddressOfRawData    DWORD      +4
            //   AddressOfIndex         DWORD      +8
            //   AddressOfCallBacks     DWORD      +12 ← we need this
            //   SizeOfZeroFill         DWORD      +16
            //   Characteristics        DWORD      +20
            int tlsDirSize = is64 ? 40 : 24;
            var tlsBuf = new byte[tlsDirSize];
            var tlsAddr = new IntPtr(modBase.ToInt64() + tlsRva);
            if (!ReadProcessMemory(hProcess, tlsAddr, tlsBuf, tlsDirSize, out int tlsRead)
                || tlsRead < tlsDirSize) return 0;

            int cbPtrOffset = is64 ? 24 : 12;
            long cbArrayVA = is64
                ? BitConverter.ToInt64(tlsBuf, cbPtrOffset)
                : (long)BitConverter.ToUInt32(tlsBuf, cbPtrOffset);
            if (cbArrayVA == 0) return 0;

            // Check that the TLS directory itself is in image memory (anti-tampering)
            if (VirtualQueryEx(hProcess, tlsAddr, out var tlsMbi,
                (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()))
            {
                if (tlsMbi.State == MEM_COMMIT && tlsMbi.Type != MEM_IMAGE)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "TLS-Callback-Missbrauch-Erkennung",
                        Title    = $"TLS-Verzeichnis in privatem Speicher: {mod.ModuleName}",
                        Risk     = RiskLevel.Critical,
                        Location = $"PID {proc.Id}: {mod.ModuleName}!TLS-Dir @ 0x{tlsAddr.ToInt64():X}",
                        Reason   = $"Modul '{mod.ModuleName}' in '{procExe}' hat TLS-Verzeichnis " +
                                   $"@ 0x{tlsAddr.ToInt64():X} in privatem Speicher " +
                                   $"(MemType=0x{tlsMbi.Type:X}). " +
                                   "Das TLS-Verzeichnis sollte immer im Image-Speicher des Moduls liegen. " +
                                   "Ein privates TLS-Verzeichnis deutet auf reflektive DLL-Injektion " +
                                   "hin — das Modul wurde manuell gemappt, nicht vom OS-Loader geladen.",
                        Detail   = $"Modul={mod.ModuleName} | TLSdir_RVA=0x{tlsRva:X} | " +
                                   $"TLSdir_VA=0x{tlsAddr.ToInt64():X} | MemType=0x{tlsMbi.Type:X}"
                    });
                    return 1;
                }
            }

            // Read the null-terminated callback pointer array
            int ptrSize = is64 ? 8 : 4;
            int readBytes = MaxCallbacksPerModule * ptrSize + ptrSize; // +1 null terminator
            var cbBuf = new byte[readBytes];
            if (!ReadProcessMemory(hProcess, new IntPtr(cbArrayVA), cbBuf, readBytes,
                out int cbRead) || cbRead < ptrSize) return 0;

            int hits = 0;
            for (int i = 0; i + ptrSize <= cbRead && i < MaxCallbacksPerModule * ptrSize;
                 i += ptrSize)
            {
                long cbAddr = is64
                    ? BitConverter.ToInt64(cbBuf, i)
                    : (long)BitConverter.ToUInt32(cbBuf, i);
                if (cbAddr == 0) break; // null-terminated

                var cbPtr = new IntPtr(cbAddr);
                if (!VirtualQueryEx(hProcess, cbPtr, out var cbMbi,
                    (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>())) continue;

                if (cbMbi.State == MEM_COMMIT && cbMbi.Type != MEM_IMAGE)
                {
                    int cbIndex = i / ptrSize;
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "TLS-Callback-Missbrauch-Erkennung",
                        Title    = $"TLS-Callback in privatem Speicher: {mod.ModuleName} in {procExe}",
                        Risk     = RiskLevel.Critical,
                        Location = $"PID {proc.Id}: {mod.ModuleName}!TLS[{cbIndex}] @ 0x{cbAddr:X}",
                        Reason   = $"'{mod.ModuleName}' in '{procExe}' (PID {proc.Id}): " +
                                   $"TLS-Callback #{cbIndex} zeigt auf 0x{cbAddr:X} " +
                                   $"in privatem Speicher (MemType=0x{cbMbi.Type:X}). " +
                                   "TLS-Callbacks werden vom Windows-Loader VOR dem Einstiegspunkt " +
                                   "(OEP/DllMain) aufgerufen. " +
                                   "Mögliche Szenarien: " +
                                   "(1) Anti-Cheat-DLL-TLS wurde auf Shellcode umgeleitet " +
                                   "(AC-Neutralisierung), " +
                                   "(2) Injiziertes Modul führt Code vor Anti-Cheat-Init aus, " +
                                   "(3) Manuell gemapptes PE mit synthetischem TLS-Verzeichnis.",
                        Detail   = $"Modul={mod.ModuleName} | TLS[{cbIndex}]=0x{cbAddr:X} | " +
                                   $"MemType=0x{cbMbi.Type:X} | Protect=0x{cbMbi.Protect:X} | " +
                                   $"Prozess={procExe} PID={proc.Id}"
                    });

                    if (hits >= 3) break; // Cap per module to avoid flooding
                }
            }
            return hits;
        }
        catch { return 0; }
    }
}
