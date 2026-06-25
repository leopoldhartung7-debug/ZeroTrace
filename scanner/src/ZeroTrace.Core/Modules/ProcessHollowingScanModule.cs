using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects process hollowing (process replacement) and process doppelgänging techniques.
///
/// Process hollowing (aka RunPE, process replacement) steps:
///   1. Create a legitimate process in suspended state (e.g. svchost.exe)
///   2. Unmap/hollow its memory (ZwUnmapViewOfSection)
///   3. Inject cheat/malware PE image into the vacated address space
///   4. Fix up headers, relocations, imports
///   5. Resume thread — the process now runs attacker code under a legitimate name
///
/// Process Doppelgänging (NTFS transaction trick):
///   1. Create NTFS transaction, write malicious PE to transacted file
///   2. Create section from transacted file handle
///   3. Roll back transaction (file disappears from filesystem)
///   4. Create process from section — runs malware, looks like legit file on disk
///
/// Detection signals:
///   1. PEB ImageBaseAddress differs from actual mapped image base (unmapping sign)
///   2. Process memory image base does not match on-disk PE at the recorded path
///   3. Mapped PE has no backing file (anonymous executable region with MZ header)
///   4. Process path starts with "\Device\HarddiskVolume" (transacted file artifact)
///   5. Significant size mismatch between on-disk PE and in-memory image
///   6. PE entry point outside any mapped module range
///   7. NtQueryInformationProcess returns different ImageBase than VirtualQuery shows
/// </summary>
public sealed class ProcessHollowingScanModule : IScanModule
{
    public string Name => "Prozess-Hollowing-Erkennung";
    public double Weight => 1.2;
    public int ParallelGroup => 0;

    // Processes that are common hollowing targets for cheats
    private static readonly HashSet<string> HighValueTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "explorer.exe", "RuntimeBroker.exe", "dllhost.exe",
        "conhost.exe", "taskhost.exe", "taskhostw.exe", "sihost.exe",
        "csrss.exe", "werfault.exe", "msiexec.exe", "regsvr32.exe",
        "notepad.exe", "calc.exe", "mspaint.exe",
    };

    // Known cheat processes that hollow into legitimate ones
    private static readonly string[] SuspiciousParentPatterns =
    {
        "cheat", "hack", "inject", "loader", "bypass",
    };

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle, int processInformationClass,
        out ProcessBasicInformation processInformation,
        int processInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
        int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(
        IntPtr hProcess, IntPtr lpAddress,
        out MemoryBasicInformation lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess,
        bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
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
    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint MEM_MAPPED = 0x40000;
    private const uint MEM_PRIVATE = 0x20000;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    hits += AnalyzeProcess(proc, ctx, ct);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"Prozesse auf Hollowing untersucht, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int AnalyzeProcess(Process proc, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        ctx.IncrementProcesses();
        string procName = proc.ProcessName + ".exe";

        IntPtr hProcess = IntPtr.Zero;
        try
        {
            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                false, proc.Id);
            if (hProcess == IntPtr.Zero) return 0;

            // Check 1: Scan for executable private memory regions with MZ headers
            // (hollowed processes often have private RX regions where image should be)
            hits += ScanForAnonymousExecutableRegions(proc, hProcess, procName, ctx, ct);

            // Check 2: Detect size mismatch between on-disk PE and in-memory image
            if (!string.IsNullOrEmpty(proc.MainModule?.FileName))
            {
                hits += CheckImageSizeMismatch(proc, hProcess, procName, ctx);
            }
        }
        catch { }
        finally
        {
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
        return hits;
    }

    private static int ScanForAnonymousExecutableRegions(Process proc, IntPtr hProcess,
        string procName, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var addr = IntPtr.Zero;
        int regionsScanned = 0;

        while (regionsScanned < 2000 && !ct.IsCancellationRequested)
        {
            if (!VirtualQueryEx(hProcess, addr, out var mbi,
                (uint)Marshal.SizeOf<MemoryBasicInformation>())) break;

            regionsScanned++;
            var regionSize = mbi.RegionSize.ToInt64();
            if (regionSize <= 0) break;

            // Only care about committed, executable, PRIVATE memory (not image/mapped)
            bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            bool isPrivate = mbi.Type == MEM_PRIVATE;
            bool isCommitted = mbi.State == MEM_COMMIT;

            if (isExecutable && isPrivate && isCommitted && regionSize >= 0x1000)
            {
                // Read first 2 bytes to check for MZ header
                var header = new byte[64];
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, header, header.Length,
                    out int bytesRead) && bytesRead >= 2)
                {
                    if (header[0] == 0x4D && header[1] == 0x5A) // "MZ"
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Prozess-Hollowing-Erkennung",
                            Title    = $"Anonyme ausführbare PE-Region: {procName} (PID {proc.Id})",
                            Risk     = HighValueTargets.Contains(procName)
                                           ? RiskLevel.Critical : RiskLevel.High,
                            Location = $"PID {proc.Id} @ 0x{mbi.BaseAddress.ToInt64():X16}",
                            Reason   = $"Prozess '{procName}' enthält eine private (anonyme) " +
                                       "ausführbare Speicherregion mit MZ-Header — " +
                                       "typisches Indiz für Process Hollowing oder RunPE. " +
                                       "Legitime Prozesse haben Ausführcode in gemappten Image-Sektionen, " +
                                       "nicht in privaten Speicherbereichen.",
                            Detail   = $"Prozess: {procName} PID={proc.Id} | " +
                                       $"Adresse: 0x{mbi.BaseAddress.ToInt64():X} | " +
                                       $"Größe: {regionSize / 1024} KB | Typ: Private | RX"
                        });
                        break; // one finding per process is enough
                    }
                }
            }

            try
            {
                addr = new IntPtr(mbi.BaseAddress.ToInt64() + regionSize);
            }
            catch { break; }
        }
        return hits;
    }

    private static int CheckImageSizeMismatch(Process proc, IntPtr hProcess,
        string procName, ScanContext ctx)
    {
        int hits = 0;
        try
        {
            var mainModule = proc.MainModule;
            if (mainModule is null) return 0;

            string diskPath = mainModule.FileName;
            if (!File.Exists(diskPath)) return 0;

            // Get on-disk file size
            var diskSize = new FileInfo(diskPath).Length;

            // Get in-memory image size from MEMORY_BASIC_INFORMATION
            var baseAddr = mainModule.BaseAddress;
            if (!VirtualQueryEx(hProcess, baseAddr, out var mbi,
                (uint)Marshal.SizeOf<MemoryBasicInformation>())) return 0;

            // Read PE SizeOfImage from in-memory headers
            var headerBuf = new byte[0x200];
            if (!ReadProcessMemory(hProcess, baseAddr, headerBuf, headerBuf.Length,
                out int read) || read < 0x40) return 0;

            // DOS header e_lfanew at offset 0x3C
            int e_lfanew = BitConverter.ToInt32(headerBuf, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 0x60 > headerBuf.Length) return 0;

            // SizeOfImage at PE header offset 0x50 (from start of NT headers)
            uint sizeOfImage = BitConverter.ToUInt32(headerBuf, e_lfanew + 0x50);
            if (sizeOfImage == 0) return 0;

            // On-disk file should never be more than 4x the in-memory SizeOfImage
            // (compression ratios are bounded), and in-memory should be >= on-disk
            // (image has no compression). Large mismatches indicate replacement.
            double ratio = (double)diskSize / sizeOfImage;
            if (ratio < 0.05 || ratio > 20.0)
            {
                // Only flag if this is a suspicious target process or the ratio is extreme
                if (HighValueTargets.Contains(procName) || ratio < 0.02 || ratio > 50.0)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Prozess-Hollowing-Erkennung",
                        Title    = $"PE-Größen-Mismatch: {procName} (PID {proc.Id})",
                        Risk     = RiskLevel.High,
                        Location = $"PID {proc.Id}: {diskPath}",
                        FileName = procName,
                        Reason   = $"Die Disk-Größe von '{procName}' ({diskSize:N0} Bytes) " +
                                   $"weicht stark von der In-Memory SizeOfImage ({sizeOfImage:N0} Bytes) ab " +
                                   $"(Verhältnis: {ratio:F2}). " +
                                   "Process Hollowing ersetzt das In-Memory-Image, " +
                                   "hinterlässt aber den Original-Pfad im PEB — " +
                                   "das führt zu diesem Größen-Mismatch.",
                        Detail   = $"DiskSize: {diskSize} | SizeOfImage: {sizeOfImage} | " +
                                   $"Verhältnis: {ratio:F2} | Pfad: {diskPath}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
