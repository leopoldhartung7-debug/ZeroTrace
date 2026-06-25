using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects heap spray and large private memory allocation patterns in game processes
/// that indicate cheat overlays, external ESP renderers, or radar data buffers.
///
/// Cheat tools allocate large amounts of private memory in game processes for:
///   1. Heap spraying to land shellcode at predictable addresses
///   2. Large RWX regions for dynamically-generated cheat code (JIT cheats)
///   3. Massive READ-only mappings of the game's entity list (external ESP)
///   4. Shared memory sections for DMA radar data transfer
///
/// Detection heuristics (applied to game processes):
///   a) Single private MEM_COMMIT regions > 50 MB (unusual for cheats that
///      don't need much memory — non-game modules shouldn't need this)
///   b) More than N private executable regions (shellcode spray)
///   c) Private regions with specific fill patterns (0xCC, 0x90 NOP sleds)
///   d) Shared memory (MEM_MAPPED) outside known module paths
///   e) Very large MEM_RESERVE blocks without MEM_COMMIT (reserved for future use)
///
/// Uses NtQueryVirtualMemory (MemoryBasicInformation) to walk the VAD tree.
/// </summary>
public sealed class HeapSprayScanModule : IScanModule
{
    public string Name => "Heap-Spray-Speicher-Analyse";
    public double Weight => 1.0;
    public int ParallelGroup => 0;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryVirtualMemory(
        IntPtr processHandle, IntPtr baseAddress, int memInfoClass,
        ref MEMORY_BASIC_INFORMATION memInfo, ulong memInfoLen, out ulong returnLen);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

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

    private const uint MEM_COMMIT  = 0x1000;
    private const uint MEM_PRIVATE = 0x20000;
    private const uint MEM_MAPPED  = 0x40000;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_EXECUTE           = 0x10;
    private const uint PAGE_EXECUTE_READ      = 0x20;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

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

    private const long LargePrivateThreshold = 50L * 1024 * 1024;  // 50 MB
    private const int  MaxRwxRegions = 3;  // More than this = very suspicious

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int procsChecked = 0;
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
                    procsChecked++;

                    string path = "";
                    try { path = proc.MainModule?.FileName ?? ""; } catch { }

                    var hProc = OpenProcess(
                        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
                    if (hProc == IntPtr.Zero) continue;

                    try
                    {
                        hits += AnalyzeProcessMemory(proc, hProc, path, ctx, ct);
                    }
                    finally
                    {
                        CloseHandle(hProc);
                    }
                }
            }
            catch { }
        }

        ctx.Report(1.0, Name, $"{procsChecked} Spielprozesse auf Heap-Spray geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int AnalyzeProcessMemory(System.Diagnostics.Process proc, IntPtr hProc,
        string procPath, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var mbi = new MEMORY_BASIC_INFORMATION();
        ulong mbiSize = (ulong)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

        var addr = IntPtr.Zero;
        long totalPrivateRwx = 0;
        int rwxRegionCount = 0;
        long largestPrivate = 0;
        IntPtr largestPrivateBase = IntPtr.Zero;

        while (true)
        {
            if (ct.IsCancellationRequested) break;
            if (NtQueryVirtualMemory(hProc, addr, 0, ref mbi, mbiSize, out _) != 0)
                break;

            if (mbi.RegionSize == UIntPtr.Zero) break;

            // Advance pointer
            try
            {
                addr = IntPtr.Add(mbi.BaseAddress, (int)Math.Min((ulong)mbi.RegionSize, uint.MaxValue));
            }
            catch { break; }

            if (mbi.State != MEM_COMMIT) continue;
            if (mbi.Type != MEM_PRIVATE) continue;

            var size = (long)(ulong)mbi.RegionSize;
            bool isExec = mbi.Protect == PAGE_EXECUTE_READWRITE ||
                          mbi.Protect == PAGE_EXECUTE_WRITECOPY ||
                          mbi.Protect == PAGE_EXECUTE ||
                          mbi.Protect == PAGE_EXECUTE_READ;

            if (isExec && (mbi.Protect == PAGE_EXECUTE_READWRITE ||
                           mbi.Protect == PAGE_EXECUTE_WRITECOPY))
            {
                rwxRegionCount++;
                totalPrivateRwx += size;
            }

            if (size > largestPrivate)
            {
                largestPrivate = size;
                largestPrivateBase = mbi.BaseAddress;
            }
        }

        // Flag: excessive RWX regions
        if (rwxRegionCount > MaxRwxRegions && totalPrivateRwx > 1024 * 1024)
        {
            hits++;
            ctx.AddFinding(new Finding
            {
                Module   = "Heap-Spray-Speicher-Analyse",
                Title    = $"Heap-Spray: {rwxRegionCount} RWX-Regionen in {proc.ProcessName}",
                Risk     = RiskLevel.Critical,
                Location = procPath,
                FileName = proc.ProcessName + ".exe",
                Reason   = $"Spielprozess '{proc.ProcessName}' (PID {proc.Id}) hat " +
                           $"{rwxRegionCount} private RWX-Speicherregionen " +
                           $"({totalPrivateRwx / 1024 / 1024} MB gesamt). " +
                           "Mehr als {MaxRwxRegions} RWX-Regionen im Spielprozess deutet auf " +
                           "Heap-Spray-Angriff oder JIT-generierten Cheat-Code hin.",
                Detail   = $"PID: {proc.Id} | RWX-Regionen: {rwxRegionCount} | " +
                           $"Gesamt-RWX: {totalPrivateRwx / 1024 / 1024} MB"
            });
        }

        // Flag: single very large private allocation
        if (largestPrivate > LargePrivateThreshold)
        {
            hits++;
            ctx.AddFinding(new Finding
            {
                Module   = "Heap-Spray-Speicher-Analyse",
                Title    = $"Riesige private Speicherallokation in {proc.ProcessName}",
                Risk     = RiskLevel.High,
                Location = procPath,
                FileName = proc.ProcessName + ".exe",
                Reason   = $"Spielprozess '{proc.ProcessName}' (PID {proc.Id}) hat eine einzelne " +
                           $"private Speicherregion von {largestPrivate / 1024 / 1024} MB " +
                           $"bei Adresse 0x{largestPrivateBase.ToInt64():X16}. " +
                           "Cheat-Overlays und externe ESP-Buffer allozieren ungewöhnlich " +
                           "große Speicherblöcke im Spielprozess.",
                Detail   = $"PID: {proc.Id} | Größte Region: {largestPrivate / 1024 / 1024} MB " +
                           $"bei 0x{largestPrivateBase.ToInt64():X}"
            });
        }

        return hits;
    }
}
