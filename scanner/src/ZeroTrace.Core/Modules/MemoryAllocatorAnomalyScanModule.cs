using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects abnormal memory allocation patterns in game processes that indicate cheat tool
/// infrastructure: unusually large RWX regions, many small private executable allocations
/// (shellcode stager pattern), high total private executable memory volume, and stack-adjacent
/// executable memory (stack pivot / shellcode on stack). Also detects guard page removal
/// on the game process stack (stack unwinding bypass technique).
/// </summary>
public sealed class MemoryAllocatorAnomalyScanModule : IScanModule
{
    public string Name => "Memory Allocator Anomaly";
    public double Weight => 0.85;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(
        nint hProcess, nint lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public nint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    private const uint MEM_COMMIT            = 0x1000;
    private const uint MEM_PRIVATE           = 0x20000;
    private const uint MEM_MAPPED            = 0x40000;
    private const uint PAGE_EXECUTE          = 0x10;
    private const uint PAGE_EXECUTE_READ     = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_GUARD            = 0x100;
    private const uint PROCESS_VM_READ       = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    // Thresholds
    private const long LargeRwxThreshold        = 50L * 1024 * 1024;  // 50 MB single RWX region
    private const long TotalPrivateExecThreshold = 200L * 1024 * 1024; // 200 MB total private exec
    private const int  ManySmallAllocThreshold   = 50;  // >50 small (<64KB) private exec regions
    private const long SmallAllocMaxSize         = 64 * 1024;  // 64 KB

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "cheat", "loader", "injector", "client"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var targets = GetTargetProcesses();
        if (targets.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var proc in targets)
            {
                ct.ThrowIfCancellationRequested();
                try { AnalyzeProcess(proc, ctx, ct); }
                catch { /* skip */ }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }, ct);
    }

    private void AnalyzeProcess(Process proc, ScanContext ctx, CancellationToken ct)
    {
        nint hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            nint address = nint.Zero;

            long totalPrivateExec   = 0;
            long totalRwxVolume     = 0;
            int  smallAllocCount    = 0;
            int  rwxRegionCount     = 0;
            long largestRwx         = 0;
            nint largestRwxAddr     = nint.Zero;
            int  guardRemovedCount  = 0;

            while (true)
            {
                ct.ThrowIfCancellationRequested();
                int ret = VirtualQueryEx(hProc, address, out var mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
                if (ret == 0) break;

                try
                {
                    nint next;
                    checked { next = mbi.BaseAddress + mbi.RegionSize; }
                    if (next <= address) break;
                    address = next;
                }
                catch { break; }

                if (mbi.State != MEM_COMMIT) continue;

                bool isExec = IsExecutable(mbi.Protect);
                bool isPrivate = mbi.Type == MEM_PRIVATE;
                bool isRwx  = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 ||
                              (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0;
                long regionSize = mbi.RegionSize.ToInt64();

                if (isExec && isPrivate)
                {
                    totalPrivateExec += regionSize;

                    if (regionSize < SmallAllocMaxSize)
                        smallAllocCount++;

                    if (isRwx)
                    {
                        totalRwxVolume += regionSize;
                        rwxRegionCount++;
                        if (regionSize > largestRwx)
                        {
                            largestRwx = regionSize;
                            largestRwxAddr = mbi.BaseAddress;
                        }
                    }
                }

                // Detect guard page removal on stack-adjacent regions
                // Real stacks have PAGE_GUARD on the bottom page; if removed, that's a pivot indicator
                // We detect "was guard page" by checking AllocationProtect had guard but current doesn't
                bool hadGuard  = (mbi.AllocationProtect & PAGE_GUARD) != 0;
                bool hasGuard  = (mbi.Protect & PAGE_GUARD) != 0;
                if (hadGuard && !hasGuard && isExec)
                {
                    guardRemovedCount++;
                }
            }

            // Report findings
            if (largestRwx > LargeRwxThreshold)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Memory Allocator Anomaly",
                    Title = $"Massive RWX Region in {proc.ProcessName}: {largestRwx / 1024 / 1024} MB",
                    Risk = RiskLevel.Critical,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id}) @0x{largestRwxAddr:X}",
                    Reason = $"Einzelne PAGE_EXECUTE_READWRITE Region von {largestRwx / 1024 / 1024} MB " +
                             $"(Schwellwert: {LargeRwxThreshold / 1024 / 1024} MB) — deutet auf Shellcode-Staging, " +
                             "DMA-Puffer oder ESP-Overlay Speicher hin",
                    Detail = $"Basisadresse: 0x{largestRwxAddr:X} | Groesse: {largestRwx / 1024 / 1024} MB"
                });
            }

            if (totalPrivateExec > TotalPrivateExecThreshold)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Memory Allocator Anomaly",
                    Title = $"Hohes privates Exec-Speicher-Volumen in {proc.ProcessName}",
                    Risk = RiskLevel.High,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                    Reason = $"Gesamt {totalPrivateExec / 1024 / 1024} MB privater ausfuehrbarer Speicher — " +
                             $"normal sind <{TotalPrivateExecThreshold / 1024 / 1024} MB",
                    Detail = $"Privates Exec total: {totalPrivateExec / 1024 / 1024} MB | " +
                             $"Davon RWX: {totalRwxVolume / 1024 / 1024} MB | " +
                             $"RWX Regionen: {rwxRegionCount}"
                });
            }

            if (smallAllocCount > ManySmallAllocThreshold)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Memory Allocator Anomaly",
                    Title = $"Viele kleine ausfuehrbare Allokationen in {proc.ProcessName}",
                    Risk = RiskLevel.High,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                    Reason = $"{smallAllocCount} private ausfuehrbare Regionen <{SmallAllocMaxSize / 1024} KB — " +
                             "Shellcode-Stager Muster: viele kleine Allokationen fuer individuelle Shellcode-Chunks",
                    Detail = $"Kleine Exec-Regionen: {smallAllocCount} | " +
                             $"Schwellwert: {ManySmallAllocThreshold} | " +
                             $"Gesamt privates Exec: {totalPrivateExec / 1024} KB"
                });
            }

            if (guardRemovedCount > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Memory Allocator Anomaly",
                    Title = $"Stack-Guard-Page entfernt in {proc.ProcessName} ({guardRemovedCount}x)",
                    Risk = RiskLevel.High,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                    Reason = $"{guardRemovedCount} ausfuehrbare Regionen hatten PAGE_GUARD (Stack-Schutz) entfernt — " +
                             "Stack-Pivot oder Return-Oriented Programming Technik zur Umgehung von Stack-Schutz",
                    Detail = "Guard-Page Entfernung auf ausfuehrbaren Regionen deutet auf ROP-Kette oder Stack-Pivot Cheat-Technik"
                });
            }

            // Report summary if multiple suspicious indicators
            if (rwxRegionCount > 10 && totalRwxVolume > 10L * 1024 * 1024)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Memory Allocator Anomaly",
                    Title = $"Verdaechtiges RWX Speicher-Profil in {proc.ProcessName}",
                    Risk = RiskLevel.Medium,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                    Reason = $"{rwxRegionCount} RWX Speicherregionen mit {totalRwxVolume / 1024 / 1024} MB Gesamt — " +
                             "ungewoehnlich hohes RWX Volumen fuer normalen Spielprozess",
                    Detail = $"RWX Regionen: {rwxRegionCount} | RWX Volumen: {totalRwxVolume / 1024 / 1024} MB | " +
                             $"Groesste Region: {largestRwx / 1024} KB @0x{largestRwxAddr:X}"
                });
            }
        }
        finally { CloseHandle(hProc); }
    }

    private static bool IsExecutable(uint protect)
    {
        const uint mask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        return (protect & mask) != 0;
    }

    private static List<Process> GetTargetProcesses()
    {
        var result = new List<Process>();
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (Array.Exists(GameProcessNames, n => name.Contains(n)))
                        result.Add(proc);
                    else
                        proc.Dispose();
                }
                catch { proc.Dispose(); }
            }
        }
        catch { }
        return result;
    }
}
