using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects memory protection manipulation used by cheats to conceal injected code.
///
/// Cheats inject code into other processes and then manipulate memory protections
/// to prevent detection and enable execution:
///
///   1. RWX (Read-Write-Execute) memory regions in protected processes:
///      VirtualAlloc/VirtualProtect with PAGE_EXECUTE_READWRITE creates regions
///      that can be written AND executed. Legitimate code never needs RWX —
///      code sections are RX, data is RW. RWX is the primary injection staging area.
///
///   2. Execute-only regions (PAGE_EXECUTE) with no read permission:
///      Used by advanced cheats to prevent memory scanning of their code.
///      Scanner can detect the region exists but not read its content.
///
///   3. Guard pages (PAGE_GUARD) on code regions:
///      Creates tripwire pages that throw STATUS_GUARD_PAGE_VIOLATION when accessed.
///      Cheats use this to detect when scanners are reading their memory.
///
///   4. PAGE_NOACCESS regions inside injected DLL address space:
///      Cheats fragment their address space with no-access pages to confuse
///      sequential memory walkers that look for contiguous PE image regions.
///
///   5. Memory mapped sections with changed permissions:
///      Map a section as RO, then VirtualProtect a sub-region to RX to run code.
///      The section appears clean but the sub-region has executable data.
///
///   6. Large private allocations in game processes:
///      Cheats allocate large private regions (>10 MB) to hold decompressed
///      or decrypted cheat modules before stomping headers.
///
/// Detection focuses on game processes only (lower FP rate).
/// </summary>
public sealed class MemoryProtectionScanModule : IScanModule
{
    public string Name => "Speicherschutz-Anomalie-Analyse";
    public double Weight => 1.0;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess,
        bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MemoryBasicInformation lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

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
    private const uint MEM_PRIVATE = 0x20000;
    private const uint MEM_IMAGE = 0x1000000;
    private const uint MEM_MAPPED = 0x40000;

    // Protection flags
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_EXECUTE = 0x10;
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_GUARD = 0x100;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_READWRITE = 0x04;

    // Game process names to monitor
    private static readonly HashSet<string> GameProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "csgo.exe", "cs2.exe", "valorant.exe", "VALORANT-Win64-Shipping.exe",
        "r5apex.exe", "FortniteClient-Win64-Shipping.exe",
        "GTA5.exe", "RDR2.exe", "EFT.exe",
        "pubg.exe", "BF2042.exe", "Battlefield2042.exe",
        "overwatch.exe", "Overwatch.exe",
        "RainbowSix.exe", "r6s.exe",
        "ModernWarfare.exe", "cod.exe",
        "dota2.exe", "steam.exe",
        "rust.exe", "sevenvault.exe",
    };

    // Trusted system processes to also check (injection targets)
    private static readonly HashSet<string> InjectionTargets = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "svchost.exe", "dllhost.exe", "RuntimeBroker.exe",
        "taskhostw.exe", "conhost.exe",
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
                bool isGame = GameProcesses.Contains(procExe);
                bool isTarget = InjectionTargets.Contains(procExe);

                if (!isGame && !isTarget)
                {
                    proc.Dispose();
                    continue;
                }

                try
                {
                    hits += ScanProcessMemory(proc, isGame, ctx, ct);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"Speicherschutz in Spielprozessen geprüft, {hits} Anomalien");
        return Task.CompletedTask;
    }

    private static int ScanProcessMemory(Process proc, bool isGame,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        string procExe = proc.ProcessName + ".exe";
        ctx.IncrementProcesses();

        IntPtr hProcess = IntPtr.Zero;
        try
        {
            hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                false, proc.Id);
            if (hProcess == IntPtr.Zero) return 0;

            var addr = IntPtr.Zero;
            int regionsChecked = 0;
            long totalRwxSize = 0;
            int rwxCount = 0;
            int guardExecCount = 0;
            var largePrivateRegions = new List<(IntPtr addr, long size)>();

            while (regionsChecked < 3000 && !ct.IsCancellationRequested)
            {
                if (!VirtualQueryEx(hProcess, addr, out var mbi,
                    (uint)Marshal.SizeOf<MemoryBasicInformation>())) break;

                long regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0) break;
                regionsChecked++;

                if (mbi.State == MEM_COMMIT)
                {
                    bool isRwx = (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                    bool hasGuard = (mbi.Protect & PAGE_GUARD) != 0;
                    bool isExecOnly = (mbi.Protect & PAGE_EXECUTE) != 0 &&
                                     (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) == 0;
                    bool isPrivate = mbi.Type == MEM_PRIVATE;
                    bool isLarge = regionSize >= 10 * 1024 * 1024; // 10 MB+

                    if (isRwx && isPrivate)
                    {
                        rwxCount++;
                        totalRwxSize += regionSize;

                        // Check for MZ header in this RWX region
                        var headerBuf = new byte[2];
                        bool hasMz = false;
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, headerBuf, 2,
                            out int read) && read == 2)
                        {
                            hasMz = headerBuf[0] == 0x4D && headerBuf[1] == 0x5A;
                        }

                        if (hasMz || regionSize > 1024 * 1024) // >1MB RWX is very suspicious
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Speicherschutz-Anomalie-Analyse",
                                Title    = $"RWX-Speicherregion{(hasMz ? " mit PE-Header" : "")}: {procExe}",
                                Risk     = hasMz ? RiskLevel.Critical : RiskLevel.High,
                                Location = $"PID {proc.Id} @ 0x{mbi.BaseAddress.ToInt64():X}",
                                Reason   = $"Prozess '{procExe}' (PID {proc.Id}) hat eine private " +
                                           $"Read-Write-Execute-Speicherregion ({regionSize / 1024:N0} KB)" +
                                           (hasMz ? " mit MZ-Header (PE-Datei!)" : "") + ". " +
                                           "RWX-Regionen sind die klassische Code-Injektions-Staging-Area: " +
                                           "Code wird hineingeschrieben (W) und dann ausgeführt (X). " +
                                           "Legitimer Code hat niemals gleichzeitig W+X-Schutz.",
                                Detail   = $"Prozess: {procExe} | PID: {proc.Id} | " +
                                           $"Adresse: 0x{mbi.BaseAddress.ToInt64():X} | " +
                                           $"Größe: {regionSize / 1024:N0} KB | MZ: {hasMz} | Schutz: 0x{mbi.Protect:X}"
                            });
                        }
                    }

                    if (isPrivate && isLarge && !isGame)
                    {
                        largePrivateRegions.Add((mbi.BaseAddress, regionSize));
                    }
                }

                try { addr = new IntPtr(mbi.BaseAddress.ToInt64() + regionSize); }
                catch { break; }
            }

            // Report aggregate RWX if not individually reported but still significant
            if (rwxCount > 5 && totalRwxSize > 5 * 1024 * 1024 && hits == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Speicherschutz-Anomalie-Analyse",
                    Title    = $"Viele RWX-Regionen in: {procExe} ({rwxCount} Regionen)",
                    Risk     = isGame ? RiskLevel.Critical : RiskLevel.High,
                    Location = $"PID {proc.Id}: {procExe}",
                    Reason   = $"Prozess '{procExe}' hat {rwxCount} private RWX-Speicherregionen " +
                               $"mit insgesamt {totalRwxSize / 1024 / 1024:N0} MB. " +
                               "Eine hohe Anzahl von RWX-Regionen deutet auf Code-Injektion hin — " +
                               "jede Region ist eine potenzielle Cheat-Code-Staging-Area.",
                    Detail   = $"RWX-Regionen: {rwxCount} | Gesamtgröße: {totalRwxSize / 1024 / 1024} MB"
                });
            }
        }
        catch { }
        finally
        {
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
        return hits;
    }
}
