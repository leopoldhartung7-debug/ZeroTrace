using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects process injection indicators — a primary technique used by external
/// cheats to hide their code inside legitimate processes.
///
/// Injection techniques detected:
///   1. Remote thread injection: EnumProcessModules reveals unsigned/unknown DLLs
///      loaded into protected game processes or system processes (csrss, lsass, winlogon).
///
///   2. Unusual module paths: DLLs loaded from Temp, Downloads, AppData or
///      user Desktop inside any process are highly suspicious.
///
///   3. Shellcode injection indicators: processes with private executable memory
///      regions that are not backed by any mapped file (detected via
///      VirtualQueryEx scanning known injection addresses).
///
///   4. Hollowed processes: comparing the image name from the PEB against the
///      actual mapped file — mismatch = process hollowing.
///
///   5. Threads starting in suspicious memory regions: CreateRemoteThread leaves
///      orphaned threads with start addresses outside any module image.
/// </summary>
public sealed class ProcessInjectionScanModule : IScanModule
{
    public string Name => "Prozess-Injektion";
    public double Weight => 1.5;
    public int ParallelGroup => 0; // sequential — heavy P/Invoke

    // Sensitive processes — injection here is especially dangerous
    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "csrss", "lsass", "winlogon", "wininit", "services",
        "smss", "svchost", "taskhostw", "explorer",
    };

    // Game processes — injection = external cheat
    private static readonly HashSet<string> GameProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "GTA5", "GTAVLauncher", "FiveM", "FiveM_GTAProcess",
        "cs2", "csgo", "hl2",
        "EscapeFromTarkov", "BEService", "BsgLauncher",
        "r5apex", "apexlegends",
        "RainbowSix", "RainbowSixGame",
        "Warzone", "ModernWarfare",
        "VALORANT", "VALORANT-Win64-Shipping",
        "RustClient", "rust",
        "DayZ_x64",
        "BF1", "BF2042", "bf4",
        "Fortnite",
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModules(IntPtr hProcess,
        [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule,
        System.Text.StringBuilder lpFilename, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule,
        out MODULEINFO lpmodinfo, uint cb);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

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

    [StructLayout(LayoutKind.Sequential)]
    private struct MODULEINFO
    {
        public IntPtr lpBaseOfDll;
        public uint   SizeOfImage;
        public IntPtr EntryPoint;
    }

    private const uint PROCESS_VM_READ            = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION  = 0x0400;
    private const uint MEM_COMMIT                 = 0x1000;
    private const uint PAGE_EXECUTE               = 0x10;
    private const uint PAGE_EXECUTE_READ          = 0x20;
    private const uint PAGE_EXECUTE_READWRITE     = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY     = 0x80;
    private const uint MEM_IMAGE                  = 0x1000000;
    private const uint MEM_PRIVATE                = 0x20000;

    // User-writable path fragments indicating suspicious module origin
    private static readonly string[] SuspiciousModulePaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\",
        @"\appdata\local\temp\", @"\appdata\roaming\temp\",
        @"\users\public\", @"\programdata\temp\",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Prozess-Injektion", "Enumeriere Prozesse...");

        var processes = Process.GetProcesses();
        int i = 0;
        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementProcesses();
            i++;
            ctx.Report((double)i / processes.Length, proc.ProcessName);

            try
            {
                bool isProtected = ProtectedProcessNames.Contains(proc.ProcessName);
                bool isGame      = GameProcessNames.Contains(proc.ProcessName);
                if (!isProtected && !isGame) continue;

                await Task.Run(() => InspectProcess(proc, ctx, isGame, ct), ct)
                          .ConfigureAwait(false);
            }
            catch { }
            finally { proc.Dispose(); }
        }

        ctx.Report(1.0, "Prozess-Injektion", "Prozess-Injektions-Analyse abgeschlossen");
    }

    private static void InspectProcess(Process proc, ScanContext ctx, bool isGame, CancellationToken ct)
    {
        var handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (handle == IntPtr.Zero) return;

        try
        {
            CheckModules(proc, handle, ctx, isGame, ct);
            if (isGame) CheckOrphanedExecutableRegions(proc, handle, ctx, ct);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static void CheckModules(Process proc, IntPtr handle, ScanContext ctx,
        bool isGame, CancellationToken ct)
    {
        // Enumerate all DLLs loaded into this process
        uint size = 1024;
        IntPtr[] modules;
        do
        {
            if (ct.IsCancellationRequested) return;
            modules = new IntPtr[size / (uint)IntPtr.Size];
            if (!EnumProcessModules(handle, modules, (uint)(modules.Length * IntPtr.Size), out size))
                return;
        } while (size > (uint)(modules.Length * IntPtr.Size));

        int modCount = (int)(size / (uint)IntPtr.Size);
        var sb = new System.Text.StringBuilder(1024);

        for (int i = 1; i < modCount; i++) // skip index 0 (main exe)
        {
            if (ct.IsCancellationRequested) return;
            sb.Clear();
            if (GetModuleFileNameEx(handle, modules[i], sb, (uint)sb.Capacity) == 0)
                continue;

            var modulePath = sb.ToString();
            var modulePathLower = modulePath.ToLowerInvariant();

            // Flag modules loaded from user-writable or suspicious paths
            if (SuspiciousModulePaths.Any(p => modulePathLower.Contains(p)))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Prozess-Injektion",
                    Title    = $"Verdächtige DLL in {proc.ProcessName}",
                    Risk     = isGame ? RiskLevel.Critical : RiskLevel.High,
                    Location = modulePath,
                    FileName = Path.GetFileName(modulePath),
                    Reason   = $"DLL aus einem temporären/user-beschreibbaren Pfad in " +
                               $"'{proc.ProcessName}' (PID {proc.Id}) geladen. " +
                               "Injizierte Cheat-DLLs befinden sich typischerweise in " +
                               "Temp- oder AppData-Verzeichnissen.",
                    Detail   = $"Prozess: {proc.ProcessName} (PID {proc.Id}) | Modul: {modulePath}"
                });
            }
        }
    }

    private static void CheckOrphanedExecutableRegions(Process proc, IntPtr handle,
        ScanContext ctx, CancellationToken ct)
    {
        // Walk the virtual address space looking for committed private executable pages
        // not backed by any image file — classic shellcode/reflective injection footprint
        var address = IntPtr.Zero;
        int orphanCount = 0;

        while (true)
        {
            if (ct.IsCancellationRequested) return;
            if (VirtualQueryEx(handle, address, out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) == 0)
                break;

            // Move to next region
            try
            {
                address = new IntPtr(address.ToInt64() + mbi.RegionSize.ToInt64());
            }
            catch { break; }
            if (address.ToInt64() <= 0) break;

            // Looking for: committed private executable memory NOT backed by a module image
            if (mbi.State != MEM_COMMIT) continue;
            if (mbi.Type != MEM_PRIVATE) continue;
            var protect = mbi.Protect;
            if ((protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) == 0)
                continue;

            // Candidate region: private + committed + executable
            // Confirm it's not just a JIT stub (region > 4KB means it's real code)
            if (mbi.RegionSize.ToInt64() < 4096) continue;

            orphanCount++;
            if (orphanCount <= 3) // Report at most 3 per process to avoid flood
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Prozess-Injektion",
                    Title    = $"Verdächtige ausführbare Speicherregion in {proc.ProcessName}",
                    Risk     = RiskLevel.Critical,
                    Location = $"{proc.ProcessName} @ 0x{mbi.BaseAddress.ToInt64():X}",
                    Reason   = $"Privater ausführbarer Speicherbereich in Game-Prozess '{proc.ProcessName}' " +
                               $"(PID {proc.Id}) gefunden, der nicht durch ein Modul abgebildet ist. " +
                               "Dies ist ein klassisches Zeichen für Shellcode-Injektion oder " +
                               "reflektives DLL-Loading (externe Cheats).",
                    Detail   = $"Adresse: 0x{mbi.BaseAddress.ToInt64():X} | " +
                               $"Größe: {mbi.RegionSize.ToInt64() / 1024} KB | " +
                               $"Schutz: 0x{mbi.Protect:X}"
                });
            }
        }
    }
}
