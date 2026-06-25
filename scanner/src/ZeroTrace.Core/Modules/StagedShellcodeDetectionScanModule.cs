using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects staged shellcode in game processes: private executable regions whose allocation
/// protection was PAGE_EXECUTE_READWRITE (the shellcode was written there) but whose current
/// protection has been hardened to PAGE_EXECUTE_READ or PAGE_EXECUTE. This "harden after
/// write" pattern is used by sophisticated cheat loaders to reduce detection: they allocate
/// RWX memory, decrypt and write the shellcode/DLL payload, then call VirtualProtect to
/// make it appear read-only — harder to find than persistent RWX regions. Also detects
/// the classic RWX→RX transition by checking AllocationProtect == RWX while current
/// Protect is RX. Requires at least 4096 bytes (one page) to avoid false positives
/// from small JIT compiler allocations in non-game contexts.
/// </summary>
public sealed class StagedShellcodeDetectionScanModule : IScanModule
{
    public string Name => "Staged Shellcode Detection";
    public double Weight => 0.95;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualQueryEx(
        nint hProcess, nint lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        nint hProcess, nint lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

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

    private const uint MEM_COMMIT             = 0x1000;
    private const uint MEM_PRIVATE            = 0x20000;
    private const uint PAGE_EXECUTE           = 0x10;
    private const uint PAGE_EXECUTE_READ      = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_GUARD             = 0x100;
    private const uint PAGE_NOCACHE           = 0x200;
    private const uint PAGE_WRITECOMBINE      = 0x400;
    private const uint PROTECT_MODIFIER_MASK  = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
    private const uint PROCESS_VM_READ        = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    // Minimum region size to flag — avoids false positives from tiny JIT stubs
    private const int MinStagedSize = 4096; // 4 KB

    // Byte patterns that indicate shellcode (PE header, common stager opcodes)
    private static readonly byte[][] ShellcodePatterns =
    {
        new byte[] { 0x4D, 0x5A },                   // MZ header (reflective DLL)
        new byte[] { 0x50, 0x45, 0x00, 0x00 },       // PE signature
        new byte[] { 0xFC, 0x48, 0x83, 0xE4 },       // CobaltStrike x64 shellcode stager
        new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D }, // CALL $+5 / POP RBP (position-independent)
        new byte[] { 0x64, 0x48, 0x8B, 0x04, 0x25 }, // MOV RAX, GS:[...] (PEB walk x64)
        new byte[] { 0x65, 0x8B, 0x40, 0x30 },       // MOV EAX, FS:[...] (PEB walk x86)
        new byte[] { 0x48, 0x31, 0xC9, 0x48, 0x31 }, // XOR RCX,RCX / XOR ... (msfvenom pattern)
    };

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "cheat", "loader", "injector", "client",
        "battlefront", "paladins", "rocketleague", "insurgency", "deadlock",
    };

    // Processes known to use RWX-then-harden pattern legitimately
    private static readonly string[] LegitJitProcesses =
    {
        "mono", "unity", "node", "chrome", "firefox", "msedge", "java",
        "pythonw", "python", "dotnet", "powershell",
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
                try { ScanProcess(proc, ctx, ct); }
                catch { }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }, ct);
    }

    private void ScanProcess(Process proc, ScanContext ctx, CancellationToken ct)
    {
        string nameLower = proc.ProcessName.ToLowerInvariant();
        // Skip known JIT-heavy processes (too many legitimate RWX→RX transitions)
        if (Array.Exists(LegitJitProcesses, p => nameLower.Contains(p))) return;

        nint hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            nint addr = nint.Zero;
            int findingCount = 0;
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

            while (VirtualQueryEx(hProc, addr, out var mbi, mbiSize) != nint.Zero)
            {
                ct.ThrowIfCancellationRequested();
                if (findingCount >= 8) break;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    (long)mbi.RegionSize >= MinStagedSize)
                {
                    uint protect      = mbi.Protect      & ~PROTECT_MODIFIER_MASK;
                    uint allocProtect = mbi.AllocationProtect & ~PROTECT_MODIFIER_MASK;

                    bool isCurrentlyExec = protect == PAGE_EXECUTE_READ || protect == PAGE_EXECUTE;
                    bool wasAllocatedRwx = allocProtect == PAGE_EXECUTE_READWRITE ||
                                          allocProtect == PAGE_EXECUTE_WRITECOPY;

                    if (isCurrentlyExec && wasAllocatedRwx)
                    {
                        // Read first bytes to check for shellcode patterns
                        string? patternName = CheckShellcodeContent(hProc, mbi.BaseAddress, ct);
                        bool hasPattern = patternName is not null;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Staged-Shellcode-Region in '{proc.ProcessName}' @0x{(ulong)mbi.BaseAddress:X}",
                            Risk     = hasPattern ? RiskLevel.Critical : RiskLevel.High,
                            Location = $"PID {proc.Id} @0x{(ulong)mbi.BaseAddress:X}",
                            FileName = proc.ProcessName,
                            Reason   = $"Private ausführbare Region bei 0x{(ulong)mbi.BaseAddress:X} in '{proc.ProcessName}' wurde " +
                                       "als PAGE_EXECUTE_READWRITE alloziert (Schreib-Phase) und dann auf " +
                                       $"{(protect == PAGE_EXECUTE_READ ? "PAGE_EXECUTE_READ" : "PAGE_EXECUTE")} " +
                                       "gehärtet (Ausführungs-Phase) — klassisches Staged-Shellcode/Loader-Muster" +
                                       (hasPattern ? $" | Inhalt: {patternName}" : ""),
                            Detail   = $"Prozess: {proc.ProcessName} (PID {proc.Id}) | " +
                                       $"Basis: 0x{(ulong)mbi.BaseAddress:X} | " +
                                       $"Größe: {(long)mbi.RegionSize:N0} Bytes | " +
                                       $"Aktuell: 0x{protect:X} | Allokiert: 0x{allocProtect:X} | " +
                                       $"Shellcode-Muster: {patternName ?? "keines erkannt (mögl. verschlüsselt)"}"
                        });
                        findingCount++;
                    }
                }

                try { addr = mbi.BaseAddress + mbi.RegionSize; }
                catch (OverflowException) { break; }
                if (Environment.Is64BitProcess && (ulong)addr >= 0x7FFFFFFF0000UL) break;
                if (!Environment.Is64BitProcess && (ulong)addr >= 0xFFF00000UL) break;
            }
        }
        finally
        {
            CloseHandle(hProc);
        }
    }

    private string? CheckShellcodeContent(nint hProc, nint baseAddr, CancellationToken ct)
    {
        try
        {
            var buf = new byte[64];
            if (!ReadProcessMemory(hProc, baseAddr, buf, buf.Length, out int read) || read < 4)
                return null;

            foreach (var pattern in ShellcodePatterns)
            {
                ct.ThrowIfCancellationRequested();
                if (pattern.Length > read) continue;

                bool match = true;
                for (int i = 0; i < pattern.Length; i++)
                    if (buf[i] != pattern[i]) { match = false; break; }

                if (!match) continue;

                return pattern[0] == 0x4D ? "MZ-Header (Reflective DLL)" :
                       pattern[0] == 0x50 ? "PE-Signatur" :
                       pattern[0] == 0xFC ? "CobaltStrike x64 Stager" :
                       pattern[0] == 0xE8 ? "CALL $+5 (PIC-Shellcode)" :
                       pattern[0] == 0x64 ? "PEB-Walk x64" :
                       pattern[0] == 0x65 ? "PEB-Walk x86" :
                       pattern[0] == 0x48 ? "XOR-Nulling (msfvenom)" :
                       "Bekanntes Shellcode-Muster";
            }
        }
        catch { }
        return null;
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
