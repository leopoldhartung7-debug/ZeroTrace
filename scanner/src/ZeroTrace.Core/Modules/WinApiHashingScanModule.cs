using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects API hashing stubs in game process memory: shellcode and advanced cheats avoid
/// static imports by walking the PEB InMemoryOrderModuleList, hashing DLL export names at
/// runtime, and calling them by hash rather than name. These PEB-walk + hash-loop patterns
/// are distinctive byte sequences not associated with any legitimate module and indicate
/// sophisticated injected code or a cheat loader's position-independent payload.
/// </summary>
public sealed class WinApiHashingScanModule : IScanModule
{
    public string Name => "WinAPI Hashing Detection";
    public double Weight => 0.95;
    public int ParallelGroup => 0;

    // PEB walk + export hash loop byte patterns (all x64)
    // Each entry: (label, byte pattern, mask — null mask = exact match)
    private static readonly (string Label, byte[] Pattern, byte[]? Mask)[] HashPatterns =
    {
        // GS:[0x60] PEB access — universal shellcode PEB access (x64)
        ("PEB-GS60 Zugriff",
         new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 },
         null),

        // GS:[0x30] TEB access to reach PEB via TEB.ProcessEnvironmentBlock
        ("TEB-GS30 zu PEB",
         new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00 },
         null),

        // CALL $+5 / POP R_ — classic get-EIP / get-RIP for position-independent code
        ("CALL+5 get-RIP",
         new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x59 }, // E8 00000000 POP RCX
         new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }),

        ("CALL+5 get-RIP RDX variant",
         new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5A }, // E8 00000000 POP RDX
         new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }),

        ("CALL+5 get-RIP RAX variant",
         new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 }, // E8 00000000 POP RAX
         new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }),

        // ROR/ROL hash loop — common hash algorithm: ror r, 0xd; xor r, byte
        ("ROR-0x0D Hash-Schleife",
         new byte[] { 0xC1, 0xC8, 0x0D }, // ROR eax, 0xd
         null),

        ("ROR-0x13 Hash-Schleife",
         new byte[] { 0xC1, 0xC8, 0x13 }, // ROR eax, 0x13
         null),

        ("ROL-0x07 Hash-Schleife",
         new byte[] { 0xC1, 0xC0, 0x07 }, // ROL eax, 7
         null),

        // Metasploit x64 stager prefix (CLD; then PEB walk)
        ("msfvenom x64 Stager CLD",
         new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8 },
         null),

        // CobaltStrike-style hash beacon init
        ("CobaltStrike Beacon Init",
         new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC8, 0x00 },
         null),

        // SysWhispers2/3 direct syscall stub: mov r10, rcx; mov eax, <syscall-nr>; syscall
        ("SysWhispers Syscall Stub",
         new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 }, // MOV R10, RCX; MOV EAX, ...
         null),

        // Hell's Gate / Tartarus Gate pattern: scanning ntdll for syscall numbers
        ("HellsGate Syscall-Scanner",
         new byte[] { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05 },
         new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF }),

        // PEB->Ldr->InMemoryOrderModuleList walking (64-bit offset 0x18/0x20)
        // mov rax, [rax+0x18] — walk InMemoryOrderLinks
        ("InMemoryOrderLinks Walk",
         new byte[] { 0x48, 0x8B, 0x40, 0x18 }, // MOV RAX, [RAX+0x18]
         null),

        // ExportDirectory RVA resolution — common in shellcode
        // cmp [r+0x3c], 'P' 'E' \0 \0
        ("PE-Header ExportDir Check",
         new byte[] { 0x50, 0x45, 0x00, 0x00 }, // 'PE\0\0'
         null),

        // BSWAP-based hash (some Donut payloads use BSWAP for hashing)
        ("BSWAP Hash-Variante",
         new byte[] { 0x0F, 0xC8, 0xC1, 0xE0 }, // BSWAP EAX; SHL EAX, ...
         null),

        // XOR-based null-free decoder (common in shellcode to avoid null bytes)
        ("XOR Null-Free Decoder",
         new byte[] { 0x31, 0xC9, 0x64, 0x8B, 0x71, 0x30 }, // XOR ECX,ECX; FS/GS PEB access
         null),

        // Direct SYSCALL; RET pattern (evasion: execute syscall directly)
        ("Direkter SYSCALL+RET",
         new byte[] { 0x0F, 0x05, 0xC3 }, // SYSCALL; RET
         null),

        // INT2E (alternative syscall on older Windows, used by some bypass tools)
        ("INT 2E Syscall-Variante",
         new byte[] { 0xCD, 0x2E, 0xC3 }, // INT 2Eh; RET
         null),

        // LoadLibrary by hash pattern — common proxy for hash-resolved LoadLibrary calls
        // push 0x<hash>; call <resolve_func>
        ("Push-Hash LoadLibrary Aufruf",
         new byte[] { 0x68, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0 }, // PUSH imm32; CALL RAX
         new byte[] { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF }),
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(
        nint hProcess, nint lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

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

    private const uint MEM_COMMIT            = 0x1000;
    private const uint MEM_PRIVATE           = 0x20000;
    private const uint PAGE_EXECUTE          = 0x10;
    private const uint PAGE_EXECUTE_READ     = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PROCESS_VM_READ       = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const int  MaxReadBytes          = 2 * 1024 * 1024; // 2MB per region cap

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
                try { ScanProcess(proc, ctx, ct); }
                catch { /* skip */ }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }, ct);
    }

    private void ScanProcess(Process proc, ScanContext ctx, CancellationToken ct)
    {
        nint hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            nint address = nint.Zero;
            int findingCount = 0;

            while (findingCount < 20)
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
                if (mbi.Type != MEM_PRIVATE)  continue;  // only anonymous private memory
                if (!IsExecutable(mbi.Protect)) continue;

                long regionSize = mbi.RegionSize.ToInt64();
                if (regionSize < 16) continue;

                int readBytes = (int)Math.Min(regionSize, MaxReadBytes);
                var buf = new byte[readBytes];
                if (!ReadProcessMemory(hProc, mbi.BaseAddress, buf, readBytes, out int bytesRead) || bytesRead < 8)
                    continue;

                var matches = new List<string>();
                foreach (var (label, pattern, mask) in HashPatterns)
                {
                    if (FindPattern(buf, bytesRead, pattern, mask))
                        matches.Add(label);
                }

                // Require at least 2 matches to reduce FP on coincidental byte sequences,
                // OR 1 match if the region is RWX (always suspicious)
                bool isRwx = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 ||
                             (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0;

                if (matches.Count >= 2 || (matches.Count >= 1 && isRwx))
                {
                    findingCount++;
                    ctx.AddFinding(new Finding
                    {
                        Module = "WinAPI Hashing Detection",
                        Title = $"API-Hashing Muster in {proc.ProcessName} @0x{mbi.BaseAddress:X}",
                        Risk = isRwx ? RiskLevel.Critical : RiskLevel.High,
                        Location = $"Prozess {proc.ProcessName} (PID {proc.Id}) @0x{mbi.BaseAddress:X}",
                        Reason = $"Privater ausfuehrbarer Speicherbereich enthaelt {matches.Count} API-Hashing Muster — " +
                                 "typisch fuer Shellcode oder Cheat-Loader die Imports durch Hash-Aufloesung verschleiern",
                        Detail = $"Schutz: 0x{mbi.Protect:X} | Groesse: {regionSize / 1024} KB | " +
                                 $"Muster: {string.Join(", ", matches)}"
                    });
                }
            }
        }
        finally { CloseHandle(hProc); }
    }

    private static bool FindPattern(byte[] buf, int length, byte[] pattern, byte[]? mask)
    {
        int patLen = pattern.Length;
        int limit = length - patLen;

        for (int i = 0; i <= limit; i++)
        {
            bool found = true;
            for (int j = 0; j < patLen; j++)
            {
                byte b = buf[i + j];
                byte p = pattern[j];
                if (mask != null)
                {
                    if ((b & mask[j]) != (p & mask[j])) { found = false; break; }
                }
                else
                {
                    if (b != p) { found = false; break; }
                }
            }
            if (found) return true;
        }
        return false;
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
