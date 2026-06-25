using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans game process private memory for known shellcode signatures and injection stubs.
///
/// Unlike ProcessHollowingScanModule (which detects PE structures in memory) and
/// MemoryProtectionScanModule (which detects RWX regions), this module searches the
/// CONTENT of private executable memory for specific byte sequences that identify:
///
///   1. Metasploit/msfvenom x64 stager patterns:
///      FC 48 83 E4 F0 E8 CC 00 00 00  — standard x64 stager (CLD + stack align)
///
///   2. Cobalt Strike beacon shellcode (x64):
///      FC 48 83 E4 F0 E8 C8 00 00 00  — Cobalt Strike beacon variant
///      Common pattern: XOR loop decrypt, then JMP to decrypted payload
///
///   3. SysWhispers / Hell's Gate direct syscall stubs:
///      4C 8B D1 B8 xx 00 00 00 0F 05  — MOV R10,RCX; MOV EAX,<syscall_num>; SYSCALL
///      Common in cheats to bypass ntdll hooks by issuing syscalls directly
///
///   4. GetProcAddress-less shellcode (PEB walking):
///      65 48 8B 04 25 60 00 00 00      — MOV RAX,GS:[0x60] (get PEB via GS segment)
///      65 48 8B 04 25 30 00 00 00      — MOV RAX,GS:[0x30] (older PEB access pattern)
///
///   5. x64 position-independent shellcode call-next trick:
///      E8 00 00 00 00 5B              — CALL $+5; POP RBX (get current instruction pointer)
///      E8 00 00 00 00 58              — CALL $+5; POP RAX variant
///
///   6. LoadLibrary shellcode patterns:
///      48 83 EC 28 E8 .. .. .. ..     — push frame + CALL (LoadLibrary stub)
///      followed by FF D0 or FF E0     — CALL RAX / JMP RAX to function pointer
///
///   7. XOR decryption loop (most shellcode packers):
///      31 D2 EB 0B C3 90 90 90        — common XOR decode prologue
///      or: 48 31 C9 48 31 D2          — x64 XOR ECX,ECX; XOR EDX,EDX; (null-free)
///
///   8. Stack pivot patterns (ROP chains):
///      9C 9D 50 53 51 52 56 57        — PUSHFQ POPFQ PUSH RAX ... (full register save)
///      or: 48 89 E5 48 83 EC 20       — MOV RBP,RSP; SUB RSP,0x20 (common stub)
///
/// Scanning strategy:
///   1. Walk all MEM_COMMIT, private (non-MEM_IMAGE), executable memory regions
///   2. Read region contents with ReadProcessMemory
///   3. Scan for signature patterns with Boyer-Moore-Horspool or naive search
///   4. Flag regions where ≥2 distinct signatures are found (reduces false positives)
///   5. Single signature hits are flagged at lower risk if region is large and
///      RWX-protected (common shellcode allocation pattern)
/// </summary>
public sealed class ShellcodeSignatureScanModule : IScanModule
{
    public string Name => "Shellcode-Signatur-Erkennung";
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
    private const uint PAGE_EXECUTE             = 0x10;
    private const uint PAGE_EXECUTE_READ        = 0x20;
    private const uint PAGE_EXECUTE_READWRITE   = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY   = 0x80;

    // Maximum region size to scan (avoid reading huge allocations)
    private const long MaxScanRegionBytes = 4 * 1024 * 1024; // 4 MB

    // Minimum matches required to flag a region (reduces false positives)
    private const int MinMatchesForFlag = 2;

    // Shellcode signature database
    private static readonly (string Label, byte[] Pattern)[] Signatures =
    [
        ("msfvenom-x64-stager",    new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8 }),
        ("CobaltStrike-x64-beacon",new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC8 }),
        ("SysWhispers-stub",       new byte[] { 0x4C, 0x8B, 0xD1, 0xB8 }),              // MOV R10,RCX; MOV EAX,syscall#
        ("PEB-GS60-access",        new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60 }),  // MOV RAX,GS:[0x60]
        ("PEB-GS30-access",        new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30 }),  // MOV RAX,GS:[0x30]
        ("get-RIP-CALL5-POPRAX",   new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58 }),  // CALL$+5; POP RAX
        ("get-RIP-CALL5-POPRBX",   new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B }),  // CALL$+5; POP RBX
        ("get-RIP-CALL5-POPRCX",   new byte[] { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x59 }),  // CALL$+5; POP RCX
        ("x64-null-free-xor-init", new byte[] { 0x48, 0x31, 0xC9, 0x48, 0x31, 0xD2 }),  // XOR RCX,RCX; XOR RDX,RDX
        ("hash-API-CLD",           new byte[] { 0xFC, 0xE8 }),                           // CLD; CALL (common hash loop start)
        ("Shikata-xor-prologue",   new byte[] { 0xD9, 0x74, 0x24, 0xF4, 0x5B }),         // Shikata-ga-nai XOR decode
        ("LoadLib-stub-x64",       new byte[] { 0x48, 0x83, 0xEC, 0x28, 0xFF, 0x15 }),   // SUB RSP,0x28; CALL [RIP+...]
        ("VirtualAlloc-call-rax",  new byte[] { 0x48, 0xB8 }),                           // MOV RAX,imm64 (very common in shellcode)
        ("stack-pivot-pushfq",     new byte[] { 0x9C, 0x9D, 0x50, 0x53 }),               // PUSHFQ; POPFQ; PUSH RAX; PUSH RBX
        ("Donut-header",           new byte[] { 0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48 }),   // Donut shellcode PE header
        ("direct-SYSCALL",         new byte[] { 0x0F, 0x05, 0xC3 }),                     // SYSCALL; RET (direct syscall stub)
        ("Tartarus-Gate-stub",     new byte[] { 0x4C, 0x8B, 0xD1, 0x49, 0x89, 0xCA }),   // MOV R10,RCX; MOV R9,RDX (Tartarus)
    ];

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

                    hits += ScanProcessShellcode(proc, hProcess, procExe, ctx, ct);
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

        ctx.Report(1.0, Name, $"Shellcode-Signaturen gesucht, {hits} Treffer");
        return Task.CompletedTask;
    }

    private static int ScanProcessShellcode(Process proc, IntPtr hProcess, string procExe,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var mbi = new MEMORY_BASIC_INFORMATION();
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
            IntPtr addr = IntPtr.Zero;

            while (!ct.IsCancellationRequested)
            {
                if (!VirtualQueryEx(hProcess, addr, out mbi, mbiSize)) break;
                if (mbi.RegionSize == IntPtr.Zero) break;

                long regionBase = mbi.BaseAddress.ToInt64();
                long regionSize = mbi.RegionSize.ToInt64();

                try { addr = new IntPtr(regionBase + regionSize); } catch { break; }

                // Only private, committed, executable memory
                if (mbi.State != MEM_COMMIT) continue;
                if (mbi.Type == MEM_IMAGE) continue;

                bool isExec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
                if (!isExec) continue;

                // Skip very tiny or huge regions
                if (regionSize < 64 || regionSize > MaxScanRegionBytes) continue;

                // Read region
                int readSize = (int)Math.Min(regionSize, MaxScanRegionBytes);
                var buf = new byte[readSize];
                if (!ReadProcessMemory(hProcess, mbi.BaseAddress, buf, readSize, out int nRead)
                    || nRead < 64) continue;

                // Scan for signatures
                var matchedSigs = new HashSet<string>();
                foreach (var (label, pattern) in Signatures)
                {
                    if (matchedSigs.Contains(label)) continue;
                    if (IndexOf(buf, nRead, pattern) >= 0)
                        matchedSigs.Add(label);
                }

                if (matchedSigs.Count == 0) continue;

                // Single weak match only flags if region is RWX (higher confidence)
                bool isRwx = (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0 ||
                             (mbi.Protect & PAGE_EXECUTE_WRITECOPY) != 0;
                if (matchedSigs.Count < MinMatchesForFlag && !isRwx) continue;

                RiskLevel risk = matchedSigs.Count >= 3 ? RiskLevel.Critical :
                                 matchedSigs.Count >= 2 ? RiskLevel.High : RiskLevel.Medium;

                hits++;
                string sigList = string.Join(", ", matchedSigs);
                ctx.AddFinding(new Finding
                {
                    Module   = "Shellcode-Signatur-Erkennung",
                    Title    = $"Shellcode-Signaturen in privatem Speicher: {procExe}",
                    Risk     = risk,
                    Location = $"PID {proc.Id}: 0x{regionBase:X}–0x{regionBase + nRead:X}",
                    Reason   = $"Privater ausführbarer Speicher in '{procExe}' (PID {proc.Id}) " +
                               $"bei 0x{regionBase:X} ({nRead / 1024} KB) enthält " +
                               $"{matchedSigs.Count} Shellcode-Signaturen: [{sigList}]. " +
                               "Shellcode-Muster werden von bekannten Injection-Frameworks " +
                               "hinterlassen: msfvenom-Stager (Metasploit), Cobalt Strike Beacon, " +
                               "SysWhispers/Hell's Gate/Tartarus Gate (Direct-Syscall-Cheat-Loader), " +
                               "Donut (PE→shellcode-Konverter), Shikata-ga-nai XOR-Encoder. " +
                               "Der private (nicht-image) Speicher mit diesen Mustern deutet auf " +
                               "aktive Shellcode-Ausführung hin.",
                    Detail   = $"Addr=0x{regionBase:X} | Size={nRead / 1024}KB | " +
                               $"Protect=0x{mbi.Protect:X} | RWX={isRwx} | " +
                               $"Signaturen=[{sigList}] | Prozess={procExe} PID={proc.Id}"
                });

                if (hits >= 5) break; // Cap per process
            }
        }
        catch { }
        return hits;
    }

    private static int IndexOf(byte[] haystack, int length, byte[] needle)
    {
        if (needle.Length == 0 || needle.Length > length) return -1;
        int limit = length - needle.Length;
        for (int i = 0; i <= limit; i++)
        {
            bool found = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { found = false; break; }
            }
            if (found) return i;
        }
        return -1;
    }
}
