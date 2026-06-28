using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects inline (byte-patch) hooks in critical DLLs loaded in game processes.
///
/// Inline hooking is the most common runtime code-modification technique used by
/// cheat software to intercept or redirect Windows API calls:
///
/// How inline hooking works:
///   1. Calculate the target function's address (GetProcAddress / manual export walk)
///   2. Overwrite the first 5–14 bytes with a jump instruction:
///      - x86: E9 xx xx xx xx            (JMP rel32)
///      - x64: FF 25 00 00 00 00 xx...   (JMP [RIP+0]; abs64 in next 8 bytes)
///      - x64: 48 B8 xx...xx FF E0       (MOV RAX,imm64; JMP RAX)
///   3. The hook redirects control to the cheat's handler
///   4. The handler can: suppress the call, log parameters, or modify return values
///
/// Who hooks what and why:
///
///   Cheat hooks (to bypass anti-cheat):
///   - NtQuerySystemInformation → hide cheat processes from process lists
///   - NtOpenProcess → block AC from opening the cheat process
///   - NtReadVirtualMemory → return zeros when AC reads cheat memory
///   - SetWindowsHookEx / GetAsyncKeyState → hide input
///   - EtwEventWrite → disable ETW telemetry to prevent logging
///   - NtProtectVirtualMemory → prevent AC from changing page protections
///
///   Anti-cheat hooks (to monitor games):
///   - LoadLibraryA/W → detect DLL injection into game
///   - VirtualAlloc / NtAllocateVirtualMemory → track memory allocation
///   - CreateThread / NtCreateThreadEx → detect thread injection
///
///   Cheat counter-hooks (to remove AC hooks from game):
///   - Cheats often detect that AC installed inline hooks and remove them
///   - They overwrite AC's hooks with the original bytes (restoring the function)
///   - This leaves the function prologue matching disk, while AC thinks it's hooked
///   → Our reverse-detection: if AC expects hooks to be there, their absence = cheat
///
/// Detection:
///   1. For each game process, find key DLLs: ntdll.dll, kernel32.dll,
///      kernelbase.dll, win32u.dll (AC hooks here; cheats patch these)
///   2. Read the export directory from the module's in-memory copy
///   3. For critical exported functions, read the first 16 bytes from:
///      a) Process memory (ReadProcessMemory)
///      b) The on-disk DLL file (FileStream at the same RVA offset)
///   4. Compare bytes. If they differ AND the memory bytes start with a hook opcode:
///      flag as inline hook
///   5. Report the function name, hook opcode, and first bytes for forensics
/// </summary>
public sealed class InlineHookDetectionScanModule : IScanModule
{
    public string Name => "Inline-Hook-Erkennung";
    public double Weight => 1.1;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    // IMAGE_DIRECTORY_ENTRY_EXPORT = 0
    private const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

    // Hook-pattern first bytes (x86/x64 JMP/INT3 patterns)
    private static readonly byte[] HookFirstBytes = { 0xE9, 0xFF, 0x48, 0xCC, 0xEB, 0x68, 0x90 };

    // Critical DLL names to check (these are hooked most often by cheats)
    private static readonly string[] CriticalDlls =
    {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "win32u.dll",
        "user32.dll", "advapi32.dll",
    };

    // High-value exports to specifically target (most commonly hooked by cheats)
    private static readonly HashSet<string> HighValueExports = new(StringComparer.OrdinalIgnoreCase)
    {
        // ntdll — AC and cheats fight over these
        "NtQuerySystemInformation", "NtOpenProcess", "NtReadVirtualMemory",
        "NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtAllocateVirtualMemory",
        "NtFreeVirtualMemory", "NtCreateThreadEx", "NtQueryVirtualMemory",
        "NtQueryInformationProcess", "NtSetInformationThread", "NtQueryInformationThread",
        "NtSuspendThread", "NtResumeThread", "NtGetContextThread", "NtSetContextThread",
        "EtwEventWrite", "EtwEventWriteFull", "EtwEventWriteEx",
        "LdrLoadDll", "LdrGetProcedureAddress",
        // kernel32/kernelbase
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "OpenProcess", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetAsyncKeyState", "GetKeyState",
        // win32u
        "NtUserSendInput", "NtUserGetForegroundWindow",
    };

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

                    hits += ScanProcess(proc, hProcess, procExe, ctx, ct);
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

        ctx.Report(1.0, Name, $"Inline-Hooks analysiert, {hits} Treffer");
        return Task.CompletedTask;
    }

    private static int ScanProcess(Process proc, IntPtr hProcess, string procExe,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (ProcessModule mod in proc.Modules)
            {
                if (ct.IsCancellationRequested) break;
                if (!CriticalDlls.Any(d =>
                    mod.ModuleName?.Equals(d, StringComparison.OrdinalIgnoreCase) ?? false))
                    continue;

                try { hits += ScanModule(proc, hProcess, procExe, mod, ctx, ct); }
                catch { }
            }
        }
        catch { }
        return hits;
    }

    private static int ScanModule(Process proc, IntPtr hProcess, string procExe,
        ProcessModule mod, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var modBase = mod.BaseAddress;
            string modPath = mod.FileName ?? "";
            if (!File.Exists(modPath)) return 0;

            // Read PE header from process memory
            var header = new byte[0x1000];
            if (!ReadProcessMemory(hProcess, modBase, header, header.Length, out int hRead)
                || hRead < 0x200) return 0;
            if (header[0] != 'M' || header[1] != 'Z') return 0;

            int e_lfanew = BitConverter.ToInt32(header, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 0x100 > hRead) return 0;
            if (header[e_lfanew] != 'P' || header[e_lfanew + 1] != 'E') return 0;

            ushort machine = BitConverter.ToUInt16(header, e_lfanew + 4);
            bool is64 = machine == 0x8664;

            // Locate EXPORT DataDirectory
            int optOff = e_lfanew + 24;
            int ddOffset = optOff + (is64 ? 0x70 : 0x60) + IMAGE_DIRECTORY_ENTRY_EXPORT * 8;
            if (ddOffset + 8 > hRead) return 0;

            uint exportRva  = BitConverter.ToUInt32(header, ddOffset);
            uint exportSize = BitConverter.ToUInt32(header, ddOffset + 4);
            if (exportRva == 0 || exportSize < 40) return 0;

            // Read export directory
            var expBuf = new byte[(int)Math.Min(exportSize + 0x10000, 512 * 1024)];
            var expAddr = new IntPtr(modBase.ToInt64() + exportRva);
            if (!ReadProcessMemory(hProcess, expAddr, expBuf, expBuf.Length, out int expRead)
                || expRead < 40) return 0;

            uint numNames    = BitConverter.ToUInt32(expBuf, 16);
            uint addrOfNames = BitConverter.ToUInt32(expBuf, 28) - exportRva;
            uint addrOfOrds  = BitConverter.ToUInt32(expBuf, 32) - exportRva;
            uint addrOfFuncs = BitConverter.ToUInt32(expBuf, 24) - exportRva;
            uint numFuncs    = BitConverter.ToUInt32(expBuf, 20);

            if (numNames > 5000 || numFuncs > 5000) return 0;

            // Open on-disk file for comparison
            byte[] diskBuf;
            try
            {
                diskBuf = File.ReadAllBytes(modPath);
            }
            catch { return 0; }

            // Build disk RVA → file offset map via section headers
            int sectionStart = e_lfanew + 24 + BitConverter.ToUInt16(header, e_lfanew + 20);
            int numSections  = BitConverter.ToUInt16(header, e_lfanew + 6);

            // Helper: RVA → disk file offset via section table
            static int RvaToFileOffset(byte[] pe, int secStart, int secCount, uint rva)
            {
                for (int s = 0; s < secCount; s++)
                {
                    int sOff = secStart + s * 40;
                    if (sOff + 40 > pe.Length) break;
                    uint virt = BitConverter.ToUInt32(pe, sOff + 12);
                    uint raw  = BitConverter.ToUInt32(pe, sOff + 20);
                    uint vsz  = BitConverter.ToUInt32(pe, sOff + 8);
                    if (rva >= virt && rva < virt + vsz)
                        return (int)(raw + (rva - virt));
                }
                return -1;
            }

            for (uint i = 0; i < numNames && !ct.IsCancellationRequested; i++)
            {
                try
                {
                    uint nameRvaOff = addrOfNames + i * 4U;
                    if (nameRvaOff + 4U > (uint)expRead) continue;
                    uint nameRva = BitConverter.ToUInt32(expBuf, (int)nameRvaOff) - exportRva;
                    if (nameRva >= expRead) continue;

                    // Extract null-terminated function name
                    int nameEnd = (int)nameRva;
                    while (nameEnd < expRead && expBuf[nameEnd] != 0) nameEnd++;
                    string funcName = System.Text.Encoding.ASCII.GetString(
                        expBuf, (int)nameRva, nameEnd - (int)nameRva);

                    // Only check high-value exports
                    if (!HighValueExports.Contains(funcName)) continue;

                    // Get ordinal → function RVA
                    uint ordOff = addrOfOrds + i * 2U;
                    if (ordOff + 2U > (uint)expRead) continue;
                    ushort ord = BitConverter.ToUInt16(expBuf, (int)ordOff);
                    uint funcRvaOff = addrOfFuncs + (uint)ord * 4U;
                    if (funcRvaOff + 4U > (uint)expRead) continue;
                    uint funcRva = BitConverter.ToUInt32(expBuf, (int)funcRvaOff);
                    if (funcRva == 0) continue;

                    // Read first 16 bytes from process memory
                    var memBytes = new byte[16];
                    var funcVA = new IntPtr(modBase.ToInt64() + funcRva);
                    if (!ReadProcessMemory(hProcess, funcVA, memBytes, 16, out int mr)
                        || mr < 8) continue;

                    // Read first 16 bytes from disk file
                    int diskOffset = RvaToFileOffset(diskBuf, sectionStart, numSections, funcRva);
                    if (diskOffset < 0 || diskOffset + 16 > diskBuf.Length) continue;

                    // Compare
                    bool differs = false;
                    for (int j = 0; j < Math.Min(mr, 16); j++)
                    {
                        if (memBytes[j] != diskBuf[diskOffset + j]) { differs = true; break; }
                    }
                    if (!differs) continue;

                    // Check if the memory bytes start with a hook opcode
                    bool isHookOpcode = HookFirstBytes.Contains(memBytes[0]);
                    if (!isHookOpcode) continue;

                    string memHex = BitConverter.ToString(memBytes, 0, Math.Min(mr, 8))
                        .Replace("-", " ");
                    string diskHex = BitConverter.ToString(diskBuf, diskOffset, 8)
                        .Replace("-", " ");

                    string hookType = memBytes[0] switch
                    {
                        0xE9 => "JMP rel32 (5-Byte-Hook)",
                        0xFF => "JMP [RIP+...] (x64 absoluter Hook)",
                        0x48 => "MOV RAX,imm64+JMP RAX (x64 Hook)",
                        0xCC => "INT3 (Breakpoint/Trampolin-Hook)",
                        0xEB => "JMP short (2-Byte-Hook)",
                        0x68 => "PUSH/RET (Stack-Hook)",
                        0x90 => "NOP-Sled (Patch)",
                        _    => $"Unbekannter Opcode 0x{memBytes[0]:X2}"
                    };

                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Inline-Hook-Erkennung",
                        Title    = $"Inline-Hook in {mod.ModuleName}!{funcName}: {procExe}",
                        Risk     = RiskLevel.Critical,
                        Location = $"PID {proc.Id}: {mod.ModuleName}!{funcName} @ 0x{funcVA.ToInt64():X}",
                        Reason   = $"'{mod.ModuleName}!{funcName}' in '{procExe}' (PID {proc.Id}) " +
                                   $"wurde mit {hookType} überschrieben. " +
                                   $"Speicher-Bytes: [{memHex}] | Disk-Bytes: [{diskHex}]. " +
                                   "Inline-Hooks modifizieren die ersten Bytes einer API-Funktion, " +
                                   "um Aufrufe auf Cheat-Code umzuleiten. " +
                                   "Häufige Ziele: NtOpenProcess (AC vom Prozess fernhalten), " +
                                   "NtReadVirtualMemory (Speicherinhalt verbergen), " +
                                   "EtwEventWrite (ETW-Logging deaktivieren), " +
                                   "NtQuerySystemInformation (Prozesse aus Liste entfernen).",
                        Detail   = $"Funktion={mod.ModuleName}!{funcName} | " +
                                   $"VA=0x{funcVA.ToInt64():X} | " +
                                   $"Speicher=[{memHex}] | Disk=[{diskHex}] | " +
                                   $"HookTyp={hookType} | Prozess={procExe} PID={proc.Id}"
                    });
                }
                catch { }
            }
        }
        catch { }
        return hits;
    }
}
