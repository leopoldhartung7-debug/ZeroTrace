using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects inline hooks in critical ntdll.dll / win32u.dll syscall stubs.
///
/// Every NT system call on x64 Windows starts with the canonical 3-byte prologue:
///   4C 8B D1  MOV R10, RCX
///   B8 XX XX XX XX  MOV EAX, &lt;syscall number&gt;
///
/// If the first byte(s) differ — particularly if a JMP (E9), far-JMP (FF 25),
/// MOV RAX/JMP shellcode (48 B8 ... FF E0), INT3 (CC), or PUSH/RET (68 ... C3)
/// instruction is present — the stub has been redirected to third-party code.
///
/// Rootkits and kernel-level anti-detection layers hook NT functions such as
/// NtQuerySystemInformation and NtOpenProcess to hide processes, modules, and
/// registry keys from user-mode tools (including anti-cheats and this scanner).
/// Read-only; nothing is modified.
/// </summary>
public sealed class SyscallHookScanModule : IScanModule
{
    public string Name => "Syscall-Hook-Erkennung";
    public double Weight => 0.3;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetModuleHandleA(string moduleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    // NT syscalls that cheats and rootkits most commonly hook
    private static readonly string[] NtCritical =
    {
        "NtReadVirtualMemory",       // external cheat: read game memory
        "NtWriteVirtualMemory",      // external cheat: write game memory
        "NtOpenProcess",             // hide process from scanners
        "NtProtectVirtualMemory",    // inject shellcode, bypass DEP
        "NtQueryVirtualMemory",      // hide memory regions
        "NtQuerySystemInformation",  // hide processes, modules, handles
        "NtQueryInformationProcess", // hide debugger status
        "NtSetInformationThread",    // HideFromDebugger thread flag
        "NtCreateThreadEx",          // stealthy thread injection
        "NtAllocateVirtualMemory",   // allocate shellcode buffer
        "NtMapViewOfSection",        // map section for code injection
        "NtUnmapViewOfSection",      // process hollowing
        "NtSuspendThread",           // freeze threads for injection
        "NtResumeThread",            // resume after injection
        "NtTerminateProcess",        // prevent cleanup / analysis
        "LdrLoadDll",                // DLL injection via loader
        "NtLoadDriver",              // load kernel driver (BYOVD)
        "NtSetSystemInformation",    // tamper with system state
    };

    private static readonly string[] Win32uCritical =
    {
        "NtUserFindWindowEx",        // find game window for overlay cheats
        "NtUserQueryWindow",         // query window properties
        "NtUserGetForegroundWindow",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var ntdll  = GetModuleHandleA("ntdll.dll");
        var win32u = GetModuleHandleA("win32u.dll");

        var hooks = new List<(string module, string fn, string reason, byte[] bytes)>();

        if (ntdll != IntPtr.Zero)
            foreach (var fn in NtCritical)
            {
                if (ct.IsCancellationRequested) break;
                var addr = GetProcAddress(ntdll, fn);
                if (addr != IntPtr.Zero) Inspect(addr, fn, "ntdll.dll", hooks);
            }

        if (win32u != IntPtr.Zero)
            foreach (var fn in Win32uCritical)
            {
                if (ct.IsCancellationRequested) break;
                var addr = GetProcAddress(win32u, fn);
                if (addr != IntPtr.Zero) Inspect(addr, fn, "win32u.dll", hooks);
            }

        foreach (var (module, fn, reason, bytes) in hooks)
        {
            string hexBytes = BitConverter.ToString(bytes).Replace("-", " ");
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Syscall-Hook erkannt: {module}!{fn}",
                Risk     = RiskLevel.Critical,
                Location = $"{module}!{fn}",
                FileName = module,
                Reason   = $"'{fn}' in {module} wurde gehooked: {reason}. " +
                           "Rootkits und Kernel-Cheats hooken NT-Syscalls, um " +
                           "Anti-Cheat-Abfragen zu manipulieren (z.B. Prozesse oder " +
                           "Treiber verstecken, Speicherinhalte faelschen).",
                Detail   = $"Erste 16 Bytes: {hexBytes}"
            });
        }

        int total = NtCritical.Length + Win32uCritical.Length;
        ctx.Report(1.0, "Syscall-Hooks",
            $"{total} Syscalls geprueft · {hooks.Count} Hook(s) gefunden");
        return Task.CompletedTask;
    }

    private static void Inspect(IntPtr addr, string fn, string module,
        List<(string, string, string, byte[])> hooks)
    {
        var bytes = new byte[16];
        try { Marshal.Copy(addr, bytes, 0, 16); }
        catch { return; }

        // Canonical x64 NT syscall stub: MOV R10, RCX (4C 8B D1)
        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1)
            return; // unmodified

        // Canonical x64 syscall stub with patchguard-safe MOV EAX prolog variant:
        // Some Windows builds use  B8 XX 00 00 00  as the first instruction.
        // This is not normally at byte 0 for NT* functions; treat any other variant as hooked.

        string reason = bytes[0] switch
        {
            0xE9 => $"JMP rel32 (Ziel: 0x{Rel32Target(addr, bytes):X}) – Inline-Hook",
            0xEB => "JMP short – Short-Jump-Hook",
            0xCC => "INT3 (Breakpoint) – Debug-Hook / Hypervisor-Hook",
            0x68 => "PUSH imm32 – PUSH/RET-Hook",
            0x90 => "NOP-Sled – Prolog ersetzt",
            0xFF when bytes[1] == 0x25 => "JMP [mem64] – Far-Indirect-Hook (haeufig bei VMware- und KVM-basierten Cheats)",
            0x48 when bytes[1] == 0xB8 => "MOV RAX, imm64; JMP RAX – Absoluter-Shellcode-Hook",
            _ => $"Unerwartetes Byte 0x{bytes[0]:X2} an Position 0 (erwartet: 0x4C = MOV R10,RCX)"
        };

        hooks.Add((module, fn, reason, bytes[..Math.Min(bytes.Length, 16)]));
    }

    private static ulong Rel32Target(IntPtr baseAddr, byte[] bytes)
    {
        if (bytes.Length < 5) return 0;
        int rel = BitConverter.ToInt32(bytes, 1);
        return (ulong)((long)baseAddr + 5 + rel);
    }
}
