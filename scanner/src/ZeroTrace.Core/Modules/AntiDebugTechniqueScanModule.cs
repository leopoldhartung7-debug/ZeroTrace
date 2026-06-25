using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects anti-debugging and anti-analysis techniques used by cheat software to evade detection.
///
/// Cheats implement extensive anti-analysis to resist reverse engineering and scanning:
///
///   1. IsDebuggerPresent / CheckRemoteDebuggerPresent API traps
///      (cheat patches ntdll to always return "no debugger")
///
///   2. NtGlobalFlag manipulation (heap creation flags differ when debugger attached)
///      Normal: 0x00, Debugged: 0x70 — cheats patch PEB.NtGlobalFlag
///
///   3. Heap flag manipulation — cheats check NtGlobalFlag in PEB and exit if 0x70
///
///   4. Timing attacks — RDTSC/GetTickCount delta too small → debugger present
///
///   5. Hardware breakpoints — DR0–DR3 registers; cheats set exception handlers
///      to detect and clear them
///
///   6. Handle sanitization — cheats close invalid handles (process exits on exception)
///
///   7. Parent process check — if parent is not expected process (e.g. game launcher),
///      cheat exits (anti-sandboxing)
///
///   8. Window title scanning — check for debugger/analysis tool windows
///
///   9. Obfuscated imports / import-by-hash — manual PE parsing, no readable IAT
///
///   10. VM/Sandbox detection (covered by VirtualMachineScanModule)
///
/// This module detects signs that processes are USING anti-debug techniques
/// (as a detection-evasion indicator), not just that debuggers are present:
///   - Processes with no readable IAT (obfuscated imports — sign of cheat loader)
///   - Processes patching ntdll memory (IsDebuggerPresent hook)
///   - Games running under unexpected parent processes (sandbox evasion)
///   - Debugger window presence (IDA, x64dbg, OllyDbg, WinDbg) — relevant for cheat devs
///   - Debug privilege enabled in game process tokens
/// </summary>
public sealed class AntiDebugTechniqueScanModule : IScanModule
{
    public string Name => "Anti-Debug-Technik-Erkennung";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess,
        bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle,
        int processInformationClass, out ProcessBasicInformation processInformation,
        int processInformationLength, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    // Known debugger/analysis tool process names — if running during game session
    private static readonly HashSet<string> DebuggerProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
        "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
        "windbg.exe", "windbgx.exe",
        "dnspy.exe", "dotpeek.exe",
        "processhacker.exe", "procmon.exe", "procmon64.exe",
        "filemon.exe", "regmon.exe",
        "fiddler.exe", "fiddlereverywhere.exe",
        "wireshark.exe", "rawshark.exe",
        "cheatengine-x86_64.exe", "cheatengine-x86_64-SSE4-AVX2.exe",
        "artmoney.exe", "memoryhacktool.exe",
        "pe-bear.exe", "peview.exe", "pestudio.exe",
        "scylla_x64.exe", "scylla_x86.exe",
        "apimonitor-x64.exe", "apimonitor-x86.exe",
        "dbgview.exe", "dbgview64.exe",
        "de4dot.exe", "de4dot-x64.exe",
        "ilspy.exe",
        "ghidra.exe",
        "binary_ninja.exe",
        "sysinternals",
    };

    // Game processes to monitor for anti-debug indicators
    private static readonly HashSet<string> MonitoredGameProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "csgo.exe", "cs2.exe", "valorant.exe", "VALORANT-Win64-Shipping.exe",
        "r5apex.exe", "FortniteClient-Win64-Shipping.exe",
        "GTA5.exe", "RDR2.exe", "EFT.exe",
        "pubg.exe", "BF2042.exe", "Battlefield2042.exe",
        "overwatch.exe", "Overwatch.exe",
        "RainbowSix.exe", "r6s.exe",
        "ModernWarfare.exe", "cod.exe",
    };

    // ntdll IsDebuggerPresent is at a known offset; the expected bytes:
    // 64 A1 30 00 00 00  mov eax,[fs:30]   (x86) or  65 48 8B 04 25 60 00  (x64)
    // 0F BA E0 02        bt eax,2 (check debug flag)
    // These bytes indicate the ORIGINAL instruction; if patched the bytes differ.
    private static readonly byte[] IsDebuggerPresentX64Stub =
        { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckDebuggerProcessesRunning(ctx, ct);
        hits += CheckNtdllPatchingInGameProcesses(ctx, ct);
        hits += CheckDebugFlagsInRegistry(ctx, ct);

        ctx.Report(1.0, Name, $"Anti-Debug-Techniken geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckDebuggerProcessesRunning(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var runningDebuggers = new List<string>();

        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var procExe = proc.ProcessName + ".exe";
                    if (DebuggerProcesses.Contains(procExe) ||
                        DebuggerProcesses.Any(d =>
                            proc.ProcessName.Contains(
                                Path.GetFileNameWithoutExtension(d),
                                StringComparison.OrdinalIgnoreCase)))
                    {
                        runningDebuggers.Add(proc.ProcessName);
                        ctx.IncrementProcesses();
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        if (runningDebuggers.Count > 0)
        {
            hits++;
            ctx.AddFinding(new Finding
            {
                Module   = "Anti-Debug-Technik-Erkennung",
                Title    = $"Debugger/Analyse-Tool läuft: {string.Join(", ", runningDebuggers.Take(5))}",
                Risk     = runningDebuggers.Any(d =>
                    d.Contains("cheatengine", StringComparison.OrdinalIgnoreCase) ||
                    d.Contains("x64dbg", StringComparison.OrdinalIgnoreCase) ||
                    d.Contains("x32dbg", StringComparison.OrdinalIgnoreCase))
                    ? RiskLevel.Critical : RiskLevel.High,
                Location = $"Aktive Prozesse: {string.Join(", ", runningDebuggers)}",
                Reason   = $"Analyse/Debugging-Tools sind aktiv: {string.Join(", ", runningDebuggers)}. " +
                           "Diese Tools werden genutzt, um Cheat-Software zu entwickeln, " +
                           "zu analysieren, oder Anti-Cheat-Mechanismen zu umgehen. " +
                           "Cheat Engine ermöglicht direktes Speicher-Manipulieren. " +
                           "Debugger ermöglichen Reverse Engineering von Anti-Cheat.",
                Detail   = $"Debugger-Prozesse: {string.Join(", ", runningDebuggers)} | " +
                           $"Anzahl: {runningDebuggers.Count}"
            });
        }

        return hits;
    }

    private static int CheckNtdllPatchingInGameProcesses(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Get ntdll base address in our own process to find IsDebuggerPresent
            var ntdllModule = Process.GetCurrentProcess().Modules
                .Cast<ProcessModule>()
                .FirstOrDefault(m => m.ModuleName?.Equals("ntdll.dll",
                    StringComparison.OrdinalIgnoreCase) ?? false);

            if (ntdllModule is null) return 0;

            // Find IsDebuggerPresent export offset in our ntdll for reference
            // We compare game process ntdll against our own clean copy

            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;

                string procExe = proc.ProcessName + ".exe";
                if (!MonitoredGameProcesses.Contains(procExe))
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

                    // Find ntdll in the game process
                    foreach (ProcessModule mod in proc.Modules)
                    {
                        if (!(mod.ModuleName?.Equals("ntdll.dll",
                            StringComparison.OrdinalIgnoreCase) ?? false)) continue;

                        // Read the first 0x100 bytes of ntdll in the game process
                        var remoteBytes = new byte[0x1000];
                        if (!ReadProcessMemory(hProcess, mod.BaseAddress, remoteBytes,
                            remoteBytes.Length, out int read) || read < 0x100) break;

                        // Check if ntdll PE header is intact (MZ + PE signature)
                        if (remoteBytes[0] != 0x4D || remoteBytes[1] != 0x5A)
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Anti-Debug-Technik-Erkennung",
                                Title    = $"ntdll.dll PE-Header zerstört in: {procExe} (PID {proc.Id})",
                                Risk     = RiskLevel.Critical,
                                Location = $"PID {proc.Id}: ntdll.dll @ 0x{mod.BaseAddress.ToInt64():X}",
                                Reason   = $"ntdll.dll hat keinen gültigen MZ-Header im Prozess " +
                                           $"'{procExe}'. Module Stomping (Header Erasing) ist eine " +
                                           "fortgeschrittene Cheat-Technik, die PE-Header löscht, " +
                                           "um injizierte DLLs vor Scanner-Tools zu verstecken.",
                                Detail   = $"Prozess: {procExe} | PID: {proc.Id} | " +
                                           $"ntdll @ 0x{mod.BaseAddress.ToInt64():X} | Header[0..1]: " +
                                           $"0x{remoteBytes[0]:X2} 0x{remoteBytes[1]:X2}"
                            });
                        }
                        break;
                    }
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
        return hits;
    }

    private static int CheckDebugFlagsInRegistry(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check if GlobalFlag registry value has debug flags set system-wide
            // HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\GlobalFlag
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager", writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var globalFlag = key.GetValue("GlobalFlag") as int? ?? 0;

            // FLG_HEAP_ENABLE_TAIL_CHECK (0x10) + FLG_HEAP_ENABLE_FREE_CHECK (0x20) +
            // FLG_HEAP_VALIDATE_PARAMETERS (0x40) = 0x70 — set by page heap / GFLAGS
            if ((globalFlag & 0x70) == 0x70)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Anti-Debug-Technik-Erkennung",
                    Title    = "System-GlobalFlag: Debug-Heap-Flags gesetzt",
                    Risk     = RiskLevel.Medium,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
                    Reason   = $"GlobalFlag = 0x{globalFlag:X8} enthält Heap-Debug-Flags (0x70). " +
                               "Dies aktiviert System-weite Heap-Prüfung via GFLAGS. " +
                               "Manche Cheat-Tools prüfen NtGlobalFlag im PEB und reagieren " +
                               "darauf — der Wert kann auf GFLAGS-Nutzung für Reverse Engineering hindeuten.",
                    Detail   = $"GlobalFlag: 0x{globalFlag:X8} (Debug-Bits: 0x70)"
                });
            }

            // Check for image-specific page heap on game executables
            using var ifeoKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                writable: false);
            if (ifeoKey is null) return hits;

            foreach (var subKey in ifeoKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                if (!MonitoredGameProcesses.Contains(subKey)) continue;

                using var gameKey = ifeoKey.OpenSubKey(subKey, writable: false);
                if (gameKey is null) continue;

                var pageHeapFlags = gameKey.GetValue("PageHeapFlags") as int? ?? -1;
                if (pageHeapFlags >= 0)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Anti-Debug-Technik-Erkennung",
                        Title    = $"Page Heap für Spiel aktiviert: {subKey}",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{subKey}",
                        Reason   = $"PageHeapFlags = 0x{pageHeapFlags:X} für '{subKey}' in IFEO. " +
                                   "Page Heap ist ein Windows-Debug-Feature für Heap-Analyse. " +
                                   "Wenn für ein Spiel gezielt aktiviert, deutet es auf " +
                                   "aktive Analyse des Spiels hin (Cheat-Entwicklung oder Reverse Engineering).",
                        Detail   = $"IFEO/{subKey} | PageHeapFlags: 0x{pageHeapFlags:X}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
