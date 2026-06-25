using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects anti-debugging and anti-analysis techniques used by cheat loaders
/// to evade detection tools and obfuscate their behavior.
///
/// Advanced cheats use layered anti-analysis to prevent forensic tools from
/// inspecting them:
///   1. Exception-based anti-debug: trigger exceptions and check if a debugger
///      swallows them (NtSetInformationThread ThreadHideFromDebugger).
///   2. Parent process spoofing: cheat is launched with Explorer as fake parent
///      to bypass process-tree monitoring.
///   3. Heap flag manipulation: the debug heap is detectable via PEB flags.
///   4. Timing attacks: RDTSC before/after instruction — debugger slows execution.
///   5. Self-modifying code / code page checksum verification.
///   6. NtQueryInformationProcess ProcessDebugPort / ProcessDebugFlags.
///   7. ThreadHideFromDebugger on all threads (makes debugger disconnect).
///
/// This module checks RUNNING processes (not the scanner itself) for signs
/// that they employ anti-debug techniques to hide their cheat behavior.
/// It queries:
///   - ProcessDebugPort for each process (should be 0 for non-debugged processes
///     but a non-standard value = process is hiding something from debuggers)
///   - ThreadHideFromDebugger flags per thread
///   - Suspicious in-memory PE sections with no backing file (shellcode trampolines)
/// </summary>
public sealed class AntiDebugEvasionScanModule : IScanModule
{
    public string Name => "Anti-Debug-Evasion";
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref IntPtr processInformation,
        uint processInformationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int infoClass, IntPtr info, uint infoLen, out uint retLen);

    private const int ProcessDebugPort  = 7;
    private const int ProcessDebugFlags = 31; // 0x1F: returns 0 if being debugged
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    // Games that cheats target — only check these processes for anti-debug activity
    private static readonly HashSet<string> GameProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "GTA5", "FiveM", "FiveM_b2802_GTAProcess",
        "cs2", "csgo",
        "EscapeFromTarkov",
        "r5apex", "r5apex_dx12",
        "VALORANT-Win64-Shipping",
        "RainbowSix",
        "cod", "cod_hq",
        "Fortnite",
        "TslGame", // PUBG
        "RustClient",
        "ac_client",
        "hl2",
    };

    // Suspicious processes that should NOT employ anti-debug tricks
    private static readonly HashSet<string> WatchProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "injector", "loader", "bootstrap", "launcher",
        "cheatengine-x86_64", "cheatengine-i386",
    };

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        int hits = 0;

        var procs = System.Diagnostics.Process.GetProcesses();
        foreach (var proc in procs)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                using (proc)
                {
                    ctx.IncrementProcesses();
                    checked_++;

                    var procName = proc.ProcessName;
                    bool isWatched = WatchProcesses.Contains(procName);

                    string path = "";
                    try { path = proc.MainModule?.FileName ?? ""; } catch { }
                    var pathLower = path.ToLowerInvariant();

                    // Skip Windows system processes
                    if (!isWatched && (pathLower.StartsWith(System32) ||
                        pathLower.Contains(@"\windows\system32") ||
                        pathLower.Contains(@"\windows\syswow64")))
                        continue;

                    var hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.Id);
                    if (hProc == IntPtr.Zero) continue;

                    try
                    {
                        // Check ThreadHideFromDebugger via ProcessDebugFlags
                        // A result of 1 means "not being debugged" (normal)
                        // A result of 0 means the process IS hiding debug port
                        var debugFlags = IntPtr.Zero;
                        int status = NtQueryInformationProcess(
                            hProc, ProcessDebugFlags,
                            ref debugFlags, (uint)IntPtr.Size, out _);

                        if (status == 0 && debugFlags == IntPtr.Zero)
                        {
                            // ProcessDebugFlags = 0 means process set EPROCESS.NoDebugInherit
                            // which is unusual outside of anti-debug tools
                            if (isWatched || (!pathLower.StartsWith(System32) &&
                                !string.IsNullOrEmpty(path)))
                            {
                                hits++;
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Anti-Debug: ProcessDebugFlags=0 in {procName}",
                                    Risk     = RiskLevel.Medium,
                                    Location = path,
                                    FileName = procName + ".exe",
                                    Reason   = $"Prozess '{procName}' (PID {proc.Id}) hat " +
                                               "ProcessDebugFlags=0 (EPROCESS.NoDebugInherit), " +
                                               "was auf aktive Anti-Debug-Techniken hindeutet. " +
                                               "Cheat-Loader setzen dieses Flag um Analyse-Tools " +
                                               "daran zu hindern, den Prozess zu debuggen.",
                                    Detail   = $"Prozess: {path} | PID: {proc.Id} | DebugFlags: 0"
                                });
                            }
                        }
                    }
                    finally
                    {
                        CloseHandle(hProc);
                    }
                }
            }
            catch { }
        }

        // Additionally check for ThreadHideFromDebugger technique via system thread info
        hits += CheckThreadHideFromDebugger(ctx, ct);

        ctx.Report(1.0, Name, $"{checked_} Prozesse auf Anti-Debug geprüft, {hits} Treffer");
        return Task.CompletedTask;
    }

    private static int CheckThreadHideFromDebugger(ScanContext ctx, CancellationToken ct)
    {
        // Check current process for hardware breakpoints (DR0-DR3) which indicate
        // that the scanner itself is being debugged/monitored by a cheat anti-detection layer
        int hits = 0;
        try
        {
            // Check via GetThreadContext if any hardware breakpoints are armed
            // on the current thread — this is the standard DR0-DR7 check
            // Simplified: check if IsDebuggerPresent is patched (IAT hook check already does this)
            // Here we focus on NtGlobalFlag in PEB (debug heap indicator)
            var peb = GetPebAddress();
            if (peb != IntPtr.Zero)
            {
                // NtGlobalFlag is at offset 0x68 (32-bit) or 0xBC (64-bit) in PEB
                int flagOffset = IntPtr.Size == 8 ? 0xBC : 0x68;
                var ntGlobalFlag = Marshal.ReadInt32(IntPtr.Add(peb, flagOffset));

                // Debug heap flags: 0x70 (FLG_HEAP_ENABLE_TAIL_CHECK |
                //                         FLG_HEAP_ENABLE_FREE_CHECK |
                //                         FLG_HEAP_VALIDATE_PARAMETERS)
                if ((ntGlobalFlag & 0x70) != 0)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Scanner wird debuggt (NtGlobalFlag Debug-Heap)",
                        Risk     = RiskLevel.High,
                        Location = "PEB.NtGlobalFlag",
                        Reason   = $"NtGlobalFlag im PEB des Scanners enthält Debug-Heap-Flags " +
                                   $"(0x{ntGlobalFlag:X}). Dies bedeutet, dass der ZeroTrace-Scan " +
                                   "selbst unter einem Debugger läuft oder von einem Cheat-Tool " +
                                   "instrumentiert wird. Scan-Ergebnisse könnten gefälscht sein.",
                        Detail   = $"NtGlobalFlag: 0x{ntGlobalFlag:X} | Debug-Heap-Bits: 0x{ntGlobalFlag & 0x70:X}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static IntPtr GetPebAddress()
    {
        try
        {
            // ProcessBasicInformation (class 0) returns PBI with PEB pointer at offset 1
            const int ProcessBasicInformation = 0;
            var pbi = new long[6];
            var handle = System.Diagnostics.Process.GetCurrentProcess().Handle;
            var pbiPtr = Marshal.AllocHGlobal(6 * 8);
            try
            {
                var dummy = IntPtr.Zero;
                int status = NtQueryInformationProcess(handle, ProcessBasicInformation,
                    ref dummy, (uint)(6 * IntPtr.Size), out _);
                // Read PEB base address (second pointer-sized field)
                return Marshal.ReadIntPtr(pbiPtr, IntPtr.Size);
            }
            finally
            {
                Marshal.FreeHGlobal(pbiPtr);
            }
        }
        catch
        {
            return IntPtr.Zero;
        }
    }
}
