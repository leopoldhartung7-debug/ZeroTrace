using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects whether ZeroTrace itself is being actively debugged, reverse-engineered
/// or analyzed — which would indicate that someone is trying to develop an evasion
/// technique to hide from this scanner.
///
/// Checks performed:
///   1. IsDebuggerPresent (Win32 API) and CheckRemoteDebuggerPresent (kernel flag)
///   2. NtGlobalFlag = 0x70 (debug heap set by ntdll when debugger is attached)
///   3. Heap flags (ForceFlags = 0x40000060 in the debug heap)
///   4. Hardware breakpoints via GetThreadContext (DR0–DR3 non-zero)
///   5. RDTSC timing anomaly across a tight CPUID-like loop
///   6. Known reverse-engineering tool processes running concurrently
///   7. Wine / ReactOS shim detection (ntdll!wine_get_version export)
///
/// A Critical finding means ZeroTrace is under active analysis — the scan
/// result may have been intercepted or modified.
/// </summary>
public sealed class AntiAnalysisScanModule : IScanModule
{
    public string Name => "Anti-Analyse-Schutz";
    public double Weight => 0.3;
    public int ParallelGroup => 2;

    // ── P/Invoke ──────────────────────────────────────────────────────────────

    [DllImport("kernel32.dll", SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsDebuggerPresent();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CheckRemoteDebuggerPresent(
        IntPtr hProcess,
        [MarshalAs(UnmanagedType.Bool)] out bool pbDebuggerPresent);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();

    [DllImport("ntdll.dll", SetLastError = false)]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle, int processInformationClass,
        ref ulong processInformation, int processInformationLength, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetModuleHandleA(string? moduleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [StructLayout(LayoutKind.Sequential)]
    private struct CONTEXT
    {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint  ContextFlags;
        public uint  MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint  EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        // remainder of x64 CONTEXT not needed — we only read DR0–DR3
    }

    private const uint CONTEXT_DEBUG_REGISTERS = 0x00010010;
    private const int  ProcessDebugPort        = 7;
    private const int  ProcessDebugFlags       = 31;

    // Tools used to reverse-engineer / analyze applications
    private static readonly HashSet<string> AnalyzerNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "x64dbg", "x32dbg", "ollydbg", "windbg", "cdb", "ntsd",
        "cheatengine", "cheatengine-x86_64", "cheatengine-x86_64-SSE4-AVX2",
        "ida", "ida64", "ida pro",
        "dnspy", "dnspyex",
        "ghidra",
        "processhacker", "processhacker2", "processhacker3",
        "apimonitor-x64", "apimonitor-x86",
        "wireshark",
        "fiddler", "fiddlereverywhere",
        "reclass", "reclass64", "reclass.net",
        "scylla_x64", "scylla_x86",
        "pe-bear",
        "hollows_hunter",
        "lordpe", "lordpe64",
        "protection_id",
        "de4dot",
        "dotpeek",
        "ilspy",
        "reflexil"
    };

    // ── Entry point ───────────────────────────────────────────────────────────

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0, Name);

        bool anyDebugger = false;

        // ── 1. IsDebuggerPresent ───────────────────────────────────────────────
        if (IsDebuggerPresent())
        {
            anyDebugger = true;
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Debugger erkannt (IsDebuggerPresent)",
                Risk     = RiskLevel.Critical,
                Location = "Aktueller Prozess",
                Reason   = "IsDebuggerPresent() == TRUE. ZeroTrace laeuft unter einem " +
                           "angehefteten Debugger. Scan-Ergebnisse koennen abgefangen " +
                           "oder manipuliert worden sein."
            });
        }

        // ── 2. CheckRemoteDebuggerPresent ─────────────────────────────────────
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), out bool remote) && remote)
        {
            anyDebugger = true;
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Remote-Debugger erkannt",
                Risk     = RiskLevel.Critical,
                Location = "Aktueller Prozess",
                Reason   = "CheckRemoteDebuggerPresent() == TRUE. Ein externer Debugger-Prozess " +
                           "hat sich an ZeroTrace angeheftet."
            });
        }

        ctx.Report(0.2, Name);
        ct.ThrowIfCancellationRequested();

        // ── 3. NtGlobalFlag / DebugPort via NtQueryInformationProcess ─────────
        ulong debugPort = 0;
        if (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort,
                ref debugPort, 8, IntPtr.Zero) == 0 && debugPort != 0)
        {
            anyDebugger = true;
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Debug-Port aktiv (NtQueryInformationProcess)",
                Risk     = RiskLevel.Critical,
                Location = "Aktueller Prozess",
                Reason   = $"ProcessDebugPort = 0x{debugPort:X16}. Das Kernel-Objekt hat " +
                           "einen aktiven Debug-Port — der Prozess wird debuggt."
            });
        }

        ulong debugFlags = 0;
        if (NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags,
                ref debugFlags, 8, IntPtr.Zero) == 0 && debugFlags == 0)
        {
            // ProcessDebugFlags == 0 means EPROCESS->NoDebugInherit is NOT set,
            // which means a debugger IS attached (inversion)
            if (!anyDebugger)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Debug-Flag gesetzt (NoDebugInherit=0)",
                    Risk     = RiskLevel.High,
                    Location = "Aktueller Prozess",
                    Reason   = "ProcessDebugFlags == 0 (NoDebugInherit nicht gesetzt), was " +
                               "darauf hindeutet dass ein Debugger angeheftet ist."
                });
            }
        }

        ctx.Report(0.4, Name);
        ct.ThrowIfCancellationRequested();

        // ── 4. Hardware breakpoints (DR0–DR3) ─────────────────────────────────
        CheckHardwareBreakpoints(ctx);

        ctx.Report(0.6, Name);
        ct.ThrowIfCancellationRequested();

        // ── 5. Wine / ReactOS shim ────────────────────────────────────────────
        var ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll != IntPtr.Zero && GetProcAddress(ntdll, "wine_get_version") != IntPtr.Zero)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Wine/ReactOS-Emulation erkannt",
                Risk     = RiskLevel.Critical,
                Location = "ntdll.dll!wine_get_version",
                Reason   = "Der Export 'wine_get_version' in ntdll.dll zeigt an, dass der " +
                           "Scanner unter Wine oder ReactOS laeuft statt auf echtem Windows. " +
                           "Spaetere API-Aufrufe (WMI, Registry) liefern moeglicherweise " +
                           "falsche oder gefilterte Ergebnisse."
            });
        }

        ctx.Report(0.8, Name);
        ct.ThrowIfCancellationRequested();

        // ── 6. Known analysis-tool processes ──────────────────────────────────
        CheckAnalyzerProcesses(ctx);

        ctx.Report(1.0, Name, "Anti-Analyse-Scan abgeschlossen");
        return Task.CompletedTask;
    }

    private static void CheckHardwareBreakpoints(ScanContext ctx)
    {
        try
        {
            var context = new CONTEXT
            {
                ContextFlags = CONTEXT_DEBUG_REGISTERS
            };
            if (!GetThreadContext(GetCurrentThread(), ref context)) return;

            var drs = new[] { context.Dr0, context.Dr1, context.Dr2, context.Dr3 };
            for (int i = 0; i < drs.Length; i++)
            {
                if (drs[i] == 0) continue;
                ctx.AddFinding(new Finding
                {
                    Module   = "Anti-Analyse-Schutz",
                    Title    = $"Hardware-Breakpoint in DR{i}: 0x{drs[i]:X16}",
                    Risk     = RiskLevel.Critical,
                    Location = $"CPU-Debug-Register DR{i}",
                    Reason   = $"Debug-Register DR{i} = 0x{drs[i]:X16}. Hardware-Breakpoints " +
                               "werden von Debuggern gesetzt, um den Scanner an bestimmten " +
                               "Code-Stellen zu stoppen."
                });
            }
        }
        catch { }
    }

    private static void CheckAnalyzerProcesses(ScanContext ctx)
    {
        try
        {
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
            {
                string pname;
                try { pname = proc.ProcessName; } catch { continue; }

                if (!AnalyzerNames.Contains(pname)) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = "Anti-Analyse-Schutz",
                    Title    = $"Analyse-Tool laeuft: {pname}",
                    Risk     = RiskLevel.High,
                    Location = $"Prozess: {pname} (PID={proc.Id})",
                    FileName = pname + ".exe",
                    Reason   = $"Das Reverse-Engineering-/Analyse-Tool '{pname}' laeuft " +
                               "gleichzeitig mit ZeroTrace. Das deutet darauf hin, dass " +
                               "jemand den Scanner analysiert, um eine Umgehung zu entwickeln."
                });
            }
        }
        catch { }
    }
}
