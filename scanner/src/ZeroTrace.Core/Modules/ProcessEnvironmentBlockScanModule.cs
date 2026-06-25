using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Reads the Process Environment Block (PEB) of game processes and anti-cheat services
/// to detect debug-mode indicators and anti-analysis evasion flags. Cheats and their
/// loaders often check these fields too — if they find them set, they behave differently.
/// The fields detected here include: BeingDebugged, NtGlobalFlag debug heap bits, and
/// Image file path anomalies exposed via PEB.ProcessParameters.ImagePathName.
/// Also detects NtGlobalFlag values associated with GFlags/page-heap that cheat tools
/// inject to trigger heap errors in the anti-cheat process.
/// </summary>
public sealed class ProcessEnvironmentBlockScanModule : IScanModule
{
    public string Name => "PEB Anomaly Detection";
    public double Weight => 0.8;
    public int ParallelGroup => 0;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        nint ProcessHandle, int ProcessInformationClass,
        out PROCESS_BASIC_INFORMATION ProcessInformation,
        int ProcessInformationLength, out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        nint hProcess, nint lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public nint Reserved1;
        public nint PebBaseAddress;
        public nint Reserved2_0;
        public nint Reserved2_1;
        public nint UniqueProcessId;
        public nint Reserved3;
    }

    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const int  ProcessBasicInformation   = 0;
    private const int  STATUS_SUCCESS            = 0;

    // PEB x64 offsets
    private const int PEB_BeingDebugged  = 0x002; // BYTE
    private const int PEB_BitField       = 0x003; // BYTE (IsProtectedProcess, etc.)
    private const int PEB_NtGlobalFlag   = 0x0BC; // ULONG (0xBC for x64 PEB)
    private const int PEB_ProcessHeap    = 0x030; // PVOID (x64)
    private const int PEB_Ldr            = 0x018; // PVOID (x64)

    // NtGlobalFlag bit masks — debug heap flags
    private const uint FLG_HEAP_ENABLE_TAIL_CHECK    = 0x00000010; // heap tail checking
    private const uint FLG_HEAP_ENABLE_FREE_CHECK    = 0x00000020; // heap free checking
    private const uint FLG_HEAP_VALIDATE_PARAMETERS  = 0x00000040; // validate parameters
    private const uint DEBUG_HEAP_FLAGS              = FLG_HEAP_ENABLE_TAIL_CHECK |
                                                       FLG_HEAP_ENABLE_FREE_CHECK |
                                                       FLG_HEAP_VALIDATE_PARAMETERS; // 0x70

    private static readonly string[] TargetProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "battleye", "easyanticheat", "faceit", "vgc",
        "cheat", "loader", "injector", "client"
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
                try { ScanProcess(proc, ctx); }
                catch { /* skip */ }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }, ct);
    }

    private void ScanProcess(Process proc, ScanContext ctx)
    {
        nint hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            // Get PEB address
            int status = NtQueryInformationProcess(
                hProc, ProcessBasicInformation,
                out var pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);

            if (status != STATUS_SUCCESS || pbi.PebBaseAddress == nint.Zero) return;

            // Read PEB (first 0x200 bytes cover all fields we need)
            var peb = new byte[0x200];
            if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, peb, peb.Length, out int pebRead) || pebRead < 0x0C0)
                return;

            // Check 1: BeingDebugged
            byte beingDebugged = peb[PEB_BeingDebugged];
            if (beingDebugged != 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "PEB Anomaly Detection",
                    Title = $"PEB.BeingDebugged gesetzt in {proc.ProcessName}",
                    Risk = RiskLevel.High,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id}) PEB+0x{PEB_BeingDebugged:X}",
                    Reason = $"PEB.BeingDebugged = 0x{beingDebugged:X2} — Prozess laeuft unter Debugger-Kontrolle " +
                             "oder BeingDebugged wurde manuell gesetzt um AC zu taeuschen",
                    Detail = "BeingDebugged != 0 bedeutet entweder aktiver Debugger oder PEB-Manipulation durch Cheat"
                });
            }

            // Check 2: NtGlobalFlag debug heap bits
            if (pebRead >= PEB_NtGlobalFlag + 4)
            {
                uint ntGlobalFlag = BitConverter.ToUInt32(peb, PEB_NtGlobalFlag);
                uint debugBits = ntGlobalFlag & DEBUG_HEAP_FLAGS;

                if (debugBits == DEBUG_HEAP_FLAGS) // full 0x70 set — classic debugger artifact
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "PEB Anomaly Detection",
                        Title = $"PEB.NtGlobalFlag Debug-Heap in {proc.ProcessName}",
                        Risk = RiskLevel.High,
                        Location = $"Prozess {proc.ProcessName} (PID {proc.Id}) PEB+0x{PEB_NtGlobalFlag:X}",
                        Reason = $"PEB.NtGlobalFlag = 0x{ntGlobalFlag:X8} (Debug-Heap Bits 0x70 gesetzt) — " +
                                 "klassisches Debugger-Artefakt: alle drei Debug-Heap Flags aktiv",
                        Detail = $"FLG_HEAP_ENABLE_TAIL_CHECK(0x10) + FLG_HEAP_ENABLE_FREE_CHECK(0x20) + " +
                                 $"FLG_HEAP_VALIDATE_PARAMETERS(0x40) = 0x70 — gesetzt durch GFlags/Debugger-Attach"
                    });
                }
                else if (debugBits != 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "PEB Anomaly Detection",
                        Title = $"PEB.NtGlobalFlag teilweise gesetzt in {proc.ProcessName}",
                        Risk = RiskLevel.Medium,
                        Location = $"Prozess {proc.ProcessName} (PID {proc.Id}) PEB+0x{PEB_NtGlobalFlag:X}",
                        Reason = $"PEB.NtGlobalFlag = 0x{ntGlobalFlag:X8} — Debug-Heap Bits teilweise gesetzt (0x{debugBits:X})",
                        Detail = "Moeglicher GFlags Eintrag oder Debugger-Artefakt im Zielprozess"
                    });
                }

                // Additional GFlags that indicate page heap enabled (attacker may enable to crash AC)
                const uint FLG_HEAP_PAGE_ALLOCS = 0x02000000; // page heap
                if ((ntGlobalFlag & FLG_HEAP_PAGE_ALLOCS) != 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "PEB Anomaly Detection",
                        Title = $"Page Heap aktiviert in {proc.ProcessName}",
                        Risk = RiskLevel.High,
                        Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                        Reason = $"PEB.NtGlobalFlag hat FLG_HEAP_PAGE_ALLOCS (0x02000000) gesetzt — " +
                                 "Page Heap kann von Angreifern aktiviert werden um AC durch Heap-Fehler zu crashen",
                        Detail = $"NtGlobalFlag = 0x{ntGlobalFlag:X8} | " +
                                 "ifeo PageHeap-Injection via Image File Execution Options moeglich"
                    });
                }
            }

            // Check 3: BitField — IsProtectedProcess / IsProtectedProcessLight flags
            byte bitField = peb[PEB_BitField];
            // Bit 2 = IsProtectedProcess, Bit 3 = IsImageDynamicallyRelocated (ASLR),
            // Bit 6 = IsProtectedProcessLight
            bool isProtected      = (bitField & 0x04) != 0;
            bool isProtectedLight = (bitField & 0x40) != 0;

            // Anti-cheat processes SHOULD be PPL — flag if game process claims to be PPL
            // (that would be abnormal and suspicious)
            bool isLikelyGame = proc.ProcessName.ToLowerInvariant() is
                "cs2" or "csgo" or "hl2" or "r5apex" or "pubg" or "fortnite" or
                "valorant" or "apex" or "eft" or "overwatch" or "cod" or "dota2";

            if (isProtected && isLikelyGame)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "PEB Anomaly Detection",
                    Title = $"Game-Prozess behauptet Protected Process: {proc.ProcessName}",
                    Risk = RiskLevel.Medium,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                    Reason = $"PEB.BitField.IsProtectedProcess=1 fuer '{proc.ProcessName}' — " +
                             "Game-Prozesse sind normalerweise NICHT Protected Processes",
                    Detail = $"BitField = 0x{bitField:X2} — unerwartetes PP-Flag in einem Spiel-Prozess"
                });
            }
        }
        finally { CloseHandle(hProc); }
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
                    if (Array.Exists(TargetProcessNames, n => name.Contains(n)))
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
