using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects debuggers attached to game processes using kernel-level indicators that
/// cannot be spoofed from userland without a driver. Unlike PEB.BeingDebugged (trivially
/// cleared by cheat loaders), three independent kernel-side signals are queried via
/// NtQueryInformationProcess:
///   - ProcessDebugPort (class 7): kernel HANDLE non-zero when debugger is attached
///   - ProcessDebugObjectHandle (class 30): handle to the debug object in the kernel
///   - ProcessDebugFlags (class 31): value 0 means debugger present (inverted flag)
/// Any combination of these signals with a game process as target indicates Cheat Engine,
/// x64dbg, WinDbg, or a custom debugger-based cheat tool is actively attached.
/// </summary>
public sealed class DebuggerAttachDetectionScanModule : IScanModule
{
    public string Name => "Debugger Attach Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 0;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        nint ProcessHandle, int ProcessInformationClass,
        ref nint ProcessInformation, uint ProcessInformationLength,
        out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    private const int  ProcessDebugPort         = 7;
    private const int  ProcessDebugObjectHandle  = 30;
    private const int  ProcessDebugFlags         = 31;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const int  STATUS_SUCCESS            = 0;

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "battlefront", "paladins", "rocketleague",
        "insurgency", "l4d2", "deadlock",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            foreach (var proc in Process.GetProcesses())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (!Array.Exists(GameProcessNames, n => name.Contains(n)))
                        continue;

                    CheckProcess(proc, ctx);
                    ctx.IncrementProcesses();
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }, ct);
    }

    private void CheckProcess(Process proc, ScanContext ctx)
    {
        nint hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            bool hasDebugPort  = false;
            bool hasDebugObj   = false;
            bool debugFlagZero = false;
            nint debugPortVal  = nint.Zero;

            // Signal 1: ProcessDebugPort — non-zero kernel handle means debugger attached
            nint val = nint.Zero;
            int status = NtQueryInformationProcess(hProc, ProcessDebugPort,
                ref val, (uint)nint.Size, out _);
            if (status == STATUS_SUCCESS && val != nint.Zero)
            {
                hasDebugPort = true;
                debugPortVal = val;
            }

            // Signal 2: ProcessDebugObjectHandle — returns the debug object handle
            val = nint.Zero;
            status = NtQueryInformationProcess(hProc, ProcessDebugObjectHandle,
                ref val, (uint)nint.Size, out _);
            if (status == STATUS_SUCCESS && val != nint.Zero)
            {
                hasDebugObj = true;
                CloseHandle(val); // we received ownership of this handle
            }

            // Signal 3: ProcessDebugFlags — 0 = debugger attached (kernel sets 0 on attach)
            val = nint.Zero;
            status = NtQueryInformationProcess(hProc, ProcessDebugFlags,
                ref val, (uint)nint.Size, out _);
            if (status == STATUS_SUCCESS && val == nint.Zero)
                debugFlagZero = true;

            if (!hasDebugPort && !hasDebugObj && !debugFlagZero) return;

            int signals = (hasDebugPort ? 1 : 0) + (hasDebugObj ? 1 : 0) + (debugFlagZero ? 1 : 0);
            RiskLevel risk = signals >= 2 ? RiskLevel.Critical : RiskLevel.High;

            var evidence = new System.Text.StringBuilder();
            if (hasDebugPort)  evidence.Append($"DebugPort=0x{(ulong)debugPortVal:X} ");
            if (hasDebugObj)   evidence.Append("DebugObjectHandle≠0 ");
            if (debugFlagZero) evidence.Append("DebugFlags=0 ");

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Debugger an '{proc.ProcessName}' (PID {proc.Id}) angehängt",
                Risk     = risk,
                Location = proc.ProcessName,
                FileName = proc.ProcessName,
                Reason   = $"NtQueryInformationProcess meldet {signals} Kernel-Signal(e) für aktiven Debugger an " +
                           $"'{proc.ProcessName}' (PID {proc.Id}) — Cheat Engine, x64dbg, WinDbg oder " +
                           "ein Custom-Debugger-Cheat ist aktiv angehängt",
                Detail   = $"Signale ({signals}/3): {evidence.ToString().Trim()} | " +
                           "Kernel-seitige Indikatoren — nicht aus Userland manipulierbar ohne Treiber"
            });
        }
        finally
        {
            CloseHandle(hProc);
        }
    }
}
