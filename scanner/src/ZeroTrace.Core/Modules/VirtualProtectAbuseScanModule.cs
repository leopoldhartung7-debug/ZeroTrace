using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects VirtualProtect abuse in game processes: MEM_IMAGE pages whose current
/// protection has been elevated to PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY.
/// Inline hook installers must first call VirtualProtect to make a .text section
/// page writable before patching a JMP/CALL at the function entry point.
/// Legitimate games and system DLLs never need writable executable image pages —
/// any such region is evidence of in-place code modification (hooking or patching).
/// Also detects AllocationProtect vs current Protect mismatches indicating transient
/// or permanent protection changes on otherwise legitimate loaded modules.
/// </summary>
public sealed class VirtualProtectAbuseScanModule : IScanModule
{
    public string Name => "VirtualProtect Abuse Detection";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint VirtualQueryEx(
        nint hProcess, nint lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

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
    private const uint MEM_IMAGE              = 0x1000000;
    private const uint PAGE_EXECUTE_READ      = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_GUARD             = 0x100;
    private const uint PAGE_NOCACHE           = 0x200;
    private const uint PAGE_WRITECOMBINE      = 0x400;
    private const uint PROTECT_MODIFIER_MASK  = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;

    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "cheat", "loader", "injector", "client",
        "battlefront", "paladins", "rocketleague", "insurgency", "deadlock",
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
                if (findingCount >= 12) break;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
                {
                    uint protect      = mbi.Protect      & ~PROTECT_MODIFIER_MASK;
                    uint allocProtect = mbi.AllocationProtect & ~PROTECT_MODIFIER_MASK;

                    bool isRwx = protect == PAGE_EXECUTE_READWRITE;
                    bool isRwc = protect == PAGE_EXECUTE_WRITECOPY;

                    if (isRwx || isRwc)
                    {
                        bool protectionChanged = protect != allocProtect;
                        string protName = isRwx ? "PAGE_EXECUTE_READWRITE (RWX)" : "PAGE_EXECUTE_WRITECOPY (RWC)";
                        string allocName = allocProtect switch
                        {
                            0x02 => "PAGE_READONLY",
                            0x04 => "PAGE_READWRITE",
                            0x10 => "PAGE_EXECUTE",
                            0x20 => "PAGE_EXECUTE_READ",
                            0x40 => "PAGE_EXECUTE_READWRITE",
                            0x80 => "PAGE_EXECUTE_WRITECOPY",
                            _    => $"0x{allocProtect:X}"
                        };

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Schreibbare Modulseite in '{proc.ProcessName}' @0x{(ulong)mbi.BaseAddress:X}",
                            Risk     = protectionChanged ? RiskLevel.High : RiskLevel.Medium,
                            Location = $"PID {proc.Id} @0x{(ulong)mbi.BaseAddress:X}",
                            FileName = proc.ProcessName,
                            Reason   = $"MEM_IMAGE-Seite bei 0x{(ulong)mbi.BaseAddress:X} in '{proc.ProcessName}' hat " +
                                       $"Schutz {protName}" +
                                       (protectionChanged
                                           ? $" (ursprünglich {allocName}) — VirtualProtect hat Code-Seite beschreibbar gemacht"
                                           : " — unerwartete Berechtigung in geladenem Modul") +
                                       " (typisch für Inline-Hook-Installation oder Byte-Patch)",
                            Detail   = $"Prozess: {proc.ProcessName} (PID {proc.Id}) | " +
                                       $"Basis: 0x{(ulong)mbi.BaseAddress:X} | " +
                                       $"Größe: {mbi.RegionSize} Bytes | " +
                                       $"Schutz: {protName} | AllocSchutz: {allocName}"
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
