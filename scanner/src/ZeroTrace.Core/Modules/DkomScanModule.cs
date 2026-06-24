using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects hidden processes via DKOM (Direct Kernel Object Manipulation) by
/// comparing three independent enumeration sources:
/// 1. NtQuerySystemInformation(SystemProcessInformation) — direct kernel data
/// 2. CreateToolhelp32Snapshot (via Process.GetProcesses) — Win32 Toolhelp32
/// 3. WMI Win32_Process — WMI provider layer
///
/// A process visible in one layer but absent in another is evidence of tampering
/// with kernel EPROCESS list entries — the classic DKOM rootkit/cheat-loader
/// technique to hide a process from Task Manager and anti-cheats.
/// Read-only; nothing is created or modified.
/// </summary>
public sealed class DkomScanModule : IScanModule
{
    public string Name => "DKOM-Prozess-Erkennung";
    public double Weight => 0.5;
    public int ParallelGroup => 2;

    private const int SystemProcessInformation       = 5;
    private const int STATUS_INFO_LENGTH_MISMATCH    = unchecked((int)0xC0000004);
    private const int STATUS_SUCCESS                 = 0;

    // Byte offsets into SYSTEM_PROCESS_INFORMATION (64-bit Windows)
    private const int Off_NextEntryOffset  = 0;
    private const int Off_ImageNameLength  = 56;  // UNICODE_STRING.Length
    private const int Off_ImageNameBuffer  = 64;  // UNICODE_STRING.Buffer (ptr)
    private const int Off_UniqueProcessId  = 80;  // IntPtr

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int    SystemInformationClass,
        IntPtr SystemInformation,
        int    SystemInformationLength,
        out int ReturnLength);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var ntPids  = GetNtProcessMap(ct);
        if (ct.IsCancellationRequested) return Task.CompletedTask;

        var th32Pids = GetToolhelp32ProcessMap();
        var wmiPids  = GetWmiProcessMap();

        // Processes in kernel (NtQSI) but invisible to Toolhelp32 API
        foreach (var (pid, name) in ntPids)
        {
            if (ct.IsCancellationRequested) break;
            if (pid == 0 || pid == 4) continue; // System Idle / System
            if (th32Pids.ContainsKey(pid)) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Versteckter Prozess (DKOM): PID {pid} – {name}",
                Risk     = RiskLevel.Critical,
                Location = $"Kernel-Prozessliste · PID {pid}",
                FileName = name,
                Reason   = $"Prozess PID {pid} ('{name}') ist in der direkten NT-Kernel-Enumeration " +
                           "sichtbar, fehlt aber in der Windows-API (Toolhelp32 / Task Manager). " +
                           "Dies ist das Merkmal von DKOM – ein Cheat-Loader oder Rootkit hat den " +
                           "EPROCESS-Listeneintrag aus der normalen Sicht entfernt.",
            });
        }

        // Processes in WMI but absent from both Toolhelp32 and NtQSI
        foreach (var (pid, name) in wmiPids)
        {
            if (ct.IsCancellationRequested) break;
            if (pid == 0 || pid == 4) continue;
            if (th32Pids.ContainsKey(pid) || ntPids.ContainsKey(pid)) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Prozess nur in WMI sichtbar: PID {pid} – {name}",
                Risk     = RiskLevel.High,
                Location = $"WMI Win32_Process · PID {pid}",
                FileName = name,
                Reason   = $"Prozess PID {pid} ('{name}') erscheint in der WMI-Quelle, ist aber " +
                           "weder in NtQuerySystemInformation noch in Toolhelp32 sichtbar. " +
                           "Deutet auf unvollstaendige DKOM-Manipulation oder WMI-Cache-Anomalie hin.",
            });
        }

        ctx.Report(1.0, "DKOM", "DKOM-Pruefung abgeschlossen");
        return Task.CompletedTask;
    }

    private static Dictionary<int, string> GetNtProcessMap(CancellationToken ct)
    {
        var result = new Dictionary<int, string>();
        int size   = 0x100000; // 1 MB initial

        while (!ct.IsCancellationRequested)
        {
            var buf = Marshal.AllocHGlobal(size);
            try
            {
                int status = NtQuerySystemInformation(SystemProcessInformation, buf, size, out int needed);
                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    size = Math.Max(needed + 0x10000, size * 2);
                    continue;
                }
                if (status != STATUS_SUCCESS) return result;

                long offset = 0;
                while (!ct.IsCancellationRequested)
                {
                    uint next = (uint)Marshal.ReadInt32(buf, (int)offset + Off_NextEntryOffset);
                    int  pid  = Marshal.ReadInt32(buf, (int)offset + Off_UniqueProcessId);

                    ushort nameLen = (ushort)Marshal.ReadInt16(buf, (int)offset + Off_ImageNameLength);
                    IntPtr nameBuf = Marshal.ReadIntPtr(buf + (int)offset + Off_ImageNameBuffer);

                    string name = "";
                    if (nameLen > 0 && nameBuf != IntPtr.Zero)
                        try { name = Marshal.PtrToStringUni(nameBuf, nameLen / 2) ?? ""; } catch { }

                    result[pid] = name;

                    if (next == 0) break;
                    offset += next;
                    if (offset > size) break;
                }
                return result;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        return result;
    }

    private static Dictionary<int, string> GetToolhelp32ProcessMap()
    {
        var result = new Dictionary<int, string>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try { result[p.Id] = p.ProcessName; } catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }
        return result;
    }

    private static Dictionary<int, string> GetWmiProcessMap()
    {
        var result = new Dictionary<int, string>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ProcessId, Name FROM Win32_Process");
            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    int    pid  = Convert.ToInt32(obj["ProcessId"]);
                    string name = obj["Name"]?.ToString() ?? "";
                    result[pid] = name;
                }
                catch { }
            }
        }
        catch { }
        return result;
    }
}
