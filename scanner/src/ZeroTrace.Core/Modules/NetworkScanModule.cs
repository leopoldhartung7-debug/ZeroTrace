using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Read-only network surface:
///   - active (established) TCP connections, mapped to the owning process; a
///     connection owned by a process that matches a cheat indicator is flagged
///     (live auth/C2 traffic that the browser-history check would miss);
///   - the DNS client cache, matched against cheat URL-domain indicators (catches
///     recently resolved cheat domains even with no browser trace).
/// Nothing is sent or modified.
/// </summary>
public sealed class NetworkScanModule : IScanModule
{
    public string Name => "Netzwerk";
    public double Weight => 0.4;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        try { ScanTcp(ctx); } catch { }
        ctx.Report(0.6, "Verbindungen", "Aktive Verbindungen geprueft");
        try { ScanDnsCache(ctx); } catch { }
        ctx.Report(1.0, "DNS", "DNS-Cache geprueft");
        return Task.CompletedTask;
    }

    // --- active TCP connections ------------------------------------------------

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(byte[]? table, ref int size, bool order,
        int af, int tableClass, uint reserved);

    private void ScanTcp(ScanContext ctx)
    {
        const int AF_INET = 2;
        const int TCP_TABLE_OWNER_PID_ALL = 5;
        const uint STATE_ESTABLISHED = 5;

        int size = 0;
        GetExtendedTcpTable(null, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 4) return;
        var buf = new byte[size];
        if (GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;

        int count = BitConverter.ToInt32(buf, 0);
        int off = 4;
        const int rowSize = 24; // dwState,localAddr,localPort,remoteAddr,remotePort,owningPid

        for (int i = 0; i < count && off + rowSize <= buf.Length; i++, off += rowSize)
        {
            uint state = BitConverter.ToUInt32(buf, off);
            if (state != STATE_ESTABLISHED) continue;

            uint remoteAddr = BitConverter.ToUInt32(buf, off + 12);
            int remotePort = ((buf[off + 16] << 8) | buf[off + 17]); // network byte order
            int pid = BitConverter.ToInt32(buf, off + 20);
            if (pid <= 4) continue;

            string procName;
            try { using var p = Process.GetProcessById(pid); procName = p.ProcessName + ".exe"; }
            catch { continue; }

            var ind = ctx.Matcher.MatchProcessName(procName) ?? ctx.Matcher.MatchFileName(procName);
            if (ind is null) continue;

            var ip = new IPAddress(BitConverter.GetBytes(remoteAddr)).ToString();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Aktive Verbindung eines verdaechtigen Prozesses: {ind.Category}",
                Risk = ind.Risk,
                Location = $"{procName} (PID {pid}) \u2192 {ip}:{remotePort}",
                FileName = procName,
                Reason = $"Der Prozess '{procName}' entspricht dem Indikator '{ind.Pattern}' und hat eine " +
                         $"aktive Verbindung zu {ip}:{remotePort}. {ind.Description}"
            });
        }
    }

    // --- DNS client cache (best effort; undocumented API) ----------------------

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsCacheEntry
    {
        public IntPtr Next;
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        public ushort Type;
        public ushort DataLength;
        public uint Flags;
    }

    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable", CharSet = CharSet.Unicode)]
    private static extern int DnsGetCacheDataTable(out IntPtr table);

    private void ScanDnsCache(ScanContext ctx)
    {
        if (!ctx.Matcher.HasUrlDomainSignatures) return;
        if (DnsGetCacheDataTable(out var head) != 1 || head == IntPtr.Zero) return;

        var current = head;
        int guard = 0;
        while (current != IntPtr.Zero && guard++ < 20000)
        {
            DnsCacheEntry entry;
            try { entry = Marshal.PtrToStructure<DnsCacheEntry>(current); }
            catch { break; }

            var host = entry.Name;
            if (!string.IsNullOrWhiteSpace(host))
            {
                var ind = ctx.Matcher.MatchUrlDomain(host);
                if (ind is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat-Domain im DNS-Cache: {ind.Category}",
                        Risk = ind.Risk,
                        Location = host!,
                        Reason = $"Die Domain '{host}' wurde kuerzlich aufgeloest (DNS-Cache) und entspricht " +
                                 $"dem Indikator '{ind.Pattern}'. {ind.Description}"
                    });
                }
            }
            current = entry.Next;
        }
    }
}
