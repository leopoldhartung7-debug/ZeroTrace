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
        try { ScanTcp(ctx, AF_INET); } catch { }
        try { ScanTcp(ctx, AF_INET6); } catch { }
        ctx.Report(0.6, "Verbindungen", "Aktive Verbindungen geprueft");
        try { ScanDnsCache(ctx); } catch { }
        ctx.Report(1.0, "DNS", "DNS-Cache geprueft");
        return Task.CompletedTask;
    }

    // --- active TCP connections ------------------------------------------------

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(byte[]? table, ref int size, bool order,
        int af, int tableClass, uint reserved);

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint STATE_ESTABLISHED = 5;

    // MIB_TCPROW_OWNER_PID (IPv4): dwState(4) + localAddr(4) + localPort(4) + remoteAddr(4) + remotePort(4) + pid(4) = 24 bytes
    private const int IPv4RowSize = 24;

    // MIB_TCP6ROW_OWNER_PID (IPv6): localAddr(16) + localScopeId(4) + localPort(4) + remoteAddr(16) + remoteScopeId(4) + remotePort(4) + dwState(4) + pid(4) = 56 bytes
    private const int IPv6RowSize = 56;

    private void ScanTcp(ScanContext ctx, int af)
    {
        int size = 0;
        GetExtendedTcpTable(null, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size <= 4) return;
        var buf = new byte[size];
        if (GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0) != 0) return;

        int count = BitConverter.ToInt32(buf, 0);
        int off = 4;
        int rowSize = af == AF_INET ? IPv4RowSize : IPv6RowSize;

        for (int i = 0; i < count && off + rowSize <= buf.Length; i++, off += rowSize)
        {
            int pid;
            uint state;
            string remoteEndpoint;

            if (af == AF_INET)
            {
                state = BitConverter.ToUInt32(buf, off);
                if (state != STATE_ESTABLISHED) continue;
                uint remoteAddr = BitConverter.ToUInt32(buf, off + 12);
                int remotePort = (buf[off + 16] << 8) | buf[off + 17]; // network byte order
                pid = BitConverter.ToInt32(buf, off + 20);
                remoteEndpoint = $"{new IPAddress(BitConverter.GetBytes(remoteAddr))}:{remotePort}";
            }
            else
            {
                // IPv6: localAddr(16) + localScopeId(4) + localPort(4) + remoteAddr(16) + remoteScopeId(4) + remotePort(4) + dwState(4) + pid(4)
                var remoteAddrBytes = new byte[16];
                Array.Copy(buf, off + 24, remoteAddrBytes, 0, 16);
                int remotePort = (buf[off + 44] << 8) | buf[off + 45]; // network byte order
                state = BitConverter.ToUInt32(buf, off + 48);
                if (state != STATE_ESTABLISHED) continue;
                pid = BitConverter.ToInt32(buf, off + 52);
                remoteEndpoint = $"[{new IPAddress(remoteAddrBytes)}]:{remotePort}";
            }

            if (pid <= 4) continue;

            string procName;
            try { using var p = Process.GetProcessById(pid); procName = p.ProcessName + ".exe"; }
            catch { continue; }

            var ind = ctx.Matcher.MatchProcessName(procName) ?? ctx.Matcher.MatchFileName(procName);
            if (ind is null) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Aktive Verbindung eines verdaechtigen Prozesses: {ind.Category}",
                Risk = ind.Risk,
                Location = $"{procName} (PID {pid}) \u2192 {remoteEndpoint}",
                FileName = procName,
                Reason = $"Der Prozess '{procName}' entspricht dem Indikator '{ind.Pattern}' und hat eine " +
                         $"aktive {(af == AF_INET6 ? "IPv6-" : "")}Verbindung zu {remoteEndpoint}. {ind.Description}"
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
