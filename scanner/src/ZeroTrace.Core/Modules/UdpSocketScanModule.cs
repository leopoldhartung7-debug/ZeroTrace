using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans active UDP sockets and detects suspicious network listeners.
///
/// While NetworkConnectionScanModule covers TCP connections from game processes,
/// this module focuses on UDP — the protocol used by many cheat components:
///
///   1. DMA Radar external network: Some DMA radar systems use UDP to transmit
///      entity data from the cheat PC to an external display device (phone/tablet/PC).
///
///   2. Cheat overlay network: ESP overlay communicates via UDP loopback or LAN.
///
///   3. Cheat license server check-in: Some cheats ping their license server
///      via UDP to avoid TCP connection tracking.
///
///   4. DNS tunneling: Advanced cheats exfiltrate data via crafted DNS queries
///      over UDP port 53 to avoid firewall inspection.
///
///   5. Game packet interception: Packet-based cheats (wallhack, speed hack)
///      bind to UDP ports used by the game to intercept or forge packets.
///
/// Uses GetExtendedUdpTable (IP Helper API) to enumerate all active UDP sockets
/// with owner process IDs, similar to the TCP module's approach.
/// </summary>
public sealed class UdpSocketScanModule : IScanModule
{
    public string Name => "UDP-Socket-Analyse";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref uint pdwSize, bool bOrder,
        uint ulAf, uint tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public int  dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPTABLE_OWNER_PID
    {
        public uint dwNumEntries;
        // MIB_UDPROW_OWNER_PID[] follows
    }

    private const uint AF_INET = 2;
    private const uint UDP_TABLE_OWNER_PID = 1;

    // Suspicious destination ports used by cheat systems
    private static readonly HashSet<int> SuspiciousLocalPorts = new()
    {
        4444, 4445, 4446,    // common reverse shell / C2 ports
        1337, 31337,         // "elite" hacker ports
        6666, 6667, 6668,    // IRC (sometimes used for C2)
        8888, 9999,          // generic bot ports
        55555, 54321,        // reversed well-known ports
    };

    // Known legitimate game UDP ports (to reduce false positives)
    private static readonly HashSet<int> KnownGamePorts = new()
    {
        // Steam
        27000, 27001, 27002, 27003, 27004, 27005,
        27010, 27011, 27012, 27013, 27014, 27015,
        27016, 27017, 27018, 27019, 27020,
        // EA / Origin
        1024, 3659, 9988, 17503, 17504,
        // Riot Games
        5222, 8088,
        // Activision / Blizzard
        3724, 6012, 1119,
        // General gaming
        7777, 7778, 8472,
    };

    // Cheat-keyword process names to flag even on normal ports
    private static readonly string[] CheatProcessKeywords =
    {
        "cheat", "hack", "inject", "radar", "esp",
        "kiddion", "cherax", "aimware", "spoofer",
        "loader", "bypass",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var rows = GetUdpTable();

        // Build a PID→process name map
        var pidNames = BuildPidNameMap();

        foreach (var row in rows)
        {
            if (ct.IsCancellationRequested) break;

            var localPort = (int)BitConverter.ToUInt16(
                new[] { (byte)(row.dwLocalPort >> 8), (byte)(row.dwLocalPort & 0xFF) }, 0);

            var localAddr = new IPAddress(row.dwLocalAddr);
            var pid       = row.dwOwningPid;
            pidNames.TryGetValue(pid, out var procName);
            procName ??= $"PID {pid}";

            var nameLower = procName.ToLowerInvariant();

            // Check if the process name contains cheat keywords
            var cheatKw = CheatProcessKeywords.FirstOrDefault(k =>
                nameLower.Contains(k, StringComparison.OrdinalIgnoreCase));

            bool isSuspiciousPort = SuspiciousLocalPorts.Contains(localPort);
            bool isGamePort       = KnownGamePorts.Contains(localPort);

            // Only flag suspicious ports or cheat-named processes
            if (cheatKw is null && !isSuspiciousPort) continue;
            if (isGamePort && cheatKw is null) continue;

            hits++;
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Verdächtiger UDP-Socket: {procName}:{localPort}",
                Risk     = cheatKw is not null ? RiskLevel.High : RiskLevel.Medium,
                Location = $"{localAddr}:{localPort} (PID {pid})",
                Reason   = $"Prozess '{procName}' (PID {pid}) hört auf UDP {localAddr}:{localPort}. " +
                           (cheatKw is not null
                               ? $"Prozessname enthält Cheat-Keyword '{cheatKw}'. "
                                 + "Cheat-Tools nutzen UDP für DMA-Radar-Datenübertragung, ESP-Overlay-IPC "
                                 + "und Lizenzserver-Kommunikation. "
                               : $"Port {localPort} ist ein bekannter C2/Reverse-Shell-Port. "),
                Detail   = $"Prozess: {procName} | PID: {pid} | UDP: {localAddr}:{localPort} | Keyword: {cheatKw ?? "keins"}"
            });
        }

        ctx.Report(1.0, Name, $"{rows.Count} UDP-Sockets geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static List<MIB_UDPROW_OWNER_PID> GetUdpTable()
    {
        var result = new List<MIB_UDPROW_OWNER_PID>();
        uint size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (size == 0) return result;

        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetExtendedUdpTable(buf, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0) != 0)
                return result;

            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            int offset  = 4; // skip dwNumEntries

            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(
                    IntPtr.Add(buf, offset));
                result.Add(row);
                offset += rowSize;
            }
        }
        catch { }
        finally { Marshal.FreeHGlobal(buf); }
        return result;
    }

    private static Dictionary<int, string> BuildPidNameMap()
    {
        var map = new Dictionary<int, string>();
        try
        {
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
            {
                try { map[proc.Id] = proc.ProcessName; }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
        return map;
    }
}
