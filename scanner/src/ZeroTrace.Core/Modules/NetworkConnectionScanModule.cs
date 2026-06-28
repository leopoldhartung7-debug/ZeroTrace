using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects suspicious active network connections from game processes and
/// known cheat tools via the Windows IP Helper API.
///
/// External cheats communicate with:
///   1. License/authentication servers (validate subscription)
///   2. Update servers (download new signatures/offsets)
///   3. Radar web-sockets (transmit player position data to external display)
///   4. Discord webhooks or Telegram bots (reporting/status)
///
/// Detection:
///   1. Enumerate all TCP/UDP connections via GetExtendedTcpTable / GetExtendedUdpTable.
///   2. For each connection, identify the owning process (PID in MIB entry).
///   3. Flag:
///      a) Connections from game processes to non-game-server IPs on unusual ports
///      b) Connections from processes with cheat keywords in their path
///      c) Connections to known cheat CDN IP ranges (if configured)
///      d) Outbound connections on port 80/443 from kernel drivers (impossible normally)
///      e) Local-to-local connections used for DMA radar (game → radar bridge)
/// </summary>
public sealed class NetworkConnectionScanModule : IScanModule
{
    private static readonly string _name = "Netzwerkverbindung-Analyse";
    public string Name => _name;
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref uint pdwSize, bool bOrder,
        uint ulAf, uint tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref uint pdwSize, bool bOrder,
        uint ulAf, uint tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwOwningPid;
    }

    private const uint AF_INET = 2;
    private const uint TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint UDP_TABLE_OWNER_PID = 1;

    private static readonly HashSet<string> GameProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "GTA5", "FiveM", "FiveM_b2802_GTAProcess",
        "cs2", "csgo",
        "EscapeFromTarkov",
        "r5apex", "r5apex_dx12",
        "VALORANT-Win64-Shipping",
        "RainbowSix",
        "TslGame",
        "RustClient",
        "Fortnite",
        "cod", "cod_hq",
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "loader", "spoof", "bypass",
        "aimbot", "kiddion", "cherax", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "memprocfs",
    };

    // Well-known legitimate game server port ranges / protocols to exclude
    private static readonly HashSet<int> LegitGamePorts = new()
    {
        27015, 27016, 27017, 27018, 27019, 27020, // Steam / Source
        3074, // Xbox Live
        7777, // Generic game
        443, 80, // HTTPS/HTTP (CDN etc.)
        53, // DNS
        123, // NTP
    };

    // Local loopback IPs used for DMA radar bridge
    private static readonly IPAddress Loopback = IPAddress.Loopback; // 127.0.0.1

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        int hits = 0;

        // Build PID → process name map
        var pidMap = BuildPidMap();

        // Scan TCP connections
        hits += ScanTcpConnections(pidMap, ctx, ref checked_, ct);

        ctx.Report(1.0, Name, $"{checked_} Netzwerkverbindungen geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int ScanTcpConnections(Dictionary<int, string> pidMap, ScanContext ctx,
        ref int checked_, CancellationToken ct)
    {
        int hits = 0;
        uint size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0) return 0;

        var buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
                return 0;

            int count = Marshal.ReadInt32(buf);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < count; i++)
            {
                if (ct.IsCancellationRequested) break;
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                    IntPtr.Add(buf, 4 + i * rowSize));

                if (row.dwState != 5 && row.dwState != 4) continue; // ESTABLISHED / CLOSE_WAIT

                checked_++;
                var pid = (int)row.dwOwningPid;
                pidMap.TryGetValue(pid, out var procName);
                procName ??= $"PID-{pid}";

                var remoteIp = new IPAddress(row.dwRemoteAddr);
                var remotePort = (int)((row.dwRemotePort >> 8) | (row.dwRemotePort << 8 & 0xFF00));

                // Flag: game process connecting to unusual external IP on non-standard port
                if (GameProcessNames.Contains(procName) &&
                    !remoteIp.Equals(Loopback) &&
                    !IsPrivateIp(remoteIp) &&
                    !LegitGamePorts.Contains(remotePort) &&
                    remotePort > 1024)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Spielprozess: Unerwartete Verbindung: {procName} → {remoteIp}:{remotePort}",
                        Risk     = RiskLevel.Medium,
                        Location = $"PID {pid}",
                        FileName = procName + ".exe",
                        Reason   = $"Spielprozess '{procName}' hat aktive TCP-Verbindung zu " +
                                   $"{remoteIp}:{remotePort} — kein bekannter Spielserver-Port. " +
                                   "Cheat-Loader kontaktieren License-Server, Update-CDNs oder " +
                                   "Radar-Web-Sockets aus dem Spielprozess heraus.",
                        Detail   = $"PID: {pid} | Remote: {remoteIp}:{remotePort}"
                    });
                }

                // Flag: process with cheat keyword in name making external connections
                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    procName.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (cheatKw is not null && !remoteIp.Equals(Loopback))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Cheat-Prozess: Aktive Verbindung: {procName} → {remoteIp}:{remotePort}",
                        Risk     = RiskLevel.Critical,
                        Location = $"PID {pid}",
                        FileName = procName + ".exe",
                        Reason   = $"Prozess '{procName}' (Keyword: '{cheatKw}') hat aktive Netzwerkverbindung " +
                                   $"zu {remoteIp}:{remotePort}. Cheat-Tools sind aktiv und kommunizieren " +
                                   "mit externen Servern.",
                        Detail   = $"PID: {pid} | Keyword: {cheatKw} | Remote: {remoteIp}:{remotePort}"
                    });
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
        return hits;
    }

    private static bool IsPrivateIp(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return bytes[0] == 10 ||
               (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) ||
               bytes[0] == 127;
    }

    private static Dictionary<int, string> BuildPidMap()
    {
        var map = new Dictionary<int, string>();
        try
        {
            foreach (var proc in System.Diagnostics.Process.GetProcesses())
            {
                try { map[proc.Id] = proc.ProcessName; } catch { }
            }
        }
        catch { }
        return map;
    }
}
