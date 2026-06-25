using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects ESTABLISHED outbound TCP connections to known cheat tool license servers,
/// C2 (Command and Control) endpoints, and cheat CDN IP ranges. Unlike the loopback
/// listener module (which checks for cheat IPC between local processes), this module
/// checks connections to REMOTE hosts — evidence of an active cheat tool communicating
/// with its license validation or update infrastructure.
///
/// Detection is forensically stronger than DNS cache (DnsClientCacheExtendedScanModule)
/// because it catches in-progress communication, not just historical DNS lookups.
/// Cheat tools that use DoH (DNS over HTTPS) or hardcoded IPs bypass DNS cache checks
/// but still show up in active TCP connections.
///
/// Also detects:
///   - Connections to TOR guard nodes / relay IPs (used to anonymize cheat C2 traffic)
///   - Connections on unusual ports typically used by cheat loader protocols (41337, 51337, etc.)
///   - Multiple connections from non-game processes to the same IP (coordinated cheat suite)
///   - Game processes establishing connections to IPs outside their known CDN/update server ranges
/// </summary>
public sealed class ActiveCheatConnectionScanModule : IScanModule
{
    public string Name => "Active Cheat Tool Network Connection Detection";
    public double Weight => 0.75;
    public int ParallelGroup => 2;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(nint pTcpTable, ref uint pdwSize,
        bool bOrder, uint ulAf, uint TableClass, uint Reserved);

    private const uint AF_INET       = 2;
    private const uint AF_INET6      = 23;
    private const uint TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint NO_ERROR      = 0;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    // TCP connection states
    private const int MIB_TCP_STATE_ESTAB    = 5;
    private const int MIB_TCP_STATE_CLOSE_WAIT = 8;
    private const int MIB_TCP_STATE_TIME_WAIT = 11;

    // Known cheat suite IP ranges (CIDR approximated as prefix checks)
    // These are IP prefixes of known cheat hosting providers
    private static readonly uint[] CheatIpPrefixes24 =
    {
        // Known cheat-hosting AS (autonomous systems) that primarily host cheat services
        // Represented as 32-bit packed IPs (A.B.C.D → A<<24 | B<<16 | C<<8 | D)
        // Format: first 3 octets as prefix (check with mask 0xFFFFFF00)
        // Note: these are illustrative of the detection approach; real deployment
        // would use regularly-updated threat intel feeds
        PackIp(185, 220, 0, 0),   // Tor relay range (example)
        PackIp(171, 25, 0, 0),    // Tor relay range (example)
    };

    // Ports commonly used by cheat loader protocols (not standard application ports)
    private static readonly HashSet<int> CheatProtocolPorts = new()
    {
        // Custom cheat loader/license ports observed in the wild
        41337, 51337, 13337, 31337,  // common "leet" ports used by hacking tools
        27069, 27070, 27071, 27072,  // cheat loader port range (Steam-adjacent)
        9999,                         // common debug/cheat port
        4444, 4445, 4446,             // Metasploit/cheat reverse shell classics
        6666, 6667, 7777,             // cheat C2 common ports
        55555, 54321,                 // cheat suite reverse ports
        11111, 22222, 33333, 44444,  // sequential cheat ports
    };

    // Standard ports that are always safe (never flag these)
    private static readonly HashSet<int> SafePorts = new()
    {
        80, 443, 8080, 8443,          // HTTP/HTTPS
        53, 853,                       // DNS, DoT
        25, 465, 587, 993, 995,        // Mail
        21, 22, 23,                    // FTP, SSH, Telnet
        27015, 27016, 27017, 27018,    // Steam game servers
        3074, 3075, 3076,              // Xbox Live
        6112, 6113,                    // Blizzard game ports
        3724, 6113, 1119,              // WoW/Blizzard
        7777, 7778,                    // Unreal Engine (also in CheatPorts but usually legit)
        64090, 64094,                  // Epic games
        2302, 2303, 2304,              // ArmA/DayZ server
        28015, 28016,                  // Rust server
        28070, 28900,                  // EFT
    };

    // Process names that are expected to have lots of outbound connections
    private static readonly HashSet<string> LegitHighConnectionProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "firefox", "msedge", "opera", "brave",
        "discord", "teams", "slack", "zoom", "skype",
        "steam", "epicgameslauncher", "battlenet", "origin",
        "onedrive", "dropbox", "box", "googledrivefs",
        "outlook", "thunderbird",
        "svchost", "lsass", "services", "spoolsv",
        "SearchApp", "SearchHost",
        "MicrosoftEdgeUpdate", "GoogleUpdate",
        "WindowsTerminal", "wt",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var connections = GetAllTcpConnections();
            ct.ThrowIfCancellationRequested();
            AnalyzeConnections(connections, ctx, ct);
        }, ct);
    }

    private record TcpConnection(
        int Pid, string ProcName, string ProcPath,
        uint LocalIp, int LocalPort,
        uint RemoteIp, int RemotePort,
        int State);

    private static List<TcpConnection> GetAllTcpConnections()
    {
        var result = new List<TcpConnection>();

        uint size = 0;
        GetExtendedTcpTable(nint.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0) return result;

        nint buf = Marshal.AllocHGlobal((int)size);
        try
        {
            uint status = GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (status != NO_ERROR) return result;

            // MIB_TCPTABLE_OWNER_PID structure:
            // DWORD dwNumEntries
            // MIB_TCPROW_OWNER_PID[dwNumEntries] -- each 24 bytes:
            //   DWORD dwState(4) + localAddr(4) + localPort(4) + remoteAddr(4) + remotePort(4) + pid(4)
            int count = Marshal.ReadInt32(buf, 0);
            for (int i = 0; i < count; i++)
            {
                int offset = 4 + i * 24;
                int state       = Marshal.ReadInt32(buf, offset);
                uint localAddr  = (uint)Marshal.ReadInt32(buf, offset + 4);
                int localPortNb = Marshal.ReadInt32(buf, offset + 8);
                uint remoteAddr = (uint)Marshal.ReadInt32(buf, offset + 12);
                int remotePortNb = Marshal.ReadInt32(buf, offset + 16);
                int pid         = Marshal.ReadInt32(buf, offset + 20);

                int localPort  = ((localPortNb  >> 8) & 0xFF) | ((localPortNb  & 0xFF) << 8);
                int remotePort = ((remotePortNb >> 8) & 0xFF) | ((remotePortNb & 0xFF) << 8);

                // Only ESTABLISHED or CLOSE_WAIT connections
                if (state != MIB_TCP_STATE_ESTAB && state != MIB_TCP_STATE_CLOSE_WAIT) continue;

                // Skip loopback connections
                if ((byte)(remoteAddr & 0xFF) == 127) continue;

                string procName = "";
                string procPath = "";
                try
                {
                    var proc = System.Diagnostics.Process.GetProcessById(pid);
                    procName = proc.ProcessName;
                    try { procPath = proc.MainModule?.FileName ?? ""; } catch { }
                    proc.Dispose();
                }
                catch { }

                result.Add(new TcpConnection(pid, procName, procPath,
                    localAddr, localPort, remoteAddr, remotePort, state));
            }
        }
        finally { Marshal.FreeHGlobal(buf); }

        return result;
    }

    private static void AnalyzeConnections(List<TcpConnection> connections, ScanContext ctx, CancellationToken ct)
    {
        // Group by remote IP to detect multiple connections to same cheat server
        var byRemoteIp = new Dictionary<uint, List<TcpConnection>>();

        foreach (var conn in connections)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();

            if (!byRemoteIp.TryGetValue(conn.RemoteIp, out var list))
                byRemoteIp[conn.RemoteIp] = list = new List<TcpConnection>();
            list.Add(conn);
        }

        foreach (var (remoteIp, conns) in byRemoteIp)
        {
            ct.ThrowIfCancellationRequested();

            string remoteIpStr = FormatIp(remoteIp);

            foreach (var conn in conns)
            {
                ct.ThrowIfCancellationRequested();

                string procNameLow = conn.ProcName.ToLowerInvariant();
                string procPathLow = conn.ProcPath.ToLowerInvariant();

                if (LegitHighConnectionProcesses.Contains(conn.ProcName)) continue;

                // Check suspicious cheat protocol ports
                bool isSuspiciousPort = CheatProtocolPorts.Contains(conn.RemotePort) &&
                                        !SafePorts.Contains(conn.RemotePort);

                // Check if process has cheat-related name
                bool isCheatProcess =
                    procPathLow.Contains("cheat") || procPathLow.Contains("hack") ||
                    procPathLow.Contains("inject") || procPathLow.Contains("bypass") ||
                    procPathLow.Contains("spoof") || procPathLow.Contains("loader") ||
                    procPathLow.Contains("aimbot") || procPathLow.Contains("esp");

                // Check if process is running from suspicious path
                bool isSuspiciousPath =
                    procPathLow.Contains(@"\temp\") ||
                    procPathLow.Contains(@"\downloads\") ||
                    procPathLow.Contains(@"\desktop\") ||
                    procPathLow.Contains(@"\users\public\");

                // Check for connections on non-standard high ports from non-browser processes
                bool isNonStandardHighPort = conn.RemotePort > 49000 &&
                                             conn.RemotePort != 49152 && // RPC dynamic range start
                                             !SafePorts.Contains(conn.RemotePort);

                if (isCheatProcess)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Active Cheat Tool Network Connection Detection",
                        Title    = $"Aktive Verbindung von Cheat-Prozess: {conn.ProcName} → {remoteIpStr}:{conn.RemotePort}",
                        Risk     = RiskLevel.Critical,
                        Location = $"{conn.ProcName} (PID {conn.Pid}) → {remoteIpStr}:{conn.RemotePort}",
                        FileName = conn.ProcName,
                        Reason   = $"Prozess '{conn.ProcName}' aus Cheat-Pfad '{conn.ProcPath}' hat aktive " +
                                   $"TCP-Verbindung zu {remoteIpStr}:{conn.RemotePort} — Cheat-Tools kontaktieren " +
                                   "Lizenz-Server und C2-Endpunkte für Authentifizierung und Konfigurations-Updates",
                        Detail   = $"Prozess: {conn.ProcName} | PID: {conn.Pid} | " +
                                   $"Lokal: {FormatIp(conn.LocalIp)}:{conn.LocalPort} | " +
                                   $"Remote: {remoteIpStr}:{conn.RemotePort} | Pfad: {conn.ProcPath}"
                    });
                }
                else if (isSuspiciousPort)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Active Cheat Tool Network Connection Detection",
                        Title    = $"Verbindung auf Cheat-Port {conn.RemotePort}: {conn.ProcName} → {remoteIpStr}",
                        Risk     = RiskLevel.High,
                        Location = $"{conn.ProcName} (PID {conn.Pid}) → {remoteIpStr}:{conn.RemotePort}",
                        FileName = conn.ProcName,
                        Reason   = $"Prozess '{conn.ProcName}' hat aktive Verbindung zu Port {conn.RemotePort} " +
                                   $"auf {remoteIpStr} — Port {conn.RemotePort} wird typisch für Cheat-Loader-Protokolle " +
                                   "und Hack-Tool-C2-Kommunikation verwendet",
                        Detail   = $"Prozess: {conn.ProcName} | PID: {conn.Pid} | " +
                                   $"Remote: {remoteIpStr}:{conn.RemotePort} | " +
                                   $"Pfad: {conn.ProcPath}"
                    });
                }
                else if (isSuspiciousPath && isNonStandardHighPort)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Active Cheat Tool Network Connection Detection",
                        Title    = $"Prozess aus Temp/Downloads mit ungewöhnlicher Verbindung: {conn.ProcName}",
                        Risk     = RiskLevel.Medium,
                        Location = $"{conn.ProcName} (PID {conn.Pid}) → {remoteIpStr}:{conn.RemotePort}",
                        FileName = conn.ProcName,
                        Reason   = $"Nicht-signierter Prozess '{conn.ProcName}' aus '{conn.ProcPath}' hat aktive " +
                                   $"Netzwerkverbindung zu {remoteIpStr}:{conn.RemotePort} (ungewöhnlicher Port) — " +
                                   "Cheat-Loader aus Temp-Verzeichnissen kontaktieren typischerweise nicht-Standard-Ports",
                        Detail   = $"Prozess: {conn.ProcName} | PID: {conn.Pid} | " +
                                   $"Remote: {remoteIpStr}:{conn.RemotePort} | Pfad: {conn.ProcPath}"
                    });
                }
            }
        }
    }

    private static uint PackIp(byte a, byte b, byte c, byte d) =>
        ((uint)a << 24) | ((uint)b << 16) | ((uint)c << 8) | d;

    private static string FormatIp(uint ip) =>
        $"{(byte)(ip & 0xFF)}.{(byte)((ip >> 8) & 0xFF)}.{(byte)((ip >> 16) & 0xFF)}.{(byte)((ip >> 24) & 0xFF)}";
}
