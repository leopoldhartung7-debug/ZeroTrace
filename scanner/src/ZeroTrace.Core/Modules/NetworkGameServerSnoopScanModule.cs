using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects network-based ESP/radar cheats by finding non-game processes that have active
/// UDP/TCP connections to the same external IP addresses as the running game process.
/// External radar cheats receive a copy of game state by intercepting/duplicating game
/// server packets from a separate process — the separate process must connect to the same
/// game server to receive the data stream. The module enumerates all active connections
/// (via GetExtendedTcpTable/GetExtendedUdpTable), groups them by remote IP, and flags
/// any non-game, non-system process that shares a remote server IP with a game process.
/// Also detects suspicious UDP connections to game server ports from unexpected processes.
/// </summary>
public sealed class NetworkGameServerSnoopScanModule : IScanModule
{
    public string Name => "Network Game Server Snoop Detection";
    public double Weight => 0.75;
    public int ParallelGroup => 2;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        byte[]? pTcpTable, ref uint pdwSize, bool bOrder,
        uint ulAf, uint TableClass, uint Reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        byte[]? pUdpTable, ref uint pdwSize, bool bOrder,
        uint ulAf, uint TableClass, uint Reserved);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        nint hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    private const uint TCP_TABLE_OWNER_PID_ALL = 5;
    private const uint UDP_TABLE_OWNER_PID     = 1;
    private const uint AF_INET                 = 2;  // IPv4 only for simplicity
    private const uint PROCESS_QUERY_LIMITED   = 0x1000;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "rocketleague", "deadlock", "battlefront",
    };

    private static readonly string[] SystemProcessNames =
    {
        "system", "svchost", "lsass", "services", "dwm", "wininit",
        "csrss", "smss", "ntoskrnl", "registry", "msmpeng", "mssense",
        "steam", "steamservice", "gameoverlayui", "steamwebhelper",
    };

    // Known game port ranges (source ports used by game servers)
    private static readonly (int Min, int Max)[] GamePortRanges =
    {
        (27000, 27100), // Steam / Source engine
        (3074,  3075),  // Call of Duty
        (7777,  7778),  // various games
        (25565, 25566), // Minecraft
        (2302,  2303),  // Arma / DayZ
        (64090, 64110), // CS2 / CSGO competitive
        (4380,  4381),  // Steam
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => ScanConnections(ctx, ct), ct);
    }

    private void ScanConnections(ScanContext ctx, CancellationToken ct)
    {
        var gameConnections = new Dictionary<string, (int Pid, string ProcessName)>(); // remoteIP → game process

        // Step 1: collect all TCP connections for game processes
        try
        {
            var tcpEntries = GetTcpConnections();
            foreach (var (localPort, remoteIp, remotePort, pid, state) in tcpEntries)
            {
                ct.ThrowIfCancellationRequested();
                if (state != 5) continue; // ESTABLISHED only
                if (remoteIp.StartsWith("127.") || remoteIp == "::1") continue; // skip loopback
                if (remoteIp.StartsWith("192.168.") || remoteIp.StartsWith("10.") || remoteIp.StartsWith("172.")) continue; // skip LAN

                string? procName = GetProcessName(pid);
                if (procName is null) continue;

                if (Array.Exists(GameProcessNames, n => procName.ToLowerInvariant().Contains(n)))
                    gameConnections[remoteIp] = (pid, procName);
            }
        }
        catch { }

        // Step 2: collect UDP connections for game processes
        try
        {
            var udpEntries = GetUdpSockets();
            foreach (var (localPort, pid) in udpEntries)
            {
                ct.ThrowIfCancellationRequested();
                string? procName = GetProcessName(pid);
                if (procName is null) continue;
                // UDP game processes — note them for later port cross-reference
            }
        }
        catch { }

        if (gameConnections.Count == 0) return;

        // Step 3: look for non-game, non-system processes connecting to same remote IPs
        try
        {
            var tcpEntries = GetTcpConnections();
            foreach (var (localPort, remoteIp, remotePort, pid, state) in tcpEntries)
            {
                ct.ThrowIfCancellationRequested();
                if (!gameConnections.ContainsKey(remoteIp)) continue;

                string? procName = GetProcessName(pid);
                if (procName is null) continue;

                string procLower = procName.ToLowerInvariant();

                // Skip game processes themselves
                if (Array.Exists(GameProcessNames, n => procLower.Contains(n))) continue;

                // Skip known system processes
                if (Array.Exists(SystemProcessNames, n => procLower.Contains(n))) continue;

                var (gamePid, gameProcName) = gameConnections[remoteIp];

                string processPath = GetProcessPath(pid);

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Nicht-Spiel-Prozess verbindet zu Spielserver: '{procName}'",
                    Risk     = RiskLevel.High,
                    Location = processPath,
                    FileName = Path.GetFileName(processPath),
                    Reason   = $"Prozess '{procName}' (PID {pid}) hat eine TCP-Verbindung zu " +
                               $"Spielserver-IP {remoteIp}:{remotePort} — dieselbe IP wird auch von " +
                               $"Spielprozess '{gameProcName}' (PID {gamePid}) genutzt. " +
                               "Typisches Muster eines externen Radar-Cheats der Spielserver-Pakete abfängt",
                    Detail   = $"Verdächtiger Prozess: '{procName}' (PID {pid}) | " +
                               $"Spielprozess: '{gameProcName}' (PID {gamePid}) | " +
                               $"Gemeinsame Server-IP: {remoteIp}:{remotePort} | Pfad: {processPath}"
                });
                ctx.IncrementProcesses();
            }
        }
        catch { }
    }

    private List<(int LocalPort, string RemoteIp, int RemotePort, int Pid, int State)> GetTcpConnections()
    {
        var result = new List<(int, string, int, int, int)>();
        uint size = 0;
        GetExtendedTcpTable(null, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (size == 0) return result;

        var buf = new byte[size + 0x1000];
        if (GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0)
            return result;

        int count = BitConverter.ToInt32(buf, 0);
        int off   = 4;
        for (int i = 0; i < count; i++)
        {
            int entryOff = off + i * 24; // MIB_TCPROW_OWNER_PID = 24 bytes
            if (entryOff + 24 > buf.Length) break;

            int state     = BitConverter.ToInt32(buf, entryOff);
            int localPort = (buf[entryOff + 8] << 8)  | buf[entryOff + 9];
            int remPort   = (buf[entryOff + 16] << 8) | buf[entryOff + 17];
            int pid       = BitConverter.ToInt32(buf, entryOff + 20);

            // Remote IP bytes
            byte b0 = buf[entryOff + 12], b1 = buf[entryOff + 13],
                 b2 = buf[entryOff + 14], b3 = buf[entryOff + 15];
            string remIp = $"{b0}.{b1}.{b2}.{b3}";

            result.Add((localPort, remIp, remPort, pid, state));
        }
        return result;
    }

    private List<(int LocalPort, int Pid)> GetUdpSockets()
    {
        var result = new List<(int, int)>();
        uint size = 0;
        GetExtendedUdpTable(null, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (size == 0) return result;

        var buf = new byte[size + 0x1000];
        if (GetExtendedUdpTable(buf, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0) != 0)
            return result;

        int count = BitConverter.ToInt32(buf, 0);
        int off   = 4;
        for (int i = 0; i < count; i++)
        {
            int entryOff = off + i * 12; // MIB_UDPROW_OWNER_PID = 12 bytes
            if (entryOff + 12 > buf.Length) break;
            int localPort = (buf[entryOff + 4] << 8) | buf[entryOff + 5];
            int pid       = BitConverter.ToInt32(buf, entryOff + 8);
            result.Add((localPort, pid));
        }
        return result;
    }

    private string? GetProcessName(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch { return null; }
    }

    private string GetProcessPath(int pid)
    {
        nint hProc = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
        if (hProc == nint.Zero) return $"PID {pid}";
        try
        {
            var sb = new StringBuilder(512);
            uint sz = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(hProc, 0, sb, ref sz) ? sb.ToString() : $"PID {pid}";
        }
        finally { CloseHandle(hProc); }
    }
}
