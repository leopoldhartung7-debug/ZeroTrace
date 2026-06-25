using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects non-system processes listening on loopback TCP/UDP ports — a hallmark of cheat
/// IPC channels. Cheat architectures split into multiple cooperating processes: a ring-0 DMA
/// reader, a ring-3 ESP renderer, and a radar bridge all communicate over localhost sockets
/// to share game state without touching the game process directly. The module enumerates all
/// loopback listeners via GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER) and
/// GetExtendedUdpTable(UDP_TABLE_OWNER_PID), cross-references the owning PID against a
/// whitelist of known-legitimate listener processes, and flags unexpected listeners —
/// especially on ports matching the empirically observed cheat IPC range 13337–13999,
/// and processes whose names contain cheat-related keywords.
/// </summary>
public sealed class SuspiciousLoopbackListenerScanModule : IScanModule
{
    public string Name => "Suspicious Loopback Port Listener Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 2;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        nint pTcpTable, ref uint pdwSize, bool bOrder,
        uint ulAf, uint TableClass, uint Reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        nint pUdpTable, ref uint pdwSize, bool bOrder,
        uint ulAf, uint TableClass, uint Reserved);

    private const uint AF_INET  = 2;
    private const uint AF_INET6 = 23;
    private const uint TCP_TABLE_OWNER_PID_LISTENER = 2;
    private const uint UDP_TABLE_OWNER_PID          = 1;

    private static readonly HashSet<string> SystemListenerProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "lsass", "services", "wininit", "csrss", "smss", "System",
        "spoolsv", "wlanext", "audiodg", "winlogon", "fontdrvhost",
        "RuntimeBroker", "SearchHost", "SearchIndexer", "MsMpEng",
        "taskhostw", "dwm", "ShellExperienceHost", "ApplicationFrameHost",
        "SystemSettings", "WmiPrvSE", "dllhost", "conhost", "explorer",
        "OneDrive", "Teams", "TeamsMeetingAddin", "Spotify", "Discord",
        "steam", "steamwebhelper", "EpicGamesLauncher", "EpicWebHelper",
        "origin", "OriginWebHelperService", "Battle.net", "GalaxyClient",
        "GogGalaxy", "BethesdaNetLauncher",
        "node", "python", "python3", "java", "javaw", "pythonw",
        "postgres", "mysqld", "mongod", "redis-server",
        "nginx", "apache", "httpd", "inetinfo", "w3wp",
        "Code", "devenv", "rider64", "idea64", "webstorm64", "clion64",
        "chrome", "msedge", "firefox", "opera", "brave",
        "Zoom", "slack", "skype",
        "vscode-server", "git-remote-http",
        "kubectl", "docker", "containerd", "dockerd",
        "ZeroTrace",
    };

    private static readonly string[] CheatLoopbackKeywords =
    {
        "cheat", "hack", "esp", "radar", "aimbot", "inject", "loader",
        "bypass", "trigger", "spoofer", "rage", "softaim", "silent",
        "overlay", "menu", "trainer", "wallhack", "norecoil",
        "external", "internal", "dumper", "reader",
    };

    // Common legitimate loopback ports — never flag these
    private static readonly HashSet<int> SafePorts = new()
    {
        80, 443, 8080, 8081, 8082, 8443, 8888, 8889, 9000, 9090,
        3000, 3001, 4000, 4200, 5000, 5001, 5173, 5432, 3306,
        27017, 6379, 11211, 9200, 5601, 4369, 5672, 15672,
        1433, 1521, 5900, 5901, 6000, 6001, 7000, 7001,
        9229, 9230, // Node.js inspector
        1716, // Windows Subsystem for Android
        49152, 49153, 49154, 49155, // ephemeral — always skip
    };

    // Observed cheat IPC port ranges
    private const int CheatPortLow  = 13337;
    private const int CheatPortHigh = 13999;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanTcpListeners(ctx, ct);
            ScanUdpListeners(ctx, ct);
        }, ct);
    }

    private void ScanTcpListeners(ScanContext ctx, CancellationToken ct)
    {
        uint size = 0;
        GetExtendedTcpTable(nint.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (size == 0) return;

        nint buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetExtendedTcpTable(buf, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != 0)
                return;

            int count = Marshal.ReadInt32(buf);
            int offset = 4;
            for (int i = 0; i < count; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (offset + 24 > (int)size) break;

                // MIB_TCPROW_OWNER_PID: dwState(4) + dwLocalAddr(4) + dwLocalPort(4) +
                //                       dwRemoteAddr(4) + dwRemotePort(4) + dwOwningPid(4) = 24
                int localAddr = Marshal.ReadInt32(buf, offset + 4);
                int localPort = Marshal.ReadInt32(buf, offset + 8);
                int pid       = Marshal.ReadInt32(buf, offset + 20);
                offset += 24;
                ctx.IncrementRegistryKeys();

                // Only loopback: 127.x.x.x (LSB = 127 in little-endian)
                if ((byte)(localAddr & 0xFF) != 127) continue;

                int port = ((localPort >> 8) & 0xFF) | ((localPort & 0xFF) << 8);
                if (SafePorts.Contains(port)) continue;
                if (port > 49151) continue;   // ephemeral / dynamic range

                string procName = GetProcessName(pid);
                if (SystemListenerProcesses.Contains(procName)) continue;

                bool cheatName = Array.Exists(CheatLoopbackKeywords,
                    kw => procName.Contains(kw, StringComparison.OrdinalIgnoreCase));
                bool cheatPort = port >= CheatPortLow && port <= CheatPortHigh;

                if (!cheatName && !cheatPort) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdächtiger TCP-Loopback-Listener: {procName}:{port}",
                    Risk     = cheatName ? RiskLevel.High : RiskLevel.Medium,
                    Location = $"TCP 127.0.0.1:{port}",
                    FileName = procName,
                    Reason   = cheatName
                        ? $"Prozess '{procName}' (PID {pid}) lauscht auf Loopback-Port {port} " +
                          "und enthält Cheat-Keyword im Namen — typischer IPC-Kanal eines Cheat-Loaders " +
                          "oder Radar-Bridge (DMA-Reader ↔ ESP-Renderer-Kommunikation)"
                        : $"Prozess '{procName}' (PID {pid}) lauscht auf Port {port} " +
                          $"im bekannten Cheat-IPC-Portbereich ({CheatPortLow}–{CheatPortHigh}) — " +
                          "oft genutzt von Radar-Cheats und Loader-Komponenten",
                    Detail   = $"PID: {pid} | Prozess: {procName} | Port: 127.0.0.1:{port} | " +
                               $"Protokoll: TCP | Cheat-Name: {cheatName} | Cheat-Port: {cheatPort}"
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private void ScanUdpListeners(ScanContext ctx, CancellationToken ct)
    {
        uint size = 0;
        GetExtendedUdpTable(nint.Zero, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (size == 0) return;

        nint buf = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetExtendedUdpTable(buf, ref size, false, AF_INET, UDP_TABLE_OWNER_PID, 0) != 0)
                return;

            int count = Marshal.ReadInt32(buf);
            // MIB_UDPROW_OWNER_PID: dwLocalAddr(4) + dwLocalPort(4) + dwOwningPid(4) = 12
            int offset = 4;
            for (int i = 0; i < count; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (offset + 12 > (int)size) break;

                int localAddr = Marshal.ReadInt32(buf, offset);
                int localPort = Marshal.ReadInt32(buf, offset + 4);
                int pid       = Marshal.ReadInt32(buf, offset + 8);
                offset += 12;
                ctx.IncrementRegistryKeys();

                if ((byte)(localAddr & 0xFF) != 127) continue;

                int port = ((localPort >> 8) & 0xFF) | ((localPort & 0xFF) << 8);
                if (SafePorts.Contains(port)) continue;
                if (port > 49151) continue;

                string procName = GetProcessName(pid);
                if (SystemListenerProcesses.Contains(procName)) continue;

                bool cheatName = Array.Exists(CheatLoopbackKeywords,
                    kw => procName.Contains(kw, StringComparison.OrdinalIgnoreCase));
                bool cheatPort = port >= CheatPortLow && port <= CheatPortHigh;

                if (!cheatName && !cheatPort) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdächtiger UDP-Loopback-Listener: {procName}:{port}",
                    Risk     = cheatName ? RiskLevel.High : RiskLevel.Medium,
                    Location = $"UDP 127.0.0.1:{port}",
                    FileName = procName,
                    Reason   = cheatName
                        ? $"Prozess '{procName}' (PID {pid}) hat UDP-Socket auf Loopback-Port {port} " +
                          "mit Cheat-Keyword im Namen — UDP wird von Radar-Cheats für niedrige Latenz genutzt"
                        : $"Prozess '{procName}' (PID {pid}) hat UDP-Socket auf Port {port} " +
                          $"im bekannten Cheat-IPC-Bereich ({CheatPortLow}–{CheatPortHigh})",
                    Detail   = $"PID: {pid} | Prozess: {procName} | Port: 127.0.0.1:{port} | " +
                               $"Protokoll: UDP | Cheat-Name: {cheatName} | Cheat-Port: {cheatPort}"
                });
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private static string GetProcessName(int pid)
    {
        try { return System.Diagnostics.Process.GetProcessById(pid).ProcessName; }
        catch { return $"PID:{pid}"; }
    }
}
