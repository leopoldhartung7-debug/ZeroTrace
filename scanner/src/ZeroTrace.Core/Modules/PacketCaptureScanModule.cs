using Microsoft.Win32;
using System.Diagnostics;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects packet capture and network monitoring tools that can be used to
/// intercept game-server communications for wallhacks, ESP, or radar overlays.
///
/// Cheats that use network-based ESP (e.g. for games with server-authoritative
/// position data) install packet capture drivers to intercept game traffic and
/// extract entity positions. Detection targets:
///
///   1. WinPcap / Npcap installation (both user-mode and driver components).
///
///   2. Raw socket driver services (packet capture kernel drivers).
///
///   3. Running Wireshark, TCPDump, or specialized game-traffic analysis tools.
///
///   4. Network Tap services registered in SCM.
///
///   5. NDIS filter drivers with suspicious names (cheat-written NDIS hooks).
///
///   6. Packet injection tools: NetFilterSDK, WinDivert, WinDivertNT.
/// </summary>
public sealed class PacketCaptureScanModule : IScanModule
{
    public string Name => "Paketerfassung";
    public double Weight => 0.5;
    public int ParallelGroup => 1;

    private static readonly string[] CaptureDriverServices =
    {
        // WinPcap
        "npf", "npfinstall",
        // Npcap
        "npcap", "npcaplwf",
        // WinDivert — used by cheats for packet injection and filtering
        "windivert", "windivert14", "windivert32",
        // NetFilterSDK
        "netfilter2", "netfiltersdk",
        // Generic packet capture drivers
        "pktmon", // Windows Packet Monitor
        "ndiscap", // NDIS capture
        // Suspicious NDIS filter driver names
        "hackndis", "cheatndis", "gamefilter",
        // RawCap / etherpeek
        "rawcap",
    };

    private static readonly string[] CaptureProcesses =
    {
        // Classic tools
        "wireshark", "tshark", "dumpcap", "windump",
        // TCPView / TCPMon
        "tcpview", "tcpmon",
        // Packet injection tools
        "windivert", "windivertcmd",
        // Game-specific traffic analyzers (often cheats)
        "gamepacketsniffer", "gametap", "networkesp",
        "packetsniffer", "packetcapture",
        // Scapy
        "scapy",
        // CommView
        "cv", "commview",
        // OmniPeek / EtherPeek
        "omnipeek", "etherpeek",
    };

    private static readonly string[] CaptureRegistryKeys =
    {
        @"SOFTWARE\WinPcap",
        @"SOFTWARE\Npcap",
        @"SOFTWARE\WinDivert",
        @"SOFTWARE\NetFilterSDK",
        @"SYSTEM\CurrentControlSet\Services\NPF",
        @"SYSTEM\CurrentControlSet\Services\npcap",
        @"SYSTEM\CurrentControlSet\Services\WinDivert",
    };

    // NDIS filter driver class GUID — all registered filter drivers go here
    private const string NdisFilterKey =
        @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

    // Known legitimate NDIS filter drivers that should NOT be flagged
    private static readonly HashSet<string> WhitelistedNdisFilters = new(StringComparer.OrdinalIgnoreCase)
    {
        "ms_msclient", "ms_tcpip", "ms_tcpip6", "ms_pacer",
        "ms_implat", "ms_ndisuio", "ms_netbios", "ms_lltdio",
        "ms_rspndr", "ms_server", "ms_msclientnet",
        "vboxnetflt", "virtualbox", "vmware", "vmnetbridge",
        "npcaplwf", "npf",  // these are already flagged separately
        "ndiscap",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Paketerfassung", "Prüfe Capture-Dienste...");
        CheckCaptureServices(ctx, ct);

        ctx.Report(0.3, "Paketerfassung", "Prüfe Registry...");
        CheckCaptureRegistry(ctx, ct);

        ctx.Report(0.5, "Paketerfassung", "Prüfe Prozesse...");
        CheckCaptureProcesses(ctx, ct);

        ctx.Report(0.75, "Paketerfassung", "Prüfe NDIS-Filter-Treiber...");
        CheckNdisFilters(ctx, ct);

        ctx.Report(1.0, "Paketerfassung", "Paketerfassungs-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    private static void CheckCaptureServices(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (services is null) return;

            foreach (var svcName in services.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                var nameLower = svcName.ToLowerInvariant();
                var matched = CaptureDriverServices.FirstOrDefault(d =>
                    nameLower == d || nameLower.StartsWith(d));
                if (matched is null) continue;

                try
                {
                    using var svc = services.OpenSubKey(svcName, writable: false);
                    if (svc is null) continue;
                    var type = svc.GetValue("Type") as int? ?? 0;
                    var imgPath = svc.GetValue("ImagePath") as string ?? "";
                    var start = svc.GetValue("Start") as int? ?? 3;

                    var isDriver = type == 1 || type == 2;
                    var isRunning = start <= 2; // Boot=0, System=1, Auto=2

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Paketerfassung",
                        Title    = $"Paketerfassungs-Dienst: {svcName}",
                        Risk     = isDriver && isRunning ? RiskLevel.High : RiskLevel.Medium,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        Reason   = $"Bekannter Paketerfassungs-Dienst/Treiber '{svcName}' ist " +
                                   (isRunning ? "aktiv (Autostart)" : "installiert") + ". " +
                                   "Netzwerk-ESP-Cheats nutzen Packet-Capture-Treiber, um " +
                                   "verschlüsselte Spielserver-Pakete abzufangen.",
                        Detail   = $"StartType: {start} | IsDriver: {isDriver} | ImagePath: {imgPath}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CheckCaptureRegistry(ScanContext ctx, CancellationToken ct)
    {
        foreach (var regPath in CaptureRegistryKeys)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();
            try
            {
                // Many are already caught in CheckCaptureServices; only report the
                // user-mode installation keys here
                if (regPath.StartsWith(@"SYSTEM\CurrentControlSet\Services\"))
                    continue;

                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false)
                             ?? Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = "Paketerfassung",
                    Title    = $"Paketerfassung installiert: {Path.GetFileName(regPath)}",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKLM\{regPath}",
                    Reason   = $"Installationsrückstand von '{Path.GetFileName(regPath)}' gefunden. " +
                               "Paketerfassungs-Bibliotheken ermöglichen Netzwerk-ESP-Cheats.",
                    Detail   = $"Registry-Schlüssel: {regPath}"
                });
            }
            catch { }
        }
    }

    private static void CheckCaptureProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementProcesses();
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (!CaptureProcesses.Any(p => name.Contains(p)))
                    {
                        proc.Dispose();
                        continue;
                    }

                    string? exePath = null;
                    try { exePath = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Paketerfassung",
                        Title    = $"Paketerfassungs-Prozess aktiv: {proc.ProcessName}",
                        Risk     = RiskLevel.High,
                        Location = exePath ?? $"PID {proc.Id}",
                        FileName = proc.ProcessName,
                        Reason   = $"Paketerfassungs- oder Netzwerkanalyse-Tool '{proc.ProcessName}' " +
                                   "läuft gerade. Netzwerk-ESP nutzt solche Tools zur Echtzeit-" +
                                   "Spielerdatenextraktion aus Netzwerkpaketen.",
                        Detail   = $"PID: {proc.Id} | Name: {proc.ProcessName}"
                    });
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private static void CheckNdisFilters(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(NdisFilterKey, writable: false);
            if (classKey is null) return;

            // Look in UpperFilters/LowerFilters values of network adapter keys
            foreach (var subKeyName in classKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();
                try
                {
                    using var sub = classKey.OpenSubKey(subKeyName, writable: false);
                    if (sub is null) continue;

                    foreach (var filterProp in new[] { "UpperFilters", "LowerFilters" })
                    {
                        var filters = sub.GetValue(filterProp) as string[];
                        if (filters is null) continue;

                        foreach (var filter in filters)
                        {
                            if (ct.IsCancellationRequested) return;
                            if (WhitelistedNdisFilters.Contains(filter)) continue;

                            // Unknown filter — check if it's in our known capture list
                            var filterLower = filter.ToLowerInvariant();
                            bool isCaptureFilter = CaptureDriverServices.Any(d =>
                                filterLower.Contains(d));

                            if (isCaptureFilter)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Paketerfassung",
                                    Title    = $"NDIS-Filter-Treiber: {filter}",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKLM\{NdisFilterKey}\{subKeyName}",
                                    Reason   = $"Paketerfassungs-NDIS-Filter '{filter}' in Netzwerkadapter " +
                                               $"'{subKeyName}' registriert. NDIS-Filter sehen allen " +
                                               "Netzwerkverkehr ungefiltert.",
                                    Detail   = $"Filter: {filter} | Eigenschaft: {filterProp} | Adapter: {subKeyName}"
                                });
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }
}
