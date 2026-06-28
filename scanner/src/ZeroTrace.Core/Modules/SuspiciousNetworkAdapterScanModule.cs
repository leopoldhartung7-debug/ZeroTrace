using System.Runtime.InteropServices;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects suspicious network adapter configurations used by cheat tools, particularly
/// DMA (Direct Memory Access) cheat setups and network-based cheats:
///
///   1. Promiscuous Mode Detection: Adapters in promiscuous mode capture ALL network
///      traffic on the segment, not just traffic addressed to the local MAC. Used by:
///      - Packet-sniffing radar cheats that intercept game server packets to reveal
///        enemy positions without injecting into the game process
///      - DMA cheat setups that use a second machine to read game state via network
///
///   2. Virtual/Bridge Adapter Detection: Certain virtual adapters indicate DMA setups:
///      - PCILeech / MemProcFS: creates a virtual PCIe device that maps as a network
///        adapter on Windows. The DMA hardware (FPGA/hardware implant) presents as
///        a network or USB device to avoid IOMMU detection
///      - WinPcap/NPcap adapters in permanent mode (not just pcap filter, but driver
///        level promiscuous that persists across sessions)
///      - TAP adapters with suspicious names
///
///   3. DMA Hardware Detection:
///      - PCIe FPGA devices (Xilinx, Altera) listed in device manager that don't
///        correspond to known peripheral cards
///      - USB-to-PCIe adapters (UD-6950Z, Thunderbolt devices) used as DMA vectors
///      - Custom PCI device IDs matching known DMA cheat hardware
///
///   4. Network Interface Anomalies:
///      - Adapters with spoofed MAC addresses (first byte OUI check)
///      - Adapters registered but not bound to any protocol
///      - Multiple adapters with the same MAC address
/// </summary>
public sealed class SuspiciousNetworkAdapterScanModule : IScanModule
{
    public string Name => "Suspicious Network Adapter / DMA Hardware Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetAdaptersInfo(nint AdapterInfo, ref uint SizePointer);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetAdaptersAddresses(uint Family, uint Flags, nint Reserved,
        nint AdapterAddresses, ref uint SizePointer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct IP_ADAPTER_INFO
    {
        public nint Next;
        public uint ComboIndex;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string AdapterName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 132)]
        public string Description;
        public uint AddressLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Address;
        public uint Index;
        public uint Type;
        public uint DhcpEnabled;
        public nint CurrentIpAddress;
        // IP_ADDR_STRING IpAddressList (simplified)
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] IpAddressList; // simplified: skip the full nested struct
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] GatewayList;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] DhcpServer;
        public bool HaveWins;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] PrimaryWinsServer;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] SecondaryWinsServer;
        public uint LeaseObtained;
        public uint LeaseExpires;
    }

    private const uint ERROR_BUFFER_OVERFLOW = 111;
    private const uint NO_ERROR              = 0;
    private const uint MIB_IF_TYPE_ETHERNET  = 6;
    private const uint MIB_IF_TYPE_LOOPBACK  = 24;
    private const uint IF_TYPE_IEEE80211     = 71;
    private const uint IF_TYPE_TUNNEL        = 131;

    // Suspicious adapter description keywords indicating DMA/cheat hardware
    private static readonly string[] DmaAdapterKeywords =
    {
        "pcileech", "memflow", "dma", "fpga", "xilinx", "altera",
        "screen-east", "squirrel", "AC701", "SP605",
        "USB Emulation", "DMA Bridge",
    };

    // TAP/virtual adapter keywords used by cheat setups
    private static readonly string[] VirtualAdapterKeywords =
    {
        "tap", "tun", "vpn", "bridge", "virtual", "npcap loopback",
        "winpcap", "npcap",
        // Specific cheat-related virtual adapter names
        "cheat", "hack", "bypass",
    };

    // Known legitimate virtual adapter descriptions
    private static readonly HashSet<string> LegitVirtualAdapters = new(StringComparer.OrdinalIgnoreCase)
    {
        "VirtualBox Host-Only Ethernet Adapter",
        "VMware Virtual Ethernet Adapter for VMnet1",
        "VMware Virtual Ethernet Adapter for VMnet8",
        "Hyper-V Virtual Ethernet Adapter",
        "Microsoft KM-TEST Loopback Adapter",
        "Microsoft Wi-Fi Direct Virtual Adapter",
        "Microsoft Hosted Network Virtual Adapter",
        "Npcap Loopback Adapter",
        "TAP-Windows Adapter V9",      // OpenVPN — often legit
        "TAP Adapter OAS NDIS 6.0",   // ESET
    };

    // Known legitimate OUI prefixes (first 3 bytes of MAC)
    // DMA hardware often uses random/invalid OUIs
    private static readonly HashSet<string> PrivateLocalOuis = new(StringComparer.OrdinalIgnoreCase)
    {
        // Locally administered MAC ranges (bit 1 of first byte set)
        // These are valid for virtual adapters but suspicious for physical hardware
        // We'll flag physical adapters with locally-administered bit set
    };

    // Registry path for network adapter configurations
    private const string NetworkAdaptersKey =
        @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckAdapterList(ctx, ct);
            ct.ThrowIfCancellationRequested();
            CheckRegistryAdapters(ctx, ct);
            ct.ThrowIfCancellationRequested();
            CheckNpcapWinpcap(ctx, ct);
            ct.ThrowIfCancellationRequested();
            CheckDmaDeviceClasses(ctx, ct);
        }, ct);
    }

    private static void CheckAdapterList(ScanContext ctx, CancellationToken ct)
    {
        uint bufSize = 16 * 1024;
        nint buf = Marshal.AllocHGlobal((int)bufSize);
        try
        {
            uint result = GetAdaptersInfo(buf, ref bufSize);
            if (result == ERROR_BUFFER_OVERFLOW)
            {
                Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal((int)bufSize);
                result = GetAdaptersInfo(buf, ref bufSize);
            }
            if (result != NO_ERROR) return;

            nint current = buf;
            var seenMacs = new Dictionary<string, string>(); // mac -> adapter name

            while (current != nint.Zero)
            {
                ct.ThrowIfCancellationRequested();

                IP_ADAPTER_INFO adapter;
                try { adapter = Marshal.PtrToStructure<IP_ADAPTER_INFO>(current); }
                catch { break; }

                ctx.IncrementRegistryKeys();

                string name    = adapter.AdapterName ?? "";
                string desc    = adapter.Description ?? "";
                string descLow = desc.ToLowerInvariant();
                uint type      = adapter.Type;

                // Build MAC string
                string mac = "";
                if (adapter.AddressLength >= 6)
                    mac = string.Join(":", adapter.Address.Take(6).Select(b => b.ToString("X2")));

                // Check for DMA hardware keywords
                string? dmakw = Array.Find(DmaAdapterKeywords, kw => descLow.Contains(kw.ToLowerInvariant()));
                if (dmakw is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Suspicious Network Adapter / DMA Hardware Detection",
                        Title    = $"DMA-Hardware-Adapter erkannt: {desc}",
                        Risk     = RiskLevel.Critical,
                        Location = $"Netzwerkadapter: {name}",
                        FileName = name,
                        Reason   = $"Netzwerkadapter '{desc}' enthält DMA-Cheat-Hardware-Schlüsselwort '{dmakw}' — " +
                                   "PCIe FPGA / PCILeech-basierte DMA-Cheats stellen sich als Netzwerkadapter " +
                                   "dar um IOMMU-Erkennung zu umgehen und direkten Speicherzugriff auf das " +
                                   "Spiel-Prozess-Memory zu erhalten",
                        Detail   = $"Adapter: {desc} | Name: {name} | MAC: {mac} | Typ: {type} | DMA-Kw: {dmakw}"
                    });
                }

                // Check for suspicious virtual adapters
                if (type != MIB_IF_TYPE_ETHERNET && type != IF_TYPE_IEEE80211)
                {
                    string? tapkw = Array.Find(VirtualAdapterKeywords, kw => descLow.Contains(kw.ToLowerInvariant()));
                    if (tapkw is not null && !LegitVirtualAdapters.Contains(desc))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Suspicious Network Adapter / DMA Hardware Detection",
                            Title    = $"Verdächtiger virtueller Netzwerkadapter: {desc}",
                            Risk     = RiskLevel.High,
                            Location = $"Netzwerkadapter: {name}",
                            FileName = name,
                            Reason   = $"Nicht-legitimer virtueller Netzwerkadapter '{desc}' mit TAP/VPN-Schlüsselwort " +
                                       $"'{tapkw}' — kann für Packet-Sniffing-Radar-Cheats oder DMA-Tunnel-Setup genutzt werden",
                            Detail   = $"Adapter: {desc} | Name: {name} | MAC: {mac} | Typ: {type}"
                        });
                    }
                }

                // Check for locally-administered MAC bit on physical adapters (bit 1 of first byte)
                if (adapter.AddressLength >= 6 && type == MIB_IF_TYPE_ETHERNET)
                {
                    bool locallyAdministered = (adapter.Address[0] & 0x02) != 0;
                    bool multicast           = (adapter.Address[0] & 0x01) != 0;
                    bool allZeroMac          = adapter.Address.Take(6).All(b => b == 0);
                    bool allFFMac            = adapter.Address.Take(6).All(b => b == 0xFF);

                    if (locallyAdministered && !allZeroMac && !allFFMac &&
                        !descLow.Contains("virtual") && !descLow.Contains("hyper-v") &&
                        !descLow.Contains("vmware") && !descLow.Contains("virtualbox"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Suspicious Network Adapter / DMA Hardware Detection",
                            Title    = $"MAC-Adress-Spoofing auf physischem Adapter: {desc}",
                            Risk     = RiskLevel.High,
                            Location = $"Netzwerkadapter: {name}",
                            FileName = name,
                            Reason   = $"Physischer Ethernet-Adapter '{desc}' hat lokal verwaltetes MAC-Address-Flag " +
                                       $"(MAC: {mac}) — HWID-Spoofer modifizieren MAC-Adressen um Hardware-Bans zu umgehen",
                            Detail   = $"Adapter: {desc} | MAC: {mac} | Lokal-Admin-Bit: {locallyAdministered}"
                        });
                    }

                    // Duplicate MAC detection
                    if (!string.IsNullOrEmpty(mac) && !allZeroMac && !allFFMac)
                    {
                        if (seenMacs.TryGetValue(mac, out string? prevAdapter))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Suspicious Network Adapter / DMA Hardware Detection",
                                Title    = $"Doppelte MAC-Adresse auf mehreren Adaptern: {mac}",
                                Risk     = RiskLevel.High,
                                Location = $"Netzwerkadapter: {name} und {prevAdapter}",
                                FileName = name,
                                Reason   = $"MAC-Adresse '{mac}' wird von zwei Adaptern geteilt ('{desc}' und '{prevAdapter}') " +
                                           "— deutet auf MAC-Spoofing durch HWID-Spoofer hin",
                                Detail   = $"MAC: {mac} | Adapter 1: {prevAdapter} | Adapter 2: {desc}"
                            });
                        }
                        else
                        {
                            seenMacs[mac] = desc;
                        }
                    }
                }

                current = adapter.Next;
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static void CheckRegistryAdapters(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var adaptersKey = Registry.LocalMachine.OpenSubKey(NetworkAdaptersKey);
            if (adaptersKey is null) return;

            foreach (var subName in adaptersKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                if (subName == "Properties") continue;

                try
                {
                    using var adapterKey = adaptersKey.OpenSubKey(subName);
                    if (adapterKey is null) continue;

                    ctx.IncrementRegistryKeys();

                    string? driverDesc   = adapterKey.GetValue("DriverDesc") as string;
                    string? netCfgInstId = adapterKey.GetValue("NetCfgInstanceId") as string;
                    string? componentId  = adapterKey.GetValue("ComponentId") as string;
                    string? serviceKey   = adapterKey.GetValue("ServiceName") as string;

                    if (driverDesc is null && componentId is null) continue;

                    string combined = $"{driverDesc} {componentId} {serviceKey}".ToLowerInvariant();

                    // Check for NpCap/WinPcap in driver-level configs
                    if (combined.Contains("npcap") || combined.Contains("winpcap") ||
                        combined.Contains("pktmon"))
                    {
                        // Only flag if it's set to a permanent/global capture mode
                        object? promiscuous = adapterKey.GetValue("PromiscuousMode");
                        if (promiscuous is int p && p != 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Suspicious Network Adapter / DMA Hardware Detection",
                                Title    = $"Netzwerkadapter im promiskuösen Modus: {driverDesc}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{NetworkAdaptersKey}\{subName}",
                                FileName = driverDesc ?? subName,
                                Reason   = $"Netzwerkadapter '{driverDesc}' hat PromiscuousMode={p} in der Registry — " +
                                           "promiskuöser Modus ermöglicht Packet-Sniffing aller Netzwerkpakete für " +
                                           "Radar-Cheats die Spielserver-Pakete abfangen",
                                Detail   = $"Adapter: {driverDesc} | ComponentId: {componentId} | " +
                                           $"Service: {serviceKey} | PromiscuousMode: {p}"
                            });
                        }
                    }

                    // Check for DMA-related component IDs or hardware IDs
                    string? hwId = adapterKey.GetValue("MatchingDeviceId") as string;
                    if (hwId is not null)
                    {
                        string hwIdLow = hwId.ToLowerInvariant();
                        string? dmakw = Array.Find(DmaAdapterKeywords, kw => hwIdLow.Contains(kw.ToLowerInvariant()));
                        if (dmakw is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Suspicious Network Adapter / DMA Hardware Detection",
                                Title    = $"DMA-Hardware-ID in Netzwerkadapter-Registry: {hwId}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{NetworkAdaptersKey}\{subName}",
                                FileName = driverDesc ?? subName,
                                Reason   = $"Netzwerkadapter mit Hardware-ID '{hwId}' enthält DMA-Schlüsselwort '{dmakw}' — " +
                                           "DMA-Cheat-Hardware registriert sich als Netzwerkgerät",
                                Detail   = $"HwID: {hwId} | Adapter: {driverDesc} | ComponentId: {componentId}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CheckNpcapWinpcap(ScanContext ctx, CancellationToken ct)
    {
        // Check for NpCap / WinPcap service registrations
        string[] captureServices = { "npcap", "npf", "winpcap", "pktmon", "ndiscap" };

        foreach (var svc in captureServices)
        {
            ct.ThrowIfCancellationRequested();
            string svcKey = $@"SYSTEM\CurrentControlSet\Services\{svc}";
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(svcKey);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                int startType = key.GetValue("Start") is int s ? s : -1;
                string? description = key.GetValue("Description") as string;
                string? imagePath   = key.GetValue("ImagePath") as string;

                if (startType < 0 || startType > 3) continue; // only running/auto services

                // NpCap by itself is not malicious, but combined with promiscuous mode
                // or no legitimate software using it is suspicious
                // We check if it's enabled (Start <= 3 = auto/demand) without a legit owner
                bool isLegitCaptureTool = false;

                // Check if Wireshark, Fiddler, or other legit tools are installed
                string[] legitCaptureTools =
                {
                    @"SOFTWARE\WiresharkGroup\Wireshark",
                    @"SOFTWARE\Microsoft\Fiddler2",
                    @"SOFTWARE\Mefics\Burp",
                };

                foreach (var toolKey in legitCaptureTools)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var tk = Registry.LocalMachine.OpenSubKey(toolKey) ??
                                       Registry.CurrentUser.OpenSubKey(toolKey);
                        if (tk is not null) { isLegitCaptureTool = true; break; }
                    }
                    catch { }
                }

                if (!isLegitCaptureTool && svc != "pktmon" && svc != "ndiscap")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Suspicious Network Adapter / DMA Hardware Detection",
                        Title    = $"Packet-Capture-Treiber ohne legitime Anwendung: {svc}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{svcKey}",
                        FileName = svc,
                        Reason   = $"Packet-Capture-Treiber '{svc}' (Start-Typ {startType}) ist installiert " +
                                   "aber keine bekannte legitime Capture-Anwendung (Wireshark, Fiddler) gefunden — " +
                                   "könnte für Radar-Cheat oder DMA-Sniffing genutzt werden",
                        Detail   = $"Service: {svc} | Start: {startType} | Image: {imagePath} | " +
                                   $"Beschreibung: {description}"
                    });
                }
            }
            catch { }
        }
    }

    private static void CheckDmaDeviceClasses(ScanContext ctx, CancellationToken ct)
    {
        // Check PCI device registry for known DMA cheat hardware signatures
        // PCI devices are enumerated under HKLM\SYSTEM\CurrentControlSet\Enum\PCI
        const string pciEnumKey = @"SYSTEM\CurrentControlSet\Enum\PCI";

        // Known DMA cheat hardware vendor/device IDs (VID_xxxx&PID_xxxx format)
        // PCILeech FPGA boards use various IDs depending on firmware
        string[] suspiciousPciIds =
        {
            // Xilinx/AMD FPGA evaluation boards used for DMA cheats
            "VID_10EE",  // Xilinx (AMD) — PCILeech commonly uses Xilinx FPGAs
            "VID_1172",  // Altera (Intel) FPGA
            // Screen-East DMA hardware
            "VID_1234&PID_1111",  // QEMU/custom DMA test device ID often used
            // USB-to-PCIe DMA adapters
            "VID_2109&PID_0715",  // VLI USB-PCIe bridge (used in some DMA setups)
        };

        try
        {
            using var pciKey = Registry.LocalMachine.OpenSubKey(pciEnumKey);
            if (pciKey is null) return;

            foreach (var devId in pciKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                string devIdUpper = devId.ToUpperInvariant();
                string? matchedId = Array.Find(suspiciousPciIds,
                    id => devIdUpper.StartsWith(id.ToUpperInvariant()));

                if (matchedId is null) continue;

                try
                {
                    using var devKey = pciKey.OpenSubKey(devId);
                    if (devKey is null) continue;

                    foreach (var instanceId in devKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var instanceKey = devKey.OpenSubKey(instanceId);
                            string? friendlyName = instanceKey?.GetValue("FriendlyName") as string ??
                                                   instanceKey?.GetValue("DeviceDesc") as string;
                            string? driver = instanceKey?.GetValue("Driver") as string;

                            // Xilinx/Altera FPGA boards in eval/development mode
                            // without a known legitimate FPGA application are suspicious
                            string descLow = (friendlyName ?? "").ToLowerInvariant();
                            bool isLegitFpga = descLow.Contains("ethernet") ||
                                               descLow.Contains("audio") ||
                                               descLow.Contains("serial");

                            if (!isLegitFpga)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = "Suspicious Network Adapter / DMA Hardware Detection",
                                    Title    = $"FPGA/DMA-Hardware in PCI-Geräteliste: {devId}",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKLM\{pciEnumKey}\{devId}\{instanceId}",
                                    FileName = devId,
                                    Reason   = $"PCI-Gerät '{devId}' ({friendlyName ?? "unbekannt"}) ist eine " +
                                               $"FPGA-Evaluierungsplatine (VID match: {matchedId}) ohne erkannte " +
                                               "legitime FPGA-Anwendung — PCILeech und andere DMA-Cheat-Tools " +
                                               "verwenden Xilinx/Altera FPGAs für direkten Speicherzugriff",
                                    Detail   = $"DevID: {devId} | Instance: {instanceId} | " +
                                               $"Name: {friendlyName} | Treiber: {driver} | VID-Match: {matchedId}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch { }
    }
}
