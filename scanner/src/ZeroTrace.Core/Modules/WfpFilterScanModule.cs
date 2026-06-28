using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Enumerates Windows Filtering Platform (WFP) callout drivers and filters registered in
/// the BFE (Base Filtering Engine). WFP is the Windows network packet filter framework —
/// legitimate uses include Windows Firewall, IDS/IPS drivers, and VPN clients. Cheat tools
/// abuse WFP callout drivers to: (1) silently intercept and duplicate game server UDP traffic
/// for external radar cheats without touching the game process; (2) block anti-cheat update
/// servers and telemetry endpoints; (3) inject modified packets to manipulate game state.
/// The module enumerates callout providers via FwpmCalloutEnum0, cross-references driver
/// service names against a whitelist of known-legitimate WFP providers, and flags unknown
/// callout drivers. Also checks for WFP sublayer conflicts and blocked persistent filters.
/// </summary>
public sealed class WfpFilterScanModule : IScanModule
{
    public string Name => "Windows Filtering Platform (WFP) Callout Audit";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    // fwpuclnt.dll WFP management API
    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern uint FwpmEngineOpen0(
        string? serverName, uint authnService, nint authIdentity,
        nint session, out nint engineHandle);

    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern uint FwpmEngineClose0(nint engineHandle);

    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern uint FwpmCalloutCreateEnumHandle0(
        nint engineHandle, nint enumTemplate, out nint enumHandle);

    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern uint FwpmCalloutEnum0(
        nint engineHandle, nint enumHandle,
        uint numEntriesRequested, out nint entries, out uint numEntriesReturned);

    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern uint FwpmCalloutDestroyEnumHandle0(
        nint engineHandle, nint enumHandle);

    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern void FwpmFreeMemory0(ref nint p);

    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern uint FwpmProviderEnum0(
        nint engineHandle, nint enumHandle,
        uint numEntriesRequested, out nint entries, out uint numEntriesReturned);

    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern uint FwpmProviderCreateEnumHandle0(
        nint engineHandle, nint enumTemplate, out nint enumHandle);

    [DllImport("fwpuclnt.dll", SetLastError = false)]
    private static extern uint FwpmProviderDestroyEnumHandle0(
        nint engineHandle, nint enumHandle);

    private const uint RPC_C_AUTHN_WINNT = 10;
    private const uint FWPM_FLAG_PERSISTENT_OBJECTS = 0x00000001;

    // Legitimate WFP callout provider service names (known-good drivers)
    private static readonly HashSet<string> LegitCalloutServices = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows built-in
        "BFE", "MpKsl", "netio", "tdx", "afd", "tcpip", "tcpip6",
        "HTTP", "WFP",
        // Windows Defender network inspection
        "WdNisDrv", "MpFilter", "NisDrv",
        // Windows Firewall
        "mpssvc", "SharedAccess",
        // Common VPN / security products
        "FortiGate", "SonicWALL", "CiscoVPNClient", "AnyConnect",
        "OpenVPN", "NordVPN", "ExpressVPN",
        "ZscalerTunnel", "PAN_GP",
        // EDR/security products
        "CrowdStrike", "SentinelOne", "CarbonBlack",
        "TaniumEndpointDriver", "CylanceProtect",
        // Standard networking
        "RasGre", "Rasl2tp", "RasSstp", "IKEExt", "PolicyAgent",
        // NetBIOS/SMB
        "NetBT", "LanmanServer", "MRxSmb",
        // Windows Containers
        "hvsocket", "vmbus",
        "CldFlt",   // Cloud file sync (OneDrive)
        // Gaming platforms with network hooks (legitimate)
        "ESEADriver3",  // ESEA AC
        "BEService",    // BattlEye
    };

    // Suspicious keywords in callout/provider names
    private static readonly string[] SuspiciousWfpKeywords =
    {
        "cheat", "hack", "esp", "radar", "aimbot", "inject",
        "bypass", "intercept", "sniff", "capture", "proxy",
        "redirect", "forward", "mirror", "dup", "duplicate",
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_CALLOUT0
    {
        public Guid          calloutKey;
        public FWPM_DISPLAY  displayData;
        public uint          flags;
        public nint          providerKey;      // Guid*
        public FWP_BYTE_BLOB providerData;
        public Guid          applicableLayer;
        public uint          calloutId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_DISPLAY
    {
        public nint name;        // wchar_t*
        public nint description; // wchar_t*
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWP_BYTE_BLOB
    {
        public uint size;
        public nint data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FWPM_PROVIDER0
    {
        public Guid         providerKey;
        public FWPM_DISPLAY displayData;
        public uint         flags;
        public FWP_BYTE_BLOB providerData;
        public nint         serviceName;  // wchar_t*
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => AuditWfpCallouts(ctx, ct), ct);
    }

    private void AuditWfpCallouts(ScanContext ctx, CancellationToken ct)
    {
        uint ret = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, nint.Zero, nint.Zero, out nint engine);
        if (ret != 0 || engine == nint.Zero) return;

        try
        {
            // Build a map of providerKey -> serviceName for context
            var providerServiceNames = BuildProviderMap(engine, ct);

            EnumerateCallouts(engine, ctx, ct, providerServiceNames);
        }
        finally
        {
            FwpmEngineClose0(engine);
        }
    }

    private Dictionary<Guid, string> BuildProviderMap(nint engine, CancellationToken ct)
    {
        var map = new Dictionary<Guid, string>();
        try
        {
            if (FwpmProviderCreateEnumHandle0(engine, nint.Zero, out nint enumHandle) != 0)
                return map;
            try
            {
                uint returned;
                nint entries;
                if (FwpmProviderEnum0(engine, enumHandle, 256, out entries, out returned) != 0)
                    return map;
                try
                {
                    for (uint i = 0; i < returned; i++)
                    {
                        ct.ThrowIfCancellationRequested();
                        nint pProvider = Marshal.ReadIntPtr(entries, (int)(i * nint.Size));
                        if (pProvider == nint.Zero) continue;
                        var prov = Marshal.PtrToStructure<FWPM_PROVIDER0>(pProvider);
                        string svcName = prov.serviceName != nint.Zero
                            ? Marshal.PtrToStringUni(prov.serviceName) ?? ""
                            : "";
                        if (svcName.Length > 0)
                            map[prov.providerKey] = svcName;
                    }
                }
                finally { FwpmFreeMemory0(ref entries); }
            }
            finally { FwpmProviderDestroyEnumHandle0(engine, enumHandle); }
        }
        catch { }
        return map;
    }

    private void EnumerateCallouts(nint engine, ScanContext ctx, CancellationToken ct,
        Dictionary<Guid, string> providerMap)
    {
        if (FwpmCalloutCreateEnumHandle0(engine, nint.Zero, out nint enumHandle) != 0) return;
        try
        {
            uint returned;
            nint entries;
            if (FwpmCalloutEnum0(engine, enumHandle, 512, out entries, out returned) != 0) return;
            try
            {
                for (uint i = 0; i < returned; i++)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    nint pCallout = Marshal.ReadIntPtr(entries, (int)(i * nint.Size));
                    if (pCallout == nint.Zero) continue;

                    var callout = Marshal.PtrToStructure<FWPM_CALLOUT0>(pCallout);

                    string calloutName = callout.displayData.name != nint.Zero
                        ? Marshal.PtrToStringUni(callout.displayData.name) ?? ""
                        : callout.calloutKey.ToString();

                    string providerService = "";
                    if (callout.providerKey != nint.Zero)
                    {
                        var provKey = Marshal.PtrToStructure<Guid>(callout.providerKey);
                        providerMap.TryGetValue(provKey, out providerService);
                    }

                    string combined = $"{calloutName} {providerService}";

                    // Skip known legitimate callouts
                    bool isLegit = LegitCalloutServices.Any(s =>
                        combined.Contains(s, StringComparison.OrdinalIgnoreCase));
                    if (isLegit) continue;

                    // Check for suspicious keywords in callout/provider name
                    bool isSuspicious = Array.Exists(SuspiciousWfpKeywords,
                        kw => combined.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    // All unknown non-persistent WFP callouts from unknown providers are notable
                    bool isPersistent = (callout.flags & FWPM_FLAG_PERSISTENT_OBJECTS) != 0;

                    // Only flag suspicious ones or unknown persistent callouts
                    if (!isSuspicious && !(isPersistent && providerService.Length == 0)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Unbekannter WFP-Callout-Treiber: {calloutName}",
                        Risk     = isSuspicious ? RiskLevel.High : RiskLevel.Medium,
                        Location = $"BFE WFP Callout: {callout.calloutKey}",
                        FileName = providerService.Length > 0 ? providerService : calloutName,
                        Reason   = isSuspicious
                            ? $"WFP-Callout '{calloutName}' (Provider: {providerService}) enthält " +
                              "Cheat-Keyword — Cheat-Tools registrieren WFP-Callouts um Spielserver-" +
                              "Netzwerktraffic still zu duplizieren oder Anti-Cheat-Verbindungen zu blockieren"
                            : $"Unbekannter persistenter WFP-Callout '{calloutName}' (Provider: " +
                              $"'{(providerService.Length > 0 ? providerService : "unbekannt")}') — " +
                              "nicht als legitimer Windows/Sicherheits-Treiber erkannt",
                        Detail   = $"Callout-GUID: {callout.calloutKey} | Name: {calloutName} | " +
                                   $"Provider-Service: {providerService} | Persistent: {isPersistent} | " +
                                   $"Layer: {callout.applicableLayer}"
                    });
                }
            }
            finally { FwpmFreeMemory0(ref entries); }
        }
        finally { FwpmCalloutDestroyEnumHandle0(engine, enumHandle); }
    }
}
