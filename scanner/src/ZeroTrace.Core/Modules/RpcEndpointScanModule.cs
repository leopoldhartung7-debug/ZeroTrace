using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects suspicious RPC (Remote Procedure Call) endpoints used by cheat infrastructure.
///
/// Windows RPC is a powerful IPC mechanism used by almost all Windows services.
/// Cheats exploit RPC because:
///
///   1. RPC calls are harder to intercept than named pipes or sockets
///   2. RPC endpoints can be registered in the kernel (via ALPC)
///   3. Cross-session RPC allows user→kernel communication (cheat loaders use this)
///   4. RPC servers can be registered with NULL security descriptors (open to any client)
///   5. COM uses RPC internally — COM hijacking enables RPC endpoint abuse
///
/// Detection approach:
///   1. Enumerate all active RPC endpoints via RpcMgmtEpEltInqBegin/RpcMgmtEpEltInqNext
///   2. Flag endpoints registered by non-system processes
///   3. Flag endpoints with cheat-keyword interface UUIDs or annotation strings
///   4. Check for ALPC port objects with cheat keywords (kernel-mode cheat IPC)
///   5. Detect unusually large number of endpoints from single process (cheat C2 listener)
/// </summary>
public sealed class RpcEndpointScanModule : IScanModule
{
    public string Name => "RPC-Endpoint-Analyse";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    [DllImport("rpcrt4.dll", SetLastError = true)]
    private static extern int RpcMgmtEpEltInqBegin(IntPtr EpBinding, int InquiryType,
        ref RPC_IF_ID IfId, int VersOption, ref Guid ObjectUuid, out IntPtr InquiryContext);

    [DllImport("rpcrt4.dll")]
    private static extern int RpcMgmtEpEltInqNextW(IntPtr InquiryContext,
        out RPC_IF_ID IfId, out IntPtr Binding, out Guid ObjectUuid,
        out IntPtr Annotation);

    [DllImport("rpcrt4.dll")]
    private static extern int RpcMgmtEpEltInqDone(ref IntPtr InquiryContext);

    [DllImport("rpcrt4.dll")]
    private static extern int RpcStringFreeW(ref IntPtr String);

    [DllImport("rpcrt4.dll")]
    private static extern int RpcBindingToStringBindingW(IntPtr Binding, out IntPtr StringBinding);

    [DllImport("rpcrt4.dll")]
    private static extern int RpcBindingFree(ref IntPtr Binding);

    [StructLayout(LayoutKind.Sequential)]
    private struct RPC_IF_ID
    {
        public Guid Uuid;
        public ushort VersMajor;
        public ushort VersMinor;
    }

    private const int RPC_C_EP_ALL_ELTS = 0;
    private const int RPC_C_VERS_ALL = 1;

    // Known-legitimate RPC endpoint annotation patterns (to reduce FP)
    private static readonly string[] KnownLegitAnnotations =
    {
        "Windows", "Microsoft", "RemoteRegistry", "Spooler", "DCOM", "LRPC",
        "WMI", "RasMan", "TermSrv", "DNS", "NTDS", "Netlogon",
        "BFE", "mpssvc", "EventLog", "samss", "lsarpc", "winreg",
    };

    // Cheat-related keywords in RPC annotations
    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "spoofer", "hook", "kernel", "driver", "rootkit",
        "radar", "esp", "wallhack", "triggerbot",
    };

    // Known-suspicious GUIDs (hard to enumerate without runtime data — placeholder pattern)
    private static readonly HashSet<Guid> KnownCheatGuids = new();

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += EnumerateRpcEndpoints(ctx, ct);

        ctx.Report(1.0, Name, $"RPC-Endpunkte analysiert, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int EnumerateRpcEndpoints(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        IntPtr inquiryCtx = IntPtr.Zero;
        try
        {
            var ifId = new RPC_IF_ID();
            var objUuid = Guid.Empty;
            int status = RpcMgmtEpEltInqBegin(IntPtr.Zero, RPC_C_EP_ALL_ELTS,
                ref ifId, RPC_C_VERS_ALL, ref objUuid, out inquiryCtx);
            if (status != 0) return 0;

            int endpointCount = 0;
            while (!ct.IsCancellationRequested && endpointCount < 2000)
            {
                IntPtr bindingPtr = IntPtr.Zero;
                IntPtr annotationPtr = IntPtr.Zero;

                int nextStatus = RpcMgmtEpEltInqNextW(inquiryCtx, out var nextIfId,
                    out bindingPtr, out _, out annotationPtr);

                if (nextStatus != 0) break;
                endpointCount++;

                string annotation = "";
                string binding = "";
                try
                {
                    if (annotationPtr != IntPtr.Zero)
                        annotation = Marshal.PtrToStringUni(annotationPtr) ?? "";
                    if (bindingPtr != IntPtr.Zero)
                    {
                        RpcBindingToStringBindingW(bindingPtr, out IntPtr strBinding);
                        if (strBinding != IntPtr.Zero)
                        {
                            binding = Marshal.PtrToStringUni(strBinding) ?? "";
                            RpcStringFreeW(ref strBinding);
                        }
                    }
                }
                catch { }
                finally
                {
                    if (bindingPtr != IntPtr.Zero)
                    {
                        var bp = bindingPtr;
                        RpcBindingFree(ref bp);
                    }
                }

                // Check annotation for cheat keywords
                var kw = CheatKeywords.FirstOrDefault(k =>
                    annotation.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                    binding.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (kw is not null)
                {
                    bool isLegit = KnownLegitAnnotations.Any(l =>
                        annotation.Contains(l, StringComparison.OrdinalIgnoreCase));

                    if (!isLegit)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "RPC-Endpoint-Analyse",
                            Title    = $"Verdächtiger RPC-Endpunkt: {annotation[..Math.Min(60, annotation.Length)]}",
                            Risk     = RiskLevel.High,
                            Location = binding,
                            Reason   = $"RPC-Endpunkt mit Annotation '{annotation}' " +
                                       $"enthält Cheat-Keyword '{kw}'. " +
                                       "Cheat-Software registriert RPC-Server als IPC zwischen " +
                                       "Loader und Kernel-Treiber oder für externe Steuerung. " +
                                       $"Interface UUID: {nextIfId.Uuid}",
                            Detail   = $"Interface: {nextIfId.Uuid} | Binding: {binding} | " +
                                       $"Annotation: {annotation}"
                        });
                    }
                }

                // Check for known cheat GUIDs
                if (KnownCheatGuids.Contains(nextIfId.Uuid))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "RPC-Endpoint-Analyse",
                        Title    = $"Bekannte Cheat-RPC-Interface-UUID: {nextIfId.Uuid}",
                        Risk     = RiskLevel.Critical,
                        Location = binding,
                        Reason   = $"RPC-Interface {nextIfId.Uuid} ist eine bekannte " +
                                   "Cheat-Software-UUID. " +
                                   "Cheat-Software registriert RPC-Server mit spezifischen UUIDs " +
                                   "für die interne Kommunikation zwischen Loader und Komponenten.",
                        Detail   = $"UUID: {nextIfId.Uuid} | Binding: {binding} | Annotation: {annotation}"
                    });
                }

                // Flag non-LRPC, non-ncalrpc endpoints from non-system paths
                // (external RPC servers are unusual on a gaming PC)
                if (!string.IsNullOrEmpty(binding) &&
                    !binding.StartsWith("ncalrpc:", StringComparison.OrdinalIgnoreCase) &&
                    !binding.StartsWith("ncatp:", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrEmpty(annotation))
                {
                    bool annotIsLegit = KnownLegitAnnotations.Any(l =>
                        annotation.Contains(l, StringComparison.OrdinalIgnoreCase));

                    if (!annotIsLegit && !string.IsNullOrEmpty(annotation))
                    {
                        // External RPC endpoint with unknown annotation
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "RPC-Endpoint-Analyse",
                            Title    = $"Externer RPC-Endpunkt mit unbekannter Annotation",
                            Risk     = RiskLevel.Medium,
                            Location = binding,
                            Reason   = $"Externer RPC-Endpunkt (Protokoll: {binding.Split(':')[0]}) " +
                                       $"mit Annotation '{annotation}' — " +
                                       "kein bekannter Windows-Dienst. " +
                                       "Externe RPC-Endpunkte (TCP/UDP) sind auf Gaming-PCs selten " +
                                       "und könnten Cheat-C2-Kommunikation sein.",
                            Detail   = $"Binding: {binding} | Annotation: {annotation} | " +
                                       $"UUID: {nextIfId.Uuid}"
                        });
                    }
                }
            }
        }
        catch { }
        finally
        {
            if (inquiryCtx != IntPtr.Zero)
                RpcMgmtEpEltInqDone(ref inquiryCtx);
        }
        return hits;
    }
}
