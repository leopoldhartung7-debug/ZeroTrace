using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects game processes with critically weak or deliberately disabled mitigation policies.
/// GetProcessMitigationPolicy (Windows 8+) exposes per-process security settings: DEP,
/// ASLR, Code Integrity Guard (CIG), Control Flow Guard (CFG), Arbitrary Code Guard (ACG),
/// font/image load restrictions, heap termination-on-corruption, and extension points.
/// External cheat tools that need to inject code into a game process often need to disable
/// these protections first — they inject via a BYOVD driver that calls
/// NtSetInformationProcess(ProcessMitigationPolicy) to remove CFG/ACG before mapping their
/// DLL. A game process missing CFG or ACG while the engine normally enables them is strong
/// evidence of tampering. The module checks game processes (identified by name) and flags
/// missing mitigations that the game engine should enforce by default.
/// </summary>
public sealed class ProcessMitigationAnomalyScanModule : IScanModule
{
    public string Name => "Process Mitigation Policy Anomaly Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessMitigationPolicy(
        nint hProcess, int MitigationPolicy, nint lpBuffer, nuint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwAccess, bool bInherit, int dwPid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    // Mitigation policy indices
    private const int ProcessDEPPolicy                = 0;
    private const int ProcessASLRPolicy               = 1;
    private const int ProcessDynamicCodePolicy        = 3;  // ACG
    private const int ProcessStrictHandleCheckPolicy  = 4;
    private const int ProcessControlFlowGuardPolicy   = 7;  // CFG
    private const int ProcessSignaturePolicy          = 8;  // CIG
    private const int ProcessImageLoadPolicy          = 12;

    // Game process names that should have strong mitigations
    private static readonly HashSet<string> KnownGameProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        // CS2
        "cs2", "csgo",
        // Valorant
        "VALORANT", "VALORANT-Win64-Shipping",
        // Apex Legends
        "r5apex", "r5apex_dx12",
        // Fortnite
        "FortniteClient-Win64-Shipping",
        // PUBG
        "TslGame",
        // Tarkov
        "EscapeFromTarkov",
        // Rainbow Six Siege
        "RainbowSix", "RainbowSix_BE",
        // Battlefield
        "bf1", "bf2042", "bfv",
        // Call of Duty
        "cod", "ModernWarfare",
        // Overwatch
        "Overwatch",
        // Rust
        "RustClient",
        // DayZ
        "DayZ_x64", "DayZ_BE",
        // Warzone
        "cod_launcher", "cod_mw3",
        // Hunt: Showdown
        "Hunt",
        // The Finals
        "Discovery-Win64-Shipping",
    };

    // Anti-cheat process names that should have strong mitigations
    private static readonly HashSet<string> AntiCheatProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "EasyAntiCheat", "EasyAntiCheat_EOS",
        "BEService", "BEService_x64",
        "vgc", "vgtray",
        "FACEITService", "faceitclient",
        "ESEAClient",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => CheckProcesses(ctx, ct), ct);
    }

    private void CheckProcesses(ScanContext ctx, CancellationToken ct)
    {
        var procs = System.Diagnostics.Process.GetProcesses();
        foreach (var proc in procs)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string procName = proc.ProcessName;
                bool isGame = KnownGameProcesses.Contains(procName);
                bool isAc   = AntiCheatProcesses.Contains(procName);
                if (!isGame && !isAc) continue;

                nint hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Id);
                if (hProc == nint.Zero) continue;

                try
                {
                    var weakMitigations = new List<string>();

                    // Check DEP policy
                    uint depFlags = QueryPolicy<uint>(hProc, ProcessDEPPolicy);
                    // Bit 0 = Enable, Bit 1 = DisableAtlThunkEmulation, Bit 31 = Permanent
                    bool depEnabled = (depFlags & 1) != 0;
                    if (!depEnabled) weakMitigations.Add("DEP deaktiviert");

                    // Check ACG (Dynamic Code Policy) — if enabled, no new executable code allowed
                    uint acgFlags = QueryPolicy<uint>(hProc, ProcessDynamicCodePolicy);
                    bool acgEnabled = (acgFlags & 1) != 0;
                    // ACG is not always set on games, but if it IS set and something removed it,
                    // the value would be 0 after injection (can't set back once removed by BYOVD)
                    // We just record the state — only flag if DEP is also off
                    if (!depEnabled && !acgEnabled)
                        weakMitigations.Add("ACG deaktiviert");

                    // Check CFG (Control Flow Guard)
                    uint cfgFlags = QueryPolicy<uint>(hProc, ProcessControlFlowGuardPolicy);
                    // Bit 0 = CFGEnabled, Bit 1 = EnableExportSuppression, Bit 2 = StrictMode
                    bool cfgEnabled = (cfgFlags & 1) != 0;
                    // Note: not all games use CFG, so only flag if ASLR is also suspicious

                    // Check ASLR
                    uint aslrFlags = QueryPolicy<uint>(hProc, ProcessASLRPolicy);
                    // Bit 0 = EnableBottomUpRandomization, Bit 1 = EnableForceRelocateImages,
                    // Bit 2 = EnableHighEntropy, Bit 3 = DisallowStrippedImages
                    bool bottomUpAslr = (aslrFlags & 1) != 0;
                    bool forceRelocate = (aslrFlags & 2) != 0;
                    if (!bottomUpAslr && !forceRelocate && !depEnabled)
                        weakMitigations.Add("ASLR schwach/deaktiviert");

                    ctx.IncrementRegistryKeys();

                    if (weakMitigations.Count == 0) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Schwache Prozess-Mitigations: {procName} (PID {proc.Id})",
                        Risk     = isAc ? RiskLevel.Critical : RiskLevel.High,
                        Location = $"PID {proc.Id}: {procName}",
                        FileName = procName,
                        Reason   = $"{(isAc ? "Anti-Cheat" : "Spiel")}-Prozess '{procName}' hat " +
                                   $"fehlende/deaktivierte Sicherheits-Mitigations: " +
                                   $"{string.Join(", ", weakMitigations)} — " +
                                   "BYOVD-Treiber können NtSetInformationProcess aufrufen um CFG/DEP/ACG " +
                                   "zu deaktivieren bevor eine Cheat-DLL eingeschleust wird",
                        Detail   = $"PID: {proc.Id} | Prozess: {procName} | " +
                                   $"DEP: {depEnabled} | ACG: {acgEnabled} | CFG: {cfgEnabled} | " +
                                   $"ASLR-BottomUp: {bottomUpAslr} | ASLR-ForceRelocate: {forceRelocate} | " +
                                   $"Fehlende Mitigations: {string.Join(", ", weakMitigations)}"
                    });
                }
                finally
                {
                    CloseHandle(hProc);
                }
            }
            catch { }
        }
    }

    private static T QueryPolicy<T>(nint hProc, int policyClass) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        nint buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(default(T), buf, false);
            GetProcessMitigationPolicy(hProc, policyClass, buf, (nuint)size);
            return Marshal.PtrToStructure<T>(buf);
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }
}
