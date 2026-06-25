using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects non-system processes with SeDebugPrivilege actively enabled. SeDebugPrivilege
/// (privilege LUID 20) grants the ability to open ANY process with PROCESS_ALL_ACCESS,
/// bypassing normal security checks — it is the single most powerful privilege for external
/// cheat development. Unlike ScanTokenPrivileges which reports presence, this module verifies
/// SE_PRIVILEGE_ENABLED (not just held): the privilege must be explicitly enabled via
/// AdjustTokenPrivileges before it grants elevated handle access. Legitimate holders are only
/// a handful of processes (LSASS, winlogon, csrss, Task Manager). Any unexpected enabled
/// SeDebugPrivilege indicates an external cheat tool, DMA reader, debugger-based cheat, or
/// process that has elevated its own access level to read game memory.
/// </summary>
public sealed class SeDebugPrivilegeActiveScanModule : IScanModule
{
    public string Name => "SeDebugPrivilege Active Detection";
    public double Weight => 0.7;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwAccess, bool bInherit, int dwPid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(nint hProcess, uint desiredAccess, out nint hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(nint hToken, int infoClass,
        nint info, uint infoLen, out uint returnLen);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName,
        string lpName, out long lpLuid);

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint TOKEN_QUERY              = 0x0008;
    private const int  TokenPrivileges          = 3;
    private const uint SE_PRIVILEGE_ENABLED     = 0x00000002;
    // SE_PRIVILEGE_ENABLED_BY_DEFAULT is 0x01 — also active

    // Processes that legitimately hold enabled SeDebug
    private static readonly HashSet<string> SystemDebugProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass", "winlogon", "csrss", "wininit", "services",
        "taskmgr",          // Task Manager needs SeDebug to show all processes
        "procexp", "procexp64", // Sysinternals Process Explorer
        "procmon", "procmon64", // Sysinternals Process Monitor
        "autoruns", "autorunsc",
        "WerFault", "WerFaultSecure",
        "MsMpEng",          // Windows Defender
        "SecurityHealthService",
        "SgrmBroker",       // System Guard Runtime Monitor
        "NisSrv",           // Network Inspection Service
        "SenseNdr",         // Microsoft Defender for Endpoint
        "MsSense",
        "System",
        "ZeroTrace",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => CheckProcesses(ctx, ct), ct);
    }

    private void CheckProcesses(ScanContext ctx, CancellationToken ct)
    {
        long seDebugLuid = 0;
        // SE_DEBUG_NAME = "SeDebugPrivilege"
        if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out seDebugLuid)) return;

        var procs = System.Diagnostics.Process.GetProcesses();
        foreach (var proc in procs)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string procName = proc.ProcessName;
                if (SystemDebugProcesses.Contains(procName)) continue;

                nint hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.Id);
                if (hProc == nint.Zero) continue;

                try
                {
                    if (!OpenProcessToken(hProc, TOKEN_QUERY, out nint hToken)) continue;

                    try
                    {
                        bool hasEnabledSeDebug = HasEnabledPrivilege(hToken, seDebugLuid);
                        if (!hasEnabledSeDebug) continue;

                        ctx.IncrementRegistryKeys();

                        string imagePath = "";
                        try { imagePath = proc.MainModule?.FileName ?? ""; } catch { }

                        bool isSuspicious = !imagePath.StartsWith(@"C:\Windows\",
                            StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"SeDebugPrivilege aktiv: {procName} (PID {proc.Id})",
                            Risk     = isSuspicious ? RiskLevel.Critical : RiskLevel.High,
                            Location = $"PID {proc.Id}: {imagePath}",
                            FileName = procName,
                            Reason   = $"Prozess '{procName}' hat SeDebugPrivilege aktiv (ENABLED) — " +
                                       "diese Berechtigung erlaubt das Öffnen von PROCESS_ALL_ACCESS-Handles " +
                                       "auf beliebige Prozesse (inkl. Spielprozesse) und ist das Kernprivileg " +
                                       "für externe Cheats (Memory-Reader, Aimbot, ESP). " +
                                       (isSuspicious
                                           ? $"Prozess läuft außerhalb von C:\\Windows\\: '{imagePath}'"
                                           : "Prozess liegt in Windows-Verzeichnis aber ist unbekannt."),
                            Detail   = $"PID: {proc.Id} | Name: {procName} | Pfad: {imagePath} | " +
                                       $"SeDebugPrivilege: ENABLED | " +
                                       $"Außerhalb System32: {isSuspicious}"
                        });
                    }
                    finally { CloseHandle(hToken); }
                }
                finally { CloseHandle(hProc); }
            }
            catch { }
        }
    }

    private static bool HasEnabledPrivilege(nint hToken, long targetLuid)
    {
        // First call: get required buffer size
        GetTokenInformation(hToken, TokenPrivileges, nint.Zero, 0, out uint needed);
        if (needed == 0) return false;

        nint buf = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (!GetTokenInformation(hToken, TokenPrivileges, buf, needed, out _))
                return false;

            // TOKEN_PRIVILEGES: DWORD PrivilegeCount, LUID_AND_ATTRIBUTES Privileges[]
            // LUID_AND_ATTRIBUTES: LUID (2×DWORD = 8 bytes), Attributes (DWORD = 4 bytes) → 12 bytes
            int count = Marshal.ReadInt32(buf);
            int offset = 4;
            for (int i = 0; i < count; i++)
            {
                if (offset + 12 > (int)needed) break;
                long luid = Marshal.ReadInt64(buf, offset);
                uint attrs = (uint)Marshal.ReadInt32(buf, offset + 8);
                offset += 12;

                if (luid == targetLuid &&
                    (attrs & SE_PRIVILEGE_ENABLED) != 0)
                    return true;
            }
            return false;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
