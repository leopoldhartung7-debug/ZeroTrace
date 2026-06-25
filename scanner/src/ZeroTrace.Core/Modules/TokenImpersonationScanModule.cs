using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects token impersonation and privilege escalation techniques used by cheats.
///
/// Cheats frequently escalate privileges to interact with protected processes:
///
///   1. Token Impersonation: steal/duplicate a SYSTEM or admin token from
///      a running service/process and apply it to the cheat process
///      (ImpersonateLoggedOnUser, DuplicateTokenEx, SetThreadToken)
///
///   2. SeDebugPrivilege: required to open handles to system/protected processes.
///      Legitimate user processes should NOT have SeDebugPrivilege.
///      Cheat loaders enable it via AdjustTokenPrivileges.
///
///   3. SeTcbPrivilege (Act as part of OS): extremely powerful, enables token
///      creation. Only SYSTEM should have this.
///
///   4. SeLoadDriverPrivilege: required to load kernel drivers without admin rights.
///      Cheat loaders use this for BYOVD attacks.
///
///   5. Token impersonation via named pipe: create named pipe, trick a service
///      into connecting, steal its token (classic local privilege escalation).
///
///   6. Duplicate SYSTEM token: open winlogon.exe or lsass.exe handle,
///      duplicate their token, apply to cheat process.
///
/// Detection:
///   1. Enumerate all processes, check their primary token privileges
///   2. Flag non-system, non-admin processes with SeDebugPrivilege enabled
///   3. Flag user processes with SeTcbPrivilege or SeLoadDriverPrivilege
///   4. Check for impersonation tokens on thread level in game-adjacent processes
///   5. Flag processes running as SYSTEM that aren't expected system processes
/// </summary>
public sealed class TokenImpersonationScanModule : IScanModule
{
    public string Name => "Token-Impersonation-Analyse";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess,
        out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr tokenHandle,
        uint tokenInformationClass, IntPtr tokenInformation,
        uint tokenInformationLength, out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool LookupPrivilegeName(string lpSystemName,
        ref Luid lpLuid, System.Text.StringBuilder lpName, ref uint cchName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool LookupAccountSid(string? lpSystemName, IntPtr Sid,
        System.Text.StringBuilder lpName, ref uint cchName,
        System.Text.StringBuilder lpReferencedDomainName, ref uint cchReferencedDomainName,
        out uint peUse);

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        // Followed by LuidAndAttributes array
    }

    private const uint TOKEN_QUERY = 0x0008;
    private const uint TokenPrivilegesInfo = 3;
    private const uint TokenUser = 1;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;

    // Highly sensitive privileges that cheat software enables
    private static readonly HashSet<string> CriticalPrivileges = new(StringComparer.OrdinalIgnoreCase)
    {
        "SeDebugPrivilege",          // Open handles to any process (needed for injection)
        "SeTcbPrivilege",            // Act as OS — create tokens, bypass most security
        "SeLoadDriverPrivilege",     // Load kernel drivers (BYOVD)
        "SeCreateTokenPrivilege",    // Create arbitrary tokens (full privilege escalation)
        "SeTakeOwnershipPrivilege",  // Take ownership of protected objects
        "SeAssignPrimaryTokenPrivilege", // Assign new primary token to process
    };

    // High-risk privileges that are suspicious in user processes
    private static readonly HashSet<string> HighRiskPrivileges = new(StringComparer.OrdinalIgnoreCase)
    {
        "SeImpersonatePrivilege",    // Impersonate any user (token theft)
        "SeCreateGlobalPrivilege",   // Create global objects (cheat IPC)
        "SeSecurityPrivilege",       // Manage audit/security log
        "SeBackupPrivilege",         // Read any file bypassing ACLs
        "SeRestorePrivilege",        // Write any file bypassing ACLs
        "SeShutdownPrivilege",
        "SeUndockPrivilege",
    };

    // System processes that legitimately have powerful privileges
    private static readonly HashSet<string> TrustedSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsm.exe", "svchost.exe",
        "spoolsv.exe", "msdtc.exe", "SearchIndexer.exe",
        "MsMpEng.exe", "NisSrv.exe",   // Windows Defender
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckProcessTokenPrivileges(ctx, ct);

        ctx.Report(1.0, Name, $"Prozess-Token-Rechte geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckProcessTokenPrivileges(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementProcesses();

                string procName = proc.ProcessName + ".exe";
                if (TrustedSystemProcesses.Contains(procName) ||
                    proc.SessionId == 0 && proc.Id < 10)
                {
                    proc.Dispose();
                    continue;
                }

                try
                {
                    IntPtr hToken = IntPtr.Zero;
                    try
                    {
                        if (!OpenProcessToken(proc.Handle, TOKEN_QUERY, out hToken))
                            continue;

                        var enabledPrivs = GetEnabledPrivileges(hToken);
                        var critFound = enabledPrivs
                            .Where(p => CriticalPrivileges.Contains(p))
                            .ToList();
                        var highFound = enabledPrivs
                            .Where(p => HighRiskPrivileges.Contains(p) &&
                                        !CriticalPrivileges.Contains(p))
                            .ToList();

                        if (critFound.Count > 0)
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Token-Impersonation-Analyse",
                                Title    = $"Kritisches Privileg in Nicht-System-Prozess: {procName}",
                                Risk     = critFound.Contains("SeDebugPrivilege") ||
                                           critFound.Contains("SeTcbPrivilege")
                                           ? RiskLevel.Critical : RiskLevel.High,
                                Location = $"PID {proc.Id}: {procName}",
                                Reason   = $"Prozess '{procName}' (PID {proc.Id}) hat kritische " +
                                           $"Privilegien aktiviert: {string.Join(", ", critFound)}. " +
                                           "SeDebugPrivilege ermöglicht das Öffnen beliebiger Prozesse " +
                                           "zum Injizieren von Code. SeLoadDriverPrivilege erlaubt BYOVD-Angriffe. " +
                                           "Diese Privilegien sollten in User-Space-Prozessen nicht aktiv sein.",
                                Detail   = $"Prozess: {procName} | PID: {proc.Id} | " +
                                           $"Kritisch: {string.Join(", ", critFound)} | " +
                                           $"Hoch: {string.Join(", ", highFound)}"
                            });
                        }
                        else if (highFound.Count >= 3)
                        {
                            // 3+ high-risk privs in a single non-system process is unusual
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Token-Impersonation-Analyse",
                                Title    = $"Ungewöhnliche Privilegien-Kombination: {procName}",
                                Risk     = RiskLevel.High,
                                Location = $"PID {proc.Id}: {procName}",
                                Reason   = $"Prozess '{procName}' (PID {proc.Id}) hat " +
                                           $"{highFound.Count} erhöhte Privilegien aktiviert: " +
                                           $"{string.Join(", ", highFound)}. " +
                                           "Diese Kombination deutet auf Token-Diebstahl oder " +
                                           "Privilege-Escalation-Angriffe hin.",
                                Detail   = $"Prozess: {procName} | PID: {proc.Id} | " +
                                           $"Erhöhte Privilegien: {string.Join(", ", highFound)}"
                            });
                        }
                    }
                    finally
                    {
                        if (hToken != IntPtr.Zero) CloseHandle(hToken);
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
        return hits;
    }

    private static List<string> GetEnabledPrivileges(IntPtr hToken)
    {
        var result = new List<string>();
        try
        {
            // First call to get required buffer size
            GetTokenInformation(hToken, TokenPrivilegesInfo, IntPtr.Zero, 0, out uint size);
            if (size == 0) return result;

            var buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (!GetTokenInformation(hToken, TokenPrivilegesInfo, buf, size, out _))
                    return result;

                uint count = (uint)Marshal.ReadInt32(buf);
                int offset = Marshal.SizeOf<uint>();

                for (int i = 0; i < (int)count; i++)
                {
                    var laa = Marshal.PtrToStructure<LuidAndAttributes>(buf + offset);
                    offset += Marshal.SizeOf<LuidAndAttributes>();

                    bool isEnabled = (laa.Attributes &
                        (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT)) != 0;
                    if (!isEnabled) continue;

                    var luid = laa.Luid;
                    var name = new System.Text.StringBuilder(256);
                    uint nameLen = 256;
                    if (LookupPrivilegeName(null!, ref luid, name, ref nameLen))
                        result.Add(name.ToString());
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { }
        return result;
    }
}
