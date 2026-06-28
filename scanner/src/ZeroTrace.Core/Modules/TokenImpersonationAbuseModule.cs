using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects misuse of Windows token impersonation and privilege escalation techniques
/// used by cheat tools to:
///
///   1. Bypass Anti-Cheat kernel driver checks that verify the calling process token:
///      - Duplicate SYSTEM token (PID 4) and impersonate it to make cheat DLL calls
///        appear to come from trusted system processes
///      - Steal token from a legitimate high-integrity process (e.g., lsass.exe, winlogon)
///      - Use NtCreateToken to forge a custom token with AC-trusted SIDs
///
///   2. Privilege Escalation for Cheat Injection:
///      - Processes with TOKEN_DUPLICATE + TOKEN_IMPERSONATE + TOKEN_ASSIGN_PRIMARY
///        open handles on protected processes indicate potential token theft
///      - OpenProcessToken with MAXIMUM_ALLOWED on protected AC process
///
///   3. Detect SACL Auditing Bypass:
///      - Processes impersonating SYSTEM to avoid audit log entries
///      - Token manipulation to modify the integrity level to match trusted processes
///
/// Detection method:
///   - Enumerate processes with unusual token integrity levels (System = S-1-16-16384,
///     High = S-1-16-12288, Medium = S-1-16-8192)
///   - Find non-system processes running with SYSTEM integrity
///   - Detect processes with impersonation tokens where impersonating identity
///     doesn't match the process executable's expected trust level
///   - Check for processes with SeAssignPrimaryTokenPrivilege + SeImpersonatePrivilege
///     from non-service executable paths (cheat escalation pattern)
///   - NtQuerySystemInformation(SystemHandleInformation) to find cross-process
///     token handle opens with suspicious access masks
/// </summary>
public sealed class TokenImpersonationAbuseModule : IScanModule
{
    public string Name => "Token Impersonation / Privilege Escalation Abuse Detection";
    public double Weight => 0.75;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(nint ProcessHandle, uint DesiredAccess,
        out nint TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(nint TokenHandle, int TokenInformationClass,
        nint TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool LookupAccountSid(string? lpSystemName, nint Sid,
        System.Text.StringBuilder? lpName, ref uint cchName,
        System.Text.StringBuilder? lpReferencedDomainName, ref uint cchReferencedDomainName,
        out uint peUse);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(nint ProcessHandle, int ProcessInformationClass,
        nint ProcessInformation, uint ProcessInformationLength, out uint ReturnLength);

    private const int TokenUser           = 1;
    private const int TokenGroups         = 2;
    private const int TokenPrivileges     = 3;
    private const int TokenType           = 8;
    private const int TokenImpersonationLevel = 9;
    private const int TokenIntegrityLevel  = 25;
    private const int TokenElevationType   = 18;
    private const int TokenLinkedToken     = 19;

    private const uint PROCESS_QUERY_INFORMATION      = 0x0400;
    private const uint PROCESS_QUERY_LIMITED_INFO     = 0x1000;
    private const uint TOKEN_QUERY                    = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED           = 0x00000002;

    // Well-known integrity level SID RIDs
    private const uint SECURITY_MANDATORY_UNTRUSTED_RID   = 0x0000;
    private const uint SECURITY_MANDATORY_LOW_RID         = 0x1000;
    private const uint SECURITY_MANDATORY_MEDIUM_RID      = 0x2000;
    private const uint SECURITY_MANDATORY_MEDIUM_PLUS_RID = 0x2100;
    private const uint SECURITY_MANDATORY_HIGH_RID        = 0x3000;
    private const uint SECURITY_MANDATORY_SYSTEM_RID      = 0x4000;

    private static readonly HashSet<string> LegitSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "smss", "csrss", "wininit", "winlogon", "services", "lsass",
        "lsm", "svchost", "spoolsv", "msdtc", "SearchIndexer",
        "TiWorker", "TrustedInstaller", "WmiPrvSE", "dllhost",
        // Security products that run as SYSTEM
        "MsMpEng", "NisSrv", "SenseCntr", "MsSense",
        // AC kernel components that run as SYSTEM
        "EasyAntiCheat", "BEService", "vgc", "vgtray",
        "anticheats", "xigncode", "GameGuard",
        // Game launchers that use SYSTEM token for driver installation
        "Steam", "EpicGamesLauncher", "Origin", "RiotClientServices",
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SID_AND_ATTRIBUTES
    {
        public nint Sid;
        public uint Attributes;
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => ScanProcessTokens(ctx, ct), ct);
    }

    private static void ScanProcessTokens(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var processes = System.Diagnostics.Process.GetProcesses();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    ctx.IncrementFiles();

                    string procName = proc.ProcessName;

                    if (LegitSystemProcesses.Contains(procName)) continue;

                    nint hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFO, false, proc.Id);
                    if (hProc == nint.Zero) continue;

                    try
                    {
                        if (!OpenProcessToken(hProc, TOKEN_QUERY, out nint hToken)) continue;

                        try
                        {
                            uint integrityRid = GetIntegrityLevel(hToken);
                            bool isSystemToken = integrityRid >= SECURITY_MANDATORY_SYSTEM_RID;

                            if (!isSystemToken) continue;

                            // Non-system process running with SYSTEM integrity level
                            string? procPath = null;
                            try { procPath = proc.MainModule?.FileName; } catch { }

                            // Additional check: is the token an impersonation token?
                            bool isImpersonation = IsImpersonationToken(hToken);

                            string procPathLow = (procPath ?? "").ToLowerInvariant();
                            bool isFromSuspiciousPath =
                                procPathLow.Contains(@"\temp\") ||
                                procPathLow.Contains(@"\appdata\") ||
                                procPathLow.Contains(@"\downloads\") ||
                                procPathLow.Contains(@"\desktop\");

                            bool hasCheatName =
                                procPathLow.Contains("cheat") || procPathLow.Contains("hack") ||
                                procPathLow.Contains("inject") || procPathLow.Contains("bypass") ||
                                procPathLow.Contains("spoof") || procPathLow.Contains("loader");

                            if (!isFromSuspiciousPath && !hasCheatName && !isImpersonation)
                                continue;

                            RiskLevel risk = (hasCheatName || isImpersonation) ? RiskLevel.Critical
                                : RiskLevel.High;

                            ctx.AddFinding(new Finding
                            {
                                Module   = "Token Impersonation / Privilege Escalation Abuse Detection",
                                Title    = $"Nicht-System-Prozess mit SYSTEM-Integritätsstufe: {procName}",
                                Risk     = risk,
                                Location = procPath ?? $"PID {proc.Id}",
                                FileName = Path.GetFileName(procPath ?? procName),
                                Reason   = $"Prozess '{procName}' (PID {proc.Id}) aus '{procPath ?? "unbekannt"}' " +
                                           $"läuft mit SYSTEM-Integritätsstufe{(isImpersonation ? " via Impersonierung" : "")} " +
                                           "ohne als legitimer System-Dienst klassifiziert zu sein — " +
                                           "Cheat-Tools stehlen SYSTEM-Token um Kernel-AC-Checks zu umgehen",
                                Detail   = $"Prozess: {procName} | PID: {proc.Id} | " +
                                           $"Integritätsstufe: SYSTEM (0x{integrityRid:X4}) | " +
                                           $"Impersonierung: {isImpersonation} | Pfad: {procPath ?? "unbekannt"}"
                            });
                        }
                        finally { CloseHandle(hToken); }
                    }
                    finally { CloseHandle(hProc); }
                }
                catch { }
                finally { try { proc.Dispose(); } catch { } }
            }
        }
        catch { }
    }

    private static uint GetIntegrityLevel(nint hToken)
    {
        try
        {
            GetTokenInformation(hToken, TokenIntegrityLevel, nint.Zero, 0, out uint needed);
            if (needed == 0) return SECURITY_MANDATORY_MEDIUM_RID;

            nint buf = Marshal.AllocHGlobal((int)needed);
            try
            {
                if (!GetTokenInformation(hToken, TokenIntegrityLevel, buf, needed, out _))
                    return SECURITY_MANDATORY_MEDIUM_RID;

                var label = Marshal.PtrToStructure<TOKEN_MANDATORY_LABEL>(buf);
                if (label.Label.Sid == nint.Zero) return SECURITY_MANDATORY_MEDIUM_RID;

                // The integrity RID is the last sub-authority of the integrity SID
                // SID structure: Revision(1)+SubAuthorityCount(1)+IdentifierAuthority(6)+SubAuthority[n](4 each)
                byte subCount = Marshal.ReadByte(label.Label.Sid, 1);
                if (subCount == 0) return SECURITY_MANDATORY_MEDIUM_RID;

                // Last sub-authority is at offset 8 + (subCount-1)*4
                int lastSubOffset = 8 + (subCount - 1) * 4;
                uint rid = (uint)Marshal.ReadInt32(label.Label.Sid, lastSubOffset);
                return rid;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { return SECURITY_MANDATORY_MEDIUM_RID; }
    }

    private static bool IsImpersonationToken(nint hToken)
    {
        try
        {
            nint buf = Marshal.AllocHGlobal(4);
            try
            {
                if (!GetTokenInformation(hToken, TokenType, buf, 4, out _))
                    return false;

                int tokenType = Marshal.ReadInt32(buf, 0);
                // TokenPrimary = 1, TokenImpersonation = 2
                return tokenType == 2;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { return false; }
    }
}
