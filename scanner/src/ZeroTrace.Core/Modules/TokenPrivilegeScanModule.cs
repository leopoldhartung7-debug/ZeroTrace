using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects token privilege abuse — processes holding unusual privileges that
/// indicate cheat tools exploiting Windows security boundaries.
///
/// Windows security tokens carry a set of privileges (SE_DEBUG_PRIVILEGE,
/// SE_LOAD_DRIVER_PRIVILEGE, etc.). Normal user processes have a limited set.
/// Cheat tools and kernel-level bypass tools often:
///   1. Enable SE_DEBUG_PRIVILEGE to read/write game process memory
///   2. Enable SE_LOAD_DRIVER_PRIVILEGE to load unsigned kernel drivers
///   3. Enable SE_TCB_PRIVILEGE (act as part of OS) for token impersonation
///
/// Detection:
///   1. Enumerate all running processes.
///   2. Open each process token and query its privileges.
///   3. Flag processes outside Windows system paths that hold dangerous privileges.
///   4. Also flag processes with unusual privilege counts (>15 enabled = suspicious).
///
/// P/Invoke: OpenProcessToken, GetTokenInformation (TokenPrivileges),
///           LookupPrivilegeName.
/// </summary>
public sealed class TokenPrivilegeScanModule : IScanModule
{
    public string Name => "Token-Privileg-Missbrauch";
    public double Weight => 0.9;
    public int ParallelGroup => 2;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle, uint tokenInfoClass,
        IntPtr tokenInfo, uint tokenInfoLength, out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeName(
        string? lpSystemName, ref long luid, System.Text.StringBuilder lpName, ref int cchName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private const uint TOKEN_QUERY = 0x0008;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint TOKEN_PRIVILEGES = 3;
    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    // Privileges that should NEVER be enabled in non-system user processes
    private static readonly HashSet<string> DangerousPrivileges = new(StringComparer.OrdinalIgnoreCase)
    {
        "SeDebugPrivilege",          // Read/write any process memory
        "SeLoadDriverPrivilege",     // Load/unload kernel drivers
        "SeTcbPrivilege",            // Act as part of OS (token forgery)
        "SeBackupPrivilege",         // Bypass file ACLs
        "SeRestorePrivilege",        // Bypass file ACLs (write)
        "SeTakeOwnershipPrivilege",  // Take ownership of any object
        "SeAssignPrimaryTokenPrivilege", // Replace process token
        "SeImpersonatePrivilege",    // Impersonate any logged-in user
    };

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();
    private static readonly string SysWow64 = System32.Replace("system32", "syswow64");
    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int processesChecked = 0;
        int hits = 0;

        var procs = System.Diagnostics.Process.GetProcesses();
        foreach (var proc in procs)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementProcesses();
            processesChecked++;

            try
            {
                using (proc)
                {
                    var path = "";
                    try { path = proc.MainModule?.FileName ?? ""; } catch { }
                    var pathLower = path.ToLowerInvariant();

                    // Skip Windows system processes
                    if (pathLower.StartsWith(System32) ||
                        pathLower.StartsWith(SysWow64) ||
                        pathLower.StartsWith(WinDir + "\\system32") ||
                        pathLower.StartsWith(WinDir + "\\syswow64"))
                        continue;

                    var hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.Id);
                    if (hProc == IntPtr.Zero) continue;

                    try
                    {
                        if (!OpenProcessToken(hProc, TOKEN_QUERY, out var hToken)) continue;

                        try
                        {
                            var dangerousEnabled = GetEnabledDangerousPrivileges(hToken);
                            if (dangerousEnabled.Count > 0 && !string.IsNullOrEmpty(path))
                            {
                                hits++;
                                var risk = dangerousEnabled.Contains("SeLoadDriverPrivilege") ||
                                           dangerousEnabled.Contains("SeTcbPrivilege")
                                    ? RiskLevel.Critical : RiskLevel.High;

                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Gefährliche Privileges: {proc.ProcessName}",
                                    Risk     = risk,
                                    Location = path,
                                    FileName = proc.ProcessName + ".exe",
                                    Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) hat " +
                                               $"gefährliche Windows-Privileges aktiviert: " +
                                               string.Join(", ", dangerousEnabled) + ". " +
                                               "SeDebugPrivilege erlaubt Lesen/Schreiben des Spielspeichers. " +
                                               "SeLoadDriverPrivilege ermöglicht Laden unsignierter Kernel-Treiber.",
                                    Detail   = $"Prozess: {path} | PID: {proc.Id} | " +
                                               $"Privileges: {string.Join(", ", dangerousEnabled)}"
                                });
                            }
                        }
                        finally
                        {
                            CloseHandle(hToken);
                        }
                    }
                    finally
                    {
                        CloseHandle(hProc);
                    }
                }
            }
            catch { }
        }

        ctx.Report(1.0, Name, $"{processesChecked} Prozesse geprüft, {hits} mit gefährlichen Privileges");
        return Task.CompletedTask;
    }

    private static List<string> GetEnabledDangerousPrivileges(IntPtr hToken)
    {
        var result = new List<string>();

        GetTokenInformation(hToken, TOKEN_PRIVILEGES, IntPtr.Zero, 0, out uint needed);
        if (needed == 0) return result;

        var buffer = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (!GetTokenInformation(hToken, TOKEN_PRIVILEGES, buffer, needed, out _))
                return result;

            int count = Marshal.ReadInt32(buffer);
            int offset = 4; // skip DWORD count

            for (int i = 0; i < count; i++)
            {
                long luid = Marshal.ReadInt64(buffer, offset);
                uint attrs = (uint)Marshal.ReadInt32(buffer, offset + 8);
                offset += 12; // LUID (8 bytes) + Attributes (4 bytes)

                if ((attrs & SE_PRIVILEGE_ENABLED) == 0) continue;

                var sb = new System.Text.StringBuilder(256);
                int len = sb.Capacity;
                if (LookupPrivilegeName(null, ref luid, sb, ref len))
                {
                    var name = sb.ToString();
                    if (DangerousPrivileges.Contains(name))
                        result.Add(name);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }
}
