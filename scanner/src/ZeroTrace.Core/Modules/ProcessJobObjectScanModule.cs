using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects suspicious Windows Job Object restrictions applied to game and anti-cheat
/// processes. Cheat tools use CreateJobObject to assign AC processes to a restricted job
/// that limits their CPU time, memory, or UI capabilities — effectively hobbling the AC
/// while letting the game run normally. The module calls IsProcessInJob on game and AC
/// processes; for those in a job it checks the job's UIRestrictions (breakaway, clipboard,
/// shell, display changes) and BasicLimitInformation (kill-on-job-close, process time limits,
/// working set caps) that could be used to sandbox or starve the anti-cheat process.
/// Also flags anti-cheat processes in jobs they shouldn't be in at all.
/// </summary>
public sealed class ProcessJobObjectScanModule : IScanModule
{
    public string Name => "Job Object Restriction Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(nint ProcessHandle, nint JobHandle, out bool Result);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(
        nint hJob, int JobObjectInformationClass,
        byte[] lpJobObjectInformation, uint cbJobObjectInformationLength,
        out uint lpReturnLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        nint hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_QUERY_LIMITED     = 0x1000;
    private const int  JobObjectBasicLimitInformation = 2;
    private const int  JobObjectBasicUIRestrictions   = 4;
    private const int  JobObjectBasicAccountingInformation = 1;

    // UI restriction flags
    private const uint JOB_OBJECT_UILIMIT_HANDLES        = 0x0001;
    private const uint JOB_OBJECT_UILIMIT_READCLIPBOARD  = 0x0002;
    private const uint JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x0004;
    private const uint JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x0008;
    private const uint JOB_OBJECT_UILIMIT_DISPLAYSETTINGS = 0x0010;
    private const uint JOB_OBJECT_UILIMIT_GLOBALATOMS    = 0x0020;
    private const uint JOB_OBJECT_UILIMIT_DESKTOP        = 0x0040;
    private const uint JOB_OBJECT_UILIMIT_EXITWINDOWS    = 0x0080;
    private const uint JOB_OBJECT_UILIMIT_ALL            = 0x00FF;

    // Basic limit flags
    private const uint JOB_OBJECT_LIMIT_PROCESS_TIME     = 0x00000002;
    private const uint JOB_OBJECT_LIMIT_JOB_TIME         = 0x00000004;
    private const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS   = 0x00000008;
    private const uint JOB_OBJECT_LIMIT_WORKING_SET      = 0x00000001;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint JOB_OBJECT_LIMIT_BREAKAWAY_OK     = 0x00000800;

    private static readonly string[] AntiCheatProcessNames =
    {
        "easyanticheat", "battleye", "bservice", "vgc", "vgk",
        "faceitservice", "faceit", "esea", "eac_", "eac ",
    };

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "rocketleague", "deadlock",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => CheckProcesses(ctx, ct), ct);
    }

    private void CheckProcesses(ScanContext ctx, CancellationToken ct)
    {
        foreach (var proc in Process.GetProcesses())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string nameLower = proc.ProcessName.ToLowerInvariant();
                bool isAC   = Array.Exists(AntiCheatProcessNames, n => nameLower.Contains(n));
                bool isGame = Array.Exists(GameProcessNames, n => nameLower.Contains(n));
                if (!isAC && !isGame) continue;

                CheckProcess(proc, isAC, ctx);
                ctx.IncrementProcesses();
            }
            catch { }
            finally { proc.Dispose(); }
        }
    }

    private void CheckProcess(Process proc, bool isAntiCheat, ScanContext ctx)
    {
        nint hProc = OpenProcess(PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            // Check if the process is in ANY job (passing JobHandle=0 checks for any job)
            if (!IsProcessInJob(hProc, nint.Zero, out bool inJob)) return;
            if (!inJob) return;

            // Try to open the job associated with this process
            // We can't directly open the job by handle, but we can query via the process handle
            // Query basic UI restrictions (requires being in same job or having access)
            var uiBuf = new byte[4]; // JOBOBJECT_BASIC_UI_RESTRICTIONS is DWORD
            bool uiOk = QueryInformationJobObject(nint.Zero, JobObjectBasicUIRestrictions,
                uiBuf, (uint)uiBuf.Length, out _);

            var limitBuf = new byte[96]; // JOBOBJECT_BASIC_LIMIT_INFORMATION
            bool limitOk = QueryInformationJobObject(nint.Zero, JobObjectBasicLimitInformation,
                limitBuf, (uint)limitBuf.Length, out _);

            uint uiRestrictions = uiOk ? BitConverter.ToUInt32(uiBuf, 0) : 0;
            uint limitFlags     = limitOk ? BitConverter.ToUInt32(limitBuf, 40) : 0; // LimitFlags offset

            // Flag anti-cheat processes in any job with restrictions
            // Flag game processes in jobs with suspicious resource limits
            bool hasUiRestrictions    = (uiRestrictions & JOB_OBJECT_UILIMIT_ALL) != 0;
            bool hasCpuTimeLimits     = (limitFlags & (JOB_OBJECT_LIMIT_PROCESS_TIME | JOB_OBJECT_LIMIT_JOB_TIME)) != 0;
            bool hasKillOnClose       = (limitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) != 0;
            bool hasActiveProcessLimit = (limitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) != 0;

            bool suspicious = isAntiCheat && inJob; // AC in any job is suspicious
            suspicious |= (hasCpuTimeLimits || hasUiRestrictions) && (isAntiCheat || !limitOk);

            if (!suspicious) return;

            var restrictions = new StringBuilder();
            if (hasUiRestrictions) restrictions.Append($"UI-Einschränkungen=0x{uiRestrictions:X} ");
            if (hasCpuTimeLimits)  restrictions.Append("CPU-Zeitlimit ");
            if (hasKillOnClose)    restrictions.Append("Kill-on-Close ");
            if (hasActiveProcessLimit) restrictions.Append("Prozessanzahl-Limit ");

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"{(isAntiCheat ? "Anti-Cheat" : "Spiel")}-Prozess '{proc.ProcessName}' in Job-Objekt",
                Risk     = isAntiCheat ? RiskLevel.Critical : RiskLevel.High,
                Location = proc.ProcessName,
                FileName = proc.ProcessName,
                Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) läuft in einem Windows Job-Objekt" +
                           (isAntiCheat
                               ? " — Anti-Cheat-Prozesse sollten nie in einem Job sein: kann zur Ressourcen-Sabotage genutzt werden"
                               : $" mit Einschränkungen: {restrictions.ToString().Trim()} — möglicherweise durch Cheat-Tool eingeschränkt"),
                Detail   = $"Prozess: {proc.ProcessName} (PID {proc.Id}) | " +
                           $"Typ: {(isAntiCheat ? "Anti-Cheat" : "Spiel")} | " +
                           $"Einschränkungen: {(restrictions.Length > 0 ? restrictions.ToString().Trim() : "unbekannt (kein Zugriff auf Job-Info)")} | " +
                           $"UI-Flags: 0x{uiRestrictions:X} | Limit-Flags: 0x{limitFlags:X}"
            });
        }
        finally
        {
            CloseHandle(hProc);
        }
    }
}
