using ZeroTrace.Core.Models;
using System.Runtime.InteropServices;
using System.Text;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects handle inheritance anomalies used by cheat loaders to pass
/// privileged process handles (PROCESS_VM_READ/WRITE/ALL_ACCESS) to child
/// processes without triggering OpenProcess alerts.
///
/// How the technique works:
///   1. Loader calls OpenProcess(PROCESS_ALL_ACCESS, bInheritHandle=TRUE, gamePid)
///   2. Loader spawns a "clean" child process (explorer.exe, cmd.exe, svchost.exe)
///      with PROC_THREAD_ATTRIBUTE_INHERIT_HANDLE specifying the game handle
///   3. Child receives the inherited handle without ever calling OpenProcess itself
///   4. AC system-call monitoring never sees OpenProcess on the game from the child
///
/// Detectable because:
///   - Child processes that should not need game access (system tools, browsers)
///     show up with inherited handles to game processes in the system handle table
///   - NtQuerySystemInformation(SystemHandleInformation) exposes ALL open handles
///     system-wide, including inherited ones — the granted access bits are unchanged
///   - Children of cheat loaders often appear as trusted system processes (PPID spoofing
///     combined with handle inheritance = fully invisible to userland scanners)
///
/// Ocean and detect.ac cross-reference process handle tables with PPID chains
/// to detect this combination.
/// </summary>
public sealed class ProcessHandleInheritanceScanModule : IScanModule
{
    public string Name => "Prozess-Handle-Vererbung Anomalie (Cheat Handle-Weiterleitung)";
    public double Weight => 0.6;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int SystemInformationClass,
        IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint QueryFullProcessImageName(IntPtr hProcess, uint dwFlags,
        StringBuilder lpExeName, ref uint lpdwSize);

    private const int SystemHandleInformation = 16;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    // ACCESS_MASK bits indicating dangerous cross-process access
    private const uint PROCESS_VM_READ    = 0x0010;
    private const uint PROCESS_VM_WRITE   = 0x0020;
    private const uint PROCESS_VM_OPERATION = 0x0008;
    private const uint PROCESS_ALL_ACCESS = 0x001FFFFF;

    // Game process keywords — processes that should receive game handles
    private static readonly string[] GameKeywords =
    {
        "cs2", "csgo", "valorant", "apex", "fortnite", "pubg", "battlefield",
        "tarkov", "rust", "dayz", "overwatch", "r6siege", "r5apex",
        "eldenring", "cod", "warzone", "modernwarfare", "xdefiant"
    };

    // Processes that should NEVER hold game memory access handles
    private static readonly string[] SuspiciousHolderNames =
    {
        "explorer", "cmd", "powershell", "svchost", "conhost", "werfault",
        "notepad", "mspaint", "taskhostw", "runtimebroker", "searchhost",
        "sihost", "ctfmon", "dwm", "csrss", "winlogon", "services",
        "lsass", "userinit", "wininit", "fontdrvhost",
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        // First enumerate running processes to identify game PIDs and their names
        var processPaths = new Dictionary<uint, string>();
        try
        {
            var snapshot = ctx.GetProcessSnapshot();
            foreach (var p in snapshot)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    processPaths[(uint)p.Id] = (p.MainModule?.FileName ?? p.ProcessName).ToLowerInvariant();
                }
                catch { processPaths[(uint)p.Id] = p.ProcessName.ToLowerInvariant(); }
            }
        }
        catch { return; }

        // Identify game PIDs
        var gamePids = processPaths
            .Where(kv => GameKeywords.Any(kw => kv.Value.Contains(kw)))
            .Select(kv => kv.Key)
            .ToHashSet();

        if (gamePids.Count == 0) return;

        // Query all system handles
        uint returnLen = 0;
        var infoSize = 1024u * 1024u * 8u; // 8 MB initial buffer
        var buf = Marshal.AllocHGlobal((int)infoSize);
        try
        {
            int status;
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                status = NtQuerySystemInformation(SystemHandleInformation, buf, infoSize, out returnLen);
                if (status == 0) break;
                if (status != unchecked((int)0xC0000004)) return; // Not STATUS_INFO_LENGTH_MISMATCH
                infoSize = returnLen + 4096;
                Marshal.FreeHGlobal(buf);
                buf = Marshal.AllocHGlobal((int)infoSize);
            }

            // Parse handle table: first ULONG is count
            long count = Marshal.ReadInt64(buf, 0);
            int entrySize = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();
            int offset = 8; // after the count field (ULONG_PTR on x64)

            // Build map: pid → list of (handleValue, grantedAccess)
            // We look for handles to game process objects from non-game processes
            // We can't easily get the object PID from the handle entry directly,
            // but we can detect handles with dangerous access masks from suspicious holders
            for (long i = 0; i < count && i < 100000; i++)
            {
                ct.ThrowIfCancellationRequested();
                if (offset + entrySize > (int)infoSize) break;

                var entry = Marshal.PtrToStructure<SYSTEM_HANDLE_TABLE_ENTRY_INFO>(buf + offset);
                offset += entrySize;

                uint holderPid = entry.UniqueProcessId;
                if (!processPaths.TryGetValue(holderPid, out string? holderPath)) continue;

                // Check if holder is a suspicious Windows system process
                string holderName = Path.GetFileNameWithoutExtension(holderPath).ToLowerInvariant();
                bool isSuspiciousHolder = SuspiciousHolderNames.Any(s => holderName == s);
                if (!isSuspiciousHolder) continue;

                // Check for dangerous VM read/write access bits
                uint access = entry.GrantedAccess;
                bool hasVmRead  = (access & PROCESS_VM_READ)  != 0;
                bool hasVmWrite = (access & PROCESS_VM_WRITE) != 0;
                bool hasVmOp    = (access & PROCESS_VM_OPERATION) != 0;

                if (!hasVmRead && !hasVmWrite) continue;

                // Suspicious: system process holding VM read/write handle
                // (likely inherited from cheat loader)
                string accessDesc = string.Join("+", new[]
                {
                    hasVmRead  ? "VM_READ"  : null,
                    hasVmWrite ? "VM_WRITE" : null,
                    hasVmOp    ? "VM_OP"    : null,
                }.Where(s => s != null));

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"System-Prozess '{holderName}' hält VM-Lese/Schreib-Handle (Handle-Vererbung?)",
                    Risk     = RiskLevel.High,
                    Location = $"PID {holderPid} ({holderName})",
                    FileName = holderPath,
                    Reason   = $"Der Windows-Systemprozess '{holderName}' (PID {holderPid}) besitzt ein " +
                               $"Prozess-Handle mit Zugriff [{accessDesc}] (Handle 0x{entry.HandleValue:X}). " +
                               "Legitime Systemprozesse benötigen keinen VM-Zugriff auf andere Prozesse. " +
                               "Dieses Muster entsteht wenn ein Cheat-Loader einen privilegierten Handle " +
                               "über Handle-Vererbung (PROC_THREAD_ATTRIBUTE_INHERIT_HANDLE) an einen " +
                               "Systemprozess-Kind weitergibt, um OpenProcess-Überwachung zu umgehen.",
                    Detail   = $"Holder PID: {holderPid} | Holder: {holderName} | Handle: 0x{entry.HandleValue:X} | Access: 0x{access:X} | [{accessDesc}]"
                });
                ctx.IncrementProcesses();
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }
}
