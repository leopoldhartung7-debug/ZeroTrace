using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects processes with open PROCESS_VM_READ handles on game processes — the primary
/// mechanism used by external cheats to read game state (player positions, health, ammo,
/// map data). Enumerates all system handles via NtQuerySystemInformation (class 16),
/// filters to PROCESS handles with VM_READ access, and cross-references against game
/// process PIDs. Excludes known-legitimate readers (anti-cheat, debuggers, GPU drivers,
/// Windows system processes). High confidence: any unexpected process reading game memory
/// is very likely a cheat tool.
/// </summary>
public sealed class GameMemoryReadAccessScanModule : IScanModule
{
    public string Name => "Game Memory Read Access Monitor";
    public double Weight => 1.0;
    public int ParallelGroup => 0;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int SystemInformationClass, byte[] SystemInformation,
        uint SystemInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint DuplicateHandle(
        nint hSourceProcessHandle, nint hSourceHandle,
        nint hTargetProcessHandle, out nint lpTargetHandle,
        uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        nint hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    private const int  SystemHandleInformation     = 16;
    private const uint PROCESS_DUP_HANDLE          = 0x0040;
    private const uint PROCESS_QUERY_LIMITED       = 0x1000;
    private const uint PROCESS_VM_READ             = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION   = 0x0400;
    private const uint DUPLICATE_SAME_ACCESS       = 0x2;
    private const int  STATUS_SUCCESS              = 0;
    private const int  STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte   ObjectTypeIndex;
        public byte   HandleAttributes;
        public ushort HandleValue;
        public nint   Object;
        public uint   GrantedAccess;
    }

    // Known legitimate processes that read game memory
    private static readonly string[] LegitReaders =
    {
        "system", "smss", "csrss", "wininit", "services", "lsass", "svchost",
        "ntoskrnl", "dwm", "winlogon", "fontdrvhost", "spoolsv",
        // Anti-cheat processes
        "battleye", "beyondgame", "easyanticheat", "faceit", "vgc", "vgk",
        "anticheatexpert", "xigncode",
        // Game-related legitimate processes
        "steam", "steamservice", "gameoverlayui", "steamwebhelper",
        // GPU/display drivers
        "nvdisplay", "nvcontainer", "nvcplui", "nvidia", "amdow",
        // Windows system processes
        "taskhost", "taskhostw", "searchhost", "runtimebroker", "sihost",
        "explorer", "ctfmon", "audiodg",
        // Anti-virus / security
        "mssense", "msmpeng", "windefend", "mbam",
        // Development/debugging — only if ZeroTrace is running under debugger
        "vsdbg", "devenv",
    };

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "battlefront", "paladins", "rocketleague",
        "insurgency", "l4d2", "deadlock"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var gameProcessIds = GetGameProcessIds();
            if (gameProcessIds.Count == 0) return;

            var pidToName = BuildPidNameMap(ct);
            ScanHandles(gameProcessIds, pidToName, ctx, ct);
        }, ct);
    }

    private void ScanHandles(
        HashSet<int> gameProcessIds, Dictionary<int, string> pidToName,
        ScanContext ctx, CancellationToken ct)
    {
        // Query all system handles — start with a reasonable buffer and grow
        uint bufSize = 0x50000;
        byte[]? buf = null;
        int status;

        for (int attempt = 0; attempt < 8; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            buf = new byte[bufSize];
            status = NtQuerySystemInformation(SystemHandleInformation, buf, bufSize, out uint needed);
            if (status == STATUS_SUCCESS) break;
            if (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                bufSize = Math.Max(needed + 0x10000, bufSize * 2);
                buf = null;
                continue;
            }
            return; // other error
        }

        if (buf == null) return;

        // SYSTEM_HANDLE_INFORMATION: [0]=HandleCount (ULONG), then array of SYSTEM_HANDLE_TABLE_ENTRY_INFO
        uint handleCount = BitConverter.ToUInt32(buf, 0);
        int entrySize    = Marshal.SizeOf<SYSTEM_HANDLE_TABLE_ENTRY_INFO>();
        int baseOff      = IntPtr.Size == 8 ? 8 : 4; // alignment on x64

        var alreadyReported = new HashSet<(int, int)>(); // (readerPid, gamePid) pairs

        for (uint i = 0; i < handleCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            int off = baseOff + (int)(i * entrySize);
            if (off + entrySize > buf.Length) break;

            ushort ownerPid   = BitConverter.ToUInt16(buf, off);
            ushort handleVal  = BitConverter.ToUInt16(buf, off + 6);
            uint   access     = BitConverter.ToUInt32(buf, off + 12);

            // Check if this handle grants VM_READ
            if ((access & PROCESS_VM_READ) == 0) continue;

            // Skip if owned by a game process itself (they can read own memory)
            if (gameProcessIds.Contains(ownerPid)) continue;

            // Get owner name
            pidToName.TryGetValue(ownerPid, out string? ownerName);
            ownerName ??= $"PID {ownerPid}";

            // Skip known legitimate readers
            if (LegitReaders.Any(lr => ownerName.Contains(lr, StringComparison.OrdinalIgnoreCase))) continue;

            // The handle is a PROCESS handle — try to duplicate it and check which process it refers to
            // This requires PROCESS_DUP_HANDLE access on the owning process
            nint hOwner = OpenProcess(PROCESS_DUP_HANDLE, false, ownerPid);
            if (hOwner == nint.Zero) continue;

            try
            {
                nint dupHandle;
                bool dup = DuplicateHandle(hOwner, (nint)handleVal, GetCurrentProcess(),
                    out dupHandle, PROCESS_QUERY_LIMITED, false, 0);
                if (!dup) continue;

                try
                {
                    // Query the PID of the process this handle refers to
                    int targetPid = GetProcessIdFromHandle(dupHandle);
                    if (targetPid == 0) continue;
                    if (!gameProcessIds.Contains(targetPid)) continue;

                    // Skip if already reported this pair
                    if (!alreadyReported.Add((ownerPid, targetPid))) continue;

                    string targetName = pidToName.TryGetValue(targetPid, out string? tn) ? tn : $"PID {targetPid}";
                    string ownerPath = GetProcessPath(ownerPid);

                    ctx.AddFinding(new Finding
                    {
                        Module = "Game Memory Read Access Monitor",
                        Title = $"Prozess '{ownerName}' liest Spielspeicher von '{targetName}'",
                        Risk = RiskLevel.Critical,
                        Location = ownerPath,
                        FileName = Path.GetFileName(ownerPath),
                        Reason = $"Prozess '{ownerName}' (PID {ownerPid}) haelt ein PROCESS_VM_READ Handle " +
                                 $"auf Spielprozess '{targetName}' (PID {targetPid}) — " +
                                 "klassisches Muster fuer externe Cheats (ESP, Aimbot, Radar)",
                        Detail = $"Handle: 0x{handleVal:X} | Zugriffsrechte: 0x{access:X} | " +
                                 $"Leser: {ownerPath}"
                    });
                    ctx.IncrementProcesses();
                }
                finally { CloseHandle(dupHandle); }
            }
            finally { CloseHandle(hOwner); }
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetProcessId(nint Process);

    private static int GetProcessIdFromHandle(nint hProcess)
    {
        uint pid = GetProcessId(hProcess);
        return (int)pid;
    }

    private static string GetProcessPath(int pid)
    {
        nint hProc = OpenProcess(PROCESS_QUERY_LIMITED, false, pid);
        if (hProc == nint.Zero) return $"PID {pid}";
        try
        {
            var sb = new StringBuilder(512);
            uint sz = (uint)sb.Capacity;
            return QueryFullProcessImageNameW(hProc, 0, sb, ref sz) ? sb.ToString() : $"PID {pid}";
        }
        finally { CloseHandle(hProc); }
    }

    private static HashSet<int> GetGameProcessIds()
    {
        var ids = new HashSet<int>();
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (Array.Exists(GameProcessNames, n => name.Contains(n)))
                        ids.Add(proc.Id);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
        return ids;
    }

    private static Dictionary<int, string> BuildPidNameMap(CancellationToken ct)
    {
        var map = new Dictionary<int, string>();
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                ct.ThrowIfCancellationRequested();
                try { map[proc.Id] = proc.ProcessName; }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
        return map;
    }
}
