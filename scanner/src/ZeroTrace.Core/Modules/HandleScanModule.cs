using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects external memory-reading cheats by enumerating all system-wide process
/// handles via NtQuerySystemInformation(SystemExtendedHandleInformation). For each
/// detected game process, it looks for handles owned by a different, non-whitelisted
/// process that grant PROCESS_VM_READ (and optionally PROCESS_VM_WRITE) access.
///
/// External cheats (Wallhack, ESP, Aimbot) work by:
///   1. OpenProcess(PROCESS_VM_READ, game_pid)
///   2. ReadProcessMemory(handle, entity_list_addr, ...)
///
/// The open handle is visible systemwide via the handle table — this module finds it.
/// Requires elevation. Read-only; no handles are closed or processes terminated.
/// </summary>
public sealed class HandleScanModule : IScanModule
{
    public string Name => "Handle-Scan (externe Cheats)";
    public double Weight => 0.5;
    public int ParallelGroup => 2;

    private const int SystemExtendedHandleInformation  = 64;
    private const int STATUS_INFO_LENGTH_MISMATCH       = unchecked((int)0xC0000004);
    private const int STATUS_SUCCESS                    = 0;
    private const uint PROCESS_VM_READ                  = 0x0010;
    private const uint PROCESS_VM_WRITE                 = 0x0020;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    // Layout of SYSTEM_EXTENDED_HANDLE_TABLE_ENTRY_INFO (64-bit, 40 bytes each)
    // Object           [+0]  8 bytes (kernel EPROCESS ptr)
    // UniqueProcessId  [+8]  8 bytes
    // HandleValue      [+16] 8 bytes
    // GrantedAccess    [+24] 4 bytes
    // CreatorBackTrace [+28] 2 bytes
    // ObjectTypeIndex  [+30] 2 bytes
    // HandleCount      [+32] 4 bytes
    // PointerCount     [+36] 4 bytes
    private const int EntrySize  = 40;
    private const int HeaderSize = 16; // NumberOfHandles (8) + Reserved (8)

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int SystemInformationClass, IntPtr SystemInformation,
        int SystemInformationLength, out int ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll")]
    private static extern int GetCurrentProcessId();

    // Known game process names that external cheats target
    private static readonly HashSet<string> GameProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // GTA V / FiveM
        "GTA5", "gta5", "FiveM", "FiveM_b3095_GTAProcess", "FiveM_b2699_GTAProcess",
        "FiveM_GTAProcess", "FiveM_b2060_GTAProcess",
        // CS2 / CSGO
        "cs2", "csgo",
        // EFT
        "EscapeFromTarkov",
        // R6 Siege
        "RainbowSix", "Rainbow Six Siege",
        // Apex
        "r5apex",
        // Warzone / COD
        "ModernWarfare", "Warzone",
        // Valorant
        "VALORANT-Win64-Shipping",
        // Rust
        "RustClient",
        // DayZ
        "DayZ_x64",
        // Battlefield
        "bf2042",
    };

    // Processes expected to legitimately read game memory (AC, OS, etc.)
    private static readonly HashSet<string> WhitelistedOwners = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "services", "lsass", "csrss", "winlogon", "wininit",
        "System", "smss", "explorer", "taskmgr", "SearchHost",
        "SecurityHealthService", "SecurityHealthSystray",
        "MsMpEng", "NisSrv",           // Windows Defender
        "BEService", "EasyAntiCheat",  // Anti-cheats (BE, EAC)
        "vgc", "vgtray", "VALORANT",   // Vanguard
        "ZeroTrace",                   // ourselves
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!PrivilegeChecker.IsElevated())
        {
            ctx.Report(1.0, "Handle-Scan", "Nicht erhoeht – Handle-Scan erfordert Administratorrechte");
            return Task.CompletedTask;
        }

        var gamePids = FindGameProcessPids();
        if (gamePids.Count == 0)
        {
            ctx.Report(1.0, "Handle-Scan", "Kein Spielprozess aktiv – Handle-Scan uebersprungen");
            return Task.CompletedTask;
        }

        int ourPid = GetCurrentProcessId();
        // Open handles to each game process so we can find their Object pointers
        var ourHandleToGame = new Dictionary<long, (int gamePid, string gameName)>();
        var openedHandles   = new List<IntPtr>();

        foreach (var (gamePid, gameName) in gamePids)
        {
            var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, gamePid);
            if (h != IntPtr.Zero)
            {
                openedHandles.Add(h);
                ourHandleToGame[h.ToInt64()] = (gamePid, gameName);
            }
        }

        if (ourHandleToGame.Count == 0)
        {
            foreach (var h in openedHandles) CloseHandle(h);
            ctx.Report(1.0, "Handle-Scan", "Spielprozesse konnten nicht geoeffnet werden");
            return Task.CompletedTask;
        }

        IntPtr buf  = IntPtr.Zero;
        int    size = 0x400000; // 4 MB
        try
        {
            while (!ct.IsCancellationRequested)
            {
                buf    = Marshal.AllocHGlobal(size);
                int status = NtQuerySystemInformation(
                    SystemExtendedHandleInformation, buf, size, out int needed);

                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
                    size = Math.Max(needed + 0x40000, size * 2);
                    continue;
                }
                if (status != STATUS_SUCCESS) break;

                long count = Marshal.ReadInt64(buf, 0);

                // Phase 1: resolve Object pointer for each game process we opened
                var gameObjects = new Dictionary<long, (int pid, string name)>();
                for (long i = 0; i < count && !ct.IsCancellationRequested; i++)
                {
                    int  off       = (int)(HeaderSize + i * EntrySize);
                    long objPtr    = Marshal.ReadInt64(buf, off +  0);
                    long ownerPid  = Marshal.ReadInt64(buf, off +  8);
                    long handleVal = Marshal.ReadInt64(buf, off + 16);

                    if (ownerPid == ourPid &&
                        ourHandleToGame.TryGetValue(handleVal, out var gInfo))
                        gameObjects[objPtr] = gInfo;
                }

                if (gameObjects.Count == 0) break;

                // Phase 2: find handles from other processes to those game objects
                var reported = new HashSet<string>();
                for (long i = 0; i < count && !ct.IsCancellationRequested; i++)
                {
                    int  off          = (int)(HeaderSize + i * EntrySize);
                    long objPtr       = Marshal.ReadInt64(buf, off +  0);
                    long ownerPid     = Marshal.ReadInt64(buf, off +  8);
                    uint grantedAccess = (uint)Marshal.ReadInt32(buf, off + 24);

                    if (ownerPid == ourPid) continue;
                    if (ownerPid == 0 || ownerPid == 4) continue;
                    if ((grantedAccess & PROCESS_VM_READ) == 0) continue;
                    if (!gameObjects.TryGetValue(objPtr, out var gameInfo)) continue;

                    string ownerName = "";
                    try
                    {
                        using var p = Process.GetProcessById((int)ownerPid);
                        ownerName = p.ProcessName;
                    }
                    catch { ownerName = $"PID {ownerPid}"; }

                    if (WhitelistedOwners.Contains(ownerName)) continue;

                    var dedup = $"{ownerPid}:{gameInfo.pid}";
                    if (!reported.Add(dedup)) continue;

                    bool hasWrite = (grantedAccess & PROCESS_VM_WRITE) != 0;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Externer Speicher-Zugriff: '{ownerName}' -> '{gameInfo.name}'",
                        Risk     = hasWrite ? RiskLevel.Critical : RiskLevel.High,
                        Location = $"Prozess '{ownerName}' (PID {ownerPid})",
                        FileName = ownerName + ".exe",
                        Reason   = $"Prozess '{ownerName}' (PID {ownerPid}) haelt einen Handle mit " +
                                   $"PROCESS_VM_READ{(hasWrite ? " + PROCESS_VM_WRITE" : "")} auf den " +
                                   $"Spielprozess '{gameInfo.name}' (PID {gameInfo.pid}). " +
                                   "Externe Cheats (Wallhack, ESP, Aimbot) arbeiten exakt so: " +
                                   "sie oeffnen den Spielprozess und lesen den Spielspeicher " +
                                   "kontinuierlich mit ReadProcessMemory. Kein legitimes Programm " +
                                   "benoetigt diesen Zugriff waehrend einer Spielsitzung.",
                        Detail   = $"Handle-Zugriffsmaske: 0x{grantedAccess:X8} · " +
                                   $"VM_READ={hasWrite || true} VM_WRITE={hasWrite}"
                    });
                }
                break;
            }
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
            foreach (var h in openedHandles) CloseHandle(h);
        }

        ctx.Report(1.0, "Handle-Scan", "Handle-Scan abgeschlossen");
        return Task.CompletedTask;
    }

    private static List<(int pid, string name)> FindGameProcessPids()
    {
        var result = new List<(int, string)>();
        try
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (GameProcessNames.Contains(p.ProcessName))
                        result.Add((p.Id, p.ProcessName));
                }
                catch { }
                finally { p.Dispose(); }
            }
        }
        catch { }
        return result;
    }
}
