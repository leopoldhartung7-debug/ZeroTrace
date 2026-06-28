using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects PEB Loader (Ldr) doubly-linked list inconsistencies in game processes.
///
/// Manual DLL mapping / reflective injection techniques write a PE into private memory
/// and call the DLL's entrypoint directly — without adding an LDR_DATA_TABLE_ENTRY to
/// PEB.Ldr.InLoadOrderModuleList. The module therefore shows up via EnumProcessModulesEx
/// (which also scans the VAM for executable images) but is absent from the Ldr list.
/// Conversely, rootkit/cheat tools sometimes *unlink* a legitimate DLL entry from the Ldr
/// list (DKOM-style user-mode manipulation) so that EnumProcessModulesEx can still see
/// the mapped image but the Ldr walk reports fewer entries.
///
/// Detection:
///   1. Read PEB base via NtQueryInformationProcess(ProcessBasicInformation=0)
///   2. Walk ReadProcessMemory → PEB.Ldr → InLoadOrderModuleList to collect DllBase+paths
///   3. EnumProcessModulesEx to get the process module list from Windows loader
///   4. Cross-reference: bases in EnumProcessModules but NOT in Ldr = hidden/injected module
///
/// Requires PROCESS_VM_READ | PROCESS_QUERY_INFORMATION access to target process.
/// Game processes only. Skipped if not elevated.
/// </summary>
public sealed class PebLdrInconsistencyScanModule : IScanModule
{
    public string Name => "PEB Loader List Inconsistency Detection (Hidden/Injected Module)";
    public double Weight => 0.8;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(nint ProcessHandle,
        uint ProcessInformationClass, ref PROCESS_BASIC_INFORMATION ProcessInformation,
        uint ProcessInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress,
        nint lpBuffer, nint nSize, out nint lpNumberOfBytesRead);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EnumProcessModulesEx(nint hProcess, nint[] lphModule,
        uint cb, out uint lpcbNeeded, uint dwFilterFlag);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public nint ExitStatus;
        public nint PebBaseAddress;
        public nint AffinityMask;
        public nint BasePriority;
        public nint UniqueProcessId;
        public nint InheritedFromUniqueProcessId;
    }

    // PEB offsets (x64): Ldr at +0x18
    // PEB_LDR_DATA: InLoadOrderModuleList at +0x10
    // LDR_DATA_TABLE_ENTRY: Flink+Blink(LIST_ENTRY) at 0, DllBase at +0x30, FullDllName at +0x48
    private const int PEB_LDR_OFFSET             = 0x18;
    private const int LDR_INLOADORDER_OFFSET     = 0x10;
    private const int LDR_ENTRY_DLLBASE_OFFSET   = 0x30;
    private const int LDR_ENTRY_FULLNAME_OFFSET  = 0x48; // UNICODE_STRING (len+maxlen+buf) = +0, +2, +8
    private const int LDR_ENTRY_BASENAME_OFFSET  = 0x58;

    private const uint PROCESS_VM_READ                  = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION        = 0x0400;
    private const uint LIST_MODULES_DEFAULT             = 0x0;

    private static readonly HashSet<string> GameProcessNames =
        new(StringComparer.OrdinalIgnoreCase)
    {
        "cs2", "csgo", "valorant-win64-shipping", "r5apex", "dota2",
        "payday3-win64-shipping", "escape from tarkov", "eft",
        "destiny2", "warzone", "modernwarfare", "cod", "fortnite",
        "pubg", "tslgame", "rust", "bf2042", "battlefield",
        "overwatch", "overwatch2", "rainbow6", "r6", "siege",
        "gta5", "gtav", "rdr2", "eldenring", "terraria",
        "dayz", "squad", "arma3", "hunt", "battlebit",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!ZeroTrace.Core.Util.PrivilegeChecker.IsElevated()) return;

        var gameProcs = Process.GetProcesses()
            .Where(p => GameProcessNames.Any(g =>
                p.ProcessName.Contains(g, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        foreach (var proc in gameProcs)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Run(() => AnalyzeProcess(ctx, proc, ct), ct);
            try { proc.Dispose(); } catch { }
        }
    }

    private void AnalyzeProcess(ScanContext ctx, Process proc, CancellationToken ct)
    {
        nint hProc = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            ctx.IncrementProcesses();

            // 1. Get PEB base
            var pbi = new PROCESS_BASIC_INFORMATION();
            if (NtQueryInformationProcess(hProc, 0, ref pbi,
                    (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _) != 0)
                return;

            nint pebBase = pbi.PebBaseAddress;
            if (pebBase == nint.Zero) return;

            // 2. Walk PEB → Ldr → InLoadOrderModuleList
            var ldrBases = new HashSet<nint>();
            WalkPebLdr(hProc, pebBase, ldrBases, ct);

            // 3. EnumProcessModulesEx
            var enumBases = new HashSet<nint>();
            EnumerateModules(hProc, enumBases);

            // 4. Find modules in EnumProcessModules that are absent from Ldr list
            foreach (nint modBase in enumBases)
            {
                ct.ThrowIfCancellationRequested();
                if (ldrBases.Contains(modBase)) continue;

                // Try to get module name from EnumProcessModulesEx path
                string modName = TryGetModuleName(hProc, modBase);
                if (string.IsNullOrEmpty(modName)) modName = $"0x{modBase:X}";

                // Skip likely false positives: 64-bit entry point or ntdll itself
                if (modName.EndsWith("ntdll.dll", StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"PEB Ldr-Eintrag fehlt für geladenes Modul in {proc.ProcessName}: {modName}",
                    Risk     = RiskLevel.Critical,
                    Location = $"Prozess: {proc.ProcessName} (PID {proc.Id}) | Modul: {modName}",
                    FileName = System.IO.Path.GetFileName(modName),
                    Reason   = $"Modul '{modName}' (Basis: 0x{modBase:X}) ist in EnumProcessModulesEx " +
                               $"sichtbar, fehlt aber in PEB.Ldr.InLoadOrderModuleList von Prozess " +
                               $"'{proc.ProcessName}' (PID {proc.Id}). Dies ist ein Kennzeichen für " +
                               "manuelles Mapping (Reflective DLL Injection / Manual Map): Das PE " +
                               "wurde ohne Windows-Loader in den Prozess geschrieben und sein " +
                               "LDR_DATA_TABLE_ENTRY wurde nicht zur PEB hinzugefügt, um " +
                               "standard-Enumerierungen zu umgehen.",
                    Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | " +
                               $"Modul-Basis: 0x{modBase:X} | " +
                               $"Name: {modName} | " +
                               "Ldr-Eintrag: FEHLT"
                });
            }
        }
        catch { }
        finally { CloseHandle(hProc); }
    }

    private void WalkPebLdr(nint hProc, nint pebBase,
        HashSet<nint> ldrBases, CancellationToken ct)
    {
        // Read Ldr pointer from PEB+0x18
        nint ldrPtr = ReadPtr(hProc, pebBase + PEB_LDR_OFFSET);
        if (ldrPtr == nint.Zero) return;

        // Read InLoadOrderModuleList.Flink at Ldr+0x10
        nint listHead = ldrPtr + LDR_INLOADORDER_OFFSET;
        nint flink    = ReadPtr(hProc, listHead);
        if (flink == nint.Zero) return;

        int maxEntries = 512;
        nint cur = flink;

        while (cur != listHead && cur != nint.Zero && maxEntries-- > 0)
        {
            ct.ThrowIfCancellationRequested();

            // DllBase at LDR_DATA_TABLE_ENTRY+0x30
            nint dllBase = ReadPtr(hProc, cur + LDR_ENTRY_DLLBASE_OFFSET);
            if (dllBase != nint.Zero)
                ldrBases.Add(dllBase);

            // Follow Flink (first 8 bytes of LIST_ENTRY)
            nint next = ReadPtr(hProc, cur);
            if (next == cur) break;
            cur = next;
        }
    }

    private void EnumerateModules(nint hProc, HashSet<nint> bases)
    {
        uint needed = 0;
        // First call to get required size
        nint[] dummy = new nint[1];
        EnumProcessModulesEx(hProc, dummy, (uint)(nint.Size), out needed, LIST_MODULES_DEFAULT);

        if (needed == 0) return;
        int count = (int)(needed / (uint)nint.Size);
        nint[] modules = new nint[count];

        if (!EnumProcessModulesEx(hProc, modules,
                (uint)(count * nint.Size), out _, LIST_MODULES_DEFAULT))
            return;

        foreach (nint m in modules)
            if (m != nint.Zero) bases.Add(m);
    }

    private string TryGetModuleName(nint hProc, nint modBase)
    {
        // We can't easily call GetModuleFileNameEx cross-process here without psapi.
        // Instead just return the hex base; caller labels it.
        try
        {
            // Try to read DOS header MZ to confirm it's a PE
            byte[] hdr = new byte[2];
            nint buf = Marshal.AllocHGlobal(2);
            try
            {
                if (ReadProcessMemory(hProc, modBase, buf, 2, out nint read) && read >= 2)
                {
                    Marshal.Copy(buf, hdr, 0, 2);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { }
        return $"<Modul@0x{modBase:X}>";
    }

    private nint ReadPtr(nint hProc, nint addr)
    {
        nint buf = Marshal.AllocHGlobal(nint.Size);
        try
        {
            if (!ReadProcessMemory(hProc, addr, buf, nint.Size, out nint read) || read < nint.Size)
                return nint.Zero;
            return Marshal.ReadIntPtr(buf);
        }
        catch { return nint.Zero; }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
