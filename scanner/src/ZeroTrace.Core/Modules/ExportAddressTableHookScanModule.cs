using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Export Address Table (EAT) hooks in critical DLLs loaded in game processes.
/// Unlike inline hooks (which patch bytes at the function start), EAT hooks modify the
/// export directory's address table so the exported function pointer redirects to a
/// different address — typically shellcode or a trampoline in private memory. This is
/// harder to detect visually in a memory dump and is used by advanced cheat tools.
/// The module reads the EAT from the in-memory PE of ntdll.dll, kernel32.dll, and
/// kernelbase.dll in game processes, then cross-references each function VA against
/// the module's memory range — any export pointing outside the module indicates an EAT hook.
/// </summary>
public sealed class ExportAddressTableHookScanModule : IScanModule
{
    public string Name => "Export Address Table Hook Detection";
    public double Weight => 0.85;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        nint hProcess, nint lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Module32First(nint hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll")]
    private static extern bool Module32Next(nint hSnapshot, ref MODULEENTRY32 lpme);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID, th32ProcessID, GlblcntUsage, ProccntUsage;
        public nint modBaseAddr;
        public uint modBaseSize;
        public nint hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    private const uint TH32CS_SNAPMODULE    = 0x00000008;
    private const uint TH32CS_SNAPMODULE32  = 0x00000010;
    private const uint PROCESS_VM_READ      = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private static readonly nint InvalidHandle = new nint(-1);

    // DLLs to check — critical system DLLs whose EAT is a high-value hook target
    private static readonly string[] TargetDlls =
    {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "win32u.dll",
    };

    // High-value exports — only check these to limit false positives and scan time
    private static readonly string[] HighValueExports =
    {
        "NtOpenProcess", "NtReadVirtualMemory", "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
        "NtQueueApcThread", "NtSuspendThread", "NtResumeThread",
        "NtSetContextThread", "NtGetContextThread", "NtQueryInformationProcess",
        "NtQuerySystemInformation", "EtwEventWrite", "EtwEventWriteFull",
        "LdrLoadDll", "LdrGetProcedureAddress", "RtlExitUserProcess",
        "CreateRemoteThreadEx", "VirtualAllocEx", "WriteProcessMemory",
        "ReadProcessMemory", "OpenProcess", "GetProcAddress", "LoadLibraryA",
    };

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "cheat", "loader", "injector",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var targets = GetTargetProcesses();
        if (targets.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var proc in targets)
            {
                ct.ThrowIfCancellationRequested();
                try { ScanProcess(proc, ctx, ct); }
                catch { }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }, ct);
    }

    private void ScanProcess(Process proc, ScanContext ctx, CancellationToken ct)
    {
        nint hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        nint hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)proc.Id);
        if (hSnap == InvalidHandle) { CloseHandle(hProc); return; }

        try
        {
            var me = new MODULEENTRY32 { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>() };
            if (!Module32First(hSnap, ref me)) return;

            int findingCount = 0;
            do
            {
                ct.ThrowIfCancellationRequested();
                if (findingCount >= 20) break;

                string modNameLower = me.szModule.ToLowerInvariant();
                if (!Array.Exists(TargetDlls, d => d.Equals(modNameLower, StringComparison.OrdinalIgnoreCase)))
                    continue;

                try
                {
                    var hookedExports = CheckEat(hProc, me, ct);
                    foreach (var (funcName, exportRva, resolvedVa, isOutOfModule) in hookedExports)
                    {
                        if (!isOutOfModule) continue;
                        findingCount++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"EAT-Hook in '{me.szModule}' von '{proc.ProcessName}': {funcName}",
                            Risk     = RiskLevel.Critical,
                            Location = $"{me.szExePath} @0x{(ulong)me.modBaseAddr:X}",
                            FileName = me.szModule,
                            Reason   = $"Export '{funcName}' in '{me.szModule}' zeigt auf Adresse 0x{resolvedVa:X} " +
                                       $"die AUSSERHALB des Moduls liegt (Modul-Bereich: 0x{(ulong)me.modBaseAddr:X}–" +
                                       $"0x{(ulong)(me.modBaseAddr + (nint)me.modBaseSize):X}) — " +
                                       "EAT-Hook leitet API-Aufruf auf Shellcode/Trampolin um",
                            Detail   = $"Prozess: {proc.ProcessName} (PID {proc.Id}) | Modul: {me.szModule} | " +
                                       $"Export: {funcName} | EAT-RVA: 0x{exportRva:X} | " +
                                       $"Aufgelöste VA: 0x{resolvedVa:X} | Außerhalb: ja"
                        });
                    }
                }
                catch { }
            }
            while (Module32Next(hSnap, ref me));
        }
        finally
        {
            CloseHandle(hSnap);
            CloseHandle(hProc);
        }
    }

    private List<(string Name, uint ExportRva, ulong ResolvedVa, bool OutOfModule)> CheckEat(
        nint hProc, MODULEENTRY32 me, CancellationToken ct)
    {
        var result = new List<(string, uint, ulong, bool)>();

        var header = new byte[0x400];
        if (!ReadProcessMemory(hProc, me.modBaseAddr, header, header.Length, out _)) return result;
        if (header[0] != 'M' || header[1] != 'Z') return result;

        int e_lfanew = BitConverter.ToInt32(header, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 24 >= header.Length) return result;
        if (header[e_lfanew] != 'P' || header[e_lfanew + 1] != 'E') return result;

        ushort machine    = BitConverter.ToUInt16(header, e_lfanew + 4);
        bool is64         = machine == 0x8664;
        int  optHdrOff    = e_lfanew + 24;
        int  eatDirOffset = optHdrOff + (is64 ? 0x70 : 0x60);

        if (eatDirOffset + 8 > header.Length) return result;
        uint exportDirRva  = BitConverter.ToUInt32(header, eatDirOffset);
        uint exportDirSize = BitConverter.ToUInt32(header, eatDirOffset + 4);
        if (exportDirRva == 0) return result;

        // Read export directory (typically ~40 bytes)
        var expDir = new byte[40];
        nint expDirVa = me.modBaseAddr + (nint)exportDirRva;
        if (!ReadProcessMemory(hProc, expDirVa, expDir, expDir.Length, out _)) return result;

        uint numberOfFunctions = BitConverter.ToUInt32(expDir, 20);  // NumberOfFunctions
        uint numberOfNames     = BitConverter.ToUInt32(expDir, 24);  // NumberOfNames
        uint addressTableRva   = BitConverter.ToUInt32(expDir, 28);  // AddressOfFunctions
        uint nameTableRva      = BitConverter.ToUInt32(expDir, 32);  // AddressOfNames
        uint ordinalTableRva   = BitConverter.ToUInt32(expDir, 36);  // AddressOfNameOrdinals

        if (numberOfFunctions > 10_000 || numberOfNames > 10_000) return result;

        // Read address table
        var addrTable = new byte[numberOfFunctions * 4];
        if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)addressTableRva,
            addrTable, addrTable.Length, out _)) return result;

        // Read name and ordinal tables
        var nameTable    = new byte[numberOfNames * 4];
        var ordinalTable = new byte[numberOfNames * 2];
        if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)nameTableRva,
            nameTable, nameTable.Length, out _)) return result;
        if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)ordinalTableRva,
            ordinalTable, ordinalTable.Length, out _)) return result;

        ulong modBase = (ulong)me.modBaseAddr;
        ulong modEnd  = modBase + me.modBaseSize;

        for (uint n = 0; n < numberOfNames; n++)
        {
            ct.ThrowIfCancellationRequested();

            uint nameRva     = BitConverter.ToUInt32(nameTable, (int)(n * 4));
            ushort ordinal   = BitConverter.ToUInt16(ordinalTable, (int)(n * 2));
            if (ordinal >= numberOfFunctions) continue;

            uint funcRva = BitConverter.ToUInt32(addrTable, (int)(ordinal * 4));
            if (funcRva == 0) continue;

            ulong funcVa = modBase + funcRva;

            // Is this a forwarder? Forwarder RVAs point inside the export directory
            bool isForwarder = funcRva >= exportDirRva && funcRva < exportDirRva + exportDirSize;
            if (isForwarder) continue;

            // Is the resolved VA within the module's memory range?
            bool isOutOfModule = funcVa < modBase || funcVa >= modEnd;
            if (!isOutOfModule) continue;

            // Read the export name
            var nameBuf = new byte[128];
            if (!ReadProcessMemory(hProc, me.modBaseAddr + (nint)nameRva, nameBuf, nameBuf.Length, out _))
                continue;

            int nameLen = Array.IndexOf(nameBuf, (byte)0);
            if (nameLen <= 0) continue;
            string funcName = System.Text.Encoding.ASCII.GetString(nameBuf, 0, nameLen);

            // Only report high-value exports to limit false positives
            if (!Array.Exists(HighValueExports, h => h.Equals(funcName, StringComparison.Ordinal)))
                continue;

            result.Add((funcName, funcRva, funcVa, true));
            if (result.Count >= 10) break;
        }

        return result;
    }

    private static List<Process> GetTargetProcesses()
    {
        var result = new List<Process>();
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    string name = proc.ProcessName.ToLowerInvariant();
                    if (Array.Exists(GameProcessNames, n => name.Contains(n)))
                        result.Add(proc);
                    else
                        proc.Dispose();
                }
                catch { proc.Dispose(); }
            }
        }
        catch { }
        return result;
    }
}
