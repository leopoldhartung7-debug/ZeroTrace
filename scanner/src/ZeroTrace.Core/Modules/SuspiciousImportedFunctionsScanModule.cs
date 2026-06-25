using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Inspects the Import Address Table of non-system modules loaded in game processes.
/// Flags dangerous function combinations used for process injection, privilege escalation,
/// thread hijacking, and anti-analysis evasion.
/// </summary>
public sealed class SuspiciousImportedFunctionsScanModule : IScanModule
{
    public string Name => "Suspicious Imported Functions";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    private static readonly (string[] Required, string Description, RiskLevel Risk)[] DangerousCombos =
    {
        (new[] { "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" },
         "Klassische Injektions-Triade: VirtualAllocEx+WriteProcessMemory+CreateRemoteThread",
         RiskLevel.Critical),
        (new[] { "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx" },
         "NT-Level Thread-Injektion: VirtualAllocEx+WriteProcessMemory+NtCreateThreadEx",
         RiskLevel.Critical),
        (new[] { "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx" },
         "Direkte NT-API Injektion: NtAllocateVirtualMemory+NtWriteVirtualMemory+NtCreateThreadEx",
         RiskLevel.Critical),
        (new[] { "QueueUserAPC", "WriteProcessMemory", "VirtualAllocEx" },
         "APC Injektion: VirtualAllocEx+WriteProcessMemory+QueueUserAPC",
         RiskLevel.Critical),
        (new[] { "NtQueueApcThread", "NtWriteVirtualMemory", "NtAllocateVirtualMemory" },
         "NT APC Injektion: NtAllocateVirtualMemory+NtWriteVirtualMemory+NtQueueApcThread",
         RiskLevel.Critical),
        (new[] { "NtCreateSection", "NtMapViewOfSection", "NtCreateThreadEx" },
         "Section-basierte Injektion: NtCreateSection+NtMapViewOfSection+NtCreateThreadEx",
         RiskLevel.Critical),
        (new[] { "SetThreadContext", "SuspendThread", "WriteProcessMemory" },
         "Thread-Hijacking: SuspendThread+SetThreadContext+WriteProcessMemory",
         RiskLevel.Critical),
        (new[] { "RtlCreateUserThread", "WriteProcessMemory" },
         "RtlCreateUserThread Injektion: undokumentierte Thread-Erstellung fuer Remote-Injektion",
         RiskLevel.Critical),
        (new[] { "SetWindowsHookExA", "GetAsyncKeyState" },
         "Keylogger-Muster: SetWindowsHookExA + GetAsyncKeyState",
         RiskLevel.High),
        (new[] { "SetWindowsHookExW", "GetAsyncKeyState" },
         "Keylogger-Muster: SetWindowsHookExW + GetAsyncKeyState",
         RiskLevel.High),
        (new[] { "VirtualProtect", "WriteProcessMemory" },
         "Code-Patch Muster: VirtualProtect+WriteProcessMemory zum Aendern von Code-Bytes",
         RiskLevel.High),
        (new[] { "CreateFileMappingA", "MapViewOfFile", "WriteProcessMemory" },
         "Shared-Memory Injektion: CreateFileMappingA+MapViewOfFile+WriteProcessMemory",
         RiskLevel.High),
        (new[] { "NtSuspendProcess", "WriteProcessMemory" },
         "Prozess-Freeze + Write: NtSuspendProcess fuer atomares Patchen von Anti-Cheat",
         RiskLevel.Critical),
        (new[] { "LoadLibraryA", "WriteProcessMemory", "VirtualAllocEx" },
         "LoadLibrary-Injektion: VirtualAllocEx+WriteProcessMemory+LoadLibraryA",
         RiskLevel.High),
        (new[] { "LoadLibraryW", "WriteProcessMemory", "VirtualAllocEx" },
         "LoadLibrary-Injektion: VirtualAllocEx+WriteProcessMemory+LoadLibraryW",
         RiskLevel.High),
    };

    private static readonly (string Function, string Description, RiskLevel Risk)[] HighRiskSingles =
    {
        ("RtlCreateUserThread", "Undokumentiertes NT API fuer Remote-Thread-Erstellung (Injektion)", RiskLevel.High),
        ("NtCreateThreadEx", "Low-Level NT Thread-Erstellung — umgeht Anti-Cheat Hooks in ntdll", RiskLevel.High),
        ("NtMapViewOfSection", "NT Section-Mapping — Kern-Primitive fuer Section-basierte Injektion", RiskLevel.Medium),
        ("ZwSetInformationThread", "Thread-Info Manipulation — versteckt Threads vor Debuggern (ThreadHideFromDebugger)", RiskLevel.High),
        ("NtSuspendProcess", "Prozess einfrieren — Cheat friert Anti-Cheat ein um ihn sicher zu patchen", RiskLevel.High),
        ("DbgUiRemoteBreakin", "Remote Debugger-Einbruch API — verwendet von Debuggern und Injection-Tools", RiskLevel.Medium),
        ("NtWriteVirtualMemory", "Direktes NT Write in fremde Prozesse — bevorzugt von Cheat-Loadern", RiskLevel.Medium),
        ("NtAllocateVirtualMemory", "Direkte NT Speicher-Allokation — bevorzugt von Cheat-Loadern", RiskLevel.Medium),
        ("NtProtectVirtualMemory", "Direkte NT Speicher-Schutz-Aenderung — umgeht Hooks in VirtualProtect", RiskLevel.Medium),
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        nint hProcess, nint lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Module32First(nint hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll")]
    private static extern bool Module32Next(nint hSnapshot, ref MODULEENTRY32 lpme);

    private const uint PROCESS_VM_READ = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint TH32CS_SNAPMODULE = 0x00000008;
    private const uint TH32CS_SNAPMODULE32 = 0x00000010;
    private static readonly nint InvalidHandle = new nint(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct MODULEENTRY32
    {
        public uint dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public nint modBaseAddr;
        public uint modBaseSize;
        public nint hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;
    }

    private static readonly string[] SystemDirMarkers =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\sysnative\",
        @"\microsoft.net\",
        @"\windows\winsxs\",
        @"\program files\windows ",
        @"\windows\servicing\",
    };

    private static bool IsSystemModule(string path)
    {
        if (string.IsNullOrEmpty(path)) return true;
        var lower = path.ToLowerInvariant();
        foreach (var marker in SystemDirMarkers)
            if (lower.Contains(marker)) return true;
        return false;
    }

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "client", "ffxiv", "fortnite", "valorant",
        "apex", "r5apex", "pubg", "rust", "eft", "destiny", "warzone", "overwatch",
        "battlefront", "cod", "paladins", "rocketleague", "dota2", "tf2", "l4d2",
        "insurgency", "hll", "cheat", "loader", "injector"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var gameProcesses = GetTargetProcesses();
        if (gameProcesses.Count == 0) return;

        await Task.Run(() =>
        {
            foreach (var proc in gameProcesses)
            {
                ct.ThrowIfCancellationRequested();
                try { ScanProcess(proc, ctx); }
                catch { /* skip unreadable */ }
                finally { proc.Dispose(); }
                ctx.IncrementProcesses();
            }
        }, ct);
    }

    private void ScanProcess(Process proc, ScanContext ctx)
    {
        nint hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (hProc == nint.Zero) return;

        try
        {
            nint hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)proc.Id);
            if (hSnap == InvalidHandle) return;

            try
            {
                var me = new MODULEENTRY32 { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>() };
                if (!Module32First(hSnap, ref me)) return;

                do
                {
                    ct.ThrowIfCancellationRequested();
                    if (IsSystemModule(me.szExePath)) continue;

                    try
                    {
                        var imports = ReadModuleImports(hProc, me.modBaseAddr, (int)me.modBaseSize);
                        if (imports.Count > 0)
                            CheckImports(imports, proc.ProcessName, me.szModule, me.szExePath, ctx);
                    }
                    catch { /* skip unreadable module */ }
                }
                while (Module32Next(hSnap, ref me));
            }
            finally { CloseHandle(hSnap); }
        }
        finally { CloseHandle(hProc); }
    }

    private HashSet<string> ReadModuleImports(nint hProc, nint baseAddr, int moduleSize)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var header = new byte[0x1000];
        if (!ReadProcessMemory(hProc, baseAddr, header, header.Length, out _)) return result;

        if (header[0] != 'M' || header[1] != 'Z') return result;
        int e_lfanew = BitConverter.ToInt32(header, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 0x18 >= header.Length) return result;
        if (header[e_lfanew] != 'P' || header[e_lfanew + 1] != 'E') return result;

        ushort machine = BitConverter.ToUInt16(header, e_lfanew + 4);
        bool is64 = machine == 0x8664;

        // DataDirectory[1] = Import Directory
        int ddBase = e_lfanew + 24 + (is64 ? 0x70 : 0x60);
        int importDdOff = ddBase + 8; // index 1 * 8
        if (importDdOff + 8 > header.Length) return result;

        uint importRva = BitConverter.ToUInt32(header, importDdOff);
        uint importSize = BitConverter.ToUInt32(header, importDdOff + 4);
        if (importRva == 0 || importSize == 0) return result;

        int readSize = (int)Math.Min(importSize, 8192u);
        var importData = new byte[readSize];
        if (!ReadProcessMemory(hProc, baseAddr + (nint)importRva, importData, readSize, out _))
            return result;

        // Each IMAGE_IMPORT_DESCRIPTOR = 20 bytes
        // [0]=OriginalFirstThunk [4]=TimeDateStamp [8]=ForwarderChain [12]=Name [16]=FirstThunk
        for (int pos = 0; pos + 20 <= importData.Length; pos += 20)
        {
            uint origThunkRva = BitConverter.ToUInt32(importData, pos);
            uint nameRva      = BitConverter.ToUInt32(importData, pos + 12);
            uint thunkRva     = BitConverter.ToUInt32(importData, pos + 16);
            if (nameRva == 0 && thunkRva == 0) break;

            uint thunkStart = origThunkRva != 0 ? origThunkRva : thunkRva;
            if (thunkStart == 0) continue;

            int thunkSz = is64 ? 8 : 4;
            const int MaxThunks = 512;
            var thunkData = new byte[thunkSz * MaxThunks];
            if (!ReadProcessMemory(hProc, baseAddr + (nint)thunkStart, thunkData, thunkData.Length, out int bytesRead))
                continue;

            for (int t = 0; t + thunkSz <= bytesRead; t += thunkSz)
            {
                ulong entry = is64
                    ? BitConverter.ToUInt64(thunkData, t)
                    : BitConverter.ToUInt32(thunkData, t);

                if (entry == 0) break;

                bool byOrdinal = is64
                    ? (entry & 0x8000000000000000UL) != 0
                    : (entry & 0x80000000UL) != 0;
                if (byOrdinal) continue;

                uint hintRva = (uint)(entry & (is64 ? 0x7FFFFFFFFFFFFFFFUL : 0x7FFFFFFFUL));
                if (hintRva == 0 || hintRva > (uint)moduleSize) continue;

                var nameBytes = new byte[128];
                // Skip 2-byte Hint before the name
                if (!ReadProcessMemory(hProc, baseAddr + (nint)hintRva + 2, nameBytes, nameBytes.Length, out _))
                    continue;

                int nl = Array.IndexOf(nameBytes, (byte)0);
                if (nl <= 0) continue;
                string fn = Encoding.ASCII.GetString(nameBytes, 0, nl);
                if (!string.IsNullOrEmpty(fn)) result.Add(fn);
            }
        }

        return result;
    }

    private static void CheckImports(
        HashSet<string> imports, string procName, string modName, string modPath, ScanContext ctx)
    {
        foreach (var (required, desc, risk) in DangerousCombos)
        {
            if (required.All(fn => imports.Contains(fn)))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Suspicious Imported Functions",
                    Title = $"Gefaehrliche Import-Kombination in {modName}",
                    Risk = risk,
                    Location = modPath,
                    FileName = modName,
                    Reason = $"Prozess {procName}: Modul importiert Injektions-Funktionskombination",
                    Detail = $"{desc} — Funktionen: {string.Join(", ", required)}"
                });
            }
        }

        foreach (var (func, desc, risk) in HighRiskSingles)
        {
            if (imports.Contains(func))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Suspicious Imported Functions",
                    Title = $"Risiko-Import: {func} in {modName}",
                    Risk = risk,
                    Location = modPath,
                    FileName = modName,
                    Reason = $"Prozess {procName}: Nicht-System-Modul importiert verdaechtige Funktion",
                    Detail = desc
                });
            }
        }
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
                    bool isTarget = Array.Exists(GameProcessNames, n => name.Contains(n));
                    if (isTarget) result.Add(proc);
                    else proc.Dispose();
                }
                catch { proc.Dispose(); }
            }
        }
        catch { }
        return result;
    }
}
