using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects anti-dump and anti-analysis protections applied to loaded modules in game processes:
/// erased PE headers (e_magic zeroed to prevent dump tools from finding modules), SizeOfImage
/// mismatches between in-memory OptionalHeader and on-disk file (indicating stealth patching),
/// and missing/wrong PE signature at e_lfanew offset. These are classic obfuscation techniques
/// used by advanced cheat packers (Themida, VMProtect, custom loaders) to hinder forensic
/// analysis and memory dumping by anti-cheat tools.
/// </summary>
public sealed class AntiDumpProtectionScanModule : IScanModule
{
    public string Name => "Anti-Dump Protection Detection";
    public double Weight => 0.9;
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
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public nint modBaseAddr;
        public uint modBaseSize;
        public nint hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExePath;
    }

    private const uint TH32CS_SNAPMODULE        = 0x00000008;
    private const uint TH32CS_SNAPMODULE32       = 0x00000010;
    private const uint PROCESS_VM_READ           = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private static readonly nint InvalidHandle   = new nint(-1);

    private static readonly string[] SkipPaths =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\winsxs\",
    };

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust", "fortnite",
        "valorant", "apex", "eft", "destiny", "warzone", "overwatch", "cod",
        "dota2", "tf2", "hll", "cheat", "loader", "injector", "client"
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
                catch { /* skip */ }
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

                string pathLower = me.szExePath.ToLowerInvariant();
                bool isSystem = Array.Exists(SkipPaths, sp => pathLower.Contains(sp));
                if (isSystem) continue;

                try
                {
                    var anomalies = AnalyzeModule(hProc, me.modBaseAddr, (int)me.modBaseSize,
                        me.szExePath, me.szModule);
                    foreach (var (title, detail, risk) in anomalies)
                    {
                        findingCount++;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Anti-Dump Protection Detection",
                            Title = $"{title} in {proc.ProcessName}\\{me.szModule}",
                            Risk = risk,
                            Location = $"Prozess {proc.ProcessName} (PID {proc.Id}) — {me.szExePath}",
                            FileName = me.szModule,
                            Reason = $"Modul '{me.szModule}' zeigt Anti-Dump Schutz: {title}",
                            Detail = detail
                        });
                    }
                }
                catch { /* skip unreadable module */ }
            }
            while (Module32Next(hSnap, ref me));
        }
        finally
        {
            CloseHandle(hSnap);
            CloseHandle(hProc);
        }
    }

    private List<(string Title, string Detail, RiskLevel Risk)> AnalyzeModule(
        nint hProc, nint baseAddr, int moduleSize, string diskPath, string modName)
    {
        var results = new List<(string, string, RiskLevel)>();

        var header = new byte[0x400];
        if (!ReadProcessMemory(hProc, baseAddr, header, header.Length, out int bytesRead) || bytesRead < 64)
            return results;

        // Check 1: Erased e_magic (should be 'MZ' = 0x4D5A)
        if (header[0] == 0 && header[1] == 0)
        {
            results.Add((
                "PE-Header gelöscht (Anti-Dump)",
                $"e_magic ist 0x0000 statt 0x5A4D ('MZ') bei Basisadresse 0x{baseAddr:X} — " +
                "Packer/Loader hat den Header gezielt geloescht um Memory-Dumps zu erschweren",
                RiskLevel.High
            ));
            return results; // Can't parse further without MZ
        }

        bool hasMz = header[0] == 'M' && header[1] == 'Z';
        if (!hasMz) return results; // Not a PE, skip

        int e_lfanew = BitConverter.ToInt32(header, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 24 >= bytesRead)
            return results;

        // Check 2: Invalid PE signature
        bool hasPeSig = header[e_lfanew] == 'P' && header[e_lfanew + 1] == 'E' &&
                        header[e_lfanew + 2] == 0 && header[e_lfanew + 3] == 0;
        if (!hasPeSig)
        {
            results.Add((
                "PE-Signatur gelöscht oder verfaelscht",
                $"PE-Signatur bei Offset 0x{e_lfanew:X} ist 0x{header[e_lfanew]:X2}{header[e_lfanew+1]:X2} " +
                $"statt 0x5045 ('PE') — Anti-Dump oder Packer-Manipulation",
                RiskLevel.High
            ));
            return results;
        }

        ushort machine = BitConverter.ToUInt16(header, e_lfanew + 4);
        bool is64 = machine == 0x8664;
        bool is32 = machine == 0x14C;
        if (!is64 && !is32) return results;

        int optHdrOff = e_lfanew + 24;

        // Check 3: SizeOfImage from in-memory header vs disk file size
        int sizeOfImageOff = optHdrOff + 56;
        if (sizeOfImageOff + 4 <= bytesRead)
        {
            uint memSizeOfImage = BitConverter.ToUInt32(header, sizeOfImageOff);

            if (File.Exists(diskPath))
            {
                long diskFileSize = new FileInfo(diskPath).Length;
                // SizeOfImage is the mapped size, usually larger than file size due to page alignment.
                // Flag when SizeOfImage is dramatically smaller than disk file (truncation / stomping)
                // or when they're wildly different in suspicious ways.
                if (memSizeOfImage > 0 && diskFileSize > 0)
                {
                    double ratio = (double)memSizeOfImage / diskFileSize;
                    if (ratio < 0.1 && diskFileSize > 100 * 1024)
                    {
                        results.Add((
                            "SizeOfImage drastisch kleiner als Disk-Datei (Stomping)",
                            $"Im Speicher: SizeOfImage=0x{memSizeOfImage:X} ({memSizeOfImage/1024} KB) vs " +
                            $"Disk: {diskFileSize/1024} KB — Verhaeltnis {ratio:P0} — deutet auf " +
                            "Modul-Stomping hin (anderes PE ueber legitimes Modul geschrieben)",
                            RiskLevel.Critical
                        ));
                    }
                }
            }

            // SizeOfImage should be page-aligned (multiple of 0x1000)
            if (memSizeOfImage > 0 && (memSizeOfImage & 0xFFF) != 0)
            {
                results.Add((
                    "SizeOfImage nicht page-aligned",
                    $"SizeOfImage=0x{memSizeOfImage:X} ist nicht durch 0x1000 teilbar — " +
                    "geaenderter PE-Header oder manuell gemapptes PE (kein Windows-Loader)",
                    RiskLevel.Medium
                ));
            }
        }

        // Check 4: TimeDateStamp = 0 or 0xFFFFFFFF in loaded module (common packer trick)
        int timeDateOff = e_lfanew + 8;
        if (timeDateOff + 4 <= bytesRead)
        {
            uint ts = BitConverter.ToUInt32(header, timeDateOff);
            if (ts == 0 || ts == 0xFFFFFFFF)
            {
                results.Add((
                    "TimeDateStamp geloescht oder gefaelscht",
                    $"COFF TimeDateStamp = 0x{ts:X8} — Packer oder Loader hat den Zeitstempel " +
                    "geloescht um PE-Analyse und Signatur-Vergleich zu erschweren",
                    RiskLevel.Low
                ));
            }
        }

        // Check 5: CheckSum = 0 in a system-path adjacent module (packed/modified PE)
        int checkSumOff = optHdrOff + 64;
        if (checkSumOff + 4 <= bytesRead)
        {
            uint checksum = BitConverter.ToUInt32(header, checkSumOff);
            // Non-system modules commonly have checksum=0; only flag for driver-adjacent names
            if (checksum == 0 && (modName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) ||
                                  modName.StartsWith("ntdll", StringComparison.OrdinalIgnoreCase) ||
                                  modName.StartsWith("kernel", StringComparison.OrdinalIgnoreCase)))
            {
                results.Add((
                    "CheckSum fehlt in kritischer DLL",
                    $"OptionalHeader.CheckSum = 0 fuer '{modName}' — alle signierten Systemdateien " +
                    "haben ein gueltiges Checksum; Wert 0 deutet auf manuell gemapptes oder gepatchtes PE",
                    RiskLevel.Medium
                ));
            }
        }

        // Check 6: Subsystem is NATIVE (1) for non-driver files — cheat driver injected as DLL?
        int subsystemOff = optHdrOff + 68;
        if (subsystemOff + 2 <= bytesRead)
        {
            ushort subsystem = BitConverter.ToUInt16(header, subsystemOff);
            if (subsystem == 1 && !modName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
            {
                results.Add((
                    "NATIVE Subsystem in Nicht-Treiber DLL",
                    $"Subsystem = 1 (NATIVE) fuer '{modName}' — normale DLLs sind WINDOWS_GUI (2) oder " +
                    "WINDOWS_CUI (3); NATIVE deutet auf Treiber-Code der als DLL geladen wurde",
                    RiskLevel.High
                ));
            }
        }

        return results;
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
