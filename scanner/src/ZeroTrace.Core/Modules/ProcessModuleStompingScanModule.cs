using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects module stomping (also called module overwriting or DLL hollowing): a technique
/// where legitimate loaded DLLs are overwritten with a different PE image in the game
/// process's address space. The attacker loads a legitimate DLL (passing module list checks),
/// then overwrites its memory with their payload, leaving the module list entry intact
/// but with completely different code. Detection: compare the first 64 bytes of loaded
/// module .text sections in process memory against the actual bytes on disk at the
/// corresponding file offset. Significant divergence (>50% mismatch) flags stomping.
/// Also detects modules where in-memory ImageBase differs from the address where
/// they are actually loaded (manual mapping with forged optional header).
/// </summary>
public sealed class ProcessModuleStompingScanModule : IScanModule
{
    public string Name => "Module Stomping Detection";
    public double Weight => 1.0;
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

    private const int CompareBytes = 256; // bytes from .text section to compare
    private const double MismatchThreshold = 0.60; // >60% different bytes = stomped

    // Only check non-system modules unless the name is specifically suspicious
    private static readonly string[] SkipSystemPaths =
    {
        @"\windows\system32\ntdll.dll",    // checked by InlineHookDetectionScanModule
        @"\windows\system32\kernel32.dll",
        @"\windows\system32\kernelbase.dll",
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
                if (findingCount >= 15) break;

                string diskPath = me.szExePath;
                string pathLower = diskPath.ToLowerInvariant();

                // Skip files we can't read from disk
                if (!File.Exists(diskPath)) continue;

                // Skip known excluded paths
                bool skip = Array.Exists(SkipSystemPaths, sp => pathLower.Contains(sp));
                if (skip) continue;

                try
                {
                    var stomping = DetectStomping(hProc, me.modBaseAddr, diskPath, me.szModule);
                    if (stomping.HasValue)
                    {
                        findingCount++;
                        var (title, detail, risk) = stomping.Value;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Module Stomping Detection",
                            Title = $"{title} — {proc.ProcessName}\\{me.szModule}",
                            Risk = risk,
                            Location = $"Prozess {proc.ProcessName} (PID {proc.Id}) — {diskPath}",
                            FileName = me.szModule,
                            Reason = $"Modul '{me.szModule}' in Prozess {proc.ProcessName}: {title}",
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

    private (string Title, string Detail, RiskLevel Risk)? DetectStomping(
        nint hProc, nint baseAddr, string diskPath, string modName)
    {
        // Read PE header from process memory
        var memHeader = new byte[0x400];
        if (!ReadProcessMemory(hProc, baseAddr, memHeader, memHeader.Length, out int memRead) || memRead < 0x40)
            return null;

        if (memHeader[0] != 'M' || memHeader[1] != 'Z') return null;

        int e_lfanew = BitConverter.ToInt32(memHeader, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 0x20 >= memRead) return null;
        if (memHeader[e_lfanew] != 'P' || memHeader[e_lfanew + 1] != 'E') return null;

        ushort machine = BitConverter.ToUInt16(memHeader, e_lfanew + 4);
        bool is64 = machine == 0x8664;
        bool is32 = machine == 0x14C;
        if (!is64 && !is32) return null;

        // Check 1: ImageBase in OptionalHeader vs actual load address
        int optBase = e_lfanew + 24;
        long declaredBase;
        if (is64 && optBase + 32 <= memRead)
        {
            declaredBase = BitConverter.ToInt64(memHeader, optBase + 24);
        }
        else if (is32 && optBase + 32 <= memRead)
        {
            declaredBase = BitConverter.ToUInt32(memHeader, optBase + 28);
        }
        else return null;

        long actualBase = baseAddr.ToInt64();

        // Manual mapping often forges the ImageBase to differ significantly
        // ASLR means a small delta is OK. Flag if >4GB difference for 64-bit
        // (impossible from real ASLR) or any difference for 32-bit in unusual ranges.
        if (is64 && Math.Abs(declaredBase - actualBase) > 4L * 1024 * 1024 * 1024)
        {
            return (
                "ImageBase Anomalie (Manuelles Mapping)",
                $"OptionalHeader.ImageBase = 0x{declaredBase:X16} aber geladen bei 0x{actualBase:X16} — " +
                $"Differenz {Math.Abs(declaredBase - actualBase) / 1024 / 1024} MB, typisch fuer manuell gemappte PEs",
                RiskLevel.High
            );
        }

        // Check 2: Find the .text section and compare first CompareBytes against disk
        int sectionCount = BitConverter.ToUInt16(memHeader, e_lfanew + 6);
        int optHdrSize   = BitConverter.ToUInt16(memHeader, e_lfanew + 20);
        int firstSectionOff = e_lfanew + 24 + optHdrSize;

        nint textVa      = nint.Zero;
        uint textFileOff = 0;
        uint textRawSize = 0;

        for (int i = 0; i < sectionCount && i < 32; i++)
        {
            int sOff = firstSectionOff + i * 40;
            if (sOff + 40 > memRead) break;

            // Section name is 8 bytes ASCII, null-padded
            string secName = System.Text.Encoding.ASCII.GetString(memHeader, sOff, 8).TrimEnd('\0');
            if (secName == ".text" || secName == "CODE" || secName == ".code")
            {
                textRawSize = BitConverter.ToUInt32(memHeader, sOff + 16); // SizeOfRawData
                uint textRva = BitConverter.ToUInt32(memHeader, sOff + 12); // VirtualAddress
                textFileOff  = BitConverter.ToUInt32(memHeader, sOff + 20); // PointerToRawData
                textVa = baseAddr + (nint)textRva;
                break;
            }
        }

        if (textVa == nint.Zero || textFileOff == 0 || textRawSize < CompareBytes) return null;

        // Read from process memory at .text section
        var memText = new byte[CompareBytes];
        if (!ReadProcessMemory(hProc, textVa, memText, CompareBytes, out int memTextRead) || memTextRead < CompareBytes / 2)
            return null;

        // Read from disk at corresponding offset
        byte[] diskText;
        try
        {
            using var fs = File.Open(diskPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (textFileOff + CompareBytes > fs.Length) return null;
            fs.Seek(textFileOff, SeekOrigin.Begin);
            diskText = new byte[CompareBytes];
            int diskRead = fs.Read(diskText, 0, CompareBytes);
            if (diskRead < CompareBytes / 2) return null;
        }
        catch { return null; }

        // Count mismatching bytes
        int mismatch = 0;
        int compareLen = Math.Min(memTextRead, diskText.Length);
        for (int i = 0; i < compareLen; i++)
        {
            if (memText[i] != diskText[i]) mismatch++;
        }

        double mismatchRatio = (double)mismatch / compareLen;

        // Allow some minor differences (patches, relocations) — flag > threshold
        if (mismatchRatio > MismatchThreshold)
        {
            return (
                "Modul-Stomping erkannt (Code-Abschnitt abweichend)",
                $".text Abschnitt: {mismatch}/{compareLen} Bytes ({mismatchRatio:P0}) unterscheiden sich " +
                $"von Disk-PE — Stomping: anderes PE ueber legitimes '{modName}' geladen | " +
                $"Mem[0..3]: {memText[0]:X2} {memText[1]:X2} {memText[2]:X2} {memText[3]:X2} vs " +
                $"Disk[0..3]: {diskText[0]:X2} {diskText[1]:X2} {diskText[2]:X2} {diskText[3]:X2}",
                mismatchRatio > 0.9 ? RiskLevel.Critical : RiskLevel.High
            );
        }

        return null;
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
