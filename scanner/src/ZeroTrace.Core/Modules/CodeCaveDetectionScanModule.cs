using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects code caves in loaded module .text sections of game processes. A code cave is
/// a region of zeroed or NOP-filled bytes within a legitimate module's executable section
/// where an attacker has written shellcode (replacing the original bytes after saving them).
/// The module reads the .text section of each non-system loaded module, identifies runs of
/// identical bytes (0x00 or 0x90) longer than 32 bytes within otherwise functional code,
/// and then reads those same regions from the on-disk PE to confirm the disk has different
/// (non-zero) content — proving the in-memory bytes were overwritten.
/// </summary>
public sealed class CodeCaveDetectionScanModule : IScanModule
{
    public string Name => "Code Cave Detection";
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
        public uint th32ModuleID, th32ProcessID, GlblcntUsage, ProccntUsage;
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

    private const int MinCaveLength = 32;  // minimum zeroed/NOP run to flag
    private const int MaxReadBytes  = 512 * 1024; // 512 KB of .text section

    private static readonly string[] SkipPaths =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\winsxs\",
        @"\microsoft.net\",
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

                string pathLower = me.szExePath.ToLowerInvariant();
                bool skip = Array.Exists(SkipPaths, sp => pathLower.Contains(sp));
                if (skip) continue;

                if (!File.Exists(me.szExePath)) continue;

                try
                {
                    var caves = FindCodeCaves(hProc, me, ct);
                    foreach (var (offset, length, byteVal, diskDiffers) in caves)
                    {
                        if (!diskDiffers) continue; // cave exists on disk too = legitimate padding

                        findingCount++;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Code Cave Detection",
                            Title = $"Code Cave in {proc.ProcessName}\\{me.szModule} @+0x{offset:X}",
                            Risk = RiskLevel.High,
                            Location = $"{me.szExePath} @+0x{offset:X}",
                            FileName = me.szModule,
                            Reason = $"Lauf von {length} 0x{byteVal:X2}-Bytes im .text-Abschnitt von '{me.szModule}' — " +
                                     "nicht auf Disk vorhanden: Shellcode wurde geschrieben und dann gecleart oder Cave-Speicher ueberschrieben",
                            Detail = $"Offset in .text: +0x{offset:X} | Laenge: {length} Bytes | " +
                                     $"Byte: 0x{byteVal:X2} | Disk-Bytes unterscheiden sich (Cave-Nachweis bestaetigt)"
                        });
                    }
                }
                catch { /* skip unreadable */ }
            }
            while (Module32Next(hSnap, ref me));
        }
        finally
        {
            CloseHandle(hSnap);
            CloseHandle(hProc);
        }
    }

    private List<(uint Offset, int Length, byte ByteVal, bool DiskDiffers)> FindCodeCaves(
        nint hProc, MODULEENTRY32 me, CancellationToken ct)
    {
        var result = new List<(uint, int, byte, bool)>();

        // Read PE header to find .text section
        var header = new byte[0x400];
        if (!ReadProcessMemory(hProc, me.modBaseAddr, header, header.Length, out _))
            return result;

        if (header[0] != 'M' || header[1] != 'Z') return result;
        int e_lfanew = BitConverter.ToInt32(header, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 24 >= header.Length) return result;
        if (header[e_lfanew] != 'P' || header[e_lfanew + 1] != 'E') return result;

        int sectionCount = BitConverter.ToUInt16(header, e_lfanew + 6);
        int optHdrSize   = BitConverter.ToUInt16(header, e_lfanew + 20);
        int firstSection = e_lfanew + 24 + optHdrSize;

        // Read disk bytes for later comparison
        byte[] diskBytes;
        try { diskBytes = File.ReadAllBytes(me.szExePath); }
        catch { return result; }

        for (int i = 0; i < Math.Min(sectionCount, 16); i++)
        {
            ct.ThrowIfCancellationRequested();
            int sOff = firstSection + i * 40;
            if (sOff + 40 > header.Length) break;

            string secName = System.Text.Encoding.ASCII.GetString(header, sOff, 8).TrimEnd('\0');
            // Only check executable sections
            uint characteristics = BitConverter.ToUInt32(header, sOff + 36);
            bool isExec = (characteristics & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
            if (!isExec) continue;

            uint textRva    = BitConverter.ToUInt32(header, sOff + 12); // VirtualAddress
            uint textVirtSz = BitConverter.ToUInt32(header, sOff + 8);  // VirtualSize
            uint textRawOff = BitConverter.ToUInt32(header, sOff + 20); // PointerToRawData
            uint textRawSz  = BitConverter.ToUInt32(header, sOff + 16); // SizeOfRawData

            if (textRva == 0 || textVirtSz == 0) continue;

            int readLen = (int)Math.Min(textVirtSz, (uint)MaxReadBytes);
            var memSection = new byte[readLen];
            nint sectionVa = me.modBaseAddr + (nint)textRva;

            if (!ReadProcessMemory(hProc, sectionVa, memSection, readLen, out int memRead) || memRead < 64)
                continue;

            // Find runs of 0x00 or 0x90 (NOP) bytes
            byte[] caveCandidates = { 0x00, 0x90 };
            foreach (byte caveB in caveCandidates)
            {
                int runStart = -1;
                int runLen   = 0;

                for (int b = 0; b < memRead; b++)
                {
                    if (memSection[b] == caveB)
                    {
                        if (runStart < 0) runStart = b;
                        runLen++;
                    }
                    else
                    {
                        if (runLen >= MinCaveLength && runStart >= 0)
                        {
                            // Verify the corresponding disk bytes are different
                            uint diskOffset = textRawOff + (uint)runStart;
                            bool diskDiffers = false;

                            if (diskOffset + 4 < diskBytes.Length)
                            {
                                diskDiffers = diskBytes[diskOffset]     != caveB ||
                                              diskBytes[diskOffset + 1] != caveB ||
                                              diskBytes[diskOffset + 2] != caveB ||
                                              diskBytes[diskOffset + 3] != caveB;
                            }

                            if (diskDiffers)
                            {
                                result.Add(((uint)runStart, runLen, caveB, true));
                                if (result.Count >= 5) return result; // limit per module
                            }
                        }
                        runStart = -1;
                        runLen   = 0;
                    }
                }
            }
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
