using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects section-based (NtMapViewOfSection) code injection: executable MEM_MAPPED regions
/// in game processes with no valid on-disk backing file. Cheats use NtCreateSection +
/// NtMapViewOfSection to share a shellcode payload between loader and target without ever
/// calling WriteProcessMemory, evading many standard injection detectors.
/// </summary>
public sealed class MmapCodeInjectionScanModule : IScanModule
{
    public string Name => "Mapped Section Code Injection";
    public double Weight => 1.0;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(
        nint hProcess, nint lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetMappedFileNameW(
        nint hProcess, nint lpv, StringBuilder lpFilename, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        nint hProcess, nint lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Module32First(nint hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll")]
    private static extern bool Module32Next(nint hSnapshot, ref MODULEENTRY32 lpme);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public nint BaseAddress;
        public nint AllocationBase;
        public uint AllocationProtect;
        public nint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

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

    private const uint MEM_COMMIT  = 0x1000;
    private const uint MEM_MAPPED  = 0x40000;
    private const uint PAGE_EXECUTE           = 0x10;
    private const uint PAGE_EXECUTE_READ      = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PROCESS_VM_READ        = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint TH32CS_SNAPMODULE      = 0x00000008;
    private const uint TH32CS_SNAPMODULE32    = 0x00000010;
    private static readonly nint InvalidHandle = new nint(-1);

    private static readonly string[] GameProcessNames =
    {
        "cs2", "csgo", "hl2", "game", "r5apex", "pubg", "rust",
        "fortnite", "valorant", "apex", "eft", "destiny", "warzone",
        "overwatch", "cod", "dota2", "tf2", "hll", "cheat", "loader", "injector"
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

        try
        {
            // Build set of known module base addresses to exclude legit mapped images
            var knownBases = CollectModuleBases(proc.Id);

            nint address = nint.Zero;
            long suspiciousTotal = 0;
            int findingCount = 0;

            while (findingCount < 30) // cap findings per process
            {
                ct.ThrowIfCancellationRequested();
                int mbiSize = Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();
                int ret = VirtualQueryEx(hProc, address, out var mbi, mbiSize);
                if (ret == 0) break;

                try
                {
                    nint next;
                    checked { next = mbi.BaseAddress + mbi.RegionSize; }
                    if (next <= address) break;
                    address = next;
                }
                catch { break; }

                if (mbi.State != MEM_COMMIT) continue;
                if (mbi.Type != MEM_MAPPED)  continue;
                if (!IsExecutable(mbi.Protect)) continue;

                // Skip if this is a known module base
                if (knownBases.Contains(mbi.AllocationBase)) continue;

                // Get mapped file name
                var sb = new StringBuilder(512);
                uint nameLen = GetMappedFileNameW(hProc, mbi.BaseAddress, sb, (uint)sb.Capacity);
                string mappedFile = nameLen > 0 ? sb.ToString() : string.Empty;

                // Anonymous mapped section (no file) with execute permissions = suspicious
                bool isAnonymous = string.IsNullOrEmpty(mappedFile);

                // File-backed but file doesn't exist on disk or path is suspicious
                bool suspiciousFile = false;
                string diskPath = string.Empty;
                if (!isAnonymous)
                {
                    diskPath = DevicePathToDrivePath(mappedFile);
                    if (!string.IsNullOrEmpty(diskPath) && !File.Exists(diskPath))
                        suspiciousFile = true;
                    else if (!string.IsNullOrEmpty(diskPath))
                    {
                        var lp = diskPath.ToLowerInvariant();
                        if (lp.Contains(@"\temp\") || lp.Contains(@"\tmp\") ||
                            lp.Contains(@"\appdata\") || lp.Contains(@"\downloads\"))
                            suspiciousFile = true;
                    }
                }

                if (!isAnonymous && !suspiciousFile) continue;

                // Read first 64 bytes to check for PE/shellcode header
                var peek = new byte[64];
                string headerNote = "";
                if (ReadProcessMemory(hProc, mbi.BaseAddress, peek, peek.Length, out int peeked) && peeked >= 2)
                {
                    if (peek[0] == 'M' && peek[1] == 'Z') headerNote = " [PE-Header MZ gefunden]";
                    else if (peek[0] == 0xFC && peek[1] == 0x48) headerNote = " [msfvenom-Signatur]";
                    else if (peek[0] == 0x4C && peek[1] == 0x8B) headerNote = " [SysWhispers-Stub-Signatur]";
                    else if (peek[0] == 0xE8 || peek[0] == 0xFF || peek[0] == 0xEB)
                        headerNote = " [Shellcode-Einstieg erkannt]";
                }

                long regionSize = mbi.RegionSize.ToInt64();
                suspiciousTotal += regionSize;
                findingCount++;

                string location = isAnonymous
                    ? $"Anonym — Prozess {proc.ProcessName} (PID {proc.Id}) @0x{mbi.BaseAddress:X}"
                    : $"{diskPath} — Prozess {proc.ProcessName} (PID {proc.Id}) @0x{mbi.BaseAddress:X}";

                string detail = isAnonymous
                    ? $"Anonyme ausfuehrbare MEM_MAPPED Region ({regionSize / 1024} KB), Schutz: 0x{mbi.Protect:X}{headerNote}"
                    : $"Datei-gemappte ausfuehrbare Region, Datei nicht auf Disk: {diskPath} ({regionSize / 1024} KB){headerNote}";

                ctx.AddFinding(new Finding
                {
                    Module = "Mapped Section Code Injection",
                    Title = isAnonymous
                        ? $"Anonyme ausfuehrbare Section in {proc.ProcessName}"
                        : $"Fehlendes Disk-Image fuer gemappte Section in {proc.ProcessName}",
                    Risk = headerNote.Length > 0 ? RiskLevel.Critical : RiskLevel.High,
                    Location = location,
                    Reason = isAnonymous
                        ? "NtMapViewOfSection-Injektion: Anonymer ausfuehrbarer Speicherbereich ohne Disk-Backing"
                        : "Section-Injektion: Ausfuehrbarer Bereich gemappt von nicht existierender Datei",
                    Detail = detail
                });
            }

            if (suspiciousTotal > 10L * 1024 * 1024)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Mapped Section Code Injection",
                    Title = $"Hohes anonymes Section-Volumen in {proc.ProcessName}",
                    Risk = RiskLevel.High,
                    Location = $"Prozess {proc.ProcessName} (PID {proc.Id})",
                    Reason = $"Insgesamt {suspiciousTotal / 1024 / 1024} MB anonymer ausfuehrbarer MEM_MAPPED Speicher",
                    Detail = "Grosses anonymes Section-Mapping kann Shellcode-Staging oder DMA-Kommunikation anzeigen"
                });
            }
        }
        finally { CloseHandle(hProc); }
    }

    private static HashSet<nint> CollectModuleBases(int pid)
    {
        var bases = new HashSet<nint>();
        nint hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)pid);
        if (hSnap == InvalidHandle) return bases;
        try
        {
            var me = new MODULEENTRY32 { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>() };
            if (Module32First(hSnap, ref me))
            {
                do { bases.Add(me.modBaseAddr); }
                while (Module32Next(hSnap, ref me));
            }
        }
        finally { CloseHandle(hSnap); }
        return bases;
    }

    private static bool IsExecutable(uint protect)
    {
        const uint mask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        return (protect & mask) != 0;
    }

    private static string DevicePathToDrivePath(string devicePath)
    {
        // \Device\HarddiskVolume3\... → C:\...
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType != DriveType.Fixed) continue;
                string letter = drive.Name.TrimEnd('\\');
                var sb = new StringBuilder(512);
                if (QueryDosDevice(letter, sb, (uint)sb.Capacity) > 0)
                {
                    string deviceName = sb.ToString();
                    if (devicePath.StartsWith(deviceName, StringComparison.OrdinalIgnoreCase))
                        return letter + devicePath[deviceName.Length..];
                }
            }
        }
        catch { }
        return devicePath;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, uint ucchMax);

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
