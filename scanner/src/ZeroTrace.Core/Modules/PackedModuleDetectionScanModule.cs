using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects packed, virtualized, or obfuscated DLLs loaded in game processes by inspecting
/// PE section names. Legitimate game engine DLLs and system DLLs use standard section names
/// (.text, .data, .rdata, .bss, .rsrc, .reloc). Cheat tools and their loaders are often
/// protected with commercial packers/virtualizers to impede reverse engineering and AV
/// detection: VMProtect (.vmp0/.vmp1), UPX (UPX0/UPX1), Themida/WinLicense (.themida/.wl),
/// Enigma Protector (.enigma), Obsidium (.obsidium), PECompact (.pec), and ASPack (.aspack).
/// Packed modules loaded inside a game process indicate a cheat tool using a protector to
/// evade static analysis. Also flags modules with an abnormally low number of sections or
/// suspiciously high entropy section names.
/// </summary>
public sealed class PackedModuleDetectionScanModule : IScanModule
{
    public string Name => "Packed/Virtualized Module Detection";
    public double Weight => 0.8;
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

    // Known packer/virtualizer section name prefixes
    private static readonly (string Pattern, string Packer)[] PackerSectionNames =
    {
        ("upx", "UPX"),
        (".vmp",   "VMProtect"),
        (".themida", "Themida"),
        (".wl",    "WinLicense/Themida"),
        (".enigma", "Enigma Protector"),
        (".obsidium", "Obsidium"),
        (".pec",   "PECompact"),
        (".aspack", "ASPack"),
        (".nsp",   "NsPack"),
        (".petite", "Petite"),
        (".ksn",   "Kaspersky Self-Protect/Packed"),
        ("codvirt", "Code Virtualizer"),
        (".cvirt", "Code Virtualizer"),
        (".nap",   "NSIS/Packed"),
        (".boot",  "MPress Boot Section"),
        ("mpress", "MPRESS"),
        (".packed", "Generic Packer"),
        (".protect", "Generic Protector"),
        (".crypt",  "Encrypted Section"),
        (".loader", "Cheat Loader Section"),
    };

    // These section names are never suspicious
    private static readonly HashSet<string> KnownLegitNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc",
        ".pdata", ".xdata", ".idata", ".edata", ".tls", ".debug",
        ".CRT", ".textbss", "CODE", "DATA", "BSS", ".sxdata",
        "INIT", "PAGE", ".didat", ".gfids", ".gehcont", ".00cfg",
        ".msvcjmc", ".voltbl", ".orpc",
    };

    private static readonly string[] SystemPathPrefixes =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\windows\winsxs\",
        @"\microsoft.net\",
        @"\program files\windows ",
        @"\program files (x86)\windows ",
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
                if (findingCount >= 10) break;

                string pathLower = me.szExePath.ToLowerInvariant();
                if (Array.Exists(SystemPathPrefixes, sp => pathLower.Contains(sp))) continue;

                try
                {
                    string? packerName = AnalyzeSections(hProc, me);
                    if (packerName is null) continue;

                    findingCount++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Gepacktes/Virtualisiertes Modul in '{proc.ProcessName}': {me.szModule} ({packerName})",
                        Risk     = RiskLevel.High,
                        Location = me.szExePath,
                        FileName = me.szModule,
                        Reason   = $"Modul '{me.szModule}' in '{proc.ProcessName}' enthält {packerName}-Sektionen — " +
                                   "Cheat-Tools werden oft mit kommerziellen Packern/Virtualisierern " +
                                   "geschützt um Reverse-Engineering und AV-Erkennung zu erschweren",
                        Detail   = $"Prozess: {proc.ProcessName} (PID {proc.Id}) | " +
                                   $"Modul: {me.szModule} | Packer: {packerName} | Pfad: {me.szExePath}"
                    });
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

    private string? AnalyzeSections(nint hProc, MODULEENTRY32 me)
    {
        var header = new byte[0x400];
        if (!ReadProcessMemory(hProc, me.modBaseAddr, header, header.Length, out _)) return null;
        if (header[0] != 'M' || header[1] != 'Z') return null;

        int e_lfanew = BitConverter.ToInt32(header, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 24 >= header.Length) return null;
        if (header[e_lfanew] != 'P' || header[e_lfanew + 1] != 'E') return null;

        int sectionCount = BitConverter.ToUInt16(header, e_lfanew + 6);
        int optHdrSize   = BitConverter.ToUInt16(header, e_lfanew + 20);
        int firstSection = e_lfanew + 24 + optHdrSize;

        var detectedPackers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < Math.Min(sectionCount, 24); i++)
        {
            int sOff = firstSection + i * 40;
            if (sOff + 8 > header.Length) break;

            string secName = System.Text.Encoding.ASCII.GetString(header, sOff, 8)
                .TrimEnd('\0').ToLowerInvariant();

            // Skip empty or known-legit names
            if (string.IsNullOrEmpty(secName)) continue;
            if (KnownLegitNames.Contains(secName)) continue;

            // Check packer patterns
            foreach (var (pattern, packer) in PackerSectionNames)
            {
                if (secName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase) ||
                    secName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    detectedPackers.Add(packer);
                    break;
                }
            }
        }

        return detectedPackers.Count > 0 ? string.Join(", ", detectedPackers) : null;
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
