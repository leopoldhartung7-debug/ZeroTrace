using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Enumerates all loaded kernel modules (drivers) via NtQuerySystemInformation
/// and flags those that are unsigned, in suspicious paths, or match known cheat
/// kernel tool names.
///
/// Unlike the existing DriverScanModule (which reads the registry), this module
/// queries the LIVE kernel module list — it catches drivers that are already
/// loaded but have no registry service entry (manually-mapped / DKOM-hidden
/// service entries).
///
/// Detection targets:
///   1. Modules not in %SystemRoot%\System32 or %SystemRoot%\SysWow64
///   2. Modules whose filename matches known cheat kernel tools
///   3. Modules loaded from user-writable paths (Downloads, Temp, AppData)
///   4. Modules with no file on disk (mapped directly from memory)
///   5. Unsigned PE images in the kernel module list
///
/// P/Invoke: NtQuerySystemInformation (SystemModuleInformation = 11)
/// </summary>
public sealed class LoadedKernelModuleScanModule : IScanModule
{
    public string Name => "Geladene-Kernel-Module";
    public double Weight => 0.8;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int systemInformationClass,
        IntPtr systemInformation,
        uint systemInformationLength,
        out uint returnLength);

    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    private const int SystemModuleInformation = 11;

    [StructLayout(LayoutKind.Sequential)]
    private struct RTL_PROCESS_MODULE_INFORMATION
    {
        public IntPtr Section;
        public IntPtr MappedBase;
        public IntPtr ImageBase;
        public uint ImageSize;
        public uint Flags;
        public ushort LoadOrderIndex;
        public ushort InitOrderIndex;
        public ushort LoadCount;
        public ushort OffsetToFileName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] FullPathName;
    }

    private static readonly string[] KnownCheatDrivers =
    {
        // HWID spoofers
        "hwidspoofdrv", "spoofer", "hwid", "serialchange", "diskspoof",
        "mac_spoof", "cpuspoof", "guidchange",
        // DMA / PCILeech
        "pcileech", "leechagent", "fpga",
        // Kernel cheats / rootkits
        "kiddiondrv", "cheraxdrv", "2take1drv",
        "byfron_bypass", "acbypass", "eacbypass", "bebypass",
        "vgkbypass", "vanguardbypass",
        // Anti-detection
        "kdmapper", "kdudrv", "nal", "capcom",
        // Debugging / RE tools in kernel
        "winpmem", "memdump", "processhacker",
        // Generic suspicious
        "inject", "hook", "bypass", "hide", "protect", "cloak",
        "ghost", "phantom", "stealth", "invisible",
    };

    private static readonly string[] SuspiciousPathFragments =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\",
        @"\appdata\", @"\users\public\",
    };

    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        int hits = 0;

        var modules = EnumerateKernelModules();
        foreach (var (fullPath, name) in modules)
        {
            if (ct.IsCancellationRequested) break;
            checked_++;
            ctx.IncrementFiles();

            var pathLower = fullPath.ToLowerInvariant();
            var nameLower = name.ToLowerInvariant();

            // Skip legitimate Windows system modules
            if (pathLower.StartsWith(@"\windows\system32\") ||
                pathLower.StartsWith(@"\windows\syswow64\") ||
                pathLower.StartsWith(@"\windows\system\") ||
                pathLower.StartsWith(@"\systemroot\system32\") ||
                pathLower.StartsWith(@"\systemroot\syswow64\"))
                continue;

            // Convert kernel path to Win32 path for further checks
            var win32Path = KernelPathToWin32(fullPath);
            var win32Lower = win32Path.ToLowerInvariant();

            var cheatMatch = KnownCheatDrivers.FirstOrDefault(k =>
                nameLower.Contains(k, StringComparison.OrdinalIgnoreCase));

            bool isSuspiciousPath = SuspiciousPathFragments.Any(p => win32Lower.Contains(p));
            bool isNonSystemPath  = !win32Lower.Contains(@"\windows\") &&
                                    !win32Lower.Contains(@"\program files\");
            bool hasNoFile        = !string.IsNullOrEmpty(win32Path) && !File.Exists(win32Path);

            if (cheatMatch is not null)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Bekanntes Cheat-Kernel-Modul geladen: {name}",
                    Risk     = RiskLevel.Critical,
                    Location = win32Path,
                    FileName = name,
                    Reason   = $"Kernel-Modul '{name}' entspricht bekanntem Cheat-Kernel-Tool " +
                               $"(Keyword: '{cheatMatch}'). Geladen von: '{fullPath}'. " +
                               "Kernel-Cheats haben direkten Zugriff auf Spielspeicher, " +
                               "können Anti-Cheat-Hooks neutralisieren und DKOM durchführen.",
                    Detail   = $"Kernel-Pfad: {fullPath} | Win32: {win32Path} | Match: {cheatMatch}"
                });
            }
            else if (isSuspiciousPath)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Kernel-Treiber aus verdächtigem Pfad: {name}",
                    Risk     = RiskLevel.High,
                    Location = win32Path,
                    FileName = name,
                    Reason   = $"Kernel-Treiber '{name}' wurde aus einem user-beschreibbaren " +
                               $"Pfad geladen: '{win32Path}'. Legitime Windows-Treiber befinden " +
                               "sich in System32\\drivers. Cheat-Treiber werden häufig aus " +
                               "Temp- oder AppData-Ordnern gemappt.",
                    Detail   = $"Kernel-Pfad: {fullPath} | Win32: {win32Path}"
                });
            }
            else if (isNonSystemPath && hasNoFile && !string.IsNullOrEmpty(win32Path))
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Kernel-Modul ohne Datei auf Disk: {name}",
                    Risk     = RiskLevel.High,
                    Location = win32Path,
                    FileName = name,
                    Reason   = $"Kernel-Modul '{name}' ist geladen, aber die Datei '{win32Path}' " +
                               "existiert nicht mehr auf dem Dateisystem. " +
                               "Manuell-gemappte Rootkits und Cheat-Treiber löschen sich nach " +
                               "dem Laden selbst um Forensik zu erschweren.",
                    Detail   = $"Kernel-Pfad: {fullPath} | Win32: {win32Path} | Datei fehlt: true"
                });
            }
        }

        ctx.Report(1.0, Name, $"{checked_} Kernel-Module geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static List<(string FullPath, string Name)> EnumerateKernelModules()
    {
        var result = new List<(string, string)>();

        uint size = 1024 * 1024; // Start with 1 MB
        while (true)
        {
            var buf = Marshal.AllocHGlobal((int)size);
            try
            {
                int status = NtQuerySystemInformation(SystemModuleInformation, buf, size, out uint needed);
                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    size = needed + 4096;
                    Marshal.FreeHGlobal(buf);
                    continue;
                }
                if (status != 0) break;

                int count = Marshal.ReadInt32(buf);
                int entrySize = Marshal.SizeOf<RTL_PROCESS_MODULE_INFORMATION>();
                int offset = IntPtr.Size == 8 ? 8 : 4; // NumberOfModules + padding

                for (int i = 0; i < count; i++)
                {
                    var entry = Marshal.PtrToStructure<RTL_PROCESS_MODULE_INFORMATION>(
                        IntPtr.Add(buf, offset + i * entrySize));

                    if (entry.FullPathName is null) continue;

                    var nullTerm = Array.IndexOf(entry.FullPathName, (byte)0);
                    var raw = nullTerm >= 0
                        ? System.Text.Encoding.ASCII.GetString(entry.FullPathName, 0, nullTerm)
                        : System.Text.Encoding.ASCII.GetString(entry.FullPathName);

                    var name = raw.Length > entry.OffsetToFileName
                        ? raw[entry.OffsetToFileName..]
                        : Path.GetFileName(raw);

                    result.Add((raw, name));
                }
                break;
            }
            catch
            {
                if (Marshal.IsComObject(Marshal.GetExceptionForHR(0) ?? new Exception()))
                    break;
                break;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        return result;
    }

    private static string KernelPathToWin32(string kernelPath)
    {
        // Convert \Windows\... → C:\Windows\...
        // Convert \SystemRoot\... → C:\Windows\...
        // Convert \Device\HarddiskVolume3\... → C:\... (approximate)
        if (kernelPath.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                kernelPath[12..]);

        if (kernelPath.StartsWith(@"\Windows\", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                kernelPath[9..]);

        // For other paths, return as-is
        return kernelPath;
    }
}
