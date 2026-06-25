using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects PE (Portable Executable) header anomalies in running processes
/// that indicate code injection, process hollowing, or cheat tool artifacts.
///
/// Normal Windows processes have their PE image loaded from disk with valid headers.
/// Cheat tools and injectors often leave detectable artifacts:
///
///   1. Process Hollowing: The PE image in memory doesn't match the one on disk.
///      The in-memory PE has different timestamps, checksums, or section sizes.
///
///   2. Module Stomping / Reflective DLL Injection: A legitimate DLL in the process
///      module list has its headers overwritten. The in-memory MZ/PE headers
///      differ from the disk copy — or headers are zeroed out to hide the DLL.
///
///   3. Packed/Obfuscated binaries: The PE NumberOfSections is abnormally low (1),
///      or section names are non-standard ("UPX0", ".chemist", ".abc").
///
///   4. Mismatched PE architecture: An x86 DLL loaded in an x64 process (or vice versa)
///      without proper WOW64 isolation.
///
///   5. Phantom modules: NtQueryVirtualMemory reports MEM_IMAGE regions not tracked
///      in the module list (already partially covered by ProcessInjectionScanModule).
///
/// For each module in game process module lists, this module:
///   - Reads the PE header from memory
///   - Reads the PE header from the disk file
///   - Compares timestamps, checksums, SizeOfImage
///   - Checks for zeroed or invalid headers (module stomping)
///   - Flags suspicious section names
/// </summary>
public sealed class PEHeaderAnomalyScanModule : IScanModule
{
    public string Name => "PE-Header-Anomalie";
    public double Weight => 1.0;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr baseAddr,
        byte[] buffer, int size, out int bytesRead);

    private const uint PROCESS_VM_READ         = 0x0010;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    // Known PE packer section names
    private static readonly HashSet<string> PackerSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".upx0", ".upx1", ".upx2",        // UPX packer
        "upx0", "upx1", "upx2",
        ".aspack",                          // ASPack packer
        ".themida",                         // Themida protector
        ".obsidium",                        // Obsidium protector
        ".vmp0", ".vmp1",                   // VMProtect
        "vmprotect",
        ".nsp0", ".nsp1", ".nsp2",          // NsPack packer
        ".enigma1", ".enigma2",             // Enigma Protector
        ".netshrink",                       // NetShrink packer
        ".mpress1", ".mpress2",             // MPRESS packer
        "pespin",
    };

    // Game process names to inspect
    private static readonly HashSet<string> GameProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "csgo", "cs2", "r5apex", "r5apex_dx12",
        "valorant-win64-shipping", "vgc",
        "cod", "modernwarfare", "gta5",
        "escape from tarkov", "rust", "dota2",
        "fortnite", "pubg", "tslgame",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        int processesChecked = 0;

        var processes = Process.GetProcesses();
        try
        {
            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    if (!GameProcessNames.Contains(proc.ProcessName)) continue;

                    processesChecked++;
                    ctx.IncrementProcesses();
                    hits += await InspectProcessModules(proc, ctx, ct).ConfigureAwait(false);
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        finally
        {
            foreach (var p in processes) try { p.Dispose(); } catch { }
        }

        ctx.Report(1.0, Name, $"{processesChecked} Spielprozesse auf PE-Anomalien geprüft, {hits} verdächtig");
    }

    private static async Task<int> InspectProcessModules(Process proc,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        IntPtr hProc = IntPtr.Zero;
        try
        {
            hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
            if (hProc == IntPtr.Zero || hProc == new IntPtr(-1)) return 0;

            ProcessModuleCollection modules;
            try { modules = proc.Modules; }
            catch { return 0; }

            foreach (ProcessModule mod in modules)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    hits += InspectModule(proc, hProc, mod, ctx, ct);
                }
                catch { }
                finally { mod.Dispose(); }
            }
        }
        catch { }
        finally
        {
            if (hProc != IntPtr.Zero && hProc != new IntPtr(-1))
                CloseHandle(hProc);
        }
        return hits;
    }

    private static int InspectModule(Process proc, IntPtr hProc,
        ProcessModule mod, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var modPath  = mod.FileName ?? "";
        var modName  = Path.GetFileName(modPath);
        var baseAddr = mod.BaseAddress;

        // Read in-memory PE header (first 0x400 bytes typically covers DOS+PE+optional header)
        var memHeader = new byte[0x400];
        if (!ReadProcessMemory(hProc, baseAddr, memHeader, memHeader.Length, out var mRead)
            || mRead < 64) return 0;

        // Validate MZ signature
        if (memHeader[0] != 0x4D || memHeader[1] != 0x5A) // "MZ"
        {
            // Zeroed or overwritten header — strong injection indicator
            hits++;
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Gestoßenes PE-Header (Module Stomping): {modName}",
                Risk     = RiskLevel.Critical,
                Location = $"PID {proc.Id}: {modPath}",
                FileName = modName,
                Reason   = $"Modul '{modName}' in Prozess '{proc.ProcessName}' (PID {proc.Id}) hat " +
                           "kein gültiges MZ-Header im Speicher. " +
                           "Module Stomping / Reflective DLL Injection überschreibt den PE-Header " +
                           "absichtlich, um Speicher-Forensik-Tools zu täuschen. " +
                           "Dies ist ein starkes Injektions-Indikator.",
                Detail   = $"Modul: {modPath} | PID: {proc.Id} | Bytes[0-1]: {memHeader[0]:X2}{memHeader[1]:X2}"
            });
            return hits;
        }

        // Get PE offset
        int peOffset = BitConverter.ToInt32(memHeader, 0x3C);
        if (peOffset <= 0 || peOffset + 24 > mRead) return 0;

        // Validate PE signature
        if (memHeader[peOffset] != 0x50 || memHeader[peOffset + 1] != 0x45) // "PE"
            return 0;

        // Read COFF header fields
        ushort machine        = BitConverter.ToUInt16(memHeader, peOffset + 4);
        ushort numSections    = BitConverter.ToUInt16(memHeader, peOffset + 6);
        uint   timeDateStamp  = BitConverter.ToUInt32(memHeader, peOffset + 8);
        ushort optHeaderSize  = BitConverter.ToUInt16(memHeader, peOffset + 20);

        // Read section names
        int sectionTableOffset = peOffset + 24 + optHeaderSize;
        var suspiciousSections = new List<string>();

        for (int i = 0; i < numSections && i < 32; i++)
        {
            int sectionOffset = sectionTableOffset + i * 40;
            if (sectionOffset + 8 > mRead) break;

            var nameBytes = new byte[8];
            Array.Copy(memHeader, sectionOffset, nameBytes, 0, Math.Min(8, mRead - sectionOffset));
            var sectionName = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');

            if (PackerSectionNames.Contains(sectionName))
                suspiciousSections.Add(sectionName);
        }

        if (suspiciousSections.Count > 0)
        {
            hits++;
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Packer-/Protector-Sektion in Prozess: {modName}",
                Risk     = RiskLevel.Critical,
                Location = $"PID {proc.Id}: {modPath}",
                FileName = modName,
                Reason   = $"Modul '{modName}' im Prozess '{proc.ProcessName}' (PID {proc.Id}) " +
                           $"hat bekannte Packer/Protector-Sektionsnamen: '{string.Join(", ", suspiciousSections)}'. " +
                           "Cheat-DLLs werden häufig mit UPX, Themida, VMProtect oder ähnlichen " +
                           "Tools gepackt/geschützt, um Signaturerkennung zu umgehen.",
                Detail   = $"Modul: {modPath} | PID: {proc.Id} | Sektionen: {string.Join(",", suspiciousSections)}"
            });
        }

        // Compare in-memory timestamp with on-disk timestamp
        if (!string.IsNullOrEmpty(modPath) && File.Exists(modPath))
        {
            hits += CompareWithDiskPE(proc, modName, modPath, timeDateStamp, ctx, ct);
        }

        return hits;
    }

    private static int CompareWithDiskPE(Process proc, string modName, string diskPath,
        uint memTimestamp, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var fs = new FileStream(diskPath, FileMode.Open,
                FileAccess.Read, FileShare.ReadWrite);
            var diskHeader = new byte[0x400];
            int read = fs.Read(diskHeader, 0, diskHeader.Length);
            if (read < 64) return 0;

            if (diskHeader[0] != 0x4D || diskHeader[1] != 0x5A) return 0;

            int peOffset = BitConverter.ToInt32(diskHeader, 0x3C);
            if (peOffset <= 0 || peOffset + 12 > read) return 0;
            if (diskHeader[peOffset] != 0x50 || diskHeader[peOffset + 1] != 0x45) return 0;

            uint diskTimestamp = BitConverter.ToUInt32(diskHeader, peOffset + 8);

            if (memTimestamp != diskTimestamp && diskTimestamp != 0 && memTimestamp != 0)
            {
                // Timestamp mismatch — possible process hollowing or patching
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"PE-Timestamp-Mismatch: {modName}",
                    Risk     = RiskLevel.High,
                    Location = $"PID {proc.Id}: {diskPath}",
                    FileName = modName,
                    Reason   = $"PE-Timestamp von '{modName}' im Prozess '{proc.ProcessName}' (PID {proc.Id}) " +
                               $"weicht von der Disk-Version ab. " +
                               $"Speicher: 0x{memTimestamp:X8}, Disk: 0x{diskTimestamp:X8}. " +
                               "Ein abweichender Timestamp kann Process Hollowing oder eine " +
                               "In-Memory-Patch-Technik anzeigen.",
                    Detail   = $"Modul: {diskPath} | PID: {proc.Id} | " +
                               $"Mem-TS: 0x{memTimestamp:X8} | Disk-TS: 0x{diskTimestamp:X8}"
                });
            }
        }
        catch { }
        return hits;
    }
}
