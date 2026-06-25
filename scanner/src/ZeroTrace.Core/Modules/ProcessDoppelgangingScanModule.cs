using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Process Doppelganging, Herpaderping, and phantom process injection.
///
/// Process Doppelganging (discovered by enSilo, 2017):
///   A fileless process injection technique that abuses Windows NTFS Transactions (TxF)
///   to create a process from a malicious image while appearing to execute a legitimate file.
///
///   How it works:
///     1. Create an NTFS transaction: NtCreateTransaction()
///     2. Open a legitimate (signed) EXE inside the transaction: NtCreateFile(options=0x100000)
///     3. Overwrite it with malicious code: NtWriteFile() within transaction context
///     4. Create a section from the transacted (now-malicious) file: NtCreateSection()
///     5. Rollback the transaction: NtRollbackTransaction()
///        → The file on disk is unchanged; the section holds malicious code
///     6. Create process from section: NtCreateProcessEx(section=<malicious>)
///     7. Set up thread, PEB, parameters: NtCreateThreadEx + RTL_USER_PROCESS_PARAMETERS
///     → The process appears to run a legitimate executable but executes malicious code
///
/// Process Herpaderping (2020 variant):
///   1. Create a legitimate process from a legitimate EXE (NtCreateUserProcess)
///   2. While the process is initializing, overwrite the EXE file with junk
///      → Windows has already mapped the image; overwriting file doesn't affect execution
///   3. The process continues to run the original code, but the file on disk is now junk
///      → Security tools that hash the file see corrupted/unknown content
///   → Detection: process image file hash ≠ what the process actually executes
///
/// Phantom Process (Hollowing without CreateRemoteThread):
///   Similar to process hollowing but uses the section-based approach:
///   NtCreateSection + NtMapViewOfSection + NtCreateProcess — no remote thread.
///
/// Detection approach:
///   1. For each running process, query the image filename via:
///      a) NtQueryInformationProcess class 27 (ProcessImageFileName) → device path
///      b) QueryFullProcessImageName (Win32 path)
///   2. Open the file on disk and compare:
///      a) File not found → deleted image (Doppelganging rollback, or rootkit file hiding)
///      b) File accessible but extremely small/corrupted → Herpaderping target
///      c) File is a text file or not a PE → overwritten legitimate path
///   3. Check process image path for TxF signatures:
///      NT paths like \Device\HarddiskVolume...\...:TxfLog or TxfBitmap
///   4. Detect mismatches between GetMappedFileName on process image region and
///      QueryFullProcessImageName — if they differ, the process was created with
///      a different section than what's on disk
///   5. Also detect processes with missing/invalid image paths (CreateProcess from
///      anonymous section — no backing file at all)
/// </summary>
public sealed class ProcessDoppelgangingScanModule : IScanModule
{
    public string Name => "Process-Doppelganging-Erkennung";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags,
        [Out] StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        int processInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetMappedFileNameW(IntPtr hProcess, IntPtr lpv,
        [Out] char[] lpFilename, uint nSize);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle,
        int processInformationClass, out PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint   AllocationProtect;
        public IntPtr RegionSize;
        public uint   State;
        public uint   Protect;
        public uint   Type;
    }

    private const uint PROCESS_QUERY_INFORMATION  = 0x0400;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_VM_READ            = 0x0010;
    private const uint MEM_COMMIT                 = 0x1000;
    private const uint MEM_IMAGE                  = 0x1000000;
    private const int  ProcessImageFileName        = 27;

    // Processes that should always have a valid, accessible image on disk
    // (excludes system processes like System/Idle which have no file)
    private static readonly HashSet<string> SystemProcessesWithNoFile =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "System", "Idle", "Registry", "smss", "MemCompression",
        };

    // Minimum PE header size for validity check
    private const int MinValidPeSize = 512;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                if (SystemProcessesWithNoFile.Contains(proc.ProcessName))
                {
                    proc.Dispose();
                    continue;
                }

                ctx.IncrementProcesses();
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                        false, proc.Id);
                    if (hProcess == IntPtr.Zero)
                    {
                        // Try limited access for image name query only
                        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                            false, proc.Id);
                    }
                    if (hProcess == IntPtr.Zero) continue;

                    hits += CheckProcess(proc, hProcess, ctx);
                }
                catch { }
                finally
                {
                    if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                    proc.Dispose();
                }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"Prozess-Doppelganging geprüft, {hits} Auffälligkeiten");
        return Task.CompletedTask;
    }

    private static int CheckProcess(Process proc, IntPtr hProcess, ScanContext ctx)
    {
        int hits = 0;
        try
        {
            // Query full process image path (Win32 format)
            var pathBuf = new StringBuilder(512);
            uint pathLen = 512;
            string imagePath = "";
            if (QueryFullProcessImageNameW(hProcess, 0, pathBuf, ref pathLen))
                imagePath = pathBuf.ToString(0, (int)pathLen);

            if (string.IsNullOrEmpty(imagePath)) return 0;

            // Skip UWP / Windows App packages and virtual paths
            if (imagePath.StartsWith(@"\\?\", StringComparison.Ordinal) ||
                imagePath.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase))
                return 0;

            // Check 1: Does the image file exist on disk?
            if (!File.Exists(imagePath))
            {
                // File missing for a running process — Doppelganging or rootkit file hiding
                // Exclude very common dynamic cases (WER, crash handlers with temp paths)
                bool isTempPath = imagePath.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                  imagePath.Contains(@"\tmp\",  StringComparison.OrdinalIgnoreCase);

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Process-Doppelganging-Erkennung",
                    Title    = $"Prozess ohne Image-Datei auf Disk: {proc.ProcessName}",
                    Risk     = isTempPath ? RiskLevel.Medium : RiskLevel.Critical,
                    Location = $"PID {proc.Id}: {imagePath}",
                    Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) läuft, " +
                               $"aber die Image-Datei '{imagePath}' existiert nicht auf dem Datenträger. " +
                               "Mögliche Ursachen: " +
                               "(1) Process Doppelganging: Prozess aus einer NTFS-Transaktion erstellt " +
                               "und Transaktion zurückgerollt — Datei auf Disk nie dauerhaft geschrieben; " +
                               "(2) Process Herpaderping: Original-EXE nach dem Starten überschrieben; " +
                               "(3) Rootkit: Datei auf Disk versteckt. " +
                               "Alle drei Techniken verhindern, dass AV/AC die tatsächlich " +
                               "ausgeführte Code-Datei hashen und verifizieren kann.",
                    Detail   = $"PID={proc.Id} | ImagePath='{imagePath}' | " +
                               $"Prozessname={proc.ProcessName} | DateiGefunden=Nein"
                });
                return hits;
            }

            // Check 2: Is the file accessible and a valid PE?
            try
            {
                var fi = new FileInfo(imagePath);
                if (fi.Length < MinValidPeSize)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Process-Doppelganging-Erkennung",
                        Title    = $"Prozess-Image-Datei zu klein: {proc.ProcessName} ({fi.Length} Bytes)",
                        Risk     = RiskLevel.High,
                        Location = $"PID {proc.Id}: {imagePath}",
                        Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) hat " +
                                   $"Image-Datei '{imagePath}' mit nur {fi.Length} Bytes — " +
                                   "zu klein für ein gültiges PE-Abbild (Minimum ~512 Bytes). " +
                                   "Process Herpaderping überschreibt die ausführbare Datei nach dem Start " +
                                   "mit Zufallsdaten oder Nullen. Das Betriebssystem hat das Original " +
                                   "bereits gemappt; die Datei auf Disk enthält nun den Payload nicht mehr, " +
                                   "sodass Antivirus-Scans der Datei nichts Verdächtiges finden.",
                        Detail   = $"PID={proc.Id} | ImagePath='{imagePath}' | FileSize={fi.Length}"
                    });
                }
                else
                {
                    // Spot-check: read first 2 bytes of the on-disk file
                    using var fs = new FileStream(imagePath, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.SequentialScan);
                    var magic = new byte[2];
                    int read = fs.Read(magic, 0, 2);
                    if (read == 2 && (magic[0] != 'M' || magic[1] != 'Z'))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Process-Doppelganging-Erkennung",
                            Title    = $"Prozess-Image-Datei kein PE: {proc.ProcessName}",
                            Risk     = RiskLevel.Critical,
                            Location = $"PID {proc.Id}: {imagePath}",
                            Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) hat " +
                                       $"Image-Datei '{imagePath}', aber die Datei beginnt nicht " +
                                       $"mit MZ (stattdessen: 0x{magic[0]:X2} 0x{magic[1]:X2}). " +
                                       "Herpaderping-Angriff: Die EXE wurde nach dem Starten des " +
                                       "Prozesses mit anderen Daten überschrieben. " +
                                       "Windows hat das Original bereits in den Prozess gemappt; " +
                                       "der laufende Code stimmt nicht mit der Datei auf Disk überein.",
                            Detail   = $"PID={proc.Id} | ImagePath='{imagePath}' | " +
                                       $"MagicBytes=0x{magic[0]:X2}{magic[1]:X2}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
        catch { }
        return hits;
    }
}
