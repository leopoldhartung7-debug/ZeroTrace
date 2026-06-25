using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects tampering with Protected Process Light (PPL) and Protected Processes.
///
/// Windows Protected Processes are designed to resist tampering from even admin/SYSTEM:
///
///   Protected Process (PP): Windows 8+, originally for DRM (Media Foundation)
///   Protected Process Light (PPL): Windows 8.1+, for security-critical processes
///     - PPL-Antimalware: used by AV/EDR engines (MsMpEng, MBAMService)
///     - PPL-Windows: Windows components (smss, csrss, wininit)
///     - PPL-WindowsTcb: LSA, LSAISO (Isolated LSA), SvcHost critical services
///
/// Cheats attack protected processes to:
///   1. Bypass anti-cheat engines that run as PPL (BattlEye, EAC run as PPL)
///   2. Dump LSASS (credential theft requires defeating PPL-Antimalware)
///   3. Inject into protected game processes to bypass cheat detection
///
/// PPL downgrade attacks:
///   A. PPLKiller / PPLDump: exploit kernel vulnerability to remove PPL from EPROCESS
///   B. BYOVD: use vulnerable driver with kernel access to clear PS_PROTECTED_SIGNER
///   C. Mimidrv: Mimikatz kernel driver removes PPL from lsass.exe
///   D. EDRSandBlast: uses vulnerable driver to clear PP/PPL callbacks (ELAM, PsLoadImage)
///
/// Detection:
///   1. Enumerate all processes, check their protection level via NtQuerySystemInformation
///   2. Flag expected-PPL processes that are NOT protected (PPL removed!)
///   3. Flag processes with unexpected PPL level (lower than expected)
///   4. Check for known PPL-killer tools in running processes or recent file activity
/// </summary>
public sealed class ProtectedProcessScanModule : IScanModule
{
    public string Name => "Geschützte-Prozesse-Analyse";
    public double Weight => 1.0;
    public int ParallelGroup => 2;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int SystemInformationClass,
        IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle,
        int processInformationClass, IntPtr processInformation,
        uint processInformationLength, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    // ProcessProtectionInformation = 61
    private const int ProcessProtectionInformation = 61;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessProtectionInformationStruct
    {
        public byte Type;   // PS_PROTECTED_TYPE
        public byte Audit;
        public byte Signer; // PS_PROTECTED_SIGNER
    }

    // PS_PROTECTED_TYPE values
    private enum ProtectionType : byte
    {
        PsProtectedTypeNone = 0,
        PsProtectedTypeProtectedLight = 1,
        PsProtectedTypeProtected = 2
    }

    // PS_PROTECTED_SIGNER values
    private enum ProtectionSigner : byte
    {
        PsProtectedSignerNone = 0,
        PsProtectedSignerAuthenticode = 1,
        PsProtectedSignerCodeGen = 2,
        PsProtectedSignerAntimalware = 3,
        PsProtectedSignerLsa = 4,
        PsProtectedSignerWindows = 5,
        PsProtectedSignerWinTcb = 6,
        PsProtectedSignerWinSystem = 7,
        PsProtectedSignerApp = 8,
    }

    // Processes that MUST be PPL and their expected minimum protection
    private static readonly Dictionary<string, (ProtectionType MinType, ProtectionSigner MinSigner)>
        RequiredProtectionLevels = new(StringComparer.OrdinalIgnoreCase)
    {
        ["lsass.exe"]     = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerLsa),
        ["MsMpEng.exe"]   = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerAntimalware),
        ["MpDefenderCoreService.exe"] = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerAntimalware),
        ["NisSrv.exe"]    = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerAntimalware),
        ["csrss.exe"]     = (ProtectionType.PsProtectedTypeProtected, ProtectionSigner.PsProtectedSignerWinSystem),
        ["wininit.exe"]   = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerWindows),
        ["smss.exe"]      = (ProtectionType.PsProtectedTypeProtected, ProtectionSigner.PsProtectedSignerWinSystem),
    };

    // Anti-cheat processes that use PPL
    private static readonly Dictionary<string, (ProtectionType MinType, ProtectionSigner MinSigner)>
        AntiCheatProtectedProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        ["EasyAntiCheat.exe"] = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerAntimalware),
        ["BEService.exe"]     = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerAntimalware),
        ["vgc.exe"]           = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerAntimalware),
        ["vgtray.exe"]        = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerAntimalware),
        ["faceit.exe"]        = (ProtectionType.PsProtectedTypeProtectedLight, ProtectionSigner.PsProtectedSignerAntimalware),
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckProtectedProcessLevels(ctx, ct);
        hits += CheckPplKillerArtifacts(ctx, ct);

        ctx.Report(1.0, Name, $"PPL-Schutzlevel geprüft, {hits} Probleme");
        return Task.CompletedTask;
    }

    private static int CheckProtectedProcessLevels(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var allExpected = new Dictionary<string, (ProtectionType, ProtectionSigner)>(
            RequiredProtectionLevels, StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in AntiCheatProtectedProcesses)
            allExpected[kvp.Key] = kvp.Value;

        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementProcesses();
                string procExe = proc.ProcessName + ".exe";

                if (!allExpected.TryGetValue(procExe, out var expected))
                {
                    proc.Dispose();
                    continue;
                }

                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Id);
                    if (hProcess == IntPtr.Zero) continue;

                    var protInfo = new ProcessProtectionInformationStruct();
                    var buf = Marshal.AllocHGlobal(Marshal.SizeOf<ProcessProtectionInformationStruct>());
                    try
                    {
                        int status = NtQueryInformationProcess(hProcess,
                            ProcessProtectionInformation, buf,
                            (uint)Marshal.SizeOf<ProcessProtectionInformationStruct>(),
                            out _);

                        if (status == 0)
                        {
                            protInfo = Marshal.PtrToStructure<ProcessProtectionInformationStruct>(buf);
                        }
                    }
                    finally { Marshal.FreeHGlobal(buf); }

                    var actualType = (ProtectionType)protInfo.Type;
                    var actualSigner = (ProtectionSigner)protInfo.Signer;

                    bool isProtected = actualType != ProtectionType.PsProtectedTypeNone;
                    bool meetsMinimum = actualType >= expected.Item1;

                    if (!isProtected)
                    {
                        bool isAc = AntiCheatProtectedProcesses.ContainsKey(procExe);
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Geschützte-Prozesse-Analyse",
                            Title    = $"PPL-Schutz fehlt: {procExe} (PID {proc.Id})",
                            Risk     = isAc ? RiskLevel.Critical : RiskLevel.High,
                            Location = $"PID {proc.Id}: {procExe}",
                            Reason   = $"Prozess '{procExe}' (PID {proc.Id}) sollte als " +
                                       $"Protected Process Light laufen " +
                                       $"(erwartet: {expected.Item1}/{expected.Item2}), " +
                                       "ist aber ungeschützt (Type=None). " +
                                       "PPL-Killer-Tools (PPLKiller, EDRSandBlast, Mimidrv) " +
                                       "entfernen den PPL-Schutz über Kernel-Exploits, " +
                                       "um Anti-Cheat-Prozesse zu manipulieren oder LSASS zu dumpen.",
                            Detail   = $"Prozess: {procExe} | PID: {proc.Id} | " +
                                       $"Aktuell: Type={actualType} Signer={actualSigner} | " +
                                       $"Erwartet: Type>={expected.Item1}"
                        });
                    }
                    else if (!meetsMinimum)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Geschützte-Prozesse-Analyse",
                            Title    = $"PPL-Schutz degradiert: {procExe} (PID {proc.Id})",
                            Risk     = RiskLevel.Critical,
                            Location = $"PID {proc.Id}: {procExe}",
                            Reason   = $"PPL-Schutz von '{procExe}' ist niedriger als erwartet: " +
                                       $"Aktuell {actualType}/{actualSigner}, " +
                                       $"erwartet mindestens {expected.Item1}/{expected.Item2}. " +
                                       "Herabstufung des PPL-Levels deutet auf einen " +
                                       "aktiven Kernel-Level PPL-Bypass-Angriff hin.",
                            Detail   = $"Prozess: {procExe} | PID: {proc.Id} | " +
                                       $"Aktuell: {actualType}/{actualSigner} | " +
                                       $"Erwartet: >= {expected.Item1}/{expected.Item2}"
                        });
                    }
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
        return hits;
    }

    private static int CheckPplKillerArtifacts(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        // Known PPL-killer tool process names and file names
        var pplKillerNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "PPLKiller.exe", "PPLdump.exe", "PPLFault.exe",
            "mimidrv.sys", "mimidrv.exe",
            "EDRSandblast.exe", "EDRSandBlast.exe",
            "gdrv.sys", "gdrv2.sys",
            "rtcore64.sys", "RTCore64.sys",
        };

        // Check running processes
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                string procExe = proc.ProcessName + ".exe";
                if (pplKillerNames.Contains(procExe))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Geschützte-Prozesse-Analyse",
                        Title    = $"PPL-Killer-Tool läuft: {procExe}",
                        Risk     = RiskLevel.Critical,
                        Location = $"PID {proc.Id}: {procExe}",
                        Reason   = $"'{procExe}' ist ein bekanntes PPL-Killer-Tool. " +
                                   "Diese Tools nutzen Kernel-Exploits oder verwundbare Treiber, " +
                                   "um den Protected Process Light-Schutz von Windows-Prozessen " +
                                   "zu entfernen — Standard-Vorbereitung für LSASS-Dump und " +
                                   "Anti-Cheat-Deaktivierung.",
                        Detail   = $"PPL-Killer Prozess: {procExe} | PID: {proc.Id}"
                    });
                }
                proc.Dispose();
            }
        }
        catch { }

        // Check temp/download dirs for PPL killer files
        var scanPaths = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var dir in scanPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    if (pplKillerNames.Contains(fname))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Geschützte-Prozesse-Analyse",
                            Title    = $"PPL-Killer-Datei gefunden: {fname}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fname,
                            Reason   = $"PPL-Killer-Werkzeug '{fname}' in '{dir}' gefunden. " +
                                       "PPL-Killer werden für Kernel-Level-Angriffe auf " +
                                       "Anti-Cheat-Prozesse und LSASS-Dumps eingesetzt.",
                            Detail   = $"Datei: {file}"
                        });
                    }
                }
            }
            catch { }
        }

        return hits;
    }
}
