using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects anti-cheat service tampering and manipulation attempts.
///
/// Cheaters kill, suspend, or manipulate anti-cheat services to prevent detection:
///   1. Stopping the AC service before launching the game
///   2. Changing the service start type to Disabled
///   3. Replacing the AC service executable with a dummy/patched version
///   4. Manipulating service ACLs to deny the AC write access
///   5. Hooking the AC process to intercept its memory scans
///
/// Known anti-cheat services that should be running when their games are active:
///   - BEService / BEService_x64 (BattlEye)
///   - EasyAntiCheat_EOS / EasyAntiCheat (EAC/EOS)
///   - vgc, vgtray (Vanguard - Valorant)
///   - PnkBstrA, PnkBstrB (PunkBuster)
///   - xhunter1 (XIGNCODE)
///   - GameGuard (NProtect GameGuard)
///   - MfeAV (McAfee integration for some ACs)
///
/// Ocean and detect.ac check AC service state because:
///   - A disabled BattlEye service on a system that has BattlEye games = tampering
///   - An AC service set to Manual that was previously Automatic = suspicious change
///   - Size/hash mismatch of AC service executable vs known-good version
/// </summary>
public sealed class AnticheatServiceTamperScanModule : IScanModule
{
    public string Name => "Anti-Cheat Service Tampering Erkennung";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint OpenSCManager(string? lpMachineName, string? lpDatabaseName,
        uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint OpenService(nint hSCManager, string lpServiceName,
        uint dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceConfig(nint hService, nint lpServiceConfig,
        int cbBufSize, out int pcbBytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(nint hService, out SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(nint hSCObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    private const uint SERVICE_QUERY_CONFIG         = 0x0001;
    private const uint SERVICE_QUERY_STATUS         = 0x0004;
    private const uint SERVICE_RUNNING              = 0x00000004;
    private const uint SERVICE_STOPPED              = 0x00000001;

    private sealed record AcServiceInfo(string ServiceName, string DisplayName,
        string ExeName, int ExpectedStartType);

    // ExpectedStartType: 2=Automatic, 3=Manual, 4=Disabled
    private static readonly AcServiceInfo[] KnownAcServices =
    {
        new("BEService",         "BattlEye Service",              "BEService.exe",          2),
        new("BEService_x64",     "BattlEye Service x64",          "BEService_x64.exe",      2),
        new("EasyAntiCheat",     "Easy Anti-Cheat",               "EasyAntiCheat.exe",      3),
        new("EasyAntiCheat_EOS", "Easy Anti-Cheat (EOS)",         "EasyAntiCheat_EOS.exe",  3),
        new("vgc",               "Vanguard",                      "vgc.exe",                2),
        new("vgtray",            "Vanguard Tray",                 "vgtray.exe",             3),
        new("PnkBstrA",          "PunkBuster Service A",          "PnkBstrA.exe",           2),
        new("PnkBstrB",          "PunkBuster Service B",          "PnkBstrB.exe",           2),
        new("xhunter1",          "Wellbia XIGNCODE",              "xhunter1.sys",           2),
        new("nsvmon",            "nProtect GameGuard",            "GameGuard.exe",          3),
        new("mfevtps",           "McAfee Virus Token Protection", "mfevtps.exe",            2),
        new("FACEIT",            "FACEIT Anti-Cheat",             "faceit.exe",             2),
        new("ESEADriver3",       "ESEA Driver",                   "ESEADriver3.sys",        3),
        new("faceitsac",         "FACEIT SAC",                    "faceitsac.exe",          2),
        new("riot_games_ac",     "Riot Vanguard",                 "vanguard.exe",           2),
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanAcServiceRegistry(ctx, ct);
        CheckRunningAcProcesses(ctx, ct);
    }

    private void ScanAcServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        nint scm = OpenSCManager(null, null, SC_MANAGER_ENUMERATE_SERVICE);
        if (scm == nint.Zero) return;

        try
        {
            foreach (var svc in KnownAcServices)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                // Check registry first (faster than SCM query)
                using var regKey = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svc.ServiceName}", writable: false);

                if (regKey is null) continue; // service not installed

                int startType = (int)(regKey.GetValue("Start") ?? -1);
                string? imagePath = regKey.GetValue("ImagePath") as string ?? "";

                if (startType == 4) // Disabled
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Anti-Cheat-Dienst deaktiviert: {svc.DisplayName} ({svc.ServiceName})",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc.ServiceName}",
                        FileName = svc.ServiceName,
                        Reason   = $"Anti-Cheat-Dienst '{svc.DisplayName}' ('{svc.ServiceName}') ist " +
                                   "auf Deaktiviert gesetzt (Start=4). Ein deaktivierter AC-Dienst " +
                                   "ermöglicht das Spielen ohne den AC-Schutz. Ocean und detect.ac " +
                                   "flaggen deaktivierte AC-Dienste als primäres Manipulationsindiz.",
                        Detail   = $"Dienst: {svc.ServiceName} | Start-Typ: {startType} (4=Disabled) | " +
                                   $"ImagePath: {imagePath}"
                    });
                }
                else if (startType == 3 && svc.ExpectedStartType == 2) // Manual instead of Automatic
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Anti-Cheat-Dienst auf Manuell geändert: {svc.DisplayName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc.ServiceName}",
                        FileName = svc.ServiceName,
                        Reason   = $"Anti-Cheat-Dienst '{svc.DisplayName}' wurde von Automatisch auf " +
                                   "Manuell geändert (Start=3 statt 2). Dies verhindert den automatischen " +
                                   "Start des AC-Dienstes beim Systemstart und ist ein bekanntes Vorgehen " +
                                   "zum Umgehen von Kernel-Level-ACs (Vanguard, BattlEye).",
                        Detail   = $"Dienst: {svc.ServiceName} | Start-Typ: {startType} (erwartet: {svc.ExpectedStartType})"
                    });
                }

                // Check if the service executable exists and is not suspiciously small
                if (!string.IsNullOrEmpty(imagePath))
                {
                    string exePath = imagePath.Trim('"').Split(' ')[0];
                    if (System.IO.File.Exists(exePath))
                    {
                        var exeInfo = new System.IO.FileInfo(exePath);
                        if (exeInfo.Length < 1024) // Suspiciously small (patched/dummy)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Anti-Cheat-Dienst-EXE verdächtig klein: {svc.ServiceName}",
                                Risk     = RiskLevel.Critical,
                                Location = exePath,
                                FileName = System.IO.Path.GetFileName(exePath),
                                Reason   = $"Anti-Cheat-Dienst '{svc.ServiceName}' zeigt auf eine " +
                                           $"Executable der Größe {exeInfo.Length} Bytes — zu klein für " +
                                           "eine legitime AC-Komponente. Dies deutet auf eine Patched/Dummy-" +
                                           "Version hin, die den AC-Dienst deaktiviert ohne ihn zu entfernen.",
                                Detail   = $"Pfad: {exePath} | Größe: {exeInfo.Length} Bytes"
                            });
                        }
                    }
                }
            }
        }
        finally { CloseServiceHandle(scm); }
    }

    private void CheckRunningAcProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();
        var runningNames = new HashSet<string>(
            processes.Select(p => p.ProcessName),
            StringComparer.OrdinalIgnoreCase);

        // Check if any known AC is installed but NOT running
        foreach (var svc in KnownAcServices)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var regKey = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svc.ServiceName}", writable: false);
                if (regKey is null) continue;

                // AC service is installed — check if process is running
                string exeBaseName = System.IO.Path.GetFileNameWithoutExtension(svc.ExeName);
                bool isRunning = runningNames.Contains(exeBaseName);

                int startType = (int)(regKey.GetValue("Start") ?? -1);
                // Only flag if service is Auto-start but process is not running
                if (!isRunning && startType == 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Anti-Cheat-Prozess nicht aktiv: {svc.DisplayName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc.ServiceName}",
                        FileName = svc.ExeName,
                        Reason   = $"Anti-Cheat-Dienst '{svc.DisplayName}' ist als Automatisch " +
                                   "konfiguriert, aber Prozess '{svc.ExeName}' läuft nicht. " +
                                   "Dies kann darauf hinweisen, dass der AC-Prozess getötet wurde " +
                                   "oder der Dienst durch Manipulation nicht gestartet wurde.",
                        Detail   = $"Dienst: {svc.ServiceName} | Erwartet: {svc.ExeName} laufend | " +
                                   $"Start-Typ: {startType}"
                    });
                }
            }
            catch { }
        }
    }
}
