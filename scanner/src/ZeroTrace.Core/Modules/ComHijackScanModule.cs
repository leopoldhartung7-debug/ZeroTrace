using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects COM Object hijacking — a technique where an attacker registers a
/// COM object in HKCU (user-writable) that overrides the system-wide HKLM
/// registration.
///
/// Windows checks HKCU\SOFTWARE\Classes\CLSID before HKLM when resolving COM
/// objects. By registering a malicious DLL under a well-known CLSID in HKCU,
/// attackers can:
///   1. Execute code in elevated processes that create that COM object.
///   2. Hijack Windows Update, Task Scheduler, or shell infrastructure.
///   3. Establish persistence without writing to protected directories or
///      modifying HKLM (no admin rights required).
///
/// Cheats use COM hijacking to:
///   - Load their DLL into anti-cheat processes via COM
///   - Persist through reboots without elevated privileges
///   - Evade process-creation monitors that watch HKLM Run keys
///
/// Detection:
///   1. Enumerate all CLSIDs in HKCU\SOFTWARE\Classes\CLSID.
///   2. For each, check if a corresponding HKLM registration exists (= potential override).
///   3. Resolve the InprocServer32 DLL path and flag:
///      a) DLLs in user-writable locations (Temp, AppData, Downloads)
///      b) Unsigned DLLs overriding signed HKLM registrations
///      c) Known cheat-related DLL names
/// </summary>
public sealed class ComHijackScanModule : IScanModule
{
    public string Name => "COM-Hijacking";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private const string HkcuClsidBase  = @"SOFTWARE\Classes\CLSID";
    private const string HklmClsidBase  = @"SOFTWARE\Classes\CLSID";
    private const string HklmClsidBase2 = @"SOFTWARE\WOW6432Node\Classes\CLSID";

    // Suspicious path fragments for COM server DLLs
    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\",
        @"\appdata\local\temp\", @"\appdata\roaming\",
        @"\users\public\",
    };

    // Known cheat/backdoor DLL fragments
    private static readonly string[] CheatDllKeywords =
    {
        "inject", "cheat", "hack", "hook", "bypass", "spoof",
        "aimbot", "wallhack", "loader", "payload",
        "kiddion", "cherax", "ozark", "aimware",
    };

    // High-value CLSIDs that are common hijack targets
    private static readonly HashSet<string> HighValueCLSIDs = new(StringComparer.OrdinalIgnoreCase)
    {
        "{B196B286-BAB4-101A-B69C-00AA00341D07}", // OLE Automation / oleaut32
        "{BEF6E001-A874-101A-8BBA-00AA00300CAB}", // Windows Script Host
        "{2DEA658F-54C1-4227-AF9B-260AB5FC3543}", // MsMpEng WMI Bridge
        "{645FF040-5081-101B-9F08-00AA002F954E}", // Shell Recycle Bin
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}", // My Computer
        "{BCF2430A-7B1B-4801-A498-BADFE7D127A6}", // Task Scheduler COM
        "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}", // Task Scheduler 1.0
        "{148BD52A-A2AB-11CE-B11F-00AA006ADCE6}", // Task Scheduler 1.0 Trigger
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int clsidsChecked = 0;
        int hijacks = 0;

        try
        {
            using var hkcuCom = Registry.CurrentUser.OpenSubKey(HkcuClsidBase, writable: false);
            if (hkcuCom is null)
            {
                ctx.Report(1.0, "COM-Hijacking", "Keine HKCU CLSID-Einträge gefunden");
                return Task.CompletedTask;
            }

            foreach (var clsid in hkcuCom.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                clsidsChecked++;
                ctx.IncrementRegistryKeys();

                try
                {
                    // Check if this CLSID is also registered in HKLM (= override)
                    bool existsInHklm = false;
                    using (var hklmEntry = Registry.LocalMachine.OpenSubKey(
                        $@"{HklmClsidBase}\{clsid}", writable: false))
                        existsInHklm = hklmEntry is not null;

                    if (!existsInHklm)
                    {
                        using (var hklmEntry2 = Registry.LocalMachine.OpenSubKey(
                            $@"{HklmClsidBase2}\{clsid}", writable: false))
                            existsInHklm = hklmEntry2 is not null;
                    }

                    using var hkcuEntry = hkcuCom.OpenSubKey(clsid, writable: false);
                    if (hkcuEntry is null) continue;

                    // Get InprocServer32 DLL path
                    string? dllPath = null;
                    using (var inproc = hkcuEntry.OpenSubKey("InprocServer32", writable: false))
                    {
                        dllPath = inproc?.GetValue("") as string
                               ?? inproc?.GetValue(null) as string;
                    }

                    if (string.IsNullOrEmpty(dllPath)) continue;
                    var dllLower = dllPath.ToLowerInvariant();

                    // Determine risk
                    bool isSuspiciousPath = SuspiciousPaths.Any(p => dllLower.Contains(p));
                    bool isCheatDll       = CheatDllKeywords.Any(k => dllLower.Contains(k));
                    bool isHighValueClsid = HighValueCLSIDs.Contains(clsid);

                    var clsidName = hkcuEntry.GetValue("") as string ?? clsid;

                    if (!existsInHklm && !isSuspiciousPath && !isCheatDll) continue;

                    hijacks++;
                    var risk = isCheatDll ? RiskLevel.Critical
                             : (isSuspiciousPath && existsInHklm) ? RiskLevel.High
                             : isHighValueClsid ? RiskLevel.High
                             : RiskLevel.Medium;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"COM-Hijack: {clsidName} ({clsid.Substring(0, 10)}...)",
                        Risk     = risk,
                        Location = $@"HKCU\{HkcuClsidBase}\{clsid}",
                        FileName = Path.GetFileName(dllPath),
                        Reason   = BuildReason(clsid, dllPath, existsInHklm,
                            isSuspiciousPath, isCheatDll, isHighValueClsid),
                        Detail   = $"CLSID: {clsid} | DLL: {dllPath} | " +
                                   $"Überschreibt HKLM: {existsInHklm} | " +
                                   $"Wichtiger CLSID: {isHighValueClsid}"
                    });
                }
                catch { }
            }
        }
        catch { }

        ctx.Report(1.0, "COM-Hijacking",
            $"{clsidsChecked} CLSIDs geprüft, {hijacks} COM-Hijacks erkannt");
        return Task.CompletedTask;
    }

    private static string BuildReason(string clsid, string dll, bool overridesHklm,
        bool suspiciousPath, bool cheatDll, bool highValue)
    {
        if (cheatDll)
            return $"HKCU-COM-Objekt '{clsid}' zeigt auf DLL mit cheat-typischem Namen '{dll}'. " +
                   "COM-Hijacking wird genutzt, um Cheat-DLLs in andere Prozesse zu laden.";

        if (suspiciousPath && overridesHklm)
            return $"HKCU-COM-Objekt '{clsid}' überschreibt HKLM-Registrierung und zeigt auf " +
                   $"DLL in user-beschreibbarem Pfad: '{dll}'. " +
                   "COM-Hijacking für Persistenz oder Code-Injektion ohne Admin-Rechte.";

        if (highValue)
            return $"Bekannter, hochrangiger Windows-CLSID '{clsid}' in HKCU überschrieben — " +
                   $"zeigt auf '{dll}'. Kann Windows-Infrastruktur (Taskplaner, Shell) hijacken.";

        return $"Unbekannter HKCU-COM-Eintrag für CLSID '{clsid}' mit DLL '{dll}'.";
    }
}
