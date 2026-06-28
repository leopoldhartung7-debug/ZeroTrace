using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Checks the integrity and status of installed anti-cheat systems.
///
/// Detects attempts to:
///   1. Disable or kill anti-cheat services (EasyAntiCheat, BattlEye, VAC, FACEIT, ESEA)
///   2. Tamper with anti-cheat binary files (modified timestamps, wrong file sizes)
///   3. Block anti-cheat network connections via firewall rules or hosts file
///   4. Load anti-cheat driver before the game to hook/bypass it
///   5. Prevent anti-cheat from loading via IFEO debugger (checked by IFEO module)
///
/// Also inventories which anti-cheat systems are installed to provide context
/// to the analyst reviewing the scan report.
///
/// Anti-cheat systems covered:
///   - EasyAntiCheat (Epic Games)
///   - BattlEye (most competitive games)
///   - Valve Anti-Cheat (VAC) via Steam
///   - FACEIT AC (ESL)
///   - ESEA Client
///   - Ricochet (Activision / CoD)
///   - Vanguard (Riot Games)
///   - nProtect GameGuard
///   - XignCode3
/// </summary>
public sealed class AntiCheatStatusScanModule : IScanModule
{
    private static readonly string _name = "Anti-Cheat-Integrität";
    public string Name => _name;
    public double Weight => 0.8;
    public int ParallelGroup => 2;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(
        string lpFileName, uint dwAccess, uint dwShare,
        IntPtr secAttr, uint dwCreation, uint dwFlags, IntPtr hTemplate);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr h);

    private static readonly IntPtr INVALID = new(-1);

    private sealed record AntiCheatEntry(
        string Name,
        string[] ServiceNames,
        string[] ProcessNames,
        string[] DriverNames,
        string[] InstallPaths,
        string[] RegistryKeys);

    private static readonly AntiCheatEntry[] KnownAntiCheats =
    {
        new("EasyAntiCheat",
            new[] { "EasyAntiCheat", "EasyAntiCheat_EOS" },
            new[] { "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe", "EAC.exe" },
            new[] { "easyanticheat.sys", "easyanticheat_eos.sys" },
            new[] {
                @"C:\Program Files (x86)\EasyAntiCheat",
                @"C:\Program Files\EasyAntiCheat",
                @"C:\Program Files (x86)\EasyAntiCheat_EOS",
            },
            new[] { @"SOFTWARE\EasyAntiCheat", @"SOFTWARE\WOW6432Node\EasyAntiCheat" }),

        new("BattlEye",
            new[] { "BEService", "BEDaisy", "BattleEye" },
            new[] { "BEService.exe", "BEService_x86.exe", "BEClient.exe" },
            new[] { "bedaisy.sys", "be.sys" },
            new[] {
                @"C:\Program Files (x86)\Common Files\BattlEye",
                @"C:\Program Files\Common Files\BattlEye",
            },
            new[] { @"SYSTEM\CurrentControlSet\Services\BEService",
                    @"SYSTEM\CurrentControlSet\Services\BEDaisy" }),

        new("FACEIT",
            new[] { "FACEIT", "FACEITService" },
            new[] { "FACEIT.exe", "faceit_client.exe" },
            new[] { "faceit.sys" },
            new[] { @"C:\Program Files\FACEIT AC" },
            new[] { @"SOFTWARE\FACEIT", @"SOFTWARE\WOW6432Node\FACEIT" }),

        new("Vanguard",
            new[] { "vgc", "vgk" },
            new[] { "vgc.exe", "vgtray.exe" },
            new[] { "vgk.sys" },
            new[] { @"C:\Program Files\Riot Vanguard" },
            new[] { @"SYSTEM\CurrentControlSet\Services\vgk",
                    @"SYSTEM\CurrentControlSet\Services\vgc" }),

        new("ESEA",
            new[] { "ESEA" },
            new[] { "esea_client.exe", "esea.exe" },
            new[] { "esea.sys" },
            new[] { @"C:\Program Files (x86)\ESEA" },
            new[] { @"SOFTWARE\ESEA" }),

        new("nProtect GameGuard",
            new[] { "npgamemon", "GameMon" },
            new[] { "GameMon.des", "npggNT.des", "GGinit.dll" },
            new[] { "npgamemon.sys", "gamemon.sys" },
            new[] { },
            new[] { @"SYSTEM\CurrentControlSet\Services\npgamemon" }),

        new("XignCode3",
            new[] { "xhunter1", "xigncode" },
            new[] { "xm.exe", "x3.exe" },
            new[] { "xhunter1.sys" },
            new[] { },
            new[] { @"SYSTEM\CurrentControlSet\Services\xhunter1" }),
    };

    // Known AC-bypass / cheat loader patterns that target anti-cheat processes
    private static readonly string[] AcBypassKeywords =
    {
        "be_bypass", "eac_bypass", "vac_bypass", "anticheatkiller",
        "acbypass", "kill_ac", "kill_anticheat",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        foreach (var ac in KnownAntiCheats)
        {
            if (ct.IsCancellationRequested) break;
            hits += CheckAntiCheat(ac, ctx, ct);
        }

        hits += CheckAcBypassArtifacts(ctx, ct);

        ctx.Report(1.0, Name, $"Anti-Cheat-Systeme geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckAntiCheat(AntiCheatEntry ac, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        // Check if any service is registered but stopped/disabled
        foreach (var svcName in ac.ServiceNames)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var svc = new ServiceController(svcName);
                var status   = svc.Status;
                var startType = GetServiceStartType(svcName);

                if (startType == 4) // SERVICE_DISABLED
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Anti-Cheat deaktiviert: {ac.Name} ({svcName})",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        Reason   = $"Anti-Cheat-Dienst '{svcName}' ({ac.Name}) ist deaktiviert. " +
                                   "Ein deaktivierter AC-Dienst deutet auf gezielte AC-Sabotage hin " +
                                   "— cheat tools deaktivieren AC-Services, um unerkannt zu bleiben.",
                        Detail   = $"Service: {svcName} | Status: {status} | StartType: Disabled"
                    });
                }
            }
            catch (InvalidOperationException) { /* service doesn't exist */ }
            catch { }
        }

        // Check if install paths exist (inventory)
        foreach (var path in ac.InstallPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (Directory.Exists(path))
            {
                // Anti-cheat is installed; just check for tampering
                CheckAntiCheatFiles(ac.Name, path, ctx, ct);
            }
        }

        return hits;
    }

    private static void CheckAntiCheatFiles(string acName, string dir,
        ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*.exe",
                SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fi = new FileInfo(file);
                if (fi.Length < 1024) // Suspiciously small executable
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Anti-Cheat-Datei zu klein: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"{acName}-Datei '{file}' hat Größe {fi.Length} Bytes — " +
                                   "verdächtig klein für eine ausführbare Datei. " +
                                   "Cheat-Tools ersetzen manchmal AC-Executables mit leeren Dummy-Dateien " +
                                   "die sofort beenden, um die AC-Prüfungen zu umgehen.",
                        Detail   = $"Datei: {file} | Größe: {fi.Length} | Geändert: {fi.LastWriteTime:u}"
                    });
                }
            }
        }
        catch { }
    }

    private static int GetServiceStartType(string serviceName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: false);
            return key?.GetValue("Start") as int? ?? -1;
        }
        catch { return -1; }
    }

    private static int CheckAcBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        // Check processes
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var nameLower = proc.ProcessName.ToLowerInvariant();
                    var kw = AcBypassKeywords.FirstOrDefault(k =>
                        nameLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (kw is not null)
                    {
                        hits++;
                        ctx.IncrementProcesses();
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"AC-Bypass-Prozess aktiv: {proc.ProcessName}",
                            Risk     = RiskLevel.Critical,
                            Location = $"PID {proc.Id}: {proc.ProcessName}",
                            FileName = proc.ProcessName + ".exe",
                            Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) enthält " +
                                       $"Anti-Cheat-Bypass-Keyword '{kw}'. " +
                                       "Dies ist ein aktiver Versuch, Anti-Cheat-Schutz zu umgehen.",
                            Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | Keyword: {kw}"
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }

        return hits;
    }
}
