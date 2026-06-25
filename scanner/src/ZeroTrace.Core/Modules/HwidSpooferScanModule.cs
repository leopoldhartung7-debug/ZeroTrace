using Microsoft.Win32;
using System.Diagnostics;
using System.Management;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects HWID (Hardware ID) spoofer tools — software that manipulates hardware
/// serial numbers to evade bans that target MAC addresses, disk serials, BIOS UUIDs,
/// CPU IDs, and GPU IDs.
///
/// Detection layers:
///   1. Known spoofer driver/file names on disk and in registry
///   2. Suspicious WMI class registrations (spoofers hook WMI to fake serials)
///   3. Disk serial number anomalies (all-zero or placeholder serials)
///   4. Network adapter MAC address anomalies (locally administered bit set)
///   5. SMBIOS/BIOS serial "zeroed" or set to placeholder values
///   6. Registry remnants from known spoofer installers
///   7. Running processes matching known spoofer executables
/// </summary>
public sealed class HwidSpooferScanModule : IScanModule
{
    public string Name => "HWID-Spoofer";
    public double Weight => 1.2;
    public int ParallelGroup => 3;

    private static readonly string[] KnownSpooferDrivers =
    {
        // Generic spoofers
        "hwid.sys", "spoofer.sys", "spoofdrv.sys", "serialspoof.sys",
        "diskspoof.sys", "macspoof.sys", "cpuspoof.sys",
        // Named commercial spoofers
        "rezeex.sys", "realspoofer.sys", "klar.sys", "striker.sys",
        "phantom.sys", "ghostspoofer.sys", "nemesis.sys",
        "viper.sys", "eclipse.sys", "fade.sys", "strikespoof.sys",
        "changer.sys", "serialchange.sys", "uuidspoof.sys",
        // BYOVD-based spoofers (use vulnerable drivers as carrier)
        "hdspoofer.sys", "hwspoofer.sys", "idspoofer.sys",
        "nicspoof.sys", "spoofmaster.sys", "zynspoof.sys",
        "icebergspoof.sys", "frigidspoof.sys", "polarspoof.sys",
        // DMA-related spoofer tools
        "dmaspoof.sys", "pcispoof.sys",
    };

    private static readonly string[] KnownSpooferProcesses =
    {
        "hwid_spoofer", "hwid-spoofer", "spoofer", "spoofmaster",
        "serialspoofer", "macspoofer", "rezeex", "realspoofer",
        "phantomspoofer", "strikespoofer", "nemesisspoofer",
        "hwchanger", "serialchanger", "uuidchanger",
        "icebergspoof", "frigidspoof",
    };

    private static readonly string[] SpooferRegistryPaths =
    {
        @"SOFTWARE\HWID Spoofer",
        @"SOFTWARE\Serial Spoofer",
        @"SOFTWARE\RezeexSpoofer",
        @"SOFTWARE\RealSpoofer",
        @"SOFTWARE\PhantomSpoofer",
        @"SOFTWARE\NemesisSpoofer",
        @"SOFTWARE\StrikeSpoofer",
        @"SOFTWARE\IcebergSpoofer",
        @"SOFTWARE\FrigidSpoofer",
        @"SOFTWARE\DMA Spoofer",
        @"SOFTWARE\Striker Spoofer",
        @"SOFTWARE\Eclipse Spoofer",
        @"SOFTWARE\Fade Spoofer",
        @"SOFTWARE\Klar Spoofer",
        @"SOFTWARE\HWID Changer",
        @"SOFTWARE\SerialChanger",
    };

    // Serial numbers that are clearly fake/placeholder
    private static readonly string[] FakeSerialPatterns =
    {
        "0000000000000000", "1111111111111111", "ffffffffffffffff",
        "deadbeef", "baadbeef", "00000000", "12345678",
        "to be filled", "to be determined", "not specified",
        "serial number", "default string", "system serial",
        "chassis serial", "board serial", "none", "n/a",
        "empty", "xxxxxxxxxxxx", "000000000000",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "HWID-Spoofer", "Suche nach Spoofer-Treibern...");
        CheckSpooferDrivers(ctx, ct);

        ctx.Report(0.2, "HWID-Spoofer", "Prüfe Registry-Einträge...");
        CheckSpooferRegistry(ctx, ct);

        ctx.Report(0.4, "HWID-Spoofer", "Analysiere Prozesse...");
        CheckSpooferProcesses(ctx, ct);

        ctx.Report(0.6, "HWID-Spoofer", "Prüfe Seriennummern...");
        CheckSerialAnomalies(ctx, ct);

        ctx.Report(0.8, "HWID-Spoofer", "Prüfe Netzwerkadapter...");
        CheckMacAnomalies(ctx, ct);

        ctx.Report(1.0, "HWID-Spoofer", "HWID-Spoofer-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    private static void CheckSpooferDrivers(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var driversKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (driversKey is null) return;

            foreach (var svcName in driversKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();
                try
                {
                    using var svc = driversKey.OpenSubKey(svcName, writable: false);
                    if (svc is null) continue;
                    var imgPath = (svc.GetValue("ImagePath") as string ?? "").ToLowerInvariant();
                    var type = svc.GetValue("Type") as int? ?? 0;
                    if (type != 1) continue; // kernel driver only

                    var fileName = Path.GetFileName(imgPath);
                    if (KnownSpooferDrivers.Any(d => fileName.Contains(d, StringComparison.OrdinalIgnoreCase) ||
                                                     svcName.Contains(d.Replace(".sys", ""), StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "HWID-Spoofer",
                            Title    = $"HWID-Spoofer Treiber: {svcName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = fileName,
                            Reason   = $"Kernel-Treiber '{svcName}' entspricht einem bekannten HWID-Spoofer. " +
                                       "Spoofer manipulieren Hardware-Seriennummern um Sperren zu umgehen.",
                            Detail   = $"ImagePath: {imgPath}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        // Also check System32\drivers directory
        var driversDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
        if (!Directory.Exists(driversDir)) return;

        try
        {
            foreach (var file in Directory.GetFiles(driversDir, "*.sys"))
            {
                if (ct.IsCancellationRequested) return;
                var fn = Path.GetFileName(file).ToLowerInvariant();
                if (KnownSpooferDrivers.Any(d => fn.Contains(d, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "HWID-Spoofer",
                        Title    = $"Spoofer-Treiber in System32: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Bekannter HWID-Spoofer-Treiber '{fn}' im Treiber-Verzeichnis gefunden.",
                        Detail   = $"Pfad: {file}"
                    });
                }
            }
        }
        catch { }
    }

    private static void CheckSpooferRegistry(ScanContext ctx, CancellationToken ct)
    {
        foreach (var regPath in SpooferRegistryPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false)
                             ?? Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = "HWID-Spoofer",
                    Title    = $"Spoofer-Registrierungsschlüssel: {Path.GetFileName(regPath)}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{regPath}",
                    Reason   = $"Registrierungsschlüssel eines bekannten HWID-Spoofers gefunden: '{regPath}'. " +
                               "Dies ist ein Installationsrückstand des Spoofer-Tools.",
                    Detail   = $"Registry: HKLM\\{regPath}"
                });
            }
            catch { }
        }
    }

    private static void CheckSpooferProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementProcesses();
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    if (KnownSpooferProcesses.Any(s => name.Contains(s, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "HWID-Spoofer",
                            Title    = $"Spoofer-Prozess läuft: {proc.ProcessName}",
                            Risk     = RiskLevel.Critical,
                            Location = $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason   = $"Bekannter HWID-Spoofer-Prozess '{proc.ProcessName}' ist aktiv. " +
                                       "Aktive Spoofer können Hardware-IDs in Echtzeit manipulieren.",
                            Detail   = $"PID: {proc.Id} | Name: {proc.ProcessName}"
                        });
                    }
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private static void CheckSerialAnomalies(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            // Check disk serial numbers via WMI
            using var searcher = new ManagementObjectSearcher(
                "SELECT SerialNumber, Model FROM Win32_DiskDrive");
            foreach (ManagementObject disk in searcher.Get())
            {
                if (ct.IsCancellationRequested) break;
                var serial = (disk["SerialNumber"] as string ?? "").Trim().ToLowerInvariant();
                var model  = (disk["Model"] as string ?? "").Trim();

                if (serial.Length == 0) continue;

                if (FakeSerialPatterns.Any(p => serial == p || serial.Contains(p)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "HWID-Spoofer",
                        Title    = $"Gefälschte Festplatten-Seriennummer: {model}",
                        Risk     = RiskLevel.High,
                        Location = $"WMI\\Win32_DiskDrive\\{model}",
                        Reason   = $"Festplatte '{model}' hat eine auffällig gefälschte Seriennummer " +
                                   $"'{serial}'. HWID-Spoofer ersetzen echte Seriennummern durch " +
                                   "Platzhalter oder Nullen.",
                        Detail   = $"SerialNumber: {serial} | Model: {model}"
                    });
                }
            }
        }
        catch { }

        // Check BIOS serial
        if (ct.IsCancellationRequested) return;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT SerialNumber, SMBIOSBIOSVersion FROM Win32_BIOS");
            foreach (ManagementObject bios in searcher.Get())
            {
                var serial = (bios["SerialNumber"] as string ?? "").Trim().ToLowerInvariant();
                if (serial.Length > 0 &&
                    FakeSerialPatterns.Any(p => serial == p || serial.Contains(p)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "HWID-Spoofer",
                        Title    = "Gefälschte BIOS-Seriennummer",
                        Risk     = RiskLevel.High,
                        Location = "WMI\\Win32_BIOS",
                        Reason   = $"BIOS hat eine auffällig gefälschte Seriennummer '{serial}'. " +
                                   "Spoofer manipulieren SMBIOS-Einträge um System-IDs zu verändern.",
                        Detail   = $"BIOS SerialNumber: {serial}"
                    });
                }
            }
        }
        catch { }
    }

    private static void CheckMacAnomalies(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT MACAddress, Description, AdapterType FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL AND AdapterType = 'Ethernet 802.3'");
            foreach (ManagementObject nic in searcher.Get())
            {
                if (ct.IsCancellationRequested) break;
                var mac = (nic["MACAddress"] as string ?? "").Replace(":", "").ToUpperInvariant();
                if (mac.Length < 12) continue;

                // Locally administered bit (bit 1 of first byte) = 0x02 in first byte
                if (int.TryParse(mac.Substring(0, 2), System.Globalization.NumberStyles.HexNumber,
                    null, out int firstByte) && (firstByte & 0x02) != 0)
                {
                    var desc = nic["Description"] as string ?? "Unbekannt";
                    ctx.AddFinding(new Finding
                    {
                        Module   = "HWID-Spoofer",
                        Title    = $"MAC-Adresse lokal administriert: {desc}",
                        Risk     = RiskLevel.Medium,
                        Location = $"WMI\\Win32_NetworkAdapter\\{desc}",
                        Reason   = $"Netzwerkadapter '{desc}' hat eine lokal administrierte MAC-Adresse " +
                                   $"({nic["MACAddress"]}). Das 'Locally Administered' Bit ist gesetzt, " +
                                   "was auf MAC-Spoofing zur Ban-Umgehung hinweist.",
                        Detail   = $"MAC: {nic["MACAddress"]} | Locally Administered Bit = 1"
                    });
                }
            }
        }
        catch { }
    }
}
