using System.Management;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// DMA / hardware-risk HEURISTICS. A DMA cheat runs on separate hardware on the
/// PCIe bus and reads memory directly, bypassing Windows — so there is usually
/// no process/file/driver on this PC to detect. This module therefore produces
/// HINTS, never proof:
///   1) the platform DMA defenses (Kernel DMA Protection / IOMMU-VT-d) state;
///   2) Windows service/driver registry artifacts for known DMA software tools
///      (PCILeech, LeechCore, MemProcFS) and hardware chip drivers (FT600/FT601,
///      Cypress FX3) — high-confidence if the tool name matches, medium if it is
///      a DMA-capable chip driver that could also belong to legit hardware;
///   3) a read-only inventory of PCIe/USB/Thunderbolt devices, first checked
///      against known DMA-board USB VID/PID pairs (FT601, FX3 dev kits), then
///      against generic FPGA/capture-card name fragments.
/// Legitimate capture cards look identical to DMA boards, so every device hit
/// is reported as review-only, not as proof. Nothing is changed.
/// </summary>
public sealed class DmaRiskScanModule : IScanModule
{
    public string Name => "DMA / Hardware (Hinweis)";
    public double Weight => 0.4;
    public int ParallelGroup => 2;

    // Name/vendor fragments over-represented in DMA-board builds or capture hardware.
    private static readonly string[] SuspectFragments =
    {
        "fpga", "xilinx", "lattice", "altera", "spartan", "artix",
        "ft601", "ft600", "ft60", "ftdi",
        "screamer", "pcileech", "pciescrm", "lambdaconcept",
        "zdma", "squirrel",
        "cypress fx3", "fx3", "cyusb", "cyusb3",
        "datalogger", "leetdma", "dma",
        "capture", "video capture", "hdmi capture",
    };

    // Windows service names associated with DMA tools.
    // highConfidence = true  → named after a known software DMA tool (strong signal)
    // highConfidence = false → hardware chip driver that DMA boards use (could be legit)
    private static readonly (string fragment, bool highConfidence)[] DmaServicePatterns =
    {
        ("pcileech",  true),
        ("leechcore", true),
        ("memprocfs", true),
        ("screamer",  true),
        ("zdma",      true),
        ("FT600",     false),  // FTDI FT600 SuperSpeed USB chip driver
        ("FT601",     false),  // FTDI FT601 - used in Screamer M2, ZDMA, PCIe Squirrel
        ("ftdibus",   false),  // FTDI bus driver covering FT600/FT601 family
        ("cyusb3",    false),  // Cypress FX3 USB SuperSpeed driver
        ("CyUSB",     false),
    };

    // USB hardware ID prefixes for chips used almost exclusively in DMA boards.
    // VID_0403 = FTDI; PID 601E/601F = FT600/FT601 SuperSpeed bridge chips.
    // VID_04B4 = Cypress Semiconductor; common FX3 development kit PIDs.
    private static readonly string[] DmaUsbHwIds =
    {
        "USB\\VID_0403&PID_601E",  // FTDI FT600
        "USB\\VID_0403&PID_601F",  // FTDI FT601 (Screamer M2, ZDMA, PCIe Squirrel...)
        "USB\\VID_04B4&PID_00F3",  // Cypress FX3 SuperSpeed Explorer Kit
        "USB\\VID_04B4&PID_4720",  // Cypress EZ-USB FX3 Bootloader
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ReportDmaProtection(ctx);
        ctx.Report(0.25, "DMA-Schutz", "Plattform-DMA-Schutz geprueft");

        CheckDmaServiceArtifacts(ctx);
        ctx.Report(0.5, "DMA-Dienste", "Dienste-Artefakte geprueft");

        ScanPnpDevices(ctx, ct);
        ctx.Report(1.0, "PCIe-Geraete", "Geraeteliste geprueft");
        return Task.CompletedTask;
    }

    // --- 1) Platform DMA protection state ------------------------------------

    private void ReportDmaProtection(ScanContext ctx)
    {
        bool? kernelDmaOn = ReadKernelDmaProtection();
        bool iommuLikely = ReadIommuLikely();

        if (kernelDmaOn == true)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Kernel-DMA-Schutz aktiv",
                Risk = RiskLevel.Low,
                Location = "Plattform",
                Reason = "Der Windows-Kernel-DMA-Schutz ist aktiv. Viele PCIe/Thunderbolt-" +
                         "DMA-Angriffe werden dadurch blockiert (gutes Zeichen)."
            });
        }
        else
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Kernel-DMA-Schutz nicht nachweisbar aktiv",
                Risk = RiskLevel.Medium,
                Location = "Plattform",
                Reason = "Der Windows-Kernel-DMA-Schutz konnte nicht als aktiv bestaetigt werden" +
                         (iommuLikely ? " (IOMMU/VT-d scheint aber vorhanden)" : "") +
                         ". Ohne diesen Hardware-Schutz sind DMA-Angriffe ueber PCIe/Thunderbolt " +
                         "leichter moeglich. Hinweis, kein Beweis fuer einen Cheat.",
                Detail = "Empfehlung: im BIOS/UEFI VT-d/IOMMU und – falls vorhanden – " +
                         "Kernel-DMA-Schutz aktivieren."
            });
        }
    }

    private static bool? ReadKernelDmaProtection()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = baseKey.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses");
            if (k is not null && k.GetValueNames().Length >= 0) return true;
        }
        catch { }
        return null;
    }

    private static bool ReadIommuLikely()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name FROM Win32_PnPEntity WHERE Name LIKE '%IOMMU%' OR Name LIKE '%VT-d%' OR Name LIKE '%DMAR%'");
            foreach (var _ in searcher.Get()) return true;
        }
        catch { }
        return false;
    }

    // --- 2) Service/driver registry artifacts for DMA tools/hardware ---------

    private void CheckDmaServiceArtifacts(ScanContext ctx)
    {
        const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var svcRoot = baseKey.OpenSubKey(ServicesKey, writable: false);
            if (svcRoot is null) return;

            foreach (var svcName in svcRoot.GetSubKeyNames())
            {
                string? matchFrag = null;
                bool highConf = false;
                foreach (var (frag, hc) in DmaServicePatterns)
                {
                    if (!svcName.Contains(frag, StringComparison.OrdinalIgnoreCase)) continue;
                    matchFrag = frag;
                    highConf = hc;
                    break;
                }
                if (matchFrag is null) continue;

                using var svcKey = svcRoot.OpenSubKey(svcName, writable: false);
                var imagePath = svcKey?.GetValue("ImagePath")?.ToString();

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = highConf
                        ? $"DMA-Tool-Dienst erkannt: {svcName}"
                        : $"DMA-Hardware-Treiber erkannt: {svcName}",
                    Risk = highConf ? RiskLevel.High : RiskLevel.Medium,
                    Location = $@"HKLM\{ServicesKey}\{svcName}",
                    Reason = highConf
                        ? $"Windows-Dienst '{svcName}' entspricht einem bekannten DMA-Software-Tool " +
                          $"(Muster: '{matchFrag}'). PCILeech / LeechCore / MemProcFS sind Werkzeuge " +
                          "fuer direkten DMA-Speicherzugriff, die auch fuer Cheats eingesetzt werden."
                        : $"Windows-Dienst '{svcName}' entspricht einem Treiber fuer DMA-faehige " +
                          $"Hardware-Chips (Muster: '{matchFrag}'). FTDI FT600/FT601 und Cypress FX3 " +
                          "werden haeufig in DMA-Cheat-Boards verbaut. Kann auch legitime Hardware sein.",
                    Detail = imagePath is null ? null : $"Image: {imagePath}"
                });
            }
        }
        catch { }
    }

    // --- 3) PCIe / PnP device inventory with USB VID/PID matching ------------

    private void ScanPnpDevices(ScanContext ctx, CancellationToken ct)
    {
        int flagged = 0;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, Manufacturer, PNPDeviceID, PNPClass FROM Win32_PnPEntity");
            foreach (ManagementObject mo in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                if (flagged >= 25) break;

                var name = mo["Name"]?.ToString() ?? "";
                var mfg  = mo["Manufacturer"]?.ToString() ?? "";
                var id   = mo["PNPDeviceID"]?.ToString() ?? "";
                var cls  = mo["PNPClass"]?.ToString() ?? "";
                var hay  = (name + " " + mfg + " " + id + " " + cls).ToLowerInvariant();

                bool relevantBus = id.StartsWith("PCI", StringComparison.OrdinalIgnoreCase)
                                   || id.StartsWith("USB", StringComparison.OrdinalIgnoreCase)
                                   || id.StartsWith("TBT", StringComparison.OrdinalIgnoreCase);
                if (!relevantBus) continue;

                // High-specificity USB VID/PID check: chips used almost only in DMA boards.
                var hwIdMatch = DmaUsbHwIds.FirstOrDefault(prefix =>
                    id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
                if (hwIdMatch is not null)
                {
                    flagged++;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "DMA-Board-Chip per VID/PID erkannt",
                        Risk = RiskLevel.Medium,
                        Recommendation = Recommendation.Review,
                        Location = string.IsNullOrWhiteSpace(name) ? id : name,
                        Reason = $"USB-Geraet mit Hardware-ID '{hwIdMatch}' erkannt. " +
                                 "FTDI FT600/FT601 und Cypress FX3 werden fast ausschliesslich " +
                                 "als USB-Host-Interface in DMA-Cheat-Boards eingesetzt " +
                                 "(Screamer M2, ZDMA, PCIe Squirrel u.a.). " +
                                 "Legitime Geraete mit diesen Chips existieren, sind aber selten.",
                        Detail = $"Hardware-ID: {id} · Hersteller: {(string.IsNullOrWhiteSpace(mfg) ? "?" : mfg)}"
                    });
                    continue;
                }

                // General fragment match on name/manufacturer/class (lower confidence).
                var match = SuspectFragments.FirstOrDefault(f => hay.Contains(f));
                if (match is null) continue;

                flagged++;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Auffaelliges Geraet (DMA-faehig moeglich)",
                    Risk = RiskLevel.Low,
                    Recommendation = Recommendation.Review,
                    Location = string.IsNullOrWhiteSpace(name) ? id : name,
                    Reason = $"Ein angeschlossenes Geraet passt zum Muster '{match}'. FPGA-/Capture-" +
                             "aehnliche Geraete koennen fuer DMA missbraucht werden – legitime " +
                             "Capture-Karten sehen aber identisch aus. Nur ein Hinweis zur manuellen " +
                             "Pruefung, KEIN Cheat-Nachweis.",
                    Detail = $"Hersteller: {(string.IsNullOrWhiteSpace(mfg) ? "?" : mfg)} · ID: {id}"
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }

        if (flagged == 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Keine auffaelligen DMA-faehigen Geraete",
                Risk = RiskLevel.Low,
                Location = "PCIe/PnP",
                Reason = "In der Geraeteliste wurde nichts Auffaelliges gefunden. Das schliesst ein " +
                         "DMA-Geraet NICHT aus – gute DMA-Boards tarnen sich als unauffaellige Hardware."
            });
        }
    }
}
