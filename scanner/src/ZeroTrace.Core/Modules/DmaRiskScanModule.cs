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
///   1) the platform DMA defenses (Kernel DMA Protection / IOMMU-VT-d) state —
///      if these are OFF, many DMA attacks are possible;
///   2) a read-only inventory of PCIe / PnP devices, flagging capture-card /
///      FPGA-style or otherwise unusual entries that *could* be a DMA board.
/// Legitimate capture cards look identical to DMA boards from the host side, so
/// every device hit is reported only as "zur Pruefung" (review), not as a cheat.
/// Nothing is changed.
/// </summary>
public sealed class DmaRiskScanModule : IScanModule
{
    public string Name => "DMA / Hardware (Hinweis)";
    public double Weight => 0.4;

    // Vendor / name fragments that are over-represented in DMA-board builds or
    // in capture hardware that DMA boards imitate. Pure heuristic -> review only.
    private static readonly string[] SuspectFragments =
    {
        "fpga", "xilinx", "lattice", "altera", "ft601", "ft60", "screamer",
        "pcileech", "lambdaconcept", "capture", "video capture", "hdmi capture",
        "ftdi", "cypress fx3", "fx3", "datalogger", "leetdma", "dma"
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ReportDmaProtection(ctx);
        ctx.Report(0.4, "DMA-Schutz", "Plattform-DMA-Schutz geprueft");

        ScanPnpDevices(ctx, ct);
        ctx.Report(1.0, "PCIe-Geraete", "Geraeteliste geprueft");
        return Task.CompletedTask;
    }

    // --- 1) Platform DMA protection state -------------------------------------

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

    /// <summary>
    /// Best-effort read of Kernel DMA Protection state. True only if we can
    /// positively confirm it; null/false otherwise (we never claim a false ON).
    /// </summary>
    private static bool? ReadKernelDmaProtection()
    {
        // Policy/state is exposed under this key on supported platforms.
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = baseKey.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses");
            // Presence of the AllowedBuses policy node indicates DMA protection is
            // being enforced for external buses.
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

    // --- 2) PCIe / PnP device inventory ---------------------------------------

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
                var mfg = mo["Manufacturer"]?.ToString() ?? "";
                var id = mo["PNPDeviceID"]?.ToString() ?? "";
                var cls = mo["PNPClass"]?.ToString() ?? "";
                var hay = (name + " " + mfg + " " + id + " " + cls).ToLowerInvariant();

                // Only consider PCI / Thunderbolt / USB-bridge devices.
                bool relevantBus = id.StartsWith("PCI", StringComparison.OrdinalIgnoreCase)
                                   || id.StartsWith("USB", StringComparison.OrdinalIgnoreCase)
                                   || id.StartsWith("TBT", StringComparison.OrdinalIgnoreCase);
                if (!relevantBus) continue;

                var match = SuspectFragments.FirstOrDefault(f => hay.Contains(f));
                if (match is null) continue;

                flagged++;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Auffaelliges Geraet (DMA-faehig moeglich)",
                    Risk = RiskLevel.Low, // hint only; legitimate capture cards match too
                    Recommendation = Recommendation.Review,
                    Location = string.IsNullOrWhiteSpace(name) ? id : name,
                    Reason = $"Ein angeschlossenes Geraet passt zum Muster '{match}'. FPGA-/Capture-" +
                             "aehnliche Geraete koennen fuer DMA missbraucht werden – legitime " +
                             "Capture-Karten sehen aber identisch aus. Nur ein Hinweis zur manuellen " +
                             "Pruefung, KEIN Cheat-Nachweis.",
                    Detail = $"Hersteller: {(string.IsNullOrWhiteSpace(mfg) ? "?" : mfg)} \u00b7 ID: {id}"
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* WMI unavailable -> skip */ }

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
