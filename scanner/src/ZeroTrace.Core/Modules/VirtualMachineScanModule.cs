using System.Management;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects whether the current system is running inside a virtual machine or
/// hypervisor guest. Cheaters use VMs to test cheats without risking their main
/// account being banned, and some cheat setups rely on a VM layer to hide memory
/// manipulation from the host game. Checks: WMI hardware strings, registry
/// presence of VM guest tools, and disk drive model strings. A VM finding alone
/// is not conclusive — it is a weak signal (Medium) that is meaningful when
/// combined with other findings. Read-only.
/// </summary>
public sealed class VirtualMachineScanModule : IScanModule
{
    public string Name => "Virtuelle Maschine";
    public double Weight => 0.3;

    // Strings that appear in hardware/model/manufacturer fields of VMs.
    private static readonly (string token, string platform)[] VmTokens =
    {
        ("vmware",              "VMware"),
        ("virtualbox",          "VirtualBox"),
        ("innotek gmbh",        "VirtualBox"),
        ("virtual machine",     "Hyper-V / Hyper-Visor"),
        ("vbox",                "VirtualBox"),
        ("qemu",                "QEMU"),
        ("bochs",               "Bochs"),
        ("xen",                 "Xen"),
        ("parallels",           "Parallels"),
        ("microsoft hv",        "Hyper-V"),
        ("kvm",                 "KVM"),
        ("virtual hd",          "Hyper-V VHD"),
        ("vmware virtual disk", "VMware"),
        ("vbox harddisk",       "VirtualBox"),
        ("qemu harddisk",       "QEMU"),
    };

    // Registry keys present only when VM guest tools are installed.
    private static readonly (string key, string platform)[] VmRegistryKeys =
    {
        (@"SOFTWARE\VMware, Inc.\VMware Tools",                   "VMware"),
        (@"SOFTWARE\Oracle\VirtualBox Guest Additions",           "VirtualBox"),
        (@"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",  "Hyper-V"),
        (@"SOFTWARE\Parallels\Tools",                             "Parallels"),
        (@"SYSTEM\CurrentControlSet\Services\VBoxGuest",          "VirtualBox"),
        (@"SYSTEM\CurrentControlSet\Services\vmci",               "VMware"),
        (@"SYSTEM\CurrentControlSet\Services\vmhgfs",             "VMware"),
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        string? platform = null;
        string? evidence = null;

        platform = CheckRegistry(out evidence);
        if (platform is null) platform = CheckWmi(out evidence);

        ctx.Report(1.0, "VM-Erkennung", "Hypervisor-Pruefung abgeschlossen");

        if (platform is null) return Task.CompletedTask;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"System laeuft in einer virtuellen Maschine ({platform})",
            Risk = RiskLevel.Medium,
            Recommendation = Recommendation.Review,
            Location = "System-Hardware",
            Reason = $"Das System wurde als '{platform}'-Gastbetriebssystem identifiziert. " +
                     "Cheater betreiben Spielkonten in VMs um bei einem Ban den Host-Account " +
                     "zu schuetzen. Bestimmte Cheat-Setups nutzen ausserdem VM-Schichten " +
                     "(DMA-Cheating, Hypervisor-rootkits) um Speicherzugriffe vor dem Spiel " +
                     "zu verbergen.",
            Detail = evidence ?? platform
        });

        return Task.CompletedTask;
    }

    private static string? CheckRegistry(out string? evidence)
    {
        foreach (var (key, platform) in VmRegistryKeys)
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(key);
                if (k is null) continue;
                evidence = $"Registry-Schluessel gefunden: HKLM\\{key}";
                return platform;
            }
            catch { }
        }
        evidence = null;
        return null;
    }

    private static string? CheckWmi(out string? evidence)
    {
        var wmiQueries = new[]
        {
            ("SELECT Manufacturer, Model FROM Win32_ComputerSystem",
             new[] { "Manufacturer", "Model" }),
            ("SELECT Manufacturer FROM Win32_BIOS",
             new[] { "Manufacturer" }),
            ("SELECT Model FROM Win32_DiskDrive",
             new[] { "Model" }),
        };

        foreach (var (query, fields) in wmiQueries)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher(query);
                foreach (ManagementObject mo in searcher.Get())
                {
                    foreach (var field in fields)
                    {
                        var val = mo[field]?.ToString() ?? "";
                        var lower = val.ToLowerInvariant();
                        foreach (var (token, platform) in VmTokens)
                        {
                            if (lower.Contains(token))
                            {
                                evidence = $"WMI {field}: {val}";
                                return platform;
                            }
                        }
                    }
                }
            }
            catch { }
        }

        evidence = null;
        return null;
    }
}
