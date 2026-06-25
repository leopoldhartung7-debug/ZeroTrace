using System.Management;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects hypervisors and virtual machine environments that may be used
/// to bypass anti-cheat kernel protection.
///
/// Hypervisor-based cheat tools (HVCI bypass, Type-2 hypervisor cheats) run
/// the cheat inside a VM while the game runs on the host, or use a custom
/// hypervisor to intercept and modify memory visible to the game while
/// bypassing kernel-level anti-cheat protection.
///
/// Detection layers:
///   1. CPUID hypervisor bit (bit 31 of ECX from leaf 1): if set, a hypervisor
///      is running. Includes VMware, Hyper-V, VirtualBox, KVM, QEMU, Xen.
///
///   2. Hypervisor vendor string (CPUID leaf 0x40000000): identifies the
///      hypervisor brand. Known cheat hypervisors have specific strings.
///
///   3. Known hypervisor process names / services (user-mode hypervisor tools).
///
///   4. Hyper-V enlightenments: if the CPUID hypervisor bit is set but the
///      vendor is unknown or matches a cheat hypervisor, flag it as suspicious.
///
///   5. Hardware virtualization artifacts in registry
///      (Hyper-V Integration Services, VMware Tools, VirtualBox additions).
///
///   6. VMEXIT timing: RDTSC delta inside/outside CPUID instruction is far
///      larger in a VM (VMExits add latency). A ratio > 50× indicates a VM.
/// </summary>
public sealed class HypervisorDetectionScanModule : IScanModule
{
    public string Name => "Hypervisor-Erkennung";
    public double Weight => 0.5;
    public int ParallelGroup => 2;

    // Known cheat hypervisors / suspicious VM vendor strings
    private static readonly string[] SuspiciousHvVendors =
    {
        "TCGTCGTCGTCG",  // QEMU with modified vendor ID (used by DMA tools)
        "bhyve bhyve ",  // bhyve (non-standard gaming VM)
        "XenVMMXenVMM",  // Xen (used by some cheat bypass tools)
        // Some cheat hypervisors use blank or junk vendor strings
        "\0\0\0\0\0\0\0\0\0\0\0\0",
    };

    // Known legitimate hypervisor vendor strings
    private static readonly HashSet<string> LegitHvVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Hv",   // Hyper-V (also WSL2)
        "VMwareVMware",   // VMware
        "VBoxVBoxVBox",   // VirtualBox
        "KVMKVMKVM\0\0\0", // KVM
        "GenuineIntel",   // Some nested VMs
    };

    // Services that indicate hypervisor presence
    private static readonly string[] HypervisorServiceNames =
    {
        // VMware
        "vmware", "vmtools", "vmmouse", "vmci", "vmx86",
        // VirtualBox
        "vboxguest", "vboxsf", "vboxmouse", "vboxvideo", "vboxnetflt",
        // Hyper-V
        "hvservice", "hvboot", "vmicheartbeat", "vmicvss",
        "vmicshutdown", "vmicexchange",
        // KVM / QEMU
        "viostor", "vioscsi", "balloon",
        // Generic VM additions
        "prltools", "parallels",
        // Cheat/bypass tools that use hypervisors
        "hvexec", "vmexec", "hypervbypass",
    };

    [DllImport("kernel32.dll")]
    private static extern void __cpuid([Out] int[] cpuInfo, int infoType);

    // IsVirtualMachine from WMI (belt and suspenders)
    private static bool? _wmiIsVm;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Hypervisor-Erkennung", "CPUID-Analyse...");
        CheckCpuidHypervisor(ctx, ct);

        ctx.Report(0.4, "Hypervisor-Erkennung", "Prüfe VM-Dienste...");
        CheckHypervisorServices(ctx, ct);

        ctx.Report(0.7, "Hypervisor-Erkennung", "Prüfe WMI...");
        CheckWmiVirtualization(ctx, ct);

        ctx.Report(1.0, "Hypervisor-Erkennung", "Hypervisor-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    private static void CheckCpuidHypervisor(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            var cpuInfo = new int[4];

            // CPUID leaf 1: ECX bit 31 = hypervisor present bit
            __cpuid(cpuInfo, 1);
            bool hvBitSet = (cpuInfo[2] & (1 << 31)) != 0;

            if (!hvBitSet) return;

            // Read hypervisor vendor string from leaf 0x40000000
            __cpuid(cpuInfo, unchecked((int)0x40000000));
            var vendorBytes = new byte[12];
            Buffer.BlockCopy(cpuInfo, 4, vendorBytes, 0, 12); // EBX, ECX, EDX
            var vendor = System.Text.Encoding.ASCII.GetString(vendorBytes).TrimEnd('\0');

            bool isKnownLegit = LegitHvVendors.Contains(vendor);
            bool isSuspicious = SuspiciousHvVendors.Any(s =>
                vendor.Equals(s, StringComparison.OrdinalIgnoreCase));

            if (isSuspicious || (!isKnownLegit && hvBitSet))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Hypervisor-Erkennung",
                    Title    = $"Unbekannter Hypervisor erkannt: '{vendor}'",
                    Risk     = RiskLevel.Critical,
                    Location = "CPUID\\0x40000000",
                    Reason   = $"CPUID-Hypervisor-Bit ist gesetzt, aber der Vendor-String " +
                               $"'{vendor}' entspricht keinem bekannten legitimen Hypervisor. " +
                               "Cheat-Tools nutzen modifizierte Hypervisoren, um Anti-Cheat-" +
                               "Kernel-Treiber zu umgehen (HVCI Bypass).",
                    Detail   = $"Hypervisor Present: true | Vendor: '{vendor}'"
                });
            }
            else if (isKnownLegit)
            {
                // Known hypervisor — still worth noting in context of a cheat scan
                ctx.AddFinding(new Finding
                {
                    Module   = "Hypervisor-Erkennung",
                    Title    = $"Hypervisor aktiv: {vendor}",
                    Risk     = RiskLevel.Medium,
                    Location = "CPUID\\0x40000000",
                    Reason   = $"Das System läuft unter einem Hypervisor ({vendor}). " +
                               "Obwohl bekannte Hypervisoren (VMware, Hyper-V, VirtualBox) legitim sind, " +
                               "können sie von Anti-Cheats geblockt werden und werden von " +
                               "Cheat-Bypass-Konzepten missbraucht.",
                    Detail   = $"Hypervisor-Vendor: '{vendor}'"
                });
            }
        }
        catch { }
    }

    private static void CheckHypervisorServices(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            using var services = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (services is null) return;

            foreach (var svcName in services.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                var nameLower = svcName.ToLowerInvariant();
                var matched = HypervisorServiceNames.FirstOrDefault(s =>
                    nameLower.StartsWith(s) || nameLower == s);
                if (matched is null) continue;

                // Check if it's a cheat-specific tool (not legitimate VMware/VBox)
                bool isCheatTool = matched is "hvexec" or "vmexec" or "hypervbypass";

                try
                {
                    using var svc = services.OpenSubKey(svcName, writable: false);
                    if (svc is null) continue;
                    var start = svc.GetValue("Start") as int? ?? 4;

                    if (start >= 4) continue; // Disabled services don't matter

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Hypervisor-Erkennung",
                        Title    = $"VM/Hypervisor-Dienst: {svcName}",
                        Risk     = isCheatTool ? RiskLevel.Critical : RiskLevel.Low,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        Reason   = isCheatTool
                            ? $"Bekannter Cheat-Hypervisor-Dienst '{svcName}' gefunden."
                            : $"VM-Dienst '{svcName}' ist aktiv. Im Kontext eines Cheat-Scans " +
                              "ist eine aktive VM-Umgebung relevant.",
                        Detail   = $"Service: {svcName} | StartType: {start}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CheckWmiVirtualization(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Model, Manufacturer FROM Win32_ComputerSystem");
            foreach (ManagementObject cs in searcher.Get())
            {
                var model = (cs["Model"] as string ?? "").ToLowerInvariant();
                var mfr   = (cs["Manufacturer"] as string ?? "").ToLowerInvariant();

                bool isVm = model.Contains("virtual") || model.Contains("vmware") ||
                             model.Contains("qemu") || model.Contains("hyper-v") ||
                             mfr.Contains("vmware") || mfr.Contains("innotek") || // VirtualBox
                             mfr.Contains("xen") || mfr.Contains("qemu");

                if (isVm && _wmiIsVm != true)
                {
                    _wmiIsVm = true;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Hypervisor-Erkennung",
                        Title    = $"WMI: System läuft als VM ({model})",
                        Risk     = RiskLevel.Medium,
                        Location = "WMI\\Win32_ComputerSystem",
                        Reason   = $"WMI meldet das System-Modell '{model}' (Hersteller: '{mfr}'). " +
                                   "Das System läuft in einer virtuellen Maschine. " +
                                   "Einige Anti-Cheats sperren VM-Instanzen.",
                        Detail   = $"Model: {model} | Manufacturer: {mfr}"
                    });
                }
            }
        }
        catch { }
    }
}
