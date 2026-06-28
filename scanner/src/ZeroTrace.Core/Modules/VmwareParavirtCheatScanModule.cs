using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects VMware / VirtualBox / Hyper-V paravirtualization used to hide cheat
/// processes and inject DLLs from a guest VM into the host game process.
///
/// VM-based cheating techniques ("VM cheat", "hypervisor cheat"):
///   - Run cheat in a VM guest that can read host memory via shared memory / VMCI sockets
///   - Use a hypervisor rootkit (Intel VT-x / AMD-V based) that runs below Windows
///     and is invisible to OS-level anti-cheat
///   - Run cheat process inside WSL2 (Windows Subsystem for Linux) to avoid Windows
///     process enumeration
///
/// Ocean and detect.ac flag VM/hypervisor indicators because:
///   - A Valorant player with VMware Workstation running on the gaming PC is suspicious
///   - Hypervisor cheats (KVM-based) require specific registry and driver artifacts
///   - WSL2 + Python + CUDA is a common AI aimbot deployment path
///
/// Detection:
///   - Installed VM software (Uninstall registry)
///   - VM driver services running (vmx_svga, VBoxDrv, etc.)
///   - Hyper-V isolation features enabled
///   - WSL distributions with cheat-related packages
///   - CPUID hypervisor bit (would require unsafe code, skipped)
/// </summary>
public sealed class VmwareParavirtCheatScanModule : IScanModule
{
    public string Name => "VM / Hypervisor / WSL Cheat-Hiding Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    private static readonly string[] VmSoftwareNames =
    {
        "VMware Workstation", "VMware Player", "VMware Fusion",
        "VirtualBox", "Oracle VM VirtualBox",
        "QEMU", "QEMU/KVM",
        "Parallels Desktop",
        "Virtual PC", "Microsoft Virtual PC",
        "Hyper-V Manager",
        "Vagrant",
    };

    private static readonly string[] VmDriverServices =
    {
        // VMware
        "vmx86", "vmci", "vsock", "vmrawdsk", "vmusbmouse",
        "VMwareAutostop", "VMwareHostd", "vmware-hostd",
        "vmnetadapter", "vmnetbridge", "vmnetuserif",
        // VirtualBox
        "VBoxDrv", "VBoxNetAdp", "VBoxNetFlt", "VBoxSF", "VBoxUSB",
        "VBoxGuest", "VirtualBox NDIS",
        // QEMU/KVM
        "WHPX", "haxm",
        // Hyper-V guest drivers (indicates VM is present/active)
        "hvservice",
    };

    private static readonly HashSet<string> CheatRelatedWslDistros =
        new(StringComparer.OrdinalIgnoreCase)
    {
        // Standard distros alone aren't suspicious, but note uncommon ones
        // that might be set up specifically for cheat tools
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanVmInstalled(ctx, ct);
        ScanVmDriverServices(ctx, ct);
        ScanHyperVState(ctx, ct);
        ScanWslDistributions(ctx, ct);
    }

    private void ScanVmInstalled(ScanContext ctx, CancellationToken ct)
    {
        string[] uninstallPaths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (string path in uninstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
                if (key is null) continue;

                foreach (string sub in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var subKey = key.OpenSubKey(sub, writable: false);
                        string? name = subKey?.GetValue("DisplayName") as string ?? "";
                        if (string.IsNullOrEmpty(name)) continue;

                        foreach (string vmName in VmSoftwareNames)
                        {
                            if (!name.Contains(vmName, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Virtualisierungssoftware installiert: {name}",
                                Risk     = RiskLevel.Medium,
                                Location = $@"HKLM\{path}\{sub}",
                                FileName = name,
                                Reason   = $"Virtualisierungssoftware '{name}' ist auf dem Gaming-PC " +
                                           "installiert. VMs ermöglichen Hypervisor-basierte Cheats, " +
                                           "die unterhalb des Windows-Kernels laufen und für Standard-AC " +
                                           "unsichtbar sind. In Kombination mit DMA-Hardware oder anderen " +
                                           "Indikatoren ist dies ein starkes Signal.",
                                Detail   = $"Software: {name} | Match: '{vmName}'"
                            });
                            break;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void ScanVmDriverServices(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is null) return;

            foreach (string svcName in VmDriverServices)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                    if (svcKey is null) continue;

                    int start = (int)(svcKey.GetValue("Start") ?? 4);
                    string? imagePath = svcKey.GetValue("ImagePath") as string ?? "";

                    // Only flag if not disabled (Start != 4)
                    if (start == 4) continue;

                    string product = GetVmProduct(svcName);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"VM-Treiber aktiv: {svcName} ({product})",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = svcName,
                        Reason   = $"VM-Kerntreiber '{svcName}' ({product}) ist aktiv (Start={start}). " +
                                   "VM-Treiber ermöglichen Hypervisor-Cheat-Techniken und " +
                                   "speicherbasierte Cheat-Injektion über VM-Shared-Memory. " +
                                   "Ocean und detect.ac flaggen VM-Treiber als Risikosignal.",
                        Detail   = $"Dienst: {svcName} | Produkt: {product} | " +
                                   $"Start-Typ: {start} | ImagePath: {imagePath}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static string GetVmProduct(string service)
    {
        if (service.StartsWith("vmx") || service.StartsWith("VMware") ||
            service.StartsWith("vmnet") || service.StartsWith("vmci") ||
            service.StartsWith("vsock"))
            return "VMware";
        if (service.StartsWith("VBox") || service.Contains("VirtualBox"))
            return "VirtualBox";
        if (service is "WHPX" or "haxm")
            return "QEMU/HAXM";
        if (service is "hvservice")
            return "Hyper-V";
        return "VM";
    }

    private void ScanHyperVState(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            // VBS / HVCI enabled = Hyper-V is active (affects game AC compatibility)
            using var vbsKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                writable: false);

            if (vbsKey is null) return;
            int enabled = (int)(vbsKey.GetValue("Enabled") ?? 0);
            if (enabled != 1) return;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Hyper-V Enforced Code Integrity (HVCI) aktiv",
                Risk     = RiskLevel.Low,
                Location = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\...\HVCI",
                FileName = "HVCI",
                Reason   = "Hyper-V Enforced Code Integrity ist aktiv. HVCI aktiviert einen " +
                           "Hypervisor unter Windows, der für Kernel-Level-Cheats genutzt werden kann. " +
                           "Allein kein starkes Signal, aber relevant in Kombination mit anderen Indikatoren.",
                Detail   = $"Enabled: {enabled}"
            });
        }
        catch { }
    }

    private void ScanWslDistributions(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            // WSL distros are listed under HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss
            using var lxssKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss", writable: false);
            if (lxssKey is null) return;

            int wslCount = 0;
            foreach (string distroGuid in lxssKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var distroKey = lxssKey.OpenSubKey(distroGuid, writable: false);
                    if (distroKey is null) continue;

                    string? name = distroKey.GetValue("DistributionName") as string ?? "";
                    string? basePath = distroKey.GetValue("BasePath") as string ?? "";
                    wslCount++;

                    // Check if the WSL distro filesystem contains cheat-related Python packages
                    if (!string.IsNullOrEmpty(basePath))
                    {
                        string rootfsPath = System.IO.Path.Combine(basePath, "rootfs");
                        if (System.IO.Directory.Exists(rootfsPath))
                            CheckWslRootfs(ctx, name ?? distroGuid, rootfsPath, ct);
                    }
                }
                catch { }
            }

            if (wslCount > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"WSL2 mit {wslCount} Distribution(en) installiert",
                    Risk     = RiskLevel.Low,
                    Location = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss",
                    FileName = "WSL2",
                    Reason   = $"Windows Subsystem for Linux (WSL2) mit {wslCount} Distribution(en) gefunden. " +
                               "WSL2 + Python + CUDA ist ein verbreiteter Deployment-Pfad für KI-Aimbots. " +
                               "Linux-Prozesse in WSL2 sind für Windows-Anti-Cheat-Systeme schwerer " +
                               "zu enumerieren als native Windows-Prozesse.",
                    Detail   = $"WSL-Distributionen: {wslCount}"
                });
            }
        }
        catch { }
    }

    private void CheckWslRootfs(ScanContext ctx, string distroName,
        string rootfs, CancellationToken ct)
    {
        // Check for AI aimbot packages in WSL Python environment
        string[] aiPackageDirs =
        {
            "ultralytics", "onnxruntime", "bettercam", "torch", "tensorrt",
        };

        try
        {
            string sitePackages = System.IO.Path.Combine(rootfs, "usr", "local", "lib");
            if (!System.IO.Directory.Exists(sitePackages)) return;

            foreach (string dir in System.IO.Directory.EnumerateDirectories(
                         sitePackages, "site-packages", System.IO.SearchOption.AllDirectories))
            {
                foreach (string pkg in aiPackageDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    string pkgDir = System.IO.Path.Combine(dir, pkg);
                    if (!System.IO.Directory.Exists(pkgDir)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"KI-Aimbot-Paket in WSL2 ({distroName}): {pkg}",
                        Risk     = RiskLevel.High,
                        Location = pkgDir,
                        FileName = pkg,
                        Reason   = $"KI/ML-Paket '{pkg}' ist in der WSL2-Distribution '{distroName}' " +
                                   "installiert. WSL2 + ultralytics/onnxruntime/bettercam ist das " +
                                   "klassische Setup für Linux-basierte KI-Aimbots, die Windows-AC umgehen.",
                        Detail   = $"Distribution: {distroName} | Paket: {pkg} | Pfad: {pkgDir}"
                    });
                }
            }
        }
        catch { }
    }
}
