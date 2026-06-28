using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class VirtualMachineBanEvasionForensicScanModule : IScanModule
{
    public string Name => "VM Ban Evasion Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] VMwareServiceNames = { "vmtools", "vmhgfs", "vmmouse", "vmrawdsk", "vmusbmouse", "vmvss", "vmxnet", "vmxnet3", "vmci", "vmscsi" };
    private static readonly string[] VBoxServiceNames = { "VBoxSVC", "VBoxUSB", "VBoxNetAdp", "VBoxNetFlt", "VBoxDrv", "VBoxMouse", "VBoxGuest", "VBoxSF" };
    private static readonly string[] HyperVServiceNames = { "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown", "vmictimesync", "vmicvss", "VmSwitch", "nvspwmi", "netvsc" };
    private static readonly string[] VMDiskExtensions = { ".vmdk", ".vdi", ".vhd", ".vhdx", ".qcow2", ".ova", ".ovf", ".vmss", ".vmsn", ".avhd", ".avhdx" };
    private static readonly string[] VMSpoofingTools = { "vmcloak.exe", "vmdetector_bypass.exe", "vboxhardening_bypass.exe", "hyperdetach.exe", "cpuz_spoofer.exe", "cpuid_fake.exe", "vminspect_bypass.exe" };
    private static readonly string[] BanEvasionVMConfigKeywords = { "SMBIOS.reflectHost", "hypervisor.cpuid.v0", "scsi0.sharedBus", "anti-detect", "ban-evade", "fresh-install", "new-identity" };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckVMwareInstallArtifacts(ctx, ct),
            CheckVirtualBoxInstallArtifacts(ctx, ct),
            CheckHyperVArtifacts(ctx, ct),
            CheckQEMUKVMArtifacts(ctx, ct),
            CheckVMNetworkAdapterHistory(ctx, ct),
            CheckVMSharedFolderArtifacts(ctx, ct),
            CheckVMSnapshotArtifacts(ctx, ct),
            CheckVMDiskImageFiles(ctx, ct),
            CheckVMwareToolsHistory(ctx, ct),
            CheckBanEvasionVMConfig(ctx, ct),
            CheckVMSpoofingTools(ctx, ct),
            CheckParallelDesktopArtifacts(ctx, ct),
            CheckSandboxEnvironmentArtifacts(ctx, ct),
            CheckRemoteGamingStreamArtifacts(ctx, ct),
            CheckWSLCheatArtifacts(ctx, ct),
            CheckDockerCheatContainerArtifacts(ctx, ct),
            CheckVMwareRecentMRU(ctx, ct),
            CheckVMCloneArtifacts(ctx, ct)
        );
    }

    private Task CheckVMwareInstallArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            string[] vmwareRegKeys = new[]
            {
                @"SOFTWARE\VMware, Inc.",
                @"SOFTWARE\WOW6432Node\VMware, Inc."
            };

            foreach (string regKey in vmwareRegKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(regKey, writable: false);
                    ctx.IncrementRegistryKeys();
                    if (key is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "VMware Installation Registry Key Found",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKLM\{regKey}",
                            FileName = null,
                            Reason = "VMware installation registry key detected. In a gaming context, VMware presence is suspicious and may indicate VM-based ban evasion.",
                            Detail = $"Registry key: HKLM\\{regKey}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is not null)
            {
                foreach (string svcName in VMwareServiceNames)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (svcKey is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VMware Service Artifact: {svcName}",
                                Risk = RiskLevel.Medium,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = null,
                                Reason = $"VMware service '{svcName}' found in registry. This is a VMware guest tools artifact indicating the system has operated as a VMware VM.",
                                Detail = $"Service name: {svcName}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        string[] vmwareProgramPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "VMware"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "VMware")
        };

        foreach (string vmwarePath in vmwareProgramPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                if (Directory.Exists(vmwarePath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VMware Installation Directory Found",
                        Risk = RiskLevel.Medium,
                        Location = vmwarePath,
                        FileName = "VMware",
                        Reason = "VMware installation directory exists. VMware is commonly used for ban evasion by running a gaming VM that can be cloned or restored after a ban.",
                        Detail = $"Path: {vmwarePath}"
                    });
                }
            }
            catch { }
        }

        string[] searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        };

        foreach (string searchDir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(searchDir)) continue;
            try
            {
                foreach (string vmxFile in Directory.GetFiles(searchDir, "*.vmx", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VMware VM Config File Found",
                        Risk = RiskLevel.High,
                        Location = vmxFile,
                        FileName = Path.GetFileName(vmxFile),
                        Reason = "VMware VM configuration file (.vmx) found in user directories. VM config files in easily accessible locations suggest active VM-based ban evasion setups.",
                        Detail = $"Path: {vmxFile}"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVirtualBoxInstallArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var vboxKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Oracle\VirtualBox", writable: false);
            ctx.IncrementRegistryKeys();
            if (vboxKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "VirtualBox Installation Registry Key Found",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\Oracle\VirtualBox",
                    FileName = null,
                    Reason = "VirtualBox installation key detected in registry. VirtualBox is widely used for gaming ban evasion via disposable VM identities.",
                    Detail = @"Registry key: HKLM\SOFTWARE\Oracle\VirtualBox"
                });
            }
        }
        catch { }

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is not null)
            {
                foreach (string svcName in VBoxServiceNames)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (svcKey is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VirtualBox Service Artifact: {svcName}",
                                Risk = RiskLevel.Medium,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = null,
                                Reason = $"VirtualBox service '{svcName}' found in registry indicating a prior or current VirtualBox guest environment.",
                                Detail = $"Service: {svcName}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            string vboxProgramPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Oracle", "VirtualBox");
            if (Directory.Exists(vboxProgramPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "VirtualBox Installation Directory Found",
                    Risk = RiskLevel.Medium,
                    Location = vboxProgramPath,
                    FileName = "VirtualBox",
                    Reason = "VirtualBox installation directory found. VirtualBox allows easy creation and restoration of VM snapshots used for ban evasion.",
                    Detail = $"Path: {vboxProgramPath}"
                });
            }
        }
        catch { }

        try
        {
            using var netAdaptersKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}", writable: false);
            if (netAdaptersKey is not null)
            {
                foreach (string subKeyName in netAdaptersKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var adapterKey = netAdaptersKey.OpenSubKey(subKeyName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (adapterKey is null) continue;
                        string driverDesc = (adapterKey.GetValue("DriverDesc") as string) ?? string.Empty;
                        if (driverDesc.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "VirtualBox Network Adapter Found",
                                Risk = RiskLevel.Medium,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Class\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{subKeyName}",
                                FileName = null,
                                Reason = $"VirtualBox network adapter '{driverDesc}' found in registry. VirtualBox adapters indicate an installed VirtualBox environment.",
                                Detail = $"DriverDesc: {driverDesc}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        string[] userDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
        };

        foreach (string userDir in userDirs)
        {
            if (!Directory.Exists(userDir)) continue;
            foreach (string ext in new[] { "*.vbox", "*.vdi" })
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (string vmFile in Directory.GetFiles(userDir, ext, SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VirtualBox VM Image File Found: {Path.GetFileName(vmFile)}",
                            Risk = RiskLevel.High,
                            Location = vmFile,
                            FileName = Path.GetFileName(vmFile),
                            Reason = "VirtualBox VM configuration or disk image file found in user directory. These files may contain ban-evading VM identities.",
                            Detail = $"Path: {vmFile}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckHyperVArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var hypervKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization", writable: false);
            ctx.IncrementRegistryKeys();
            if (hypervKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Hyper-V Virtualization Registry Key Found",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization",
                    FileName = null,
                    Reason = "Hyper-V virtualization registry key found. Hyper-V can be used to host gaming VMs for ban evasion via isolated VM identities.",
                    Detail = @"Registry key: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization"
                });
            }
        }
        catch { }

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is not null)
            {
                foreach (string svcName in HyperVServiceNames)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (svcKey is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Hyper-V Service Artifact: {svcName}",
                                Risk = RiskLevel.Medium,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = null,
                                Reason = $"Hyper-V integration service '{svcName}' found. Hyper-V services indicate an active or previously active Hyper-V guest configuration.",
                                Detail = $"Service: {svcName}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            string hypervVmPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows", "Hyper-V");
            if (Directory.Exists(hypervVmPath))
            {
                ctx.IncrementFiles();
                foreach (string vmcxFile in Directory.GetFiles(hypervVmPath, "*.vmcx", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Hyper-V VM Config File Found",
                        Risk = RiskLevel.Medium,
                        Location = vmcxFile,
                        FileName = Path.GetFileName(vmcxFile),
                        Reason = "Hyper-V VM configuration file (.vmcx) found. Hyper-V VMs with separate identities are used for ban evasion in gaming.",
                        Detail = $"Path: {vmcxFile}"
                    });
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckQEMUKVMArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var biosKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS", writable: false);
            ctx.IncrementRegistryKeys();
            if (biosKey is not null)
            {
                string[] biosValueNames = biosKey.GetValueNames();
                foreach (string valueName in biosValueNames)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        string biosValue = (biosKey.GetValue(valueName) as string) ?? string.Empty;
                        if (biosValue.Contains("QEMU", StringComparison.OrdinalIgnoreCase) ||
                            biosValue.Contains("Bochs", StringComparison.OrdinalIgnoreCase) ||
                            biosValue.Contains("SeaBIOS", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "QEMU/KVM BIOS String Detected",
                                Risk = RiskLevel.High,
                                Location = @"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
                                FileName = null,
                                Reason = $"BIOS registry value '{valueName}' contains QEMU/Bochs/SeaBIOS string '{biosValue}'. QEMU is rarely used for legitimate gaming and strongly indicates VM-based ban evasion.",
                                Detail = $"Value: {valueName} = {biosValue}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            ctx.IncrementRegistryKeys();
            if (servicesKey is not null)
            {
                using var qemuGaKey = servicesKey.OpenSubKey("qemu-ga", writable: false);
                if (qemuGaKey is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "QEMU Guest Agent Service Found",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\qemu-ga",
                        FileName = null,
                        Reason = "QEMU guest agent service 'qemu-ga' found in registry. This confirms the system has operated as a QEMU/KVM virtual machine.",
                        Detail = "Service: qemu-ga (QEMU Guest Agent)"
                    });
                }
            }
        }
        catch { }

        try
        {
            string driversPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
            if (Directory.Exists(driversPath))
            {
                string[] qemuDriverNames = new[] { "qemu", "virtio", "vioscsi", "vioser", "balloon", "netkvm", "viostor" };
                foreach (string driverPattern in qemuDriverNames)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        foreach (string driverFile in Directory.GetFiles(driversPath, $"*{driverPattern}*.sys"))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"QEMU/VirtIO Driver File Found: {Path.GetFileName(driverFile)}",
                                Risk = RiskLevel.High,
                                Location = driverFile,
                                FileName = Path.GetFileName(driverFile),
                                Reason = $"QEMU/VirtIO driver file '{Path.GetFileName(driverFile)}' found in System32\\drivers. VirtIO drivers are exclusively used in QEMU/KVM virtual machines.",
                                Detail = $"Path: {driverFile}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVMNetworkAdapterHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] vmAdapterKeywords = new[] { "VMware", "VirtualBox", "Hyper-V", "QEMU", "Virtual", "VirtIO" };

        try
        {
            using var networkKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Network", writable: false);
            ctx.IncrementRegistryKeys();
            if (networkKey is not null)
            {
                foreach (string subKeyName in networkKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var adapterKey = networkKey.OpenSubKey(subKeyName, writable: false);
                        if (adapterKey is null) continue;
                        string name = (adapterKey.GetValue("Name") as string) ?? string.Empty;
                        foreach (string keyword in vmAdapterKeywords)
                        {
                            if (name.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.IncrementRegistryKeys();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Virtual Network Adapter History: {name}",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Network\{subKeyName}",
                                    FileName = null,
                                    Reason = $"Virtual network adapter '{name}' found in network history. Virtual NICs are a reliable indicator of VM usage for ban evasion.",
                                    Detail = $"Adapter name: {name}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}", writable: false);
            ctx.IncrementRegistryKeys();
            if (classKey is not null)
            {
                foreach (string subKeyName in classKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var adapterKey = classKey.OpenSubKey(subKeyName, writable: false);
                        if (adapterKey is null) continue;
                        string driverDesc = (adapterKey.GetValue("DriverDesc") as string) ?? string.Empty;
                        foreach (string keyword in vmAdapterKeywords)
                        {
                            if (driverDesc.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.IncrementRegistryKeys();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Virtual NIC Registry Entry: {driverDesc}",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Class\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{subKeyName}",
                                    FileName = null,
                                    Reason = $"Virtual network adapter '{driverDesc}' found in class registry. This is a persistent artifact of VM network configuration.",
                                    Detail = $"DriverDesc: {driverDesc}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVMSharedFolderArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            ctx.IncrementRegistryKeys();
            if (servicesKey is not null)
            {
                using var vmhgfsKey = servicesKey.OpenSubKey("vmhgfs", writable: false);
                if (vmhgfsKey is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VMware Shared Folders Driver Found",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\vmhgfs",
                        FileName = null,
                        Reason = "VMware HGFS shared folder driver found. Shared folders are used to transfer cheat files between host and ban-evading VM without leaving file traces in the VM.",
                        Detail = "Service: vmhgfs (VMware Host-Guest File System)"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var vboxSfKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\VBoxSF", writable: false);
            ctx.IncrementRegistryKeys();
            if (vboxSfKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "VirtualBox Shared Folder Service Found",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\VBoxSF",
                    FileName = null,
                    Reason = "VirtualBox shared folder service (VBoxSF) found. Shared folders enable cheat delivery from host to VM without the VM containing permanent cheat artifacts.",
                    Detail = "Service: VBoxSF (VirtualBox Shared Folders)"
                });
            }
        }
        catch { }

        string[] recentDocPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Recent")
        };

        foreach (string recentDir in recentDocPaths)
        {
            if (!Directory.Exists(recentDir)) continue;
            try
            {
                foreach (string lnkFile in Directory.GetFiles(recentDir, "*.lnk"))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    string lnkName = lnkFile.ToUpperInvariant();
                    if (lnkName.Contains("VMWARE-HOST", StringComparison.OrdinalIgnoreCase) ||
                        lnkName.Contains("VBOXSVR", StringComparison.OrdinalIgnoreCase) ||
                        lnkName.Contains("SHARED FOLDER", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "VM Shared Folder Recent Document Found",
                            Risk = RiskLevel.High,
                            Location = lnkFile,
                            FileName = Path.GetFileName(lnkFile),
                            Reason = "Recent document shortcut references a VM shared folder path. Files accessed via VM shared folders can be used to stage cheats into the VM.",
                            Detail = $"Shortcut: {lnkFile}"
                        });
                    }
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVMSnapshotArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] snapshotExtensions = new[] { "*.vmss", "*.vmsn", "*.avhd", "*.avhdx", "*.sav" };
        string[] searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
        };

        foreach (string searchDir in searchDirs)
        {
            if (!Directory.Exists(searchDir)) continue;
            foreach (string snapshotPattern in snapshotExtensions)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (string snapshotFile in Directory.GetFiles(searchDir, snapshotPattern, SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VM Snapshot File Found: {Path.GetFileName(snapshotFile)}",
                            Risk = RiskLevel.Critical,
                            Location = snapshotFile,
                            FileName = Path.GetFileName(snapshotFile),
                            Reason = "VM snapshot file found. Snapshots are a primary ban evasion technique: players snapshot a clean VM state and instantly revert to it after receiving a ban, creating an unlimited supply of clean identities.",
                            Detail = $"Snapshot file: {snapshotFile} | Extension: {Path.GetExtension(snapshotFile)}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVMDiskImageFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] diskImageExtensions = new[] { "*.vmdk", "*.vdi", "*.vhd", "*.vhdx", "*.qcow2", "*.ova", "*.ovf" };
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads")
        };

        foreach (string searchDir in searchDirs)
        {
            if (!Directory.Exists(searchDir)) continue;
            foreach (string diskPattern in diskImageExtensions)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (string diskFile in Directory.GetFiles(searchDir, diskPattern, SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VM Disk Image File Found: {Path.GetFileName(diskFile)}",
                            Risk = RiskLevel.High,
                            Location = diskFile,
                            FileName = Path.GetFileName(diskFile),
                            Reason = "VM disk image file found. Disk images store complete virtual machine identities and can be deployed to create fresh ban-evading instances with unique hardware profiles.",
                            Detail = $"Path: {diskFile} | Format: {Path.GetExtension(diskFile).TrimStart('.').ToUpperInvariant()}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVMwareToolsHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var vmwareToolsKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\VMware, Inc.\VMware Tools", writable: false);
            ctx.IncrementRegistryKeys();
            if (vmwareToolsKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "VMware Tools Installation Key Found",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
                    FileName = null,
                    Reason = "VMware Tools registry key found. VMware Tools are installed inside VMware guest VMs, confirming this system has operated as a VMware virtual machine.",
                    Detail = @"Registry key: HKLM\SOFTWARE\VMware, Inc.\VMware Tools"
                });
            }
        }
        catch { }

        try
        {
            string vmwareProgramData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VMware");
            if (Directory.Exists(vmwareProgramData))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "VMware ProgramData Directory Found",
                    Risk = RiskLevel.Medium,
                    Location = vmwareProgramData,
                    FileName = "VMware",
                    Reason = "VMware application data directory found in ProgramData. This directory contains VMware Tools logs and configuration indicating past VM guest operation.",
                    Detail = $"Path: {vmwareProgramData}"
                });
            }
        }
        catch { }

        try
        {
            string[] startupPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup))
            };

            foreach (string startupPath in startupPaths)
            {
                if (!Directory.Exists(startupPath)) continue;
                foreach (string startupFile in Directory.GetFiles(startupPath))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    if (Path.GetFileName(startupFile).Contains("vmtoolsd", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "VMware Tools Startup Entry Found",
                            Risk = RiskLevel.Medium,
                            Location = startupFile,
                            FileName = Path.GetFileName(startupFile),
                            Reason = "VMware Tools daemon startup entry found. vmtoolsd.exe is the VMware Tools service and its presence in startup confirms this is a VMware guest.",
                            Detail = $"Startup file: {startupFile}"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] searchPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads")
            };

            foreach (string searchPath in searchPaths)
            {
                if (!Directory.Exists(searchPath)) continue;
                try
                {
                    foreach (string zipFile in Directory.GetFiles(searchPath, "vm-support*.zip", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VMware Support Bundle Found: {Path.GetFileName(zipFile)}",
                            Risk = RiskLevel.Medium,
                            Location = zipFile,
                            FileName = Path.GetFileName(zipFile),
                            Reason = "VMware vm-support diagnostic bundle found. These bundles are generated inside VMware guests and contain detailed VM configuration information.",
                            Detail = $"Bundle: {zipFile}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckBanEvasionVMConfig(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
        };

        foreach (string searchDir in searchDirs)
        {
            if (!Directory.Exists(searchDir)) continue;
            try
            {
                foreach (string vmxFile in Directory.GetFiles(searchDir, "*.vmx", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string fileNameLower = Path.GetFileNameWithoutExtension(vmxFile).ToLowerInvariant();
                    if (fileNameLower.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        fileNameLower.Contains("evasion", StringComparison.OrdinalIgnoreCase) ||
                        fileNameLower.Contains("ban", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious VM Config Filename: {Path.GetFileName(vmxFile)}",
                            Risk = RiskLevel.Critical,
                            Location = vmxFile,
                            FileName = Path.GetFileName(vmxFile),
                            Reason = "VMware configuration file with ban evasion-related name found. The filename explicitly references bypass or evasion techniques.",
                            Detail = $"File: {vmxFile}"
                        });
                        continue;
                    }

                    try
                    {
                        using var fs = new FileStream(vmxFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (string keyword in BanEvasionVMConfigKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Ban Evasion VM Config Setting Found: {keyword}",
                                    Risk = RiskLevel.Critical,
                                    Location = vmxFile,
                                    FileName = Path.GetFileName(vmxFile),
                                    Reason = $"VMware config file contains anti-detection setting '{keyword}'. This setting is specifically used to hide the VM from anti-cheat software, confirming deliberate ban evasion configuration.",
                                    Detail = $"File: {vmxFile} | Keyword: {keyword}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVMSpoofingTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] searchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp")
        };

        foreach (string searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (string toolName in VMSpoofingTools)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    string fullPath = Path.Combine(searchPath, toolName);
                    if (File.Exists(fullPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VM Detection Spoofing Tool Found: {toolName}",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = toolName,
                            Reason = $"VM detection bypass tool '{toolName}' found. These tools specifically defeat anti-cheat VM detection checks, enabling cheats inside VMs that would otherwise be blocked.",
                            Detail = $"Path: {fullPath}"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            using var acpiKey = Registry.LocalMachine.OpenSubKey(@"HARDWARE\ACPI\DSDT", writable: false);
            ctx.IncrementRegistryKeys();
            if (acpiKey is not null)
            {
                string[] subKeys = acpiKey.GetSubKeyNames();
                foreach (string subKey in subKeys)
                {
                    if (ct.IsCancellationRequested) return;
                    if (subKey.Contains("VBOX", StringComparison.OrdinalIgnoreCase) ||
                        subKey.Contains("VMWARE", StringComparison.OrdinalIgnoreCase) ||
                        subKey.Contains("BOCHS", StringComparison.OrdinalIgnoreCase) ||
                        subKey.Contains("QEMU", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Spoofed ACPI DSDT Table Found: {subKey}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\HARDWARE\ACPI\DSDT\{subKey}",
                            FileName = null,
                            Reason = $"ACPI DSDT table with VM vendor name '{subKey}' found. VM ACPI tables are a primary fingerprint used by anti-cheat systems; their presence confirms VM-based operation.",
                            Detail = $"DSDT OEM ID: {subKey}"
                        });
                    }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckParallelDesktopArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var parallelsKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Parallels", writable: false);
            ctx.IncrementRegistryKeys();
            if (parallelsKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Parallels Desktop Registry Key Found",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\Parallels",
                    FileName = null,
                    Reason = "Parallels Desktop registry key found. Parallels enables macOS users to run a Windows VM for gaming, then ban-evade by recreating the Windows VM with a fresh identity.",
                    Detail = @"Registry key: HKLM\SOFTWARE\Parallels"
                });
            }
        }
        catch { }

        string[] parallelsServiceNames = new[] { "prl_tools", "prl_fs", "prl_memdev", "prl_tg", "prl_pv32" };
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is not null)
            {
                foreach (string svcName in parallelsServiceNames)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (svcKey is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Parallels Service Artifact: {svcName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = null,
                                Reason = $"Parallels Tools service '{svcName}' found. Parallels Tools are installed inside Parallels Desktop VMs confirming VM guest operation.",
                                Detail = $"Service: {svcName}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}", writable: false);
            if (classKey is not null)
            {
                foreach (string subKeyName in classKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var adapterKey = classKey.OpenSubKey(subKeyName, writable: false);
                        if (adapterKey is null) continue;
                        string driverDesc = (adapterKey.GetValue("DriverDesc") as string) ?? string.Empty;
                        if (driverDesc.Contains("Parallels", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementRegistryKeys();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Parallels Network Adapter Found: {driverDesc}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Class\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{subKeyName}",
                                FileName = null,
                                Reason = $"Parallels virtual network adapter '{driverDesc}' found. This confirms a Parallels Desktop virtual machine environment.",
                                Detail = $"DriverDesc: {driverDesc}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckSandboxEnvironmentArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] sandboxRegKeys = new[]
        {
            @"SOFTWARE\Sandboxie",
            @"SOFTWARE\Sandboxie Plus",
            @"SYSTEM\CurrentControlSet\Services\SbieDrv"
        };

        foreach (string regKey in sandboxRegKeys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regKey, writable: false);
                ctx.IncrementRegistryKeys();
                if (key is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Sandboxie Registry Key Found",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{regKey}",
                        FileName = null,
                        Reason = "Sandboxie sandbox environment key found in registry. Sandboxie can be used to run cheats in an isolated sandbox preventing detection and ban propagation.",
                        Detail = $"Registry key: HKLM\\{regKey}"
                    });
                }
            }
            catch { }
        }

        string sbieDriverPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "SbieDrv.sys");
        try
        {
            if (File.Exists(sbieDriverPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Sandboxie Driver File Found",
                    Risk = RiskLevel.High,
                    Location = sbieDriverPath,
                    FileName = "SbieDrv.sys",
                    Reason = "Sandboxie driver file SbieDrv.sys found. The presence of the Sandboxie kernel driver confirms sandbox environment usage.",
                    Detail = $"Path: {sbieDriverPath}"
                });
            }
        }
        catch { }

        string[] cuckooMarkers = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "cuckoo.dll"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cuckoo.dll")
        };

        foreach (string marker in cuckooMarkers)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                if (File.Exists(marker))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cuckoo Sandbox Marker Found",
                        Risk = RiskLevel.High,
                        Location = marker,
                        FileName = Path.GetFileName(marker),
                        Reason = "Cuckoo sandbox marker file found. Cuckoo is an automated malware/cheat analysis sandbox that can be used to test cheat behavior in an isolated environment.",
                        Detail = $"Path: {marker}"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRemoteGamingStreamArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var rdpKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Terminal Server Client\Default", writable: false);
            ctx.IncrementRegistryKeys();
            if (rdpKey is not null)
            {
                string[] rdpValues = rdpKey.GetValueNames();
                if (rdpValues.Length > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Remote Desktop Connection History Found ({rdpValues.Length} entries)",
                        Risk = RiskLevel.Medium,
                        Location = @"HKCU\Software\Microsoft\Terminal Server Client\Default",
                        FileName = null,
                        Reason = $"RDP connection history found with {rdpValues.Length} entries. Playing games via Remote Desktop from a different machine is a ban evasion technique that routes traffic through a clean system.",
                        Detail = $"First entry: {(rdpValues.Length > 0 ? rdpKey.GetValue(rdpValues[0]) as string : string.Empty)}"
                    });
                }
            }
        }
        catch { }

        string[] cloudGamingPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NVIDIA", "GeForceNOW"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GeForceNow")
        };

        foreach (string cloudPath in cloudGamingPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                if (Directory.Exists(cloudPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "GeForce NOW Cloud Gaming Artifacts Found",
                        Risk = RiskLevel.Medium,
                        Location = cloudPath,
                        FileName = "GeForceNOW",
                        Reason = "GeForce NOW cloud gaming cache found. Cloud gaming services run games on remote servers, potentially bypassing local hardware bans by using cloud server identifiers.",
                        Detail = $"Path: {cloudPath}"
                    });
                }
            }
            catch { }
        }

        try
        {
            string xboxCloudPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Packages");
            if (Directory.Exists(xboxCloudPath))
            {
                foreach (string pkgDir in Directory.GetDirectories(xboxCloudPath, "Microsoft.GamingApp*"))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Xbox Cloud Gaming Package Found",
                        Risk = RiskLevel.Medium,
                        Location = pkgDir,
                        FileName = Path.GetFileName(pkgDir),
                        Reason = "Xbox Cloud Gaming (xCloud) application package found. Cloud gaming bypasses hardware bans by running games on Microsoft servers with non-banned identifiers.",
                        Detail = $"Package directory: {pkgDir}"
                    });
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckWSLCheatArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var lxssKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Lxss", writable: false);
            ctx.IncrementRegistryKeys();
            if (lxssKey is not null)
            {
                string[] distroKeys = lxssKey.GetSubKeyNames();
                foreach (string distroKey in distroKeys)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var distro = lxssKey.OpenSubKey(distroKey, writable: false);
                        if (distro is null) continue;
                        string distroName = (distro.GetValue("DistributionName") as string) ?? string.Empty;
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"WSL Distro Found: {distroName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss\{distroKey}",
                            FileName = null,
                            Reason = $"WSL Linux distribution '{distroName}' found. WSL can be used to compile cheat source code and develop cheat tools without leaving Windows-visible traces.",
                            Detail = $"Distribution: {distroName} | Key: {distroKey}"
                        });
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string packagesPath = Path.Combine(localAppData, "Packages");
            if (Directory.Exists(packagesPath))
            {
                foreach (string canonicalDir in Directory.GetDirectories(packagesPath, "CanonicalGroup*"))
                {
                    if (ct.IsCancellationRequested) return;
                    string rootfsPath = Path.Combine(canonicalDir, "LocalState", "rootfs");
                    if (Directory.Exists(rootfsPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "WSL Ubuntu Root Filesystem Found",
                            Risk = RiskLevel.High,
                            Location = rootfsPath,
                            FileName = "rootfs",
                            Reason = "WSL Ubuntu root filesystem found. This Linux environment can contain compiled cheat binaries, source code, build tools, and Python-based cheat scripts not visible to Windows scanners.",
                            Detail = $"WSL rootfs: {rootfsPath}"
                        });

                        string[] cheatIndicators = new[]
                        {
                            Path.Combine(rootfsPath, "home"),
                            Path.Combine(rootfsPath, "tmp"),
                            Path.Combine(rootfsPath, "root")
                        };

                        foreach (string cheatDir in cheatIndicators)
                        {
                            if (!Directory.Exists(cheatDir)) continue;
                            try
                            {
                                foreach (string cFile in Directory.GetFiles(cheatDir, "*.c", SearchOption.AllDirectories))
                                {
                                    if (ct.IsCancellationRequested) return;
                                    ctx.IncrementFiles();
                                    string cFileName = Path.GetFileNameWithoutExtension(cFile).ToLowerInvariant();
                                    if (cFileName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                        cFileName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                        cFileName.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                                        cFileName.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                                        cFileName.Contains("wallhack", StringComparison.OrdinalIgnoreCase))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = $"Suspicious C Source File in WSL: {Path.GetFileName(cFile)}",
                                            Risk = RiskLevel.High,
                                            Location = cFile,
                                            FileName = Path.GetFileName(cFile),
                                            Reason = "C source file with cheat-related name found inside WSL filesystem. Cheat developers use WSL's GCC compiler to build Windows cheats from Linux-side source code.",
                                            Detail = $"WSL source file: {cFile}"
                                        });
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDockerCheatContainerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var dockerKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Docker Inc.", writable: false);
            ctx.IncrementRegistryKeys();
            if (dockerKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Docker Desktop Registry Key Found",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\Docker Inc.",
                    FileName = null,
                    Reason = "Docker Desktop installation found. Docker containers provide isolated environments for testing cheats without affecting the host system's detection fingerprint.",
                    Detail = @"Registry key: HKLM\SOFTWARE\Docker Inc."
                });
            }
        }
        catch { }

        try
        {
            string dockerProgramDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Docker");
            if (Directory.Exists(dockerProgramDataPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Docker ProgramData Directory Found",
                    Risk = RiskLevel.Medium,
                    Location = dockerProgramDataPath,
                    FileName = "Docker",
                    Reason = "Docker application data directory found. Docker enables cheat container isolation and reproducible cheat testing environments.",
                    Detail = $"Path: {dockerProgramDataPath}"
                });
            }
        }
        catch { }

        try
        {
            string dockerConfigPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".docker", "config.json");
            if (File.Exists(dockerConfigPath))
            {
                ctx.IncrementFiles();
                using var fs = new FileStream(dockerConfigPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                if (content.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("bypass", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Suspicious Docker Config Content Found",
                        Risk = RiskLevel.Medium,
                        Location = dockerConfigPath,
                        FileName = "config.json",
                        Reason = "Docker config file contains suspicious keywords related to cheating or bypassing. This may indicate Docker was used to host cheat testing containers.",
                        Detail = $"Path: {dockerConfigPath}"
                    });
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVMwareRecentMRU(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] vmExtensions = new[] { ".vmx", ".vmdk", ".vmss", ".vmsn", ".vmem" };

        try
        {
            using var recentDocsKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs", writable: false);
            ctx.IncrementRegistryKeys();
            if (recentDocsKey is not null)
            {
                foreach (string ext in vmExtensions)
                {
                    if (ct.IsCancellationRequested) return;
                    string extKey = ext.TrimStart('.');
                    try
                    {
                        using var extSubKey = recentDocsKey.OpenSubKey("." + extKey, writable: false);
                        if (extSubKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        byte[]? mruListData = extSubKey.GetValue("MRUListEx") as byte[];
                        if (mruListData is not null && mruListData.Length > 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VM File MRU Entry Found: {ext}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.{extKey}",
                                FileName = null,
                                Reason = $"Windows recently-opened document MRU list contains {ext} VM file entries. MRU lists persist even after the VM files are deleted, proving past VM usage.",
                                Detail = $"Extension: {ext} | MRU data length: {mruListData.Length} bytes"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            using var vmwareWorkstationKey = Registry.CurrentUser.OpenSubKey(
                @"Software\VMware, Inc.\VMware Workstation\Recently Opened VMs", writable: false);
            ctx.IncrementRegistryKeys();
            if (vmwareWorkstationKey is not null)
            {
                string[] valueNames = vmwareWorkstationKey.GetValueNames();
                foreach (string valueName in valueNames)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        string vmPath = (vmwareWorkstationKey.GetValue(valueName) as string) ?? string.Empty;
                        if (!string.IsNullOrEmpty(vmPath))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VMware Workstation Recent VM: {Path.GetFileName(vmPath)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\Software\VMware, Inc.\VMware Workstation\Recently Opened VMs",
                                FileName = Path.GetFileName(vmPath),
                                Reason = $"VMware Workstation recently opened VM '{vmPath}' found in MRU. This confirms active VM usage and retains the path even if the VM was later deleted.",
                                Detail = $"VM path: {vmPath}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVMCloneArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)
        };

        foreach (string searchDir in searchDirs)
        {
            if (!Directory.Exists(searchDir)) continue;

            try
            {
                string[] vmxFiles = Directory.GetFiles(searchDir, "*.vmx", SearchOption.AllDirectories);
                string[] cloneVmxFiles = vmxFiles.Where(f =>
                    Path.GetFileNameWithoutExtension(f).Contains("clone", StringComparison.OrdinalIgnoreCase) ||
                    Path.GetFileNameWithoutExtension(f).Contains("evasion", StringComparison.OrdinalIgnoreCase) ||
                    Path.GetFileNameWithoutExtension(f).Contains("fresh", StringComparison.OrdinalIgnoreCase) ||
                    Path.GetFileNameWithoutExtension(f).Contains("new", StringComparison.OrdinalIgnoreCase)
                ).ToArray();

                foreach (string cloneFile in cloneVmxFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"VM Clone Config File Found: {Path.GetFileName(cloneFile)}",
                        Risk = RiskLevel.Critical,
                        Location = cloneFile,
                        FileName = Path.GetFileName(cloneFile),
                        Reason = "VMware config file with clone/evasion/fresh naming pattern found. Cloned VMs are created to generate multiple distinct hardware identities from one base VM for sequential ban evasion.",
                        Detail = $"Clone file: {cloneFile}"
                    });
                }

                string[] vmdkFiles = Directory.GetFiles(searchDir, "*.vmdk", SearchOption.AllDirectories);
                var sequentialVmdks = vmdkFiles
                    .Where(f =>
                    {
                        string nameWithoutExt = Path.GetFileNameWithoutExtension(f).ToLowerInvariant();
                        return nameWithoutExt.Contains("clone", StringComparison.OrdinalIgnoreCase) ||
                               System.Text.RegularExpressions.Regex.IsMatch(nameWithoutExt, @"\d+$");
                    })
                    .ToList();

                if (sequentialVmdks.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Multiple Sequential VM Disk Images Found ({sequentialVmdks.Count} files)",
                        Risk = RiskLevel.Critical,
                        Location = searchDir,
                        FileName = null,
                        Reason = $"Found {sequentialVmdks.Count} VMDK files with sequential or clone naming pattern. Multiple numbered VM disk images indicate systematic VM cloning for generating fresh identities after each ban.",
                        Detail = $"Files: {string.Join(", ", sequentialVmdks.Select(Path.GetFileName).Take(5))}"
                    });
                }
            }
            catch { }

            try
            {
                string[] vdiFiles = Directory.GetFiles(searchDir, "*.vdi", SearchOption.AllDirectories);
                var cloneVdiFiles = vdiFiles
                    .Where(f =>
                    {
                        string nameWithoutExt = Path.GetFileNameWithoutExtension(f).ToLowerInvariant();
                        return nameWithoutExt.Contains("clone", StringComparison.OrdinalIgnoreCase) ||
                               nameWithoutExt.Contains("evasion", StringComparison.OrdinalIgnoreCase) ||
                               System.Text.RegularExpressions.Regex.IsMatch(nameWithoutExt, @"\d+$");
                    })
                    .ToList();

                if (cloneVdiFiles.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Multiple VirtualBox Clone Disk Images Found ({cloneVdiFiles.Count} files)",
                        Risk = RiskLevel.Critical,
                        Location = searchDir,
                        FileName = null,
                        Reason = $"Found {cloneVdiFiles.Count} VDI disk image files with clone or sequential naming. Multiple VDI clones are a direct indicator of identity farming for ban evasion.",
                        Detail = $"Files: {string.Join(", ", cloneVdiFiles.Select(Path.GetFileName).Take(5))}"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);
}
