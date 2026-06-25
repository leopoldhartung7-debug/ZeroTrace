using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class VirtualMachineCheatBypassScanModule : IScanModule
{
    public string Name => "Virtual Machine Cheat Bypass Detection";
    public double Weight => 3.9;
    public int ParallelGroup => 4;

    private static readonly string[] VmSoftwareNames =
    [
        "vmware.exe", "vmware-vmx.exe", "vmware-tray.exe", "vmplayer.exe",
        "vmware-hostd.exe", "vmware-authd.exe", "vmware-netcfg.exe",
        "VirtualBox.exe", "VirtualBoxVM.exe", "VBoxHeadless.exe",
        "VBoxManage.exe", "VBoxSVC.exe", "VBoxTray.exe",
        "QEMU.exe", "qemu-system-x86_64.exe", "qemu-system-i386.exe",
        "HyperV.exe", "vmms.exe", "hvhost.exe",
        "Parallels.exe", "prl_cc.exe", "prl_vm_app.exe",
        "UTM.exe", "utm.exe",
        "bochs.exe", "DOSBox.exe",
        "virt-manager.exe", "virt-viewer.exe",
        "xenserver.exe", "xen.exe",
    ];

    private static readonly string[] VmCheatTechniqueFiles =
    [
        "vm_bypass.exe", "vmbypass.exe", "vm_escape.exe",
        "sandbox_bypass.exe", "sandboxbypass.exe", "sandbox_escape.exe",
        "vbox_bypass.exe", "vmware_bypass.exe", "hyperv_bypass.exe",
        "vm_detect_bypass.exe", "anti_vm_bypass.exe", "antivm.exe",
        "vm_cheat.exe", "vm_aimbot.exe", "vm_esp.exe",
        "external_vm.exe", "vm_external.exe", "vmexternal.exe",
        "second_pc_cheat.exe", "second_monitor_cheat.exe",
        "kvm_cheat.exe", "qemu_cheat.exe", "hyperv_cheat.exe",
        "vm_inject.exe", "vm_injector.exe", "vminjector.exe",
        "vm_radar.exe", "vmradar.exe", "vm_map.exe",
        "vm_overlay.exe", "vmoverlay.exe", "ext_overlay.exe",
        "cross_vm_cheat.exe", "vm_bridge.exe", "vmbridge.exe",
        "vm_memory_reader.exe", "vm_mem_read.exe",
        "virtio_cheat.exe", "shared_memory_cheat.exe",
        "ivshmem_cheat.exe", "looking_glass_cheat.exe",
        "vfio_cheat.exe", "gpu_passthrough_cheat.exe",
    ];

    private static readonly string[] VmConfigKeywords =
    [
        "vm_bypass", "sandbox_bypass", "antivirus_sandbox",
        "detect_vm", "detect_sandbox", "is_vm", "is_sandbox",
        "vmware_detect", "vbox_detect", "hyperv_detect",
        "cpuid_spoof", "cpuid_bypass", "rdtsc_bypass",
        "vm_artifact_clean", "registry_clean_vm",
        "kvm_hidden", "qemu_hidden", "vbox_hidden",
        "vmware_hidden", "hypervisor_hidden", "hypervisor_bypass",
        "vfio_passthrough", "gpu_passthrough", "looking_glass",
        "ivshmem", "shared_mem_cheat", "vm_shared_memory",
        "second_pc", "external_monitor", "second_screen_cheat",
        "vm_external_cheat", "external_vm_cheat",
        "virt_cheat", "kvm_cheat", "xen_cheat",
    ];

    private static readonly string[] VmArtifactRegistryPaths =
    [
        @"SOFTWARE\VMware, Inc.\VMware Tools",
        @"SOFTWARE\VMware, Inc.\VMware Workstation",
        @"SOFTWARE\Oracle\VirtualBox Guest Additions",
        @"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
        @"SYSTEM\CurrentControlSet\Services\VBoxGuest",
        @"SYSTEM\CurrentControlSet\Services\VBoxMouse",
        @"SYSTEM\CurrentControlSet\Services\VBoxSF",
        @"SYSTEM\CurrentControlSet\Services\VBoxVideo",
        @"SYSTEM\CurrentControlSet\Services\vmhgfs",
        @"SYSTEM\CurrentControlSet\Services\vmmouse",
        @"SYSTEM\CurrentControlSet\Services\vmci",
        @"SYSTEM\CurrentControlSet\Services\vmx86",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>
        {
            ScanVmSoftwareAsync(ctx, ct),
            ScanVmCheatTechniqueFilesAsync(ctx, ct),
            ScanVmConfigFilesAsync(ctx, ct),
            ScanVmRegistryAsync(ctx, ct),
            ScanVmProcessesAsync(ctx, ct),
            ScanLookingGlassArtifactsAsync(ctx, ct),
            ScanGpuPassthroughArtifactsAsync(ctx, ct),
            ScanVmNetworkShareArtifactsAsync(ctx, ct),
        };
        await Task.WhenAll(tasks);
    }

    private async Task ScanVmSoftwareAsync(ScanContext ctx, CancellationToken ct)
    {
        // VM software in program files — not suspicious alone, but flag when combined with cheat artifacts
        var vmPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "VMware"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Oracle", "VirtualBox"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "VMware"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Oracle", "VirtualBox"),
        };

        foreach (var vmPath in vmPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(vmPath)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Virtualization Software Installed",
                Risk = Risk.Medium,
                Location = vmPath,
                FileName = Path.GetFileName(vmPath),
                Reason = $"Virtualization software at '{vmPath}' — may be used for VM-based cheat bypass",
                Detail = "Some cheats run in a VM while the game runs on the host, bypassing anti-cheat that scans the game process host"
            });
        }
        await Task.CompletedTask;
    }

    private async Task ScanVmCheatTechniqueFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (VmCheatTechniqueFiles.Any(v => fn.Equals(v, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VM-Based Cheat Tool",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"VM-based cheat bypass tool '{fn}' found",
                        Detail = "VM-based cheats run the cheat in an isolated VM to evade anti-cheat scanning"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanVmConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath(),
        };

        foreach (var dir in configDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".ini" && ext != ".cfg" && ext != ".json" && ext != ".txt" &&
                    ext != ".vmx" && ext != ".vbox") continue;

                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var hits = VmConfigKeywords.Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)).ToList();
                if (hits.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VM Cheat Bypass Configuration",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Config file contains {hits.Count} VM cheat bypass keywords",
                        Detail = "Keywords: " + string.Join(", ", hits.Take(6))
                    });
                }

                // VMX files with cheat-related parameters
                if (ext == ".vmx" || ext == ".vbox")
                {
                    if (content.Contains("CPUID.0.eax", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("hypervisor.cpuid.v0 = \"FALSE\"", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("monitor_control.disable_acpi = TRUE", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "VM Config with Anti-Detection Settings",
                            Risk = Risk.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "VM configuration file has CPUID/hypervisor spoofing settings",
                            Detail = "Modified VMX/VBOX configs hide VM presence from anti-cheat detection"
                        });
                    }
                }
            }
        }
    }

    private async Task ScanVmRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check for VM guest additions — indicates running inside a VM
            foreach (var vmPath in VmArtifactRegistryPaths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(vmPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    // This is informational — running inside a VM
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Virtual Machine Guest Detected",
                        Risk = Risk.High,
                        Location = $@"HKLM\{vmPath}",
                        FileName = "Registry",
                        Reason = $"VM guest components detected at {vmPath} — system may be running inside a VM",
                        Detail = "Some cheats run the game inside a VM to evade anti-cheat hardware fingerprinting"
                    });
                    break;
                }
                catch { }
            }

            // Check for IVSHMEM driver (used for VM-to-host shared memory cheats)
            try
            {
                using var ivshmem = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\ivshmem");
                if (ivshmem != null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "IVSHMEM Shared Memory Driver",
                        Risk = Risk.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\ivshmem",
                        FileName = "Registry",
                        Reason = "IVSHMEM (Inter-VM Shared Memory) driver installed — used by VM-based cheats for host-VM data transfer",
                        Detail = "IVSHMEM enables cheats to read game memory from a VM and render overlay on host"
                    });
                }
            }
            catch { }

            // Looking Glass KVMFR driver (VM gaming with external display)
            try
            {
                using var kvmfr = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\kvmfr");
                if (kvmfr != null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Looking Glass KVMFR Driver",
                        Risk = Risk.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\kvmfr",
                        FileName = "Registry",
                        Reason = "Looking Glass KVMFR framebuffer driver installed — used for VM gaming with GPU passthrough",
                        Detail = "Looking Glass streams VM display to host; combined with external cheat process enables AC bypass"
                    });
                }
            }
            catch { }

            // VFIO driver for GPU passthrough
            try
            {
                using var vfio = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\vfio-pci");
                if (vfio != null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VFIO GPU Passthrough Driver",
                        Risk = Risk.Medium,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\vfio-pci",
                        FileName = "Registry",
                        Reason = "VFIO PCI passthrough driver installed — enables GPU passthrough for VM gaming",
                        Detail = "GPU passthrough VMs run games at native performance; external cheat process bypasses AC"
                    });
                }
            }
            catch { }
        }, ct);
    }

    private async Task ScanVmProcessesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var processes = ctx.GetProcessSnapshot();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();
                var pname = proc.ProcessName + ".exe";

                if (VmSoftwareNames.Any(v => pname.Equals(v, StringComparison.OrdinalIgnoreCase)))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Virtualization Software Running",
                        Risk = Risk.Medium,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Virtualization software '{pname}' is running during game session",
                        Detail = $"PID: {proc.Id} — VM software running concurrently with games may indicate VM-based cheat"
                    });
                }

                if (VmCheatTechniqueFiles.Any(v => pname.Equals(v, StringComparison.OrdinalIgnoreCase)))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VM Cheat Tool Running",
                        Risk = Risk.Critical,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"VM-based cheat tool '{pname}' is currently running",
                        Detail = $"PID: {proc.Id}"
                    });
                }
            }
        }, ct);
    }

    private async Task ScanLookingGlassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        // Looking Glass software artifacts
        var lgPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Looking Glass"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "looking-glass-client"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "looking-glass-client"),
        };

        foreach (var lgPath in lgPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(lgPath)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Looking Glass VM Display Software",
                Risk = Risk.High,
                Location = lgPath,
                FileName = Path.GetFileName(lgPath),
                Reason = "Looking Glass VM-to-host display streaming software found",
                Detail = "Looking Glass streams a VM's display to the host machine; enables AC bypass via VM isolation"
            });
        }

        // Looking Glass config file
        var lgConfig = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "looking-glass-client", "looking-glass-client.ini");
        if (File.Exists(lgConfig))
        {
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Looking Glass Configuration Found",
                Risk = Risk.High,
                Location = lgConfig,
                FileName = "looking-glass-client.ini",
                Reason = "Looking Glass configuration file present",
                Detail = "Looking Glass is used in 'VM gaming' setups that can host cheats on the VM while streaming to host"
            });
        }
        await Task.CompletedTask;
    }

    private async Task ScanGpuPassthroughArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        // GPU passthrough setup files
        var passthroughFiles = new[]
        {
            "vfio.conf", "vfio-pci.cfg", "gpu-passthrough.xml",
            "passthrough.xml", "vm-passthrough.conf", "kvm-passthrough.sh",
            "gpu_passthrough.bat", "passthrough.bat",
        };

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file);
                if (passthroughFiles.Any(p => fn.Equals(p, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "GPU Passthrough Configuration",
                        Risk = Risk.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"GPU passthrough config '{fn}' found — indicates VM gaming setup",
                        Detail = "GPU passthrough allows running games in a VM at native GPU performance for AC bypass"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanVmNetworkShareArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Shared folders between VM and host (used to transfer cheat configs)
            var sharedFolderKeys = new[]
            {
                @"SOFTWARE\Oracle\VirtualBox\SharedFolders",
                @"SOFTWARE\VMware, Inc.\VMware Tools\SharedFolders",
            };

            foreach (var sfKey in sharedFolderKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(sfKey) ??
                                    Registry.CurrentUser.OpenSubKey(sfKey);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var shareName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var shareKey = key.OpenSubKey(shareName);
                            ctx.IncrementRegistryKeys();
                            var path = shareKey?.GetValue("Path") as string ?? string.Empty;
                            if (path.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                path.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                path.Contains("bypass", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "VM Shared Folder with Cheat Path",
                                    Risk = Risk.Critical,
                                    Location = $@"HKLM\{sfKey}\{shareName}",
                                    FileName = "Registry",
                                    Reason = $"VM shared folder '{shareName}' points to path with cheat keyword: {path}",
                                    Detail = "Shared folders transfer cheat tools and configs between VM and host"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }, ct);
    }
}
