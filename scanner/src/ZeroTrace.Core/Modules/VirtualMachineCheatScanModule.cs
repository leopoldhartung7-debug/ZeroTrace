using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class VirtualMachineCheatScanModule : IScanModule
{
    public string Name => "VM-Cheat";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    private static readonly string[] KnownGameProcessNames =
    {
        "gta5", "fivem", "cs2", "csgo", "valorant-win64-shipping",
        "rustclient", "rust", "r5apex",
    };

    private static readonly string[] VmwareProcessNames =
    {
        "vmware", "vmplayer", "vmrun", "vmnat", "vmnetdhcp",
    };

    private static readonly string[] VirtualBoxProcessNames =
    {
        "virtualbox", "vboxheadless", "vboxmanage", "vboxsvc",
    };

    private static readonly string[] HyperVProcessNames =
    {
        "vmconnect", "vmcomputeservice",
    };

    private static readonly string[] QemuProcessNames =
    {
        "qemu-system-x86_64", "qemu-img",
    };

    private static readonly string[] ParallelsProcessNames =
    {
        "prl_cc", "prl_tools",
    };

    private static readonly string[] SandboxieProcessNames =
    {
        "sandboxierpcss", "sbiesvc", "start",
    };

    private static readonly string[] DockerProcessNames =
    {
        "dockerd", "docker desktop",
    };

    private static readonly string[] RemoteAccessProcessNames =
    {
        "mstsc", "anydesk", "nxplayer", "parsecd", "teamviewer",
    };

    private static readonly string[] DmaCheatExeNames =
    {
        "dma_tool.exe", "dma_cheat.exe", "pcileech.exe", "pcileech_fpga.exe", "screenshotcheat.exe",
    };

    private static readonly string[] DmaConfigFileNames =
    {
        "dma_config.json", "dma_settings.ini", "dma_offsets.json",
    };

    private static readonly string[] VmDiskExtensions =
    {
        ".vmdk", ".vdi", ".vhd", ".vhdx",
    };

    private static readonly string[] GameNamedVmDiskPatterns =
    {
        "rust_vm", "gta_vm", "cs2_vm", "fivem_vm", "apex_vm", "valorant_vm",
        "rust", "gta", "cs2", "fivem", "apex",
    };

    private static readonly string[] VmwareServiceNames =
    {
        "VMwareTools", "vmvss", "vmscsi", "vmmouse",
    };

    private static readonly string[] VirtualBoxServiceNames =
    {
        "VBoxDrv", "VBoxUSBMon", "VBoxNetAdp", "VBoxNetFlt",
    };

    private static readonly string[] HyperVServiceNames =
    {
        "vmbus", "vmicheartbeat", "vmicshutdown",
    };

    private static readonly string[] VmBiosManufacturerKeywords =
    {
        "VMware", "VirtualBox", "QEMU", "Xen", "Microsoft Corporation", "Parallels",
    };

    private static readonly string[] VmBiosProductKeywords =
    {
        "Virtual", "VMware", "VirtualBox", "HVM", "KVM",
    };

    private static readonly string[] VmScsiIdentifierKeywords =
    {
        "VBOX", "VMWARE", "QEMU",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ctx.Report(0.0, Name, "Scanning for VM software installations...");
            ScanVmSoftwareInstalls(ctx, ct);

            ctx.Report(0.18, Name, "Scanning VM hardware/BIOS signatures...");
            ScanVmHardwareSignatures(ctx, ct);

            ctx.Report(0.32, Name, "Scanning VM services in registry...");
            ScanVmServices(ctx, ct);

            ctx.Report(0.44, Name, "Scanning for VM disk images in unusual locations...");
            ScanVmDiskImages(ctx, ct);

            ctx.Report(0.56, Name, "Scanning sandbox and container tools...");
            ScanSandboxAndContainerTools(ctx, ct);

            ctx.Report(0.68, Name, "Scanning remote access and VM streaming indicators...");
            ScanRemoteAccessAndStreaming(ctx, ct);

            ctx.Report(0.80, Name, "Scanning for DMA cheat infrastructure...");
            ScanDmaCheatInfrastructure(ctx, ct);

            ctx.Report(0.92, Name, "Scanning running processes for VM and cheat correlation...");
            ScanRunningProcesses(ctx, ct);

            ctx.Report(1.0, Name, "VM cheat scan complete.");
        }, ct);
    }

    private static void ScanVmSoftwareInstalls(ScanContext ctx, CancellationToken ct)
    {
        CheckVmwareInstall(ctx, ct);
        CheckVirtualBoxInstall(ctx, ct);
        CheckHyperVInstall(ctx, ct);
        CheckQemuInstall(ctx, ct);
        CheckParallelsInstall(ctx, ct);
    }

    private static void CheckVmwareInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var vmwareDirs = new[]
        {
            Path.Combine(programFiles, "VMware"),
            Path.Combine(programFilesX86, "VMware"),
        };

        foreach (var dir in vmwareDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = $"VMware Workstation/Player installation: {dir}",
                Risk = RiskLevel.Medium,
                Location = dir,
                FileName = "VMware",
                Reason = $"VMware virtualization software installation found at '{dir}'. " +
                         "Cheaters use VMware to run games in isolated virtual environments to protect their main system from bans, " +
                         "run multiple instances simultaneously, or bypass kernel-level anti-cheat detection.",
                Detail = $"Directory={dir}",
            });
        }

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\VMware, Inc.", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = "VMware registry key detected",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\VMware, Inc.",
                    Reason = "Registry key for VMware found under HKLM. Indicates VMware is or was installed on this system.",
                    Detail = "Registry=HKLM\\SOFTWARE\\VMware, Inc.",
                });
            }
        }
        catch { }

        CheckVmNic(ctx, ct, "VMware", "VMware");
    }

    private static void CheckVirtualBoxInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var vboxDir = Path.Combine(programFiles, "Oracle", "VirtualBox");

        if (Directory.Exists(vboxDir))
        {
            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = $"VirtualBox installation: {vboxDir}",
                Risk = RiskLevel.Medium,
                Location = vboxDir,
                FileName = "VirtualBox",
                Reason = $"Oracle VirtualBox installation found at '{vboxDir}'. " +
                         "VirtualBox is used by cheaters to run game accounts in isolated VMs, enabling rapid ban recovery by reverting to snapshots.",
                Detail = $"Directory={vboxDir}",
            });
        }

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Oracle\VirtualBox", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = "VirtualBox registry key detected",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\Oracle\VirtualBox",
                    Reason = "Registry key for Oracle VirtualBox found. Indicates VirtualBox is or was installed.",
                    Detail = "Registry=HKLM\\SOFTWARE\\Oracle\\VirtualBox",
                });
            }
        }
        catch { }

        CheckVmNic(ctx, ct, "VirtualBox", "VirtualBox");
    }

    private static void CheckHyperVInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = "Running inside a Hyper-V guest VM",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
                    Reason = "The Hyper-V guest parameters registry key exists, indicating this machine is running as a Hyper-V virtual machine guest. " +
                             "This is a strong indicator that the scanned system is a VM environment, not the player's physical host.",
                    Detail = "Registry=HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
                });
            }
        }
        catch { }
    }

    private static void CheckQemuInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var qemuDir = Path.Combine(programFiles, "QEMU");

        if (Directory.Exists(qemuDir))
        {
            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = $"QEMU/KVM installation: {qemuDir}",
                Risk = RiskLevel.Medium,
                Location = qemuDir,
                FileName = "QEMU",
                Reason = $"QEMU virtualization software found at '{qemuDir}'. " +
                         "QEMU/KVM is used by advanced cheaters for DMA (Direct Memory Access) cheat setups and to run game clients in isolated VMs.",
                Detail = $"Directory={qemuDir}",
            });
        }

        CheckVmNic(ctx, ct, "QEMU", "QEMU");
        CheckVmNic(ctx, ct, "QEMU-Virtio", "Virtio");
    }

    private static void CheckParallelsInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Parallels", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = "Parallels Desktop VM registry key detected",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\Parallels",
                    Reason = "Registry key for Parallels Desktop virtualization found. " +
                             "Mac users sometimes use Parallels to run Windows games inside a VM, which can affect anti-cheat kernel-mode access.",
                    Detail = "Registry=HKLM\\SOFTWARE\\Parallels",
                });
            }
        }
        catch { }
    }

    private static void CheckVmNic(ScanContext ctx, CancellationToken ct, string label, string nicKeyword)
    {
        if (ct.IsCancellationRequested) return;

        const string nicClassKey = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";
        ctx.IncrementRegistryKeys();
        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(nicClassKey, writable: false);
            if (classKey is null) return;

            foreach (var subName in classKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();
                try
                {
                    using var subKey = classKey.OpenSubKey(subName, writable: false);
                    if (subKey is null) continue;

                    var desc = (subKey.GetValue("DriverDesc") as string) ?? "";
                    if (desc.IndexOf(nicKeyword, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "VM-Cheat",
                            Title = $"{label} virtual network adapter detected",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKLM\{nicClassKey}\{subName}",
                            Reason = $"Virtual network adapter with description '{desc}' matching {label} found in NIC class registry. " +
                                     "A virtual NIC confirms a VM hypervisor is running or recently ran on this system.",
                            Detail = $"DriverDesc={desc} SubKey={subName}",
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void ScanVmHardwareSignatures(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        const string biosKey = @"HARDWARE\DESCRIPTION\System\BIOS";
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(biosKey, writable: false);
            if (key is null) return;

            var manufacturer = (key.GetValue("SystemManufacturer") as string) ?? "";
            var productName = (key.GetValue("SystemProductName") as string) ?? "";

            var mfgHit = VmBiosManufacturerKeywords.FirstOrDefault(kw =>
                manufacturer.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0);

            if (mfgHit is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = $"VM SMBIOS manufacturer signature: {manufacturer}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{biosKey}",
                    Reason = $"System BIOS/SMBIOS SystemManufacturer field contains VM indicator '{mfgHit}' (value: '{manufacturer}'). " +
                             "Anti-cheat systems read SMBIOS data to detect virtual machines. A VM manufacturer in SMBIOS strongly indicates " +
                             "the system is running inside a hypervisor, which cheaters use to hide from kernel-level anti-cheat.",
                    Detail = $"SystemManufacturer={manufacturer} Keyword={mfgHit}",
                });
            }

            var productHit = VmBiosProductKeywords.FirstOrDefault(kw =>
                productName.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0);

            if (productHit is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = $"VM SMBIOS product name signature: {productName}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{biosKey}",
                    Reason = $"System BIOS/SMBIOS SystemProductName field contains VM indicator '{productHit}' (value: '{productName}'). " +
                             "Virtual machine product names in SMBIOS are a reliable hardware-level indicator of a VM guest environment.",
                    Detail = $"SystemProductName={productName} Keyword={productHit}",
                });
            }
        }
        catch { }

        CheckScsiVmSignature(ctx, ct);
    }

    private static void CheckScsiVmSignature(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        const string scsiKey = @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0";
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(scsiKey, writable: false);
            if (key is null) return;

            var identifier = (key.GetValue("Identifier") as string) ?? "";
            var idHit = VmScsiIdentifierKeywords.FirstOrDefault(kw =>
                identifier.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0);

            if (idHit is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = $"VM SCSI disk identifier signature: {identifier}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{scsiKey}",
                    Reason = $"SCSI disk identifier '{identifier}' contains VM indicator '{idHit}'. " +
                             "Virtual disk identifiers in the device map registry confirm that the system boot disk is a virtual disk, " +
                             "indicating a VM environment. Anti-cheat systems check this to detect VM guests.",
                    Detail = $"Identifier={identifier} Keyword={idHit}",
                });
            }
        }
        catch { }
    }

    private static void ScanVmServices(ScanContext ctx, CancellationToken ct)
    {
        CheckVmServiceGroup(ctx, ct, VmwareServiceNames, "VMware");
        CheckVmServiceGroup(ctx, ct, VirtualBoxServiceNames, "VirtualBox");
        CheckVmServiceGroup(ctx, ct, HyperVServiceNames, "Hyper-V");
    }

    private static void CheckVmServiceGroup(ScanContext ctx, CancellationToken ct, string[] serviceNames, string platform)
    {
        foreach (var svcName in serviceNames)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svcName}", writable: false);
                if (key is null) continue;

                var startType = key.GetValue("Start") as int?;
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = $"{platform} service found: {svcName}",
                    Risk = RiskLevel.Medium,
                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                    Reason = $"{platform} guest/host service '{svcName}' found in the service registry with start type {startType}. " +
                             $"Presence of {platform} services confirms VM software is installed and integrated into the OS.",
                    Detail = $"Service={svcName} Platform={platform} StartType={startType}",
                });
            }
            catch { }
        }
    }

    private static void ScanVmDiskImages(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var driveLetter in new[] { "D", "E", "F", "G" })
        {
            var drive = $"{driveLetter}:\\";
            if (Directory.Exists(drive))
                searchDirs.Add(drive);
        }

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    var ext = Path.GetExtension(fname);

                    bool isVmDiskExt = VmDiskExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase));
                    if (!isVmDiskExt) continue;

                    var fnameNoExt = Path.GetFileNameWithoutExtension(fname).ToLowerInvariant();
                    bool isGameNamedDisk = GameNamedVmDiskPatterns.Any(p =>
                        fnameNoExt.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0);

                    if (isGameNamedDisk)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "VM-Cheat",
                            Title = $"Game-named VM disk image: {fname}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fname,
                            Reason = $"Virtual machine disk image '{fname}' with a game-related name found at '{file}'. " +
                                     "A VM disk named after a specific game is a strong indicator of a dedicated cheat VM setup — " +
                                     "cheaters create game-specific VMs to play with cheats in an isolated environment while keeping " +
                                     "their main system clean. Snapshots allow instant ban recovery.",
                            Detail = $"Extension={ext} Path={file}",
                        });
                    }
                    else
                    {
                        long fileSizeBytes = 0;
                        try { fileSizeBytes = new FileInfo(file).Length; } catch { }

                        if (fileSizeBytes > 1L * 1024 * 1024 * 1024)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "VM-Cheat",
                                Title = $"Large VM disk image in unusual location: {fname}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fname,
                                Reason = $"Large virtual machine disk image '{fname}' ({fileSizeBytes / (1024 * 1024)} MB) found outside of typical VM software directories. " +
                                         "VM disk files in unusual locations like desktop, downloads, or external drives may indicate a portable VM setup used for gaming cheat isolation.",
                                Detail = $"SizeMB={fileSizeBytes / (1024 * 1024)} Extension={ext} Path={file}",
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void ScanSandboxAndContainerTools(ScanContext ctx, CancellationToken ct)
    {
        CheckSandboxie(ctx, ct);
        CheckWindowsSandbox(ctx, ct);
        CheckDocker(ctx, ct);
    }

    private static void CheckSandboxie(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var sandboxieDirs = new[]
        {
            Path.Combine(programFiles, "Sandboxie"),
            Path.Combine(programFiles, "Sandboxie-Plus"),
        };

        foreach (var dir in sandboxieDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = $"Sandboxie installation: {Path.GetFileName(dir)}",
                Risk = RiskLevel.Medium,
                Location = dir,
                FileName = Path.GetFileName(dir),
                Reason = $"Sandboxie installation found at '{dir}'. " +
                         "Sandboxie is used by cheaters to run games in a sandboxed environment that isolates the game process, " +
                         "potentially hiding user-mode anti-cheat detection mechanisms from the sandboxed game.",
                Detail = $"Directory={dir}",
            });
        }

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Sandboxie-Plus", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = "Sandboxie-Plus registry key detected",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\Sandboxie-Plus",
                    Reason = "Registry key for Sandboxie-Plus found. Sandboxie-Plus provides process isolation that can bypass user-mode anti-cheat hooks.",
                    Detail = "Registry=HKLM\\SOFTWARE\\Sandboxie-Plus",
                });
            }
        }
        catch { }

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SbieDrv", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = "Sandboxie kernel driver (SbieDrv) registered",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\SbieDrv",
                    Reason = "Sandboxie kernel driver 'SbieDrv' is registered in the services registry. " +
                             "The Sandboxie kernel driver intercepts system calls and file I/O at the kernel level to sandbox processes, " +
                             "which can prevent anti-cheat from observing real system state of a sandboxed game process.",
                    Detail = "Service=SbieDrv",
                });
            }
        }
        catch { }
    }

    private static void CheckWindowsSandbox(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        ctx.IncrementRegistryKeys();
        try
        {
            var snapshot = ctx.GetProcessSnapshot();
            bool wdagSvcRunning = snapshot.Any(p =>
                p.ProcessName.Equals("wdagsvc", StringComparison.OrdinalIgnoreCase));

            if (wdagSvcRunning)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = "Windows Sandbox (WDAG service) is running",
                    Risk = RiskLevel.Medium,
                    Location = "Process: wdagsvc",
                    FileName = "wdagsvc.exe",
                    Reason = "The Windows Defender Application Guard service (wdagsvc.exe) is running, which backs Windows Sandbox. " +
                             "Windows Sandbox provides a lightweight VM for running applications in isolation, usable for sandboxed cheat testing.",
                    Detail = "Process=wdagsvc",
                });
            }
        }
        catch { }
    }

    private static void CheckDocker(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var dockerDir = Path.Combine(programFiles, "Docker");

        if (Directory.Exists(dockerDir))
        {
            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = $"Docker installation: {dockerDir}",
                Risk = RiskLevel.Low,
                Location = dockerDir,
                FileName = "Docker",
                Reason = $"Docker Desktop installation found at '{dockerDir}'. " +
                         "Docker is a container platform primarily used by developers; in cheat contexts it can be used for server-side cheat deployment or isolated testing environments.",
                Detail = $"Directory={dockerDir}",
            });
        }
    }

    private static void ScanRemoteAccessAndStreaming(ScanContext ctx, CancellationToken ct)
    {
        CheckRdpEnabled(ctx, ct);
        CheckTeamViewerInstall(ctx, ct);
    }

    private static void CheckRdpEnabled(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Terminal Server", writable: false);
            if (key is null) return;

            var fDenyTSConnections = key.GetValue("fDenyTSConnections") as int?;
            bool rdpEnabled = fDenyTSConnections == 0;

            if (!rdpEnabled) return;

            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = "Remote Desktop Protocol (RDP) is enabled",
                Risk = RiskLevel.Medium,
                Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                Reason = "Remote Desktop Protocol (RDP) is enabled on this system (fDenyTSConnections=0). " +
                         "Cheaters sometimes use RDP to remotely control a separate physical or virtual machine running the game, " +
                         "ensuring the machine being scanned is not the one actually running the cheat.",
                Detail = "fDenyTSConnections=0 (RDP enabled)",
            });
        }
        catch { }
    }

    private static void CheckTeamViewerInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\TeamViewer", writable: false);
            if (key is null) return;

            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = "TeamViewer remote access software detected",
                Risk = RiskLevel.Low,
                Location = @"HKLM\SOFTWARE\TeamViewer",
                Reason = "TeamViewer remote access software registry key found. " +
                         "TeamViewer can be used for remote gaming setups where a remote machine runs the game with cheats while the scanned machine serves as a viewer.",
                Detail = "Registry=HKLM\\SOFTWARE\\TeamViewer",
            });
        }
        catch { }
    }

    private static void ScanDmaCheatInfrastructure(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);

                    if (DmaCheatExeNames.Any(n => n.Equals(fname, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "VM-Cheat",
                            Title = $"DMA cheat tool executable: {fname}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fname,
                            Reason = $"DMA (Direct Memory Access) cheat tool '{fname}' found on disk. " +
                                     "DMA cheats use a second computer with a PCIe-to-USB DMA card or FPGA device to read game memory directly over the hardware bus, " +
                                     "completely bypassing software-based anti-cheat memory protection. " +
                                     "PCILeech is the most well-known DMA memory access framework used in cheat setups.",
                            Detail = $"Path={file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            foreach (var configName in DmaConfigFileNames)
            {
                var configPath = Path.Combine(dir, configName);
                if (!File.Exists(configPath)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = "VM-Cheat",
                    Title = $"DMA cheat configuration file: {configName}",
                    Risk = RiskLevel.Critical,
                    Location = configPath,
                    FileName = configName,
                    Reason = $"DMA cheat configuration file '{configName}' found at '{configPath}'. " +
                             "DMA cheat config files contain memory offsets, target process names, and hardware settings used " +
                             "to configure a DMA device to read game memory from a second computer.",
                    Detail = $"Path={configPath}",
                });
            }

            ScanNetworkMemoryRelayScripts(ctx, ct, dir);
        }
    }

    private static void ScanNetworkMemoryRelayScripts(ScanContext ctx, CancellationToken ct, string dir)
    {
        if (!Directory.Exists(dir)) return;

        try
        {
            foreach (var file in Directory.GetFiles(dir, "*.py", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    string content;
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();

                    bool hasSocketRecv = content.IndexOf("socket.recv", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        content.IndexOf("sock.recv", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool hasMemoryRead = content.IndexOf("ReadProcessMemory", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        content.IndexOf("ctypes.windll.kernel32", StringComparison.OrdinalIgnoreCase) >= 0;

                    if (hasSocketRecv && hasMemoryRead)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "VM-Cheat",
                            Title = $"Network memory relay script: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Python script '{Path.GetFileName(file)}' combines network socket receive operations with process memory read API calls. " +
                                     "This pattern matches a network-based memory relay — a script that reads game memory on one machine and transmits it " +
                                     "over a local network to a second machine running the aimbot or ESP display, a common DMA cheat architecture.",
                            Detail = $"HasSocketRecv=true HasMemoryRead=true Path={file}",
                        });
                    }
                }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private static void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        bool gameRunning = false;
        bool vmwareRunning = false;
        bool vboxRunning = false;
        bool sandboxRunning = false;
        bool rdpClientRunning = false;
        bool remoteStreamRunning = false;
        var runningVmProcesses = new List<string>();
        var runningGameProcesses = new List<string>();

        try
        {
            var snapshot = ctx.GetProcessSnapshot();
            foreach (var proc in snapshot)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementProcesses();

                try
                {
                    var procNameLower = proc.ProcessName.ToLowerInvariant();

                    if (KnownGameProcessNames.Any(g => procNameLower.Equals(g, StringComparison.OrdinalIgnoreCase)))
                    {
                        gameRunning = true;
                        runningGameProcesses.Add(proc.ProcessName);
                    }

                    if (VmwareProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        vmwareRunning = true;
                        runningVmProcesses.Add(proc.ProcessName);
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "VM-Cheat",
                            Title = $"VMware process running: {proc.ProcessName}",
                            Risk = RiskLevel.Medium,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"VMware process '{proc.ProcessName}' is currently running, indicating an active VMware VM.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                    else if (VirtualBoxProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        vboxRunning = true;
                        runningVmProcesses.Add(proc.ProcessName);
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "VM-Cheat",
                            Title = $"VirtualBox process running: {proc.ProcessName}",
                            Risk = RiskLevel.Medium,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"VirtualBox process '{proc.ProcessName}' is currently running, indicating an active VirtualBox VM.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                    else if (QemuProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        runningVmProcesses.Add(proc.ProcessName);
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "VM-Cheat",
                            Title = $"QEMU process running: {proc.ProcessName}",
                            Risk = RiskLevel.Medium,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"QEMU virtualization process '{proc.ProcessName}' is currently running.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                    else if (HyperVProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        runningVmProcesses.Add(proc.ProcessName);
                    }
                    else if (SandboxieProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase))
                             && !procNameLower.Equals("start", StringComparison.OrdinalIgnoreCase))
                    {
                        sandboxRunning = true;
                        runningVmProcesses.Add(proc.ProcessName);
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "VM-Cheat",
                            Title = $"Sandboxie process running: {proc.ProcessName}",
                            Risk = RiskLevel.Medium,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"Sandboxie process '{proc.ProcessName}' is currently running. " +
                                     "Sandboxie active during a game session can isolate the game from the real system environment.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                    else if (procNameLower.Equals("mstsc", StringComparison.OrdinalIgnoreCase))
                    {
                        rdpClientRunning = true;
                    }
                    else if (RemoteAccessProcessNames.Any(n =>
                        n.Equals(procNameLower, StringComparison.OrdinalIgnoreCase) &&
                        !n.Equals("mstsc", StringComparison.OrdinalIgnoreCase)))
                    {
                        remoteStreamRunning = true;
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "VM-Cheat",
                            Title = $"Remote access / streaming tool running: {proc.ProcessName}",
                            Risk = RiskLevel.Low,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"Remote access or game streaming process '{proc.ProcessName}' is running. " +
                                     "Tools like AnyDesk, NoMachine, and Parsec are used by cheaters to play games remotely on a separate machine " +
                                     "that is not subject to anti-cheat inspection, while controlling it from the scanned device.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        if ((vmwareRunning || vboxRunning) && gameRunning)
        {
            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = "VM software active while game is running",
                Risk = RiskLevel.High,
                Location = "Process snapshot",
                Reason = $"VM host process(es) ({string.Join(", ", runningVmProcesses)}) are running at the same time as game process(es) ({string.Join(", ", runningGameProcesses)}). " +
                         "A VM hypervisor running alongside a game is a common cheat infrastructure pattern: the VM provides a clean inner environment " +
                         "for a second game client with cheats while the outer host presents a clean scan surface.",
                Detail = $"VmProcesses={string.Join("|", runningVmProcesses)} GameProcesses={string.Join("|", runningGameProcesses)}",
            });
        }

        if (rdpClientRunning && gameRunning)
        {
            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = "RDP client (mstsc) running while game is active",
                Risk = RiskLevel.Medium,
                Location = "Process: mstsc.exe",
                Reason = $"Remote Desktop client (mstsc.exe) is running alongside game process(es) ({string.Join(", ", runningGameProcesses)}). " +
                         "This may indicate the player is remotely viewing or controlling a separate machine running a cheat-enabled game instance.",
                Detail = $"GameProcesses={string.Join("|", runningGameProcesses)}",
            });
        }

        if (sandboxRunning && gameRunning)
        {
            ctx.AddFinding(new Finding
            {
                Module = "VM-Cheat",
                Title = "Sandboxie active while game is running",
                Risk = RiskLevel.High,
                Location = "Process snapshot",
                Reason = $"Sandboxie is running alongside game process(es) ({string.Join(", ", runningGameProcesses)}). " +
                         "Sandboxie can isolate the game from real OS state, potentially hiding cheat injection and process activity from kernel-level anti-cheat.",
                Detail = $"GameProcesses={string.Join("|", runningGameProcesses)}",
            });
        }
    }
}
