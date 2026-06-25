using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class HypervisorCheatDetectionScanModule : IScanModule
{
    public string Name => "Hypervisor & VM-Based Cheat Detection";
    public double Weight => 4.2;
    public int ParallelGroup => 4;

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32Dir =
        Path.Combine(WinDir, "System32");
    private static readonly string DriversDir =
        Path.Combine(System32Dir, "drivers");

    private static readonly (string name, RiskLevel risk, string reason)[] KnownDmaCheatFileNames =
    {
        ("DmaMemoryReader.exe", RiskLevel.Critical,
            "DMA memory reading tool — reads game process memory via hardware DMA without any Windows API call"),
        ("dma_cheat.exe",       RiskLevel.Critical,
            "DMA-based cheat executable detected by name signature"),
        ("physmem_read.exe",    RiskLevel.Critical,
            "Physical memory reader — raw DMA access tool used with FPGA DMA boards"),
        ("pcileech.exe",        RiskLevel.Critical,
            "PCILeech DMA attack framework — industry-standard tool for DMA memory access via PCIe"),
        ("MemProcFS.exe",       RiskLevel.Critical,
            "MemProcFS process filesystem — mounts remote process memory as a filesystem via LeechCore/PCILeech"),
        ("ExternalCheat.exe",   RiskLevel.Critical,
            "Generic external cheat binary — name indicates a cheat that reads game memory externally"),
        ("ReadPhysMem.exe",     RiskLevel.Critical,
            "Physical memory reader utility used for DMA-based cheat development"),
        ("WritePhysMem.exe",    RiskLevel.Critical,
            "Physical memory writer utility — enables DMA-based cheat aimbot memory writes"),
        ("hypervisor_cheat.exe",RiskLevel.Critical,
            "Hypervisor-level cheat executable — runs in VMX root mode above the guest OS"),
        ("hv_cheat.dll",        RiskLevel.Critical,
            "Hypervisor cheat DLL — injected into hypervisor layer"),
        ("vmx_cheat.exe",       RiskLevel.Critical,
            "VMX-mode cheat — exploits Intel VT-x to run cheat code outside guest OS detection"),
        ("kvm_cheat.exe",       RiskLevel.Critical,
            "KVM hypervisor cheat — runs cheat in KVM host while game is in a guest VM"),
        ("DmaCheat.exe",        RiskLevel.Critical,
            "DMA-based cheat executable"),
        ("leechcore.dll",       RiskLevel.High,
            "LeechCore DMA device abstraction library — required by PCILeech and MemProcFS"),
        ("vmm.dll",             RiskLevel.High,
            "PCILeech Virtual Memory Manager DLL — used for process-level memory access via DMA"),
        ("leechcore_device_fpga.sys", RiskLevel.Critical,
            "LeechCore FPGA kernel driver — signed PCILeech driver for FPGA DMA board communication"),
        ("pcileech.sys",        RiskLevel.Critical,
            "PCILeech kernel driver — provides kernel-mode DMA access to PCIe hardware"),
        ("vmm.sys",             RiskLevel.High,
            "PCILeech VMM kernel component for DMA-based memory access"),
    };

    private static readonly (string fragment, RiskLevel risk, string reason)[] DmaCheatFileFragments =
    {
        ("pcileech",       RiskLevel.Critical, "PCILeech DMA framework artifact"),
        ("pcileech_fpga",  RiskLevel.Critical, "PCILeech FPGA firmware or config artifact"),
        ("pcileech_shell", RiskLevel.Critical, "PCILeech shellcode payload"),
        ("leechcore",      RiskLevel.Critical, "LeechCore DMA library artifact (part of PCILeech suite)"),
        ("memprocfs",      RiskLevel.Critical, "MemProcFS DMA-based process filesystem artifact"),
        ("dma_cheat",      RiskLevel.Critical, "DMA cheat tool artifact"),
        ("dma-cheat",      RiskLevel.Critical, "DMA cheat tool artifact"),
        ("dma_external",   RiskLevel.Critical, "DMA external cheat artifact"),
        ("dma-external",   RiskLevel.Critical, "DMA external cheat artifact"),
        ("hypervisor_cheat", RiskLevel.Critical, "Hypervisor cheat artifact"),
        ("hypervisor-cheat", RiskLevel.Critical, "Hypervisor cheat artifact"),
        ("squirrel_cheat", RiskLevel.Critical, "PCIe Squirrel FPGA cheat firmware artifact"),
        ("squirrel-cheat", RiskLevel.Critical, "PCIe Squirrel FPGA cheat firmware artifact"),
        ("scatter_read",   RiskLevel.High,   "ScatterRead DMA read pattern — used in PCILeech-based cheats"),
        ("scatterread",    RiskLevel.High,   "ScatterRead DMA pattern artifact"),
        ("physmem",        RiskLevel.High,   "Physical memory access tool artifact"),
        ("phys_mem",       RiskLevel.High,   "Physical memory access tool artifact"),
        ("screamer_dma",   RiskLevel.High,   "Screamer DMA board configuration artifact"),
        ("screamerdma",    RiskLevel.High,   "Screamer DMA board artifact"),
        ("fpga_cheat",     RiskLevel.Critical, "FPGA-based cheat artifact"),
        ("fpga-cheat",     RiskLevel.Critical, "FPGA-based cheat artifact"),
        ("external_cheat", RiskLevel.Critical, "External memory cheat artifact"),
        ("external-cheat", RiskLevel.Critical, "External memory cheat artifact"),
        ("hv_cheat",       RiskLevel.Critical, "Hypervisor cheat artifact"),
        ("hv-cheat",       RiskLevel.Critical, "Hypervisor cheat artifact"),
        ("vmx_cheat",      RiskLevel.Critical, "VMX-mode cheat artifact"),
        ("vmx-cheat",      RiskLevel.Critical, "VMX-mode cheat artifact"),
        ("kvm_cheat",      RiskLevel.Critical, "KVM hypervisor cheat artifact"),
        ("kvm-cheat",      RiskLevel.Critical, "KVM hypervisor cheat artifact"),
        ("enigma_pcie",    RiskLevel.High,   "Enigma-protected PCIe cheat firmware config"),
        ("pcie_firmware",  RiskLevel.High,   "PCIe FPGA firmware — may be DMA board firmware"),
        ("leetdma",        RiskLevel.Critical, "LeetDMA cheat board artifact"),
        ("leet_dma",       RiskLevel.Critical, "LeetDMA cheat board artifact"),
        ("zdma_cheat",     RiskLevel.Critical, "ZDMA board cheat artifact"),
        ("cloudstreamer",  RiskLevel.High,   "Cloud Streamer DMA cheat artifact"),
    };

    private static readonly string[] KnownCheatGitRepoFragments =
    {
        "dma-cheat", "dma_cheat", "pcileech-cheat", "pcileech_cheat",
        "external-cheat", "external_cheat", "hypervisor-cheat", "hypervisor_cheat",
        "squirrel-cheat", "squirrel_cheat", "dma-external", "dma_external",
        "hv-cheat", "hv_cheat", "vmx-cheat", "vmx_cheat", "kvm-cheat",
        "fpga-cheat", "fpga_cheat", "leechcore-cheat", "memprocfs-cheat",
        "screamer-cheat", "leetdma", "leet-dma", "beetlecrap", "dmacheat",
    };

    private static readonly (string vid, string pid, string description)[] DmaFpgaUsbIds =
    {
        ("0403", "601e", "FTDI FT600 SuperSpeed USB3 bridge (Screamer M2, PCIe Squirrel, ZDMA)"),
        ("0403", "601f", "FTDI FT601 SuperSpeed USB3 bridge (PCIe Squirrel rev2, ZDMA board)"),
        ("04b4", "00f3", "Cypress FX3 SuperSpeed USB3 (CY7C68013A dev kit, used in DMA boards)"),
        ("04b4", "4720", "Cypress EZ-USB FX3 bootloader mode (DMA board firmware update)"),
        ("0547", "1002", "Anchorchips EZ-USB (legacy DMA board)"),
        ("16c0", "05dc", "Van Ooijen Technische Informatica VUSB (custom DMA firmware)"),
    };

    private static readonly (string nameFragment, string description)[] FpgaVendorFragments =
    {
        ("xilinx",       "Xilinx FPGA device (used in high-end DMA cheat boards)"),
        ("altera",       "Altera/Intel FPGA device (DMA board FPGA vendor)"),
        ("lattice",      "Lattice Semiconductor FPGA (budget DMA board platform)"),
        ("spartan",      "Xilinx Spartan FPGA series (common in PCILeech FPGA boards)"),
        ("artix",        "Xilinx Artix FPGA series (used in Squirrel and similar DMA boards)"),
        ("screamer",     "Screamer DMA board device (dedicated PCIe DMA tool)"),
        ("lambdaconcept","LambdaConcept PCIe DMA board manufacturer"),
        ("pciescrm",     "PCIe Screamer variant DMA device"),
        ("zdma",         "ZDMA board device — dedicated PCIe DMA hardware"),
        ("leetdma",      "LeetDMA board device"),
    };

    private static readonly string[] AntiVmBypassConfigFragments =
    {
        "cpuid.1.eax",
        "cpuid.0.eax",
        "hypervisor.cpuid.v0",
        "monitor_control.restrict_backdoor",
        "vmware.fullscreen.cursor.constrain",
        "board.product.name",
        "VBOX_E_OBJECT_NOT_FOUND",
        "VBoxService",
        "vmtoolsd",
        "hyperv_enlightenments",
        "kvm_hint-dedicated",
        "host_model_passthrough",
        "-cpu host",
        "vmxnet3",
        "VMWARE_CPUID",
        "hv_vendor_id",
        "hv_relaxed",
        "hv_vapic",
        "hv_time",
        "vmx,",
        "invtsc",
        "rdtsc_offset",
        "rdtsc",
    };

    private static readonly string[] QemuConfigExtensions =
    {
        ".qcow2", ".vmdk", ".vhd", ".vhdx", ".ova", ".ovf",
    };

    private static readonly string[] QemuLaunchKeywords =
    {
        "qemu-system-x86_64",
        "qemu-system-i386",
        "qemu-kvm",
        "-device vfio-pci",
        "-device pcie-root-port",
        "iommu=pt",
        "intel_iommu=on",
        "amd_iommu=on",
        "pcie_port_pm=off",
        "pci-stub.ids",
        "vfio-pci.ids",
        "vfio_pci",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanFileSystemForDmaToolsAsync(ctx, ct);
        ctx.Report(0.22, "DMA tool files", "File system scan for DMA cheat tools complete");

        await ScanGitReposForHypervisorCheatsAsync(ctx, ct);
        ctx.Report(0.38, "Git repos", "Git repository DMA cheat scan complete");

        await ScanQemuConfigsAsync(ctx, ct);
        ctx.Report(0.52, "QEMU configs", "QEMU VM config files scanned");

        ScanHypervisorCheatRegistry(ctx, ct);
        ctx.Report(0.67, "Registry", "Hypervisor cheat registry scan complete");

        ScanPciFpgaDevices(ctx, ct);
        ctx.Report(0.82, "PCIe devices", "PCIe/FPGA DMA device registry scan complete");

        ScanDriverDirectoryForDmaDrivers(ctx, ct);
        ctx.Report(0.92, "DMA drivers", "Driver directory DMA artifact scan complete");

        ScanAntiVmBypassRegistry(ctx, ct);
        ctx.Report(1.00, "Anti-VM bypass", "Anti-VM detection bypass registry scan complete");
    }

    private async Task ScanFileSystemForDmaToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.GetTempPath(),
            Path.Combine(WinDir, "Temp"),
        };

        foreach (var drive in DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
        {
            var root = drive.RootDirectory.FullName;
            if (!searchRoots.Any(r => r.StartsWith(root, StringComparison.OrdinalIgnoreCase)))
                searchRoots.Add(root);
        }

        var scannedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var searchRoot in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(searchRoot)) continue;
            if (!scannedPaths.Add(searchRoot)) continue;

            await ScanDirectoryForDmaToolsAsync(searchRoot, ctx, ct, depth: 0, maxDepth: 4);
        }
    }

    private async Task ScanDirectoryForDmaToolsAsync(
        string dir, ScanContext ctx, CancellationToken ct, int depth, int maxDepth)
    {
        if (depth > maxDepth) return;
        ct.ThrowIfCancellationRequested();

        IEnumerable<string> files;
        try { files = Directory.EnumerateFiles(dir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var filePath in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(filePath);

            var exactMatch = KnownDmaCheatFileNames.FirstOrDefault(e =>
                e.name.Equals(fileName, StringComparison.OrdinalIgnoreCase));
            if (exactMatch != default)
            {
                bool isInSystem = filePath.StartsWith(System32Dir, StringComparison.OrdinalIgnoreCase);
                if (!isInSystem || exactMatch.risk == RiskLevel.Critical)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"DMA/Hypervisor cheat file: {fileName}",
                        Risk = exactMatch.risk,
                        Location = filePath,
                        FileName = fileName,
                        Reason = exactMatch.reason,
                        Detail = $"Full path: {filePath}"
                    });
                }
                continue;
            }

            var fileNameLow = fileName.ToLowerInvariant();
            var fragMatch = DmaCheatFileFragments.FirstOrDefault(f =>
                fileNameLow.Contains(f.fragment, StringComparison.OrdinalIgnoreCase));
            if (fragMatch != default)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"DMA cheat artifact by name pattern: {fileName}",
                    Risk = fragMatch.risk,
                    Location = filePath,
                    FileName = fileName,
                    Reason = fragMatch.reason,
                    Detail = $"Matched pattern: '{fragMatch.fragment}' in file name"
                });
                continue;
            }

            if (QemuConfigExtensions.Any(ext =>
                    fileName.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) &&
                depth <= 3)
            {
                await CheckQemuDiskImageNameAsync(filePath, fileName, ctx, ct);
            }
        }

        IEnumerable<string> subdirs;
        try { subdirs = Directory.EnumerateDirectories(dir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var subDir in subdirs)
        {
            ct.ThrowIfCancellationRequested();

            var dirName = Path.GetFileName(subDir);
            var dirNameLow = dirName.ToLowerInvariant();

            var dirFrag = DmaCheatFileFragments.FirstOrDefault(f =>
                dirNameLow.Contains(f.fragment, StringComparison.OrdinalIgnoreCase));
            if (dirFrag != default)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"DMA cheat directory: {dirName}",
                    Risk = dirFrag.risk,
                    Location = subDir,
                    FileName = dirName,
                    Reason = $"Directory name matches DMA/hypervisor cheat artifact pattern: {dirFrag.reason}",
                    Detail = $"Matched pattern: '{dirFrag.fragment}'"
                });
            }

            var knownRepo = KnownCheatGitRepoFragments.FirstOrDefault(r =>
                dirNameLow.Contains(r, StringComparison.OrdinalIgnoreCase));
            if (knownRepo is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Hypervisor cheat repository directory: {dirName}",
                    Risk = RiskLevel.Critical,
                    Location = subDir,
                    FileName = dirName,
                    Reason = "Directory name matches a known DMA/hypervisor cheat repository naming pattern. " +
                             "These repositories contain source code or binaries for reading game memory " +
                             "via FPGA DMA hardware without any Windows API interaction.",
                    Detail = $"Matched repo pattern: '{knownRepo}'"
                });
            }

            await ScanDirectoryForDmaToolsAsync(subDir, ctx, ct, depth + 1, maxDepth);
        }
    }

    private static async Task CheckQemuDiskImageNameAsync(
        string path, string fileName, ScanContext ctx, CancellationToken ct)
    {
        var fileNameLow = fileName.ToLowerInvariant();

        bool suspiciousName =
            fileNameLow.Contains("game", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("cs2", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("csgo", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("apex", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("valorant", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("rust_vm", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("fortnite", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("dma", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("external", StringComparison.OrdinalIgnoreCase) ||
            fileNameLow.Contains("guest", StringComparison.OrdinalIgnoreCase);

        if (!suspiciousName) return;

        ctx.AddFinding(new Finding
        {
            Module = "Hypervisor & VM-Based Cheat Detection",
            Title = $"Suspicious VM disk image: {fileName}",
            Risk = RiskLevel.High,
            Location = path,
            FileName = fileName,
            Reason = "A virtual machine disk image was found with a name suggesting it hosts a game " +
                     "for DMA cheating. The DMA cheat pattern involves running the target game inside " +
                     "a VM while a cheat reads its memory from the host via FPGA DMA hardware. " +
                     "A disk image named after a game on a gaming PC is a strong indicator.",
            Detail = $"VM disk image: {path}"
        });
    }

    private async Task ScanGitReposForHypervisorCheatsAsync(ScanContext ctx, CancellationToken ct)
    {
        var gitSearchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "source"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "repos"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "projects"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var drive in DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
        {
            gitSearchRoots.Add(drive.RootDirectory.FullName);
        }

        var scanned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in gitSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            if (!scanned.Add(root)) continue;

            await FindGitReposAsync(root, ctx, ct, depth: 0, maxDepth: 5);
        }
    }

    private async Task FindGitReposAsync(
        string dir, ScanContext ctx, CancellationToken ct, int depth, int maxDepth)
    {
        if (depth > maxDepth) return;
        ct.ThrowIfCancellationRequested();

        var gitDir = Path.Combine(dir, ".git");
        if (Directory.Exists(gitDir))
        {
            await CheckGitRepoForDmaCheatsAsync(dir, gitDir, ctx, ct);
            return;
        }

        IEnumerable<string> subdirs;
        try { subdirs = Directory.EnumerateDirectories(dir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var sub in subdirs)
        {
            ct.ThrowIfCancellationRequested();
            await FindGitReposAsync(sub, ctx, ct, depth + 1, maxDepth);
        }
    }

    private async Task CheckGitRepoForDmaCheatsAsync(
        string repoRoot, string gitDir, ScanContext ctx, CancellationToken ct)
    {
        var configPath = Path.Combine(gitDir, "config");
        if (!File.Exists(configPath)) return;

        string configContent;
        try
        {
            using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            configContent = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }

        if (string.IsNullOrWhiteSpace(configContent)) return;

        var configLow = configContent.ToLowerInvariant();

        var matchedRepoPattern = KnownCheatGitRepoFragments.FirstOrDefault(pattern =>
            configLow.Contains(pattern, StringComparison.OrdinalIgnoreCase));

        var matchedFileFrag = DmaCheatFileFragments.FirstOrDefault(f =>
            configLow.Contains(f.fragment, StringComparison.OrdinalIgnoreCase));

        if (matchedRepoPattern is not null || matchedFileFrag != default)
        {
            var repoName = Path.GetFileName(repoRoot);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Hypervisor/DMA cheat Git repository: {repoName}",
                Risk = RiskLevel.Critical,
                Location = repoRoot,
                FileName = ".git/config",
                Reason = "A git repository's remote URL contains patterns matching known DMA or " +
                         "hypervisor cheat repositories. These repositories provide source code " +
                         "or binaries for reading game memory from a hypervisor or via FPGA DMA hardware.",
                Detail = $"Matched pattern: '{matchedRepoPattern ?? matchedFileFrag.fragment}' in {configPath}"
            });
            return;
        }

        var commitMsgPath = Path.Combine(gitDir, "COMMIT_EDITMSG");
        if (File.Exists(commitMsgPath))
        {
            string commitMsg;
            try
            {
                using var fs = new FileStream(commitMsgPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                commitMsg = await sr.ReadToEndAsync();
            }
            catch (IOException) { goto skipCommitMsg; }

            var commitLow = commitMsg.ToLowerInvariant();
            var commitFrag = DmaCheatFileFragments.FirstOrDefault(f =>
                commitLow.Contains(f.fragment, StringComparison.OrdinalIgnoreCase));

            if (commitFrag != default)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"DMA cheat commit message in git repo: {Path.GetFileName(repoRoot)}",
                    Risk = RiskLevel.High,
                    Location = repoRoot,
                    FileName = "COMMIT_EDITMSG",
                    Reason = "A git repository's most recent commit message contains DMA or hypervisor " +
                             "cheat-related keywords, suggesting active cheat development or modification.",
                    Detail = $"Commit message excerpt: {Truncate(commitMsg.Trim(), 200)}"
                });
            }
        }

        skipCommitMsg:;
    }

    private async Task ScanQemuConfigsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        };

        var qemuConfigExtensions = new[] { ".xml", ".bat", ".sh", ".cmd", ".conf", ".cfg", ".ini" };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
                    .Where(f => qemuConfigExtensions.Any(ext =>
                        f.EndsWith(ext, StringComparison.OrdinalIgnoreCase)));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            int scanned = 0;
            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                if (++scanned > 300) break;

                await CheckQemuConfigFileAsync(file, ctx, ct);
            }
        }
    }

    private static async Task CheckQemuConfigFileAsync(string path, ScanContext ctx, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        if (string.IsNullOrWhiteSpace(content) || content.Length < 30) return;

        var lower = content.ToLowerInvariant();

        int qemuScore = 0;
        var matchedQemuTokens = new List<string>();

        foreach (var token in QemuLaunchKeywords)
        {
            if (lower.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                qemuScore++;
                matchedQemuTokens.Add(token);
            }
        }

        if (qemuScore < 2) return;

        bool hasPciePassthrough = lower.Contains("vfio-pci", StringComparison.OrdinalIgnoreCase) ||
                                  lower.Contains("pcie passthrough", StringComparison.OrdinalIgnoreCase) ||
                                  lower.Contains("-device pcie", StringComparison.OrdinalIgnoreCase) ||
                                  lower.Contains("iommu=pt", StringComparison.OrdinalIgnoreCase);

        bool hasAntiVmBypass = AntiVmBypassConfigFragments.Any(t =>
            lower.Contains(t, StringComparison.OrdinalIgnoreCase));

        if (hasPciePassthrough || hasAntiVmBypass || qemuScore >= 3)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Hypervisor & VM-Based Cheat Detection",
                Title = $"QEMU DMA cheat VM config: {Path.GetFileName(path)}",
                Risk = hasPciePassthrough ? RiskLevel.Critical : RiskLevel.High,
                Location = path,
                FileName = Path.GetFileName(path),
                Reason = hasPciePassthrough
                    ? "A QEMU virtual machine configuration was found with PCIe passthrough settings. " +
                      "The DMA cheat technique requires running a game in a QEMU VM with a GPU passed " +
                      "through, while the host reads game memory via FPGA DMA hardware. This exact " +
                      "configuration (QEMU + PCIe passthrough + gaming PC) is the canonical DMA cheat setup."
                    : "A QEMU virtual machine configuration was found on this gaming PC with multiple " +
                      "hypervisor-related keywords. QEMU VMs on a gaming system may be used for the " +
                      "DMA cheating pattern (game in VM, cheat in host reading via PCIe DMA).",
                Detail = "Matched tokens: " + string.Join(", ", matchedQemuTokens.Take(6)) +
                         (hasAntiVmBypass ? " | Anti-VM bypass settings detected" : "")
            });
        }
    }

    private void ScanHypervisorCheatRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string VirtKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization";

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var virtKey = baseKey.OpenSubKey(VirtKey, writable: false);
            if (virtKey is not null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Hyper-V / Windows virtualization platform registry key present",
                    Risk = RiskLevel.Low,
                    Location = $@"HKLM\{VirtKey}",
                    Reason = "The Windows virtualization registry key is present, indicating Hyper-V or " +
                             "the Windows Hypervisor Platform is enabled. While this has many legitimate " +
                             "uses (WSL2, Docker, Sandbox), in combination with DMA tool artifacts it " +
                             "indicates a possible hypervisor-based cheat setup where the game runs as a " +
                             "Hyper-V guest while cheat code runs at the hypervisor level.",
                    Detail = $"Registry key: HKLM\\{VirtKey}"
                });
            }
        }
        catch { }

        const string ServicesRoot = @"SYSTEM\CurrentControlSet\Services";
        var dmaToolServices = new[]
        {
            ("pcileech",      RiskLevel.Critical, "PCILeech DMA attack framework service"),
            ("leechcore",     RiskLevel.Critical, "LeechCore DMA abstraction library service"),
            ("memprocfs",     RiskLevel.Critical, "MemProcFS DMA process filesystem service"),
            ("screamer",      RiskLevel.Critical, "Screamer DMA board service"),
            ("zdma",          RiskLevel.Critical, "ZDMA board kernel service"),
            ("leetdma",       RiskLevel.Critical, "LeetDMA board kernel service"),
            ("vmm_service",   RiskLevel.High,     "PCILeech VMM service component"),
            ("fpga_driver",   RiskLevel.High,     "FPGA DMA board driver service"),
            ("pciescrm",      RiskLevel.High,     "PCIe Screamer DMA board service"),
        };

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var svcRoot = baseKey.OpenSubKey(ServicesRoot, writable: false);
            if (svcRoot is null) return;

            foreach (var svcName in svcRoot.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();

                var svcLow = svcName.ToLowerInvariant();
                var match = dmaToolServices.FirstOrDefault(t =>
                    svcLow.Contains(t.Item1, StringComparison.OrdinalIgnoreCase));
                if (match == default) continue;

                try
                {
                    using var svcKey = svcRoot.OpenSubKey(svcName, writable: false);
                    if (svcKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    var imagePath = svcKey.GetValue("ImagePath")?.ToString() ?? "";

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"DMA/Hypervisor cheat service: {svcName}",
                        Risk = match.Item2,
                        Location = $@"HKLM\{ServicesRoot}\{svcName}",
                        Reason = $"Windows service '{svcName}' matches a known DMA or hypervisor cheat " +
                                 $"tool service pattern: {match.Item3}. This service provides kernel-mode " +
                                 "or user-mode access to PCIe DMA hardware or FPGA boards used to read " +
                                 "game process memory without any Windows API interception.",
                        Detail = string.IsNullOrEmpty(imagePath)
                            ? null
                            : $"Service image: {imagePath}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanPciFpgaDevices(ScanContext ctx, CancellationToken ct)
    {
        const string PciEnumKey = @"SYSTEM\CurrentControlSet\Enum\PCI";
        const string UsbEnumKey = @"SYSTEM\CurrentControlSet\Enum\USB";

        ScanDeviceEnumKey(PciEnumKey, ctx, ct, isFpgaContext: true);
        ScanDeviceEnumKey(UsbEnumKey, ctx, ct, isFpgaContext: false);
    }

    private void ScanDeviceEnumKey(string enumKeyPath, ScanContext ctx, CancellationToken ct, bool isFpgaContext)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var enumKey = baseKey.OpenSubKey(enumKeyPath, writable: false);
            if (enumKey is null) return;

            foreach (var deviceId in enumKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    using var deviceKey = enumKey.OpenSubKey(deviceId, writable: false);
                    if (deviceKey is null) continue;

                    foreach (var instanceId in deviceKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();

                        try
                        {
                            using var instanceKey = deviceKey.OpenSubKey(instanceId, writable: false);
                            if (instanceKey is null) continue;
                            ctx.IncrementRegistryKeys();

                            var friendlyName = instanceKey.GetValue("FriendlyName")?.ToString() ?? "";
                            var deviceDesc = instanceKey.GetValue("DeviceDesc")?.ToString() ?? "";
                            var mfg = instanceKey.GetValue("Mfg")?.ToString() ?? "";
                            var combined = (friendlyName + " " + deviceDesc + " " + mfg + " " + deviceId)
                                .ToLowerInvariant();

                            if (!isFpgaContext)
                            {
                                var deviceIdLow = deviceId.ToLowerInvariant();
                                foreach (var (vid, pid, desc) in DmaFpgaUsbIds)
                                {
                                    var pattern = $"vid_{vid}&pid_{pid}";
                                    if (deviceIdLow.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = $"DMA board USB chip detected: VID_{vid.ToUpperInvariant()}&PID_{pid.ToUpperInvariant()}",
                                            Risk = RiskLevel.High,
                                            Location = $@"HKLM\{enumKeyPath}\{deviceId}\{instanceId}",
                                            Reason = desc,
                                            Detail = $"FriendlyName: {(string.IsNullOrEmpty(friendlyName) ? deviceDesc : friendlyName)}"
                                        });
                                        break;
                                    }
                                }
                            }

                            if (isFpgaContext)
                            {
                                var fragMatch = FpgaVendorFragments.FirstOrDefault(f =>
                                    combined.Contains(f.nameFragment, StringComparison.OrdinalIgnoreCase));
                                if (fragMatch != default)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"FPGA/DMA-capable PCIe device: {(string.IsNullOrEmpty(friendlyName) ? deviceDesc : friendlyName)}",
                                        Risk = RiskLevel.Medium,
                                        Location = $@"HKLM\{enumKeyPath}\{deviceId}",
                                        Reason = fragMatch.description +
                                                 " FPGA devices are the hardware platform for PCILeech and similar " +
                                                 "DMA cheat frameworks. Legitimate capture cards use the same " +
                                                 "hardware — this is a hint for manual review, not definitive proof.",
                                        Detail = $"Device ID: {deviceId} · " +
                                                 $"Name: {(string.IsNullOrEmpty(friendlyName) ? deviceDesc : friendlyName)} · " +
                                                 $"Manufacturer: {mfg}"
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanDriverDirectoryForDmaDrivers(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(DriversDir)) return;

        IEnumerable<string> driverFiles;
        try
        {
            driverFiles = Directory.EnumerateFiles(DriversDir, "*.sys");
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var driverPath in driverFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var driverName = Path.GetFileName(driverPath);
            var driverNameLow = driverName.ToLowerInvariant();

            var exactMatch = KnownDmaCheatFileNames.FirstOrDefault(e =>
                e.name.Equals(driverName, StringComparison.OrdinalIgnoreCase));
            if (exactMatch != default)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known DMA cheat driver in System32\\drivers: {driverName}",
                    Risk = RiskLevel.Critical,
                    Location = driverPath,
                    FileName = driverName,
                    Reason = "A kernel driver matching a known DMA cheat tool driver name was found in " +
                             "the Windows drivers directory. " + exactMatch.reason,
                    Detail = $"Driver path: {driverPath}"
                });
                continue;
            }

            var fragMatch = DmaCheatFileFragments.FirstOrDefault(f =>
                driverNameLow.Contains(f.fragment, StringComparison.OrdinalIgnoreCase));
            if (fragMatch != default)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"DMA cheat driver pattern in System32\\drivers: {driverName}",
                    Risk = fragMatch.risk,
                    Location = driverPath,
                    FileName = driverName,
                    Reason = $"Kernel driver name matches a DMA/hypervisor cheat pattern: {fragMatch.reason}",
                    Detail = $"Matched pattern: '{fragMatch.fragment}'"
                });
            }
        }
    }

    private void ScanAntiVmBypassRegistry(ScanContext ctx, CancellationToken ct)
    {
        var vmArtifactKeys = new[]
        {
            @"SOFTWARE\VMware, Inc.\VMware Tools",
            @"SOFTWARE\VMware, Inc.\VMware Workstation",
            @"SOFTWARE\Oracle\VirtualBox Guest Additions",
            @"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
            @"HARDWARE\ACPI\DSDT\VBOX__",
            @"HARDWARE\ACPI\FADT\VBOX__",
            @"HARDWARE\ACPI\RSDT\VBOX__",
            @"SOFTWARE\Wine",
            @"SOFTWARE\QEMU",
        };

        bool vmSoftwareKeysAbsent = true;
        bool runningInVm = false;

        foreach (var keyPath in vmArtifactKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var key = baseKey.OpenSubKey(keyPath, writable: false);
                if (key is not null)
                {
                    vmSoftwareKeysAbsent = false;
                    runningInVm = true;
                    ctx.IncrementRegistryKeys();
                }
            }
            catch { }
        }

        const string CpuidSpoofKey = @"SOFTWARE\Microsoft\Virtual Machine\Guest";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var key = baseKey.OpenSubKey(CpuidSpoofKey, writable: false);
            if (key is not null)
            {
                ctx.IncrementRegistryKeys();
                var physHostName = key.GetValue("PhysicalHostName")?.ToString();
                if (!string.IsNullOrEmpty(physHostName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "System is running inside a Hyper-V guest VM",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{CpuidSpoofKey}",
                        Reason = "The system appears to be running inside a Hyper-V virtual machine " +
                                 "(PhysicalHostName registry value is present). Running a game inside " +
                                 "a hypervisor VM is the prerequisite for Hyper-V partition-based cheats " +
                                 "and DMA cheating where the host reads VM memory.",
                        Detail = $"Host name: {physHostName}"
                    });
                }
            }
        }
        catch { }

        if (runningInVm)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Virtual machine software detected on gaming system",
                Risk = RiskLevel.Medium,
                Location = "HKLM\\SOFTWARE (VM vendor keys)",
                Reason = "VMware, VirtualBox, QEMU, or Hyper-V guest artifacts are present in the " +
                         "registry. A VM on a gaming PC, especially combined with DMA hardware, " +
                         "indicates a possible DMA cheat setup. The game runs in the VM while the " +
                         "cheat runs on the host and reads memory via PCIe DMA.",
                Detail = "VM artifact registry keys found. This alone is not proof of cheating."
            });
        }

        const string MacSpoofKey = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var nicClassKey = baseKey.OpenSubKey(MacSpoofKey, writable: false);
            if (nicClassKey is null) return;

            foreach (var instanceName in nicClassKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var nicKey = nicClassKey.OpenSubKey(instanceName, writable: false);
                    if (nicKey is null) continue;

                    var networkAddress = nicKey.GetValue("NetworkAddress")?.ToString();
                    var driverDesc = nicKey.GetValue("DriverDesc")?.ToString() ?? "";

                    if (string.IsNullOrEmpty(networkAddress)) continue;

                    bool isVmNic = driverDesc.Contains("VMware", StringComparison.OrdinalIgnoreCase) ||
                                   driverDesc.Contains("VirtualBox", StringComparison.OrdinalIgnoreCase) ||
                                   driverDesc.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase) ||
                                   driverDesc.Contains("Virtual", StringComparison.OrdinalIgnoreCase);

                    if (isVmNic)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"MAC address spoofing on virtual NIC: {driverDesc}",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKLM\{MacSpoofKey}\{instanceName}",
                            Reason = "A virtual network adapter has a custom MAC address (NetworkAddress) " +
                                     "configured. Anti-cheat VM detection commonly checks whether the MAC " +
                                     "address belongs to a VM vendor (VMware OUI 00:0C:29, VirtualBox OUI " +
                                     "08:00:27 etc.). Spoofing to a real NIC vendor OUI is used to evade " +
                                     "VM detection in anti-cheat systems.",
                            Detail = $"Adapter: {driverDesc} · Custom MAC: {networkAddress}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "…";
}
