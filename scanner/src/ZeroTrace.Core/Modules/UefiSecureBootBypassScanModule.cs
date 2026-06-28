using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class UefiSecureBootBypassScanModule : IScanModule
{
    public string Name => "UEFI / Secure Boot Bypass Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    private static readonly string[] BootkitFileNames =
    [
        "bootkit.efi", "uefi_hack.efi", "secureboot_bypass.efi",
        "BlackLotus.efi", "blacklotus.efi", "bootx64_patch.efi",
        "grubx64_mod.efi", "shimx64_bypass.efi", "moonbounce.efi",
        "cosmicstrand.efi", "finspy.efi", "vectoredescape.efi",
        "especter.efi", "espooky.efi", "ueficanhazbuffet.efi",
        "rockboot.efi", "hacking_team_uefi.efi", "lojax.efi",
        "uefi_implant.efi", "uefi_rootkit.efi",
    ];

    private static readonly string[] BypassToolNames =
    [
        "secureboot_bypass.exe", "sbbypass.exe", "uefi_patcher.exe",
        "bootkit_installer.exe", "uefi_rootkit.exe", "efi_injector.exe",
        "shimboot_bypass.exe", "mokutil_bypass.exe", "sbctl_bypass.exe",
        "pk_bypass.exe", "db_bypass.exe", "dbx_bypass.exe",
        "uefi_bypass.exe", "secure_boot_bypass.exe", "uefi_exploit.exe",
        "boot_bypass.exe", "bcd_tamper.exe", "bootmgr_patch.exe",
        "winload_patch.exe", "efi_tamper.exe", "efi_patch.exe",
        "uefi_write.exe", "nvram_write.exe", "fwupd_bypass.exe",
        "capsule_bypass.exe", "uefi_flash.exe", "spi_flash.exe",
        "hvci_bypass.exe", "vbs_bypass.exe", "devguard_bypass.exe",
        "hypervisor_bypass.exe", "kvm_bypass.exe", "hyperv_bypass.exe",
        "bitlocker_bypass.exe", "tpm_bypass.exe", "cold_boot.exe",
        "tpm_extract.exe", "bitcracker.exe", "bitleaker.exe",
        "tpm_bleed.exe", "evil_maid.exe",
    ];

    private static readonly string[] BcdTamperKeywords =
    [
        "testsigning", "nointegritychecks", "loadoptions", "safeboot",
        "disableelamappinflight", "bootdebug", "debug", "nx AlwaysOff",
        "nx OptIn", "hyperisorlaunchtype off", "nointegritycheck",
        "kernel", "winpe", "ems", "sos", "quietboot",
        "vsmlaunchtype off", "vsmlaunchtype auto",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>
        {
            ScanEfiPartitionAsync(ctx, ct),
            ScanBypassToolsAsync(ctx, ct),
            ScanBootConfigRegistryAsync(ctx, ct),
            ScanHvciVbsRegistryAsync(ctx, ct),
            ScanSecureBootRegistryAsync(ctx, ct),
            ScanWindowsBootFilesAsync(ctx, ct),
            ScanBitLockerTpmArtifactsAsync(ctx, ct),
            ScanSystemDriversForBootkitsAsync(ctx, ct),
        };
        await Task.WhenAll(tasks);
    }

    private async Task ScanEfiPartitionAsync(ScanContext ctx, CancellationToken ct)
    {
        // EFI System Partition typically mounted at a hidden path
        // Check for bootkit EFI files in Windows boot paths accessible from user-space
        var efiPaths = new[]
        {
            @"C:\EFI\Microsoft\Boot\",
            @"C:\EFI\Boot\",
            @"C:\Windows\Boot\EFI\",
            @"C:\Windows\System32\Boot\",
        };

        foreach (var efiDir in efiPaths)
        {
            if (!Directory.Exists(efiDir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(efiDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                foreach (var bootkit in BootkitFileNames)
                {
                    if (fn.Equals(bootkit, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "UEFI Bootkit File Detected",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known UEFI bootkit EFI file '{fn}' found in boot partition",
                            Detail = "UEFI bootkits persist through OS reinstalls and survive at firmware level"
                        });
                        break;
                    }
                }

                // Unexpected .efi files outside of known legitimate names
                var ext = Path.GetExtension(fn).ToLowerInvariant();
                if (ext == ".efi")
                {
                    var knownLegit = new[] { "bootmgfw.efi", "bootx64.efi", "grubx64.efi", "shimx64.efi", "mmx64.efi", "fbx64.efi", "MokManager.efi" };
                    if (!knownLegit.Any(l => fn.Equals(l, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Unexpected EFI File in Boot Partition",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Unexpected EFI file '{fn}' in Windows boot directory",
                            Detail = "Non-standard EFI files may indicate UEFI bootkit or implant"
                        });
                    }
                }
            }
        }

        // Check bootmgfw.efi size anomaly
        var bootmgrPath = @"C:\Windows\Boot\EFI\bootmgfw.efi";
        if (File.Exists(bootmgrPath))
        {
            try
            {
                ctx.IncrementFiles();
                var info = new FileInfo(bootmgrPath);
                // Normal bootmgfw.efi is typically 1.5–2.5 MB
                if (info.Length < 500_000 || info.Length > 5_000_000)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "bootmgfw.efi Size Anomaly",
                        Risk = RiskLevel.High,
                        Location = bootmgrPath,
                        FileName = "bootmgfw.efi",
                        Reason = $"bootmgfw.efi has unexpected size: {info.Length / 1024} KB",
                        Detail = "Unexpected size may indicate bootmgfw.efi replacement/tampering"
                    });
                }
            }
            catch (IOException) { }
        }
        await Task.CompletedTask;
    }

    private async Task ScanBypassToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
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
                ctx.IncrementFiles();

                foreach (var tool in BypassToolNames)
                {
                    if (fn.Equals(tool, StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains(tool.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "UEFI/Secure Boot Bypass Tool",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"UEFI/Secure Boot bypass tool '{fn}' found",
                            Detail = "Tools that bypass Secure Boot or UEFI integrity are used by cheat rootkits"
                        });
                        break;
                    }
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanBootConfigRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check for testsigning mode (allows unsigned drivers — used by cheat rootkits)
            try
            {
                using var ciKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Protected");
                if (ciKey != null)
                {
                    ctx.IncrementRegistryKeys();
                    var protected_ = ciKey.GetValue("Protected");
                    if (protected_ is int p && p == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Code Integrity Protection Disabled",
                            Risk = RiskLevel.Critical,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Protected",
                            FileName = "Registry",
                            Reason = "CI\\Protected=0 — Windows code integrity protection disabled",
                            Detail = "Allows unsigned kernel drivers — used by cheat rootkits and BYOVD attacks"
                        });
                    }
                }
            }
            catch { }

            // Check boot options
            try
            {
                using var bootKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
                if (bootKey != null)
                {
                    ctx.IncrementRegistryKeys();
                    // VerifyDrivers — 0 disables driver verification
                    var verifyDrivers = bootKey.GetValue("VerifyDriverLevel");
                    if (verifyDrivers is int vd && vd == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Driver Verification Disabled",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                            FileName = "Registry",
                            Reason = "VerifyDriverLevel=0 — kernel driver verification disabled",
                            Detail = "Disabling driver verification allows rootkit drivers to load"
                        });
                    }
                }
            }
            catch { }

            // System integrity policy settings
            try
            {
                using var siPolicy = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Policy");
                if (siPolicy != null)
                {
                    ctx.IncrementRegistryKeys();
                    var umci = siPolicy.GetValue("VerifiedAndReputablePolicyState");
                    if (umci is int v && v == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Smart App Control Disabled",
                            Risk = RiskLevel.Medium,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
                            FileName = "Registry",
                            Reason = "Windows Smart App Control (WDAC) disabled",
                            Detail = "May indicate bypass of Windows integrity policies by cheat loader"
                        });
                    }
                }
            }
            catch { }
        }, ct);
    }

    private async Task ScanHvciVbsRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Virtualization Based Security (VBS) / HVCI
            try
            {
                using var vbs = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard");
                if (vbs != null)
                {
                    ctx.IncrementRegistryKeys();
                    var vbsEnabled = vbs.GetValue("EnableVirtualizationBasedSecurity");
                    if (vbsEnabled is int v && v == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "VBS (HVCI) Disabled",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
                            FileName = "Registry",
                            Reason = "Virtualization Based Security disabled — HVCI kernel protection off",
                            Detail = "Without VBS/HVCI, kernel memory can be modified by cheat drivers"
                        });
                    }

                    var hvci = vbs.GetValue("HypervisorEnforcedCodeIntegrity");
                    if (hvci is int h && h == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "HVCI Disabled",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
                            FileName = "Registry",
                            Reason = "Hypervisor-Protected Code Integrity disabled",
                            Detail = "HVCI enforces kernel code signing — disabling allows driver bypass"
                        });
                    }
                }
            }
            catch { }

            // Credential Guard / LSA protection
            try
            {
                using var lsa = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
                if (lsa != null)
                {
                    ctx.IncrementRegistryKeys();
                    var lsaCfgFlags = lsa.GetValue("LsaCfgFlags");
                    if (lsaCfgFlags is int l && l == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Credential Guard Disabled",
                            Risk = RiskLevel.Medium,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                            FileName = "Registry",
                            Reason = "Credential Guard disabled (LsaCfgFlags=0)",
                            Detail = "Some cheat loaders disable Credential Guard to bypass security policies"
                        });
                    }
                }
            }
            catch { }

            // Device Guard policy
            try
            {
                using var dg = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard");
                if (dg != null)
                {
                    ctx.IncrementRegistryKeys();
                    var enableVbs = dg.GetValue("EnableVirtualizationBasedSecurity");
                    if (enableVbs is int e && e == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Device Guard VBS Policy Disabled",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                            FileName = "Registry",
                            Reason = "Device Guard Virtualization Based Security policy disabled",
                            Detail = "Group policy disabling VBS — allows kernel rootkit drivers"
                        });
                    }
                }
            }
            catch { }
        }, ct);
    }

    private async Task ScanSecureBootRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Secure Boot state
            try
            {
                using var sb = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                if (sb != null)
                {
                    ctx.IncrementRegistryKeys();
                    var state = sb.GetValue("UEFISecureBootEnabled");
                    if (state is int s && s == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "UEFI Secure Boot Disabled",
                            Risk = RiskLevel.Critical,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                            FileName = "Registry",
                            Reason = "UEFI Secure Boot is disabled (UEFISecureBootEnabled=0)",
                            Detail = "Secure Boot disabled allows UEFI bootkits and unsigned drivers to load at boot"
                        });
                    }
                }
            }
            catch { }

            // Check Secure Boot policy mode
            try
            {
                using var sbPolicy = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot");
                if (sbPolicy != null)
                {
                    ctx.IncrementRegistryKeys();
                    var policyMode = sbPolicy.GetValue("PolicyMode");
                    if (policyMode is int pm && pm != 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Secure Boot Policy Mode Anomaly",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot",
                            FileName = "Registry",
                            Reason = $"Secure Boot PolicyMode={pm} (expected 1=Audit, should be enforcement mode)",
                            Detail = "Non-standard Secure Boot policy mode may indicate bypass attempt"
                        });
                    }
                }
            }
            catch { }
        }, ct);
    }

    private async Task ScanWindowsBootFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var bootFiles = new Dictionary<string, (long MinBytes, long MaxBytes)>
        {
            { @"C:\Windows\System32\winload.efi", (500_000, 2_500_000) },
            { @"C:\Windows\System32\bootmgr", (300_000, 1_500_000) },
            { @"C:\Windows\System32\ntoskrnl.exe", (5_000_000, 25_000_000) },
            { @"C:\Windows\System32\hal.dll", (100_000, 1_000_000) },
        };

        foreach (var (path, (min, max)) in bootFiles)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(path)) continue;

            try
            {
                ctx.IncrementFiles();
                var info = new FileInfo(path);
                if (info.Length < min || info.Length > max)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Windows Boot File Size Anomaly: {Path.GetFileName(path)}",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = Path.GetFileName(path),
                        Reason = $"{Path.GetFileName(path)} has unexpected size: {info.Length / 1024} KB (expected {min / 1024}–{max / 1024} KB)",
                        Detail = "Boot file size outside expected range may indicate tampering or replacement"
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        await Task.CompletedTask;
    }

    private async Task ScanBitLockerTpmArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        var tpmBypassFiles = new[]
        {
            "tpm_extract.exe", "tpm_bypass.exe", "bitcracker.exe", "bitleaker.exe",
            "tpm_bleed.exe", "evil_maid.exe", "cold_boot.exe", "cold_boot_attack.exe",
            "bitlocker_bypass.exe", "bitlocker_crack.exe", "bl_bypass.exe",
            "tpm_dump.exe", "tpm_keys.exe", "tpm_extract_keys.exe",
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

                if (tpmBypassFiles.Any(t => fn.Equals(t, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "BitLocker/TPM Bypass Tool",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"BitLocker/TPM bypass or key extraction tool '{fn}' found",
                        Detail = "TPM bypass tools used for evil maid attacks and cheat loader bypasses"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanSystemDriversForBootkitsAsync(ScanContext ctx, CancellationToken ct)
    {
        // Scan for bootkit-related driver names in System32\drivers
        var driversDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
        if (!Directory.Exists(driversDir)) return;

        string[] sysFiles;
        try { sysFiles = Directory.GetFiles(driversDir, "*.sys"); }
        catch (UnauthorizedAccessException) { return; }

        var suspectDrivers = new[]
        {
            "bootkit.sys", "uefi_drv.sys", "secureboot_bypass.sys",
            "blacklotus.sys", "moonbounce.sys", "efi_drv.sys",
            "bcd_tamper.sys", "boot_inject.sys", "preboot.sys",
            "uefi_implant.sys", "firmware_drv.sys", "nvram_drv.sys",
        };

        foreach (var sysFile in sysFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fn = Path.GetFileName(sysFile);

            if (suspectDrivers.Any(s => fn.Equals(s, StringComparison.OrdinalIgnoreCase)))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Bootkit Driver in System32",
                    Risk = RiskLevel.Critical,
                    Location = sysFile,
                    FileName = fn,
                    Reason = $"Known bootkit-related driver '{fn}' found in System32\\drivers",
                    Detail = "Bootkit drivers that persist through reboots and survive OS reinstall"
                });
            }
        }
        await Task.CompletedTask;
    }
}
