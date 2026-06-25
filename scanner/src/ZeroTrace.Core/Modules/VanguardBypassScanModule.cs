using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class VanguardBypassScanModule : IScanModule
{
    public string Name => "Riot Vanguard Bypass Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Environment paths
    // -------------------------------------------------------------------------
    private static readonly string SystemRoot =
        Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";

    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    private static readonly string Downloads =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly string TempDir = Path.GetTempPath();

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    // -------------------------------------------------------------------------
    // Vanguard bypass tool file names — any match is Critical
    // -------------------------------------------------------------------------
    private static readonly string[] BypassToolFileNames =
    [
        "vanguard_bypass.exe",
        "VanguardBypass.exe",
        "vanguard-bypass.exe",
        "vgk_bypass.dll",
        "vgk_bypass.exe",
        "vgk_killer.exe",
        "vgk_unloader.exe",
        "vgk_patch.exe",
        "vgk_disable.bat",
        "vgk_disable.exe",
        "vgk_stop.exe",
        "vgk_remove.exe",
        "vgk_emu.dll",
        "vgk_emulator.dll",
        "vanguard_spoofer.exe",
        "VanguardSpoofer.exe",
        "valorant_bypass.exe",
        "ValorantBypass.exe",
        "valorant-bypass.exe",
        "AntiCheatKiller.exe",
        "vgc_bypass.exe",
        "vgc_kill.exe",
        "vgc_killer.exe",
        "vgc_disable.exe",
        "vgc_patch.exe",
        "vgc_unloader.exe",
        "vgkiller.exe",
        "VGKiller.exe",
        "VGC_Bypass.exe",
        "RiotBypass.exe",
        "riot_bypass.exe",
        "vanguard_hook.dll",
        "vgk_hook.dll",
        "vgk_loader.exe",
        "BypassVanguard.exe",
        "bypass_vgk.exe",
        "vanguard_patch.exe",
        "vanguard_disable.exe",
        "VanguardDisable.exe",
        "VanguardKiller.exe",
        "vanguard_killer.exe",
        "vgk_inject.dll",
        "vgk_inject.exe",
        "vanguard_inject.dll",
        "VanguardEmu.exe",
        "vanguard_emu.exe",
        "vgk_emu.exe",
        "vgk_emulator.exe",
        "vgk_spoof.exe",
        "vanguard_unloader.exe",
        "VanguardUnloader.exe",
        "vanguard_remover.exe",
        "valorant_spoofer.exe",
        "ValorantSpoofer.exe",
    ];

    // -------------------------------------------------------------------------
    // BYOVD drivers commonly used to kill Vanguard (vgk) kernel callbacks
    // -------------------------------------------------------------------------
    private static readonly (string FileName, string Cve, string Description)[] ByovdDrivers =
    [
        ("gdrv.sys",            "CVE-2018-19320", "Gigabyte hardware driver with kernel R/W exploit"),
        ("RTCore64.sys",        "CVE-2019-16098", "MSI Afterburner RTCore64 with kernel R/W exploit"),
        ("dbutil_2_3.sys",      "CVE-2021-21551", "Dell BIOS utility driver with kernel privilege escalation"),
        ("WinRing0x64.sys",     "N/A",            "WinRing0 hardware monitor driver abused for kernel access"),
        ("WinRing0.sys",        "N/A",            "WinRing0 (32-bit) hardware monitor driver abused for kernel access"),
        ("AsrDrv103.sys",       "N/A",            "ASRock motherboard driver with kernel R/W exploit"),
        ("HwRwDrv.sys",         "N/A",            "Hardware read/write driver abused for kernel callback removal"),
        ("MsIo64.sys",          "N/A",            "MSI companion driver with unauthenticated kernel I/O"),
        ("iqvw64e.sys",         "CVE-2015-2291",  "Intel network adapter diagnostics driver with kernel exploit"),
        ("cpuz141_x64.sys",     "N/A",            "CPU-Z hardware monitor driver abused for kernel access"),
        ("cpuz143_x64.sys",     "N/A",            "CPU-Z 1.43 driver variant abused for kernel access"),
        ("kprocesshacker.sys",  "N/A",            "Process Hacker kernel driver used for process/callback manipulation"),
        ("ATSZIO64.sys",        "N/A",            "ASUSTeK System IO driver with kernel R/W exploit"),
        ("WinIo64.sys",         "N/A",            "WinIo 64-bit I/O driver abused for kernel memory access"),
        ("rwdrv.sys",           "N/A",            "RWEverything driver with unrestricted kernel memory access"),
        ("viragt64.sys",        "N/A",            "ViRobot antivirus driver abused for kernel access"),
        ("mhyprot2.sys",        "CVE-2022-0185",  "MiHoYo anti-cheat driver repurposed for kernel manipulation"),
        ("AsIO3.sys",           "N/A",            "ASUS ACPIO driver with kernel R/W primitives"),
        ("Speedfan.sys",        "N/A",            "SpeedFan driver with physical memory access exploit"),
        ("phymem64.sys",        "N/A",            "Physical memory access driver abused for kernel patching"),
        ("nicm.sys",            "N/A",            "NZXT Cam driver with kernel memory R/W exploit"),
    ];

    // -------------------------------------------------------------------------
    // GitHub clone directory names for Vanguard bypass repos
    // -------------------------------------------------------------------------
    private static readonly string[] BypassRepoDirNames =
    [
        "vanguard-bypass",
        "vgk-bypass",
        "valorant-bypass",
        "vanguard-emulator",
        "vgk-emu",
        "VanguardBypass",
        "VGKBypass",
        "ValorantBypass",
        "riot-bypass",
        "vanguard-cheat",
        "valorant-cheat",
        "vgk-hook",
        "vgk-spoofer",
        "vgk-disable",
        "VGK-Disable",
        "vgk-unloader",
        "vanguard-unloader",
        "valorant-hack",
        "riot-vanguard-bypass",
        "vanguard_bypass",
    ];

    // -------------------------------------------------------------------------
    // PowerShell/batch history patterns targeting Vanguard
    // -------------------------------------------------------------------------
    private static readonly (string Pattern, RiskLevel Risk, string Title)[] PsHistoryPatterns =
    [
        ("sc stop vgk",                          RiskLevel.Critical, "Vanguard Kernel Driver Stopped via sc.exe"),
        ("sc stop vgc",                          RiskLevel.Critical, "Vanguard Client Service Stopped via sc.exe"),
        ("sc delete vgk",                        RiskLevel.Critical, "Vanguard Kernel Driver Deleted via sc.exe"),
        ("sc delete vgc",                        RiskLevel.Critical, "Vanguard Client Service Deleted via sc.exe"),
        ("net stop vgk",                         RiskLevel.Critical, "Vanguard Kernel Driver Stopped via net stop"),
        ("net stop vgc",                         RiskLevel.Critical, "Vanguard Client Service Stopped via net stop"),
        ("taskkill /im vgc.exe",                 RiskLevel.Critical, "Vanguard Client Process Killed via taskkill"),
        ("taskkill /f /im vgc.exe",              RiskLevel.Critical, "Vanguard Client Process Force-Killed via taskkill"),
        ("taskkill /im vgk.exe",                 RiskLevel.High,     "Vanguard Kernel Driver Process Terminated via taskkill"),
        ("bcdedit /set testsigning on",          RiskLevel.Critical, "Test Signing Mode Enabled (DSE Bypass) via bcdedit"),
        ("bcdedit /set nointegritychecks on",    RiskLevel.Critical, "Driver Integrity Checks Disabled via bcdedit"),
        ("bcdedit /set loadoptions DISABLE_INTEGRITY_CHECKS", RiskLevel.Critical, "Boot Driver Integrity Disabled via bcdedit"),
        ("kdmapper",                             RiskLevel.Critical, "kdmapper Unsigned Driver Mapper in PS History"),
        ("vgk_bypass",                           RiskLevel.Critical, "Vanguard Kernel Bypass Script Reference in PS History"),
        ("vanguard_bypass",                      RiskLevel.Critical, "Vanguard Bypass Script Reference in PS History"),
        ("sc config vgk start= disabled",        RiskLevel.Critical, "Vanguard Kernel Driver Disabled via sc config"),
        ("sc config vgc start= disabled",        RiskLevel.Critical, "Vanguard Client Service Disabled via sc config"),
        ("reg add.*vgk",                         RiskLevel.High,     "Registry Modification Targeting Vanguard vgk Key"),
        ("reg add.*vgc",                         RiskLevel.High,     "Registry Modification Targeting Vanguard vgc Key"),
        ("PatchGuard",                           RiskLevel.Critical, "PatchGuard Bypass Artifact in PS History"),
        ("EtwpDisablePatchGuard",                RiskLevel.Critical, "EtwpDisablePatchGuard Call in PS History"),
        ("NtLoadDriver",                         RiskLevel.High,     "NtLoadDriver API Call in PS History"),
        ("DSE bypass",                           RiskLevel.Critical, "Driver Signature Enforcement Bypass in PS History"),
        ("VulnerableDriverBlocklistEnable",      RiskLevel.High,     "Vulnerable Driver Blocklist Modification in PS History"),
    ];

    // -------------------------------------------------------------------------
    // Known Valorant cheat folder names in AppData locations
    // -------------------------------------------------------------------------
    private static readonly string[] ValCheatFolderNames =
    [
        "ValorantCheat",
        "valorant_cheat",
        "ValorantHack",
        "valorant_hack",
        "ValorantAimbot",
        "ValorantESP",
        "ValorantWallhack",
        "ValorantTrigger",
        "val_cheat",
        "val_hack",
        "VGKBypass",
        "VanguardBypass",
        "valorant-bypass",
        "valorant_bypass",
        "ValorantUnban",
        "valorant_unban",
        "ValESP",
        "ValAimbot",
        "ValorantLoader",
        "valorant_loader",
        "RiotCheat",
        "riot_cheat",
        "ValorantMod",
        "valorant_mod",
    ];

    // -------------------------------------------------------------------------
    // Known Valorant cheat process names
    // -------------------------------------------------------------------------
    private static readonly string[] ValCheatProcessNames =
    [
        "valorant_aimbot",
        "valorant_esp",
        "valorant_hack",
        "valorant_cheat",
        "valorant_wallhack",
        "valorant_trigger",
        "val_aimbot",
        "val_esp",
        "val_cheat",
        "val_hack",
        "ValAimbot",
        "ValESP",
        "ValWH",
        "ValTrigger",
        "ValorantLoader",
        "valorant_loader",
        "RiotAimbot",
        "riot_aimbot",
        "vanguard_bypass",
        "vgk_bypass",
        "vgk_killer",
        "vgc_bypass",
        "VGKBypass",
        "VanguardBypass",
        "valorant_spoofer",
        "ValSpoofer",
        "valorantbot",
        "val_bot",
        "ValorantBot",
        "valorant_radar",
        "ValRadar",
        "valorant_skin",
        "ValSkin",
        "valorant_unban",
        "ValUnban",
        "AimtrainerOverlay",
        "AimOverlay",
        "ValorantOverlay",
        "val_overlay",
    ];

    // =========================================================================
    // Entry point
    // =========================================================================
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await CheckVanguardServiceRegistryAsync(ctx, ct);
        await ScanBypassToolFilesAsync(ctx, ct);
        await CheckByovdDriversAsync(ctx, ct);
        await CheckBypassRepoDirsAsync(ctx, ct);
        await CheckPowerShellHistoryAsync(ctx, ct);
        await CheckCertificateStoreTamperingAsync(ctx, ct);
        await CheckTestSigningArtifactsAsync(ctx, ct);
        await CheckValCheatFoldersAsync(ctx, ct);
        await CheckValCheatProcessesAsync(ctx, ct);
        await ScanBatchScriptFilesAsync(ctx, ct);
    }

    // =========================================================================
    // 1. Vanguard service registry checks (vgk and vgc)
    // =========================================================================
    private async Task CheckVanguardServiceRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var serviceChecks = new[]
            {
                (
                    KeyPath:     @"SYSTEM\CurrentControlSet\Services\vgk",
                    ServiceName: "vgk",
                    FriendlyName: "Vanguard Kernel Driver",
                    ExpectedPath: Path.Combine(SystemRoot, @"System32\drivers\vgk.sys")
                ),
                (
                    KeyPath:     @"SYSTEM\CurrentControlSet\Services\vgc",
                    ServiceName: "vgc",
                    FriendlyName: "Vanguard Client Service",
                    ExpectedPath: string.Empty
                ),
            };

            foreach (var svc in serviceChecks)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(svc.KeyPath, writable: false);
                    if (key is null)
                        continue;

                    object? startVal = key.GetValue("Start");
                    if (startVal is int startInt && startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"{svc.FriendlyName} Disabled in Registry",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{svc.KeyPath}",
                            Reason   = $"The {svc.FriendlyName} ({svc.ServiceName}) Start value is 4 (Disabled). A bypass tool may have disabled this service to prevent Vanguard from loading.",
                            Detail   = $"Start = {startInt}",
                        });
                    }

                    object? imagePathVal = key.GetValue("ImagePath");
                    if (imagePathVal is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                    {
                        string expandedPath = Environment.ExpandEnvironmentVariables(imagePath);

                        if (!string.IsNullOrEmpty(svc.ExpectedPath))
                        {
                            if (!expandedPath.Contains("vgk.sys", StringComparison.OrdinalIgnoreCase) ||
                                !expandedPath.Contains(@"System32\drivers", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"{svc.FriendlyName} ImagePath Outside Expected Location",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM\{svc.KeyPath}",
                                    Reason   = $"The {svc.FriendlyName} ImagePath does not reference the expected System32\\drivers\\vgk.sys path. The driver binary may have been redirected by a bypass tool.",
                                    Detail   = $"ImagePath = {imagePath}",
                                });
                            }
                        }

                        if (IsInSuspiciousUserPath(expandedPath))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"{svc.FriendlyName} ImagePath in User-Writable Location",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{svc.KeyPath}",
                                Reason   = $"The {svc.FriendlyName} ImagePath points to a Temp, Downloads, or AppData directory. This strongly indicates binary substitution by a bypass tool.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }
        }, ct);
    }

    // =========================================================================
    // 2. Known bypass tool file scan across user directories
    // =========================================================================
    private async Task ScanBypassToolFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs = BuildScanDirectories();

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                try
                {
                    foreach (string bad in BypassToolFileNames)
                    {
                        if (fileName.Equals(bad, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Known Vanguard Bypass Tool Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File name \"{fileName}\" matches a known Riot Vanguard bypass tool. This software is specifically designed to circumvent Vanguard anti-cheat protection.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 3. BYOVD (Bring Your Own Vulnerable Driver) detection
    // =========================================================================
    private async Task CheckByovdDriversAsync(ScanContext ctx, CancellationToken ct)
    {
        string driversDir = Path.Combine(SystemRoot, "System32", "drivers");

        string[] searchDirs =
        [
            TempDir,
            Downloads,
            Desktop,
            Documents,
            AppDataRoaming,
            AppDataLocal,
            driversDir,
        ];

        foreach (string dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.sys",
                    dir.Equals(driversDir, StringComparison.OrdinalIgnoreCase)
                        ? SearchOption.TopDirectoryOnly
                        : SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                try
                {
                    foreach (var (driverFile, cve, description) in ByovdDrivers)
                    {
                        if (fileName.Equals(driverFile, StringComparison.OrdinalIgnoreCase))
                        {
                            bool inSystemDir = filePath.StartsWith(driversDir,
                                StringComparison.OrdinalIgnoreCase);

                            RiskLevel risk = inSystemDir ? RiskLevel.High : RiskLevel.Critical;
                            string locationNote = inSystemDir
                                ? "found in System32\\drivers (may be legitimately installed but check usage)"
                                : "found outside System32\\drivers (strongly suspicious)";

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"BYOVD Driver Detected: {driverFile}",
                                Risk     = risk,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"Known vulnerable driver \"{driverFile}\" ({description}) detected. This driver is commonly used in BYOVD attacks to kill Vanguard kernel callbacks. {locationNote}.",
                                Detail   = string.IsNullOrEmpty(cve) ? description : $"CVE: {cve} — {description}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 4. GitHub clone directory names for Vanguard bypass repos
    // =========================================================================
    private async Task CheckBypassRepoDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] repoSearchRoots =
        [
            Desktop,
            Downloads,
            Documents,
            UserProfile,
            AppDataRoaming,
            AppDataLocal,
            Path.Combine(UserProfile, "source"),
            Path.Combine(UserProfile, "repos"),
            Path.Combine(UserProfile, "projects"),
            Path.Combine(UserProfile, "git"),
            Path.Combine(UserProfile, "GitHub"),
            Path.Combine(UserProfile, "GitLab"),
        ];

        foreach (string root in repoSearchRoots)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(root))
                continue;

            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();

                string dirName = Path.GetFileName(subdir);

                foreach (string repoName in BypassRepoDirNames)
                {
                    if (dirName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                    {
                        bool hasGitFolder = Directory.Exists(Path.Combine(subdir, ".git"));

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Vanguard Bypass GitHub Repository Clone Detected",
                            Risk     = RiskLevel.Critical,
                            Location = subdir,
                            FileName = dirName,
                            Reason   = $"Directory \"{dirName}\" matches a known Riot Vanguard bypass repository name. This suggests the user cloned bypass source code or tools from a public code repository.",
                            Detail   = hasGitFolder
                                ? $"Git repository confirmed (.git folder present). Clone path: {subdir}"
                                : $"Directory name matches but no .git folder found. Path: {subdir}",
                        });
                        break;
                    }
                }

                // Also check one level deeper (e.g. root/user/vanguard-bypass)
                IEnumerable<string> nestedDirs;
                try
                {
                    nestedDirs = Directory.EnumerateDirectories(subdir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string nested in nestedDirs)
                {
                    ct.ThrowIfCancellationRequested();

                    string nestedName = Path.GetFileName(nested);
                    foreach (string repoName in BypassRepoDirNames)
                    {
                        if (nestedName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                        {
                            bool hasGit = Directory.Exists(Path.Combine(nested, ".git"));
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Vanguard Bypass Repository Clone (Nested) Detected",
                                Risk     = RiskLevel.Critical,
                                Location = nested,
                                FileName = nestedName,
                                Reason   = $"Directory \"{nestedName}\" matches a known Vanguard bypass repository name (found nested under {Path.GetFileName(subdir)}).",
                                Detail   = hasGit
                                    ? $"Git repo confirmed. Path: {nested}"
                                    : $"Path: {nested}",
                            });
                            break;
                        }
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 5. PowerShell history scanning
    // =========================================================================
    private async Task CheckPowerShellHistoryAsync(ScanContext ctx, CancellationToken ct)
    {
        // PowerShell 5+ history file
        string ps5History = Path.Combine(
            AppDataRoaming,
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

        // PowerShell Core (7+) history
        string psCoreHistory = Path.Combine(
            AppDataRoaming,
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

        // cmd.exe does not maintain a persistent history file by default,
        // but some third-party tools write one — check common locations
        string[] cmdHistoryPaths =
        [
            Path.Combine(UserProfile, "AppData", "Roaming", "doskey.log"),
            Path.Combine(UserProfile, ".bash_history"),
        ];

        var historyFiles = new List<string> { ps5History, psCoreHistory };
        historyFiles.AddRange(cmdHistoryPaths);

        foreach (string histFile in historyFiles)
        {
            ct.ThrowIfCancellationRequested();

            if (!File.Exists(histFile))
                continue;

            string content;
            try
            {
                using var fs = new FileStream(histFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(content))
                continue;

            ctx.IncrementFiles();

            string[] lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (string rawLine in lines)
            {
                ct.ThrowIfCancellationRequested();

                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line))
                    continue;

                foreach (var (pattern, risk, title) in PsHistoryPatterns)
                {
                    if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = title,
                            Risk     = risk,
                            Location = histFile,
                            FileName = Path.GetFileName(histFile),
                            Reason   = $"Shell history entry matches Vanguard bypass pattern \"{pattern}\". This indicates the user executed commands to disable or circumvent Vanguard.",
                            Detail   = $"Matched line: {line.Substring(0, Math.Min(line.Length, 300))}",
                        });
                        break;
                    }
                }
            }
        }
    }

    // =========================================================================
    // 6. Certificate store tampering (Riot Games signing cert removal)
    // =========================================================================
    private async Task CheckCertificateStoreTamperingAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Attackers may add Riot Games certs to the Disallowed store to
            // prevent Vanguard from verifying its own driver signature.
            string[] disallowedPaths =
            [
                @"SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates",
                @"SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\Certificates",
            ];

            foreach (string regPath in disallowedPaths)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                    if (key is null)
                        continue;

                    string[] subkeyNames = key.GetSubKeyNames();
                    foreach (string thumbprint in subkeyNames)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Certificate in Disallowed Store (Possible Vanguard Signature Block)",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{regPath}\{thumbprint}",
                            Reason   = "A certificate exists in the system Disallowed certificate store. Placing a Riot Games code-signing certificate here prevents Vanguard from verifying its own driver signature, which is a known bypass technique.",
                            Detail   = $"Thumbprint subkey: {thumbprint}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }

            // Check the ROOT store for rogue entries that could shadow Riot's cert
            string rootCertsPath = @"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates";
            ctx.IncrementRegistryKeys();
            try
            {
                using RegistryKey? rootKey = Registry.LocalMachine.OpenSubKey(rootCertsPath, writable: false);
                if (rootKey is not null)
                {
                    // We only flag if there are extremely many certs (attacker-planted)
                    // Normal systems have ~30-60; >200 is anomalous
                    int count = rootKey.GetSubKeyNames().Length;
                    if (count > 200)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Anomalous Number of Root Certificates Installed",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{rootCertsPath}",
                            Reason   = $"An unusually large number of root certificates ({count}) are installed in the system store. Bypass tools sometimes inject rogue CA certificates to shadow legitimate signing chains.",
                            Detail   = $"Certificate count: {count} (normal range: 30-60)",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }, ct);
    }

    // =========================================================================
    // 7. TestSigning / DSE bypass artifacts
    // =========================================================================
    private async Task CheckTestSigningArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // VulnerableDriverBlocklistEnable = 0 disables the Microsoft driver blocklist,
            // which is required to load BYOVD drivers on modern Windows
            string ciConfigPath = @"SYSTEM\CurrentControlSet\Control\CI\Configuration";
            ctx.IncrementRegistryKeys();

            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(ciConfigPath, writable: false);
                if (key is not null)
                {
                    object? blocklistVal = key.GetValue("VulnerableDriverBlocklistEnable");
                    if (blocklistVal is int blocklistInt && blocklistInt == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Vulnerable Driver Blocklist Disabled",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{ciConfigPath}",
                            Reason   = "VulnerableDriverBlocklistEnable is set to 0, disabling Microsoft's built-in BYOVD driver blocklist. This is required for BYOVD attacks against Vanguard and is almost never disabled for legitimate reasons.",
                            Detail   = $"VulnerableDriverBlocklistEnable = {blocklistInt}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }

            // Check BCD-related registry for TestSigning
            string bcdobjectsPath = @"BCD00000000";
            ctx.IncrementRegistryKeys();
            try
            {
                using RegistryKey? bcdo = Registry.LocalMachine.OpenSubKey(bcdobjectsPath, writable: false);
                if (bcdo is not null)
                {
                    // The presence of this key means BCD was modified — test signing artifacts
                    // stored here by bcdedit. We flag conservatively since this is heuristic.
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "BCD Objects Registry Key Found",
                        Risk     = RiskLevel.Low,
                        Location = $@"HKLM\{bcdobjectsPath}",
                        Reason   = "The BCD00000000 registry key exists, indicating Boot Configuration Data was written via registry access rather than standard bcdedit. Some bypass tools modify BCD this way to enable test signing.",
                        Detail   = "Low confidence indicator — review in context of other findings.",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }

            // Check HKCU for bcdedit wrappers or test signing scripts
            string hkcuRunPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            ctx.IncrementRegistryKeys();
            try
            {
                using RegistryKey? runKey = Registry.CurrentUser.OpenSubKey(hkcuRunPath, writable: false);
                if (runKey is not null)
                {
                    foreach (string valueName in runKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        object? val = runKey.GetValue(valueName);
                        if (val is string runVal)
                        {
                            if (runVal.Contains("testsigning", StringComparison.OrdinalIgnoreCase) ||
                                runVal.Contains("vgk_bypass", StringComparison.OrdinalIgnoreCase) ||
                                runVal.Contains("vgk_disable", StringComparison.OrdinalIgnoreCase) ||
                                runVal.Contains("vanguard_bypass", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "Vanguard Bypass Command in HKCU Run Key",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKCU\{hkcuRunPath}\{valueName}",
                                    Reason   = $"A startup Run key value references Vanguard bypass or test signing commands, indicating a persistent bypass attempt.",
                                    Detail   = $"ValueName: {valueName} | Value: {runVal}",
                                });
                            }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }, ct);
    }

    // =========================================================================
    // 8. Valorant cheat folders in AppData
    // =========================================================================
    private async Task CheckValCheatFoldersAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] appDataRoots =
        [
            AppDataRoaming,
            AppDataLocal,
            Path.Combine(AppDataLocal, "Temp"),
        ];

        foreach (string root in appDataRoots)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(root))
                continue;

            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();

                string dirName = Path.GetFileName(subdir);

                foreach (string cheatDir in ValCheatFolderNames)
                {
                    if (dirName.Equals(cheatDir, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Valorant Cheat Folder Detected in AppData",
                            Risk     = RiskLevel.Critical,
                            Location = subdir,
                            FileName = dirName,
                            Reason   = $"Directory \"{dirName}\" in AppData matches a known Valorant cheat or bypass tool folder name.",
                            Detail   = $"Full path: {subdir}",
                        });
                        break;
                    }
                }

                // Heuristic: flag any AppData dir containing "valorant" and "cheat", "hack", "bypass", or "esp"
                if (dirName.Contains("valorant", StringComparison.OrdinalIgnoreCase) ||
                    dirName.Contains("vanguard", StringComparison.OrdinalIgnoreCase) ||
                    dirName.Contains("vgk", StringComparison.OrdinalIgnoreCase))
                {
                    if (dirName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains("esp", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains("spoof", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Suspicious Valorant/Vanguard-Related Folder in AppData",
                            Risk     = RiskLevel.High,
                            Location = subdir,
                            FileName = dirName,
                            Reason   = $"Directory name \"{dirName}\" combines Valorant/Vanguard keywords with cheat-related terms, indicating possible cheat tool residue.",
                            Detail   = $"Full path: {subdir}",
                        });
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 9. Valorant cheat process name detection
    // =========================================================================
    private async Task CheckValCheatProcessesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            System.Diagnostics.Process[] processes;
            try
            {
                processes = ctx.GetProcessSnapshot();
            }
            catch (Exception)
            {
                return;
            }

            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();

                string procName;
                try
                {
                    procName = proc.ProcessName;
                }
                catch (Exception)
                {
                    continue;
                }

                foreach (string cheatProc in ValCheatProcessNames)
                {
                    if (procName.Equals(cheatProc, StringComparison.OrdinalIgnoreCase))
                    {
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Known Valorant Cheat Process Running",
                            Risk     = RiskLevel.Critical,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = procName,
                            Reason   = $"Process \"{procName}\" (PID {proc.Id}) matches a known Valorant cheat or Vanguard bypass tool process name.",
                            Detail   = exePath is not null ? $"Executable: {exePath}" : $"PID: {proc.Id}",
                        });
                        break;
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 10. Batch / script file content scan for Vanguard disable commands
    // =========================================================================
    private async Task ScanBatchScriptFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] scanRoots =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataRoaming,
            AppDataLocal,
        ];

        string[] scriptExtensions = [".bat", ".cmd", ".ps1", ".vbs", ".py"];

        var suspiciousPatterns = new[]
        {
            ("sc stop vgk",                       RiskLevel.Critical),
            ("sc stop vgc",                       RiskLevel.Critical),
            ("sc delete vgk",                     RiskLevel.Critical),
            ("sc delete vgc",                     RiskLevel.Critical),
            ("net stop vgk",                      RiskLevel.Critical),
            ("net stop vgc",                      RiskLevel.Critical),
            ("taskkill.*vgc",                     RiskLevel.Critical),
            ("taskkill.*vgk",                     RiskLevel.Critical),
            ("bcdedit.*testsigning",              RiskLevel.Critical),
            ("bcdedit.*nointegritychecks",        RiskLevel.Critical),
            ("vgk_bypass",                        RiskLevel.Critical),
            ("vanguard_bypass",                   RiskLevel.Critical),
            ("vgk_disable",                       RiskLevel.High),
            ("vanguard_disable",                  RiskLevel.High),
            ("sc config vgk",                     RiskLevel.High),
            ("sc config vgc",                     RiskLevel.High),
        };

        foreach (string root in scanRoots)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(root))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                string ext = Path.GetExtension(filePath);
                bool isScript = false;
                foreach (string scriptExt in scriptExtensions)
                {
                    if (ext.Equals(scriptExt, StringComparison.OrdinalIgnoreCase))
                    {
                        isScript = true;
                        break;
                    }
                }
                if (!isScript)
                    continue;

                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException)
                {
                    continue;
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(content))
                    continue;

                foreach (var (pattern, risk) in suspiciousPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        string fileName = Path.GetFileName(filePath);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Vanguard Bypass Script Detected",
                            Risk     = risk,
                            Location = filePath,
                            FileName = fileName,
                            Reason   = $"Script file \"{fileName}\" contains Vanguard bypass command pattern \"{pattern}\". This script may be used to disable or circumvent Vanguard before launching a cheat.",
                            Detail   = $"Pattern matched: {pattern}",
                        });
                        break;
                    }
                }
            }
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================
    private static string[] BuildScanDirectories() =>
    [
        Desktop,
        Downloads,
        Documents,
        TempDir,
        AppDataRoaming,
        AppDataLocal,
        Path.Combine(AppDataLocal, "Temp"),
        Path.Combine(UserProfile, "Games"),
    ];

    private static bool IsInSuspiciousUserPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;

        string[] suspiciousSegments =
        [
            @"\Temp\",
            @"\Downloads\",
            @"\AppData\",
            @"/Temp/",
            @"/Downloads/",
        ];

        foreach (string seg in suspiciousSegments)
        {
            if (path.Contains(seg, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
