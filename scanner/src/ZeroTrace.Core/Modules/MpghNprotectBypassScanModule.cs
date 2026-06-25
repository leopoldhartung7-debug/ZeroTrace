using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class MpghNprotectBypassScanModule : IScanModule
{
    public string Name => "MPGH / nProtect / Xigncode Bypass Detection";
    public double Weight => 3.9;
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
    // nProtect GameGuard bypass tool names
    // -------------------------------------------------------------------------
    private static readonly string[] GameGuardBypassFileNames =
    [
        "gg_bypass.exe",
        "GGBypass.exe",
        "gameguard_bypass.dll",
        "gameguard_bypass.exe",
        "GameGuardBypass.exe",
        "GameGuard_Bypass.exe",
        "npgg_bypass.exe",
        "npgg_bypass.dll",
        "NPGGBypass.exe",
        "nProtect_bypass.exe",
        "nProtectBypass.exe",
        "nprotect_bypass.exe",
        "gg_kill.exe",
        "GGKill.exe",
        "gg_killer.exe",
        "GGKiller.exe",
        "nProtectKiller.exe",
        "nprotect_killer.exe",
        "GameGuardKiller.exe",
        "gameguard_kill.exe",
        "npggNT_patch.exe",
        "npggNT_bypass.exe",
        "npggNT_replace.exe",
        "gg_patch.exe",
        "GGPatch.exe",
        "npgg_patch.dll",
        "npgg_hook.dll",
        "gg_hook.dll",
        "gameguard_hook.dll",
        "gg_disable.exe",
        "gg_disable.bat",
        "npgg_disable.exe",
        "GameGuardDisable.exe",
        "gg_bypass.bat",
        "gg_emu.dll",
        "gameguard_emu.dll",
        "npgg_emu.dll",
    ];

    // -------------------------------------------------------------------------
    // nProtect GameGuard GitHub clone directory names
    // -------------------------------------------------------------------------
    private static readonly string[] GameGuardRepoDirNames =
    [
        "gameguard-bypass",
        "GameGuardBypass",
        "nprotect-bypass",
        "nProtectBypass",
        "npgg-bypass",
        "NPGGBypass",
        "gg-bypass",
        "GGBypass",
        "gameguard-hack",
        "GameGuard-Bypass",
        "nprotect-gameguard-bypass",
        "gameguard-emulator",
        "npgg-emu",
        "gameguard_bypass",
        "nprotect_bypass",
    ];

    // -------------------------------------------------------------------------
    // Xigncode3 bypass tool names
    // -------------------------------------------------------------------------
    private static readonly string[] XigncodeBypassFileNames =
    [
        "xigncode_bypass.exe",
        "XigncodeBypass.exe",
        "xigncode-bypass.exe",
        "x3_bypass.dll",
        "x3_bypass.exe",
        "X3Bypass.exe",
        "xcorona_bypass.exe",
        "XcoronaBypass.exe",
        "xcorona_bypass.dll",
        "xigncode_bypass.dll",
        "XignCodeBypass.exe",
        "XignCode_Bypass.exe",
        "xigncode_kill.exe",
        "xigncode_killer.exe",
        "XigncodeKiller.exe",
        "x3_kill.exe",
        "xcorona_kill.exe",
        "xigncode_patch.exe",
        "x3_patch.dll",
        "xcorona_patch.dll",
        "xigncode_hook.dll",
        "x3_hook.dll",
        "xigncode_disable.exe",
        "x3_disable.exe",
        "xigncode_emu.dll",
        "x3_emu.dll",
        "XigncodeEmu.exe",
        "x3_emulator.dll",
    ];

    // -------------------------------------------------------------------------
    // Xigncode GitHub clone directory names
    // -------------------------------------------------------------------------
    private static readonly string[] XigncodeRepoDirNames =
    [
        "xigncode-bypass",
        "XigncodeBypass",
        "x3-bypass",
        "X3Bypass",
        "xigncode3-bypass",
        "Xigncode3Bypass",
        "xcorona-bypass",
        "xigncode_bypass",
        "x3_bypass",
        "xhunter-bypass",
        "xigncode-emulator",
        "x3-emu",
    ];

    // -------------------------------------------------------------------------
    // MPGH-distributed tool file names (common MPGH-hosted hack names)
    // -------------------------------------------------------------------------
    private static readonly string[] MpghToolFileNames =
    [
        "mpgh_loader.exe",
        "MPGHLoader.exe",
        "mpgh_hack.exe",
        "MPGHHack.exe",
        "mpgh_cheat.exe",
        "mpgh_tool.exe",
        "MPGHTool.exe",
        "mpgh_injector.exe",
        "MPGHInjector.exe",
        "mpgh_bypass.exe",
        "MPGHBypass.exe",
        "mpgh_downloader.exe",
        "MPGHDownloader.exe",
        "mpgh_patcher.exe",
        "mpgh_undetected.exe",
        "mpgh_hack_v1.exe",
        "mpgh_hack_v2.exe",
        "mpgh_aimbot.exe",
        "mpgh_esp.exe",
        "mpgh_wallhack.exe",
        "MPGH_Loader.dll",
        "mpgh_loader.dll",
        "MPGHLoader.dll",
    ];

    // -------------------------------------------------------------------------
    // Known MPGH tool directory names on Desktop/Downloads
    // -------------------------------------------------------------------------
    private static readonly string[] MpghToolDirNames =
    [
        "MPGH",
        "mpgh",
        "MPGHTool",
        "mpgh_tools",
        "MPGHTools",
        "MPGHHacks",
        "mpgh_hacks",
        "mpgh_cheats",
        "MPGHCheats",
        "MPGH_Loader",
        "mpgh_loader",
        "MultiPlayerGameHacking",
        "mpgh_download",
        "MPGHDownload",
    ];

    // -------------------------------------------------------------------------
    // UnknownCheats / Gamerhash / marketplace directory naming conventions
    // -------------------------------------------------------------------------
    private static readonly string[] MarketplaceDirNames =
    [
        "UnknownCheats",
        "unknowncheats",
        "unknown_cheats",
        "UC_Cheats",
        "uc_cheats",
        "Gamerhash",
        "gamerhash",
        "GamerHash",
        "GamerhashCheats",
        "GamerhashHacks",
        "MPGH_Cheats",
        "mpgh_cheats",
        "elitepvpers",
        "ElitePvpers",
        "hackforums",
        "HackForums",
        "unknowncheat",
        "UnknownCheat",
        "uc_loader",
        "UCLoader",
    ];

    // -------------------------------------------------------------------------
    // EQU8 bypass artifacts
    // -------------------------------------------------------------------------
    private static readonly string[] Equ8BypassFileNames =
    [
        "equ8_bypass.exe",
        "EQU8Bypass.exe",
        "equ8_kill.exe",
        "EQU8Killer.exe",
        "equ8_patch.exe",
        "equ8_hook.dll",
        "equ8_bypass.dll",
        "equ8_disable.exe",
        "equ8_emu.dll",
    ];

    // -------------------------------------------------------------------------
    // Ricochet (CoD) bypass artifacts
    // -------------------------------------------------------------------------
    private static readonly string[] RicochetBypassFileNames =
    [
        "ricochet_bypass.exe",
        "RicochetBypass.exe",
        "ricochet_kill.exe",
        "RicochetKiller.exe",
        "ricochet_patch.exe",
        "ricochet_hook.dll",
        "ricochet_bypass.dll",
        "ricochet_disable.exe",
        "cod_bypass.exe",
        "CodBypass.exe",
        "warzone_bypass.exe",
        "WarzoneBypass.exe",
        "ricochet_emu.dll",
        "RicochetEmu.exe",
    ];

    // -------------------------------------------------------------------------
    // Nexon Game Security (NGS) bypass artifacts
    // -------------------------------------------------------------------------
    private static readonly string[] NexonBypassFileNames =
    [
        "ngs_bypass.exe",
        "NGSBypass.exe",
        "nexon_bypass.exe",
        "NexonBypass.exe",
        "ngs_kill.exe",
        "NGSKiller.exe",
        "nexon_kill.exe",
        "ngs_patch.exe",
        "ngs_hook.dll",
        "ngs_bypass.dll",
        "ngs_disable.exe",
        "nexon_anticheat_bypass.exe",
    ];

    // -------------------------------------------------------------------------
    // Cheat subscription / auth key file names
    // -------------------------------------------------------------------------
    private static readonly string[] CheatKeyFileNames =
    [
        "license.key",
        "auth.key",
        "hwid.key",
        "activation.key",
        "product.key",
        "serial.key",
        "cheat.key",
        "loader.key",
        "bypass.key",
        "sub.key",
        "subscription.key",
        "token.key",
        "access.key",
        "unlock.key",
        "hack.key",
    ];

    // -------------------------------------------------------------------------
    // PowerShell history patterns for MPGH/nProtect/Xigncode bypass
    // -------------------------------------------------------------------------
    private static readonly (string Pattern, RiskLevel Risk, string Title)[] PsHistoryPatterns =
    [
        ("sc stop npggsvc",                    RiskLevel.Critical, "GameGuard Service Stopped via sc.exe"),
        ("sc delete npggsvc",                  RiskLevel.Critical, "GameGuard Service Deleted via sc.exe"),
        ("net stop npggsvc",                   RiskLevel.Critical, "GameGuard Service Stopped via net stop"),
        ("sc stop xhunter1",                   RiskLevel.Critical, "Xigncode Service (xhunter1) Stopped via sc.exe"),
        ("sc delete xhunter1",                 RiskLevel.Critical, "Xigncode Service (xhunter1) Deleted via sc.exe"),
        ("sc stop xigncode",                   RiskLevel.Critical, "Xigncode Service Stopped via sc.exe"),
        ("sc delete xigncode",                 RiskLevel.Critical, "Xigncode Service Deleted via sc.exe"),
        ("sc stop equ8",                       RiskLevel.Critical, "EQU8 Service Stopped via sc.exe"),
        ("sc delete equ8",                     RiskLevel.Critical, "EQU8 Service Deleted via sc.exe"),
        ("sc stop ricochet",                   RiskLevel.Critical, "Ricochet Service Stopped via sc.exe"),
        ("taskkill /im GameMon.des",           RiskLevel.Critical, "GameGuard Monitor Process Killed via taskkill"),
        ("taskkill /im npgg",                  RiskLevel.Critical, "GameGuard Process Killed via taskkill"),
        ("taskkill /im xhunter",               RiskLevel.Critical, "Xigncode Process Killed via taskkill"),
        ("del GameGuard.des",                  RiskLevel.High,     "GameGuard.des Deleted via del Command"),
        ("del GameMon.des",                    RiskLevel.High,     "GameMon.des Deleted via del Command"),
        ("del npggNT.des",                     RiskLevel.High,     "npggNT.des Deleted via del Command"),
        ("wget.*mpgh.net",                     RiskLevel.High,     "wget Download from mpgh.net in PS History"),
        ("curl.*mpgh.net",                     RiskLevel.High,     "curl Download from mpgh.net in PS History"),
        ("wget.*unknowncheats",                RiskLevel.High,     "wget Download from unknowncheats in PS History"),
        ("curl.*unknowncheats",                RiskLevel.High,     "curl Download from unknowncheats in PS History"),
        ("wget.*gamerhash",                    RiskLevel.High,     "wget Download from gamerhash in PS History"),
        ("curl.*gamerhash",                    RiskLevel.High,     "curl Download from gamerhash in PS History"),
        ("Invoke-WebRequest.*mpgh",            RiskLevel.High,     "PowerShell Download from mpgh.net in PS History"),
        ("Invoke-WebRequest.*unknowncheats",   RiskLevel.High,     "PowerShell Download from unknowncheats.net in PS History"),
        ("bcdedit /set testsigning on",        RiskLevel.Critical, "Test Signing Mode Enabled via bcdedit"),
        ("bcdedit /set nointegritychecks on",  RiskLevel.Critical, "Driver Integrity Checks Disabled via bcdedit"),
        ("kdmapper",                           RiskLevel.Critical, "kdmapper Unsigned Driver Mapper in PS History"),
    ];

    // =========================================================================
    // Entry point
    // =========================================================================
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await CheckGameGuardServiceRegistryAsync(ctx, ct);
        await CheckGameGuardIntegrityAsync(ctx, ct);
        await ScanGameGuardBypassFilesAsync(ctx, ct);
        await CheckGameGuardRepoDirsAsync(ctx, ct);
        await CheckXigncodeServiceRegistryAsync(ctx, ct);
        await ScanXigncodeBypassFilesAsync(ctx, ct);
        await ScanXigncodeDriversAsync(ctx, ct);
        await CheckXigncodeRepoDirsAsync(ctx, ct);
        await ScanMpghToolFilesAsync(ctx, ct);
        await CheckMpghToolDirsAsync(ctx, ct);
        await CheckMpghPsHistoryDownloadsAsync(ctx, ct);
        await CheckMarketplaceDirsAsync(ctx, ct);
        await ScanCheatMarketplaceConfigsAsync(ctx, ct);
        await ScanCheatAuthKeyFilesAsync(ctx, ct);
        await ScanEqu8BypassFilesAsync(ctx, ct);
        await ScanRicochetBypassFilesAsync(ctx, ct);
        await ScanNexonBypassFilesAsync(ctx, ct);
        await CheckPowerShellHistoryAsync(ctx, ct);
        await CheckAdditionalAntiCheatServicesBypassAsync(ctx, ct);
    }

    // =========================================================================
    // 1. nProtect GameGuard service registry checks
    // =========================================================================
    private async Task CheckGameGuardServiceRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string[] ggServiceKeys =
            [
                @"SYSTEM\CurrentControlSet\Services\npggsvc",
                @"SYSTEM\CurrentControlSet\Services\npgg",
                @"SYSTEM\CurrentControlSet\Services\GameGuard",
                @"SYSTEM\CurrentControlSet\Services\nProtect",
            ];

            foreach (string keyPath in ggServiceKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    object? startVal = key.GetValue("Start");
                    if (startVal is int startInt && startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "nProtect GameGuard Service Disabled in Registry",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"The nProtect GameGuard service ({Path.GetFileName(keyPath)}) Start value is 4 (Disabled). A bypass tool may have disabled this service to prevent GameGuard from loading.",
                            Detail   = $"Start = {startInt}",
                        });
                    }

                    object? imagePathVal = key.GetValue("ImagePath");
                    if (imagePathVal is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                    {
                        string expanded = Environment.ExpandEnvironmentVariables(imagePath);
                        if (IsInSuspiciousUserPath(expanded))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "GameGuard Service ImagePath in User-Writable Location",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                Reason   = "The nProtect GameGuard service ImagePath references a Temp, Downloads, or AppData directory — indicating possible binary redirection by a bypass tool.",
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
    // 2. GameGuard folder integrity checks
    // =========================================================================
    private async Task CheckGameGuardIntegrityAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // GameGuard is typically installed as a GameGuard\ subfolder inside the game directory.
            // Check common game library paths for tampered GameGuard installations.
            string[] gameLibraryRoots =
            [
                @"C:\Program Files (x86)\Steam\steamapps\common",
                @"C:\Program Files\Steam\steamapps\common",
                @"C:\Nexon",
                @"C:\Program Files\Nexon",
                @"C:\Program Files (x86)\Nexon",
                @"C:\NC Soft",
                @"C:\NCSoft",
                @"C:\Program Files\NCsoft",
                @"C:\Program Files (x86)\NCsoft",
                @"C:\GameGuard",
                @"C:\HanGame",
            ];

            foreach (string libraryRoot in gameLibraryRoots)
            {
                ct.ThrowIfCancellationRequested();

                if (!Directory.Exists(libraryRoot))
                    continue;

                IEnumerable<string> gameDirs;
                try
                {
                    gameDirs = Directory.EnumerateDirectories(libraryRoot, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string gameDir in gameDirs)
                {
                    ct.ThrowIfCancellationRequested();

                    string ggFolder = Path.Combine(gameDir, "GameGuard");
                    if (!Directory.Exists(ggFolder))
                        continue;

                    // GameGuard.des must be present; if missing or zero bytes, it may be tampered
                    string gameGuardDes = Path.Combine(ggFolder, "GameGuard.des");
                    if (!File.Exists(gameGuardDes))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "GameGuard.des Missing from GameGuard Folder",
                            Risk     = RiskLevel.High,
                            Location = ggFolder,
                            FileName = "GameGuard.des",
                            Reason   = $"The GameGuard folder exists at \"{ggFolder}\" but GameGuard.des is missing. This critical file may have been deleted by a bypass tool to disable GameGuard.",
                            Detail   = $"Game directory: {gameDir}",
                        });
                    }
                    else
                    {
                        try
                        {
                            var fi = new FileInfo(gameGuardDes);
                            if (fi.Length == 0)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "GameGuard.des Is Zero Bytes",
                                    Risk     = RiskLevel.Critical,
                                    Location = gameGuardDes,
                                    FileName = "GameGuard.des",
                                    Reason   = "GameGuard.des has zero byte size. This file contains GameGuard's protection configuration; being zeroed out is a clear indicator of tampering by a bypass tool.",
                                    Detail   = $"File size: {fi.Length} bytes | Game: {Path.GetFileName(gameDir)}",
                                });
                            }
                            ctx.IncrementFiles();
                        }
                        catch (IOException) { }
                    }

                    // GameMon.des cleared check
                    string gameMonDes = Path.Combine(ggFolder, "GameMon.des");
                    if (File.Exists(gameMonDes))
                    {
                        try
                        {
                            var fi = new FileInfo(gameMonDes);
                            if (fi.Length == 0)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "GameMon.des Is Zero Bytes (GameGuard Monitor Tampered)",
                                    Risk     = RiskLevel.Critical,
                                    Location = gameMonDes,
                                    FileName = "GameMon.des",
                                    Reason   = "GameMon.des (GameGuard's kernel monitor driver) has been zeroed out. This is a known GameGuard bypass technique that disables the anti-cheat monitoring driver.",
                                    Detail   = $"File size: {fi.Length} bytes | Game: {Path.GetFileName(gameDir)}",
                                });
                            }
                            ctx.IncrementFiles();
                        }
                        catch (IOException) { }
                    }

                    // npggNT.des integrity
                    string npggNtDes = Path.Combine(ggFolder, "npggNT.des");
                    if (File.Exists(npggNtDes))
                    {
                        try
                        {
                            var fi = new FileInfo(npggNtDes);
                            if (fi.Length == 0)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "npggNT.des Is Zero Bytes",
                                    Risk     = RiskLevel.Critical,
                                    Location = npggNtDes,
                                    FileName = "npggNT.des",
                                    Reason   = "npggNT.des (GameGuard's NT kernel component) has been zeroed out. Clearing this file is a documented GameGuard bypass technique.",
                                    Detail   = $"File size: {fi.Length} bytes | Game: {Path.GetFileName(gameDir)}",
                                });
                            }
                            ctx.IncrementFiles();
                        }
                        catch (IOException) { }
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 3. GameGuard bypass tool file scan
    // =========================================================================
    private async Task ScanGameGuardBypassFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataRoaming,
            AppDataLocal,
        ];

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
                    foreach (string bypassFile in GameGuardBypassFileNames)
                    {
                        if (fileName.Equals(bypassFile, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Known nProtect GameGuard Bypass Tool Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File \"{fileName}\" matches a known nProtect GameGuard bypass tool name. This software is specifically designed to circumvent GameGuard anti-cheat protection.",
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
    // 4. GameGuard bypass GitHub repo clone directory check
    // =========================================================================
    private async Task CheckGameGuardRepoDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        await CheckRepoDirNamesAsync(ctx, ct, GameGuardRepoDirNames, "nProtect GameGuard bypass");
    }

    // =========================================================================
    // 5. Xigncode3 service registry checks
    // =========================================================================
    private async Task CheckXigncodeServiceRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string[] x3ServiceKeys =
            [
                @"SYSTEM\CurrentControlSet\Services\xhunter1",
                @"SYSTEM\CurrentControlSet\Services\xigncode",
                @"SYSTEM\CurrentControlSet\Services\xcorona",
                @"SYSTEM\CurrentControlSet\Services\XignCode",
            ];

            foreach (string keyPath in x3ServiceKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    object? startVal = key.GetValue("Start");
                    if (startVal is int startInt && startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Xigncode3 Service Disabled: {Path.GetFileName(keyPath)}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"Xigncode3 service ({Path.GetFileName(keyPath)}) Start value is 4 (Disabled). A bypass tool likely disabled this service to prevent Xigncode3 from loading.",
                            Detail   = $"Start = {startInt}",
                        });
                    }

                    object? imagePathVal = key.GetValue("ImagePath");
                    if (imagePathVal is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                    {
                        string expanded = Environment.ExpandEnvironmentVariables(imagePath);
                        if (IsInSuspiciousUserPath(expanded))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Xigncode3 Service ImagePath in Suspicious Location",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                Reason   = "Xigncode3 service ImagePath references a Temp, Downloads, or AppData directory. This is characteristic of binary substitution by a bypass tool.",
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
    // 6. Xigncode3 bypass file scan
    // =========================================================================
    private async Task ScanXigncodeBypassFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataRoaming,
            AppDataLocal,
        ];

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
                    foreach (string bypassFile in XigncodeBypassFileNames)
                    {
                        if (fileName.Equals(bypassFile, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Known Xigncode3 Bypass Tool Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File \"{fileName}\" matches a known Xigncode3 bypass tool name. This software is designed to circumvent Xigncode3 anti-cheat.",
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
    // 7. Xigncode3 driver files outside game directory
    // =========================================================================
    private async Task ScanXigncodeDriversAsync(ScanContext ctx, CancellationToken ct)
    {
        // x3.xem and xcorona.xem are Xigncode3 driver files that should only
        // exist inside a game installation directory
        string[] xigncodeDriverFiles = ["x3.xem", "xcorona.xem", "xhunter1.sys", "xigncode.sys"];

        string[] searchDirs =
        [
            TempDir,
            Downloads,
            Desktop,
            Documents,
            AppDataRoaming,
            AppDataLocal,
        ];

        foreach (string dir in searchDirs)
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
                    foreach (string xDriver in xigncodeDriverFiles)
                    {
                        if (fileName.Equals(xDriver, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Xigncode3 Driver File Outside Game Directory",
                                Risk     = RiskLevel.High,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"Xigncode3 driver file \"{fileName}\" found outside a legitimate game installation directory. This file should only exist inside a game folder — its presence elsewhere may indicate extraction by a bypass tool.",
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
    // 8. Xigncode3 GitHub repo clone directory check
    // =========================================================================
    private async Task CheckXigncodeRepoDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        await CheckRepoDirNamesAsync(ctx, ct, XigncodeRepoDirNames, "Xigncode3 bypass");
    }

    // =========================================================================
    // 9. MPGH tool file scan
    // =========================================================================
    private async Task ScanMpghToolFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataRoaming,
            AppDataLocal,
        ];

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
                    // Check exact MPGH tool names
                    foreach (string mpghTool in MpghToolFileNames)
                    {
                        if (fileName.Equals(mpghTool, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "MPGH-Distributed Tool File Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File \"{fileName}\" matches a known MPGH (MultiPlayerGameHacking) distributed tool name. MPGH is a well-known cheat distribution forum.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }

                    // Heuristic: any file with "mpgh" in the name combined with hack/cheat/loader
                    string lowerName = fileName.ToLowerInvariant();
                    if (lowerName.Contains("mpgh") &&
                        (lowerName.Contains("hack") ||
                         lowerName.Contains("cheat") ||
                         lowerName.Contains("loader") ||
                         lowerName.Contains("bypass") ||
                         lowerName.Contains("inject") ||
                         lowerName.Contains("aimbot") ||
                         lowerName.Contains("esp")))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "MPGH-Branded Cheat File Detected",
                            Risk     = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason   = $"File \"{fileName}\" contains \"mpgh\" combined with cheat-related keywords. This suggests a file obtained from or distributed via MPGH.",
                            Detail   = $"Full path: {filePath}",
                        });
                    }
                }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 10. MPGH tool directory name check
    // =========================================================================
    private async Task CheckMpghToolDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] searchRoots =
        [
            Desktop,
            Downloads,
            Documents,
            UserProfile,
        ];

        foreach (string root in searchRoots)
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

                foreach (string mpghDir in MpghToolDirNames)
                {
                    if (dirName.Equals(mpghDir, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "MPGH Tool Directory Detected",
                            Risk     = RiskLevel.High,
                            Location = subdir,
                            FileName = dirName,
                            Reason   = $"Directory \"{dirName}\" matches a known MPGH tool directory name. MPGH is a cheat distribution community.",
                            Detail   = $"Path: {subdir}",
                        });
                        break;
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 11. MPGH PowerShell history download command detection
    // =========================================================================
    private async Task CheckMpghPsHistoryDownloadsAsync(ScanContext ctx, CancellationToken ct)
    {
        string psHistoryFile = Path.Combine(
            AppDataRoaming,
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

        if (!File.Exists(psHistoryFile))
            return;

        string content;
        try
        {
            using var fs = new FileStream(psHistoryFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content))
            return;

        ctx.IncrementFiles();

        // Already handled more broadly in CheckPowerShellHistoryAsync;
        // here we do targeted mpgh.net URL detection in wget/curl/Invoke-WebRequest
        string[] cheatSiteKeywords =
        [
            "mpgh.net",
            "unknowncheats.me",
            "gamerhash.com",
            "elitepvpers.com",
            "hackforums.net",
            "cheatautomation.com",
        ];

        string[] lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (string rawLine in lines)
        {
            ct.ThrowIfCancellationRequested();

            string line = rawLine.Trim();
            if (string.IsNullOrEmpty(line)) continue;

            foreach (string site in cheatSiteKeywords)
            {
                if (line.Contains(site, StringComparison.OrdinalIgnoreCase))
                {
                    bool isDownload = line.Contains("wget", StringComparison.OrdinalIgnoreCase) ||
                                      line.Contains("curl", StringComparison.OrdinalIgnoreCase) ||
                                      line.Contains("Invoke-WebRequest", StringComparison.OrdinalIgnoreCase) ||
                                      line.Contains("iwr ", StringComparison.OrdinalIgnoreCase) ||
                                      line.Contains("Start-BitsTransfer", StringComparison.OrdinalIgnoreCase) ||
                                      line.Contains("DownloadFile", StringComparison.OrdinalIgnoreCase);

                    if (isDownload)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat Site Download Command in PS History: {site}",
                            Risk     = RiskLevel.High,
                            Location = psHistoryFile,
                            FileName = Path.GetFileName(psHistoryFile),
                            Reason   = $"PowerShell history contains a download command targeting \"{site}\" — a known cheat distribution or forum site.",
                            Detail   = $"Command: {line.Substring(0, Math.Min(line.Length, 300))}",
                        });
                    }
                    break;
                }
            }
        }
    }

    // =========================================================================
    // 12. Cheat marketplace directory detection (UC, Gamerhash, MPGH)
    // =========================================================================
    private async Task CheckMarketplaceDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] searchRoots =
        [
            Desktop,
            Downloads,
            Documents,
            UserProfile,
            AppDataRoaming,
            AppDataLocal,
        ];

        foreach (string root in searchRoots)
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

                foreach (string marketplaceDir in MarketplaceDirNames)
                {
                    if (dirName.Equals(marketplaceDir, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Cheat Marketplace Directory Detected",
                            Risk     = RiskLevel.High,
                            Location = subdir,
                            FileName = dirName,
                            Reason   = $"Directory \"{dirName}\" matches a known cheat marketplace naming convention (UnknownCheats, Gamerhash, MPGH, etc.).",
                            Detail   = $"Path: {subdir}",
                        });
                        break;
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 13. Cheat marketplace config file scan (.json with source/site/marketplace fields)
    // =========================================================================
    private async Task ScanCheatMarketplaceConfigsAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] marketplaceSourceKeywords =
        [
            "unknowncheats",
            "mpgh",
            "gamerhash",
            "elitepvpers",
            "hackforums",
            "cheatautomation",
        ];

        string[] jsonFieldPatterns =
        [
            "\"source\"",
            "\"site\"",
            "\"marketplace\"",
            "\"platform\"",
            "\"provider\"",
        ];

        string[] scanDirs =
        [
            Desktop,
            Downloads,
            Documents,
            AppDataRoaming,
            AppDataLocal,
            TempDir,
        ];

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.json", SearchOption.AllDirectories);
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

                bool hasMarketplaceField = false;
                foreach (string field in jsonFieldPatterns)
                {
                    if (content.Contains(field, StringComparison.OrdinalIgnoreCase))
                    {
                        hasMarketplaceField = true;
                        break;
                    }
                }

                if (!hasMarketplaceField)
                    continue;

                foreach (string keyword in marketplaceSourceKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Cheat Marketplace Config File Detected",
                            Risk     = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason   = $"JSON config file \"{fileName}\" contains both marketplace/source field indicators and a reference to cheat marketplace \"{keyword}\". This file may be a cheat loader configuration.",
                            Detail   = $"Keyword: {keyword} | Path: {filePath}",
                        });
                        break;
                    }
                }
            }
        }
    }

    // =========================================================================
    // 14. Cheat auth key file detection in cheat-adjacent directories
    // =========================================================================
    private async Task ScanCheatAuthKeyFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        // Scan common cheat install directories for auth/license key files
        string[] cheatParentDirs =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataLocal,
            AppDataRoaming,
        ];

        foreach (string parentDir in cheatParentDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(parentDir))
                continue;

            // Only look one level deep for key files to avoid false positives
            // from legitimate application license files at the root level
            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(parentDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();

                // Only check directories whose names suggest cheat tool content
                string dirName = Path.GetFileName(subdir).ToLowerInvariant();
                bool isCheatDir = dirName.Contains("cheat") ||
                                  dirName.Contains("hack") ||
                                  dirName.Contains("aimbot") ||
                                  dirName.Contains("bypass") ||
                                  dirName.Contains("loader") ||
                                  dirName.Contains("inject") ||
                                  dirName.Contains("esp") ||
                                  dirName.Contains("spoof") ||
                                  dirName.Contains("mpgh") ||
                                  dirName.Contains("uc_") ||
                                  dirName.Contains("_uc") ||
                                  dirName.Contains("gamerhash") ||
                                  dirName.Contains("unknowncheats");

                if (!isCheatDir)
                    continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(subdir, "*", SearchOption.TopDirectoryOnly);
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
                        foreach (string keyFileName in CheatKeyFileNames)
                        {
                            if (fileName.Equals(keyFileName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "Cheat Subscription Key File Detected",
                                    Risk     = RiskLevel.High,
                                    Location = filePath,
                                    FileName = fileName,
                                    Reason   = $"Key file \"{fileName}\" found inside directory \"{Path.GetFileName(subdir)}\", which has a cheat-related name. This pattern indicates a subscription-based cheat tool with authentication.",
                                    Detail   = $"Full path: {filePath}",
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 15. EQU8 bypass file scan
    // =========================================================================
    private async Task ScanEqu8BypassFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanBypassFilesInDirsAsync(ctx, ct, Equ8BypassFileNames, "EQU8 Anti-Cheat");
    }

    // =========================================================================
    // 16. Ricochet (CoD) bypass file scan
    // =========================================================================
    private async Task ScanRicochetBypassFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanBypassFilesInDirsAsync(ctx, ct, RicochetBypassFileNames, "Ricochet (Call of Duty)");
    }

    // =========================================================================
    // 17. Nexon Game Security bypass file scan
    // =========================================================================
    private async Task ScanNexonBypassFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanBypassFilesInDirsAsync(ctx, ct, NexonBypassFileNames, "Nexon Game Security");
    }

    // =========================================================================
    // 18. PowerShell/batch history scan
    // =========================================================================
    private async Task CheckPowerShellHistoryAsync(ScanContext ctx, CancellationToken ct)
    {
        string psHistoryFile = Path.Combine(
            AppDataRoaming,
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

        if (!File.Exists(psHistoryFile))
            return;

        string content;
        try
        {
            using var fs = new FileStream(psHistoryFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content))
            return;

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
                        Location = psHistoryFile,
                        FileName = Path.GetFileName(psHistoryFile),
                        Reason   = $"Shell history entry matches pattern \"{pattern}\". This indicates the user executed commands to bypass or disable anti-cheat systems.",
                        Detail   = $"Matched line: {line.Substring(0, Math.Min(line.Length, 300))}",
                    });
                    break;
                }
            }
        }
    }

    // =========================================================================
    // 19. Additional anti-cheat (EQU8, Ricochet, NGS) service bypass registry
    // =========================================================================
    private async Task CheckAdditionalAntiCheatServicesBypassAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var additionalServices = new[]
            {
                (ServiceName: "equ8",          FriendlyName: "EQU8 Anti-Cheat"),
                (ServiceName: "ricochet",      FriendlyName: "Ricochet Anti-Cheat (CoD)"),
                (ServiceName: "cod_ac",        FriendlyName: "Call of Duty Anti-Cheat"),
                (ServiceName: "ngs",           FriendlyName: "Nexon Game Security"),
                (ServiceName: "ngs_sdk",       FriendlyName: "Nexon Game Security SDK"),
                (ServiceName: "nexon_ac",      FriendlyName: "Nexon Anti-Cheat"),
                (ServiceName: "equ8_drv",      FriendlyName: "EQU8 Kernel Driver"),
                (ServiceName: "ricochet_drv",  FriendlyName: "Ricochet Kernel Driver"),
            };

            foreach (var svc in additionalServices)
            {
                ct.ThrowIfCancellationRequested();

                string keyPath = $@"SYSTEM\CurrentControlSet\Services\{svc.ServiceName}";
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    object? startVal = key.GetValue("Start");
                    if (startVal is int startInt && startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"{svc.FriendlyName} Service Disabled in Registry",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"The {svc.FriendlyName} service ({svc.ServiceName}) has Start=4 (Disabled). A bypass tool may have disabled this service.",
                            Detail   = $"Start = {startInt}",
                        });
                    }

                    object? imagePathVal = key.GetValue("ImagePath");
                    if (imagePathVal is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                    {
                        if (IsInSuspiciousUserPath(Environment.ExpandEnvironmentVariables(imagePath)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"{svc.FriendlyName} Service ImagePath in Suspicious Location",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                Reason   = $"{svc.FriendlyName} service ImagePath references a user-writable directory. This indicates possible binary substitution.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }

            // Check for EQU8 / Ricochet related bypass registry keys in HKCU SOFTWARE
            string[] bypassSoftwareKeys =
            [
                @"SOFTWARE\EQU8 Bypass",
                @"SOFTWARE\EQU8Bypass",
                @"SOFTWARE\Ricochet Bypass",
                @"SOFTWARE\RicochetBypass",
                @"SOFTWARE\NGS Bypass",
                @"SOFTWARE\NGSBypass",
                @"SOFTWARE\Nexon Bypass",
                @"SOFTWARE\NexonBypass",
                @"SOFTWARE\GameGuard Bypass",
                @"SOFTWARE\GameGuardBypass",
                @"SOFTWARE\Xigncode Bypass",
                @"SOFTWARE\XigncodeBypass",
            ];

            foreach (string bpKey in bypassSoftwareKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? lmKey = Registry.LocalMachine.OpenSubKey(bpKey, writable: false);
                    if (lmKey is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Anti-Cheat Bypass Tool Registry Key Found",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{bpKey}",
                            Reason   = $"Registry key \"{bpKey}\" indicates an anti-cheat bypass tool has been installed on this system.",
                            Detail   = $"Key: HKLM\\{bpKey}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }

                ctx.IncrementRegistryKeys();
                try
                {
                    using RegistryKey? cuKey = Registry.CurrentUser.OpenSubKey(bpKey, writable: false);
                    if (cuKey is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Anti-Cheat Bypass Tool Registry Key Found (HKCU)",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKCU\{bpKey}",
                            Reason   = $"Registry key \"{bpKey}\" in HKCU indicates an anti-cheat bypass tool was installed for the current user.",
                            Detail   = $"Key: HKCU\\{bpKey}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }
        }, ct);
    }

    // =========================================================================
    // Shared helpers
    // =========================================================================

    private async Task ScanBypassFilesInDirsAsync(
        ScanContext ctx,
        CancellationToken ct,
        string[] bypassFileNames,
        string antiCheatName)
    {
        string[] scanDirs =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataRoaming,
            AppDataLocal,
        ];

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
                    foreach (string bypassFile in bypassFileNames)
                    {
                        if (fileName.Equals(bypassFile, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Known {antiCheatName} Bypass Tool Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File \"{fileName}\" matches a known {antiCheatName} bypass tool name. This software is designed to circumvent {antiCheatName} anti-cheat protection.",
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

    private async Task CheckRepoDirNamesAsync(
        ScanContext ctx,
        CancellationToken ct,
        string[] repoDirNames,
        string repoCategory)
    {
        string[] searchRoots =
        [
            Desktop,
            Downloads,
            Documents,
            UserProfile,
            AppDataRoaming,
            AppDataLocal,
            Path.Combine(UserProfile, "source"),
            Path.Combine(UserProfile, "repos"),
            Path.Combine(UserProfile, "git"),
            Path.Combine(UserProfile, "GitHub"),
        ];

        foreach (string root in searchRoots)
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

                foreach (string repoName in repoDirNames)
                {
                    if (dirName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                    {
                        bool hasGit = Directory.Exists(Path.Combine(subdir, ".git"));
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"{repoCategory} GitHub Repository Clone Detected",
                            Risk     = RiskLevel.Critical,
                            Location = subdir,
                            FileName = dirName,
                            Reason   = $"Directory \"{dirName}\" matches a known {repoCategory} repository name. This indicates the user cloned bypass source code or tools from a public code repository.",
                            Detail   = hasGit
                                ? $"Git repo confirmed (.git folder present). Path: {subdir}"
                                : $"Path: {subdir}",
                        });
                        break;
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    private static bool IsInSuspiciousUserPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;

        string[] suspiciousSegments =
        [
            @"\Temp\",
            @"\Downloads\",
            @"\AppData\",
            @"\Desktop\",
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
