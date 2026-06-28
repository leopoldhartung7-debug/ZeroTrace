using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

// BattlEye bypass detection module.
// Checks BEService/BEDaisy registry entries, BEDaisy.sys location anomalies,
// game directory integrity for PUBG/DayZ/Arma 3/Rainbow Six, BEClient.log
// cleared/missing, known bypass tool files, GitHub clone dirs, batch/PS scripts,
// BYOVD drivers, hosts file modifications, Wireshark captures, PUBG-specific
// bypass DLLs, DayZ BEClient.dll replacement, and cheat loader injection markers.
public sealed class BattlEyeBypassScanModule : IScanModule
{
    public string Name => "BattlEye Bypass Detection";
    public double Weight => 4.1;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Known BattlEye bypass tool file names — flagged Critical anywhere found
    // -------------------------------------------------------------------------
    private static readonly string[] KnownBypassFileNames =
    [
        "BELoader.exe",
        "BEBypass.dll",
        "BattlEyeBypass.exe",
        "be_bypass.dll",
        "BE_Bypass.exe",
        "battleye_bypass.exe",
        "BEService_fake.exe",
        "BEKiller.exe",
        "BEUnloader.exe",
        "BE_Emu.dll",
        "BattlEye_Emu.dll",
        "be_emulator.dll",
        "be_emu.exe",
        "BEPatch.exe",
        "BEPatcher.exe",
        "BEDisable.exe",
        "be_disable.bat",
        "BERemover.exe",
        "BEBypassLoader.exe",
        "be_spoofer.exe",
        "BESpoofer.exe",
        "be_hook.dll",
        "be_hook.exe",
        "BattlEyeHook.dll",
        "battleye_hook.exe",
        "be_bypass_v2.dll",
        "be_bypass_x64.dll",
        "be_bypass_x86.dll",
        "pubg_be_bypass.dll",
        "pubg_bypass.exe",
        "dayz_be_bypass.dll",
        "arma_be_bypass.exe",
        "r6_be_bypass.dll",
        "BEClientBypass.dll",
        "BEClientFake.dll",
        "BEClientReplace.dll",
        "beservice_bypass.exe",
        "beservice_killer.exe",
        "BattlEyeKiller.exe",
        "BEUninstaller_bypass.exe",
        "battleye_unloader.exe",
        "BE_Unload.exe",
        "be_inject.dll",
        "be_inject.exe",
        "BattlEyeInject.exe",
        "openbe.exe",
        "OpenBattlEye.exe",
        "BEEmulator.exe",
        "be_emu_loader.exe",
        "battleye_emulator.dll",
        "fake_beclient.dll",
        "BEClientStub.dll",
        "be_bypass_pub.dll",
        "bypass_be.exe",
        "killbe.exe",
        "stopbe.bat",
        "be_off.exe",
        "nobe.exe",
        "battleye_off.exe",
        "be_bypass_internal.dll",
        "be_loader_internal.exe",
        "BEService_spoof.exe",
        "be_bypass_loader.exe",
    ];

    // -------------------------------------------------------------------------
    // BYOVD driver names commonly used to kill BattlEye kernel callbacks
    // -------------------------------------------------------------------------
    private static readonly string[] ByovdDriverNames =
    [
        "ATSZIO64.sys",
        "NvflashStrapper.sys",
        "piddrv64.sys",
        "rwdrv.sys",
        "sysdiag64.sys",
        "viragt64.sys",
        "WinIo64.sys",
        "gdrv.sys",
        "WinRing0x64.sys",
        "WinRing0.sys",
        "cpuz141_x64.sys",
        "RTCore64.sys",
        "dbutil_2_3.sys",
        "AsrDrv103.sys",
        "HwRwDrv.sys",
        "MsIo64.sys",
        "kprocesshacker.sys",
        "cpuz143_x64.sys",
        "iqvw64e.sys",
        "PhyMemDrv.sys",
        "AsUpIO64.sys",
        "NalDrv.sys",
        "Speedfan.sys",
        "mhyprot2.sys",
        "Dbk64.sys",
        "AsIO3.sys",
        "phymem64.sys",
        "nicm.sys",
    ];

    // -------------------------------------------------------------------------
    // Known BattlEye bypass GitHub repository folder names
    // -------------------------------------------------------------------------
    private static readonly string[] BypassRepoDirNames =
    [
        "BattlEye-Bypass",
        "be-bypass",
        "battleye-emu",
        "OpenBattlEye",
        "BEEmulator",
        "BEBypass",
        "battleye_bypass",
        "be_bypass_source",
        "battleye-emulator",
        "BattlEyeEmulator",
        "be-emu",
        "BEClient-bypass",
    ];

    // -------------------------------------------------------------------------
    // Games that ship BattlEye — missing BattlEye folder is suspicious
    // -------------------------------------------------------------------------
    private static readonly (string GameDir, string DisplayName)[] BeGames =
    [
        ("PLAYERUNKNOWN'S BATTLEGROUNDS", "PUBG"),
        ("PUBG", "PUBG"),
        ("DayZ", "DayZ"),
        ("Arma 3", "Arma 3"),
        ("Tom Clancy's Rainbow Six Siege", "Rainbow Six Siege"),
        ("Rainbow Six Siege", "Rainbow Six Siege"),
        ("Escape From Tarkov", "Escape From Tarkov"),
        ("EscapeFromTarkov", "Escape From Tarkov"),
    ];

    // -------------------------------------------------------------------------
    // Script/PS-history patterns targeting BEService or BEDaisy
    // -------------------------------------------------------------------------
    private static readonly (string Pattern, RiskLevel Risk, string Title)[] ScriptPatterns =
    [
        ("sc stop BEService",             RiskLevel.Critical, "BEService Stopped via sc.exe"),
        ("sc delete BEService",           RiskLevel.Critical, "BEService Deleted via sc.exe"),
        ("taskkill /im BEService.exe",    RiskLevel.Critical, "BEService Killed via taskkill"),
        ("taskkill /f /im BEService.exe", RiskLevel.Critical, "BEService Force-Killed via taskkill"),
        ("net stop BEService",            RiskLevel.High,     "BEService Stopped via net stop"),
        ("net stop BEDaisy",              RiskLevel.High,     "BEDaisy Stopped via net stop"),
        ("sc stop BEDaisy",               RiskLevel.High,     "BEDaisy Stopped via sc.exe"),
        ("taskkill /im BEDaisy",          RiskLevel.High,     "BEDaisy Killed via taskkill"),
        ("BEService",                     RiskLevel.Medium,   "BEService Referenced in Script"),
        ("BattlEye",                      RiskLevel.Medium,   "BattlEye Referenced in Script"),
    ];

    // =========================================================================
    // Entry point
    // =========================================================================
    public async Task RunAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await CheckBeServiceRegistryAsync(ctx, ct);
        await CheckBeDaisyDriverAsync(ctx, ct);
        await CheckGameDirectoryIntegrityAsync(ctx, ct);
        await CheckBeClientLogAsync(ctx, ct);
        await ScanBypassToolFilesAsync(ctx, ct);
        await CheckBypassRepoDirsAsync(ctx, ct);
        await ScanScriptFilesAsync(ctx, ct);
        await CheckPowerShellHistoryAsync(ctx, ct);
        await ScanByovdDriversAsync(ctx, ct);
        await CheckHostsFileAsync(ctx, ct);
        await ScanWiresharkCapturesAsync(ctx, ct);
        await CheckPubgBeDllsAsync(ctx, ct);
        await CheckDayzBeClientDllAsync(ctx, ct);
        await ScanInjectionMarkerConfigsAsync(ctx, ct);
    }

    // =========================================================================
    // 1. BEService / BEDaisy registry checks
    // =========================================================================
    private async Task CheckBeServiceRegistryAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string[] serviceKeys =
            [
                @"SYSTEM\CurrentControlSet\Services\BEService",
                @"SYSTEM\CurrentControlSet\Services\BEDaisy",
            ];

            foreach (string keyPath in serviceKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null)
                        continue;

                    object? startVal = key.GetValue("Start");
                    if (startVal is int startInt && startInt != 2)
                    {
                        string interpretation = startInt switch
                        {
                            0 => "Boot",
                            1 => "System",
                            3 => "Manual",
                            4 => "Disabled",
                            _ => startInt.ToString()
                        };

                        RiskLevel risk = startInt == 4 ? RiskLevel.High : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"BattlEye Service Start Value Anomaly ({interpretation})",
                            Risk     = risk,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"The {Path.GetFileName(keyPath)} service Start value is {startInt} ({interpretation}). Expected value is 2 (Automatic). A bypass tool may have altered the service configuration.",
                            Detail   = $"Start = {startInt} ({interpretation})",
                        });
                    }

                    object? imagePathVal = key.GetValue("ImagePath");
                    if (imagePathVal is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                    {
                        string normalized = imagePath
                            .Trim('"')
                            .Replace(@"\??\", string.Empty, StringComparison.OrdinalIgnoreCase);

                        bool inBeDir   = normalized.Contains(@"\BattlEye\", StringComparison.OrdinalIgnoreCase);
                        bool inGameDir = normalized.Contains(@"\steamapps\", StringComparison.OrdinalIgnoreCase)
                                      || normalized.Contains(@"\Epic Games\", StringComparison.OrdinalIgnoreCase)
                                      || normalized.Contains(@"\Program Files\", StringComparison.OrdinalIgnoreCase);
                        bool inSys32   = normalized.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase);

                        if (!inBeDir && !inGameDir && !inSys32)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "BattlEye Service ImagePath Outside Expected Game Directory",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                Reason   = "The BattlEye service ImagePath does not reference a BattlEye, Steam, Epic Games, or Program Files directory. The binary may have been redirected by a bypass tool.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }

                        if (IsInSuspiciousUserPath(normalized))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "BattlEye Service ImagePath in User-Writable Location",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                Reason   = "The BattlEye service ImagePath references a Temp, Downloads, or AppData location. This strongly indicates the service binary was replaced by a fake.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                }
            }
        }, ct);
    }

    // =========================================================================
    // 2. BEDaisy.sys location anomaly
    // =========================================================================
    private async Task CheckBeDaisyDriverAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string windir   = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            string sys32Drv = Path.Combine(windir, "System32", "drivers");

            const string keyPath = @"SYSTEM\CurrentControlSet\Services\BEDaisy";
            ctx.IncrementRegistryKeys();

            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                if (key is not null)
                {
                    object? imagePathVal = key.GetValue("ImagePath");
                    if (imagePathVal is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                    {
                        string normalized = imagePath
                            .Trim('"')
                            .Replace(@"\??\", string.Empty, StringComparison.OrdinalIgnoreCase);

                        bool inSys32 = normalized.StartsWith(sys32Drv, StringComparison.OrdinalIgnoreCase);
                        bool inBeDir = normalized.Contains(@"\BattlEye\", StringComparison.OrdinalIgnoreCase);

                        if (!inSys32 && !inBeDir)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "BEDaisy.sys Loaded from Anomalous Path",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                FileName = "BEDaisy.sys",
                                Reason   = "BEDaisy.sys is configured to load from outside System32\\drivers\\ and outside any BattlEye directory. This indicates driver path hijacking by a bypass tool.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
            }
        }, ct);

        // Also look for BEDaisy.sys copies in user-writable locations
        foreach (string dir in BuildUserScanDirectories())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> sysFiles;
            try
            {
                sysFiles = Directory.EnumerateFiles(dir, "BEDaisy.sys", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string sysPath in sysFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "BEDaisy.sys Found in User-Writable Directory",
                        Risk     = RiskLevel.Critical,
                        Location = sysPath,
                        FileName = "BEDaisy.sys",
                        Reason   = "A copy of BEDaisy.sys was found in a Temp, Downloads, or AppData location. The legitimate driver lives only in game BattlEye folders or System32\\drivers\\.",
                        Detail   = $"Path: {sysPath}",
                    });
                }
                catch (IOException)
                {
                }
            }
        }
    }

    // =========================================================================
    // 3. Game directory integrity — BattlEye folder presence and contents
    // =========================================================================
    private async Task CheckGameDirectoryIntegrityAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string[] libraryRoots =
            [
                @"C:\Program Files (x86)\Steam\steamapps\common",
                @"C:\Program Files\Steam\steamapps\common",
                @"C:\Program Files\Epic Games",
                @"C:\Program Files (x86)\Epic Games",
            ];

            foreach (string libraryRoot in libraryRoots)
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

                    string gameName = Path.GetFileName(gameDir);

                    foreach (var (knownDir, displayName) in BeGames)
                    {
                        if (!gameName.Equals(knownDir, StringComparison.OrdinalIgnoreCase))
                            continue;

                        InspectBeGameDirectory(ctx, gameDir, displayName, ct);
                        break;
                    }
                }
            }
        }, ct);
    }

    private void InspectBeGameDirectory(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string gameDir,
        string displayName,
        CancellationToken ct)
    {
        string beFolder = Path.Combine(gameDir, "BattlEye");

        if (!Directory.Exists(beFolder))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"BattlEye Folder Missing in {displayName}",
                Risk     = RiskLevel.High,
                Location = gameDir,
                Reason   = $"The BattlEye anti-cheat folder is absent from the {displayName} game directory. It may have been deleted or renamed by a bypass tool.",
                Detail   = $"Expected path: {beFolder}",
            });
            return;
        }

        // Check for BEClient.dll presence
        string beClientDll = Path.Combine(beFolder, "BEClient.dll");
        string beClient64  = Path.Combine(beFolder, "BEClient_x64.dll");

        bool dllPresent = File.Exists(beClientDll) || File.Exists(beClient64);
        if (!dllPresent)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"BEClient.dll Missing from {displayName} BattlEye Folder",
                Risk     = RiskLevel.High,
                Location = beFolder,
                Reason   = $"Neither BEClient.dll nor BEClient_x64.dll is present inside the {displayName} BattlEye directory. The BattlEye client library may have been removed.",
                Detail   = $"BattlEye folder: {beFolder}",
            });
        }

        // Look for renamed BattlEye-like folder variants in the game dir
        IEnumerable<string> siblings;
        try
        {
            siblings = Directory.EnumerateDirectories(gameDir, "*Eye*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (string sibling in siblings)
        {
            ct.ThrowIfCancellationRequested();

            string sibName = Path.GetFileName(sibling);
            if (sibName.Equals("BattlEye", StringComparison.OrdinalIgnoreCase))
                continue;

            if (sibName.Contains("battleye", StringComparison.OrdinalIgnoreCase)
                || sibName.Contains("battle_eye", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Renamed BattlEye Folder Detected in {displayName}",
                    Risk     = RiskLevel.High,
                    Location = sibling,
                    Reason   = $"A folder with a name similar to 'BattlEye' but a different spelling was found in the {displayName} directory. The BattlEye folder may have been renamed to evade detection.",
                    Detail   = $"Folder name: {sibName}",
                });
            }
        }
    }

    // =========================================================================
    // 4. BEClient.log cleared or missing after gaming session
    // =========================================================================
    private async Task CheckBeClientLogAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string[] libraryRoots =
            [
                @"C:\Program Files (x86)\Steam\steamapps\common",
                @"C:\Program Files\Steam\steamapps\common",
                @"C:\Program Files\Epic Games",
            ];

            foreach (string root in libraryRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root))
                    continue;

                IEnumerable<string> logFiles;
                try
                {
                    logFiles = Directory.EnumerateFiles(root, "BEClient.log", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string logPath in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        var fi = new FileInfo(logPath);
                        if (fi.Length == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "BEClient.log Cleared (Zero Bytes)",
                                Risk     = RiskLevel.Medium,
                                Location = logPath,
                                FileName = "BEClient.log",
                                Reason   = "BEClient.log exists but is empty. BattlEye bypass tools routinely clear this log to remove evidence of detection events recorded during the gaming session.",
                                Detail   = $"Game folder: {Path.GetDirectoryName(Path.GetDirectoryName(logPath))}",
                            });
                        }
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 5. Known bypass tool files on disk
    // =========================================================================
    private async Task ScanBypassToolFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs = BuildUserScanDirectories();

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

                try
                {
                    string fileName = Path.GetFileName(filePath);
                    ctx.IncrementFiles();

                    foreach (string bad in KnownBypassFileNames)
                    {
                        if (fileName.Equals(bad, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Known BattlEye Bypass Tool File Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File \"{fileName}\" matches a known BattlEye bypass tool name.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 6. GitHub bypass repository directories
    // =========================================================================
    private async Task CheckBypassRepoDirsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] searchRoots =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            ];

            foreach (string root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
                    continue;

                IEnumerable<string> subDirs;
                try
                {
                    subDirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string subDir in subDirs)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        string dirName = Path.GetFileName(subDir);

                        foreach (string repoName in BypassRepoDirNames)
                        {
                            if (dirName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "BattlEye Bypass Repository Directory Found",
                                    Risk     = RiskLevel.High,
                                    Location = subDir,
                                    Reason   = $"Directory \"{dirName}\" matches a known BattlEye bypass GitHub repository name. The user likely cloned or possesses bypass source code.",
                                    Detail   = $"Matched pattern: {repoName}",
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 7. Batch/script files with BE-targeting commands
    // =========================================================================
    private async Task ScanScriptFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] scriptDirs =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        ];

        string[] scriptExtensions = ["*.bat", "*.cmd", "*.ps1", "*.vbs"];

        foreach (string dir in scriptDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            foreach (string ext in scriptExtensions)
            {
                IEnumerable<string> scriptFiles;
                try
                {
                    scriptFiles = Directory.EnumerateFiles(dir, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string scriptPath in scriptFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    await InspectScriptFileAsync(ctx, scriptPath, ct);
                }
            }
        }
    }

    private async Task InspectScriptFileAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string scriptPath,
        CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(scriptPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
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

        ct.ThrowIfCancellationRequested();

        string fileName = Path.GetFileName(scriptPath);

        foreach (var (pattern, risk, title) in ScriptPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Script Contains BattlEye Command: {title}",
                    Risk     = risk,
                    Location = scriptPath,
                    FileName = fileName,
                    Reason   = $"Script file contains the pattern \"{pattern}\", indicating it is designed to interfere with BattlEye.",
                    Detail   = ExtractMatchingLine(content, pattern),
                });
                return;
            }
        }
    }

    // =========================================================================
    // 8. PowerShell history for BE-targeting commands
    // =========================================================================
    private async Task CheckPowerShellHistoryAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string historyPath = Path.Combine(
            appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (!File.Exists(historyPath))
            return;

        ctx.IncrementFiles();

        string content;
        try
        {
            using var fs = new FileStream(historyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
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

        foreach (var (pattern, risk, title) in ScriptPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"BattlEye Command in PS History: {title}",
                    Risk     = risk,
                    Location = historyPath,
                    FileName = Path.GetFileName(historyPath),
                    Reason   = $"PowerShell history contains the pattern \"{pattern}\", indicating an attempt to interfere with BattlEye.",
                    Detail   = ExtractMatchingLine(content, pattern),
                });
                break;
            }
        }

        // Combined check: taskkill + BEService together on any line
        foreach (string line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            ct.ThrowIfCancellationRequested();
            if (line.Contains("taskkill", StringComparison.OrdinalIgnoreCase)
                && line.Contains("beservice", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "BEService Kill Attempt via taskkill in PS History",
                    Risk     = RiskLevel.Critical,
                    Location = historyPath,
                    FileName = Path.GetFileName(historyPath),
                    Reason   = "PowerShell history contains a line with both 'taskkill' and 'beservice', indicating a forced termination attempt against BattlEye.",
                    Detail   = line.Trim(),
                });
                break;
            }
        }

        // kdmapper — kernel driver mapper often used in BYOVD attacks against BE
        if (content.Contains("kdmapper", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "kdmapper Kernel Driver Mapper Invocation in PS History",
                Risk     = RiskLevel.Critical,
                Location = historyPath,
                FileName = Path.GetFileName(historyPath),
                Reason   = "PowerShell history references 'kdmapper', a tool used to load unsigned kernel drivers. This is commonly part of BYOVD BattlEye bypass setups.",
                Detail   = ExtractMatchingLine(content, "kdmapper"),
            });
        }

        // bcdedit + testsigning: disables DSE, prerequisite for unsigned BYOVD drivers
        if (content.Contains("bcdedit", StringComparison.OrdinalIgnoreCase)
            && content.Contains("testsigning", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Test Signing Mode Enabled via bcdedit in PS History",
                Risk     = RiskLevel.High,
                Location = historyPath,
                FileName = Path.GetFileName(historyPath),
                Reason   = "PowerShell history contains a bcdedit testsigning command. Enabling test signing mode is a prerequisite for loading unsigned BYOVD drivers to bypass BattlEye.",
                Detail   = ExtractMatchingLine(content, "bcdedit"),
            });
        }
    }

    // =========================================================================
    // 9. BYOVD vulnerable driver detection (files + registry)
    // =========================================================================
    private async Task ScanByovdDriversAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs = BuildUserScanDirectories();

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> sysFiles;
            try
            {
                sysFiles = Directory.EnumerateFiles(dir, "*.sys", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string sysPath in sysFiles)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    string sysName = Path.GetFileName(sysPath);
                    ctx.IncrementFiles();

                    foreach (string bad in ByovdDriverNames)
                    {
                        if (sysName.Equals(bad, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "BYOVD Vulnerable Driver Found on Disk (BattlEye Context)",
                                Risk     = RiskLevel.Critical,
                                Location = sysPath,
                                FileName = sysName,
                                Reason   = $"Known vulnerable driver \"{sysName}\" found in a user-writable location. BYOVD attacks exploit these drivers to disable BattlEye kernel callbacks.",
                                Detail   = $"Directory: {Path.GetDirectoryName(sysPath)}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        await ScanByovdRegistryAsync(ctx, ct);
    }

    private async Task ScanByovdRegistryAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string windir   = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            string sys32Drv = Path.Combine(windir, "System32", "drivers");
            const string servicesRoot = @"SYSTEM\CurrentControlSet\Services";

            try
            {
                using RegistryKey? servicesKey = Registry.LocalMachine.OpenSubKey(servicesRoot, writable: false);
                if (servicesKey is null)
                    return;

                string[] serviceNames = servicesKey.GetSubKeyNames();

                foreach (string serviceName in serviceNames)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    bool matched       = false;
                    string matchedDrv  = string.Empty;

                    foreach (string driverFile in ByovdDriverNames)
                    {
                        string driverBase = Path.GetFileNameWithoutExtension(driverFile);
                        if (serviceName.Equals(driverBase, StringComparison.OrdinalIgnoreCase))
                        {
                            matched    = true;
                            matchedDrv = driverFile;
                            break;
                        }
                    }

                    if (!matched)
                        continue;

                    try
                    {
                        using RegistryKey? svcKey = servicesKey.OpenSubKey(serviceName, writable: false);
                        if (svcKey is null)
                            continue;

                        object? imagePathVal = svcKey.GetValue("ImagePath");
                        if (imagePathVal is not string imagePath || string.IsNullOrWhiteSpace(imagePath))
                            continue;

                        string normalized = imagePath
                            .Replace(@"\??\", string.Empty, StringComparison.OrdinalIgnoreCase)
                            .Trim('"');

                        if (!normalized.StartsWith(sys32Drv, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "BYOVD Driver Service with Suspicious ImagePath (BattlEye Context)",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{servicesRoot}\{serviceName}",
                                FileName = matchedDrv,
                                Reason   = $"Service \"{serviceName}\" matches a known BYOVD driver name and its ImagePath is outside System32\\drivers\\. This driver is commonly used to disable BattlEye kernel callbacks.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }
                    }
                    catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                    {
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
            }
        }, ct);
    }

    // =========================================================================
    // 10. Hosts file blocking BattlEye servers
    // =========================================================================
    private async Task CheckHostsFileAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string windir    = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        string hostsPath = Path.Combine(windir, "System32", "drivers", "etc", "hosts");

        if (!File.Exists(hostsPath))
            return;

        ctx.IncrementFiles();

        string content;
        try
        {
            using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
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

        string[] beHostnames =
        [
            "anti-cheat.battleye.com",
            "battleye.com",
            "be-service.battleye.com",
            "update.battleye.com",
        ];

        foreach (string line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            ct.ThrowIfCancellationRequested();

            string trimmedLine = line.Trim();
            if (trimmedLine.StartsWith('#'))
                continue;

            foreach (string hostname in beHostnames)
            {
                if (trimmedLine.Contains(hostname, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Hosts File Blocks BattlEye Server",
                        Risk     = RiskLevel.Critical,
                        Location = hostsPath,
                        FileName = "hosts",
                        Reason   = $"The hosts file contains a redirect entry for \"{hostname}\". Blocking BattlEye's telemetry and update servers prevents cloud-side detection and is a known bypass technique.",
                        Detail   = trimmedLine,
                    });
                    break;
                }
            }
        }
    }

    // =========================================================================
    // 11. Wireshark packet captures (protocol reverse-engineering artifact)
    // =========================================================================
    private async Task ScanWiresharkCapturesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(userProfile, "Documents", "Wireshark"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Wireshark"),
        ];

        string[] captureExtensions = ["*.pcap", "*.pcapng"];

        foreach (string dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            foreach (string ext in captureExtensions)
            {
                IEnumerable<string> captureFiles;
                try
                {
                    captureFiles = Directory.EnumerateFiles(dir, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string capturePath in captureFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        string fileName = Path.GetFileName(capturePath);
                        long fileSize   = new FileInfo(capturePath).Length;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Wireshark Network Capture File Found",
                            Risk     = RiskLevel.Medium,
                            Location = capturePath,
                            FileName = fileName,
                            Reason   = "A Wireshark packet capture file was found. Captures during gaming sessions are used to reverse-engineer BattlEye protocol patterns for bypass development.",
                            Detail   = $"File size: {fileSize} bytes",
                        });
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 12. PUBG-specific BattlEye bypass DLLs in PUBG game directories
    // =========================================================================
    private async Task CheckPubgBeDllsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] pubgDirs =
        [
            @"C:\Program Files (x86)\Steam\steamapps\common\PLAYERUNKNOWN'S BATTLEGROUNDS",
            @"C:\Program Files (x86)\Steam\steamapps\common\PUBG",
            @"C:\Program Files\PUBG",
        ];

        string[] suspiciousDllNames =
        [
            "tslgame_be.dll",
            "pubg_bypass.dll",
            "pubg_be_bypass.dll",
            "BEClient_bypass.dll",
            "be_bypass_pubg.dll",
            "pubg_cheat.dll",
            "pubg_hack.dll",
        ];

        foreach (string pubgDir in pubgDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(pubgDir))
                continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(pubgDir, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string dllPath in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    string fileName = Path.GetFileName(dllPath);

                    foreach (string bad in suspiciousDllNames)
                    {
                        if (fileName.Equals(bad, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "PUBG-Specific BattlEye Bypass DLL Detected",
                                Risk     = RiskLevel.Critical,
                                Location = dllPath,
                                FileName = fileName,
                                Reason   = $"DLL \"{fileName}\" matches a known PUBG BattlEye bypass file name. This DLL is used to disable or mock BattlEye in PUBG.",
                                Detail   = $"PUBG directory: {pubgDir}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 13. DayZ BEClient.dll replacement check (file size + PE export anomaly)
    // =========================================================================
    private async Task CheckDayzBeClientDllAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] dayzDirs =
        [
            @"C:\Program Files (x86)\Steam\steamapps\common\DayZ",
            @"C:\Program Files\DayZ",
        ];

        // A replacement stub is typically very small; a bloated fake is very large.
        const long suspSmallBytes = 50 * 1024;
        const long suspLargeBytes = 5 * 1024 * 1024;
        const long minLegitSize   = 300 * 1024;
        const long maxLegitSize   = 2 * 1024 * 1024;

        foreach (string dayzDir in dayzDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dayzDir))
                continue;

            IEnumerable<string> beClientDlls;
            try
            {
                beClientDlls = Directory.EnumerateFiles(dayzDir, "BEClient*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string dllPath in beClientDlls)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    var fi   = new FileInfo(dllPath);
                    long size = fi.Length;

                    if (size < suspSmallBytes)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "DayZ BEClient.dll Suspiciously Small (Possible Stub Replacement)",
                            Risk     = RiskLevel.High,
                            Location = dllPath,
                            FileName = Path.GetFileName(dllPath),
                            Reason   = $"BEClient DLL file size is {size / 1024} KB, which is below the expected minimum of ~{minLegitSize / 1024} KB. A minimal stub that does nothing would disable BattlEye silently.",
                            Detail   = $"File size: {size} bytes | Expected minimum: {minLegitSize} bytes",
                        });
                    }
                    else if (size > suspLargeBytes)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "DayZ BEClient.dll Suspiciously Large (Possible Bloated Replacement)",
                            Risk     = RiskLevel.Medium,
                            Location = dllPath,
                            FileName = Path.GetFileName(dllPath),
                            Reason   = $"BEClient DLL file size is {size / 1024} KB, exceeding the expected maximum of ~{maxLegitSize / 1024} KB. The file may be a packed or padded replacement.",
                            Detail   = $"File size: {size} bytes | Expected maximum: {maxLegitSize} bytes",
                        });
                    }

                    // PE export check: legitimate BEClient.dll must export functions
                    await CheckDllExportPresenceAsync(ctx, dllPath, ct);
                }
                catch (IOException)
                {
                }
            }
        }
    }

    private async Task CheckDllExportPresenceAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string dllPath,
        CancellationToken ct)
    {
        byte[] header = new byte[4096];
        int bytesRead;

        try
        {
            using var fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            bytesRead = await fs.ReadAsync(header.AsMemory(0, header.Length), ct);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (bytesRead < 64)
            return;

        // Validate MZ magic
        if (header[0] != 0x4D || header[1] != 0x5A)
            return;

        // PE header offset is at 0x3C
        int peOffset = BitConverter.ToInt32(header, 0x3C);
        if (peOffset < 0 || peOffset + 28 >= bytesRead)
            return;

        // Validate PE signature
        if (header[peOffset] != 0x50 || header[peOffset + 1] != 0x45)
            return;

        int optOffset = peOffset + 24;
        if (optOffset + 116 >= bytesRead)
            return;

        ushort magic          = BitConverter.ToUInt16(header, optOffset);
        int exportRvaOffset   = magic == 0x20B ? optOffset + 112 : optOffset + 96;

        if (exportRvaOffset + 4 >= bytesRead)
            return;

        uint exportRva = BitConverter.ToUInt32(header, exportRvaOffset);
        if (exportRva == 0)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "DayZ BEClient.dll Has No PE Export Directory (Possible Stub)",
                Risk     = RiskLevel.Critical,
                Location = dllPath,
                FileName = Path.GetFileName(dllPath),
                Reason   = "BEClient.dll has no PE export directory (export RVA is 0). A legitimate BEClient.dll exports functions; a stub designed to disable BattlEye silently would have no exports.",
                Detail   = "Export directory RVA = 0x00000000",
            });
        }
    }

    // =========================================================================
    // 14. Cheat loader configs with BattlEye-specific injection markers
    // =========================================================================
    private async Task ScanInjectionMarkerConfigsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] searchDirs   = BuildUserScanDirectories();
        string[] configExts   = ["*.ini", "*.cfg", "*.json", "*.txt", "*.xml"];

        string[] beKeywords =
        [
            "be_bypass",
            "battleye_bypass",
            "be_safe",
            "bypass_be",
            "inject_timing",
            "be_delay",
            "battleye_delay",
            "be_hook_mode",
            "be_unload",
            "be_spoof",
            "skip_battleye",
            "disable_be",
            "be_killer",
            "battleye_safe",
            "be_loader_mode",
        ];

        foreach (string dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            foreach (string ext in configExts)
            {
                IEnumerable<string> configFiles;
                try
                {
                    configFiles = Directory.EnumerateFiles(dir, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string configPath in configFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    await InspectConfigForBeMarkersAsync(ctx, configPath, beKeywords, ct);
                }
            }
        }
    }

    private async Task InspectConfigForBeMarkersAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string configPath,
        string[] keywords,
        CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
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

        ct.ThrowIfCancellationRequested();

        string fileName = Path.GetFileName(configPath);

        foreach (string keyword in keywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Config File Contains BattlEye Bypass Marker",
                    Risk     = RiskLevel.High,
                    Location = configPath,
                    FileName = fileName,
                    Reason   = $"Config file contains the keyword \"{keyword}\", a known BattlEye bypass parameter used by cheat loaders to control injection timing or disable BattlEye hooks.",
                    Detail   = ExtractMatchingLine(content, keyword),
                });
                return;
            }
        }
    }

    // =========================================================================
    // Private utility helpers
    // =========================================================================

    private static string[] BuildUserScanDirectories()
    {
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string desktop      = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string userProfile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloads    = Path.Combine(userProfile, "Downloads");
        string systemTemp   = Path.GetTempPath();
        string localTemp    = Path.Combine(localAppData, "Temp");

        return
        [
            desktop,
            downloads,
            systemTemp,
            localTemp,
            appData,
            localAppData,
        ];
    }

    private static bool IsInSuspiciousUserPath(string path)
    {
        string[] fragments =
        [
            @"\Temp\",
            @"\Downloads\",
            @"\AppData\",
        ];

        foreach (string fragment in fragments)
        {
            if (path.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        string[] endings =
        [
            @"\Temp",
            @"\Downloads",
            @"\AppData",
        ];

        foreach (string ending in endings)
        {
            if (path.EndsWith(ending, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string ExtractMatchingLine(string content, string pattern)
    {
        foreach (string line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return line.Trim();
        }

        return string.Empty;
    }
}
