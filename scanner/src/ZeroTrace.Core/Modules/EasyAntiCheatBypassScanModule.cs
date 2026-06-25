using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

// EasyAntiCheat bypass detection module.
// Checks registry services, known bypass tool files, certificate store tampering,
// game directory integrity, log anomalies, DLL sideloading, BYOVD drivers,
// GitHub repo artifacts, PowerShell history, ETW ntdll copies, and script files.
public sealed class EasyAntiCheatBypassScanModule : IScanModule
{
    public string Name => "Easy Anti-Cheat Bypass Detection";
    public double Weight => 4.2;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Known bypass tool file names — flagged Critical anywhere they appear
    // -------------------------------------------------------------------------
    private static readonly string[] KnownBypassFileNames =
    [
        "eac_bypass.exe",
        "eac_spoofer.exe",
        "eac_patcher.exe",
        "eac_unloader.dll",
        "EACBypass.dll",
        "EAC-Bypass.exe",
        "anticlient_bypass.dll",
        "EACLoader.exe",
        "EACKiller.exe",
        "AntiCheatKiller.exe",
        "ServiceKiller.exe",
        "DriverUnloader.exe",
        "BypassLoader.exe",
        "FortniteBypass.exe",
        "ApexBypass.exe",
        "RustBypass.exe",
        "eac_emu.dll",
        "eac_emulator.dll",
        "eac_hook.dll",
        "eac_hook.exe",
        "eac_disable.exe",
        "eac_disable.bat",
        "EACFix.exe",
        "EACPatch.exe",
        "EACRemover.exe",
        "EACStub.exe",
        "EACLoader_bypass.exe",
        "eac_launcher_bypass.exe",
        "noeac.exe",
        "eacoff.exe",
    ];

    // anticlient.dll is only suspicious outside a legitimate EAC install directory
    private const string AntclientDll = "anticlient.dll";

    // -------------------------------------------------------------------------
    // Legitimate DLLs that are expected to live next to EasyAntiCheat_EOS.exe
    // -------------------------------------------------------------------------
    private static readonly string[] LegitEacDlls =
    [
        "EasyAntiCheat_EOS.dll",
        "EasyAntiCheat.dll",
    ];

    // -------------------------------------------------------------------------
    // BYOVD (Bring Your Own Vulnerable Driver) known-bad driver filenames
    // -------------------------------------------------------------------------
    private static readonly string[] ByovdDriverNames =
    [
        "gdrv.sys",
        "WinRing0x64.sys",
        "WinRing0.sys",
        "cpuz141_x64.sys",
        "cpuz143_x64.sys",
        "AsrDrv103.sys",
        "HwRwDrv.sys",
        "iqvw64e.sys",
        "MsIo64.sys",
        "PhyMemDrv.sys",
        "PROCEXP152.SYS",
        "dbutil_2_3.sys",
        "RTCore64.sys",
        "kprocesshacker.sys",
        "AsUpIO64.sys",
        "NalDrv.sys",
        "Speedfan.sys",
        "mhyprot2.sys",
        "Dbk64.sys",
        "HackerShield.sys",
        "viragt64.sys",
        "AsIO3.sys",
        "cpuz145.sys",
        "ALCPU64.sys",
        "EneTechIo64.sys",
        "phymem64.sys",
        "nicm.sys",
    ];

    // -------------------------------------------------------------------------
    // Known EAC bypass GitHub repository folder names
    // -------------------------------------------------------------------------
    private static readonly string[] BypassRepoDirNames =
    [
        "EAC-Bypass",
        "EasyAntiCheat-Bypass",
        "eac-emu",
        "eac-emulator",
        "EACBypass",
        "eac-bypass",
        "EasyAntiCheatBypass",
        "eac_bypass_source",
        "anticlient_bypass",
    ];

    // -------------------------------------------------------------------------
    // PowerShell history command patterns and their associated risk levels
    // -------------------------------------------------------------------------
    private static readonly (string Pattern, RiskLevel Risk, string Title)[] PsHistoryPatterns =
    [
        ("sc delete EasyAntiCheat",                                            RiskLevel.Critical, "EAC Service Deletion via sc.exe"),
        ("EtwpDisablePatchGuard",                                              RiskLevel.Critical, "EtwpDisablePatchGuard Invocation in PS History"),
        ("bcdedit /set nointegritychecks on",                                  RiskLevel.Critical, "Boot Integrity Checks Disabled via bcdedit"),
        ("kdmapper",                                                            RiskLevel.Critical, "kdmapper Kernel Driver Mapper in PS History"),
        ("[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer",   RiskLevel.High,     "ETW Function Pointer Patch Pattern in PS History"),
        ("sc stop EasyAntiCheat",                                              RiskLevel.High,     "EAC Service Stopped via sc.exe"),
        ("net stop EasyAntiCheat",                                             RiskLevel.High,     "EAC Service Stopped via net stop"),
        ("bcdedit /set testsigning on",                                        RiskLevel.High,     "Test Signing Mode Enabled via bcdedit"),
        ("NtLoadDriver",                                                        RiskLevel.High,     "NtLoadDriver Call in PS History"),
        ("[Reflection.Assembly]::LoadWithPartialName",                         RiskLevel.Medium,   "Reflection Assembly Load (ETW patch artifact) in PS History"),
    ];

    // -------------------------------------------------------------------------
    // Entry point — delegates to all helper methods
    // -------------------------------------------------------------------------
    public async Task RunAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        // Run all detection helpers in sequence.
        // Each helper is async and uses await internally.
        await CheckEacServiceRegistryAsync(ctx, ct);
        await ScanBypassToolFilesAsync(ctx, ct);
        await CheckCertificateStoreTamperingAsync(ctx, ct);
        await CheckGameDirectoryIntegrityAsync(ctx, ct);
        await CheckEacLogAnomaliesAsync(ctx, ct);
        await CheckDllSideloadingAsync(ctx, ct);
        await CheckEacDriverPathAsync(ctx, ct);
        await ScanByovdDriversAsync(ctx, ct);
        await CheckBypassRepoDirsAsync(ctx, ct);
        await CheckPowerShellHistoryAsync(ctx, ct);
        await CheckNtdllCopiesAsync(ctx, ct);
        await ScanScriptFilesAsync(ctx, ct);
    }

    // =========================================================================
    // 1. EAC service registry checks
    // =========================================================================
    private async Task CheckEacServiceRegistryAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string[] serviceKeys =
            [
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS",
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

                    // Check Start value — 4 means disabled
                    object? startVal = key.GetValue("Start");
                    if (startVal is int startInt && startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "EAC Service Disabled in Registry",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = "The EasyAntiCheat service Start value is set to 4 (Disabled). A bypass tool may have disabled the service.",
                            Detail   = $"Start = {startInt}",
                        });
                    }

                    // Check ImagePath value
                    object? imagePathVal = key.GetValue("ImagePath");
                    if (imagePathVal is string imagePath && !string.IsNullOrWhiteSpace(imagePath)
                        )
                    {
                        // Flag if ImagePath does not contain \EasyAntiCheat\ (case-insensitive)
                        if (!imagePath.Contains(@"\EasyAntiCheat\", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "EAC Service ImagePath Outside EAC Directory",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                Reason   = "EasyAntiCheat service ImagePath does not reference the \\EasyAntiCheat\\ directory. The service binary may have been redirected.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }

                        // Flag if ImagePath points to Temp, Downloads, or AppData locations
                        if (IsInSuspiciousUserPath(imagePath))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "EAC Service ImagePath Points to User Writable Location",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                Reason   = "EasyAntiCheat service ImagePath references a Temp, Downloads, or AppData directory — a strong indicator of binary redirection by a bypass tool.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                    // Insufficient privileges to read this key — skip silently
                }
            }
        }, ct);
    }

    // =========================================================================
    // 2. Known EAC bypass tool files
    // =========================================================================
    private async Task ScanBypassToolFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        // Directories to scan for known bypass tool filenames
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

                    // Check against the known bypass filename list
                    foreach (string bad in KnownBypassFileNames)
                    {
                        if (fileName.Equals(bad, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Known EAC Bypass Tool Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File name \"{fileName}\" matches a known EasyAntiCheat bypass tool.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }

                    // anticlient.dll is only suspicious outside a legitimate EAC install directory
                    if (fileName.Equals(AntclientDll, StringComparison.OrdinalIgnoreCase))
                    {
                        string fileDir = Path.GetDirectoryName(filePath) ?? string.Empty;
                        if (!fileDir.Contains(@"\EasyAntiCheat\", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "anticlient.dll Outside EAC Directory",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = "anticlient.dll found outside the EasyAntiCheat installation directory. This DLL is legitimate only inside an EAC game folder.",
                                Detail   = $"Directory: {fileDir}",
                            });
                        }
                    }
                }
                catch (IOException)
                {
                    // File may have been deleted or locked — skip silently
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 3. EAC certificate store tampering
    // =========================================================================
    private async Task CheckCertificateStoreTamperingAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check HKLM Disallowed certificate store — entries here block EAC code-signing chain
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

                        // Any certificate in the Disallowed store is anomalous and may block EAC.
                        // Flag each one — attacker-placed certs here prevent EAC from launching.
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Certificate in Disallowed Store (Possible EAC Block)",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{regPath}\{thumbprint}",
                            Reason   = "A certificate exists in the system Disallowed store. Placing an EasyAntiCheat code-signing certificate here prevents EAC from launching.",
                            Detail   = $"Thumbprint subkey: {thumbprint}",
                        });
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                    // Skip if we cannot read this key
                }
            }

            // Also check HKCU Disallowed store
            string hkcuDisallowed = @"SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates";
            ctx.IncrementRegistryKeys();

            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(hkcuDisallowed, writable: false);
                if (key is not null)
                {
                    string[] subkeyNames = key.GetSubKeyNames();
                    foreach (string thumbprint in subkeyNames)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Certificate in HKCU Disallowed Store (Possible EAC Block)",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{hkcuDisallowed}\{thumbprint}",
                            Reason   = "A certificate exists in the current user Disallowed store. This can block EasyAntiCheat's code-signing verification.",
                            Detail   = $"Thumbprint subkey: {thumbprint}",
                        });
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
                // Skip if we cannot read HKCU key
            }
        }, ct);
    }

    // =========================================================================
    // 4. EAC game directory integrity checks
    // =========================================================================
    private async Task CheckGameDirectoryIntegrityAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Standalone EAC installation directory
            string[] standaloneDirs =
            [
                @"C:\Program Files\EasyAntiCheat",
                @"C:\Program Files (x86)\EasyAntiCheat",
            ];

            foreach (string dir in standaloneDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir))
                    continue;

                CheckEacExePresence(ctx, dir, dir);
            }

            // Steam game library
            string steamAppsCommon = @"C:\Program Files (x86)\Steam\steamapps\common";
            ScanGameLibraryForEac(ctx, steamAppsCommon, ct);

            // Epic Games library
            string epicGames = @"C:\Program Files\Epic Games";
            ScanGameLibraryForEac(ctx, epicGames, ct);

            // EA/Origin library
            string[] eaLibraries =
            [
                @"C:\Program Files\EA Games",
                @"C:\Program Files (x86)\Origin Games",
                @"C:\Program Files\Origin Games",
                @"C:\Program Files\EA",
            ];

            foreach (string lib in eaLibraries)
            {
                ct.ThrowIfCancellationRequested();
                ScanGameLibraryForEac(ctx, lib, ct);
            }
        }, ct);
    }

    // Enumerate immediate subdirectories of a game library root and check each for EAC
    private void ScanGameLibraryForEac(ZeroTrace.Core.Engine.ScanContext ctx, string libraryRoot, CancellationToken ct)
    {
        if (!Directory.Exists(libraryRoot))
            return;

        IEnumerable<string> gameDirs;
        try
        {
            gameDirs = Directory.EnumerateDirectories(libraryRoot, "*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (string gameDir in gameDirs)
        {
            ct.ThrowIfCancellationRequested();

            // Only inspect game directories that appear to ship EAC
            string eacSubdir = Path.Combine(gameDir, "EasyAntiCheat");
            if (!Directory.Exists(eacSubdir))
                continue; // Game does not use EAC — not our concern

            CheckEacExePresence(ctx, gameDir, eacSubdir);
        }
    }

    // Verify that EasyAntiCheat\EasyAntiCheat_EOS.exe or EasyAntiCheat.exe is present
    private void CheckEacExePresence(ZeroTrace.Core.Engine.ScanContext ctx, string gameRoot, string eacDir)
    {
        string eosExe    = Path.Combine(eacDir, "EasyAntiCheat_EOS.exe");
        string legacyExe = Path.Combine(eacDir, "EasyAntiCheat.exe");

        bool eosPresent    = File.Exists(eosExe);
        bool legacyPresent = File.Exists(legacyExe);

        if (!eosPresent && !legacyPresent)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "EAC Executable Missing from Game Directory",
                Risk     = RiskLevel.Medium,
                Location = eacDir,
                Reason   = "The EasyAntiCheat directory exists but neither EasyAntiCheat_EOS.exe nor EasyAntiCheat.exe is present. The EAC executable may have been removed by a bypass tool.",
                Detail   = $"Game root: {gameRoot}",
            });
        }
    }

    // =========================================================================
    // 5. EAC log file anomalies
    // =========================================================================
    private async Task CheckEacLogAnomaliesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Build a list of candidate game directories to search for EAC logs
            List<string> gameDirs = [];
            CollectGameDirectories(gameDirs);

            foreach (string gameDir in gameDirs)
            {
                ct.ThrowIfCancellationRequested();

                string logDir = Path.Combine(gameDir, "EasyAntiCheat", "Logs");
                if (!Directory.Exists(logDir))
                    continue;

                // Check whether the log directory is completely empty
                string[] allEntries;
                try
                {
                    allEntries = Directory.GetFileSystemEntries(logDir);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                if (allEntries.Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "EAC Log Directory Is Empty",
                        Risk     = RiskLevel.Low,
                        Location = logDir,
                        Reason   = "The EasyAntiCheat Logs directory exists but contains no files. Log files may have been deleted.",
                        Detail   = $"Game directory: {gameDir}",
                    });
                    continue;
                }

                // Check individual .log files for zero-byte size (cleared logs)
                IEnumerable<string> logFiles;
                try
                {
                    logFiles = Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        var fi = new FileInfo(logFile);
                        if (fi.Length == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "EAC Log File Cleared (Zero Bytes)",
                                Risk     = RiskLevel.Medium,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason   = "An EasyAntiCheat log file exists but has zero bytes. Logs are typically cleared by bypass tools to hide detection events.",
                                Detail   = $"Game directory: {gameDir}",
                            });
                        }
                    }
                    catch (IOException)
                    {
                        // File inaccessible — skip silently
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 6. DLL sideloading next to EasyAntiCheat_EOS.exe
    // =========================================================================
    private async Task CheckDllSideloadingAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            List<string> gameDirs = [];
            CollectGameDirectories(gameDirs);

            // Also check standalone EAC install paths
            gameDirs.Add(@"C:\Program Files\EasyAntiCheat");
            gameDirs.Add(@"C:\Program Files (x86)\EasyAntiCheat");

            foreach (string gameDir in gameDirs)
            {
                ct.ThrowIfCancellationRequested();

                // Look for EasyAntiCheat_EOS.exe in all subdirectories
                IEnumerable<string> exeFiles;
                try
                {
                    exeFiles = Directory.EnumerateFiles(gameDir, "EasyAntiCheat_EOS.exe", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string eosExe in exeFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string eosDir = Path.GetDirectoryName(eosExe) ?? string.Empty;
                    if (string.IsNullOrEmpty(eosDir))
                        continue;

                    CheckForUnexpectedDllsInDir(ctx, eosDir, ct);
                }
            }
        }, ct);
    }

    // Check a directory for DLL files that are not in the known-legitimate EAC DLL list
    private void CheckForUnexpectedDllsInDir(ZeroTrace.Core.Engine.ScanContext ctx, string dir, CancellationToken ct)
    {
        IEnumerable<string> dllFiles;
        try
        {
            dllFiles = Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (string dllPath in dllFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            try
            {
                string dllName = Path.GetFileName(dllPath);

                // Check whether this DLL is in the known-legitimate set
                bool isLegit = false;
                foreach (string legit in LegitEacDlls)
                {
                    if (dllName.Equals(legit, StringComparison.OrdinalIgnoreCase))
                    {
                        isLegit = true;
                        break;
                    }
                }

                if (!isLegit)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Unexpected DLL Next to EasyAntiCheat_EOS.exe",
                        Risk     = RiskLevel.Critical,
                        Location = dllPath,
                        FileName = dllName,
                        Reason   = $"DLL \"{dllName}\" is not a known legitimate EasyAntiCheat file but resides in the same directory as EasyAntiCheat_EOS.exe. This is a classic DLL sideloading indicator.",
                        Detail   = $"Directory: {dir}",
                    });
                }
            }
            catch (IOException)
            {
                // File inaccessible — skip silently
            }
        }
    }

    // =========================================================================
    // 7. EAC driver outside expected path
    // =========================================================================
    private async Task CheckEacDriverPathAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string windir   = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
            string sys32Drv = Path.Combine(windir, "System32", "drivers");

            // Check registry ImagePath for the EAC service driver
            string[] serviceKeys =
            [
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS",
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

                    object? imagePathVal = key.GetValue("ImagePath");
                    if (imagePathVal is string imagePath && !string.IsNullOrWhiteSpace(imagePath))
                    {
                        // Only examine kernel driver entries (*.sys)
                        if (!imagePath.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
                            continue;

                        // Normalize: strip \??\ prefix if present
                        string normalizedPath = imagePath
                            .Replace(@"\??\", string.Empty, StringComparison.OrdinalIgnoreCase)
                            .Trim('"');

                        bool inSystem32  = normalizedPath.StartsWith(sys32Drv, StringComparison.OrdinalIgnoreCase);
                        bool inEacFolder = normalizedPath.Contains(@"\EasyAntiCheat\", StringComparison.OrdinalIgnoreCase);

                        if (!inSystem32 && !inEacFolder)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "EAC Driver Loaded from Unexpected Path",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                FileName = Path.GetFileName(normalizedPath),
                                Reason   = "The EasyAntiCheat kernel driver is configured to load from a path outside System32\\drivers\\ and outside the EAC installation directory.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                    // Skip inaccessible registry key silently
                }
            }

            // Also search Temp, Downloads, and AppData for a stray easyanticheat.sys file
            string[] suspiciousSearchDirs = BuildUserScanDirectories();
            foreach (string searchDir in suspiciousSearchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(searchDir))
                    continue;

                IEnumerable<string> sysFiles;
                try
                {
                    sysFiles = Directory.EnumerateFiles(searchDir, "easyanticheat.sys", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string sysFile in sysFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "EAC Driver File in Suspicious Location",
                            Risk     = RiskLevel.Critical,
                            Location = sysFile,
                            FileName = Path.GetFileName(sysFile),
                            Reason   = "easyanticheat.sys was found in a Temp, Downloads, or AppData directory. The EAC driver should never reside in user-writable locations.",
                            Detail   = $"Path: {sysFile}",
                        });
                    }
                    catch (IOException)
                    {
                        // File inaccessible — skip silently
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 8. BYOVD vulnerable driver detection
    // =========================================================================
    private async Task ScanByovdDriversAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        // Part A: Check files on disk in suspicious directories
        await ScanByovdDriverFilesAsync(ctx, ct);

        // Part B: Check registry services for BYOVD driver entries pointing outside System32
        await ScanByovdDriverRegistryAsync(ctx, ct);
    }

    private async Task ScanByovdDriverFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
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
                                Title    = "BYOVD Vulnerable Driver Found on Disk",
                                Risk     = RiskLevel.Critical,
                                Location = sysPath,
                                FileName = sysName,
                                Reason   = $"Known vulnerable driver \"{sysName}\" found in a user-writable location. BYOVD (Bring Your Own Vulnerable Driver) attacks exploit these drivers to disable kernel-level anti-cheat such as EAC.",
                                Detail   = $"Directory: {Path.GetDirectoryName(sysPath)}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                    // File inaccessible — skip silently
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanByovdDriverRegistryAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
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

                    // Check whether the service name matches a BYOVD driver filename (without extension)
                    bool matchesByovd = false;
                    string matchedDriver = string.Empty;

                    foreach (string driverFile in ByovdDriverNames)
                    {
                        string driverBase = Path.GetFileNameWithoutExtension(driverFile);
                        if (serviceName.Equals(driverBase, StringComparison.OrdinalIgnoreCase))
                        {
                            matchesByovd  = true;
                            matchedDriver = driverFile;
                            break;
                        }
                    }

                    if (!matchesByovd)
                        continue;

                    // Service name matches — inspect ImagePath
                    try
                    {
                        using RegistryKey? svcKey = servicesKey.OpenSubKey(serviceName, writable: false);
                        if (svcKey is null)
                            continue;

                        object? imagePathVal = svcKey.GetValue("ImagePath");
                        if (imagePathVal is not string imagePath || string.IsNullOrWhiteSpace(imagePath))
                            continue;

                        string normalizedPath = imagePath
                            .Replace(@"\??\", string.Empty, StringComparison.OrdinalIgnoreCase)
                            .Trim('"');

                        // Flag if the driver is NOT in System32\drivers
                        if (!normalizedPath.StartsWith(sys32Drv, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "BYOVD Driver Service with Suspicious ImagePath",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{servicesRoot}\{serviceName}",
                                FileName = matchedDriver,
                                Reason   = $"Registry service \"{serviceName}\" matches a known BYOVD vulnerable driver and its ImagePath is outside System32\\drivers\\. The driver may be loaded to disable EAC at the kernel level.",
                                Detail   = $"ImagePath = {imagePath}",
                            });
                        }
                    }
                    catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                    {
                        // Skip inaccessible service subkeys silently
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
                // Cannot read Services key — skip silently
            }
        }, ct);
    }

    // =========================================================================
    // 9. GitHub bypass repository directory artifacts
    // =========================================================================
    private async Task CheckBypassRepoDirsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string[] searchRoots =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is string profile
                    ? Path.Combine(profile, "Downloads") : string.Empty,
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
                                    Title    = "EAC Bypass Repository Directory Found",
                                    Risk     = RiskLevel.High,
                                    Location = subDir,
                                    Reason   = $"Directory \"{dirName}\" matches a known EasyAntiCheat bypass GitHub repository name. This strongly indicates the user has cloned or possessed bypass source code.",
                                    Detail   = $"Matched pattern: {repoName}",
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException)
                    {
                        // Directory entry inaccessible — skip silently
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // 10. PowerShell history — EAC bypass commands
    // =========================================================================
    private async Task CheckPowerShellHistoryAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string historyPath = Path.Combine(
            appData,
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

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

        // Check all static patterns
        foreach (var (pattern, risk, title) in PsHistoryPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = title,
                    Risk     = risk,
                    Location = historyPath,
                    FileName = Path.GetFileName(historyPath),
                    Reason   = $"PowerShell history contains the pattern: \"{pattern}\"",
                    Detail   = ExtractMatchingLine(content, pattern),
                });
            }
        }

        // taskkill + EasyAntiCheat combined check
        if (content.Contains("taskkill", StringComparison.OrdinalIgnoreCase)
            && content.Contains("EasyAntiCheat", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "EAC Process Kill via taskkill in PS History",
                Risk     = RiskLevel.High,
                Location = historyPath,
                FileName = Path.GetFileName(historyPath),
                Reason   = "PowerShell history contains both \"taskkill\" and \"EasyAntiCheat\" — indicative of an attempt to forcibly terminate the EAC process.",
                Detail   = ExtractMatchingLine(content, "taskkill"),
            });
        }

        // EtwEventWrite combined with patch/hook/bypass/disable
        if (content.Contains("EtwEventWrite", StringComparison.OrdinalIgnoreCase))
        {
            string[] etwCompanions = ["patch", "hook", "bypass", "disable"];
            foreach (string companion in etwCompanions)
            {
                if (content.Contains(companion, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "ETW EtwEventWrite Patch/Hook Command in PS History",
                        Risk     = RiskLevel.Critical,
                        Location = historyPath,
                        FileName = Path.GetFileName(historyPath),
                        Reason   = $"PowerShell history contains \"EtwEventWrite\" combined with \"{companion}\". ETW patching is used to blind kernel-level anti-cheat telemetry.",
                        Detail   = ExtractMatchingLine(content, "EtwEventWrite"),
                    });
                    break;
                }
            }
        }

        // "eac" combined with bypass/disable/kill/patch
        string[] eacActionWords = ["bypass", "disable", "kill", "patch"];
        foreach (string action in eacActionWords)
        {
            // Search line by line to find lines containing both "eac" and the action word
            bool found = false;
            foreach (string line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.Contains("eac", StringComparison.OrdinalIgnoreCase)
                    && line.Contains(action, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"EAC {action} Command in PS History",
                        Risk     = RiskLevel.High,
                        Location = historyPath,
                        FileName = Path.GetFileName(historyPath),
                        Reason   = $"PowerShell history line contains both \"eac\" and \"{action}\", indicating an attempt to {action} EasyAntiCheat.",
                        Detail   = line.Trim(),
                    });
                    found = true;
                    break;
                }
            }

            if (found)
                break; // Avoid duplicate findings for the same history file
        }
    }

    // =========================================================================
    // 11. Modified ntdll.dll in application directories (ETW patching artifact)
    // =========================================================================
    private async Task CheckNtdllCopiesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string windir       = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        string sys32        = Path.Combine(windir, "System32");
        string syswow64     = Path.Combine(windir, "SysWOW64");

        // Directories to search for stray ntdll.dll copies
        List<string> searchDirs = [..BuildUserScanDirectories()];

        // Also check under Program Files game directories
        string[] programFileRoots =
        [
            @"C:\Program Files",
            @"C:\Program Files (x86)",
        ];

        foreach (string pfRoot in programFileRoots)
        {
            if (!Directory.Exists(pfRoot))
                continue;

            IEnumerable<string> pfSubDirs;
            try
            {
                pfSubDirs = Directory.EnumerateDirectories(pfRoot, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string pfSubDir in pfSubDirs)
            {
                ct.ThrowIfCancellationRequested();
                searchDirs.Add(pfSubDir);
            }
        }

        foreach (string dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> ntdllFiles;
            try
            {
                ntdllFiles = Directory.EnumerateFiles(dir, "ntdll.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string ntdllPath in ntdllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    // Only flag if it is NOT in System32 or SysWOW64
                    bool inSystem32  = ntdllPath.StartsWith(sys32, StringComparison.OrdinalIgnoreCase);
                    bool inSysWow64  = ntdllPath.StartsWith(syswow64, StringComparison.OrdinalIgnoreCase);

                    if (!inSystem32 && !inSysWow64)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "ntdll.dll Copy Outside System32 (ETW Patch Artifact)",
                            Risk     = RiskLevel.Critical,
                            Location = ntdllPath,
                            FileName = "ntdll.dll",
                            Reason   = "A copy of ntdll.dll was found outside System32 and SysWOW64. Attackers place a patched ntdll.dll next to game executables to intercept ETW calls and blind EasyAntiCheat telemetry (double-load technique).",
                            Detail   = $"Directory: {Path.GetDirectoryName(ntdllPath)}",
                        });
                    }
                }
                catch (IOException)
                {
                    // File inaccessible — skip silently
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 12. Batch/script files targeting EAC
    // =========================================================================
    private async Task ScanScriptFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scriptExtensions = ["*.bat", "*.cmd", "*.ps1", "*.vbs"];

        string[] scriptSearchDirs =
        [
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Downloads"),
        ];

        // Action words that make the script suspicious when paired with EAC identifiers
        string[] actionWords = ["stop", "delete", "kill", "disable", "taskkill"];

        // EAC identifier strings to look for in script content
        string[] eacIdentifiers = ["EasyAntiCheat", "EACService", "eac_service"];

        foreach (string dir in scriptSearchDirs)
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

                    await InspectScriptFileAsync(ctx, scriptPath, eacIdentifiers, actionWords, ct);
                }
            }
        }
    }

    private async Task InspectScriptFileAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string scriptPath,
        string[] eacIdentifiers,
        string[] actionWords,
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
        string extension = Path.GetExtension(scriptPath).ToLowerInvariant();

        // Check each EAC identifier against each action word
        foreach (string identifier in eacIdentifiers)
        {
            if (!content.Contains(identifier, StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (string action in actionWords)
            {
                if (!content.Contains(action, StringComparison.OrdinalIgnoreCase))
                    continue;

                // Determine risk: delete/kill actions are Critical; stop/disable are High
                RiskLevel risk = (action.Equals("delete", StringComparison.OrdinalIgnoreCase)
                                  || action.Equals("kill", StringComparison.OrdinalIgnoreCase))
                    ? RiskLevel.Critical
                    : RiskLevel.High;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Script File Targeting EAC ({action})",
                    Risk     = risk,
                    Location = scriptPath,
                    FileName = fileName,
                    Reason   = $"Script file contains both \"{identifier}\" and \"{action}\", indicating it may be used to {action} EasyAntiCheat.",
                    Detail   = $"Extension: {extension}, Identifier matched: {identifier}",
                });

                // Only one finding per file — avoid flooding with multiple identifier/action combinations
                return;
            }
        }
    }

    // =========================================================================
    // Private utility helpers
    // =========================================================================

    // Build the list of user-writable directories to scan for suspicious files
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

    // Collect all likely game installation directories for EAC-related checks
    private static void CollectGameDirectories(List<string> dirs)
    {
        string[] steamRoots =
        [
            @"C:\Program Files (x86)\Steam\steamapps\common",
            @"C:\Program Files\Steam\steamapps\common",
        ];

        foreach (string root in steamRoots)
        {
            if (!Directory.Exists(root))
                continue;

            try
            {
                foreach (string subDir in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
                    dirs.Add(subDir);
            }
            catch (UnauthorizedAccessException) { }
        }

        string[] epicRoots =
        [
            @"C:\Program Files\Epic Games",
            @"C:\Program Files (x86)\Epic Games",
        ];

        foreach (string root in epicRoots)
        {
            if (!Directory.Exists(root))
                continue;

            try
            {
                foreach (string subDir in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
                    dirs.Add(subDir);
            }
            catch (UnauthorizedAccessException) { }
        }

        string[] eaRoots =
        [
            @"C:\Program Files\EA Games",
            @"C:\Program Files (x86)\Origin Games",
            @"C:\Program Files\Origin Games",
            @"C:\Program Files\EA",
        ];

        foreach (string root in eaRoots)
        {
            if (!Directory.Exists(root))
                continue;

            try
            {
                foreach (string subDir in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
                    dirs.Add(subDir);
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    // Returns true if the given path resides in a Temp, Downloads, or AppData location
    private static bool IsInSuspiciousUserPath(string path)
    {
        string[] suspiciousFragments =
        [
            @"\Temp\",
            @"\Downloads\",
            @"\AppData\",
        ];

        foreach (string fragment in suspiciousFragments)
        {
            if (path.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        // Also catch paths ending with these directory names (no trailing slash)
        string[] suspiciousEndings =
        [
            @"\Temp",
            @"\Downloads",
            @"\AppData",
        ];

        foreach (string ending in suspiciousEndings)
        {
            if (path.EndsWith(ending, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    // Extract the first line of content that contains the given pattern (for Detail field)
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
