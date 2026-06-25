using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class DllInjectionArtifactScanModule : IScanModule
{
    public string Name => "DLL-Injection-Artifacts";
    public double Weight => 0.7;
    public int ParallelGroup => 4;

    private static readonly string[] KnownInjectorExeNames =
    {
        "injector.exe", "dll_injector.exe", "dllinjector.exe",
        "extreme_injector.exe", "xenos.exe", "xenosinjector.exe",
        "cheatengine.exe", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
        "process_hacker.exe", "processhacker.exe",
        "gh-injector.exe", "ghinjector.exe", "gh_injector.exe",
        "manualmapper.exe", "manual_map.exe",
        "shellcode_injector.exe", "reflective_injector.exe",
        "syringe.exe", "winject.exe",
        "loadlibrary_injector.exe", "remotethread_injector.exe",
        "xenos64.exe",
    };

    private static readonly string[] ManualMapperExeNames =
    {
        "mapper.exe", "manualmapper.exe", "kdmapper.exe", "ksocket.exe",
        "capcom_mapper.exe", "physmem_mapper.exe",
    };

    private static readonly string[] ManualMapperDllNames =
    {
        "mapper.dll", "inject_helper.dll", "shellcode.dll", "payload.dll",
    };

    private static readonly string[] GhInjectorDllNames =
    {
        "GH Injector - x86.dll", "GH Injector - x64.dll",
    };

    private static readonly string[] CheatEnginePrefetchPatterns =
    {
        "CHEATENGINE",
    };

    private static readonly string[] InjectorPrefetchPatterns =
    {
        "INJECTOR", "CHEATENGINE", "XENOS", "EXTREME_INJECTOR",
        "MANUALMAPPER", "KDMAPPER",
    };

    private static readonly string[] CheatTableExtensions =
    {
        ".ct",
    };

    private static readonly string[] GameExecutableNames =
    {
        "GTA5.exe", "FiveM.exe", "RageMP.exe", "altv.exe", "cs2.exe",
        "valorant.exe", "EscapeFromTarkov.exe", "RustClient.exe",
        "Fortnite.exe", "r5apex.exe", "RainbowSix.exe", "BF1.exe",
        "DayZ_x64.exe", "pubg.exe", "bf4.exe", "BF2042.exe",
    };

    private static readonly string[] SuspiciousProcessPathFragments =
    {
        @"\appdata\local\temp\", @"\appdata\roaming\", @"\temp\", @"\tmp\",
    };

    private static readonly string[] SuspiciousProcessArgs =
    {
        "--inject", "--dll", "--pid", "--process",
    };

    private static readonly string[] WerCheatKeywords =
    {
        "injector", "cheatengine", "xenos", "manualmapper", "kdmapper",
        "aimbot", "spoofer", "cheat", "hack",
    };

    private static readonly string[] RecentDocsDllKeywords =
    {
        ".dll",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "DLL-Injection-Artifacts", "Scanning for injector executables on disk...");
        await ScanInjectorFilesOnDiskAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.18, "DLL-Injection-Artifacts", "Checking Cheat Engine artifacts...");
        CheckCheatEngineArtifacts(ctx, ct);

        ctx.Report(0.3, "DLL-Injection-Artifacts", "Checking process injection tool registry artifacts...");
        CheckInjectorRegistryArtifacts(ctx, ct);

        ctx.Report(0.42, "DLL-Injection-Artifacts", "Checking AppInit_DLLs persistence...");
        CheckAppInitDlls(ctx, ct);

        ctx.Report(0.52, "DLL-Injection-Artifacts", "Checking Image File Execution Options hijacking...");
        CheckImageFileExecutionOptions(ctx, ct);

        ctx.Report(0.62, "DLL-Injection-Artifacts", "Scanning Temp for shellcode payloads...");
        await ScanTempForShellcodeAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.73, "DLL-Injection-Artifacts", "Scanning prefetch for injector artifacts...");
        ScanPrefetchArtifacts(ctx, ct);

        ctx.Report(0.82, "DLL-Injection-Artifacts", "Checking running processes for injection indicators...");
        CheckRunningProcessesForInjection(ctx, ct);

        ctx.Report(0.9, "DLL-Injection-Artifacts", "Checking WER crash artifacts...");
        await ScanWerArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.96, "DLL-Injection-Artifacts", "Checking AppCompat and RecentDocs registry...");
        CheckAppCompatAndRecentDocs(ctx, ct);

        ctx.Report(1.0, "DLL-Injection-Artifacts", "DLL injection artifact scan complete.");
    }

    private static readonly string[] DiskSearchRoots = BuildDiskSearchRoots();

    private static string[] BuildDiskSearchRoots()
    {
        var roots = new List<string>();
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
        roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
        roots.Add(Path.GetTempPath());
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        return roots.Where(r => !string.IsNullOrEmpty(r)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static async Task ScanInjectorFilesOnDiskAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in DiskSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
            }
            catch { continue; }

            foreach (var filePath in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(filePath);
                var ext = Path.GetExtension(fileName).ToLowerInvariant();

                foreach (var known in KnownInjectorExeNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "DLL-Injection-Artifacts",
                            Title = $"Known DLL injector executable: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"File '{fileName}' is a known DLL injector tool. " +
                                     "DLL injectors load external cheat DLLs into game processes by abusing " +
                                     "Windows APIs such as CreateRemoteThread, NtCreateThreadEx, or manual mapping.",
                            Detail = $"Path: {filePath}",
                        });
                        goto nextFile;
                    }
                }

                foreach (var known in ManualMapperExeNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "DLL-Injection-Artifacts",
                            Title = $"Manual mapper executable: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"File '{fileName}' is a known manual mapper tool. " +
                                     "Manual mappers load DLLs by directly mapping PE sections into process memory " +
                                     "without calling LoadLibrary, bypassing many anti-cheat module enumeration checks.",
                            Detail = $"Path: {filePath}",
                        });
                        goto nextFile;
                    }
                }

                foreach (var known in ManualMapperDllNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        bool isNonStandardLocation = !filePath.Contains(
                            Environment.GetFolderPath(Environment.SpecialFolder.System),
                            StringComparison.OrdinalIgnoreCase)
                            && !filePath.Contains(
                            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                            StringComparison.OrdinalIgnoreCase);

                        if (isNonStandardLocation)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "DLL-Injection-Artifacts",
                                Title = $"Manual mapper DLL in non-standard location: {fileName}",
                                Risk = RiskLevel.High,
                                Location = filePath,
                                FileName = fileName,
                                Reason = $"DLL '{fileName}' with a known injection helper name found outside standard " +
                                         "system directories. These files are used as injection staging payloads " +
                                         "by manual mapper and reflective injector tools.",
                                Detail = $"Path: {filePath}",
                            });
                        }
                        goto nextFile;
                    }
                }

                foreach (var known in GhInjectorDllNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "DLL-Injection-Artifacts",
                            Title = $"GH Injector DLL found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"'{fileName}' is a DLL component of GH Injector, a widely-used multi-method " +
                                     "DLL injection tool that supports LoadLibrary, LdrLoadDll, manual map, " +
                                     "and other injection techniques.",
                            Detail = $"Path: {filePath}",
                        });
                        goto nextFile;
                    }
                }

                if (ext == ".ct")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "DLL-Injection-Artifacts",
                        Title = $"Cheat Engine table file: {fileName}",
                        Risk = RiskLevel.Medium,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"Cheat Engine table file '{fileName}' (.ct) found. " +
                                 "Cheat Engine tables store memory addresses and value modifications for cheating " +
                                 "in games. Their presence confirms Cheat Engine was used on this machine.",
                        Detail = $"Path: {filePath}",
                    });
                    goto nextFile;
                }

                if (ext == ".bin")
                {
                    bool isDesktopOrDownloads =
                        root.Equals(Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                            StringComparison.OrdinalIgnoreCase)
                        || root.Contains("Downloads", StringComparison.OrdinalIgnoreCase);

                    if (isDesktopOrDownloads)
                    {
                        long fileSize;
                        try { fileSize = new FileInfo(filePath).Length; }
                        catch { goto nextFile; }

                        if (fileSize >= 4 * 1024 && fileSize <= 2 * 1024 * 1024)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "DLL-Injection-Artifacts",
                                Title = $"Suspicious .bin payload on Desktop/Downloads: {fileName}",
                                Risk = RiskLevel.Medium,
                                Location = filePath,
                                FileName = fileName,
                                Reason = $".bin file '{fileName}' ({fileSize / 1024} KB) found in a user-accessible " +
                                         "directory within the typical size range of shellcode or PE payloads (4 KB - 2 MB). " +
                                         "DLL injectors often stage payloads as .bin files to avoid extension-based detection.",
                                Detail = $"Size: {fileSize / 1024} KB | Path: {filePath}",
                            });
                        }
                    }
                }

                nextFile:;
            }
        }
    }

    private static void CheckCheatEngineArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var ceDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine 7.5"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine 7.4"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine 7.3"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine 7.2"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Cheat Engine 7.5"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Cheat Engine 7.4"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Cheat Engine"),
        };

        foreach (var dir in ceDirs)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            if (Directory.Exists(dir))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "DLL-Injection-Artifacts",
                    Title = $"Cheat Engine installation directory found: {Path.GetFileName(dir)}",
                    Risk = RiskLevel.Medium,
                    Location = dir,
                    Reason = $"Cheat Engine installation directory '{dir}' exists. " +
                             "Cheat Engine is a memory scanner and DLL injector widely used to modify game values " +
                             "and attach cheat code to game processes.",
                    Detail = $"Directory: {dir}",
                });
                break;
            }
        }

        if (ct.IsCancellationRequested) return;

        var ceRegistryPaths = new[]
        {
            @"Software\Cheat Engine",
            @"SOFTWARE\Cheat Engine",
        };

        foreach (var regPath in ceRegistryPaths)
        {
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false)
                             ?? Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "DLL-Injection-Artifacts",
                    Title = "Cheat Engine registry key found",
                    Risk = RiskLevel.Medium,
                    Location = $@"HKCU\{regPath}",
                    Reason = "Registry key left by Cheat Engine found. This confirms Cheat Engine was installed " +
                             "on this system. Cheat Engine can inject DLLs, read/write game memory, and intercept " +
                             "system calls used by anti-cheat software.",
                    Detail = $"Registry: {regPath}",
                });
                break;
            }
            catch { }
        }

        if (ct.IsCancellationRequested) return;

        var processes = ctx.GetProcessSnapshot();
        foreach (var proc in processes)
        {
            ctx.IncrementProcesses();
            if (proc.ProcessName.Contains("cheatengine", StringComparison.OrdinalIgnoreCase))
            {
                string? exePath = null;
                try { exePath = proc.MainModule?.FileName; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = "DLL-Injection-Artifacts",
                    Title = $"Cheat Engine process running: {proc.ProcessName}",
                    Risk = RiskLevel.Critical,
                    Location = exePath ?? $"PID {proc.Id}",
                    FileName = proc.ProcessName + ".exe",
                    Reason = $"Cheat Engine process '{proc.ProcessName}' (PID {proc.Id}) is currently running. " +
                             "An active Cheat Engine session can read and write game memory, inject DLLs, " +
                             "and intercept system calls in real time.",
                    Detail = $"PID: {proc.Id} | Path: {exePath ?? "unknown"}",
                });
            }
        }
    }

    private static void CheckInjectorRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var injectorRegEntries = new[]
        {
            (@"Software\Xenos",            "Xenos",            "HKCU"),
            (@"Software\ExtremeInjector",  "Extreme Injector", "HKCU"),
            (@"Software\GHInjector",       "GH Injector",      "HKCU"),
        };

        foreach (var (path, toolName, hive) in injectorRegEntries)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();

            try
            {
                using var key = hive == "HKCU"
                    ? Registry.CurrentUser.OpenSubKey(path, writable: false)
                    : Registry.LocalMachine.OpenSubKey(path, writable: false);
                if (key is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "DLL-Injection-Artifacts",
                    Title = $"DLL injector registry artifact: {toolName}",
                    Risk = RiskLevel.High,
                    Location = $@"{hive}\{path}",
                    Reason = $"Registry key for '{toolName}' found. This is a known DLL injector tool. " +
                             "Its registry artifact confirms it was installed or used on this system, " +
                             "even if the executable has since been deleted.",
                    Detail = $"Registry: {hive}\\{path}",
                });
            }
            catch { }
        }
    }

    private static void CheckAppInitDlls(ScanContext ctx, CancellationToken ct)
    {
        var appInitPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        };

        foreach (var regPath in appInitPaths)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                var appInitDlls = (key.GetValue("AppInit_DLLs") as string ?? string.Empty).Trim();
                if (string.IsNullOrEmpty(appInitDlls)) continue;

                var loadEnabled = key.GetValue("LoadAppInit_DLLs") as int?;

                ctx.AddFinding(new Finding
                {
                    Module = "DLL-Injection-Artifacts",
                    Title = "AppInit_DLLs persistence value set",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{regPath}",
                    Reason = "AppInit_DLLs registry value is populated. This causes the listed DLLs to be " +
                             "automatically injected into every process that loads user32.dll. " +
                             "This is a classic DLL injection persistence technique used by cheat loaders.",
                    Detail = $"AppInit_DLLs: {appInitDlls} | LoadAppInit_DLLs: {loadEnabled} | Key: {regPath}",
                });
            }
            catch { }
        }
    }

    private static void CheckImageFileExecutionOptions(ScanContext ctx, CancellationToken ct)
    {
        const string ifeoPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

        try
        {
            using var ifeoKey = Registry.LocalMachine.OpenSubKey(ifeoPath, writable: false);
            if (ifeoKey is null) return;

            foreach (var subKeyName in ifeoKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                bool isGameExe = GameExecutableNames.Any(g =>
                    subKeyName.Equals(g, StringComparison.OrdinalIgnoreCase));
                if (!isGameExe) continue;

                try
                {
                    using var gameKey = ifeoKey.OpenSubKey(subKeyName, writable: false);
                    if (gameKey is null) continue;

                    var debuggerValue = (gameKey.GetValue("Debugger") as string ?? string.Empty).Trim();
                    if (string.IsNullOrEmpty(debuggerValue)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "DLL-Injection-Artifacts",
                        Title = $"IFEO Debugger hijack on game executable: {subKeyName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{ifeoPath}\{subKeyName}",
                        FileName = subKeyName,
                        Reason = $"Image File Execution Options (IFEO) for game '{subKeyName}' has a Debugger value set " +
                                 $"to '{debuggerValue}'. This causes an alternate executable to be launched instead of " +
                                 "the game, which is used by cheat loaders to intercept the game launch and inject DLLs " +
                                 "before the game's anti-cheat initializes.",
                        Detail = $"Debugger: {debuggerValue} | Target: {subKeyName}",
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static async Task ScanTempForShellcodeAsync(ScanContext ctx, CancellationToken ct)
    {
        var tempDir = Path.GetTempPath();
        if (!Directory.Exists(tempDir)) return;

        IEnumerable<string> tempFiles;
        try
        {
            tempFiles = Directory.EnumerateFiles(tempDir, "*", SearchOption.TopDirectoryOnly);
        }
        catch { return; }

        var peSignature = new byte[] { 0x4D, 0x5A };
        var freshlyStagedCutoff = DateTime.Now.AddDays(-7);

        foreach (var filePath in tempFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(filePath);
            var ext = Path.GetExtension(fileName).ToLowerInvariant();

            if (ext is ".bin" or ".dat" or ".raw")
            {
                long fileSize;
                try { fileSize = new FileInfo(filePath).Length; }
                catch { continue; }

                if (fileSize < 4 * 1024 || fileSize > 10 * 1024 * 1024) continue;

                try
                {
                    var header = new byte[64];
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    int bytesRead = await fs.ReadAsync(header, 0, 64, ct).ConfigureAwait(false);
                    if (bytesRead < 2) continue;

                    if (header[0] == peSignature[0] && header[1] == peSignature[1])
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "DLL-Injection-Artifacts",
                            Title = $"PE binary disguised as data file in Temp: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"File '{fileName}' in %Temp% has a PE header (MZ magic bytes 0x4D 0x5A) " +
                                     $"despite having a '{ext}' extension. Injectors stage PE payloads as data files " +
                                     "to evade file-type-based detection before mapping them into game processes.",
                            Detail = $"Size: {fileSize / 1024} KB | PE header detected | Path: {filePath}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
                continue;
            }

            if (ext == ".dll")
            {
                DateTime created;
                try { created = File.GetCreationTime(filePath); }
                catch { continue; }

                if (created >= freshlyStagedCutoff)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "DLL-Injection-Artifacts",
                        Title = $"Freshly staged DLL in Temp: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"DLL file '{fileName}' in %Temp% was created within the last 7 days. " +
                                 "Cheat DLLs are commonly staged in the Temp directory immediately before injection " +
                                 "into a game process and may be deleted afterwards.",
                        Detail = $"Created: {created:yyyy-MM-dd HH:mm:ss} | Path: {filePath}",
                    });
                }
            }
        }
    }

    private static void ScanPrefetchArtifacts(ScanContext ctx, CancellationToken ct)
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        IEnumerable<string> pfFiles;
        try
        {
            pfFiles = Directory.EnumerateFiles(prefetchDir, "*.pf");
        }
        catch { return; }

        foreach (var pfPath in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(pfPath).ToUpperInvariant();

            foreach (var pattern in InjectorPrefetchPatterns)
            {
                if (pfName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    DateTime lastRun;
                    try { lastRun = File.GetLastWriteTime(pfPath); }
                    catch { lastRun = DateTime.MinValue; }

                    ctx.AddFinding(new Finding
                    {
                        Module = "DLL-Injection-Artifacts",
                        Title = $"Injector tool prefetch artifact: {pfName}",
                        Risk = RiskLevel.High,
                        Location = pfPath,
                        FileName = Path.GetFileName(pfPath),
                        Reason = $"Prefetch file '{pfName}.pf' indicates that a DLL injection tool matching " +
                                 $"pattern '{pattern}' was previously executed on this system. " +
                                 "Windows Prefetch records persist even after the injector executable is deleted.",
                        Detail = lastRun != DateTime.MinValue
                            ? $"Last executed (approx.): {lastRun:yyyy-MM-dd HH:mm:ss}"
                            : null,
                    });
                    break;
                }
            }
        }
    }

    private static void CheckRunningProcessesForInjection(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementProcesses();

            string? exePath = null;
            try { exePath = proc.MainModule?.FileName; } catch { }

            if (string.IsNullOrEmpty(exePath)) continue;

            var pathLower = exePath.ToLowerInvariant();

            bool isSuspiciousPath = SuspiciousProcessPathFragments.Any(f =>
                pathLower.Contains(f, StringComparison.OrdinalIgnoreCase));

            if (!isSuspiciousPath) continue;

            string? cmdLine = null;
            try { cmdLine = proc.StartInfo.Arguments; } catch { }

            bool hasSuspiciousArgs = cmdLine is not null && SuspiciousProcessArgs.Any(a =>
                cmdLine.Contains(a, StringComparison.OrdinalIgnoreCase));

            if (hasSuspiciousArgs)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "DLL-Injection-Artifacts",
                    Title = $"Process with injection args running from Temp/AppData: {proc.ProcessName}",
                    Risk = RiskLevel.High,
                    Location = exePath,
                    FileName = proc.ProcessName + ".exe",
                    Reason = $"Process '{proc.ProcessName}' (PID {proc.Id}) is running from a user-writable " +
                             "temporary directory and has command-line arguments associated with DLL injection " +
                             $"('{cmdLine}'). This pattern matches known injector staging behavior.",
                    Detail = $"PID: {proc.Id} | Path: {exePath} | Args: {cmdLine}",
                });
                continue;
            }

            ctx.AddFinding(new Finding
            {
                Module = "DLL-Injection-Artifacts",
                Title = $"Process running from Temp/AppData staging path: {proc.ProcessName}",
                Risk = RiskLevel.Medium,
                Location = exePath,
                FileName = proc.ProcessName + ".exe",
                Reason = $"Process '{proc.ProcessName}' (PID {proc.Id}) is running from a user-writable " +
                         "temporary or AppData directory. Injector tools commonly stage in Temp before executing.",
                Detail = $"PID: {proc.Id} | Path: {exePath}",
            });
        }
    }

    private static async Task ScanWerArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var werDirs = new[]
        {
            Path.Combine(localAppData, "Microsoft", "Windows", "WER", "ReportArchive"),
            Path.Combine(localAppData, "Microsoft", "Windows", "WER", "ReportQueue"),
        };

        foreach (var werDir in werDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(werDir)) continue;

            IEnumerable<string> reportFiles;
            try
            {
                reportFiles = Directory.EnumerateFiles(werDir, "*.wer", SearchOption.AllDirectories);
            }
            catch { continue; }

            foreach (var filePath in reportFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    using var sr = new StreamReader(filePath);
                    string content = await sr.ReadToEndAsync().ConfigureAwait(false);

                    foreach (var keyword in WerCheatKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            var fileName = Path.GetFileName(filePath);
                            ctx.AddFinding(new Finding
                            {
                                Module = "DLL-Injection-Artifacts",
                                Title = $"WER crash report references cheat/injector: {fileName}",
                                Risk = RiskLevel.Medium,
                                Location = filePath,
                                FileName = fileName,
                                Reason = $"Windows Error Reporting crash report '{fileName}' contains keyword '{keyword}', " +
                                         "suggesting a cheat or injector tool crashed on this system. " +
                                         "WER reports persist after the crashing process is deleted.",
                                Detail = $"Keyword: {keyword} | Report: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
    }

    private static void CheckAppCompatAndRecentDocs(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        try
        {
            using var storeKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
                writable: false);

            if (storeKey is not null)
            {
                foreach (var valueName in storeKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    foreach (var known in KnownInjectorExeNames)
                    {
                        if (valueName.Contains(known, StringComparison.OrdinalIgnoreCase)
                            || valueName.Contains(Path.GetFileNameWithoutExtension(known),
                                StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "DLL-Injection-Artifacts",
                                Title = $"AppCompat record for injector: {known}",
                                Risk = RiskLevel.High,
                                Location = @"HKCU\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
                                Reason = $"AppCompatFlags Compatibility Assistant Store contains an entry for '{valueName}', " +
                                         $"which matches known injector '{known}'. This registry key records programs that " +
                                         "Windows has seen run, and persists after the program is deleted.",
                                Detail = $"Entry: {valueName}",
                            });
                            break;
                        }
                    }
                }
            }
        }
        catch { }

        if (ct.IsCancellationRequested) return;

        try
        {
            using var recentDocsKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.dll",
                writable: false);

            if (recentDocsKey is null) return;
            ctx.IncrementRegistryKeys();

            ctx.AddFinding(new Finding
            {
                Module = "DLL-Injection-Artifacts",
                Title = "RecentDocs contains DLL file access",
                Risk = RiskLevel.Medium,
                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.dll",
                Reason = "The Windows RecentDocs registry key shows that a DLL file was recently opened " +
                         "by the user via Explorer. Manually opening DLL files is a common step in " +
                         "preparing a DLL for injection into a game process.",
                Detail = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.dll",
            });
        }
        catch { }
    }
}
