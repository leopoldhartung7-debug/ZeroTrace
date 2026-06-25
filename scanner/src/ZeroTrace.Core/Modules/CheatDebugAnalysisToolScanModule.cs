using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CheatDebugAnalysisToolScanModule : IScanModule
{
    public string Name => "Cheat-Debug-Analysis";
    public double Weight => 0.55;
    public int ParallelGroup => 4;

    private static readonly string[] IdaProcessNames =
    {
        "ida", "ida64", "ida_server",
    };

    private static readonly string[] X64DbgProcessNames =
    {
        "x64dbg", "x32dbg",
    };

    private static readonly string[] OllyDbgProcessNames =
    {
        "ollydbg",
    };

    private static readonly string[] ReClassProcessNames =
    {
        "reclass", "reclass64", "reclass.net", "reclass_net",
    };

    private static readonly string[] ScyllaExeNames = new[]
    {
        "scylla.exe", "scylla_x64.exe",
    };

    private static readonly string[] ScyllaDllNames = new[]
    {
        "scyllahide.dll", "ScyllaHide.dll",
    };

    private static readonly string[] ProcessHackerProcessNames =
    {
        "processhacker", "systeminformer",
    };

    private static readonly string[] KnownGameProcessNames =
    {
        "gta5", "fivem", "cs2", "csgo", "rustclient", "rust",
        "r5apex", "valorant-win64-shipping", "fortnite",
        "cod", "modernwarfare", "warzone",
    };

    private static readonly string[] AcResearchPdfNames =
    {
        "eac_internals", "battleye_analysis", "vanguard_internals",
        "anti_cheat_bypass", "kernel_bypass", "driver_bypass",
    };

    private static readonly string[] AcResearchMdTitles =
    {
        "# EAC bypass", "# BattlEye bypass", "# Vanguard bypass", "## Anti-Cheat",
    };

    private static readonly string[] GameBinaryIdbNames =
    {
        "client.dll", "engine.dll", "FiveM.exe", "GTA5.exe", "cs2.exe",
        "csgo.exe", "r5apex.exe", "VALORANT-Win64-Shipping.exe",
    };

    private static readonly string[] PrefetchPatterns =
    {
        "IDA", "X64DBG", "GHIDRA", "OLLYDBG", "RECLASS", "SCYLLA", "PROCESSHACKER",
    };

    private static readonly string[] CheatSourceCodePatterns =
    {
        "ReadProcessMemory", "WriteProcessMemory", "GetEntityByIndex", "GetPlayerList",
        "GetBonePosition", "DrawESP", "DrawBox", "DrawLine",
        "aimbot", "triggerbot", "esp", "wallhack", "godmode",
    };

    private static readonly string[] CheatDirNames =
    {
        "cheat", "hack", "aimbot", "esp", "bypass", "inject", "trainer",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ctx.Report(0.0, Name, "Scanning for installed reverse engineering tools...");
            ScanReverseEngineeringToolInstalls(ctx, ct);

            ctx.Report(0.2, Name, "Scanning for memory analysis tools...");
            ScanMemoryAnalysisTools(ctx, ct);

            ctx.Report(0.38, Name, "Scanning for cheat development source code artifacts...");
            ScanCheatSourceCodeArtifacts(ctx, ct);

            ctx.Report(0.55, Name, "Scanning for anti-cheat research artifacts...");
            ScanAntiCheatResearchArtifacts(ctx, ct);

            ctx.Report(0.70, Name, "Scanning for IDA disassembly database files...");
            ScanDisassemblyOutputArtifacts(ctx, ct);

            ctx.Report(0.82, Name, "Scanning running processes for analysis tools...");
            ScanRunningAnalysisProcesses(ctx, ct);

            ctx.Report(0.92, Name, "Scanning Prefetch artifacts for analysis tools...");
            ScanPrefetchArtifacts(ctx, ct);

            ctx.Report(1.0, Name, "Cheat debug/analysis tool scan complete.");
        }, ct);
    }

    private static void ScanReverseEngineeringToolInstalls(ScanContext ctx, CancellationToken ct)
    {
        CheckIdaProInstall(ctx, ct);
        CheckX64DbgInstall(ctx, ct);
        CheckGhidraInstall(ctx, ct);
        CheckOllyDbgInstall(ctx, ct);
        CheckReClassInstall(ctx, ct);
    }

    private static void CheckIdaProInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var idaDirs = new[]
        {
            Path.Combine(programFiles, "IDA Pro"),
            Path.Combine(programFiles, "IDA Pro 8"),
            Path.Combine(programFiles, "IDA Pro 7"),
            Path.Combine(programFilesX86, "IDA"),
            Path.Combine(appData, "Hex-Rays"),
        };

        foreach (var dir in idaDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Debug-Analysis",
                Title = $"IDA Pro reverse engineering tool directory: {dir}",
                Risk = RiskLevel.High,
                Location = dir,
                FileName = Path.GetFileName(dir),
                Reason = $"IDA Pro installation or configuration directory found at '{dir}'. " +
                         "IDA Pro is a professional disassembler and debugger widely used to reverse engineer game binaries, " +
                         "map memory structures, and develop cheats or anti-cheat bypasses.",
                Detail = $"Directory={dir}",
            });
        }

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Hex-Rays", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Debug-Analysis",
                    Title = "IDA Pro registry key (Hex-Rays) detected",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\Hex-Rays",
                    Reason = "Registry key for IDA Pro (Hex-Rays) found in the current user hive. " +
                             "This confirms IDA Pro was installed or run on this system.",
                    Detail = "Registry=HKCU\\Software\\Hex-Rays",
                });
            }
        }
        catch { }
    }

    private static void CheckX64DbgInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var x64Dirs = new[]
        {
            @"C:\x64dbg",
            Path.Combine(appData, "x64dbg"),
            Path.Combine(localAppData, "x64dbg"),
        };

        foreach (var dir in x64Dirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Debug-Analysis",
                Title = $"x64dbg/x32dbg debugger directory: {dir}",
                Risk = RiskLevel.High,
                Location = dir,
                FileName = Path.GetFileName(dir),
                Reason = $"x64dbg debugger directory found at '{dir}'. " +
                         "x64dbg is a popular userland debugger used to attach to game processes, inspect memory, " +
                         "bypass anti-cheat integrity checks, and find offsets for cheat development.",
                Detail = $"Directory={dir}",
            });
        }

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\x64dbg", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Debug-Analysis",
                    Title = "x64dbg registry key detected",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\x64dbg",
                    Reason = "Registry key for x64dbg debugger found. x64dbg is commonly used by cheat developers to reverse engineer games and bypass anti-cheat.",
                    Detail = "Registry=HKCU\\Software\\x64dbg",
                });
            }
        }
        catch { }
    }

    private static void CheckGhidraInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var searchRoots = new[] { @"C:\", userProfile, localAppData, appData };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var dir in Directory.GetDirectories(root, "ghidra*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Debug-Analysis",
                        Title = $"Ghidra reverse engineering tool: {Path.GetFileName(dir)}",
                        Risk = RiskLevel.High,
                        Location = dir,
                        FileName = Path.GetFileName(dir),
                        Reason = $"Ghidra NSA reverse engineering framework installation found at '{dir}'. " +
                                 "Ghidra is used to disassemble game binaries, analyze anti-cheat code, and develop bypass techniques.",
                        Detail = $"Directory={dir}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void CheckOllyDbgInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        foreach (var baseDir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "ollydbg.exe", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Debug-Analysis",
                        Title = $"OllyDbg debugger executable: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"OllyDbg debugger found at '{file}'. " +
                                 "OllyDbg is a 32-bit debugger frequently used to analyze game code, patch anti-cheat checks, and develop injection cheats.",
                        Detail = $"Path={file}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void CheckReClassInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var reClassDir = Path.Combine(appData, "ReClass.NET");

        if (Directory.Exists(reClassDir))
        {
            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Debug-Analysis",
                Title = "ReClass.NET game memory structure mapper directory",
                Risk = RiskLevel.High,
                Location = reClassDir,
                FileName = "ReClass.NET",
                Reason = $"ReClass.NET AppData directory found at '{reClassDir}'. " +
                         "ReClass.NET is specifically designed to map game process memory into C++ structures, " +
                         "a prerequisite step for building external aimbots, ESP, and memory-read cheats.",
                Detail = $"Directory={reClassDir}",
            });
        }

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\ReClass.NET", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Debug-Analysis",
                    Title = "ReClass.NET registry key detected",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\ReClass.NET",
                    Reason = "Registry key for ReClass.NET found. ReClass.NET is used exclusively for game memory structure analysis to build cheats.",
                    Detail = "Registry=HKCU\\Software\\ReClass.NET",
                });
            }
        }
        catch { }

        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        };

        var reClassExeNames = new[] { "reclass.exe", "reclass64.exe", "reclass.net.exe", "reclass_net.exe" };

        foreach (var baseDir in searchBases)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);

                    if (reClassExeNames.Any(n => n.Equals(fname, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"ReClass.NET executable on disk: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"ReClass.NET executable '{fname}' found on disk. " +
                                     "This tool reads live game process memory to reconstruct class and entity structures, enabling development of aimbot and ESP cheats.",
                            Detail = $"Path={file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void ScanMemoryAnalysisTools(ScanContext ctx, CancellationToken ct)
    {
        CheckProcessHacker(ctx, ct);
        CheckScyllaHide(ctx, ct);
        CheckHexEditorPatchFiles(ctx, ct);
    }

    private static void CheckProcessHacker(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var phDirs = new[]
        {
            Path.Combine(programFiles, "Process Hacker 2"),
            Path.Combine(programFiles, "Process Hacker"),
            Path.Combine(programFiles, "System Informer"),
            Path.Combine(programFilesX86, "Process Hacker 2"),
            Path.Combine(programFilesX86, "Process Hacker"),
        };

        foreach (var dir in phDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Debug-Analysis",
                Title = $"Process Hacker / System Informer installation: {Path.GetFileName(dir)}",
                Risk = RiskLevel.Low,
                Location = dir,
                FileName = Path.GetFileName(dir),
                Reason = $"Process Hacker or System Informer installation found at '{dir}'. " +
                         "Legitimate system administration tool, but also used by cheat developers to inspect game process memory, " +
                         "find handle ownership, and enumerate loaded modules in running games.",
                Detail = $"Directory={dir}",
            });
        }

        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Process Hacker 2", writable: false);
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Debug-Analysis",
                    Title = "Process Hacker registry key detected",
                    Risk = RiskLevel.Low,
                    Location = @"HKCU\Software\Process Hacker 2",
                    Reason = "Process Hacker registry key found. Informational; flagged as Low risk in isolation, but elevates context when found alongside cheat artifacts.",
                    Detail = "Registry=HKCU\\Software\\Process Hacker 2",
                });
            }
        }
        catch { }
    }

    private static void CheckScyllaHide(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var scyllaDir = Path.Combine(appData, "ScyllaHide");
        if (Directory.Exists(scyllaDir))
        {
            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Debug-Analysis",
                Title = "ScyllaHide anti-detection plugin directory",
                Risk = RiskLevel.High,
                Location = scyllaDir,
                FileName = "ScyllaHide",
                Reason = $"ScyllaHide AppData directory found at '{scyllaDir}'. " +
                         "ScyllaHide is an anti-anti-debug plugin for x64dbg and OllyDbg that hides the debugger from anti-cheat " +
                         "and game integrity checks, enabling covert reverse engineering of protected game binaries.",
                Detail = $"Directory={scyllaDir}",
            });
        }

        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var baseDir in searchBases)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "scylla*.exe", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Debug-Analysis",
                        Title = $"Scylla IAT reconstruction tool: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Scylla (IAT reconstruction tool) found at '{file}'. " +
                                 "Scylla rebuilds import address tables for dumped executables, used to reconstruct obfuscated game binaries for cheat analysis and bypass development.",
                        Detail = $"Path={file}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "scyllahide.dll", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Debug-Analysis",
                        Title = $"ScyllaHide DLL found: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"ScyllaHide plugin DLL found at '{file}'. " +
                                 "This plugin bypasses debugger detection in anti-cheat systems, allowing hidden debugger attachment to game processes.",
                        Detail = $"Path={file}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void CheckHexEditorPatchFiles(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var ext in new[] { "*.hex", "*.patch" })
            {
                try
                {
                    foreach (var file in Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"Binary patch file on disk: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Binary hex or patch file '{Path.GetFileName(file)}' found on desktop/downloads. " +
                                     "Such files are used to distribute game binary patches that disable anti-cheat checks or enable developer/cheat modes.",
                            Detail = $"Path={file}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }

    private static void ScanCheatSourceCodeArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var baseDir in searchBases)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(baseDir)) continue;

            ScanCppSourceFiles(ctx, ct, baseDir);
            ScanVisualStudioProjectsInCheatDirs(ctx, ct, baseDir);
            ScanGitRemoteConfigFiles(ctx, ct, baseDir);
        }

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        ScanGitRemoteConfigFiles(ctx, ct, appData);
        ScanGitRemoteConfigFiles(ctx, ct, docs);
    }

    private static void ScanCppSourceFiles(ScanContext ctx, CancellationToken ct, string baseDir)
    {
        if (!Directory.Exists(baseDir)) return;

        foreach (var ext in new[] { "*.cpp", "*.h" })
        {
            try
            {
                foreach (var file in Directory.GetFiles(baseDir, ext, SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();

                        var hits = CheatSourceCodePatterns
                            .Where(p => content.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0)
                            .ToList();

                        if (hits.Count >= 3)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Cheat-Debug-Analysis",
                                Title = $"Cheat source code detected: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"C/C++ source file '{Path.GetFileName(file)}' contains {hits.Count} cheat development patterns: " +
                                         $"{string.Join(", ", hits)}. The combination of process memory access APIs with game entity and drawing function names " +
                                         "is a strong indicator of cheat source code (external aimbot, ESP, or memory-read cheat).",
                                Detail = $"Patterns={string.Join("|", hits)} Path={file}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanVisualStudioProjectsInCheatDirs(ScanContext ctx, CancellationToken ct, string baseDir)
    {
        if (!Directory.Exists(baseDir)) return;

        try
        {
            foreach (var dir in Directory.GetDirectories(baseDir, "*", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;

                var dirName = Path.GetFileName(dir);
                bool isCheatDir = CheatDirNames.Any(cd =>
                    dirName.IndexOf(cd, StringComparison.OrdinalIgnoreCase) >= 0);

                if (!isCheatDir) continue;

                foreach (var ext in new[] { "*.sln", "*.vcxproj" })
                {
                    try
                    {
                        foreach (var projFile in Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly))
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = "Cheat-Debug-Analysis",
                                Title = $"Visual Studio cheat project: {Path.GetFileName(projFile)}",
                                Risk = RiskLevel.High,
                                Location = projFile,
                                FileName = Path.GetFileName(projFile),
                                Reason = $"Visual Studio project file '{Path.GetFileName(projFile)}' found in directory '{dirName}' with a cheat-related name. " +
                                         "This indicates active cheat development — a project structure for building a cheat DLL or executable.",
                                Detail = $"Directory={dirName} Path={projFile}",
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }

                try
                {
                    var cmakeFile = Path.Combine(dir, "CMakeLists.txt");
                    if (File.Exists(cmakeFile))
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            string cmakeContent;
                            using var fs = new FileStream(cmakeFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            cmakeContent = sr.ReadToEnd();

                            var projectMatch = Regex.Match(cmakeContent, @"project\s*\((\w+)", RegexOptions.IgnoreCase);
                            if (projectMatch.Success)
                            {
                                var projectName = projectMatch.Groups[1].Value;
                                if (CheatDirNames.Any(cd => projectName.IndexOf(cd, StringComparison.OrdinalIgnoreCase) >= 0))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Cheat-Debug-Analysis",
                                        Title = $"CMake cheat project: {projectName}",
                                        Risk = RiskLevel.High,
                                        Location = cmakeFile,
                                        FileName = "CMakeLists.txt",
                                        Reason = $"CMakeLists.txt with project name '{projectName}' found in cheat-named directory '{dirName}'. " +
                                                 "Indicates a CMake-based cheat build system.",
                                        Detail = $"ProjectName={projectName} Path={cmakeFile}",
                                    });
                                }
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private static void ScanGitRemoteConfigFiles(ScanContext ctx, CancellationToken ct, string baseDir)
    {
        if (!Directory.Exists(baseDir)) return;

        var cheatRemoteKeywords = new[]
        {
            "cheat", "hack", "aimbot", "bypass", "inject",
        };

        try
        {
            foreach (var gitConfig in Directory.GetFiles(baseDir, "config", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;

                var parent = Path.GetDirectoryName(gitConfig) ?? "";
                if (!parent.EndsWith(".git", StringComparison.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();

                try
                {
                    string content;
                    using var fs = new FileStream(gitConfig, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();

                    bool hasRemoteSection = content.IndexOf("[remote", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (!hasRemoteSection) continue;

                    var urlMatch = Regex.Match(content, @"url\s*=\s*(.+)", RegexOptions.IgnoreCase);
                    if (!urlMatch.Success) continue;

                    var url = urlMatch.Groups[1].Value.Trim();
                    var matchedKeywords = cheatRemoteKeywords
                        .Where(k => url.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0)
                        .ToList();

                    if (matchedKeywords.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"Git repository with cheat remote URL: {Path.GetFileName(Path.GetDirectoryName(parent) ?? parent)}",
                            Risk = RiskLevel.High,
                            Location = gitConfig,
                            FileName = "config",
                            Reason = $"Git repository config at '{gitConfig}' has remote.origin.url containing cheat-related keywords: " +
                                     $"{string.Join(", ", matchedKeywords)}. URL: '{url}'. " +
                                     "This indicates a code repository for cheat development or distribution.",
                            Detail = $"RemoteUrl={url} Keywords={string.Join("|", matchedKeywords)}",
                        });
                    }
                }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private static void ScanAntiCheatResearchArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir, "*.pdf", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fname = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();

                    if (AcResearchPdfNames.Any(n => fname.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"Anti-cheat research/bypass PDF: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"PDF file '{Path.GetFileName(file)}' with a name matching anti-cheat research patterns found on desktop/downloads. " +
                                     "Documents covering EAC/BattlEye/Vanguard internals are typically used for bypass development.",
                            Detail = $"Path={file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var file in Directory.GetFiles(dir, "*.md", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();

                        var matchedTitle = AcResearchMdTitles.FirstOrDefault(t =>
                            content.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                        if (matchedTitle is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Cheat-Debug-Analysis",
                                Title = $"Anti-cheat bypass notes/documentation: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Markdown file '{Path.GetFileName(file)}' contains a heading matching anti-cheat bypass research: '{matchedTitle}'. " +
                                         "This indicates written documentation or notes about anti-cheat internals for bypass development.",
                                Detail = $"Title={matchedTitle} Path={file}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }

            foreach (var ext in new[] { "*.pcapng", "*.pcap" })
            {
                try
                {
                    foreach (var file in Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fname = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                        bool mentionsGame = KnownGameProcessNames.Any(g =>
                            fname.IndexOf(g, StringComparison.OrdinalIgnoreCase) >= 0) ||
                            fname.IndexOf("eac", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            fname.IndexOf("battleye", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            fname.IndexOf("anticheat", StringComparison.OrdinalIgnoreCase) >= 0;

                        if (!mentionsGame) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"Game/AC protocol capture file: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Wireshark packet capture '{Path.GetFileName(file)}' with a game or anti-cheat related name found on desktop/downloads. " +
                                     "Protocol captures of game or anti-cheat communication are used to reverse engineer AC heartbeat/integrity check protocols.",
                            Detail = $"Path={file}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }

    private static void ScanDisassemblyOutputArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var baseDir in searchBases)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.asm", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();

                        var gameBinaryHit = GameBinaryIdbNames.FirstOrDefault(g =>
                            content.IndexOf(g, StringComparison.OrdinalIgnoreCase) >= 0);

                        if (gameBinaryHit is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Cheat-Debug-Analysis",
                                Title = $"Game disassembly output ASM file: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Assembly output file '{Path.GetFileName(file)}' contains a reference to game binary '{gameBinaryHit}' in comments. " +
                                         "Disassembly output files indicate that a game binary was analyzed with a disassembler such as IDA Pro or Ghidra, " +
                                         "which is a step in cheat or anti-cheat bypass development.",
                                Detail = $"GameBinary={gameBinaryHit} Path={file}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }

            foreach (var ext in new[] { "*.idb", "*.i64" })
            {
                try
                {
                    foreach (var file in Directory.GetFiles(baseDir, ext, SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fname = Path.GetFileName(file);

                        var gameBinaryHit = GameBinaryIdbNames.FirstOrDefault(g =>
                            fname.IndexOf(g, StringComparison.OrdinalIgnoreCase) >= 0);

                        if (gameBinaryHit is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Cheat-Debug-Analysis",
                                Title = $"IDA Pro disassembly database for game binary: {fname}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fname,
                                Reason = $"IDA Pro database file '{fname}' for game binary '{gameBinaryHit}' found. " +
                                         "IDA database files (.idb/.i64) store completed disassembly projects with named functions, " +
                                         "type definitions, and annotations. A game binary disassembly database is a primary artifact " +
                                         "of cheat or anti-cheat bypass development — it represents significant reverse engineering work.",
                                Detail = $"GameBinary={gameBinaryHit} Path={file}",
                            });
                        }
                        else
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Cheat-Debug-Analysis",
                                Title = $"IDA Pro disassembly database: {fname}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fname,
                                Reason = $"IDA Pro database file '{fname}' found. Disassembly databases indicate reverse engineering activity. " +
                                         "Review the target binary to determine if this relates to game or anti-cheat analysis.",
                                Detail = $"Path={file}",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }

    private static void ScanRunningAnalysisProcesses(ScanContext ctx, CancellationToken ct)
    {
        bool reClassRunning = false;
        bool gameRunning = false;
        var runningAnalysisTools = new List<string>();

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
                        gameRunning = true;

                    if (IdaProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        runningAnalysisTools.Add(proc.ProcessName);
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"IDA Pro running: {proc.ProcessName}",
                            Risk = RiskLevel.High,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"IDA Pro disassembler process '{proc.ProcessName}' is currently running. " +
                                     "IDA running during a scan indicates active reverse engineering activity.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                    else if (X64DbgProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        runningAnalysisTools.Add(proc.ProcessName);
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"x64dbg/x32dbg debugger running: {proc.ProcessName}",
                            Risk = RiskLevel.High,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"x64dbg debugger '{proc.ProcessName}' is currently running. " +
                                     "Debuggers running alongside games are used to inspect and patch game memory in real time.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                    else if (OllyDbgProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        runningAnalysisTools.Add(proc.ProcessName);
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"OllyDbg debugger running: {proc.ProcessName}",
                            Risk = RiskLevel.High,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"OllyDbg debugger is currently running (PID {proc.Id}). " +
                                     "OllyDbg is used for game binary debugging and cheat injection.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                    else if (ReClassProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        reClassRunning = true;
                        runningAnalysisTools.Add(proc.ProcessName);
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"ReClass.NET running: {proc.ProcessName}",
                            Risk = RiskLevel.High,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"ReClass.NET process '{proc.ProcessName}' is currently running. " +
                                     "ReClass.NET reads game process memory to reconstruct entity and player data structures for cheat development.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                    else if (ProcessHackerProcessNames.Any(n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                    {
                        runningAnalysisTools.Add(proc.ProcessName);
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Debug-Analysis",
                            Title = $"Process Hacker / System Informer running: {proc.ProcessName}",
                            Risk = RiskLevel.Low,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = proc.ProcessName,
                            Reason = $"Process Hacker or System Informer '{proc.ProcessName}' is running. " +
                                     "Legitimate sysadmin tool; note if combined with game or cheat artifacts.",
                            Detail = $"PID={proc.Id} Name={proc.ProcessName}",
                        });
                    }
                    else if (procNameLower.Equals("java", StringComparison.OrdinalIgnoreCase))
                    {
                        string? cmdLine = null;
                        try { cmdLine = proc.MainModule?.FileName; } catch { }
                        if (cmdLine is not null && cmdLine.IndexOf("ghidra", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            runningAnalysisTools.Add("ghidra(java)");
                            ctx.AddFinding(new Finding
                            {
                                Module = "Cheat-Debug-Analysis",
                                Title = "Ghidra running (via Java process)",
                                Risk = RiskLevel.High,
                                Location = cmdLine,
                                FileName = "java.exe",
                                Reason = "Java process with Ghidra in the command line is currently running. Ghidra is being actively used for reverse engineering.",
                                Detail = $"PID={proc.Id} CommandLine={cmdLine}",
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }

        if (reClassRunning && gameRunning)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Debug-Analysis",
                Title = "ReClass.NET running simultaneously with a game process",
                Risk = RiskLevel.Critical,
                Location = "Process snapshot",
                Reason = "ReClass.NET and a game process are running at the same time. " +
                         "ReClass.NET is designed to read game process memory structures; running it while a game is active " +
                         "is the active use of a memory mapping tool for cheat development or real-time memory inspection.",
                Detail = $"AnalysisTools={string.Join("|", runningAnalysisTools)} GameRunning=true",
            });
        }
    }

    private static void ScanPrefetchArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var file in Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fname = Path.GetFileName(file).ToUpperInvariant();

                var matchedPattern = PrefetchPatterns.FirstOrDefault(p =>
                    fname.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                if (matchedPattern is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Debug-Analysis",
                    Title = $"Analysis/debugger tool Prefetch artifact: {Path.GetFileName(file)}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = $"Windows Prefetch file '{Path.GetFileName(file)}' indicates that a reverse engineering or debugging tool " +
                             $"matching pattern '{matchedPattern}' was previously executed on this system. " +
                             "Prefetch records persist after deletion, providing forensic evidence of past analysis tool usage.",
                    Detail = $"Pattern={matchedPattern} Path={file}",
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }
}
