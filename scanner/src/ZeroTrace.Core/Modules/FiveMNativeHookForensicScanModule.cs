using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class FiveMNativeHookForensicScanModule : IScanModule
{
    public string Name => "FiveM Native Hook Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] NativeHookDLLNames = { "gta5_hook.dll", "natives_hook.dll", "citgame_hook.dll", "fivem_hook.dll", "citizen_hook.dll", "scriptHookV.dll", "asi_loader.dll", "NativeTrainer.dll" };
    private static readonly string[] DXHijackDLLNames = { "dinput8.dll", "dsound.dll", "winmm.dll", "d3d11.dll", "dxgi.dll", "d3d12.dll", "d3d9.dll" };
    private static readonly string[] PremiumMenuConfigFiles = { "2take1_config.json", "stand_config.json", "yimmenu_config.json", "eulen_config.json", "redengine_config.json", "skript_config.json", "brainobrain_config.json" };
    private static readonly string[] PremiumMenuRegistryKeys = { @"Software\2Take1", @"Software\Stand", @"Software\YimMenu", @"Software\Eulen", @"Software\RedEngine", @"Software\Skript", @"Software\BrainOBrain" };
    private static readonly string[] HookingLibraryNames = { "MinHook.dll", "MinHook64.dll", "detours.dll", "minhook_x64.dll", "kiero.lib", "kiero.dll" };
    private static readonly string[] InternalCheatSourceHeaders = { "invoker.hpp", "Invoker.hpp", "NativeInvoker.hpp", "call_native.hpp", "natives.hpp", "crossmap.hpp", "joaat.hpp" };
    private static readonly string[] ProcessMemoryAPIStrings = { "ReadProcessMemory", "WriteProcessMemory", "OpenProcess", "VirtualProtectEx", "CreateRemoteThread", "VirtualAllocEx", "NtCreateThreadEx" };
    private static readonly string[] GameTargetProcessNames = { "GTA5.exe", "FiveM.exe", "RAGE Multiplayer.exe", "altv.exe", "RageMP.exe" };

    private static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Downloads => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    private static string Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static string Temp => Path.GetTempPath();
    private static string FiveMAppData => Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app");
    private static string FiveMLocalAppData => Path.Combine(LocalAppData, "FiveM", "FiveM.app");

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckNativeHookDLLArtifacts(ctx, ct),
            CheckASILoaderArtifacts(ctx, ct),
            CheckScriptHookVArtifacts(ctx, ct),
            CheckNativeTrainerConfigArtifacts(ctx, ct),
            CheckNativeDBDumpArtifacts(ctx, ct),
            CheckInternalCheatSourceArtifacts(ctx, ct),
            CheckHookingLibraryArtifacts(ctx, ct),
            CheckDirectXHookArtifacts(ctx, ct),
            CheckMemoryPatcherArtifacts(ctx, ct),
            CheckFiveMInternalMenuConfig(ctx, ct),
            CheckLuaInjectorArtifacts(ctx, ct),
            CheckOffsetScannerArtifacts(ctx, ct),
            CheckAntiCheatKillerScripts(ctx, ct),
            CheckFiveMCrashDumpAnalysis(ctx, ct),
            CheckNativeHookRegistryTraces(ctx, ct),
            CheckImportedFunctionSignatures(ctx, ct),
            CheckFiveMKernelDriverHookArtifacts(ctx, ct),
            CheckCheatTableFiles(ctx, ct)
        );
    }

    private Task CheckNativeHookDLLArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Desktop,
            Downloads,
            Temp,
            AppData,
            FiveMAppData,
            FiveMLocalAppData,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (NativeHookDLLNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        bool isFiveMSpecific = file.Contains("FiveM", StringComparison.OrdinalIgnoreCase) ||
                                               file.Contains("citizenfx", StringComparison.OrdinalIgnoreCase) ||
                                               file.Contains("citizen", StringComparison.OrdinalIgnoreCase);

                        bool isScriptHookV = fileName.Equals("scriptHookV.dll", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = isScriptHookV
                                ? "ScriptHookV DLL Found in FiveM-Adjacent Path"
                                : $"Native Hook DLL Artifact Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = isScriptHookV
                                ? "ScriptHookV.dll was found in a FiveM-adjacent directory. ScriptHookV is intentionally blocked by FiveM; its presence in these paths indicates a bypass attempt or residual injection artifact."
                                : $"A DLL matching a known FiveM native hook filename was found. These DLLs are used to intercept and manipulate GTA V native function calls within the FiveM process.",
                            Detail = $"Path: {file} | FiveM-adjacent: {isFiveMSpecific}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckASILoaderArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var fiveMRoots = new[]
        {
            FiveMAppData,
            FiveMLocalAppData,
            Path.Combine(LocalAppData, "FiveM"),
        };

        foreach (var root in fiveMRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (DXHijackDLLNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DLL Hijack Position Artifact in FiveM Directory: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"A DLL with the name '{fileName}' was found inside FiveM directories. Placing system DLLs such as dsound.dll, dinput8.dll, or winmm.dll in application directories is a classic DLL hijacking technique used to load ASI loaders and inject cheats into the FiveM process.",
                            Detail = $"Path: {file}"
                        });
                    }
                }

                foreach (var file in Directory.EnumerateFiles(root, "*.asi", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"ASI Plugin File Found in FiveM Directory: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = "An ASI plugin file was found inside FiveM directories. ASI files are DLLs loaded by ASI loaders; their presence in FiveM paths indicates an attempt to inject code into the FiveM process via the ASI plugin mechanism.",
                        Detail = $"Path: {file}"
                    });
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckScriptHookVArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scriptHookVDLLs = new[]
        {
            "ScriptHookV.dll",
            "ScriptHookVDotNet.dll",
            "ScriptHookVDotNet2.dll",
            "ScriptHookVDotNet3.dll",
        };

        var searchRoots = new[]
        {
            FiveMAppData,
            FiveMLocalAppData,
            Path.Combine(LocalAppData, "FiveM"),
            Desktop,
            Downloads,
        };

        var gtaVDirectoryHints = new[] { "Grand Theft Auto V", "GTAV", "GTA5", "GTA_V" };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (scriptHookVDLLs.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ScriptHookV Artifact Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "ScriptHookV or ScriptHookVDotNet was found in a FiveM-adjacent or user-accessible directory. FiveM intentionally blocks ScriptHookV; its presence here indicates an attempt to bypass this block or residual artifacts from a hook injection attempt.",
                            Detail = $"Path: {file}"
                        });
                    }
                }

                foreach (var file in Directory.EnumerateFiles(root, "scripthookv.log", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ScriptHookV Log File Found in FiveM Directory",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "A ScriptHookV log file was found in a FiveM-adjacent path. This log is only created when ScriptHookV successfully initializes, confirming that ScriptHookV was loaded alongside FiveM.",
                        Detail = $"Path: {file}"
                    });
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        foreach (var hint in gtaVDirectoryHints)
        {
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            var candidateDirs = new[]
            {
                Path.Combine(programFiles, hint),
                Path.Combine(programFilesX86, hint),
            };

            foreach (var dir in candidateDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var dll in scriptHookVDLLs)
                    {
                        var filePath = Path.Combine(dir, dll);
                        if (!File.Exists(filePath)) continue;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ScriptHookV DLL in GTA V Directory: {dll}",
                            Risk = RiskLevel.Critical,
                            Location = filePath,
                            FileName = dll,
                            Reason = "ScriptHookV was found in a GTA V installation directory. While ScriptHookV is legitimate in single-player story mode, its presence paired with FiveM installation indicates a FiveM bypass attempt.",
                            Detail = $"Path: {filePath}"
                        });
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }
    }, ct);

    private Task CheckNativeTrainerConfigArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var trainerLogFileNames = new[]
        {
            "menyoo.log", "trainerv.log", "ENT.log", "EnhancedNativeTrainer.log", "GTAV.log",
        };

        var trainerConfigFileNames = new[]
        {
            "trainerv.ini", "SimpList.xml",
        };

        var searchRoots = new[]
        {
            FiveMAppData,
            FiveMLocalAppData,
            Desktop,
            Downloads,
            Path.Combine(Documents, "Rockstar Games", "GTA V"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                var menyooFolder = Path.Combine(root, "menyooStuff");
                if (Directory.Exists(menyooFolder))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Menyoo Trainer Data Directory Found",
                        Risk = RiskLevel.High,
                        Location = menyooFolder,
                        FileName = "menyooStuff",
                        Reason = "The 'menyooStuff' folder created by the Menyoo trainer was found adjacent to FiveM directories. Menyoo is a GTA V native trainer whose artifacts here indicate usage alongside FiveM.",
                        Detail = $"Directory: {menyooFolder}"
                    });
                }

                foreach (var logName in trainerLogFileNames)
                {
                    var filePath = Path.Combine(root, logName);
                    if (!File.Exists(filePath)) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Native Trainer Log Artifact Found: {logName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = logName,
                        Reason = $"A log file created by a known GTA V native trainer was found. The file '{logName}' is only created when the trainer initializes successfully, confirming trainer usage in this environment.",
                        Detail = $"Path: {filePath}"
                    });
                }

                foreach (var configName in trainerConfigFileNames)
                {
                    var filePath = Path.Combine(root, configName);
                    if (!File.Exists(filePath)) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Native Trainer Config File Found: {configName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = configName,
                        Reason = $"A configuration file belonging to a known GTA V native trainer was found. The file '{configName}' is created by native trainers to persist hotkeys and settings.",
                        Detail = $"Path: {filePath}"
                    });
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        var documentsRoot = Path.Combine(Documents, "Rockstar Games", "GTA V");
        if (Directory.Exists(documentsRoot))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(documentsRoot, "*.log", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (trainerLogFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Trainer Log in GTA V Documents Folder: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known trainer log file was found in the GTA V documents directory, confirming native trainer usage in the game environment.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckNativeDBDumpArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var nativeDBFileNames = new[]
        {
            "natives.json", "nativedb.json", "Nativedb.json", "gta5_natives.json",
            "fivem_natives.json", "hazedumper.json", "csgo.cs", "patterns.hpp",
        };

        var searchRoots = new[]
        {
            Desktop,
            Downloads,
            Documents,
            AppData,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (nativeDBFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        bool isHazeDumper = fileName.Equals("hazedumper.json", StringComparison.OrdinalIgnoreCase) ||
                                            fileName.Equals("csgo.cs", StringComparison.OrdinalIgnoreCase) ||
                                            fileName.Equals("patterns.hpp", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = isHazeDumper
                                ? $"HazeDumper Offset Output Found: {fileName}"
                                : $"GTA V / FiveM Native Database Dump Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = isHazeDumper
                                ? "A HazeDumper output file was found. HazeDumper is an automated offset scanner used by cheat developers to extract memory offsets from GTA V / FiveM for use in native hooks."
                                : $"A native database dump file named '{fileName}' was found. These files contain the full GTA V native function database and are used as a foundation for building FiveM native hook cheats.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    if (fileName.StartsWith("natives_since_", StringComparison.OrdinalIgnoreCase) &&
                        fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Versioned Native Database Dump Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = "A versioned native database JSON file was found. These files contain GTA V native function signatures indexed by game version and are used to maintain compatibility in native hook cheats across updates.",
                            Detail = $"Path: {file}"
                        });
                    }
                }

                try
                {
                    foreach (var hazeDumperOutput in Directory.EnumerateFiles(root, "hazedumper*.json", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(hazeDumperOutput, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            if (content.Contains("GTA5.exe", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("FiveM.exe", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"HazeDumper GTA V Offset File Found: {Path.GetFileName(hazeDumperOutput)}",
                                    Risk = RiskLevel.High,
                                    Location = hazeDumperOutput,
                                    FileName = Path.GetFileName(hazeDumperOutput),
                                    Reason = "A HazeDumper JSON file referencing GTA5.exe or FiveM.exe was found. This file contains extracted memory offsets for GTA V / FiveM natives, a key artifact of cheat development toolchains.",
                                    Detail = $"Path: {hazeDumperOutput}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckInternalCheatSourceArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Desktop,
            Downloads,
            Documents,
        };

        var cheatProjectNameHints = new[]
        {
            "internal", "hook", "cheat", "inject", "native", "fivem_base", "gta_base", "menu", "trainer",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.hpp", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.h", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (InternalCheatSourceHeaders.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Internal Cheat Source Header Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"A source header file named '{fileName}' associated with GTA V / FiveM internal cheat development was found. These headers implement native function invokers used to call GTA V natives from injected DLLs.",
                            Detail = $"Path: {file}"
                        });
                    }
                    else
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            bool hasNativeInvoker = content.Contains("NativeInvoker", StringComparison.OrdinalIgnoreCase) ||
                                                    content.Contains("invoker", StringComparison.OrdinalIgnoreCase);
                            bool hasFiveMNative = content.Contains("invoke<", StringComparison.OrdinalIgnoreCase) ||
                                                  content.Contains("NATIVE::", StringComparison.OrdinalIgnoreCase);
                            if (hasNativeInvoker && hasFiveMNative)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "GTA V Native Invoker Pattern in Source Header",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = "A C++ header file contains GTA V native invoker patterns including NativeInvoker references and native call templates, indicating internal cheat source code.",
                                    Detail = $"Path: {file}"
                                });
                            }
                        }
                        catch { }
                    }
                }

                foreach (var file in Directory.EnumerateFiles(root, "*.sln", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.vcxproj", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    bool isCheatProject = cheatProjectNameHints.Any(hint =>
                        Path.GetFileNameWithoutExtension(file).Contains(hint, StringComparison.OrdinalIgnoreCase));

                    if (isCheatProject)
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            bool referencesGTA = content.Contains("GTA5", StringComparison.OrdinalIgnoreCase) ||
                                                 content.Contains("FiveM", StringComparison.OrdinalIgnoreCase) ||
                                                 content.Contains("natives.hpp", StringComparison.OrdinalIgnoreCase) ||
                                                 content.Contains("invoker.hpp", StringComparison.OrdinalIgnoreCase);
                            if (referencesGTA)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"GTA V / FiveM Cheat Visual Studio Project Found: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = "A Visual Studio project file with cheat-indicative naming was found and references GTA V or FiveM internals such as native headers. This is a direct artifact of internal cheat development.",
                                    Detail = $"Path: {file}"
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckHookingLibraryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
        var sysWow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

        var searchRoots = new[]
        {
            Desktop,
            Downloads,
            Documents,
            Temp,
            AppData,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (!HookingLibraryNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                        continue;

                    bool isInSystem32 = file.StartsWith(system32, StringComparison.OrdinalIgnoreCase) ||
                                        file.StartsWith(sysWow64, StringComparison.OrdinalIgnoreCase);

                    if (!isInSystem32)
                    {
                        bool isKiero = fileName.StartsWith("kiero", StringComparison.OrdinalIgnoreCase);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = isKiero
                                ? $"DirectX Hook Library (Kiero) Found: {fileName}"
                                : $"Function Hooking Library Found Outside System Path: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = isKiero
                                ? "The Kiero DirectX hooking library was found. Kiero is exclusively used to hook DirectX rendering pipelines, which is a fundamental component of ESP (wallhack) and aimbot overlay cheats for FiveM."
                                : $"A function hooking library ('{fileName}') was found outside of standard system directories. MinHook and Microsoft Detours are used in cheat development to redirect GTA V native function calls in the FiveM process.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckDirectXHookArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var dxHookDLLNames = new[]
        {
            "d3d11_hook.dll", "dxgi_hook.dll", "d3d12_hook.dll", "d3d9_hook.dll",
        };

        var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
        var sysWow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

        var fiveMRoots = new[]
        {
            FiveMAppData,
            FiveMLocalAppData,
            Path.Combine(LocalAppData, "FiveM"),
        };

        foreach (var root in fiveMRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (dxHookDLLNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DirectX Hook DLL Found in FiveM Directory: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"A DirectX hook DLL named '{fileName}' was found inside FiveM directories. These DLLs intercept DirectX rendering calls to draw ESP overlays (wallhacks, player outlines, radar) or implement aimbot features within the FiveM game window.",
                            Detail = $"Path: {file}"
                        });
                    }

                    bool isSystemDXName = DXHijackDLLNames.Contains(fileName, StringComparer.OrdinalIgnoreCase) &&
                                         (fileName.StartsWith("d3d", StringComparison.OrdinalIgnoreCase) ||
                                          fileName.Equals("dxgi.dll", StringComparison.OrdinalIgnoreCase));

                    if (isSystemDXName)
                    {
                        bool isInSystem32 = file.StartsWith(system32, StringComparison.OrdinalIgnoreCase) ||
                                            file.StartsWith(sysWow64, StringComparison.OrdinalIgnoreCase);

                        if (!isInSystem32)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"System DirectX DLL in Non-System Path (DLL Hijack): {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = $"A system DirectX DLL named '{fileName}' was found inside a FiveM application directory rather than System32. Placing system DLLs in game directories is a DLL hijacking technique used to intercept DirectX calls for cheat overlay rendering.",
                                Detail = $"Path: {file}"
                            });
                        }
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckMemoryPatcherArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Desktop,
            Downloads,
            Documents,
            AppData,
        };

        var cheatTableExtensions = new[] { "*.CT" };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.py", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool targetsFiveMOrGTA = content.Contains("FiveM.exe", StringComparison.OrdinalIgnoreCase) ||
                                                 content.Contains("GTA5.exe", StringComparison.OrdinalIgnoreCase);

                        if (!targetsFiveMOrGTA) continue;

                        int apiMatchCount = ProcessMemoryAPIStrings.Count(api =>
                            content.Contains(api, StringComparison.OrdinalIgnoreCase));

                        if (apiMatchCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Memory Patcher Script Targeting FiveM/GTA V Found: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "A script file was found that references Windows process memory APIs (ReadProcessMemory, WriteProcessMemory, VirtualProtectEx, etc.) while explicitly targeting the FiveM.exe or GTA5.exe process. This is a direct artifact of an external memory cheat or native patcher.",
                                Detail = $"Memory API matches: {apiMatchCount} | File: {file}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckFiveMInternalMenuConfig(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            AppData,
            Desktop,
            Downloads,
            LocalAppData,
        };

        var menuSkinFileExtensions = new[] { "*.skin", "*.theme", "*.layout" };

        var menuHotkeyFileHints = new[]
        {
            "hotkeys.json", "keybinds.json", "config.json", "settings.json",
        };

        var menuFolderHints = new[]
        {
            "2take1", "Stand", "YimMenu", "Eulen", "RedEngine", "Skript", "BrainOBrain",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (PremiumMenuConfigFiles.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        var menuName = Path.GetFileNameWithoutExtension(fileName).Replace("_config", "", StringComparison.OrdinalIgnoreCase);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Premium Mod Menu Config Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"A configuration file for a known FiveM premium internal mod menu was found. The menu '{menuName}' is a paid FiveM cheat that provides native hooks, ESP, aimbot, and anti-detection features.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    bool isInMenuFolder = menuFolderHints.Any(hint =>
                        file.Contains(Path.DirectorySeparatorChar + hint + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));

                    if (isInMenuFolder && menuHotkeyFileHints.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            bool looksLikeCheatConfig = content.Contains("hotkey", StringComparison.OrdinalIgnoreCase) ||
                                                        content.Contains("keybind", StringComparison.OrdinalIgnoreCase) ||
                                                        content.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                                                        content.Contains("esp", StringComparison.OrdinalIgnoreCase) ||
                                                        content.Contains("fov", StringComparison.OrdinalIgnoreCase);
                            if (looksLikeCheatConfig)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Mod Menu Config File in Menu Folder: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = "A JSON configuration file with cheat-related keys (hotkey, aimbot, esp, fov) was found inside a directory named after a known FiveM premium mod menu.",
                                    Detail = $"Path: {file}"
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckLuaInjectorArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var luaInjectorExecutableNames = new[]
        {
            "lua_injector.exe", "lua_exec.exe", "fivem_lua.exe", "executor.exe",
        };

        var luaLoaderDLLNames = new[]
        {
            "lua5.4.dll", "lua54.dll", "lua5.3.dll", "lua53.dll",
        };

        var luaScriptFileNames = new[]
        {
            "executor.lua", "inject.lua", "autoexec.lua",
        };

        var searchRoots = new[]
        {
            Desktop,
            Downloads,
            AppData,
            FiveMAppData,
            FiveMLocalAppData,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (luaInjectorExecutableNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Lua Injector Executable Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"A known Lua injector executable named '{fileName}' was found. These tools inject Lua scripts into the FiveM process at runtime, bypassing FiveM's resource security model.",
                            Detail = $"Path: {file}"
                        });
                    }
                }

                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (luaScriptFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        var dirPath = Path.GetDirectoryName(file) ?? string.Empty;
                        bool hasLuaLoaderNearby = luaLoaderDLLNames.Any(dll =>
                            File.Exists(Path.Combine(dirPath, dll)));

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Lua Injector Script Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = hasLuaLoaderNearby
                                ? $"A Lua injector script named '{fileName}' was found alongside a Lua runtime DLL, confirming a Lua injection toolkit is present. These scripts are injected into the FiveM process to execute privileged native calls."
                                : $"A Lua script named '{fileName}' was found in a FiveM-adjacent or user directory. Files with this name are associated with Lua injection toolkits used to execute arbitrary code in FiveM.",
                            Detail = $"Path: {file} | Lua loader DLL nearby: {hasLuaLoaderNearby}"
                        });
                    }
                }

                foreach (var file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (!luaLoaderDLLNames.Contains(fileName, StringComparer.OrdinalIgnoreCase)) continue;

                    var dirPath = Path.GetDirectoryName(file) ?? string.Empty;
                    bool hasInjectorExeNearby = luaInjectorExecutableNames.Any(exe =>
                        File.Exists(Path.Combine(dirPath, exe)));

                    if (hasInjectorExeNearby)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Lua Runtime DLL Co-Located With Injector: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"The Lua runtime library '{fileName}' was found in the same directory as a known Lua injector executable. This combination confirms a complete Lua injection toolkit used to execute arbitrary scripts within the FiveM process.",
                            Detail = $"Directory: {dirPath}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckOffsetScannerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var reclassExtensions = new[] { "*.reclass", "*.rcnet" };
        var idaExtensions = new[] { "*.idb", "*.i64" };
        var ghidraExtensions = new[] { "*.gpr", "*.rep" };

        var searchRoots = new[]
        {
            Desktop,
            Downloads,
            Documents,
            AppData,
        };

        var offsetPatterns = new[]
        {
            "GTA5.exe+0x",
            "GTA5Base+0x",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var ext in reclassExtensions)
                {
                    foreach (var file in Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ReClass.NET Project File Found: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "A ReClass.NET project file was found. ReClass.NET is a reverse engineering tool used to map out GTA V memory structures and extract native function offsets for use in FiveM cheats.",
                            Detail = $"Path: {file}"
                        });
                    }
                }

                foreach (var ext in idaExtensions)
                {
                    foreach (var file in Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        bool referencesGTA = fileName.Contains("GTA", StringComparison.OrdinalIgnoreCase) ||
                                             fileName.Contains("FiveM", StringComparison.OrdinalIgnoreCase) ||
                                             fileName.Contains("gta5", StringComparison.OrdinalIgnoreCase);
                        if (referencesGTA)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"IDA Pro Database for GTA V / FiveM Found: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = "An IDA Pro disassembly database file with GTA V / FiveM naming was found. IDA Pro databases represent extensive reverse engineering work on game binaries and are used to discover native function offsets for cheat development.",
                                Detail = $"Path: {file}"
                            });
                        }
                    }
                }

                foreach (var ext in ghidraExtensions)
                {
                    foreach (var file in Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        bool referencesGTA = fileName.Contains("GTA", StringComparison.OrdinalIgnoreCase) ||
                                             fileName.Contains("FiveM", StringComparison.OrdinalIgnoreCase);
                        if (referencesGTA)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Ghidra Project for GTA V / FiveM Found: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = "A Ghidra reverse engineering project file with GTA V / FiveM naming was found. Ghidra projects contain disassembly and analysis of game executables used to locate native function addresses for FiveM cheat development.",
                                Detail = $"Path: {file}"
                            });
                        }
                    }
                }

                foreach (var file in Directory.EnumerateFiles(root, "*.txt", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.h", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(root, "*.hpp", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        int offsetMatchCount = offsetPatterns.Count(p => content.Contains(p, StringComparison.OrdinalIgnoreCase));
                        if (offsetMatchCount == 0) continue;

                        int hexOffsetCount = 0;
                        int idx = 0;
                        while ((idx = content.IndexOf("0x", idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                        {
                            hexOffsetCount++;
                            idx += 2;
                        }

                        if (hexOffsetCount >= 10)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"GTA V Offset List / Pattern File Found: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "A file referencing GTA5.exe/GTA5Base offsets with a high density of hexadecimal offset values was found. These offset lists are produced by offset scanners and used as input to native hook cheats.",
                                Detail = $"Offset pattern matches: {offsetMatchCount} | Hex literals: {hexOffsetCount} | Path: {file}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckAntiCheatKillerScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var antiCheatKillPatterns = new[]
        {
            "taskkill /f /im EasyAntiCheat.exe",
            "taskkill /f /im BEService.exe",
            "taskkill /im EasyAntiCheat.exe",
            "taskkill /im BEService.exe",
            "net stop EasyAntiCheat",
            "sc delete cfx-anticheat",
            "sc stop EasyAntiCheat",
            "sc delete EasyAntiCheat",
        };

        var searchRoots = new[]
        {
            Desktop,
            Downloads,
            Documents,
            AppData,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.bat", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.cmd", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(root, "*.ps1", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var pattern in antiCheatKillPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                bool targetsCFX = pattern.Contains("cfx-anticheat", StringComparison.OrdinalIgnoreCase);
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = targetsCFX
                                        ? "FiveM Anti-Cheat Killer Script Found"
                                        : "Anti-Cheat Process Termination Script Found",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = targetsCFX
                                        ? "A script was found that explicitly targets and attempts to disable the FiveM (cfx-anticheat) anti-cheat service. This is a direct anti-detection artifact associated with FiveM cheat bypass attempts."
                                        : $"A script was found containing the command '{pattern}', which terminates or disables EasyAntiCheat or BattlEye processes. These commands are used to disable anti-cheat software before launching FiveM with cheats.",
                                    Detail = $"Matched pattern: {pattern} | File: {file}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckFiveMCrashDumpAnalysis(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var crashDumpRoots = new[]
        {
            Path.Combine(FiveMAppData, "crashes"),
            Path.Combine(FiveMLocalAppData, "crashes"),
        };

        foreach (var root in crashDumpRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                var dmpFiles = Directory.EnumerateFiles(root, "*.dmp", SearchOption.TopDirectoryOnly)
                    .Select(f => (Path: f, Info: new FileInfo(f)))
                    .OrderByDescending(f => f.Info.LastWriteTimeUtc)
                    .ToList();

                foreach (var (filePath, info) in dmpFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Crash Dump File Found",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = Path.GetFileName(filePath),
                        Reason = "A FiveM crash dump file was found. Crash dumps generated shortly after FiveM startup or resource loading can indicate that a native hook or injected DLL caused an access violation or memory corruption, a common artifact of failed injection attempts.",
                        Detail = $"Dump file: {Path.GetFileName(filePath)} | Last write: {info.LastWriteTimeUtc:u} | Size: {info.Length} bytes"
                    });
                }

                if (dmpFiles.Count >= 3)
                {
                    var recent = dmpFiles.Take(3).ToList();
                    var oldest = recent.Max(f => f.Info.LastWriteTimeUtc);
                    var newest = recent.Min(f => f.Info.LastWriteTimeUtc);
                    var span = oldest - newest;

                    if (span.TotalMinutes <= 30)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Repeated FiveM Crash Pattern Detected",
                            Risk = RiskLevel.High,
                            Location = root,
                            FileName = "crashes",
                            Reason = "Multiple FiveM crash dumps were found within a 30-minute window. Repeated crashes in rapid succession are a hallmark of failed native hook injection attempts where the cheat DLL causes FiveM to crash.",
                            Detail = $"Crash count: {recent.Count} | Time span: {span.TotalMinutes:F1} minutes | Directory: {root}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckNativeHookRegistryTraces(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            foreach (var keyPath in PremiumMenuRegistryKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                    if (key == null) continue;

                    var menuName = keyPath.Split('\\').Last();
                    bool isPremiumMenu = new[] { "2Take1", "Stand", "YimMenu", "Eulen", "RedEngine", "Skript", "BrainOBrain" }
                        .Contains(menuName, StringComparer.OrdinalIgnoreCase);

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Mod Menu Registry Key Found: {menuName}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKCU\{keyPath}",
                        FileName = null,
                        Reason = $"A registry key for the known FiveM mod menu '{menuName}' was found under HKCU. Premium FiveM menus such as 2Take1, Stand, YimMenu, and Eulen write configuration keys to the registry. This is a persistent artifact of cheat software installation.",
                        Detail = $"Registry key: HKCU\\{keyPath}"
                    });
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }

            ctx.IncrementRegistryKeys();
            try
            {
                using var scriptHookKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\ScriptHookV");
                if (scriptHookKey != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ScriptHookV Registry Installation Key Found",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SOFTWARE\ScriptHookV",
                        FileName = null,
                        Reason = "A ScriptHookV registry installation key was found under HKLM. ScriptHookV registers itself here on installation; its presence alongside FiveM indicates an attempt to use ScriptHookV bypass techniques.",
                        Detail = @"Registry key: HKLM\SOFTWARE\ScriptHookV"
                    });
                }
            }
            catch { }

            var mruPaths = new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            };

            var mruCheatHints = new[]
            {
                "hook", "inject", "cheat", "fivem_hook", "natives_hook", "2take1", "stand_", "yimmenu",
            };

            foreach (var mruPath in mruPaths)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var mruKey = Registry.CurrentUser.OpenSubKey(mruPath);
                    if (mruKey == null) continue;

                    foreach (var subKeyName in mruKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = mruKey.OpenSubKey(subKeyName);
                            if (subKey == null) continue;

                            foreach (var valueName in subKey.GetValueNames())
                            {
                                ctx.IncrementRegistryKeys();
                                var rawValue = subKey.GetValue(valueName);
                                if (rawValue == null) continue;
                                string valueStr = rawValue.ToString() ?? string.Empty;

                                if (mruCheatHints.Any(hint => valueStr.Contains(hint, StringComparison.OrdinalIgnoreCase)))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Recent File MRU Entry References Native Hook Tool",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKCU\{mruPath}\{subKeyName}",
                                        FileName = null,
                                        Reason = "A Windows Explorer MRU (Most Recently Used) registry entry references a file path consistent with native hook tools, injectors, or known FiveM mod menus, indicating recent user interaction with these files.",
                                        Detail = $"MRU value: {valueStr.Substring(0, Math.Min(200, valueStr.Length))}"
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }, ct);

    private Task CheckImportedFunctionSignatures(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
        var sysWow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

        var searchRoots = new[]
        {
            FiveMAppData,
            FiveMLocalAppData,
            Downloads,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    bool isInSystem32 = file.StartsWith(system32, StringComparison.OrdinalIgnoreCase) ||
                                        file.StartsWith(sysWow64, StringComparison.OrdinalIgnoreCase);
                    if (isInSystem32) continue;

                    try
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.Length > 50 * 1024 * 1024) continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        string content = await sr.ReadToEndAsync(ct);

                        var matchedAPIs = new List<string>();
                        var matchPositions = new List<int>();

                        foreach (var api in ProcessMemoryAPIStrings)
                        {
                            int idx = content.IndexOf(api, StringComparison.Ordinal);
                            if (idx >= 0)
                            {
                                matchedAPIs.Add(api);
                                matchPositions.Add(idx);
                            }
                        }

                        if (matchedAPIs.Count < 5) continue;

                        matchPositions.Sort();
                        int minPos = matchPositions[0];
                        int maxPos = matchPositions[matchPositions.Count - 1];
                        int spread = maxPos - minPos;

                        if (spread <= 1024)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Import Cluster in Non-System DLL: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "A DLL outside System32 contains 5 or more process memory injection API strings (ReadProcessMemory, WriteProcessMemory, OpenProcess, VirtualAllocEx, CreateRemoteThread, NtCreateThreadEx) clustered within 1KB of binary content. This pattern is characteristic of injection or hooking DLLs.",
                                Detail = $"Matched APIs: {string.Join(", ", matchedAPIs)} | Spread: {spread} bytes | File: {file}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckFiveMKernelDriverHookArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Temp,
            Downloads,
            Desktop,
            AppData,
        };

        var vulnerableDriverHints = new[]
        {
            "gdrv", "WinRing0", "WinRing0x64", "AsIO", "CPUZ", "GPUZ",
            "dbutil", "HpPortIox64", "kprocesshacker", "procexp",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.sys", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    bool isKnownVulnDriver = vulnerableDriverHints.Any(hint =>
                        fileName.Contains(hint, StringComparison.OrdinalIgnoreCase));

                    try
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.Length > 10 * 1024 * 1024) continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        string content = await sr.ReadToEndAsync(ct);

                        bool targetsGameProcess = GameTargetProcessNames.Any(proc =>
                            content.Contains(proc, StringComparison.OrdinalIgnoreCase));

                        if (targetsGameProcess || isKnownVulnDriver)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = isKnownVulnDriver
                                    ? $"Known Vulnerable Kernel Driver Found: {fileName}"
                                    : $"Kernel Driver With Game Process References Found: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = isKnownVulnDriver
                                    ? $"A kernel driver matching the name of a known vulnerable or dual-use driver ('{fileName}') was found in a user-accessible directory. These drivers are exploited by cheat software to achieve kernel-level read/write access to the FiveM or GTA V process, bypassing user-mode anti-cheat detection."
                                    : $"A kernel driver (.sys) found outside system directories contains string references to GTA5.exe or FiveM.exe, indicating it was written to target the game process for kernel-level memory manipulation.",
                                Detail = $"Path: {file} | Known vulnerable driver: {isKnownVulnDriver} | References game process: {targetsGameProcess}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckCheatTableFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Desktop,
            Downloads,
            Documents,
            AppData,
            LocalAppData,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.CT", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasProcessName = content.Contains("<ProcessName>", StringComparison.OrdinalIgnoreCase) ||
                                              content.Contains("ProcessName", StringComparison.OrdinalIgnoreCase);

                        if (!hasProcessName) continue;

                        string? matchedProcess = null;
                        bool isFiveMOrMultiplayer = false;

                        foreach (var processName in GameTargetProcessNames)
                        {
                            if (!content.Contains(processName, StringComparison.OrdinalIgnoreCase)) continue;
                            matchedProcess = processName;
                            isFiveMOrMultiplayer = !processName.Equals("GTA5.exe", StringComparison.OrdinalIgnoreCase);
                            break;
                        }

                        if (matchedProcess == null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = isFiveMOrMultiplayer
                                ? $"Cheat Engine Table Targeting FiveM/Multiplayer Client Found: {Path.GetFileName(file)}"
                                : $"Cheat Engine Table Targeting GTA5.exe Found: {Path.GetFileName(file)}",
                            Risk = isFiveMOrMultiplayer ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = isFiveMOrMultiplayer
                                ? $"A Cheat Engine table (.CT) file was found with a ProcessName entry targeting '{matchedProcess}'. Cheat Engine tables for FiveM, RAGE Multiplayer, or alt:V are used to scan and patch multiplayer client memory in real time, which constitutes a direct cheating artifact."
                                : $"A Cheat Engine table (.CT) file targeting GTA5.exe was found. While GTA V has a single-player mode, Cheat Engine tables for GTA5.exe are frequently adapted for use with FiveM and represent a foundational cheat development artifact.",
                            Detail = $"Process target: {matchedProcess} | File: {file}"
                        });
                    }
                    catch { }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);
}
