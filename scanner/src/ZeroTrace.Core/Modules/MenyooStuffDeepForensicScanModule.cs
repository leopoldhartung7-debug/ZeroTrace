using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class MenyooStuffDeepForensicScanModule : IScanModule
{
    public string Name => "Menyoo/Trainer Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string UserProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static readonly string LocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string Downloads = Path.Combine(UserProfile, "Downloads");
    private static readonly string Desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    private static readonly string ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    private static readonly string SystemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";

    private static readonly string[] GtaVInstallPaths =
    {
        @"Rockstar Games\Grand Theft Auto V",
        @"Program Files\Rockstar Games\Grand Theft Auto V",
        @"Program Files (x86)\Rockstar Games\Grand Theft Auto V",
        @"Epic Games\GTAV"
    };

    private static readonly string[] MenyooArtifactFiles =
    {
        "menyooStuff", "menyoo.log", "menyoo.ini", "SimpList.xml",
        "PropertyList.xml", "VehicleList.xml", "Menyoo.asi", "Menyoo.dll"
    };

    private static readonly string[] TrainerAsiFiles =
    {
        "NativeTrainer.asi", "trainerv.asi", "ENT.asi", "EnhancedNativeTrainer.asi",
        "Menyoo.asi", "SessionHijack.asi", "MoneyDrop.asi"
    };

    private static readonly string[] ScriptHookVFiles =
    {
        "ScriptHookV.dll", "ScriptHookV.log", "ScriptHookVDotNet.dll",
        "ScriptHookVDotNet2.dll", "ScriptHookVDotNet3.dll"
    };

    private static readonly string[] ASILoaderShimFiles =
    {
        "dinput8.dll", "dsound.dll", "winmm.dll"
    };

    private static readonly string[] TrainerDownloadPatterns =
    {
        "Menyoo", "menyoo", "MenyooPC", "TrainerV", "NativeTrainer", "SimpleTrainer", "ENT_"
    };

    private static readonly string[] TrainerRegistryKeys =
    {
        @"Software\Menyoo", @"Software\MenyooPC", @"Software\ScriptHookV",
        @"Software\GTATrainer", @"Software\WeMod"
    };

    private static readonly string[] GriefingLogKeywords =
    {
        "explosion", "kill", "spawn", "crash", "kicked", "money drop",
        "teleport", "wanted", "explosive", "orbital cannon"
    };

    private static readonly string[] MenyooXmlRootElements =
    {
        "SimpList", "PropertyList", "VehicleList", "NPC_Interaction",
        "Menyoo", "OutfitSlot", "VehicleSlot"
    };

    private static readonly string[] FiveMAppPaths =
    {
        @"FiveM\FiveM.app",
        @"FiveM Application Data",
        @"CitizenFX"
    };

    private static readonly string[] WeModConfigFiles =
    {
        "games.json", "settings.json", "trainers.json"
    };

    private static readonly string[] PrefetchTrainerPatterns =
    {
        "MENYOO", "GTATRAINER", "TRAINERV", "NATIVETRAINER", "SIMPLTRAINNER", "ENT", "SCRIPTHOOKV"
    };

    private static readonly string[] SpooferArtifactNames =
    {
        "spoofer.exe", "hwid_spoofer.exe", "hwid-spoofer.exe", "spoofer.sys",
        "hwspoofer.exe", "serialspoofer.exe", "rezeex.exe", "striker.exe",
        "phantom_spoofer.exe", "icebergspoof.exe"
    };

    private static readonly string[] GtaOnlineCheatFiles =
    {
        "SessionHijack.asi", "MoneyDrop.asi", "CashDrop.asi", "GiveMoney.asi",
        "LobbyHack.asi", "GTA5Online.asi", "CrashLobby.asi", "KickAll.asi"
    };

    private IEnumerable<string> ResolveGtaVPaths()
    {
        var candidates = new List<string>();

        foreach (var rel in GtaVInstallPaths)
        {
            candidates.Add(Path.Combine(SystemDrive, rel));
            candidates.Add(Path.Combine(ProgramFiles, rel));
            candidates.Add(Path.Combine(ProgramFilesX86, rel));
        }

        var docGta = Path.Combine(Documents, @"Rockstar Games\GTA V");
        candidates.Add(docGta);

        try
        {
            using var steamKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Valve\Steam", writable: false)
                ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam", writable: false);
            if (steamKey?.GetValue("InstallPath") is string steamPath)
                candidates.Add(Path.Combine(steamPath, "steamapps", "common", "Grand Theft Auto V"));
        }
        catch { }

        return candidates.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckMenyooDirectoryArtifacts(ctx, ct),
            CheckMenyooConfigXMLArtifacts(ctx, ct),
            CheckMenyooDLLArtifacts(ctx, ct),
            CheckNativeTrainerArtifacts(ctx, ct),
            CheckSimpleTrainerArtifacts(ctx, ct),
            CheckEnhancedNativeTrainerArtifacts(ctx, ct),
            CheckOpenInteriorArtifacts(ctx, ct),
            CheckScriptHookVArtifactsDeep(ctx, ct),
            CheckASILoaderArtifactsDeep(ctx, ct),
            CheckVehicleAndOutfitSaveArtifacts(ctx, ct),
            CheckMenyooLogForGriefingEvidence(ctx, ct),
            CheckGTAVOnlineCheatArtifacts(ctx, ct),
            CheckTrainerDownloadArtifacts(ctx, ct),
            CheckMenyooSpooferCombinationArtifacts(ctx, ct),
            CheckMenyooRegistryArtifacts(ctx, ct),
            CheckMenyooPrefetchArtifacts(ctx, ct),
            CheckWeMODAndSimilarTrainerArtifacts(ctx, ct),
            CheckFiveMTrainerBypassArtifacts(ctx, ct)
        );
    }

    private Task CheckMenyooDirectoryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchRoots = ResolveGtaVPaths().ToList();
                searchRoots.Add(Path.Combine(Documents, @"Rockstar Games\GTA V"));

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    var menyooStuffDir = Path.Combine(root, "menyooStuff");
                    if (Directory.Exists(menyooStuffDir))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Menyoo menyooStuff Directory Found",
                            Risk = RiskLevel.Critical,
                            Location = menyooStuffDir,
                            FileName = "menyooStuff",
                            Reason = "The menyooStuff directory is created exclusively by the Menyoo PC trainer for GTA V. Its presence indicates Menyoo was installed and used on this system.",
                            Detail = $"Directory found at: {menyooStuffDir}"
                        });
                    }

                    var subDirsToCheck = new[]
                    {
                        Path.Combine(root, "menyooStuff", "menyoo_outfits"),
                        Path.Combine(root, "menyooStuff", "menyoo_vehicles"),
                        Path.Combine(root, "menyooStuff", "Mods")
                    };

                    foreach (var sub in subDirsToCheck)
                    {
                        if (ct.IsCancellationRequested) return;
                        if (!Directory.Exists(sub)) continue;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Menyoo Trainer Sub-Directory Artifact",
                            Risk = RiskLevel.Critical,
                            Location = sub,
                            FileName = Path.GetFileName(sub),
                            Reason = "Menyoo PC trainer save/config sub-directory found. This directory is created by the Menyoo trainer to store saved outfits, vehicles, or mod configurations.",
                            Detail = $"Menyoo sub-directory: {sub}"
                        });
                    }

                    var artifactFiles = new[]
                    {
                        ("menyoo.log", "Menyoo trainer runtime log file"),
                        ("menyoo.ini", "Menyoo trainer configuration file"),
                        ("menyoo_hotkeys.ini", "Menyoo trainer hotkey configuration"),
                        ("menyoo_sp.ini", "Menyoo SP (single-player) settings file")
                    };

                    foreach (var (fileName, description) in artifactFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, fileName);
                        if (!File.Exists(fullPath)) continue;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Menyoo Trainer Config/Log File",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = $"{description} found. This file is created exclusively by the Menyoo PC GTA V trainer.",
                            Detail = $"File path: {fullPath}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckMenyooConfigXMLArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchRoots = ResolveGtaVPaths().ToList();
                searchRoots.Add(Path.Combine(Documents, @"Rockstar Games\GTA V"));
                searchRoots.Add(Path.Combine(Documents, @"Rockstar Games\GTA V\Profiles"));

                var xmlFiles = new[]
                {
                    "SimpList.xml",
                    "PropertyList.xml",
                    "VehicleList.xml",
                    "NPC_Interaction.xml"
                };

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    foreach (var xmlFile in xmlFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, xmlFile);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();

                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch { }

                        bool hasMenyooElement = MenyooXmlRootElements.Any(el =>
                            content.Contains(el, StringComparison.OrdinalIgnoreCase));

                        if (!hasMenyooElement && content.Length < 10) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Menyoo Trainer XML Config File",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = xmlFile,
                            Reason = $"Menyoo PC trainer XML configuration/save file found. {xmlFile} is a save file used exclusively by the Menyoo GTA V trainer to store outfit, vehicle, or property configurations.",
                            Detail = hasMenyooElement
                                ? $"File contains Menyoo-specific XML elements. Path: {fullPath}"
                                : $"File present at expected Menyoo location. Path: {fullPath}"
                        });
                    }

                    if (ct.IsCancellationRequested) return;
                    var menyooStuffDir = Path.Combine(root, "menyooStuff");
                    if (!Directory.Exists(menyooStuffDir)) continue;

                    try
                    {
                        foreach (var xmlPath in Directory.EnumerateFiles(menyooStuffDir, "*.xml", SearchOption.AllDirectories))
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();

                            string xmlContent = string.Empty;
                            try
                            {
                                using var fs = new FileStream(xmlPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                xmlContent = await sr.ReadToEndAsync(ct);
                            }
                            catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Menyoo Trainer XML Save File in menyooStuff",
                                Risk = RiskLevel.Critical,
                                Location = xmlPath,
                                FileName = Path.GetFileName(xmlPath),
                                Reason = "XML save file found inside the Menyoo trainer menyooStuff directory. These files store trainer configurations, saved outfits, vehicle loadouts, or property saves created by Menyoo PC.",
                                Detail = $"File: {xmlPath}, Size: {(xmlContent.Length > 0 ? xmlContent.Length.ToString() : "unknown")} bytes"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckMenyooDLLArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var gtaVPaths = ResolveGtaVPaths().ToList();
                var fiveMPaths = FiveMAppPaths
                    .Select(p => Path.Combine(LocalAppData, p))
                    .Where(Directory.Exists)
                    .ToList();

                var menyooFileChecks = new[]
                {
                    ("Menyoo.asi", "Menyoo PC trainer ASI plugin — requires ASI loader (ScriptHookV) to inject into GTA V"),
                    ("Menyoo.dll", "Menyoo PC trainer DLL artifact — indicates Menyoo was installed on this system"),
                    ("Menyoo.asi.log", "Menyoo PC ASI plugin log file — records trainer activity during GTA V sessions")
                };

                foreach (var root in gtaVPaths)
                {
                    if (ct.IsCancellationRequested) return;

                    bool hasScriptHookV = File.Exists(Path.Combine(root, "ScriptHookV.dll"));
                    bool hasMenyooAsi = File.Exists(Path.Combine(root, "Menyoo.asi"));

                    foreach (var (fileName, reason) in menyooFileChecks)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, fileName);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Menyoo Trainer DLL/ASI File Detected",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = reason,
                            Detail = hasScriptHookV && hasMenyooAsi
                                ? $"Both Menyoo.asi and ScriptHookV.dll are present in the same GTA V directory ({root}), confirming a working Menyoo installation."
                                : $"Found in GTA V directory: {root}"
                        });
                    }

                    var shvPath = Path.Combine(root, "ScriptHookV.dll");
                    if (File.Exists(shvPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "ScriptHookV Present in GTA V Directory",
                            Risk = RiskLevel.Critical,
                            Location = shvPath,
                            FileName = "ScriptHookV.dll",
                            Reason = "ScriptHookV.dll is required by Menyoo and other GTA V ASI trainers to inject into the game process. Its presence alongside Menyoo artifacts confirms trainer usage.",
                            Detail = hasMenyooAsi
                                ? "Menyoo.asi also found in the same directory — confirmed working Menyoo setup."
                                : $"Found in: {root}"
                        });
                    }
                }

                foreach (var fiveMPath in fiveMPaths)
                {
                    if (ct.IsCancellationRequested) return;
                    foreach (var (fileName, reason) in menyooFileChecks)
                    {
                        var fullPath = Path.Combine(fiveMPath, fileName);
                        if (!File.Exists(fullPath)) continue;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Menyoo Trainer File Found in FiveM Directory",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = "Menyoo trainer file detected inside a FiveM application directory. Menyoo is banned from FiveM; its presence in the FiveM directory indicates an attempted bypass of FiveM protections.",
                            Detail = $"FiveM path: {fiveMPath}, file: {fileName}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckNativeTrainerArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchRoots = ResolveGtaVPaths().ToList();
                searchRoots.Add(Downloads);

                var nativeTrainerFiles = new[]
                {
                    ("NativeTrainer.asi", "Native Trainer ASI plugin by GTAmodding — original GTA V trainer"),
                    ("trainerv.asi", "TrainerV ASI plugin — original GTA V native trainer"),
                    ("trainerv.ini", "TrainerV configuration file — Native Trainer settings"),
                    ("trainerv.log", "TrainerV runtime log file — records Native Trainer session activity"),
                    ("NativeTrainer.log", "Native Trainer log file — records trainer usage")
                };

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    foreach (var (fileName, reason) in nativeTrainerFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, fileName);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Native Trainer Artifact Detected",
                            Risk = RiskLevel.High,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = reason,
                            Detail = $"Found at: {fullPath}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckSimpleTrainerArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchRoots = ResolveGtaVPaths().ToList();
                searchRoots.Add(Downloads);

                var simpleTrainerFiles = new[]
                {
                    ("trainerv.asi", "Simple Trainer for GTA V (by sjaak327) ASI plugin"),
                    ("trainerv_config.ini", "Simple Trainer configuration file (sjaak327)"),
                    ("trainerv.log", "Simple Trainer log file"),
                    ("TrainerV.ini", "TrainerV configuration file — Simple Trainer settings variant"),
                    ("TrainerV.asi", "TrainerV ASI plugin — Simple Trainer by sjaak327"),
                    ("trainerv_saved_cars.ini", "Simple Trainer saved vehicle configuration"),
                    ("trainerv_saved_teleports.ini", "Simple Trainer saved teleport locations"),
                    ("trainerv_saved_skins.ini", "Simple Trainer saved skin/outfit configurations")
                };

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    foreach (var (fileName, reason) in simpleTrainerFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, fileName);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Simple Trainer for GTA V Artifact",
                            Risk = RiskLevel.High,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = reason,
                            Detail = $"Found in GTA V directory: {root}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckEnhancedNativeTrainerArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchRoots = ResolveGtaVPaths().ToList();
                searchRoots.Add(Downloads);

                var entFiles = new[]
                {
                    ("ENT.asi", "Enhanced Native Trainer (ENT) ASI plugin"),
                    ("EnhancedNativeTrainer.asi", "Enhanced Native Trainer full-name ASI plugin"),
                    ("ENT.log", "Enhanced Native Trainer log file — records ENT session activity"),
                    ("ENT_config.ini", "Enhanced Native Trainer configuration file"),
                    ("ENT.ini", "Enhanced Native Trainer settings file"),
                    ("EnhancedNativeTrainer.log", "Enhanced Native Trainer full-name log artifact")
                };

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    foreach (var (fileName, reason) in entFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, fileName);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Enhanced Native Trainer (ENT) Artifact",
                            Risk = RiskLevel.High,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = reason,
                            Detail = $"Found in directory: {root}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckOpenInteriorArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchRoots = ResolveGtaVPaths().ToList();

                var openInteriorFiles = new[]
                {
                    ("OpenInteriors.asi", "Open All Interiors mod ASI plugin — commonly paired with trainers for cheating"),
                    ("open_interiors.ini", "Open All Interiors configuration file"),
                    ("AllInteriors.asi", "All Interiors ASI mod — interior unlock plugin used alongside GTA V trainers"),
                    ("OpenAllInteriors.asi", "Open All Interiors variant ASI plugin"),
                    ("OpenInteriors.log", "Open All Interiors log artifact")
                };

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    foreach (var (fileName, reason) in openInteriorFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, fileName);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Open All Interiors Mod Artifact",
                            Risk = RiskLevel.Medium,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = reason,
                            Detail = $"Found at: {fullPath}. This mod requires ScriptHookV and an ASI loader, and is frequently installed alongside GTA V trainers."
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckScriptHookVArtifactsDeep(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var gtaVPaths = ResolveGtaVPaths().ToList();
                var fiveMPaths = FiveMAppPaths
                    .Select(p => Path.Combine(LocalAppData, p))
                    .Where(Directory.Exists)
                    .ToList();

                var shvFiles = new[]
                {
                    ("ScriptHookV.dll", "ScriptHookV core DLL — enables ASI mod loading in GTA V"),
                    ("ScriptHookV.log", "ScriptHookV runtime log — records ScriptHookV session activity and loaded ASI mods"),
                    ("dsound.dll", "dsound.dll in GTA V directory may be an ASI loader shim used to load ScriptHookV"),
                    ("ScriptHookVDotNet.dll", "ScriptHookV .NET extension — enables .NET/C# script mods"),
                    ("ScriptHookVDotNet2.dll", "ScriptHookV .NET v2 extension — second-generation .NET mod support"),
                    ("ScriptHookVDotNet3.dll", "ScriptHookV .NET v3 extension — third-generation .NET mod support"),
                    ("SHVDNPro.log", "ScriptHookV .NET Pro log file")
                };

                foreach (var root in gtaVPaths)
                {
                    if (ct.IsCancellationRequested) return;

                    foreach (var (fileName, reason) in shvFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, fileName);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "ScriptHookV Artifact in GTA V Directory",
                            Risk = RiskLevel.Medium,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = reason,
                            Detail = $"Found in GTA V install directory ({root}). ScriptHookV in a standalone GTA V directory may be legitimate for single-player modding but is prohibited in FiveM."
                        });
                    }
                }

                foreach (var fiveMPath in fiveMPaths)
                {
                    if (ct.IsCancellationRequested) return;

                    foreach (var (fileName, reason) in shvFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(fiveMPath, fileName);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "ScriptHookV Found in FiveM Directory — Critical",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = $"ScriptHookV artifact found inside a FiveM directory. {reason}. ScriptHookV is strictly prohibited in FiveM and its presence here indicates an attempted bypass of FiveM's anti-cheat protections.",
                            Detail = $"FiveM directory: {fiveMPath}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckASILoaderArtifactsDeep(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var systemDllSizes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase)
                {
                    { "dinput8.dll", 200_000L },
                    { "dsound.dll", 250_000L },
                    { "winmm.dll", 200_000L }
                };

                var searchRoots = ResolveGtaVPaths().ToList();

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    int asiCount = 0;
                    try
                    {
                        asiCount = Directory.EnumerateFiles(root, "*.asi", SearchOption.TopDirectoryOnly).Count();
                    }
                    catch { }

                    foreach (var shimFile in ASILoaderShimFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, shimFile);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();

                        long fileSize = 0;
                        try { fileSize = new FileInfo(fullPath).Length; } catch { }

                        long minLegitimateSize = systemDllSizes.TryGetValue(shimFile, out var sz) ? sz : 100_000L;
                        bool likelyShim = fileSize > 0 && fileSize < minLegitimateSize;

                        var risk = (likelyShim || asiCount > 0) ? RiskLevel.Critical : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = likelyShim
                                ? "ASI Loader Shim DLL Detected in GTA V Directory"
                                : "Potential ASI Loader DLL in GTA V Directory",
                            Risk = risk,
                            Location = fullPath,
                            FileName = shimFile,
                            Reason = likelyShim
                                ? $"{shimFile} in the GTA V directory is much smaller than the legitimate system DLL ({fileSize} bytes vs expected >{minLegitimateSize} bytes), indicating it is an ASI loader proxy DLL used to load trainer plugins."
                                : $"{shimFile} found in GTA V directory. This file name is commonly used as an ASI loader shim to inject trainer ASI plugins into GTA V.",
                            Detail = asiCount > 0
                                ? $"File size: {fileSize} bytes. {asiCount} .asi plugin(s) also found in this directory, confirming ASI loader is active."
                                : $"File size: {fileSize} bytes. No additional .asi files found in directory."
                        });
                    }

                    if (ct.IsCancellationRequested) return;

                    try
                    {
                        foreach (var asiFile in Directory.EnumerateFiles(root, "*.asi", SearchOption.TopDirectoryOnly))
                        {
                            if (ct.IsCancellationRequested) return;
                            var asiFileName = Path.GetFileName(asiFile);
                            if (TrainerAsiFiles.Any(t => t.Equals(asiFileName, StringComparison.OrdinalIgnoreCase)))
                                continue;

                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Unknown ASI Plugin in GTA V Directory",
                                Risk = RiskLevel.High,
                                Location = asiFile,
                                FileName = asiFileName,
                                Reason = "An ASI plugin file was found in the GTA V directory that does not match known trainer names. ASI plugins require an ASI loader (ScriptHookV or a proxy DLL) and are commonly used to inject trainers and cheats.",
                                Detail = $"ASI file: {asiFile}. Total ASI plugins in directory: {asiCount}."
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckVehicleAndOutfitSaveArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchRoots = ResolveGtaVPaths().ToList();
                searchRoots.Add(Path.Combine(Documents, @"Rockstar Games\GTA V"));
                searchRoots.Add(Path.Combine(Documents, @"Rockstar Games\GTA V\Profiles"));

                var saveFiles = new[]
                {
                    ("SpawnVehicle.xml", "Trainer vehicle spawn configuration — saves trainer-spawned vehicle loadouts"),
                    ("vehicle_list.xml", "Trainer vehicle list configuration"),
                    ("spawn_vehicles.txt", "Trainer vehicle spawn list file"),
                    ("outfit_list.xml", "Trainer outfit save file — stores trainer-configured player outfits"),
                    ("saved_vehicles.xml", "Trainer saved vehicles file"),
                    ("saved_outfits.xml", "Trainer saved outfits file"),
                    ("vehicle_mods.xml", "Trainer vehicle modifications save file"),
                    ("SpawnedVehicles.xml", "Trainer spawned vehicle log")
                };

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    foreach (var (fileName, reason) in saveFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, fileName);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Trainer Vehicle/Outfit Save File",
                            Risk = RiskLevel.High,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = reason,
                            Detail = $"Found at: {fullPath}"
                        });
                    }

                    if (ct.IsCancellationRequested) return;
                    var menyooModsDir = Path.Combine(root, "menyooStuff", "Mods");
                    if (!Directory.Exists(menyooModsDir)) continue;

                    try
                    {
                        foreach (var xmlFile in Directory.EnumerateFiles(menyooModsDir, "*.xml", SearchOption.AllDirectories))
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Menyoo Mods XML Save File",
                                Risk = RiskLevel.High,
                                Location = xmlFile,
                                FileName = Path.GetFileName(xmlFile),
                                Reason = "XML mod configuration file found inside Menyoo's Mods save directory. These files store trainer mod presets, vehicle configurations, and character customizations created by Menyoo PC.",
                                Detail = $"Menyoo Mods directory: {menyooModsDir}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckMenyooLogForGriefingEvidence(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchRoots = ResolveGtaVPaths().ToList();
                var logFilesToCheck = new[] { "menyoo.log", "menyoo.ini" };

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    foreach (var logFile in logFilesToCheck)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, logFile);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();

                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch { }

                        if (string.IsNullOrWhiteSpace(content)) continue;

                        var foundGriefingKeywords = GriefingLogKeywords
                            .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (foundGriefingKeywords.Count > 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Menyoo Log Contains Griefing Evidence",
                                Risk = RiskLevel.Critical,
                                Location = fullPath,
                                FileName = logFile,
                                Reason = $"The Menyoo trainer log file contains keywords associated with griefing actions: {string.Join(", ", foundGriefingKeywords)}. This indicates the trainer was used for disruptive multiplayer actions.",
                                Detail = $"Keywords matched: [{string.Join(", ", foundGriefingKeywords)}]. Log file: {fullPath}"
                            });
                        }

                        var ipPattern = new System.Text.RegularExpressions.Regex(
                            @"\b(\d{1,3}\.){3}\d{1,3}(:\d{2,5})?\b");
                        var ipMatches = ipPattern.Matches(content);
                        if (ipMatches.Count > 0)
                        {
                            var ips = ipMatches.Cast<System.Text.RegularExpressions.Match>()
                                .Select(m => m.Value)
                                .Distinct()
                                .Take(5)
                                .ToList();

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Menyoo Log Contains Server IP Addresses",
                                Risk = RiskLevel.Critical,
                                Location = fullPath,
                                FileName = logFile,
                                Reason = "The Menyoo trainer log file contains IP addresses, indicating the trainer was used in multiplayer sessions. Menyoo is banned from FiveM and GTA Online.",
                                Detail = $"IP addresses found in log: {string.Join(", ", ips)} (showing first 5). Log file: {fullPath}"
                            });
                        }
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckGTAVOnlineCheatArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchRoots = ResolveGtaVPaths().ToList();
                var docGtaOnline = Path.Combine(Documents, @"Rockstar Games\GTA V");
                searchRoots.Add(docGtaOnline);

                var onlineCheatFiles = new[]
                {
                    ("SessionHijack.asi", "Session Hijack ASI — GTA Online session takeover cheat tool"),
                    ("MoneyDrop.asi", "Money Drop ASI — GTA Online money drop cheat for griefing other players"),
                    ("CashDrop.asi", "Cash Drop ASI — GTA Online cash drop cheat"),
                    ("GiveMoney.asi", "Give Money ASI — GTA Online money-giving cheat"),
                    ("LobbyHack.asi", "Lobby Hack ASI — GTA Online lobby manipulation cheat"),
                    ("CrashLobby.asi", "Crash Lobby ASI — GTA Online lobby crash tool"),
                    ("KickAll.asi", "Kick All ASI — GTA Online player kick exploit"),
                    ("GTA5Online.asi", "GTA Online-specific cheat ASI plugin"),
                    ("MoneyDrop.ini", "Money Drop configuration file — GTA Online cash drop cheat settings"),
                    ("SessionHijack.ini", "Session Hijack configuration — GTA Online session control cheat settings")
                };

                foreach (var root in searchRoots)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(root)) continue;

                    foreach (var (fileName, reason) in onlineCheatFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(root, fileName);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "GTA Online Cheat Tool Artifact",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = fileName,
                            Reason = reason,
                            Detail = $"GTA Online cheat artifact found at: {fullPath}. These tools are used to grief other players, drop money, crash lobbies, or take control of online sessions."
                        });
                    }

                    if (ct.IsCancellationRequested) return;

                    var onlineConfigDir = Path.Combine(root, "GTA Online");
                    if (!Directory.Exists(onlineConfigDir)) continue;

                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(onlineConfigDir, "*.xml", SearchOption.AllDirectories))
                        {
                            if (ct.IsCancellationRequested) return;
                            var name = Path.GetFileName(file);

                            string xmlContent = string.Empty;
                            try
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                xmlContent = await sr.ReadToEndAsync(ct);
                            }
                            catch { }

                            bool suspicious = GriefingLogKeywords.Any(kw =>
                                xmlContent.Contains(kw, StringComparison.OrdinalIgnoreCase));

                            if (!suspicious) continue;

                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "GTA Online Cheat Config with Griefing Content",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = name,
                                Reason = "XML configuration file in GTA Online directory contains keywords associated with cheating or griefing activities.",
                                Detail = $"File: {file}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckTrainerDownloadArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var searchDirs = new[] { Downloads, Desktop };
                var archiveExtensions = new[] { ".zip", ".rar", ".7z", ".tar", ".gz" };
                var exeExtensions = new[] { ".exe", ".msi" };

                foreach (var dir in searchDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(dir)) continue;

                    IEnumerable<string> files;
                    try
                    {
                        files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
                    }
                    catch { continue; }

                    foreach (var file in files)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fileName = Path.GetFileName(file);
                        var ext = Path.GetExtension(file);

                        bool isArchive = archiveExtensions.Any(e =>
                            ext.Equals(e, StringComparison.OrdinalIgnoreCase));
                        bool isExe = exeExtensions.Any(e =>
                            ext.Equals(e, StringComparison.OrdinalIgnoreCase));

                        if (!isArchive && !isExe) continue;

                        bool matchesPattern = TrainerDownloadPatterns.Any(p =>
                            fileName.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (!matchesPattern) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Trainer Download Archive/Installer",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"A file matching a known GTA V trainer download pattern was found in {dir}. The file name contains a known trainer keyword.",
                            Detail = $"File: {fileName} in {dir}. Pattern matched. This may be a Menyoo, SimpleTrainer, NativeTrainer, or ENT installer or update archive."
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckMenyooSpooferCombinationArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                bool trainerFound = false;
                string trainerArtifactPath = string.Empty;

                foreach (var root in ResolveGtaVPaths())
                {
                    if (ct.IsCancellationRequested) return;
                    foreach (var trainerFile in MenyooArtifactFiles)
                    {
                        var fullPath = Path.Combine(root, trainerFile);
                        if (!File.Exists(fullPath) && !Directory.Exists(fullPath)) continue;
                        trainerFound = true;
                        trainerArtifactPath = fullPath;
                        break;
                    }
                    if (trainerFound) break;
                }

                if (!trainerFound)
                {
                    foreach (var root in ResolveGtaVPaths())
                    {
                        if (ct.IsCancellationRequested) return;
                        foreach (var asiFile in TrainerAsiFiles)
                        {
                            var fullPath = Path.Combine(root, asiFile);
                            if (!File.Exists(fullPath)) continue;
                            trainerFound = true;
                            trainerArtifactPath = fullPath;
                            break;
                        }
                        if (trainerFound) break;
                    }
                }

                if (!trainerFound) return;

                bool spooferFound = false;
                string spooferArtifactPath = string.Empty;

                var spooferSearchDirs = new List<string>
                {
                    Downloads,
                    Desktop,
                    Path.Combine(LocalAppData, "Temp"),
                    Path.Combine(AppData, "Roaming"),
                    UserProfile
                };

                foreach (var dir in spooferSearchDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(dir)) continue;

                    IEnumerable<string> files;
                    try { files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                    catch { continue; }

                    foreach (var file in files)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fileName = Path.GetFileName(file);
                        if (!SpooferArtifactNames.Any(s => fileName.Contains(s, StringComparison.OrdinalIgnoreCase)))
                            continue;
                        spooferFound = true;
                        spooferArtifactPath = file;
                        break;
                    }
                    if (spooferFound) break;
                }

                if (!spooferFound)
                {
                    try
                    {
                        using var spooferKey = Registry.CurrentUser.OpenSubKey(@"Software\HWID Spoofer", writable: false)
                            ?? Registry.CurrentUser.OpenSubKey(@"Software\Serial Spoofer", writable: false)
                            ?? Registry.CurrentUser.OpenSubKey(@"Software\RezeexSpoofer", writable: false)
                            ?? Registry.CurrentUser.OpenSubKey(@"Software\RealSpoofer", writable: false);

                        if (spooferKey is not null)
                        {
                            spooferFound = true;
                            spooferArtifactPath = "Registry: HKCU\\Software\\[Spoofer]";
                            ctx.IncrementRegistryKeys();
                        }
                    }
                    catch { }
                }

                if (!spooferFound) return;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Trainer + HWID Spoofer Combination Detected",
                    Risk = RiskLevel.Critical,
                    Location = trainerArtifactPath,
                    FileName = Path.GetFileName(trainerArtifactPath),
                    Reason = "Both a GTA V trainer artifact and a HWID/hardware spoofer artifact were found on this system. This combination strongly indicates intent to use trainers in multiplayer environments while evading hardware bans.",
                    Detail = $"Trainer artifact: {trainerArtifactPath} | Spoofer artifact: {spooferArtifactPath}"
                });
            }
            catch { }
        }, ct);

    private Task CheckMenyooRegistryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                foreach (var regKey in TrainerRegistryKeys)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var key = Registry.CurrentUser.OpenSubKey(regKey, writable: false);
                        if (key is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Trainer Registry Key Found",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{regKey}",
                            Reason = $"A registry key associated with a GTA V trainer was found: HKCU\\{regKey}. This indicates the trainer was installed or run on this system.",
                            Detail = $"Registry path: HKCU\\{regKey}. Value count: {key.ValueCount}"
                        });
                    }
                    catch { }
                }

                var recentDocExtensions = new[]
                {
                    (@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.asi",
                        "Recent Documents entry for .asi files — user opened or interacted with ASI trainer files"),
                    (@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.xml",
                        "Recent Documents entry for .xml files — user opened Menyoo XML config files")
                };

                foreach (var (keyPath, reason) in recentDocExtensions)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: false);
                        if (key is null) continue;

                        var mruList = key.GetValue("MRUListEx") as byte[];
                        if (mruList is null || mruList.Length == 0) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Trainer File Type in Explorer Recent Documents",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{keyPath}",
                            Reason = reason,
                            Detail = $"Registry key: HKCU\\{keyPath}. MRU list has {mruList.Length / 4} entries indicating recent interactions with these file types."
                        });
                    }
                    catch { }
                }

                var lmTrainerKeys = new[]
                {
                    @"SOFTWARE\Menyoo",
                    @"SOFTWARE\MenyooPC",
                    @"SOFTWARE\ScriptHookV",
                    @"SOFTWARE\GTATrainer"
                };

                foreach (var regKey in lmTrainerKeys)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(regKey, writable: false);
                        if (key is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Trainer Registry Key in HKLM",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{regKey}",
                            Reason = $"A system-wide registry key associated with a GTA V trainer was found: HKLM\\{regKey}. System-level registration indicates the trainer was installed with elevated privileges.",
                            Detail = $"Registry path: HKLM\\{regKey}"
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckMenyooPrefetchArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                if (!Directory.Exists(prefetchDir)) return;

                IEnumerable<string> prefetchFiles;
                try { prefetchFiles = Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly); }
                catch { return; }

                foreach (var pfFile in prefetchFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var pfName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();

                    bool matches = PrefetchTrainerPatterns.Any(p =>
                        pfName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                    if (!matches) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Trainer Prefetch File Found",
                        Risk = RiskLevel.High,
                        Location = pfFile,
                        FileName = Path.GetFileName(pfFile),
                        Reason = $"A Windows Prefetch file matching a known GTA V trainer pattern was found: {Path.GetFileName(pfFile)}. Prefetch files are created when an application is executed, confirming that the trainer was run on this system.",
                        Detail = $"Prefetch file: {pfFile}. Prefetch files persist for approximately 30 days after last execution."
                    });
                }

                var userAssistPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
                var userAssistGuids = new[]
                {
                    @"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
                    @"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count"
                };

                foreach (var guidPath in userAssistGuids)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    try
                    {
                        using var key = Registry.CurrentUser.OpenSubKey(
                            Path.Combine(userAssistPath, guidPath), writable: false);
                        if (key is null) continue;

                        foreach (var valueName in key.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;

                            bool trainerMatch = TrainerDownloadPatterns.Any(p =>
                                valueName.Contains(p, StringComparison.OrdinalIgnoreCase));

                            if (!trainerMatch) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Trainer Execution in UserAssist Registry",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{userAssistPath}\{guidPath}",
                                FileName = valueName,
                                Reason = $"UserAssist registry entry records execution of a trainer-matching application: {valueName}. UserAssist tracks program launch counts and timestamps.",
                                Detail = $"UserAssist key: HKCU\\{userAssistPath}\\{guidPath}\\{valueName}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckWeMODAndSimilarTrainerArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var weModPath = Path.Combine(LocalAppData, "WeMod");
                if (Directory.Exists(weModPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "WeMod Trainer Platform Installed",
                        Risk = RiskLevel.High,
                        Location = weModPath,
                        FileName = "WeMod",
                        Reason = "WeMod is a popular game trainer platform that supports GTA V trainers. Its presence indicates a game trainer platform is installed on this system.",
                        Detail = $"WeMod directory: {weModPath}"
                    });

                    foreach (var configFile in WeModConfigFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var configPath = Path.Combine(weModPath, configFile);
                        if (!File.Exists(configPath)) continue;

                        ctx.IncrementFiles();
                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch { }

                        bool hasGtaV = content.Contains("GTA", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("Grand Theft Auto", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("GTAV", StringComparison.OrdinalIgnoreCase);

                        if (!hasGtaV) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "WeMod Config Contains GTA V Trainer Entry",
                            Risk = RiskLevel.High,
                            Location = configPath,
                            FileName = configFile,
                            Reason = "WeMod trainer platform configuration file references GTA V, indicating WeMod trainers were actively used for GTA V on this system.",
                            Detail = $"WeMod config file with GTA V reference: {configPath}"
                        });
                    }

                    var weModExe = Path.Combine(weModPath, "app", "WeMod.exe");
                    if (!File.Exists(weModExe))
                    {
                        try
                        {
                            weModExe = Directory.EnumerateFiles(weModPath, "WeMod.exe", SearchOption.AllDirectories)
                                .FirstOrDefault() ?? string.Empty;
                        }
                        catch { }
                    }

                    if (File.Exists(weModExe))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "WeMod Trainer Executable Found",
                            Risk = RiskLevel.High,
                            Location = weModExe,
                            FileName = "WeMod.exe",
                            Reason = "WeMod.exe trainer platform executable found. WeMod provides in-memory game trainers for hundreds of games including GTA V.",
                            Detail = $"WeMod executable: {weModExe}"
                        });
                    }
                }

                var artMoneyAppData = Path.Combine(AppData, "ArtMoney");
                if (Directory.Exists(artMoneyAppData))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ArtMoney Memory Editor Installed",
                        Risk = RiskLevel.High,
                        Location = artMoneyAppData,
                        FileName = "ArtMoney",
                        Reason = "ArtMoney is a memory editor used as a game trainer to modify in-memory values (money, health, ammunition). Its presence alongside GTA V indicates potential game value manipulation.",
                        Detail = $"ArtMoney appdata directory: {artMoneyAppData}"
                    });
                }

                var artMoneyExePaths = new[]
                {
                    Path.Combine(ProgramFiles, "ArtMoney", "ArtMoney.exe"),
                    Path.Combine(ProgramFilesX86, "ArtMoney", "ArtMoney.exe"),
                    Path.Combine(Desktop, "ArtMoney.exe"),
                    Path.Combine(Downloads, "ArtMoney.exe")
                };

                foreach (var exePath in artMoneyExePaths)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!File.Exists(exePath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ArtMoney Memory Editor Executable",
                        Risk = RiskLevel.High,
                        Location = exePath,
                        FileName = "ArtMoney.exe",
                        Reason = "ArtMoney.exe memory editor found. ArtMoney is used to search and modify game memory values, functioning as a universal game trainer.",
                        Detail = $"Executable path: {exePath}"
                    });
                }

                var trainerFtwPath = Path.Combine(LocalAppData, "TrainerFTW");
                if (Directory.Exists(trainerFtwPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "TrainerFTW Platform Installed",
                        Risk = RiskLevel.High,
                        Location = trainerFtwPath,
                        FileName = "TrainerFTW",
                        Reason = "TrainerFTW game trainer platform directory found. TrainerFTW provides game trainers for multiple titles including GTA V.",
                        Detail = $"TrainerFTW directory: {trainerFtwPath}"
                    });
                }
            }
            catch { }
        }, ct);

    private Task CheckFiveMTrainerBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            try
            {
                var fiveMRoots = FiveMAppPaths
                    .Select(p => Path.Combine(LocalAppData, p))
                    .Where(Directory.Exists)
                    .ToList();

                if (fiveMRoots.Count == 0) return;

                bool fiveMInstalled = fiveMRoots.Count > 0;

                bool scriptHookInFiveM = false;
                string scriptHookFiveMPath = string.Empty;

                foreach (var fiveMRoot in fiveMRoots)
                {
                    if (ct.IsCancellationRequested) return;

                    foreach (var shvFile in ScriptHookVFiles)
                    {
                        var fullPath = Path.Combine(fiveMRoot, shvFile);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        scriptHookInFiveM = true;
                        scriptHookFiveMPath = fullPath;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "ScriptHookV Copied into FiveM Directory",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = shvFile,
                            Reason = $"ScriptHookV file ({shvFile}) was found inside a FiveM application directory. ScriptHookV is strictly prohibited in FiveM. Copying it into the FiveM directory is a known technique to attempt bypassing FiveM's trainer protection.",
                            Detail = $"FiveM directory: {fiveMRoot}, ScriptHookV file: {fullPath}"
                        });
                    }

                    var patchScripts = new[]
                    {
                        "fivem_patch.bat",
                        "fivem_patch.ps1",
                        "disable_protection.bat",
                        "disable_anticheat.bat",
                        "fivem_bypass.bat",
                        "inject.bat",
                        "asi_inject.bat",
                        "launch_fivem_mod.bat"
                    };

                    foreach (var patchScript in patchScripts)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fullPath = Path.Combine(fiveMRoot, patchScript);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Protection Bypass Script",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = patchScript,
                            Reason = $"A script file with a name suggesting FiveM protection bypass was found in the FiveM directory: {patchScript}. These scripts are used to disable FiveM's anti-cheat checks or inject ASI mods.",
                            Detail = $"Script path: {fullPath}"
                        });
                    }

                    if (ct.IsCancellationRequested) return;

                    var fiveMExe = Path.Combine(fiveMRoot, "FiveM.exe");
                    if (!File.Exists(fiveMExe))
                    {
                        try
                        {
                            fiveMExe = Directory.EnumerateFiles(fiveMRoot, "FiveM*.exe", SearchOption.TopDirectoryOnly)
                                .FirstOrDefault() ?? string.Empty;
                        }
                        catch { }
                    }

                    if (!File.Exists(fiveMExe)) continue;

                    string fiveMContent = string.Empty;
                    try
                    {
                        using var fs = new FileStream(fiveMExe, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        var buffer = new char[8192];
                        var sb = new StringBuilder();
                        int read;
                        while ((read = await sr.ReadAsync(buffer, ct)) > 0)
                        {
                            sb.Append(buffer, 0, read);
                            if (sb.Length > 1_000_000) break;
                        }
                        fiveMContent = sb.ToString();
                    }
                    catch { }

                    bool patchedFiveM = fiveMContent.Contains("ScriptHookV", StringComparison.OrdinalIgnoreCase)
                        || fiveMContent.Contains("menyoo", StringComparison.OrdinalIgnoreCase)
                        || fiveMContent.Contains("asi_load", StringComparison.OrdinalIgnoreCase);

                    if (patchedFiveM)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Executable Contains Trainer-Related Strings",
                            Risk = RiskLevel.Critical,
                            Location = fiveMExe,
                            FileName = Path.GetFileName(fiveMExe),
                            Reason = "The FiveM executable contains strings associated with ScriptHookV, Menyoo, or ASI loading. This may indicate the FiveM binary has been patched or replaced to allow trainer injection.",
                            Detail = $"FiveM executable with suspicious content: {fiveMExe}"
                        });
                    }
                }

                if (fiveMInstalled && scriptHookInFiveM)
                {
                    bool citFxRegistry = false;
                    bool shvRegistry = false;

                    try
                    {
                        using var citKey = Registry.CurrentUser.OpenSubKey(@"Software\CitizenFX", writable: false);
                        ctx.IncrementRegistryKeys();
                        citFxRegistry = citKey is not null;
                    }
                    catch { }

                    try
                    {
                        using var shvKey = Registry.CurrentUser.OpenSubKey(@"Software\ScriptHookV", writable: false);
                        ctx.IncrementRegistryKeys();
                        shvRegistry = shvKey is not null;
                    }
                    catch { }

                    if (citFxRegistry && shvRegistry)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM + ScriptHookV Registry Combination — Bypass Evidence",
                            Risk = RiskLevel.Critical,
                            Location = @"HKCU\Software\CitizenFX + HKCU\Software\ScriptHookV",
                            Reason = "Both HKCU\\Software\\CitizenFX (FiveM) and HKCU\\Software\\ScriptHookV registry keys exist simultaneously. Combined with ScriptHookV found in the FiveM directory, this strongly indicates an attempt to run GTA V trainers inside FiveM by bypassing its protections.",
                            Detail = $"FiveM is installed and ScriptHookV registry presence confirmed. ScriptHookV also found at: {scriptHookFiveMPath}"
                        });
                    }
                }
            }
            catch { }
        }, ct);
}
