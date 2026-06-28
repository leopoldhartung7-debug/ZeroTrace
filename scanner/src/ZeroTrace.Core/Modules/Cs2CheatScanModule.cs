using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class Cs2CheatScanModule : IScanModule
{
    public string Name => "CS2-Cheat";
    public double Weight => 0.7;
    public int ParallelGroup => 4;

    private static readonly HashSet<string> KnownCheatExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cs2_cheat.exe", "csgo_cheat.exe", "cs2_hack.exe", "cs2_aimbot.exe", "cs2_esp.exe",
        "cs2_wallhack.exe", "cs2_loader.exe", "cs2_bypass.exe", "aimware_cs2.exe",
        "skeet_cs2.exe", "gamesense_cs2.exe", "onetap_cs2.exe", "fatality_cs2.exe",
        "nixware_cs2.exe", "neverlose_cs2.exe", "interwebz_cs2.exe", "pandora_cs2.exe",
        "hvh_cheat.exe", "hvh_loader.exe", "legit_hack.exe", "rage_hack.exe",
        "spinbot.exe", "spinbot_cs2.exe", "triggerbot_cs2.exe", "aimlock_cs2.exe",
        "bhop_cs2.exe", "recoil_cs2.exe", "cs2_external.exe", "cs2_internal.exe",
        "counterstrike_cheat.exe",
    };

    private static readonly HashSet<string> KnownCheatDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cs2_cheat.dll", "csgo_cheat.dll", "cs2_esp.dll", "cs2_aimbot.dll",
        "cs2_hook.dll", "client_cheat.dll", "engine_cheat.dll", "tier0_hook.dll",
    };

    private static readonly string[] CheatAppDataDirNames =
    {
        "aimware", "skeet", ".skeet", "gamesense", "onetap",
        "fatality", "nixware", "interwebz", "neverlose", "pandora",
    };

    private static readonly string[] SuspiciousLaunchOptions =
    {
        "-insecure", "-allow_third_party_software", "+sv_cheats 1",
        "-noverifyfiles", "+exec cheat", "+exec hack", "+exec aimbot", "-novac",
    };

    private static readonly string[] CfgCheatCommands =
    {
        "sv_cheats 1", "r_drawothermodels 2", "mat_wireframe 2",
        "host_timescale", "sv_gravity 0", "noclip", "ent_fire",
    };

    private static readonly string[] CfgBindCheatCommands =
    {
        "bind.*aimbot", "bind.*esp", "bind.*wallhack",
    };

    private static readonly HashSet<string> ExternalCheatOffsetFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cs2_offsets.json", "cs2_offsets.ini", "offsets.hpp", "offsets.h",
        "netvars.json", "client.dll_offsets.json",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "aimbot", "esp", "resolver", "backtrack", "spinbot", "hvh", "rage", "legit",
    };

    private static readonly string[] PrefetchPatterns =
    {
        "CS2_CHEAT", "CSGO_CHEAT", "AIMWARE", "SKEET",
        "ONETAP", "FATALITY", "NIXWARE", "NEVERLOSE", "HVH_CHEAT", "SPINBOT",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanKnownCheatFiles(ctx, ct);
            ScanCs2LaunchOptions(ctx, ct);
            ScanCs2CfgFiles(ctx, ct);
            ScanCheatAppDataDirectories(ctx, ct);
            ScanExternalCheatIndicators(ctx, ct);
            ScanWorkshopArtifacts(ctx, ct);
            ScanRunningProcessesAndPrefetch(ctx, ct);
        }, ct);
    }

    private static void ScanKnownCheatFiles(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var baseDir in searchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    if (!KnownCheatExeNames.Contains(fname)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "CS2-Cheat",
                        Title = $"CS2 cheat EXE on disk: {fname}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fname,
                        Reason = $"Known CS2/CSGO cheat executable '{fname}' found on disk. " +
                                 "This file is a recognized cheat tool targeting Counter-Strike 2.",
                        Detail = $"Path={file}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    if (!KnownCheatDllNames.Contains(fname)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "CS2-Cheat",
                        Title = $"CS2 cheat DLL on disk: {fname}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fname,
                        Reason = $"Known CS2 cheat DLL '{fname}' found on disk. " +
                                 "This DLL is associated with CS2 injection cheats or in-game hooks.",
                        Detail = $"Path={file}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        ScanCs2GameDirForCheatDlls(ctx, ct);
    }

    private static void ScanCs2GameDirForCheatDlls(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var steamApps = FindSteamAppsPath();
        if (steamApps == null) return;

        var cs2GameDir = Path.Combine(steamApps, "common", "Counter-Strike Global Offensive", "game");
        if (!Directory.Exists(cs2GameDir)) return;

        try
        {
            foreach (var file in Directory.GetFiles(cs2GameDir, "*.dll", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fname = Path.GetFileName(file);
                if (!KnownCheatDllNames.Contains(fname)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "CS2-Cheat",
                    Title = $"Cheat DLL inside CS2 game directory: {fname}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fname,
                    Reason = $"Known CS2 cheat DLL '{fname}' found inside the CS2 game installation directory. " +
                             "Placing a cheat DLL in the game directory is a common DLL side-loading injection technique.",
                    Detail = $"Path={file}",
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }

    private static void ScanCs2LaunchOptions(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        using var appsKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam\Apps\730");
        if (appsKey == null) return;

        ctx.IncrementRegistryKeys();
        var launchOptions = appsKey.GetValue("LaunchOptions") as string;
        if (string.IsNullOrEmpty(launchOptions)) return;

        var lowerOptions = launchOptions.ToLowerInvariant();
        var matchedOptions = new List<string>();
        foreach (var opt in SuspiciousLaunchOptions)
        {
            if (lowerOptions.Contains(opt.ToLowerInvariant()))
                matchedOptions.Add(opt);
        }

        if (matchedOptions.Count == 0) return;

        ctx.AddFinding(new Finding
        {
            Module = "CS2-Cheat",
            Title = "Suspicious CS2 Steam launch options detected",
            Risk = RiskLevel.Medium,
            Location = @"HKCU\SOFTWARE\Valve\Steam\Apps\730",
            Reason = $"CS2 (App 730) Steam launch options contain suspicious flags: {string.Join(", ", matchedOptions)}. " +
                     "These options can disable VAC, allow third-party software injection, or enable cheat console variables.",
            Detail = $"LaunchOptions={launchOptions} Matches={string.Join("|", matchedOptions)}",
        });
    }

    private static void ScanCs2CfgFiles(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var steamApps = FindSteamAppsPath();

        var cfgDirs = new List<string>();
        if (steamApps != null)
        {
            cfgDirs.Add(Path.Combine(steamApps, "common",
                "Counter-Strike Global Offensive", "game", "csgo", "cfg"));
            cfgDirs.Add(Path.Combine(steamApps, "common",
                "Counter-Strike Global Offensive", "game", "cs2", "cfg"));
        }

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        cfgDirs.Add(Path.Combine(profile, "AppData", "Roaming", "Counter-Strike Global Offensive"));

        foreach (var cfgDir in cfgDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cfgDir)) continue;

            try
            {
                foreach (var cfgFile in Directory.GetFiles(cfgDir, "*.cfg", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();
                    }
                    catch (IOException) { continue; }

                    var lower = content.ToLowerInvariant();
                    var matched = new List<string>();

                    foreach (var cmd in CfgCheatCommands)
                    {
                        if (lower.Contains(cmd.ToLowerInvariant()))
                            matched.Add(cmd);
                    }

                    foreach (var bindPattern in CfgBindCheatCommands)
                    {
                        var parts = bindPattern.Split(new[] { ".*" }, StringSplitOptions.None);
                        if (parts.Length == 2 && lower.Contains(parts[0]) && lower.Contains(parts[1]))
                            matched.Add(bindPattern);
                    }

                    if (matched.Count < 2) continue;

                    var risk = matched.Count >= 4 ? RiskLevel.Critical : RiskLevel.High;
                    ctx.AddFinding(new Finding
                    {
                        Module = "CS2-Cheat",
                        Title = $"CS2 config file with {matched.Count} cheat commands: {Path.GetFileName(cfgFile)}",
                        Risk = risk,
                        Location = cfgFile,
                        FileName = Path.GetFileName(cfgFile),
                        Reason = $"CS2 config file '{Path.GetFileName(cfgFile)}' contains {matched.Count} cheat-related " +
                                 $"commands: {string.Join(", ", matched)}. Multiple cheat commands in a config indicate " +
                                 "intentional cheating setup.",
                        Detail = $"File={cfgFile} Matches={string.Join("|", matched)} Count={matched.Count}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void ScanCheatAppDataDirectories(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var dirName in CheatAppDataDirNames)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var baseRoot in new[] { appData, localAppData })
            {
                var candidatePath = Path.Combine(baseRoot, dirName);
                if (!Directory.Exists(candidatePath)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "CS2-Cheat",
                    Title = $"CS2 cheat tool AppData directory: {dirName}",
                    Risk = RiskLevel.High,
                    Location = candidatePath,
                    Reason = $"Known CS2 cheat tool config directory '{dirName}' found in AppData. " +
                             "This directory is created by the corresponding CS2 cheat client.",
                    Detail = $"Dir={candidatePath}",
                });

                ScanCheatDirContents(ctx, candidatePath, dirName, ct);
            }

            var regPath = $@"Software\{dirName}";
            using var regKey = Registry.CurrentUser.OpenSubKey(regPath);
            if (regKey == null) continue;

            ctx.IncrementRegistryKeys();
            ctx.AddFinding(new Finding
            {
                Module = "CS2-Cheat",
                Title = $"CS2 cheat registry key: HKCU\\Software\\{dirName}",
                Risk = RiskLevel.High,
                Location = $@"HKCU\{regPath}",
                Reason = $"Registry key for known CS2 cheat tool '{dirName}' found under HKCU\\Software. " +
                         "This key is typically created by the cheat installer or client on first run.",
                Detail = $"RegKey=HKCU\\{regPath}",
            });
        }
    }

    private static void ScanCheatDirContents(ScanContext ctx, string dir, string cheatName, CancellationToken ct)
    {
        try
        {
            foreach (var file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".json" && ext != ".cfg" && ext != ".ini" && ext != ".txt" && ext != ".xml") continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();
                }
                catch (IOException) { continue; }

                var lower = content.ToLowerInvariant();
                var foundKeywords = CheatConfigKeywords.Where(k => lower.Contains(k)).ToList();
                if (foundKeywords.Count < 2) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "CS2-Cheat",
                    Title = $"CS2 cheat config with feature keywords: {Path.GetFileName(file)}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = $"Config file in '{cheatName}' cheat directory contains feature keywords: " +
                             $"{string.Join(", ", foundKeywords)}. This confirms the cheat was configured and used.",
                    Detail = $"File={file} Keywords={string.Join("|", foundKeywords)}",
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }

    private static void ScanExternalCheatIndicators(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var baseDir in searchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(baseDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fname = Path.GetFileName(file);

                if (ExternalCheatOffsetFileNames.Contains(fname))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "CS2-Cheat",
                        Title = $"CS2 external cheat offset file: {fname}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = fname,
                        Reason = $"File '{fname}' contains CS2 memory offsets used by external cheats to read game state. " +
                                 "External cheats use these offsets to locate player positions, health, and game objects in cs2.exe memory.",
                        Detail = $"Path={file}",
                    });
                    continue;
                }

                var ext = Path.GetExtension(fname).ToLowerInvariant();
                if (ext != ".py" && ext != ".cpp" && ext != ".c" && ext != ".h") continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();
                }
                catch (IOException) { continue; }

                var lower = content.ToLowerInvariant();
                var hasReadProcessMemory = lower.Contains("readprocessmemory");
                var hasCs2 = lower.Contains("cs2.exe") || lower.Contains("counter-strike");
                var hasCheatFeature = lower.Contains("aimbot") || lower.Contains("esp") || lower.Contains("wallhack");

                if (hasReadProcessMemory && hasCs2 && hasCheatFeature)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "CS2-Cheat",
                        Title = $"CS2 external cheat source code: {fname}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fname,
                        Reason = $"Source code file '{fname}' contains ReadProcessMemory combined with CS2 process references " +
                                 "and cheat feature keywords. This is consistent with an external CS2 memory-reading cheat.",
                        Detail = $"Path={file} ReadPM={hasReadProcessMemory} CS2={hasCs2} Features={hasCheatFeature}",
                    });
                    continue;
                }

                ScanFileForOffsetPattern(ctx, file, fname, lower);
            }
        }
    }

    private static void ScanFileForOffsetPattern(ScanContext ctx, string filePath, string fname, string contentLower)
    {
        var ext = Path.GetExtension(fname).ToLowerInvariant();
        if (ext != ".json" && ext != ".ini" && ext != ".cfg" && ext != ".hpp" && ext != ".h") return;

        var hexCount = 0;
        var searchIndex = 0;
        while (searchIndex < contentLower.Length - 3)
        {
            var pos = contentLower.IndexOf("0x", searchIndex, StringComparison.OrdinalIgnoreCase);
            if (pos < 0) break;
            var afterPrefix = pos + 2;
            var end = afterPrefix;
            while (end < contentLower.Length && end < afterPrefix + 8)
            {
                var c = contentLower[end];
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
                    end++;
                else
                    break;
            }
            if (end - afterPrefix >= 4)
                hexCount++;
            searchIndex = end;
            if (hexCount >= 10) break;
        }

        if (hexCount < 10) return;

        ctx.AddFinding(new Finding
        {
            Module = "CS2-Cheat",
            Title = $"CS2 cheat offset config (10+ hex values): {fname}",
            Risk = RiskLevel.Medium,
            Location = filePath,
            FileName = fname,
            Reason = $"File '{fname}' contains {hexCount}+ hexadecimal offset values (0xNNNNNN). " +
                     "This pattern is characteristic of CS2 external cheat offset configuration files " +
                     "used to locate game state in process memory.",
            Detail = $"Path={filePath} HexOffsetCount>={hexCount}",
        });
    }

    private static void ScanWorkshopArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var steamApps = FindSteamAppsPath();
        if (steamApps == null) return;

        var workshopDir = Path.Combine(steamApps, "workshop", "content", "730");
        if (!Directory.Exists(workshopDir)) return;

        string[] workshopItemDirs;
        try
        {
            workshopItemDirs = Directory.GetDirectories(workshopDir);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var itemDir in workshopItemDirs)
        {
            ct.ThrowIfCancellationRequested();
            var itemName = Path.GetFileName(itemDir);

            try
            {
                foreach (var dllFile in Directory.GetFiles(itemDir, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = "CS2-Cheat",
                        Title = $"DLL inside CS2 Workshop content: {Path.GetFileName(dllFile)}",
                        Risk = RiskLevel.Medium,
                        Location = dllFile,
                        FileName = Path.GetFileName(dllFile),
                        Reason = "A DLL file was found inside CS2 Steam Workshop content (App 730). " +
                                 "Workshop items should not contain DLL files — this is highly unusual and may indicate " +
                                 "a cheat payload disguised as workshop content.",
                        Detail = $"WorkshopItem={itemName} DLL={dllFile}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var cfgFile in Directory.GetFiles(itemDir, "*.cfg", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();
                    }
                    catch (IOException) { continue; }

                    if (!content.ToLowerInvariant().Contains("sv_cheats 1")) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "CS2-Cheat",
                        Title = $"CS2 Workshop CFG with sv_cheats 1: {Path.GetFileName(cfgFile)}",
                        Risk = RiskLevel.Medium,
                        Location = cfgFile,
                        FileName = Path.GetFileName(cfgFile),
                        Reason = "A CS2 Steam Workshop config file contains 'sv_cheats 1'. " +
                                 "This command enables cheat console variables and can be exploited via workshop-delivered scripts.",
                        Detail = $"WorkshopItem={itemName} CFG={cfgFile}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            ScanWorkshopScriptsForCheatKeywords(ctx, itemDir, itemName, ct);
        }
    }

    private static void ScanWorkshopScriptsForCheatKeywords(ScanContext ctx, string itemDir, string itemName, CancellationToken ct)
    {
        var scriptExtensions = new[] { "*.lua", "*.js", "*.vdf", "*.txt" };

        foreach (var ext in scriptExtensions)
        {
            string[] scriptFiles;
            try { scriptFiles = Directory.GetFiles(itemDir, ext, SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var scriptFile in scriptFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();
                }
                catch (IOException) { continue; }

                var lower = content.ToLowerInvariant();
                var hasAimbot = lower.Contains("aimbot");
                var hasEsp = lower.Contains("esp");
                if (!hasAimbot && !hasEsp) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "CS2-Cheat",
                    Title = $"CS2 Workshop script with cheat keywords: {Path.GetFileName(scriptFile)}",
                    Risk = RiskLevel.Medium,
                    Location = scriptFile,
                    FileName = Path.GetFileName(scriptFile),
                    Reason = $"CS2 Steam Workshop script file contains cheat keywords (aimbot={hasAimbot}, esp={hasEsp}). " +
                             "Cheat-related scripts embedded in Workshop content can deliver unauthorized game advantages.",
                    Detail = $"WorkshopItem={itemName} Script={scriptFile} Aimbot={hasAimbot} ESP={hasEsp}",
                });
            }
        }
    }

    private static void ScanRunningProcessesAndPrefetch(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var snapshot = ctx.GetProcessSnapshot();

        foreach (var proc in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            var procExe = proc.ProcessName + ".exe";
            if (!KnownCheatExeNames.Contains(procExe)) continue;

            string procPath;
            try { procPath = proc.MainModule?.FileName ?? string.Empty; }
            catch { procPath = string.Empty; }

            ctx.AddFinding(new Finding
            {
                Module = "CS2-Cheat",
                Title = $"CS2 cheat process ACTIVELY RUNNING: {proc.ProcessName}",
                Risk = RiskLevel.Critical,
                Location = string.IsNullOrEmpty(procPath) ? $"PID {proc.Id}" : procPath,
                FileName = procExe,
                Reason = $"Known CS2 cheat process '{proc.ProcessName}' (PID {proc.Id}) is currently running. " +
                         "This is direct evidence of an active CS2 cheat session.",
                Detail = $"PID={proc.Id} Name={proc.ProcessName} Path={procPath}",
            });
        }

        ScanPrefetchFiles(ctx, ct);
    }

    private static void ScanPrefetchFiles(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        string[] prefetchFiles;
        try
        {
            prefetchFiles = Directory.GetFiles(prefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var pfFile in prefetchFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var pfName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();

            string? matchedPattern = null;
            foreach (var pattern in PrefetchPatterns)
            {
                if (pfName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    matchedPattern = pattern;
                    break;
                }
            }

            if (matchedPattern == null) continue;

            ctx.AddFinding(new Finding
            {
                Module = "CS2-Cheat",
                Title = $"CS2 cheat Prefetch artifact: {Path.GetFileName(pfFile)}",
                Risk = RiskLevel.High,
                Location = pfFile,
                FileName = Path.GetFileName(pfFile),
                Reason = $"Windows Prefetch file '{Path.GetFileName(pfFile)}' indicates that a CS2 cheat tool " +
                         $"matching pattern '{matchedPattern}' was previously executed on this machine. " +
                         "Prefetch files persist as forensic evidence even after the cheat binary is deleted.",
                Detail = $"PrefetchFile={pfFile} Pattern={matchedPattern}",
            });
        }
    }

    private static string? FindSteamAppsPath()
    {
        using var steamKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam");
        var steamPath = steamKey?.GetValue("SteamPath") as string;
        if (!string.IsNullOrEmpty(steamPath))
        {
            var candidate = Path.Combine(steamPath, "steamapps");
            if (Directory.Exists(candidate)) return candidate;
        }

        var fallbackPaths = new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps",
            @"C:\Program Files\Steam\steamapps",
            @"D:\Steam\steamapps",
            @"D:\SteamLibrary\steamapps",
            @"E:\Steam\steamapps",
            @"E:\SteamLibrary\steamapps",
        };

        return fallbackPaths.FirstOrDefault(Directory.Exists);
    }
}
