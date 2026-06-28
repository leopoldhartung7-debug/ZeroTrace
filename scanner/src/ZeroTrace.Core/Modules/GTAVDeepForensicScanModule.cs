using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class GTAVDeepForensicScanModule : IScanModule
{
    public string Name => "GTA V Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] ModMenuConfigFileNames =
    {
        "menyooStuff", "menyoo_config.xml", "SimpList.xml", "trainerv.ini",
        "EnhancedNativeTrainer.ini", "2take1.dll", "Stand.dll", "YimMenu.dll",
        "Eulen.dll", "RedEngine.dll", "Skript.dll", "BrainOBrain.dll",
        "menu_config.json", "trainer_settings.json", "cheat_config.ini",
        "modmenu.ini", "modmenu_config.json", "gtav_menu.cfg"
    };

    private static readonly string[] PremiumMenuDLLNames =
    {
        "2take1.dll", "Stand.dll", "YimMenu.dll", "Eulen.dll", "RedEngine.dll",
        "Skript.dll", "BrainOBrain.dll", "Midnight.dll", "ZeroEvade.dll",
        "Impulse.dll", "Phantom.dll", "Ozark.dll", "Kiddions.dll",
        "Modest_Menu.dll", "KiddionModestMenu.dll"
    };

    private static readonly string[] CheatToolBinaryNames =
    {
        "ScriptHookV.dll", "ScriptHookVDotNet.dll", "ScriptHookVDotNet2.dll",
        "ScriptHookVDotNet3.dll", "NativeTrainer.dll", "asi_loader.dll",
        "dinput8.dll", "dsound.dll", "winmm.dll", "version.dll",
        "binkw64.dll", "d3d11.dll", "dxgi.dll", "xinput1_3.dll"
    };

    private static readonly string[] GTAOnlineCheatKeywords =
    {
        "money_drop", "money_loop", "add_cash", "set_money", "give_weapon",
        "explode_all", "kick_player", "crash_lobby", "modder_detection",
        "god_mode", "no_clip", "teleport_player", "spawn_vehicle",
        "vehicle_godmode", "never_wanted", "always_wanted", "set_wanted",
        "freeze_player", "set_player_model", "session_type", "join_session"
    };

    private static readonly string[] GTAVCheatPrefetchNames =
    {
        "MENYOO", "TRAINERV", "NATIVETRAINER", "YIMMENU", "2TAKE1",
        "STAND_LOADER", "EULEN_LOADER", "REDENGINE", "SKRIPT_LOADER",
        "KIDDION", "MODEST_MENU", "IMPULSE", "OZARK", "PHANTOM"
    };

    private static readonly string[] GTAVCheatRegistryPaths =
    {
        @"Software\2Take1", @"Software\Stand", @"Software\YimMenu",
        @"Software\Eulen", @"Software\RedEngine", @"Software\Skript",
        @"Software\BrainOBrain", @"Software\KiddionModestMenu",
        @"Software\ModMenu", @"Software\GtaModMenu"
    };

    private static readonly string[] SpooferToolNames =
    {
        "gta_spoofer.exe", "hwid_spoofer_gta.exe", "gta5_spoofer.exe",
        "rockstar_spoofer.exe", "sc_spoofer.exe", "socialclub_spoofer.exe",
        "ban_evader_gta.exe", "gta_bypass.exe", "rockstar_bypass.exe"
    };

    private static readonly string[] GTAVNetworkCheatKeywords =
    {
        "session_kick", "packet_flood", "lobby_crash", "otr_money",
        "boss_mode", "ceo_abuse", "vip_abuse", "mc_abuse", "bunker_abuse",
        "nightclub_abuse", "passive_bypass", "ghosting", "dns_spoof_gta"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckGTAVModMenuConfigFiles(ctx, ct),
            CheckScriptHookVArtifacts(ctx, ct),
            CheckGTAVCheatDLLPayloads(ctx, ct),
            CheckGTAVModMenuRegistryArtifacts(ctx, ct),
            CheckGTAVPrefetchCheatArtifacts(ctx, ct),
            CheckGTAVCheatLogFiles(ctx, ct),
            CheckGTAVCheatSaveFiles(ctx, ct),
            CheckGTAVNetworkCheatArtifacts(ctx, ct),
            CheckGTAVSpooferArtifacts(ctx, ct),
            CheckGTAVOnlineCheatScripts(ctx, ct),
            CheckGTAVCheatDownloadArtifacts(ctx, ct),
            CheckGTAVTrainerArtifacts(ctx, ct),
            CheckGTAVASILoaderArtifacts(ctx, ct),
            CheckGTAVCheatEngineFiles(ctx, ct),
            CheckGTAVCrashDumpsFromCheat(ctx, ct),
            CheckRockstarGameLauncherTamper(ctx, ct),
            CheckGTAVCheatCommunityHistory(ctx, ct),
            CheckGTAVBanEvasionArtifacts(ctx, ct)
        );
    }

    private Task CheckGTAVModMenuConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var gtaVDocs = Path.Combine(docs, "Rockstar Games", "GTA V");
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchPaths = new[]
        {
            gtaVDocs,
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.GetTempPath()
        };

        foreach (var searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (var configName in ModMenuConfigFileNames)
            {
                var configPath = Path.Combine(searchPath, configName);
                if (File.Exists(configPath) || Directory.Exists(configPath))
                {
                    ctx.IncrementFiles();
                    bool isPremium = configName.Contains("2take1", StringComparison.OrdinalIgnoreCase) ||
                                     configName.Contains("stand", StringComparison.OrdinalIgnoreCase) ||
                                     configName.Contains("YimMenu", StringComparison.OrdinalIgnoreCase) ||
                                     configName.Contains("Eulen", StringComparison.OrdinalIgnoreCase) ||
                                     configName.Contains("RedEngine", StringComparison.OrdinalIgnoreCase);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = isPremium ? "Premium GTA V mod menu config/artifact" : "GTA V mod menu config file",
                        Risk = isPremium ? RiskLevel.Critical : RiskLevel.High,
                        Location = searchPath,
                        FileName = configName,
                        Reason = $"GTA V mod menu artifact: '{configName}'",
                        Detail = configPath
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckScriptHookVArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchPaths = new[]
        {
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        };

        var shvFiles = new[]
        {
            "ScriptHookV.dll", "ScriptHookVDotNet.dll", "ScriptHookVDotNet2.dll",
            "ScriptHookVDotNet3.dll", "NativeTrainer.dll", "scripthookv.log",
            "ScriptHookVDotNet.log", "asi_list.log"
        };

        foreach (var searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (var shvFile in shvFiles)
            {
                var fullPath = Path.Combine(searchPath, shvFile);
                if (File.Exists(fullPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ScriptHookV artifact in user directory",
                        Risk = RiskLevel.Critical,
                        Location = searchPath,
                        FileName = shvFile,
                        Reason = $"ScriptHookV component found outside game directory: '{shvFile}' — used for GTA V native function execution",
                        Detail = fullPath
                    });
                }
            }
        }

        var logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "Rockstar Games", "GTA V", "scripthookv.log");
        if (File.Exists(logPath))
        {
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);
                if (content.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("failed", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ScriptHookV log file found",
                        Risk = RiskLevel.High,
                        Location = Path.GetDirectoryName(logPath) ?? "",
                        FileName = "scripthookv.log",
                        Reason = "ScriptHookV log exists in GTA V documents folder indicating SHV usage",
                        Detail = logPath
                    });
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckGTAVCheatDLLPayloads(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchPaths = new[]
        {
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
        };

        foreach (var searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (var dllFile in Directory.EnumerateFiles(searchPath, "*.dll", SearchOption.TopDirectoryOnly))
            {
                var dllName = Path.GetFileName(dllFile);
                ctx.IncrementFiles();

                foreach (var premiumDll in PremiumMenuDLLNames)
                {
                    if (dllName.Equals(premiumDll, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Premium GTA V mod menu DLL",
                            Risk = RiskLevel.Critical,
                            Location = searchPath,
                            FileName = dllName,
                            Reason = $"Known premium GTA V mod menu DLL: '{premiumDll}'",
                            Detail = dllFile
                        });
                        break;
                    }
                }

                if (dllName.Contains("menu", StringComparison.OrdinalIgnoreCase) ||
                    dllName.Contains("trainer", StringComparison.OrdinalIgnoreCase) ||
                    dllName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                    dllName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                    dllName.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                    dllName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                    dllName.Contains("gta5", StringComparison.OrdinalIgnoreCase) ||
                    dllName.Contains("gtav", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Suspicious GTA V cheat DLL",
                        Risk = RiskLevel.High,
                        Location = searchPath,
                        FileName = dllName,
                        Reason = "DLL name suggests GTA V cheat payload",
                        Detail = dllFile
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckGTAVModMenuRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var regPath in GTAVCheatRegistryPaths)
        {
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "GTA V mod menu registry key found",
                        Risk = RiskLevel.Critical,
                        Location = $"HKCU\\{regPath}",
                        FileName = regPath.Split('\\').Last(),
                        Reason = $"Registry key indicates GTA V mod menu installation: '{regPath}'",
                        Detail = $"Key has {key.ValueCount} values and {key.SubKeyCount} subkeys"
                    });
                }
            }
            catch (Exception) { }
        }

        ctx.IncrementRegistryKeys();
        try
        {
            using var runKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");
            if (runKey != null)
            {
                foreach (var valueName in runKey.GetValueNames())
                {
                    var val = runKey.GetValue(valueName)?.ToString() ?? "";
                    if ((val.Contains("gta", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("rockstar", StringComparison.OrdinalIgnoreCase)) &&
                        (val.Contains("menu", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("trainer", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("bypass", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "GTA V cheat tool in Run MRU",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                            FileName = valueName,
                            Reason = $"Run MRU entry references GTA V cheat tool: '{val}'",
                            Detail = val
                        });
                    }
                }
            }
        }
        catch (Exception) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckGTAVPrefetchCheatArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var prefetchPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchPath)) return;

        foreach (var pfFile in Directory.EnumerateFiles(prefetchPath, "*.pf", SearchOption.TopDirectoryOnly))
        {
            var pfName = Path.GetFileName(pfFile).ToUpperInvariant();
            ctx.IncrementFiles();

            foreach (var cheatName in GTAVCheatPrefetchNames)
            {
                if (pfName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                {
                    bool isPremium = cheatName is "2TAKE1" or "STAND_LOADER" or "EULEN_LOADER" or "YIMMENU";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = isPremium ? "Premium GTA V mod menu prefetch artifact" : "GTA V cheat tool prefetch artifact",
                        Risk = isPremium ? RiskLevel.Critical : RiskLevel.High,
                        Location = prefetchPath,
                        FileName = Path.GetFileName(pfFile),
                        Reason = $"Prefetch entry indicates GTA V cheat tool execution: '{cheatName}'",
                        Detail = pfFile
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckGTAVCheatLogFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var gtaVPath = Path.Combine(docs, "Rockstar Games", "GTA V");
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var logSearchPaths = new[]
        {
            gtaVPath,
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };

        var cheatLogNames = new[]
        {
            "menyoo.log", "trainerv.log", "NativeTrainer.log", "ScriptHookV.log",
            "2take1.log", "stand.log", "yimmenu.log", "cheat.log", "menu.log",
            "trainer.log", "ENT.log", "EnhancedNativeTrainer.log", "GTAV.log",
            "asi_log.txt", "kiddion.log"
        };

        foreach (var searchPath in logSearchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (var logName in cheatLogNames)
            {
                var logPath = Path.Combine(searchPath, logName);
                if (!File.Exists(logPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "GTA V cheat log file found",
                    Risk = RiskLevel.High,
                    Location = searchPath,
                    FileName = logName,
                    Reason = $"Cheat tool log file indicates '{logName.Replace(".log", "").Replace(".txt", "")}' was used",
                    Detail = logPath
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckGTAVCheatSaveFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var gtaSavePath = Path.Combine(docs, "Rockstar Games", "GTA V", "Profiles");

        if (!Directory.Exists(gtaSavePath)) return;

        foreach (var profileDir in Directory.EnumerateDirectories(gtaSavePath))
        {
            foreach (var saveFile in Directory.EnumerateFiles(profileDir, "*.b*", SearchOption.TopDirectoryOnly))
            {
                ctx.IncrementFiles();
                var fileInfo = new FileInfo(saveFile);
                if (fileInfo.Length < 100 || fileInfo.Length > 50 * 1024 * 1024) continue;

                try
                {
                    using var fs = new FileStream(saveFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var buffer = new byte[Math.Min(4096, (int)fs.Length)];
                    await fs.ReadAsync(buffer, 0, buffer.Length, ct);
                    string content = Encoding.UTF8.GetString(buffer);

                    if (content.Contains("modded", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("trainer", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("cheat", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious GTA V save file content",
                            Risk = RiskLevel.Medium,
                            Location = profileDir,
                            FileName = Path.GetFileName(saveFile),
                            Reason = "Save file contains cheat-indicative strings in header",
                            Detail = saveFile
                        });
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckGTAVNetworkCheatArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchDirs = new[]
        {
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath()
        };

        var networkCheatTools = new[]
        {
            "lobby_finder.exe", "session_finder.exe", "gta_network_tool.exe",
            "gta_packet.exe", "otr_money.exe", "gta_dns.exe", "passive_bypass.exe",
            "gta_dns_spoof.exe", "lobby_filter.exe", "session_manager.exe"
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var toolName in networkCheatTools)
            {
                var toolPath = Path.Combine(dir, toolName);
                if (File.Exists(toolPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "GTA Online network cheat tool",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = toolName,
                        Reason = $"GTA Online network manipulation tool: '{toolName}'",
                        Detail = toolPath
                    });
                }
            }
        }

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var file in Directory.EnumerateFiles(dir, "*.txt", SearchOption.TopDirectoryOnly)
                .Concat(Directory.EnumerateFiles(dir, "*.json", SearchOption.TopDirectoryOnly)))
            {
                var fileName = Path.GetFileName(file);
                ctx.IncrementFiles();
                if (!fileName.Contains("gta", StringComparison.OrdinalIgnoreCase) &&
                    !fileName.Contains("online", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (var kw in GTAVNetworkCheatKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "GTA Online network cheat config",
                                Risk = RiskLevel.High,
                                Location = dir,
                                FileName = fileName,
                                Reason = $"File contains GTA Online network cheat keyword: '{kw}'",
                                Detail = file
                            });
                            break;
                        }
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckGTAVSpooferArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchDirs = new[]
        {
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var file in Directory.EnumerateFiles(dir, "*.*", SearchOption.TopDirectoryOnly))
            {
                var fileName = Path.GetFileName(file);
                ctx.IncrementFiles();
                foreach (var spooferName in SpooferToolNames)
                {
                    if (fileName.Equals(spooferName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "GTA V/Rockstar ban bypass spoofer tool",
                            Risk = RiskLevel.Critical,
                            Location = dir,
                            FileName = fileName,
                            Reason = $"Known GTA V spoofer/ban bypass tool: '{spooferName}'",
                            Detail = file
                        });
                        break;
                    }
                }
                if ((fileName.Contains("spoofer", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("bypass", StringComparison.OrdinalIgnoreCase)) &&
                    (fileName.Contains("gta", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("rockstar", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("sc", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "GTA V spoofer tool artifact",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = fileName,
                        Reason = "File name suggests GTA V/Rockstar ban bypass/spoofer tool",
                        Detail = file
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckGTAVOnlineCheatScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var gtaVPath = Path.Combine(docs, "Rockstar Games", "GTA V");
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var scriptSearchPaths = new[]
        {
            gtaVPath,
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };

        var scriptExtensions = new[] { "*.lua", "*.cs", "*.py", "*.js", "*.txt" };

        foreach (var searchPath in scriptSearchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (var ext in scriptExtensions)
            {
                foreach (var file in Directory.EnumerateFiles(searchPath, ext, SearchOption.TopDirectoryOnly))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        int cheatHits = 0;
                        string firstHit = "";
                        foreach (var kw in GTAOnlineCheatKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                cheatHits++;
                                if (firstHit.Length == 0) firstHit = kw;
                            }
                        }
                        if (cheatHits >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "GTA Online cheat script",
                                Risk = RiskLevel.High,
                                Location = searchPath,
                                FileName = Path.GetFileName(file),
                                Reason = $"Script contains {cheatHits} GTA Online cheat keywords (first: '{firstHit}')",
                                Detail = file
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
        }
    }, ct);

    private Task CheckGTAVCheatDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(profile, "Downloads");

        if (!Directory.Exists(downloads)) return;

        var cheatArchiveKeywords = new[]
        {
            "menyoo", "trainer_v", "trainerv", "2take1", "stand_gta", "yimmenu",
            "eulen", "kiddion", "modest_menu", "gtav_cheat", "gta5_hack",
            "gta_online_hack", "gtao_money", "gta_menu", "gtav_bypass"
        };

        foreach (var file in Directory.EnumerateFiles(downloads, "*.zip", SearchOption.TopDirectoryOnly)
            .Concat(Directory.EnumerateFiles(downloads, "*.rar", SearchOption.TopDirectoryOnly))
            .Concat(Directory.EnumerateFiles(downloads, "*.7z", SearchOption.TopDirectoryOnly))
            .Concat(Directory.EnumerateFiles(downloads, "*.exe", SearchOption.TopDirectoryOnly)))
        {
            var fileName = Path.GetFileName(file);
            ctx.IncrementFiles();
            foreach (var kw in cheatArchiveKeywords)
            {
                if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "GTA V cheat tool download",
                        Risk = RiskLevel.Critical,
                        Location = downloads,
                        FileName = fileName,
                        Reason = $"Downloaded file name matches GTA V cheat pattern: '{kw}'",
                        Detail = file
                    });
                    break;
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckGTAVTrainerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var gtaVPath = Path.Combine(docs, "Rockstar Games", "GTA V");

        if (!Directory.Exists(gtaVPath)) return;

        var trainerFiles = new[]
        {
            "SimpList.xml", "trainerv.ini", "EnhancedNativeTrainer.ini",
            "GTAV.log", "ENT.log", "teleport_list.ini", "vehicle_list.ini",
            "weapon_list.ini", "ped_list.ini", "settings.xml", "favorites.xml"
        };

        foreach (var trainerFile in trainerFiles)
        {
            var trainerPath = Path.Combine(gtaVPath, trainerFile);
            if (!File.Exists(trainerPath)) continue;
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "GTA V trainer artifact in documents",
                Risk = RiskLevel.High,
                Location = gtaVPath,
                FileName = trainerFile,
                Reason = $"Trainer artifact found in GTA V documents folder: '{trainerFile}'",
                Detail = trainerPath
            });
        }

        if (Directory.Exists(Path.Combine(gtaVPath, "menyooStuff")))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Menyoo mod menu directory found",
                Risk = RiskLevel.Critical,
                Location = gtaVPath,
                FileName = "menyooStuff",
                Reason = "Menyoo mod menu configuration directory found in GTA V documents",
                Detail = Path.Combine(gtaVPath, "menyooStuff")
            });
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckGTAVASILoaderArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchDirs = new[]
        {
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath()
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var toolDll in CheatToolBinaryNames)
            {
                var toolPath = Path.Combine(dir, toolDll);
                if (!File.Exists(toolPath)) continue;
                ctx.IncrementFiles();

                bool isRedFlag = toolDll.StartsWith("dinput8", StringComparison.OrdinalIgnoreCase) ||
                                 toolDll.StartsWith("dsound", StringComparison.OrdinalIgnoreCase) ||
                                 toolDll.StartsWith("winmm", StringComparison.OrdinalIgnoreCase);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = isRedFlag ? "DLL hijack position file for GTA V ASI loading" : "GTA V ASI/cheat tool DLL",
                    Risk = isRedFlag ? RiskLevel.Critical : RiskLevel.High,
                    Location = dir,
                    FileName = toolDll,
                    Reason = isRedFlag
                        ? $"'{toolDll}' in user directory is used to hijack DLL loading for ASI/cheat injection"
                        : $"Known GTA V cheat tool DLL: '{toolDll}'",
                    Detail = toolPath
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckGTAVCheatEngineFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchDirs = new[]
        {
            docs,
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var ctFile in Directory.EnumerateFiles(dir, "*.CT", SearchOption.TopDirectoryOnly))
            {
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(ctFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if (content.Contains("GTA5.exe", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("GTAVLauncher.exe", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("FiveM.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Engine table targeting GTA V",
                            Risk = RiskLevel.Critical,
                            Location = dir,
                            FileName = Path.GetFileName(ctFile),
                            Reason = "Cheat Engine .CT file targets GTA5.exe/GTAVLauncher.exe/FiveM.exe",
                            Detail = ctFile
                        });
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckGTAVCrashDumpsFromCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var gtaCrashPath = Path.Combine(docs, "Rockstar Games", "GTA V", "Crashes");

        if (!Directory.Exists(gtaCrashPath)) return;

        var dumpFiles = Directory.EnumerateFiles(gtaCrashPath, "*.dmp", SearchOption.TopDirectoryOnly)
            .Concat(Directory.EnumerateFiles(gtaCrashPath, "*.log", SearchOption.TopDirectoryOnly))
            .ToArray();

        if (dumpFiles.Length >= 5)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Multiple GTA V crash dumps found",
                Risk = RiskLevel.Medium,
                Location = gtaCrashPath,
                FileName = "*.dmp",
                Reason = $"{dumpFiles.Length} crash dumps in GTA V crash folder — may indicate cheat injection causing instability",
                Detail = gtaCrashPath
            });
        }

        foreach (var dumpFile in dumpFiles.Take(5))
        {
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(dumpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var buffer = new byte[Math.Min(8192, (int)fs.Length)];
                await fs.ReadAsync(buffer, 0, buffer.Length, ct);
                string content = Encoding.UTF8.GetString(buffer);

                if (content.Contains("scripthook", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("menyoo", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("trainer", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "GTA V crash dump references cheat tool",
                        Risk = RiskLevel.High,
                        Location = gtaCrashPath,
                        FileName = Path.GetFileName(dumpFile),
                        Reason = "Crash dump contains strings referencing cheat tools in crash context",
                        Detail = dumpFile
                    });
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckRockstarGameLauncherTamper(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        ctx.IncrementRegistryKeys();
        try
        {
            using var rglKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Rockstar Games\Launcher");
            if (rglKey != null)
            {
                var installFolder = rglKey.GetValue("InstallFolder")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(installFolder))
                {
                    foreach (var hijackDll in new[] { "dinput8.dll", "dsound.dll", "winmm.dll", "version.dll" })
                    {
                        var dllPath = Path.Combine(installFolder, hijackDll);
                        if (File.Exists(dllPath))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious DLL in Rockstar Launcher directory",
                                Risk = RiskLevel.Critical,
                                Location = installFolder,
                                FileName = hijackDll,
                                Reason = $"'{hijackDll}' in Rockstar Launcher folder is a DLL hijack position for cheat injection",
                                Detail = dllPath
                            });
                        }
                    }
                }
            }
        }
        catch (Exception) { }

        ctx.IncrementRegistryKeys();
        try
        {
            using var scKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Rockstar Games\Social Club");
            if (scKey != null)
            {
                var installPath = scKey.GetValue("InstallFolder")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(installPath) && Directory.Exists(installPath))
                {
                    var scConfigPath = Path.Combine(installPath, "scui.config.xml");
                    if (File.Exists(scConfigPath))
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(scConfigPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            if (content.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("spoof", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("fake", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Suspicious Rockstar Social Club config",
                                    Risk = RiskLevel.High,
                                    Location = installPath,
                                    FileName = "scui.config.xml",
                                    Reason = "Social Club config file contains suspicious modification keywords",
                                    Detail = scConfigPath
                                });
                            }
                        }
                        catch (Exception) { }
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckGTAVCheatCommunityHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var historyPaths = new[]
        {
            Path.Combine(local, "Google", "Chrome", "User Data", "Default", "History"),
            Path.Combine(local, "Microsoft", "Edge", "User Data", "Default", "History"),
            Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History")
        };

        var gtaCheatDomains = new[]
        {
            "2take1.menu", "stand.gg", "yimmenu.net", "eulen.app", "kiddions.gg",
            "modestmenu.net", "gta5-mods.com", "gtaall.com", "gtainside.com",
            "gta-mod.ru", "gta-cheats.com", "gta-hack.com"
        };

        foreach (var histPath in historyPaths)
        {
            if (!File.Exists(histPath)) continue;
            var tempPath = Path.Combine(Path.GetTempPath(), $"zt_gtav_hist_{Path.GetRandomFileName()}.db");
            try
            {
                File.Copy(histPath, tempPath, true);
                ctx.IncrementFiles();

                using var fs = new FileStream(tempPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true,
                    bufferSize: 65536, leaveOpen: false);
                string content = await sr.ReadToEndAsync(ct);

                foreach (var domain in gtaCheatDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "GTA V cheat site in browser history",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(histPath) ?? "",
                            FileName = "History",
                            Reason = $"Browser history contains visit to GTA V cheat site: '{domain}'",
                            Detail = histPath
                        });
                    }
                }
            }
            catch (Exception) { }
            finally
            {
                try { File.Delete(tempPath); } catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckGTAVBanEvasionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var banEvasionToolNames = new[]
        {
            "rockstar_ban_evader.exe", "gta_ban_bypass.exe", "sc_ban_bypass.exe",
            "socialclub_bypass.exe", "gta_ip_changer.exe", "gta_hwid_bypass.exe",
            "rockstar_hwid_bypass.exe", "gta_account_changer.exe", "sc_multi_acc.exe",
            "gta_fresh_install.exe", "gta_ban_checker.exe"
        };

        var searchDirs = new[]
        {
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Path.GetTempPath()
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var toolName in banEvasionToolNames)
            {
                var toolPath = Path.Combine(dir, toolName);
                if (!File.Exists(toolPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "GTA V ban evasion tool",
                    Risk = RiskLevel.Critical,
                    Location = dir,
                    FileName = toolName,
                    Reason = $"Known GTA V/Rockstar ban evasion tool: '{toolName}'",
                    Detail = toolPath
                });
            }
        }

        ctx.IncrementRegistryKeys();
        try
        {
            using var runKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Run");
            if (runKey != null)
            {
                foreach (var valueName in runKey.GetValueNames())
                {
                    var val = runKey.GetValue(valueName)?.ToString() ?? "";
                    if ((val.Contains("gta", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("rockstar", StringComparison.OrdinalIgnoreCase)) &&
                        (val.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("spoofer", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("evade", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "GTA V ban evasion tool in autostart",
                            Risk = RiskLevel.Critical,
                            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                            FileName = valueName,
                            Reason = $"Autostart entry contains GTA V ban evasion tool reference: '{val}'",
                            Detail = val
                        });
                    }
                }
            }
        }
        catch (Exception) { }

        await Task.CompletedTask;
    }, ct);
}
