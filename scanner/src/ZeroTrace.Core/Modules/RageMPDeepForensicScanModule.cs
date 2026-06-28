using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class RageMPDeepForensicScanModule : IScanModule
{
    public string Name => "RageMP Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatPackageNames = new[]
    {
        "cheat", "hack", "esp", "aimbot", "wallhack", "noclip", "godmode", "bypass",
        "inject", "trainer", "menu", "mod", "exploit", "speedhack", "bhop",
        "triggerbot", "spinbot", "silentaim", "nofall", "vehicle", "teleport",
        "moneymod", "rpmod", "kiddion", "stand", "cherax", "2take1",
        "radar", "overlay", "evade", "unban", "spoof", "hwid",
        "ragemod", "rage_mod", "rage-mod", "ragecheat", "rage_cheat",
        "pvp_cheat", "pvpmod", "ragemp_bypass", "mp_cheat",
        "anticheat_bypass", "ac_bypass", "rage_bypass",
    };

    private static readonly string[] CheatBridgeScriptKeywords = new[]
    {
        "mp.events.add", "mp.players.forEach", "mp.vehicles.forEach",
        "mp.blips.new", "mp.markers.new",
        "PLAYER_PED_ID", "SET_ENTITY_COORDS", "GIVE_WEAPON_TO_PED",
        "SET_PLAYER_INVINCIBLE", "SET_PED_MAX_HEALTH",
        "ADD_EXPLOSION", "SHOOT_SINGLE_BULLET_BETWEEN_COORDS",
        "esp", "aimbot", "wallhack", "godmode", "noclip", "bypass",
        "cheat", "hack", "inject", "speedhack", "teleport",
        "DISABLE_CONTROL_ACTION", "SET_VEHICLE_ENGINE_HEALTH",
        "GET_CLOSEST_PED", "GET_NEARBY_PEDS",
        "SET_ENTITY_ALPHA", "SET_ENTITY_VISIBLE",
        "mp.trigger", "mp.callRemote",
        "require('./cheat')", "require('./hack')", "require('./esp')",
        "module.exports.*cheat", "module.exports.*hack",
        "process.exit.*anticheat", "throw.*anticheat",
    };

    private static readonly string[] RageMPCheatServerHosts = new[]
    {
        "ragemp-cheat", "ragemp-hack", "rage-cheat", "rage-hack",
        "ragemod", "ragecheat", "ragebypass", "ragemp.hack",
        "ragemp-esp", "ragemp-inject",
        "kiddion", "stand.gg", "cherax", "2take1",
        "mpgh", "unknowncheats", "nexusmods",
        "cheat-ragemp", "hack-ragemp",
        "inject-rage", "bypass-rage",
    };

    private static readonly string[] RageMPPaths = new[]
    {
        @"AppData\Roaming\RAGE Multiplayer",
        @"AppData\Local\RAGE Multiplayer",
    };

    private static readonly string[] NativeHashCheatPatterns = new[]
    {
        "0x9A2938DB", "0xD3A7B003", "0xB9EFD6B7", "0xE9F2CF43",
        "0x12A8E5A0", "0xFC8202EF", "0x6ABFA3E0", "0xEB1C5B24",
        "Citizen.InvokeNative", "InvokeNative", "NATIVE_CALL",
        "nativeCall", "native_call", "callNative",
        "0x2F7A49D3", "0x7D40A50F",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckRageMPPackages(ctx, ct),
            CheckRageMPClientScripts(ctx, ct),
            CheckRageMPBridgeScripts(ctx, ct),
            CheckRageMPConfig(ctx, ct),
            CheckRageMPLogs(ctx, ct),
            CheckRageMPCEFCache(ctx, ct),
            CheckRageMPPluginDLLs(ctx, ct),
            CheckRageMPServerHistory(ctx, ct),
            CheckRageMPCrashDumps(ctx, ct),
            CheckRageMPNativeHashPatterns(ctx, ct),
            CheckRageMPLauncherArtifacts(ctx, ct),
            CheckRageMPDownloadedCheats(ctx, ct),
            CheckRageMPRegistryArtifacts(ctx, ct),
            CheckRageMPUpdateArtifacts(ctx, ct),
            CheckRageMPInjectedDLLs(ctx, ct),
            CheckRageMPAntiCheatBypass(ctx, ct),
            CheckRageMPScreenshotBypass(ctx, ct),
            CheckRageMPCustomBinaries(ctx, ct)
        );
    }

    private Task CheckRageMPPackages(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string packagesPath = Path.Combine(userProfile, rageRelPath, "packages");
            if (!Directory.Exists(packagesPath)) continue;

            foreach (string packageDir in Directory.GetDirectories(packagesPath, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string packageName = Path.GetFileName(packageDir).ToLowerInvariant();

                foreach (string cheatName in CheatPackageNames)
                {
                    if (packageName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Package — Cheat Package Installed",
                            Risk = RiskLevel.Critical,
                            Location = packageDir,
                            FileName = packageName,
                            Reason = $"RageMP package directory matches cheat pattern: '{cheatName}'",
                            Detail = "RageMP packages are client-side code bundles — a cheat-named package proves cheat was installed and active"
                        });
                        break;
                    }
                }

                foreach (string scriptFile in new[]
                {
                    Path.Combine(packageDir, "index.js"),
                    Path.Combine(packageDir, "client.js"),
                }.Where(File.Exists))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        int matchCount = 0;
                        string? lastKw = null;
                        foreach (string kw in CheatBridgeScriptKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase)) { matchCount++; lastKw = kw; }
                        }
                        if (matchCount >= 3)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Package Script — Cheat Logic",
                                Risk = RiskLevel.Critical,
                                Location = scriptFile,
                                FileName = Path.GetFileName(scriptFile),
                                Reason = $"Package script contains {matchCount} cheat-related API patterns (last: '{lastKw}')",
                                Detail = $"Package '{packageName}' client script uses multiple cheat native/event API patterns"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
    }, ct);

    private Task CheckRageMPClientScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string clientPath = Path.Combine(userProfile, rageRelPath, "client_packages");
            if (!Directory.Exists(clientPath)) continue;
            foreach (string jsFile in Directory.GetFiles(clientPath, "*.js", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string kw in CheatBridgeScriptKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Client Script — Cheat Code",
                                Risk = RiskLevel.Critical,
                                Location = jsFile,
                                FileName = Path.GetFileName(jsFile),
                                Reason = $"RageMP client script contains cheat keyword: '{kw}'",
                                Detail = "Client-side RageMP JavaScript can implement ESP, aimbot, speedhack and other cheats"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPBridgeScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string bridgePath = Path.Combine(userProfile, rageRelPath, "bridge");
            if (!Directory.Exists(bridgePath)) continue;
            foreach (string jsFile in Directory.GetFiles(bridgePath, "*.js", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string kw in CheatBridgeScriptKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Bridge Script — Cheat Modification",
                                Risk = RiskLevel.Critical,
                                Location = jsFile,
                                FileName = Path.GetFileName(jsFile),
                                Reason = $"RageMP bridge script modified with cheat keyword: '{kw}'",
                                Detail = "RageMP bridge scripts mediate between CEF and game — modification here enables deep cheat integration"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPConfig(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] configCheatKeywords = new[]
        {
            "bypass", "cheat", "hack", "inject", "no_anticheat",
            "disable_anticheat", "disable_protection",
            "no_screenshot", "screenshot_bypass", "dev_mode",
        };
        foreach (string rageRelPath in RageMPPaths)
        {
            string basePath = Path.Combine(userProfile, rageRelPath);
            if (!Directory.Exists(basePath)) continue;
            foreach (string configFile in Directory.GetFiles(basePath, "*.json", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(basePath, "*.cfg", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string cfgKw in configCheatKeywords)
                    {
                        if (content.Contains(cfgKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Config — Cheat/Bypass Setting",
                                Risk = RiskLevel.High,
                                Location = configFile,
                                FileName = Path.GetFileName(configFile),
                                Reason = $"RageMP config contains suspicious setting: '{cfgKw}'",
                                Detail = "RageMP configuration modified to disable security features or enable cheat-compatible settings"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string logPath = Path.Combine(userProfile, rageRelPath);
            if (!Directory.Exists(logPath)) continue;
            foreach (string logFile in Directory.GetFiles(logPath, "*.log", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string cheatHost in RageMPCheatServerHosts)
                    {
                        if (content.Contains(cheatHost, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Log — Cheat Server Connection",
                                Risk = RiskLevel.Critical,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"RageMP log shows connection to cheat server: '{cheatHost}'",
                                Detail = "RageMP logs record all server connections — cheat server references are definitive forensic evidence"
                            });
                            break;
                        }
                    }
                    foreach (string cheatKw in CheatPackageNames)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Log — Cheat Package Reference",
                                Risk = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"RageMP log references cheat package: '{cheatKw}'",
                                Detail = "Log entries naming cheat packages indicate the cheat was loaded and active"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPCEFCache(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string cefCachePath = Path.Combine(userProfile, rageRelPath, "cef_cache");
            if (!Directory.Exists(cefCachePath)) continue;
            int scanned = 0;
            foreach (string cacheFile in Directory.GetFiles(cefCachePath, "f_*", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested || scanned > 200) break;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);
                    foreach (string cheatKw in CheatPackageNames)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP CEF Cache — Cheat UI Artifact",
                                Risk = RiskLevel.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason = $"RageMP CEF cache contains cheat keyword: '{cheatKw}'",
                                Detail = "CEF cache in RageMP stores cheat overlay/menu UI assets loaded from cheat servers"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPPluginDLLs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string pluginPath = Path.Combine(userProfile, rageRelPath, "plugins");
            if (!Directory.Exists(pluginPath)) continue;
            foreach (string dllFile in Directory.GetFiles(pluginPath, "*.dll", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string dllName = Path.GetFileName(dllFile).ToLowerInvariant();
                foreach (string cheatName in CheatPackageNames)
                {
                    if (dllName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Plugin DLL — Cheat Library",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Reason = $"RageMP plugin DLL matches cheat pattern: '{cheatName}'",
                            Detail = "RageMP plugin DLLs are loaded into the game process and can implement any cheat functionality"
                        });
                        break;
                    }
                }
                try
                {
                    using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);
                    if (CheatBridgeScriptKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)) &&
                        (content.Contains("RAGE", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("ragemp", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Plugin DLL — Cheat Native Calls",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Reason = "RageMP plugin DLL references RAGE API alongside cheat-related patterns",
                            Detail = "Plugin DLL hooking the RAGE Multiplayer API with cheat native call patterns"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPServerHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            foreach (string histFile in new[]
            {
                Path.Combine(userProfile, rageRelPath, "config.xml"),
                Path.Combine(userProfile, rageRelPath, "settings.xml"),
                Path.Combine(userProfile, rageRelPath, "recent_servers.json"),
                Path.Combine(userProfile, rageRelPath, "favorites.json"),
            }.Where(File.Exists))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(histFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string cheatHost in RageMPCheatServerHosts)
                    {
                        if (content.Contains(cheatHost, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Server History — Cheat Server",
                                Risk = RiskLevel.Critical,
                                Location = histFile,
                                FileName = Path.GetFileName(histFile),
                                Reason = $"RageMP server history contains cheat server: '{cheatHost}'",
                                Detail = "Server connection history proves active use of RageMP cheat-providing servers"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPCrashDumps(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string crashPath = Path.Combine(userProfile, rageRelPath, "crash_dumps");
            if (!Directory.Exists(crashPath)) continue;
            foreach (string dmpFile in Directory.GetFiles(crashPath, "*.dmp", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RageMP Crash Dump — Forensic Artifact",
                    Risk = RiskLevel.Medium,
                    Location = dmpFile,
                    FileName = Path.GetFileName(dmpFile),
                    Reason = "RageMP crash dump found — may contain cheat module evidence in process memory",
                    Detail = "Crash dumps capture loaded DLLs and memory state — may reveal injected cheat modules"
                });
            }
        }
    }, ct);

    private Task CheckRageMPNativeHashPatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string basePath = Path.Combine(userProfile, rageRelPath);
            if (!Directory.Exists(basePath)) continue;
            foreach (string jsFile in Directory.GetFiles(basePath, "*.js", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string hashPattern in NativeHashCheatPatterns)
                    {
                        if (content.Contains(hashPattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Script — Raw Native Hash Calls",
                                Risk = RiskLevel.High,
                                Location = jsFile,
                                FileName = Path.GetFileName(jsFile),
                                Reason = $"Script uses raw native hash: '{hashPattern}'",
                                Detail = "Direct native hash invocations are used by cheat scripts to call game functions without API restrictions"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPLauncherArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string launcherPath in new[]
        {
            Path.Combine(userProfile, @"AppData\Local\RAGE Multiplayer"),
            Path.Combine(userProfile, @"AppData\Local\ragemp"),
        })
        {
            if (!Directory.Exists(launcherPath)) continue;
            foreach (string exeFile in Directory.GetFiles(launcherPath, "*.exe", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string exeName = Path.GetFileName(exeFile).ToLowerInvariant();
                foreach (string cheatName in CheatPackageNames)
                {
                    if (exeName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Launcher — Cheat Executable",
                            Risk = RiskLevel.Critical,
                            Location = exeFile,
                            FileName = Path.GetFileName(exeFile),
                            Reason = $"Cheat executable in RageMP launcher directory: '{cheatName}'",
                            Detail = "Cheat executables placed in the RageMP launcher directory run alongside the multiplayer client"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckRageMPDownloadedCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string dir in new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, @"AppData\Local\Temp"),
        })
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string file in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string fileName = Path.GetFileName(file).ToLowerInvariant();
                if (fileName.Contains("rage", StringComparison.OrdinalIgnoreCase) &&
                    CheatPackageNames.Any(c => fileName.Contains(c, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Downloaded RageMP Cheat File",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Downloaded file matches RageMP cheat pattern: '{fileName}'",
                        Detail = "File with RageMP and cheat keywords in name found in Downloads/Desktop/Temp"
                    });
                }
            }
        }
    }, ct);

    private Task CheckRageMPRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (string regPath in new[]
        {
            @"SOFTWARE\RAGE Multiplayer",
            @"SOFTWARE\RAGEMP",
            @"SOFTWARE\WOW6432Node\RAGE Multiplayer",
        })
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath) ??
                                Registry.CurrentUser.OpenSubKey(regPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                foreach (string valueName in key.GetValueNames())
                {
                    string val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    foreach (string cheatKw in CheatPackageNames)
                    {
                        if (val.Contains(cheatKw, StringComparison.OrdinalIgnoreCase) ||
                            valueName.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Registry — RageMP Cheat Artifact",
                                Risk = RiskLevel.High,
                                Location = $@"Registry\{regPath}\{valueName}",
                                FileName = valueName,
                                Reason = $"RageMP registry entry contains cheat keyword: '{cheatKw}'",
                                Detail = "RageMP registry configuration modified by cheat tools"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckRageMPUpdateArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string updatePath = Path.Combine(userProfile, rageRelPath, "updater");
            if (!Directory.Exists(updatePath)) continue;
            foreach (string logFile in Directory.GetFiles(updatePath, "*.log", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string cheatKw in CheatPackageNames)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Updater Log — Cheat Update",
                                Risk = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"RageMP updater log references cheat: '{cheatKw}'",
                                Detail = "Update logs reveal cheat packages downloaded or updated via the RageMP updater"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPInjectedDLLs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] proxyDllNames = new[]
        {
            "dinput8.dll", "dsound.dll", "winmm.dll", "version.dll",
            "d3d11.dll", "dxgi.dll", "winhttp.dll",
        };
        foreach (string rageRelPath in RageMPPaths)
        {
            string basePath = Path.Combine(userProfile, rageRelPath);
            if (!Directory.Exists(basePath)) continue;
            foreach (string proxyDll in proxyDllNames)
            {
                string dllPath = Path.Combine(basePath, proxyDll);
                if (!File.Exists(dllPath)) continue;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);
                    if (CheatPackageNames.Any(c => content.Contains(c, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Root — Proxy DLL with Cheat Strings",
                            Risk = RiskLevel.Critical,
                            Location = dllPath,
                            FileName = proxyDll,
                            Reason = $"Proxy DLL '{proxyDll}' in RageMP root contains cheat strings",
                            Detail = "Proxy DLLs in the multiplayer client root intercept API calls to inject cheat code"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPAntiCheatBypass(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] bypassKeywords = new[]
        {
            "anticheat_bypass", "ac_bypass", "disable_ac",
            "bypass_detection", "evade_detection",
            "hook_anticheat", "patch_anticheat",
        };
        foreach (string rageRelPath in RageMPPaths)
        {
            string basePath = Path.Combine(userProfile, rageRelPath);
            if (!Directory.Exists(basePath)) continue;
            foreach (string file in Directory.GetFiles(basePath, "*.js", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(basePath, "*.json", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string bpKw in bypassKeywords)
                    {
                        if (content.Contains(bpKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP — Anti-Cheat Bypass Script",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"RageMP script contains anti-cheat bypass keyword: '{bpKw}'",
                                Detail = "Anti-cheat bypass scripts in RageMP data are used to evade server-side detection"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPScreenshotBypass(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string rageRelPath in RageMPPaths)
        {
            string basePath = Path.Combine(userProfile, rageRelPath);
            if (!Directory.Exists(basePath)) continue;
            foreach (string jsFile in Directory.GetFiles(basePath, "*.js", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if ((content.Contains("screenshot", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("screengrab", StringComparison.OrdinalIgnoreCase)) &&
                        content.Contains("bypass", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP — Screenshot Bypass Artifact",
                            Risk = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = "RageMP script contains screenshot bypass logic",
                            Detail = "Screenshot bypass hides cheat overlays/ESPs from server-side AC screenshot captures"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPCustomBinaries(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] expectedBinaries = new[]
        {
            "RAGEMP.exe", "updater.exe", "browser_sandbox.exe",
            "d3dcompiler_47.dll", "libcef.dll",
        };
        foreach (string rageRelPath in RageMPPaths)
        {
            string basePath = Path.Combine(userProfile, rageRelPath);
            if (!Directory.Exists(basePath)) continue;
            foreach (string exeFile in Directory.GetFiles(basePath, "*.exe", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string exeName = Path.GetFileName(exeFile);
                if (!expectedBinaries.Contains(exeName, StringComparer.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Directory — Unexpected Executable",
                        Risk = RiskLevel.High,
                        Location = exeFile,
                        FileName = exeName,
                        Reason = $"Unexpected executable in RageMP root: '{exeName}'",
                        Detail = "Non-standard executables in the RageMP directory may be cheat launchers or injectors"
                    });
                }
            }
        }
    }, ct);
}
