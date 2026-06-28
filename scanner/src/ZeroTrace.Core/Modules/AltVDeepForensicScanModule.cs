using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class AltVDeepForensicScanModule : IScanModule
{
    public string Name => "alt:V Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatResourceNames = new[]
    {
        "cheat", "hack", "esp", "aimbot", "wallhack", "noclip", "godmode", "bypass",
        "inject", "trainer", "menu", "mod", "exploit", "speedhack", "bhop",
        "triggerbot", "spinbot", "silentaim", "teleport", "unban", "spoof", "hwid",
        "radar", "overlay", "evade", "anticheat_bypass", "ac_bypass",
        "altv_cheat", "altv_hack", "altv_esp", "altv_bypass",
        "money_drop", "rp_drop", "recovery", "unlocker", "unlock_all",
        "vehicle_spawn", "weapon_give", "godmod", "invincible",
        "nocollision", "superrun", "superjump", "nofalldown",
    };

    private static readonly string[] CheatJSKeywords = new[]
    {
        "alt.emit", "alt.on", "alt.onServer", "alt.emitServer",
        "game.getEntityFromScriptId", "game.invokeNative",
        "game.setPedComponentVariation", "game.giveWeaponToPed",
        "game.setEntityCoords", "game.setPlayerInvincible",
        "game.addExplosion", "game.shootSingleBulletBetweenCoords",
        "game.getClosestPed", "game.getPlayerId",
        "esp", "aimbot", "wallhack", "cheat", "hack", "bypass", "inject",
        "speedhack", "noclip", "godmode", "teleport",
        "alt.LocalPlayer.pos", "alt.LocalPlayer.health",
        "natives.setEntityCoords", "natives.giveWeaponToPed",
        "natives.setPedMaxHealth", "natives.addExplosion",
        "setImmediate.*cheat", "setInterval.*esp",
    };

    private static readonly string[] CheatCSKeywords = new[]
    {
        "AltV.Net", "Alt.Emit", "Alt.On", "Alt.EmitServer",
        "RAGE.NativeHashes", "Function.Call",
        "SetEntityCoords", "GiveWeaponToPed", "SetPlayerInvincible",
        "GetClosestPed", "GetNearbyEntities", "AddExplosion",
        "esp", "aimbot", "wallhack", "cheat", "hack", "bypass",
        "noclip", "godmode", "speedhack", "teleport",
        "[Command.*cheat]", "[Command.*hack]",
        "Bypass", "AntiCheat", "Inject",
    };

    private static readonly string[] AltVCheatServerHosts = new[]
    {
        "altv-cheat", "altv-hack", "alt-cheat", "alt-hack",
        "altv-esp", "altv-inject", "altv-bypass",
        "altv_cheat", "altv_hack",
        "kiddion", "stand.gg", "cherax", "2take1",
        "mpgh", "unknowncheats",
        "cheat-altv", "hack-altv",
    };

    private static readonly string[] AltVPaths = new[]
    {
        @"AppData\Roaming\altv",
        @"AppData\Local\altv",
        @"AppData\Roaming\alt-v",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAltVResourceManifests(ctx, ct),
            CheckAltVClientJSScripts(ctx, ct),
            CheckAltVCSharpResources(ctx, ct),
            CheckAltVServerHistory(ctx, ct),
            CheckAltVLogs(ctx, ct),
            CheckAltVPlugins(ctx, ct),
            CheckAltVConfig(ctx, ct),
            CheckAltVCEFCache(ctx, ct),
            CheckAltVCrashDumps(ctx, ct),
            CheckAltVNPMPackages(ctx, ct),
            CheckAltVDownloadedCheats(ctx, ct),
            CheckAltVRegistryArtifacts(ctx, ct),
            CheckAltVScreenshotBypass(ctx, ct),
            CheckAltVAntiCheatBypass(ctx, ct),
            CheckAltVProxyDLLs(ctx, ct),
            CheckAltVVoiceBypass(ctx, ct),
            CheckAltVCustomBinaries(ctx, ct),
            CheckAltVUpdateArtifacts(ctx, ct)
        );
    }

    private Task CheckAltVResourceManifests(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string resourcePath = Path.Combine(userProfile, altVRelPath, "resources");
            if (!Directory.Exists(resourcePath)) continue;

            foreach (string manifestFile in Directory.GetFiles(resourcePath, "resource.cfg", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(resourcePath, "*.toml", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string resourceDir = Path.GetDirectoryName(manifestFile) ?? string.Empty;
                string resourceName = Path.GetFileName(resourceDir).ToLowerInvariant();
                try
                {
                    using var fs = new FileStream(manifestFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (string cheatName in CheatResourceNames)
                    {
                        if (resourceName.Contains(cheatName, StringComparison.OrdinalIgnoreCase) ||
                            content.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V Resource Manifest — Cheat Resource",
                                Risk = RiskLevel.Critical,
                                Location = manifestFile,
                                FileName = Path.GetFileName(manifestFile),
                                Reason = $"alt:V resource manifest contains cheat keyword: '{cheatName}'",
                                Detail = $"Resource '{resourceName}' — cheat resources run as part of the alt:V client"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVClientJSScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string resourcePath = Path.Combine(userProfile, altVRelPath, "resources");
            if (!Directory.Exists(resourcePath)) continue;

            int scanned = 0;
            foreach (string jsFile in Directory.GetFiles(resourcePath, "*.js", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(resourcePath, "*.mjs", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested || scanned > 500) break;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    int matchCount = 0;
                    string? lastKw = null;
                    foreach (string kw in CheatJSKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase)) { matchCount++; lastKw = kw; }
                    }

                    if (matchCount >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Client JS — Cheat Script",
                            Risk = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"alt:V JS resource uses {matchCount} cheat API patterns (last: '{lastKw}')",
                            Detail = "alt:V client-side JavaScript with multiple cheat native call patterns detected"
                        });
                    }
                    else if (matchCount >= 1 &&
                             CheatResourceNames.Any(c => content.Contains(c, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Client JS — Suspicious Cheat Pattern",
                            Risk = RiskLevel.High,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"alt:V JS combines native API with cheat keywords (last: '{lastKw}')",
                            Detail = "alt:V JavaScript resource contains cheat-related native calls and cheat keywords"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVCSharpResources(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string resourcePath = Path.Combine(userProfile, altVRelPath, "resources");
            if (!Directory.Exists(resourcePath)) continue;

            foreach (string dllFile in Directory.GetFiles(resourcePath, "*.dll", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string dllName = Path.GetFileName(dllFile).ToLowerInvariant();

                foreach (string cheatName in CheatResourceNames)
                {
                    if (dllName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V C# Resource DLL — Cheat Name",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Reason = $"alt:V C# resource DLL matches cheat pattern: '{cheatName}'",
                            Detail = "alt:V C# resource DLLs run directly in the game process and can implement any cheat"
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

                    int matches = CheatCSKeywords.Count(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (matches >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V C# DLL — Cheat API Patterns",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Reason = $"alt:V C# DLL contains {matches} cheat-related API patterns",
                            Detail = "C# DLL with multiple alt:V cheat API patterns detected in binary content"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVServerHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            foreach (string histFile in new[]
            {
                Path.Combine(userProfile, altVRelPath, "config.cfg"),
                Path.Combine(userProfile, altVRelPath, "altv.cfg"),
                Path.Combine(userProfile, altVRelPath, "server-history.json"),
                Path.Combine(userProfile, altVRelPath, "recent-servers.json"),
            }.Where(File.Exists))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(histFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (string cheatHost in AltVCheatServerHosts)
                    {
                        if (content.Contains(cheatHost, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V Server History — Cheat Server",
                                Risk = RiskLevel.Critical,
                                Location = histFile,
                                FileName = Path.GetFileName(histFile),
                                Reason = $"alt:V history contains cheat server: '{cheatHost}'",
                                Detail = "alt:V server history proves connection to cheat-providing servers"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string logPath = Path.Combine(userProfile, altVRelPath);
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

                    foreach (string cheatKw in CheatResourceNames)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V Log — Cheat Resource Reference",
                                Risk = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"alt:V log file references cheat keyword: '{cheatKw}'",
                                Detail = "alt:V log entries naming cheat resources prove the cheat was loaded and active"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVPlugins(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string pluginPath = Path.Combine(userProfile, altVRelPath, "plugins");
            if (!Directory.Exists(pluginPath)) continue;

            foreach (string dllFile in Directory.GetFiles(pluginPath, "*.dll", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string dllName = Path.GetFileName(dllFile).ToLowerInvariant();

                foreach (string cheatName in CheatResourceNames)
                {
                    if (dllName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Plugin DLL — Cheat Library",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Reason = $"alt:V plugin DLL matches cheat pattern: '{cheatName}'",
                            Detail = "alt:V plugin DLLs are loaded into the game process and can implement any cheat"
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

                    if (CheatCSKeywords.Count(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)) >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Plugin DLL — Cheat API Usage",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Reason = "alt:V plugin DLL binary contains multiple cheat API patterns",
                            Detail = "Plugin DLL with cheat-related alt:V API calls detected in binary"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVConfig(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] configCheatKeywords = new[]
        {
            "bypass", "cheat", "hack", "inject", "no_anticheat",
            "disable_anticheat", "disable_protection",
            "no_screenshot", "screenshot_bypass",
            "devMode", "debug", "unsafe",
        };
        foreach (string altVRelPath in AltVPaths)
        {
            string basePath = Path.Combine(userProfile, altVRelPath);
            if (!Directory.Exists(basePath)) continue;

            foreach (string configFile in Directory.GetFiles(basePath, "*.cfg", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(basePath, "*.toml", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(basePath, "*.json", SearchOption.TopDirectoryOnly)))
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
                                Title = "alt:V Config — Cheat/Bypass Setting",
                                Risk = RiskLevel.High,
                                Location = configFile,
                                FileName = Path.GetFileName(configFile),
                                Reason = $"alt:V config contains suspicious setting: '{cfgKw}'",
                                Detail = "alt:V configuration modified to disable security features or enable cheat-compatible mode"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVCEFCache(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string cefPath = Path.Combine(userProfile, altVRelPath, "cache");
            if (!Directory.Exists(cefPath)) continue;

            int scanned = 0;
            foreach (string cacheFile in Directory.GetFiles(cefPath, "f_*", SearchOption.AllDirectories))
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
                    foreach (string cheatKw in CheatResourceNames)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V CEF Cache — Cheat UI Artifact",
                                Risk = RiskLevel.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason = $"alt:V CEF cache contains cheat keyword: '{cheatKw}'",
                                Detail = "CEF cache in alt:V stores cheat overlay/menu UI assets"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVCrashDumps(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string crashPath = Path.Combine(userProfile, altVRelPath, "crashes");
            if (!Directory.Exists(crashPath)) continue;
            foreach (string dmpFile in Directory.GetFiles(crashPath, "*.dmp", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "alt:V Crash Dump — Forensic Artifact",
                    Risk = RiskLevel.Medium,
                    Location = dmpFile,
                    FileName = Path.GetFileName(dmpFile),
                    Reason = "alt:V crash dump found — may contain injected cheat module evidence",
                    Detail = "Crash dumps capture process state at crash time including all loaded DLLs"
                });
            }
        }
    }, ct);

    private Task CheckAltVNPMPackages(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string basePath = Path.Combine(userProfile, altVRelPath);
            if (!Directory.Exists(basePath)) continue;

            foreach (string pkgJson in Directory.GetFiles(basePath, "package.json", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(pkgJson, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string cheatKw in CheatResourceNames)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V NPM Package — Cheat Dependency",
                                Risk = RiskLevel.High,
                                Location = pkgJson,
                                FileName = Path.GetFileName(pkgJson),
                                Reason = $"alt:V package.json references cheat keyword: '{cheatKw}'",
                                Detail = "NPM package manifest with cheat dependencies indicates a cheat resource project"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVDownloadedCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                if (fileName.Contains("altv", StringComparison.OrdinalIgnoreCase) &&
                    CheatResourceNames.Any(c => fileName.Contains(c, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Downloaded alt:V Cheat File",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Downloaded file matches alt:V cheat pattern: '{fileName}'",
                        Detail = "File with alt:V and cheat keywords in name found in Downloads/Desktop/Temp"
                    });
                }
            }
        }
    }, ct);

    private Task CheckAltVRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (string regPath in new[]
        {
            @"SOFTWARE\altv",
            @"SOFTWARE\alt-v",
            @"SOFTWARE\WOW6432Node\altv",
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
                    foreach (string cheatKw in CheatResourceNames)
                    {
                        if (val.Contains(cheatKw, StringComparison.OrdinalIgnoreCase) ||
                            valueName.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Registry — alt:V Cheat Artifact",
                                Risk = RiskLevel.High,
                                Location = $@"Registry\{regPath}\{valueName}",
                                FileName = valueName,
                                Reason = $"alt:V registry entry contains cheat keyword: '{cheatKw}'",
                                Detail = "alt:V registry configuration modified by cheat tools"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckAltVScreenshotBypass(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string basePath = Path.Combine(userProfile, altVRelPath);
            if (!Directory.Exists(basePath)) continue;
            foreach (string file in Directory.GetFiles(basePath, "*.js", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(basePath, "*.mjs", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if ((content.Contains("screenshot", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("screengrab", StringComparison.OrdinalIgnoreCase)) &&
                        content.Contains("bypass", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V — Screenshot Bypass Artifact",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "alt:V script contains screenshot bypass logic",
                            Detail = "Screenshot bypass hides cheat overlays from server-side AC screenshot detection"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVAntiCheatBypass(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] bypassKeywords = new[]
        {
            "anticheat_bypass", "ac_bypass", "bypass_ac", "disable_ac",
            "patch_anticheat", "hook_anticheat", "evade_detection",
            "bypass_detection", "no_detection",
        };
        foreach (string altVRelPath in AltVPaths)
        {
            string basePath = Path.Combine(userProfile, altVRelPath);
            if (!Directory.Exists(basePath)) continue;
            foreach (string file in Directory.GetFiles(basePath, "*.js", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(basePath, "*.json", SearchOption.AllDirectories))
                .Concat(Directory.GetFiles(basePath, "*.dll", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);
                    foreach (string bpKw in bypassKeywords)
                    {
                        if (content.Contains(bpKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V — Anti-Cheat Bypass Artifact",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"alt:V file contains anti-cheat bypass keyword: '{bpKw}'",
                                Detail = "Anti-cheat bypass artifacts in alt:V data indicate evasion of server-side detection"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVProxyDLLs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] proxyDllNames = new[]
        {
            "dinput8.dll", "dsound.dll", "winmm.dll", "version.dll",
            "d3d11.dll", "dxgi.dll", "winhttp.dll",
        };
        foreach (string altVRelPath in AltVPaths)
        {
            string basePath = Path.Combine(userProfile, altVRelPath);
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
                    if (CheatResourceNames.Any(c => content.Contains(c, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Root — Proxy DLL with Cheat Strings",
                            Risk = RiskLevel.Critical,
                            Location = dllPath,
                            FileName = proxyDll,
                            Reason = $"Proxy DLL '{proxyDll}' in alt:V root contains cheat strings",
                            Detail = "Proxy DLLs intercept alt:V API calls to inject cheat code into the game process"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVVoiceBypass(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string basePath = Path.Combine(userProfile, altVRelPath);
            if (!Directory.Exists(basePath)) continue;
            foreach (string file in Directory.GetFiles(basePath, "*.js", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    if (content.Contains("voice", StringComparison.OrdinalIgnoreCase) &&
                        (content.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("exploit", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Voice System — Bypass Artifact",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "alt:V script references voice system alongside bypass/exploit",
                            Detail = "alt:V voice/networking bypass can be exploited for cheat synchronization across clients"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAltVCustomBinaries(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] expectedBinaries = new[]
        {
            "altv.exe", "altv-crash-handler.exe", "altv-updater.exe",
            "libcef.dll", "chrome_elf.dll",
        };
        foreach (string altVRelPath in AltVPaths)
        {
            string basePath = Path.Combine(userProfile, altVRelPath);
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
                        Title = "alt:V Directory — Unexpected Executable",
                        Risk = RiskLevel.High,
                        Location = exeFile,
                        FileName = exeName,
                        Reason = $"Unexpected executable in alt:V root: '{exeName}'",
                        Detail = "Non-standard executables in the alt:V directory may be cheat launchers or injectors"
                    });
                }
            }
        }
    }, ct);

    private Task CheckAltVUpdateArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string altVRelPath in AltVPaths)
        {
            string updatePath = Path.Combine(userProfile, altVRelPath);
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
                    foreach (string cheatKw in CheatResourceNames)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V Update Log — Cheat Reference",
                                Risk = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"alt:V update log references cheat: '{cheatKw}'",
                                Detail = "Update logs reveal cheat resources downloaded or updated via the alt:V updater"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);
}
