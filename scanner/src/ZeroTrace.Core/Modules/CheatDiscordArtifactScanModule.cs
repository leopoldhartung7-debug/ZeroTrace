using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CheatDiscordArtifactScanModule : IScanModule
{
    public string Name => "Discord Cheat Artifact Forensic Scan";
    public double Weight => 3.5;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string RoamingAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string TempPath =
        Path.GetTempPath();

    private static readonly string[] DiscordRoots =
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discord"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discordptb"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discordcanary"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Discord"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DiscordPTB"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DiscordCanary"),
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "cheats", "hack", "hacks", "aimbot", "wallhack", "esp",
        "triggerbot", "bunnyhop", "bhop", "no-recoil", "norecoil", "spinbot",
        "spoofer", "hwid", "bypass", "inject", "injector", "loader", "menu",
        "modmenu", "mod menu", "private menu", "internal", "external",
        "crack", "keygen", "unlock", "exploit", "cheatengine", "cheat engine",
        "kiddion", "2take1", "cherax", "ozark", "tsunami", "rxce",
        "yimmenu", "stand menu", "lambda menu", "absolute menu", "spectre menu",
        "susano", "hyperion", "nexus menu", "scarlet", "celestial", "reaper",
        "neverlose", "onetap", "gamesense", "aimware", "fatality",
        "nixware", "lumina", "fecurity", "primordial", "sunset",
        "phoenix cheat", "skycheats", "interium", "skeet",
        "vape client", "liquidbounce", "wurst client", "meteor client",
        "sigma client", "novoline", "aristois",
        "redengine", "eulen", "hammafia", "desudo", "impaught",
        "phantom-x", "hxcheats", "fearless cheat", "lynx cheat",
        "engineowning", "ring-1", "ring1", "blackcell", "ricochet bypass",
        "memprocfs", "pcileech", "dma software", "dmaclient",
        "extremeinjector", "xenos injector", "process injector",
        "manualmap", "manual map", "sxlib", "skeetloader",
        "legitbot", "rage bot", "hvh", "head vs head",
        "skid", "skidded", "leaked", "cracked menu",
        "fivem cheat", "rust hack", "csgo cheat", "cs2 cheat",
        "valorant cheat", "apex cheat", "tarkov cheat",
        "fortnite hack", "warzone cheat", "overwatch cheat",
        "pubg cheat", "r6 cheat", "rainbow six cheat",
        "purchase cheat", "buy cheat", "key shop", "loader shop",
        "crack bypass", "eac bypass", "battleye bypass", "vac bypass",
        "anti-cheat bypass", "anticheat bypass", "be bypass",
        "sellix", "sellauth", "shoppy",
    };

    private static readonly string[] CheatBotCommands =
    {
        ".cheat", ".inject", ".load", ".bypass", ".menu",
        ".loader", ".getkey", ".keygen", ".activate", ".purchase",
        ".buy", ".hwid", ".spoof", ".reset", ".help cheat",
        "!inject", "!load", "!bypass", "!cheat", "!loader",
        "!getkey", "!activate", "!purchase", "!hwid",
        "/inject", "/load", "/bypass", "/cheat", "/loader",
        "/getkey", "/activate", "/purchase",
        "$inject", "$cheat", "$load", "$bypass",
        "-inject", "-load", "-bypass",
    };

    private static readonly string[] DiscordInjectorArtifacts =
    {
        "DiscordInject.exe", "discord_bypass.dll", "discord_inject.dll",
        "DiscordBypass.exe", "discord_hook.dll", "discordpatch.exe",
        "discord_patch.dll", "DiscordHook.dll", "discord_loader.exe",
        "discordinject.exe", "discordmod.dll", "discord_rpc_hook.dll",
        "DiscordTokenGrabber.exe", "discord_stealer.exe",
        "discord_nitro_gen.exe", "nitro_generator.exe",
        "discord_fake.exe", "fake_discord.exe",
        "BetterDiscord.exe", "BetterDiscordSetup.exe",
        "powercord_installer.exe", "GooseMod.exe",
    };

    private static readonly string[] SuspiciousBdPlugins =
    {
        "bd_plugin_cheat.js", "cheat_notifier.js", "cheat_overlay.js",
        "inject_notify.js", "hwid_helper.js", "cheat_purchase.js",
        "loader_helper.js", "key_display.js", "cheat_status.js",
        "bypass_notifier.js", "anti_detection.js", "stealth_plugin.js",
        "token_grabber.js", "discord_logger.js", "keylogger.js",
        "cheat_discord.js", "cheat_bot.js", "rpc_cheat.js",
        "spoofer_helper.js", "cheat_rpc.js", "modmenu_rpc.js",
        "game_status_cheat.js", "cheat_server_notifier.js",
    };

    private static readonly string[] SuspiciousRpcNames =
    {
        "cheat loader", "cheat menu", "injector", "bypass loader",
        "modmenu", "private cheat", "aimbot", "esp loader",
        "spoofer", "hwid bypass", "kiddion", "2take1", "cherax",
        "onetap", "neverlose", "gamesense", "aimware", "fatality",
        "cheat engine", "cheat client", "hack loader",
        "fecurity", "nixware", "lumina", "skeet",
        "loader active", "cheat active", "injected",
    };

    private static readonly string[] KnownCheatInvitePatterns =
    {
        "discord.gg/cheat", "discord.gg/hack", "discord.gg/aimbot",
        "discord.gg/spoofer", "discord.gg/loader", "discord.gg/bypass",
        "discord.gg/inject", "discord.gg/menu",
        "discord.com/invite/cheat", "discord.com/invite/hack",
        "discordapp.com/invite/cheat",
        "kiddion", "2take1", "cherax", "ozark", "neverlose", "onetap",
        "gamesense", "aimware", "fatality", "nixware", "fecurity",
        "lumina", "skeet", "interium", "phoenix-cheat",
    };

    private static readonly string[] PurchaseConfirmationPatterns =
    {
        "payment confirmed", "payment received", "purchase confirmed",
        "order confirmed", "key activated", "hwid registered",
        "license activated", "subscription active", "access granted",
        "your key is", "your license", "activation code",
        "thank you for your purchase", "thank you for buying",
        "sellix", "sellauth", "shoppy.gg", "crypto payment",
        "bitcoin payment", "paypal payment", "order #",
        "invoice", "receipt", "payment successful",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Discord cheat artifact scan");

        await Task.WhenAll(
            CheckDiscordLocalStorage(ctx, ct),
            CheckDiscordCache(ctx, ct),
            CheckDiscordLogs(ctx, ct),
            CheckDiscordSettings(ctx, ct),
            CheckDiscordBotCommandArtifacts(ctx, ct),
            CheckDiscordInstallerArtifacts(ctx, ct),
            CheckBetterDiscordPlugins(ctx, ct),
            CheckDiscordLevelDb(ctx, ct),
            CheckUserAssistDiscord(ctx, ct),
            CheckMuiCacheDiscordTools(ctx, ct),
            CheckTempDiscordDelivered(ctx, ct),
            CheckDiscordCustomRpc(ctx, ct),
            CheckDiscordCheatInvites(ctx, ct),
            CheckDiscordPurchaseConfirmations(ctx, ct)
        );

        ctx.Report(1.0, Name, "Discord cheat artifact scan complete");
    }

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if      (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    private Task CheckDiscordLocalStorage(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;
                var localStorageDir = Path.Combine(root, "Local Storage");
                if (!Directory.Exists(localStorageDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(localStorageDir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext != ".ldb" && ext != ".log" && ext != ".json" && ext != "") continue;

                        var fi = new FileInfo(file);
                        if (fi.Length > 16 * 1024 * 1024) continue;

                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs, Encoding.Latin1);
                            content = sr.ReadToEnd();
                        }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        var lower = content.ToLowerInvariant();
                        foreach (var kw in CheatKeywords)
                        {
                            if (lower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Discord Cheat Artifact Forensic Scan",
                                    Title = $"Discord Local Storage: cheat-related cached content ({kw})",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Discord Local Storage file '{Path.GetFileName(file)}' contains " +
                                             $"cheat-related content matching keyword '{kw}'. " +
                                             "Discord caches message and channel data locally; this artifact " +
                                             "persists even after messages are deleted on the server.",
                                    Detail = $"Path: {file} | Keyword: {kw} | Size: {fi.Length} bytes"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckDiscordCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var suspiciousExtensions = new[] { ".exe", ".dll", ".zip", ".rar", ".7z", ".msi", ".bat", ".ps1", ".vbs" };
            var cheatCacheNamePatterns = new[]
            {
                "cheat", "hack", "inject", "loader", "bypass", "spoofer",
                "aimbot", "wallhack", "modmenu", "kiddion", "cherax", "2take1",
                "ozark", "neverlose", "onetap", "aimware", "fatality",
            };

            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;

                var cacheDirs = new[]
                {
                    Path.Combine(root, "Cache", "Cache_Data"),
                    Path.Combine(root, "Cache"),
                    Path.Combine(root, "GPUCache"),
                    Path.Combine(root, "Code Cache"),
                    Path.Combine(root, "blob_storage"),
                };

                foreach (var cacheDir in cacheDirs)
                {
                    if (!Directory.Exists(cacheDir)) continue;
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(cacheDir).Take(500))
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();

                            var fi = new FileInfo(file);
                            if (fi.Length < 4) continue;
                            if (fi.Length > 32 * 1024 * 1024) continue;

                            string content;
                            try
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs, Encoding.Latin1);
                                content = sr.ReadToEnd();
                            }
                            catch (IOException) { continue; }

                            foreach (var ext in suspiciousExtensions)
                            {
                                if (content.Contains(ext, StringComparison.OrdinalIgnoreCase))
                                {
                                    foreach (var pattern in cheatCacheNamePatterns)
                                    {
                                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                        {
                                            ctx.AddFinding(new Finding
                                            {
                                                Module = "Discord Cheat Artifact Forensic Scan",
                                                Title = $"Discord Cache: cheat file download artifact ({pattern}{ext})",
                                                Risk = RiskLevel.High,
                                                Location = file,
                                                FileName = Path.GetFileName(file),
                                                Reason = $"Discord cache entry references a suspicious file " +
                                                         $"matching '{pattern}' with extension '{ext}'. " +
                                                         "This indicates a cheat-related file may have been " +
                                                         "downloaded or shared via Discord.",
                                                Detail = $"Cache file: {file} | Pattern: {pattern} | Ext: {ext} | Size: {fi.Length}"
                                            });
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }, ct);

    private Task CheckDiscordLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;

                var logDirs = new[]
                {
                    root,
                    Path.Combine(root, "logs"),
                    Path.Combine(root, "app-*"),
                };

                var logFiles = new List<string>();
                try
                {
                    foreach (var f in Directory.EnumerateFiles(root, "*.log", SearchOption.TopDirectoryOnly))
                        logFiles.Add(f);
                }
                catch (UnauthorizedAccessException) { }

                foreach (var versionDir in SafeGetVersionDirs(root))
                {
                    try
                    {
                        foreach (var f in Directory.EnumerateFiles(versionDir, "*.log", SearchOption.TopDirectoryOnly))
                            logFiles.Add(f);
                    }
                    catch (UnauthorizedAccessException) { }
                }

                foreach (var logFile in logFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var invite in KnownCheatInvitePatterns)
                    {
                        if (content.Contains(invite, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Discord Cheat Artifact Forensic Scan",
                                Title = $"Discord Log: cheat server invite artifact ({invite})",
                                Risk = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"Discord log file '{Path.GetFileName(logFile)}' contains a reference " +
                                         $"to known cheat server or brand '{invite}'. " +
                                         "Log files record connection attempts, server joins, and navigation events.",
                                Detail = $"Log: {logFile} | Invite pattern: {invite}"
                            });
                            break;
                        }
                    }

                    foreach (var cmd in CheatBotCommands)
                    {
                        if (content.Contains(cmd, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Discord Cheat Artifact Forensic Scan",
                                Title = $"Discord Log: cheat bot command artifact ({cmd})",
                                Risk = RiskLevel.Medium,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"Discord log file contains cheat bot command '{cmd}'. " +
                                         "This indicates interaction with a Discord cheat distribution bot.",
                                Detail = $"Log: {logFile} | Command: {cmd}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    private Task CheckDiscordSettings(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;

                var settingsFiles = new[]
                {
                    Path.Combine(root, "settings.json"),
                    Path.Combine(root, "Local Storage", "leveldb", "MANIFEST"),
                };

                foreach (var settingsFile in settingsFiles)
                {
                    if (!File.Exists(settingsFile)) continue;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(settingsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var rpc in SuspiciousRpcNames)
                    {
                        if (content.Contains(rpc, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Discord Cheat Artifact Forensic Scan",
                                Title = $"Discord Settings: suspicious custom RPC activity ({rpc})",
                                Risk = RiskLevel.High,
                                Location = settingsFile,
                                FileName = Path.GetFileName(settingsFile),
                                Reason = $"Discord settings file contains suspicious custom Rich Presence (RPC) " +
                                         $"activity name '{rpc}'. Cheat loaders frequently set Discord RPC " +
                                         "to display their product name while active, leaving this artifact " +
                                         "in the settings even after the cheat is removed.",
                                Detail = $"Settings file: {settingsFile} | RPC name: {rpc}"
                            });
                            break;
                        }
                    }

                    if (content.Contains("DISABLE_HARDWARE_ACCELERATION", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("false", StringComparison.OrdinalIgnoreCase))
                    {
                        // Some cheat overlays require GPU acceleration disabled; not conclusive alone
                    }

                    if (content.Contains("\"skipHostUpdate\"", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("true", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Discord Cheat Artifact Forensic Scan",
                            Title = "Discord Settings: auto-update skip enabled (cheat injector artifact)",
                            Risk = RiskLevel.Medium,
                            Location = settingsFile,
                            FileName = Path.GetFileName(settingsFile),
                            Reason = "Discord settings show 'skipHostUpdate' is enabled. Some Discord injectors " +
                                     "disable auto-updates to prevent patching of injected code or to maintain " +
                                     "compatibility with a patched Discord version.",
                            Detail = $"Settings file: {settingsFile}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckDiscordBotCommandArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;

                var sessionStorageDir = Path.Combine(root, "Session Storage");
                if (!Directory.Exists(sessionStorageDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(sessionStorageDir))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fi = new FileInfo(file);
                        if (fi.Length > 8 * 1024 * 1024) continue;

                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs, Encoding.Latin1);
                            content = sr.ReadToEnd();
                        }
                        catch (IOException) { continue; }

                        foreach (var cmd in CheatBotCommands)
                        {
                            if (content.Contains(cmd, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Discord Cheat Artifact Forensic Scan",
                                    Title = $"Discord Session Storage: cheat bot command cached ({cmd})",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Discord session storage contains cheat bot command '{cmd}'. " +
                                             "Session storage caches recently viewed channel content and " +
                                             "interactions, indicating active use of a cheat distribution bot.",
                                    Detail = $"File: {file} | Command: {cmd}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckDiscordInstallerArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchDirs = new[]
            {
                RoamingAppData,
                LocalAppData,
                TempPath,
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        var name = Path.GetFileName(file);
                        foreach (var artifact in DiscordInjectorArtifacts)
                        {
                            if (name.Equals(artifact, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Discord Cheat Artifact Forensic Scan",
                                    Title = $"Discord injector artifact found: {name}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = name,
                                    Reason = $"Known Discord injector or fake Discord artifact '{name}' found at '{file}'. " +
                                             "Discord injectors patch the Discord client to load unauthorized code, " +
                                             "bypass token protection, or integrate with cheat loaders. " +
                                             "This file is a strong indicator of cheat infrastructure.",
                                    Detail = $"Path: {file} | Artifact: {artifact}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var name = Path.GetFileName(file).ToLowerInvariant();
                        if (name.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                            name.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            name.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                            name.Contains("hook", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = "Discord Cheat Artifact Forensic Scan",
                                Title = $"Suspicious DLL in Discord directory: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Suspicious DLL '{Path.GetFileName(file)}' found inside a Discord " +
                                         $"installation directory at '{file}'. Discord does not ship DLLs with " +
                                         "names containing 'inject', 'bypass', 'patch', or 'hook'. " +
                                         "This is consistent with a Discord injector or mod loader.",
                                Detail = $"Path: {file}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckBetterDiscordPlugins(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var bdDirs = new[]
            {
                Path.Combine(RoamingAppData, "BetterDiscord", "plugins"),
                Path.Combine(RoamingAppData, "BetterDiscord", "themes"),
                Path.Combine(RoamingAppData, "BetterDiscord"),
                Path.Combine(LocalAppData, "BetterDiscord", "plugins"),
                Path.Combine(RoamingAppData, "Powercord", "plugins"),
                Path.Combine(RoamingAppData, "GooseMod", "plugins"),
                Path.Combine(RoamingAppData, "Vizality", "addons"),
            };

            foreach (var bdDir in bdDirs)
            {
                if (!Directory.Exists(bdDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(bdDir, "*.js", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var name = Path.GetFileName(file);
                        foreach (var plugin in SuspiciousBdPlugins)
                        {
                            if (name.Equals(plugin, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Discord Cheat Artifact Forensic Scan",
                                    Title = $"Known cheat BetterDiscord plugin: {name}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = name,
                                    Reason = $"BetterDiscord plugin '{name}' matches a known cheat-related plugin. " +
                                             "This plugin is associated with cheat status display, purchase " +
                                             "notifications, loader RPC integration, or credential theft.",
                                    Detail = $"Plugin path: {file}"
                                });
                                break;
                            }
                        }

                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        foreach (var kw in new[] { "cheat", "inject", "bypass", "loader", "aimbot", "spoofer", "hwid" })
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Discord Cheat Artifact Forensic Scan",
                                    Title = $"BetterDiscord plugin with cheat content: {name}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = name,
                                    Reason = $"BetterDiscord plugin '{name}' contains cheat-related keyword '{kw}'. " +
                                             "Plugins can display cheat status, automate cheat bot commands, " +
                                             "or exfiltrate Discord tokens to cheat sellers.",
                                    Detail = $"Plugin: {file} | Keyword: {kw}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckDiscordLevelDb(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;

                var levelDbDir = Path.Combine(root, "Local Storage", "leveldb");
                if (!Directory.Exists(levelDbDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(levelDbDir))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext != ".ldb" && ext != ".log") continue;

                        var fi = new FileInfo(file);
                        if (fi.Length > 24 * 1024 * 1024) continue;

                        byte[] bytes;
                        try { bytes = File.ReadAllBytes(file); }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        var text = Encoding.Latin1.GetString(bytes);

                        foreach (var kw in CheatKeywords)
                        {
                            if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Discord Cheat Artifact Forensic Scan",
                                    Title = $"Discord LevelDB: cheat-related cached content ({kw})",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Discord LevelDB storage file '{Path.GetFileName(file)}' contains " +
                                             $"cheat-related content matching keyword '{kw}'. " +
                                             "LevelDB stores all Discord local data including cached messages, " +
                                             "channel lists, and server metadata. Cheat server memberships, " +
                                             "bot interactions, and purchase messages are cached here.",
                                    Detail = $"LevelDB file: {file} | Keyword: {kw} | Size: {fi.Length} bytes"
                                });
                                break;
                            }
                        }

                        foreach (var invite in KnownCheatInvitePatterns)
                        {
                            if (text.Contains(invite, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Discord Cheat Artifact Forensic Scan",
                                    Title = $"Discord LevelDB: cheat server invite cached ({invite})",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Discord LevelDB file contains cached cheat server reference '{invite}'. " +
                                             "This indicates the user visited or was invited to a known cheat " +
                                             "distribution server.",
                                    Detail = $"LevelDB: {file} | Invite: {invite}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckUserAssistDiscord(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string UserAssistBase =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            var cheatToolsLaunchedAlongsideDiscord = new[]
            {
                "kiddion", "2take1", "cherax", "ozark", "neverlose", "onetap",
                "aimware", "fatality", "gamesense", "nixware", "fecurity", "lumina",
                "spoofer", "injector", "xenos", "extremeinjector", "manualmap",
                "cheatengine", "cheat engine", "x64dbg", "memprocfs",
                "DiscordInject", "discord_bypass", "discord_inject",
                "BetterDiscord", "discordpatch", "discord_hook",
                "discordmod", "GooseMod", "powercord",
            };

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(UserAssistBase, writable: false);
                if (baseKey is null) return;

                foreach (var guidName in baseKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                        if (countKey is null) continue;

                        foreach (var encodedName in countKey.GetValueNames())
                        {
                            ctx.IncrementRegistryKeys();
                            var decoded = Rot13Decode(encodedName);

                            foreach (var tool in cheatToolsLaunchedAlongsideDiscord)
                            {
                                if (decoded.Contains(tool, StringComparison.OrdinalIgnoreCase))
                                {
                                    int runCount = 0;
                                    DateTime? lastRun = null;
                                    try
                                    {
                                        var data = countKey.GetValue(encodedName) as byte[];
                                        if (data is { Length: >= 16 })
                                        {
                                            runCount = BitConverter.ToInt32(data, 4);
                                            var ft = BitConverter.ToInt64(data, 8);
                                            if (ft > 0) lastRun = DateTime.FromFileTimeUtc(ft);
                                        }
                                    }
                                    catch { }

                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Discord Cheat Artifact Forensic Scan",
                                        Title = $"UserAssist: Discord cheat tool executed ({tool})",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKCU\{UserAssistBase}\{guidName}\Count",
                                        FileName = Path.GetFileName(decoded),
                                        Reason = $"UserAssist registry shows execution of '{Path.GetFileName(decoded)}' " +
                                                 $"which matches cheat-Discord-related tool '{tool}' " +
                                                 $"({runCount} runs" +
                                                 (lastRun.HasValue ? $", last: {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                                 "). UserAssist entries persist even after the binary is deleted.",
                                        Detail = $"Decoded: {decoded} | Runs: {runCount} | " +
                                                 $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")} | Tool: {tool}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckMuiCacheDiscordTools(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string MuiCacheKey =
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

            var discordCheatToolNames = new[]
            {
                "DiscordInject", "discord_bypass", "discord_inject", "DiscordBypass",
                "discord_hook", "discordpatch", "discord_patch", "DiscordHook",
                "discord_loader", "discordinject", "discordmod", "discord_rpc_hook",
                "BetterDiscordSetup", "GooseMod", "powercord_installer",
                "discord_stealer", "discord_nitro_gen", "nitro_generator",
                "bd_plugin_cheat", "cheat_notifier",
            };

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(MuiCacheKey, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    var pathLower = valueName.ToLowerInvariant();
                    var friendlyName = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                    var combined = pathLower + " " + friendlyName;

                    foreach (var toolName in discordCheatToolNames)
                    {
                        if (combined.Contains(toolName, StringComparison.OrdinalIgnoreCase))
                        {
                            var dotIdx = valueName.LastIndexOf('.');
                            var cleanPath = (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                                ? valueName[..dotIdx] : valueName;

                            ctx.AddFinding(new Finding
                            {
                                Module = "Discord Cheat Artifact Forensic Scan",
                                Title = $"MuiCache: Discord cheat tool executed ({toolName})",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{MuiCacheKey}",
                                FileName = Path.GetFileName(cleanPath),
                                Reason = $"MuiCache entry shows execution of '{Path.GetFileName(cleanPath)}' " +
                                         $"matching Discord cheat tool name '{toolName}'. " +
                                         "MuiCache persists after the binary is deleted and is a reliable " +
                                         "forensic indicator of program execution.",
                                Detail = $"Path: {cleanPath} | FriendlyName: {friendlyName} | Tool: {toolName} | Exists: {File.Exists(cleanPath)}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckTempDiscordDelivered(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var scanDirs = new[]
            {
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            };

            var cheatExtensions = new[] { ".exe", ".dll", ".zip", ".rar", ".7z", ".bat", ".ps1" };
            var discordDeliveryNames = new[]
            {
                "discord_cheat", "discord_inject", "discord_loader", "discord_bypass",
                "discord_hack", "discord_mod", "discord_keygen", "discord_crack",
                "cheat_from_discord", "download_discord", "discord_purchase",
                "discord_key", "discord_activation", "discord_license",
                "dc_cheat", "dc_loader", "dc_inject", "dc_bypass",
                "cheat_installer", "loader_setup", "bypass_installer",
                "inject_tool", "spoofer_setup", "hwid_spoofer_setup",
                "cheat_setup", "hack_installer", "exploit_setup",
            };

            foreach (var dir in scanDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (!cheatExtensions.Contains(ext)) continue;

                        var nameLower = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();

                        foreach (var pattern in discordDeliveryNames)
                        {
                            if (nameLower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Discord Cheat Artifact Forensic Scan",
                                    Title = $"Temp: Discord-delivered cheat file artifact ({Path.GetFileName(file)})",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"File '{Path.GetFileName(file)}' in temp/downloads directory matches " +
                                             $"pattern '{pattern}' associated with Discord cheat delivery. " +
                                             "Cheats are commonly shared as direct Discord file attachments " +
                                             "and downloaded to temp folders.",
                                    Detail = $"Path: {file} | Pattern: {pattern}"
                                });
                                break;
                            }
                        }

                        foreach (var kw in new[] { "cheat", "hack", "inject", "bypass", "loader", "spoofer", "aimbot" })
                        {
                            if (nameLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                var fi = new FileInfo(file);
                                var age = DateTime.UtcNow - fi.CreationTimeUtc;

                                if (age.TotalDays < 90)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Discord Cheat Artifact Forensic Scan",
                                        Title = $"Temp: recent cheat-named file artifact ({Path.GetFileName(file)})",
                                        Risk = RiskLevel.High,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Recently created file '{Path.GetFileName(file)}' ({age.TotalDays:F0} days old) " +
                                                 $"in a user-writable directory matches cheat keyword '{kw}'. " +
                                                 "This is consistent with a cheat delivered via Discord attachment.",
                                        Detail = $"Path: {file} | Created: {fi.CreationTimeUtc:O} | Age: {age.TotalDays:F0} days"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckDiscordCustomRpc(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;

                var presenceFiles = new List<string>();
                try
                {
                    foreach (var f in Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories))
                        presenceFiles.Add(f);
                }
                catch (UnauthorizedAccessException) { }

                foreach (var presenceFile in presenceFiles.Take(20))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(presenceFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    if (!content.Contains("application_id", StringComparison.OrdinalIgnoreCase) &&
                        !content.Contains("rpc", StringComparison.OrdinalIgnoreCase)) continue;

                    foreach (var rpc in SuspiciousRpcNames)
                    {
                        if (content.Contains(rpc, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Discord Cheat Artifact Forensic Scan",
                                Title = $"Discord RPC config: cheat loader RPC artifact ({rpc})",
                                Risk = RiskLevel.High,
                                Location = presenceFile,
                                FileName = Path.GetFileName(presenceFile),
                                Reason = $"Discord RPC/presence configuration file '{Path.GetFileName(presenceFile)}' " +
                                         $"references cheat-related activity name '{rpc}'. " +
                                         "Cheat loaders integrate Discord Rich Presence to display their " +
                                         "brand while the cheat is active, advertising use to friends.",
                                Detail = $"File: {presenceFile} | RPC: {rpc}"
                            });
                            break;
                        }
                    }
                }
            }

            const string discordRpcRegKey =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\discord.exe";
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(discordRpcRegKey, writable: false)
                             ?? Registry.LocalMachine.OpenSubKey(discordRpcRegKey, writable: false);
                if (key is not null)
                {
                    var path = key.GetValue(null) as string;
                    if (!string.IsNullOrEmpty(path))
                    {
                        var dir = Path.GetDirectoryName(path);
                        if (dir is not null && Directory.Exists(dir))
                        {
                            try
                            {
                                foreach (var dll in Directory.EnumerateFiles(dir, "*.dll"))
                                {
                                    var dllName = Path.GetFileName(dll).ToLowerInvariant();
                                    if (dllName.Contains("rpc", StringComparison.OrdinalIgnoreCase) &&
                                        dllName.Contains("cheat", StringComparison.OrdinalIgnoreCase))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = "Discord Cheat Artifact Forensic Scan",
                                            Title = $"Discord directory: cheat RPC DLL ({Path.GetFileName(dll)})",
                                            Risk = RiskLevel.Critical,
                                            Location = dll,
                                            FileName = Path.GetFileName(dll),
                                            Reason = $"DLL '{Path.GetFileName(dll)}' in Discord installation directory " +
                                                     "has a name suggesting a cheat RPC hook or integration module.",
                                            Detail = $"Path: {dll}"
                                        });
                                    }
                                }
                            }
                            catch (UnauthorizedAccessException) { }
                        }
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckDiscordCheatInvites(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;

                var indexedDbDir = Path.Combine(root, "IndexedDB");
                if (!Directory.Exists(indexedDbDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(indexedDbDir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fi = new FileInfo(file);
                        if (fi.Length > 16 * 1024 * 1024) continue;

                        byte[] bytes;
                        try { bytes = File.ReadAllBytes(file); }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        var text = Encoding.Latin1.GetString(bytes);

                        foreach (var invite in KnownCheatInvitePatterns)
                        {
                            if (text.Contains(invite, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Discord Cheat Artifact Forensic Scan",
                                    Title = $"Discord IndexedDB: cheat invite cached ({invite})",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Discord IndexedDB entry references known cheat distribution " +
                                             $"server or brand '{invite}'. " +
                                             "IndexedDB stores structured browser storage data for the Discord " +
                                             "web app, including server membership and navigation history.",
                                    Detail = $"IndexedDB file: {file} | Invite: {invite}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckDiscordPurchaseConfirmations(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var root in DiscordRoots)
            {
                if (!Directory.Exists(root)) continue;

                var dirsToScan = new[]
                {
                    Path.Combine(root, "Local Storage", "leveldb"),
                    Path.Combine(root, "IndexedDB"),
                    Path.Combine(root, "Session Storage"),
                };

                foreach (var dir in dirsToScan)
                {
                    if (!Directory.Exists(dir)) continue;
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(dir).Take(100))
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();

                            var fi = new FileInfo(file);
                            if (fi.Length > 16 * 1024 * 1024) continue;

                            byte[] bytes;
                            try { bytes = File.ReadAllBytes(file); }
                            catch (IOException) { continue; }
                            catch (UnauthorizedAccessException) { continue; }

                            var text = Encoding.Latin1.GetString(bytes).ToLowerInvariant();

                            bool hasCheatContext = CheatKeywords.Any(k =>
                                text.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (!hasCheatContext) continue;

                            foreach (var pattern in PurchaseConfirmationPatterns)
                            {
                                if (text.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Discord Cheat Artifact Forensic Scan",
                                        Title = $"Discord storage: cheat purchase confirmation cached ({pattern})",
                                        Risk = RiskLevel.Critical,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Discord storage file contains both cheat-related content and " +
                                                 $"purchase/transaction language '{pattern}'. " +
                                                 "This is a strong indicator of a cheat purchase transaction " +
                                                 "conducted via Discord. Purchase confirmations, activation keys, " +
                                                 "and license codes sent via Discord are cached in local storage.",
                                        Detail = $"File: {file} | Purchase pattern: {pattern}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }, ct);

    private static IEnumerable<string> SafeGetVersionDirs(string discordRoot)
    {
        if (!Directory.Exists(discordRoot)) yield break;
        string[] dirs;
        try { dirs = Directory.GetDirectories(discordRoot, "app-*"); }
        catch { yield break; }
        foreach (var d in dirs) yield return d;
    }
}
