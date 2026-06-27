using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class DiscordCheatCommunicationScanModule : IScanModule
{
    public string Name => "Discord Cheat Communication Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatServerKeywords = new[]
    {
        "cheat", "hack", "esp", "aimbot", "wallhack", "triggerbot", "spinbot", "bhop", "bunny",
        "inject", "bypass", "spoof", "hwid", "unban", "menu", "mod", "trainer", "lua", "script",
        "fivem", "ragemp", "altv", "gta", "gtav", "rust", "csgo", "cs2", "valorant", "warzone",
        "internal", "external", "kernal", "kernel", "ring0", "driver", "eac", "battleye", "vanguard",
        "detect", "detection", "private", "crack", "cracked", "leaked", "free", "nulled",
        "purchase", "buy", "sub", "subscription", "premium", "vip", "invite", "discord.gg",
        "reshade", "overlay", "radar", "no recoil", "silent aim", "player esp", "item esp",
        "godmode", "noclip", "teleport", "speedhack", "money hack", "rp hack", "cash drop",
    };

    private static readonly string[] CheatPurchaseKeywords = new[]
    {
        "purchase", "bought", "payment", "invoice", "receipt", "order", "checkout", "paypal",
        "crypto", "bitcoin", "btc", "ltc", "monero", "eth", "ethereum", "license", "key",
        "activation", "serial", "hwid reset", "reseller", "voucher", "discount", "promo",
        "trial", "free trial", "cracked", "leaked", "nulled", "free cheat", "working cheat",
        "download link", "mega.nz", "mediafire", "dropbox", "gofile", "sendspace",
    };

    private static readonly string[] KnownCheatDiscordServers = new[]
    {
        "skycheats", "neverlose", "onetap", "projectinfinity", "gamesense", "interwebz",
        "aimware", "fatality", "supremacy", "primordial", "csgocheats", "hvh.best",
        "fivemhacks", "lspd", "ragemp hack", "altv hack", "oceancheats", "detect.ac",
        "ketamine", "hyperion", "phantom", "shadow", "ghost", "stealth", "silent",
        "ezfrags", "legitbot", "closet", "legit hack", "legit cheat", "spin", "spinbot",
        "doubletap", "hitscan", "multipoint", "backtrack", "resolver",
    };

    private static readonly string[] DiscordLevelDBPaths = new[]
    {
        @"AppData\Roaming\discord\Local Storage\leveldb",
        @"AppData\Roaming\discordcanary\Local Storage\leveldb",
        @"AppData\Roaming\discordptb\Local Storage\leveldb",
        @"AppData\Roaming\Discord\Local Storage\leveldb",
    };

    private static readonly string[] DiscordCachePaths = new[]
    {
        @"AppData\Roaming\discord\Cache\Cache_Data",
        @"AppData\Roaming\discordcanary\Cache\Cache_Data",
        @"AppData\Roaming\discordptb\Cache\Cache_Data",
    };

    private static readonly string[] DiscordLogPaths = new[]
    {
        @"AppData\Roaming\discord\logs",
        @"AppData\Roaming\discordcanary\logs",
    };

    private static readonly string[] DiscordModulePaths = new[]
    {
        @"AppData\Roaming\discord\modules",
        @"AppData\Roaming\discordcanary\modules",
    };

    private static readonly string[] TokenGrabberIndicators = new[]
    {
        "token", "grabber", "stealer", "webhook", "discord.com/api/webhooks",
        "Authorization", "mfa.", "nfa.", "discordapp",
    };

    private static readonly string[] InjectionModKeywords = new[]
    {
        "betterdiscord", "powercord", "goosecord", "replugged", "vencord",
        "injection", "asar", "app.asar.unpacked", "index.js", "renderer.js",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckDiscordLevelDB(ctx, ct),
            CheckDiscordCacheCheat(ctx, ct),
            CheckDiscordLogsCheat(ctx, ct),
            CheckDiscordInstallArtifacts(ctx, ct),
            CheckDiscordModInjection(ctx, ct),
            CheckDiscordWebhookArtifacts(ctx, ct),
            CheckDiscordTokenGrabberHistory(ctx, ct),
            CheckDiscordAutoStartRegistry(ctx, ct),
            CheckDiscordInviteHistory(ctx, ct),
            CheckDiscordDownloadHistory(ctx, ct),
            CheckDiscordPresenceCheat(ctx, ct),
            CheckBrowserDiscordHistory(ctx, ct),
            CheckDiscordBackupFiles(ctx, ct),
            CheckDiscordCheatScripts(ctx, ct),
            CheckDiscordServerHistoryRegistry(ctx, ct),
            CheckDiscordFriendListCheat(ctx, ct),
            CheckDiscordStorageCheat(ctx, ct),
            CheckDiscordNetworkLogs(ctx, ct)
        );
    }

    private Task CheckDiscordLevelDB(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string dbRelPath in DiscordLevelDBPaths)
        {
            string dbPath = Path.Combine(userProfile, dbRelPath);
            if (!Directory.Exists(dbPath)) continue;

            string[] ldbFiles = Directory.GetFiles(dbPath, "*.ldb", SearchOption.TopDirectoryOnly);
            string[] logFiles = Directory.GetFiles(dbPath, "*.log", SearchOption.TopDirectoryOnly);
            string[] allFiles = ldbFiles.Concat(logFiles).ToArray();

            foreach (string ldbFile in allFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(ldbFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buffer = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
                    int read = await fs.ReadAsync(buffer, 0, buffer.Length, ct);
                    string content = Encoding.UTF8.GetString(buffer, 0, read);
                    string contentLower = content.ToLowerInvariant();

                    foreach (string keyword in CheatServerKeywords)
                    {
                        if (contentLower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Discord LevelDB Cheat Reference",
                                Risk = Risk.High,
                                Location = ldbFile,
                                FileName = Path.GetFileName(ldbFile),
                                Reason = $"Discord local storage contains cheat-related keyword: '{keyword}'",
                                Detail = $"Found in Discord LevelDB storage file — may indicate cheat server membership or purchases"
                            });
                            break;
                        }
                    }

                    foreach (string keyword in CheatPurchaseKeywords)
                    {
                        if (contentLower.Contains(keyword, StringComparison.OrdinalIgnoreCase) &&
                            (contentLower.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                             contentLower.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                             contentLower.Contains("inject", StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Discord Cheat Purchase Evidence",
                                Risk = Risk.Critical,
                                Location = ldbFile,
                                FileName = Path.GetFileName(ldbFile),
                                Reason = $"Discord storage contains cheat purchase keyword: '{keyword}'",
                                Detail = "Evidence of cheat software transaction in Discord local storage"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckDiscordCacheCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string cacheRelPath in DiscordCachePaths)
        {
            string cachePath = Path.Combine(userProfile, cacheRelPath);
            if (!Directory.Exists(cachePath)) continue;

            string[] cacheFiles = Directory.GetFiles(cachePath, "f_*", SearchOption.TopDirectoryOnly);
            int scanned = 0;
            foreach (string cacheFile in cacheFiles)
            {
                if (ct.IsCancellationRequested || scanned > 200) break;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buffer = new byte[Math.Min(fs.Length, 512 * 1024)];
                    int read = await fs.ReadAsync(buffer, 0, buffer.Length, ct);
                    string content = Encoding.UTF8.GetString(buffer, 0, read);

                    foreach (string kw in KnownCheatDiscordServers)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Discord Cache — Known Cheat Server Reference",
                                Risk = Risk.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason = $"Discord cache file references known cheat provider: '{kw}'",
                                Detail = "Cached Discord content matches known cheat community or provider name"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckDiscordLogsCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string logRelPath in DiscordLogPaths)
        {
            string logPath = Path.Combine(userProfile, logRelPath);
            if (!Directory.Exists(logPath)) continue;

            foreach (string logFile in Directory.GetFiles(logPath, "*.log", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    if (content.Contains("guild", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (string kw in CheatServerKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Discord Log — Cheat Guild Activity",
                                    Risk = Risk.Medium,
                                    Location = logFile,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"Discord log file references cheat-related activity: '{kw}'",
                                    Detail = "Discord application log contains references to cheat-related guild or server activity"
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckDiscordInstallArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] discordPaths = new[]
        {
            Path.Combine(userProfile, @"AppData\Local\Discord"),
            Path.Combine(userProfile, @"AppData\Local\DiscordCanary"),
            Path.Combine(userProfile, @"AppData\Roaming\Discord"),
        };

        foreach (string discordPath in discordPaths)
        {
            if (!Directory.Exists(discordPath)) continue;

            string settingsJson = Path.Combine(discordPath, "settings.json");
            if (File.Exists(settingsJson))
            {
                ctx.IncrementFiles();
                try
                {
                    string content = File.ReadAllText(settingsJson);
                    if (content.Contains("DANGEROUS_ENABLE_DEVTOOLS_ONLY_ENABLE_IF_YOU_KNOW_WHAT_YOURE_DOING", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("\"devtools\"", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord DevTools Enabled",
                            Risk = Risk.Medium,
                            Location = settingsJson,
                            FileName = "settings.json",
                            Reason = "Discord developer tools forcefully enabled — used for token extraction",
                            Detail = "DevTools in Discord can be used to extract user tokens for cheat subscriptions or account selling"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckDiscordModInjection(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string modRelPath in DiscordModulePaths)
        {
            string modPath = Path.Combine(userProfile, modRelPath);
            if (!Directory.Exists(modPath)) continue;

            foreach (string injectorKeyword in InjectionModKeywords)
            {
                string[] matchedDirs = Directory.GetDirectories(modPath, "*", SearchOption.AllDirectories)
                    .Where(d => d.Contains(injectorKeyword, StringComparison.OrdinalIgnoreCase))
                    .ToArray();

                foreach (string dir in matchedDirs)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Discord Client Mod Injection Artifact",
                        Risk = Risk.Medium,
                        Location = dir,
                        FileName = Path.GetFileName(dir),
                        Reason = $"Discord modules directory contains client mod: '{injectorKeyword}'",
                        Detail = "Modified Discord client can be used to join private cheat channels or automate purchase flows"
                    });
                }
            }

            string appAsarPath = Path.Combine(modPath.Replace("modules", ""), "app", "app.asar");
            if (File.Exists(appAsarPath))
            {
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(appAsarPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);
                    if (content.Contains("BetterDiscord", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("injection", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord ASAR Modification Detected",
                            Risk = Risk.High,
                            Location = appAsarPath,
                            FileName = "app.asar",
                            Reason = "Discord app.asar contains injection or modification markers",
                            Detail = "The Discord application bundle appears to have been tampered with — common in cheat tools that hook Discord"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckDiscordWebhookArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, @"AppData\Local\Temp"),
        };

        string[] scriptExtensions = new[] { "*.bat", "*.ps1", "*.vbs", "*.js", "*.py", "*.lua" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string ext in scriptExtensions)
            {
                foreach (string scriptFile in Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        if (content.Contains("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("discordapp.com/api/webhooks", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Discord Webhook Script Artifact",
                                Risk = Risk.High,
                                Location = scriptFile,
                                FileName = Path.GetFileName(scriptFile),
                                Reason = "Script file contains Discord webhook URL — used by cheat software for status reporting",
                                Detail = "Cheat tools commonly use Discord webhooks to notify operators of detections, bans, or HWID data"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
    }, ct);

    private Task CheckDiscordTokenGrabberHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string tempPath = Path.Combine(userProfile, @"AppData\Local\Temp");
        if (!Directory.Exists(tempPath)) return;

        foreach (string file in Directory.GetFiles(tempPath, "*", SearchOption.TopDirectoryOnly)
            .Where(f => f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".log", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);
                foreach (string kw in TokenGrabberIndicators)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord Token Grabber Artifact",
                            Risk = Risk.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Temp file contains Discord token grabber indicator: '{kw}'",
                            Detail = "Token grabbers are used to steal Discord accounts for cheat subscription bypass"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckDiscordAutoStartRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        foreach (string runKey in runKeys)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(runKey);
                if (key == null) continue;
                foreach (string valueName in key.GetValueNames())
                {
                    string val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (val.Contains("Discord", StringComparison.OrdinalIgnoreCase) &&
                        (val.Contains("--startup", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("--minimized", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementRegistryKeys();
                        // normal Discord autostart — skip
                        continue;
                    }
                    if (valueName.Contains("discord", StringComparison.OrdinalIgnoreCase) &&
                        !val.Contains("DiscordSetup", StringComparison.OrdinalIgnoreCase) &&
                        !val.Contains("Update.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious Discord Autostart Entry",
                            Risk = Risk.Medium,
                            Location = $@"HKCU\{runKey}\{valueName}",
                            FileName = valueName,
                            Reason = $"Non-standard Discord autostart entry: '{val}'",
                            Detail = "Modified Discord clients used for cheat operations may install custom autostart entries"
                        });
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckDiscordInviteHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] browserPaths = new[]
        {
            Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default\History"),
            Path.Combine(userProfile, @"AppData\Local\Microsoft\Edge\User Data\Default\History"),
            Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles"),
        };

        foreach (string browserPath in browserPaths)
        {
            if (!File.Exists(browserPath) && !Directory.Exists(browserPath)) continue;

            string[] filesToCheck = File.Exists(browserPath)
                ? new[] { browserPath }
                : Directory.GetFiles(browserPath, "places.sqlite", SearchOption.AllDirectories);

            foreach (string histFile in filesToCheck)
            {
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(histFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    if (content.Contains("discord.gg/", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("discord.com/invite/", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (string kw in CheatServerKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Browser History — Discord Cheat Invite",
                                    Risk = Risk.High,
                                    Location = histFile,
                                    FileName = Path.GetFileName(histFile),
                                    Reason = $"Browser history shows Discord invite with cheat keyword: '{kw}'",
                                    Detail = "Discord invite links to cheat servers found in browser navigation history"
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckDiscordDownloadHistory(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] downloadPaths = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, @"AppData\Local\Temp"),
        };

        string[] cheatFileNamePatterns = new[]
        {
            "cheat", "hack", "inject", "bypass", "spoof", "hwid", "unban", "esp",
            "aimbot", "triggerbot", "bhop", "loader", "trainer", "menu", "mod",
            "fivem", "ragemp", "altv", "gta5", "rust", "csgo", "cs2",
        };

        foreach (string dir in downloadPaths)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string file in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string fileName = Path.GetFileName(file).ToLowerInvariant();
                foreach (string pattern in cheatFileNamePatterns)
                {
                    if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat File Downloaded via Discord",
                            Risk = Risk.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Downloaded file name matches cheat pattern: '{pattern}'",
                            Detail = "File name indicates a cheat tool downloaded, likely shared via Discord DM or cheat server"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckDiscordPresenceCheat(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string discordStoragePath = Path.Combine(userProfile, @"AppData\Roaming\discord\storage");
        if (!Directory.Exists(discordStoragePath)) return;

        foreach (string file in Directory.GetFiles(discordStoragePath, "*.json", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                string content = File.ReadAllText(file);
                foreach (string kw in CheatServerKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord Storage — Cheat Reference",
                            Risk = Risk.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Discord storage JSON contains cheat keyword: '{kw}'",
                            Detail = "Discord application storage file contains references related to cheat activity"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBrowserDiscordHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] historyFiles = new[]
        {
            Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default\History"),
            Path.Combine(userProfile, @"AppData\Local\Microsoft\Edge\User Data\Default\History"),
            Path.Combine(userProfile, @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History"),
        };

        foreach (string histFile in historyFiles)
        {
            if (!File.Exists(histFile)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(histFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string kw in KnownCheatDiscordServers)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — Known Cheat Discord Server",
                            Risk = Risk.High,
                            Location = histFile,
                            FileName = Path.GetFileName(histFile),
                            Reason = $"Browser history references known cheat Discord community: '{kw}'",
                            Detail = "Navigation to known cheat provider Discord servers indicates active cheat community membership"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckDiscordBackupFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] backupPaths = new[]
        {
            Path.Combine(userProfile, @"AppData\Roaming\discord"),
            Path.Combine(userProfile, @"AppData\Local\Discord"),
        };

        foreach (string basePath in backupPaths)
        {
            if (!Directory.Exists(basePath)) continue;
            foreach (string file in Directory.GetFiles(basePath, "*.bak", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(basePath, "*.backup", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Discord Backup File Found",
                    Risk = Risk.Low,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = "Discord backup file may preserve cheat communication evidence",
                    Detail = "Backup files can retain cheat server conversations even if original cache was cleared"
                });
            }
        }
    }, ct);

    private Task CheckDiscordCheatScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string pluginsPath = Path.Combine(userProfile, @"AppData\Roaming\BetterDiscord\plugins");
        if (!Directory.Exists(pluginsPath)) return;

        foreach (string pluginFile in Directory.GetFiles(pluginsPath, "*.plugin.js", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(pluginFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);
                foreach (string kw in CheatServerKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "BetterDiscord Plugin — Cheat Reference",
                            Risk = Risk.High,
                            Location = pluginFile,
                            FileName = Path.GetFileName(pluginFile),
                            Reason = $"BetterDiscord plugin references cheat keyword: '{kw}'",
                            Detail = "Custom Discord plugins may be used to automate cheat server interactions or hide activity"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckDiscordServerHistoryRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Discord");
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            foreach (string valueName in key.GetValueNames())
            {
                string val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                foreach (string kw in CheatServerKeywords)
                {
                    if (val.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord Registry — Cheat Reference",
                            Risk = Risk.Medium,
                            Location = $@"HKCU\SOFTWARE\Discord\{valueName}",
                            FileName = valueName,
                            Reason = $"Discord registry value contains cheat keyword: '{kw}'",
                            Detail = "Discord configuration in registry contains cheat-related references"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckDiscordFriendListCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string dbRelPath in DiscordLevelDBPaths)
        {
            string dbPath = Path.Combine(userProfile, dbRelPath);
            if (!Directory.Exists(dbPath)) continue;

            foreach (string ldbFile in Directory.GetFiles(dbPath, "*.ldb", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(ldbFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 1024 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    if ((content.Contains("friend", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("relationship", StringComparison.OrdinalIgnoreCase)) &&
                        CheatServerKeywords.Any(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord Friend List — Cheat Contact",
                            Risk = Risk.Medium,
                            Location = ldbFile,
                            FileName = Path.GetFileName(ldbFile),
                            Reason = "Discord LevelDB contains friend/relationship data alongside cheat keywords",
                            Detail = "Discord friend list may include cheat sellers, developers, or community members"
                        });
                        break;
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckDiscordStorageCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] squirrelPaths = new[]
        {
            Path.Combine(userProfile, @"AppData\Local\Discord"),
            Path.Combine(userProfile, @"AppData\Local\DiscordCanary"),
        };

        foreach (string squirrelPath in squirrelPaths)
        {
            if (!Directory.Exists(squirrelPath)) continue;
            foreach (string updateLog in Directory.GetFiles(squirrelPath, "*.log", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(updateLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string kw in InjectionModKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Discord Updater Log — Injection Artifact",
                                Risk = Risk.High,
                                Location = updateLog,
                                FileName = Path.GetFileName(updateLog),
                                Reason = $"Discord update log references injection keyword: '{kw}'",
                                Detail = "Discord update process logs may reveal tampering with the application (e.g., BetterDiscord injection)"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckDiscordNetworkLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] crashLogPaths = new[]
        {
            Path.Combine(userProfile, @"AppData\Roaming\discord\Crashpad\reports"),
            Path.Combine(userProfile, @"AppData\Roaming\discord\Crashpad"),
        };

        foreach (string crashPath in crashLogPaths)
        {
            if (!Directory.Exists(crashPath)) continue;
            foreach (string crashFile in Directory.GetFiles(crashPath, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(crashFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 512 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string kw in CheatServerKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Discord Crash Report — Cheat Reference",
                                Risk = Risk.Medium,
                                Location = crashFile,
                                FileName = Path.GetFileName(crashFile),
                                Reason = $"Discord crash report contains cheat-related keyword: '{kw}'",
                                Detail = "Discord crash reports can reveal what was running or loaded when the cheat was active"
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
