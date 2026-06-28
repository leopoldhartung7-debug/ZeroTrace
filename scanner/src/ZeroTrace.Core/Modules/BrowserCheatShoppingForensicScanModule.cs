using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class BrowserCheatShoppingForensicScanModule : IScanModule
{
    public string Name => "Browser Cheat Shopping Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatSiteKeywords = new[]
    {
        "skycheats", "neverlose", "onetap", "projectinfinity", "gamesense",
        "interwebz", "aimware", "fatality", "supremacy", "primordial",
        "csgocheats", "hvh.best", "fivemhacks", "ragemp-cheat",
        "altv-cheat", "oceancheats", "detect.ac",
        "ketamine", "hyperion", "phantom", "shadow", "ghostcheat",
        "stealthcheat", "silentcheat", "ezfrags", "legitbot",
        "doubletap", "hitscan", "multipoint", "backtrack",
        "unknowncheats", "mpgh.net", "hackforums", "nulled.to",
        "cracked.io", "leakforums", "leakgames",
        "cheats4u", "free-cheats", "freecheats",
        "cheat-engine.org", "cheatengine",
        "kiddionsmods", "stand.gg", "eulen.xyz", "disturbed.lol",
        "2take1.menu", "midnight.gg", "cherax.net", "lynxmenu",
        "redengine.cc", "cobramodmenu", "excaliburcheat",
        "buy cheat", "purchase cheat", "cheat subscription",
        "hwid spoofer", "hwid ban", "unban tool", "hwid reset",
        "inject", "injector", "dll inject", "dll injection",
        "bypass eac", "bypass battleye", "bypass vanguard",
        "esp cheat", "aimbot cheat", "wallhack cheat",
        "fivem cheat", "ragemp cheat", "altv cheat",
        "gta5 cheat", "gta online cheat", "gta money",
        "rust cheat", "csgo cheat", "cs2 cheat", "valorant cheat",
        "warzone cheat", "apex cheat", "fortnite cheat",
        "tarkov cheat", "escape from tarkov hack",
        "rainbow six cheat", "r6 cheat",
    };

    private static readonly string[] CheatPaymentKeywords = new[]
    {
        "cheat payment", "hack payment", "cheat purchase", "buy cheat",
        "cheat subscription", "monthly subscription", "cheat invoice",
        "crypto payment", "bitcoin payment", "monero payment",
        "cheat receipt", "cheat order", "cheat checkout",
        "paypal.*cheat", "cashapp.*cheat",
        "cheat license", "cheat key", "activation key",
        "hwid license", "hwid key",
    };

    private static readonly string[] CheatDownloadKeywords = new[]
    {
        "cheat.exe", "hack.exe", "inject.exe", "bypass.exe", "spoof.exe",
        "loader.exe", "injector.exe", "aimbot.exe", "esp.exe",
        "cheat.dll", "hack.dll", "inject.dll", "bypass.dll",
        "cheat.zip", "hack.zip", "cheat.rar", "hack.rar",
        "download cheat", "download hack", "download inject",
        "mega.nz.*cheat", "mediafire.*cheat", "gofile.*cheat",
        "dropbox.*cheat", "sendspace.*cheat",
        "fivem_cheat", "ragemp_cheat", "altv_cheat",
        "gta_cheat", "rust_cheat", "csgo_cheat",
    };

    private static readonly string[] KnownCheatDomains = new[]
    {
        "skycheats.com", "neverlose.cc", "onetap.com", "gamesense.pub",
        "interwebz.cc", "aimware.net", "fatality.win", "hvh.best",
        "unknowncheats.me", "mpgh.net", "hackforums.net", "nulled.to",
        "cracked.io", "kiddionsmods.com", "stand.gg", "eulen.xyz",
        "disturbed.lol", "2take1.menu", "midnight.gg", "cherax.net",
        "lynxmenu.com", "redengine.cc",
        "cheat.gg", "hack.gg", "cheater.fun",
        "fivemhacks.net", "ragecheats.com",
        "oceancheats.net", "detect.ac",
    };

    private static readonly string[] BrowserHistoryPaths = new[]
    {
        @"AppData\Local\Google\Chrome\User Data\Default\History",
        @"AppData\Local\Microsoft\Edge\User Data\Default\History",
        @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History",
        @"AppData\Local\Google\Chrome\User Data\Profile 1\History",
        @"AppData\Local\Google\Chrome\User Data\Profile 2\History",
        @"AppData\Roaming\Opera Software\Opera Stable\History",
        @"AppData\Roaming\Opera Software\Opera GX Stable\History",
        @"AppData\Local\Vivaldi\User Data\Default\History",
    };

    private static readonly string[] BrowserBookmarkPaths = new[]
    {
        @"AppData\Local\Google\Chrome\User Data\Default\Bookmarks",
        @"AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks",
        @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Bookmarks",
        @"AppData\Roaming\Opera Software\Opera Stable\Bookmarks",
        @"AppData\Roaming\Opera Software\Opera GX Stable\Bookmarks",
    };

    private static readonly string[] BrowserDownloadPaths = new[]
    {
        @"AppData\Local\Google\Chrome\User Data\Default\History",
        @"AppData\Local\Microsoft\Edge\User Data\Default\History",
        @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History",
    };

    private static readonly string[] BrowserExtensionPaths = new[]
    {
        @"AppData\Local\Google\Chrome\User Data\Default\Extensions",
        @"AppData\Local\Microsoft\Edge\User Data\Default\Extensions",
        @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckBrowserHistoryCheatSites(ctx, ct),
            CheckBrowserHistoryCheatPayments(ctx, ct),
            CheckBrowserHistoryCheatDownloads(ctx, ct),
            CheckBrowserBookmarksCheat(ctx, ct),
            CheckBrowserExtensionsCheat(ctx, ct),
            CheckBrowserLocalStorageCheat(ctx, ct),
            CheckFirefoxHistoryCheat(ctx, ct),
            CheckFirefoxBookmarksCheat(ctx, ct),
            CheckBrowserDownloadedCheatFiles(ctx, ct),
            CheckBrowserCookieCheatSites(ctx, ct),
            CheckBrowserCacheCheatAssets(ctx, ct),
            CheckBrowserSearchHistoryCheat(ctx, ct),
            CheckBrowserLoginDataCheat(ctx, ct),
            CheckBrowserSyncCheatData(ctx, ct),
            CheckBrowserWebDataCheat(ctx, ct),
            CheckOperaGXCheatHistory(ctx, ct),
            CheckBrowserShortcutsCheat(ctx, ct),
            CheckBrowserIndexedDBCheat(ctx, ct)
        );
    }

    private Task CheckBrowserHistoryCheatSites(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string histRelPath in BrowserHistoryPaths)
        {
            string histPath = Path.Combine(userProfile, histRelPath);
            if (!File.Exists(histPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string domain in KnownCheatDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — Known Cheat Provider Site",
                            Risk = Risk.Critical,
                            Location = histPath,
                            FileName = Path.GetFileName(histPath),
                            Reason = $"Browser history shows visit to known cheat provider: '{domain}'",
                            Detail = "Navigation to known cheat provider websites indicates cheat purchase or download activity"
                        });
                        break;
                    }
                }

                foreach (string keyword in CheatSiteKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — Cheat Site Keyword",
                            Risk = Risk.High,
                            Location = histPath,
                            FileName = Path.GetFileName(histPath),
                            Reason = $"Browser history contains cheat-related keyword: '{keyword}'",
                            Detail = "Browser navigation history shows searches or visits related to cheat tools or services"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBrowserHistoryCheatPayments(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string histRelPath in BrowserHistoryPaths)
        {
            string histPath = Path.Combine(userProfile, histRelPath);
            if (!File.Exists(histPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string payKw in CheatPaymentKeywords)
                {
                    if (content.Contains(payKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — Cheat Payment Evidence",
                            Risk = Risk.Critical,
                            Location = histPath,
                            FileName = Path.GetFileName(histPath),
                            Reason = $"Browser history shows cheat payment activity: '{payKw}'",
                            Detail = "Browser navigation to payment pages for cheat subscriptions is strong evidence of purchase"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBrowserHistoryCheatDownloads(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string histRelPath in BrowserDownloadPaths)
        {
            string histPath = Path.Combine(userProfile, histRelPath);
            if (!File.Exists(histPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string dlKw in CheatDownloadKeywords)
                {
                    if (content.Contains(dlKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Download History — Cheat File",
                            Risk = Risk.Critical,
                            Location = histPath,
                            FileName = Path.GetFileName(histPath),
                            Reason = $"Browser download history contains cheat file reference: '{dlKw}'",
                            Detail = "Browser download database records cheat tool downloads even if the files were later deleted"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBrowserBookmarksCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string bkmkRelPath in BrowserBookmarkPaths)
        {
            string bkmkPath = Path.Combine(userProfile, bkmkRelPath);
            if (!File.Exists(bkmkPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(bkmkPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string domain in KnownCheatDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Bookmarks — Cheat Site Saved",
                            Risk = Risk.High,
                            Location = bkmkPath,
                            FileName = Path.GetFileName(bkmkPath),
                            Reason = $"Browser bookmarks contain cheat provider: '{domain}'",
                            Detail = "Bookmarked cheat sites indicate deliberate, repeated use of cheat services"
                        });
                        break;
                    }
                }

                foreach (string cheatKw in CheatSiteKeywords)
                {
                    if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Bookmarks — Cheat Keyword",
                            Risk = Risk.Medium,
                            Location = bkmkPath,
                            FileName = Path.GetFileName(bkmkPath),
                            Reason = $"Browser bookmarks contain cheat-related keyword: '{cheatKw}'",
                            Detail = "Cheat-related bookmarks indicate intentional navigation to cheat communities"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBrowserExtensionsCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string extRelPath in BrowserExtensionPaths)
        {
            string extPath = Path.Combine(userProfile, extRelPath);
            if (!Directory.Exists(extPath)) continue;

            foreach (string manifestFile in Directory.GetFiles(extPath, "manifest.json", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(manifestFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string[] extCheatKeywords = new[]
                    {
                        "cheat", "hack", "inject", "esp", "aimbot",
                        "game trainer", "game mod", "item esp",
                        "bypass", "exploit", "vpn bypass",
                        "discord token", "token grab", "stealer",
                    };

                    foreach (string extKw in extCheatKeywords)
                    {
                        if (content.Contains(extKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Browser Extension — Cheat/Malicious Keyword",
                                Risk = Risk.High,
                                Location = manifestFile,
                                FileName = Path.GetFileName(manifestFile),
                                Reason = $"Browser extension manifest contains cheat keyword: '{extKw}'",
                                Detail = "Browser extensions with cheat keywords may be used to interact with cheat shopping sites or steal tokens"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckBrowserLocalStorageCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] localStoragePaths = new[]
        {
            @"AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb",
            @"AppData\Local\Microsoft\Edge\User Data\Default\Local Storage\leveldb",
            @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb",
        };

        foreach (string lsRelPath in localStoragePaths)
        {
            string lsPath = Path.Combine(userProfile, lsRelPath);
            if (!Directory.Exists(lsPath)) continue;

            int scanned = 0;
            foreach (string ldbFile in Directory.GetFiles(lsPath, "*.ldb", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(lsPath, "*.log", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested || scanned > 100) break;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(ldbFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 1 * 1024 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string domain in KnownCheatDomains)
                    {
                        if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Browser Local Storage — Cheat Site Data",
                                Risk = Risk.High,
                                Location = ldbFile,
                                FileName = Path.GetFileName(ldbFile),
                                Reason = $"Browser local storage contains data from cheat site: '{domain}'",
                                Detail = "Local storage data from cheat sites may include session tokens, license keys, or HWID data"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFirefoxHistoryCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string ffProfilesPath = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
        if (!Directory.Exists(ffProfilesPath)) return;

        foreach (string placesFile in Directory.GetFiles(ffProfilesPath, "places.sqlite", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(placesFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string domain in KnownCheatDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Firefox History — Cheat Provider Visit",
                            Risk = Risk.Critical,
                            Location = placesFile,
                            FileName = Path.GetFileName(placesFile),
                            Reason = $"Firefox places.sqlite contains cheat provider: '{domain}'",
                            Detail = "Firefox navigation history shows visits to known cheat provider websites"
                        });
                        break;
                    }
                }

                foreach (string cheatKw in CheatSiteKeywords)
                {
                    if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Firefox History — Cheat Site Keyword",
                            Risk = Risk.High,
                            Location = placesFile,
                            FileName = Path.GetFileName(placesFile),
                            Reason = $"Firefox history contains cheat-related keyword: '{cheatKw}'",
                            Detail = "Firefox navigation history contains references to cheat tools or communities"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckFirefoxBookmarksCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string ffProfilesPath = Path.Combine(userProfile, @"AppData\Roaming\Mozilla\Firefox\Profiles");
        if (!Directory.Exists(ffProfilesPath)) return;

        foreach (string bkmkFile in Directory.GetFiles(ffProfilesPath, "*.sqlite", SearchOption.AllDirectories)
            .Where(f => Path.GetFileName(f).StartsWith("places", StringComparison.OrdinalIgnoreCase)))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(bkmkFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string domain in KnownCheatDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Firefox Bookmarks — Cheat Site Saved",
                            Risk = Risk.High,
                            Location = bkmkFile,
                            FileName = Path.GetFileName(bkmkFile),
                            Reason = $"Firefox bookmarks contain cheat provider: '{domain}'",
                            Detail = "Bookmarked cheat sites in Firefox indicate deliberate repeated use"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBrowserDownloadedCheatFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadPath = Path.Combine(userProfile, "Downloads");
        if (!Directory.Exists(downloadPath)) return;

        string[] cheatFilePatterns = new[]
        {
            "cheat", "hack", "inject", "bypass", "spoof", "loader",
            "aimbot", "esp", "wallhack", "triggerbot", "bhop",
            "fivem", "ragemp", "altv", "gta5", "rust", "csgo", "cs2",
            "kiddion", "stand", "eulen", "cherax", "2take1", "midnight",
            "trainer", "menu", "mod", "exploit", "crack", "keygen",
        };

        foreach (string file in Directory.GetFiles(downloadPath, "*", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            string fileName = Path.GetFileName(file).ToLowerInvariant();
            foreach (string pattern in cheatFilePatterns)
            {
                if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Downloads — Cheat Tool File",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Downloaded file matches cheat tool pattern: '{pattern}'",
                        Detail = "File in Downloads folder matches known cheat tool naming patterns"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckBrowserCookieCheatSites(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] cookiePaths = new[]
        {
            @"AppData\Local\Google\Chrome\User Data\Default\Cookies",
            @"AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
            @"AppData\Local\Microsoft\Edge\User Data\Default\Cookies",
            @"AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies",
            @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cookies",
        };

        foreach (string cookieRelPath in cookiePaths)
        {
            string cookiePath = Path.Combine(userProfile, cookieRelPath);
            if (!File.Exists(cookiePath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(cookiePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string domain in KnownCheatDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Cookies — Cheat Site Session",
                            Risk = Risk.Critical,
                            Location = cookiePath,
                            FileName = Path.GetFileName(cookiePath),
                            Reason = $"Browser cookies contain session data for cheat provider: '{domain}'",
                            Detail = "Cookies from cheat provider sites indicate active login sessions — user is a registered member"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBrowserCacheCheatAssets(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] cachePaths = new[]
        {
            @"AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data",
            @"AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data",
        };

        foreach (string cacheRelPath in cachePaths)
        {
            string cachePath = Path.Combine(userProfile, cacheRelPath);
            if (!Directory.Exists(cachePath)) continue;

            int scanned = 0;
            foreach (string cacheFile in Directory.GetFiles(cachePath, "f_*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested || scanned > 300) break;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string domain in KnownCheatDomains)
                    {
                        if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Browser Cache — Cheat Site Asset",
                                Risk = Risk.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason = $"Browser cache contains asset from cheat provider: '{domain}'",
                                Detail = "Cached content from cheat provider sites proves page was loaded and content displayed"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckBrowserSearchHistoryCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string histRelPath in BrowserHistoryPaths)
        {
            string histPath = Path.Combine(userProfile, histRelPath);
            if (!File.Exists(histPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                string[] searchCheatKeywords = new[]
                {
                    "buy cheat fivem", "buy cheat gta", "buy aimbot", "buy esp",
                    "fivem cheat download", "gta cheat download",
                    "best cheat fivem", "undetected cheat",
                    "bypass eac", "bypass battleye",
                    "hwid spoofer free", "hwid ban bypass",
                    "free injector", "free aimbot",
                };

                foreach (string searchKw in searchCheatKeywords)
                {
                    if (content.Contains(searchKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Search — Cheat Purchase Query",
                            Risk = Risk.High,
                            Location = histPath,
                            FileName = Path.GetFileName(histPath),
                            Reason = $"Browser history contains cheat purchase search query: '{searchKw}'",
                            Detail = "Search engine queries for cheat tools indicate active intent to obtain and use cheats"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBrowserLoginDataCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] loginDataPaths = new[]
        {
            @"AppData\Local\Google\Chrome\User Data\Default\Login Data",
            @"AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
            @"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data",
        };

        foreach (string loginRelPath in loginDataPaths)
        {
            string loginPath = Path.Combine(userProfile, loginRelPath);
            if (!File.Exists(loginPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(loginPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string domain in KnownCheatDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Login Data — Cheat Site Credentials Saved",
                            Risk = Risk.Critical,
                            Location = loginPath,
                            FileName = Path.GetFileName(loginPath),
                            Reason = $"Browser saved credentials for cheat provider: '{domain}'",
                            Detail = "Saved login credentials for cheat sites prove registered account membership"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBrowserSyncCheatData(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] syncPaths = new[]
        {
            @"AppData\Local\Google\Chrome\User Data\Default\Sync Data",
            @"AppData\Local\Microsoft\Edge\User Data\Default\Sync Data",
        };

        foreach (string syncRelPath in syncPaths)
        {
            string syncPath = Path.Combine(userProfile, syncRelPath);
            if (Directory.Exists(syncPath))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Browser Sync Data Found",
                    Risk = Risk.Low,
                    Location = syncPath,
                    FileName = "Sync Data",
                    Reason = "Browser sync data directory exists — cheat site history/bookmarks may be synced across devices",
                    Detail = "Browser sync preserves cheat site history across devices and re-populates after clearing local data"
                });
            }
        }
    }, ct);

    private Task CheckBrowserWebDataCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] webDataPaths = new[]
        {
            @"AppData\Local\Google\Chrome\User Data\Default\Web Data",
            @"AppData\Local\Microsoft\Edge\User Data\Default\Web Data",
        };

        foreach (string webDataRelPath in webDataPaths)
        {
            string webDataPath = Path.Combine(userProfile, webDataRelPath);
            if (!File.Exists(webDataPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(webDataPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string domain in KnownCheatDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Web Data — Cheat Site Autofill",
                            Risk = Risk.High,
                            Location = webDataPath,
                            FileName = Path.GetFileName(webDataPath),
                            Reason = $"Browser web data (autofill/forms) contains cheat site: '{domain}'",
                            Detail = "Autofill data from cheat sites preserved in browser Web Data database"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckOperaGXCheatHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string operaGXPath = Path.Combine(userProfile, @"AppData\Roaming\Opera Software\Opera GX Stable\History");
        if (!File.Exists(operaGXPath)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(operaGXPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            foreach (string domain in KnownCheatDomains)
            {
                if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Opera GX History — Cheat Provider Visit",
                        Risk = Risk.Critical,
                        Location = operaGXPath,
                        FileName = Path.GetFileName(operaGXPath),
                        Reason = $"Opera GX history shows visit to cheat provider: '{domain}'",
                        Detail = "Opera GX (popular gaming browser) history shows visits to known cheat provider websites"
                    });
                    break;
                }
            }

            foreach (string cheatKw in CheatSiteKeywords)
            {
                if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Opera GX History — Cheat Keyword",
                        Risk = Risk.High,
                        Location = operaGXPath,
                        FileName = Path.GetFileName(operaGXPath),
                        Reason = $"Opera GX history contains cheat keyword: '{cheatKw}'",
                        Detail = "Opera GX browser history contains references to cheat tools or communities"
                    });
                    break;
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckBrowserShortcutsCheat(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] shortcutDirs = new[]
        {
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, @"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch"),
            Path.Combine(userProfile, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"),
        };

        foreach (string dir in shortcutDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string lnkFile in Directory.GetFiles(dir, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string lnkName = Path.GetFileName(lnkFile).ToLowerInvariant();
                foreach (string cheatKw in CheatSiteKeywords.Take(20))
                {
                    if (lnkName.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Desktop/Start Menu — Cheat Site Shortcut",
                            Risk = Risk.High,
                            Location = lnkFile,
                            FileName = Path.GetFileName(lnkFile),
                            Reason = $"Shortcut name matches cheat site pattern: '{cheatKw}'",
                            Detail = "Desktop or Start Menu shortcut pointing to a cheat site or tool"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckBrowserIndexedDBCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] idbPaths = new[]
        {
            @"AppData\Local\Google\Chrome\User Data\Default\IndexedDB",
            @"AppData\Local\Microsoft\Edge\User Data\Default\IndexedDB",
        };

        foreach (string idbRelPath in idbPaths)
        {
            string idbPath = Path.Combine(userProfile, idbRelPath);
            if (!Directory.Exists(idbPath)) continue;

            int scanned = 0;
            foreach (string ldbFile in Directory.GetFiles(idbPath, "*.ldb", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(idbPath, "*.log", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested || scanned > 100) break;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(ldbFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 512 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string domain in KnownCheatDomains)
                    {
                        if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Browser IndexedDB — Cheat Site App Data",
                                Risk = Risk.High,
                                Location = ldbFile,
                                FileName = Path.GetFileName(ldbFile),
                                Reason = $"Browser IndexedDB contains data from cheat site: '{domain}'",
                                Detail = "IndexedDB stores rich application data from web apps — cheat subscription portals use this for offline access"
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
