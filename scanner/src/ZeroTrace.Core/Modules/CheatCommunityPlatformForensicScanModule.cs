using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class CheatCommunityPlatformForensicScanModule : IScanModule
{
    public string Name => "Cheat Community Platform Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatForumDomains = { "unknowncheats.me", "mpgh.net", "hackforums.net", "elitepvpers.com", "nulled.to", "cracked.io", "leakforums.net", "blackbay.gg", "cheatautomation.com", "aimware.net", "gamesense.pub", "weave.gg", "cheat.gg", "namelessnoobs.com", "interwebz.cc", "xenforo.net/cheat" };
    private static readonly string[] PremiumCheatSites = { "2take1.menu", "stand.gg", "yimmenu.net", "eulen.app", "redengine.cc", "skript.gg", "brainobrain.gg", "midnight-software.xyz", "zeroevade.net", "onioncheats.net", "unknownproducts.net" };
    private static readonly string[] CheatPaymentPlatforms = { "sellix.io", "shoppy.gg", "selly.gg", "payhip.com", "gumroad.com", "itch.io" };
    private static readonly string[] CheatSearchKeywords = { "fivem cheat", "ragemp hack", "altv bypass", "gta cheat", "rust esp", "valorant bypass", "warzone hack", "free cheat", "buy cheat", "private cheat", "undetected cheat", "cheat download", "bypass anticheat", "hack download" };
    private static readonly string[] DiscordCheatKeywords = { "cheat", "hack", "esp", "aimbot", "bypass", "leak", "crack", "private", "internal", "external", "injector", "trainer", "mod menu" };
    private static readonly string[] PaymentReceiptKeywords = { "Order Confirmation", "Purchase Successful", "Payment Received", "License Key", "Activation Code", "Subscription Activated", "Invoice", "Receipt" };
    private static readonly string[] ChromePaths = { @"Google\Chrome\User Data\Default\", @"Microsoft\Edge\User Data\Default\", @"BraveSoftware\Brave-Browser\User Data\Default\" };

    private static readonly string[] CheatForumFilePatterns = { "[UC]*.zip", "[MPGH]*.zip", "[HF]*.rar", "[EP]*.zip", "release_v*.zip", "private_release_*.rar", "update_*.zip" };
    private static readonly string[] CheatInstallKeywords = { "cheat", "hack", "esp", "aimbot", "bypass", "injector", "trainer", "loader", "menu", "exploit" };
    private static readonly string[] CheatSubreddits = { "reddit.com/r/Cheatengine", "reddit.com/r/GamingHacks", "reddit.com/r/FiveMRP", "reddit.com/r/ragemp", "reddit.com/r/altv" };
    private static readonly string[] GitHubCheatPathKeywords = { "cheat", "hack", "esp", "aimbot", "bypass", "trainer", "injector" };
    private static readonly string[] DiscordTokenFileNames = { "token.txt", "discord_token.txt", "bot_token.txt" };
    private static readonly string[] DiscordSelfBotFiles = { "selfbot.js", "discord_selfbot.js", "automation_bot.js" };
    private static readonly string[] CheatAppUninstallKeywords = { "cheat", "hack", "loader", "injector", "bypass", "trainer", "mod menu", "cheatlauncher", "cheat launcher" };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckCheatForumBrowserHistory(ctx, ct),
            CheckCheatForumDownloadedFiles(ctx, ct),
            CheckDiscordCheatServerArtifacts(ctx, ct),
            CheckTelegramCheatChannelArtifacts(ctx, ct),
            CheckWhatsAppCheatGroupArtifacts(ctx, ct),
            CheckRedditCheatCommunityHistory(ctx, ct),
            CheckYouTubeCheatTutorialHistory(ctx, ct),
            CheckCheatMarketplaceArtifacts(ctx, ct),
            CheckStreamingCheatCommunityArtifacts(ctx, ct),
            CheckGitHubCheatRepositoryHistory(ctx, ct),
            CheckCheatSubscriptionSiteCredentials(ctx, ct),
            CheckCheatForumCookies(ctx, ct),
            CheckDiscordTokenCheatBotArtifacts(ctx, ct),
            CheckCheatForumSearchHistory(ctx, ct),
            CheckCheatInviteLinksInFiles(ctx, ct),
            CheckCheatNewsletterEmailArtifacts(ctx, ct),
            CheckCheatCommunityInstalledApps(ctx, ct),
            CheckCheatForumPaymentRecords(ctx, ct)
        );
    }

    private Task CheckCheatForumBrowserHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tempDir = Path.GetTempPath();

        foreach (string chromePath in ChromePaths)
        {
            string historyPath = Path.Combine(localAppData, chromePath, "History");
            if (!File.Exists(historyPath)) continue;

            string tempCopy = Path.Combine(tempDir, $"zt_hist_{Guid.NewGuid():N}.tmp");
            try
            {
                File.Copy(historyPath, tempCopy, true);
                ctx.IncrementFiles();

                using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string domain in PremiumCheatSites)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — Premium Cheat Site Visit",
                            Risk = RiskLevel.High,
                            Location = historyPath,
                            FileName = "History",
                            Reason = $"Browser history contains visit to premium cheat site: '{domain}'",
                            Detail = $"History database in '{chromePath}' references premium cheat service domain"
                        });
                    }
                }

                foreach (string domain in CheatForumDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — Cheat Forum Visit",
                            Risk = RiskLevel.Medium,
                            Location = historyPath,
                            FileName = "History",
                            Reason = $"Browser history contains visit to cheat forum: '{domain}'",
                            Detail = $"History database in '{chromePath}' references known cheat community forum"
                        });
                    }
                }

                foreach (string domain in new[] { "lc.cx", "leetcheats" })
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — Cheat Distribution Site Visit",
                            Risk = RiskLevel.High,
                            Location = historyPath,
                            FileName = "History",
                            Reason = $"Browser history references cheat distribution link: '{domain}'",
                            Detail = $"History database in '{chromePath}' contains reference to cheat distribution service"
                        });
                    }
                }
            }
            catch { }
            finally
            {
                try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
            }
        }
    }, ct);

    private Task CheckCheatForumDownloadedFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsDir = Path.Combine(userProfile, "Downloads");
        if (!Directory.Exists(downloadsDir)) return;

        foreach (string pattern in CheatForumFilePatterns)
        {
            try
            {
                foreach (string file in Directory.GetFiles(downloadsDir, pattern, SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Downloaded Cheat Forum Release File",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Downloaded file matches cheat forum release naming pattern: '{pattern}'",
                        Detail = "Files with cheat forum release prefixes indicate direct downloads from cheat distribution threads"
                    });
                }
            }
            catch { }
        }

        string[] archiveExtensions = { "*.zip", "*.rar", "*.dll" };
        foreach (string ext in archiveExtensions)
        {
            try
            {
                foreach (string file in Directory.GetFiles(downloadsDir, ext, SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    string fileName = Path.GetFileName(file);
                    bool hasVersionSuffix = System.Text.RegularExpressions.Regex.IsMatch(
                        fileName, @"v\d+\.\d+", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (!hasVersionSuffix) continue;
                    bool hasCheatKeyword = CheatInstallKeywords.Any(k => fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (!hasCheatKeyword) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Downloaded Cheat DLL/Archive with Version Suffix",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Downloaded file matches cheat release versioning pattern: '{fileName}'",
                        Detail = "Versioned cheat archives in Downloads match common cheat distribution packaging formats"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckDiscordCheatServerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string levelDbPath = Path.Combine(appData, "discord", "Local Storage", "leveldb");
        if (Directory.Exists(levelDbPath))
        {
            try
            {
                foreach (string ldbFile in Directory.GetFiles(levelDbPath, "*.ldb", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(levelDbPath, "*.log", SearchOption.TopDirectoryOnly)))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(ldbFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        byte[] buf = new byte[Math.Min(fs.Length, 512 * 1024)];
                        int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                        string content = Encoding.UTF8.GetString(buf, 0, read);

                        int matchCount = 0;
                        string? lastKw = null;
                        foreach (string kw in DiscordCheatKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                matchCount++;
                                lastKw = kw;
                            }
                        }

                        if (matchCount >= 3)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Discord LevelDB — Cheat Server Artifacts",
                                Risk = RiskLevel.High,
                                Location = ldbFile,
                                FileName = Path.GetFileName(ldbFile),
                                Reason = $"Discord LevelDB storage contains {matchCount} cheat-related keywords (last: '{lastKw}')",
                                Detail = "Discord local storage with multiple cheat keywords indicates membership in cheat community servers"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        string storageJson = Path.Combine(appData, "discord", "storage.json");
        if (File.Exists(storageJson))
        {
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(storageJson, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);
                foreach (string kw in DiscordCheatKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord Storage — Cheat Server Reference",
                            Risk = RiskLevel.High,
                            Location = storageJson,
                            FileName = "storage.json",
                            Reason = $"Discord storage.json references cheat keyword: '{kw}'",
                            Detail = "Discord storage configuration referencing cheat-related server names or keywords"
                        });
                        break;
                    }
                }
            }
            catch { }
        }

        string discordLogsPath = Path.Combine(appData, "discord", "logs");
        if (Directory.Exists(discordLogsPath))
        {
            try
            {
                foreach (string logFile in Directory.GetFiles(discordLogsPath, "*.log", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasInvite = content.Contains("discord.gg/", StringComparison.OrdinalIgnoreCase) ||
                                         content.Contains("discord.com/invite/", StringComparison.OrdinalIgnoreCase);
                        bool hasCheatKw = DiscordCheatKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (hasInvite && hasCheatKw)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Discord Log — Cheat Server Invite Link",
                                Risk = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = "Discord log file contains invite links combined with cheat-related keywords",
                                Detail = "Discord logs with cheat community invite links indicate active participation in cheat distribution channels"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckTelegramCheatChannelArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string tdataPath = Path.Combine(appData, "Telegram Desktop", "tdata");
        if (!Directory.Exists(tdataPath)) return;

        string dumpsPath = Path.Combine(tdataPath, "dumps");
        if (Directory.Exists(dumpsPath))
        {
            try
            {
                foreach (string dumpFile in Directory.GetFiles(dumpsPath, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(dumpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                        int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                        string content = Encoding.UTF8.GetString(buf, 0, read);

                        foreach (string kw in CheatInstallKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Telegram Desktop — Cheat Channel Dump",
                                    Risk = RiskLevel.High,
                                    Location = dumpFile,
                                    FileName = Path.GetFileName(dumpFile),
                                    Reason = $"Telegram dump file contains cheat keyword: '{kw}'",
                                    Detail = "Telegram dump files with cheat references indicate downloaded content from cheat distribution channels"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsDir = Path.Combine(userProfile, "Downloads");
        if (Directory.Exists(downloadsDir))
        {
            try
            {
                foreach (string file in Directory.GetFiles(downloadsDir, "telegram_*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    string fileName = Path.GetFileName(file);
                    bool hasCheatKw = CheatInstallKeywords.Any(k => fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                    ctx.IncrementFiles();
                    if (hasCheatKw)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Telegram Download — Cheat File",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Telegram-prefixed download file contains cheat keyword: '{fileName}'",
                            Detail = "Files downloaded via Telegram Desktop with cheat-related names indicate cheat channel distribution"
                        });
                    }
                }
            }
            catch { }
        }

        try
        {
            int fileCount = 0;
            foreach (string tdFile in Directory.GetFiles(tdataPath, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                if (fileCount++ > 50) break;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(tdFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 128 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    int matches = CheatInstallKeywords.Count(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (matches >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Telegram tdata — Cheat Channel References",
                            Risk = RiskLevel.High,
                            Location = tdFile,
                            FileName = Path.GetFileName(tdFile),
                            Reason = $"Telegram tdata file contains {matches} cheat-related keywords",
                            Detail = "Telegram database artifacts with cheat references suggest communication in cheat distribution channels"
                        });
                        break;
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckWhatsAppCheatGroupArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] whatsappDirs = {
            Path.Combine(appData, "WhatsApp"),
            Path.Combine(localAppData, "WhatsApp"),
        };

        foreach (string dir in whatsappDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (string file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                }
            }
            catch { }
        }

        string whatsappMedia = Path.Combine(userProfile, "Documents", "WhatsApp", "Media");
        if (!Directory.Exists(whatsappMedia)) return;

        string[] waPrefixes = { "WhatsApp Image", "WhatsApp Video", "WhatsApp Document" };
        try
        {
            foreach (string file in Directory.GetFiles(whatsappMedia, "*", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                string fileName = Path.GetFileName(file);
                bool isWaFile = waPrefixes.Any(p => fileName.StartsWith(p, StringComparison.OrdinalIgnoreCase));
                if (!isWaFile) continue;
                ctx.IncrementFiles();
                bool hasCheatKw = CheatInstallKeywords.Any(k => fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (hasCheatKw)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "WhatsApp Media — Cheat Group Download",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = fileName,
                        Reason = $"WhatsApp media file matches cheat-related naming: '{fileName}'",
                        Detail = "WhatsApp document/media downloads with cheat keywords indicate receipt from cheat distribution groups"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckRedditCheatCommunityHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tempDir = Path.GetTempPath();

        foreach (string chromePath in ChromePaths)
        {
            string historyPath = Path.Combine(localAppData, chromePath, "History");
            if (!File.Exists(historyPath)) continue;

            string tempCopy = Path.Combine(tempDir, $"zt_reddit_{Guid.NewGuid():N}.tmp");
            try
            {
                File.Copy(historyPath, tempCopy, true);
                ctx.IncrementFiles();

                using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string subreddit in CheatSubreddits)
                {
                    if (content.Contains(subreddit, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — Reddit Cheat Community Visit",
                            Risk = RiskLevel.Medium,
                            Location = historyPath,
                            FileName = "History",
                            Reason = $"Browser history contains visit to cheat-related subreddit: '{subreddit}'",
                            Detail = "Reddit cheat subreddit visits indicate active participation in cheat discussion communities"
                        });
                    }
                }
            }
            catch { }
            finally
            {
                try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
            }
        }

        try
        {
            string localPackages = Path.Combine(localAppData, "Packages");
            if (Directory.Exists(localPackages))
            {
                foreach (string packageDir in Directory.GetDirectories(localPackages, "*Reddit*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Reddit App — Installed Package Artifact",
                        Risk = RiskLevel.Medium,
                        Location = packageDir,
                        FileName = Path.GetFileName(packageDir),
                        Reason = "Reddit application package found — may contain cheat community browsing history",
                        Detail = "Reddit app local packages can contain cached subreddit browsing data including cheat communities"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckYouTubeCheatTutorialHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tempDir = Path.GetTempPath();

        string[] youtubeCheatTerms = { "cheat", "hack", "esp", "aimbot", "bypass", "free cheat", "undetected", "injector", "trainer" };

        foreach (string chromePath in ChromePaths)
        {
            string historyPath = Path.Combine(localAppData, chromePath, "History");
            if (!File.Exists(historyPath)) continue;

            string tempCopy = Path.Combine(tempDir, $"zt_yt_{Guid.NewGuid():N}.tmp");
            try
            {
                File.Copy(historyPath, tempCopy, true);
                ctx.IncrementFiles();

                using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                bool hasYouTubeWatch = content.Contains("youtube.com/watch?v=", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("youtu.be/", StringComparison.OrdinalIgnoreCase);
                if (!hasYouTubeWatch) continue;

                foreach (string term in youtubeCheatTerms)
                {
                    if (content.Contains("youtube.com", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains(term, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — YouTube Cheat Tutorial Visit",
                            Risk = RiskLevel.Medium,
                            Location = historyPath,
                            FileName = "History",
                            Reason = $"Browser history contains YouTube visits combined with cheat keyword: '{term}'",
                            Detail = "YouTube cheat tutorial viewing artifacts in browser history indicate research into cheat methods"
                        });
                        break;
                    }
                }
            }
            catch { }
            finally
            {
                try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
            }
        }
    }, ct);

    private Task CheckCheatMarketplaceArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string[] marketplaceDirs = {
            Path.Combine(appData, "Sellix"),
            Path.Combine(appData, "CheatAutomation"),
        };

        foreach (string dir in marketplaceDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Cheat Marketplace App Data Folder",
                Risk = RiskLevel.High,
                Location = dir,
                FileName = Path.GetFileName(dir),
                Reason = $"Cheat payment platform application data folder found: '{dir}'",
                Detail = "Presence of cheat marketplace application data indicates active use of cheat purchasing platforms"
            });
        }

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tempDir = Path.GetTempPath();

        foreach (string chromePath in ChromePaths)
        {
            string historyPath = Path.Combine(localAppData, chromePath, "History");
            if (!File.Exists(historyPath)) continue;

            string tempCopy = Path.Combine(tempDir, $"zt_market_{Guid.NewGuid():N}.tmp");
            try
            {
                File.Copy(historyPath, tempCopy, true);
                ctx.IncrementFiles();

                using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string platform in CheatPaymentPlatforms)
                {
                    if (content.Contains(platform, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — Cheat Payment Platform Visit",
                            Risk = RiskLevel.High,
                            Location = historyPath,
                            FileName = "History",
                            Reason = $"Browser history contains visit to cheat payment platform: '{platform}'",
                            Detail = "Visits to cheat payment platforms indicate purchasing activity from cheat marketplaces"
                        });
                    }
                }
            }
            catch { }
            finally
            {
                try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
            }
        }

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsDir = Path.Combine(userProfile, "Downloads");
        if (!Directory.Exists(downloadsDir)) return;

        try
        {
            foreach (string file in Directory.GetFiles(downloadsDir, "*.pdf", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(downloadsDir, "*.html", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    bool hasPlatform = CheatPaymentPlatforms.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase));
                    bool hasPaymentKw = PaymentReceiptKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hasPlatform && hasPaymentKw)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Downloaded Payment Confirmation — Cheat Marketplace",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Downloaded receipt file from cheat payment platform found in Downloads",
                            Detail = "Payment confirmation from cheat marketplace proves a cheat purchase transaction"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckStreamingCheatCommunityArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string twitchPath = Path.Combine(appData, "Twitch");

        if (Directory.Exists(twitchPath))
        {
            try
            {
                foreach (string file in Directory.GetFiles(twitchPath, "*.json", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        int matchCount = 0;
                        string? lastKw = null;
                        foreach (string kw in CheatInstallKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                matchCount++;
                                lastKw = kw;
                            }
                        }

                        if (matchCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Twitch App Data — Cheat Streamer Reference",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Twitch app data contains {matchCount} cheat-related keywords (last: '{lastKw}')",
                                Detail = "Twitch application data referencing cheat terms may indicate following cheat-promoting streamers"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        string[] streamingConfigPaths = {
            Path.Combine(appData, "StreamElements"),
            Path.Combine(appData, "Streamlabs"),
        };

        foreach (string configDir in streamingConfigPaths)
        {
            if (!Directory.Exists(configDir)) continue;
            try
            {
                foreach (string file in Directory.GetFiles(configDir, "*.json", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        bool hasCheatKw = CheatInstallKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hasCheatKw)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Streaming Config — Cheat Community Affiliation",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Streaming platform config in '{Path.GetFileName(configDir)}' references cheat-related content",
                                Detail = "Streaming app configuration with cheat keywords may indicate cheat community affiliation in streaming context"
                            });
                            break;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckGitHubCheatRepositoryHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tempDir = Path.GetTempPath();

        foreach (string chromePath in ChromePaths)
        {
            string historyPath = Path.Combine(localAppData, chromePath, "History");
            if (!File.Exists(historyPath)) continue;

            string tempCopy = Path.Combine(tempDir, $"zt_gh_{Guid.NewGuid():N}.tmp");
            try
            {
                File.Copy(historyPath, tempCopy, true);
                ctx.IncrementFiles();

                using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                if (!content.Contains("github.com", StringComparison.OrdinalIgnoreCase)) continue;

                foreach (string kw in GitHubCheatPathKeywords)
                {
                    if (content.Contains("github.com", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History — GitHub Cheat Repository Visit",
                            Risk = RiskLevel.High,
                            Location = historyPath,
                            FileName = "History",
                            Reason = $"Browser history contains GitHub visit with cheat repository keyword: '{kw}'",
                            Detail = "GitHub cheat repository browsing history indicates research into or use of open-source cheat tools"
                        });
                        break;
                    }
                }
            }
            catch { }
            finally
            {
                try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
            }
        }

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = {
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            userProfile,
        };

        foreach (string searchDir in searchDirs)
        {
            if (!Directory.Exists(searchDir)) continue;
            try
            {
                foreach (string gitConfig in Directory.GetFiles(searchDir, "config", SearchOption.AllDirectories)
                    .Where(f => Path.GetFileName(Path.GetDirectoryName(f) ?? string.Empty)
                        .Equals(".git", StringComparison.OrdinalIgnoreCase)))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(gitConfig, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        if (!content.Contains("github.com", StringComparison.OrdinalIgnoreCase) &&
                            !content.Contains("gitlab.com", StringComparison.OrdinalIgnoreCase)) continue;

                        foreach (string kw in GitHubCheatPathKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Local Git Repo — Cheat Repository Clone",
                                    Risk = RiskLevel.High,
                                    Location = gitConfig,
                                    FileName = "config",
                                    Reason = $"Local git config remote URL contains cheat keyword: '{kw}'",
                                    Detail = "Locally cloned git repository with cheat-related remote URL proves download of cheat source code"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckCheatSubscriptionSiteCredentials(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tempDir = Path.GetTempPath();

        foreach (string chromePath in ChromePaths)
        {
            string loginDataPath = Path.Combine(localAppData, chromePath, "Login Data");
            if (!File.Exists(loginDataPath)) continue;

            string tempCopy = Path.Combine(tempDir, $"zt_login_{Guid.NewGuid():N}.tmp");
            try
            {
                File.Copy(loginDataPath, tempCopy, true);
                ctx.IncrementFiles();

                using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string domain in CheatForumDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Saved Login Credentials — Cheat Forum Account",
                            Risk = RiskLevel.Critical,
                            Location = loginDataPath,
                            FileName = "Login Data",
                            Reason = $"Browser saved login credentials for cheat forum: '{domain}'",
                            Detail = "Saved credentials for a cheat forum domain prove an active registered account on the platform"
                        });
                    }
                }

                foreach (string domain in PremiumCheatSites)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Saved Login Credentials — Premium Cheat Site Account",
                            Risk = RiskLevel.Critical,
                            Location = loginDataPath,
                            FileName = "Login Data",
                            Reason = $"Browser saved login credentials for premium cheat service: '{domain}'",
                            Detail = "Saved credentials for a premium cheat service prove an active paying subscription account"
                        });
                    }
                }
            }
            catch { }
            finally
            {
                try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
            }
        }
    }, ct);

    private Task CheckCheatForumCookies(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tempDir = Path.GetTempPath();

        foreach (string chromePath in ChromePaths)
        {
            string cookiesPath = Path.Combine(localAppData, chromePath, "Cookies");
            if (!File.Exists(cookiesPath)) continue;

            string tempCopy = Path.Combine(tempDir, $"zt_cookies_{Guid.NewGuid():N}.tmp");
            try
            {
                File.Copy(cookiesPath, tempCopy, true);
                ctx.IncrementFiles();

                using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string domain in CheatForumDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Cookies — Cheat Forum Active Session",
                            Risk = RiskLevel.High,
                            Location = cookiesPath,
                            FileName = "Cookies",
                            Reason = $"Browser cookies database contains session cookie for cheat forum: '{domain}'",
                            Detail = "Session cookies for cheat forums indicate recent active browsing sessions on those platforms"
                        });
                    }
                }

                foreach (string domain in PremiumCheatSites)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Cookies — Premium Cheat Site Session",
                            Risk = RiskLevel.High,
                            Location = cookiesPath,
                            FileName = "Cookies",
                            Reason = $"Browser cookies database contains session cookie for premium cheat site: '{domain}'",
                            Detail = "Session cookies for premium cheat services indicate active subscription access"
                        });
                    }
                }
            }
            catch { }
            finally
            {
                try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
            }
        }
    }, ct);

    private Task CheckDiscordTokenCheatBotArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = {
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Documents"),
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (string tokenFile in DiscordTokenFileNames)
                {
                    string tokenPath = Path.Combine(dir, tokenFile);
                    if (!File.Exists(tokenPath)) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Discord Token File — Cheat Bot Artifact",
                        Risk = RiskLevel.Critical,
                        Location = tokenPath,
                        FileName = tokenFile,
                        Reason = $"Discord token file found in user directory: '{tokenFile}'",
                        Detail = "Discord bot token files are used with cheat automation bots for server raiding or account automation"
                    });
                }

                foreach (string selfBotFile in DiscordSelfBotFiles)
                {
                    string selfBotPath = Path.Combine(dir, selfBotFile);
                    if (!File.Exists(selfBotPath)) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Discord Self-Bot Script — Cheat Automation",
                        Risk = RiskLevel.Critical,
                        Location = selfBotPath,
                        FileName = selfBotFile,
                        Reason = $"Discord self-bot script found: '{selfBotFile}'",
                        Detail = "Discord self-bot scripts automate account actions and are commonly used for cheat community automation"
                    });
                }

                foreach (string configFile in Directory.GetFiles(dir, "config.json", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        if (content.Contains("\"token\":", StringComparison.OrdinalIgnoreCase) &&
                            CheatInstallKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Config File — Discord Token with Cheat Context",
                                Risk = RiskLevel.Critical,
                                Location = configFile,
                                FileName = "config.json",
                                Reason = "config.json contains Discord token field combined with cheat-related keywords",
                                Detail = "Configuration file with embedded Discord token and cheat keywords indicates a cheat bot or automation tool"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckCheatForumSearchHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tempDir = Path.GetTempPath();

        foreach (string chromePath in ChromePaths)
        {
            string historyPath = Path.Combine(localAppData, chromePath, "History");
            if (!File.Exists(historyPath)) continue;

            string tempCopy = Path.Combine(tempDir, $"zt_search_{Guid.NewGuid():N}.tmp");
            try
            {
                File.Copy(historyPath, tempCopy, true);
                ctx.IncrementFiles();

                using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string searchTerm in CheatSearchKeywords)
                {
                    if (content.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser Search History — Cheat Search Term",
                            Risk = RiskLevel.High,
                            Location = historyPath,
                            FileName = "History",
                            Reason = $"Browser search history contains cheat-related search query: '{searchTerm}'",
                            Detail = "Search queries for cheat tools in browser history indicate intentional research into cheating"
                        });
                    }
                }
            }
            catch { }
            finally
            {
                try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
            }
        }
    }, ct);

    private Task CheckCheatInviteLinksInFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = {
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Documents"),
        };

        string[] textExtensionPatterns = { "*.txt", "*.md", "*.log", "*.cfg", "*.ini", "*.json", "*.html", "*.htm" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string pattern in textExtensionPatterns)
            {
                try
                {
                    foreach (string file in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            bool hasDiscordInvite = content.Contains("discord.gg/", StringComparison.OrdinalIgnoreCase) ||
                                                    content.Contains("discord.com/invite/", StringComparison.OrdinalIgnoreCase);
                            bool hasCheatKw = DiscordCheatKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (hasDiscordInvite && hasCheatKw)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Text File — Discord Cheat Server Invite Link",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "File contains Discord invite link combined with cheat-related keywords",
                                    Detail = "Saved Discord invite links with cheat context indicate stored access to cheat distribution servers"
                                });
                            }

                            bool hasPastebin = content.Contains("pastebin.com/", StringComparison.OrdinalIgnoreCase) ||
                                               content.Contains("paste.ee/", StringComparison.OrdinalIgnoreCase) ||
                                               content.Contains("hastebin.com/", StringComparison.OrdinalIgnoreCase);
                            bool hasPastebinCheat = hasPastebin && CheatInstallKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (hasPastebinCheat)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Text File — Cheat Download Pastebin Link",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "File contains pastebin link combined with cheat download keywords",
                                    Detail = "Pastebin links with cheat keywords are commonly used for cheat distribution outside of dedicated forums"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckCheatNewsletterEmailArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        string outlookPath = Path.Combine(localAppData, "Programs", "Microsoft", "Outlook");
        if (Directory.Exists(outlookPath))
        {
            try
            {
                foreach (string file in Directory.GetFiles(outlookPath, "*.json", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        bool hasCheatDomain = CheatForumDomains.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase)) ||
                                              PremiumCheatSites.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase));
                        if (hasCheatDomain)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Outlook Config — Cheat Newsletter Sender",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Outlook application data references cheat service domain in email configuration",
                                Detail = "Cheat service domain in Outlook configuration data indicates subscription to cheat newsletters"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        string thunderbirdProfiles = Path.Combine(appData, "Thunderbird", "Profiles");
        if (Directory.Exists(thunderbirdProfiles))
        {
            try
            {
                foreach (string profileDir in Directory.GetDirectories(thunderbirdProfiles))
                {
                    if (ct.IsCancellationRequested) return;
                    foreach (string mailFile in Directory.GetFiles(profileDir, "*.msf", SearchOption.AllDirectories)
                        .Concat(Directory.GetFiles(profileDir, "INBOX", SearchOption.AllDirectories))
                        .Concat(Directory.GetFiles(profileDir, "INBOX.msf", SearchOption.AllDirectories)))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(mailFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            bool hasCheatDomain = CheatForumDomains.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase)) ||
                                                  PremiumCheatSites.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase));
                            if (hasCheatDomain)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Thunderbird Mail — Cheat Newsletter Email",
                                    Risk = RiskLevel.High,
                                    Location = mailFile,
                                    FileName = Path.GetFileName(mailFile),
                                    Reason = "Thunderbird mail database references cheat service domain",
                                    Detail = "Cheat service domain found in Thunderbird mailbox indicates received cheat newsletter or purchase confirmation emails"
                                });
                                break;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsDir = Path.Combine(userProfile, "Downloads");
        if (Directory.Exists(downloadsDir))
        {
            try
            {
                foreach (string file in Directory.GetFiles(downloadsDir, "*.eml", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(downloadsDir, "*.msg", SearchOption.TopDirectoryOnly)))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        bool hasCheatDomain = CheatForumDomains.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase)) ||
                                              PremiumCheatSites.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase));
                        if (hasCheatDomain)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Downloaded Email File — Cheat Newsletter",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Downloaded .eml/.msg file in Downloads references cheat service domain",
                                Detail = "Saved email file from cheat newsletter sender found in Downloads folder"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckCheatCommunityInstalledApps(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] uninstallPaths = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (string regPath in uninstallPaths)
        {
            foreach (RegistryHive hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                    using var uninstallKey = baseKey.OpenSubKey(regPath);
                    if (uninstallKey == null) continue;

                    foreach (string subKeyName in uninstallKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        try
                        {
                            using var appKey = uninstallKey.OpenSubKey(subKeyName);
                            if (appKey == null) continue;
                            ctx.IncrementRegistryKeys();

                            string displayName = appKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                            string publisher = appKey.GetValue("Publisher")?.ToString() ?? string.Empty;
                            string installLocation = appKey.GetValue("InstallLocation")?.ToString() ?? string.Empty;

                            foreach (string kw in CheatAppUninstallKeywords)
                            {
                                if (displayName.Contains(kw, StringComparison.OrdinalIgnoreCase) ||
                                    publisher.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Installed App — Cheat Community Application",
                                        Risk = RiskLevel.High,
                                        Location = $@"Registry\{regPath}\{subKeyName}",
                                        FileName = displayName,
                                        Reason = $"Installed application matches cheat tool keyword: '{kw}' (App: '{displayName}')",
                                        Detail = $"Publisher: '{publisher}', Install Location: '{installLocation}'"
                                    });
                                    break;
                                }
                            }

                            foreach (string cheatDomain in CheatForumDomains.Concat(PremiumCheatSites))
                            {
                                if (displayName.Contains(cheatDomain, StringComparison.OrdinalIgnoreCase) ||
                                    installLocation.Contains(cheatDomain, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Installed App — Cheat Service Application",
                                        Risk = RiskLevel.High,
                                        Location = $@"Registry\{regPath}\{subKeyName}",
                                        FileName = displayName,
                                        Reason = $"Installed application references known cheat service: '{cheatDomain}'",
                                        Detail = $"Application registered in Add/Remove Programs matching cheat service domain"
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckCheatForumPaymentRecords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Documents"),
        };

        string[] allCheatDomains = CheatForumDomains.Concat(PremiumCheatSites).Concat(CheatPaymentPlatforms).ToArray();

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (string file in Directory.GetFiles(dir, "*.pdf", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(dir, "*.html", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.GetFiles(dir, "*.htm", SearchOption.TopDirectoryOnly)))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        int receiptKeywordMatches = PaymentReceiptKeywords.Count(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (receiptKeywordMatches < 2) continue;

                        bool hasCheatService = allCheatDomains.Any(d => content.Contains(d, StringComparison.OrdinalIgnoreCase));
                        bool hasLicenseOrActivation = content.Contains("License Key", StringComparison.OrdinalIgnoreCase) ||
                                                      content.Contains("Activation Code", StringComparison.OrdinalIgnoreCase) ||
                                                      content.Contains("Subscription", StringComparison.OrdinalIgnoreCase);

                        if (hasCheatService || hasLicenseOrActivation)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Payment Record — Cheat Service Purchase",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Payment receipt file contains {receiptKeywordMatches} purchase confirmation keywords combined with cheat service references",
                                Detail = "Payment confirmation document from a cheat service proves a completed financial transaction for cheat software"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);
}
