using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CheatMarketplaceArtifactScanModule : IScanModule
{
    public string Name => "Cheat-Marktplatz";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    private const string PrefetchDir = @"C:\Windows\Prefetch";

    private static readonly string[] LoaderExeNames =
    {
        "cheat_loader.exe", "cheatloader.exe", "game_loader.exe",
        "uc_loader.exe", "unknowncheats_loader.exe", "cs2_loader.exe",
        "valorant_loader.exe", "fivem_loader.exe", "inject_loader.exe",
        "premium_loader.exe", "private_loader.exe", "cracked_loader.exe",
        "bypassed_loader.exe",
    };

    private static readonly string[] SuspectDirKeywords =
    {
        "loader", "cheat", "hack", "bypass", "inject", "crack",
        "premium_cheat", "private_cheat",
    };

    private static readonly string[] CheatBrandNames =
    {
        "aimware", "skeet", "gamesense", "onetap", "fatality",
        "neverlose", "nixware", "interwebz", "eulen", "lynx",
        "hamster", "impulse", "evolution", "nighthawk", "cherax",
        "stand", "kiddion", "2take1", "pandora", "aimjunkies",
    };

    private static readonly string[] DiscordCheatInviteSlugs =
    {
        "eulen", "lynxclient", "hamster", "impulse", "aimware",
        "skeet", "gamesense", "onetap", "fatality", "neverlose",
        "interwebz", "nixware", "cherax", "stand", "kiddion",
        "2take1", "evolution", "nighthawk", "epsilon", "phantom",
    };

    private static readonly string[] KnownCheatServerIds =
    {
        "768430940415877120", "836684256590831646", "712890023619313674",
        "780350114120335360", "895302278399041536", "752399296388808765",
        "770012795440701440", "705893553741062154", "893558468028579880",
        "931019046012579880",
    };

    private static readonly string[] CheatForumDomains =
    {
        "unknowncheats.me", "mpgh.net", "hackforums.net",
        "elitepvpers.com", "uc.to",
    };

    private static readonly string[] CheatMarketplaceDomains =
    {
        "aimware.net", "skeet.cc", "gamesense.pub", "onetap.su",
        "fatality.win", "neverlose.cc", "nixware.pw", "interwebz.wtf",
        "pandora.wtf", "aimjunkies.com",
    };

    private static readonly string[] FiveMCheatDomains =
    {
        "eulen.ac", "lynxclient.com", "hamster-cheat.com",
        "impulse-cheats.com", "desudo.de",
    };

    private static readonly string[] OtherCheatDomains =
    {
        "evolution-cheat.com", "nighthawk-cheat.com",
    };

    private static readonly string[] CheatAppDataDirs =
    {
        "aimware", "Aimware", "skeet", ".skeet", "gamesense",
        "interwebz", "fatality", "nixware", "onetap", "aimjunkies",
        "neverlose", "pandora",
    };

    private static readonly string[] ArchiveExtensions =
    {
        ".exe", ".dll", ".zip", ".rar", ".7z", ".tar", ".gz",
    };

    private static readonly string[] InvoiceKeywords =
    {
        "invoice", "receipt", "payment", "order", "subscription",
    };

    private static readonly string[] InvoiceCheatKeywords =
    {
        "aimware", "skeet", "cheat", "hack", "hack-tool",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Suche nach Loader-Artefakten...");
        await ScanForLoaderArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.15, Name, "Suche nach Lizenz-Dateien...");
        await ScanForLicenseFilesAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.28, Name, "Pruefe bekannte Cheat-AppData-Verzeichnisse...");
        await CheckCheatAppDataDirectoriesAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.42, Name, "Scanne Browser-Verlauf auf Cheat-Domains...");
        await ScanBrowserHistoryFilesAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.60, Name, "Pruefe Downloads auf Cheat-Archive...");
        await ScanDownloadsForCheatArchivesAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.75, Name, "Suche nach Kaufbelegen...");
        await ScanForPaymentReceiptsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.90, Name, "Pruefe Prefetch auf Loader-Artefakte...");
        ScanPrefetchForLoaders(ctx, ct);

        ctx.Report(1.0, Name, "Cheat-Marktplatz-Analyse abgeschlossen");
    }

    // -------------------------------------------------------------------------
    // Loader artifacts
    // -------------------------------------------------------------------------

    private async Task ScanForLoaderArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            await ScanDirectoryForLoadersAsync(ctx, dir, ct).ConfigureAwait(false);
        }
    }

    private static async Task ScanDirectoryForLoadersAsync(ScanContext ctx, string directory, CancellationToken ct)
    {
        if (!Directory.Exists(directory)) return;

        string[] topFiles;
        try { topFiles = Directory.GetFiles(directory, "*.*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in topFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(file);
            if (!LoaderExeNames.Any(l => fn.Equals(l, StringComparison.OrdinalIgnoreCase))) continue;

            long size = 0;
            try { size = new FileInfo(file).Length; } catch { }

            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Marktplatz",
                Title = $"Cheat-Loader gefunden: {fn}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = fn,
                Reason = $"Datei '{fn}' ist ein bekannter Cheat-Loader-Name. " +
                         "Abo-Cheats verwenden Loader, um die eigentliche Cheat-DLL zur Laufzeit herunterzuladen und einzuspritzen.",
                Detail = $"Pfad: {file} | Groesse: {size} Bytes"
            });
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            var dirName = Path.GetFileName(sub);
            bool isSuspectDir = SuspectDirKeywords.Any(k =>
                dirName.Contains(k, StringComparison.OrdinalIgnoreCase));

            string[] subFiles;
            try { subFiles = Directory.GetFiles(sub, "*.*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in subFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);
                var ext = Path.GetExtension(fn).ToLowerInvariant();

                bool isKnownLoader = LoaderExeNames.Any(l => fn.Equals(l, StringComparison.OrdinalIgnoreCase));
                bool isLoaderInSuspectDir = isSuspectDir &&
                    (fn.Equals("loader.exe", StringComparison.OrdinalIgnoreCase) ||
                     fn.Equals("loader.dll", StringComparison.OrdinalIgnoreCase)) &&
                    (ext == ".exe" || ext == ".dll");

                if (!isKnownLoader && !isLoaderInSuspectDir) continue;

                long size = 0;
                try { size = new FileInfo(file).Length; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Marktplatz",
                    Title = isLoaderInSuspectDir
                        ? $"Loader in verdaechtigem Verzeichnis: {dirName}"
                        : $"Cheat-Loader gefunden: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = isLoaderInSuspectDir
                        ? $"Datei 'loader.exe/dll' in Verzeichnis '{dirName}', das Cheat-Schluesselwoerter enthaelt. " +
                          "Cheat-Loader befinden sich typischerweise in benannten Verzeichnissen."
                        : $"Bekannter Cheat-Loader '{fn}' im Verzeichnis '{dirName}' gefunden.",
                    Detail = $"Pfad: {file} | Verzeichnis: {dirName} | Groesse: {size} Bytes"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // License file artifacts
    // -------------------------------------------------------------------------

    private static async Task ScanForLicenseFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var licenseFileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "license.txt", "license.key", "auth.txt", "hwid.txt", "key.txt",
        };

        var licenseExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".license", ".key", ".auth", ".hwid",
        };

        var cheatDirNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "eulen", "lynx", "aimware", "skeet", "gamesense", "interwebz",
            "fatality", "nixware", "onetap", "aimjunkies", "neverlose", "pandora",
        };

        foreach (var baseDir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(baseDir)) continue;

            string[] subDirs;
            try { subDirs = Directory.GetDirectories(baseDir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var sub in subDirs)
            {
                if (ct.IsCancellationRequested) return;
                var dirName = Path.GetFileName(sub);
                bool isCheatDir = cheatDirNames.Contains(dirName) ||
                    CheatBrandNames.Any(b => dirName.Contains(b, StringComparison.OrdinalIgnoreCase));

                string[] files;
                try { files = Directory.GetFiles(sub, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();

                    bool isLicenseFile = licenseFileNames.Contains(fn);
                    bool isLicenseExt = licenseExtensions.Contains(ext);
                    bool isConfigWithCheatKeys = false;

                    if (fn.Equals("config.json", StringComparison.OrdinalIgnoreCase) && isCheatDir)
                    {
                        isConfigWithCheatKeys = await CheckConfigJsonForCheatKeysAsync(file, ct).ConfigureAwait(false);
                    }

                    if (!isLicenseFile && !isLicenseExt && !isConfigWithCheatKeys) continue;
                    if ((isLicenseFile || isLicenseExt) && !isCheatDir) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Marktplatz",
                        Title = $"Cheat-Lizenzdatei gefunden: {fn}",
                        Risk = isCheatDir ? RiskLevel.Critical : RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Lizenzdatei '{fn}' im Cheat-Verzeichnis '{dirName}' gefunden. " +
                                 "Abo-Cheats speichern Lizenzschluessel, HWID-Tokens und Auth-Informationen als Dateien.",
                        Detail = $"Verzeichnis: {dirName} | Datei: {fn}"
                    });
                }
            }
        }
    }

    private static async Task<bool> CheckConfigJsonForCheatKeysAsync(string file, CancellationToken ct)
    {
        var cheatConfigKeys = new[] { "hwid", "license", "subscription", "expiry", "token", "api_key" };
        try
        {
            string content;
            using var sr = new StreamReader(file, detectEncodingFromByteOrderMarks: true);
            content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

            bool hasCheatKey = cheatConfigKeys.Any(k => content.Contains($"\"{k}\"", StringComparison.OrdinalIgnoreCase));
            bool hasCheatBrand = CheatBrandNames.Any(b => content.Contains(b, StringComparison.OrdinalIgnoreCase));
            return hasCheatKey && hasCheatBrand;
        }
        catch { return false; }
    }

    // -------------------------------------------------------------------------
    // Known cheat AppData directories
    // -------------------------------------------------------------------------

    private static async Task CheckCheatAppDataDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var cheatDirDefs = new (string dirName, string cheatName, string regPath)[]
        {
            ("aimware",    "Aimware",    @"Software\Aimware"),
            ("Aimware",    "Aimware",    @"Software\Aimware"),
            ("skeet",      "Skeet.cc",   ""),
            (".skeet",     "Skeet.cc",   ""),
            ("gamesense",  "GamesenseGG",""),
            ("interwebz",  "Interwebz",  ""),
            ("fatality",   "Fatality.win",""),
            ("nixware",    "Nixware",    ""),
            ("onetap",     "Onetap.su",  @"Software\onetap"),
            ("aimjunkies", "AimJunkies", ""),
            ("neverlose",  "Neverlose.cc",""),
            ("pandora",    "Pandora",    ""),
        };

        foreach (var (dirName, cheatName, regPath) in cheatDirDefs)
        {
            if (ct.IsCancellationRequested) return;

            var roamingPath = Path.Combine(appData, dirName);
            var localPath = Path.Combine(localAppData, dirName);

            foreach (var cheatPath in new[] { roamingPath, localPath })
            {
                if (!Directory.Exists(cheatPath)) continue;

                bool hasConfigFile = false;
                string? configFileName = null;

                string[] dirFiles;
                try { dirFiles = Directory.GetFiles(cheatPath, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var f in dirFiles)
                {
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(f);
                    if (fn.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) ||
                        fn.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                        fn.EndsWith(".ini", StringComparison.OrdinalIgnoreCase))
                    {
                        hasConfigFile = true;
                        configFileName = fn;
                        break;
                    }
                }

                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Marktplatz",
                    Title = $"Cheat-Verzeichnis gefunden: {cheatName}",
                    Risk = hasConfigFile ? RiskLevel.Critical : RiskLevel.High,
                    Location = cheatPath,
                    Reason = $"AppData-Verzeichnis fuer bekannten Cheat '{cheatName}' gefunden" +
                             (hasConfigFile ? $" mit Konfigurationsdatei '{configFileName}'" : "") +
                             ". Dieses Verzeichnis wird von aktiver Cheat-Software erstellt.",
                    Detail = $"Pfad: {cheatPath} | Konfiguration: {(hasConfigFile ? configFileName : "keine")}"
                });
            }

            if (!string.IsNullOrEmpty(regPath))
            {
                try
                {
                    using var k = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                    ctx.IncrementRegistryKeys();
                    if (k is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Marktplatz",
                            Title = $"Cheat-Registry-Eintrag: {cheatName}",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + regPath,
                            Reason = $"Registry-Schluessel fuer Cheat '{cheatName}' gefunden. " +
                                     "Cheat-Software schreibt Konfiguration und Lizenzdaten in die Registry.",
                            Detail = $"Registry: HKCU\\{regPath}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // Browser history scanning (binary text search, no SQLite library)
    // -------------------------------------------------------------------------

    private static async Task ScanBrowserHistoryFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var historyFiles = LocateBrowserHistoryFiles();
        var allCheatDomains = CheatForumDomains
            .Concat(CheatMarketplaceDomains)
            .Concat(FiveMCheatDomains)
            .Concat(OtherCheatDomains)
            .ToArray();

        foreach (var (browser, historyPath) in historyFiles)
        {
            if (ct.IsCancellationRequested) return;
            if (!File.Exists(historyPath)) continue;

            ctx.IncrementFiles();
            await ScanBinaryFileForUrlPatternsAsync(ctx, browser, historyPath,
                allCheatDomains, DiscordCheatInviteSlugs, KnownCheatServerIds, ct).ConfigureAwait(false);
        }
    }

    private static async Task ScanBinaryFileForUrlPatternsAsync(
        ScanContext ctx, string browser, string filePath,
        string[] cheatDomains, string[] discordSlugs, string[] serverIds,
        CancellationToken ct)
    {
        const int maxReadBytes = 512 * 1024;
        try
        {
            byte[] buffer = new byte[maxReadBytes];
            int bytesRead;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                bytesRead = await fs.ReadAsync(buffer.AsMemory(0, maxReadBytes), ct).ConfigureAwait(false);
            }

            var content = System.Text.Encoding.Latin1.GetString(buffer, 0, bytesRead);

            var hitDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var domain in cheatDomains)
            {
                if (ct.IsCancellationRequested) return;
                if (!content.Contains(domain, StringComparison.OrdinalIgnoreCase)) continue;
                if (hitDomains.Add(domain))
                {
                    bool isForum = CheatForumDomains.Contains(domain, StringComparer.OrdinalIgnoreCase);
                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Marktplatz",
                        Title = $"Browser-Besuch: {domain}",
                        Risk = isForum ? RiskLevel.Medium : RiskLevel.High,
                        Location = domain,
                        Reason = isForum
                            ? $"Browser-Verlauf ({browser}) enthaelt Besuch von Cheat-Forum '{domain}'. " +
                              "Diese Webseite ist ein bekanntes Forum fuer den Austausch von Cheats und Exploits."
                            : $"Browser-Verlauf ({browser}) enthaelt Besuch von Cheat-Marktplatz '{domain}'. " +
                              "Diese Webseite ist ein kommerzieller Anbieter von Cheat-Software.",
                        Detail = $"Browser: {browser} | Domain: {domain}"
                    });
                }
            }

            foreach (var slug in discordSlugs)
            {
                if (ct.IsCancellationRequested) return;
                var pattern = "discord.gg/" + slug;
                if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Marktplatz",
                    Title = $"Discord Cheat-Einladung: {slug}",
                    Risk = RiskLevel.Medium,
                    Location = "discord.gg/" + slug,
                    Reason = $"Browser-Verlauf ({browser}) enthaelt Discord-Einladungslink 'discord.gg/{slug}'. " +
                             "Dieser Discord-Server ist mit einer bekannten Cheat-Community assoziiert.",
                    Detail = $"Browser: {browser} | Einladungslink: discord.gg/{slug}"
                });
            }

            foreach (var serverId in serverIds)
            {
                if (ct.IsCancellationRequested) return;
                var pattern = "discord.com/channels/" + serverId;
                if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Marktplatz",
                    Title = "Discord Cheat-Server-Zugriff",
                    Risk = RiskLevel.Medium,
                    Location = "discord.com/channels/" + serverId,
                    Reason = $"Browser-Verlauf ({browser}) enthaelt Zugriff auf bekannten Cheat-Discord-Server (ID: {serverId}).",
                    Detail = $"Browser: {browser} | Server-ID: {serverId}"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private static IEnumerable<(string browser, string path)> LocateBrowserHistoryFiles()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var chromiumRoots = new (string browser, string root)[]
        {
            ("Chrome",  Path.Combine(local, "Google", "Chrome", "User Data")),
            ("Edge",    Path.Combine(local, "Microsoft", "Edge", "User Data")),
            ("Brave",   Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Vivaldi", Path.Combine(local, "Vivaldi", "User Data")),
        };

        foreach (var (browser, root) in chromiumRoots)
        {
            if (!Directory.Exists(root)) continue;
            var defaultHistory = Path.Combine(root, "Default", "History");
            if (File.Exists(defaultHistory)) yield return (browser, defaultHistory);

            string[] profiles;
            try { profiles = Directory.GetDirectories(root, "Profile *"); }
            catch { profiles = Array.Empty<string>(); }
            foreach (var prof in profiles)
            {
                var db = Path.Combine(prof, "History");
                if (File.Exists(db)) yield return (browser, db);
            }
        }

        foreach (var opera in new[] { "Opera Stable", "Opera GX Stable" })
        {
            var db = Path.Combine(roaming, "Opera Software", opera, "History");
            if (File.Exists(db)) yield return ("Opera", db);
        }

        var ffProfiles = Path.Combine(roaming, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(ffProfiles))
        {
            string[] profs;
            try { profs = Directory.GetDirectories(ffProfiles); }
            catch { profs = Array.Empty<string>(); }
            foreach (var prof in profs)
            {
                var db = Path.Combine(prof, "places.sqlite");
                if (File.Exists(db)) yield return ("Firefox", db);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Downloads folder scan
    // -------------------------------------------------------------------------

    private static async Task ScanDownloadsForCheatArchivesAsync(ScanContext ctx, CancellationToken ct)
    {
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (!Directory.Exists(downloads)) return;

        string[] files;
        try { files = Directory.GetFiles(downloads, "*.*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(file).ToLowerInvariant();
            var ext = Path.GetExtension(fn).ToLowerInvariant();

            if (!ArchiveExtensions.Contains(ext)) continue;

            bool matchesBrand = CheatBrandNames.Any(b => fn.Contains(b, StringComparison.OrdinalIgnoreCase));
            if (!matchesBrand) continue;

            string? matchedBrand = CheatBrandNames.FirstOrDefault(b =>
                fn.Contains(b, StringComparison.OrdinalIgnoreCase));

            long size = 0;
            try { size = new FileInfo(file).Length; } catch { }

            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Marktplatz",
                Title = $"Cheat-Archiv heruntergeladen: {matchedBrand}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = Path.GetFileName(file),
                Reason = $"Datei '{Path.GetFileName(file)}' im Downloads-Ordner enthaelt bekannten Cheat-Markennamen '{matchedBrand}'. " +
                         "Heruntergeladene Cheat-Archive sind ein starker Indikator fuer aktiven Cheat-Gebrauch.",
                Detail = $"Pfad: {file} | Groesse: {size} Bytes | Marke: {matchedBrand}"
            });
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // Payment receipts / invoices
    // -------------------------------------------------------------------------

    private static async Task ScanForPaymentReceiptsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
        };

        var receiptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".pdf", ".png", ".jpg", ".jpeg", ".bmp", ".webp",
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file).ToLowerInvariant();
                var ext = Path.GetExtension(fn).ToLowerInvariant();

                if (!receiptExtensions.Contains(ext)) continue;

                bool hasInvoiceKeyword = InvoiceKeywords.Any(k =>
                    fn.Contains(k, StringComparison.OrdinalIgnoreCase));
                bool hasCheatKeyword = InvoiceCheatKeywords.Any(k =>
                    fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!hasInvoiceKeyword || !hasCheatKeyword) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Marktplatz",
                    Title = $"Moeglicher Cheat-Kaufbeleg: {Path.GetFileName(file)}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = $"Datei '{Path.GetFileName(file)}' koennte ein Kaufbeleg fuer Cheat-Software sein. " +
                             "Kaeufer behalten oft Rechnungen oder Quittungen fuer gekaufte Cheat-Abonnements.",
                    Detail = $"Pfad: {file}"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // Prefetch for loaders
    // -------------------------------------------------------------------------

    private static void ScanPrefetchForLoaders(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(PrefetchDir)) return;
        string[] files;
        try { files = Directory.GetFiles(PrefetchDir, "*.pf"); }
        catch { return; }

        var loaderPrefixes = new[]
        {
            "CHEAT_LOADER", "CHEATLOADER", "INJECT_LOADER", "PREMIUM_LOADER",
            "PRIVATE_LOADER", "CRACKED_LOADER", "BYPASSED_LOADER",
            "CS2_LOADER", "VALORANT_LOADER", "FIVEM_LOADER",
        };

        var brandPrefixes = CheatBrandNames
            .Select(b => b.ToUpperInvariant())
            .ToArray();

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var pfName = Path.GetFileNameWithoutExtension(file);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            bool isLoaderPrefix = loaderPrefixes.Any(p =>
                exeName.StartsWith(p, StringComparison.OrdinalIgnoreCase));
            bool isBrandPrefix = brandPrefixes.Any(b =>
                exeName.StartsWith(b, StringComparison.OrdinalIgnoreCase));

            if (!isLoaderPrefix && !isBrandPrefix) continue;

            DateTime? lastWrite = null;
            try { lastWrite = File.GetLastWriteTime(file); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Marktplatz",
                Title = isLoaderPrefix
                    ? $"Cheat-Loader in Prefetch: {exeName}"
                    : $"Cheat-Markenname in Prefetch: {exeName}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = exeName + ".exe",
                Reason = isLoaderPrefix
                    ? $"Prefetch-Eintrag '{exeName}' weist auf Ausfuehrung eines Cheat-Loaders hin. " +
                      "Loader werden zum Herunterladen und Einspritzen von Cheat-DLLs verwendet."
                    : $"Prefetch-Eintrag '{exeName}' enthaelt bekannten Cheat-Markennamen. " +
                      "Dieser Eintrag deutet auf direkte Ausfuehrung von Cheat-Software hin.",
                Detail = lastWrite.HasValue
                    ? $"Prefetch zuletzt aktualisiert: {lastWrite.Value:yyyy-MM-dd HH:mm:ss}"
                    : null
            });
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static IEnumerable<string> GetUserScanDirectories()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        return new[]
        {
            Path.Combine(profile, "Desktop"),
            Path.Combine(profile, "Downloads"),
            Path.Combine(profile, "Documents"),
            appData,
            localAppData,
        }.Where(Directory.Exists);
    }
}
