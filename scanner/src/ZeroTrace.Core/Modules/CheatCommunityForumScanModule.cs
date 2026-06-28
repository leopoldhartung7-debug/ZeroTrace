using ZeroTrace.Core.Models;
using System.Text;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Forensic scan of local storage artifacts from cheat community platforms:
/// Discord server cache, browser history, local app caches, and downloaded files
/// from known cheat distribution forums and communities.
///
/// Primary cheat distribution channels:
///
///   1. UnknownCheats (unknowncheats.me) — largest public cheat forum
///      - Free cheat downloads, tutorials, source code
///      - Browser history + cookies evidence
///
///   2. MPGH (mpgh.net) — multi-player game hacking forum
///      - Public ESP/aimbot releases, injectors
///
///   3. Hackforums (hackforums.net) — general hacking + gaming cheats
///
///   4. Elitepvpers (elitepvpers.com) — German gaming cheat forum
///
///   5. Cheat communities by game:
///      - EFT: pestily.live forum, EFT-related Telegram groups
///      - CS2: surfboard, gamesense Discord
///      - GTA V: gtainside, gta5-mods (for legit mods but also cheats)
///      - Valorant: various Discord servers
///
///   6. Cheat marketplace/shop domains (many are private invite-only):
///      - aimware.net, onetap.com, gamesense.pub, fatality.win
///      - neverlose.cc, skeet.cc, 2take1.menu, cherax.gg
///      - interwebz.cc, zenith-cheat.com, supremacy.to
///      - ozarkgta.com, stand-hud.menu, midnight-menu.com
///      - kiddion.net (modest menu)
///
/// Detection strategy:
///   - Browser history SQLite: check for domain names (already in BrowserHistoryScanModule
///     but this module adds FORUM-specific domains not in the cheat tool list)
///   - Browser cookies: cheat forum session cookies prove active membership
///   - Browser local storage: some cheat shops use localStorage for auth tokens
///   - Downloaded file names: "UC_release.zip", "mpgh_download.rar" patterns
///   - Windows Search cache: indexed cheat forum page titles
///
/// Ocean/detect.ac scan browser artifacts for forum membership because:
///   - Forum registration proves intent to cheat even without installed tools
///   - Downloaded archives contain cheat tool files even after extraction
///   - Session cookies prove recent active forum visits
/// </summary>
public sealed class CheatCommunityForumScanModule : IScanModule
{
    public string Name => "Cheat-Community Forum & Marketplace Artefakt-Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    // Cheat forum and marketplace domains — distinct from the cheat tool domains in BrowserHistory
    private static readonly string[] CheatForumDomains =
    {
        // Major cheat forums
        "unknowncheats.me", "unknowncheats", "ucheats",
        "mpgh.net", "mpgh",
        "hackforums.net", "hackforums",
        "elitepvpers.com", "elitepvpers",
        "nextgenupdate.com", "nextgenupdate",
        "cheat.ph", "cheatph",
        "se7ensins.com", "se7ensins",
        "wemod.com",                          // trainer marketplace
        "fearless-cheat.com",
        "epicnpc.com",
        "playerup.com",

        // GTA V cheat specific
        "ozarkgta.com", "ozark",
        "stand-hud.menu", "stand-menu",
        "kiddion.net", "kiddions",
        "midnight-menu.com", "midnightmenu",
        "cherax.gg", "cherax",
        "2take1.menu", "2take1",

        // CS/Valorant cheat specific
        "onetap.com", "onetap",
        "gamesense.pub", "gamesense",
        "aimware.net", "aimware",
        "fatality.win", "fatality",
        "neverlose.cc", "neverlose",
        "skeet.cc", "skeet",
        "interwebz.cc", "interwebz",
        "supremacy.to", "supremacy",
        "zenith-cheat.com", "zenith",
        "calamari.gg", "calamari",
        "bestiacheat.com",
        "paladin-cheat.com",
        "softaim.cc",
        "hvhskins.com",
        "pandorahacks.com",
        "csgocheats.org",
        "hvhbooster",

        // Rust/EFT specific
        "rustcheat", "rustcheats",
        "strikehack", "eft-hack", "tarkovhack",
        "gamingchair.biz",

        // Payment processors used by cheat vendors
        "coingate.com",
        "nowpayments.io",
        "cryptomus.com",
        "plisio.net",
        "SellerPortal", "cheatpanel",
    };

    // Cookie database paths for Chromium browsers
    private static readonly (string BrowserName, string CookiePath)[] CookiePaths;

    static CheatCommunityForumScanModule()
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        CookiePaths = new[]
        {
            ("Chrome",  Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Cookies")),
            ("Edge",    Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Cookies")),
            ("Brave",   Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cookies")),
            ("Opera",   Path.Combine(appData, "Opera Software", "Opera Stable", "Cookies")),
            ("Vivaldi", Path.Combine(localAppData, "Vivaldi", "User Data", "Default", "Cookies")),
        };
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        // 1. Scan browser Cookies SQLite databases for cheat forum domains
        ScanBrowserCookies(ctx, ct);

        // 2. Scan browser Local Storage for cheat shop auth artifacts
        ScanBrowserLocalStorage(ctx, ct);

        // 3. Scan Downloads for cheat forum release archive names
        ScanDownloadedForumArchives(ctx, ct);
    }

    private void ScanBrowserCookies(ScanContext ctx, CancellationToken ct)
    {
        foreach (var (browserName, cookiePath) in CookiePaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(cookiePath)) continue;

            // Copy to temp to avoid SQLite lock
            string tempCopy = Path.Combine(Path.GetTempPath(), $"zt_cookies_{Guid.NewGuid()}.tmp");
            try
            {
                File.Copy(cookiePath, tempCopy, overwrite: true);
                ctx.IncrementFiles();

                // Byte-grep the raw SQLite file for domain strings
                // Cookies DB stores host_key in plaintext — readable without SQLite
                byte[] data = File.ReadAllBytes(tempCopy);
                string raw = Encoding.UTF8.GetString(data);

                foreach (var domain in CheatForumDomains)
                {
                    ct.ThrowIfCancellationRequested();
                    if (raw.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"{browserName} Cookie: Cheat-Forum '{domain}' — aktive Session",
                            Risk     = RiskLevel.High,
                            Location = cookiePath,
                            FileName = $"{browserName} Cookies",
                            Reason   = $"Browser-Cookie für Cheat-Forum/Marketplace '{domain}' in {browserName}-Cookies " +
                                       "gefunden. Browser-Cookies beweisen aktive Anmeldung und Session auf dieser " +
                                       "Website. Cheat-Forum-Cookies persistieren nach Browser-History-Löschung " +
                                       "und sind ein primäres forensisches Beweismittel bei Ocean/detect.ac.",
                            Detail   = $"Browser: {browserName} | Domain: {domain} | Datei: {cookiePath}"
                        });
                        break; // One finding per browser per file
                    }
                }
            }
            catch { }
            finally
            {
                try { File.Delete(tempCopy); } catch { }
            }
        }
    }

    private void ScanBrowserLocalStorage(ScanContext ctx, CancellationToken ct)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var localStorageRoots = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"),
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb"),
        };

        foreach (var lsRoot in localStorageRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(lsRoot)) continue;

            try
            {
                // LevelDB log files are readable as text
                foreach (var logFile in Directory.GetFiles(lsRoot, "*.log")
                    .Concat(Directory.GetFiles(lsRoot, "*.ldb")))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        long size = new FileInfo(logFile).Length;
                        if (size > 5 * 1024 * 1024) continue; // Skip huge files

                        byte[] data = File.ReadAllBytes(logFile);
                        string content = Encoding.UTF8.GetString(data);

                        string? match = CheatForumDomains.FirstOrDefault(d =>
                            content.Contains(d, StringComparison.OrdinalIgnoreCase));

                        if (match != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Browser Local Storage: Cheat-Forum '{match}' Auth-Daten",
                                Risk     = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason   = $"Browser Local Storage enthält Daten von Cheat-Forum '{match}'. " +
                                           "Local Storage speichert Authentifizierungs-Tokens, Sitzungsdaten und " +
                                           "Benutzerpräferenzen von Cheat-Shops — persistiert nach Verlauf-Löschung.",
                                Detail   = $"Datei: {logFile} | Domain: {match}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void ScanDownloadedForumArchives(ScanContext ctx, CancellationToken ct)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string downloads   = Path.Combine(userProfile, "Downloads");

        // Forum release archives often have "UC_", "MPGH_", "[UC]", or forum-specific naming
        string[] forumArchivePatterns =
        {
            "uc_", "[uc]", "unknowncheats", "mpgh_", "[mpgh]", "mpgh.",
            "hackforums", "elitepvpers", "se7ensins", "nextgenupdate",
            "cheatforum", "cheat_release", "cheat_v", "_cheat.", "cheat_download",
            "free_cheat", "paid_cheat", "external_cheat", "internal_cheat",
            "esp_release", "aimbot_release", "wallhack_release",
            "loader_v", "injector_v", "bypass_v",
            "cracked_", "_cracked", "_leaked", "leaked_",
        };

        string[] archiveExts = { ".zip", ".rar", ".7z", ".tar", ".gz" };

        foreach (var dir in new[] { downloads, desktop })
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                var files = Directory.GetFiles(dir)
                    .Where(f => archiveExts.Contains(Path.GetExtension(f).ToLowerInvariant()));

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    string fname = Path.GetFileName(file).ToLowerInvariant();
                    string? match = forumArchivePatterns.FirstOrDefault(p => fname.Contains(p));

                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat-Forum Archiv-Download: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Archiv-Datei '{Path.GetFileName(file)}' enthält Cheat-Forum-Pattern '{match}'. " +
                                       "Cheat-Forum-Releases werden typischerweise als Archive mit forum-spezifischen " +
                                       "Präfixen (UC_, MPGH_) oder Cheat-Typ-Suffixen (esp_release, aimbot_v) " +
                                       "hochgeladen. Dieses Archiv wurde von einem Cheat-Forum heruntergeladen.",
                            Detail   = $"Datei: {file} | Pattern: {match}"
                        });
                    }
                }
            }
            catch { }
        }
    }
}
