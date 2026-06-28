using System.Text.Json;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans browser bookmark files for entries pointing to cheat sites and cheat
/// marketplaces. Browser bookmarks are a permanent record of user interest in
/// cheat tools — they persist across history clears (a "Clear browsing history"
/// does NOT remove bookmarks). Ocean and detect.ac mine this signal because
/// users who bookmark cheat sites almost always intend to use them.
///
/// Bookmark file locations:
///   Chromium family: %LOCALAPPDATA%\&lt;Browser&gt;\User Data\Default\Bookmarks (JSON)
///   Firefox:         %APPDATA%\Mozilla\Firefox\Profiles\&lt;profile&gt;\places.sqlite
///   Brave:           %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Bookmarks
///   Vivaldi:         %LOCALAPPDATA%\Vivaldi\User Data\Default\Bookmarks
///   Opera:           %APPDATA%\Opera Software\Opera Stable\Bookmarks
///   Edge:            %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Bookmarks
///
/// Chromium bookmarks are plain JSON — we parse the file for "url" entries and
/// match against a curated cheat-site fragment list. Firefox places.sqlite is
/// SQLite; we byte-grep the same way as the Timeline DB module.
/// </summary>
public sealed class BrowserBookmarksCheatScanModule : IScanModule
{
    public string Name => "Browser Bookmarks Cheat-Site Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    private static readonly string[] CheatHostFragments =
    {
        // Marketplaces and cheat suites (known reseller / vendor domains)
        "gamesense.pub", "onetap.com", "fatality.win", "aimware.net",
        "limeware.fr", "ev0lve.cc", "neverlose.cc", "skeet.cc",
        "primordial.cc", "weave.gg", "intellect.cx",
        // GTA V
        "kiddion.com", "2take1.menu", "stand.sh", "cherax.dev",
        "midnight.menu", "ozark.menu", "rampage.menu",
        // EFT
        "skycheats.com", "magicbullet.cc", "skytap.io",
        // CoD / Warzone
        "engineowning.to", "iniuria.us", "vapeflux.io", "interwebz.cc",
        // Apex
        "apexlegit.com", "spectre.gg",
        // Valorant
        "tronix.gg", "lethal.gg", "absolutesoftware.cc",
        // Universal cheat marketplaces
        "elitepvpers.com", "unknowncheats.me", "mpgh.net",
        "guidedhacking.com", "ownedcore.com", "battlelog.co",
        // DMA hardware
        "pcileech.cc", "memprocfs.io", "ufactory.cc",
        // HWID spoofers
        "permspoofer.com", "tempspoofer.io", "hwidchanger.com",
        // Cheat-Engine related
        "cheatengine.org", "cheat-engine.com",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string local   = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var chromiumPaths = new[]
        {
            System.IO.Path.Combine(local,   "Google",        "Chrome",        "User Data"),
            System.IO.Path.Combine(local,   "BraveSoftware", "Brave-Browser", "User Data"),
            System.IO.Path.Combine(local,   "Microsoft",     "Edge",          "User Data"),
            System.IO.Path.Combine(local,   "Vivaldi",       "User Data"),
            System.IO.Path.Combine(local,   "Yandex",        "YandexBrowser", "User Data"),
            System.IO.Path.Combine(local,   "Chromium",      "User Data"),
            System.IO.Path.Combine(roaming, "Opera Software","Opera Stable"),
            System.IO.Path.Combine(roaming, "Opera Software","Opera GX Stable"),
        };

        foreach (string root in chromiumPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(root)) continue;

            // Profiles: Default, Profile 1, Profile 2, ...
            try
            {
                foreach (string profile in System.IO.Directory.EnumerateDirectories(root))
                {
                    string bookmarks = System.IO.Path.Combine(profile, "Bookmarks");
                    if (System.IO.File.Exists(bookmarks))
                        ScanChromiumBookmarks(ctx, bookmarks, ct);
                }

                // Also check the root for Opera-style flat layout
                string flatBookmarks = System.IO.Path.Combine(root, "Bookmarks");
                if (System.IO.File.Exists(flatBookmarks))
                    ScanChromiumBookmarks(ctx, flatBookmarks, ct);
            }
            catch { }
        }

        // Firefox profiles
        string ff = System.IO.Path.Combine(roaming, "Mozilla", "Firefox", "Profiles");
        if (System.IO.Directory.Exists(ff))
        {
            try
            {
                foreach (string profile in System.IO.Directory.EnumerateDirectories(ff))
                {
                    string places = System.IO.Path.Combine(profile, "places.sqlite");
                    if (System.IO.File.Exists(places))
                        ScanFirefoxPlaces(ctx, places, ct);
                }
            }
            catch { }
        }
    }

    private void ScanChromiumBookmarks(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            var info = new System.IO.FileInfo(path);
            if (info.Length == 0 || info.Length > 32 * 1024 * 1024) return;
            ctx.IncrementFiles();

            string json = System.IO.File.ReadAllText(path);
            using JsonDocument doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("roots", out var roots)) return;

            foreach (JsonProperty rootEntry in roots.EnumerateObject())
            {
                WalkBookmarkNode(ctx, path, rootEntry.Value, ct);
            }
        }
        catch { }
    }

    private void WalkBookmarkNode(ScanContext ctx, string sourceFile,
        JsonElement node, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (node.ValueKind != JsonValueKind.Object) return;

        if (node.TryGetProperty("type", out var typeEl))
        {
            string? type = typeEl.GetString();
            if (type == "url" && node.TryGetProperty("url", out var urlEl))
            {
                string? url = urlEl.GetString();
                string? name = node.TryGetProperty("name", out var nameEl) ? nameEl.GetString() : null;
                if (!string.IsNullOrEmpty(url)) CheckUrl(ctx, sourceFile, url, name);
            }
        }

        if (node.TryGetProperty("children", out var children) &&
            children.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement child in children.EnumerateArray())
                WalkBookmarkNode(ctx, sourceFile, child, ct);
        }
    }

    private void CheckUrl(ScanContext ctx, string sourceFile, string url, string? name)
    {
        string urlLower = url.ToLowerInvariant();
        foreach (string frag in CheatHostFragments)
        {
            if (!urlLower.Contains(frag)) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Cheat-Lesezeichen: {(name ?? frag)}",
                Risk     = RiskLevel.High,
                Location = url,
                FileName = System.IO.Path.GetFileName(sourceFile),
                Reason   = $"Browser-Lesezeichen verweist auf bekannte Cheat-/Hack-Domain " +
                           $"'{frag}'. Lesezeichen überleben das Löschen des Browser-Verlaufs " +
                           "und sind ein dauerhaftes Indiz für Interesse an Cheat-Tools. " +
                           "Ocean und detect.ac mining diese Quelle als Standard-Signal.",
                Detail   = $"URL: {url}" +
                           (name is not null ? $" | Titel: {name}" : "") +
                           $" | Bookmark-Datei: {sourceFile}"
            });
            return;
        }
    }

    private void ScanFirefoxPlaces(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            var info = new System.IO.FileInfo(path);
            if (info.Length == 0 || info.Length > 256 * 1024 * 1024) return;
            ctx.IncrementFiles();

            byte[] data = System.IO.File.ReadAllBytes(path);
            string utf8 = System.Text.Encoding.UTF8.GetString(data);
            string lower = utf8.ToLowerInvariant();

            foreach (string frag in CheatHostFragments)
            {
                if (!lower.Contains(frag)) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Domain in Firefox places.sqlite: {frag}",
                    Risk     = RiskLevel.High,
                    Location = path,
                    FileName = "places.sqlite",
                    Reason   = $"Firefox-Datenbank places.sqlite enthält die Cheat-Domain '{frag}'. " +
                               "places.sqlite speichert sowohl Lesezeichen als auch Verlaufsdaten " +
                               "im selben SQLite-Schema. Treffer kann Lesezeichen oder besuchte " +
                               "Adresse sein — beides starkes Indiz für Cheat-Tool-Nutzung.",
                    Detail   = $"Datei: {path} | Fragment: {frag}"
                });
                break;
            }
        }
        catch { }
    }
}
