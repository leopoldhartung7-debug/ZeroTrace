using System.Text;
using System.Text.RegularExpressions;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Recovers Discord guild (server) memberships and account info from the
/// Discord client's local cache (LevelDB + IndexedDB blobs under
/// %APPDATA%\discord\Local Storage and the message cache).
///
/// Output:
///  - Inventory.DiscordGuilds: list of all locally-cached guilds with a
///    classification flag ("clean", "reselling", "cheat") plus the keyword
///    that triggered the flag (so the operator can see why).
///  - Inventory.DiscordAccount: the logged-in user's ID, username and global
///    name (no token, no email, no DMs, no messages).
///  - Findings: one High-Risk finding per cheat-Discord, one Medium-Risk
///    finding per reseller-Discord, and an additional Critical finding when
///    a cheat-Discord is paired with an already-known cheat process or file
///    elsewhere in the scan (cross-module correlation).
///
/// Strictly read-only. No tokens, messages, DMs, friend lists or PII other
/// than the user's own public Discord identity are touched.
/// </summary>
public sealed class DiscordScanModule : IScanModule
{
    public string Name => "Discord-Server";
    public double Weight => 0.4;

    // Keywords that flag a guild as a cheat-/hack-distribution server.
    // Match is case-insensitive and against the full guild name.
    private static readonly string[] CheatKeywords =
    {
        "cheat", "cheats", "hack", "hacks", "spoofer", "loader", "menu",
        "modmenu", "mod menu", "aimbot", " esp", "unlock", "crack",
        "leak", "bypass", "inject", "exploit", "ggez", "rage",
        "skid", "private menu", "internal menu", "external menu",
        "fivem cheat", "rust hack", "csgo cheat", "valorant cheat",
        "killaura", "wallhack",
        // Modern FiveM/CS2/Valorant cheat brands (2025/2026)
        "redengine", "skript", "eulen", "hammafia", "desudo", "impaught",
        "tsunami", "phantom-x", "ozark", "rxce", "nexusmenu", "lynx",
        "hxcheats", "scarlet", "fearless cheat", "fearless-cheat",
        "kiddion", "cherax", "2take1", "stand menu", "midnight",
        "neverlose", "onetap", "gamesense", "aimware", "fatality",
        "nixware", "lumina", "fecurity", "primordial", "sunset",
        "phoenix cheat", "phoenix-cheat", "skycheats",
        "vape client", "liquidbounce", "wurst client", "meteor client",
        "sigma client", "novoline", "aristois",
        // FiveM-specific marketplaces / loaders
        "yimmenu", "yim menu", "lambda menu", "absolute menu",
        "void cheats", "void-cheats", "celestial", "susano", "hyperion",
        "nsa-ware", "nsaware", "reaper", "spectre menu",
    };

    // Keywords that flag a guild as a reseller / cheat-marketplace server.
    private static readonly string[] ResellerKeywords =
    {
        "resell", "reseller", "reselling", "shop", "store", "market",
        "sellix", ".gg/buy", "sales", "verkauf", "sellauth", "plug",
        "services", "marketplace", "vouches", "paypal shop",
        "cheap cheats", "cheap menus", "key shop", "loader shop",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        // Discord installs as: Stable / PTB / Canary — scan all three.
        var clients = new[] { "discord", "discordptb", "discordcanary" };
        var allGuilds = new Dictionary<string, DiscordGuildInfo>(StringComparer.OrdinalIgnoreCase);
        DiscordAccountInfo? account = null;

        foreach (var client in clients)
        {
            if (ct.IsCancellationRequested) break;
            var root = Path.Combine(roaming, client);
            if (!Directory.Exists(root)) continue;

            try { CollectFromLocalStorage(root, allGuilds, ref account, ct); } catch { }
            try { CollectFromCache(root, allGuilds, ref account, ct); } catch { }
        }

        ctx.Inventory.DiscordAccount = account;
        ctx.Report(0.5, "Discord",
            $"{allGuilds.Count} Server gefunden" +
            (account is null ? "" : $", Account: {account.Username}"));

        if (allGuilds.Count == 0 && account is null)
        {
            ctx.Report(1.0, "Discord", "Kein Discord-Client / keine Daten im Cache");
            return Task.CompletedTask;
        }

        // Pre-compute the set of cheat-related artifacts already found by
        // other modules so we can flag a "Cheat-Discord + Cheat-File on disk"
        // pairing as Critical via cross-module correlation.
        var hasCheatArtifactsOnDisk = ctx.Findings.Any(
            f => f.Risk >= RiskLevel.High &&
                 (f.Module == "Drives" || f.Module == "AppData" ||
                  f.Module == "Installierte Software" || f.Module == "Downloads" ||
                  f.Module == "Prozesse" || f.Module == "FiveM" ||
                  f.Module == "Suspicious Executables"));

        int cheatHits = 0, resellHits = 0;
        foreach (var g in allGuilds.Values)
        {
            if (ct.IsCancellationRequested) break;
            var (flag, kw) = ClassifyGuild(g.Name);
            g.Flag = flag;
            g.MatchedKeyword = kw;

            if (flag == "cheat")
            {
                cheatHits++;
                // Critical when paired with on-disk cheat artifact, else High.
                var risk = hasCheatArtifactsOnDisk ? RiskLevel.Critical : RiskLevel.High;
                var crossNote = hasCheatArtifactsOnDisk
                    ? " Zusaetzlich wurden Cheat-Artefakte auf der Disk gefunden — diese Kombination ist ein starkes Indiz."
                    : string.Empty;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Mitglied in Cheat-Discord: {g.Name}",
                    Risk = risk,
                    Location = $"Discord-Server-ID: {g.Id}",
                    Reason = $"Der gescannte Nutzer ist Mitglied im Discord-Server '{g.Name}' " +
                             $"(Stichwort '{kw}'). Diese Information stammt aus dem lokalen " +
                             $"Discord-Cache.{crossNote}",
                    Detail = $"Server: {g.Name} | ID: {g.Id} | Keyword: {kw}"
                });
            }
            else if (flag == "reselling")
            {
                resellHits++;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Mitglied in Reseller-Discord: {g.Name}",
                    Risk = RiskLevel.Medium,
                    Location = $"Discord-Server-ID: {g.Id}",
                    Reason = $"Der gescannte Nutzer ist Mitglied im Discord-Server '{g.Name}' " +
                             $"(Stichwort '{kw}'), der auf einen Cheat-Marketplace / Reseller hinweist.",
                    Detail = $"Server: {g.Name} | ID: {g.Id} | Keyword: {kw}"
                });
            }
        }

        // Multiple flagged Discords on the same account is itself an indicator.
        if (cheatHits >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Account in {cheatHits} Cheat-Discords",
                Risk = RiskLevel.Critical,
                Location = "Discord-Konto",
                Reason = $"Der Account ist gleichzeitig Mitglied in {cheatHits} Discord-Servern, " +
                         "deren Namen auf Cheats hinweisen. Mehrere Mitgliedschaften sind ein starkes Indiz.",
                Detail = string.Join(" | ", allGuilds.Values
                    .Where(g => g.Flag == "cheat").Select(g => g.Name))
            });
        }

        // If we recovered the user's account, attach it as a context finding so
        // the operator sees who was scanned. Risk is Low — it's metadata.
        if (account != null && !string.IsNullOrEmpty(account.UserId))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Discord-Account erkannt: {account.Username}",
                Risk = RiskLevel.Low,
                Location = $"Discord-User-ID: {account.UserId}",
                Reason = $"Der lokal eingeloggte Discord-Account wurde aus dem Client-Cache gelesen: " +
                         $"@{account.Username}" +
                         (string.IsNullOrEmpty(account.GlobalName) ? "" : $" ({account.GlobalName})") +
                         $" — ID {account.UserId}.",
                Detail = $"Username: {account.Username} | UserID: {account.UserId} | " +
                         $"GlobalName: {account.GlobalName ?? "-"} | Discriminator: {account.Discriminator}"
            });
        }

        ctx.Report(0.9, "Discord",
            $"{cheatHits} Cheat-Server, {resellHits} Reseller-Server geflagt");

        // Cap to 200 entries so an account in thousands of guilds doesn't
        // bloat the report. Flagged servers sort to the top so the dashboard
        // shows them first.
        var sorted = allGuilds.Values
            .OrderBy(g => g.Flag == "cheat" ? 0 : g.Flag == "reselling" ? 1 : 2)
            .ThenBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
            .Take(200)
            .ToList();

        ctx.Inventory.DiscordGuilds.AddRange(sorted);

        ctx.Report(1.0, "Discord", "Discord-Server geprueft");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Returns (flag, matchedKeyword). Cheat-keywords take precedence over
    /// reseller-keywords so a "Cheat Shop" server lands on the cheat list.
    /// </summary>
    private static (string flag, string? keyword) ClassifyGuild(string name)
    {
        var n = (name ?? string.Empty).ToLowerInvariant();
        foreach (var k in CheatKeywords) if (n.Contains(k)) return ("cheat", k.Trim());
        foreach (var k in ResellerKeywords) if (n.Contains(k)) return ("reselling", k.Trim());
        return ("clean", null);
    }

    // --- LevelDB scrape: Local Storage / leveldb/*.ldb + *.log ---------------
    // Discord's Local Storage uses Chromium's LevelDB. We don't parse the
    // SSTable structure — we just read the raw bytes and grep for the
    // guild-membership patterns Discord writes to it.
    private static void CollectFromLocalStorage(
        string discordRoot,
        Dictionary<string, DiscordGuildInfo> sink,
        ref DiscordAccountInfo? account,
        CancellationToken ct)
    {
        var ldbDir = Path.Combine(discordRoot, "Local Storage", "leveldb");
        if (!Directory.Exists(ldbDir)) return;

        foreach (var file in Directory.EnumerateFiles(ldbDir))
        {
            if (ct.IsCancellationRequested) return;
            var ext = Path.GetExtension(file).ToLowerInvariant();
            if (ext != ".ldb" && ext != ".log") continue;
            ExtractFromBlob(file, sink, ref account);
        }
    }

    // --- IndexedDB / Cache scrape: %APPDATA%\discord\Cache\Cache_Data\* ------
    private static void CollectFromCache(
        string discordRoot,
        Dictionary<string, DiscordGuildInfo> sink,
        ref DiscordAccountInfo? account,
        CancellationToken ct)
    {
        // Chromium has migrated cache layouts over the years; cover both.
        var candidates = new[]
        {
            Path.Combine(discordRoot, "Cache", "Cache_Data"),
            Path.Combine(discordRoot, "Cache"),
            Path.Combine(discordRoot, "Code Cache", "js"),
            Path.Combine(discordRoot, "Session Storage"),
        };

        foreach (var dir in candidates)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir).Take(80))
                {
                    if (ct.IsCancellationRequested) return;
                    var fi = new FileInfo(file);
                    if (fi.Length > 8 * 1024 * 1024) continue; // skip > 8 MB
                    ExtractFromBlob(file, sink, ref account);
                }
            }
            catch { /* skip unreadable directory */ }
        }
    }

    // Discord serializes guild objects as {"id":"...","name":"..."} fragments.
    // The "id" must be a Discord snowflake (17–20 digits).
    private static readonly Regex GuildRegex = new(
        @"""id""\s*:\s*""(\d{17,20})""\s*,\s*""name""\s*:\s*""([^""\\]{1,80}(?:\\.[^""\\]{0,80})*)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Self-user payload: usually written as {"user":{"id":"...","username":"...",
    // "discriminator":"...","global_name":"..."}}. Capture the key fields.
    private static readonly Regex SelfUserRegex = new(
        @"""user""\s*:\s*\{\s*""id""\s*:\s*""(\d{17,20})""\s*,\s*""username""\s*:\s*""([^""\\]{1,32}(?:\\.[^""\\]{0,32})*)""(?:\s*,\s*""discriminator""\s*:\s*""(\d{0,4})"")?(?:[^}]{0,200}?""global_name""\s*:\s*""?([^""\\]{0,32}(?:\\.[^""\\]{0,32})*)""?)?",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static void ExtractFromBlob(
        string path,
        Dictionary<string, DiscordGuildInfo> sink,
        ref DiscordAccountInfo? account)
    {
        byte[] bytes;
        try { bytes = File.ReadAllBytes(path); }
        catch { return; }

        // Treat the blob as Latin-1 so every byte stays distinct and the regex
        // can match the JSON fragments verbatim through Chromium's framing.
        var text = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

        foreach (Match m in GuildRegex.Matches(text))
        {
            var id = m.Groups[1].Value;
            var name = UnescapeJson(m.Groups[2].Value);
            if (string.IsNullOrWhiteSpace(name) || name.Length > 100) continue;
            // Skip Discord's special "@me" pseudo-guild and other obvious noise.
            if (name == "@me" || name == "null") continue;
            if (!sink.ContainsKey(id))
                sink[id] = new DiscordGuildInfo { Id = id, Name = name };
        }

        // Only the FIRST self-user payload wins — Discord writes one and
        // multiple cached writes shouldn't switch accounts mid-scan.
        if (account is null)
        {
            var sm = SelfUserRegex.Match(text);
            if (sm.Success)
            {
                account = new DiscordAccountInfo
                {
                    UserId = sm.Groups[1].Value,
                    Username = UnescapeJson(sm.Groups[2].Value),
                    Discriminator = sm.Groups[3].Success ? sm.Groups[3].Value : "",
                    GlobalName = sm.Groups[4].Success
                        ? UnescapeJson(sm.Groups[4].Value)
                        : null,
                };
            }
        }
    }

    private static string UnescapeJson(string raw) =>
        raw.Replace(@"\""", "\"")
           .Replace(@"\\", "\\")
           .Replace(@"\/", "/")
           .Replace(@"\n", " ")
           .Replace(@"\t", " ")
           .Trim();
}
