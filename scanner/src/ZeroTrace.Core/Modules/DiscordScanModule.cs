using System.Text;
using System.Text.RegularExpressions;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Recovers Discord guild (server) memberships from the Discord client's local
/// cache (LevelDB + IndexedDB blobs under %APPDATA%\discord\Local Storage and
/// the message cache). Guild names are classified as either cheat- or
/// reseller-related, and matches are reported as findings and added to the
/// host inventory's DiscordGuilds list (which feeds the dashboard's "Discord
/// Server" panel and the webhook payload).
///
/// Read-only. No tokens, messages, DMs or PII are exfiltrated — only the
/// guild names and IDs that are already locally cached on the user's machine
/// are inspected.
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
    };

    // Keywords that flag a guild as a reseller / cheat-marketplace server.
    private static readonly string[] ResellerKeywords =
    {
        "resell", "reseller", "reselling", "shop", "store", "market",
        "sellix", ".gg/buy", "sales", "verkauf", "sellauth", "plug",
        "services", "marketplace", "vouches", "paypal shop",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        // Discord installs as: Stable / PTB / Canary — scan all three.
        var clients = new[] { "discord", "discordptb", "discordcanary" };
        var allGuilds = new Dictionary<string, DiscordGuildInfo>(StringComparer.OrdinalIgnoreCase);

        foreach (var client in clients)
        {
            if (ct.IsCancellationRequested) break;
            var root = Path.Combine(roaming, client);
            if (!Directory.Exists(root)) continue;

            try { CollectFromLocalStorage(root, allGuilds, ct); } catch { }
            try { CollectFromCache(root, allGuilds, ct); } catch { }
        }

        ctx.Report(0.5, "Discord", $"{allGuilds.Count} Server gefunden");

        if (allGuilds.Count == 0)
        {
            ctx.Report(1.0, "Discord", "Kein Discord-Client / keine Server im Cache");
            return Task.CompletedTask;
        }

        int cheatHits = 0, resellHits = 0;
        foreach (var g in allGuilds.Values)
        {
            if (ct.IsCancellationRequested) break;
            g.Flag = ClassifyGuild(g.Name);

            if (g.Flag == "cheat")
            {
                cheatHits++;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Mitglied in Cheat-Discord: {g.Name}",
                    Risk = RiskLevel.High,
                    Location = $"Discord-Server-ID: {g.Id}",
                    Reason = $"Der gescannte Nutzer ist Mitglied im Discord-Server '{g.Name}', " +
                             "dessen Name auf einen Cheat- / Hack-Server hinweist. " +
                             "Diese Information stammt aus dem lokalen Discord-Cache.",
                    Detail = $"Server: {g.Name} | ID: {g.Id}"
                });
            }
            else if (g.Flag == "reselling")
            {
                resellHits++;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Mitglied in Reseller-Discord: {g.Name}",
                    Risk = RiskLevel.Medium,
                    Location = $"Discord-Server-ID: {g.Id}",
                    Reason = $"Der gescannte Nutzer ist Mitglied im Discord-Server '{g.Name}', " +
                             "dessen Name auf einen Cheat-Marketplace / Reseller hinweist.",
                    Detail = $"Server: {g.Name} | ID: {g.Id}"
                });
            }
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

        // Hand the guild list to the host inventory. The webhook builder and the
        // dashboard's "Discord Server" panel both pick it up from there.
        ctx.Inventory.DiscordGuilds.AddRange(sorted);

        ctx.Report(1.0, "Discord", "Discord-Server geprueft");
        return Task.CompletedTask;
    }

    private static string ClassifyGuild(string name)
    {
        var n = (name ?? string.Empty).ToLowerInvariant();
        if (CheatKeywords.Any(k => n.Contains(k))) return "cheat";
        if (ResellerKeywords.Any(k => n.Contains(k))) return "reselling";
        return "clean";
    }

    // --- LevelDB scrape: Local Storage / leveldb/*.ldb + *.log ---------------
    // Discord's Local Storage uses Chromium's LevelDB. We don't parse the
    // SSTable structure — we just read the raw bytes and grep for the
    // guild-membership patterns Discord writes to it. Names appear in JSON
    // fragments like {"id":"123456789012345678","name":"Server Name", ...}.
    private static void CollectFromLocalStorage(
        string discordRoot,
        Dictionary<string, DiscordGuildInfo> sink,
        CancellationToken ct)
    {
        var ldbDir = Path.Combine(discordRoot, "Local Storage", "leveldb");
        if (!Directory.Exists(ldbDir)) return;

        foreach (var file in Directory.EnumerateFiles(ldbDir))
        {
            if (ct.IsCancellationRequested) return;
            var ext = Path.GetExtension(file).ToLowerInvariant();
            if (ext != ".ldb" && ext != ".log") continue;
            ExtractGuildsFromBlob(file, sink);
        }
    }

    // --- IndexedDB / Cache scrape: %APPDATA%\discord\Cache\Cache_Data\* ------
    private static void CollectFromCache(
        string discordRoot,
        Dictionary<string, DiscordGuildInfo> sink,
        CancellationToken ct)
    {
        // Chromium has migrated cache layouts over the years; cover both.
        var candidates = new[]
        {
            Path.Combine(discordRoot, "Cache", "Cache_Data"),
            Path.Combine(discordRoot, "Cache"),
            Path.Combine(discordRoot, "Code Cache", "js"),
        };

        foreach (var dir in candidates)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir).Take(60))
                {
                    if (ct.IsCancellationRequested) return;
                    var fi = new FileInfo(file);
                    if (fi.Length > 8 * 1024 * 1024) continue; // skip > 8 MB
                    ExtractGuildsFromBlob(file, sink);
                }
            }
            catch { /* skip unreadable directory */ }
        }
    }

    // Extracts {id, name} pairs from a Chromium / Discord storage blob.
    // We tolerate binary noise around JSON fragments — the regex pins on the
    // shape Discord serializes guild objects with.
    private static readonly Regex GuildRegex = new(
        @"""id""\s*:\s*""(\d{17,20})""\s*,\s*""name""\s*:\s*""([^""\\]{1,80}(?:\\.[^""\\]{0,80})*)""",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static void ExtractGuildsFromBlob(
        string path,
        Dictionary<string, DiscordGuildInfo> sink)
    {
        byte[] bytes;
        try { bytes = File.ReadAllBytes(path); }
        catch { return; }

        // The blob is UTF-8 text with binary framing — Latin-1 keeps every byte
        // distinct so the regex can match the JSON fragments verbatim.
        var text = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

        foreach (Match m in GuildRegex.Matches(text))
        {
            var id = m.Groups[1].Value;
            var rawName = m.Groups[2].Value;
            // Unescape common JSON escapes; ignore the rest.
            var name = rawName
                .Replace(@"\""", "\"")
                .Replace(@"\\", "\\")
                .Replace(@"\/", "/")
                .Replace(@"\n", " ")
                .Replace(@"\t", " ")
                .Trim();
            if (string.IsNullOrWhiteSpace(name) || name.Length > 100) continue;

            if (!sink.ContainsKey(id))
                sink[id] = new DiscordGuildInfo { Id = id, Name = name };
        }
    }
}
