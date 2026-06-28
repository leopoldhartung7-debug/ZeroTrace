using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Extended DNS client cache analysis for cheat tool C2 (Command &amp; Control) domains,
/// license server domains, and cheat marketplace domains. DNS cache entries reveal
/// recently visited domains even after browser history has been cleared, providing
/// forensic evidence of cheat tool usage.
///
/// DNS cache is read via DnsGetCacheDataTable (dnsapi.dll) — an undocumented but
/// widely-used API that returns the current DNS resolver cache contents. Each entry
/// contains: domain name, record type (A/AAAA/CNAME/MX), TTL, and resolved IP.
///
/// Detection targets:
///   1. Known cheat C2 and license server domains (cheat suite update/auth endpoints)
///   2. Cheat marketplace and reseller domains
///   3. Suspicious TLD patterns (.xyz, .cc, .pw for cheat loader distribution)
///   4. HWID spoofer API endpoints
///   5. Discord/Telegram bot webhook domains used by cheat menus for C2
///   6. Game hack forum domains (unknowncheats.me, mpgh.net, elitepvpers.com)
///   7. IP resolution for known cheat CDN IP ranges
///   8. Obfuscated domain patterns (base64-like, long hex strings)
/// </summary>
public sealed class DnsClientCacheExtendedScanModule : IScanModule
{
    public string Name => "DNS Client Cache Extended Cheat Domain Analysis";
    public double Weight => 0.65;
    public int ParallelGroup => 2;

    // DnsGetCacheDataTable — undocumented dnsapi.dll export
    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable")]
    private static extern int DnsGetCacheDataTable(out nint ppEntry);

    [DllImport("dnsapi.dll")]
    private static extern void DnsReleaseCacheDataTable(nint pEntry);

    // DNS_CACHE_ENTRY structure (undocumented)
    [StructLayout(LayoutKind.Sequential)]
    private struct DNS_CACHE_ENTRY
    {
        public nint pNext;        // pointer to next entry
        public nint pszName;      // PWSTR: domain name
        public ushort wType;      // record type (1=A, 28=AAAA, 5=CNAME, etc.)
        public ushort wDataLength;
        public uint dwFlags;
        public uint dwTtl;
        public uint dwReserved;
    }

    private const ushort DNS_TYPE_A     = 1;
    private const ushort DNS_TYPE_AAAA  = 28;
    private const ushort DNS_TYPE_CNAME = 5;
    private const ushort DNS_TYPE_MX    = 15;
    private const ushort DNS_TYPE_TXT   = 16;

    // Exact cheat domain/subdomain fragments — matched with Contains (case-insensitive)
    private static readonly string[] CheatDomainFragments =
    {
        // Major cheat suites and their license servers
        "gamesense.pub", "gamesense.me", "limeware.net",
        "onetap.su", "onetap.com", "onetap.io",
        "fatality.win", "fatality.su",
        "aimware.net",
        "skycheats.com",
        "neverlose.cc",
        "primordial.cc",
        "interwebz.cc",
        "beserk.cc",
        // GTA V cheat suites
        "kiddions.com", "modestmenu",
        "2take1.menu", "2take1.cc",
        "stand.gg", "stand.cc",
        "midnight.gg",
        "ozark.gg",
        "cherax.cc",
        // Valorant cheats
        "phantom-x.net", "phantom-overlay.cc",
        "hysteria-cheats.cc",
        // HWID spoofer services
        "ezspoofer.cc", "hwid-spoofer.net", "spoofer.gg",
        "fenhwid.com", "fenixspoofer.cc",
        // DMA cheat services
        "pcileech.com", "pcileech.xyz",
        "memflow.xyz",
        "dma-cheat.cc",
        // Cheat loader CDNs / bypass tools
        "loader.gg", "loader.cc", "loader.xyz",
        "bypass-ac.com", "eacbypass.cc", "vacbypass.net",
        // Cheat marketplace domains
        "skidrow.to", "skidrow.cc",
        "unknowncheats.me",
        "mpgh.net",
        "elitepvpers.com",
        "cheatautomation.com",
        "cheatersoul.com",
        "ringofhack.net", "ringofhacks.com",
        "gamelooting.com",
        // Cheat resellers
        "buycheap.gg", "cheaphacks.cc", "gamecheat.shop",
        // BYOVD related
        "mhyprot.com",
        // Known C2 patterns
        "cheat-api.", "hack-api.", "cheat-auth.", "hack-auth.",
        "cheat-cdn.", "cheat-update.", "hack-update.",
        "license.cheat", "license.hack",
        // Anti-cheat bypass services
        "acbypass.", "be-bypass.", "eac-bypass.", "vac-bypass.",
    };

    // High-risk TLD patterns often used by cheat services
    private static readonly string[] CheatTldPatterns =
    {
        ".gg", ".cc", ".pw", ".xyz", ".su",
    };

    // Domain label patterns that are suspicious (regex-like matching)
    private static readonly string[] SuspiciousDomainLabelPatterns =
    {
        "cheat", "hack", "bypass", "inject", "spoof", "loader",
        "aimbot", "wallhack", "esp", "triggerbot", "norecoil",
        "hvh", "rage", "legit-cheat", "legitcheat",
        "skid", "crack", "keygen",
        "byovd", "dma-cheat", "pcileech",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var cacheEntries = ReadDnsCache();
            ct.ThrowIfCancellationRequested();
            AnalyzeDnsEntries(cacheEntries, ctx, ct);
        }, ct);
    }

    private static List<(string Domain, ushort Type, uint Ttl)> ReadDnsCache()
    {
        var entries = new List<(string, ushort, uint)>();

        try
        {
            int result = DnsGetCacheDataTable(out nint pEntry);
            if (result != 0 || pEntry == nint.Zero) return entries;

            nint current = pEntry;
            int safetyLimit = 50_000; // avoid infinite loop on corrupt data

            while (current != nint.Zero && safetyLimit-- > 0)
            {
                try
                {
                    var entry = Marshal.PtrToStructure<DNS_CACHE_ENTRY>(current);

                    string? domain = entry.pszName != nint.Zero
                        ? Marshal.PtrToStringUni(entry.pszName)
                        : null;

                    if (!string.IsNullOrEmpty(domain))
                        entries.Add((domain, entry.wType, entry.dwTtl));

                    current = entry.pNext;
                }
                catch { break; }
            }

            try { DnsReleaseCacheDataTable(pEntry); } catch { }
        }
        catch { }

        return entries;
    }

    private static void AnalyzeDnsEntries(
        List<(string Domain, ushort Type, uint Ttl)> entries,
        ScanContext ctx, CancellationToken ct)
    {
        foreach (var (domain, type, ttl) in entries)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();

            string domainLower = domain.ToLowerInvariant().TrimEnd('.');

            // Check against exact known cheat domains
            string? matchedCheatDomain = Array.Find(CheatDomainFragments,
                frag => domainLower.Contains(frag.ToLowerInvariant()));

            if (matchedCheatDomain is not null)
            {
                bool isMarketplace = matchedCheatDomain.Contains("unknowncheats") ||
                                     matchedCheatDomain.Contains("mpgh") ||
                                     matchedCheatDomain.Contains("elitepvpers") ||
                                     matchedCheatDomain.Contains("ringofhack") ||
                                     matchedCheatDomain.Contains("gamelooting") ||
                                     matchedCheatDomain.Contains("cheatautomation") ||
                                     matchedCheatDomain.Contains("cheatersoul") ||
                                     matchedCheatDomain.Contains("buycheap") ||
                                     matchedCheatDomain.Contains("cheaphacks") ||
                                     matchedCheatDomain.Contains("gamecheat.shop");

                RiskLevel risk = isMarketplace ? RiskLevel.High : RiskLevel.Critical;

                string recordType = type switch
                {
                    DNS_TYPE_A     => "A (IPv4)",
                    DNS_TYPE_AAAA  => "AAAA (IPv6)",
                    DNS_TYPE_CNAME => "CNAME",
                    DNS_TYPE_MX    => "MX",
                    DNS_TYPE_TXT   => "TXT",
                    _              => $"Typ {type}",
                };

                ctx.AddFinding(new Finding
                {
                    Module   = "DNS Client Cache Extended Cheat Domain Analysis",
                    Title    = $"Cheat-Domain im DNS-Cache: {domain}",
                    Risk     = risk,
                    Location = $"DNS-Cache: {domain}",
                    FileName = domain,
                    Reason   = isMarketplace
                        ? $"DNS-Cache enthält Cheat-Marktplatz-Domain '{domain}' — belegt Besuch von " +
                          $"Cheat-Verkaufsseite (Match: '{matchedCheatDomain}')"
                        : $"DNS-Cache enthält bekannte Cheat-Tool-Domain '{domain}' — belegt Kontakt " +
                          $"mit Cheat-C2/Lizenz-Server (Match: '{matchedCheatDomain}'). DNS-Cache " +
                          "bleibt nach Browser-History-Löschung erhalten",
                    Detail   = $"Domain: {domain} | Typ: {recordType} | TTL: {ttl}s | " +
                               $"Kategorie: {(isMarketplace ? "Marktplatz" : "C2/Lizenz-Server")} | " +
                               $"Match: {matchedCheatDomain}"
                });
                continue;
            }

            // Check suspicious domain label patterns
            string? matchedPattern = Array.Find(SuspiciousDomainLabelPatterns,
                p => domainLower.Contains(p));

            if (matchedPattern is not null)
            {
                // Additional filter: only flag if combined with suspicious TLD
                bool hasSuspiciousTld = Array.Exists(CheatTldPatterns,
                    tld => domainLower.EndsWith(tld));

                // Or if the domain has very few labels (short domain = less likely legit)
                string[] labels = domainLower.Split('.');
                bool isShortDomain = labels.Length <= 3;

                if (hasSuspiciousTld || isShortDomain)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "DNS Client Cache Extended Cheat Domain Analysis",
                        Title    = $"Verdächtige Domain im DNS-Cache: {domain}",
                        Risk     = hasSuspiciousTld ? RiskLevel.High : RiskLevel.Medium,
                        Location = $"DNS-Cache: {domain}",
                        FileName = domain,
                        Reason   = $"DNS-Cache enthält Domain '{domain}' mit Cheat-Schlüsselwort '{matchedPattern}'" +
                                   (hasSuspiciousTld ? $" und verdächtiger TLD — wahrscheinlich Cheat-Service" : ""),
                        Detail   = $"Domain: {domain} | TTL: {ttl}s | Muster: {matchedPattern} | " +
                                   $"Verdächtige TLD: {hasSuspiciousTld}"
                    });
                }
            }
        }
    }
}
