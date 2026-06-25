using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Queries the Windows DNS cache for domains associated with cheat distribution
/// sites, license servers, and cheat APIs.
///
/// The Windows DNS Client service caches all DNS lookups made on this machine.
/// Unlike browser history (which can be cleared), the DNS cache:
///   - Is shared system-wide (game + browser + cheat loader all use it)
///   - Is harder to selectively clear without clearing all DNS
///   - Survives browser history deletion
///   - Can reveal cheat loader license check domains even when the browser
///     history was wiped
///
/// Detection:
///   1. Use DnsGetCacheDataTable (undocumented dnsapi.dll export) to enumerate
///      all currently cached DNS entries.
///   2. Compare each hostname against a blocklist of known cheat domains.
///   3. Also check hosts file for cheat-domain blocks/redirects.
///
/// Note: The DNS cache is ephemeral and cleared on reboot. It only shows
/// domains queried since the last boot — but cheat loaders typically do a
/// license check each session.
/// </summary>
public sealed class DnsHistoryScanModule : IScanModule
{
    public string Name => "DNS-Cache-Analyse";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    // DNS_STATUS is int, DNS_CACHE_ENTRY is a linked list
    [DllImport("dnsapi.dll", EntryPoint = "DnsGetCacheDataTable")]
    private static extern bool DnsGetCacheDataTable(out IntPtr pEntry);

    [StructLayout(LayoutKind.Sequential)]
    private struct DNS_CACHE_ENTRY
    {
        public IntPtr Next;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Name;
        public ushort Type;
        public ushort DataLength;
        public uint Flags;
    }

    private static readonly string[] CheatDomains =
    {
        // GTA V cheat services
        "kiddion.net", "kiddionmodmenu", "2take1.menu", "cherax.gg",
        "ozarkcheat.com", "ozark.gg", "midnightcheat", "nightcheat",
        "stand.gg",
        // FPS cheat services
        "aimware.net", "skeet.cc", "fatality.win", "neverlose.cc",
        "onetap.su", "onetap.com", "interium.store", "nixware.cc",
        "gamesense.pub", "lhook.net", "hvh.studio",
        // Tarkov cheats
        "eft-cheat", "tarkov-cheat", "escapefromtarkov-hack",
        // Apex / Valorant
        "baphacks", "legitaimbot", "apexhacks",
        // Loaders / injectors
        "extremeinjector", "xenos-injector",
        // HWID spoofing
        "hwid-spoofer", "hwidspoofer", "hwidchanger",
        // DMA tools
        "pcileech.io", "memprocfs",
        // Cheat marketplaces
        "unknowncheats.me", "mpgh.net", "uc.to",
        "cheatersoul.com", "elitepvpers.com",
        // License / update CDNs (match substrings)
        "cheat-api", "cheat-license", "loader-cdn",
        "hwid-ban", "eac-bypass", "be-bypass",
    };

    private static readonly string[] CheatSubstrings =
    {
        "cheat-", "-cheat", "hack-", "-hack",
        "aimbot", "wallhack", "esp-", "esp.",
        "spoofer", "bypass", "-inject",
        "cheater", "cheats.", ".cheats",
    };

    private static readonly string HostsFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        @"drivers\etc\hosts");

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        int hits = 0;

        // 1. Check DNS cache
        hits += ScanDnsCache(ctx, ref checked_, ct);

        // 2. Check hosts file for cheat-domain modifications
        hits += ScanHostsFile(ctx, ct);

        ctx.Report(1.0, Name, $"{checked_} DNS-Einträge geprüft, {hits} verdächtige Domains");
        return Task.CompletedTask;
    }

    private static int ScanDnsCache(ScanContext ctx, ref int checked_, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            if (!DnsGetCacheDataTable(out var pEntry) || pEntry == IntPtr.Zero)
                return 0;

            var current = pEntry;
            while (current != IntPtr.Zero)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                try
                {
                    var entry = Marshal.PtrToStructure<DNS_CACHE_ENTRY>(current);
                    current = entry.Next;

                    if (string.IsNullOrEmpty(entry.Name)) continue;
                    checked_++;

                    var nameLower = entry.Name.ToLowerInvariant();

                    // Check exact domain matches
                    var domainHit = CheatDomains.FirstOrDefault(d =>
                        nameLower.Contains(d, StringComparison.OrdinalIgnoreCase));

                    if (domainHit is null)
                    {
                        // Check substring patterns
                        domainHit = CheatSubstrings.FirstOrDefault(s =>
                            nameLower.Contains(s, StringComparison.OrdinalIgnoreCase));
                    }

                    if (domainHit is not null)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "DNS-Cache-Analyse",
                            Title    = $"DNS-Cache: Cheat-Domain aufgerufen: {entry.Name}",
                            Risk     = RiskLevel.High,
                            Location = "DNS-Cache (ipconfig /displaydns)",
                            FileName = entry.Name,
                            Reason   = $"DNS-Cache zeigt Namensauflösung für bekannte Cheat-Domain: " +
                                       $"'{entry.Name}' (Pattern: '{domainHit}'). " +
                                       "Cheat-Loader kontaktieren License-Server oder Update-CDNs " +
                                       "bei jedem Start. DNS-Cache überlebt Browser-History-Löschung.",
                            Detail   = $"Domain: {entry.Name} | Typ: {entry.Type} | Match: {domainHit}"
                        });
                    }
                }
                catch
                {
                    break; // Pointer chain corrupted
                }
            }
        }
        catch { }
        return hits;
    }

    private static int ScanHostsFile(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        if (!File.Exists(HostsFile)) return 0;

        try
        {
            var lines = File.ReadAllLines(HostsFile);
            foreach (var line in lines)
            {
                if (ct.IsCancellationRequested) break;
                if (line.TrimStart().StartsWith('#')) continue; // comment
                if (string.IsNullOrWhiteSpace(line)) continue;

                var lower = line.ToLowerInvariant();

                // Check if hosts file blocks anti-cheat domains
                // (a cheat may redirect AC telemetry to 0.0.0.0)
                var acDomains = new[]
                {
                    "easyanticheat", "battleye", "vac.", "valve.net",
                    "faceit.com", "anticheatsdk", "esportal",
                    "punkbuster", "fairfight", "nprotect",
                    "xigncode", "gameguard",
                };

                var acHit = acDomains.FirstOrDefault(d =>
                    lower.Contains(d, StringComparison.OrdinalIgnoreCase));
                if (acHit is not null && (lower.Contains("0.0.0.0") || lower.Contains("127.0.0.1")))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "DNS-Cache-Analyse",
                        Title    = $"Hosts-Datei blockiert Anti-Cheat-Domain: {acHit}",
                        Risk     = RiskLevel.Critical,
                        Location = HostsFile,
                        FileName = "hosts",
                        Reason   = $"Die Windows-Hosts-Datei leitet eine Anti-Cheat-Domain um: " +
                                   $"'{line.Trim()}'. Cheats blockieren Anti-Cheat-Telemetrie " +
                                   "und Updater indem sie deren Domains auf localhost/0.0.0.0 " +
                                   "umleiten, um Erkennung und Bans zu verhindern.",
                        Detail   = $"Hosts-Zeile: {line.Trim()} | Anti-Cheat: {acHit}"
                    });
                    continue;
                }

                // Check if cheat domains are hardcoded in hosts (for offline license bypass)
                var domainHit = CheatDomains.FirstOrDefault(d =>
                    lower.Contains(d, StringComparison.OrdinalIgnoreCase));
                if (domainHit is not null)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "DNS-Cache-Analyse",
                        Title    = $"Hosts-Datei: Cheat-Domain eingetragen: {domainHit}",
                        Risk     = RiskLevel.High,
                        Location = HostsFile,
                        FileName = "hosts",
                        Reason   = $"Die Windows-Hosts-Datei enthält eine Cheat-Domain: " +
                                   $"'{line.Trim()}'. Cheats tragen ihren License-Server " +
                                   "in die Hosts-Datei ein für Offline-License-Bypass oder " +
                                   "um Traffic-Analyse zu erschweren.",
                        Detail   = $"Hosts-Zeile: {line.Trim()} | Domain: {domainHit}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
