using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Catches two evasion/remnant surfaces, read-only:
///   1) the hosts file — cheat domains pinned there, or anti-cheat/telemetry
///      domains redirected to a null IP (cheaters block reporting);
///   2) the Recycle Bin — a cheat that was "deleted" is still recoverable. The
///      original name/path is read from the $I metadata and matched against the
///      indicators.
/// Nothing is modified or restored.
/// </summary>
public sealed class RemnantsScanModule : IScanModule
{
    public string Name => "Tarnung & Reste";
    public double Weight => 0.5;
    public int ParallelGroup => 5;

    private static readonly string[] NullIps = { "0.0.0.0", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1" };
    private static readonly string[] AntiCheatTokens =
    {
        "battleye", "easyanticheat", "easy-anti-cheat", "anticheat", "anti-cheat",
        "cfx.re", "fivem", "rockstargames", "ragemp", "altv.mp", "faceit",
        "valve", "steampowered", "punkbuster",
        // additional anti-cheat/game-integrity services
        "gameguard", "nprotect", "xigncode", "hackshield",
        "mhyprot", "vanguard", "ricochet-anticheat",
        "citizenfx", "trueplay", "warden.valvesoftware"
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ScanHosts(ctx);
        ctx.Report(0.4, "hosts", "hosts-Datei geprueft");

        ScanRecycleBin(ctx, ct);
        ctx.Report(1.0, "Papierkorb", "Papierkorb geprueft");
        return Task.CompletedTask;
    }

    // --- 1) hosts file ---------------------------------------------------------

    private void ScanHosts(ScanContext ctx)
    {
        var hosts = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers", "etc", "hosts");
        string[] lines;
        try { lines = File.ReadAllLines(hosts); }
        catch { return; }

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            var ip = parts[0];

            for (int i = 1; i < parts.Length; i++)
            {
                var host = parts[i];
                if (host.StartsWith('#')) break;

                // (a) a known cheat domain pinned in hosts
                var urlHit = ctx.Matcher.MatchUrlDomain(host);
                if (urlHit is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat-Domain in hosts-Datei: {urlHit.Category}",
                        Risk = urlHit.Risk,
                        Location = hosts,
                        Reason = $"Die hosts-Datei enthaelt einen Eintrag fuer '{host}', der dem " +
                                 $"Indikator '{urlHit.Pattern}' entspricht. {urlHit.Description}",
                        Detail = $"Zeile: {line}"
                    });
                    continue;
                }

                // (b)/(c) anti-cheat / telemetry / game domain pinned in hosts.
                var hl = host.ToLowerInvariant();
                if (AntiCheatTokens.Any(t => hl.Contains(t)))
                {
                    if (NullIps.Contains(ip))
                    {
                        // (b) blocked via a null/loopback address.
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Cheat-/Telemetrie-Domain in hosts geblockt",
                            Risk = RiskLevel.Medium,
                            Recommendation = Recommendation.Review,
                            Location = hosts,
                            Reason = $"'{host}' wird in der hosts-Datei auf {ip} umgeleitet (geblockt). " +
                                     "Das Blocken von Anti-Cheat-/Telemetrie-Domains ist ein typisches " +
                                     "Verschleierungs-Muster.",
                            Detail = $"Zeile: {line}"
                        });
                    }
                    else
                    {
                        // (c) redirected to a FOREIGN ip — possible license/auth/update
                        // server spoofing. Much stronger signal than a simple block.
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Cheat-/Spiel-Domain in hosts umgeleitet",
                            Risk = RiskLevel.Critical,
                            Recommendation = Recommendation.Review,
                            Location = hosts,
                            Reason = $"'{host}' wird in der hosts-Datei auf die fremde IP {ip} umgeleitet. " +
                                     "Das Umbiegen von Lizenz-/Authentifizierungs-/Update-Servern ist ein " +
                                     "starkes Manipulations-Signal.",
                            Detail = $"Zeile: {line}"
                        });
                    }
                }
            }
        }
    }

    // --- 2) recycle bin --------------------------------------------------------

    private void ScanRecycleBin(ScanContext ctx, CancellationToken ct)
    {
        int seen = 0;
        foreach (var drive in SafeFixedDrives())
        {
            var bin = Path.Combine(drive, "$Recycle.Bin");
            if (!Directory.Exists(bin)) continue;

            string[] sidDirs;
            try { sidDirs = Directory.GetDirectories(bin); }
            catch { continue; }

            foreach (var sidDir in sidDirs)
            {
                if (ct.IsCancellationRequested) return;
                string[] metaFiles;
                try { metaFiles = Directory.GetFiles(sidDir, "$I*"); }
                catch { continue; }

                foreach (var meta in metaFiles)
                {
                    if (++seen > 4000) return;
                    var (origPath, deleted) = ParseRecycleMeta(meta);
                    if (string.IsNullOrEmpty(origPath)) continue;

                    var fileName = SafeName(origPath!);
                    var ind = ctx.Matcher.MatchFileName(fileName)
                              ?? ctx.Matcher.MatchFileNameKeyword(fileName)
                              ?? ctx.Matcher.MatchPathKeyword(origPath!);

                    // The actual recycled data lives in the paired $R file.
                    var dataFile = meta.Replace($"{Path.DirectorySeparatorChar}$I",
                                                $"{Path.DirectorySeparatorChar}$R");

                    if (ind is null)
                    {
                        // No name hit: still inspect a recoverable binary for hash/signature.
                        if (File.Exists(dataFile))
                        {
                            var f = FileInspector.Inspect(dataFile, ctx, Name);
                            if (f is not null)
                            {
                                f.Title = "Im Papierkorb: " + f.Title;
                                f.FileName = fileName;
                                f.Reason = $"[Papierkorb] Geloeschte Datei '{origPath}'" +
                                           (deleted is null ? "" : $" (geloescht {deleted})") + ". " + f.Reason;
                                ctx.AddFinding(f);
                            }
                        }
                        continue;
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Im Papierkorb (wiederherstellbar): {ind.Category}",
                        Risk = ind.Risk,
                        Location = origPath!,
                        FileName = fileName,
                        Reason = $"Eine geloeschte Datei im Papierkorb entspricht dem Indikator " +
                                 $"'{ind.Pattern}'. {ind.Description} Datei ist noch wiederherstellbar." +
                                 (deleted is null ? "" : $" Geloescht: {deleted}."),
                        Detail = $"Daten: {dataFile}"
                    });
                }
            }
        }
    }

    /// <summary>Reads original path + deletion time from a $I metadata file.</summary>
    private static (string? path, string? deleted) ParseRecycleMeta(string metaPath)
    {
        try
        {
            var b = File.ReadAllBytes(metaPath);
            if (b.Length < 28) return (null, null);

            long version = BitConverter.ToInt64(b, 0);
            string? deleted = null;
            try
            {
                long ft = BitConverter.ToInt64(b, 16);
                if (ft > 0) deleted = DateTime.FromFileTime(ft).ToString("yyyy-MM-dd HH:mm");
            }
            catch { }

            string path;
            if (version == 2)
            {
                int nameLen = BitConverter.ToInt32(b, 24); // chars incl. terminating null
                int byteLen = Math.Max(0, (nameLen - 1) * 2);
                if (28 + byteLen > b.Length) byteLen = Math.Max(0, b.Length - 28);
                path = Encoding.Unicode.GetString(b, 28, byteLen);
            }
            else
            {
                // version 1: fixed 520-byte UTF-16 path at offset 24
                int len = Math.Min(520, b.Length - 24);
                path = Encoding.Unicode.GetString(b, 24, len).TrimEnd('\0');
            }
            return (string.IsNullOrWhiteSpace(path) ? null : path, deleted);
        }
        catch { return (null, null); }
    }

    private static IEnumerable<string> SafeFixedDrives()
    {
        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); }
        catch { yield break; }
        foreach (var d in drives)
        {
            string? root = null;
            try { if (d.DriveType == DriveType.Fixed && d.IsReady) root = d.RootDirectory.FullName; }
            catch { root = null; }
            if (root is not null) yield return root;
        }
    }

    private static string SafeName(string path)
    {
        try { return Path.GetFileName(path.TrimEnd('\\', '/')); }
        catch { return path; }
    }
}
