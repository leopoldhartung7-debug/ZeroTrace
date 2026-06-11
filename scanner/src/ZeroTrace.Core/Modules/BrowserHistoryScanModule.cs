using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;
using Microsoft.Data.Sqlite;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Read-only inspection of the local browser history for visits to known
/// cheat or reseller domains (e.g. cheat shops). Supports the Chromium family
/// (Chrome, Edge, Brave, Opera, Vivaldi) and Firefox.
///
/// PRIVACY BY DESIGN — DATA MINIMISATION:
///   * The full browsing history is NEVER stored, counted by URL, or sent.
///   * Each history entry is inspected transiently in memory; ONLY hosts that
///     match a cheat/reseller domain indicator become findings.
///   * A finding records the matched HOST only (no full URL, no query string,
///     no page title) plus an aggregate visit count.
/// This keeps the check consistent with the tool's consent + transparency model
/// and deliberately avoids turning it into general browsing surveillance.
/// </summary>
public sealed class BrowserHistoryScanModule : IScanModule
{
    public string Name => "Browser-Verlauf";
    public double Weight => 1.0;

    private enum Engine { Chromium, Firefox }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        // No domain list -> nothing to do (avoids reading history for no reason).
        if (!ctx.Matcher.HasUrlDomainSignatures)
        {
            ctx.Report(1.0, "Browser-Verlauf", "Keine Domain-Indikatoren aktiv");
            return Task.CompletedTask;
        }

        var dbs = LocateHistoryDatabases().ToList();
        if (dbs.Count == 0)
        {
            ctx.Report(1.0, "Browser-Verlauf", "Kein Browser-Verlauf gefunden");
            return Task.CompletedTask;
        }

        // Aggregate matches by (browser, host) so each cheat/reseller domain is
        // reported once, with a summed visit count.
        var hits = new Dictionary<string, (string browser, string host, long visits, Indicator ind)>(
            StringComparer.OrdinalIgnoreCase);

        int idx = 0;
        foreach (var (browser, engine, path) in dbs)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            ctx.Report((double)idx / (dbs.Count + 1), browser, $"Prüfe {browser}-Verlauf");
            InspectDatabase(browser, engine, path, ctx, hits, ct);
        }

        foreach (var (_, h) in hits)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Indikator-Treffer: {h.ind.Category}",
                Risk = h.ind.Risk,
                Location = h.host,
                Detail = $"Browser: {h.browser} · Besuche: {h.visits}",
                Reason = $"Besuch einer als '{h.ind.Category}' eingestuften Domain im " +
                         $"Browser-Verlauf (Treffer über Domain-Schlüsselwort '{h.ind.Pattern}'). " +
                         $"{h.ind.Description} Hinweis: nur die Domain wird erfasst, nicht der " +
                         "übrige Verlauf."
            });
        }

        ctx.Report(1.0, "Browser-Verlauf", "Verlaufsprüfung abgeschlossen");
        return Task.CompletedTask;
    }

    private static void InspectDatabase(
        string browser, Engine engine, string path, ScanContext ctx,
        Dictionary<string, (string, string, long, Indicator)> hits, CancellationToken ct)
    {
        // The live history DB is usually locked by the running browser, so work
        // on a read-only temporary copy and delete it afterwards.
        string? temp = null;
        try
        {
            temp = Path.Combine(Path.GetTempPath(), "zt_hist_" + Guid.NewGuid().ToString("N") + ".db");
            File.Copy(path, temp, overwrite: true);

            var cs = new SqliteConnectionStringBuilder
            {
                DataSource = temp,
                Mode = SqliteOpenMode.ReadOnly
            }.ToString();

            using var conn = new SqliteConnection(cs);
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = engine == Engine.Chromium
                ? "SELECT url, visit_count FROM urls;"
                : "SELECT url, visit_count FROM moz_places;";

            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles(); // throughput counter only; no URL is stored

                string url = r.IsDBNull(0) ? "" : r.GetString(0);
                if (url.Length == 0) continue;

                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) continue;
                var host = uri.Host;
                if (string.IsNullOrEmpty(host)) continue;

                var ind = ctx.Matcher.MatchUrlDomain(host);
                if (ind is null) continue; // not a flagged domain -> discarded, never stored

                long visits = r.IsDBNull(1) ? 0 : Convert.ToInt64(r.GetValue(1));
                var key = browser + "|" + host;
                if (hits.TryGetValue(key, out var existing))
                    hits[key] = (existing.Item1, existing.Item2, existing.Item3 + Math.Max(visits, 1), existing.Item4);
                else
                    hits[key] = (browser, host, Math.Max(visits, 1), ind);
            }
        }
        catch
        {
            // Locked/missing/unsupported schema -> skip this browser silently.
        }
        finally
        {
            if (temp is not null)
            {
                try { File.Delete(temp); } catch { }
            }
        }
    }

    private static IEnumerable<(string browser, Engine engine, string path)> LocateHistoryDatabases()
    {
        var local = KnownPaths.LocalAppData;
        var roaming = KnownPaths.RoamingAppData;

        // Chromium-family "User Data" roots: enumerate Default + Profile* folders.
        var chromiumRoots = new (string browser, string root)[]
        {
            ("Chrome",  Path.Combine(local, "Google", "Chrome", "User Data")),
            ("Edge",    Path.Combine(local, "Microsoft", "Edge", "User Data")),
            ("Brave",   Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Vivaldi", Path.Combine(local, "Vivaldi", "User Data"))
        };

        foreach (var (browser, root) in chromiumRoots)
        {
            if (!Directory.Exists(root)) continue;
            string[] profiles = Array.Empty<string>();
            try { profiles = Directory.GetDirectories(root); } catch { }
            foreach (var prof in profiles)
            {
                var db = Path.Combine(prof, "History");
                if (File.Exists(db)) yield return (browser, Engine.Chromium, db);
            }
        }

        // Opera stores directly under Roaming (Stable / GX Stable).
        foreach (var opera in new[] { "Opera Stable", "Opera GX Stable" })
        {
            var db = Path.Combine(roaming, "Opera Software", opera, "History");
            if (File.Exists(db)) yield return ("Opera", Engine.Chromium, db);
        }

        // Firefox: every profile's places.sqlite.
        var ffProfiles = Path.Combine(roaming, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(ffProfiles))
        {
            string[] profs = Array.Empty<string>();
            try { profs = Directory.GetDirectories(ffProfiles); } catch { }
            foreach (var prof in profs)
            {
                var db = Path.Combine(prof, "places.sqlite");
                if (File.Exists(db)) yield return ("Firefox", Engine.Firefox, db);
            }
        }
    }
}
