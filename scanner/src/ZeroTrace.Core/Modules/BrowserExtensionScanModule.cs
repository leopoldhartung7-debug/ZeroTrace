using System.Text.Json;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans installed browser extensions (Chrome, Edge, Brave, Vivaldi) for
/// suspicious characteristics: dangerous permission combinations (debugger,
/// nativeMessaging), cheat-related names/descriptions, or content matching
/// the indicator URL-domain list. Only manifest.json metadata is read — no
/// extension code is executed. Read-only.
/// </summary>
public sealed class BrowserExtensionScanModule : IScanModule
{
    public string Name => "Browser-Erweiterungen";
    public double Weight => 0.4;
    public int ParallelGroup => 1; // manifest.json reads only

    // Permissions that are rarely needed by legitimate extensions but give
    // an extension powerful access to inspect or redirect page traffic.
    private static readonly string[] DangerousPerms =
        { "debugger", "nativeMessaging", "proxy" };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "aimbot", "esp", "triggerbot", "wallhack",
        "speedhack", "bhop", "noclip", "unlock all", "god mode",
        "injector", "loader", "trainer", "spoofer", "bypass"
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var local = KnownPaths.LocalAppData;
        var roaming = KnownPaths.RoamingAppData;

        var roots = new (string browser, string path)[]
        {
            ("Chrome",  Path.Combine(local,   "Google",          "Chrome",        "User Data")),
            ("Edge",    Path.Combine(local,   "Microsoft",       "Edge",          "User Data")),
            ("Brave",   Path.Combine(local,   "BraveSoftware",   "Brave-Browser", "User Data")),
            ("Vivaldi", Path.Combine(local,   "Vivaldi",         "User Data")),
            ("Opera",   Path.Combine(roaming, "Opera Software",  "Opera Stable")),
            ("Opera GX",Path.Combine(roaming, "Opera Software",  "Opera GX Stable")),
        };

        int i = 0;
        foreach (var (browser, root) in roots)
        {
            if (ct.IsCancellationRequested) break;
            ctx.Report((double)i++ / roots.Length, browser, $"Pruefe {browser}-Erweiterungen");
            if (!Directory.Exists(root)) continue;
            try { ScanBrowserRoot(ctx, browser, root, ct); } catch { }
        }

        ctx.Report(1.0, "Erweiterungen", "Browser-Erweiterungen geprueft");
        return Task.CompletedTask;
    }

    private void ScanBrowserRoot(ScanContext ctx, string browser, string root,
        CancellationToken ct)
    {
        // Chromium: each profile has an Extensions/ folder
        string[] profiles;
        try { profiles = Directory.GetDirectories(root); } catch { return; }

        foreach (var profile in profiles)
        {
            if (ct.IsCancellationRequested) return;
            var extsDir = Path.Combine(profile, "Extensions");
            if (!Directory.Exists(extsDir)) continue;

            string[] extIds;
            try { extIds = Directory.GetDirectories(extsDir); } catch { continue; }

            foreach (var extIdDir in extIds)
            {
                if (ct.IsCancellationRequested) return;
                // Each extension has one or more version directories
                string[] versions;
                try { versions = Directory.GetDirectories(extIdDir); } catch { continue; }

                foreach (var versionDir in versions)
                {
                    var manifest = Path.Combine(versionDir, "manifest.json");
                    if (!File.Exists(manifest)) continue;
                    try { InspectManifest(ctx, browser, manifest, Path.GetFileName(extIdDir)); }
                    catch { }
                    break; // only check the first (latest) version
                }
            }
        }
    }

    private void InspectManifest(ScanContext ctx, string browser, string manifestPath, string extId)
    {
        string json;
        try { json = File.ReadAllText(manifestPath); }
        catch { return; }

        string name = "", description = "";
        var permissions = new List<string>();

        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true });
            var root = doc.RootElement;

            if (root.TryGetProperty("name", out var nameProp))
                name = nameProp.GetString() ?? "";
            if (root.TryGetProperty("description", out var descProp))
                description = descProp.GetString() ?? "";

            foreach (var permKey in new[] { "permissions", "optional_permissions" })
            {
                if (!root.TryGetProperty(permKey, out var permArr) ||
                    permArr.ValueKind != JsonValueKind.Array) continue;
                foreach (var p in permArr.EnumerateArray())
                    if (p.ValueKind == JsonValueKind.String)
                        permissions.Add(p.GetString() ?? "");
            }
        }
        catch { return; }

        // Strip localisation placeholders like __MSG_name__
        if (name.StartsWith("__MSG_")) name = extId;

        var combined = (name + " " + description).ToLowerInvariant();

        // 1) Dangerous permission combination
        var dangerousPerm = DangerousPerms.FirstOrDefault(
            p => permissions.Any(ep => ep.Equals(p, StringComparison.OrdinalIgnoreCase)));

        // 2) Cheat-related name / description
        var cheatKw = CheatKeywords.FirstOrDefault(k => combined.Contains(k));

        // 3) Indicator URL-domain match in manifest text
        var urlInd = ctx.Matcher.MatchUrlDomain(combined);

        if (dangerousPerm is null && cheatKw is null && urlInd is null) return;

        string titleReason;
        RiskLevel risk;
        if (cheatKw is not null || urlInd is not null)
        {
            titleReason = cheatKw is not null
                ? $"Verdaechtiges Schluesselwort '{cheatKw}' in Name/Beschreibung"
                : $"Indikator-Domain '{urlInd!.Pattern}' in Manifest";
            risk = RiskLevel.High;
        }
        else
        {
            titleReason = $"Gefaehrliche Berechtigung '{dangerousPerm}'";
            risk = RiskLevel.Medium;
        }

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Verdaechtige Browser-Erweiterung ({browser}): {name}",
            Risk = risk,
            Recommendation = Recommendation.Review,
            Location = manifestPath,
            FileName = name,
            Reason = $"Die {browser}-Erweiterung '{name}' (ID: {extId}) ist verdaechtig: " +
                     $"{titleReason}. Browser-Erweiterungen koennen Netzwerkverkehr umleiten, " +
                     "Seiteninhalte manipulieren oder ueber nativeMessaging auf lokale " +
                     "Programme zugreifen.",
            Detail = $"ID: {extId} · Berechtigungen: {string.Join(", ", permissions.Take(6))}"
        });
    }
}
