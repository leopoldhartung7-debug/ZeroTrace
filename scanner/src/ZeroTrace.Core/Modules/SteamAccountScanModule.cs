using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Reads previously logged-in Steam accounts from the client's loginusers.vdf.
/// Multiple accounts on the same machine can indicate ban evasion through
/// alt-accounts. Account names are also matched against cheat indicators.
///
/// NOTE: HostInventoryCollector already populates Inventory.SteamAccounts for
/// the dashboard panel. This module only adds findings for anomalous patterns
/// it detects (multiple accounts, indicator matches).
/// </summary>
public sealed class SteamAccountScanModule : IScanModule
{
    public string Name => "Steam-Konten";
    public double Weight => 0.3;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var steamPath = Registry.GetValue(
            @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;
        if (string.IsNullOrEmpty(steamPath))
        {
            ctx.Report(1.0, "Steam", "Kein Steam-Client gefunden");
            return Task.CompletedTask;
        }

        var vdf = Path.Combine(steamPath, "config", "loginusers.vdf");
        if (!File.Exists(vdf))
        {
            ctx.Report(1.0, "Steam", "loginusers.vdf nicht gefunden");
            return Task.CompletedTask;
        }

        var accounts = ParseLoginUsers(vdf);
        ctx.Report(0.5, "Steam", $"{accounts.Count} Konto(en) gefunden");

        if (accounts.Count == 0)
        {
            ctx.Report(1.0, "Steam", "Keine Steam-Konten gefunden");
            return Task.CompletedTask;
        }

        // Multiple accounts → potential alt-account farming / ban evasion.
        if (accounts.Count > 1)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Mehrere Steam-Konten auf diesem PC ({accounts.Count})",
                Risk = accounts.Count >= 3 ? RiskLevel.Medium : RiskLevel.Low,
                Location = "Steam loginusers.vdf",
                Reason = $"Es wurden {accounts.Count} verschiedene Steam-Konten gefunden, die sich auf " +
                         "diesem PC eingeloggt haben. Mehrere Konten koennen auf Ban-Umgehung durch " +
                         "Alt-Accounts hinweisen.",
                Detail = string.Join(", ", accounts.Select(a => a.AccountName).Where(n => !string.IsNullOrEmpty(n)))
            });
        }

        // Check each account name against cheat indicators.
        foreach (var acc in accounts)
        {
            ct.ThrowIfCancellationRequested();
            var name = acc.AccountName;
            if (string.IsNullOrWhiteSpace(name)) continue;

            var ind = ctx.Matcher.MatchFileName(name + ".exe")
                      ?? ctx.Matcher.MatchFileNameKeyword(name);
            if (ind is null) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Steam-Konto entspricht Cheat-Indikator: {ind.Category}",
                Risk = ind.Risk,
                Location = $"SteamID: {acc.SteamId}",
                Reason = $"Der Steam-Benutzername '{name}' entspricht dem Indikator " +
                         $"'{ind.Pattern}'. {ind.Description}",
                Detail = $"AccountName: {acc.AccountName} | PersonaName: {acc.PersonaName}"
            });
        }

        ctx.Report(1.0, "Steam", "Steam-Konten geprueft");
        return Task.CompletedTask;
    }

    private static List<(string SteamId, string AccountName, string PersonaName)> ParseLoginUsers(string vdf)
    {
        var result = new List<(string, string, string)>();
        string[] lines;
        try { lines = File.ReadAllLines(vdf, System.Text.Encoding.UTF8); }
        catch { return result; }

        string? steamId = null;
        string accountName = "";
        string personaName = "";
        int depth = 0;

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line == "{") { depth++; continue; }
            if (line == "}")
            {
                if (depth == 2 && steamId != null)
                    result.Add((steamId, accountName, personaName));
                if (depth == 2) { steamId = null; accountName = ""; personaName = ""; }
                depth--;
                continue;
            }

            if (depth == 1 && line.StartsWith('"') && line.EndsWith('"'))
            {
                var id = line.Trim('"');
                if (id.Length >= 17 && long.TryParse(id, out _)) steamId = id;
                continue;
            }

            if (depth == 2 && steamId != null)
            {
                var m = System.Text.RegularExpressions.Regex.Match(
                    line, @"""([^""]+)""\s+""([^""]*)""");
                if (!m.Success) continue;
                switch (m.Groups[1].Value.ToLowerInvariant())
                {
                    case "accountname": accountName = m.Groups[2].Value; break;
                    case "personaname": personaName = m.Groups[2].Value; break;
                }
            }
        }
        return result;
    }
}
