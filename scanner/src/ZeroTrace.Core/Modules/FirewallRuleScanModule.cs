using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Analyses Windows Firewall rules for entries added by cheat software.
///
/// Cheat loaders and their accompanying tools often add firewall rules to:
///   1. Allow inbound/outbound connections to cheat license servers on unusual ports.
///   2. Block outbound connections to game anti-cheat update servers (VAC, BE, EAC).
///   3. Prevent AV/EDR telemetry from reporting detections.
///   4. Open specific ports for DMA hardware communication (PCIe scatter-read tools).
///   5. Allow P2P cheat key distribution over non-standard protocols.
///
/// Detection approach:
///   - Walk HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\
///     FirewallPolicy\FirewallRules
///   - Parse each rule's embedded name, application path, and port/protocol fields
///   - Flag rules whose application path points to user-writable locations
///   - Flag rules blocking connections to known anti-cheat services
///   - Flag rules with suspicious names matching cheat tool patterns
///   - Flag rules with extremely broad allow-all semantics (Action=Allow|Dir=In|Protocol=6|LPort=*)
///     on processes in Temp/Downloads
/// </summary>
public sealed class FirewallRuleScanModule : IScanModule
{
    public string Name => "Firewall-Regeln";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private const string FirewallRulesKey =
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    // Anti-cheat service domains/executables that should never be blocked
    private static readonly string[] AntiCheatTargets =
    {
        "easyanticheat", "battleye", "vac", "valve", "faceit",
        "esportal", "vanguard", "riot", "anticheatsdk",
        "xigncode", "gameguard", "wellbia", "nprotect",
        "battlenet", "blizzard",
    };

    // Cheat-related keywords in rule names/paths
    private static readonly string[] CheatRuleKeywords =
    {
        "cheat", "hack", "inject", "spoofer", "bypass",
        "aimbot", "wallhack", "triggerbot", "memprocfs",
        "pcileech", "kiddion", "cherax", "2take1", "ozark",
        "aimware", "fecurity", "onetap", "neverlose",
        "valorhack", "apexhack", "predatorlegend",
        "evilcheats", "gamerpride", "exvalid",
        "interception", "autohotkey",
    };

    // User-writable path fragments — programs here shouldn't have firewall rules
    private static readonly string[] SuspiciousPathFragments =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\",
        @"\appdata\local\temp\", @"\appdata\roaming\",
        @"\users\public\",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int rulesChecked = 0;
        int suspicious   = 0;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(FirewallRulesKey, writable: false);
            if (key is null)
            {
                ctx.Report(1.0, "Firewall-Regeln", "Keine Firewall-Regeln gefunden");
                return Task.CompletedTask;
            }

            foreach (var ruleName in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) break;
                rulesChecked++;
                ctx.IncrementRegistryKeys();

                try
                {
                    var value = key.GetValue(ruleName) as string;
                    if (string.IsNullOrEmpty(value)) continue;

                    // Parse the pipe-delimited rule string
                    var fields = ParseRule(value);
                    if (!fields.TryGetValue("Name", out var name)) name = ruleName;
                    fields.TryGetValue("App", out var app);
                    fields.TryGetValue("Action", out var action);
                    fields.TryGetValue("Dir", out var dir);
                    fields.TryGetValue("LPort", out var lport);
                    fields.TryGetValue("RPort", out var rport);
                    fields.TryGetValue("Active", out var active);

                    if (active?.Equals("FALSE", StringComparison.OrdinalIgnoreCase) == true)
                        continue; // disabled rule

                    var nameLower = (name ?? "").ToLowerInvariant();
                    var appLower  = (app  ?? "").ToLowerInvariant();

                    // ── Cheat keywords in rule name ──────────────────────────
                    var nameHit = CheatRuleKeywords.FirstOrDefault(k =>
                        nameLower.Contains(k) || appLower.Contains(k));
                    if (nameHit is not null)
                    {
                        suspicious++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Firewall-Regel mit Cheat-Keyword: {name}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{FirewallRulesKey}",
                            Reason   = $"Firewall-Regel '{name}' enthält cheat-typisches Schlüsselwort '{nameHit}'. " +
                                       "Cheat-Tools registrieren Firewall-Regeln für ihre Lizenzserver-Kommunikation.",
                            Detail   = $"Regel: {name} | App: {app ?? "-"} | Action: {action} | Dir: {dir}"
                        });
                        continue;
                    }

                    // ── App in suspicious path ───────────────────────────────
                    if (app is { Length: > 0 } && action?.Equals("Allow", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        var pathHit = SuspiciousPathFragments.FirstOrDefault(f =>
                            appLower.Contains(f));
                        if (pathHit is not null)
                        {
                            suspicious++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Firewall-Regel für Temp-Anwendung: {Path.GetFileName(app)}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{FirewallRulesKey}",
                                FileName = Path.GetFileName(app),
                                Reason   = $"Firewall-Allow-Regel für Anwendung in '{pathHit.Trim('\\')}' " +
                                           $"gefunden: '{app}'. Anwendungen in temporären Verzeichnissen " +
                                           "haben typischerweise keine legitimen Firewall-Regeln.",
                                Detail   = $"Regel: {name} | Pfad: {app} | Aktion: {action} | Dir: {dir} | Port: {rport ?? lport ?? "*"}"
                            });
                            continue;
                        }
                    }

                    // ── Anti-cheat service blocked ───────────────────────────
                    if (action?.Equals("Block", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        var acHit = AntiCheatTargets.FirstOrDefault(a =>
                            nameLower.Contains(a) || appLower.Contains(a));
                        if (acHit is not null)
                        {
                            suspicious++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Anti-Cheat blockiert: {acHit}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{FirewallRulesKey}",
                                Reason   = $"Firewall-Block-Regel für Anti-Cheat-Service '{acHit}' gefunden. " +
                                           "Cheat-Software blockiert Anti-Cheat-Updates und Telemetrie, " +
                                           "um Erkennung zu verhindern.",
                                Detail   = $"Regel: {name} | Geblockt: {app ?? acHit} | Dir: {dir}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }

        ctx.Report(1.0, "Firewall-Regeln",
            $"{rulesChecked} Regeln geprüft, {suspicious} auffällig");
        return Task.CompletedTask;
    }

    private static Dictionary<string, string> ParseRule(string rule)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in rule.Split('|'))
        {
            var idx = part.IndexOf('=');
            if (idx < 0) continue;
            dict[part[..idx]] = part[(idx + 1)..];
        }
        return dict;
    }
}
