using System.Management;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Read-only check for WMI permanent event-subscription persistence
/// (__EventFilter + __EventConsumer + __FilterToConsumerBinding in
/// root\subscription). This is a fileless autostart method that bypasses the
/// Run keys, scheduled tasks and services the other modules cover. Command-line
/// and script consumers are uncommon on a normal gaming PC, so their mere
/// presence is reported for review; a match against the indicators escalates it.
/// Nothing is changed.
/// </summary>
public sealed class WmiPersistenceScanModule : IScanModule
{
    public string Name => "WMI-Persistenz";
    public double Weight => 0.3;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        try { ScanConsumers(ctx, ct); } catch { }
        ctx.Report(0.6, "Consumer", "WMI-Consumer geprueft");
        try { ScanFilters(ctx, ct); } catch { }
        ctx.Report(1.0, "Filter", "WMI-Filter geprueft");
        return Task.CompletedTask;
    }

    private void ScanConsumers(ScanContext ctx, CancellationToken ct)
    {
        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT * FROM __EventConsumer"));

        foreach (ManagementBaseObject mo in searcher.Get())
        {
            if (ct.IsCancellationRequested) return;
            using (mo)
            {
                string cls = mo.ClassPath?.ClassName ?? "__EventConsumer";
                if (cls.StartsWith("NTEventLog", StringComparison.OrdinalIgnoreCase)) continue;

                string name = Str(mo, "Name");
                string payload = Str(mo, "CommandLineTemplate");
                if (string.IsNullOrEmpty(payload)) payload = Str(mo, "ExecutablePath");
                if (string.IsNullOrEmpty(payload)) payload = Str(mo, "ScriptText");
                if (string.IsNullOrEmpty(payload)) payload = Str(mo, "ScriptFileName");

                var ind = ctx.Matcher.MatchPathKeyword(payload)
                          ?? ctx.Matcher.MatchFileNameKeyword(payload)
                          ?? ctx.Matcher.MatchRegistryKeyword(payload);

                var risk = ind is not null ? ind.Risk : RiskLevel.Medium;
                var why = ind is not null
                    ? $"Der Inhalt entspricht dem Indikator '{ind.Pattern}'. {ind.Description}"
                    : "Command-/Script-Consumer als WMI-Persistenz sind auf einem normalen PC " +
                      "selten und werden als fileless-Autostart genutzt – bitte pruefen.";

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"WMI-Consumer ({cls})",
                    Risk = risk,
                    Recommendation = ind is null ? Recommendation.Review : Recommendation.Remove,
                    Location = $"root\\subscription · {name}",
                    Reason = $"WMI-Event-Consumer '{name}' ({cls}). {why}",
                    Detail = Trim(payload, 300)
                });
            }
        }
    }

    private void ScanFilters(ScanContext ctx, CancellationToken ct)
    {
        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT * FROM __EventFilter"));

        foreach (ManagementBaseObject mo in searcher.Get())
        {
            if (ct.IsCancellationRequested) return;
            using (mo)
            {
                string name = Str(mo, "Name");
                string query = Str(mo, "Query");
                var ind = ctx.Matcher.MatchPathKeyword(query) ?? ctx.Matcher.MatchFileNameKeyword(query);
                if (ind is null) continue; // filters alone are common; only flag indicator hits
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"WMI-Filter mit Indikator: {ind.Category}",
                    Risk = ind.Risk,
                    Location = $"root\\subscription · {name}",
                    Reason = $"WMI-Event-Filter '{name}' enthaelt '{ind.Pattern}'. {ind.Description}",
                    Detail = Trim(query, 300)
                });
            }
        }
    }

    private static string Str(ManagementBaseObject mo, string prop)
    {
        try { return mo[prop]?.ToString() ?? ""; } catch { return ""; }
    }

    private static string Trim(string s, int max) =>
        string.IsNullOrEmpty(s) ? "" : (s.Length <= max ? s : s[..max] + "…");
}
