using System.Management;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep scan of WMI (Windows Management Instrumentation) event subscriptions
/// used for fileless persistence.
///
/// WMI subscriptions allow code to run automatically when conditions are met:
///   - __EventFilter: defines when to trigger (e.g., process start, system boot)
///   - __EventConsumer: defines what to execute (script, command, log)
///   - __FilterToConsumerBinding: links filter to consumer
///
/// Three consumer types are commonly abused:
///   1. ActiveScriptEventConsumer — runs VBScript/JScript code directly
///   2. CommandLineEventConsumer — runs arbitrary command line
///   3. LogFileEventConsumer — writes to files (used for data exfiltration)
///
/// Cheats and advanced malware use WMI subscriptions for:
///   - Auto-restart after process kill (keeps cheat loader alive)
///   - Download and execute updates when game starts
///   - Fileless code execution (no files on disk)
///   - Persistence that survives both reboots and user-space cleanup tools
///
/// This module deep-scans all three object classes in both root\subscription
/// and root\default namespaces and cross-checks for cheat keywords.
/// </summary>
public sealed class WmiSubscriptionDeepScanModule : IScanModule
{
    private static readonly string _name = "WMI-Persistenz-Deep-Scan";
    public string Name => _name;
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook",
        "gta5", "fivem", "tarkov", "apex", "valorant", "csgo",
        "memprocfs", "pcileech", "dma",
        "persist", "autorun", "restart", "download", "powershell",
        "cmd.exe", "wscript", "cscript", "mshta",
    };

    private static readonly string[] WmiNamespaces =
    {
        @"root\subscription",
        @"root\default",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        foreach (var ns in WmiNamespaces)
        {
            if (ct.IsCancellationRequested) break;
            hits += ScanNamespace(ns, ctx, ct);
        }

        ctx.Report(1.0, Name, $"WMI-Event-Subscriptions geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int ScanNamespace(string wmiNamespace, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            hits += QueryWmiClass(wmiNamespace, "__EventFilter", ctx, ct);
            hits += QueryWmiClass(wmiNamespace, "__EventConsumer", ctx, ct);
            hits += QueryWmiClass(wmiNamespace, "ActiveScriptEventConsumer", ctx, ct);
            hits += QueryWmiClass(wmiNamespace, "CommandLineEventConsumer", ctx, ct);
            hits += QueryWmiClass(wmiNamespace, "LogFileEventConsumer", ctx, ct);
            hits += QueryWmiClass(wmiNamespace, "__FilterToConsumerBinding", ctx, ct);
        }
        catch { }
        return hits;
    }

    private static int QueryWmiClass(string wmiNamespace, string className,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var scope = new ManagementScope($@"\\.\{wmiNamespace}");
            scope.Connect();

            var query = new ObjectQuery($"SELECT * FROM {className}");
            using var searcher = new ManagementObjectSearcher(scope, query);
            using var results  = searcher.Get();

            foreach (ManagementObject obj in results)
            {
                if (ct.IsCancellationRequested) break;

                // Build a single string from all property values for keyword matching
                var sb = new System.Text.StringBuilder();
                try
                {
                    foreach (var prop in obj.Properties)
                    {
                        if (prop.Value is not null)
                            sb.Append(prop.Value.ToString()).Append(' ');
                    }
                }
                catch { }

                var combined = sb.ToString().ToLowerInvariant();
                var cheatKw  = CheatKeywords.FirstOrDefault(k =>
                    combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                // Every non-system subscription that has suspicious content is flagged.
                // Also flag ALL ActiveScriptEventConsumer and CommandLineEventConsumer
                // instances because legitimate Windows uses only __EventFilter/__EventConsumer
                bool isSuspiciousClass = className is "ActiveScriptEventConsumer"
                    or "CommandLineEventConsumer";

                var name = TryGetProperty(obj, "Name") ?? className;

                // Skip well-known benign system subscriptions
                if (IsKnownGoodSubscription(name, combined)) continue;

                if (cheatKw is not null || isSuspiciousClass)
                {
                    hits++;
                    var script   = TryGetProperty(obj, "ScriptText")
                        ?? TryGetProperty(obj, "CommandLineTemplate") ?? "";
                    var truncated = script.Length > 200 ? script[..200] + "…" : script;

                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"WMI-Persistenz ({className}): {name}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"{wmiNamespace}\{className}",
                        Reason   = $"WMI-{className} '{name}' in Namespace '{wmiNamespace}' gefunden. " +
                                   (isSuspiciousClass
                                       ? $"{className} führt Code direkt aus und ist eine klassische " +
                                         "fileless-Persistenz-Technik. "
                                       : "") +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   "WMI-Subscriptions überleben Reboots und sind mit Standard-Tools " +
                                   "nicht sichtbar.",
                        Detail   = $"Klasse: {className} | Name: {name} | NS: {wmiNamespace}" +
                                   (truncated.Length > 0 ? $" | Code: {truncated}" : "")
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static string? TryGetProperty(ManagementObject obj, string name)
    {
        try { return obj[name]?.ToString(); }
        catch { return null; }
    }

    private static bool IsKnownGoodSubscription(string name, string combined)
    {
        if (string.IsNullOrEmpty(name)) return false;
        var lower = name.ToLowerInvariant();

        // Microsoft standard subscriptions
        return lower.StartsWith("scm") ||
               lower.StartsWith("sca") ||
               lower.Contains("microsoft") ||
               lower.Contains("windows") ||
               lower.Contains("defrag");
    }
}
