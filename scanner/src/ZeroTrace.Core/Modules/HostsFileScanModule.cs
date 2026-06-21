using System.IO;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Inspects the Windows hosts file (%SystemRoot%\System32\drivers\etc\hosts) for
/// entries that target anti-cheat or game/launcher domains. Cheaters commonly add
/// hosts entries to (a) block anti-cheat/telemetry by null-routing it to a
/// loopback address, or (b) redirect a license/auth domain to a custom server.
/// Only entries matching the sensitive domain list are ever recorded; unrelated
/// hosts entries are ignored to keep false positives low.
/// </summary>
public sealed class HostsFileScanModule : IScanModule
{
    public string Name => "Hosts-Datei";
    public double Weight => 0.2;

    // High-signal domains: blocking or redirecting these is almost never legit.
    private static readonly string[] SensitiveDomains =
    {
        "easyanticheat", "easy.ac", "battleye", "anticheat", "anti-cheat",
        "vanguard", "faceit", "esea", "cfx.re", "fivem", "altv", "alt-mp",
        "rage.mp", "ragemp",
    };

    // Addresses that effectively block a domain (null-route / loopback).
    private static readonly HashSet<string> LoopbackTargets =
        new(StringComparer.OrdinalIgnoreCase)
        { "0.0.0.0", "127.0.0.1", "::1", "::", "0:0:0:0:0:0:0:1" };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var path = Environment.ExpandEnvironmentVariables(
            @"%SystemRoot%\System32\drivers\etc\hosts");

        string[] lines;
        try
        {
            if (!File.Exists(path))
            {
                ctx.Report(1.0, "Hosts-Datei", "Keine hosts-Datei vorhanden");
                return Task.CompletedTask;
            }
            lines = File.ReadAllLines(path);
            ctx.IncrementFiles();
        }
        catch
        {
            // Unreadable (locked/permissions): nothing we can do, leave it to the
            // engine's per-module isolation. No finding is invented.
            ctx.Report(1.0, "Hosts-Datei", "hosts-Datei nicht lesbar");
            return Task.CompletedTask;
        }

        for (int i = 0; i < lines.Length; i++)
        {
            ct.ThrowIfCancellationRequested();

            var raw = lines[i];
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;

            // Strip an inline comment.
            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash].Trim();
            if (line.Length == 0) continue;

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;

            var ip = parts[0];
            bool blocks = LoopbackTargets.Contains(ip);

            for (int h = 1; h < parts.Length; h++)
            {
                var host = parts[h].ToLowerInvariant();
                if (!IsSensitive(host)) continue;

                if (blocks)
                {
                    ctx.AddFinding(new Finding
                    {
                        Title = "Anti-Cheat/Spiel-Domain in hosts blockiert",
                        Risk = RiskLevel.High,
                        Location = $"{path} (Zeile {i + 1})",
                        Reason = "Die hosts-Datei leitet eine sicherheits-/spielrelevante Domain auf " +
                                 "eine Loopback-Adresse um und blockiert sie damit. Das wird haeufig " +
                                 "genutzt, um Anti-Cheat- oder Telemetrie-Verbindungen zu unterbinden.",
                        Detail = $"{ip}  {host}"
                    });
                }
                else
                {
                    ctx.AddFinding(new Finding
                    {
                        Title = "Anti-Cheat/Spiel-Domain in hosts umgeleitet",
                        Risk = RiskLevel.Critical,
                        Location = $"{path} (Zeile {i + 1})",
                        Reason = "Die hosts-Datei leitet eine sicherheits-/spielrelevante Domain auf " +
                                 "eine fremde IP-Adresse um. Das kann eine Manipulation von Lizenz-/" +
                                 "Authentifizierungs- oder Update-Servern sein.",
                        Detail = $"{ip}  {host}"
                    });
                }
            }
        }

        ctx.Report(1.0, "Hosts-Datei", "hosts-Datei geprueft");
        return Task.CompletedTask;
    }

    private static bool IsSensitive(string host)
    {
        foreach (var d in SensitiveDomains)
            if (host.Contains(d, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }
}
