using System.Management;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects suspicious PowerShell / command-line activity — a common way cheats
/// and loaders are delivered (download cradles, base64-encoded commands, hidden
/// windows, or disabling the virus protection via Set-MpPreference). Two
/// read-only sources are checked:
///   1) the command lines of currently running powershell/pwsh/cmd processes
///      (via WMI), and
///   2) the PowerShell console history (PSReadLine), where ONLY the lines that
///      match a suspicious pattern are recorded — never the full history.
/// Nothing is executed or modified.
/// </summary>
public sealed class PowerShellScanModule : IScanModule
{
    public string Name => "PowerShell / Befehle";
    public double Weight => 0.6;

    // token (lower-case) -> risk + short category. Matched as a substring.
    private static readonly (string token, RiskLevel risk, string cat)[] Rules =
    {
        ("disablerealtimemonitoring", RiskLevel.Critical, "Echtzeitschutz per Skript deaktiviert"),
        ("set-mppreference",          RiskLevel.High,     "Defender-Einstellung geaendert"),
        ("add-mppreference",          RiskLevel.High,     "Defender-Ausnahme/-Einstellung gesetzt"),
        ("-exclusionpath",            RiskLevel.High,     "Defender-Ausnahme gesetzt"),
        ("frombase64string",          RiskLevel.High,     "Base64-codierter Code"),
        ("-encodedcommand",           RiskLevel.High,     "Codierter (verschleierter) Befehl"),
        ("-enc ",                     RiskLevel.High,     "Codierter (verschleierter) Befehl"),
        ("downloadstring",            RiskLevel.High,     "Download-Cradle"),
        ("downloadfile",              RiskLevel.High,     "Datei-Download per Skript"),
        ("net.webclient",             RiskLevel.High,     "Download-Cradle (WebClient)"),
        ("invoke-expression",         RiskLevel.High,     "Dynamische Code-Ausfuehrung (IEX)"),
        ("iex(",                      RiskLevel.High,     "Dynamische Code-Ausfuehrung (IEX)"),
        ("iex ",                      RiskLevel.High,     "Dynamische Code-Ausfuehrung (IEX)"),
        ("mimikatz",                  RiskLevel.Critical, "Mimikatz / Credential-Dumping"),
        ("sekurlsa",                  RiskLevel.Critical, "Mimikatz-Modul (Credential-Dump)"),
        ("invoke-mimikatz",           RiskLevel.Critical, "Mimikatz (Invoke-Mimikatz)"),
        ("sc create ",                RiskLevel.High,     "Dienst/Treiber per sc.exe installiert"),
        ("sc start ",                 RiskLevel.High,     "Dienst per sc.exe gestartet"),
        ("wmic process call create",  RiskLevel.High,     "Prozess-Erstellung via WMI"),
        ("wmic /namespace",           RiskLevel.High,     "WMI-Manipulation"),
        ("schtasks /create",          RiskLevel.High,     "Geplante Aufgabe erstellt"),
        ("regsvr32",                  RiskLevel.High,     "LOLBin regsvr32 (COM-Registrierung/Proxy)"),
        ("rundll32",                  RiskLevel.Medium,   "LOLBin rundll32"),
        ("netsh advfirewall",         RiskLevel.Medium,   "Firewall-Regel geaendert"),
        ("netsh firewall",            RiskLevel.Medium,   "Firewall-Regel geaendert"),
        ("reflection.assembly",       RiskLevel.Medium,   "Reflektives Laden"),
        ("invoke-webrequest",         RiskLevel.Medium,   "Web-Download (PowerShell)"),
        ("iwr ",                      RiskLevel.Medium,   "Web-Download (PowerShell)"),
        ("certutil",                  RiskLevel.Medium,   "LOLBin certutil"),
        ("bitsadmin",                 RiskLevel.Medium,   "LOLBin bitsadmin"),
        ("mshta",                     RiskLevel.Medium,   "LOLBin mshta"),
        ("wscript",                   RiskLevel.Medium,   "LOLBin wscript (Skript-Host)"),
        ("cscript",                   RiskLevel.Medium,   "LOLBin cscript (Skript-Host)"),
        ("-executionpolicy bypass",   RiskLevel.Medium,   "ExecutionPolicy umgangen"),
        ("-ep bypass",                RiskLevel.Medium,   "ExecutionPolicy umgangen"),
        ("-windowstyle hidden",       RiskLevel.Medium,   "Verstecktes Fenster"),
        ("-w hidden",                 RiskLevel.Medium,   "Verstecktes Fenster"),
        ("clear-eventlog",            RiskLevel.High,     "Ereignisprotokoll geloescht"),
        ("wevtutil cl ",              RiskLevel.High,     "Ereignisprotokoll geloescht"),
        ("remove-item",               RiskLevel.Low,      "Datei/Verzeichnis geloescht"),
        ("-noprofile",                RiskLevel.Low,      "Ohne PowerShell-Profil"),
        ("-nop ",                     RiskLevel.Low,      "Ohne PowerShell-Profil"),
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ScanRunningCommands(ctx, ct);
        ctx.Report(0.5, "Laufende Befehle", "Befehlszeilen geprueft");

        ScanPowerShellHistory(ctx, ct);
        ctx.Report(1.0, "PowerShell-Verlauf", "PowerShell-Verlauf geprueft");
        return Task.CompletedTask;
    }

    // --- 1) running powershell / pwsh / cmd command lines ----------------------

    private void ScanRunningCommands(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, CommandLine FROM Win32_Process " +
                "WHERE Name='powershell.exe' OR Name='pwsh.exe' OR Name='cmd.exe'");

            foreach (ManagementObject mo in searcher.Get())
            {
                ct.ThrowIfCancellationRequested();
                var cmd = mo["CommandLine"]?.ToString();
                if (string.IsNullOrWhiteSpace(cmd)) continue;

                var ev = Evaluate(cmd!);
                if (ev is null) continue;

                var pid = mo["ProcessId"]?.ToString() ?? "?";
                var name = mo["Name"]?.ToString() ?? "?";
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtiger Befehl ({ev.Value.cats})",
                    Risk = ev.Value.risk,
                    Location = $"PID {pid} \u00b7 {name}",
                    FileName = name,
                    Reason = "Laufende Befehlszeile entspricht verdaechtigen Mustern " +
                             $"({ev.Value.cats}). Haeufig bei Loadern, Download-Cradles oder dem " +
                             "Abschalten des Schutzes.",
                    Detail = "Befehl: " + Truncate(cmd!, 220)
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* WMI not available / access denied -> skip */ }
    }

    // --- 2) PowerShell console history (PSReadLine), matched lines only ---------

    private void ScanPowerShellHistory(ScanContext ctx, CancellationToken ct)
    {
        var historyPath = Path.Combine(KnownPaths.RoamingAppData,
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
        if (!File.Exists(historyPath)) return;

        string[] lines;
        try { lines = File.ReadAllLines(historyPath); }
        catch { return; }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int emitted = 0;

        foreach (var line in lines)
        {
            if (ct.IsCancellationRequested) return;
            if (string.IsNullOrWhiteSpace(line)) continue;

            var ev = Evaluate(line);
            if (ev is null) continue;

            // Minimisation: record only the matched line (truncated), de-duplicated.
            var key = Truncate(line.Trim(), 160);
            if (!seen.Add(key)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Verdaechtiger PowerShell-Verlauf ({ev.Value.cats})",
                Risk = ev.Value.risk,
                Location = historyPath,
                Reason = "Ein frueher ausgefuehrter PowerShell-Befehl entspricht verdaechtigen " +
                         $"Mustern ({ev.Value.cats}). Nur die betroffene Zeile wird erfasst, " +
                         "nicht der gesamte Verlauf.",
                Detail = "Zeile: " + key
            });

            if (++emitted >= 25) break; // bound noise
        }
    }

    // --- shared rule evaluation ------------------------------------------------

    /// <summary>Returns the strongest risk + matched categories, or null.</summary>
    private static (RiskLevel risk, string cats)? Evaluate(string text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        var t = text.ToLowerInvariant();

        bool any = false;
        var max = RiskLevel.Low;
        var cats = new List<string>();
        foreach (var (token, risk, cat) in Rules)
        {
            if (!t.Contains(token)) continue;
            any = true;
            if (risk > max) max = risk;
            if (!cats.Contains(cat)) cats.Add(cat);
        }
        return any ? (max, string.Join(", ", cats.Take(3))) : null;
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s.Substring(0, max) + "\u2026";
}
