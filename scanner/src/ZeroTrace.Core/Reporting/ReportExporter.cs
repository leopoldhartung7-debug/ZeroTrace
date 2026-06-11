using System.Net;
using System.Text;
using System.Text.Json;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Reporting;

/// <summary>Exports a <see cref="ScanReport"/> to JSON, a dark-themed HTML file, or plain text.</summary>
public static class ReportExporter
{
    /// <summary>Serialises a report to indented JSON (enum values as names).</summary>
    public static string ToJson(ScanReport report) =>
        JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
        });

    public static void ExportJson(ScanReport report, string path) =>
        File.WriteAllText(path, ToJson(report), Encoding.UTF8);

    public static void ExportText(ScanReport report, string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine("ZeroTrace - Scan-Bericht");
        sb.AppendLine("==========================");
        sb.AppendLine($"Maschine     : {report.MachineName}");
        sb.AppendLine($"Betriebssystem: {report.OsVersion}");
        sb.AppendLine($"Admin-Rechte : {(report.Elevated ? "ja" : "nein")}");
        sb.AppendLine($"Start        : {report.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Ende         : {report.FinishedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Dauer        : {report.Duration:hh\\:mm\\:ss}");
        sb.AppendLine($"Ergebnis     : {report.Result}");
        sb.AppendLine();
        sb.AppendLine("PC-Informationen");
        sb.AppendLine("----------------");
        sb.AppendLine($"System       : {report.System.System}");
        sb.AppendLine($"HWID         : {report.System.Hwid}");
        sb.AppendLine($"Lokale IP    : {(report.System.IpAddresses.Count == 0 ? "-" : string.Join(", ", report.System.IpAddresses))}");
        sb.AppendLine($"Boot-Zeit    : {report.System.BootTime ?? "-"}");
        sb.AppendLine($"Installiert  : {report.System.InstallDate ?? "-"}");
        sb.AppendLine($"VPN          : {report.System.Vpn}");
        sb.AppendLine($"Region       : {report.System.Country}");
        sb.AppendLine($"Spiel        : {report.System.Game}");
        sb.AppendLine($"Hardware     : {report.System.HardwareStats}");
        sb.AppendLine();
        sb.AppendLine("Inventar (fuers Dashboard)");
        sb.AppendLine("--------------------------");
        sb.AppendLine($"Prozesse        : {report.Inventory.Processes.Count}");
        sb.AppendLine($"Admin-gestartet : {report.Inventory.AdminExecuted.Count}");
        sb.AppendLine($"Treiber geladen : {report.Inventory.Drivers.Count}");
        sb.AppendLine($"Aufnahme-SW     : {(report.Inventory.RecordingSoftware.Count == 0 ? "keine" : string.Join(", ", report.Inventory.RecordingSoftware))}");
        sb.AppendLine($"VM-Erkennung    : {report.Inventory.Vm.Verdict}");
        sb.AppendLine($"USB-Geraete     : {report.Inventory.UsbDevices.Count}");
        sb.AppendLine();
        sb.AppendLine("Zusammenfassung");
        sb.AppendLine("---------------");
        sb.AppendLine($"Dateien geprueft   : {report.FilesScanned}");
        sb.AppendLine($"Prozesse geprueft  : {report.ProcessesScanned}");
        sb.AppendLine($"Registry-Keys      : {report.RegistryKeysScanned}");
        sb.AppendLine($"Funde gesamt       : {report.Findings.Count} " +
                      $"(Critical {report.CriticalCount}, High {report.HighCount}, " +
                      $"Medium {report.MediumCount}, Low {report.LowCount})");
        sb.AppendLine();
        sb.AppendLine("Funde");
        sb.AppendLine("-----");
        foreach (var f in report.Findings)
        {
            sb.AppendLine($"[{f.Risk}] {f.Title} ({f.Module}) -> {f.Recommendation}");
            sb.AppendLine($"  Ort   : {f.Location}");
            if (f.Sha256 is not null) sb.AppendLine($"  SHA256: {f.Sha256}");
            sb.AppendLine($"  Grund : {f.Reason}");
            sb.AppendLine();
        }
        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    public static void ExportHtml(ScanReport report, string path)
    {
        var sb = new StringBuilder();
        sb.Append("""
<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZeroTrace - Bericht</title>
<style>
  :root{--bg:#0f1115;--panel:#171a21;--line:#262b36;--text:#e6e8ee;--muted:#8b93a7;
        --low:#3b82f6;--med:#f59e0b;--high:#f97316;--crit:#ef4444;--accent:#22d3ee;}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);
    font:14px/1.5 'Segoe UI',Roboto,Arial,sans-serif;padding:32px}
  h1{font-size:22px;margin:0 0 4px} .sub{color:var(--muted);margin-bottom:24px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
  .card .n{font-size:24px;font-weight:700} .card .l{color:var(--muted);font-size:12px}
  table{width:100%;border-collapse:collapse;background:var(--panel);
        border:1px solid var(--line);border-radius:10px;overflow:hidden}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  tr:last-child td{border-bottom:none}
  .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;color:#0b0d12}
  .Low{background:var(--low)} .Medium{background:var(--med)} .High{background:var(--high)} .Critical{background:var(--crit)}
  code{color:var(--accent);word-break:break-all} .muted{color:var(--muted)}
  .disclaimer{margin-top:24px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:16px}
</style></head><body>
""");
        sb.Append($"<h1>ZeroTrace &ndash; Scan-Bericht</h1>");
        sb.Append($"<div class='sub'>{Enc(report.MachineName)} &middot; {Enc(report.OsVersion)} &middot; " +
                  $"Admin: {(report.Elevated ? "ja" : "nein")} &middot; " +
                  $"{report.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm} &middot; " +
                  $"Dauer {report.Duration:hh\\:mm\\:ss} &middot; Ergebnis {report.Result}</div>");

        sb.Append("<div class='grid'>");
        Card(sb, report.FilesScanned.ToString("N0"), "Dateien geprueft");
        Card(sb, report.ProcessesScanned.ToString("N0"), "Prozesse geprueft");
        Card(sb, report.RegistryKeysScanned.ToString("N0"), "Registry-Keys");
        Card(sb, report.Findings.Count.ToString(), "Funde gesamt");
        Card(sb, report.CriticalCount.ToString(), "Critical");
        Card(sb, report.HighCount.ToString(), "High");
        Card(sb, report.MediumCount.ToString(), "Medium");
        Card(sb, report.LowCount.ToString(), "Low");
        sb.Append("</div>");

        sb.Append("<table><thead><tr><th>Risiko</th><th>Titel / Modul</th><th>Ort</th>" +
                  "<th>SHA-256</th><th>Grund</th><th>Empfehlung</th></tr></thead><tbody>");
        foreach (var f in report.Findings)
        {
            sb.Append("<tr>");
            sb.Append($"<td><span class='pill {f.Risk}'>{f.Risk}</span></td>");
            sb.Append($"<td><b>{Enc(f.Title)}</b><br><span class='muted'>{Enc(f.Module)}</span></td>");
            sb.Append($"<td><code>{Enc(f.Location)}</code></td>");
            sb.Append($"<td><code>{Enc(f.Sha256 ?? "-")}</code></td>");
            sb.Append($"<td>{Enc(f.Reason)}</td>");
            sb.Append($"<td>{f.Recommendation}</td>");
            sb.Append("</tr>");
        }
        sb.Append("</tbody></table>");

        sb.Append("<div class='disclaimer'>ZeroTrace ist ein Analyse-Werkzeug. " +
                  "Funde sind Hinweise, kein Beweis fuer Cheating. Es besteht keine Garantie, " +
                  "dass alle Cheats erkannt werden, und False Positives sind moeglich. " +
                  "Jede Massnahme liegt in der Verantwortung des Betreibers.</div>");
        sb.Append("</body></html>");

        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    private static void Card(StringBuilder sb, string number, string label) =>
        sb.Append($"<div class='card'><div class='n'>{Enc(number)}</div><div class='l'>{Enc(label)}</div></div>");

    private static string Enc(string? s) => WebUtility.HtmlEncode(s ?? string.Empty);
}
