using System.Xml.Linq;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans C:\Windows\System32\Tasks\ for Windows Task Scheduler entries whose
/// executable has been deleted — a common cleanup pattern for cheat loaders that
/// register a scheduled task for persistence and then delete the binary to erase
/// evidence. Entries for existing executables are also cross-checked against the
/// indicator database. Read-only; nothing is created or modified.
/// </summary>
public sealed class ScheduledTaskScanModule : IScanModule
{
    public string Name => "Geplante Aufgaben";
    public double Weight => 0.4;
    public bool ParallelSafe => true;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ScanTasksFolder(ctx, ct);
        ctx.Report(1.0, "Tasks", "Geplante Aufgaben geprueft");
        return Task.CompletedTask;
    }

    private void ScanTasksFolder(ScanContext ctx, CancellationToken ct)
    {
        var tasksRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "Tasks");
        if (!Directory.Exists(tasksRoot)) return;

        string[] files;
        try { files = Directory.GetFiles(tasksRoot, "*", SearchOption.AllDirectories); }
        catch { return; }

        int checked_ = 0;
        foreach (var file in files)
        {
            if (ct.IsCancellationRequested || checked_ > 600) break;
            // Task XML files in System32\Tasks have no file extension
            if (!string.IsNullOrEmpty(Path.GetExtension(file))) continue;
            checked_++;
            try { InspectTaskFile(ctx, file); } catch { }
        }
    }

    private void InspectTaskFile(ScanContext ctx, string taskFile)
    {
        string xml;
        try { xml = File.ReadAllText(taskFile, System.Text.Encoding.UTF8); }
        catch { return; }

        XDocument doc;
        try { doc = XDocument.Parse(xml); }
        catch { return; }

        // Use LocalName to handle both namespaced and non-namespaced task XMLs
        var commands = doc.Descendants()
            .Where(e => e.Name.LocalName == "Command")
            .Select(e => e.Value.Trim())
            .Where(v => v.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var cmd in commands)
        {
            string expanded;
            try { expanded = Environment.ExpandEnvironmentVariables(cmd).Trim('"', ' '); }
            catch { expanded = cmd; }

            if (!expanded.Contains('\\')) continue; // not a filesystem path

            var fileName = Path.GetFileName(expanded);
            bool exists = File.Exists(expanded);

            // Cross-check against the indicator database regardless of file existence
            var ind = ctx.Matcher.MatchFileName(fileName)
                      ?? ctx.Matcher.MatchFileNameKeyword(fileName)
                      ?? ctx.Matcher.MatchPathKeyword(expanded);

            if (!exists)
            {
                // Deleted executable in a task = evidence-clearing indicator
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = ind is null
                        ? $"Geplante Aufgabe: Zielprogramm nicht mehr vorhanden ({Path.GetFileName(taskFile)})"
                        : $"Geplante Aufgabe – verdaechtiger Indikator ({ind.Category}): {Path.GetFileName(taskFile)}",
                    Risk = ind?.Risk ?? RiskLevel.Medium,
                    Recommendation = Recommendation.Review,
                    Location = taskFile,
                    FileName = Path.GetFileName(taskFile),
                    Reason = $"Die geplante Aufgabe '{Path.GetFileName(taskFile)}' verweist auf " +
                             $"'{expanded}', die nicht (mehr) auf der Festplatte existiert. " +
                             "Cheat-Loader registrieren sich haeufig als geplante Aufgabe fuer " +
                             "Persistenz und loeschen anschliessend die Binaerdatei." +
                             (ind is null ? "" : $" Indikator '{ind.Pattern}': {ind.Description}"),
                    Detail = $"Befehl: {cmd}"
                });
            }
            else if (ind is not null)
            {
                // Existing executable that matches a known-bad indicator
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Geplante Aufgabe – verdaechtiger Indikator ({ind.Category}): {Path.GetFileName(taskFile)}",
                    Risk = ind.Risk,
                    Location = taskFile,
                    FileName = Path.GetFileName(taskFile),
                    Reason = $"Die geplante Aufgabe '{Path.GetFileName(taskFile)}' startet '{expanded}', " +
                             $"das dem Indikator '{ind.Pattern}' entspricht. {ind.Description}",
                    Detail = $"Befehl: {cmd}"
                });
            }
        }
    }
}
