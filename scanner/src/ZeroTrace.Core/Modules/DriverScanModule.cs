using System.Management;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Read-only scan of installed/loaded KERNEL drivers (Win32_SystemDriver).
/// Serious cheats and HWID-spoofers run in the kernel via their own driver, or
/// abuse a vulnerable signed driver (BYOVD). Each driver image is run through
/// the normal file inspection (hash, real signature, self-rename, indicators).
/// A loaded driver gets escalated, and a driver image outside the system driver
/// folder is flagged on its own. Nothing is changed or unloaded.
/// File inspection is parallelized across CPU cores to reduce wall-clock time.
/// </summary>
public sealed class DriverScanModule : IScanModule
{
    public string Name => "Kernel-Treiber";
    public double Weight => 0.8;

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string DriversDir =
        Path.Combine(WinDir, "System32", "drivers");

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        List<(string name, string? path, bool running)> drivers;
        try { drivers = QueryDrivers(); }
        catch
        {
            ctx.Report(1.0, "Kernel-Treiber", "Treiberliste nicht lesbar");
            return Task.CompletedTask;
        }

        // Deduplicate and resolve paths up front (single-threaded, no I/O here).
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var work = new List<(string name, string path, bool running)>();
        foreach (var (name, rawPath, running) in drivers)
        {
            var path = NormalizeDriverPath(rawPath);
            if (string.IsNullOrEmpty(path) || !seen.Add(path!)) continue;
            if (!File.Exists(path)) continue;
            work.Add((name, path!, running));
        }

        int total = Math.Max(work.Count, 1);
        int i = 0;

        var parallelOptions = new ParallelOptions
        {
            CancellationToken = ct,
            MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount)
        };

        Parallel.ForEach(work, parallelOptions, item =>
        {
            var (name, path, running) = item;
            ctx.IncrementFiles();
            int n = System.Threading.Interlocked.Increment(ref i);
            if (n % 10 == 0 || n == work.Count)
                ctx.Report((double)n / total, name, $"{n}/{work.Count} Treiber");

            var finding = FileInspector.Inspect(path, ctx, Name);
            if (finding is not null)
            {
                finding.Title = "Treiber: " + finding.Title;
                finding.Reason = $"[Kernel-Treiber '{name}'{(running ? ", GELADEN" : "")}] " + finding.Reason;
                if (running && finding.Risk < RiskLevel.Critical) finding.Risk++;
                ctx.AddFinding(finding);
                return;
            }

            if (!IsUnderSystemDrivers(path))
            {
                var sig = SignatureChecker.CheckDetailed(path);
                if (!sig.IsTrusted)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Treiber ausserhalb des System-Ordners",
                        Risk = running ? RiskLevel.High : RiskLevel.Medium,
                        Location = path,
                        FileName = Path.GetFileName(path),
                        Signed = false,
                        Reason = $"Der Kernel-Treiber '{name}' wird aus einem ungewoehnlichen Pfad " +
                                 $"{(running ? "geladen" : "registriert")} und ist nicht vertrauenswuerdig " +
                                 "signiert. Kernel-Treiber aus Nicht-System-Ordnern sind ein starkes " +
                                 "Cheat-/Spoofer-Muster.",
                        Detail = $"System-Treiberordner: {DriversDir}"
                    });
                }
            }
        });

        ctx.Report(1.0, "Kernel-Treiber", "Treiber-Pruefung abgeschlossen");
        return Task.CompletedTask;
    }

    private static List<(string name, string? path, bool running)> QueryDrivers()
    {
        var list = new List<(string, string?, bool)>();
        using var searcher = new ManagementObjectSearcher(
            "SELECT Name, PathName, State FROM Win32_SystemDriver");
        foreach (ManagementObject mo in searcher.Get())
        {
            var name = mo["Name"]?.ToString() ?? "?";
            var path = mo["PathName"]?.ToString();
            bool running = string.Equals(mo["State"]?.ToString(), "Running", StringComparison.OrdinalIgnoreCase);
            list.Add((name, path, running));
        }
        return list;
    }

    private static string? NormalizeDriverPath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var p = raw.Trim().Trim('"');

        if (p.StartsWith(@"\??\", StringComparison.Ordinal))
            p = p[4..];

        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(WinDir, p[@"\SystemRoot\".Length..]);
        else if (p.StartsWith("SystemRoot\\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(WinDir, p["SystemRoot\\".Length..]);
        else if (p.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(WinDir, p);
        else if (!Path.IsPathRooted(p))
            p = Path.Combine(DriversDir, p);

        try { return Path.GetFullPath(p); }
        catch { return null; }
    }

    private static bool IsUnderSystemDrivers(string path)
    {
        try
        {
            return Path.GetFullPath(path)
                .StartsWith(Path.GetFullPath(DriversDir), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
