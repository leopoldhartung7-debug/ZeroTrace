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

        int total = Math.Max(drivers.Count, 1);
        int i = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (name, rawPath, running) in drivers)
        {
            ct.ThrowIfCancellationRequested();
            i++;
            if (i % 10 == 0 || i == drivers.Count)
                ctx.Report((double)i / total, name, $"{i}/{drivers.Count} Treiber");

            var path = NormalizeDriverPath(rawPath);
            if (string.IsNullOrEmpty(path)) continue;
            if (!seen.Add(path)) continue;
            if (!File.Exists(path)) continue;

            ctx.IncrementFiles();

            // Full file inspection (hash / signature / self-rename / indicators /
            // untrusted-in-user-writable).
            var finding = FileInspector.Inspect(path, ctx, Name);
            if (finding is not null)
            {
                finding.Title = "Treiber: " + finding.Title;
                finding.Reason = $"[Kernel-Treiber '{name}'{(running ? ", GELADEN" : "")}] " + finding.Reason;
                // A loaded (running) kernel driver is the highest-impact surface:
                // escalate one notch.
                if (running && finding.Risk < RiskLevel.Critical) finding.Risk++;
                ctx.AddFinding(finding);
                continue;
            }

            // No indicator/heuristic hit, but the image sits OUTSIDE the system
            // driver folder. Legit third-party drivers usually live there too, so
            // this is only notable when the driver is untrusted-signed.
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
        }

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

    /// <summary>
    /// Turns the various driver image path formats (\??\C:\..,
    /// \SystemRoot\System32\drivers\.., system32\.., or relative) into a normal
    /// absolute path. Returns null if it cannot be resolved.
    /// </summary>
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
