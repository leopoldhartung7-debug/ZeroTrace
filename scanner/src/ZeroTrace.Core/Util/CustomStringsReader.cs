using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Util;

/// <summary>
/// Reads the optional "zerotrace.strings" sidecar file placed next to the exe
/// by the dashboard when building the scanner ZIP. Each non-empty line becomes
/// a ContentString indicator with Medium risk.  Returns an empty list when the
/// file is absent, unreadable, or contains no usable patterns.
/// </summary>
public static class CustomStringsReader
{
    private const string FileName = "zerotrace.strings";
    private const int MinLength = 3;
    private const int MaxStrings = 2000;

    /// <summary>
    /// Returns the path of the sidecar file that would be read, whether or not
    /// it exists. Callers can check <see cref="File.Exists"/> if needed.
    /// </summary>
    public static string SidecarPath =>
        Path.Combine(AppContext.BaseDirectory, FileName);

    /// <summary>
    /// Reads the sidecar file and returns enabled ContentString indicators, one
    /// per distinct non-empty line. Returns an empty list on any error.
    /// </summary>
    public static List<Indicator> Read()
    {
        var path = SidecarPath;
        if (!File.Exists(path)) return new List<Indicator>();

        string[] lines;
        try { lines = File.ReadAllLines(path, System.Text.Encoding.UTF8); }
        catch { return new List<Indicator>(); }

        var result = new List<Indicator>(Math.Min(lines.Length, MaxStrings));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in lines)
        {
            if (result.Count >= MaxStrings) break;
            var pattern = raw.Trim();
            if (pattern.Length < MinLength) continue;
            if (!seen.Add(pattern)) continue;

            result.Add(new Indicator
            {
                Type = IndicatorType.ContentString,
                Pattern = pattern,
                Risk = RiskLevel.High,
                Category = "Benutzerdefiniert",
                Description = $"Benutzerdefinierter String aus dem Dashboard: '{pattern}'.",
                Source = "custom-strings",
                Enabled = true,
                CreatedUtc = DateTime.UtcNow,
            });
        }
        return result;
    }
}
