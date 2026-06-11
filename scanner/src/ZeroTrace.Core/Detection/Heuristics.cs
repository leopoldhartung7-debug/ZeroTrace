using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Detection;

/// <summary>
/// Signature-free behavioural heuristics. These do NOT identify specific cheat
/// products; they flag generally suspicious arrangements (e.g. an unsigned
/// executable running from a temp folder). Every result is low/medium by design
/// to keep false positives controllable, and always carries a reason.
/// </summary>
public static class Heuristics
{
    // Broadened set of locations normal applications do not install into but
    // cheats/loaders frequently use. More coverage, still combined with the
    // "untrusted signature" condition to keep false positives low.
    private static string[] BuildUserWritableRoots()
    {
        var profile = KnownPaths.UserProfile;
        var local = KnownPaths.LocalAppData;
        var roaming = KnownPaths.RoamingAppData;

        var roots = new List<string?>
        {
            KnownPaths.Temp,
            Path.Combine(local, "Temp"),
            KnownPaths.Downloads,
            roaming,
            local,
            // additional high-signal, user-writable locations
            SafeCombine(local, "..", "LocalLow"),                  // %LocalAppData%\..\LocalLow
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), // ProgramData
            Environment.GetEnvironmentVariable("PUBLIC"),          // C:\Users\Public
            Path.Combine(profile, "Desktop"),
            Path.Combine(profile, "Documents"),
            Path.Combine(profile, "Music"),
            Path.Combine(profile, "Videos"),
            Path.Combine(profile, "Pictures")
        };

        return roots
            .Where(r => !string.IsNullOrEmpty(r))
            .Select(r => SafeFull(r!))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static readonly string[] UserWritableRoots = BuildUserWritableRoots();

    /// <summary>True if the path sits under a directory normal apps don't install into.</summary>
    public static bool IsInUserWritableRoot(string path)
    {
        var full = SafeFull(path);
        return UserWritableRoots.Any(r =>
            full.StartsWith(r, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// True when an executable image is both unsigned AND living in a
    /// user-writable location — a common (though not exclusive) cheat pattern.
    /// </summary>
    public static bool IsUnsignedInUserWritable(string path, bool? signed) =>
        signed == false && IsInUserWritableRoot(path);

    /// <summary>
    /// Trust-aware variant: an untrusted (unsigned OR invalidly-signed) image in
    /// a user-writable location. Invalid signatures count as "not trusted".
    /// </summary>
    public static bool IsUntrustedInUserWritable(SignatureChecker.SignatureDetail sig, string path) =>
        !sig.IsTrusted && IsInUserWritableRoot(path);

    private static string SafeFull(string p)
    {
        try { return Path.GetFullPath(p); } catch { return p; }
    }

    private static string? SafeCombine(params string[] parts)
    {
        try { return Path.GetFullPath(Path.Combine(parts)); } catch { return null; }
    }
}
