using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace ZeroTrace.Core.Detection;

/// <summary>
/// Authenticode status for a PE/installer file. This now performs REAL trust
/// validation via <see cref="AuthenticodeVerifier"/> (WinVerifyTrust + catalog),
/// instead of the old "embedded certificate present == signed" assumption.
///
/// Three outcomes are distinguished:
///   * <see cref="Trust.Trusted"/>          - Windows trusts the signature.
///   * <see cref="Trust.SignedUntrusted"/>  - a signature exists but is invalid
///                                            (self-signed / tampered / expired).
///   * <see cref="Trust.Unsigned"/>          - no signature at all.
///
/// Still a heuristic input, never proof. The signer subject is extracted from the
/// embedded certificate when present (best-effort, for display only).
/// </summary>
public static class SignatureChecker
{
    public enum Trust { Unsigned, SignedUntrusted, Trusted }

    /// <summary>Back-compatible shape. <c>Signed</c> now means "validly trusted".</summary>
    public readonly record struct SignatureInfo(bool Signed, string? Signer);

    /// <summary>Full detail for callers that want to react to invalid signatures.</summary>
    public readonly record struct SignatureDetail(Trust Trust, string? Signer, bool CatalogSigned)
    {
        /// <summary>True only when Windows fully trusts the signature.</summary>
        public bool IsTrusted => Trust == Trust.Trusted;

        /// <summary>True when a signature is present (trusted or not).</summary>
        public bool HasSignature => Trust != Trust.Unsigned;
    }

    private static readonly HashSet<string> Checkable = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".ocx", ".cab", ".msi", ".cat", ".scr", ".cpl", ".asi"
    };

    // Cache Authenticode results keyed by (normalised path → (detail, lastWriteUtcTicks)).
    // WinVerifyTrust + catalog lookup is the single most expensive per-file operation;
    // caching eliminates redundant calls across modules and between scans on the same
    // session. Cleared at the start of every scan run via ClearCache().
    private static readonly ConcurrentDictionary<string, (SignatureDetail result, long ticks)> _sigCache =
        new(StringComparer.OrdinalIgnoreCase);

    public static void ClearCache() => _sigCache.Clear();

    public static bool IsCheckable(string path) =>
        Checkable.Contains(Path.GetExtension(path));

    /// <summary>Back-compatible check: Signed == validly trusted.</summary>
    public static SignatureInfo Check(string path)
    {
        var d = CheckDetailed(path);
        return new SignatureInfo(d.IsTrusted, d.Signer);
    }

    /// <summary>Full trust + signer information. Results are cached by path+lastWriteTime.</summary>
    public static SignatureDetail CheckDetailed(string path)
    {
        if (!IsCheckable(path)) return new SignatureDetail(Trust.Unsigned, null, false);

        long ticks = 0;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return new SignatureDetail(Trust.Unsigned, null, false);
            ticks = fi.LastWriteTimeUtc.Ticks;
            if (_sigCache.TryGetValue(path, out var cached) && cached.ticks == ticks)
                return cached.result;
        }
        catch { }

        var result = AuthenticodeVerifier.Verify(path);
        var trust = result.Status switch
        {
            AuthenticodeVerifier.TrustStatus.Trusted => Trust.Trusted,
            AuthenticodeVerifier.TrustStatus.SignedUntrusted => Trust.SignedUntrusted,
            _ => Trust.Unsigned
        };

        string? signer = TryReadEmbeddedSigner(path);
        if (signer is null && result.CatalogSigned) signer = "Windows-Katalog";

        var detail = new SignatureDetail(trust, signer, result.CatalogSigned);
        if (ticks != 0) _sigCache[path] = (detail, ticks);
        return detail;
    }

    /// <summary>Best-effort friendly signer name from the embedded certificate.</summary>
    private static string? TryReadEmbeddedSigner(string path)
    {
        try
        {
            using var cert = new X509Certificate2(
                X509Certificate.CreateFromSignedFile(path));
            var subject = cert.GetNameInfo(X509NameType.SimpleName, false);
            return string.IsNullOrWhiteSpace(subject) ? cert.Subject : subject;
        }
        catch
        {
            return null; // no embedded cert (e.g. catalog-signed) or unreadable
        }
    }
}
