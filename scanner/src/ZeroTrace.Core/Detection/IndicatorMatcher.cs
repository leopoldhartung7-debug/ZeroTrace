using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Detection;

/// <summary>
/// Matches scan artifacts against the loaded set of enabled indicators.
/// The indicator set is snapshotted at scan start so behaviour is deterministic
/// for the duration of a scan. Matching is allocation-light and case-insensitive.
/// </summary>
public sealed class IndicatorMatcher
{
    private readonly Dictionary<string, Indicator> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Indicator> _fileNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Indicator> _processNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Indicator> _fileNameKeywords = new();
    private readonly List<Indicator> _pathKeywords = new();
    private readonly List<Indicator> _registryKeywords = new();
    private readonly List<(Indicator ind, byte[] needle)> _contentStrings = new();
    private readonly List<Indicator> _urlDomainKeywords = new();

    public int Count { get; }

    /// <summary>True if at least one content-string signature is loaded.</summary>
    public bool HasContentSignatures => _contentStrings.Count > 0;

    public IndicatorMatcher(IEnumerable<Indicator> indicators)
    {
        foreach (var ind in indicators)
        {
            if (!ind.Enabled || string.IsNullOrWhiteSpace(ind.Pattern)) continue;
            Count++;

            switch (ind.Type)
            {
                case IndicatorType.Sha256Hash:
                    _hashes[ind.Pattern.Trim().ToLowerInvariant()] = ind;
                    break;
                case IndicatorType.FileName:
                    _fileNames[ind.Pattern.Trim()] = ind;
                    break;
                case IndicatorType.ProcessName:
                    _processNames[StripExe(ind.Pattern.Trim())] = ind;
                    break;
                case IndicatorType.FileNameKeyword:
                    _fileNameKeywords.Add(ind);
                    break;
                case IndicatorType.FilePathKeyword:
                    _pathKeywords.Add(ind);
                    break;
                case IndicatorType.RegistryValueKeyword:
                    _registryKeywords.Add(ind);
                    break;
                case IndicatorType.ContentString:
                    // Pre-fold to lower-case ASCII so matching is case-insensitive
                    // without allocating during the scan.
                    var token = ind.Pattern.Trim();
                    if (token.Length >= 3)
                        _contentStrings.Add((ind, ToLowerAsciiBytes(token)));
                    break;
                case IndicatorType.UrlDomainKeyword:
                    _urlDomainKeywords.Add(ind);
                    break;
            }
        }
    }

    public Indicator? MatchHash(string? sha256) =>
        sha256 is not null && _hashes.TryGetValue(sha256, out var ind) ? ind : null;

    public Indicator? MatchFileName(string fileName) =>
        _fileNames.TryGetValue(fileName, out var ind) ? ind : null;

    public Indicator? MatchProcessName(string processName) =>
        _processNames.TryGetValue(StripExe(processName), out var ind) ? ind : null;

    public Indicator? MatchFileNameKeyword(string fileName) =>
        _fileNameKeywords.FirstOrDefault(k =>
            fileName.Contains(k.Pattern, StringComparison.OrdinalIgnoreCase));

    public Indicator? MatchPathKeyword(string path) =>
        _pathKeywords.FirstOrDefault(k =>
            path.Contains(k.Pattern, StringComparison.OrdinalIgnoreCase));

    public Indicator? MatchRegistryKeyword(string value) =>
        _registryKeywords.FirstOrDefault(k =>
            value.Contains(k.Pattern, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Searches a raw file buffer for any loaded content-string signature.
    /// Each token is matched case-insensitively in both ASCII and UTF-16LE
    /// (so it works on both native strings and wide/Unicode strings in a PE).
    /// Returns the first matching indicator, or null.
    /// </summary>
    public Indicator? MatchContent(byte[] buffer, int length)
    {
        if (length <= 0 || _contentStrings.Count == 0) return null;
        foreach (var (ind, needle) in _contentStrings)
        {
            if (ContainsAsciiFold(buffer, length, needle) ||
                ContainsUtf16Fold(buffer, length, needle))
                return ind;
        }
        return null;
    }

    /// <summary>True if at least one URL-domain signature is loaded.</summary>
    public bool HasUrlDomainSignatures => _urlDomainKeywords.Count > 0;

    /// <summary>Matches a URL host against the cheat/reseller domain keywords.</summary>
    public Indicator? MatchUrlDomain(string host) =>
        _urlDomainKeywords.FirstOrDefault(k =>
            host.Contains(k.Pattern, StringComparison.OrdinalIgnoreCase));

    private static byte[] ToLowerAsciiBytes(string s)
    {
        var b = new byte[s.Length];
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
            b[i] = (byte)c;
        }
        return b;
    }

    private static byte Fold(byte b) => (b >= (byte)'A' && b <= (byte)'Z') ? (byte)(b + 32) : b;

    /// <summary>Case-insensitive search of a lower-cased ASCII needle (stride 1).</summary>
    private static bool ContainsAsciiFold(byte[] hay, int hayLen, byte[] needle)
    {
        int n = needle.Length;
        if (n == 0 || hayLen < n) return false;
        int last = hayLen - n;
        for (int i = 0; i <= last; i++)
        {
            int k = 0;
            while (k < n && Fold(hay[i + k]) == needle[k]) k++;
            if (k == n) return true;
        }
        return false;
    }

    /// <summary>Case-insensitive search of the needle encoded as UTF-16LE (stride 2).</summary>
    private static bool ContainsUtf16Fold(byte[] hay, int hayLen, byte[] needle)
    {
        int n = needle.Length;
        if (n == 0 || hayLen < n * 2) return false;
        int last = hayLen - n * 2;
        for (int i = 0; i <= last; i++)
        {
            int k = 0;
            while (k < n && Fold(hay[i + 2 * k]) == needle[k] && hay[i + 2 * k + 1] == 0) k++;
            if (k == n) return true;
        }
        return false;
    }

    private static string StripExe(string name) =>
        name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? name[..^4]
            : name;
}
