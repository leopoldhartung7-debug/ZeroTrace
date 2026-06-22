using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace ZeroTrace.Core.Detection;

/// <summary>SHA-256 file hashing with streaming, a size guard, and a per-run cache.</summary>
public static class HashUtil
{
    // path → (hex-hash, lastWriteTimeUtc ticks)
    // Avoids re-hashing the same file when multiple modules inspect it in one scan run.
    private static readonly ConcurrentDictionary<string, (string? hash, long ticks)> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Clears the hash cache between scan runs.</summary>
    public static void ClearCache() => _cache.Clear();

    /// <summary>
    /// Computes the lower-case hex SHA-256 of a file. Returns null if the file
    /// is unreadable, locked, or exceeds <paramref name="maxBytes"/>.
    /// Result is cached for the lifetime of the scan run.
    /// </summary>
    public static string? TryComputeSha256(string path, long maxBytes)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > maxBytes) return null;

            long ticks = info.LastWriteTimeUtc.Ticks;
            if (_cache.TryGetValue(path, out var cached) && cached.ticks == ticks)
                return cached.hash;

            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                bufferSize: 1024 * 128, FileOptions.SequentialScan);

            using var sha = SHA256.Create();
            var hashBytes = sha.ComputeHash(stream);
            var hex = Convert.ToHexString(hashBytes).ToLowerInvariant();
            _cache[path] = (hex, ticks);
            return hex;
        }
        catch
        {
            return null;
        }
    }
}
