using System.Security.Cryptography;

namespace ZeroTrace.Core.Detection;

/// <summary>SHA-256 file hashing with streaming and a size guard.</summary>
public static class HashUtil
{
    /// <summary>
    /// Computes the lower-case hex SHA-256 of a file. Returns null if the file
    /// is unreadable, locked, or exceeds <paramref name="maxBytes"/>.
    /// </summary>
    public static string? TryComputeSha256(string path, long maxBytes)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > maxBytes) return null;

            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                bufferSize: 1024 * 128, FileOptions.SequentialScan);

            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }
}
