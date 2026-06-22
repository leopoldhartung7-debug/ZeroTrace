using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Detection;

/// <summary>
/// Reads a bounded chunk of a file's raw bytes and tests it against the loaded
/// content-string signatures (cheat watermarks, menu strings, brand tokens).
/// This is a lightweight, fully local "YARA-lite" pass: it only looks for the
/// admin-maintained string set, never uploads anything, and is read-only.
///
/// A content match catches a cheat even when its file/process has been renamed,
/// because the characteristic strings still live inside the binary.
/// </summary>
public static class ContentSignatureScanner
{
    /// <summary>
    /// Maximum number of bytes read per file. Cheat watermarks/menu strings sit
    /// near the start of the image; 8 MiB covers all realistic cheat binaries
    /// and Lua scripts while cutting I/O time vs. the old 32 MiB cap.
    /// </summary>
    public const int MaxReadBytes = 8 * 1024 * 1024;

    /// <summary>
    /// Returns the first content-string indicator found in <paramref name="path"/>,
    /// or null. All I/O failures degrade safely to null (no finding).
    /// </summary>
    public static Indicator? Scan(string path, IndicatorMatcher matcher)
    {
        if (!matcher.HasContentSignatures) return null;

        byte[] buffer;
        int read;
        try
        {
            using var fs = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024,
                FileOptions.SequentialScan);

            long len = 0;
            try { len = fs.Length; } catch { /* some pseudo-files report no length */ }
            int cap = len > 0 ? (int)Math.Min(len, MaxReadBytes) : MaxReadBytes;

            buffer = new byte[cap];
            read = 0;
            int n;
            while (read < cap && (n = fs.Read(buffer, read, cap - read)) > 0)
                read += n;
        }
        catch
        {
            return null;
        }

        return matcher.MatchContent(buffer, read);
    }
}
