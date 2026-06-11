namespace ZeroTrace.Core.Util;

/// <summary>
/// Reads the NTFS "Mark of the Web" (the <c>Zone.Identifier</c> alternate data
/// stream Windows attaches to files saved from the internet). This is a precise,
/// read-only confidence signal: an unsigned executable that was downloaded from
/// the internet is materially more suspicious than one created locally.
///
///   ZoneId=3 = Internet, ZoneId=4 = Restricted. Both indicate "came from the web".
/// </summary>
public static class MarkOfWeb
{
    public readonly record struct Info(bool Present, int ZoneId, string? ReferrerUrl, string? HostUrl)
    {
        public bool FromInternet => ZoneId >= 3;
    }

    public static Info Read(string path)
    {
        try
        {
            var streamPath = path + ":Zone.Identifier";

            // Open the alternate data stream directly; if it doesn't exist this
            // throws FileNotFoundException and we return default (no MotW).
            string content;
            using (var fs = new FileStream(streamPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var reader = new StreamReader(fs))
                content = reader.ReadToEnd();

            int zone = 0;
            string? referrer = null, host = null;
            foreach (var raw in content.Split('\n'))
            {
                var line = raw.Trim();
                if (line.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase))
                    int.TryParse(line.AsSpan(7), out zone);
                else if (line.StartsWith("ReferrerUrl=", StringComparison.OrdinalIgnoreCase))
                    referrer = line[12..];
                else if (line.StartsWith("HostUrl=", StringComparison.OrdinalIgnoreCase))
                    host = line[8..];
            }
            return new Info(true, zone, referrer, host);
        }
        catch
        {
            return default; // stream missing, not NTFS, or unreadable
        }
    }
}
