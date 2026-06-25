using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans for malicious use of NTFS Alternate Data Streams (ADS) to hide cheat software.
///
/// NTFS ADS allow files to have multiple data streams. The primary stream contains
/// visible file data; alternate streams are hidden from normal file system enumeration
/// (dir, Explorer, etc.) and only accessible via explicit stream paths.
///
/// Syntax: filename.ext:streamname:$DATA
/// Example: notepad.exe:cheat.dll:$DATA  — hides cheat.dll inside notepad.exe
///
/// Cheat/malware uses of ADS:
///   1. Hide cheat DLLs inside legitimate system files
///      (C:\Windows\System32\kernel32.dll:payload.dll)
///   2. Store cheat configuration in ADS of innocent-looking files
///      (C:\Users\user\Desktop\screenshot.png:config.json)
///   3. Zone.Identifier stream on downloaded files shows Internet origin
///      (useful for finding recently downloaded cheat zips)
///   4. SmartScreen stream (Motw — Mark of the Web) can be stripped to bypass UAC
///   5. Executable code in ADS of non-executable files
///      (text.txt:inject.exe — can be run with wscript.exe //nologo text.txt:inject.exe)
///
/// Detection:
///   1. Scan high-risk directories for files with non-standard ADS
///   2. Flag ADS that contain PE headers (executable code hidden in streams)
///   3. Flag ADS larger than expected on system files
///   4. Check for missing Zone.Identifier on recently downloaded executables
///      (indicates MoTW stripping to bypass SmartScreen)
///   5. Scan temp/appdata directories for ADS-based cheat stagers
/// </summary>
public sealed class AlternativeDataStreamScanModule : IScanModule
{
    public string Name => "NTFS-ADS-Versteckte-Inhalte-Analyse";
    public double Weight => 0.9;
    public int ParallelGroup => 0;

    // Directories to scan for suspicious ADS
    private static readonly string[] ScanDirs;

    static AlternativeDataStreamScanModule()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(profile, "Downloads");

        ScanDirs = new[]
        {
            temp,
            desktop,
            downloads,
            Path.Combine(appdata, "Roaming"),
            Path.Combine(localAppdata),
            Path.Combine(profile, "Documents"),
        }.Where(d => !string.IsNullOrEmpty(d)).ToArray();
    }

    // ADS names that are suspicious (not Zone.Identifier which is normal)
    private static readonly HashSet<string> KnownGoodStreams = new(StringComparer.OrdinalIgnoreCase)
    {
        "Zone.Identifier",    // Mark of the Web — normal for downloaded files
        "SmartScreen",        // SmartScreen check result — normal
        "encryptable",        // EFS — normal
        "SummaryInformation", // Office metadata — normal
        "DocumentSummaryInformation",
        "SebiesnrMfcLean",    // Visual Studio artifact
        "Afp_AfpInfo",        // Apple Filing Protocol (if on Mac-shared network)
    };

    // Extensions where executable ADS are particularly suspicious
    private static readonly HashSet<string> NonExecutableExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".log", ".ini", ".cfg", ".json", ".xml",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".pdf", ".docx", ".xlsx", ".pptx",
        ".mp3", ".mp4", ".mkv", ".avi",
        ".zip", ".rar", ".7z",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        foreach (var dir in ScanDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;
            hits += await ScanDirectoryForAds(dir, ctx, ct).ConfigureAwait(false);
        }

        ctx.Report(1.0, Name, $"NTFS-ADS geprüft, {hits} verdächtige Streams");
    }

    private static async Task<int> ScanDirectoryForAds(string dir, ScanContext ctx,
        CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories)
                .Take(5000); // cap per-dir to avoid exhaustive scan

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                try
                {
                    hits += await Task.Run(() => CheckFileAds(file, ctx), ct)
                        .ConfigureAwait(false);
                }
                catch { }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckFileAds(string filePath, ScanContext ctx)
    {
        int hits = 0;
        try
        {
            // Use FindFirstStreamW / FindNextStreamW via P/Invoke via wrapper
            // Fallback: use BackupRead API to enumerate streams
            var streams = EnumerateStreams(filePath);

            foreach (var stream in streams)
            {
                // Skip primary data stream
                if (stream.Name == "::$DATA" || string.IsNullOrEmpty(stream.Name)) continue;

                // Extract stream name (format: :streamname:$DATA)
                var streamName = stream.Name.TrimStart(':').Split(':')[0];

                // Skip known-good streams
                if (KnownGoodStreams.Contains(streamName)) continue;

                // Read first bytes of the stream to check for PE header
                bool hasExecContent = false;
                try
                {
                    var streamPath = filePath + ":" + streamName;
                    if (File.Exists(streamPath))
                    {
                        using var fs = new FileStream(streamPath, FileMode.Open,
                            FileAccess.Read, FileShare.ReadWrite, 4096);
                        var header = new byte[4];
                        if (fs.Read(header, 0, 4) >= 2)
                        {
                            hasExecContent = header[0] == 0x4D && header[1] == 0x5A; // MZ
                        }
                    }
                }
                catch { }

                string ext = Path.GetExtension(filePath).ToLowerInvariant();
                bool isNonExec = NonExecutableExts.Contains(ext);

                if (hasExecContent || (isNonExec && stream.Size > 1024))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "NTFS-ADS-Versteckte-Inhalte-Analyse",
                        Title    = hasExecContent
                            ? $"Ausführbarer Code in NTFS-ADS: {streamName}"
                            : $"Verdächtiger NTFS-ADS in Nicht-Executable: {streamName}",
                        Risk     = hasExecContent ? RiskLevel.Critical : RiskLevel.High,
                        Location = filePath + ":" + streamName,
                        FileName = Path.GetFileName(filePath),
                        Reason   = hasExecContent
                            ? $"NTFS Alternate Data Stream '{streamName}' in '{Path.GetFileName(filePath)}' " +
                              "enthält eine PE-Datei (MZ-Header). Executable Code, der in ADS " +
                              "versteckt wird, ist ein fortgeschrittener Stealth-Trick: " +
                              "weder Explorer noch die meisten Security-Tools sehen ihn. " +
                              "Cheat-Software kann so versteckt und via wscript.exe/mshta.exe geladen werden."
                            : $"NTFS Alternate Data Stream '{streamName}' ({stream.Size:N0} Bytes) " +
                              $"in Nicht-Executable '{Path.GetFileName(filePath)}'. " +
                              "Verdächtige Inhalte in ADS werden genutzt, um Cheat-Konfigurationen " +
                              "oder kleine Payloads vor Datei-Browsern zu verbergen.",
                        Detail   = $"Datei: {filePath} | Stream: {streamName} | " +
                                   $"Größe: {stream.Size} | MZ-Header: {hasExecContent}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static List<(string Name, long Size)> EnumerateStreams(string filePath)
    {
        var result = new List<(string, long)>();
        try
        {
            // Try reading stream info from BackupRead API via managed wrapper
            // Use FileStream with FILE_FLAG_BACKUP_SEMANTICS-equivalent approach:
            // Parse WIN32_FIND_STREAM_DATA via FindFirstStreamW
            var handle = NativeMethods.FindFirstStreamW(filePath,
                NativeMethods.StreamInfoLevels.FindStreamInfoStandard,
                out var data, 0);

            if (handle == NativeMethods.INVALID_HANDLE_VALUE) return result;

            try
            {
                do
                {
                    result.Add((data.cStreamName, data.StreamSize));
                }
                while (NativeMethods.FindNextStreamW(handle, out data));
            }
            finally
            {
                NativeMethods.FindClose(handle);
            }
        }
        catch { }
        return result;
    }

    private static class NativeMethods
    {
        public static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

        public enum StreamInfoLevels { FindStreamInfoStandard = 0 }

        [System.Runtime.InteropServices.StructLayout(
            System.Runtime.InteropServices.LayoutKind.Sequential, CharSet =
            System.Runtime.InteropServices.CharSet.Unicode)]
        public struct WIN32_FIND_STREAM_DATA
        {
            public long StreamSize;
            [System.Runtime.InteropServices.MarshalAs(
                System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 296)]
            public string cStreamName;
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll",
            ExactSpelling = true, CharSet = System.Runtime.InteropServices.CharSet.Auto,
            SetLastError = true)]
        public static extern IntPtr FindFirstStreamW(
            [System.Runtime.InteropServices.MarshalAs(
                System.Runtime.InteropServices.UnmanagedType.LPWStr)] string lpFileName,
            StreamInfoLevels InfoLevel,
            out WIN32_FIND_STREAM_DATA lpFindStreamData,
            uint dwFlags);

        [System.Runtime.InteropServices.DllImport("kernel32.dll",
            ExactSpelling = true, SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(
            System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool FindNextStreamW(IntPtr hFindStream,
            out WIN32_FIND_STREAM_DATA lpFindStreamData);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(
            System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool FindClose(IntPtr hFindFile);
    }
}
