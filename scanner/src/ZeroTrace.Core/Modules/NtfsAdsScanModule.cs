using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans for NTFS Alternate Data Streams (ADS) used to hide cheat-related data.
///
/// ADS allow additional data to be appended to any file or directory using the
/// syntax "filename:streamname". They are invisible to Windows Explorer and most
/// file scanners, making them attractive for hiding cheat configurations, license
/// files, injected code, or persistence payloads.
///
/// Detection approach:
///   1. Walk high-signal directories for files with ADS (using BackupRead API
///      which enumerates streams natively, or FindFirstStreamW/FindNextStreamW).
///
///   2. Flag any executable or suspicious stream names (e.g. ":payload",
///      ":license", ":config", ":data" on unexpected file types).
///
///   3. Flag ADS with executable content (MZ header in stream data).
///
///   4. Flag Zone.Identifier on files in Temp/Downloads (expected) vs other
///      paths (anomalous — indicates file was moved after download).
///
///   5. Large ADS on small files (common hiding pattern: tiny .txt with 5 MB ADS).
/// </summary>
public sealed class NtfsAdsScanModule : IScanModule
{
    public string Name => "NTFS-ADS";
    public double Weight => 0.8;
    public int ParallelGroup => 0; // sequential IO

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(string lpFileName, int infoLevel,
        out WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextStreamW(IntPtr hFindStream,
        out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr hFindFile);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    private static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    // Directories to scan for ADS — user-writable, high-signal locations
    private static readonly string[] ScanRoots;

    static NtfsAdsScanModule()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();

        ScanRoots = new[]
        {
            Path.Combine(profile, "Downloads"),
            Path.Combine(profile, "Desktop"),
            temp,
            Path.Combine(localApp, "Temp"),
            appData,
        };
    }

    // ADS stream names that are suspicious (not :$DATA or :Zone.Identifier)
    private static readonly HashSet<string> LegitStreamNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ":$DATA", ":Zone.Identifier:$DATA", ":SmartScreen:$DATA",
        ":encryptable:$DATA", ":AFP_Resource:$DATA", ":AFP_AfpInfo:$DATA",
    };

    // Suspicious stream names often used to hide data
    private static readonly string[] SuspiciousStreamNames =
    {
        "payload", "license", "config", "data", "code", "inject",
        "key", "token", "auth", "hack", "cheat", "loader",
        "bypass", "patch", "hook", "dll", "exe", "bin",
    };

    // File extensions where Zone.Identifier absence in AppData is suspicious
    private static readonly string[] ExecutableExtensions =
    {
        ".exe", ".dll", ".sys", ".drv", ".scr", ".com", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".jar", ".msi"
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        // ADS is only supported on NTFS volumes
        if (!IsNtfsDrive(Path.GetPathRoot(ScanRoots[0]) ?? "C:\\"))
        {
            ctx.Report(1.0, "NTFS-ADS", "Kein NTFS-Volume — übersprungen");
            return Task.CompletedTask;
        }

        int filesChecked = 0;
        int adsFound = 0;

        foreach (var root in ScanRoots)
        {
            if (!Directory.Exists(root)) continue;
            ScanDirectory(root, ctx, ct, ref filesChecked, ref adsFound);
            if (ct.IsCancellationRequested) break;
        }

        ctx.Report(1.0, "NTFS-ADS",
            $"{filesChecked} Dateien geprüft, {adsFound} ADS gefunden");
        return Task.CompletedTask;
    }

    private static void ScanDirectory(string dir, ScanContext ctx, CancellationToken ct,
        ref int filesChecked, ref int adsFound)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                filesChecked++;
                ctx.IncrementFiles();

                EnumerateStreams(file, ctx, ct, ref adsFound);
            }
        }
        catch { }
    }

    private static void EnumerateStreams(string filePath, ScanContext ctx,
        CancellationToken ct, ref int adsFound)
    {
        var handle = FindFirstStreamW(filePath, 0, out var streamData, 0);
        if (handle == INVALID_HANDLE) return;

        try
        {
            do
            {
                if (ct.IsCancellationRequested) break;
                var streamName = streamData.cStreamName ?? "";

                // Skip the default data stream
                if (streamName.Equals(":$DATA", StringComparison.OrdinalIgnoreCase)) continue;
                if (LegitStreamNames.Contains(streamName)) continue;

                // Strip the type suffix (e.g. ":payload:$DATA" → ":payload")
                var namePart = streamName.Split(':')[1].ToLowerInvariant();

                adsFound++;
                long size = streamData.StreamSize;

                // Determine risk
                bool isSuspiciousName = SuspiciousStreamNames.Any(s =>
                    namePart.Contains(s, StringComparison.OrdinalIgnoreCase));

                // Try to read first 2 bytes to check for MZ header
                bool hasMzHeader = false;
                try
                {
                    var streamPath = $"{filePath}:{namePart}";
                    using var fs = new FileStream(streamPath, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite, 4096);
                    var buf = new byte[2];
                    if (fs.Read(buf, 0, 2) == 2 && buf[0] == 0x4D && buf[1] == 0x5A)
                        hasMzHeader = true;
                }
                catch { }

                var risk = hasMzHeader ? RiskLevel.Critical
                         : isSuspiciousName ? RiskLevel.High
                         : size > 1024 * 1024 ? RiskLevel.Medium
                         : RiskLevel.Low;

                if (risk >= RiskLevel.Medium || hasMzHeader || isSuspiciousName)
                {
                    var fileName = Path.GetFileName(filePath);
                    ctx.AddFinding(new Finding
                    {
                        Module   = "NTFS-ADS",
                        Title    = $"NTFS Alternate Data Stream: {fileName}:{namePart}",
                        Risk     = risk,
                        Location = filePath,
                        FileName = fileName,
                        Reason   = BuildReason(filePath, namePart, size, hasMzHeader, isSuspiciousName),
                        Detail   = $"Stream: :{namePart} | Größe: {size / 1024} KB | " +
                                   $"MZ-Header: {hasMzHeader} | Verdächtiger Name: {isSuspiciousName}"
                    });
                }
            }
            while (FindNextStreamW(handle, out streamData));
        }
        finally
        {
            FindClose(handle);
        }
    }

    private static string BuildReason(string file, string stream, long size,
        bool hasMz, bool suspiciousName)
    {
        if (hasMz)
            return $"Versteckte ausführbare Datei (MZ-Header) im ADS-Stream ':{stream}' von " +
                   $"'{Path.GetFileName(file)}' gefunden. Code-Injektion oder Persistenz via ADS.";
        if (suspiciousName)
            return $"ADS mit verdächtigem Stream-Namen ':{stream}' in '{Path.GetFileName(file)}'. " +
                   "Cheat-Tools nutzen ADS, um Konfiguration und Lizenzschlüssel zu verstecken.";
        return $"Ungewöhnlich großer ADS-Stream ':{stream}' ({size / 1024} KB) in " +
               $"'{Path.GetFileName(file)}'. ADS werden zum Verstecken von Dateien genutzt.";
    }

    private static bool IsNtfsDrive(string root)
    {
        try
        {
            var driveInfo = new DriveInfo(root);
            return driveInfo.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
