using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Forensic scan of the Windows Recycle Bin ($Recycle.Bin) for cheat-tool deletion
/// artifacts via $I metadata files.
///
/// Each deleted file generates a paired entry:
///   $I&lt;random&gt;.&lt;ext&gt; — metadata: original path, size, deletion timestamp
///   $R&lt;random&gt;.&lt;ext&gt; — actual file content
///
/// The $I files persist their original path even after the user empties the Recycle
/// Bin (until the $I file itself is overwritten on disk). Ocean and detect.ac
/// extract original paths from $I files to catch cheats that were deleted before
/// scanning began.
///
/// $I file format (Windows 10+):
///   Header (8 bytes): 0x02 0x00 0x00 0x00 0x00 0x00 0x00 0x00
///   FileSize (8 bytes): original file size
///   DeletedTime (8 bytes): FILETIME of deletion
///   NameLength (4 bytes): length of name in chars (incl. null)
///   Name (NameLength * 2 bytes): UTF-16 LE original path + null terminator
/// </summary>
public sealed class RecycleBinForensicScanModule : IScanModule
{
    public string Name => "Recycle Bin $I Forensic Cheat-Deletion Scan";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    private static readonly string[] CheatPathKeywords =
    {
        // Universal
        "cheat", "hack", "aimbot", "wallhack", "esp",
        "triggerbot", "norecoil", "spoofer", "bypass",
        "loader.exe", "inject", "injector",
        // CS / Source
        "gamesense", "onetap", "fatality", "aimware", "limeware", "ev0lve",
        "neverlose", "skeet", "primordial", "weave.gg", "intellect",
        // GTA V menus
        "kiddion", "2take1", "stand", "cherax", "midnight", "ozark",
        "menyoo", "scripthookv",
        // EFT / Apex / CoD / Valorant
        "skycheats", "magicbullet", "tarkov",
        "engineowning", "iniuria", "vapeflux",
        "apexlegit", "spectre.gg",
        "tronix", "lethal.gg",
        // Hardware/DMA
        "pcileech", "memprocfs", "memflow",
        // Loaders/injectors
        "xenos", "extreme injector", "cheatengine",
        "x64dbg", "ollydbg",
        // BYOVD drivers
        "mhyprot2", "rtcore64", "winring0", "iqvw64", "gdrv.sys",
        // Common cheat archive patterns
        "_cheat.zip", "_hack.zip", "cheat.rar", "hack.rar",
        ".asi", ".luac",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        foreach (System.IO.DriveInfo drive in System.IO.DriveInfo.GetDrives())
        {
            ct.ThrowIfCancellationRequested();
            if (drive.DriveType != System.IO.DriveType.Fixed) continue;
            if (!drive.IsReady) continue;

            string binRoot = System.IO.Path.Combine(drive.RootDirectory.FullName, "$Recycle.Bin");
            if (!System.IO.Directory.Exists(binRoot)) continue;

            try
            {
                foreach (string sidDir in System.IO.Directory.GetDirectories(binRoot))
                {
                    ct.ThrowIfCancellationRequested();
                    ScanSidDir(ctx, sidDir, ct);
                }
            }
            catch { }
        }
    }

    private void ScanSidDir(ScanContext ctx, string sidDir, CancellationToken ct)
    {
        string[] iFiles;
        try
        {
            iFiles = System.IO.Directory.GetFiles(sidDir, "$I*",
                System.IO.SearchOption.TopDirectoryOnly);
        }
        catch { return; }

        foreach (string iFile in iFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            try
            {
                byte[] data = System.IO.File.ReadAllBytes(iFile);
                if (data.Length < 28) continue;

                // Windows 10+ format: 8 header + 8 size + 8 deleted time + 4 name length
                int nameLenIdx = 24;
                int nameLen = BitConverter.ToInt32(data, nameLenIdx);
                int nameStart = nameLenIdx + 4;

                if (nameLen <= 0 || nameLen > 2000) continue;
                int nameBytes = nameLen * 2;
                if (nameStart + nameBytes > data.Length) continue;

                string origPath = Encoding.Unicode.GetString(data, nameStart, nameBytes)
                                          .TrimEnd('\0');
                if (string.IsNullOrEmpty(origPath)) continue;

                string origLower = origPath.ToLowerInvariant();

                string? hitKw = null;
                foreach (string kw in CheatPathKeywords)
                {
                    if (origLower.Contains(kw)) { hitKw = kw; break; }
                }
                if (hitKw is null) continue;

                long origSize = BitConverter.ToInt64(data, 8);
                long deletedFt = BitConverter.ToInt64(data, 16);
                DateTime? deletedUtc = null;
                try { deletedUtc = DateTime.FromFileTimeUtc(deletedFt); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Gelöschte Cheat-Datei (Recycle Bin $I): {System.IO.Path.GetFileName(origPath)}",
                    Risk     = RiskLevel.High,
                    Location = origPath,
                    FileName = System.IO.Path.GetFileName(origPath),
                    Reason   = $"Recycle-Bin-Metadaten-Datei '{System.IO.Path.GetFileName(iFile)}' " +
                               $"verweist auf gelöschte Datei '{origPath}', die das Cheat-Keyword " +
                               $"'{hitKw}' enthält. $I-Dateien speichern den Original-Pfad — auch nach " +
                               "Leeren des Papierkorbs (bis der $I-Eintrag selbst überschrieben wird). " +
                               "Eine forensische Standardquelle bei Ocean und detect.ac.",
                    Detail   = $"Original-Pfad: {origPath} | " +
                               $"Original-Größe: {origSize} Bytes | " +
                               (deletedUtc.HasValue ? $"Gelöscht am: {deletedUtc.Value:yyyy-MM-dd HH:mm:ss}Z | " : "") +
                               $"Keyword: {hitKw} | " +
                               $"$I-Datei: {iFile}"
                });
            }
            catch { }
        }
    }
}
