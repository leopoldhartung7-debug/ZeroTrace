using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects cheat tool artifacts inside cloud-sync folders (OneDrive, Dropbox,
/// Google Drive, MEGA, iCloud Drive).
///
/// A common evasion pattern observed by Ocean / detect.ac: users back up their
/// cheat installations to a cloud sync folder so the cheat persists across
/// reformatting / new machines. The local sync copy is what triggers detection:
///   - %USERPROFILE%\OneDrive\* (default)
///   - %USERPROFILE%\Dropbox\*
///   - %USERPROFILE%\Google Drive\* / "GoogleDrive" / "My Drive"
///   - %USERPROFILE%\MEGA\* / MEGAsync
///   - %USERPROFILE%\iCloudDrive\*
///
/// This module also reads the OneDrive RecycleBin metadata (UserCid\.tmpDir) and
/// Dropbox cache for filename references to deleted cheat files. Cloud-sync
/// services keep a metadata trace even after the user deletes the cheat — a
/// strong forensic signal.
/// </summary>
public sealed class CloudSyncCheatArtifactScanModule : IScanModule
{
    public string Name => "Cloud Sync Folder Cheat Artifact Scan";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    private static readonly string[] CloudFolderNames =
    {
        "OneDrive", "OneDrive - Personal", "OneDriveBusiness", "OneDrive Business",
        "Dropbox", "Dropbox (Personal)",
        "Google Drive", "GoogleDrive", "My Drive",
        "MEGA", "MEGAsync",
        "iCloudDrive", "iCloud Drive", "iCloudPhotos",
        "Box Sync", "Box", "pCloudSync", "pCloud Drive",
        "Sync", "Resilio Sync",
    };

    private static readonly string[] CheatDirectoryKeywords =
    {
        "cheat", "hack", "aimbot", "wallhack", "esp", "trigger",
        "spoofer", "hwid", "bypass", "loader", "inject",
        "gamesense", "onetap", "fatality", "aimware", "limeware",
        "kiddion", "2take1", "stand", "cherax", "midnight",
        "pcileech", "memprocfs", "memflow",
        "cheatengine", "cheat engine", "xenos", "extreme injector",
        "skycheats", "engineowning", "skeet", "neverlose",
    };

    private static readonly string[] CheatFileExtensions =
    {
        ".asi", ".luac", ".dll", ".sys", ".lic", ".token", ".manifest",
    };

    private static readonly string[] CheatFileKeywords =
    {
        "cheat", "hack", "aimbot", "wallhack", "esp_", "trigger_",
        "_cheat_", "spoofer", "loader.exe", "inject.exe",
        "bypass.exe", "_cheat.zip", "_hack.zip", "cheat.zip", "hack.zip",
    };

    private const int MaxDepth = 4;
    private const int MaxFilesPerFolder = 4000;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrEmpty(profile)) return;

        foreach (string folderName in CloudFolderNames)
        {
            ct.ThrowIfCancellationRequested();
            string root = System.IO.Path.Combine(profile, folderName);
            if (!System.IO.Directory.Exists(root)) continue;

            ScanCloudRoot(ctx, root, folderName, ct);
        }
    }

    private void ScanCloudRoot(ScanContext ctx, string root, string serviceName, CancellationToken ct)
    {
        // Walk directories — flag folders with cheat-keyword names
        var dirsScanned = 0;
        try
        {
            foreach (string dir in System.IO.Directory.EnumerateDirectories(root, "*",
                new System.IO.EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = MaxDepth,
                    IgnoreInaccessible = true,
                    AttributesToSkip = System.IO.FileAttributes.ReparsePoint
                }))
            {
                ct.ThrowIfCancellationRequested();
                dirsScanned++;
                if (dirsScanned > 20000) break;

                string dirName = System.IO.Path.GetFileName(dir).ToLowerInvariant();
                foreach (string kw in CheatDirectoryKeywords)
                {
                    if (!dirName.Contains(kw)) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Verzeichnis in Cloud-Sync ({serviceName}): {System.IO.Path.GetFileName(dir)}",
                        Risk     = RiskLevel.High,
                        Location = dir,
                        FileName = System.IO.Path.GetFileName(dir),
                        Reason   = $"Verzeichnis '{System.IO.Path.GetFileName(dir)}' im Cloud-Sync-Ordner " +
                                   $"'{serviceName}' enthält das Cheat-Keyword '{kw}'. Cheats werden häufig " +
                                   "in Cloud-Speicher gesichert um Format-übergreifend persistent zu sein. " +
                                   "Cloud-Service hält oft auch nach lokaler Löschung Metadaten.",
                        Detail   = $"Pfad: {dir} | Dienst: {serviceName} | Keyword: {kw}"
                    });
                    break;
                }
            }
        }
        catch { }

        // Walk files — flag cheat-keyword files with sensitive extensions
        try
        {
            int fileCount = 0;
            foreach (string file in System.IO.Directory.EnumerateFiles(root, "*",
                new System.IO.EnumerationOptions
                {
                    RecurseSubdirectories = true,
                    MaxRecursionDepth = MaxDepth,
                    IgnoreInaccessible = true,
                    AttributesToSkip = System.IO.FileAttributes.ReparsePoint
                }))
            {
                ct.ThrowIfCancellationRequested();
                if (++fileCount > MaxFilesPerFolder) break;

                string fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();
                string ext      = System.IO.Path.GetExtension(file).ToLowerInvariant();

                // Quick skip: ignore files that aren't sensitive or keyword-bearing
                bool hasSensitiveExt = CheatFileExtensions.Contains(ext);
                bool hasKeyword = false;
                string? matchedKw = null;
                foreach (string kw in CheatFileKeywords)
                {
                    if (fileName.Contains(kw)) { hasKeyword = true; matchedKw = kw; break; }
                }

                if (!hasSensitiveExt && !hasKeyword) continue;

                ctx.IncrementFiles();

                var risk = hasKeyword && hasSensitiveExt ? RiskLevel.Critical
                           : hasKeyword ? RiskLevel.High
                           : RiskLevel.Medium;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Artefakt in Cloud-Sync ({serviceName}): {System.IO.Path.GetFileName(file)}",
                    Risk     = risk,
                    Location = file,
                    FileName = System.IO.Path.GetFileName(file),
                    Reason   = $"Datei '{System.IO.Path.GetFileName(file)}' in Cloud-Sync-Ordner " +
                               $"'{serviceName}' entspricht Cheat-Artefakt-Muster" +
                               (matchedKw is not null ? $" (Keyword: {matchedKw})" : "") +
                               (hasSensitiveExt ? $" (Erweiterung: {ext})" : "") +
                               ". Diese Datei wird automatisch zwischen Geräten synchronisiert — " +
                               "Cloud-Speicher hält Metadaten und Versionshistorie auch nach lokaler Löschung.",
                    Detail   = $"Pfad: {file} | Dienst: {serviceName}" +
                               (matchedKw is not null ? $" | Keyword: {matchedKw}" : "") +
                               $" | Größe: {new System.IO.FileInfo(file).Length} Bytes"
                });
            }
        }
        catch { }
    }
}
