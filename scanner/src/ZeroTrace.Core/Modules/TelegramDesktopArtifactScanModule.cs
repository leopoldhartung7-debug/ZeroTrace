using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Telegram Desktop's local cache for cheat-community artifacts.
///
/// Telegram has overtaken Discord for certain cheat sub-markets because:
///   - Cheat vendors use Telegram for more anonymous key distribution
///   - Private cheat groups operate "secret chats" on Telegram
///   - DMA hardware vendors use Telegram channels to distribute firmware updates
///   - Some cheat loaders authenticate via Telegram bot API
///
/// Ocean and detect.ac mine Telegram desktop data because cached message data,
/// document names, and contact lists persist even after messages are "deleted"
/// from the Telegram UI (the cached data remains on disk until the cache is cleared).
///
/// Files scanned:
///   %APPDATA%\Telegram Desktop\tdata\                — session/config data (binary)
///   %APPDATA%\Telegram Desktop\tdata\D877F783D5D3EF8C\ — account-specific cache
///   Document/image file names cached by Telegram
/// </summary>
public sealed class TelegramDesktopArtifactScanModule : IScanModule
{
    public string Name => "Telegram Desktop Cheat-Artefakt Scan";
    public double Weight => 0.45;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywords =
    {
        "aimbot", "wallhack", "esp", "cheat", "hack",
        "gamesense", "onetap", "fatality", "aimware",
        "neverlose", "skeet", "2take1", "kiddion",
        "stand.sh", "cherax", "ozark", "midnight",
        "pcileech", "dma", "memprocfs",
        "spoofer", "hwid", "bypass",
        "triggerbot", "spinbot", "bhop",
        "rage hack", "legit hack",
        "undetected", "ud cheat",
        "cheat loader", "cheat injector",
        "no recoil", "norecoil",
        "cheat key", "license key",
        "cheat sub", "cheat invite",
        "engineowning", "unknowncheats",
        "paid cheat", "private cheat",
    };

    private static readonly string[] CachedDocExtensions =
    {
        ".exe", ".dll", ".zip", ".rar", ".7z",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var telegramRoots = new[]
        {
            System.IO.Path.Combine(roaming, "Telegram Desktop"),
            System.IO.Path.Combine(roaming, "Telegram Desktop Beta"),
        };

        foreach (string root in telegramRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(root)) continue;

            string tdataDir = System.IO.Path.Combine(root, "tdata");
            if (System.IO.Directory.Exists(tdataDir))
                ScanTdata(ctx, tdataDir, ct);

            // Emoji and sticker cache (rarely useful but documents dir contains received files)
            string tdocDir = System.IO.Path.Combine(root, "tdata", "tdocs");
            // Also check user download directory that Telegram uses
            ScanDownloads(ctx, root, ct);
        }

        // Telegram also caches received files in user's Downloads
        string downloads = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        ScanDownloadForTelegramFiles(ctx, downloads, ct);
    }

    private void ScanTdata(ScanContext ctx, string tdataDir, CancellationToken ct)
    {
        try
        {
            int fileCount = 0;
            foreach (string file in System.IO.Directory.EnumerateFiles(
                         tdataDir, "*", System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                if (++fileCount > 2000) break;

                var info = new System.IO.FileInfo(file);
                // tdata files are binary — only scan readable ones under 4MB
                if (info.Length == 0 || info.Length > 4 * 1024 * 1024) continue;

                string ext = System.IO.Path.GetExtension(file).ToLowerInvariant();
                // tdata files typically have no extension or short numeric names
                if (ext.Length > 4) continue;

                ctx.IncrementFiles();
                ScanBinaryFileForKeywords(ctx, file, "Telegram tdata", ct);
            }
        }
        catch { }
    }

    private void ScanDownloads(ScanContext ctx, string telegramRoot, CancellationToken ct)
    {
        // Telegram Desktop stores received files in a subfolder
        string downloads = System.IO.Path.Combine(telegramRoot, "downloads");
        if (!System.IO.Directory.Exists(downloads)) return;

        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(
                         downloads, "*", System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                string fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();
                string ext = System.IO.Path.GetExtension(file).ToLowerInvariant();

                ctx.IncrementFiles();

                // Check file name for cheat keywords
                foreach (string kw in CheatKeywords)
                {
                    if (!fileName.Contains(kw)) continue;
                    var info = new System.IO.FileInfo(file);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Datei via Telegram empfangen: '{kw}' in {System.IO.Path.GetFileName(file)}",
                        Risk     = CachedDocExtensions.Contains(ext) ? RiskLevel.Critical : RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"Via Telegram empfangene Datei '{System.IO.Path.GetFileName(file)}' " +
                                   $"enthält Cheat-Schlüsselwort '{kw}' im Dateinamen. " +
                                   "Cheat-Vendor verteilen Loader, Injector und Keys häufig " +
                                   "über Telegram. Ocean und detect.ac scannen Telegram-Downloads.",
                        Detail   = $"Datei: {file} | Schlüsselwort: '{kw}' | " +
                                   $"Größe: {info.Length / 1024}KB"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private void ScanDownloadForTelegramFiles(ScanContext ctx, string downloadsDir, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(downloadsDir)) return;
        try
        {
            // Look for files recently received via Telegram (name pattern: often includes telegram)
            foreach (string file in System.IO.Directory.EnumerateFiles(downloadsDir))
            {
                ct.ThrowIfCancellationRequested();
                string fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();
                if (!fileName.Contains("telegram") && !fileName.StartsWith("tg")) continue;

                string ext = System.IO.Path.GetExtension(fileName);
                if (!CachedDocExtensions.Contains(ext)) continue;

                ctx.IncrementFiles();
                foreach (string kw in CheatKeywords)
                {
                    if (!fileName.Contains(kw)) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtige Telegram-Datei im Downloads-Ordner: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"Datei '{System.IO.Path.GetFileName(file)}' im Downloads-Ordner deutet " +
                                   "auf eine über Telegram empfangene ausführbare Datei mit Cheat-Bezug hin.",
                        Detail   = $"Datei: {file} | Schlüsselwort: '{kw}'"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private void ScanBinaryFileForKeywords(ScanContext ctx, string path,
        string label, CancellationToken ct)
    {
        try
        {
            byte[] raw = System.IO.File.ReadAllBytes(path);
            string text = System.Text.Encoding.UTF8.GetString(raw).ToLowerInvariant();
            string fileName = System.IO.Path.GetFileName(path);

            foreach (string kw in CheatKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!text.Contains(kw)) continue;

                int idx = text.IndexOf(kw, StringComparison.Ordinal);
                int start = Math.Max(0, idx - 30);
                int end = Math.Min(text.Length, idx + kw.Length + 60);
                string snippet = text.Substring(start, end - start)
                                     .Replace('\0', ' ')
                                     .Replace('\n', ' ')
                                     .Trim();

                // Filter trivially short or garbage snippets
                if (snippet.Length < 3) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Schlüsselwort in {label}: '{kw}'",
                    Risk     = RiskLevel.Medium,
                    Location = path,
                    FileName = fileName,
                    Reason   = $"Telegram-Datendatei '{fileName}' enthält Cheat-Schlüsselwort '{kw}'. " +
                               "Telegram-Sitzungsdaten können Nachrichteninhalte, Kontaktnamen und " +
                               "Gruppenbezeichnungen im Klartext enthalten, die Cheat-Communitys " +
                               "und Cheat-Verkäufer-Kommunikation widerspiegeln.",
                    Detail   = $"Quelle: {label} | Datei: {fileName} | " +
                               $"Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                });
                return; // one finding per file
            }
        }
        catch { }
    }
}
