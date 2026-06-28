using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Windows Clipboard History for cheat-related artifacts.
///
/// Windows 10/11 Clipboard History (Win+V) stores up to 25 recent clipboard entries
/// in an SQLite database at:
///   %LOCALAPPDATA%\Microsoft\Windows\Clipboard\
///
/// Cheat users often copy:
///   - Cheat license keys (to paste into cheat loaders)
///   - Cheat download URLs (from Discord/Telegram to browser)
///   - Cheat config strings (serialized configs pasted into cheat menus)
///   - Injection commands (from cheat tutorials)
///   - HWID spoofer registration codes
///
/// Ocean and detect.ac mine Clipboard History because:
///   - License keys for known cheat platforms are distinctive patterns
///   - Cheat download URLs in clipboard = direct evidence of download initiation
///   - Clipboard history survives reboots (unlike RAM) until manually cleared
///
/// The Clipboard database is at:
///   %LOCALAPPDATA%\Microsoft\Windows\Clipboard\
///   Files: ActivitiesCache.db (SQLite) or individual bin files
/// </summary>
public sealed class ClipboardCheatArtifactScanModule : IScanModule
{
    public string Name => "Windows Clipboard-Verlauf Cheat-Artefakt Scan";
    public double Weight => 0.4;
    public int ParallelGroup => 4;

    private static readonly string[] CheatClipboardKeywords =
    {
        // License key patterns for known cheat platforms
        "gamesense", "onetap", "fatality", "aimware",
        "neverlose", "skeet.cc", "limeware",
        "2take1", "kiddion", "cherax", "ozark", "stand.sh",
        "engineowning", "vapeflux",
        "pcileech", "memprocfs",
        "elitepvpers", "unknowncheats",
        // Generic cheat terms
        "cheat", "hack", "aimbot", "wallhack", "esp",
        "injector", "loader", "bypass",
        "hwid", "spoofer",
        "triggerbot", "spinbot", "bhop",
        "rage", "legit", "semi-rage",
        "undetected", "ud cheat",
        // Download URLs
        "invite.discord.gg", "t.me/",    // Discord/Telegram invite links
        "mega.nz", "gofile.io",          // Anonymous file sharing used for cheats
        "anonfiles",
        // Injection commands
        "rundll32", "regsvr32",
        "loadlibrary", "createremotethread",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string clipboardDir = System.IO.Path.Combine(
            local, "Microsoft", "Windows", "Clipboard");

        if (!System.IO.Directory.Exists(clipboardDir)) return;

        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(
                         clipboardDir, "*", System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var info = new System.IO.FileInfo(file);
                if (info.Length == 0 || info.Length > 10 * 1024 * 1024) continue;

                string ext = System.IO.Path.GetExtension(file).ToLowerInvariant();
                // Clipboard stores data as binary blobs and sometimes SQLite
                // Byte-grep for keywords as UTF-16 LE (Windows clipboard format)
                ctx.IncrementFiles();
                ScanClipboardFile(ctx, file, ct);
            }
        }
        catch { }
    }

    private void ScanClipboardFile(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            byte[] raw = System.IO.File.ReadAllBytes(path);
            string utf8 = System.Text.Encoding.UTF8.GetString(raw).ToLowerInvariant();
            string utf16 = System.Text.Encoding.Unicode.GetString(raw).ToLowerInvariant();
            string combined = utf8 + " " + utf16;
            string fileName = System.IO.Path.GetFileName(path);

            foreach (string kw in CheatClipboardKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!combined.Contains(kw.ToLowerInvariant())) continue;

                int idx = combined.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                int start = Math.Max(0, idx - 30);
                int end = Math.Min(combined.Length, idx + kw.Length + 60);
                string snippet = combined.Substring(start, end - start)
                                         .Replace('\0', ' ')
                                         .Replace('\n', ' ')
                                         .Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Artefakt im Clipboard-Verlauf: '{kw}'",
                    Risk     = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason   = $"Windows Clipboard-Verlauf-Datei '{fileName}' enthält Cheat-Schlüsselwort " +
                               $"'{kw}'. Clipboard-Einträge belegen das Kopieren von Cheat-Lizenzen, " +
                               "-Download-URLs oder Injection-Befehlen. Der Clipboard-Verlauf persistiert " +
                               "über Reboots bis zur manuellen Löschung.",
                    Detail   = $"Datei: {path} | Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                });
                return;
            }
        }
        catch { }
    }
}
