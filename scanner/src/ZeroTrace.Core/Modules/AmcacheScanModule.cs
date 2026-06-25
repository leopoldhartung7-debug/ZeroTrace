using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans the Amcache hive for previously executed cheat tool binaries.
///
/// Amcache.hve (located at C:\Windows\AppCompat\Programs\Amcache.hve) is a
/// Windows Application Compatibility database that records every program that
/// has been run on the system, including:
///   - Full path of the executable
///   - SHA-1 hash of the file (computed at first run)
///   - File timestamp and PE metadata (publisher, version, description)
///   - First run time and last modified time
///
/// The registry is accessible via:
///   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache
///
/// Forensic value:
///   - Records survive file deletion (tombstone entry persists)
///   - SHA-1 hash allows cross-referencing with cheat blocklists
///   - Publisher field "unsigned" + temp path = high confidence cheat
///   - First-run timestamp correlated with game sessions
///
/// Amcache has two formats:
///   Legacy (Win 8.0): InventoryApplicationFile\{GUID}
///   Modern (Win 10+): Root\File\Volume\{SHA-1}
/// </summary>
public sealed class AmcacheScanModule : IScanModule
{
    public string Name => "Amcache-Ausführungshistorie";
    public double Weight => 0.7;
    public int ParallelGroup => 1;

    // Legacy Amcache path (Windows 8/8.1)
    private const string LegacyAmcachePath =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache\InventoryApplicationFile";

    // Modern Amcache is in the Amcache.hve hive file, not directly in HKLM.
    // We access it via the mapped path if available.
    private static readonly string AmcacheHivePath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"AppCompat\Programs\Amcache.hve");

    private static readonly string[] CheatKeywords =
    {
        // GTA V mods / trainers
        "kiddion", "cherax", "2take1", "ozark", "midnight", "stand",
        "menyoo", "simple trainer", "modmenu", "native trainer",
        // FPS cheats
        "aimware", "skeet", "fatality", "neverlose", "onetap",
        "interium", "nixware", "gamesense", "lhook", "cheatshell",
        // Injectors / loaders
        "xenos", "manualmap", "extremeinjector", "dllinjector",
        "reclass", "cheatengine", "cheat engine", "processhacker",
        // HWID / anti-cheat bypass
        "spoofer", "hwidspoofer", "hwid changer", "acbypass",
        "eacbypass", "bebypass", "vanguardbypass",
        // DMA / kernel tools
        "memprocfs", "pcileech", "arsenal", "dmafw",
        // Generic
        "aimbot", "wallhack", "esp", "triggerbot", "bhop",
        "inject", "bypass", "loader", "hack", "cheat",
        "exploit", "trainer",
    };

    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\users\public\", @"\desktop\",
        @"\appdata\local\temp\",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        int hits = 0;

        // Try legacy HKLM path first (works on some configurations)
        try
        {
            using var legacyKey = Registry.LocalMachine.OpenSubKey(LegacyAmcachePath, writable: false);
            if (legacyKey is not null)
            {
                foreach (var subName in legacyKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementRegistryKeys();
                    checked_++;

                    using var entry = legacyKey.OpenSubKey(subName, writable: false);
                    if (entry is null) continue;

                    var filePath = entry.GetValue("LowerCaseLongPath") as string
                                ?? entry.GetValue("FullPath") as string ?? "";
                    var publisher = entry.GetValue("Publisher") as string ?? "";
                    var description = entry.GetValue("FileDescription") as string ?? "";
                    var combined = $"{filePath} {publisher} {description}".ToLowerInvariant();

                    if (CheckAmcacheEntry(filePath, combined, publisher, ctx))
                        hits++;
                }
            }
        }
        catch { }

        // Try loading Amcache.hve directly via Registry.Load (requires elevation)
        // On most systems without elevation this silently fails — that's expected
        try
        {
            if (File.Exists(AmcacheHivePath) && hits == 0 && checked_ == 0)
            {
                // Read raw hive as binary and do pattern search for cheat strings
                // (lightweight fallback when we can't load the hive as a registry key)
                var hiveContent = ReadHiveBinaryStrings(AmcacheHivePath, ct);
                foreach (var entry in hiveContent)
                {
                    if (ct.IsCancellationRequested) break;
                    checked_++;

                    var lower = entry.ToLowerInvariant();
                    var keyword = CheatKeywords.FirstOrDefault(k =>
                        lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (keyword is not null && entry.Contains('\\'))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Amcache: Cheat-Tool ausgeführt: {Path.GetFileName(entry)}",
                            Risk     = RiskLevel.High,
                            Location = AmcacheHivePath,
                            FileName = Path.GetFileName(entry),
                            Reason   = $"Amcache-Hive-Analyse zeigt, dass ein Cheat-Tool ausgeführt wurde. " +
                                       $"Pfad: '{entry}' | Keyword: '{keyword}'. " +
                                       "Amcache speichert auch gelöschte Binärdateien mit SHA-1-Hash.",
                            Detail   = $"Pfad: {entry} | Keyword: {keyword} | Hive: {AmcacheHivePath}"
                        });
                    }
                }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"{checked_} Amcache-Einträge geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static bool CheckAmcacheEntry(string filePath, string combined,
        string publisher, ScanContext ctx)
    {
        var keyword = CheatKeywords.FirstOrDefault(k =>
            combined.Contains(k, StringComparison.OrdinalIgnoreCase));

        if (keyword is not null)
        {
            var fn = Path.GetFileName(filePath);
            bool fileExists = File.Exists(filePath);
            ctx.AddFinding(new Finding
            {
                Module   = "Amcache-Ausführungshistorie",
                Title    = $"Amcache: Cheat-Tool: {fn}",
                Risk     = RiskLevel.High,
                Location = $@"HKLM\{LegacyAmcachePath}",
                FileName = fn,
                Reason   = $"Amcache-Eintrag zeigt Ausführung von '{fn}' (Keyword: '{keyword}'). " +
                           (fileExists ? "Datei noch vorhanden." : "Datei gelöscht, Ausführung nachgewiesen.") +
                           " Amcache enthält SHA-1-Hash und Ausführungszeitpunkt.",
                Detail   = $"Pfad: {filePath} | Publisher: {publisher} | Keyword: {keyword} | Existiert: {fileExists}"
            });
            return true;
        }

        // Suspicious path check for unsigned executables
        var pathLower = filePath.ToLowerInvariant();
        bool suspPath = SuspiciousPaths.Any(p => pathLower.Contains(p));
        if (suspPath && string.IsNullOrEmpty(publisher) && !string.IsNullOrEmpty(filePath))
        {
            var fn = Path.GetFileName(filePath);
            ctx.AddFinding(new Finding
            {
                Module   = "Amcache-Ausführungshistorie",
                Title    = $"Amcache: Unsigned Exe aus Temp: {fn}",
                Risk     = RiskLevel.Medium,
                Location = $@"HKLM\{LegacyAmcachePath}",
                FileName = fn,
                Reason   = $"Ausführung einer unsignierten Datei aus verdächtigem Pfad: '{filePath}'. " +
                           "Cheats werden häufig ohne Publisher-Signatur aus Temp-Ordnern gestartet.",
                Detail   = $"Pfad: {filePath} | Publisher: (leer)"
            });
            return true;
        }

        return false;
    }

    private static List<string> ReadHiveBinaryStrings(string path, CancellationToken ct)
    {
        var results = new List<string>();
        try
        {
            // Read hive in chunks and extract printable Unicode strings ≥ 12 chars
            // that look like file paths (contain backslash and .exe)
            const int CHUNK = 1024 * 1024; // 1 MB at a time
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            var buf = new byte[CHUNK + 512];
            int bytesRead;
            var carry = "";

            while ((bytesRead = fs.Read(buf, 0, CHUNK)) > 0)
            {
                if (ct.IsCancellationRequested) break;

                // Decode as Unicode (UTF-16 LE) — hive stores strings as UTF-16
                var text = carry + System.Text.Encoding.Unicode.GetString(buf, 0, bytesRead);
                carry = text.Length > 512 ? text[^512..] : "";

                // Extract path-like strings
                var parts = text.Split('\0', StringSplitOptions.RemoveEmptyEntries);
                foreach (var part in parts)
                {
                    var trimmed = part.Trim();
                    if (trimmed.Length >= 12 && trimmed.Contains('\\') &&
                        trimmed.Contains('.') && trimmed.All(c => c >= 0x20 && c < 0x7f || c > 0x7f))
                    {
                        results.Add(trimmed);
                    }
                }
            }
        }
        catch { }
        return results;
    }
}
