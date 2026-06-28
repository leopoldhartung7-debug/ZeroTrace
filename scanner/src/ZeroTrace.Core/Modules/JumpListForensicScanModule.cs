using System.Text;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Forensic scan of Windows Jump Lists (.automaticDestinations-ms and
/// .customDestinations-ms files) for references to cheat tools, cheat directories,
/// and cheat-keyword filenames.
///
/// Jump Lists are stored in:
///   %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms
///   %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms
///
/// The files are OLE Compound Files containing embedded LNK shortcuts to recently
/// opened/pinned items. They persist independently of UserAssist, RecentDocs and
/// the Recent folder — and survive deletion of the original file. This is a
/// signature forensic source used by Ocean / detect.ac because:
///   - Cheat archive opens leave a Jump List entry in 7-Zip/WinRAR/Explorer
///   - Cheat folder access via Explorer is logged here even after deletion
///   - Recently-launched cheat executables appear in the application's Jump List
///
/// This module greps the raw file bytes for UTF-16 LE encoded paths matching
/// cheat-tool keywords — fast, no compound-file parsing required.
/// </summary>
public sealed class JumpListForensicScanModule : IScanModule
{
    public string Name => "Jump List Forensic Cheat Reference Scan";
    public double Weight => 0.55;
    public int ParallelGroup => 4;

    // Cheat tool, folder, and filename keywords (case-insensitive)
    private static readonly string[] CheatKeywords =
    {
        // Universal cheat / suite names
        "cheat", "hack", "aimbot", "wallhack", "esp", "triggerbot",
        "norecoil", "rage_hack",
        // CS / Source cheat suites
        "gamesense", "onetap", "fatality", "aimware", "limeware", "ev0lve",
        "cyber.fun", "memesense", "nullshit", "skeet", "primordial",
        "neverlose", "intellect", "weave.gg",
        // GTA V menus
        "kiddion", "2take1", "stand", "cherax", "midnight", "ozark",
        "rampage", "menyoo", "scripthookv",
        // EFT cheats
        "skycheats", "skytap", "tarkov_aimbot", "magicbullet",
        // CoD / Warzone
        "engineowning", "iniuria", "vapeflux", "interwebz",
        // Apex
        "apexlegit", "spectre.gg",
        // Valorant
        "tronix", "absolute_software", "lethal.gg",
        // Universal injectors / loaders
        "xenos", "extreme injector", "process hacker", "cheatengine",
        "cheat engine", "ollydbg", "x32dbg", "x64dbg", "ida pro",
        "binaryninja", "ghidra",
        // DMA hardware / tools
        "pcileech", "memprocfs", "memflow", "dma_radar", "dma_esp",
        // HWID spoofers
        "spoofer", "hwid_changer", "hwspoofer", "permspoofer", "tempspoofer",
        // Common cheat installer / archive patterns
        "loader.exe", "inject.exe", "bypass.exe", "_cheat.zip", "_hack.zip",
        ".lic", ".license", "license_key",
        // Known BYOVD driver filenames
        "mhyprot2.sys", "rtcore64.sys", "winring0", "gdrv.sys", "asio2.sys",
        "asio3.sys", "iqvw64", "cpuz.sys",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrEmpty(appData)) return;

        string autoDir = System.IO.Path.Combine(appData,
            "Microsoft", "Windows", "Recent", "AutomaticDestinations");
        string custDir = System.IO.Path.Combine(appData,
            "Microsoft", "Windows", "Recent", "CustomDestinations");

        ScanDirectory(ctx, autoDir, "AutomaticDestinations", ct);
        ScanDirectory(ctx, custDir, "CustomDestinations", ct);
    }

    private void ScanDirectory(ScanContext ctx, string dir, string kind, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(dir)) return;

        string[] files;
        try { files = System.IO.Directory.GetFiles(dir); }
        catch { return; }

        foreach (string file in files)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var info = new System.IO.FileInfo(file);
                if (info.Length == 0 || info.Length > 32 * 1024 * 1024) continue;
                ctx.IncrementFiles();

                byte[] data = System.IO.File.ReadAllBytes(file);

                // Convert to UTF-16 LE string (Jump Lists store paths as wchar_t)
                // Strip nulls between bytes to also catch ASCII fragments.
                string utf16 = Encoding.Unicode.GetString(data);
                string utf16Lower = utf16.ToLowerInvariant();

                var hits = new List<string>();
                foreach (string kw in CheatKeywords)
                {
                    if (utf16Lower.Contains(kw))
                    {
                        hits.Add(kw);
                        if (hits.Count >= 5) break;
                    }
                }

                if (hits.Count == 0) continue;

                // Extract neighboring path-like context for the first hit
                string context = ExtractPathContext(utf16, hits[0]) ?? hits[0];

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Referenz in Jump-List-Datei: {System.IO.Path.GetFileName(file)}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = System.IO.Path.GetFileName(file),
                    Reason   = $"Jump-List-Datei ({kind}) enthält {hits.Count} Cheat-Keyword(s): " +
                               $"{string.Join(", ", hits)}. Jump Lists persistieren über die " +
                               "Löschung der Original-Datei hinaus und sind eine forensische " +
                               "Goldgrube für vergangene Cheat-Tool-Nutzung — Ocean und detect.ac " +
                               "verwenden diese Quelle als Standardprüfung.",
                    Detail   = $"Datei: {file} | " +
                               $"Typ: {kind} | " +
                               $"Treffer: {string.Join(", ", hits)} | " +
                               $"Kontext: {context}"
                });
            }
            catch { }
        }
    }

    private static string? ExtractPathContext(string text, string keyword)
    {
        int idx = text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        int start = Math.Max(0, idx - 60);
        int end   = Math.Min(text.Length, idx + keyword.Length + 60);

        var sb = new StringBuilder();
        for (int i = start; i < end; i++)
        {
            char c = text[i];
            if (c >= 0x20 && c < 0x7F) sb.Append(c);
            else if (c == '\\' || c == '/' || c == ':') sb.Append(c);
            else sb.Append(' ');
        }
        return sb.ToString().Trim();
    }
}
