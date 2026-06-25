using ZeroTrace.Core.Models;
using Microsoft.Win32;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Forensic scan of Windows registry search and navigation history entries for cheat indicators.
///
/// Windows persists a rich forensic trail of user activity in several registry locations
/// that survive "Clear browsing history" and cheat uninstallation:
///
///   TypedURLs (IE/Edge address bar):
///     HKCU\Software\Microsoft\Internet Explorer\TypedURLs
///     User-typed URLs — cheat site domains appear here even if browser history is cleared
///
///   WordWheelQuery (Windows Explorer search):
///     HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
///     Stores file/folder search terms — "aimbot", "cheat", "inject" typed in Explorer
///
///   RunMRU (Start > Run dialog history):
///     HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
///     Commands executed via Win+R — "cmd /c cheat.exe", "regedit", etc.
///
///   OpenSavePidlMRU / OpenSaveMRU (File Open/Save dialogs):
///     HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
///     HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
///     File paths accessed via Open/Save dialogs — cheat config files, DLLs loaded via dialog
///
///   RecentApps:
///     HKCU\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps
///     App launch history from Windows Search
///
/// Ocean and detect.ac parse these forensic registry keys as they persist across:
///   - Cheat uninstallation
///   - Clearing browser history
///   - Deleting the cheat files
/// </summary>
public sealed class WindowsSearchHistoryForensicScanModule : IScanModule
{
    public string Name => "Windows Such- und Navigations-History Forensik Scan";
    public double Weight => 0.45;
    public int ParallelGroup => 3;

    private static readonly string[] CheatKeywords =
    {
        "aimbot", "wallhack", "esp", "triggerbot", "bhop", "spinbot",
        "no_recoil", "norecoil", "cheat", "hack", "inject", "injector",
        "loader", "bypass", "mhyprot", "pcileech", "memprocfs",
        "gamesense", "onetap", "fatality", "aimware", "neverlose", "skeet",
        "2take1", "kiddion", "cherax", "ozark", "stand.sh",
        "engineowning", "iniuria", "vapeflux",
        "rawaccel", "interception", "rzedge",
        "sv_cheats", "r_drawothermodels", "mat_wireframe",
    };

    private static readonly string[] CheatDomains =
    {
        "unknowncheats", "mpgh.net", "elitepvpers",
        "gamesense.pub", "onetap.com", "fatality.win", "aimware.net",
        "neverlose.cc", "skeet.cc", "limeware.net", "ev0lve.xyz",
        "2take1.menu", "kiddions.cc", "cherax.cc", "ozark.gg",
        "engineowning.to", "iniuria.us", "vapeflux.net",
        "pcileech.com", "alterware.dev",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanTypedUrls(ctx, ct);
        ScanWordWheelQuery(ctx, ct);
        ScanRunMru(ctx, ct);
        ScanOpenSaveMru(ctx, ct);
        ScanRecentApps(ctx, ct);
    }

    private void ScanTypedUrls(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Internet Explorer\TypedURLs", false);
            if (key == null) return;

            foreach (string valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                string url = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                if (string.IsNullOrEmpty(url)) continue;

                string? matchedDomain = CheatDomains.FirstOrDefault(d =>
                    url.Contains(d, StringComparison.OrdinalIgnoreCase));
                string? matchedKw = matchedDomain == null
                    ? CheatKeywords.FirstOrDefault(kw =>
                        url.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    : null;

                if (matchedDomain == null && matchedKw == null) continue;

                string match = matchedDomain ?? matchedKw!;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-URL in TypedURLs History: '{match}'",
                    Risk     = RiskLevel.High,
                    Location = $@"HKCU\Software\Microsoft\Internet Explorer\TypedURLs\{valueName}",
                    FileName = "TypedURLs",
                    Reason   = $"Adressleisten-History enthält '{url}' — ein Cheat-Indikator. " +
                               "TypedURLs persistieren nach 'Browser-History löschen' und sind " +
                               "ein primärer forensischer Beweis für Cheat-Website-Besuche. " +
                               "Ocean/detect.ac prüfen TypedURLs als forensische Signalquelle.",
                    Detail   = $"Registry: {valueName} = {url} | Match: '{match}'"
                });
            }
        }
        catch { }
    }

    private void ScanWordWheelQuery(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery", false);
            if (key == null) return;

            foreach (string valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                // WordWheelQuery stores values as REG_BINARY (UTF-16 LE)
                object? raw = key.GetValue(valueName);
                string term;
                if (raw is byte[] bytes)
                    term = System.Text.Encoding.Unicode.GetString(bytes).TrimEnd('\0').ToLowerInvariant();
                else
                    term = (raw as string ?? "").ToLowerInvariant();

                if (string.IsNullOrEmpty(term)) continue;

                string? match = CheatKeywords.FirstOrDefault(kw =>
                    term.Contains(kw, StringComparison.OrdinalIgnoreCase));
                if (match == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Suchbegriff in Explorer WordWheelQuery: '{term}'",
                    Risk     = RiskLevel.High,
                    Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
                    FileName = "WordWheelQuery",
                    Reason   = $"Windows Explorer Suche enthält den Begriff '{term}' — Cheat-Keyword '{match}'. " +
                               "WordWheelQuery speichert alle Dateisystem-Suchbegriffe und überlebt " +
                               "Cheat-Deinstallationen. Ocean/detect.ac nutzen diesen Schlüssel als " +
                               "forensischen Beweis für Cheat-File-Suchen.",
                    Detail   = $"Begriff: {term} | Registry-Wert: {valueName}"
                });
            }
        }
        catch { }
    }

    private void ScanRunMru(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU", false);
            if (key == null) return;

            foreach (string valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (valueName == "MRUList") continue;
                ctx.IncrementRegistryKeys();

                string cmd = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                if (string.IsNullOrEmpty(cmd)) continue;

                string? match = CheatKeywords.FirstOrDefault(kw =>
                    cmd.Contains(kw, StringComparison.OrdinalIgnoreCase));
                if (match == null) match = CheatDomains.FirstOrDefault(d =>
                    cmd.Contains(d, StringComparison.OrdinalIgnoreCase));
                if (match == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Befehl in RunMRU History: '{match}'",
                    Risk     = RiskLevel.High,
                    Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                    FileName = "RunMRU",
                    Reason   = $"Win+R Ausführungsverlauf enthält '{cmd}' — Cheat-Indikator '{match}'. " +
                               "RunMRU protokolliert alle über den Ausführen-Dialog gestarteten Befehle. " +
                               "Cheat-Loader werden häufig per Win+R gestartet. Persistiert nach Cheat-Deinstallation.",
                    Detail   = $"Befehl: {cmd} | Match: '{match}'"
                });
            }
        }
        catch { }
    }

    private void ScanOpenSaveMru(ScanContext ctx, CancellationToken ct)
    {
        string[] mruKeys =
        {
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU",
        };

        foreach (string keyPath in mruKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath, false);
                if (key == null) continue;

                // Recurse into sub-keys (one per extension)
                foreach (string subName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var sub = key.OpenSubKey(subName, false);
                        if (sub == null) continue;

                        foreach (string valueName in sub.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            if (valueName == "MRUListEx") continue;
                            ctx.IncrementRegistryKeys();

                            // Values may be string or PIDL binary; try string
                            string path = "";
                            object? raw = sub.GetValue(valueName);
                            if (raw is string s) path = s.ToLowerInvariant();
                            else if (raw is byte[] b)
                            {
                                // Try to extract string path from PIDL bytes
                                path = System.Text.Encoding.Unicode
                                    .GetString(b).ToLowerInvariant().Replace("\0", " ");
                            }

                            if (string.IsNullOrEmpty(path)) continue;

                            string? match = CheatKeywords.FirstOrDefault(kw =>
                                path.Contains(kw, StringComparison.OrdinalIgnoreCase));
                            if (match == null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Cheat-Pfad in OpenSave-Dialog-History: '{match}'",
                                Risk     = RiskLevel.High,
                                Location = $@"HKCU\{keyPath}\{subName}",
                                FileName = "OpenSavePidlMRU",
                                Reason   = $"Dateiauswahl-Dialog-History enthält Pfad mit '{match}'. " +
                                           "OpenSavePidlMRU speichert alle Dateipfade, die über Öffnen/Speichern-" +
                                           "Dialoge aufgerufen wurden — Cheat DLLs, die über Dialoge geladen " +
                                           "wurden, hinterlassen hier permanente Spuren.",
                                Detail   = $"Pfad-Fragment: {path.Substring(0, Math.Min(200, path.Length))} | Match: '{match}'"
                            });
                        }
                    }
                    catch { }
                }

                // Also check direct values
                foreach (string valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    if (valueName is "MRUList" or "MRUListEx") continue;
                    ctx.IncrementRegistryKeys();

                    string val = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                    string? match = CheatKeywords.FirstOrDefault(kw =>
                        val.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (match == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Pfad in OpenSave History: '{match}'",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\{keyPath}",
                        FileName = "OpenSaveMRU",
                        Reason   = $"Dateiauswahl-Dialog-History enthält '{match}'. Forensischer Nachweis " +
                                   "für Cheat-Datei-Zugriff via Datei-Öffnen-Dialog.",
                        Detail   = $"Wert: {valueName} = {val.Substring(0, Math.Min(200, val.Length))}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanRecentApps(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Search\RecentApps", false);
            if (key == null) return;

            foreach (string guid in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var appKey = key.OpenSubKey(guid, false);
                    if (appKey == null) continue;
                    ctx.IncrementRegistryKeys();

                    string appId = (appKey.GetValue("AppId") as string ?? "").ToLowerInvariant();
                    string launchCount = (appKey.GetValue("LaunchCount") ?? 0).ToString()!;

                    string? match = CheatKeywords.FirstOrDefault(kw =>
                        appId.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (match == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-App in Windows Search RecentApps: '{match}'",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps\{guid}",
                        FileName = "RecentApps",
                        Reason   = $"Windows Search RecentApps enthält AppId '{appId}' mit Cheat-Keyword '{match}'. " +
                                   "RecentApps protokolliert über Windows-Suche gestartete Anwendungen. " +
                                   "App wurde {launchCount}× gestartet — direkter Beweis für Cheat-Tool-Nutzung.",
                        Detail   = $"AppId: {appId} | LaunchCount: {launchCount} | GUID: {guid}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }
}
