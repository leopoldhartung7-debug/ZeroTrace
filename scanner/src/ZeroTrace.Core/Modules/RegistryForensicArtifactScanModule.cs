using ZeroTrace.Core.Models;
using Microsoft.Win32;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep forensic scan of additional Windows registry hives for cheat tool artifacts.
///
/// Windows maintains dozens of registry locations that persist evidence of past activity.
/// This module covers forensic registry sources NOT already scanned by other modules:
///
///   BAM (Background Activity Moderator):
///     HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\[SID]\
///     Contains full paths of ALL executables run recently (including deleted ones).
///     This is one of the most reliable forensic sources — persists after file deletion.
///
///   Shimcache / AppCompatCache:
///     HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache
///     Binary blob containing paths and timestamps of recently executed executables.
///     Populated on shutdown — survives reboots and file deletion.
///
///   CapabilityAccessManager (Windows 10/11 privacy permissions):
///     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\
///     Records apps that requested microphone, camera, location, etc.
///     Cheat tools sometimes abuse privacy APIs; their paths appear here.
///
///   Windows Error Reporting (additional paths not covered by WerArtifactScanModule):
///     HKCU\Software\Microsoft\Windows\Windows Error Reporting\
///     WER stores process names and paths of crashed applications — including cheats
///     that crashed during injection or anti-cheat detection.
///
///   Explorer.exe Typed Paths (not covered by WindowsSearchHistoryForensicScanModule):
///     HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
///     Paths typed directly into Explorer address bar — cheat directories navigated to.
///
/// Ocean and detect.ac use BAM and Shimcache as primary forensic sources because:
///   - They capture execution evidence even after the cheat file is deleted
///   - BAM records every background app activation since last boot
///   - Shimcache entries survive OS reinstallation (in the old hive)
/// </summary>
public sealed class RegistryForensicArtifactScanModule : IScanModule
{
    public string Name => "Registry Forensik Artefakte (BAM, Shimcache, WER, TypedPaths) Scan";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private static readonly string[] CheatKeywords =
    {
        "aimbot", "wallhack", "esp", "triggerbot", "cheat", "hack",
        "inject", "injector", "loader", "bypass", "spoofer",
        "gamesense", "onetap", "fatality", "aimware", "neverlose", "skeet",
        "2take1", "kiddion", "cherax", "ozark", "stand",
        "engineowning", "iniuria", "vapeflux",
        "pcileech", "memprocfs", "rawaccel",
        "interception", "vigem", "vjoy",
        "mhyprot", "rtcore", "winring0",
        "cheatengine", "cheat engine",
        "x64dbg", "windbg",
        "scriptware", "synapsex", "krnl", "jjsploit", "fluxus",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanBam(ctx, ct);
        ScanShimcache(ctx, ct);
        ScanTypedPaths(ctx, ct);
        ScanWerRegistryHistory(ctx, ct);
        ScanCapabilityAccessManager(ctx, ct);
    }

    private void ScanBam(ScanContext ctx, CancellationToken ct)
    {
        // BAM (Background Activity Moderator) tracks all app executions
        // Path: HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}\
        try
        {
            string[] bamPaths =
            {
                @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
                @"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
            };

            foreach (string bamPath in bamPaths)
            {
                ct.ThrowIfCancellationRequested();
                using var bamKey = Registry.LocalMachine.OpenSubKey(bamPath, false);
                if (bamKey == null) continue;

                foreach (string sidName in bamKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var sidKey = bamKey.OpenSubKey(sidName, false);
                        if (sidKey == null) continue;

                        foreach (string valueName in sidKey.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            // BAM value names ARE the executable paths
                            string path = valueName.ToLowerInvariant();
                            string? match = CheatKeywords.FirstOrDefault(kw =>
                                path.Contains(kw, StringComparison.OrdinalIgnoreCase));
                            if (match == null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Cheat-Executable in BAM-History: '{match}'",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{bamPath}\{sidName}",
                                FileName = System.IO.Path.GetFileName(valueName.TrimEnd('\0')),
                                Reason   = $"Background Activity Moderator (BAM) protokolliert '{valueName}' " +
                                           $"— Cheat-Keyword '{match}'. BAM speichert alle ausgeführten " +
                                           "Anwendungen und überlebt Dateilöschung. Dieser Eintrag beweist, " +
                                           "dass das Cheat-Tool ausgeführt wurde. Primäre Forensik-Quelle " +
                                           "für Ocean/detect.ac.",
                                Detail   = $"BAM-Pfad: {valueName} | SID: {sidName} | Keyword: '{match}'"
                            });
                        }
                    }
                    catch { }
                }
                break; // found the right BAM path
            }
        }
        catch { }
    }

    private void ScanShimcache(ScanContext ctx, CancellationToken ct)
    {
        // Shimcache / AppCompatCache stores recently executed executable paths
        // The value is a binary blob — we byte-grep for UTF-16 cheat keywords
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache", false);
            if (key == null) return;

            ctx.IncrementRegistryKeys();
            byte[]? data = key.GetValue("AppCompatCache") as byte[];
            if (data == null || data.Length < 128) return;

            // Shimcache contains UTF-16 LE encoded paths — decode and grep
            string shimText = System.Text.Encoding.Unicode.GetString(data).ToLowerInvariant();

            foreach (string kw in CheatKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!shimText.Contains(kw.ToLowerInvariant())) continue;

                int idx = shimText.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                int start = Math.Max(0, idx - 60);
                int end = Math.Min(shimText.Length, idx + kw.Length + 60);
                string snippet = shimText.Substring(start, end - start)
                    .Replace('\0', ' ').Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Executable in Shimcache (AppCompatCache): '{kw}'",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
                    FileName = "AppCompatCache",
                    Reason   = $"Windows AppCompatCache (Shimcache) enthält '{kw}'. Shimcache " +
                               "protokolliert alle ausgeführten PE-Dateien mit Pfad und Zeitstempel. " +
                               "Überlebt Dateilöschung und Neustart — direkter Beweis für Cheat-Ausführung. " +
                               "Ocean/detect.ac nutzen Shimcache als primären Forensik-Beweis.",
                    Detail   = $"Shimcache-Fragment: \"{snippet}\" | Keyword: '{kw}'"
                });
                return; // one finding per shimcache blob
            }
        }
        catch { }
    }

    private void ScanTypedPaths(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths", false);
            if (key == null) return;

            foreach (string valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                string path = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                string? match = CheatKeywords.FirstOrDefault(kw =>
                    path.Contains(kw, StringComparison.OrdinalIgnoreCase));
                if (match == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Pfad in Explorer TypedPaths: '{match}'",
                    Risk     = RiskLevel.High,
                    Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
                    FileName = "TypedPaths",
                    Reason   = $"Explorer Adressleisten-History enthält Pfad '{path}' mit Cheat-Keyword '{match}'. " +
                               "TypedPaths speichert in der Explorer-Adressleiste eingetippte Pfade — " +
                               "Cheat-Verzeichnisse, zu denen navigiert wurde, erscheinen hier.",
                    Detail   = $"Wert: {valueName} = {path}"
                });
            }
        }
        catch { }
    }

    private void ScanWerRegistryHistory(ScanContext ctx, CancellationToken ct)
    {
        // WER stores crash info for processes that crashed
        string[] werPaths =
        {
            @"Software\Microsoft\Windows\Windows Error Reporting\Debug",
            @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        };

        foreach (string werPath in werPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(werPath, false);
                if (key == null) continue;

                foreach (string valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    string val = valueName.ToLowerInvariant();
                    string? match = CheatKeywords.FirstOrDefault(kw =>
                        val.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (match == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Tool in WER/AppCompat History: '{match}'",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\{werPath}",
                        FileName = System.IO.Path.GetFileName(valueName.TrimEnd('\0')),
                        Reason   = $"Windows Error Reporting/AppCompat-Verlauf enthält '{valueName}' " +
                                   $"mit Cheat-Keyword '{match}'. WER protokolliert Anwendungen die " +
                                   "abgestürzt sind oder Kompatibilitätsprüfungen durchlaufen haben. " +
                                   "Cheat-Loader stürzen oft bei fehlgeschlagener Injektion ab.",
                        Detail   = $"Schlüssel: {werPath} | Wert: {valueName}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanCapabilityAccessManager(ScanContext ctx, CancellationToken ct)
    {
        // CapabilityAccessManager tracks which apps requested sensitive permissions
        string camPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";
        string[] capabilities = { "microphone", "webcam", "location" };

        foreach (string cap in capabilities)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                string fullPath = $@"{camPath}\{cap}";
                using var key = Registry.LocalMachine.OpenSubKey(fullPath, false);
                if (key == null) continue;

                foreach (string appName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    string appLower = appName.ToLowerInvariant().Replace("#", "\\");
                    string? match = CheatKeywords.FirstOrDefault(kw =>
                        appLower.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (match == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-App in CapabilityAccessManager ({cap}): '{match}'",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{fullPath}\{appName}",
                        FileName = appName,
                        Reason   = $"Anwendung '{appName}' hat auf '{cap}' zugegriffen und enthält " +
                                   $"Cheat-Keyword '{match}'. CapabilityAccessManager protokolliert " +
                                   "alle Apps mit Berechtigungsanfragen — Cheat-Tools greifen manchmal " +
                                   "auf Mikrofon/Kamera für Social Engineering oder Streaming-Analyse zu.",
                        Detail   = $"App: {appName} | Capability: {cap}"
                    });
                }
            }
            catch { }
        }
    }
}
