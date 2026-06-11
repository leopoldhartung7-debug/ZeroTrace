using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Read-only "what was executed recently" scan. This catches cheats/loaders even
/// after the file was deleted, by reading Windows' own execution-history
/// artifacts and matching the recorded program names/paths against the
/// indicators:
///   - Prefetch  (%WINDIR%\Prefetch\*.pf) — programs that were run.
///   - BAM/DAM   (HKLM\SYSTEM\...\bam|dam\State\UserSettings\&lt;SID&gt;) — per-user
///                last-run timestamps.
///   - UserAssist(HKCU\...\Explorer\UserAssist\{GUID}\Count) — GUI launches
///                (value names are ROT13-encoded).
/// Only entries that match an indicator are recorded — never the full history.
/// Several of these sources require administrator rights; without them the
/// affected source is skipped quietly. Nothing is changed.
/// </summary>
public sealed class ExecutionHistoryScanModule : IScanModule
{
    public string Name => "Ausfuehrungsverlauf";
    public double Weight => 0.7;

    private int _emitted;
    private const int MaxFindings = 80;
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ScanPrefetch(ctx, ct);
        ctx.Report(0.15, "Prefetch", "Prefetch geprueft");

        ScanBamDam(ctx, ct);
        ctx.Report(0.30, "BAM/DAM", "Hintergrund-Aktivitaet geprueft");

        ScanUserAssist(ctx, ct);
        ctx.Report(0.45, "UserAssist", "Programmstarts geprueft");

        ScanAmcache(ctx, ct);
        ctx.Report(0.60, "Amcache", "Amcache geprueft");

        ScanShimCache(ctx, ct);
        ctx.Report(0.72, "ShimCache", "ShimCache geprueft");

        ScanPca(ctx, ct);
        ctx.Report(0.85, "PCA", "Programmkompatibilitaets-Logs geprueft");

        ScanServiceInstalls(ctx, ct);
        ctx.Report(1.0, "Dienst-Installationen", "Dienst-/Treiber-Installationen geprueft");
        return Task.CompletedTask;
    }

    // --- Prefetch --------------------------------------------------------------

    private void ScanPrefetch(ScanContext ctx, CancellationToken ct)
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        string[] files;
        try { files = Directory.GetFiles(dir, "*.pf"); }
        catch { return; } // usually needs admin -> skip quietly

        foreach (var f in files)
        {
            if (ct.IsCancellationRequested || _emitted >= MaxFindings) return;
            // "INJECTOR.EXE-1A2B3C4D.pf" -> "INJECTOR.EXE"
            var baseName = Path.GetFileNameWithoutExtension(f);
            int dash = baseName.LastIndexOf('-');
            var exe = dash > 0 ? baseName[..dash] : baseName;
            EvaluateReference(ctx, exe, exe, "Prefetch", null);
        }
    }

    // --- BAM / DAM -------------------------------------------------------------

    private void ScanBamDam(ScanContext ctx, CancellationToken ct)
    {
        foreach (var svc in new[] { "bam", "dam" })
        {
            if (ct.IsCancellationRequested || _emitted >= MaxFindings) return;
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var us = baseKey.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svc}\State\UserSettings");
                if (us is null) continue;

                foreach (var sid in us.GetSubKeyNames())
                {
                    using var sidKey = us.OpenSubKey(sid);
                    if (sidKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in sidKey.GetValueNames())
                    {
                        if (_emitted >= MaxFindings) return;
                        if (string.IsNullOrWhiteSpace(valueName)) continue;
                        // value name is an NT path like \Device\HarddiskVolumeN\...\foo.exe
                        DateTime? lastRun = null;
                        try
                        {
                            if (sidKey.GetValue(valueName) is byte[] b && b.Length >= 8)
                                lastRun = DateTime.FromFileTime(BitConverter.ToInt64(b, 0));
                        }
                        catch { }
                        EvaluateReference(ctx, valueName, NtPathFileName(valueName),
                            $"BAM/{svc}", lastRun);
                    }
                }
            }
            catch { /* SYSTEM hive needs admin -> skip */ }
        }
    }

    // --- UserAssist ------------------------------------------------------------

    private void ScanUserAssist(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var ua = baseKey.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (ua is null) return;

            foreach (var guid in ua.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested || _emitted >= MaxFindings) return;
                using var count = ua.OpenSubKey($@"{guid}\Count");
                if (count is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in count.GetValueNames())
                {
                    if (_emitted >= MaxFindings) return;
                    var decoded = Rot13(valueName);
                    if (string.IsNullOrWhiteSpace(decoded)) continue;
                    EvaluateReference(ctx, decoded, SafeFileName(decoded), "UserAssist", null);
                }
            }
        }
        catch { /* skip */ }
    }

    // --- Amcache (InventoryApplicationFile) ------------------------------------

    private void ScanAmcache(ScanContext ctx, CancellationToken ct)
    {
        // Amcache.hve records executed/known binaries with their full path. The
        // hive is loaded privately via RegLoadAppKey (read access only, no admin
        // needed) — it is often locked, in which case this degrades to nothing.
        var hive = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "appcompat", "Programs", "Amcache.hve");
        if (!File.Exists(hive)) return;

        SafeRegistryHandle? handle = null;
        try
        {
            const int KEY_READ = 0x20019;
            int rc = RegLoadAppKey(hive, out var raw, KEY_READ, 0, 0);
            if (rc != 0 || raw == IntPtr.Zero) return;
            handle = new SafeRegistryHandle(raw, ownsHandle: true);

            using var root = RegistryKey.FromHandle(handle);
            using var apps = root.OpenSubKey("InventoryApplicationFile");
            if (apps is null) return;

            foreach (var sub in apps.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested || _emitted >= MaxFindings) return;
                using var entry = apps.OpenSubKey(sub);
                var path = entry?.GetValue("LowerCaseLongPath")?.ToString()
                           ?? entry?.GetValue("LongPathHash")?.ToString();
                if (string.IsNullOrWhiteSpace(path)) continue;
                EvaluateReference(ctx, path!, SafeFileName(path!), "Amcache", null);
            }
        }
        catch { /* locked / unsupported -> skip */ }
        finally { handle?.Dispose(); }
    }

    // --- ShimCache (AppCompatCache, Win10/11) ----------------------------------

    private void ScanShimCache(ScanContext ctx, CancellationToken ct)
    {
        byte[]? blob;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = baseKey.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache");
            blob = k?.GetValue("AppCompatCache") as byte[];
        }
        catch { return; }
        if (blob is null || blob.Length < 0x40) return;

        try
        {
            // Win10/11: 4-byte header offset to first entry; each entry begins
            // with the signature "10ts". We only extract the UTF-16 path string.
            int headerLen = BitConverter.ToInt32(blob, 0);
            int pos = headerLen is > 0 and < 0x100 ? headerLen : 0x30;
            int sig10ts = 0x73743031; // "10ts"

            while (pos + 12 <= blob.Length)
            {
                if (ct.IsCancellationRequested || _emitted >= MaxFindings) return;
                if (BitConverter.ToInt32(blob, pos) != sig10ts) { pos++; continue; }
                int p = pos + 8; // skip signature(4) + unknown(4)
                if (p + 6 > blob.Length) break;
                p += 4;          // cache-entry size
                int pathLen = BitConverter.ToUInt16(blob, p); p += 2;
                if (pathLen <= 0 || p + pathLen > blob.Length) { pos += 12; continue; }
                var path = Encoding.Unicode.GetString(blob, p, pathLen);
                EvaluateReference(ctx, path, SafeFileName(path), "ShimCache", null);
                pos = p + pathLen;
            }
        }
        catch { /* unexpected layout -> stop quietly */ }
    }

    // --- PCA logs (Program Compatibility Assistant, Win11) ---------------------

    private void ScanPca(ScanContext ctx, CancellationToken ct)
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "appcompat", "pca");
        foreach (var file in new[] { "PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt" })
        {
            var full = Path.Combine(dir, file);
            if (!File.Exists(full)) continue;
            string[] lines;
            try { lines = File.ReadAllLines(full); }
            catch { continue; }

            foreach (var line in lines)
            {
                if (ct.IsCancellationRequested || _emitted >= MaxFindings) return;
                if (string.IsNullOrWhiteSpace(line)) continue;
                // Tab- or pipe-separated; the first field is the full exe path.
                var path = line.Split('\t', '|')[0].Trim();
                if (path.Length < 4 || !path.Contains('\\')) continue;
                EvaluateReference(ctx, path, SafeFileName(path), "PCA", null);
            }
        }
    }

    // --- EVTX: service / driver installs (System log, event 7045) --------------

    private void ScanServiceInstalls(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var q = new EventLogQuery("System", PathType.LogName,
                "*[System[(EventID=7045)]]") { ReverseDirection = true };
            using var reader = new EventLogReader(q);
            int n = 0;
            EventRecord? rec;
            while (n++ < 200 && (rec = reader.ReadEvent()) is not null)
            {
                if (ct.IsCancellationRequested || _emitted >= MaxFindings) { rec.Dispose(); return; }
                try
                {
                    var props = rec.Properties;
                    // 7045 properties: [0]=ServiceName [1]=ImagePath [2]=Type [3]=StartType
                    string? svc = props.Count > 0 ? props[0].Value?.ToString() : null;
                    string? image = props.Count > 1 ? props[1].Value?.ToString() : null;
                    var when = rec.TimeCreated?.ToLocalTime();
                    if (!string.IsNullOrWhiteSpace(image))
                    {
                        var path = ExtractExe(image!);
                        EvaluateReference(ctx, path, SafeFileName(path),
                            $"Dienst-Install '{svc}'", when);
                    }
                }
                catch { }
                finally { rec.Dispose(); }
            }
        }
        catch { /* log unreadable (often needs admin) -> skip */ }
    }

    private static string ExtractExe(string imagePath)
    {
        var s = imagePath.Trim();
        if (s.StartsWith(@"\??\", StringComparison.Ordinal)) s = s[4..];
        if (s.StartsWith('"'))
        {
            int end = s.IndexOf('"', 1);
            return end > 1 ? s[1..end] : s.Trim('"');
        }
        int sp = s.IndexOf(' ');
        return sp > 0 && s.Contains('\\') ? s[..sp] : s;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int RegLoadAppKey(string file, out IntPtr hkResult, int samDesired, int options, int reserved);

    // --- shared ----------------------------------------------------------------

    /// <summary>
    /// Matches a recorded program reference (full path/name) against the
    /// indicators; on a hit, emits a finding. If the file still exists it is run
    /// through full file inspection; otherwise the name-match alone is reported
    /// (the file may already have been deleted).
    /// </summary>
    private void EvaluateReference(ScanContext ctx, string fullRef, string fileName, string source, DateTime? lastRun)
    {
        if (string.IsNullOrWhiteSpace(fileName)) return;
        if (!_seen.Add(source + "|" + fullRef)) return;

        // If the referenced file is still present, the other modules' depth
        // applies — inspect it directly for hash/signature/rename/etc.
        string? existing = ResolveExisting(fullRef);
        if (existing is not null)
        {
            var f = FileInspector.Inspect(existing, ctx, Name);
            if (f is not null)
            {
                f.Title = $"Ausgefuehrt ({source}): " + f.Title;
                f.Reason = $"[{source}{TimeSuffix(lastRun)}] " + f.Reason;
                ctx.AddFinding(f);
                _emitted++;
                return;
            }
        }

        // Otherwise (or if inspection found nothing): name/path indicator match.
        var ind = ctx.Matcher.MatchFileName(fileName)
                  ?? ctx.Matcher.MatchFileNameKeyword(fileName)
                  ?? ctx.Matcher.MatchPathKeyword(fullRef);
        if (ind is null) return;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Kuerzlich ausgefuehrt: {ind.Category}",
            Risk = ind.Risk,
            Location = fullRef,
            FileName = fileName,
            Reason = $"In '{source}' wurde ein Programm gefunden, dessen Name/Pfad dem Indikator " +
                     $"'{ind.Pattern}' entspricht. {ind.Description} " +
                     (existing is null ? "Die Datei ist aktuell nicht (mehr) vorhanden." : "") +
                     " Ausfuehrungsverlauf zeigt auch bereits geloeschte Programme.",
            Detail = $"Quelle: {source}{TimeSuffix(lastRun)}"
        });
        _emitted++;
    }

    private static string TimeSuffix(DateTime? t)
        => t is null ? "" : $" \u00b7 zuletzt: {t.Value.ToLocalTime():yyyy-MM-dd HH:mm}";

    /// <summary>Best-effort resolve of a reference to an existing file path.</summary>
    private static string? ResolveExisting(string reference)
    {
        try
        {
            if (File.Exists(reference)) return reference;
            // Map an NT device path (\Device\HarddiskVolumeN\..) is non-trivial;
            // try a plain drive path if present.
            var idx = reference.IndexOf(@":\", StringComparison.Ordinal);
            if (idx >= 1)
            {
                var drivePath = reference[(idx - 1)..];
                if (File.Exists(drivePath)) return drivePath;
            }
        }
        catch { }
        return null;
    }

    private static string SafeFileName(string path)
    {
        try { return Path.GetFileName(path.TrimEnd('\\', '/')); }
        catch { return path; }
    }

    private static string NtPathFileName(string ntPath)
    {
        int slash = ntPath.LastIndexOfAny(new[] { '\\', '/' });
        return slash >= 0 && slash < ntPath.Length - 1 ? ntPath[(slash + 1)..] : ntPath;
    }

    private static string Rot13(string s)
    {
        var a = s.ToCharArray();
        for (int i = 0; i < a.Length; i++)
        {
            char c = a[i];
            if (c is >= 'A' and <= 'Z') a[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c is >= 'a' and <= 'z') a[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(a);
    }
}
