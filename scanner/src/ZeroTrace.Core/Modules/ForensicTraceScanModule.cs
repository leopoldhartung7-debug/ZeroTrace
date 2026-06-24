using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Read-only "what was recently opened / left behind" traces that aren't covered
/// by the execution-history module:
///   - RecentDocs / MUICache / Recent *.lnk — recently opened cheat files/folders,
///     even after the file itself was deleted;
///   - WER crash reports — paths of crashed (often deleted) cheats;
///   - Alternate Data Streams — payloads hidden in "file.exe:stream".
/// Only entries matching an indicator are recorded.
/// </summary>
public sealed class ForensicTraceScanModule : IScanModule
{
    public string Name => "Forensische Spuren";
    public double Weight => 0.5;
    public int ParallelGroup => 5;

    private int _emitted;
    private const int MaxFindings = 60;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ScanRecentDocs(ctx);
        ScanMuiCache(ctx);
        ctx.Report(0.4, "Zuletzt geoeffnet", "RecentDocs/MUICache geprueft");

        ScanRecentLnk(ctx);
        ctx.Report(0.6, "Verknuepfungen", "Recent-Verknuepfungen geprueft");

        ScanWer(ctx, ct);
        ctx.Report(0.8, "Absturzberichte", "WER-Berichte geprueft");

        ScanAlternateDataStreams(ctx, ct);
        ctx.Report(1.0, "ADS", "Alternative Datenstroeme geprueft");
        return Task.CompletedTask;
    }

    private void Emit(ScanContext ctx, string title, RiskLevel risk, string loc, string fileName, string reason)
    {
        if (_emitted >= MaxFindings) return;
        _emitted++;
        ctx.AddFinding(new Finding
        {
            Module = Name, Title = title, Risk = risk,
            Location = loc, FileName = fileName, Reason = reason
        });
    }

    private void Match(ScanContext ctx, string reference, string source)
    {
        if (string.IsNullOrWhiteSpace(reference)) return;
        var name = SafeName(reference);
        var ind = ctx.Matcher.MatchFileName(name)
                  ?? ctx.Matcher.MatchFileNameKeyword(name)
                  ?? ctx.Matcher.MatchPathKeyword(reference);
        if (ind is null) return;
        Emit(ctx, $"{source}: {ind.Category}", ind.Risk, reference, name,
            $"In '{source}' gefunden – entspricht dem Indikator '{ind.Pattern}'. {ind.Description}");
    }

    // --- RecentDocs (HKCU) -----------------------------------------------------

    private void ScanRecentDocs(ScanContext ctx)
    {
        try
        {
            using var root = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs");
            if (root is null) return;
            WalkRecentDocs(ctx, root);
            foreach (var sub in root.GetSubKeyNames())
            {
                using var k = root.OpenSubKey(sub);
                if (k is not null) WalkRecentDocs(ctx, k);
            }
        }
        catch { }
    }

    private void WalkRecentDocs(ScanContext ctx, RegistryKey key)
    {
        foreach (var val in key.GetValueNames())
        {
            if (_emitted >= MaxFindings) return;
            if (val.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase)) continue;
            if (key.GetValue(val) is not byte[] data || data.Length < 2) continue;
            // Leading UTF-16 file name, terminated by a double-null.
            int end = 0;
            for (; end + 1 < data.Length; end += 2)
                if (data[end] == 0 && data[end + 1] == 0) break;
            var name = Encoding.Unicode.GetString(data, 0, end);
            Match(ctx, name, "RecentDocs");
        }
    }

    // --- MUICache (HKCU) -------------------------------------------------------

    private void ScanMuiCache(ScanContext ctx)
    {
        string[] keys =
        {
            @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"Software\Microsoft\Windows\ShellNoRoam\MUICache"
        };
        foreach (var path in keys)
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(path);
                if (k is null) continue;
                foreach (var val in k.GetValueNames())
                {
                    if (_emitted >= MaxFindings) return;
                    // Value names are full executable paths.
                    if (val.Contains('\\')) Match(ctx, val, "MUICache");
                }
            }
            catch { }
        }
    }

    // --- Recent *.lnk (file names only, no binary parse) -----------------------

    private void ScanRecentLnk(ScanContext ctx)
    {
        var dir = Path.Combine(KnownPaths.RoamingAppData, "Microsoft", "Windows", "Recent");
        string[] lnks;
        try { lnks = Directory.GetFiles(dir, "*.lnk"); }
        catch { return; }
        foreach (var lnk in lnks)
        {
            if (_emitted >= MaxFindings) return;
            // "<original name>.lnk" -> strip the .lnk to recover the document name.
            var name = Path.GetFileNameWithoutExtension(lnk);
            Match(ctx, name, "Zuletzt geoeffnet (.lnk)");
        }
    }

    // --- WER crash reports -----------------------------------------------------

    private void ScanWer(ScanContext ctx, CancellationToken ct)
    {
        var bases = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows", "WER"),
            Path.Combine(KnownPaths.LocalAppData, "Microsoft", "Windows", "WER")
        };
        foreach (var b in bases)
        {
            if (!Directory.Exists(b)) continue;
            string[] reports;
            try { reports = Directory.GetFiles(b, "Report.wer", SearchOption.AllDirectories); }
            catch { continue; }
            foreach (var rep in reports)
            {
                if (ct.IsCancellationRequested || _emitted >= MaxFindings) return;
                string[] lines;
                try { lines = File.ReadAllLines(rep); }
                catch { continue; }
                foreach (var line in lines)
                {
                    if (line.StartsWith("AppPath=", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("\\") && line.StartsWith("TargetAppId=", StringComparison.OrdinalIgnoreCase))
                    {
                        var v = line[(line.IndexOf('=') + 1)..].Trim();
                        Match(ctx, v, "Absturzbericht (WER)");
                    }
                }
            }
        }
    }

    // --- Alternate Data Streams ------------------------------------------------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string cStreamName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(string fileName, int infoLevel, out WIN32_FIND_STREAM_DATA data, int flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextStreamW(IntPtr handle, out WIN32_FIND_STREAM_DATA data);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr handle);

    private void ScanAlternateDataStreams(ScanContext ctx, CancellationToken ct)
    {
        var exts = new[] { ".exe", ".dll", ".asi", ".sys" };
        foreach (var root in KnownPaths.TargetedScanRoots())
        {
            if (ct.IsCancellationRequested || _emitted >= MaxFindings) return;
            string[] files;
            try { files = Directory.GetFiles(root); }
            catch { continue; }
            foreach (var file in files)
            {
                if (_emitted >= MaxFindings) return;
                if (!exts.Contains(Path.GetExtension(file).ToLowerInvariant())) continue;
                InspectStreams(ctx, file);
            }
        }
    }

    private void InspectStreams(ScanContext ctx, string file)
    {
        const int FindStreamInfoStandard = 0;
        IntPtr h = IntPtr.Zero;
        try
        {
            h = FindFirstStreamW(file, FindStreamInfoStandard, out var d, 0);
            if (h == new IntPtr(-1) || h == IntPtr.Zero) return;
            do
            {
                var sn = d.cStreamName ?? "";
                // Default data stream is "::$DATA"; Zone.Identifier is the MotW (handled elsewhere).
                if (sn.Equals("::$DATA", StringComparison.OrdinalIgnoreCase)) continue;
                if (sn.Contains("Zone.Identifier", StringComparison.OrdinalIgnoreCase)) continue;
                Emit(ctx, "Versteckter alternativer Datenstrom (ADS)", RiskLevel.High,
                    file + sn.TrimEnd(':', '$', 'D', 'A', 'T'), Path.GetFileName(file),
                    $"Die Datei traegt einen versteckten Datenstrom '{sn}' ({d.StreamSize} Byte). " +
                    "In ADS lassen sich Nutzlasten verstecken, die im Explorer nicht sichtbar sind.");
            }
            while (FindNextStreamW(h, out d) && _emitted < MaxFindings);
        }
        catch { }
        finally { if (h != IntPtr.Zero && h != new IntPtr(-1)) FindClose(h); }
    }

    private static string SafeName(string p)
    {
        try { return Path.GetFileName(p.TrimEnd('\\', '/')); } catch { return p; }
    }
}
