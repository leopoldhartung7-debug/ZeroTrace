using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Centralised logic for examining a single file: name/path/hash indicator
/// matching, real Authenticode trust validation, the unsigned/untrusted-in-
/// user-writable heuristic, and a Mark-of-the-Web confidence boost. Returns a
/// finding or null. Keeps every file-oriented module consistent and DRY.
/// </summary>
internal static class FileInspector
{
    public static Finding? Inspect(string path, ScanContext ctx, string moduleName)
    {
        string fileName;
        try { fileName = Path.GetFileName(path); }
        catch { return null; }
        if (string.IsNullOrEmpty(fileName)) return null;

        var ext = Path.GetExtension(path);
        bool checkable = SignatureChecker.IsCheckable(path);
        bool relevant = ctx.Options.RelevantExtensions
            .Contains(ext, StringComparer.OrdinalIgnoreCase);

        // 1) Exact file-name indicator (highest confidence among name rules).
        var nameHit = ctx.Matcher.MatchFileName(fileName);
        // 2) File-name keyword heuristic.
        var kwHit = nameHit is null ? ctx.Matcher.MatchFileNameKeyword(fileName) : null;
        // 3) Path keyword heuristic.
        var pathHit = (nameHit ?? kwHit) is null ? ctx.Matcher.MatchPathKeyword(path) : null;

        // Only hash when it can matter: relevant extension, a name/path hit, or a
        // checkable binary. (Hash indicators are the highest-confidence signal.)
        string? sha = null;
        Indicator? hashHit = null;
        if (relevant || checkable || nameHit is not null || kwHit is not null || pathHit is not null)
        {
            sha = HashUtil.TryComputeSha256(path, ctx.Options.MaxHashFileSizeBytes);
            hashHit = ctx.Matcher.MatchHash(sha);
        }

        // Real signature trust (only meaningful for PE/installer files).
        SignatureChecker.SignatureDetail sig = default;
        bool? signed = null;
        string? signer = null;
        if (checkable)
        {
            sig = SignatureChecker.CheckDetailed(path);
            signed = sig.IsTrusted;
            signer = sig.Signer;
        }

        // Catalog-signed files are in-box Windows components (kernel DLLs, system
        // drivers, WinSxS binaries). If no indicator hit occurred, there is nothing
        // more to check: they cannot be "untrusted in user-writable" or be renamed
        // cheats. Returning early here eliminates the MotW read, the content scan,
        // the self-rename check, and the heuristic for the vast majority of safe
        // system files encountered during a deep drive scan.
        if (sig.CatalogSigned && hashHit is null && nameHit is null && kwHit is null && pathHit is null)
            return null;

        // Content-string signature pass: searches the raw bytes for cheat
        // watermarks / menu strings / brand tokens. Catches renamed files.
        // Skipped when a hash indicator already matched (hash is strongest) and
        // for files with no scannable extension.
        Indicator? contentHit = null;
        if (hashHit is null && (checkable || relevant) && ctx.Matcher.HasContentSignatures)
            contentHit = ContentSignatureScanner.Scan(path, ctx.Matcher);

        // Mark-of-the-Web: only read the Zone.Identifier ADS for files in
        // user-controllable locations. Windows system files never carry MotW and
        // attempting to read their ADS wastes I/O time on every scanned binary.
        var motw = Heuristics.IsInUserWritableRoot(path)
            ? MarkOfWeb.Read(path)
            : default;

        // Pick the strongest matching indicator.
        var indicator = hashHit ?? contentHit ?? nameHit ?? kwHit ?? pathHit;

        if (indicator is not null)
        {
            var reasonKind = indicator == hashHit ? "SHA-256-Hash"
                : indicator == contentHit ? "Inhalts-Signatur (String im Datei-Inhalt)"
                : indicator == nameHit ? "exakter Dateiname"
                : indicator == kwHit ? "Dateinamen-Schluesselwort"
                : "Pfad-Schluesselwort";

            return new Finding
            {
                Module = moduleName,
                Title = $"Indikator-Treffer: {indicator.Category}",
                Risk = indicator.Risk,
                Location = path,
                FileName = fileName,
                Sha256 = sha,
                Signed = signed,
                Detail = ComposeDetail(signer, sig, motw),
                Reason = $"Treffer ueber {reasonKind} ('{indicator.Pattern}'). {indicator.Description}"
            };
        }

        // Self-rename / masquerade: the PE's embedded OriginalFilename differs
        // from the on-disk name (e.g. injector.exe renamed to svchost.exe to look
        // benign). Only flagged in user-writable locations to limit false alarms.
        if (checkable && Heuristics.IsInUserWritableRoot(path))
        {
            var orig = TryReadOriginalFilename(path);
            if (!string.IsNullOrEmpty(orig) && !OriginalNameMatches(orig!, fileName))
            {
                bool untrusted = sig.Trust != SignatureChecker.Trust.Trusted;
                var risk = (untrusted || motw.FromInternet) ? RiskLevel.High : RiskLevel.Medium;
                return new Finding
                {
                    Module = moduleName,
                    Title = "Datei umbenannt (Originalname weicht ab)",
                    Risk = risk,
                    Location = path,
                    FileName = fileName,
                    Sha256 = sha,
                    Signed = signed,
                    Detail = ComposeDetail(signer, sig, motw),
                    Reason = $"Der intern hinterlegte Originalname '{orig}' unterscheidet sich vom " +
                             $"aktuellen Dateinamen '{fileName}'. Umbenennen ist ein haeufiges Tarn-Muster " +
                             "(z. B. ein Injektor, der wie eine Systemdatei aussieht)." +
                             (untrusted ? " Zusaetzlich nicht vertrauenswuerdig signiert." : "") +
                             (motw.FromInternet ? " Stammt aus dem Internet (Mark-of-the-Web)." : "")
                };
            }
        }

        // Heuristic: untrusted (unsigned OR invalidly-signed) binary in a
        // user-writable location.
        if (checkable && Heuristics.IsUntrustedInUserWritable(sig, path))
        {
            bool invalidSig = sig.Trust == SignatureChecker.Trust.SignedUntrusted;

            // Base severity: Medium. An *invalid* signature (self-signed / tampered)
            // is more suspicious than simply unsigned; a Mark-of-the-Web from the
            // internet raises confidence one notch.
            var risk = RiskLevel.Medium;
            if (invalidSig || motw.FromInternet) risk = RiskLevel.High;

            return new Finding
            {
                Module = moduleName,
                Title = invalidSig
                    ? "Ungueltig signierte Binaerdatei in beschreibbarem Pfad"
                    : "Unsignierte Binaerdatei in beschreibbarem Pfad",
                Risk = risk,
                Location = path,
                FileName = fileName,
                Sha256 = sha,
                Signed = signed,
                Detail = ComposeDetail(signer, sig, motw),
                Reason = (invalidSig
                    ? "Ausfuehrbare Datei mit ungueltiger Authenticode-Signatur "
                    : "Ausfuehrbare Datei ohne gueltige Authenticode-Signatur ") +
                    "in einem Benutzer-Verzeichnis (z. B. Temp/Downloads/AppData)." +
                    (motw.FromInternet ? " Datei stammt nachweislich aus dem Internet (Mark-of-the-Web)." : "") +
                    " Haeufiges, aber nicht eindeutiges Cheat-Muster."
            };
        }

        return null;
    }

    private static string? ComposeDetail(
        string? signer, SignatureChecker.SignatureDetail sig, MarkOfWeb.Info motw)
    {
        var parts = new List<string>();
        if (signer is not null)
            parts.Add($"Signierer: {signer}");
        if (sig.Trust == SignatureChecker.Trust.SignedUntrusted)
            parts.Add("Signaturstatus: ungueltig/nicht vertraut");
        else if (sig.CatalogSigned)
            parts.Add("Signaturstatus: katalog-signiert (vertraut)");
        if (motw.FromInternet)
            parts.Add("Herkunft: Internet" + (motw.HostUrl is null ? "" : $" ({motw.HostUrl})"));
        return parts.Count == 0 ? null : string.Join(" \u00b7 ", parts);
    }

    /// <summary>Reads the PE's embedded OriginalFilename (version resource), or null.</summary>
    private static string? TryReadOriginalFilename(string path)
    {
        try
        {
            var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(path);
            return string.IsNullOrWhiteSpace(vi.OriginalFilename) ? null : vi.OriginalFilename;
        }
        catch { return null; }
    }

    /// <summary>
    /// True if the embedded original name still matches the on-disk name
    /// (compared without extension, case-insensitive). Empty original -> treated
    /// as a match so we never flag on missing data.
    /// </summary>
    private static bool OriginalNameMatches(string original, string current)
    {
        string a, b;
        try { a = Path.GetFileNameWithoutExtension(original).Trim(); }
        catch { a = original.Trim(); }
        try { b = Path.GetFileNameWithoutExtension(current).Trim(); }
        catch { b = current.Trim(); }
        if (a.Length == 0) return true;
        return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }
}
