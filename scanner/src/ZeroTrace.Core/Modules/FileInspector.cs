using System.Reflection;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Centralised logic for examining a single file: name/path/hash indicator
/// matching, real Authenticode trust validation, the unsigned/untrusted-in-
/// user-writable heuristic, entropy-based packer detection, .NET assembly
/// metadata inspection, and a Mark-of-the-Web confidence boost. Returns a
/// finding or null. Keeps every file-oriented module consistent and DRY.
/// </summary>
internal static class FileInspector
{
    // #8 — Allowlist: files signed by these publishers skip the
    // "untrusted in user-writable" heuristic so common software never
    // generates false positives.
    private static readonly string[] KnownGoodSigners =
    {
        "Microsoft", "Microsoft Corporation", "Windows",
        "Valve", "Steam", "Valve Corporation",
        "CitizenFX", "Cfx.re",
        "NVIDIA", "Advanced Micro Devices", "Intel Corporation",
        "Rockstar Games", "Take-Two Interactive",
        "BattlEye", "Easy Anti-Cheat", "EasyAntiCheat",
        "Google LLC", "Mozilla Corporation",
        "Discord Inc", "Discord"
    };

    // #6 — Entropy thresholds
    private const double EntropyPackerThreshold = 7.2;   // bits/byte above which packing is suspected
    private const long   EntropyMinBytes        = 8_192; // skip tiny files to avoid noise

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

        // #8 — Known-good signer allowlist: skip heuristics for well-known publishers.
        bool isKnownGoodSigner = checkable && sig.IsTrusted && signer is not null &&
            KnownGoodSigners.Any(g => signer.Contains(g, StringComparison.OrdinalIgnoreCase));

        // Content-string signature pass: searches the raw bytes for cheat
        // watermarks / menu strings / brand tokens. Catches renamed files.
        // Skipped when a hash indicator already matched (hash is strongest) and
        // for files with no scannable extension.
        Indicator? contentHit = null;
        if (hashHit is null && (checkable || relevant) && ctx.Matcher.HasContentSignatures)
            contentHit = ContentSignatureScanner.Scan(path, ctx.Matcher);

        // Mark-of-the-Web: was this file downloaded from the internet?
        var motw = MarkOfWeb.Read(path);

        // Pick the strongest matching indicator.
        var indicator = hashHit ?? contentHit ?? nameHit ?? kwHit ?? pathHit;

        if (indicator is not null)
        {
            var reasonKind = indicator == hashHit ? "SHA-256-Hash"
                : indicator == contentHit ? "Inhalts-Signatur (String im Datei-Inhalt)"
                : indicator == nameHit ? "exakter Dateiname"
                : indicator == kwHit ? "Dateinamen-Schluesselwort"
                : "Pfad-Schluesselwort";

            int conf = indicator == hashHit ? 95
                     : indicator == contentHit ? 85
                     : indicator == nameHit ? 85
                     : indicator == kwHit ? 65
                     : 60;
            if (motw.FromInternet) conf = Math.Min(conf + 5, 99);

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
                Reason = $"Treffer ueber {reasonKind} ('{indicator.Pattern}'). {indicator.Description}",
                ConfidenceScore = conf
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
                int conf = untrusted && motw.FromInternet ? 85
                         : untrusted ? 75
                         : motw.FromInternet ? 70 : 55;
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
                             (motw.FromInternet ? " Stammt aus dem Internet (Mark-of-the-Web)." : ""),
                    ConfidenceScore = conf
                };
            }
        }

        // Heuristic: untrusted (unsigned OR invalidly-signed) binary in a
        // user-writable location. Skip when the signer is on the known-good list.
        if (!isKnownGoodSigner && checkable && Heuristics.IsUntrustedInUserWritable(sig, path))
        {
            bool invalidSig = sig.Trust == SignatureChecker.Trust.SignedUntrusted;

            var risk = RiskLevel.Medium;
            if (invalidSig || motw.FromInternet) risk = RiskLevel.High;

            int conf = invalidSig && motw.FromInternet ? 82
                     : invalidSig ? 65
                     : motw.FromInternet ? 72 : 50;

            // #6 — Boost confidence and include entropy detail when the file is packed.
            string? entropyDetail = null;
            double entropy = 0;
            try
            {
                var fi = new FileInfo(path);
                if (fi.Length >= EntropyMinBytes && fi.Length <= ctx.Options.MaxHashFileSizeBytes)
                {
                    entropy = ComputeEntropy(path);
                    if (entropy >= EntropyPackerThreshold)
                    {
                        entropyDetail = $"Entropie: {entropy:F2} bit/byte (Packing-Verdacht)";
                        conf = Math.Min(conf + 12, 95);
                        if (risk < RiskLevel.High) risk = RiskLevel.High;
                    }
                }
            }
            catch { }

            var detailParts = ComposeDetail(signer, sig, motw);
            if (entropyDetail is not null)
                detailParts = detailParts is null ? entropyDetail : detailParts + " · " + entropyDetail;

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
                Detail = detailParts,
                Reason = (invalidSig
                    ? "Ausfuehrbare Datei mit ungueltiger Authenticode-Signatur "
                    : "Ausfuehrbare Datei ohne gueltige Authenticode-Signatur ") +
                    "in einem Benutzer-Verzeichnis (z. B. Temp/Downloads/AppData)." +
                    (motw.FromInternet ? " Datei stammt nachweislich aus dem Internet (Mark-of-the-Web)." : "") +
                    (entropy >= EntropyPackerThreshold ? $" Hoch-Entropie ({entropy:F2} bit/byte) deutet auf Packing/Verschluesselung hin." : "") +
                    " Haeufiges, aber nicht eindeutiges Cheat-Muster.",
                ConfidenceScore = conf
            };
        }

        // #6 — Standalone entropy check: high-entropy PE in user-writable location
        // that wasn't already caught by the trust heuristic (e.g. oddly trusted but
        // packed). Separate lower-risk finding to reduce false positives.
        if (checkable && !isKnownGoodSigner && Heuristics.IsInUserWritableRoot(path))
        {
            try
            {
                var fi = new FileInfo(path);
                if (fi.Length >= EntropyMinBytes && fi.Length <= ctx.Options.MaxHashFileSizeBytes)
                {
                    double entropy = ComputeEntropy(path);
                    if (entropy >= EntropyPackerThreshold)
                    {
                        return new Finding
                        {
                            Module = moduleName,
                            Title = "Hoch-Entropie Binaerdatei (moeglicher Packer/Cheat-Loader)",
                            Risk = RiskLevel.Medium,
                            Location = path,
                            FileName = fileName,
                            Sha256 = sha,
                            Signed = signed,
                            Detail = $"Entropie: {entropy:F2} bit/byte" +
                                     (signer is not null ? $" · Signierer: {signer}" : "") +
                                     (motw.FromInternet ? " · Herkunft: Internet" : ""),
                            Reason = $"Die Datei hat eine Shannon-Entropie von {entropy:F2} bit/byte " +
                                     $"(Schwelle: {EntropyPackerThreshold}). Das deutet auf " +
                                     "Packing oder Verschluesselung hin (UPX, custom Packer) — " +
                                     "ein haeufiges Muster bei Cheat-Loadern und Injektoren.",
                            ConfidenceScore = motw.FromInternet ? 62 : 52
                        };
                    }
                }
            }
            catch { }
        }

        // #7 — .NET assembly metadata: obfuscated assembly name in user-writable location.
        if (checkable && Heuristics.IsInUserWritableRoot(path) &&
            (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
             ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)))
        {
            string? asmName = TryGetAssemblyName(path);
            if (asmName is not null && IsObfuscatedName(asmName))
            {
                return new Finding
                {
                    Module = moduleName,
                    Title = $".NET-Assembly mit obfuskiertem Namen: {Path.GetFileName(path)}",
                    Risk = RiskLevel.Medium,
                    Location = path,
                    FileName = fileName,
                    Sha256 = sha,
                    Signed = signed,
                    Detail = $"Assembly-Name: {asmName}" +
                             (signer is not null ? $" · Signierer: {signer}" : ""),
                    Reason = $"Die .NET-Assembly hat einen zufaellig wirkenden, obfuskierten internen " +
                             $"Namen ('{asmName}'). Cheat-Clients nutzen Obfuskierung, um " +
                             "Signatur-Erkennung zu erschweren.",
                    ConfidenceScore = 50
                };
            }
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
        return parts.Count == 0 ? null : string.Join(" · ", parts);
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

    // #6 — Shannon entropy over the full file content.
    private static double ComputeEntropy(string path)
    {
        try
        {
            var counts = new long[256];
            long total = 0;
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 65_536);
            var buf = new byte[65_536];
            int read;
            while ((read = stream.Read(buf, 0, buf.Length)) > 0)
            {
                for (int i = 0; i < read; i++) counts[buf[i]]++;
                total += read;
            }
            if (total == 0) return 0;
            double entropy = 0;
            foreach (var c in counts)
            {
                if (c == 0) continue;
                double p = (double)c / total;
                entropy -= p * Math.Log2(p);
            }
            return entropy;
        }
        catch { return 0; }
    }

    // #7 — Attempt to read the assembly name from a .NET managed PE.
    private static string? TryGetAssemblyName(string path)
    {
        try
        {
            return AssemblyName.GetAssemblyName(path).Name;
        }
        catch { return null; }
    }

    /// <summary>
    /// Heuristic: a "random" assembly name suggests obfuscation.
    ///   - 32-char hex string (GUID/hash used as name)
    ///   - Very long name with fewer than 15 % vowels (random consonant string)
    ///   - All-digits name of any length
    /// </summary>
    private static bool IsObfuscatedName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length < 5) return false;

        // All-digits
        if (name.All(char.IsDigit)) return true;

        // 32-char hex (typical hash/GUID pattern)
        if (name.Length == 32 && name.All(c =>
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return true;

        // No separators + very few vowels = random-looking
        bool hasNoSeparators = !name.Any(c => c == '.' || c == '-' || c == '_' || c == ' ');
        if (hasNoSeparators && name.Length >= 10)
        {
            int vowels = name.Count(c => "aeiouAEIOU".Contains(c));
            if ((double)vowels / name.Length < 0.12) return true;
        }

        return false;
    }
}
