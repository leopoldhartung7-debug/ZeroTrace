using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Local-only integrity inspection of the installed GTA-V multiplayer
/// frameworks: FiveM, RageMP and alt:V. For each one it confirms the install,
/// then flags DLLs/binaries inside the framework tree and its mod/plugin/
/// resource folders that are unsigned, invalidly signed, carry a cheat
/// content-signature, or match an indicator.
///
/// Trust is decided by real Authenticode validation:
///   * Trusted + framework/Microsoft signer (or catalog-signed) -> quiet.
///   * Trusted but third-party signer                           -> Low (info).
///   * Unsigned                                                 -> Medium/High.
///   * Invalidly signed (self-signed / tampered)                -> High.
/// This removes false positives on catalog-signed in-box DLLs while still
/// surfacing genuinely untrusted components across all three frameworks.
/// </summary>
public sealed class FiveMScanModule : IScanModule
{
    public string Name => "GTA-MP";
    public double Weight => 1.0;

    private static readonly string[] InterestingSubfolders =
    {
        "plugins", "mods", "scripts", "resources", "client_packages",
        "FiveM.app\\plugins", "FiveM.app\\mods", "FiveM.app\\citizen", "citizen",
        "modules", "deps", "data", "cache", "dlls", "bin", "cef"
    };

    private static string[] TrustedSignerFragmentsFor(string framework) => framework switch
    {
        "FiveM"  => new[] { "CitizenFX", "Cfx.re", "Microsoft", "Microsoft Corporation", "Windows-Katalog" },
        "RageMP" => new[] { "RAGE", "ragemp", "RAGE Multiplayer", "Microsoft", "Windows-Katalog" },
        "alt:V"  => new[] { "altMP", "alt:V", "altv", "Microsoft", "Windows-Katalog" },
        _        => new[] { "Microsoft", "Windows-Katalog" }
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var frameworks = KnownPaths.FindMpFrameworks().ToList();
        if (frameworks.Count == 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Kein GTA-Multiplayer-Framework gefunden",
                Risk = RiskLevel.Low,
                Location = "%LocalAppData%\\FiveM, RAGE Multiplayer, altv",
                Reason = "Weder FiveM noch RageMP noch alt:V im Standardpfad gefunden. " +
                         "Framework-spezifische Pruefungen wurden uebersprungen."
            });
            ctx.Report(1.0, "GTA-MP", "Keine Installation gefunden");
            return Task.CompletedTask;
        }

        // Collect candidate binaries across every detected framework first so
        // progress is meaningful and each file is attributed to its framework.
        var work = new List<(string fw, string file)>();
        foreach (var (fwName, root) in frameworks)
        {
            foreach (var file in EnumerateBinaries(root, depth: 5, ct))
                work.Add((fwName, file));
        }

        int total = Math.Max(work.Count, 1);
        int i = 0;

        foreach (var (fwName, file) in work)
        {
            ct.ThrowIfCancellationRequested();
            i++;
            ctx.IncrementFiles();
            if (i % 25 == 0) ctx.Report((double)i / total, file, $"{i}/{work.Count} {fwName}-Dateien");

            var ext = Path.GetExtension(file);
            bool isDll = ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                         || ext.Equals(".asi", StringComparison.OrdinalIgnoreCase);

            // Indicator/content/heuristic pass (hash, content-signature, name,
            // path, untrusted-in-userdir).
            var finding = FileInspector.Inspect(file, ctx, Name);
            if (finding is not null)
            {
                finding.Reason = $"[{fwName}] " + finding.Reason;
                ctx.AddFinding(finding);
                continue;
            }

            if (!isDll || !SignatureChecker.IsCheckable(file)) continue;

            var sig = SignatureChecker.CheckDetailed(file);
            bool inModFolder = InterestingSubfolders.Any(s =>
                file.Contains(s, StringComparison.OrdinalIgnoreCase));
            var trusted = TrustedSignerFragmentsFor(fwName);

            if (sig.Trust == SignatureChecker.Trust.Trusted)
            {
                bool allowlisted = sig.CatalogSigned ||
                    (sig.Signer is not null && trusted.Any(t =>
                        sig.Signer.Contains(t, StringComparison.OrdinalIgnoreCase)));

                if (allowlisted) continue; // known-good, stay quiet

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Signierte Dritt-DLL im Framework-Verzeichnis",
                    Risk = RiskLevel.Low,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Sha256 = HashUtil.TryComputeSha256(file, ctx.Options.MaxHashFileSizeBytes),
                    Signed = true,
                    Detail = $"Signierer: {sig.Signer}",
                    Reason = $"[{fwName}] Gueltig signierte DLL/ASI eines Drittanbieters im " +
                             "Framework-Baum. Meist ein legitimer Mod; informativ aufgefuehrt."
                });
                continue;
            }

            // Unsigned or invalidly signed DLL/ASI inside a framework tree.
            bool invalid = sig.Trust == SignatureChecker.Trust.SignedUntrusted;
            var risk = invalid ? RiskLevel.High : (inModFolder ? RiskLevel.High : RiskLevel.Medium);

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = invalid ? "Ungueltig signierte DLL im Framework-Verzeichnis"
                                : "Untrusted DLL im Framework-Verzeichnis",
                Risk = risk,
                Location = file,
                FileName = Path.GetFileName(file),
                Sha256 = HashUtil.TryComputeSha256(file, ctx.Options.MaxHashFileSizeBytes),
                Signed = false,
                Detail = sig.Signer is null ? null : $"Signierer: {sig.Signer}",
                Reason = $"[{fwName}] DLL/ASI im Framework-Baum " +
                         (invalid ? "mit ungueltiger Signatur (selbstsigniert/manipuliert). "
                                  : "ohne vertrauenswuerdige Hersteller-Signatur. ") +
                         "Kann ein Mod, aber auch eine injizierte Komponente sein. " +
                         "Lokale Pruefung empfohlen."
            });
        }

        ctx.Report(1.0, "GTA-MP", "Framework-Pruefung abgeschlossen");
        return Task.CompletedTask;
    }

    private static IEnumerable<string> EnumerateBinaries(string root, int depth, CancellationToken ct)
    {
        var stack = new Stack<(string dir, int d)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) yield break;
            var (dir, d) = stack.Pop();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir); } catch { }
            foreach (var f in files)
            {
                var ext = Path.GetExtension(f);
                if (ext is ".dll" or ".asi" or ".exe" or ".bin" or ".lua" or ".luac" or ".sys" or ".js" or ".node" or ".dat")
                    yield return f;
            }

            if (d >= depth) continue;
            string[] subs = Array.Empty<string>();
            try { subs = Directory.GetDirectories(dir); } catch { continue; }
            foreach (var s in subs) stack.Push((s, d + 1));
        }
    }
}
