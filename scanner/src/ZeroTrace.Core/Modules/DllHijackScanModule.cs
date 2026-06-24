using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects DLL Search Order Hijacking in GTA-V multiplayer framework directories
/// (FiveM, RageMP, alt:V). A cheat that places a shadow copy of a well-known
/// system DLL (version.dll, dinput8.dll, d3d11.dll …) in the game folder will
/// be loaded by the game before the real system DLL and can hook the entire
/// process without needing an injector. The check verifies signature trust:
/// a legitimately placed DLL (rare but possible for mods) must be trusted-signed.
/// Read-only; no files are created or modified.
/// </summary>
public sealed class DllHijackScanModule : IScanModule
{
    public string Name => "DLL-Hijacking";
    public double Weight => 0.4;
    public int ParallelGroup => 5;

    // System DLLs that are high-value hijacking targets in game directories.
    private static readonly HashSet<string> TargetDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "version.dll", "dinput8.dll", "d3d11.dll", "d3d9.dll", "d3d10.dll",
        "winmm.dll", "dsound.dll", "opengl32.dll", "dwrite.dll", "xinput1_3.dll",
        "xinput1_4.dll", "wsock32.dll", "dbghelp.dll", "msacm32.dll",
        "d3dcompiler_47.dll", "iphlpapi.dll", "uxtheme.dll", "winsock.dll"
    };

    private static readonly string System32 =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var (fwName, fwRoot) in KnownPaths.FindMpFrameworks())
        {
            if (ct.IsCancellationRequested) break;
            try { ScanDirectory(ctx, fwName, fwRoot, ct); } catch { }
        }
        ctx.Report(1.0, "DLL-Hijacking", "Game-Verzeichnisse geprueft");
        return Task.CompletedTask;
    }

    private void ScanDirectory(ScanContext ctx, string fwName, string root, CancellationToken ct,
        int depth = 0)
    {
        if (depth > 3 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(root, "*.dll"); } catch { files = Array.Empty<string>(); }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            var fname = Path.GetFileName(file);
            if (!TargetDlls.Contains(fname)) continue;

            // Only flag if not the genuine system copy
            if (string.Equals(
                Path.GetFullPath(file),
                Path.Combine(System32, fname),
                StringComparison.OrdinalIgnoreCase)) continue;

            ctx.IncrementFiles();
            var sig = SignatureChecker.CheckDetailed(file);

            // Microsoft-signed system DLLs placed here for a mod should still be
            // trusted. Flag only untrusted / unsigned ones.
            if (sig.IsTrusted) continue;

            var ind = ctx.Matcher.MatchFileName(fname)
                      ?? ctx.Matcher.MatchFileNameKeyword(fname)
                      ?? ctx.Matcher.MatchPathKeyword(file);

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"DLL-Hijacking: System-DLL im Game-Verzeichnis ({fwName})",
                Risk = ind?.Risk ?? RiskLevel.High,
                Location = file,
                FileName = fname,
                Signed = false,
                Reason = $"Die Datei '{fname}' liegt im {fwName}-Verzeichnis und ist nicht " +
                         "vertrauenswuerdig signiert. Windows laedt DLLs zuerst aus dem " +
                         "Anwendungsverzeichnis (DLL Search Order) — eine dort platzierte " +
                         "gleichnamige System-DLL wird also anstelle der echten Windows-DLL " +
                         "geladen und kann den gesamten Prozess kontrollieren." +
                         (ind is null ? "" : $" Indikator '{ind.Pattern}': {ind.Description}"),
                Detail = $"Framework: {fwName} · Signatur: {(sig.Signer is null ? "unsigned" : sig.Signer)}"
            });
        }

        string[] subdirs;
        try { subdirs = Directory.GetDirectories(root); } catch { return; }
        foreach (var sub in subdirs)
            ScanDirectory(ctx, fwName, sub, ct, depth + 1);
    }
}
