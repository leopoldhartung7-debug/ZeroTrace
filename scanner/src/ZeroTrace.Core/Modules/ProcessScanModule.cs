using System.Management;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Enumerates running processes via WMI (Win32_Process), reconstructs the
/// parent/child relationships, and flags processes by name indicator, image
/// hash, image-path heuristics, and the untrusted-in-user-writable rule.
///
/// It additionally inspects the DLLs loaded into each process (see
/// <see cref="ModuleInspection"/>). Injected modules are the most common FiveM
/// cheat shape and are invisible to image-only checks. Modules loaded into the
/// FiveM process itself are escalated.
/// </summary>
public sealed class ProcessScanModule : IScanModule
{
    public string Name => "Prozesse";
    public double Weight => 2.0;
    public int ParallelGroup => 2;

    private sealed record ProcRecord(
        uint Pid, uint ParentPid, string Name, string? Path, ulong WorkingSet);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var records = QueryProcesses();
        var byPid = records.ToDictionary(r => r.Pid, r => r);
        int total = records.Count;
        int i = 0;

        // Module path -> aggregated host info, so an injected DLL loaded into many
        // processes is reported once (with a host count) instead of N times.
        var moduleHosts = new Dictionary<string, ModuleHost>(StringComparer.OrdinalIgnoreCase);

        // Process image paths, so we don't also report an .exe as a "loaded module".
        var imagePaths = new HashSet<string>(
            records.Where(r => !string.IsNullOrEmpty(r.Path)).Select(r => r.Path!),
            StringComparer.OrdinalIgnoreCase);

        foreach (var p in records)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();
            i++;
            if (i % 10 == 0 || i == total)
                ctx.Report(total == 0 ? 1 : (double)i / total * 0.7, p.Name, $"{i}/{total} Prozesse");

            string parentName = byPid.TryGetValue(p.ParentPid, out var par) ? par.Name : "?";
            string detailBase =
                $"PID {p.Pid}, Parent {p.ParentPid} ({parentName}), " +
                $"WorkingSet {p.WorkingSet / (1024 * 1024)} MB";

            string? hostFramework = KnownPaths.MpFrameworkForProcess(p.Name, p.Path);
            bool hostIsMp = hostFramework is not null;

            EvaluateImage(ctx, p, detailBase);

            // Loader pattern: check the full ancestor chain (parent + grandparent).
            // A cheat loader often sits 2 levels above the framework process.
            if (hostIsMp && byPid.TryGetValue(p.ParentPid, out var parent) && !string.IsNullOrEmpty(parent.Path))
            {
                bool parentIsFramework = KnownPaths.MpFrameworkForProcess(parent.Name, parent.Path) is not null;
                if (!parentIsFramework && Heuristics.IsInUserWritableRoot(parent.Path!))
                {
                    var psig = SignatureChecker.CheckDetailed(parent.Path!);
                    bool untrusted = !psig.IsTrusted;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"{hostFramework} von verdaechtigem Prozess gestartet",
                        Risk = untrusted ? RiskLevel.High : RiskLevel.Medium,
                        Location = parent.Path!,
                        FileName = parent.Name,
                        Reason = $"Der {hostFramework}-Prozess (PID {p.Pid}) wurde von '{parent.Name}' " +
                                 $"(PID {parent.Pid}) aus einem beschreibbaren Benutzerordner gestartet. " +
                                 (untrusted ? "Dessen Image ist nicht vertrauenswuerdig signiert. " : "") +
                                 "Das ist ein typisches Muster fuer Loader/Injektoren.",
                        Detail = $"Start-Image: {parent.Path}"
                    });
                }

                // Grandparent check: even if the direct parent looks benign,
                // a malicious grandparent in a user-writable folder is suspicious.
                if (byPid.TryGetValue(parent.ParentPid, out var grandparent) &&
                    !string.IsNullOrEmpty(grandparent.Path) &&
                    KnownPaths.MpFrameworkForProcess(grandparent.Name, grandparent.Path) is null &&
                    Heuristics.IsInUserWritableRoot(grandparent.Path!))
                {
                    var gsig = SignatureChecker.CheckDetailed(grandparent.Path!);
                    if (!gsig.IsTrusted)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige Prozesskette: {grandparent.Name} → {parent.Name} → {hostFramework}",
                            Risk = RiskLevel.High,
                            Location = grandparent.Path!,
                            FileName = grandparent.Name,
                            Reason = $"Zwei Ebenen ueber dem {hostFramework}-Prozess (PID {p.Pid}) liegt " +
                                     $"'{grandparent.Name}' (PID {grandparent.Pid}) in einem beschreibbaren " +
                                     "Benutzerordner und ist nicht vertrauenswuerdig signiert. " +
                                     "Mehrstufige Loader-Ketten sind ein starkes Cheat-Signal.",
                            Detail = $"Kette: {grandparent.Name} → {parent.Name} → {p.Name}"
                        });
                    }
                }
            }

            // Always gather candidate modules for this process (even if the image
            // already produced a finding): the injected DLL is the real signal.
            foreach (var modPath in ModuleInspection.EnumerateCandidateModules((int)p.Pid, ctx))
            {
                if (moduleHosts.TryGetValue(modPath, out var existing))
                {
                    existing.Count++;
                    existing.MpHost |= hostIsMp;
                    existing.HostFramework ??= hostFramework;
                }
                else
                {
                    moduleHosts[modPath] = new ModuleHost
                    {
                        Count = 1,
                        MpHost = hostIsMp,
                        HostFramework = hostFramework,
                        SampleProcess = p.Name
                    };
                }
            }
        }

        // Inspect each unique candidate module exactly once.
        int m = 0, mtotal = Math.Max(moduleHosts.Count, 1);
        foreach (var (modPath, host) in moduleHosts)
        {
            ct.ThrowIfCancellationRequested();
            m++;
            ctx.IncrementFiles();
            if (m % 5 == 0 || m == moduleHosts.Count)
                ctx.Report(0.7 + 0.3 * ((double)m / mtotal), modPath, $"{m}/{moduleHosts.Count} geladene Module");

            // Already covered by the image-level checks above.
            if (imagePaths.Contains(modPath)) continue;

            var finding = FileInspector.Inspect(modPath, ctx, Name);
            if (finding is null) continue;

            string hostInfo = host.MpHost
                ? $"in {host.HostFramework}-Prozess geladen (u. a. {host.SampleProcess})"
                : $"geladen in {host.Count} Prozess(en) (u. a. {host.SampleProcess})";

            finding.Title = "Geladenes Modul: " + finding.Title;
            finding.Reason = "[Geladenes Modul] " + finding.Reason + " " + hostInfo + ".";
            finding.Detail = string.IsNullOrEmpty(finding.Detail) ? hostInfo : finding.Detail + " \u00b7 " + hostInfo;

            // A suspicious DLL injected into a FiveM/RageMP/alt:V process is the
            // highest-value signal this tool can produce: escalate by one notch.
            if (host.MpHost && finding.Risk < RiskLevel.Critical)
                finding.Risk++;

            ctx.AddFinding(finding);
        }

        return Task.CompletedTask;
    }

    /// <summary>Image-level checks: name indicator, image hash, path keyword, trust heuristic.</summary>
    private static void EvaluateImage(ScanContext ctx, ProcRecord p, string detailBase)
    {
        // 1) Process-name indicator.
        var nameHit = ctx.Matcher.MatchProcessName(p.Name);
        if (nameHit is not null)
        {
            ctx.AddFinding(new Finding
            {
                Title = $"Verdaechtiger Prozess: {p.Name}",
                Risk = nameHit.Risk,
                Location = p.Path ?? p.Name,
                FileName = p.Name,
                Reason = $"Prozessname entspricht Indikator '{nameHit.Pattern}'. {nameHit.Description}",
                Detail = detailBase
            });
            return;
        }

        if (string.IsNullOrWhiteSpace(p.Path) || !File.Exists(p.Path))
            return;

        // 2) Image-hash indicator (catches renamed cheat executables).
        string? sha = HashUtil.TryComputeSha256(p.Path, ctx.Options.MaxHashFileSizeBytes);
        var hashHit = ctx.Matcher.MatchHash(sha);
        var sig = SignatureChecker.IsCheckable(p.Path)
            ? SignatureChecker.CheckDetailed(p.Path)
            : default;

        if (hashHit is not null)
        {
            ctx.AddFinding(new Finding
            {
                Title = $"Prozess-Image entspricht Hash-Indikator: {p.Name}",
                Risk = hashHit.Risk,
                Location = p.Path,
                FileName = p.Name,
                Sha256 = sha,
                Signed = sig.IsTrusted,
                Reason = $"SHA-256 des Prozess-Images entspricht Indikator. {hashHit.Description}",
                Detail = detailBase + (sig.Signer is null ? "" : $", Signierer {sig.Signer}")
            });
            return;
        }

        // 3) Path/name keyword indicator on the image.
        var pathHit = ctx.Matcher.MatchPathKeyword(p.Path)
                      ?? ctx.Matcher.MatchFileNameKeyword(p.Name);
        if (pathHit is not null)
        {
            ctx.AddFinding(new Finding
            {
                Title = $"Prozess-Image entspricht Indikator: {p.Name}",
                Risk = pathHit.Risk,
                Location = p.Path,
                FileName = p.Name,
                Sha256 = sha,
                Signed = sig.IsTrusted,
                Reason = $"Image-Pfad/Name entspricht Indikator '{pathHit.Pattern}'. {pathHit.Description}",
                Detail = detailBase + (sig.Signer is null ? "" : $", Signierer {sig.Signer}")
            });
            return;
        }

        // 4) Heuristic: untrusted (unsigned or invalidly-signed) image in a
        //    user-writable path.
        if (SignatureChecker.IsCheckable(p.Path) && Heuristics.IsUntrustedInUserWritable(sig, p.Path))
        {
            bool invalidSig = sig.Trust == SignatureChecker.Trust.SignedUntrusted;
            ctx.AddFinding(new Finding
            {
                Title = (invalidSig ? "Ungueltig signierter" : "Unsignierter")
                        + $" Prozess aus Benutzer-Verzeichnis: {p.Name}",
                Risk = invalidSig ? RiskLevel.High : RiskLevel.Medium,
                Location = p.Path,
                FileName = p.Name,
                Sha256 = sha,
                Signed = false,
                Reason = (invalidSig
                    ? "Laufender Prozess mit ungueltiger Authenticode-Signatur, "
                    : "Laufender Prozess ohne gueltige Authenticode-Signatur, ") +
                    "dessen Image in einem beschreibbaren Benutzerpfad liegt. " +
                    "Pruefenswert, nicht zwingend boesartig.",
                Detail = detailBase + (sig.Signer is null ? "" : $", Signierer {sig.Signer}")
            });
        }
    }

    private sealed class ModuleHost
    {
        public int Count;
        public bool MpHost;
        public string? HostFramework;
        public string SampleProcess = "?";
    }

    private static List<ProcRecord> QueryProcesses()
    {
        var list = new List<ProcRecord>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, WorkingSetSize FROM Win32_Process");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                using (mo)
                {
                    uint pid = ToUInt(mo["ProcessId"]);
                    uint ppid = ToUInt(mo["ParentProcessId"]);
                    string name = mo["Name"] as string ?? "?";
                    string? path = mo["ExecutablePath"] as string;
                    ulong ws = ToULong(mo["WorkingSetSize"]);
                    list.Add(new ProcRecord(pid, ppid, name, path, ws));
                }
            }
        }
        catch
        {
            // WMI unavailable; leave list empty rather than failing the whole scan.
        }
        return list;
    }

    private static uint ToUInt(object? o) =>
        o is null ? 0u : Convert.ToUInt32(o);

    private static ulong ToULong(object? o)
    {
        try { return o is null ? 0UL : Convert.ToUInt64(o); }
        catch { return 0UL; }
    }
}
