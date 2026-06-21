using System.Diagnostics;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Enumerates the modules (DLLs) loaded into a running process. Injected
/// components — the most common FiveM cheat shape — show up here even when the
/// main process image is perfectly legitimate.
///
/// A cheap pre-filter keeps this fast: a module is only treated as a candidate
/// (and thus hashed/trust-checked later) if it lives in a user-writable location
/// or matches a name/path indicator. Trusted system DLLs in System32/WinSxS are
/// skipped, so we never hash thousands of in-box libraries. Read-only throughout;
/// inaccessible processes are skipped silently.
/// </summary>
internal static class ModuleInspection
{
    public static List<string> EnumerateCandidateModules(int pid, ScanContext ctx)
    {
        var result = new List<string>();
        if (pid <= 4) return result; // Idle/System pseudo-processes

        try
        {
            using var proc = Process.GetProcessById(pid);
            foreach (ProcessModule m in proc.Modules)
            {
                string? fn = null;
                try { fn = m.FileName; } catch { /* module unloaded / access */ }
                if (string.IsNullOrEmpty(fn)) continue;
                if (IsCandidate(fn!, ctx)) result.Add(fn!);
            }
        }
        catch
        {
            // Access denied, bitness mismatch, protected process, or the process
            // exited mid-scan. Degrade to "no modules" rather than failing.
        }
        return result;
    }

    private static bool IsCandidate(string path, ScanContext ctx)
    {
        // Cheap checks only — no hashing here.
        if (Heuristics.IsInUserWritableRoot(path)) return true;

        string fn;
        try { fn = Path.GetFileName(path); }
        catch { return false; }

        return ctx.Matcher.MatchFileName(fn) is not null
            || ctx.Matcher.MatchFileNameKeyword(fn) is not null
            || ctx.Matcher.MatchPathKeyword(path) is not null;
    }

    /// <summary>
    /// Checks all loaded modules of a process for the "ghost DLL" pattern:
    /// a module that was mapped into the process but whose on-disk file no
    /// longer exists. This is used by some cheat loaders to reduce forensic
    /// traces — they inject a DLL then delete the file immediately.
    /// Adds findings directly to <paramref name="ctx"/>.
    /// </summary>
    public static void CheckGhostModules(int pid, string processName, bool isMpProcess, ScanContext ctx)
    {
        if (pid <= 4) return;
        try
        {
            using var proc = Process.GetProcessById(pid);
            foreach (ProcessModule m in proc.Modules)
            {
                string? fn = null;
                try { fn = m.FileName; } catch { }
                if (string.IsNullOrEmpty(fn)) continue;

                // Ghost DLL: path looks real but file is gone.
                if (!File.Exists(fn) && fn.Contains('\\') && fn.Length > 4)
                {
                    var risk = isMpProcess ? RiskLevel.Critical : RiskLevel.High;
                    ctx.AddFinding(new Finding
                    {
                        Module = "Prozesse",
                        Title = $"Geladenes Modul ohne Datei auf Datentraeger: {Path.GetFileName(fn)}",
                        Risk = risk,
                        Location = fn,
                        FileName = Path.GetFileName(fn),
                        Reason = $"Das Modul '{Path.GetFileName(fn)}' ist in Prozess '{processName}' " +
                                 $"(PID {pid}) geladen, die zugehoerige Datei existiert aber nicht mehr " +
                                 "auf dem Datentraeger. Dieses 'Ghost-DLL'-Muster wird von Cheat-Loadern " +
                                 "genutzt, die die Datei nach dem Injizieren sofort loeschen, um Spuren " +
                                 "zu verwischen.",
                        Detail = $"Prozess: {processName} (PID {pid})" +
                                 (isMpProcess ? " · In Multiplayer-Framework-Prozess!" : "")
                    });
                }
            }
        }
        catch { }
    }
}
