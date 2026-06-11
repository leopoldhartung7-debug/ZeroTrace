using System.Diagnostics;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;

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
}
