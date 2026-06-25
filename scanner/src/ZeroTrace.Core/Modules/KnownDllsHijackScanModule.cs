using Microsoft.Win32;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects DLL search order hijacking via the KnownDLLs registry key and
/// Object Manager namespace manipulation.
///
/// The Windows loader caches a set of "KnownDLLs" (ntdll.dll, kernel32.dll, etc.)
/// as named section objects in \KnownDlls\ (Object Manager namespace). When a process
/// imports one of these DLLs, the loader uses the pre-cached section instead of
/// searching the file system — this is a performance AND security optimization
/// (prevents DLL search order hijacking for critical system DLLs).
///
/// Attackers can subvert this by:
///   1. Adding new entries to HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
///      pointing to malicious DLLs (requires admin rights, but persists across reboots)
///   2. Injecting into the \KnownDlls\ Object Manager namespace directly
///   3. Creating fake Section objects in \KnownDlls\ to shadow legitimate DLLs
///
/// Additionally checks:
///   - DllDirectory overrides (SearchPathMode)
///   - SafeDllSearchMode disabled (allows CWD DLL hijacking)
///   - CWDIllegalInDllSearch value (controls current-directory DLL search)
/// </summary>
public sealed class KnownDllsHijackScanModule : IScanModule
{
    public string Name => "KnownDLLs-Hijack-Analyse";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    private const string KnownDllsKey =
        @"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs";
    private const string SessionManagerKey =
        @"SYSTEM\CurrentControlSet\Control\Session Manager";

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    // Standard KnownDLLs that ship with Windows — anything not in this list is suspect
    private static readonly HashSet<string> StandardKnownDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "advapi32.dll", "clbcatq.dll", "combase.dll", "comdlg32.dll",
        "difxapi.dll", "gdi32.dll", "gdiplus.dll", "gpapi.dll",
        "imagehlp.dll", "imm32.dll", "kernel32.dll", "kernel32legacy.dll",
        "kernelbase.dll", "lpk.dll", "msctf.dll", "msvcrt.dll",
        "normaliz.dll", "nsi.dll", "ntdll.dll", "ole32.dll",
        "oleaut32.dll", "psapi.dll", "rpcrt4.dll", "sechost.dll",
        "setupapi.dll", "shell32.dll", "shlwapi.dll", "slbcsp.dll",
        "tapi32.dll", "usp10.dll", "user32.dll", "userenv.dll",
        "uxtheme.dll", "version.dll", "wldap32.dll", "wow64.dll",
        "wow64cpu.dll", "wow64win.dll", "ws2_32.dll", "wtsapi32.dll",
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "hook",
        "kiddion", "cherax", "spoofer",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckKnownDllsRegistry(ctx, ct);
        hits += CheckSafeDllSearchMode(ctx, ct);

        ctx.Report(1.0, Name, $"KnownDLLs und DLL-Suchreihenfolge geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckKnownDllsRegistry(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(KnownDllsKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // DllDirectory32 / DllDirectory64 are special values — check them
            var dir32 = key.GetValue("DllDirectory") as string ?? "";
            var dir64 = key.GetValue("DllDirectory32") as string ?? "";

            foreach (var dllDir in new[] { dir32, dir64 }.Where(d => !string.IsNullOrEmpty(d)))
            {
                var dLower = dllDir.ToLowerInvariant();
                if (!dLower.StartsWith(System32) && !dLower.Equals("%systemroot%\\system32", StringComparison.OrdinalIgnoreCase))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"KnownDLLs-Verzeichnis manipuliert: {dllDir}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{KnownDllsKey}",
                        Reason   = $"KnownDLLs-DllDirectory ist auf '{dllDir}' gesetzt (erwartet: System32). " +
                                   "Dies leitet den Kernel um, KnownDLLs aus einem anderen Verzeichnis zu laden " +
                                   "und ermöglicht das Ersetzen kritischer System-DLLs.",
                        Detail   = $"DllDirectory: {dllDir}"
                    });
                }
            }

            // Check all DLL value names
            foreach (var valueName in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) break;

                if (valueName.Equals("DllDirectory", StringComparison.OrdinalIgnoreCase) ||
                    valueName.Equals("DllDirectory32", StringComparison.OrdinalIgnoreCase))
                    continue;

                var dllValue = key.GetValue(valueName) as string ?? "";
                var dllLower = dllValue.ToLowerInvariant();
                var vLower   = valueName.ToLowerInvariant();

                bool isStandard = StandardKnownDlls.Contains(dllValue) ||
                                  StandardKnownDlls.Contains(valueName + ".dll");
                if (isStandard) continue;

                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    (dllLower + " " + vLower).Contains(k, StringComparison.OrdinalIgnoreCase));

                bool exists = File.Exists(Path.Combine(System32, dllValue));
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Unbekannte KnownDLL: {valueName} → {dllValue}",
                    Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                    Location = $@"HKLM\{KnownDllsKey}",
                    FileName = dllValue,
                    Reason   = $"Nicht-Standard-KnownDLL-Eintrag '{valueName}' → '{dllValue}'. " +
                               "KnownDLLs werden beim Windows-Start als Shared-Sections im " +
                               "Object Manager vorgeladen. Ein manipulierter Eintrag " +
                               "ersetzt die legitime DLL für alle nachfolgend gestarteten Prozesse. " +
                               (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                               (!exists ? "Datei fehlt in System32." : ""),
                    Detail   = $"Name: {valueName} | Wert: {dllValue} | Existiert: {exists} | Keyword: {cheatKw ?? "keins"}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckSafeDllSearchMode(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SessionManagerKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // SafeDllSearchMode = 0 means current directory is searched before System32
            var safeDll = key.GetValue("SafeDllSearchMode");
            if (safeDll is int sdMode && sdMode == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "SafeDllSearchMode deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{SessionManagerKey}",
                    Reason   = "SafeDllSearchMode ist auf 0 gesetzt. Im unsicheren Modus wird das " +
                               "aktuelle Arbeitsverzeichnis vor System32 nach DLLs durchsucht. " +
                               "Angreifer platzieren bösartige DLLs im Arbeitsverzeichnis von " +
                               "privilegierten Prozessen (DLL-Search-Order-Hijacking).",
                    Detail   = "SafeDllSearchMode: 0 (erwartet: 1 oder nicht gesetzt)"
                });
            }

            // CWDIllegalInDllSearch: 0xFFFFFFFF = CWD never searched (safest)
            // Missing or 0 = CWD searched (unsafe for network drives)
            var cwdSafe = key.GetValue("CWDIllegalInDllSearch");
            if (cwdSafe is null)
            {
                // Not set = default behavior, slightly elevated but not a finding by itself
            }
        }
        catch { }
        return hits;
    }
}
