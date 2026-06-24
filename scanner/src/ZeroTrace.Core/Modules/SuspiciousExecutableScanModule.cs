using System.Diagnostics;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects unknown/private cheats by looking at WHERE processes run from and
/// WHETHER their executable is digitally signed — not what they are named.
///
/// Strategy:
///  1. Walk all running processes and flag any that execute from user-writable
///     directories (Downloads, Temp, AppData, Desktop, Documents) AND carry no
///     Authenticode signature.  Legitimate software virtually always ships signed;
///     private cheats never bother.
///  2. Flag process masquerading: a process using the same name as a known
///     Windows system binary but running from outside its expected directory.
///
/// Requires the process list (no special privileges beyond what a normal user has).
/// Access-denied and unavailable processes are silently skipped.
/// </summary>
public sealed class SuspiciousExecutableScanModule : IScanModule
{
    public string Name => "Unsignierte Prozesse";
    public double Weight => 0.7;

    private static readonly string[] SystemBinaries =
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
        "services.exe", "smss.exe", "wininit.exe", "taskhost.exe",
        "taskhostw.exe", "spoolsv.exe", "explorer.exe", "dwm.exe",
        "conhost.exe", "rundll32.exe", "regsvr32.exe",
    };

    private static readonly string System32 =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    private static readonly string SysWow64 =
        System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

    private static readonly string[] SuspiciousRoots;

    static SuspiciousExecutableScanModule()
    {
        var user   = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appR   = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local  = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp   = System.IO.Path.GetTempPath();

        SuspiciousRoots = new[]
        {
            System.IO.Path.Combine(user, "Downloads"),
            System.IO.Path.Combine(user, "Desktop"),
            System.IO.Path.Combine(user, "Documents"),
            appR,
            local,
            temp,
        };
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0, unsigned = 0, masq = 0;

        var processes = Process.GetProcesses();
        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            checked_++;

            string path = "";
            string name = "";
            try
            {
                name = proc.ProcessName + ".exe";
                path = proc.MainModule?.FileName ?? "";
            }
            catch { proc.Dispose(); continue; }

            if (string.IsNullOrEmpty(path)) { proc.Dispose(); continue; }

            // ── Check 1: process masquerading as a Windows binary ─────────────
            var lowerName = System.IO.Path.GetFileName(path).ToLowerInvariant();
            if (SystemBinaries.Any(b => b.Equals(lowerName, StringComparison.OrdinalIgnoreCase)))
            {
                var dir = System.IO.Path.GetDirectoryName(path) ?? "";
                bool inSystem = dir.StartsWith(System32, StringComparison.OrdinalIgnoreCase)
                             || dir.StartsWith(SysWow64, StringComparison.OrdinalIgnoreCase);
                if (!inSystem)
                {
                    masq++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Prozess-Masquerade: {lowerName}",
                        Risk     = RiskLevel.Critical,
                        Location = path,
                        FileName = lowerName,
                        Reason   = $"Prozess '{lowerName}' laeuft aus '{dir}' statt aus System32 — " +
                                   "klassisches Masquerade-Muster fuer Malware und Injektions-Launcher.",
                    });
                }
                proc.Dispose();
                continue;
            }

            // ── Check 2: unsigned binary in a user-writable location ──────────
            if (!IsInSuspiciousRoot(path)) { proc.Dispose(); continue; }
            if (HasAuthenticode(path)) { proc.Dispose(); continue; }

            unsigned++;
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Unsignierter Prozess aus User-Verzeichnis: {name}",
                Risk     = RiskLevel.High,
                Location = path,
                FileName = name,
                Reason   = $"Prozess '{name}' laeuft aus einem Benutzerverzeichnis ('{path}') " +
                           "und besitzt keine digitale Signatur. " +
                           "Private/unbekannte Cheats sind fast nie code-signiert und starten haeufig aus Temp/Downloads.",
                Detail   = $"Prozess-ID: {proc.Id}",
            });

            proc.Dispose();
        }

        ctx.Report(1.0, "Unsignierte Prozesse",
            $"{checked_} Prozesse geprueft, {unsigned} unsigniert in User-Pfaden, {masq} Masquerade");
        return Task.CompletedTask;
    }

    private static bool IsInSuspiciousRoot(string path)
    {
        foreach (var root in SuspiciousRoots)
        {
            if (!string.IsNullOrEmpty(root) &&
                path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool HasAuthenticode(string path) =>
        SignatureChecker.CheckDetailed(path).HasSignature;
}
