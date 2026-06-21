using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using Microsoft.Win32;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Inspects well-documented registry persistence/hijack locations for anomalies:
/// AppInit_DLLs, Winlogon Shell/Userinit, and Image File Execution Options
/// debuggers. Also applies registry-value keyword indicators. Every finding
/// states the expected baseline so the operator can judge deviations.
/// </summary>
public sealed class RegistryScanModule : IScanModule
{
    public string Name => "Registry";
    public double Weight => 0.5;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        CheckAppInitDlls(ctx);
        ctx.Report(0.15, "AppInit_DLLs", "AppInit-Pruefung abgeschlossen");

        CheckWinlogon(ctx);
        ctx.Report(0.30, "Winlogon", "Winlogon-Pruefung abgeschlossen");

        CheckImageFileExecutionOptions(ctx, ct);
        ctx.Report(0.50, "IFEO", "Image File Execution Options geprueft");

        CheckLsaProviders(ctx);
        ctx.Report(0.65, "LSA", "LSA-Provider geprueft");

        CheckBootExecute(ctx);
        ctx.Report(0.75, "BootExecute", "Boot-Ausfuehrung geprueft");

        CheckSilentProcessExit(ctx, ct);
        ctx.Report(0.87, "SilentExit", "Prozessbeendigungs-Hijack geprueft");

        CheckComHijacking(ctx, ct);
        ctx.Report(1.0, "COM-Hijack", "COM-Objekt-Ueberschreibungen geprueft");

        return Task.CompletedTask;
    }

    private void CheckAppInitDlls(ScanContext ctx)
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = baseKey.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                var appInit = key.GetValue("AppInit_DLLs")?.ToString();
                if (!string.IsNullOrWhiteSpace(appInit))
                {
                    ctx.AddFinding(new Finding
                    {
                        Title = "AppInit_DLLs ist gesetzt",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\...\Windows NT\CurrentVersion\Windows\AppInit_DLLs",
                        Reason = "AppInit_DLLs laedt DLLs in nahezu jeden Prozess. Erwartet ist ein " +
                                 "leerer Wert; ein Eintrag ist ein klassischer Injection-Mechanismus.",
                        Detail = appInit
                    });
                }
            }
            catch { }
        }
    }

    private void CheckWinlogon(ScanContext ctx)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            var shell = key.GetValue("Shell")?.ToString();
            if (!string.IsNullOrWhiteSpace(shell) &&
                !shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Title = "Winlogon Shell weicht vom Standard ab",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\...\Winlogon\Shell",
                    Reason = "Erwartet ist 'explorer.exe'. Ein abweichender Wert kann eine " +
                             "Persistenz-/Startmanipulation sein.",
                    Detail = shell
                });
            }

            var userinit = key.GetValue("Userinit")?.ToString();
            if (!string.IsNullOrWhiteSpace(userinit) &&
                !userinit.Contains("userinit.exe", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Title = "Winlogon Userinit weicht vom Standard ab",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\...\Winlogon\Userinit",
                    Reason = "Erwartet ist ein Verweis auf 'userinit.exe'. Abweichungen sind " +
                             "verdaechtig.",
                    Detail = userinit
                });
            }
        }
        catch { }
    }

    private void CheckImageFileExecutionOptions(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var ifeo = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            if (ifeo is null) return;

            foreach (var subName in ifeo.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var sub = ifeo.OpenSubKey(subName);
                if (sub is null) continue;
                ctx.IncrementRegistryKeys();

                var debugger = sub.GetValue("Debugger")?.ToString();
                if (!string.IsNullOrWhiteSpace(debugger))
                {
                    var kwHit = ctx.Matcher.MatchRegistryKeyword(debugger);
                    ctx.AddFinding(new Finding
                    {
                        Title = $"IFEO-Debugger gesetzt fuer {subName}",
                        Risk = kwHit?.Risk ?? RiskLevel.High,
                        Location = $@"HKLM\...\Image File Execution Options\{subName}\Debugger",
                        Reason = "Ein 'Debugger'-Wert hier kapert den Start des genannten Programms. " +
                                 "Selten legitim ausserhalb von Entwicklungs-Setups." +
                                 (kwHit is null ? "" : $" Indikator '{kwHit.Pattern}': {kwHit.Description}"),
                        Detail = debugger
                    });
                }
            }
        }
        catch { }
    }

    // LSA Security/Authentication packages — DLL injection into lsass.exe
    private void CheckLsaProviders(ScanContext ctx)
    {
        // Default Security Packages vary by Windows build, but typically include
        // kerberos, msv1_0, schannel, wdigest. Any custom DLL here is loaded into
        // lsass and can read all credentials: high risk.
        var lsaValues = new[]
        {
            (@"SYSTEM\CurrentControlSet\Control\Lsa", "Security Packages",
             new[] { "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "" }),
            (@"SYSTEM\CurrentControlSet\Control\Lsa", "Authentication Packages",
             new[] { "msv1_0", "" }),
        };

        foreach (var (keyPath, valueName, defaults) in lsaValues)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var key = baseKey.OpenSubKey(keyPath);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                var raw = key.GetValue(valueName);
                var packages = raw is string[] arr ? arr : (raw?.ToString() ?? "").Split('\0');
                var nonDefault = packages
                    .Select(p => p.Trim())
                    .Where(p => p.Length > 0 && !defaults.Contains(p, StringComparer.OrdinalIgnoreCase))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                foreach (var pkg in nonDefault)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unbekannter LSA-Provider: {pkg}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{keyPath}\{valueName}",
                        Reason = $"Der LSA-Provider '{pkg}' ist nicht im bekannten Standard-Satz. " +
                                 "Dieser Wert laedt eine DLL in lsass.exe und kann alle Anmeldedaten " +
                                 "abgreifen. Sehr seltener Legitim-Fall ausserhalb von Unternehmens-SSO.",
                        Detail = pkg
                    });
                }
            }
            catch { }
        }
    }

    // BootExecute — native programs that run before Windows boots
    private void CheckBootExecute(ScanContext ctx)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var key = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager");
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            var raw = key.GetValue("BootExecute");
            var entries = raw is string[] arr ? arr : (raw?.ToString() ?? "").Split('\0');

            foreach (var entry in entries)
            {
                var e = entry.Trim();
                if (e.Length == 0) continue;
                // The only expected default is "autocheck autochk *"
                if (e.Equals("autocheck autochk *", StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Unbekannter BootExecute-Eintrag",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\...\Session Manager\BootExecute",
                    Reason = $"Der BootExecute-Wert '{e}' weicht vom Standard ab. " +
                             "BootExecute-Programme laufen im nativen Modus noch vor dem " +
                             "Windows-Subsystem – ideal fuer tiefe Persistenz.",
                    Detail = e
                });
            }
        }
        catch { }
    }

    // SilentProcessExit — process-exit monitoring used to launch a payload when a target exits
    private void CheckSilentProcessExit(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var spe = baseKey.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit");
            if (spe is null) return;

            foreach (var procName in spe.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var sub = spe.OpenSubKey(procName);
                if (sub is null) continue;
                ctx.IncrementRegistryKeys();

                var monitor = sub.GetValue("MonitorProcess")?.ToString();
                if (string.IsNullOrWhiteSpace(monitor)) continue;

                var kwHit = ctx.Matcher.MatchRegistryKeyword(monitor)
                            ?? ctx.Matcher.MatchPathKeyword(monitor)
                            ?? ctx.Matcher.MatchFileNameKeyword(Path.GetFileName(monitor));

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"SilentProcessExit-Hijack fuer {procName}",
                    Risk = kwHit?.Risk ?? RiskLevel.High,
                    Location = $@"HKLM\...\SilentProcessExit\{procName}\MonitorProcess",
                    Reason = $"Wenn '{procName}' beendet wird, startet Windows automatisch " +
                             $"'{monitor}'. Das ist ein wenig bekannter Persistenz-Mechanismus." +
                             (kwHit is null ? "" : $" Indikator '{kwHit.Pattern}': {kwHit.Description}"),
                    Detail = $"MonitorProcess: {monitor}"
                });
            }
        }
        catch { }
    }

    // COM object hijacking — HKCU overrides HKLM COM server registrations
    private void CheckComHijacking(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var hkcu = Registry.CurrentUser.OpenSubKey(@"Software\Classes\CLSID");
            if (hkcu is null) return;

            int checked_ = 0;
            foreach (var clsid in hkcu.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                if (++checked_ > 500) break; // bound the scan

                using var sub = hkcu.OpenSubKey(clsid);
                if (sub is null) continue;

                // Look for an InprocServer32 or LocalServer32 pointing to a real file
                string? server = null;
                foreach (var serverKey in new[] { "InprocServer32", "LocalServer32" })
                {
                    using var sk = sub.OpenSubKey(serverKey);
                    var val = sk?.GetValue(null)?.ToString()   // default value
                              ?? sk?.GetValue("(Default)")?.ToString();
                    if (!string.IsNullOrWhiteSpace(val)) { server = val; break; }
                }
                if (string.IsNullOrWhiteSpace(server)) continue;

                // Only flag if the path is in a user-writable location
                var expanded = Environment.ExpandEnvironmentVariables(server!).Trim('"');
                if (!Detection.Heuristics.IsInUserWritableRoot(expanded)) continue;

                ctx.IncrementRegistryKeys();
                var kwHit = ctx.Matcher.MatchPathKeyword(expanded)
                            ?? ctx.Matcher.MatchFileNameKeyword(Path.GetFileName(expanded));

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "COM-Objekt-Hijacking (HKCU ueberschreibt System-CLSID)",
                    Risk = kwHit?.Risk ?? RiskLevel.Medium,
                    Location = $@"HKCU\Software\Classes\CLSID\{clsid}",
                    Reason = $"Eine benutzer-seitige COM-Server-Registrierung ({clsid}) zeigt auf " +
                             $"'{expanded}' in einem beschreibbaren Pfad. HKCU-Registrierungen " +
                             "ueberschreiben System-CLSIDs und sind ein haeufiger Persistenz-Trick." +
                             (kwHit is null ? "" : $" Indikator '{kwHit.Pattern}': {kwHit.Description}"),
                    Detail = $"CLSID: {clsid} · Server: {expanded}"
                });
            }
        }
        catch { }
    }
}
