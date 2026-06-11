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
        ctx.Report(0.33, "AppInit_DLLs", "AppInit-Pruefung abgeschlossen");

        CheckWinlogon(ctx);
        ctx.Report(0.66, "Winlogon", "Winlogon-Pruefung abgeschlossen");

        CheckImageFileExecutionOptions(ctx, ct);
        ctx.Report(1.0, "IFEO", "Image File Execution Options geprueft");

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
}
