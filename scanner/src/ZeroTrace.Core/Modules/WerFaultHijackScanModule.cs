using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Windows Error Reporting (WER) and crash handler hijacking.
///
/// WER (Windows Error Reporting) and crash handlers are attractive hijack targets:
///
///   1. WER LocalDumps configuration: can be set to capture process memory dumps
///      when a crash occurs. Cheats abuse this to dump game/anti-cheat memory
///      legitimately by crashing the target process and having WER capture a full dump.
///
///   2. WER DontSendAdditionalData / Disabled: cheats disable WER to prevent
///      crash reports from leaking cheat presence to Microsoft.
///
///   3. WerFault.exe hijacking via IFEO: replacing the crash handler executable
///      allows cheats to be notified (and take action) whenever any process crashes.
///
///   4. ReportingWatchdog disabled: prevents WER from auto-restarting anti-cheat
///      processes that crash under the cheat's influence.
///
///   5. AeDebug (Automatic Error Debugger): HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug
///      - Debugger value: if set to a non-standard debugger path, every crash invokes
///        the cheat's tools instead of the standard JIT debugger
///      - Auto=1 means automatic JIT attach (enables process inspection on crash)
///
///   6. Local dump paths pointing to cheat-controlled locations:
///      WER LocalDumps DumpFolder configured to dump into a cheat data folder.
///
///   7. Windows Restart Manager disabled:
///      Restart Manager helps AC restart game after cheat-caused crash — disabling it
///      helps cheats persist across game crash/restart cycles.
/// </summary>
public sealed class WerFaultHijackScanModule : IScanModule
{
    public string Name => "WER-Absturzhandler-Hijacking-Analyse";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private const string WerKey =
        @"SOFTWARE\Microsoft\Windows\Windows Error Reporting";
    private const string WerLocalDumpsKey =
        @"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps";
    private const string AeDebugKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug";

    // Known cheat-related keywords in dump paths
    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "spoofer", "temp", "appdata", "public",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckWerDisabled(ctx, ct);
        hits += CheckLocalDumps(ctx, ct);
        hits += CheckAeDebug(ctx, ct);
        hits += CheckWerFaultIfeo(ctx, ct);

        ctx.Report(1.0, Name, $"WER/Crash-Handler geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckWerDisabled(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(WerKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var disabled = key.GetValue("Disabled") as int? ?? 0;
            if (disabled != 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "WER-Absturzhandler-Hijacking-Analyse",
                    Title    = "Windows Error Reporting (WER) deaktiviert",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKLM\{WerKey}",
                    Reason   = "WER ist vollständig deaktiviert (Disabled ≠ 0). " +
                               "Windows Error Reporting sendet Crash-Telemetrie an Microsoft. " +
                               "Cheat-Software deaktiviert WER, um zu verhindern, dass " +
                               "Crash-Reports mit Cheat-Inhalten an Microsoft übermittelt werden, " +
                               "und um Diagnose durch Spiel-Entwickler zu erschweren.",
                    Detail   = $"WER Disabled: {disabled}"
                });
            }

            // Check if WER is excluded from sending reports for specific processes
            using var excludedKey = Registry.LocalMachine.OpenSubKey(
                WerKey + @"\ExcludedApplications", writable: false);
            if (excludedKey is not null)
            {
                foreach (var name in excludedKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) break;
                    var val = excludedKey.GetValue(name) as int?;
                    if (val == 1)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "WER-Absturzhandler-Hijacking-Analyse",
                            Title    = $"WER-Ausnahme für Anwendung: {name}",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{WerKey}\ExcludedApplications",
                            Reason   = $"Anwendung '{name}' ist von WER ausgeschlossen — " +
                                       "Crashes werden nicht gemeldet. " +
                                       "Cheat-Loader schließen sich selbst oder ihre Ziel-Prozesse " +
                                       "aus WER aus, um Absturz-Telemetrie zu vermeiden.",
                            Detail   = $"ExcludedApplication: {name} = {val}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckLocalDumps(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(WerLocalDumpsKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var dumpFolder = key.GetValue("DumpFolder") as string ?? "";
            var dumpType = key.GetValue("DumpType") as int? ?? 1;
            var dumpCount = key.GetValue("DumpCount") as int? ?? 10;

            // DumpType 2 = Full dump (entire process memory) — suspicious for game processes
            if (dumpType == 2)
            {
                var kw = CheatKeywords.FirstOrDefault(k =>
                    dumpFolder.Contains(k, StringComparison.OrdinalIgnoreCase));

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "WER-Absturzhandler-Hijacking-Analyse",
                    Title    = "WER konfiguriert für vollständige Prozess-Memory-Dumps",
                    Risk     = kw is not null ? RiskLevel.Critical : RiskLevel.High,
                    Location = $@"HKLM\{WerLocalDumpsKey}",
                    Reason   = "WER LocalDumps DumpType = 2 (Full Dump). " +
                               "Bei jedem Prozess-Crash wird der gesamte Prozess-Speicher " +
                               "als .dmp-Datei gespeichert. " +
                               "Cheat-Operatoren können einen Crash eines Anti-Cheat-Prozesses " +
                               "provozieren und dann den vollen Memory-Dump analysieren, " +
                               "um Schutzmechanismen zu reverse-engineeren." +
                               (kw is not null ? $" Dump-Pfad enthält Cheat-Keyword '{kw}'." : "") +
                               $" Dump-Pfad: '{dumpFolder}'",
                    Detail   = $"DumpType: {dumpType} (2=Full) | DumpFolder: {dumpFolder} | " +
                               $"DumpCount: {dumpCount}"
                });
            }
        }
        catch { }

        // Check per-process dump configs
        try
        {
            var localDumpsBaseKey = Registry.LocalMachine.OpenSubKey(
                WerLocalDumpsKey, writable: false);
            if (localDumpsBaseKey is null) return hits;

            foreach (var subKeyName in localDumpsBaseKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                using var sub = localDumpsBaseKey.OpenSubKey(subKeyName, writable: false);
                if (sub is null) continue;

                var dumpType = sub.GetValue("DumpType") as int? ?? -1;
                var dumpFolder = sub.GetValue("DumpFolder") as string ?? "";

                var kw = CheatKeywords.FirstOrDefault(k =>
                    dumpFolder.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (dumpType == 2 || kw is not null)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "WER-Absturzhandler-Hijacking-Analyse",
                        Title    = $"WER Full-Dump für Prozess: {subKeyName}",
                        Risk     = kw is not null ? RiskLevel.Critical : RiskLevel.Medium,
                        Location = $@"HKLM\{WerLocalDumpsKey}\{subKeyName}",
                        Reason   = $"WER ist konfiguriert, bei Crashes von '{subKeyName}' " +
                                   $"Full-Dumps ({dumpType}) in '{dumpFolder}' zu speichern. " +
                                   (kw is not null
                                       ? $"Pfad enthält Cheat-Keyword '{kw}'. "
                                       : "") +
                                   "Full-Dumps enthalten den gesamten Prozessinhalt — " +
                                   "Anti-Cheat-Prozess-Dumps enthüllen Schutzmechanismen.",
                        Detail   = $"Prozess: {subKeyName} | DumpType: {dumpType} | " +
                                   $"DumpFolder: {dumpFolder}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckAeDebug(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(AeDebugKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var debugger = key.GetValue("Debugger") as string ?? "";
            var auto = key.GetValue("Auto") as string ?? "0";

            // Standard Windows JIT debugger paths
            bool isStandard = debugger.Contains("drwtsn32", StringComparison.OrdinalIgnoreCase) ||
                              debugger.Contains("vsjitdebugger", StringComparison.OrdinalIgnoreCase) ||
                              debugger.Contains("WerFault", StringComparison.OrdinalIgnoreCase) ||
                              string.IsNullOrEmpty(debugger);

            if (!isStandard)
            {
                var kw = CheatKeywords.FirstOrDefault(k =>
                    debugger.Contains(k, StringComparison.OrdinalIgnoreCase));

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "WER-Absturzhandler-Hijacking-Analyse",
                    Title    = "AeDebug: Unbekannter automatischer Crash-Debugger",
                    Risk     = kw is not null ? RiskLevel.Critical : RiskLevel.High,
                    Location = $@"HKLM\{AeDebugKey}",
                    Reason   = $"AeDebug-Debugger ist auf '{debugger}' gesetzt — " +
                               "kein Standard-Windows-JIT-Debugger. " +
                               "Wenn ein Prozess abstürzt, wird dieser Debugger automatisch " +
                               "aufgerufen und erhält Zugriff auf den Crash-Dump und den Prozess. " +
                               "Cheat-Tools registrieren sich hier, um bei Crashes von " +
                               "Anti-Cheat-Prozessen benachrichtigt zu werden." +
                               (kw is not null ? $" Debugger-Pfad enthält Keyword '{kw}'." : ""),
                    Detail   = $"Debugger: {debugger} | Auto: {auto}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckWerFaultIfeo(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check if WerFault.exe itself has been hijacked via IFEO
            using var ifeoKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WerFault.exe",
                writable: false);
            if (ifeoKey is null) return 0;
            ctx.IncrementRegistryKeys();

            var debuggerVal = ifeoKey.GetValue("Debugger") as string ?? "";
            if (!string.IsNullOrEmpty(debuggerVal))
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "WER-Absturzhandler-Hijacking-Analyse",
                    Title    = "WerFault.exe über IFEO umgeleitet",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WerFault.exe",
                    Reason   = $"WerFault.exe hat einen IFEO-Debugger-Eintrag: '{debuggerVal}'. " +
                               "Wenn WerFault.exe (der Windows-Crash-Handler) startet, " +
                               "wird stattdessen dieser Prozess aufgerufen. " +
                               "Dies ist ein klassischer IFEO-Hijack: die Cheat-Software " +
                               "erhält Kontrolle über alle Crash-Handler-Aktivierungen " +
                               "und kann dabei Prozess-Dumps stehlen oder AC-Restarts verhindern.",
                    Detail   = $"IFEO Debugger für WerFault.exe: {debuggerVal}"
                });
            }
        }
        catch { }
        return hits;
    }
}
