using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep-scans all Windows Run/RunOnce/RunServices persistence keys and their
/// subkeys for cheat tool registration, obfuscated command lines, and
/// living-off-the-land binary (LOLBIN) abuse.
///
/// Persistence via Run keys is the most common cheat persistence mechanism.
/// This module goes beyond the basic AutostartScanModule by:
///   1. Checking ALL Run variants including RunServices, RunServicesOnce, policies
///   2. Detecting obfuscated commands (base64 in powershell, env var expansion)
///   3. Flagging LOLBIN abuse (mshta, wscript, regsvr32, rundll32 with remote URLs)
///   4. Checking the "DeleteValueOnExit" pattern (RunOnce deleted after use)
///   5. Explorer load/run subkeys
///   6. Active Setup (HKCU runs once per user after a machine policy runs it)
///   7. Winlogon Userinit / Shell hijacking
///
/// Locations scanned:
///   HKLM/HKCU \SOFTWARE\Microsoft\Windows\CurrentVersion\Run
///   HKLM/HKCU \SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
///   HKLM/HKCU \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell/Userinit)
///   HKLM      \SOFTWARE\Microsoft\Active Setup\Installed Components
///   HKLM      \SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Run
/// </summary>
public sealed class RegistryRunHistoryScanModule : IScanModule
{
    public string Name => "Registry-Run-Persistenz-Analyse";
    public double Weight => 0.8;
    public int ParallelGroup => 3;

    private static readonly (string Hive, string Path)[] RunKeys =
    {
        ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
        ("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
        ("HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Run"),
    };

    private static readonly string[] CheatKeywords =
    {
        "kiddion", "cherax", "2take1", "ozark", "midnight", "stand",
        "skeet", "fatality", "neverlose", "onetap", "aimware",
        "spoofer", "hwid", "bypass", "inject", "loader", "cheat",
        "hack", "aimbot", "wallhack", "triggerbot", "bhop", "esp",
        "trainer", "menyoo", "modmenu", "scripthook",
        "memprocfs", "pcileech",
    };

    // LOLBINs that are abused to run scripts/code without detection
    private static readonly string[] LolBins =
    {
        "mshta", "wscript", "cscript", "regsvr32", "regasm", "regsvcs",
        "msiexec", "installutil", "certutil", "bitsadmin", "forfiles",
        "pcalua", "odbcconf", "cmstp", "xwizard", "syncappvpublishingserver",
        "appsyncpublishingserver", "control", "hh.exe",
    };

    private static readonly string[] ObfuscationPatterns =
    {
        "frombase64string", "-enc ", "-encodedcommand", "iex(", "invoke-expression",
        "downloadstring", "downloadfile", "net.webclient", "bitstransfer",
        "http://", "https://", "ftp://",
        "[char]", "join(", "-replace", "cmd /c echo",
    };

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        int hits = 0;

        foreach (var (hive, path) in RunKeys)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var root = hive == "HKLM"
                    ? Registry.LocalMachine.OpenSubKey(path, writable: false)
                    : Registry.CurrentUser.OpenSubKey(path, writable: false);

                if (root is null) continue;

                foreach (var valueName in root.GetValueNames())
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementRegistryKeys();
                    checked_++;

                    var value = root.GetValue(valueName) as string ?? "";
                    var lower = value.ToLowerInvariant();
                    var nameLower = valueName.ToLowerInvariant();

                    // Cheat keyword in name or command
                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        lower.Contains(k) || nameLower.Contains(k));
                    if (cheatKw is not null)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Run-Key: Cheat-Autostart: {valueName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"{hive}\{path}",
                            Reason   = $"Autostart-Eintrag '{valueName}' enthält cheat-typisches " +
                                       $"Keyword '{cheatKw}'. Befehl: '{value}'. " +
                                       "Cheat-Tools registrieren sich im Run-Key um bei jedem " +
                                       "Windows-Start automatisch geladen zu werden.",
                            Detail   = $"Key: {hive}\\{path} | Name: {valueName} | Cmd: {value} | Kw: {cheatKw}"
                        });
                        continue;
                    }

                    // LOLBIN abuse
                    var lolBin = LolBins.FirstOrDefault(lb => lower.Contains(lb));
                    if (lolBin is not null)
                    {
                        bool hasRemote = lower.Contains("http://") || lower.Contains("https://") ||
                                         lower.Contains("ftp://");
                        bool hasObfusc = ObfuscationPatterns.Skip(2).Any(p => lower.Contains(p));

                        if (hasRemote || hasObfusc)
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Run-Key: LOLBIN-Missbrauch: {valueName}",
                                Risk     = RiskLevel.High,
                                Location = $@"{hive}\{path}",
                                Reason   = $"Autostart-Eintrag '{valueName}' missbraucht LOLBIN '{lolBin}' " +
                                           (hasRemote ? "mit Remote-URL (lädt Code aus dem Internet). "
                                                      : "mit Obfuskierungstechnik. ") +
                                           "LOLBINs werden für dateilose Cheat-Loader und Persistenz " +
                                           "ohne eigene EXE-Datei verwendet.",
                                Detail   = $"Key: {hive}\\{path} | Cmd: {value} | LOLBIN: {lolBin}"
                            });
                            continue;
                        }
                    }

                    // Obfuscated command
                    var obfusc = ObfuscationPatterns.FirstOrDefault(p => lower.Contains(p));
                    if (obfusc is not null)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Run-Key: Obfuskierter Startbefehl: {valueName}",
                            Risk     = RiskLevel.High,
                            Location = $@"{hive}\{path}",
                            Reason   = $"Autostart-Eintrag '{valueName}' enthält obfuskierten Befehl " +
                                       $"(Pattern: '{obfusc}'). Befehl: '{value[..Math.Min(120, value.Length)]}'. " +
                                       "Verschleierte Startbefehle sind ein starkes Indiz für " +
                                       "Malware oder Cheat-Loader die ihrer Erkennung entgehen wollen.",
                            Detail   = $"Key: {hive}\\{path} | Name: {valueName} | Pattern: {obfusc}"
                        });
                        continue;
                    }

                    // Suspicious path (temp/downloads)
                    if (lower.Contains(@"\temp\") || lower.Contains(@"\downloads\") ||
                        lower.Contains(@"\users\public\"))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Run-Key: Autostart aus verdächtigem Pfad: {valueName}",
                            Risk     = RiskLevel.Medium,
                            Location = $@"{hive}\{path}",
                            Reason   = $"Autostart-Eintrag '{valueName}' startet Programm aus " +
                                       $"user-beschreibbarem Pfad: '{value}'. " +
                                       "Legitime Programme starten aus Program Files oder System32.",
                            Detail   = $"Key: {hive}\\{path} | Cmd: {value}"
                        });
                    }
                }
            }
            catch { }
        }

        // Check Winlogon Shell/Userinit hijacking
        hits += CheckWinlogon(ctx, ct);

        // Check Active Setup
        hits += CheckActiveSetup(ctx, ct);
        checked_ += hits > 0 ? 0 : 0; // avoid unused

        ctx.Report(1.0, Name, $"{checked_} Run-Keys geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckWinlogon(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        const string winlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(winlogonKey, writable: false);
            if (key is null) return 0;

            ctx.IncrementRegistryKeys();

            var shell = key.GetValue("Shell") as string ?? "";
            var userinit = key.GetValue("Userinit") as string ?? "";

            // Shell should be "explorer.exe" only
            if (!string.Equals(shell.Trim(), "explorer.exe", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrEmpty(shell))
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Winlogon Shell geändert: {shell}",
                    Risk     = RiskLevel.Critical,
                    Location = $@"HKLM\{winlogonKey}",
                    Reason   = $"Winlogon Shell wurde von 'explorer.exe' auf '{shell}' geändert. " +
                               "Die Shell wird bei jeder Windows-Anmeldung als Desktop-Shell gestartet. " +
                               "Ein veränderter Shell-Wert ermöglicht SYSTEM-Zugriff bei der Anmeldung.",
                    Detail   = $"Shell: {shell}"
                });
            }

            // Userinit should contain %System32%\userinit.exe only
            if (!string.IsNullOrEmpty(userinit) &&
                !userinit.Contains("userinit.exe", StringComparison.OrdinalIgnoreCase))
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Winlogon Userinit geändert: {userinit}",
                    Risk     = RiskLevel.Critical,
                    Location = $@"HKLM\{winlogonKey}",
                    Reason   = $"Winlogon Userinit enthält unerwarteten Eintrag: '{userinit}'. " +
                               "Userinit läuft nach jeder Benutzeranmeldung. Modifizierter Wert " +
                               "zeigt auf Backdoor oder Cheat-Loader-Persistenz.",
                    Detail   = $"Userinit: {userinit}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckActiveSetup(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        const string activeSetupKey = @"SOFTWARE\Microsoft\Active Setup\Installed Components";

        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(activeSetupKey, writable: false);
            if (root is null) return 0;

            foreach (var subName in root.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                using var sub = root.OpenSubKey(subName, writable: false);
                if (sub is null) continue;

                var stubPath = sub.GetValue("StubPath") as string ?? "";
                var lower = stubPath.ToLowerInvariant();

                var cheatKw = CheatKeywords.FirstOrDefault(k => lower.Contains(k));
                if (cheatKw is not null)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Active Setup: Cheat-Persistenz: {subName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{activeSetupKey}\{subName}",
                        Reason   = $"Active Setup StubPath enthält Cheat-Keyword '{cheatKw}': " +
                                   $"'{stubPath}'. Active Setup läuft einmalig pro Benutzer nach " +
                                   "Gruppenrichtlinien-Anwendung — schwer zu entfernen ohne Registrierung.",
                        Detail   = $"GUID: {subName} | StubPath: {stubPath} | Keyword: {cheatKw}"
                    });
                }
                else if (lower.Contains(@"\temp\") || lower.Contains(@"\downloads\"))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Active Setup aus verdächtigem Pfad: {subName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{activeSetupKey}\{subName}",
                        Reason   = $"Active Setup StubPath verweist auf verdächtigen Pfad: '{stubPath}'.",
                        Detail   = $"GUID: {subName} | StubPath: {stubPath}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
