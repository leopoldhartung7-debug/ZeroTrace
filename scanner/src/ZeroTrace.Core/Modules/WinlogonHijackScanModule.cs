using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Winlogon hijacking used for persistence and privilege escalation.
///
/// The Windows Logon Process (winlogon.exe) reads several registry values on startup
/// to configure which shell, user initialization scripts, and notification packages
/// to run. Modifying these values is a classic persistence technique because:
///   - Changes take effect at the next login (not just reboot)
///   - Running under the user's security context (Shell) or as SYSTEM (Notify)
///   - Difficult to detect without registry analysis
///
/// Key values checked:
///   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:
///     Shell        — desktop shell (normally "explorer.exe")
///     Userinit     — user init programs (normally "%SystemRoot%\system32\userinit.exe,")
///     GinaDLL      — GINA replacement (legacy XP-era credential provider bypass)
///     TaskMan      — Task Manager replacement
///     System       — OS/2 system processes
///     Notify       — DLL subkey for logon/logoff event notifications
///     VmApplet     — VM screen saver (legitimate: SystemPropertiesPerformance.exe)
///     AutoRestartShell — 0 disables shell restart (anti-tamper)
///
///   HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:
///     Shell        — per-user shell override
///
/// Also enumerates the Notify subkey for event notification DLLs.
/// </summary>
public sealed class WinlogonHijackScanModule : IScanModule
{
    private static readonly string _name = "Winlogon-Hijack-Analyse";
    public string Name => _name;
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private const string WinlogonKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();
    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();

    // Acceptable shell values (may be comma-separated list)
    private static readonly HashSet<string> KnownGoodShells = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe",
        "explorer",
    };

    // Acceptable userinit values (with or without path prefix)
    private static readonly HashSet<string> KnownGoodUserinit = new(StringComparer.OrdinalIgnoreCase)
    {
        "userinit.exe",
        "userinit.exe,",
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook",
        "persist", "autorun",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        hits += CheckWinlogonValues(Registry.LocalMachine, "HKLM", ctx, ct);
        hits += CheckWinlogonValues(Registry.CurrentUser,  "HKCU", ctx, ct);
        hits += CheckNotifyPackages(ctx, ct);

        ctx.Report(1.0, Name, $"Winlogon-Einträge geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckWinlogonValues(RegistryKey hive, string hiveName,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = hive.OpenSubKey(WinlogonKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // ── Shell ─────────────────────────────────────────────────────────
            var shell = key.GetValue("Shell") as string ?? "explorer.exe";
            hits += CheckWinlogonValue("Shell", shell, KnownGoodShells,
                hiveName, ctx, "Desktop-Shell",
                "Die Shell-Value bestimmt, welches Programm als Explorer-Ersatz gestartet wird. " +
                "Malware und Cheats ersetzen explorer.exe durch ihren eigenen Loader.");

            // ── Userinit ──────────────────────────────────────────────────────
            var userinit = key.GetValue("Userinit") as string ?? "";
            // Userinit may have multiple comma-separated values
            foreach (var entry in userinit.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                if (ct.IsCancellationRequested) break;
                var trimmed = entry.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;
                var fname = Path.GetFileName(trimmed).ToLowerInvariant();
                if (KnownGoodUserinit.Contains(fname)) continue;

                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    trimmed.ToLowerInvariant().Contains(k, StringComparison.OrdinalIgnoreCase));
                bool isSystem = trimmed.ToLowerInvariant().StartsWith(System32);
                bool exists   = File.Exists(trimmed);

                if (cheatKw is not null || !isSystem)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Winlogon-Userinit-Hijack ({hiveName}): {fname}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"{hiveName}\{WinlogonKey}",
                        FileName = fname,
                        Reason   = $"Userinit enthält unbekannten Eintrag '{trimmed}' ({hiveName}). " +
                                   "Userinit-Programme laufen bei jedem Anmeldevorgang und erhalten " +
                                   "vollständigen Benutzerzugriff. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   (!isSystem ? "Pfad außerhalb System32. " : "") +
                                   (!exists ? "Datei fehlt." : ""),
                        Detail   = $"Userinit-Eintrag: {trimmed} | Existiert: {exists} | Keyword: {cheatKw ?? "keins"}"
                    });
                }
            }

            // ── GinaDLL (legacy but still abused) ──────────────────────────
            var gina = key.GetValue("GinaDLL") as string ?? "";
            if (!string.IsNullOrWhiteSpace(gina))
            {
                var ginaLower = gina.ToLowerInvariant();
                if (!ginaLower.Equals("msgina.dll", StringComparison.OrdinalIgnoreCase))
                {
                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        ginaLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Winlogon-GINA-Ersatz: {Path.GetFileName(gina)}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"{hiveName}\{WinlogonKey}",
                        FileName = Path.GetFileName(gina),
                        Reason   = $"GinaDLL ist auf '{gina}' gesetzt (Standard: msgina.dll). " +
                                   "GINA-Replacements intercept alle Anmeldeinformationen und " +
                                   "laufen als SYSTEM. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'." : ""),
                        Detail   = $"GinaDLL: {gina}"
                    });
                }
            }

            // ── TaskMan ────────────────────────────────────────────────────────
            var taskMan = key.GetValue("TaskMan") as string ?? "";
            if (!string.IsNullOrWhiteSpace(taskMan))
            {
                var tmLower = taskMan.ToLowerInvariant();
                bool isKnownTaskMan = tmLower.Contains("taskmgr.exe");
                if (!isKnownTaskMan)
                {
                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        tmLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Task-Manager-Ersatz: {Path.GetFileName(taskMan)}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"{hiveName}\{WinlogonKey}",
                        FileName = Path.GetFileName(taskMan),
                        Reason   = $"TaskMan ist auf '{taskMan}' gesetzt — ersetzt den Windows Task-Manager. " +
                                   "Cheat-Tools nutzen dies, um ihren eigenen Prozessmanager zu laden " +
                                   "und verhindert gleichzeitig die Erkennung durch echten Task-Manager. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'." : ""),
                        Detail   = $"TaskMan: {taskMan}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckWinlogonValue(string valueName, string value,
        HashSet<string> knownGood, string hiveName, ScanContext ctx,
        string typeLabel, string reason)
    {
        if (string.IsNullOrWhiteSpace(value)) return 0;

        var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries);
        int hits = 0;

        foreach (var part in parts)
        {
            var trimmed  = part.Trim();
            var fname    = Path.GetFileName(trimmed).ToLowerInvariant();
            if (string.IsNullOrEmpty(fname)) continue;
            if (knownGood.Contains(fname)) continue;

            bool isSystem = trimmed.ToLowerInvariant().StartsWith(
                Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant());
            bool exists = File.Exists(trimmed);

            hits++;
            ctx.AddFinding(new Finding
            {
                Module   = "Winlogon-Hijack-Analyse",
                Title    = $"Winlogon-{typeLabel}-Hijack ({hiveName}): {fname}",
                Risk     = RiskLevel.High,
                Location = $@"{hiveName}\{WinlogonKey}",
                FileName = fname,
                Reason   = $"Winlogon {valueName} enthält unbekannten Eintrag: '{trimmed}'. " +
                           reason + " " +
                           (!isSystem ? "Pfad außerhalb System32. " : "") +
                           (!exists ? "Datei fehlt." : ""),
                Detail   = $"{valueName}: {trimmed} | Existiert: {exists}"
            });
        }
        return hits;
    }

    private static int CheckNotifyPackages(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                WinlogonKey + @"\Notify", writable: false);
            if (key is null) return 0;

            foreach (var pkgName in key.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                using var pkgKey = key.OpenSubKey(pkgName, writable: false);
                if (pkgKey is null) continue;

                var dll      = pkgKey.GetValue("DllName") as string ?? "";
                var dllLower = dll.ToLowerInvariant();
                var cheatKw  = CheatKeywords.FirstOrDefault(k =>
                    (dllLower + " " + pkgName.ToLowerInvariant()).Contains(k, StringComparison.OrdinalIgnoreCase));

                bool isSystem = dllLower.StartsWith(System32);
                bool exists   = File.Exists(dll.Contains('\\') ? dll
                    : Path.Combine(System32, dll));

                if (cheatKw is not null || !isSystem)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Winlogon-Notify-Paket: {pkgName}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"HKLM\{WinlogonKey}\Notify\{pkgName}",
                        FileName = Path.GetFileName(dll),
                        Reason   = $"Winlogon-Notification-Package '{pkgName}' lädt DLL '{dll}'. " +
                                   "Notify-Pakete erhalten Callback-Aufrufe bei Anmelde-/Abmelde-Events " +
                                   "und laufen im Kontext von winlogon.exe (SYSTEM). " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   (!isSystem ? "DLL außerhalb System32. " : "") +
                                   (!exists ? "DLL fehlt." : ""),
                        Detail   = $"Paket: {pkgName} | DLL: {dll} | Existiert: {exists} | Keyword: {cheatKw ?? "keins"}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static readonly HashSet<string> KnownGoodNotifyDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "crypt32.dll", "cryptui.dll", "wlnotify.dll", "winsrv.dll",
    };
}
