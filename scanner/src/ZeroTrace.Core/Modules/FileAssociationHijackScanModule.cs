using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects file association and shell command hijacking.
///
/// Windows shell (explorer.exe) uses registry file associations to determine which
/// program opens which file type. Attackers hijack these associations to:
///   1. Intercept execution: When user double-clicks .exe, their malicious launcher
///      runs first (then optionally launches the real program)
///   2. Cheat loader injection: Associate .exe files with a loader that injects DLLs
///      before launching the game
///   3. Script execution: Associate script extensions with malicious interpreters
///   4. Persistence: Every time the associated file type is opened, malware runs
///
/// Registry locations checked:
///   HKCU\SOFTWARE\Classes\{ext}\shell\open\command  (user-level, no admin needed)
///   HKLM\SOFTWARE\Classes\{ext}\shell\open\command  (system-level)
///   HKCU\SOFTWARE\Classes\exefile\shell\open\command (hijacks ALL .exe execution!)
///   HKLM\SOFTWARE\Classes\Applications\{exe}\shell\open\command
///
/// Critical hijacks:
///   - exefile\shell\open\command: intercepts every EXE launch on the system
///   - batfile, cmdfile, comfile: intercepts command execution
///   - piffile, lnkfile: intercepts shortcut execution
///   - ps1file, vbsfile, jsfile: intercepts script execution
/// </summary>
public sealed class FileAssociationHijackScanModule : IScanModule
{
    public string Name => "Dateiverknüpfungs-Hijack";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();
    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();

    // File type ProgIDs and their expected default open command patterns
    private static readonly Dictionary<string, string> CriticalFileTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        // Executable types — hijacking these intercepts all execution
        ["exefile"]   = "explorer.exe",     // "exefile" = .exe files
        ["comfile"]   = "comfile",           // .com files
        ["batfile"]   = "cmd.exe",           // .bat files
        ["cmdfile"]   = "cmd.exe",           // .cmd files
        ["piffile"]   = "piffile",           // .pif files
        // Script types
        ["vbsfile"]   = "wscript.exe",
        ["vbeFile"]   = "wscript.exe",
        ["jsfile"]    = "wscript.exe",
        ["jseFile"]   = "wscript.exe",
        ["wsffile"]   = "wscript.exe",
        ["ps1file"]   = "powershell.exe",
        // Shortcut
        ["lnkfile"]   = "shell32.dll",
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet",
        "spoofer", "hook", "gta", "fivem", "tarkov",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        // Check critical file type associations in HKCU (no admin, highest risk)
        hits += CheckFileAssociations(Registry.CurrentUser, "HKCU",
            @"SOFTWARE\Classes", ctx, ct);

        // Check HKLM as well
        hits += CheckFileAssociations(Registry.LocalMachine, "HKLM",
            @"SOFTWARE\Classes", ctx, ct);

        // Special: check the exefile ProgID override directly (most critical)
        hits += CheckExefileHijack(ctx, ct);

        ctx.Report(1.0, Name, $"Dateiverknüpfungen geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckFileAssociations(RegistryKey hive, string hiveName,
        string classesPath, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var classesKey = hive.OpenSubKey(classesPath, writable: false);
            if (classesKey is null) return 0;

            foreach (var (progId, _) in CriticalFileTypes)
            {
                if (ct.IsCancellationRequested) break;

                using var progKey = classesKey.OpenSubKey(
                    $@"{progId}\shell\open\command", writable: false);
                if (progKey is null) continue;
                ctx.IncrementRegistryKeys();

                var command = progKey.GetValue(null) as string ?? "";
                if (string.IsNullOrWhiteSpace(command)) continue;

                var cmdLower = command.ToLowerInvariant();

                // Extract executable from command (may be quoted)
                var exe = ExtractExePath(command);
                var exeLower = exe.ToLowerInvariant();

                bool isSystemExe = exeLower.StartsWith(System32) ||
                                   exeLower.StartsWith(WinDir);
                bool isExpected  = IsExpectedCommand(progId, exeLower);

                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    cmdLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (cheatKw is not null || (!isSystemExe && !isExpected))
                {
                    hits++;
                    bool exists = File.Exists(exe);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Dateiverknüpfungs-Hijack: {progId} ({hiveName})",
                        Risk     = cheatKw is not null || progId.Equals("exefile", StringComparison.OrdinalIgnoreCase)
                            ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"{hiveName}\{classesPath}\{progId}\shell\open\command",
                        FileName = Path.GetFileName(exe),
                        Reason   = $"Dateiverknüpfung '{progId}' ({hiveName}) hat unerwarteten Open-Handler: " +
                                   $"'{command}'. " +
                                   (progId.Equals("exefile", StringComparison.OrdinalIgnoreCase)
                                       ? "KRITISCH: exefile-Hijack intercepts den Start JEDER .exe-Datei! "
                                       : "") +
                                   "Dateiverknüpfungs-Hijacks ermöglichen Code-Ausführung bei jedem " +
                                   "Öffnen des assoziierten Dateityps ohne Benutzerinteraktion. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   (!isSystemExe ? "Handler außerhalb Windows-Verzeichnis. " : "") +
                                   (!exists ? "Datei fehlt." : ""),
                        Detail   = $"ProgID: {progId} | Command: {command} | Exe: {exe} | Existiert: {exists}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckExefileHijack(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        // The most critical override: HKCU\SOFTWARE\Classes\exefile
        // This completely replaces the default .exe handler for the current user
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Classes\exefile\shell\open\command", writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var command = key.GetValue(null) as string ?? "";
            if (string.IsNullOrWhiteSpace(command)) return 0;

            // Any value here is suspicious — normal Windows doesn't set this per-user
            var exe      = ExtractExePath(command);
            var cmdLower = command.ToLowerInvariant();
            bool isNormalExeHandler = cmdLower.Contains("%1") &&
                (cmdLower.StartsWith(System32) || cmdLower.StartsWith(WinDir));

            if (!isNormalExeHandler)
            {
                hits++;
                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    cmdLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Kritischer EXE-Handler-Hijack (HKCU\\exefile)",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKCU\SOFTWARE\Classes\exefile\shell\open\command",
                    FileName = Path.GetFileName(exe),
                    Reason   = $"HKCU exefile-Handler ist auf '{command}' gesetzt. " +
                               "Dieser Wert überschreibt den Standard-.exe-Handler für den aktuellen Benutzer. " +
                               "JEDE gestartete .exe-Datei wird nun über diesen Handler gestartet — " +
                               "klassische Cheat-Loader- und Malware-Injection-Technik ohne Admin-Rechte. " +
                               (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'." : ""),
                    Detail   = $"Command: {command} | Exe: {exe}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static string ExtractExePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return "";
        command = command.Trim();
        if (command.StartsWith('"'))
        {
            int end = command.IndexOf('"', 1);
            return end > 1 ? command.Substring(1, end - 1) : command.Trim('"');
        }
        int space = command.IndexOf(' ');
        return space > 0 ? command[..space] : command;
    }

    private static bool IsExpectedCommand(string progId, string cmdLower)
    {
        return progId.ToLowerInvariant() switch
        {
            "exefile" => cmdLower.Contains("%1"),
            "batfile" or "cmdfile" => cmdLower.Contains("cmd.exe"),
            "vbsfile" or "vbefile" or "jsfile" or "jsefile" or "wsffile"
                => cmdLower.Contains("wscript.exe") || cmdLower.Contains("cscript.exe"),
            "ps1file" => cmdLower.Contains("powershell.exe") || cmdLower.Contains("pwsh.exe"),
            _ => false,
        };
    }
}
