using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans system and user environment variables for cheat tool fingerprints.
///
/// Some cheat tools, loaders, and debugging utilities leave persistent traces
/// in environment variables:
///   1. PATH modifications pointing to cheat tool directories
///   2. Cheat-specific env vars (API keys, license strings, config paths)
///   3. Debugger / reverse-engineering tool vars (DOTNET_JIT_DISASM, _NT_SYMBOL_PATH)
///   4. DLL injection via PATH: placing a malicious DLL in a directory that
///      appears in PATH before System32 causes it to be loaded by all processes
///      (DLL search order hijacking via PATH)
///   5. Custom TEMP/TMP pointing to a location the cheat controls
///   6. LD_PRELOAD-style vars set for WSL interop
///
/// Registry locations:
///   HKCU\Environment                        — user env vars
///   HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment — system env vars
/// </summary>
public sealed class EnvironmentVariableScanModule : IScanModule
{
    public string Name => "Umgebungsvariablen-Analyse";
    public double Weight => 0.4;
    public int ParallelGroup => 3;

    private const string UserEnvKey   = @"Environment";
    private const string SystemEnvKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    private static readonly string[] CheatVarNames =
    {
        "cheat", "hack", "inject", "bypass", "loader",
        "aimbot", "esp", "wallhack", "spoofer",
        "kiddion", "cherax", "2take1", "ozark",
        "skeet", "fatality", "neverlose", "onetap",
        "memprocfs", "pcileech",
    };

    private static readonly string[] CheatVarValues =
    {
        "cheat", "hack", "inject", "bypass", "aimbot",
        "wallhack", "kiddion", "cherax", "ozark",
        "skeet.cc", "fatality.win", "neverlose.cc",
        "spoofer", "memprocfs",
    };

    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\", @"\users\public\",
    };

    // Sensitive vars that should never be modified by user
    private static readonly HashSet<string> SensitiveVars = new(StringComparer.OrdinalIgnoreCase)
    {
        "PATH", "TEMP", "TMP", "PATHEXT", "COMSPEC", "WINDIR",
        "SYSTEMROOT", "SYSTEMDRIVE",
    };

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();
    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        int hits = 0;

        // Scan user environment
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(UserEnvKey, writable: false);
            if (key is not null)
                hits += ScanEnvKey(key, "HKCU", ctx, ref checked_, ct);
        }
        catch { }

        // Scan system environment
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SystemEnvKey, writable: false);
            if (key is not null)
                hits += ScanEnvKey(key, "HKLM", ctx, ref checked_, ct);
        }
        catch { }

        // Check live PATH for non-system directories placed before System32
        hits += CheckPathHijack(ctx, ct);

        ctx.Report(1.0, Name, $"{checked_} Umgebungsvariablen geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int ScanEnvKey(RegistryKey key, string hive, ScanContext ctx,
        ref int checked_, CancellationToken ct)
    {
        int hits = 0;
        foreach (var name in key.GetValueNames())
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementRegistryKeys();
            checked_++;

            var value = key.GetValue(name) as string ?? "";
            var nameLower = name.ToLowerInvariant();
            var valueLower = value.ToLowerInvariant();

            // Cheat-keyword in variable name
            var nameKw = CheatVarNames.FirstOrDefault(k =>
                nameLower.Contains(k, StringComparison.OrdinalIgnoreCase));
            if (nameKw is not null)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Umgebungsvariablen-Analyse",
                    Title    = $"Cheat-Umgebungsvariable: {name}",
                    Risk     = RiskLevel.High,
                    Location = $@"{hive}\{(hive == "HKCU" ? UserEnvKey : SystemEnvKey)}",
                    Reason   = $"Umgebungsvariable '{name}' enthält cheat-typisches Keyword '{nameKw}'. " +
                               $"Wert: '{value}'. Cheat-Tools setzen eigene Umgebungsvariablen " +
                               "für Konfiguration, API-Keys oder Pfad-Umgehung.",
                    Detail   = $"Variable: {name} | Wert: {value} | Keyword: {nameKw}"
                });
                continue;
            }

            // Cheat-keyword in variable value
            var valueKw = CheatVarValues.FirstOrDefault(k =>
                valueLower.Contains(k, StringComparison.OrdinalIgnoreCase));
            if (valueKw is not null && !SensitiveVars.Contains(name))
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Umgebungsvariablen-Analyse",
                    Title    = $"Cheat-Pfad in Umgebungsvariable: {name}",
                    Risk     = RiskLevel.Medium,
                    Location = $@"{hive}\{(hive == "HKCU" ? UserEnvKey : SystemEnvKey)}",
                    Reason   = $"Umgebungsvariable '{name}' zeigt auf cheat-typischen Pfad/Wert: " +
                               $"'{value}' (Keyword: '{valueKw}').",
                    Detail   = $"Variable: {name} | Wert: {value} | Keyword: {valueKw}"
                });
            }

            // Suspicious TEMP/TMP override
            if ((nameLower == "temp" || nameLower == "tmp") &&
                SuspiciousPaths.Any(p => valueLower.Contains(p)))
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Umgebungsvariablen-Analyse",
                    Title    = $"TEMP-Umgebungsvariable umgeleitet: {value}",
                    Risk     = RiskLevel.Medium,
                    Location = $@"{hive}\{(hive == "HKCU" ? UserEnvKey : SystemEnvKey)}",
                    Reason   = $"TEMP/TMP wurde auf einen ungewöhnlichen Pfad gesetzt: '{value}'. " +
                               "Cheats leiten TEMP um um ihre temporären Dateien vor Forensik-Tools " +
                               "zu verbergen oder in ein von ihnen kontrolliertes Verzeichnis zu schreiben.",
                    Detail   = $"Variable: {name} | Wert: {value}"
                });
            }
        }
        return hits;
    }

    private static int CheckPathHijack(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var path = Environment.GetEnvironmentVariable("PATH") ?? "";
            var dirs = path.Split(';', StringSplitOptions.RemoveEmptyEntries);

            bool foundSystem32 = false;
            foreach (var dir in dirs)
            {
                if (ct.IsCancellationRequested) break;
                var dirLower = dir.Trim().ToLowerInvariant();

                if (dirLower.StartsWith(System32) || dirLower.Contains(@"\windows\system32"))
                {
                    foundSystem32 = true;
                    continue;
                }

                // If this entry appears BEFORE System32 in PATH and is user-writable
                if (!foundSystem32 && SuspiciousPaths.Any(p => dirLower.Contains(p)))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Umgebungsvariablen-Analyse",
                        Title    = $"PATH-Hijack: Verdächtiger Pfad vor System32: {dir.Trim()}",
                        Risk     = RiskLevel.High,
                        Location = "PATH-Umgebungsvariable",
                        Reason   = $"PATH-Eintrag '{dir.Trim()}' erscheint VOR System32 und liegt " +
                                   "in einem user-beschreibbaren Verzeichnis. " +
                                   "DLL-Search-Order-Hijacking via PATH: eine gleichnamige DLL " +
                                   "in diesem Verzeichnis überschreibt System32-DLLs für alle Prozesse.",
                        Detail   = $"Verdächtiger PATH-Eintrag: {dir.Trim()} | Vor System32: true"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
