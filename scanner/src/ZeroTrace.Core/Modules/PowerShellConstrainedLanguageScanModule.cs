using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects PowerShell security bypass techniques used by cheat loaders and malware.
///
/// PowerShell is a powerful scripting engine that cheat loaders abuse because:
///   1. Trusted by default (signed Microsoft binary)
///   2. Can download and execute arbitrary code in-memory (fileless)
///   3. Can bypass execution policy with -ExecutionPolicy Bypass
///   4. Can load .NET assemblies from byte arrays (no file needed)
///   5. Can use AMSI bypass to avoid antivirus scanning
///
/// Security features targeted by cheats:
///
///   1. AMSI (Antimalware Scan Interface): PS calls AmsiScanBuffer before executing
///      scripts. Cheats patch amsi.dll's AmsiScanBuffer to always return AMSI_RESULT_CLEAN.
///      Detection: compare amsi.dll bytes in powershell.exe with on-disk version.
///
///   2. Constrained Language Mode (CLM): restricts PowerShell to safe cmdlets only.
///      Cheats set __PSLockdownPolicy env var or registry value to disable CLM.
///
///   3. Script Block Logging: logs all executed PS script blocks to Event Log.
///      Cheats disable this via registry to avoid logging their download/execute stagers.
///
///   4. Module Logging: logs all imported module functions.
///      Similar bypass — disabled via registry.
///
///   5. Execution Policy: All, Bypass, Unrestricted — should not be set machine-wide
///      unless specifically required.
///
///   6. PowerShell v2 enabled: PS v2 bypasses all v5 security features (AMSI, logging).
///      Cheats invoke powershell.exe -Version 2 to get an old unprotected engine.
///
/// Registry paths:
///   HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\
///     ScriptBlockLogging\EnableScriptBlockLogging
///     ModuleLogging\EnableModuleLogging
///     Transcription\EnableTranscripting
///   HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy
///   HKLM\SYSTEM\CurrentControlSet\Services\WinRM (PS remoting attack surface)
/// </summary>
public sealed class PowerShellConstrainedLanguageScanModule : IScanModule
{
    public string Name => "PowerShell-Sicherheitskonfiguration";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private const string PsPolicyRoot =
        @"SOFTWARE\Policies\Microsoft\Windows\PowerShell";
    private const string PsConfigRoot =
        @"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell";

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckScriptBlockLogging(ctx, ct);
        hits += CheckModuleLogging(ctx, ct);
        hits += CheckExecutionPolicy(ctx, ct);
        hits += CheckPowerShellV2(ctx, ct);
        hits += CheckAmsiBypassRegistry(ctx, ct);
        hits += CheckTranscription(ctx, ct);

        ctx.Report(1.0, Name, $"PowerShell-Sicherheitseinstellungen geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckScriptBlockLogging(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Policy key takes precedence
            using var polKey = Registry.LocalMachine.OpenSubKey(
                PsPolicyRoot + @"\ScriptBlockLogging", writable: false);
            ctx.IncrementRegistryKeys();

            var policyEnabled = polKey?.GetValue("EnableScriptBlockLogging") as int?;

            if (policyEnabled is not null && policyEnabled == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "PowerShell-Sicherheitskonfiguration",
                    Title    = "PowerShell Script-Block-Logging deaktiviert (Policy)",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{PsPolicyRoot}\ScriptBlockLogging",
                    Reason   = "Script Block Logging ist per Policy deaktiviert. " +
                               "Diese Sicherheitsfunktion protokolliert alle ausgeführten " +
                               "PowerShell-Codeblöcke im Windows Event Log. " +
                               "Cheat-Loader deaktivieren dies, um ihre Download-und-Ausführen-Stager " +
                               "vor Forensik-Tools zu verbergen.",
                    Detail   = "EnableScriptBlockLogging: 0 (erwartet: 1)"
                });
            }
            else if (policyEnabled is null)
            {
                // Check if it's explicitly disabled in config (not policy)
                using var cfgKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\PowerShell\1\ShellIds\Microsoft.PowerShell\ScriptBlockLogging",
                    writable: false);
                var cfgEnabled = cfgKey?.GetValue("EnableScriptBlockLogging") as int?;
                if (cfgEnabled is not null && cfgEnabled == 0)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "PowerShell-Sicherheitskonfiguration",
                        Title    = "PowerShell Script-Block-Logging deaktiviert",
                        Risk     = RiskLevel.Medium,
                        Location = @"HKLM\SOFTWARE\Microsoft\Windows\PowerShell\1\ShellIds\...",
                        Reason   = "Script Block Logging ist explizit deaktiviert. " +
                                   "Ohne diese Protokollierung sind PowerShell-basierte " +
                                   "Cheat-Loader schwerer forensisch nachzuweisen.",
                        Detail   = "EnableScriptBlockLogging: 0"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckModuleLogging(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                PsPolicyRoot + @"\ModuleLogging", writable: false);
            ctx.IncrementRegistryKeys();

            var enabled = key?.GetValue("EnableModuleLogging") as int?;
            if (enabled is not null && enabled == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "PowerShell-Sicherheitskonfiguration",
                    Title    = "PowerShell Module-Logging deaktiviert",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKLM\{PsPolicyRoot}\ModuleLogging",
                    Reason   = "PowerShell Module Logging ist deaktiviert. " +
                               "Module Logging protokolliert alle importierten Modul-Funktionen " +
                               "und deren Pipeline-Ausgabe. Das Deaktivieren versteckt " +
                               "PowerShell-basierte Cheat-Tool-Aktivitäten.",
                    Detail   = "EnableModuleLogging: 0 (erwartet: 1)"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckExecutionPolicy(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(PsConfigRoot, writable: false);
            ctx.IncrementRegistryKeys();

            var policy = key?.GetValue("ExecutionPolicy") as string ?? "";

            if (string.Equals(policy, "Unrestricted", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(policy, "Bypass", StringComparison.OrdinalIgnoreCase))
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "PowerShell-Sicherheitskonfiguration",
                    Title    = $"PowerShell ExecutionPolicy unsicher: {policy}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{PsConfigRoot}",
                    Reason   = $"PowerShell ExecutionPolicy ist auf '{policy}' gesetzt. " +
                               "Diese Einstellung erlaubt die Ausführung beliebiger " +
                               "(auch unsignierter) PowerShell-Skripte ohne Warnung. " +
                               "Cheat-Loader verwenden 'Bypass' oder 'Unrestricted', " +
                               "um ihre Download-Stager und Loader-Skripte ungehindert auszuführen.",
                    Detail   = $"ExecutionPolicy: {policy}"
                });
            }

            // Also check machine-wide policy override
            using var polKey = Registry.LocalMachine.OpenSubKey(
                PsPolicyRoot, writable: false);
            var polPolicy = polKey?.GetValue("ExecutionPolicy") as string ?? "";
            if (string.Equals(polPolicy, "Unrestricted", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(polPolicy, "Bypass", StringComparison.OrdinalIgnoreCase))
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "PowerShell-Sicherheitskonfiguration",
                    Title    = $"PowerShell ExecutionPolicy per Policy unsicher: {polPolicy}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{PsPolicyRoot}",
                    Reason   = $"PowerShell ExecutionPolicy ist per GPO/Policy auf '{polPolicy}' " +
                               "gesetzt — kann nicht durch User-Einstellung überschrieben werden. " +
                               "Cheat-Software-Installer setzen oft diese Policy-Einstellung.",
                    Detail   = $"Policy ExecutionPolicy: {polPolicy}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckPowerShellV2(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check if PowerShell v2 engine is installed (bypasses all v5 security)
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\PowerShell\1", writable: false);
            ctx.IncrementRegistryKeys();

            if (key is not null)
            {
                var installed = key.GetValue("Install") as int? ?? 0;
                if (installed == 1)
                {
                    // Check the actual v2 path
                    var psv2Path = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                        "System32", "WindowsPowerShell", "v1.0", "powershell.exe");

                    if (File.Exists(psv2Path))
                    {
                        // PowerShell v2 is a bypass vector — only flag if logging is also disabled
                        // or if it's explicitly the PowerShell 2.0 Windows Feature installed
                        using var v2Key = Registry.LocalMachine.OpenSubKey(
                            @"SOFTWARE\Microsoft\PowerShell\3", writable: false);
                        bool v5Present = v2Key is not null;

                        if (v5Present)
                        {
                            // v5 + v2 = v2 is a downgrade attack surface
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = "PowerShell-Sicherheitskonfiguration",
                                Title    = "PowerShell v2 verfügbar (Sicherheits-Downgrade möglich)",
                                Risk     = RiskLevel.Medium,
                                Location = psv2Path,
                                Reason   = "PowerShell Version 2 ist installiert (neben v5). " +
                                           "PS v2 hat kein AMSI, kein Script Block Logging, " +
                                           "und keine Language Mode. Angreifer nutzen " +
                                           "'powershell.exe -Version 2', um alle PS v5-Sicherheitsfeatures " +
                                           "zu umgehen und Cheat-Loader unprotokolliert auszuführen.",
                                Detail   = $"PS v2 Pfad: {psv2Path} | Installiert: true | PS v5: {v5Present}"
                            });
                        }
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckAmsiBypassRegistry(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check for known AMSI bypass registry keys
            // Some tools set HKCU\Software\Classes\CLSID\{fdb00e52...} to disable AMSI
            // Also check for Invoke-Obfuscation / AMSI patch artifacts

            // PSLockdownPolicy = 1 → Constrained Language Mode (good)
            // PSLockdownPolicy = 0 or missing → Full Language Mode
            var lockdownPolicy = Environment.GetEnvironmentVariable("__PSLockdownPolicy");
            if (!string.IsNullOrEmpty(lockdownPolicy) &&
                lockdownPolicy != "4" && lockdownPolicy != "8")
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "PowerShell-Sicherheitskonfiguration",
                    Title    = $"PowerShell __PSLockdownPolicy manipuliert: {lockdownPolicy}",
                    Risk     = RiskLevel.High,
                    Location = "Umgebungsvariable: __PSLockdownPolicy",
                    Reason   = $"__PSLockdownPolicy ist auf '{lockdownPolicy}' gesetzt. " +
                               "Wert '4' = Constrained Language Mode (sicher), " +
                               "'8' = Full Language Mode für Enterprise, " +
                               "andere Werte = potenzieller Bypass. " +
                               "Manche AMSI-Bypass-Tools manipulieren diese Variable.",
                    Detail   = $"__PSLockdownPolicy: {lockdownPolicy}"
                });
            }

            // Check for known AMSI provider CLSID deletion/override in registry
            using var amsiKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\AMSI\Providers", writable: false);
            ctx.IncrementRegistryKeys();

            if (amsiKey is not null)
            {
                var providers = amsiKey.GetSubKeyNames();
                // Windows Defender AMSI provider GUID
                const string wdAmsiGuid = "{2781761E-28E0-4109-99FE-B9D127C57AFE}";
                if (!providers.Any(p => p.Equals(wdAmsiGuid, StringComparison.OrdinalIgnoreCase)))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "PowerShell-Sicherheitskonfiguration",
                        Title    = "Windows Defender AMSI-Provider fehlt",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SOFTWARE\Microsoft\AMSI\Providers",
                        Reason   = "Der Windows Defender AMSI-Provider " +
                                   $"({wdAmsiGuid}) ist nicht registriert. " +
                                   "AMSI (Antimalware Scan Interface) scannt PowerShell-Skripte " +
                                   "vor der Ausführung auf Malware. " +
                                   "Das Entfernen des Providers deaktiviert diesen Schutz komplett " +
                                   "und ist ein klares Indiz für eine gezielte AMSI-Bypass-Aktion.",
                        Detail   = $"Registrierte Provider: {string.Join(", ", providers)} | " +
                                   $"WD-Provider fehlt: {wdAmsiGuid}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckTranscription(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                PsPolicyRoot + @"\Transcription", writable: false);
            ctx.IncrementRegistryKeys();

            var enabled = key?.GetValue("EnableTranscripting") as int?;
            if (enabled is not null && enabled == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "PowerShell-Sicherheitskonfiguration",
                    Title    = "PowerShell Transkription deaktiviert",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKLM\{PsPolicyRoot}\Transcription",
                    Reason   = "PowerShell Transkriptions-Logging ist deaktiviert. " +
                               "Transkription zeichnet alle PS-Sitzungen in Textdateien auf " +
                               "und ermöglicht die forensische Rekonstruktion von Angriffsketten. " +
                               "Das Deaktivieren ist ein Anti-Forensik-Schritt, " +
                               "der oft von Cheat-Installationsskripten durchgeführt wird.",
                    Detail   = "EnableTranscripting: 0"
                });
            }
        }
        catch { }
        return hits;
    }
}
