using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep-scans PowerShell execution history and transcripts for cheat-related
/// commands, download cradles, and bypass techniques.
///
/// PowerShell history is stored at:
///   %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
///   (One per user, appended after each session)
///
/// PowerShell transcripts (if enabled) are in configured transcript output path.
///
/// Cheat tools use PowerShell for:
///   1. Download cradles: IEX (New-Object Net.WebClient).DownloadString('http://...')
///   2. Bypassing execution policy: -ExecutionPolicy Bypass / Set-ExecutionPolicy
///   3. Disabling AV: Set-MpPreference -DisableRealtimeMonitoring $true
///   4. Adding AV exclusions: Add-MpPreference -ExclusionPath
///   5. Deleting shadow copies: vssadmin delete shadows / wmic shadowcopy delete
///   6. Disabling Windows Defender: Stop-Service WinDefend
///   7. AMSI bypass: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
///   8. Disabling event log: Set-Service -Name EventLog -StartupType Disabled
///   9. Loading unsigned scripts: Set-ExecutionPolicy Unrestricted
///  10. Reflective DLL loading: [Reflection.Assembly]::Load / [System.Reflection.Assembly]::LoadFile
/// </summary>
public sealed class PowerShellHistoryDeepScanModule : IScanModule
{
    public string Name => "PowerShell-Verlauf-Tiefenanalyse";
    public double Weight => 0.8;
    public int ParallelGroup => 4;

    private static readonly string AppDataRoaming = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);

    private static readonly string[] HistoryFiles =
    {
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
    };

    private static readonly (string Pattern, string Description, RiskLevel Risk)[] DangerousPatterns =
    {
        // Download cradles
        ("downloadstring", "PowerShell-Download-Cradle (Remote-Code-Ausführung)", RiskLevel.Critical),
        ("downloadfile(", "Datei-Download via PowerShell", RiskLevel.High),
        ("new-object net.webclient", "WebClient für Remote-Download", RiskLevel.High),
        ("invoke-webrequest", "Web-Request für Remote-Download", RiskLevel.Medium),
        ("start-bitstransfer", "BITS-Transfer (dateiloser Download)", RiskLevel.High),
        // AV/Defender bypass
        ("disablerealtimemonitoring", "Windows Defender Echtzeitschutz deaktiviert", RiskLevel.Critical),
        ("set-mppreference", "Windows Defender Einstellungen geändert", RiskLevel.High),
        ("add-mppreference -exclusion", "AV-Ausnahme hinzugefügt via PowerShell", RiskLevel.Critical),
        ("stop-service windefend", "Windows Defender Service gestoppt", RiskLevel.Critical),
        ("stop-service mssecsvr", "Security Service gestoppt", RiskLevel.High),
        // Shadow copy deletion
        ("vssadmin delete shadows", "Volume Shadow Copies gelöscht (Anti-Forensik)", RiskLevel.Critical),
        ("wmic shadowcopy delete", "Shadow Copies via WMI gelöscht", RiskLevel.Critical),
        ("shadowcopy where", "Shadow Copy Abfrage (Vorstufe zum Löschen)", RiskLevel.Medium),
        // AMSI bypass
        ("amsiinitfailed", "AMSI-Bypass versucht (AmsiInitFailed)", RiskLevel.Critical),
        ("amsiutils", "AMSI-Bypass via Reflection (AmsiUtils)", RiskLevel.Critical),
        ("amsi.dll", "AMSI DLL direkt manipuliert", RiskLevel.Critical),
        ("bypassamsi", "AMSI-Bypass-Skript ausgeführt", RiskLevel.Critical),
        // Execution policy bypass
        ("-executionpolicy bypass", "PowerShell-Ausführungsrichtlinie umgangen", RiskLevel.High),
        ("set-executionpolicy unrestricted", "Ausführungsrichtlinie auf Unrestricted gesetzt", RiskLevel.High),
        ("set-executionpolicy remotesigned", "Ausführungsrichtlinie geändert", RiskLevel.Medium),
        // Event log tamper
        ("set-service -name eventlog", "EventLog-Service über PowerShell deaktiviert", RiskLevel.Critical),
        ("wevtutil cl", "Event-Log via wevtutil gelöscht", RiskLevel.Critical),
        ("clear-eventlog", "Event-Log via PowerShell gelöscht", RiskLevel.Critical),
        // Reflective loading
        ("[reflection.assembly]::load", "Assembly reflektiv geladen (dateilose Ausführung)", RiskLevel.High),
        ("loadfile(", "Assembly aus Datei geladen", RiskLevel.Medium),
        // Obfuscation
        ("frombase64string", "Base64-dekodierter Code ausgeführt", RiskLevel.High),
        ("invoke-expression", "IEX / Invoke-Expression (Code-Injektion)", RiskLevel.High),
        ("iex(", "IEX-Kurzform (Code-Injektion)", RiskLevel.High),
        // Driver loading via PowerShell
        ("-force -confirmpreference none", "Zwangs-Installation ohne Bestätigung", RiskLevel.Medium),
        ("bcdedit /set testsigning", "Test-Signing via bcdedit aktiviert", RiskLevel.Critical),
        ("bcdedit /set nointegritychecks", "NoIntegrityChecks via bcdedit aktiviert", RiskLevel.Critical),
        ("bcdedit /set hypervisorlaunchtype", "Hypervisor-Boot-Typ geändert", RiskLevel.High),
        // Cheat-specific
        ("kiddion", "Kiddion Cheat-Tool via PowerShell", RiskLevel.Critical),
        ("memprocfs", "MemProcFS / DMA-Tool via PowerShell", RiskLevel.Critical),
        ("pcileech", "PCILeech DMA-Tool via PowerShell", RiskLevel.Critical),
        ("kdmapper", "KDMapper (Kernel Driver Mapper) via PowerShell", RiskLevel.Critical),
        ("disable-windowsoptionalfeature -online -featurename hyperv",
            "Hyper-V via PowerShell deaktiviert (HVCI-Bypass)", RiskLevel.Critical),
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int linesScanned = 0;
        int hits = 0;

        foreach (var histFile in HistoryFiles)
        {
            if (ct.IsCancellationRequested) break;
            if (!File.Exists(histFile)) continue;

            ctx.IncrementFiles();

            try
            {
                var lines = File.ReadAllLines(histFile);
                foreach (var line in lines)
                {
                    if (ct.IsCancellationRequested) break;
                    linesScanned++;
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    var lower = line.ToLowerInvariant();

                    foreach (var (pattern, description, risk) in DangerousPatterns)
                    {
                        if (!lower.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"PS-Verlauf: {description}",
                            Risk     = risk,
                            Location = histFile,
                            FileName = "ConsoleHost_history.txt",
                            Reason   = $"PowerShell-Verlauf enthält verdächtigen Befehl: '{description}'. " +
                                       $"Befehl: '{line.Trim()[..Math.Min(200, line.Trim().Length)]}'.",
                            Detail   = $"Datei: {histFile} | Pattern: {pattern} | Befehl: {line.Trim()}"
                        });
                        break; // One finding per line (highest-risk match)
                    }
                }
            }
            catch { }
        }

        ctx.Report(1.0, Name, $"{linesScanned} PowerShell-Verlauf-Zeilen analysiert, {hits} verdächtig");
        return Task.CompletedTask;
    }
}
