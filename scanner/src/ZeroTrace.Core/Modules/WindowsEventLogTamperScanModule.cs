using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class WindowsEventLogTamperScanModule : IScanModule
{
    public string Name => "Windows-EventLog-Tamper";
    public double Weight => 0.8;
    public int ParallelGroup => 3;

    private static readonly string WinevtLogsPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "winevt", "Logs");

    private static readonly string PrefetchPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Prefetch");

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly string TempPath = Path.GetTempPath();

    private const long MinValidEvtxBytes = 69632;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await CheckEventLogRegistrySizesAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await CheckEventLogFileExistenceAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await CheckEventLogServiceTamperingAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await CheckAuditPolicyTamperingAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanForLogClearingToolsAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanForTimestompArtifactsAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanPrefetchForLogClearingToolsAsync(ctx, ct);
    }

    private async Task CheckEventLogRegistrySizesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var logNames = new[] { "Security", "System", "Application" };

            foreach (var logName in logNames)
            {
                if (ct.IsCancellationRequested) return;

                var keyPath = $@"SYSTEM\CurrentControlSet\Services\EventLog\{logName}";
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    var maxSizeObj = key.GetValue("MaxSize");
                    ctx.IncrementRegistryKeys();

                    var retentionObj = key.GetValue("Retention");
                    ctx.IncrementRegistryKeys();

                    int maxSize = maxSizeObj is int ms ? ms : -1;
                    int retention = retentionObj is int r ? r : -1;

                    if (maxSize >= 0 && maxSize <= 65536)
                    {
                        var risk = (retention == 0) ? RiskLevel.High : RiskLevel.Medium;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"EventLog {logName}: MaxSize auf Minimum reduziert",
                            Risk     = risk,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"Das Windows-Ereignisprotokoll '{logName}' hat eine MaxSize von " +
                                       $"{maxSize} Bytes (64 KB), was dem absoluten Minimum entspricht. " +
                                       "Cheater reduzieren die Log-Kapazität auf das Minimum, damit " +
                                       "Anti-Cheat-Ereignisse schnell überschrieben werden." +
                                       (retention == 0
                                           ? " Zusätzlich ist Retention=0 (Overwrite), " +
                                             "was das Überschreiben beschleunigt."
                                           : string.Empty),
                            Detail   = $"MaxSize={maxSize} | Retention={retention} | Log={logName}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception) { }
            }
        }, ct);
    }

    private async Task CheckEventLogFileExistenceAsync(ScanContext ctx, CancellationToken ct)
    {
        var criticalLogs = new[]
        {
            ("Security.evtx",                                                              RiskLevel.Critical, "Sicherheits-Ereignisprotokoll"),
            ("System.evtx",                                                                RiskLevel.High,     "System-Ereignisprotokoll"),
            ("Microsoft-Windows-Kernel-PnP%4Configuration.evtx",                          RiskLevel.High,     "Kernel PnP Treiber-Lade-Ereignisse"),
            ("Microsoft-Windows-CodeIntegrity%4Operational.evtx",                         RiskLevel.High,     "Code Integrity / Treibersignierung"),
            ("Microsoft-Windows-Windows Defender%4Operational.evtx",                      RiskLevel.High,     "Windows Defender Aktivitäten"),
            ("Microsoft-Windows-PowerShell%4Operational.evtx",                            RiskLevel.Medium,   "PowerShell-Ausführungsprotokoll"),
            ("Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",             RiskLevel.Medium,   "USB/Gerätetreiber-Ereignisse"),
        };

        await Task.Run(() =>
        {
            foreach (var (fileName, risk, description) in criticalLogs)
            {
                if (ct.IsCancellationRequested) return;

                var fullPath = Path.Combine(WinevtLogsPath, fileName);
                ctx.IncrementFiles();

                if (!File.Exists(fullPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Kritisches Ereignisprotokoll fehlt: {fileName}",
                        Risk     = risk,
                        Location = fullPath,
                        FileName = fileName,
                        Reason   = $"Die Ereignisprotokolldatei '{fileName}' ({description}) ist nicht " +
                                   "vorhanden. Das Fehlen dieser Datei deutet auf eine absichtliche " +
                                   "Löschung oder Manipulation durch ein Anti-Forensik-Tool hin.",
                        Detail   = $"Erwartet: {fullPath}"
                    });
                    continue;
                }

                try
                {
                    var fi = new FileInfo(fullPath);
                    if (fi.Length < MinValidEvtxBytes)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Ereignisprotokoll zu klein (möglicherweise geleert): {fileName}",
                            Risk     = risk,
                            Location = fullPath,
                            FileName = fileName,
                            Reason   = $"Die Datei '{fileName}' ({description}) ist nur {fi.Length} Bytes " +
                                       $"groß. Eine gültige EVTX-Datei benötigt mindestens {MinValidEvtxBytes} " +
                                       "Bytes für einen validen Header mit Einträgen. Diese Größe deutet " +
                                       "auf eine geleerte oder ersetzte Protokolldatei hin.",
                            Detail   = $"Dateigröße: {fi.Length} Bytes | Minimum erwartet: {MinValidEvtxBytes} Bytes | Pfad: {fullPath}"
                        });
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private async Task CheckEventLogServiceTamperingAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            const string keyPath = @"SYSTEM\CurrentControlSet\Services\EventLog";
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                if (key is null) return;

                var startObj = key.GetValue("Start");
                ctx.IncrementRegistryKeys();

                if (startObj is int startVal && startVal == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Windows EventLog-Dienst deaktiviert (Start=4)",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{keyPath}",
                        Reason   = "Der Windows-Ereignisprotokolldienst ist auf 'Disabled' (Start=4) " +
                                   "gesetzt. Ein deaktivierter EventLog-Dienst verhindert jede " +
                                   "Protokollierung von Prozess-, Treiber- und Sicherheitsereignissen " +
                                   "und ist ein starkes Indiz für Rootkit- oder Cheat-Loader-Manipulation.",
                        Detail   = $"Start = {startVal} (4 = Disabled)"
                    });
                }

                var imagePathObj = key.GetValue("ImagePath");
                ctx.IncrementRegistryKeys();

                if (imagePathObj is string imagePath && imagePath.Length > 0)
                {
                    var normalizedPath = imagePath.Trim('"').Trim();
                    var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);

                    if (!normalizedPath.Contains("svchost", StringComparison.OrdinalIgnoreCase) &&
                        !normalizedPath.StartsWith(system32, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "EventLog-Dienst: Binärpfad außerhalb von System32",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"Der ImagePath des EventLog-Dienstes zeigt auf '{imagePath}', " +
                                       "was weder auf svchost.exe noch in System32 verweist. " +
                                       "Ein Rootkit könnte den Dienst auf eine manipulierte Binärdatei " +
                                       "umgeleitet haben, um die Ereignisprotokollierung zu unterdrücken.",
                            Detail   = $"ImagePath = {imagePath}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }
        }, ct);
    }

    private async Task CheckAuditPolicyTamperingAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            var auditChecks = new[]
            {
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine_Enabled"),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "AuditPolicyChange"),
            };

            foreach (var (keyPath, valueName) in auditChecks)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    var val = key.GetValue(valueName);
                    ctx.IncrementRegistryKeys();

                    if (val is int intVal && intVal == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Audit-Richtlinie deaktiviert: {valueName}",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"Der Audit-Richtlinien-Wert '{valueName}' ist auf 0 (deaktiviert) " +
                                       "gesetzt. Deaktivierte Audit-Richtlinien verhindern die " +
                                       "Protokollierung von Sicherheitsereignissen wie Prozesserstellen " +
                                       "(EventID 4688) und ermöglichen Cheats, ohne Spuren zu agieren.",
                            Detail   = $@"HKLM\{keyPath}\{valueName} = {intVal}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception) { }
            }

            const string lsaKeyPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
            try
            {
                using var lsaKey = Registry.LocalMachine.OpenSubKey(lsaKeyPath, writable: false);
                if (lsaKey is not null)
                {
                    var auditBaseObjects = lsaKey.GetValue("AuditBaseObjects");
                    ctx.IncrementRegistryKeys();

                    var fullPrivilegeAuditing = lsaKey.GetValue("FullPrivilegeAuditing");
                    ctx.IncrementRegistryKeys();

                    if (auditBaseObjects is int aboVal && aboVal == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "LSA: AuditBaseObjects deaktiviert",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{lsaKeyPath}",
                            Reason   = "AuditBaseObjects=0 deaktiviert die Überwachung des Zugriffs auf " +
                                       "Kernel-Objekte. Cheat-Tools deaktivieren dies, um Zugriffe auf " +
                                       "Spielprozesse und Anti-Cheat-Dienste zu verschleiern.",
                            Detail   = $"AuditBaseObjects = {aboVal}"
                        });
                    }

                    if (fullPrivilegeAuditing is int fpaVal && fpaVal == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "LSA: FullPrivilegeAuditing deaktiviert",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{lsaKeyPath}",
                            Reason   = "FullPrivilegeAuditing=0 verhindert, dass privilegierte Aktionen " +
                                       "(SeDebugPrivilege, SeLoadDriverPrivilege) im Sicherheitsprotokoll " +
                                       "erscheinen. Cheater deaktivieren dies, um Treiber-Lade-Aktionen " +
                                       "unbemerkt durchzuführen.",
                            Detail   = $"FullPrivilegeAuditing = {fpaVal}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }

            const string guestAccessKeyPath = @"SYSTEM\CurrentControlSet\Services\EventLog\Security";
            try
            {
                using var secKey = Registry.LocalMachine.OpenSubKey(guestAccessKeyPath, writable: false);
                if (secKey is not null)
                {
                    var restrictGuest = secKey.GetValue("RestrictGuestAccess");
                    ctx.IncrementRegistryKeys();

                    if (restrictGuest is int rgVal && rgVal != 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "EventLog Security: RestrictGuestAccess manipuliert",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{guestAccessKeyPath}",
                            Reason   = $"RestrictGuestAccess={rgVal} für das Sicherheitsprotokoll weicht " +
                                       "vom Standard ab. Ein geänderter Wert kann auf Manipulation der " +
                                       "Sicherheitsprotokoll-Konfiguration durch ein Anti-Forensik-Tool hindeuten.",
                            Detail   = $"RestrictGuestAccess = {rgVal} (normal: 1)"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }
        }, ct);
    }

    private async Task ScanForLogClearingToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var suspiciousExeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "clear_eventlog.exe", "evtx_cleaner.exe", "log_cleaner.exe",
            "wevtutil_wrapper.exe", "eventlog_clear.exe", "clear_logs.exe"
        };

        var scriptPatternsSingle = new[]
        {
            "wevtutil cl",
            "clear-eventlog",
            "wevtutil.exe cl system",
            "wevtutil.exe cl security",
            "remove-eventlog",
            @"wevtutil cl ""windows powershell""",
        };

        var scriptPatternsMultiClear = new[]
        {
            "foreach",
            "wevtutil",
        };

        var searchDirs = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            TempPath,
            Path.Combine(AppDataLocal, "Temp"),
            AppDataRoaming,
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);

                if (suspiciousExeNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Log-Clearing-Tool gefunden: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Die Datei '{fileName}' ist ein bekanntes Tool zum Löschen von " +
                                   "Windows-Ereignisprotokollen. Cheater verwenden solche Tools, um " +
                                   "Spuren von Cheat-Treiber-Installationen und Anti-Cheat-Umgehungen " +
                                   "aus den Ereignisprotokollen zu entfernen.",
                        Detail   = $"Pfad: {file}"
                    });
                    continue;
                }

                if (!ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) &&
                    !ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) &&
                    !ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase))
                    continue;

                try
                {
                    string content;
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();

                    var lowerContent = content.ToLowerInvariant();
                    int matchCount = 0;
                    var matchedPatterns = new List<string>();

                    foreach (var pattern in scriptPatternsSingle)
                    {
                        if (lowerContent.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            matchedPatterns.Add(pattern);
                        }
                    }

                    bool hasForEachWevtutil =
                        lowerContent.Contains("foreach", StringComparison.OrdinalIgnoreCase) &&
                        lowerContent.Contains("wevtutil", StringComparison.OrdinalIgnoreCase) &&
                        lowerContent.Contains(" cl ", StringComparison.OrdinalIgnoreCase);

                    if (matchCount >= 2 || hasForEachWevtutil)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Skript löscht mehrere Ereignisprotokolle: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Das Skript '{fileName}' enthält mehrere Befehle zum Löschen von " +
                                       "Windows-Ereignisprotokollen (z.B. foreach+wevtutil cl, Clear-EventLog). " +
                                       "Ein Skript, das mehrere Log-Kanäle auf einmal löscht, ist ein " +
                                       "starkes Indiz für Anti-Forensik-Aktivität im Zusammenhang mit Cheating.",
                            Detail   = $"Gefundene Muster: {string.Join(", ", matchedPatterns)} | Pfad: {file}"
                        });
                    }
                    else if (matchCount == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Skript enthält Log-Clearing-Befehl: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Das Skript '{fileName}' enthält den Befehl '{matchedPatterns[0]}' " +
                                       "zum Löschen von Ereignisprotokollen. Cheater verwenden solche Skripte, " +
                                       "um Beweise aus den Windows-Protokollen zu entfernen.",
                            Detail   = $"Muster: {matchedPatterns[0]} | Pfad: {file}"
                        });
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }

        await ScanPowerShellHistoryForLogClearingAsync(ctx, ct);
    }

    private async Task ScanPowerShellHistoryForLogClearingAsync(ScanContext ctx, CancellationToken ct)
    {
        var historyPath = Path.Combine(AppDataRoaming,
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (!File.Exists(historyPath)) return;

        ctx.IncrementFiles();

        var patterns = new[]
        {
            ("wevtutil cl",           RiskLevel.Medium, "wevtutil cl (Event-Log-Löschbefehl)"),
            ("clear-eventlog -logname", RiskLevel.Medium, "Clear-EventLog -LogName"),
            ("remove-eventlog",        RiskLevel.Medium, "Remove-EventLog"),
            ("clear-eventlog",         RiskLevel.Medium, "Clear-EventLog"),
        };

        try
        {
            string content;
            using var fs = new FileStream(historyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();

            foreach (var (pattern, risk, description) in patterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"PS-Verlauf: {description}",
                        Risk     = risk,
                        Location = historyPath,
                        FileName = "ConsoleHost_history.txt",
                        Reason   = $"Die PowerShell-Verlaufsdatei enthält den Befehl '{pattern}' zum " +
                                   "Löschen von Ereignisprotokollen. Dies ist ein Anti-Forensik-Indikator " +
                                   "der auf das Entfernen von Cheat-Aktivitätsspuren hindeutet.",
                        Detail   = $"Muster: {pattern} | Verlaufsdatei: {historyPath}"
                    });
                }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private async Task ScanForTimestompArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var suspiciousTimestompExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "timestomp.exe", "timestamp_changer.exe", "ntfs_changer.exe",
            "filetime_changer.exe", "touch.exe"
        };

        var searchDirs = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            TempPath,
            Path.Combine(AppDataLocal, "Temp"),
            AppDataRoaming,
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (!suspiciousTimestompExes.Contains(fileName)) continue;

                var isSystemDir = file.StartsWith(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    StringComparison.OrdinalIgnoreCase);

                if (fileName.Equals("touch.exe", StringComparison.OrdinalIgnoreCase) && isSystemDir)
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Timestamp-Manipulation-Tool gefunden: {fileName}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Das Tool '{fileName}' dient zur Manipulation von NTFS-Zeitstempeln " +
                               "(Timestomping). Cheater verwenden Timestomping, um den Zeitpunkt der " +
                               "Cheat-Installation oder -Ausführung zu verschleiern und forensische " +
                               "Timeline-Analysen zu verfälschen.",
                    Detail   = $"Pfad: {file}"
                });
            }
        }

        await ScanPowerShellHistoryForTimestompAsync(ctx, ct);
        await CheckTimestompRegistryAsync(ctx, ct);
    }

    private async Task ScanPowerShellHistoryForTimestompAsync(ScanContext ctx, CancellationToken ct)
    {
        var historyPath = Path.Combine(AppDataRoaming,
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (!File.Exists(historyPath)) return;

        var patterns = new[]
        {
            ("[system.io.file]::setcreationtime",  RiskLevel.High,   "[System.IO.File]::SetCreationTime (Erstellzeitstempel geändert)"),
            ("[system.io.file]::setlastwritetime", RiskLevel.High,   "[System.IO.File]::SetLastWriteTime (Schreibzeitstempel geändert)"),
            ("[io.file]::setcreationtime",         RiskLevel.High,   "[IO.File]::SetCreationTime"),
            ("[io.file]::setlastwritetime",        RiskLevel.High,   "[IO.File]::SetLastWriteTime"),
            ("timestomp",                          RiskLevel.High,   "Metasploit timestomp-Aufruf"),
        };

        try
        {
            string content;
            using var fs = new FileStream(historyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();

            foreach (var (pattern, risk, description) in patterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"PS-Verlauf: {description}",
                        Risk     = risk,
                        Location = historyPath,
                        FileName = "ConsoleHost_history.txt",
                        Reason   = $"Der PowerShell-Verlauf enthält '{pattern}', ein Befehl zur NTFS-Timestamp-" +
                                   "Manipulation. Cheater nutzen Timestomping gezielt, um den tatsächlichen " +
                                   "Zeitpunkt der Cheat-Installation zu verschleiern.",
                        Detail   = $"Muster: {pattern}"
                    });
                }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        await Task.CompletedTask;
    }

    private async Task CheckTimestompRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            const string keyPath = @"Software\Timestomp";
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: false);
                if (key is null) return;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Registry-Artefakt: Timestomp-Konfiguration in HKCU",
                    Risk     = RiskLevel.High,
                    Location = $@"HKCU\{keyPath}",
                    Reason   = $"Der Registry-Schlüssel '{keyPath}' existiert im Benutzerhive. " +
                               "Timestomp ist ein Metasploit-Tool zur NTFS-Timestamp-Manipulation. " +
                               "Cheater verwenden es, um Installationszeitpunkte von Cheats zu verbergen.",
                    Detail   = $@"HKCU\{keyPath}"
                });
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }
        }, ct);
    }

    private async Task ScanPrefetchForLogClearingToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(PrefetchPath)) return;

        var prefetchPatterns = new[]
        {
            ("WEVTUTIL",    RiskLevel.Medium, "wevtutil.exe (Event-Log-Löschung)"),
            ("CLEARLOG",    RiskLevel.High,   "Log-Clearing-Tool"),
            ("EVTXCLEANER", RiskLevel.High,   "EVTX-Cleaner-Tool"),
            ("TIMESTOMP",   RiskLevel.High,   "Timestomp-Tool (NTFS-Timestamp-Manipulation)"),
            ("CLEAR_LOGS",  RiskLevel.High,   "Log-Clearing-Tool"),
            ("LOG_CLEANER", RiskLevel.High,   "Log-Cleaner-Tool"),
        };

        IEnumerable<string> pfFiles;
        try
        {
            pfFiles = Directory.EnumerateFiles(PrefetchPath, "*.pf", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        await Task.Run(() =>
        {
            foreach (var pfFile in pfFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var pfName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();

                foreach (var (pattern, risk, description) in prefetchPatterns)
                {
                    if (!pfName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Prefetch: {description} zuvor ausgeführt",
                        Risk     = risk,
                        Location = pfFile,
                        FileName = Path.GetFileName(pfFile),
                        Reason   = $"Eine Prefetch-Datei für '{description}' ({Path.GetFileName(pfFile)}) " +
                                   "wurde gefunden. Prefetch-Dateien beweisen, dass eine Anwendung in der " +
                                   "Vergangenheit ausgeführt wurde, selbst wenn die Originaldatei gelöscht wurde. " +
                                   "Das deutet auf frühere Anti-Forensik-Aktivitäten hin.",
                        Detail   = $"Prefetch-Datei: {pfFile}"
                    });
                }
            }
        }, ct);
    }
}
