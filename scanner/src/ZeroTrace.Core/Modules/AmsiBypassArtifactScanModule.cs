using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AmsiBypassArtifactScanModule : IScanModule
{
    public string Name => "AMSI-Bypass-Artifact";
    public double Weight => 0.75;
    public int ParallelGroup => 4;

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly string PsHistoryPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

    private static readonly (string Pattern, string Description, RiskLevel Risk)[] AmsiBypassPatterns =
    {
        ("[ref].assembly.gettype('system.management.automation.amsiutils')",
            "AMSI-Bypass via Reflection (AmsiUtils)", RiskLevel.Critical),
        ("amsiinitfailed",
            "AMSI-Bypass: amsiInitFailed-Feld gepatcht", RiskLevel.Critical),
        ("amsiscanbuffer",
            "AMSI-Bypass: AmsiScanBuffer direkt manipuliert", RiskLevel.Critical),
        ("[runtime.interopservices.marshal]::copy",
            "AMSI-Bypass: Marshal::Copy (Memory-Patch)", RiskLevel.High),
        ("$a=[ref].assembly.gettype",
            "AMSI-Bypass (obfuskiert): Reflection-Zugriff auf AmsiUtils", RiskLevel.Critical),
        ("set-item variable:",
            "AMSI-Bypass via Environment-Variable (Set-Item Variable:)", RiskLevel.High),
        ("sET-ItEM",
            "AMSI-Bypass: Gemischte Groß-/Kleinschreibung (Case-Bypass)", RiskLevel.High),
        ("virtualprotect",
            "AMSI-Bypass: VirtualProtect-Speicherschutz-Manipulation", RiskLevel.High),
        ("0xb8,0x57,0x00,0x07,0x80",
            "AMSI-Bypass: Bekannte Patch-Bytes (B8 57 00 07 80 = NTSTATUS return)", RiskLevel.Critical),
        ("0x31,0xc0",
            "AMSI-Bypass: XOR EAX,EAX Patch-Bytes", RiskLevel.Critical),
        ("0xeb",
            "AMSI-Bypass: JMP-Opcode Patch-Bytes", RiskLevel.High),
        ("invoke-expression (new-object net.webclient).downloadstring",
            "AMSI-Bypass kombiniert mit Remote-Code-Download", RiskLevel.Critical),
        ("[byte[]] $patch",
            "AMSI-Bypass: Byte-Array-Patch im Skript", RiskLevel.Critical),
        ("amsi.dll",
            "AMSI-DLL direkt referenziert (manuelles Patching)", RiskLevel.High),
    };

    private static readonly string[] AmsiBypassExeNames =
    {
        "amsi_bypass.exe", "amsibypass.exe", "amsi_patch.exe",
        "amsi_killer.exe", "ps_amsi_bypass.exe"
    };

    private static readonly string[] WdacBypassExeNames =
    {
        "wdac_bypass.exe", "device_guard_bypass.exe", "ci_bypass.exe"
    };

    private static readonly string[] ClmBypassExeNames =
    {
        "clm_bypass.exe", "ps_bypass.exe", "constrained_bypass.exe"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanAmsiBypassInHistoryAndScriptsAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await CheckAmsiProviderRegistryAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanDotNetAmsiBypassArtifactsAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await CheckScriptBlockLoggingBypassAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanClmBypassArtifactsAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanWdacBypassArtifactsAsync(ctx, ct);
        if (ct.IsCancellationRequested) return;

        await ScanAmsiBypassToolsAndPrefetchAsync(ctx, ct);
    }

    private async Task ScanAmsiBypassInHistoryAndScriptsAsync(ScanContext ctx, CancellationToken ct)
    {
        if (File.Exists(PsHistoryPath))
        {
            ctx.IncrementFiles();
            try
            {
                string histContent;
                using var fs = new FileStream(PsHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                histContent = await sr.ReadToEndAsync();

                foreach (var (pattern, description, _) in AmsiBypassPatterns)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!histContent.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"PS-Verlauf: AMSI-Bypass-Muster — {description}",
                        Risk     = RiskLevel.High,
                        Location = PsHistoryPath,
                        FileName = "ConsoleHost_history.txt",
                        Reason   = $"Der PowerShell-Verlauf enthält das AMSI-Bypass-Muster '{pattern}'. " +
                                   "AMSI-Bypasses ermöglichen das Ausführen von Cheat-Skripten und " +
                                   "-Loadern ohne Erkennung durch Windows-Defender und Anti-Malware-APIs. " +
                                   $"Kontext: {description}",
                        Detail   = $"Muster: {pattern} | Datei: {PsHistoryPath}"
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        var scriptDirs = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Documents"),
            AppDataRoaming,
            AppDataLocal,
        };

        foreach (var dir in scriptDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    string content;
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();

                    foreach (var (pattern, description, _) in AmsiBypassPatterns)
                    {
                        if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"AMSI-Bypass-Skript gespeichert: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Die PowerShell-Datei '{Path.GetFileName(file)}' enthält AMSI-Bypass-Code " +
                                       $"(Muster: '{pattern}'). Eine gespeicherte Bypass-Skriptdatei ist ein " +
                                       "stärkerer Indikator als ein Verlaufseintrag, da sie auf eine bewusste " +
                                       $"Verwendung hinweist. Beschreibung: {description}",
                            Detail   = $"Muster: {pattern} | Pfad: {file}"
                        });
                        break;
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    private async Task CheckAmsiProviderRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            const string providersKeyPath = @"SOFTWARE\Microsoft\AMSI\Providers";
            try
            {
                using var providersKey = Registry.LocalMachine.OpenSubKey(providersKeyPath, writable: false);
                if (providersKey is null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "AMSI-Provider-Registry-Schlüssel fehlt",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{providersKeyPath}",
                        Reason   = $"Der AMSI-Provider-Registrierungsschlüssel '{providersKeyPath}' " +
                                   "existiert nicht. Fehlende AMSI-Provider bedeuten, dass keine " +
                                   "Antimalware-Lösung für Script-Scanning registriert ist — " +
                                   "ein möglicher Bypass durch Löschung aller Provider.",
                        Detail   = $@"HKLM\{providersKeyPath} nicht vorhanden"
                    });
                    return;
                }

                var subKeyNames = providersKey.GetSubKeyNames();
                ctx.IncrementRegistryKeys();

                if (subKeyNames.Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Keine AMSI-Provider registriert",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{providersKeyPath}",
                        Reason   = "Unter dem AMSI-Provider-Schlüssel sind keine Provider-GUIDs registriert. " +
                                   "Ohne registrierte Provider führt Windows keine AMSI-Scans durch. " +
                                   "Dies deutet auf einen AMSI-Bypass durch vollständiges Entfernen der Provider hin.",
                        Detail   = $"Anzahl registrierter AMSI-Provider: 0"
                    });
                    return;
                }

                var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
                var windowsDefenderPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Windows Defender");

                foreach (var guidName in subKeyNames)
                {
                    if (ct.IsCancellationRequested) return;

                    try
                    {
                        using var guidKey = providersKey.OpenSubKey(guidName, writable: false);
                        if (guidKey is null) continue;

                        ctx.IncrementRegistryKeys();
                        var dllPath = guidKey.GetValue(null) as string ?? string.Empty;

                        if (string.IsNullOrWhiteSpace(dllPath))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"AMSI-Provider ohne DLL-Pfad: {guidName}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{providersKeyPath}\{guidName}",
                                Reason   = $"Der AMSI-Provider '{guidName}' hat keinen DLL-Pfad registriert. " +
                                           "Ein Provider ohne DLL-Pfad kann nicht geladen werden — " +
                                           "dies entspricht einem defekten Provider, der den AMSI-Scan für " +
                                           "diesen Provider effektiv deaktiviert.",
                                Detail   = $"GUID: {guidName} | DLL-Pfad: (leer)"
                            });
                            continue;
                        }

                        var normalizedDll = dllPath.Trim('"').Trim();

                        if (!File.Exists(normalizedDll))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"AMSI-Provider DLL fehlt: {Path.GetFileName(normalizedDll)}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{providersKeyPath}\{guidName}",
                                Reason   = $"Der AMSI-Provider '{guidName}' referenziert die DLL " +
                                           $"'{normalizedDll}', die nicht auf der Festplatte existiert. " +
                                           "Eine fehlende Provider-DLL ist ein klassisches AMSI-Bypass-Muster: " +
                                           "Der registrierte Provider kann nicht geladen werden, " +
                                           "daher findet kein AMSI-Scan statt.",
                                Detail   = $"GUID: {guidName} | Fehlende DLL: {normalizedDll}"
                            });
                            continue;
                        }

                        var isInSystem32 = normalizedDll.StartsWith(system32, StringComparison.OrdinalIgnoreCase);
                        var isInWindowsDefender = normalizedDll.StartsWith(windowsDefenderPath, StringComparison.OrdinalIgnoreCase);

                        if (!isInSystem32 && !isInWindowsDefender)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"AMSI-Provider aus unbekanntem Pfad: {Path.GetFileName(normalizedDll)}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{providersKeyPath}\{guidName}",
                                Reason   = $"Der AMSI-Provider '{guidName}' lädt die DLL aus '{normalizedDll}', " +
                                           "einem Pfad außerhalb von System32 und Windows Defender. " +
                                           "Ein AMSI-Provider außerhalb der bekannten Systempfade könnte " +
                                           "ein gefälschter Provider sein, der AMSI-Scans ignoriert oder fälscht.",
                                Detail   = $"GUID: {guidName} | DLL: {normalizedDll}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (Exception) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }

            const string wshAmsiKeyPath = @"SOFTWARE\Microsoft\Windows Script\Settings";
            try
            {
                using var wshKey = Registry.LocalMachine.OpenSubKey(wshAmsiKeyPath, writable: false);
                if (wshKey is null) return;

                var amsiEnable = wshKey.GetValue("AmsiEnable");
                ctx.IncrementRegistryKeys();

                if (amsiEnable is int amsiVal && amsiVal == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "AMSI für Windows Script Host deaktiviert",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{wshAmsiKeyPath}",
                        Reason   = "AmsiEnable=0 unter Windows Script Settings deaktiviert AMSI-Scans " +
                                   "für alle VBScript- und JScript-Dateien, die über WSH ausgeführt werden. " +
                                   "Cheat-Loader nutzen WSH-Skripte, die ohne AMSI völlig ungehindert " +
                                   "ausgeführt werden können.",
                        Detail   = $@"HKLM\{wshAmsiKeyPath}\AmsiEnable = {amsiVal}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }
        }, ct);
    }

    private async Task ScanDotNetAmsiBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var dotNetBypassPatterns = new[]
        {
            "System.Management.Automation.AmsiUtils",
            "amsiInitFailed",
            "AmsiScanBuffer",
            "COMPLUS_ETWEnabled",
        };

        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Documents"),
            AppDataLocal,
            AppDataRoaming,
        };

        var scanExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".cs", ".exe", ".dll"
        };

        foreach (var dir in scanDirs)
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

                var ext = Path.GetExtension(file);
                if (!scanExtensions.Contains(ext)) continue;

                ctx.IncrementFiles();

                try
                {
                    byte[] buffer = new byte[4096];
                    int bytesRead;

                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    bytesRead = await fs.ReadAsync(buffer.AsMemory(0, 4096), ct);

                    var preview = System.Text.Encoding.UTF8.GetString(buffer, 0, bytesRead);

                    foreach (var pattern in dotNetBypassPatterns)
                    {
                        if (!preview.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $".NET AMSI-Bypass-Artefakt: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Die Datei '{Path.GetFileName(file)}' enthält das .NET-AMSI-Bypass-Muster " +
                                       $"'{pattern}' in den ersten 4 KB. .NET-Assemblies können AMSI via " +
                                       "Reflection umgehen, indem sie AmsiUtils direkt patchen. " +
                                       "Dies ist ein stärkeres Indiz als ein Verlaufseintrag.",
                            Detail   = $"Muster: {pattern} | Pfad: {file}"
                        });
                        break;
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
                catch (OperationCanceledException) { return; }
            }
        }
    }

    private async Task CheckScriptBlockLoggingBypassAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            var scriptBlockPaths = new[]
            {
                (@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", Registry.LocalMachine, "HKLM"),
                (@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", Registry.CurrentUser,  "HKCU"),
                (@"SOFTWARE\Policies\Microsoft\Windows\PowerShell",                   Registry.LocalMachine, "HKLM"),
                (@"SOFTWARE\Policies\Microsoft\Windows\PowerShell",                   Registry.CurrentUser,  "HKCU"),
            };

            foreach (var (keyPath, hive, hiveShort) in scriptBlockPaths)
            {
                if (ct.IsCancellationRequested) return;

                try
                {
                    using var key = hive.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    var sblObj = key.GetValue("EnableScriptBlockLogging");
                    ctx.IncrementRegistryKeys();

                    if (sblObj is int sblVal && sblVal == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Script Block Logging deaktiviert ({hiveShort})",
                            Risk     = RiskLevel.Critical,
                            Location = $@"{hiveShort}\{keyPath}",
                            Reason   = $"EnableScriptBlockLogging=0 unter '{hiveShort}\\{keyPath}' " +
                                       "deaktiviert die PowerShell-Script-Block-Protokollierung (EventID 4104). " +
                                       "Ohne Script Block Logging können AMSI-Bypass-Skripte und Cheat-Loader " +
                                       "ausgeführt werden, ohne in den Ereignisprotokollen zu erscheinen.",
                            Detail   = $@"{hiveShort}\{keyPath}\EnableScriptBlockLogging = {sblVal}"
                        });
                    }

                    var sbilObj = key.GetValue("EnableScriptBlockInvocationLogging");
                    ctx.IncrementRegistryKeys();

                    if (sbilObj is int sbilVal && sbilVal == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Script Block Invocation Logging deaktiviert ({hiveShort})",
                            Risk     = RiskLevel.High,
                            Location = $@"{hiveShort}\{keyPath}",
                            Reason   = $"EnableScriptBlockInvocationLogging=0 deaktiviert die Protokollierung " +
                                       "jedes einzelnen PS-Script-Block-Aufrufs. Dies reduziert die forensische " +
                                       "Sichtbarkeit von AMSI-Bypass-Techniken und Cheat-Loader-Aktivitäten.",
                            Detail   = $@"{hiveShort}\{keyPath}\EnableScriptBlockInvocationLogging = {sbilVal}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception) { }
            }
        }, ct);

        if (ct.IsCancellationRequested) return;

        if (!File.Exists(PsHistoryPath)) return;

        var loggingDisablePatterns = new[]
        {
            "set-itemproperty.*enablescriptblocklogging.*0",
            "new-itemproperty.*scriptblocklogging.*0",
            "enablescriptblocklogging",
        };

        try
        {
            string content;
            using var fs = new FileStream(PsHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();

            foreach (var pattern in loggingDisablePatterns)
            {
                if (content.Contains("EnableScriptBlockLogging", StringComparison.OrdinalIgnoreCase) &&
                    (content.Contains("0", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("disable", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "PS-Verlauf: Script Block Logging über PowerShell deaktiviert",
                        Risk     = RiskLevel.High,
                        Location = PsHistoryPath,
                        FileName = "ConsoleHost_history.txt",
                        Reason   = "Der PowerShell-Verlauf enthält einen Befehl zum Deaktivieren von " +
                                   "Script Block Logging (EnableScriptBlockLogging=0). " +
                                   "Dies ist ein Anti-Forensik-Schritt, der vor dem Ausführen von " +
                                   "AMSI-Bypass-Skripten oder Cheat-Loadern durchgeführt wird.",
                        Detail   = $"Muster: EnableScriptBlockLogging | Verlauf: {PsHistoryPath}"
                    });
                    break;
                }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private async Task ScanClmBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        if (File.Exists(PsHistoryPath))
        {
            ctx.IncrementFiles();
            var clmPatterns = new[]
            {
                ("[system.runtime.interopservices.runtimeenvironment]", RiskLevel.Medium, "CLM-Bypass via RuntimeEnvironment"),
                ("$env:__pslockdownpolicy",                            RiskLevel.Medium, "CLM-Bypass via __PSLockdownPolicy"),
                ("$env:psexecutionpolicypreference",                   RiskLevel.Medium, "CLM-Bypass via PSExecutionPolicyPreference"),
            };

            try
            {
                string histContent;
                using var fs = new FileStream(PsHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                histContent = await sr.ReadToEndAsync();

                foreach (var (pattern, risk, description) in clmPatterns)
                {
                    if (!histContent.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"PS-Verlauf: CLM-Bypass-Muster — {description}",
                        Risk     = risk,
                        Location = PsHistoryPath,
                        FileName = "ConsoleHost_history.txt",
                        Reason   = $"Der PS-Verlauf enthält '{pattern}' — ein Indikator für einen " +
                                   "PowerShell Constrained Language Mode Bypass. CLM-Bypasses ermöglichen " +
                                   "die Ausführung von erweiterten PS-Funktionen in gesperrten Umgebungen " +
                                   "und werden von Cheat-Loadern eingesetzt.",
                        Detail   = $"Muster: {pattern}"
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        var searchDirs = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            AppDataLocal,
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
                if (!ClmBypassExeNames.Any(n => n.Equals(fileName, StringComparison.OrdinalIgnoreCase)))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"CLM-Bypass-Tool gefunden: {fileName}",
                    Risk     = RiskLevel.Medium,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Das Programm '{fileName}' ist ein bekanntes Tool zur Umgehung des " +
                               "PowerShell Constrained Language Mode. CLM-Bypasses ermöglichen Cheat-Loadern, " +
                               "vollständige PS-Funktionalität in gesperrten Umgebungen zu nutzen.",
                    Detail   = $"Pfad: {file}"
                });
            }
        }
    }

    private async Task ScanWdacBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            AppDataLocal,
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
                if (!WdacBypassExeNames.Any(n => n.Equals(fileName, StringComparison.OrdinalIgnoreCase)))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"WDAC/Device Guard Bypass-Tool gefunden: {fileName}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Das Programm '{fileName}' ist ein bekanntes Tool zur Umgehung von " +
                               "Windows Defender Application Control (WDAC/Device Guard). " +
                               "WDAC-Bypasses ermöglichen das Ausführen unsignierter Cheat-Binärdateien " +
                               "auch in gesperrten Enterprise-Umgebungen.",
                    Detail   = $"Pfad: {file}"
                });
            }
        }

        if (File.Exists(PsHistoryPath))
        {
            var wdacPatterns = new[]
            {
                "set-ruleoption.*unsigned system integrity policy",
                "convertfrom-cipolicy",
                "[io.file]::writeallbytes.*sipolicy",
                "sipolicy",
            };

            try
            {
                string content;
                using var fs = new FileStream(PsHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();

                foreach (var pattern in wdacPatterns)
                {
                    if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"PS-Verlauf: WDAC-Policy-Manipulation — {pattern}",
                        Risk     = RiskLevel.High,
                        Location = PsHistoryPath,
                        FileName = "ConsoleHost_history.txt",
                        Reason   = $"Der PS-Verlauf enthält '{pattern}' — ein Hinweis auf Manipulation der " +
                                   "Windows Defender Application Control-Richtlinie. WDAC-Policy-Manipulation " +
                                   "ermöglicht das Ausführen unsignierter Cheat-Binärdateien und Treiber.",
                        Detail   = $"Muster: {pattern}"
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        await CheckWdacSiPolicyAsync(ctx, ct);
    }

    private async Task CheckWdacSiPolicyAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            var siPolicyPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "CodeIntegrity", "SiPolicy.p7b");

            ctx.IncrementFiles();

            if (!File.Exists(siPolicyPath)) return;

            try
            {
                var fi = new FileInfo(siPolicyPath);
                if (fi.Length < 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "SiPolicy.p7b (WDAC-Policy) ungewöhnlich klein",
                        Risk     = RiskLevel.High,
                        Location = siPolicyPath,
                        FileName = "SiPolicy.p7b",
                        Reason   = $"Die WDAC-Richtliniendatei SiPolicy.p7b ist nur {fi.Length} Bytes groß " +
                                   "(weniger als 1 KB). Eine derart kleine Datei könnte eine manipulierte " +
                                   "Policy sein, die alle Signaturen erlaubt (Allowlist-Policy), was " +
                                   "das Laden unsignierter Cheat-Treiber ermöglicht.",
                        Detail   = $"Dateigröße: {fi.Length} Bytes | Pfad: {siPolicyPath}"
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private async Task ScanAmsiBypassToolsAndPrefetchAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            AppDataLocal,
            AppDataRoaming,
            TempPath,
        };

        var tempPath = Path.GetTempPath();

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
                if (!AmsiBypassExeNames.Any(n => n.Equals(fileName, StringComparison.OrdinalIgnoreCase)))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"AMSI-Bypass-Tool gefunden: {fileName}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Das Programm '{fileName}' ist ein bekanntes AMSI-Bypass-Tool. " +
                               "AMSI-Bypass-Tools deaktivieren den Windows Antimalware Scan Interface, " +
                               "damit Cheat-Skripte und -Loader ohne AV-Erkennung ausgeführt werden können.",
                    Detail   = $"Pfad: {file}"
                });
            }
        }

        var prefetchPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Prefetch");

        if (!Directory.Exists(prefetchPath)) return;

        var pfPatterns = new[]
        {
            ("AMSI_BYPASS",  RiskLevel.High, "AMSI-Bypass-Tool"),
            ("AMSIBYPASS",   RiskLevel.High, "AMSI-Bypass-Tool"),
            ("PSBYPASS",     RiskLevel.High, "PS-Bypass-Tool"),
            ("CLM_BYPASS",   RiskLevel.Medium, "CLM-Bypass-Tool"),
            ("WDAC_BYPASS",  RiskLevel.High, "WDAC-Bypass-Tool"),
            ("PS_AMSI",      RiskLevel.High, "PS-AMSI-Bypass-Tool"),
        };

        IEnumerable<string> pfFiles;
        try
        {
            pfFiles = Directory.EnumerateFiles(prefetchPath, "*.pf", SearchOption.TopDirectoryOnly);
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

                foreach (var (pattern, risk, description) in pfPatterns)
                {
                    if (!pfName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Prefetch: {description} wurde ausgeführt",
                        Risk     = risk,
                        Location = pfFile,
                        FileName = Path.GetFileName(pfFile),
                        Reason   = $"Die Prefetch-Datei '{Path.GetFileName(pfFile)}' belegt, dass ein " +
                                   $"{description} in der Vergangenheit auf diesem System ausgeführt wurde. " +
                                   "Prefetch-Einträge bleiben nach Dateilöschung erhalten und sind starke " +
                                   "forensische Beweise für frühere AMSI-Bypass-Aktivitäten.",
                        Detail   = $"Prefetch: {pfFile}"
                    });
                }
            }
        }, ct);
    }

    private static readonly string TempPath = Path.GetTempPath();
}
