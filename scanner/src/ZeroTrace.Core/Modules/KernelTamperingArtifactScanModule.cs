using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class KernelTamperingArtifactScanModule : IScanModule
{
    public string Name => "Kernel-Tampering";
    public double Weight => 0.85;
    public int ParallelGroup => 4;

    private const string PrefetchDir = @"C:\Windows\Prefetch";

    private static readonly string[] DkomExeNames =
    {
        "dkom.exe", "dkom_tool.exe", "process_hider.exe", "hide_process.exe",
        "kprocess_hide.exe", "peb_unlink.exe", "eprocess_hide.exe",
        "ghosting_tool.exe", "process_ghost.exe", "process_doppelganging.exe",
        "transacted_hollow.exe", "modulemasking.exe",
    };

    private static readonly string[] DkomDllNames =
    {
        "dkom.dll", "process_hider.dll", "hide_process.dll", "ghosting.dll",
    };

    private static readonly string[] ByovdExeNames =
    {
        "kdmapper.exe", "drvmap.exe", "ksocket.exe", "capcom.exe", "gdrv.exe",
        "physmem.exe", "physmem_access.exe", "rtcore64_exploit.exe",
        "mhyprot_exploit.exe", "dbutil_exploit.exe", "iqvw64e_exploit.exe",
        "cpuz_exploit.exe", "aswarpot_exploit.exe", "procexp_exploit.exe",
    };

    private static readonly string[] KnownVulnerableDrivers =
    {
        "gdrv.sys", "rtcore64.sys", "mhyprot2.sys", "dbutil_2_3.sys",
        "iqvw64e.sys", "cpuz141_x64.sys", "aswarpot.sys", "kprocesshacker.sys",
    };

    private static readonly string[] DseBypassExeNames =
    {
        "dse_bypass.exe", "dse_patch.exe", "dse_disable.exe", "ci_patch.exe",
        "dsepatch.exe", "bootkit.exe", "testmode_enable.exe",
    };

    private static readonly string[] HandleToolExeNames =
    {
        "handle_hijack.exe", "handle_hijacker.exe", "ac_handle_close.exe",
        "openclosedhandle.exe", "handlekill.exe", "protected_handle_bypass.exe",
        "vachandle.exe", "eachandle.exe",
    };

    private static readonly string[] TokenTheftExeNames =
    {
        "token_theft.exe", "token_impersonation.exe", "getsystem.exe",
        "impersonate.exe", "privilege_escalation.exe",
    };

    private static readonly string[] PatchguardExeNames =
    {
        "patchguard_bypass.exe", "pg_bypass.exe", "pg_killer.exe", "kpp_bypass.exe",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Pruefe ETW-Tampering...");
        await CheckEtwTamperingAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.15, Name, "Pruefe DKOM-Werkzeuge...");
        await ScanForDkomArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.3, Name, "Pruefe BYOVD-Werkzeuge...");
        await ScanForByovdArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.45, Name, "Pruefe DSE-Bypass-Artefakte...");
        await ScanForDseBypassArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.55, Name, "Pruefe Kernel-Debugger-Artefakte...");
        await CheckKernelDebuggerArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.65, Name, "Pruefe Handle-Manipulations-Werkzeuge...");
        await ScanForHandleToolArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.72, Name, "Pruefe Token-Impersonation-Werkzeuge...");
        await ScanForTokenTheftArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.79, Name, "Pruefe PatchGuard-Bypass-Artefakte...");
        await ScanForPatchguardArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.86, Name, "Pruefe Windows Defender ELAM...");
        CheckElamDriverIntegrity(ctx);

        ctx.Report(0.93, Name, "Pruefe Prefetch-Artefakte...");
        ScanPrefetchForKernelTools(ctx, ct);

        ctx.Report(1.0, Name, "Kernel-Tampering-Analyse abgeschlossen");
    }

    // -------------------------------------------------------------------------
    // ETW tampering
    // -------------------------------------------------------------------------

    private async Task CheckEtwTamperingAsync(ScanContext ctx, CancellationToken ct)
    {
        CheckEtwAutologgerProvider(ctx,
            @"SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "Security Audit ETW Provider deaktiviert",
            "Der ETW-Provider {54849625-5478-4994-a5ba-3e3b0328c30d} (EventLog-System) ist deaktiviert. " +
            "Anti-Cheat-Software (EAC, BattlEye, VAC) verwendet ETW zur Spielueberwachung. " +
            "Cheats deaktivieren diesen Provider, um die Erkennung zu umgehen.",
            RiskLevel.High);

        ct.ThrowIfCancellationRequested();

        CheckEtwAutologgerProvider(ctx,
            @"SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger\{9e814aad-3204-11d2-9a82-006008a86939}",
            "Circular Kernel Context Logger ETW Provider deaktiviert",
            "Der Kernel-Context-Logger ETW-Provider ist deaktiviert. " +
            "Dieser Provider liefert Kernel-Ereignisse an Anti-Cheat-Systeme. " +
            "Die Deaktivierung ist ein starker Indikator fuer ETW-Tampering.",
            RiskLevel.High);

        ct.ThrowIfCancellationRequested();

        CheckEtwDiagnosticsRegistry(ctx);

        ct.ThrowIfCancellationRequested();

        await ScanPowerShellForEtwPatchingAsync(ctx, ct).ConfigureAwait(false);
    }

    private static void CheckEtwAutologgerProvider(ScanContext ctx, string subKey,
        string title, string reason, RiskLevel risk)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = baseKey.OpenSubKey(subKey, writable: false);
            ctx.IncrementRegistryKeys();
            if (k is null) return;

            var enabled = k.GetValue("Enabled");
            ctx.IncrementRegistryKeys();
            if (enabled is null) return;

            int val = Convert.ToInt32(enabled);
            if (val == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = title,
                    Risk = risk,
                    Location = @"HKLM\" + subKey,
                    Reason = reason,
                    Detail = $"Enabled = {val}"
                });
            }
        }
        catch { }
    }

    private static void CheckEtwDiagnosticsRegistry(ScanContext ctx)
    {
        const string diagKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Diagnostics\ETW";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = baseKey.OpenSubKey(diagKey, writable: false);
            ctx.IncrementRegistryKeys();
            if (k is null) return;

            foreach (var valueName in k.GetValueNames())
            {
                ctx.IncrementRegistryKeys();
                var val = k.GetValue(valueName);
                if (val is null) continue;
                var strVal = val.ToString() ?? "";
                if (strVal.Equals("0", StringComparison.OrdinalIgnoreCase) ||
                    valueName.Contains("disable", StringComparison.OrdinalIgnoreCase) ||
                    valueName.Contains("override", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Kernel-Tampering",
                        Title = $"ETW Diagnostics Override: {valueName}",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\" + diagKey,
                        Reason = $"ETW-Diagnose-Override-Registrierungsschluessel gefunden: '{valueName}' = '{strVal}'. " +
                                 "Cheat-Software setzt solche Uebersteuerungen, um ETW-Provider zu deaktivieren.",
                        Detail = $"Wert: {valueName} = {strVal}"
                    });
                }
            }
        }
        catch { }
    }

    private static async Task ScanPowerShellForEtwPatchingAsync(ScanContext ctx, CancellationToken ct)
    {
        var etwPatterns = new[]
        {
            "Remove-EtwTraceProvider",
            "[Reflection.Assembly]::LoadWithPartialName",
            "ETWProvider",
            "NtTraceControl",
            "EtwEventWrite",
        };

        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var psHistoryDir = Path.Combine(roaming, "Microsoft", "Windows", "PowerShell", "PSReadLine");
        await ScanTextFilesForPatternsAsync(ctx, psHistoryDir, "*.txt", etwPatterns,
            "ETW-Patch in PowerShell-History",
            RiskLevel.High, ct).ConfigureAwait(false);

        var psModulePath = Environment.GetEnvironmentVariable("PSModulePath") ?? "";
        foreach (var dir in psModulePath.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            if (ct.IsCancellationRequested) break;
            await ScanTextFilesForPatternsAsync(ctx, dir, "*.ps1", etwPatterns,
                "ETW-Patch in PowerShell-Skript",
                RiskLevel.High, ct).ConfigureAwait(false);
        }

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var psScriptsDir = Path.Combine(localAppData, "Microsoft", "Windows", "PowerShell");
        await ScanTextFilesForPatternsAsync(ctx, psScriptsDir, "*.ps1", etwPatterns,
            "ETW-Patch in PowerShell-Skript",
            RiskLevel.High, ct).ConfigureAwait(false);
    }

    private static async Task ScanTextFilesForPatternsAsync(
        ScanContext ctx, string directory, string searchPattern,
        string[] patterns, string title,
        RiskLevel risk, CancellationToken ct)
    {
        if (!Directory.Exists(directory)) return;
        string[] files;
        try { files = Directory.GetFiles(directory, searchPattern, SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                string content;
                using var sr = new StreamReader(file, detectEncodingFromByteOrderMarks: true);
                content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                foreach (var pattern in patterns)
                {
                    if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module = "Kernel-Tampering",
                        Title = title,
                        Risk = risk,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Datei '{Path.GetFileName(file)}' enthaelt ETW-Patch-Muster '{pattern}'. " +
                                 "Solche Skripte patchen den ETW-Schreibcode im Speicher, um Anti-Cheat-Tracing zu deaktivieren.",
                        Detail = $"Muster: {pattern}"
                    });
                    break;
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // -------------------------------------------------------------------------
    // DKOM artifacts
    // -------------------------------------------------------------------------

    private async Task ScanForDkomArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            await ScanDirectoryForFileNamesAsync(ctx, dir, DkomExeNames, DkomDllNames,
                "DKOM-Werkzeug gefunden",
                RiskLevel.Critical,
                "Direct Kernel Object Manipulation (DKOM) Werkzeug auf dem System gefunden. " +
                "DKOM-Tools entkoppeln Prozesse aus der Kernel-Prozessliste, um sie vor Anti-Cheat-Software zu verbergen.",
                ct).ConfigureAwait(false);
        }

        ScanPrefetchForPatterns(ctx, ct,
            new[] { "DKOM", "PROCESS_HIDER", "PROCESSGHOST" },
            "DKOM-Werkzeug in Prefetch",
            RiskLevel.Critical,
            "Prefetch-Eintrag weist auf Ausfuehrung eines DKOM-Werkzeugs hin. " +
            "DKOM-Tools manipulieren Kernel-Datenstrukturen um Prozesse zu verstecken.");
    }

    // -------------------------------------------------------------------------
    // BYOVD artifacts
    // -------------------------------------------------------------------------

    private async Task ScanForByovdArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            await ScanDirectoryForFileNamesAsync(ctx, dir, ByovdExeNames, Array.Empty<string>(),
                "BYOVD-Werkzeug gefunden",
                RiskLevel.Critical,
                "Bring Your Own Vulnerable Driver (BYOVD) Werkzeug gefunden. " +
                "BYOVD nutzt signierte, aber verwundbare Treiber aus, um Kernel-Zugang zu erlangen und Cheats zu laden.",
                ct).ConfigureAwait(false);
        }

        await ScanForVulnerableDriverFilesAsync(ctx, ct).ConfigureAwait(false);

        ScanPrefetchForPatterns(ctx, ct,
            new[] { "KDMAPPER", "DRVMAP", "KSOCKET", "CAPCOM", "PHYSMEM" },
            "BYOVD-Werkzeug in Prefetch",
            RiskLevel.Critical,
            "Prefetch-Eintrag deutet auf Ausfuehrung eines BYOVD-Werkzeugs hin. " +
            "Diese Tools werden verwendet, um anfaellige Treiber zu laden und Kernel-Code auszufuehren.");
    }

    private static async Task ScanForVulnerableDriverFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var system32Drivers = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");

        var dirsToCheck = new List<string>();
        if (Directory.Exists(system32Drivers)) dirsToCheck.Add(system32Drivers);

        var tempDir = Path.GetTempPath();
        if (Directory.Exists(tempDir)) dirsToCheck.Add(tempDir);

        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (Directory.Exists(downloads)) dirsToCheck.Add(downloads);

        foreach (var dir in dirsToCheck)
        {
            if (ct.IsCancellationRequested) return;
            string[] sysFiles;
            try { sysFiles = Directory.GetFiles(dir, "*.sys", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var sysFile in sysFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(sysFile);
                if (!KnownVulnerableDrivers.Any(d => fn.Equals(d, StringComparison.OrdinalIgnoreCase)))
                    continue;

                long fileSize = 0;
                try { fileSize = new FileInfo(sysFile).Length; } catch { }

                bool isNonStandard = !dir.Equals(system32Drivers, StringComparison.OrdinalIgnoreCase);

                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = $"Bekannter verwundbarer Treiber: {fn}",
                    Risk = RiskLevel.Critical,
                    Location = sysFile,
                    FileName = fn,
                    Reason = $"Bekannter BYOVD-anfaelliger Treiber '{fn}' gefunden" +
                             (isNonStandard ? " ausserhalb des System32\\drivers Verzeichnisses" : " in System32\\drivers") +
                             ". Dieser Treiber wird von BYOVD-Exploits ausgenutzt, um unautorisierten Kernel-Zugang zu erlangen.",
                    Detail = $"Pfad: {sysFile} | Groesse: {fileSize} Bytes"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // DSE bypass artifacts
    // -------------------------------------------------------------------------

    private async Task ScanForDseBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            await ScanDirectoryForFileNamesAsync(ctx, dir, DseBypassExeNames, Array.Empty<string>(),
                "DSE-Bypass-Werkzeug gefunden",
                RiskLevel.High,
                "Driver Signature Enforcement (DSE) Bypass-Werkzeug gefunden. " +
                "DSE-Bypass ermoeglicht das Laden unsignierter Kernel-Treiber, was fuer viele Cheat-Treiber erforderlich ist.",
                ct).ConfigureAwait(false);
        }

        CheckDseRegistrySettings(ctx);
        CheckSecureBootRegistry(ctx);
        CheckBootExecuteRegistry(ctx);

        ScanPrefetchForPatterns(ctx, ct,
            new[] { "DSE_BYPASS", "CIPATCH", "TESTMODE" },
            "DSE-Bypass-Werkzeug in Prefetch",
            RiskLevel.High,
            "Prefetch-Eintrag weist auf Ausfuehrung eines DSE-Bypass-Werkzeugs hin. " +
            "Diese Tools umgehen die Windows-Treibersignaturpruefung.");
    }

    private static void CheckDseRegistrySettings(ScanContext ctx)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config", writable: false);
            ctx.IncrementRegistryKeys();
            if (k is null) return;

            ctx.IncrementRegistryKeys();
            var blocklistVal = k.GetValue("VulnerableDriverBlocklistEnable");
            if (blocklistVal is not null && Convert.ToInt32(blocklistVal) == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = "Verwundbare-Treiber-Blockliste deaktiviert",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
                    Reason = "VulnerableDriverBlocklistEnable = 0. Die Windows-Blockliste fuer bekannte anfaellige Treiber " +
                             "ist deaktiviert. Dies ist eine Voraussetzung fuer BYOVD-Angriffe.",
                    Detail = $"VulnerableDriverBlocklistEnable = {blocklistVal}"
                });
            }

            ctx.IncrementRegistryKeys();
            var upgradeUnsigned = k.GetValue("UpgradeUnsignedDrivers");
            if (upgradeUnsigned is not null && Convert.ToInt32(upgradeUnsigned) == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = "Unsignierte Treiber-Hochstufung aktiviert",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
                    Reason = "UpgradeUnsignedDrivers = 1. Diese Einstellung erlaubt das Laden unsignierter Treiber " +
                             "und ist ein Zeichen fuer DSE-Manipulation.",
                    Detail = "UpgradeUnsignedDrivers = 1"
                });
            }
        }
        catch { }
    }

    private static void CheckSecureBootRegistry(ScanContext ctx)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", writable: false);
            ctx.IncrementRegistryKeys();
            if (k is null) return;

            ctx.IncrementRegistryKeys();
            var secureBootEnabled = k.GetValue("UEFISecureBootEnabled");
            if (secureBootEnabled is not null && Convert.ToInt32(secureBootEnabled) == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = "Secure Boot deaktiviert",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                    Reason = "UEFISecureBootEnabled = 0. Secure Boot ist deaktiviert, was eine Voraussetzung " +
                             "fuer viele Kernel-Cheat-Techniken und Boot-Kit-Angriffe ist.",
                    Detail = "UEFISecureBootEnabled = 0"
                });
            }
        }
        catch { }
    }

    private static void CheckBootExecuteRegistry(ScanContext ctx)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = baseKey.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager", writable: false);
            ctx.IncrementRegistryKeys();
            if (k is null) return;

            ctx.IncrementRegistryKeys();
            var bootExecute = k.GetValue("BootExecute");
            if (bootExecute is null) return;

            string[] entries = bootExecute is string[] arr ? arr : new[] { bootExecute.ToString() ?? "" };
            var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "autocheck autochk *" };

            foreach (var entry in entries)
            {
                var trimmed = entry.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;
                if (expected.Contains(trimmed)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = "Nicht-Standard BootExecute Eintrag",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
                    Reason = $"Unbekannter BootExecute-Eintrag gefunden: '{trimmed}'. " +
                             "Schadhafte Boot-Kits tragen sich hier ein, um vor dem Windows-Kernel gestartet zu werden.",
                    Detail = $"BootExecute-Eintrag: {trimmed}"
                });
            }
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // Kernel debugger artifacts
    // -------------------------------------------------------------------------

    private async Task CheckKernelDebuggerArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        CheckKernelDebuggerRegistry(ctx);

        ct.ThrowIfCancellationRequested();
        await CheckWinDbgInstallationAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        CheckDebuggerProcesses(ctx, ct);
    }

    private static void CheckKernelDebuggerRegistry(ScanContext ctx)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var filterKey = baseKey.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter", writable: false);
            ctx.IncrementRegistryKeys();

            if (filterKey is not null)
            {
                foreach (var valueName in filterKey.GetValueNames())
                {
                    ctx.IncrementRegistryKeys();
                    var val = filterKey.GetValue(valueName);
                    if (val is null) continue;
                    int intVal;
                    try { intVal = Convert.ToInt32(val); } catch { continue; }
                    if (intVal > 0xf)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Kernel-Tampering",
                            Title = $"Ungew. Debug Print Filter: {valueName}",
                            Risk = RiskLevel.Medium,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter",
                            Reason = $"Ungewoehnlicher Kernel-Debug-Filter-Wert '{valueName}' = {intVal:X}. " +
                                     "Manipulierte Debug-Filter koennen auf Kernel-Debugger-Nutzung hinweisen.",
                            Detail = $"{valueName} = 0x{intVal:X}"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var kdKey = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\kd", writable: false);
            ctx.IncrementRegistryKeys();
            if (kdKey is null) return;

            ctx.IncrementRegistryKeys();
            var start = kdKey.GetValue("Start");
            if (start is not null && Convert.ToInt32(start) <= 2)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = "Kernel-Debugger-Dienst aktiv",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\kd",
                    Reason = "Kernel-Debugger-Dienst (kd) ist aktiv oder automatisch gestartet. " +
                             "Ein aktiver Kernel-Debugger ermoeglicht das Patchen von Kernel-Speicher.",
                    Detail = $"Start = {start}"
                });
            }
        }
        catch { }
    }

    private static async Task CheckWinDbgInstallationAsync(ScanContext ctx, CancellationToken ct)
    {
        var windbgPaths = new[]
        {
            @"C:\Program Files\WinDbg",
            @"C:\Program Files (x86)\WinDbg",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Windows Kits", "10", "Debuggers"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Windows Kits", "10", "Debuggers"),
        };

        foreach (var searchPath in windbgPaths)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(searchPath)) continue;

            string[] exes;
            try { exes = Directory.GetFiles(searchPath, "windbg.exe", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var exe in exes)
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = "WinDbg Installation gefunden",
                    Risk = RiskLevel.Low,
                    Location = exe,
                    FileName = "windbg.exe",
                    Reason = "WinDbg (Kernel-Debugger) ist installiert. Legitimer Einsatz moeglich, " +
                             "aber Cheats nutzen WinDbg zum Patchen von Kernel-Speicher und Anti-Cheat-Code.",
                    Detail = $"Pfad: {exe}"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private static void CheckDebuggerProcesses(ScanContext ctx, CancellationToken ct)
    {
        var debuggerProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "windbg", "kd", "ntsd", "cdb",
        };

        var processes = ctx.GetProcessSnapshot();
        var runningDebuggers = new List<string>();

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementProcesses();
            if (!debuggerProcessNames.Contains(proc.ProcessName)) continue;
            runningDebuggers.Add(proc.ProcessName);
        }

        if (runningDebuggers.Count == 0) return;

        ctx.AddFinding(new Finding
        {
            Module = "Kernel-Tampering",
            Title = $"Kernel-Debugger laeuft: {string.Join(", ", runningDebuggers)}",
            Risk = RiskLevel.High,
            Location = "Prozessliste",
            Reason = $"Kernel-Debugger-Prozess(e) '{string.Join(", ", runningDebuggers)}' laufen aktiv. " +
                     "Kernel-Debugger koennen Anti-Cheat-Schutzmechanismen im Kernel-Speicher patchen.",
            Detail = $"Laufende Debugger: {string.Join(", ", runningDebuggers)}"
        });
    }

    // -------------------------------------------------------------------------
    // Handle tool artifacts
    // -------------------------------------------------------------------------

    private async Task ScanForHandleToolArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            await ScanDirectoryForFileNamesAsync(ctx, dir, HandleToolExeNames, Array.Empty<string>(),
                "Handle-Manipulations-Werkzeug gefunden",
                RiskLevel.High,
                "Tool zur Handle-Tabellen-Manipulation gefunden. " +
                "Diese Werkzeuge schliessen Anti-Cheat-Handles, um Prozessschutz zu umgehen.",
                ct).ConfigureAwait(false);
        }

        ScanPrefetchForPatterns(ctx, ct,
            new[] { "HANDLE_HIJACK", "HANDLEKILL", "VACHANDLE", "EACHANDLE", "AC_HANDLE" },
            "Handle-Manipulations-Werkzeug in Prefetch",
            RiskLevel.High,
            "Prefetch-Eintrag weist auf Ausfuehrung eines Handle-Manipulations-Werkzeugs hin.");
    }

    // -------------------------------------------------------------------------
    // Token theft artifacts
    // -------------------------------------------------------------------------

    private async Task ScanForTokenTheftArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            await ScanDirectoryForFileNamesAsync(ctx, dir, TokenTheftExeNames, Array.Empty<string>(),
                "Token-Impersonation-Werkzeug gefunden",
                RiskLevel.High,
                "Token-Diebstahl oder Privilegien-Eskalations-Werkzeug gefunden. " +
                "Diese Tools stehlen System-Tokens, um SYSTEM-Rechte zu erlangen, " +
                "was fuer Kernel-Cheats und Anti-Cheat-Umgehung benoetigt wird.",
                ct).ConfigureAwait(false);
        }

        ScanPrefetchForPatterns(ctx, ct,
            new[] { "TOKEN_THEFT", "GETSYSTEM", "PRIVILEGE_ESCALATION", "IMPERSONATE" },
            "Token-Diebstahl-Werkzeug in Prefetch",
            RiskLevel.High,
            "Prefetch-Eintrag weist auf Ausfuehrung eines Token-Diebstahl-Werkzeugs hin.");
    }

    // -------------------------------------------------------------------------
    // PatchGuard artifacts
    // -------------------------------------------------------------------------

    private async Task ScanForPatchguardArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            await ScanDirectoryForFileNamesAsync(ctx, dir, PatchguardExeNames, Array.Empty<string>(),
                "PatchGuard-Bypass-Werkzeug gefunden",
                RiskLevel.Critical,
                "PatchGuard (KPP) Bypass-Werkzeug gefunden. " +
                "PatchGuard schuetzt kritische Kernel-Datenstrukturen. Ein Bypass ermoeglicht " +
                "tiefgreifende Kernel-Modifikationen fuer fortgeschrittene Cheat-Treiber.",
                ct).ConfigureAwait(false);
        }

        ScanPrefetchForPatterns(ctx, ct,
            new[] { "PATCHGUARD", "PGBYPASS", "PG_BYPASS", "KPP_BYPASS", "PG_KILLER" },
            "PatchGuard-Bypass in Prefetch",
            RiskLevel.Critical,
            "Prefetch-Eintrag deutet auf Ausfuehrung eines PatchGuard-Bypass-Werkzeugs hin.");
    }

    // -------------------------------------------------------------------------
    // Windows Defender ELAM driver integrity
    // -------------------------------------------------------------------------

    private static void CheckElamDriverIntegrity(ScanContext ctx)
    {
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        CheckElamDriverKey(ctx,
            @"SYSTEM\CurrentControlSet\Services\WdBoot",
            "WdBoot (Windows Defender ELAM)",
            system32);
        CheckElamDriverKey(ctx,
            @"SYSTEM\CurrentControlSet\Services\WdFilter",
            "WdFilter (Windows Defender Mini-Filter)",
            system32);
    }

    private static void CheckElamDriverKey(ScanContext ctx, string subKey, string displayName, string system32)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var k = baseKey.OpenSubKey(subKey, writable: false);
            ctx.IncrementRegistryKeys();
            if (k is null) return;

            ctx.IncrementRegistryKeys();
            var imagePath = k.GetValue("ImagePath") as string;
            if (string.IsNullOrEmpty(imagePath)) return;

            var expanded = Environment.ExpandEnvironmentVariables(imagePath);
            bool outsideSystem32 = !expanded.Contains(system32, StringComparison.OrdinalIgnoreCase) &&
                                   !imagePath.Contains("system32", StringComparison.OrdinalIgnoreCase) &&
                                   !imagePath.Contains("%SystemRoot%", StringComparison.OrdinalIgnoreCase) &&
                                   !imagePath.Contains("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase);

            if (outsideSystem32)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = $"ELAM-Treiber-Pfad manipuliert: {displayName}",
                    Risk = RiskLevel.Critical,
                    Location = @"HKLM\" + subKey,
                    Reason = $"Der {displayName} ELAM-Treiber zeigt auf einen unerwarteten Pfad ausserhalb von System32: " +
                             $"'{imagePath}'. ELAM-Treiber werden sehr frueh beim Boot geladen; " +
                             "eine Manipulation ermoeglicht das Deaktivieren von Windows Defender vor dem Systemstart.",
                    Detail = $"ImagePath: {imagePath} | Expanded: {expanded}"
                });
            }
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // Prefetch scan dispatcher (called from RunAsync for comprehensive coverage)
    // -------------------------------------------------------------------------

    private static void ScanPrefetchForKernelTools(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(PrefetchDir)) return;
        string[] files;
        try { files = Directory.GetFiles(PrefetchDir, "*.pf"); }
        catch { return; }

        var patterns = new (string[] prefixes, string title, RiskLevel risk, string reason)[]
        {
            (new[] { "DKOM", "PROCESS_HIDER", "PROCESSGHOST" },
                "DKOM-Werkzeug in Prefetch", RiskLevel.Critical,
                "DKOM-Tools manipulieren Kernel-Datenstrukturen um Prozesse zu verstecken."),
            (new[] { "KDMAPPER", "DRVMAP", "KSOCKET", "CAPCOM", "PHYSMEM" },
                "BYOVD-Werkzeug in Prefetch", RiskLevel.Critical,
                "BYOVD-Tools laden verwundbare Kernel-Treiber aus um Kernel-Zugang zu erlangen."),
            (new[] { "DSE_BYPASS", "CIPATCH", "TESTMODE" },
                "DSE-Bypass-Werkzeug in Prefetch", RiskLevel.High,
                "DSE-Bypass-Tools umgehen die Treibersignaturpruefung."),
            (new[] { "PATCHGUARD", "PGBYPASS", "PG_BYPASS", "KPP_BYPASS", "PG_KILLER" },
                "PatchGuard-Bypass in Prefetch", RiskLevel.Critical,
                "PatchGuard-Bypass ermoeglicht tiefgreifende Kernel-Modifikationen."),
            (new[] { "HANDLE_HIJACK", "HANDLEKILL", "VACHANDLE", "EACHANDLE" },
                "Handle-Werkzeug in Prefetch", RiskLevel.High,
                "Handle-Manipulations-Tools schliessen Anti-Cheat-Handles."),
            (new[] { "TOKEN_THEFT", "GETSYSTEM", "PRIVILEGE_ESCALATION" },
                "Token-Diebstahl in Prefetch", RiskLevel.High,
                "Token-Diebstahl-Tools stehlen SYSTEM-Tokens fuer Privilegieneskalation."),
        };

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var pfName = Path.GetFileNameWithoutExtension(file);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            foreach (var (prefixes, title, risk, reason) in patterns)
            {
                if (!prefixes.Any(p => exeName.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;

                DateTime? lastWrite = null;
                try { lastWrite = File.GetLastWriteTime(file); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = title,
                    Risk = risk,
                    Location = file,
                    FileName = exeName + ".exe",
                    Reason = $"Prefetch-Datei '{pfName}.pf' weist auf Ausfuehrung von '{exeName}.exe' hin. " + reason,
                    Detail = lastWrite.HasValue
                        ? $"Prefetch zuletzt aktualisiert: {lastWrite.Value:yyyy-MM-dd HH:mm:ss}"
                        : null
                });
                break;
            }
        }
    }

    private static void ScanPrefetchForPatterns(ScanContext ctx, CancellationToken ct,
        string[] prefixes, string title, RiskLevel risk, string reason)
    {
        if (!Directory.Exists(PrefetchDir)) return;
        string[] files;
        try { files = Directory.GetFiles(PrefetchDir, "*.pf"); }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var pfName = Path.GetFileNameWithoutExtension(file);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            if (!prefixes.Any(p => exeName.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;

            DateTime? lastWrite = null;
            try { lastWrite = File.GetLastWriteTime(file); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = "Kernel-Tampering",
                Title = title,
                Risk = risk,
                Location = file,
                FileName = exeName + ".exe",
                Reason = $"Prefetch-Datei '{pfName}.pf' weist auf Ausfuehrung von '{exeName}.exe' hin. " + reason,
                Detail = lastWrite.HasValue
                    ? $"Prefetch zuletzt aktualisiert: {lastWrite.Value:yyyy-MM-dd HH:mm:ss}"
                    : null
            });
        }
    }

    // -------------------------------------------------------------------------
    // Generic directory file scanner
    // -------------------------------------------------------------------------

    private static async Task ScanDirectoryForFileNamesAsync(
        ScanContext ctx, string directory,
        string[] exeNames, string[] dllNames,
        string title, RiskLevel risk, string baseReason,
        CancellationToken ct)
    {
        if (!Directory.Exists(directory)) return;

        string[] topFiles;
        try { topFiles = Directory.GetFiles(directory, "*.*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in topFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(file);

            bool matched = exeNames.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase))
                        || dllNames.Any(d => fn.Equals(d, StringComparison.OrdinalIgnoreCase));
            if (!matched) continue;

            long size = 0;
            try { size = new FileInfo(file).Length; } catch { }

            ctx.AddFinding(new Finding
            {
                Module = "Kernel-Tampering",
                Title = title,
                Risk = risk,
                Location = file,
                FileName = fn,
                Reason = $"Datei '{fn}' in '{directory}' entspricht bekanntem Kernel-Manipulations-Werkzeug. " + baseReason,
                Detail = $"Pfad: {file} | Groesse: {size} Bytes"
            });
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            string[] subFiles;
            try { subFiles = Directory.GetFiles(sub, "*.*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in subFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                bool matched = exeNames.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase))
                            || dllNames.Any(d => fn.Equals(d, StringComparison.OrdinalIgnoreCase));
                if (!matched) continue;

                long size = 0;
                try { size = new FileInfo(file).Length; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = "Kernel-Tampering",
                    Title = title,
                    Risk = risk,
                    Location = file,
                    FileName = fn,
                    Reason = $"Datei '{fn}' in '{sub}' entspricht bekanntem Kernel-Manipulations-Werkzeug. " + baseReason,
                    Detail = $"Pfad: {file} | Groesse: {size} Bytes"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static IEnumerable<string> GetUserScanDirectories()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();

        return new[]
        {
            Path.Combine(profile, "Desktop"),
            Path.Combine(profile, "Downloads"),
            appData,
            localAppData,
            temp,
        }.Where(Directory.Exists);
    }
}
