using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class DseBypassKernelSignatureScanModule : IScanModule
{
    public string Name => "DSE & Kernel Signature Bypass Detection";
    public double Weight => 4.6;
    public int ParallelGroup => 4;

    private static readonly string[] DseToolNames =
    {
        "DSEFix.exe", "dse_bypass.exe", "DSEPatch.exe", "ci_bypass.exe",
        "patchguard_bypass.exe", "pg_bypass.exe", "PatchGuard.exe",
        "EfiGuard.efi", "BootkitRemover.exe", "EFIBypass.exe",
        "kernel_patch.exe", "nt_patch.exe", "kpatch.exe",
        "TDL4.exe", "TDL3.exe", "bootkit.exe", "bootkit_loader.exe",
        "dse_patch.exe", "cibypass.exe", "codeintegrity_bypass.exe",
        "kdmapper.exe", "KDMapper.exe", "drvmap.exe", "drivermap.exe",
        "manual_mapper.exe", "manualmapper.exe", "drv_loader.exe",
        "eac_bypass.exe", "be_bypass.exe", "antibeat_bypass.exe",
        "faceit_bypass.exe", "vac_bypass.exe", "esea_bypass.exe",
        "ci_patch.exe", "ntos_patch.exe", "ntoskrnl_patch.exe",
        "pg_patch.exe", "patchguard.exe", "kdstrike.exe",
        "tteokbokki.exe", "physmem.exe", "physmem2profit.exe",
        "iqvw64e.sys", "rtcore64.sys", "gdrv.sys",
        "BootkitRemover.exe", "EFITool.exe", "UefiTool.exe",
        "BootkitInstaller.exe", "efi_bypass.exe", "secure_boot_bypass.exe",
    };

    private static readonly string[] DseGitDirNames =
    {
        "DSEFix", "dse-bypass", "kernel-signature-bypass", "ci-bypass",
        "PatchGuardBypass", "patchguard-bypass", "kdmapper", "KDMapper",
        "dse_bypass", "kernel-patch", "EfiGuard", "efi-guard",
        "BootkitRemover", "vulnerable-driver-mapper", "ldrx64",
        "mimidrv", "physmem2profit", "blackout",
    };

    private static readonly string[] SecureBootBypassToolNames =
    {
        "UefiTool.exe", "BootkitRemover.exe", "EFIBypass.exe",
        "efi_bypass.exe", "secure_boot_bypass.exe", "BootkitInstaller.exe",
        "CosmicStrand.exe", "BootkitX.exe", "EFITool.exe",
    };

    private static readonly string[] BcdeditDsePatterns =
    {
        "bcdedit /set testsigning on",
        "bcdedit /set testsigning yes",
        "bcdedit /set nointegritychecks on",
        "bcdedit /set nointegritychecks yes",
        "bcdedit /set loadoptions disable_integrity_checks",
        "bcdedit /set TESTSIGNING YES",
        "bcdedit /set TESTSIGNING ON",
        "bcdedit.exe /set testsigning",
        "bcdedit.exe /set nointegritychecks",
        "bcdedit.exe /set loadoptions",
    };

    private static readonly string[] ScriptExtensions =
    {
        ".ps1", ".bat", ".cmd", ".sh", ".vbs", ".js",
    };

    private static readonly string[] KernelDriverSuspectPaths =
    {
        "\\Temp\\", "\\Downloads\\", "\\AppData\\", "\\Desktop\\",
        "\\Documents\\", "\\Users\\Public\\", "\\ProgramData\\",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        ScanBcdRegistry(ctx);
        ctx.Report(0.08, "BCD Registry", "BCD-Registrierungsschluessel geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanBcdFileAsync(ctx, ct);
        ctx.Report(0.16, "BCD File", "BCD-Datei geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanBootLogAsync(ctx, ct);
        ctx.Report(0.24, "ntbtlog.txt", "Boot-Protokoll geprueft");
        ct.ThrowIfCancellationRequested();

        ScanSecureBootRegistry(ctx);
        ctx.Report(0.32, "Secure Boot Registry", "Secure-Boot-Status geprueft");
        ct.ThrowIfCancellationRequested();

        ScanCodeIntegrityRegistry(ctx);
        ctx.Report(0.40, "Code Integrity Registry", "Code-Integritaet geprueft");
        ct.ThrowIfCancellationRequested();

        ScanDeviceGuardRegistry(ctx);
        ctx.Report(0.48, "Device Guard Registry", "Device-Guard-Einstellungen geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanSiPolicyAsync(ctx, ct);
        ctx.Report(0.55, "SiPolicy.p7b", "SiPolicy-Datei geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanPowerShellHistoryForDseAsync(ctx, ct);
        ctx.Report(0.63, "PowerShell-Verlauf", "PowerShell-Verlauf auf DSE-Befehle geprueft");
        ct.ThrowIfCancellationRequested();

        await ScanScriptFilesForDseAsync(ctx, ct);
        ctx.Report(0.71, "Skriptdateien", "Skriptdateien auf BCDEdit-Befehle geprueft");
        ct.ThrowIfCancellationRequested();

        ScanDseToolsInUserDirs(ctx, ct);
        ctx.Report(0.80, "DSE-Tools", "DSE-Bypass-Tools gesucht");
        ct.ThrowIfCancellationRequested();

        ScanSuspiciousSysFiles(ctx, ct);
        ctx.Report(0.88, "Sys-Dateien", "Verdaechtige Treiberdateien geprueft");
        ct.ThrowIfCancellationRequested();

        ScanServiceRegistryForUnsignedDrivers(ctx, ct);
        ctx.Report(0.94, "Dienst-Registry", "Dienst-Registrierungen auf Treiber geprueft");
        ct.ThrowIfCancellationRequested();

        ScanEfiPartitionArtifacts(ctx);
        ctx.Report(1.0, "EFI-Partition", "EFI-Partitions-Artefakte geprueft");
    }

    private void ScanBcdRegistry(ScanContext ctx)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var bcdRoot = baseKey.OpenSubKey(@"BCD00000000");
            if (bcdRoot is null) return;

            foreach (var objName in bcdRoot.GetSubKeyNames())
            {
                try
                {
                    using var objKey = bcdRoot.OpenSubKey(objName);
                    if (objKey is null) continue;

                    using var elemKey = objKey.OpenSubKey("Elements");
                    if (elemKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var elemName in elemKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var elem = elemKey.OpenSubKey(elemName);
                            if (elem is null) continue;
                            ctx.IncrementRegistryKeys();

                            var val = elem.GetValue("Element")?.ToString();
                            if (string.IsNullOrWhiteSpace(val)) continue;

                            if (val.Contains("testsigning", StringComparison.OrdinalIgnoreCase) ||
                                val.Equals("Yes", StringComparison.OrdinalIgnoreCase) && elemName.Contains("16000049", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BCD-Registry: TestSigning aktiviert",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\BCD00000000\{objName}\Elements\{elemName}",
                                    Reason = "In der BCD-Registry-Struktur wurde ein TestSigning-Eintrag gefunden. " +
                                             "TestSigning erlaubt das Laden unsignierter Treiber und deaktiviert " +
                                             "effektiv die Driver Signature Enforcement (DSE).",
                                    Detail = $"Element: {val} | Schluessel: {elemName}"
                                });
                            }

                            if (val.Contains("DISABLE_INTEGRITY_CHECKS", StringComparison.OrdinalIgnoreCase) ||
                                val.Contains("nointegritychecks", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BCD-Registry: Integritaetspruefung deaktiviert",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\BCD00000000\{objName}\Elements\{elemName}",
                                    Reason = "In der BCD-Registry wurde ein Eintrag gefunden, der die Windows-" +
                                             "Kernelintegritaetspruefung (NoIntegrityChecks/LoadOptions) deaktiviert. " +
                                             "Dies ermoeglicht das Laden beliebiger Kernelcode ohne Signaturpruefung.",
                                    Detail = $"Element: {val} | Schluessel: {elemName}"
                                });
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private async Task ScanBcdFileAsync(ScanContext ctx, CancellationToken ct)
    {
        var windir = Environment.GetEnvironmentVariable("SYSTEMROOT")
                     ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var bcdPath = Path.Combine(windir, "Boot", "BCD");

        if (!File.Exists(bcdPath)) return;
        ctx.IncrementFiles();

        try
        {
            byte[] bcdBytes;
            try
            {
                using var fs = new FileStream(bcdPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                bcdBytes = new byte[fs.Length];
                int read = 0;
                while (read < bcdBytes.Length)
                {
                    ct.ThrowIfCancellationRequested();
                    int chunk = await fs.ReadAsync(bcdBytes, read, Math.Min(65536, bcdBytes.Length - read), ct);
                    if (chunk == 0) break;
                    read += chunk;
                }
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            var asciiContent = Encoding.ASCII.GetString(bcdBytes);
            var unicodeContent = Encoding.Unicode.GetString(bcdBytes);

            bool foundTestSigning = asciiContent.Contains("testsigning", StringComparison.OrdinalIgnoreCase)
                                 || unicodeContent.Contains("testsigning", StringComparison.OrdinalIgnoreCase);

            bool foundNoIntegrity = asciiContent.Contains("nointegritychecks", StringComparison.OrdinalIgnoreCase)
                                 || unicodeContent.Contains("nointegritychecks", StringComparison.OrdinalIgnoreCase);

            bool foundLoadOptions = (asciiContent.Contains("loadoptions", StringComparison.OrdinalIgnoreCase)
                                  || unicodeContent.Contains("loadoptions", StringComparison.OrdinalIgnoreCase))
                                 && (asciiContent.Contains("DISABLE_INTEGRITY_CHECKS", StringComparison.OrdinalIgnoreCase)
                                  || unicodeContent.Contains("DISABLE_INTEGRITY_CHECKS", StringComparison.OrdinalIgnoreCase));

            if (foundTestSigning)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "BCD-Datei: TestSigning-Zeichenkette gefunden",
                    Risk = RiskLevel.Critical,
                    Location = bcdPath,
                    FileName = "BCD",
                    Reason = "In der binaeren BCD-Startdatei wurde die Zeichenkette 'testsigning' gefunden " +
                             "(ASCII und/oder Unicode). TestSigning deaktiviert die Treiberüberprüfung " +
                             "und erlaubt das Laden unsignierter Kernel-Treiber.",
                    Detail = "Gefunden in BCD-Binaerdatei (ASCII/Unicode-Scan)"
                });
            }

            if (foundNoIntegrity)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "BCD-Datei: NoIntegrityChecks-Zeichenkette gefunden",
                    Risk = RiskLevel.Critical,
                    Location = bcdPath,
                    FileName = "BCD",
                    Reason = "In der binaeren BCD-Startdatei wurde 'nointegritychecks' gefunden. " +
                             "Dieser BCD-Eintrag deaktiviert die Windows-Kernelintegritaetspruefung " +
                             "vollstaendig und ist eine bekannte DSE-Bypass-Methode.",
                    Detail = "Gefunden in BCD-Binaerdatei (ASCII/Unicode-Scan)"
                });
            }

            if (foundLoadOptions)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "BCD-Datei: DISABLE_INTEGRITY_CHECKS in LoadOptions gefunden",
                    Risk = RiskLevel.Critical,
                    Location = bcdPath,
                    FileName = "BCD",
                    Reason = "In der BCD-Datei wurde 'DISABLE_INTEGRITY_CHECKS' in Verbindung mit " +
                             "LoadOptions gefunden. Diese Kombination deaktiviert die DSE beim Systemstart " +
                             "und ist eine klassische Methode zur Umgehung der Treiberüberprüfung.",
                    Detail = "Gefunden in BCD-Binaerdatei (ASCII/Unicode-Scan)"
                });
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    private async Task ScanBootLogAsync(ScanContext ctx, CancellationToken ct)
    {
        var windir = Environment.GetEnvironmentVariable("SYSTEMROOT")
                     ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var bootLog = Path.Combine(windir, "ntbtlog.txt");

        if (!File.Exists(bootLog)) return;
        ctx.IncrementFiles();

        string content;
        try
        {
            using var fs = new FileStream(bootLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        int unsignedCount = 0;
        int integrityViolations = 0;
        var suspectDrivers = new List<string>();

        foreach (var line in content.Split('\n'))
        {
            ct.ThrowIfCancellationRequested();
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            if (trimmed.Contains("UNSIGNED MODULE", StringComparison.OrdinalIgnoreCase))
            {
                unsignedCount++;
                if (unsignedCount <= 10) suspectDrivers.Add(trimmed);
            }

            if (trimmed.Contains("BOOTLOG_NOT_LOADED", StringComparison.OrdinalIgnoreCase) &&
                (trimmed.Contains("integrity", StringComparison.OrdinalIgnoreCase) ||
                 trimmed.Contains("signature", StringComparison.OrdinalIgnoreCase)))
            {
                integrityViolations++;
            }

            if (trimmed.StartsWith("Did not load driver", StringComparison.OrdinalIgnoreCase) &&
                (trimmed.Contains("signature", StringComparison.OrdinalIgnoreCase) ||
                 trimmed.Contains("unsigned", StringComparison.OrdinalIgnoreCase)))
            {
                if (suspectDrivers.Count < 15) suspectDrivers.Add(trimmed);
            }
        }

        if (unsignedCount > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Boot-Protokoll: {unsignedCount} unsignierte Treiber beim Start geladen",
                Risk = unsignedCount > 3 ? RiskLevel.Critical : RiskLevel.High,
                Location = bootLog,
                FileName = "ntbtlog.txt",
                Reason = $"Das Windows-Boot-Protokoll (ntbtlog.txt) verzeichnet {unsignedCount} " +
                         "unsignierte Module (UNSIGNED MODULE). Unsignierte Treiber koennen " +
                         "nur geladen werden, wenn DSE oder TestSigning umgangen wurde.",
                Detail = suspectDrivers.Count > 0
                    ? string.Join(" | ", suspectDrivers.Take(5))
                    : null
            });
        }

        if (integrityViolations > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Boot-Protokoll: Integritaetsverletzungen beim Treiberladen gefunden",
                Risk = RiskLevel.High,
                Location = bootLog,
                FileName = "ntbtlog.txt",
                Reason = $"Das Boot-Protokoll verzeichnet {integrityViolations} Faelle, in denen " +
                         "Treiber aufgrund von Signatur-/Integritaetsproblemen nicht geladen wurden. " +
                         "Dies deutet auf Versuche hin, unsignierte Treiber zu laden.",
                Detail = $"Anzahl Integritaetsverletzungen: {integrityViolations}"
            });
        }
    }

    private void ScanSecureBootRegistry(ScanContext ctx)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var sbState = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (sbState is not null)
            {
                ctx.IncrementRegistryKeys();
                var enabled = sbState.GetValue("UEFISecureBootEnabled");
                if (enabled is int enabledInt && enabledInt == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Secure Boot ist deaktiviert (UEFISecureBootEnabled=0)",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                        Reason = "Der Registrierungsschluessel zeigt, dass Secure Boot deaktiviert ist. " +
                                 "Deaktiviertes Secure Boot ermoeglicht das Laden von EFI-Bootkits und " +
                                 "unsignierten Betriebssystemkomponenten vor Windows.",
                        Detail = "UEFISecureBootEnabled = 0"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var sbPolicy = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\Policy");
            if (sbPolicy is not null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var valName in sbPolicy.GetValueNames())
                {
                    var val = sbPolicy.GetValue(valName)?.ToString();
                    if (string.IsNullOrEmpty(val)) continue;
                    if (val.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("disabled", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Secure Boot Policy: Moegliche Bypass-Konfiguration",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Policy",
                            Reason = "Ein Eintrag in der Secure-Boot-Policy-Konfiguration enthaelt " +
                                     "Bezeichnungen wie 'bypass' oder 'disabled', was auf eine " +
                                     "modifizierte UEFI-Richtlinie hindeuten kann.",
                            Detail = $"{valName} = {val}"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private void ScanCodeIntegrityRegistry(ScanContext ctx)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var ciConfig = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config");
            if (ciConfig is not null)
            {
                ctx.IncrementRegistryKeys();
                var blocklistEnabled = ciConfig.GetValue("VulnerableDriverBlocklistEnable");
                if (blocklistEnabled is int bVal && bVal == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Bekannte verwundbare Treiber-Blockliste deaktiviert",
                        Risk = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
                        Reason = "VulnerableDriverBlocklistEnable=0 deaktiviert die Microsoft-Sperrliste " +
                                 "fuer bekannte verwundbare Treiber (HVCI-Blockliste). Angreifer " +
                                 "deaktivieren diese, um bekannte Exploit-Treiber laden zu koennen " +
                                 "(z.B. RTCore64.sys, iqvw64e.sys). Kein legitimer Anwendungsfall.",
                        Detail = "VulnerableDriverBlocklistEnable = 0"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var ciProtected = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Protected");
            if (ciProtected is not null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var valName in ciProtected.GetValueNames())
                {
                    var val = ciProtected.GetValue(valName)?.ToString();
                    if (string.IsNullOrEmpty(val)) continue;
                    if (val.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("disabled", StringComparison.OrdinalIgnoreCase) ||
                        val.Equals("0", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Code-Integrity Protected: Moegliche Bypass-Konfiguration",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Protected",
                            Reason = "In der CI\\Protected-Registrierung wurde ein Eintrag mit " +
                                     "verdaechtigem Inhalt (bypass/disabled/0) gefunden. " +
                                     "Diese Schluessel schtzen die Code-Integritaet des Kernels.",
                            Detail = $"{valName} = {val}"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private void ScanDeviceGuardRegistry(ScanContext ctx)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var dg = baseKey.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard");
            if (dg is null) return;
            ctx.IncrementRegistryKeys();

            var deployPolicy = dg.GetValue("DeployConfigCIPolicy");
            if (deployPolicy is int dp && dp == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "WDAC-Richtlinie deaktiviert (DeployConfigCIPolicy=0)",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                    Reason = "DeployConfigCIPolicy=0 deaktiviert die Windows Defender Application Control " +
                             "(WDAC) Code-Integritaetsrichtlinie. WDAC ist ein wichtiger Schutz gegen " +
                             "das Laden unsignierter Treiber und Programme.",
                    Detail = "DeployConfigCIPolicy = 0"
                });
            }

            var hvciEnabled = dg.GetValue("EnableVirtualizationBasedSecurity");
            if (hvciEnabled is int hv && hv == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Virtualisierungsbasierte Sicherheit deaktiviert",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                    Reason = "EnableVirtualizationBasedSecurity=0 deaktiviert die VBS/HVCI-Schutzschicht. " +
                             "HVCI (Hypervisor-Protected Code Integrity) schuetzt den Kernel vor " +
                             "unautorisierten Aenderungen und wird von DSE-Bypass-Tools gezielt deaktiviert.",
                    Detail = "EnableVirtualizationBasedSecurity = 0"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private async Task ScanSiPolicyAsync(ScanContext ctx, CancellationToken ct)
    {
        var windir = Environment.GetEnvironmentVariable("SYSTEMROOT")
                     ?? Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var siPolicyPath = Path.Combine(windir, "System32", "CodeIntegrity", "SiPolicy.p7b");

        if (!File.Exists(siPolicyPath)) return;
        ctx.IncrementFiles();

        try
        {
            var info = new FileInfo(siPolicyPath);
            var age = DateTime.Now - info.LastWriteTime;

            if (age.TotalDays < 30)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "SiPolicy.p7b kuerzlich geaendert",
                    Risk = RiskLevel.High,
                    Location = siPolicyPath,
                    FileName = "SiPolicy.p7b",
                    Reason = "Die WDAC-Code-Integritaetsrichtliniendatei (SiPolicy.p7b) wurde innerhalb " +
                             "der letzten 30 Tage geaendert. Diese Datei sollte sich selten aendern. " +
                             "Eine kuerzliche Aenderung kann auf die Installation einer Bypass-Richtlinie hindeuten.",
                    Detail = $"Letzte Aenderung: {info.LastWriteTime:yyyy-MM-dd HH:mm} " +
                             $"| Groesse: {info.Length} Bytes"
                });
            }

            if (info.Length < 512)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "SiPolicy.p7b hat ungewoehnlich geringe Groesse",
                    Risk = RiskLevel.High,
                    Location = siPolicyPath,
                    FileName = "SiPolicy.p7b",
                    Reason = "Die SiPolicy.p7b-Datei ist ungewoehnlich klein, was auf eine manipulierte " +
                             "oder leere Code-Integritaetsrichtlinie hinweisen kann, die alle " +
                             "Treiber zulassen wuerde.",
                    Detail = $"Dateigroesse: {info.Length} Bytes (erwartet: > 512 Bytes)"
                });
            }
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        await Task.CompletedTask;
    }

    private async Task ScanPowerShellHistoryForDseAsync(ScanContext ctx, CancellationToken ct)
    {
        var historyPath = Path.Combine(KnownPaths.RoamingAppData,
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (!File.Exists(historyPath)) return;
        ctx.IncrementFiles();

        string content;
        try
        {
            using var fs = new FileStream(historyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        int matchCount = 0;
        foreach (var line in content.Split('\n'))
        {
            ct.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(line)) continue;

            foreach (var pattern in BcdeditDsePatterns)
            {
                if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    matchCount++;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PowerShell-Verlauf: BCDEdit DSE-Bypass-Befehl ausgefuehrt",
                        Risk = RiskLevel.Critical,
                        Location = historyPath,
                        FileName = "ConsoleHost_history.txt",
                        Reason = "Im PowerShell-Befehlsverlauf wurde ein BCDEdit-Befehl gefunden, der " +
                                 "die Driver Signature Enforcement (DSE) oder die Kernelintegritaetspruefung " +
                                 "deaktiviert. Dies ist ein direkter Beweis fuer einen DSE-Bypass-Versuch.",
                        Detail = $"Befehl: {line.Trim()}"
                    });

                    if (matchCount >= 10) return;
                    break;
                }
            }
        }
    }

    private async Task ScanScriptFilesForDseAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents",
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!ScriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var pattern in BcdeditDsePatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Skriptdatei enthaelt BCDEdit DSE-Bypass-Befehl",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Die Skriptdatei enthaelt den BCDEdit-Befehl '{pattern}', der " +
                                     "die Driver Signature Enforcement (DSE) oder Kernelintegritaetspruefung " +
                                     "deaktiviert. Solche Skripte werden von Cheat-Loadern automatisiert.",
                            Detail = $"Gefundenes Muster: {pattern}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private void ScanDseToolsInUserDirs(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            KnownPaths.Downloads,
            KnownPaths.UserProfile + "\\Desktop",
            KnownPaths.UserProfile + "\\Documents",
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            Path.Combine(KnownPaths.RoamingAppData),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] allEntries;
            try
            {
                allEntries = Directory.GetFileSystemEntries(root, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var entry in allEntries)
            {
                ct.ThrowIfCancellationRequested();

                var name = Path.GetFileName(entry);

                foreach (var toolName in DseToolNames)
                {
                    if (name.Equals(toolName, StringComparison.OrdinalIgnoreCase))
                    {
                        bool isDir = Directory.Exists(entry);
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DSE-Bypass-Tool gefunden: {name}",
                            Risk = RiskLevel.Critical,
                            Location = entry,
                            FileName = name,
                            Reason = $"Die Datei '{name}' ist ein bekanntes DSE-Bypass- oder " +
                                     "Kernel-Patch-Tool. Diese Tools werden eingesetzt, um unsignierte " +
                                     "Treiber in den Windows-Kernel zu laden und Anti-Cheat-Schutz zu umgehen.",
                            Detail = isDir ? "Verzeichnis" : null
                        });
                        break;
                    }
                }

                if (Directory.Exists(entry))
                {
                    foreach (var gitDir in DseGitDirNames)
                    {
                        if (name.Equals(gitDir, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DSE-Bypass-Projektverzeichnis gefunden: {name}",
                                Risk = RiskLevel.High,
                                Location = entry,
                                FileName = name,
                                Reason = $"Das Verzeichnis '{name}' entspricht dem Namen eines bekannten " +
                                         "DSE-Bypass- oder Kernel-Patch-Projekts (haeufig von GitHub geklont). " +
                                         "Solche Projekte enthalten Werkzeuge zum Umgehen der Windows-Treiberverifikation.",
                                Detail = "Verzeichnis (moeglicher Git-Klon)"
                            });
                            break;
                        }
                    }
                }

                foreach (var bootTool in SecureBootBypassToolNames)
                {
                    if (name.Equals(bootTool, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Secure-Boot-Bypass-Tool gefunden: {name}",
                            Risk = RiskLevel.Critical,
                            Location = entry,
                            FileName = name,
                            Reason = $"'{name}' ist ein bekanntes Tool zur Umgehung von Secure Boot oder " +
                                     "zur Manipulation von EFI-Bootloadern. Diese Werkzeuge ermoeglichen " +
                                     "das Installieren von Bootkits und persistenter Kernel-Malware.",
                            Detail = null
                        });
                        break;
                    }
                }
            }
        }
    }

    private void ScanSuspiciousSysFiles(ScanContext ctx, CancellationToken ct)
    {
        var suspectRoots = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.Downloads,
            KnownPaths.RoamingAppData,
            KnownPaths.UserProfile + "\\Desktop",
        };

        foreach (var root in suspectRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] sysFiles;
            try
            {
                sysFiles = Directory.GetFiles(root, "*.sys", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var sysFile in sysFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(sysFile);
                FileInfo fi;
                try { fi = new FileInfo(sysFile); }
                catch { continue; }

                bool hasAuthenticode = false;
                try
                {
                    using var fs = new FileStream(sysFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var header = new byte[Math.Min(4096, (int)fi.Length)];
                    int totalRead = 0;
                    while (totalRead < header.Length)
                    {
                        int r = fs.Read(header, totalRead, header.Length - totalRead);
                        if (r == 0) break;
                        totalRead += r;
                    }
                    var headerSpan = header.AsSpan(0, totalRead);
                    hasAuthenticode = ContainsPkcs7Magic(headerSpan) || ContainsAuthenticodeMarker(headerSpan);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Treiber-Datei (.sys) in verdaechtigem Verzeichnis: {fileName}",
                    Risk = hasAuthenticode ? RiskLevel.Medium : RiskLevel.High,
                    Location = sysFile,
                    FileName = fileName,
                    Reason = $"Eine .sys-Treiberdatei wurde in einem ungewoehnlichen Verzeichnis gefunden " +
                             $"('{root}'). Legitime Treiber befinden sich in System32\\drivers. " +
                             "Treiber in Benutzerverzeichnissen sind ein starkes Indiz fuer Cheat-Loader " +
                             "oder DSE-Bypass-Aktivitaet." +
                             (hasAuthenticode ? " Moegliche Authenticode-Signatur gefunden." : " Keine Authenticode-Signatur detektiert."),
                    Signed = hasAuthenticode,
                    Detail = $"Groesse: {fi.Length} Bytes | Verzeichnis: {root}"
                });
            }
        }
    }

    private static bool ContainsPkcs7Magic(ReadOnlySpan<byte> data)
    {
        for (int i = 0; i < data.Length - 3; i++)
        {
            if (data[i] == 0x30 && data[i + 1] == 0x82)
                return true;
        }
        return false;
    }

    private static bool ContainsAuthenticodeMarker(ReadOnlySpan<byte> data)
    {
        var marker = "SpcIndirectDataContent"u8;
        for (int i = 0; i <= data.Length - marker.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < marker.Length; j++)
            {
                if (data[i + j] != marker[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    private void ScanServiceRegistryForUnsignedDrivers(ScanContext ctx, CancellationToken ct)
    {
        var serviceRoots = new[]
        {
            @"SYSTEM\CurrentControlSet\Services",
            @"SYSTEM\ControlSet001\Services",
        };

        foreach (var svcRoot in serviceRoots)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var servicesKey = baseKey.OpenSubKey(svcRoot);
                if (servicesKey is null) continue;

                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        using var svc = servicesKey.OpenSubKey(svcName);
                        if (svc is null) continue;
                        ctx.IncrementRegistryKeys();

                        var typeVal = svc.GetValue("Type");
                        if (typeVal is not int typeInt) continue;
                        if (typeInt != 1 && typeInt != 2) continue;

                        var imagePath = svc.GetValue("ImagePath")?.ToString();
                        if (string.IsNullOrWhiteSpace(imagePath)) continue;

                        var expandedPath = Environment.ExpandEnvironmentVariables(imagePath).Trim('"');

                        bool isSuspectLocation = false;
                        foreach (var suspectPath in KernelDriverSuspectPaths)
                        {
                            if (expandedPath.Contains(suspectPath, StringComparison.OrdinalIgnoreCase))
                            {
                                isSuspectLocation = true;
                                break;
                            }
                        }

                        if (!isSuspectLocation) continue;

                        if (expandedPath.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) ||
                            expandedPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Kernel-Treiber-Dienst in verdaechtigem Pfad: {svcName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{svcRoot}\{svcName}",
                                FileName = Path.GetFileName(expandedPath),
                                Reason = $"Ein Kernel-Treiber-Dienst (Type={typeInt}) mit dem Namen '{svcName}' " +
                                         $"verweist auf einen Treiber in einem ungewoehnlichen Pfad: '{expandedPath}'. " +
                                         "Legitime Treiber befinden sich in System32\\drivers. " +
                                         "Cheat-Loader installieren Treiber typisch in Temp- oder AppData-Verzeichnissen.",
                                Detail = $"ImagePath: {expandedPath} | Type: {typeInt} | Service: {svcName}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanEfiPartitionArtifacts(ScanContext ctx)
    {
        var efiCandidates = new[]
        {
            @"C:\EFI",
            @"C:\BOOT",
            @"\\?\Volume{",
        };

        var knownEfiRoots = new[]
        {
            "Microsoft", "Boot", "EFI", "ubuntu", "grub",
        };

        foreach (var efiPath in new[] { @"C:\EFI", @"C:\Boot\EFI" })
        {
            if (!Directory.Exists(efiPath)) continue;

            string[] efiDirs;
            try { efiDirs = Directory.GetDirectories(efiPath); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var dir in efiDirs)
            {
                var dirName = Path.GetFileName(dir);
                bool isKnown = false;
                foreach (var known in knownEfiRoots)
                {
                    if (dirName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        isKnown = true;
                        break;
                    }
                }

                if (!isKnown)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unbekanntes EFI-Verzeichnis: {dirName}",
                        Risk = RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason = $"Im EFI-Systempfad wurde das unbekannte Verzeichnis '{dirName}' gefunden. " +
                                 "Auf EFI-Partitionen sollten nur Microsoft-, OEM- und legitime " +
                                 "Bootloader-Verzeichnisse vorhanden sein. Fremde Verzeichnisse koennen " +
                                 "auf ein installiertes EFI-Bootkit hinweisen.",
                        Detail = $"EFI-Pfad: {efiPath} | Unbekanntes Verzeichnis: {dirName}"
                    });
                }
            }
        }

        var bootKittyNames = new[] { "BootkittyLogo.png", "BootkittyA.efi", "CosmicStrand.efi" };
        var efiSearchPaths = new[] { @"C:\EFI", @"C:\Boot" };
        foreach (var searchPath in efiSearchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (var bkName in bootKittyNames)
            {
                string[] found;
                try { found = Directory.GetFiles(searchPath, bkName, SearchOption.AllDirectories); }
                catch { continue; }

                foreach (var f in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekanntes EFI-Bootkit-Artefakt gefunden: {bkName}",
                        Risk = RiskLevel.Critical,
                        Location = f,
                        FileName = bkName,
                        Reason = $"Die Datei '{bkName}' ist ein Artefakt eines bekannten EFI-Bootkits " +
                                 "(BootKitty oder CosmicStrand). Diese Bootkits persistieren im UEFI-Firmware " +
                                 "und koennen Secure Boot und Kernelschutz umgehen.",
                        Detail = null
                    });
                }
            }
        }
    }
}
