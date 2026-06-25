using System.Diagnostics.Eventing.Reader;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class MappingDriverForensicScanModule : IScanModule
{
    public string Name => "Driver Manual Mapping Forensic Scan";
    public double Weight => 4.6;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string RoamingAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string Downloads =
        Path.Combine(UserProfile, "Downloads");
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32 =
        Path.Combine(WinDir, "System32");
    private static readonly string Temp =
        Path.GetTempPath();
    private static readonly string ProgramFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    private static readonly string ProgramData =
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    // Known kdmapper executable variants
    private static readonly string[] KdmapperExecutables =
    {
        "kdmapper.exe",
        "kdmapper64.exe",
        "kdmapper_v2.exe",
        "kdmapper_modified.exe",
        "kdmapper_test.exe",
        "kdmapper_eac.exe",
        "kdmapper_be.exe",
        "kdmapper_bypass.exe",
        "kdmapper_patched.exe",
        "kdmapper2.exe",
        "kd_mapper.exe",
        "kernel_mapper.exe",
        "kernelmapper.exe",
        "kdmap.exe",
    };

    // ThunderingTurla and related mapper names
    private static readonly string[] ThunderingTurlaExecutables =
    {
        "turla.exe",
        "turla_driver.exe",
        "turla_map.exe",
        "thunderingturla.exe",
        "thunderturla.exe",
        "turla_mapper.exe",
    };

    // Other known driver mapper tools
    private static readonly string[] OtherMapperExecutables =
    {
        "dsemap.exe",
        "winio_mapper.exe",
        "gdrv_mapper.exe",
        "rtcore_mapper.exe",
        "dsefix_mapper.exe",
        "physmem_mapper.exe",
        "mem_mapper.exe",
        "drivermap.exe",
        "drv_mapper.exe",
        "capcom_mapper.exe",
        "capcom.exe",
        "dbutil_mapper.exe",
        "iqvw64_mapper.exe",
        "mhyprot_mapper.exe",
        "winring0_mapper.exe",
        "physmem2profit.exe",
        "kMapper.exe",
        "kdrv_load.exe",
        "manual_mapper.exe",
        "manualmapper.exe",
        "efi_mapper.exe",
        "efi_guard.exe",
    };

    // DSE bypass tool names
    private static readonly string[] DseBypassExecutables =
    {
        "dsefix.exe",
        "dsefix64.exe",
        "ci_bypass.exe",
        "kernel_ci_bypass.exe",
        "dsesign.exe",
        "dse_bypass.exe",
        "ci_fix.exe",
        "dsepatch.exe",
        "kdse.exe",
        "disabledse.exe",
        "disable_dse.exe",
        "bcdfix.exe",
    };

    // PatchGuard bypass tool names
    private static readonly string[] PatchGuardBypassExecutables =
    {
        "patchguard_bypass.exe",
        "pg_bypass.exe",
        "pgbypass.exe",
        "patchguard_patcher.exe",
        "pg_patcher.exe",
        "pg_patch.exe",
        "pgpatch.exe",
        "kernelpatch.exe",
        "kernel_patch.exe",
        "kpatch.exe",
        "noPG.exe",
        "nopatchguard.exe",
    };

    // BYOVD vulnerable driver staging files
    private static readonly string[] ByovdVulnerableDrivers =
    {
        "dbutil_2_3.sys",
        "dbutil_2_3_64.sys",
        "gdrv.sys",
        "winring0.sys",
        "winring0x64.sys",
        "rtcore64.sys",
        "rtcore32.sys",
        "mhyprot.sys",
        "mhyprot2.sys",
        "iqvw64e.sys",
        "ntiolib_x64.sys",
        "msio64.sys",
        "msio32.sys",
        "asio.sys",
        "bs_hwmio64.sys",
        "bs_rcio64.sys",
        "cpuz141_x64.sys",
        "cpuz145_x64.sys",
        "cpuz143_x64.sys",
        "kprocesshacker.sys",
        "WinIo64.sys",
        "WinIo32.sys",
        "HW.sys",
        "physmem.sys",
        "nicm.sys",
        "nscm.sys",
        "rtkio64.sys",
        "atszio64.sys",
        "ene.sys",
        "amifldrv64.sys",
        "winio.sys",
        "lha.sys",
        "inpoutx64.sys",
        "msio.sys",
        "libnicm.sys",
        "speedfan.sys",
        "sandra.sys",
        "sysdrv3s.sys",
        "wiseunlo.sys",
        "bsflash64.sys",
        "glckio2.sys",
        "phlash64.sys",
        "rwdrv.sys",
    };

    // Test-signing / DSE disable batch scripts
    private static readonly string[] TestSigningBatchNames =
    {
        "bcdedit_testsigning.bat",
        "enable_testsign.bat",
        "testsign.cmd",
        "dsesign.bat",
        "enable_testmode.bat",
        "testmode.bat",
        "nointegritychecks.bat",
        "disable_signature.bat",
        "disablesigning.bat",
        "dse_off.bat",
        "unsigned_drivers.bat",
        "bcdedit_nointegrity.bat",
    };

    // Mapper output log file names
    private static readonly string[] MapperLogFileNames =
    {
        "kdmapper_log.txt",
        "mapper_output.txt",
        "driver_map.log",
        "map_status.txt",
        "injection_log.txt",
        "mapping_log.txt",
        "drv_map.txt",
        "kernel_map.log",
        "map_result.txt",
        "kdmap.log",
        "mapper.log",
        "driver_inject.log",
        "inject_log.txt",
        "bypass_log.txt",
        "dse_log.txt",
    };

    // Registry service names associated with mappers or vulnerable drivers being loaded
    private static readonly string[] SuspectMapperServiceKeywords =
    {
        "kdmapper",
        "turla",
        "thunderingturla",
        "dsemap",
        "gdrv",
        "rtcore",
        "dbutil_2_3",
        "mhyprot",
        "iqvw64",
        "winring0",
        "physmem",
        "winio",
        "cpuz",
        "kprocesshacker",
        "nicm",
        "capcom",
        "rwdrv",
        "speedfan",
        "sysdrv3s",
        "glckio",
        "amifldrv",
    };

    // MUICache / UserAssist check names for mapper tools
    private static readonly string[] MapperMuiCacheKeywords =
    {
        "kdmapper",
        "turla",
        "thunderingturla",
        "dsemap",
        "dsefix",
        "patchguard_bypass",
        "pg_bypass",
        "pgbypass",
        "physmem2profit",
        "gdrv_mapper",
        "rtcore_mapper",
        "manual_mapper",
        "kernel_mapper",
        "winio_mapper",
        "capcom",
        "manualmapper",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Driver Manual Mapping Forensic Scan", "Starte Kernel Mapper Forensic Scan...");

        await Task.WhenAll(
            CheckKdmapperExecutables(ctx, ct),
            CheckThunderingTurlaArtifacts(ctx, ct),
            CheckOtherMapperTools(ctx, ct),
            CheckByovdVulnerableDrivers(ctx, ct),
            CheckMapperLogFiles(ctx, ct),
            CheckTestSigningArtifacts(ctx, ct),
            CheckDseBypassArtifacts(ctx, ct),
            CheckPatchGuardBypassArtifacts(ctx, ct),
            CheckDriverImageInUnusualLocations(ctx, ct),
            CheckMapperRegistryServices(ctx, ct),
            CheckBcdRegistryTestSigning(ctx, ct),
            CheckEventLogUnsignedDriverLoads(ctx, ct),
            CheckMapperUserAssist(ctx, ct),
            CheckMapperMuiCache(ctx, ct),
            CheckMapperProcessArtifacts(ctx, ct),
            CheckMapperPrefetchArtifacts(ctx, ct)
        );

        ctx.Report(1.0, "Driver Manual Mapping Forensic Scan", "Kernel Mapper Forensic Scan abgeschlossen");
    }

    private Task CheckKdmapperExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchDirs = new[]
            {
                Downloads,
                Desktop,
                Documents,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(WinDir, "Temp"),
                Path.Combine(LocalAppData, "Programs"),
                Path.Combine(UserProfile, "OneDrive"),
                Path.Combine(UserProfile, "OneDrive", "Desktop"),
                Path.Combine(UserProfile, "OneDrive", "Downloads"),
                RoamingAppData,
                LocalAppData,
                ProgramData,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var fileName = Path.GetFileName(file);
                        bool isKdmapper = KdmapperExecutables.Any(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (!isKdmapper) continue;

                        ctx.IncrementFiles();
                        var fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"kdmapper Kernel-Driver-Mapper: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Das kdmapper Kernel-Treiber-Manual-Mapping-Tool '{fileName}' wurde unter " +
                                     $"'{file}' gefunden. kdmapper laedt unsignierte Kernel-Treiber, indem es " +
                                     "den Intel-Netzwerktreiber iqvw64e.sys oder aehnliche vulnerable " +
                                     "signierte Treiber (BYOVD) missbraucht, um DSE (Driver Signature Enforcement) " +
                                     "zu umgehen. Dies ist ein Standardwerkzeug fuer Kernel-Level-Cheats " +
                                     "(Aimbot, ESP, HWID-Spoofer).",
                            Detail = $"Groesse: {fi.Length} Bytes · Zuletzt geaendert: {fi.LastWriteTime:yyyy-MM-dd HH:mm} · " +
                                     $"Erstellt: {fi.CreationTime:yyyy-MM-dd HH:mm}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Also search for kdmapper in system locations where it might be hidden
            var systemSearchDirs = new[]
            {
                System32,
                Path.Combine(WinDir, "SysWOW64"),
                Path.Combine(WinDir, "System"),
            };

            foreach (var dir in systemSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var kd in KdmapperExecutables)
                    {
                        var kdPath = Path.Combine(dir, kd);
                        if (!File.Exists(kdPath)) continue;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"kdmapper im System-Verzeichnis versteckt: {kd}",
                            Risk = RiskLevel.Critical,
                            Location = kdPath,
                            FileName = kd,
                            Reason = $"kdmapper '{kd}' wurde im Windows-Systemverzeichnis '{dir}' gefunden. " +
                                     "Das Ablegen von Mapper-Tools in Systemverzeichnissen ist eine " +
                                     "Tarntaktik, um Entdeckung zu erschweren.",
                            Detail = $"Systemverzeichnis: {dir}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckThunderingTurlaArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchDirs = new[]
            {
                Downloads,
                Desktop,
                Documents,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                LocalAppData,
                RoamingAppData,
                ProgramData,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var fileName = Path.GetFileName(file);
                        bool isTurla = ThunderingTurlaExecutables.Any(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (!isTurla) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ThunderingTurla Driver Mapper: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Das ThunderingTurla Kernel-Treiber-Mapping-Tool '{fileName}' wurde unter " +
                                     $"'{file}' gefunden. ThunderingTurla ist ein fortgeschrittener " +
                                     "manueller Treiber-Mapper, der urspruenglich in Advanced Persistent " +
                                     "Threat (APT) Operationen eingesetzt wurde und nun im Cheat-Ecosystem " +
                                     "verbreitet ist. Es laedt Kernel-Treiber ohne Service-Registrierung.",
                            Detail = $"Groesse: {new FileInfo(file).Length} Bytes · " +
                                     $"Zuletzt geaendert: {File.GetLastWriteTime(file):yyyy-MM-dd HH:mm}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Check for Turla-related log files or output artifacts
            var turlaLogNames = new[]
            {
                "turla_log.txt",
                "turla_output.txt",
                "turla_map.log",
                "thunderingturla.log",
                "turla_driver.log",
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var logName in turlaLogNames)
                    {
                        var logPath = Path.Combine(dir, logName);
                        if (!File.Exists(logPath)) continue;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ThunderingTurla Log-Datei: {logName}",
                            Risk = RiskLevel.High,
                            Location = logPath,
                            FileName = logName,
                            Reason = $"Eine ThunderingTurla Ausgabe-Log-Datei wurde unter '{logPath}' gefunden. " +
                                     "Diese Log-Datei enthaelt Ausgaben des Mapper-Tools und zeigt an, " +
                                     "dass ThunderingTurla auf diesem System ausgefuehrt wurde.",
                            Detail = $"Groesse: {new FileInfo(logPath).Length} Bytes"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckOtherMapperTools(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var allOtherMappers = OtherMapperExecutables;
            var searchDirs = new[]
            {
                Downloads,
                Desktop,
                Documents,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                LocalAppData,
                RoamingAppData,
                ProgramData,
                Path.Combine(WinDir, "Temp"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var fileName = Path.GetFileName(file);
                        bool isMapper = allOtherMappers.Any(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (!isMapper) continue;

                        ctx.IncrementFiles();
                        var matchedName = allOtherMappers.First(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));

                        string description = matchedName.ToLowerInvariant() switch
                        {
                            var n when n.Contains("dsemap") =>
                                "DSEMap ist ein BYOVD-Mapper, der DSE-Bypass ueber vulnerable Treiber implementiert.",
                            var n when n.Contains("gdrv") =>
                                "GDRV-Mapper nutzt den Gigabyte-Treiber gdrv.sys (CVE-2018-19320) fuer Kernel-Zugriff.",
                            var n when n.Contains("rtcore") =>
                                "RTCore-Mapper missbraucht den MSI Afterburner rtcore64.sys Treiber fuer Ring-0-Zugriff.",
                            var n when n.Contains("physmem2profit") =>
                                "physmem2profit ist ein fortgeschrittenes BYOVD-Tool fuer physischen Speicherzugriff.",
                            var n when n.Contains("capcom") =>
                                "Der Capcom-Treiber (Hack.sys) ist ein beruehmt-beruechtigter vulnerable Treiber fuer Kernel-Exploits.",
                            var n when n.Contains("winio") =>
                                "WinIO-Mapper nutzt den WinIO-Treiber fuer direkten Kernel-Speicherzugriff.",
                            var n when n.Contains("mhyprot") =>
                                "mhyprot-Mapper nutzt den Genshin Impact Anti-Cheat-Treiber fuer BYOVD-Angriffe.",
                            _ =>
                                "Ein bekanntes Kernel-Treiber-Manual-Mapping-Tool fuer BYOVD-Angriffe wurde gefunden."
                        };

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Kernel Driver Mapper: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Das Kernel-Treiber-Mapping-Tool '{fileName}' wurde unter '{file}' " +
                                     $"gefunden. {description} Manual-Mapping-Tools laden unsignierte " +
                                     "Kernel-Treiber ohne Windows-Sicherheitskontrollen, was Kernel-Level-Cheats " +
                                     "ermoeooglicht.",
                            Detail = $"Groesse: {new FileInfo(file).Length} Bytes · " +
                                     $"Zuletzt geaendert: {File.GetLastWriteTime(file):yyyy-MM-dd HH:mm}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckByovdVulnerableDrivers(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // BYOVD staging locations - vulnerable drivers in non-standard locations
            var stagingDirs = new[]
            {
                Downloads,
                Desktop,
                Documents,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(WinDir, "Temp"),
                LocalAppData,
                RoamingAppData,
                ProgramData,
                Path.Combine(UserProfile, "AppData"),
            };

            foreach (var dir in stagingDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.sys", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var fileName = Path.GetFileName(file);
                        bool isByovd = ByovdVulnerableDrivers.Any(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (!isByovd) continue;

                        ctx.IncrementFiles();
                        var matchedName = ByovdVulnerableDrivers.First(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));

                        string cve = matchedName.ToLowerInvariant() switch
                        {
                            var n when n.Contains("dbutil_2_3") =>
                                "CVE-2021-21551 (Dell DBUtil) - beliebter Schreibzugriff auf Kernel-Speicher",
                            var n when n.Contains("gdrv") =>
                                "CVE-2018-19320 (Gigabyte GDRV) - Kernel-Speicherzugriff ohne Validierung",
                            var n when n.Contains("rtcore") =>
                                "CVE-2019-16098 (MSI Afterburner RTCore) - beliebiger Kernel-Read/Write",
                            var n when n.Contains("mhyprot") =>
                                "Genshin Impact mhyprot2.sys - missbrauchter Spieltreiber fuer BYOVD",
                            var n when n.Contains("iqvw64") =>
                                "CVE-2015-2291 (Intel NDIS) - wird von kdmapper verwendet",
                            var n when n.Contains("winring0") =>
                                "WinRing0 - Open-Source Ringzugriffs-Treiber, haeufig in BYOVD-Angriffen genutzt",
                            var n when n.Contains("cpuz") =>
                                "CPU-Z cpuz.sys - Kernel-Level-CPU-Informationstreiber mit Exploit",
                            var n when n.Contains("kprocesshacker") =>
                                "kProcessHacker - Kernel-Tool fuer Prozessmanipulation",
                            _ =>
                                "Bekannter vulnerabler Treiber, der in BYOVD-Angriffen verwendet wird"
                        };

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"BYOVD Vulnerable Treiber in ungewoehnlichem Pfad: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Der bekannte vulnerable Treiber '{fileName}' wurde in einem ungewoehnlichen " +
                                     $"Verzeichnis '{file}' gefunden (nicht in System32\\drivers). " +
                                     "Dieser Treiber wird in BYOVD-Angriffen (Bring Your Own Vulnerable Driver) " +
                                     $"eingesetzt: {cve}. Angreifer laden diesen legitim signierten, aber " +
                                     "vulnerablen Treiber, um Kernel-Zugriff ohne DSE-Bypass zu erlangen.",
                            Detail = $"Groesse: {new FileInfo(file).Length} Bytes · " +
                                     $"Erstellt: {File.GetCreationTime(file):yyyy-MM-dd HH:mm} · CVE: {cve}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Check for vulnerable drivers in System32\drivers (might have been loaded)
            var driversDir = Path.Combine(System32, "drivers");
            if (Directory.Exists(driversDir))
            {
                try
                {
                    foreach (var vulnDrv in ByovdVulnerableDrivers)
                    {
                        if (ct.IsCancellationRequested) return;
                        var drvPath = Path.Combine(driversDir, vulnDrv);
                        if (!File.Exists(drvPath)) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"BYOVD Vulnerable Treiber in System-Treiberordner: {vulnDrv}",
                            Risk = RiskLevel.High,
                            Location = drvPath,
                            FileName = vulnDrv,
                            Reason = $"Der bekannte vulnerable Treiber '{vulnDrv}' wurde im " +
                                     $"System-Treiberordner '{driversDir}' gefunden. Dies deutet darauf hin, " +
                                     "dass er als Teil eines BYOVD-Angriffs geladen oder installiert wurde. " +
                                     "Legitime Software liefert diese Treiber selten ohne zugehoerige " +
                                     "Installation.",
                            Detail = $"Systemtreiberpfad: {drvPath}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckMapperLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Downloads,
                Desktop,
                Documents,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(WinDir, "Temp"),
                LocalAppData,
                RoamingAppData,
                ProgramData,
                UserProfile,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var logName in MapperLogFileNames)
                    {
                        var logPath = Path.Combine(dir, logName);
                        if (!File.Exists(logPath)) continue;

                        ctx.IncrementFiles();
                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { }

                        // Check content for mapper-specific keywords
                        var mapperKeywords = new[]
                        {
                            "mapped", "mapping", "loaded", "driver", "kernel", "success",
                            "iqvw64", "dbutil", "gdrv", "rtcore", "mhyprot", "winring",
                            "dse", "bypass", "inject", "ntoskrnl", "ntloaddriver",
                        };
                        var foundKeywords = mapperKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Kernel Mapper Log-Datei gefunden: {logName}",
                            Risk = foundKeywords.Count >= 3 ? RiskLevel.Critical : RiskLevel.High,
                            Location = logPath,
                            FileName = logName,
                            Reason = $"Eine Kernel-Driver-Mapper Log-Datei wurde unter '{logPath}' gefunden. " +
                                     "Diese Log-Dateien werden von kdmapper und aehnlichen Tools ausgegeben " +
                                     "und enthalten Details ueber Mapping-Operationen, verwendete vulnerable " +
                                     "Treiber und Mapping-Ergebnisse. Log-Dateien bleiben als forensische " +
                                     "Artefakte erhalten, auch wenn der Mapper selbst geloescht wurde.",
                            Detail = foundKeywords.Count > 0
                                ? $"Gefundene Schluesselbegriffe: {string.Join(", ", foundKeywords)}"
                                : $"Dateigroesse: {new FileInfo(logPath).Length} Bytes"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Also do a broad search for .log files with mapper keywords in temp dirs
            var tempDirs = new[]
            {
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(WinDir, "Temp"),
            };

            foreach (var tempDir in tempDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tempDir)) continue;

                string[] logFiles;
                try { logFiles = Directory.GetFiles(tempDir, "*.log", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var logFile in logFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(logFile).ToLowerInvariant();
                    if (!fn.Contains("map") && !fn.Contains("drv") && !fn.Contains("inject")
                        && !fn.Contains("kernel") && !fn.Contains("driver")) continue;

                    ctx.IncrementFiles();
                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    bool hasMappingContent = content.Contains("kdmapper", StringComparison.OrdinalIgnoreCase)
                                         || content.Contains("iqvw64", StringComparison.OrdinalIgnoreCase)
                                         || content.Contains("dbutil_2_3", StringComparison.OrdinalIgnoreCase)
                                         || content.Contains("gdrv.sys", StringComparison.OrdinalIgnoreCase)
                                         || content.Contains("rtcore64", StringComparison.OrdinalIgnoreCase)
                                         || content.Contains("mhyprot", StringComparison.OrdinalIgnoreCase)
                                         || content.Contains("driver manual map", StringComparison.OrdinalIgnoreCase)
                                         || content.Contains("manual map", StringComparison.OrdinalIgnoreCase);
                    if (!hasMappingContent) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige Log-Datei mit Mapper-Inhalt im Temp-Ordner: {Path.GetFileName(logFile)}",
                        Risk = RiskLevel.High,
                        Location = logFile,
                        FileName = Path.GetFileName(logFile),
                        Reason = $"Eine Log-Datei im Temp-Ordner '{logFile}' enthaelt Verweise auf " +
                                 "bekannte Kernel-Driver-Mapper-Tools oder vulnerable Treiber. " +
                                 "Dies deutet auf eine kuerzlich stattgefundene Mapping-Operation hin.",
                        Detail = $"Dateiname: {fn} · Groesse: {new FileInfo(logFile).Length} Bytes"
                    });
                }
            }
        }, ct);

    private Task CheckTestSigningArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Downloads,
                Desktop,
                Documents,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                LocalAppData,
                UserProfile,
                ProgramData,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var batchName in TestSigningBatchNames)
                    {
                        var batchPath = Path.Combine(dir, batchName);
                        if (!File.Exists(batchPath)) continue;

                        ctx.IncrementFiles();
                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(batchPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { }

                        bool hasTestsignCommand = content.Contains("testsigning", StringComparison.OrdinalIgnoreCase)
                                               || content.Contains("nointegritychecks", StringComparison.OrdinalIgnoreCase)
                                               || content.Contains("bcdedit", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Test-Signing Aktivierungs-Script: {batchName}",
                            Risk = RiskLevel.High,
                            Location = batchPath,
                            FileName = batchName,
                            Reason = $"Ein Batch-Script zum Aktivieren des Windows Test-Signing-Modus wurde " +
                                     $"unter '{batchPath}' gefunden. Test-Signing deaktiviert die " +
                                     "Treiber-Signaturpruefung (DSE) fuer selbstsignierte Treiber und " +
                                     "ermoeglicht das Laden beliebiger Kernel-Treiber. Dies ist eine " +
                                     "verbreitete Methode, um Cheat-Treiber ohne Manual-Mapping zu laden.",
                            Detail = hasTestsignCommand
                                ? $"Enthaelt bcdedit/testsigning Befehle: {content[..Math.Min(200, content.Length)]}"
                                : $"Groesse: {new FileInfo(batchPath).Length} Bytes"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Also search recursively in downloads/desktop for batch files with testsigning content
            var recursiveDirs = new[] { Downloads, Desktop, Documents };
            foreach (var dir in recursiveDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] batFiles;
                try
                {
                    batFiles = Directory.GetFiles(dir, "*.bat", SearchOption.AllDirectories)
                        .Concat(Directory.GetFiles(dir, "*.cmd", SearchOption.AllDirectories))
                        .ToArray();
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var batFile in batFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    // Skip already-caught named files
                    var fn = Path.GetFileName(batFile);
                    if (TestSigningBatchNames.Any(n => fn.Equals(n, StringComparison.OrdinalIgnoreCase))) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(batFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    bool hasTestsign = (content.Contains("testsigning on", StringComparison.OrdinalIgnoreCase)
                                     || content.Contains("nointegritychecks on", StringComparison.OrdinalIgnoreCase))
                                    && content.Contains("bcdedit", StringComparison.OrdinalIgnoreCase);
                    if (!hasTestsign) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Batch-Script mit Test-Signing Befehlen: {fn}",
                        Risk = RiskLevel.High,
                        Location = batFile,
                        FileName = fn,
                        Reason = $"Ein Batch-Script '{fn}' unter '{batFile}' enthaelt bcdedit-Befehle " +
                                 "zum Aktivieren von testsigning oder nointegritychecks. Diese Befehle " +
                                 "deaktivieren die Windows-Treibersignaturueberpruefung und ermoeglichen " +
                                 "das Laden unsignierter Kernel-Treiber.",
                        Detail = $"Enthaelt: {content[..Math.Min(300, content.Length)]}"
                    });
                }
            }
        }, ct);

    private Task CheckDseBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchDirs = new[]
            {
                Downloads,
                Desktop,
                Documents,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                LocalAppData,
                RoamingAppData,
                ProgramData,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var fileName = Path.GetFileName(file);
                        bool isDseFix = DseBypassExecutables.Any(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (!isDseFix) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DSE-Bypass Tool gefunden: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Ein DSE-Bypass-Tool '{fileName}' wurde unter '{file}' gefunden. " +
                                     "Driver Signature Enforcement (DSE) Bypass-Tools patchen den " +
                                     "Windows-Kernel-CI-Check (ci.dll/wdfilter.sys), um das Laden " +
                                     "unsignierter Treiber zu ermoeglichen. DSEFix und aehnliche Tools " +
                                     "sind Kernel-Level-Werkzeuge fuer erfahrene Cheat-Entwickler.",
                            Detail = $"Groesse: {new FileInfo(file).Length} Bytes · " +
                                     $"Zuletzt geaendert: {File.GetLastWriteTime(file):yyyy-MM-dd HH:mm}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Check for DSE-related DLL files that patch ci.dll
            var dsePatchDlls = new[]
            {
                "ci_patch.dll",
                "dse_patch.dll",
                "wdfilter_patch.dll",
                "ci_bypass.dll",
                "dsepatch.dll",
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var dllName in dsePatchDlls)
                    {
                        var dllPath = Path.Combine(dir, dllName);
                        if (!File.Exists(dllPath)) continue;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DSE-Patch DLL: {dllName}",
                            Risk = RiskLevel.Critical,
                            Location = dllPath,
                            FileName = dllName,
                            Reason = $"Eine DSE-Patch DLL '{dllName}' wurde unter '{dllPath}' gefunden. " +
                                     "Patch-DLLs fuer ci.dll oder wdfilter.sys werden eingesetzt, um " +
                                     "Driver Signature Enforcement direkt im laufenden Kernel zu umgehen.",
                            Detail = $"Groesse: {new FileInfo(dllPath).Length} Bytes"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckPatchGuardBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchDirs = new[]
            {
                Downloads,
                Desktop,
                Documents,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                LocalAppData,
                RoamingAppData,
                ProgramData,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var fileName = Path.GetFileName(file);
                        bool isPgBypass = PatchGuardBypassExecutables.Any(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (!isPgBypass) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PatchGuard Bypass Tool: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Ein PatchGuard-Bypass-Tool '{fileName}' wurde unter '{file}' " +
                                     "gefunden. PatchGuard (Kernel Patch Protection, KPP) ist der " +
                                     "Windows-Schutzmechanismus, der Kernel-Patchversuche erkennt und " +
                                     "das System abbricht (BSOD). PatchGuard-Bypass-Tools umgehen diesen " +
                                     "Schutzmechanismus, um permanente Kernel-Patches durch Cheats zu " +
                                     "ermoeglichen (z.B. SSDT-Hooks, PatchGuard-Disable).",
                            Detail = $"Groesse: {new FileInfo(file).Length} Bytes · " +
                                     $"Zuletzt geaendert: {File.GetLastWriteTime(file):yyyy-MM-dd HH:mm}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Check for PG-bypass config/log files
            var pgArtifacts = new[]
            {
                "pg_bypass.log",
                "patchguard.log",
                "pg_disabled.txt",
                "patchguard_disabled.txt",
                "pg_bypass_status.txt",
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var artifact in pgArtifacts)
                    {
                        var path = Path.Combine(dir, artifact);
                        if (!File.Exists(path)) continue;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PatchGuard Bypass Artefakt: {artifact}",
                            Risk = RiskLevel.High,
                            Location = path,
                            FileName = artifact,
                            Reason = $"Ein PatchGuard-Bypass-Artefakt '{artifact}' wurde unter '{path}' " +
                                     "gefunden. Diese Dateien werden von PG-Bypass-Tools ausgegeben und " +
                                     "zeigen an, dass PatchGuard auf diesem System deaktiviert oder " +
                                     "umgangen wurde.",
                            Detail = $"Groesse: {new FileInfo(path).Length} Bytes"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckDriverImageInUnusualLocations(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // .sys files found outside System32\drivers are highly suspicious for manual mapping
            var unusualSysDirs = new[]
            {
                Downloads,
                Desktop,
                Documents,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(WinDir, "Temp"),
                RoamingAppData,
                LocalAppData,
                ProgramData,
                UserProfile,
            };

            var legitSysExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                // Skip known-good .sys files that might legitimately live outside drivers/
                "null"
            };

            foreach (var dir in unusualSysDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] sysFiles;
                try { sysFiles = Directory.GetFiles(dir, "*.sys", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var sysFile in sysFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var fileName = Path.GetFileName(sysFile);

                    // Skip already-caught BYOVD drivers (CheckByovdVulnerableDrivers handles those)
                    if (ByovdVulnerableDrivers.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Kernel-Treiber-Image in ungewoehnlichem Pfad: {fileName}",
                        Risk = RiskLevel.High,
                        Location = sysFile,
                        FileName = fileName,
                        Reason = $"Eine Kernel-Treiber-Image-Datei (.sys) wurde in einem ungewoehnlichen " +
                                 $"Verzeichnis '{sysFile}' gefunden. Kernel-Treiber sollten sich im " +
                                 "System32\\drivers-Ordner befinden. Eine .sys-Datei in Temp, Downloads, " +
                                 "AppData oder Desktop deutet auf manuelle Mapper-Staging oder BYOVD-Angriff hin.",
                        Detail = $"Groesse: {new FileInfo(sysFile).Length} Bytes · " +
                                 $"Erstellt: {File.GetCreationTime(sysFile):yyyy-MM-dd HH:mm} · " +
                                 $"Zuletzt geaendert: {File.GetLastWriteTime(sysFile):yyyy-MM-dd HH:mm}"
                    });
                }
            }
        }, ct);

    private Task CheckMapperRegistryServices(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var services = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
                if (services is null) return;

                foreach (var svcName in services.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;

                    var svcLower = svcName.ToLowerInvariant();
                    var matchedKeyword = SuspectMapperServiceKeywords.FirstOrDefault(k =>
                        svcLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (matchedKeyword is null) continue;

                    try
                    {
                        using var svcKey = services.OpenSubKey(svcName, writable: false);
                        if (svcKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        var imagePath = svcKey.GetValue("ImagePath")?.ToString() ?? string.Empty;
                        var displayName = svcKey.GetValue("DisplayName")?.ToString() ?? svcName;
                        var startType = svcKey.GetValue("Start")?.ToString() ?? "?";

                        // Verify image path matches known mapper/vulnerable driver patterns
                        bool imagePathSuspect = !string.IsNullOrEmpty(imagePath) &&
                            (imagePath.Contains("kdmapper", StringComparison.OrdinalIgnoreCase)
                          || imagePath.Contains("dbutil_2_3", StringComparison.OrdinalIgnoreCase)
                          || imagePath.Contains("gdrv", StringComparison.OrdinalIgnoreCase)
                          || imagePath.Contains("rtcore", StringComparison.OrdinalIgnoreCase)
                          || imagePath.Contains("mhyprot", StringComparison.OrdinalIgnoreCase)
                          || imagePath.Contains("iqvw64", StringComparison.OrdinalIgnoreCase)
                          || imagePath.Contains("winring0", StringComparison.OrdinalIgnoreCase)
                          || imagePath.Contains("turla", StringComparison.OrdinalIgnoreCase)
                          || imagePath.Contains("cpuz", StringComparison.OrdinalIgnoreCase)
                          || imagePath.Contains("winio", StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger Mapper/BYOVD Dienst in Registry: {svcName}",
                            Risk = imagePathSuspect ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = string.IsNullOrEmpty(imagePath) ? null : Path.GetFileName(imagePath.Trim('"')),
                            Reason = $"Ein Dienst-Eintrag '{svcName}' mit Mapper/BYOVD-Bezug wurde in der " +
                                     $"Services-Registry gefunden (Muster: '{matchedKeyword}'). " +
                                     (imagePathSuspect
                                         ? $"Der ImagePath '{imagePath}' referenziert bekannte Mapper-/vulnerable-Treiber-Dateien. "
                                         : "") +
                                     "Registry-Dienst-Eintraege fuer BYOVD-Treiber oder Mapper-Tools " +
                                     "zeigen an, dass diese als Windows-Dienst installiert wurden.",
                            Detail = $"ImagePath: {imagePath} · DisplayName: {displayName} · StartType: {startType}"
                        });
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckBcdRegistryTestSigning(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Check BCD (Boot Configuration Data) registry objects for test signing / nointegritychecks
            // BCD objects are stored under HKLM\BCD00000000
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);

                // Check the BCD store in registry for boot options
                var bcdPaths = new[]
                {
                    @"BCD00000000\Objects",
                    @"SYSTEM\CurrentControlSet\Control\CI",
                    @"SYSTEM\CurrentControlSet\Control\CI\Config",
                };

                foreach (var bcdPath in bcdPaths)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var key = hklm.OpenSubKey(bcdPath, writable: false);
                        if (key is null) continue;
                        ctx.IncrementRegistryKeys();

                        var valueNames = key.GetValueNames();
                        foreach (var vn in valueNames)
                        {
                            if (ct.IsCancellationRequested) return;
                            var val = key.GetValue(vn)?.ToString() ?? string.Empty;
                            if (val.Contains("testsigning", StringComparison.OrdinalIgnoreCase)
                             || val.Contains("nointegritychecks", StringComparison.OrdinalIgnoreCase)
                             || vn.Contains("VulnerableDriverBlocklistEnable", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Test-Signing oder DSE-Deaktivierung in BCD/CI Registry",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKLM\{bcdPath}\{vn}",
                                    Reason = $"Ein Registry-Wert unter 'HKLM\\{bcdPath}' wurde gefunden, " +
                                             "der Test-Signing oder NoIntegrityChecks-Konfiguration " +
                                             "anzeigt. Diese Einstellungen deaktivieren die " +
                                             "Windows-Treibersignaturpruefung und erlauben unsignierte " +
                                             "Kernel-Treiber.",
                                    Detail = $"Wert: {vn} = {val}"
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }

                // Check for VulnerableDriverBlocklistEnable = 0 (HVCI/WDAC blockist disabled)
                try
                {
                    using var ciKey = hklm.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\CI\Config", writable: false);
                    if (ciKey is not null)
                    {
                        ctx.IncrementRegistryKeys();
                        var blocklistVal = ciKey.GetValue("VulnerableDriverBlocklistEnable");
                        if (blocklistVal is int bv && bv == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Microsoft Vulnerable Driver Blocklist deaktiviert",
                                Risk = RiskLevel.High,
                                Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
                                Reason = "Der Microsoft Vulnerable Driver Blocklist ist deaktiviert " +
                                         "(VulnerableDriverBlocklistEnable=0). Diese Liste blockiert bekannte " +
                                         "vulnerable Treiber, die in BYOVD-Angriffen verwendet werden. " +
                                         "Die Deaktivierung ermoeglicht das Laden von Treibern wie " +
                                         "iqvw64e.sys, rtcore64.sys, dbutil_2_3.sys usw.",
                                Detail = $"VulnerableDriverBlocklistEnable = {bv}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }

                // Check for DebugFlags that indicate kernel debugging or DSE bypass
                try
                {
                    using var lsa = hklm.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\Lsa", writable: false);
                    if (lsa is not null)
                    {
                        ctx.IncrementRegistryKeys();
                        var testSigningValue = lsa.GetValue("TestSigning");
                        if (testSigningValue is int tsv && tsv != 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Test-Signing in LSA Registry aktiviert",
                                Risk = RiskLevel.High,
                                Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                                Reason = "Test-Signing ist in der LSA-Registry aktiviert. Dies ist " +
                                         "eine alternative Methode zum Aktivieren des Test-Signing-Modus " +
                                         "ohne bcdedit, die von einigen Cheat-Loadern verwendet wird.",
                                Detail = $"TestSigning = {tsv}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
            catch (UnauthorizedAccessException) { }

            // Check for bcdedit output artifact files (users sometimes save the output)
            var bcdOutputFiles = new[]
            {
                Path.Combine(Downloads, "bcdedit_output.txt"),
                Path.Combine(Desktop, "bcdedit_output.txt"),
                Path.Combine(Documents, "bcdedit_output.txt"),
                Path.Combine(Downloads, "bcd_settings.txt"),
                Path.Combine(Desktop, "bcd_settings.txt"),
                Path.Combine(Temp, "bcdedit.txt"),
            };

            foreach (var bcdFile in bcdOutputFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (!File.Exists(bcdFile)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"bcdedit Ausgabe-Datei: {Path.GetFileName(bcdFile)}",
                    Risk = RiskLevel.Medium,
                    Location = bcdFile,
                    FileName = Path.GetFileName(bcdFile),
                    Reason = $"Eine gespeicherte bcdedit-Ausgabe-Datei wurde unter '{bcdFile}' gefunden. " +
                             "Diese Dateien entstehen, wenn jemand bcdedit-Ausgaben in Dateien umleitet, " +
                             "um Boot-Konfigurationsaenderungen zu dokumentieren oder zu teilen.",
                    Detail = $"Groesse: {new FileInfo(bcdFile).Length} Bytes"
                });
            }
        }, ct);

    private Task CheckEventLogUnsignedDriverLoads(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Event ID 219: Unsigned driver load attempt (System log)
            try
            {
                var query = new EventLogQuery("System", PathType.LogName,
                    "*[System[EventID=219]]") { ReverseDirection = true };
                using var reader = new EventLogReader(query);
                int n = 0;
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                EventRecord? rec;
                while (n++ < 500 && (rec = reader.ReadEvent()) is not null)
                {
                    if (ct.IsCancellationRequested) { rec.Dispose(); return; }
                    try
                    {
                        var msg = rec.FormatDescription() ?? string.Empty;
                        var props = rec.Properties;
                        string? driverPath = null;
                        if (props.Count > 0) driverPath = props[0].Value?.ToString();

                        // Deduplicate by driver path
                        var dedupeKey = driverPath ?? msg[..Math.Min(80, msg.Length)];
                        if (!seen.Add(dedupeKey)) continue;

                        bool isSuspect = driverPath != null && (
                            ByovdVulnerableDrivers.Any(v =>
                                Path.GetFileName(driverPath).Equals(v, StringComparison.OrdinalIgnoreCase))
                            || KdmapperExecutables.Any(k =>
                                driverPath.Contains(Path.GetFileNameWithoutExtension(k),
                                    StringComparison.OrdinalIgnoreCase))
                            || msg.Contains("unsigned", StringComparison.OrdinalIgnoreCase)
                            || msg.Contains("test signing", StringComparison.OrdinalIgnoreCase));

                        var when = rec.TimeCreated?.ToLocalTime();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = isSuspect
                                ? $"Event 219: Verdaechtiger unsignierter Treiber-Ladeversuch"
                                : "Event 219: Unsignierter Treiber-Ladeversuch",
                            Risk = isSuspect ? RiskLevel.Critical : RiskLevel.High,
                            Location = "Windows Event Log: System (Event ID 219)",
                            FileName = driverPath != null ? Path.GetFileName(driverPath) : null,
                            Reason = $"Windows Event ID 219 zeigt einen Ladeversuch eines unsignierten " +
                                     "Kernel-Treibers. Dies ist ein direktes Artefakt eines manuellen " +
                                     "Treiber-Mapping-Versuchs oder BYOVD-Angriffs. Event-Log-Eintraege " +
                                     "bleiben erhalten, auch wenn der Treiber selbst geloescht wurde.",
                            Detail = $"Zeit: {when?.ToString("yyyy-MM-dd HH:mm") ?? "?"} · " +
                                     $"Treiberpfad: {driverPath ?? "??"}"
                        });
                    }
                    catch { }
                    finally { rec.Dispose(); }
                }
            }
            catch { }

            // Event ID 7045: New service installed (System log) - catch mapper/BYOVD service installs
            try
            {
                var query = new EventLogQuery("System", PathType.LogName,
                    "*[System[EventID=7045]]") { ReverseDirection = true };
                using var reader = new EventLogReader(query);
                int n = 0;
                EventRecord? rec;
                while (n++ < 400 && (rec = reader.ReadEvent()) is not null)
                {
                    if (ct.IsCancellationRequested) { rec.Dispose(); return; }
                    try
                    {
                        var props = rec.Properties;
                        string? svcName = props.Count > 0 ? props[0].Value?.ToString() : null;
                        string? imagePath = props.Count > 1 ? props[1].Value?.ToString() : null;

                        if (svcName is null && imagePath is null) continue;

                        bool isSuspect = SuspectMapperServiceKeywords.Any(k =>
                            (svcName?.Contains(k, StringComparison.OrdinalIgnoreCase) ?? false)
                            || (imagePath?.Contains(k, StringComparison.OrdinalIgnoreCase) ?? false));
                        if (!isSuspect) continue;

                        bool isByovd = imagePath != null && ByovdVulnerableDrivers.Any(v =>
                            imagePath.Contains(Path.GetFileNameWithoutExtension(v),
                                StringComparison.OrdinalIgnoreCase));

                        var when = rec.TimeCreated?.ToLocalTime();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = isByovd
                                ? $"Event 7045: BYOVD vulnerable Treiber als Dienst installiert: {svcName}"
                                : $"Event 7045: Mapper-bezogener Dienst installiert: {svcName}",
                            Risk = isByovd ? RiskLevel.Critical : RiskLevel.High,
                            Location = "Windows Event Log: System (Event ID 7045)",
                            FileName = imagePath != null ? Path.GetFileName(imagePath.Trim('"')) : null,
                            Reason = $"Windows Event 7045 zeigt die Installation eines Mapper/BYOVD-bezogenen " +
                                     $"Dienstes: '{svcName}'. " +
                                     (isByovd
                                         ? "Der ImagePath referenziert einen bekannten vulnerable Treiber (BYOVD). "
                                         : "") +
                                     "Dienst-Installations-Events bleiben im Event-Log erhalten.",
                            Detail = $"Zeit: {when?.ToString("yyyy-MM-dd HH:mm") ?? "?"} · " +
                                     $"Service: {svcName ?? "?"} · ImagePath: {imagePath ?? "?"}"
                        });
                    }
                    catch { }
                    finally { rec.Dispose(); }
                }
            }
            catch { }

            // Check Security log for privilege escalation attempts (Event 4697: service installed)
            try
            {
                var secQuery = new EventLogQuery("Security", PathType.LogName,
                    "*[System[EventID=4697]]") { ReverseDirection = true };
                using var secReader = new EventLogReader(secQuery);
                int n = 0;
                EventRecord? rec;
                while (n++ < 200 && (rec = secReader.ReadEvent()) is not null)
                {
                    if (ct.IsCancellationRequested) { rec.Dispose(); return; }
                    try
                    {
                        var props = rec.Properties;
                        // 4697: [0]=SubjectUserSid [1]=SubjectUserName ... [4]=ServiceName [5]=ServiceFileName
                        string? svcName = props.Count > 4 ? props[4].Value?.ToString() : null;
                        string? svcFile = props.Count > 5 ? props[5].Value?.ToString() : null;

                        bool isSuspect = SuspectMapperServiceKeywords.Any(k =>
                            (svcName?.Contains(k, StringComparison.OrdinalIgnoreCase) ?? false)
                            || (svcFile?.Contains(k, StringComparison.OrdinalIgnoreCase) ?? false));
                        if (!isSuspect) continue;

                        var when = rec.TimeCreated?.ToLocalTime();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Security Event 4697: Mapper/BYOVD Dienst-Sicherheitseintrag: {svcName}",
                            Risk = RiskLevel.High,
                            Location = "Windows Event Log: Security (Event ID 4697)",
                            Reason = $"Windows Security Event 4697 zeigt die Installation eines verdaechtigen " +
                                     $"Dienstes mit Mapper-Bezug: '{svcName}'. Security-Log-Eintraege " +
                                     "werden nur mit entsprechender Audit-Policy geschrieben und sind " +
                                     "besonders zuverlaessige forensische Artefakte.",
                            Detail = $"Zeit: {when?.ToString("yyyy-MM-dd HH:mm") ?? "?"} · " +
                                     $"Service: {svcName ?? "?"} · File: {svcFile ?? "?"}"
                        });
                    }
                    catch { }
                    finally { rec.Dispose(); }
                }
            }
            catch { }
        }, ct);

    private Task CheckMapperUserAssist(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            try
            {
                using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                using var ua = hkcu.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                    writable: false);
                if (ua is null) return;

                foreach (var guid in ua.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var count = ua.OpenSubKey($@"{guid}\Count", writable: false);
                        if (count is null) continue;
                        ctx.IncrementRegistryKeys();

                        foreach (var valueName in count.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            var decoded = Rot13Decode(valueName);
                            if (string.IsNullOrWhiteSpace(decoded)) continue;

                            var decodedLower = decoded.ToLowerInvariant();
                            bool isMapper = KdmapperExecutables.Any(n =>
                                decodedLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || ThunderingTurlaExecutables.Any(n =>
                                    decodedLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || OtherMapperExecutables.Any(n =>
                                    decodedLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || DseBypassExecutables.Any(n =>
                                    decodedLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || PatchGuardBypassExecutables.Any(n =>
                                    decodedLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || MapperMuiCacheKeywords.Any(k =>
                                    decodedLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (!isMapper) continue;

                            // Extract last run timestamp from UserAssist data
                            string? lastRun = null;
                            try
                            {
                                if (count.GetValue(valueName) is byte[] b && b.Length >= 72)
                                {
                                    var ft = BitConverter.ToInt64(b, 60);
                                    if (ft > 0)
                                        lastRun = DateTime.FromFileTime(ft).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
                                }
                            }
                            catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Kernel Mapper in UserAssist (Ausfuehrungsverlauf)",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Der Windows UserAssist-Schluessel zeigt, dass ein Kernel-Driver-" +
                                         $"Mapping-Tool ausgefuehrt wurde. Dekodierter Eintrag: '{decoded}'. " +
                                         "UserAssist protokolliert GUI-Programm-Starts und bleibt auch " +
                                         "nach Loeschung der Datei erhalten.",
                                Detail = lastRun is not null
                                    ? $"Zuletzt ausgefuehrt: {lastRun}"
                                    : $"Eintrag: {decoded}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckMapperMuiCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var muiCachePaths = new[]
            {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"Software\Microsoft\Windows\ShellNoRoam\MUICache",
            };

            try
            {
                using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                foreach (var muiPath in muiCachePaths)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var key = hkcu.OpenSubKey(muiPath, writable: false);
                        if (key is null) continue;
                        ctx.IncrementRegistryKeys();

                        foreach (var valueName in key.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            var vnLower = valueName.ToLowerInvariant();

                            bool isMapper = KdmapperExecutables.Any(n =>
                                vnLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || ThunderingTurlaExecutables.Any(n =>
                                    vnLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || OtherMapperExecutables.Any(n =>
                                    vnLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || DseBypassExecutables.Any(n =>
                                    vnLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || PatchGuardBypassExecutables.Any(n =>
                                    vnLower.Contains(Path.GetFileNameWithoutExtension(n).ToLowerInvariant()))
                                || MapperMuiCacheKeywords.Any(k =>
                                    vnLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (!isMapper) continue;

                            var displayName = key.GetValue(valueName)?.ToString() ?? string.Empty;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Kernel Mapper in MUICache (Ausfuehrungsverlauf)",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\{muiPath}",
                                FileName = Path.GetFileName(valueName.Split('.')[0]),
                                Reason = $"Der Windows MUICache-Schluessel zeigt, dass ein Kernel-Driver-" +
                                         "Mapping-Tool ausgefuehrt wurde. MUICache speichert Anzeigenamen " +
                                         "von ausgefuehrten GUI-Programmen und bleibt auch nach dem " +
                                         "Loeschen der Dateien erhalten.",
                                Detail = $"Pfad: {valueName} · Anzeigename: {displayName}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckMapperProcessArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var processes = ctx.GetProcessSnapshot();
            var allMapperNames = KdmapperExecutables
                .Concat(ThunderingTurlaExecutables)
                .Concat(OtherMapperExecutables)
                .Concat(DseBypassExecutables)
                .Concat(PatchGuardBypassExecutables)
                .ToArray();

            foreach (var proc in processes)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    ctx.IncrementProcesses();
                    var procExe = proc.ProcessName + ".exe";
                    bool isMapper = allMapperNames.Any(n =>
                        procExe.Equals(n, StringComparison.OrdinalIgnoreCase)
                        || proc.ProcessName.Equals(
                            Path.GetFileNameWithoutExtension(n),
                            StringComparison.OrdinalIgnoreCase));
                    if (!isMapper) continue;

                    string? imagePath = null;
                    try { imagePath = proc.MainModule?.FileName; } catch { }

                    var matchedName = allMapperNames.First(n =>
                        procExe.Equals(n, StringComparison.OrdinalIgnoreCase)
                        || proc.ProcessName.Equals(
                            Path.GetFileNameWithoutExtension(n),
                            StringComparison.OrdinalIgnoreCase));

                    bool isKdmapper = KdmapperExecutables.Any(n =>
                        procExe.Equals(n, StringComparison.OrdinalIgnoreCase));
                    bool isTurla = ThunderingTurlaExecutables.Any(n =>
                        procExe.Equals(n, StringComparison.OrdinalIgnoreCase));
                    bool isDse = DseBypassExecutables.Any(n =>
                        procExe.Equals(n, StringComparison.OrdinalIgnoreCase));
                    bool isPg = PatchGuardBypassExecutables.Any(n =>
                        procExe.Equals(n, StringComparison.OrdinalIgnoreCase));

                    string toolType = isKdmapper ? "kdmapper Kernel-Treiber-Mapper"
                        : isTurla ? "ThunderingTurla Kernel-Treiber-Mapper"
                        : isDse ? "DSE-Bypass-Tool"
                        : isPg ? "PatchGuard-Bypass-Tool"
                        : "Kernel-Driver-Mapping-Tool";

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"{toolType} AKTIV laufend: {proc.ProcessName}",
                        Risk = RiskLevel.Critical,
                        Location = imagePath ?? proc.ProcessName,
                        FileName = procExe,
                        Reason = $"Ein {toolType} laeuft AKTUELL als Prozess '{proc.ProcessName}' (PID {proc.Id}). " +
                                 "Ein aktiver Mapper-Prozess waehrend des Scans ist ein kritisches Indiz fuer " +
                                 "aktives Kernel-Level-Cheating oder eine gerade stattfindende " +
                                 "Treiber-Mapping-Operation.",
                        Detail = $"PID: {proc.Id} · Pfad: {imagePath ?? "unbekannt"} · Tool: {matchedName}"
                    });
                }
                catch { }
            }
        }, ct);

    private Task CheckMapperPrefetchArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Check Windows Prefetch for mapper tool execution history
            var prefetchDir = Path.Combine(WinDir, "Prefetch");
            if (!Directory.Exists(prefetchDir)) return;

            string[] pfFiles;
            try { pfFiles = Directory.GetFiles(prefetchDir, "*.pf"); }
            catch { return; }

            var allMapperNames = KdmapperExecutables
                .Concat(ThunderingTurlaExecutables)
                .Concat(OtherMapperExecutables)
                .Concat(DseBypassExecutables)
                .Concat(PatchGuardBypassExecutables)
                .Select(n => Path.GetFileNameWithoutExtension(n).ToUpperInvariant())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var byovdNames = ByovdVulnerableDrivers
                .Select(n => Path.GetFileNameWithoutExtension(n).ToUpperInvariant())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var pfFile in pfFiles)
            {
                if (ct.IsCancellationRequested) return;
                // "KDMAPPER.EXE-1A2B3C4D.pf" -> "KDMAPPER.EXE"
                var baseName = Path.GetFileNameWithoutExtension(pfFile);
                int dash = baseName.LastIndexOf('-');
                var exeName = dash > 0 ? baseName[..dash] : baseName;
                var exeBase = Path.GetFileNameWithoutExtension(exeName);

                bool isMapper = allMapperNames.Contains(exeBase);
                bool isByovdLoader = byovdNames.Contains(exeBase);
                bool isDseTool = exeName.Contains("DSEFIX", StringComparison.OrdinalIgnoreCase)
                              || exeName.Contains("BCDEDIT", StringComparison.OrdinalIgnoreCase);
                bool isTestSign = exeName.Contains("TESTSIGN", StringComparison.OrdinalIgnoreCase);

                if (!isMapper && !isByovdLoader && !isDseTool && !isTestSign) continue;

                string category = isMapper ? "Kernel-Driver-Mapper"
                    : isByovdLoader ? "BYOVD-Treiber-Lader"
                    : isDseTool ? "DSE-Bypass-Tool"
                    : "Test-Signing-Tool";

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Prefetch: {category} wurde ausgefuehrt: {exeName}",
                    Risk = RiskLevel.Critical,
                    Location = pfFile,
                    FileName = exeName,
                    Reason = $"Windows Prefetch zeigt, dass '{exeName}' ({category}) auf diesem System " +
                             "ausgefuehrt wurde. Prefetch-Dateien werden von Windows automatisch beim " +
                             "Start von Programmen erstellt und bleiben auch nach dem Loeschen der " +
                             "Originaldatei bestehen. Dies ist ein zuverlaessiges forensisches Artefakt " +
                             "fuer vergangene Programm-Ausfuehrungen.",
                    Detail = $"Prefetch-Datei: {pfFile} · " +
                             $"Zuletzt geaendert: {File.GetLastWriteTime(pfFile):yyyy-MM-dd HH:mm}"
                });
            }

            // Also check PCA (Program Compatibility Assistant) logs for mapper executions
            var pcaDir = Path.Combine(WinDir, "appcompat", "pca");
            if (!Directory.Exists(pcaDir)) return;

            foreach (var pcaFile in new[] { "PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt" })
            {
                if (ct.IsCancellationRequested) return;
                var pcaPath = Path.Combine(pcaDir, pcaFile);
                if (!File.Exists(pcaPath)) continue;

                string[] lines;
                try { lines = File.ReadAllLines(pcaPath); }
                catch { continue; }

                foreach (var line in lines)
                {
                    if (ct.IsCancellationRequested) return;
                    if (string.IsNullOrWhiteSpace(line)) continue;

                    var path = line.Split('\t', '|')[0].Trim();
                    if (path.Length < 4 || !path.Contains('\\')) continue;

                    var pathLower = path.ToLowerInvariant();
                    var fileName = Path.GetFileNameWithoutExtension(path).ToUpperInvariant();

                    bool isMapperRef = allMapperNames.Contains(fileName)
                        || MapperMuiCacheKeywords.Any(k =>
                            pathLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (!isMapperRef) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PCA-Log: Mapper-Tool wurde ausgefuehrt: {Path.GetFileName(path)}",
                        Risk = RiskLevel.Critical,
                        Location = $"{pcaPath} -> {path}",
                        FileName = Path.GetFileName(path),
                        Reason = $"Der Windows Program Compatibility Assistant (PCA) Log zeigt, dass " +
                                 $"'{path}' ausgefuehrt wurde. PCA-Logs sind forensische Artefakte fuer " +
                                 "vergangene Programm-Ausfuehrungen und bleiben nach Loeschung der " +
                                 "Originaldatei erhalten.",
                        Detail = $"PCA-Datei: {pcaFile} · Referenzierter Pfad: {path}"
                    });
                }
            }
        }, ct);

    private static string Rot13Decode(string s)
    {
        var a = s.ToCharArray();
        for (int i = 0; i < a.Length; i++)
        {
            char c = a[i];
            if (c is >= 'A' and <= 'Z') a[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c is >= 'a' and <= 'z') a[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(a);
    }
}
