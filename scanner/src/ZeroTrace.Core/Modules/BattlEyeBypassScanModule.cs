using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class BattlEyeBypassScanModule : IScanModule
{
    public string Name => "BattlEye Bypass Detection";
    public double Weight => 4.1;
    public int ParallelGroup => 4;

    // System root environment variable used across several checks
    private static readonly string SystemRoot =
        Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";

    // Common user-profile directories used for bypass artifact searches
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    private static readonly string Downloads =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string TempDir =
        Path.GetTempPath();

    // BattlEye service names to check in the registry
    private static readonly string[] BeServiceNames =
    {
        "BEService",
        "BEService_x64",
        "BE_x64",
        "BattlEyeService",
    };

    // Known game installation paths that use BattlEye
    private static readonly (string GameName, string GamePath)[] SupportedGames =
    {
        ("PUBG",
         @"C:\Program Files (x86)\Steam\steamapps\common\PUBG\"),
        ("DayZ",
         @"C:\Program Files (x86)\Steam\steamapps\common\DayZ\"),
        ("Arma 3",
         @"C:\Program Files (x86)\Steam\steamapps\common\Arma 3\"),
        ("Rainbow Six Siege",
         @"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Tom Clancy's Rainbow Six Siege\"),
        ("ARK Survival",
         @"C:\Program Files (x86)\Steam\steamapps\common\ARK\"),
        ("Battlegrounds (Epic)",
         @"C:\Program Files\Epic Games\PUBG\"),
    };

    // Exact filenames of known BattlEye bypass tools — all Critical risk
    private static readonly string[] BypassToolFileNames =
    {
        "BELoader.exe",
        "BEBypass.dll",
        "BattlEyeBypass.exe",
        "BE_Bypass.exe",
        "be_bypass.dll",
        "battleye_bypass.exe",
        "BEService_fake.exe",
        "be_emu.dll",
        "be_emulator.dll",
        "bebypass.exe",
        "BEKiller.exe",
        "battleye_killer.exe",
        "be_spoofer.exe",
        "BEFix.exe",
        "openbe.dll",
        "BEClient_bypass.dll",
        "BEClient_fake.dll",
        "BEDaisy_bypass.sys",
        "be_hook.dll",
        "be_patcher.exe",
        "BattleEyeBypass.exe",
        "BattlEye_Bypass.dll",
        "battleye-bypass.exe",
        "battleye-bypass.dll",
        "beloader.exe",
        "be-bypass.exe",
        "beunloader.exe",
        "BEUnlocker.exe",
        "anti_battleye.dll",
        "battleyekill.exe",
    };

    // GitHub-style clone directory names for BE bypass source repos
    private static readonly string[] BypassRepoDirNames =
    {
        "BattlEye-Bypass",
        "be-bypass",
        "battleye-emu",
        "OpenBattlEye",
        "BEEmulator",
        "battleye-bypass",
        "BE-Bypass",
        "BattlEyeEmulator",
        "open-battleye",
        "battleye_bypass_src",
        "be_bypass_source",
    };

    // BYOVD (Bring Your Own Vulnerable Driver) driver filenames known to be used
    // against BattlEye, along with a short description of each driver's origin.
    private static readonly (string FileName, string Description)[] ByovdDrivers =
    {
        ("gdrv.sys",           "Gigabyte Generic Driver — known BYOVD for arbitrary kernel read/write"),
        ("WinRing0x64.sys",    "WinRing0 x64 — open-source ring-0 utility, widely abused by cheats"),
        ("WinRing0.sys",       "WinRing0 x86 — same family as WinRing0x64, ring-0 I/O"),
        ("cpuz141_x64.sys",    "CPU-Z 1.41 x64 driver — exploitable for kernel memory access"),
        ("cpuz143_x64.sys",    "CPU-Z 1.43 x64 driver — variant with mapped physical memory exploit"),
        ("cpuz145.sys",        "CPU-Z 1.45 driver — MSR and physical memory access"),
        ("AsrDrv103.sys",      "ASRock BIOS Utility driver — arbitrary physical memory R/W"),
        ("HwRwDrv.sys",        "Hardware Read/Write Driver — generic IOCTL for ring-0 R/W"),
        ("iqvw64e.sys",        "Intel Network Adapter Diagnostics — kernel R/W via IOCTL"),
        ("MsIo64.sys",         "MSI I/O Driver x64 — port and physical memory access"),
        ("PhyMemDrv.sys",      "Physical Memory Driver — direct physical memory mapping"),
        ("PROCEXP152.SYS",     "Process Explorer driver — process handle elevation exploit"),
        ("dbutil_2_3.sys",     "Dell BIOS Utility 2.3 — arbitrary physical memory R/W (CVE-2021-21551)"),
        ("RTCore64.sys",       "MSI Afterburner/Micro-Star kernel driver — read/write kernel memory"),
        ("kprocesshacker.sys", "Process Hacker kernel driver — full kernel access"),
        ("AsUpIO64.sys",       "ASUS BIOS Update I/O driver — physical memory and MSR access"),
        ("NalDrv.sys",         "Intel Network Adapter Legacy driver — kernel memory access"),
        ("Speedfan.sys",       "SpeedFan hardware monitor driver — I/O port and MSR access"),
        ("ATSZIO64.sys",       "ASUSTeK I/O driver — physical memory and MSR R/W"),
        ("NvflashStrapper.sys","Nvidia Flash Strapper — kernel memory access"),
        ("piddrv64.sys",       "Unknown PID driver x64 — used for process enumeration bypass"),
        ("rwdrv.sys",          "RW-Everything driver — physical memory and PCI config R/W"),
        ("sysdiag64.sys",      "Sysdiag x64 — hardware diagnostics with kernel R/W"),
        ("viragt64.sys",       "VirAGT x64 — antivirus engine driver abused for kernel access"),
        ("WinIo64.sys",        "WinIo x64 — ring-0 hardware I/O, common in HWID spoofers"),
        ("mhyprot2.sys",       "miHoYo Anti-Cheat driver — ironically used to bypass other ACs"),
        ("Dbk64.sys",          "Cheat Engine x64 kernel driver — direct memory access for cheats"),
        ("phymem64.sys",       "Physical Memory x64 — direct physical page mapping"),
        ("AsIO3.sys",          "ASUS AURA I/O v3 — arbitrary kernel R/W"),
        ("EneTechIo64.sys",    "ENE Technology I/O x64 — hardware control with kernel R/W"),
    };

    // Suspicious directories to search for BYOVD drivers and bypass tools
    private static string[] SuspiciousSearchDirs => new[]
    {
        TempDir,
        Downloads,
        AppDataRoaming,
        AppDataLocal,
        Desktop,
    };

    // Script patterns to detect in PowerShell history and batch/script files
    private static readonly (string[] Keywords, string Description, RiskLevel Risk)[] ScriptPatterns =
    {
        (new[] { "sc stop BEService" },                   "BEService via sc.exe gestoppt",                     RiskLevel.High),
        (new[] { "sc delete BEService" },                 "BEService via sc.exe gelöscht",                     RiskLevel.Critical),
        (new[] { "taskkill", "BEService" },               "BEService-Prozess via taskkill beendet",             RiskLevel.High),
        (new[] { "taskkill", "BattlEye" },                "BattlEye-Prozess via taskkill beendet",              RiskLevel.High),
        (new[] { "net stop BEService" },                  "BEService via net stop gestoppt",                    RiskLevel.High),
        (new[] { "net stop BattlEye" },                   "BattlEye-Dienst via net stop gestoppt",              RiskLevel.High),
        (new[] { "sc stop BEDaisy" },                     "BEDaisy-Kerneltreiber via sc.exe gestoppt",          RiskLevel.Critical),
        (new[] { "NtLoadDriver", "BEDaisy" },             "NtLoadDriver-Aufruf mit BEDaisy-Bezug",              RiskLevel.Critical),
        (new[] { "NtLoadDriver", "battleye" },            "NtLoadDriver-Aufruf mit BattlEye-Bezug",             RiskLevel.Critical),
        (new[] { "BEDaisy", "disable" },                  "BEDaisy-Treiber deaktiviert",                        RiskLevel.Critical),
        (new[] { "BEDaisy", "unload" },                   "BEDaisy-Treiber entladen",                           RiskLevel.Critical),
        (new[] { "BEDaisy", "stop" },                     "BEDaisy-Treiber gestoppt",                           RiskLevel.Critical),
        (new[] { "sc query", "BEDaisy" },                 "BEDaisy-Treiberstatus abgefragt (Enumeration)",      RiskLevel.Medium),
    };

    // Timing-injection marker file names used by cheat loaders
    private static readonly string[] InjectionMarkerFileNames =
    {
        "inject_after_be.txt",
        "be_ready.flag",
        "be_init_done.txt",
        "be_initialized",
        "cheat_wait_be.ini",
        "loader_timing.cfg",
        "injection_delay.txt",
        "be_wait.dat",
    };

    // Keywords that indicate injection-timing config inside .ini/.cfg files
    private static readonly string[] InjectionConfigKeywords =
    {
        "be_init",
        "battleye_ready",
        "wait_be",
        "inject_delay",
    };

    // BattlEye-owned domains that bypass tools redirect to localhost/null
    private static readonly string[] BeDomains =
    {
        "anti-cheat.battleye.com",
        "battleye.com",
        "be-report.battleye.com",
    };

    // BEClient.dll content keywords that indicate a fake/bypass replacement
    private static readonly string[] BeclientBypassKeywords =
    {
        "bypass",
        "fake",
        "emu",
        "emulate",
    };

    // --------------------------------------------------------------------------
    // RunAsync — entry point, delegates to all private helper methods
    // --------------------------------------------------------------------------

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        // Phase 1: Registry checks (services, driver locations, certificates)
        await CheckBeServiceRegistryAsync(ctx, ct);
        ctx.Report(0.07, "BEService-Registry", "Dienst-Registry geprüft");

        await CheckBeDaisyDriverRegistryAsync(ctx, ct);
        ctx.Report(0.14, "BEDaisy-Registry", "Treiber-Registry geprüft");

        await CheckCertificateBypassRegistryAsync(ctx, ct);
        ctx.Report(0.20, "Zertifikat-Registry", "Zertifikate geprüft");

        await CheckDnsCacheRegistryAsync(ctx, ct);
        ctx.Report(0.24, "DNS-Registry", "DNS-Registry geprüft");

        await CheckPacketCaptureRegistryAsync(ctx, ct);
        ctx.Report(0.27, "Paketerfassung", "WinPcap/Npcap-Registry geprüft");

        // Phase 2: File system checks (game dirs, bypass tools, drivers, scripts)
        ct.ThrowIfCancellationRequested();
        await CheckGameDirectoriesAsync(ctx, ct);
        ctx.Report(0.40, "Spielverzeichnisse", "Spielverzeichnisse geprüft");

        await ScanBypassToolFilesAsync(ctx, ct);
        ctx.Report(0.50, "Bypass-Dateien", "Bypass-Tool-Dateien geprüft");

        await ScanBypassRepoDirsAsync(ctx, ct);
        ctx.Report(0.57, "Bypass-Repos", "Bypass-Repository-Ordner geprüft");

        await ScanByovdDriverFilesAsync(ctx, ct);
        ctx.Report(0.64, "BYOVD-Treiber", "BYOVD-Treiberdateien geprüft");

        await CheckByovdDriverRegistryServicesAsync(ctx, ct);
        ctx.Report(0.68, "BYOVD-Registry", "BYOVD-Treiber-Dienste geprüft");

        // Phase 3: Content-based checks (scripts, hosts file, DayZ DLL)
        ct.ThrowIfCancellationRequested();
        await CheckPowerShellHistoryAsync(ctx, ct);
        ctx.Report(0.73, "PS-Verlauf", "PowerShell-Verlauf geprüft");

        await ScanScriptFilesAsync(ctx, ct);
        ctx.Report(0.79, "Skriptdateien", "Skriptdateien geprüft");

        await CheckHostsFileAsync(ctx, ct);
        ctx.Report(0.83, "HOSTS-Datei", "HOSTS-Datei geprüft");

        await CheckDayzBeclientDllAsync(ctx, ct);
        ctx.Report(0.87, "DayZ BEClient.dll", "DayZ-BEClient.dll geprüft");

        await ScanPcapFilesAsync(ctx, ct);
        ctx.Report(0.91, "PCAP-Dateien", "Paketerfassungsdateien geprüft");

        await CheckInjectionMarkerFilesAsync(ctx, ct);
        ctx.Report(0.95, "Injection-Marker", "Injection-Marker geprüft");

        // Phase 4: Process checks
        ct.ThrowIfCancellationRequested();
        await CheckBeProcessArtifactsAsync(ctx, ct);
        ctx.Report(1.0, Name, "BattlEye-Bypass-Erkennung abgeschlossen");
    }

    // --------------------------------------------------------------------------
    // 1. BattlEye service registry check
    // --------------------------------------------------------------------------

    private async Task CheckBeServiceRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            foreach (var svcName in BeServiceNames)
            {
                ct.ThrowIfCancellationRequested();
                CheckSingleBeServiceRegistry(svcName, ctx);
            }
        }, ct);
    }

    private void CheckSingleBeServiceRegistry(string svcName, ScanContext ctx)
    {
        var keyPath = $@"SYSTEM\CurrentControlSet\Services\{svcName}";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            // Check Start value — should be 2 (auto-start) for a legitimate BE service
            var startRaw = key.GetValue("Start");
            if (startRaw is int startVal)
            {
                if (startVal == 4)
                {
                    // Disabled — strongest signal of deliberate sabotage
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"BattlEye-Dienst deaktiviert: {svcName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{keyPath}",
                        Reason   = $"Der BattlEye-Dienst '{svcName}' ist explizit deaktiviert (Start=4). " +
                                   "Ein deaktivierter BattlEye-Dienst verhindert, dass der Anti-Cheat beim " +
                                   "nächsten Spielstart lädt. Dies ist ein klassisches Muster um BattlEye " +
                                   "dauerhaft zu sabotieren.",
                        Detail   = $"Registry: HKLM\\{keyPath} | Start = {startVal} (Disabled)"
                    });
                }
                else if (startVal == 3)
                {
                    // Manual start — less severe but still suspicious for a BE service
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"BattlEye-Dienst auf manuellen Start gesetzt: {svcName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{keyPath}",
                        Reason   = $"Der BattlEye-Dienst '{svcName}' ist auf manuellen Start (Start=3) " +
                                   "gesetzt statt auf automatisch (Start=2). Dies kann verhindern, dass " +
                                   "BattlEye beim Spielstart ordnungsgemäß gestartet wird.",
                        Detail   = $"Registry: HKLM\\{keyPath} | Start = {startVal} (Manual)"
                    });
                }
            }

            // Check ImagePath — must contain \BattlEye\ for legitimacy
            var imagePathRaw = key.GetValue("ImagePath");
            var imagePath = imagePathRaw?.ToString() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(imagePath))
            {
                if (!imagePath.Contains(@"\BattlEye\", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"BattlEye-Dienst ImagePath enthält kein \\BattlEye\\: {svcName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{keyPath}",
                        Reason   = $"Der Dienst '{svcName}' hat einen ImagePath der keinen '\\BattlEye\\'" +
                                   "-Ordner enthält. Legitime BattlEye-Dienste zeigen immer in ein " +
                                   "BattlEye-Unterverzeichnis. Ein fremder ImagePath deutet auf eine " +
                                   "gefälschte oder umgeleitete Dienstregistrierung hin.",
                        Detail   = $"ImagePath: {imagePath}"
                    });
                }
                else
                {
                    // ImagePath points into BattlEye directory — check for Temp/Downloads/AppData
                    var lower = imagePath.ToLowerInvariant();
                    if (lower.Contains("\\temp\\") || lower.Contains("\\tmp\\") ||
                        lower.Contains("\\downloads\\") || lower.Contains("\\appdata\\"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"BattlEye-Dienst ImagePath in verdächtigem Verzeichnis: {svcName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"Der Dienst '{svcName}' hat einen ImagePath der auf ein " +
                                       "Temp/Downloads/AppData-Verzeichnis zeigt. Ein legitimer BattlEye-Dienst " +
                                       "wird niemals aus diesen Verzeichnissen gestartet. Dies weist auf eine " +
                                       "gefälschte oder bösartige Dienstregistrierung hin.",
                            Detail   = $"ImagePath: {imagePath}"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // --------------------------------------------------------------------------
    // 2. BEDaisy.sys driver location check
    // --------------------------------------------------------------------------

    private async Task CheckBeDaisyDriverRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var keyPath = @"SYSTEM\CurrentControlSet\Services\BEDaisy";
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                if (key is null) return;
                ctx.IncrementRegistryKeys();

                var imagePathRaw = key.GetValue("ImagePath");
                var imagePath = imagePathRaw?.ToString() ?? string.Empty;

                if (string.IsNullOrWhiteSpace(imagePath)) return;

                var lower = imagePath.ToLowerInvariant();

                // BEDaisy.sys should be in a game-specific BattlEye subfolder
                // Finding it in System32\drivers is suspicious (it should live in the game dir)
                if (lower.Contains(@"\system32\drivers\", StringComparison.OrdinalIgnoreCase) ||
                    lower.Contains("system32\\drivers", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "BEDaisy.sys in System32\\drivers registriert",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{keyPath}",
                        Reason   = "Der BEDaisy-Kerneltreiber ist in System32\\drivers registriert. " +
                                   "Legitime BEDaisy-Instanzen befinden sich im spielspezifischen " +
                                   "BattlEye-Unterordner, nicht im globalen Treiberordner. " +
                                   "Dies deutet auf eine manipulierte oder ersetzt Treiberregistrierung hin.",
                        Detail   = $"ImagePath: {imagePath}"
                    });
                }
                else if (lower.Contains("\\temp\\") || lower.Contains("\\tmp\\") ||
                         lower.Contains("\\downloads\\"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "BEDaisy.sys in Temp/Downloads-Verzeichnis registriert",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{keyPath}",
                        Reason   = "Der BEDaisy-Kerneltreiber ist aus einem Temp- oder Downloads-Verzeichnis " +
                                   "registriert. Dies ist ein eindeutiges Zeichen für eine gefälschte oder " +
                                   "manipulierte Treiberregistrierung, die zur Umgehung von BattlEye " +
                                   "verwendet werden kann.",
                        Detail   = $"ImagePath: {imagePath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }

            // Search for BEDaisy.sys in suspicious filesystem locations
            foreach (var dir in SuspiciousSearchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "BEDaisy.sys",
                        SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "BEDaisy.sys in verdächtigem Verzeichnis gefunden",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = "BEDaisy.sys",
                            Reason   = "Eine Kopie von BEDaisy.sys wurde außerhalb eines legitimen " +
                                       "Spielverzeichnisses gefunden. Angreifer kopieren den Treiber " +
                                       "in Temp/Downloads/AppData um ihn als BYOVD-ähnliches Werkzeug " +
                                       "zu laden oder den echten Treiber zu ersetzen.",
                            Detail   = $"Gefunden in: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
                catch { }
            }
        }, ct);
    }

    // --------------------------------------------------------------------------
    // 3. BattlEye folder checks in supported game directories
    // --------------------------------------------------------------------------

    private async Task CheckGameDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            foreach (var (gameName, gamePath) in SupportedGames)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(gamePath)) continue;

                CheckGameBattlEyeFolder(gameName, gamePath, ctx);
            }
        }, ct);
    }

    private void CheckGameBattlEyeFolder(string gameName, string gamePath, ScanContext ctx)
    {
        var beFolder = Path.Combine(gamePath, "BattlEye");

        // Flag if the BattlEye subfolder is missing entirely
        if (!Directory.Exists(beFolder))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"BattlEye-Ordner fehlt: {gameName}",
                Risk     = RiskLevel.Medium,
                Location = beFolder,
                Reason   = $"Das Spiel '{gameName}' ist installiert, aber der erwartete " +
                           "BattlEye-Unterordner fehlt. Dies kann bedeuten, dass BattlEye " +
                           "manuell entfernt oder nie korrekt installiert wurde.",
                Detail   = $"Erwartet: {beFolder}"
            });
            return;
        }

        // Check for BEClient.dll — the core BattlEye client library
        var beclientPath = Path.Combine(beFolder, "BEClient.dll");
        if (!File.Exists(beclientPath))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"BEClient.dll fehlt: {gameName}",
                Risk     = RiskLevel.High,
                Location = beclientPath,
                FileName = "BEClient.dll",
                Reason   = $"Das BattlEye-Verzeichnis für '{gameName}' existiert, aber " +
                           "BEClient.dll fehlt. Die Client-DLL ist der Kern des BattlEye-Schutzes — " +
                           "ihr Fehlen deutet auf absichtliche Entfernung oder einen fehlgeschlagenen " +
                           "Installationsversuch zur Umgehung des Schutzes hin.",
                Detail   = $"Erwartet: {beclientPath}"
            });
        }
        else
        {
            ctx.IncrementFiles();
        }

        // Check for BEService.exe — required for service-mode games
        var beServiceExe = Path.Combine(beFolder, "BEService.exe");
        if (!File.Exists(beServiceExe))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"BEService.exe fehlt: {gameName}",
                Risk     = RiskLevel.Medium,
                Location = beServiceExe,
                FileName = "BEService.exe",
                Reason   = $"BEService.exe fehlt im BattlEye-Verzeichnis von '{gameName}'. " +
                           "Obwohl nicht alle Spiele dieses Executable erfordern, " +
                           "ist ihr Fehlen bei Spielen die den BEService-Dienst verwenden " +
                           "ein Zeichen für eine unvollständige oder manipulierte Installation.",
                Detail   = $"Erwartet: {beServiceExe}"
            });
        }
        else
        {
            ctx.IncrementFiles();
        }

        // Check for BEClient.log anomalies
        CheckBeLogFileAnomaly(gameName, beFolder, ctx);
    }

    // --------------------------------------------------------------------------
    // 4. BE log file anomalies
    // --------------------------------------------------------------------------

    private void CheckBeLogFileAnomaly(string gameName, string beFolder, ScanContext ctx)
    {
        var logPath = Path.Combine(beFolder, "BEClient.log");

        if (!File.Exists(logPath))
        {
            // Log file missing but BattlEye folder exists — low severity informational
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"BEClient.log fehlt: {gameName}",
                Risk     = RiskLevel.Low,
                Location = logPath,
                FileName = "BEClient.log",
                Reason   = $"Der BattlEye-Ordner für '{gameName}' existiert, aber BEClient.log " +
                           "fehlt. Die Log-Datei fehlt möglicherweise weil das Spiel noch nie " +
                           "gestartet wurde, oder sie wurde absichtlich gelöscht.",
                Detail   = $"BattlEye-Ordner: {beFolder}"
            });
            return;
        }

        ctx.IncrementFiles();

        try
        {
            var fi = new FileInfo(logPath);
            if (fi.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"BEClient.log ist leer: {gameName}",
                    Risk     = RiskLevel.Medium,
                    Location = logPath,
                    FileName = "BEClient.log",
                    Reason   = $"Die BattlEye-Log-Datei für '{gameName}' hat eine Größe von 0 Bytes. " +
                               "Dies deutet darauf hin, dass der Log nach einer Sitzung absichtlich " +
                               "geleert wurde um Spuren einer BattlEye-Umgehung zu verbergen.",
                    Detail   = $"Datei: {logPath} | Größe: 0 Bytes | Geändert: {fi.LastWriteTime:u}"
                });
            }
        }
        catch (IOException) { }
        catch { }
    }

    // --------------------------------------------------------------------------
    // 5. BE certificate validation bypass
    // --------------------------------------------------------------------------

    private async Task CheckCertificateBypassRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check both HKLM and HKCU Disallowed certificate stores
            CheckDisallowedCertStore(
                Registry.LocalMachine,
                @"SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates",
                "HKLM",
                ctx);

            ct.ThrowIfCancellationRequested();

            CheckDisallowedCertStore(
                Registry.CurrentUser,
                @"SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates",
                "HKCU",
                ctx);
        }, ct);
    }

    private void CheckDisallowedCertStore(RegistryKey hive, string keyPath, string hiveName, ScanContext ctx)
    {
        try
        {
            using var disallowedKey = hive.OpenSubKey(keyPath, writable: false);
            if (disallowedKey is null) return;
            ctx.IncrementRegistryKeys();

            var thumbprints = disallowedKey.GetSubKeyNames();
            foreach (var thumbprint in thumbprints)
            {
                ctx.IncrementRegistryKeys();
                // Any entry in the Disallowed store can block BattlEye code signing verification
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Zertifikat in Disallowed-Store blockiert Code-Signatur-Prüfung",
                    Risk     = RiskLevel.High,
                    Location = $@"{hiveName}\{keyPath}\{thumbprint}",
                    Reason   = "Im Windows Disallowed-Zertifikatsspeicher wurde ein Zertifikat gefunden. " +
                               "Bypass-Tools blockieren gezielt BattlEye-Signaturzertifikate in diesem " +
                               "Speicher um die Code-Signaturprüfung von BattlEye zu unterbinden. " +
                               "Dies kann die Integrität der BattlEye-Komponenten kompromittieren.",
                    Detail   = $"Thumbprint: {thumbprint} | Store: {hiveName}\\{keyPath}"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // --------------------------------------------------------------------------
    // 6. Known BE bypass tool files
    // --------------------------------------------------------------------------

    private async Task ScanBypassToolFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            foreach (var dir in SuspiciousSearchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                ScanDirectoryForBypassTools(dir, ctx, ct);
            }
        }, ct);
    }

    private void ScanDirectoryForBypassTools(string dir, ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                foreach (var bypassName in BypassToolFileNames)
                {
                    if (!string.Equals(fileName, bypassName, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"BattlEye-Bypass-Tool gefunden: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Die Datei '{fileName}' ist ein bekanntes BattlEye-Bypass-Tool. " +
                                   "Diese Dateien werden verwendet um BattlEye zu umgehen, " +
                                   "zu emulieren oder zu deaktivieren.",
                        Detail   = $"Gefunden in: {dir} | Datei: {file}"
                    });
                    break;
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        catch { }

        // Also search one level deep into subdirectories
        try
        {
            foreach (var subDir in Directory.EnumerateDirectories(dir))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(subDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        foreach (var bypassName in BypassToolFileNames)
                        {
                            if (!string.Equals(fileName, bypassName, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"BattlEye-Bypass-Tool gefunden: {fileName}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Die Datei '{fileName}' ist ein bekanntes BattlEye-Bypass-Tool. " +
                                           "Diese Dateien werden verwendet um BattlEye zu umgehen, " +
                                           "zu emulieren oder zu deaktivieren.",
                                Detail   = $"Gefunden in: {subDir} | Datei: {file}"
                            });
                            break;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        catch { }
    }

    // --------------------------------------------------------------------------
    // 7. GitHub clone directories for BE bypass
    // --------------------------------------------------------------------------

    private async Task ScanBypassRepoDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var repoDirs = new[]
            {
                Desktop,
                Downloads,
                Documents,
                AppDataRoaming,
            };

            foreach (var searchDir in repoDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(searchDir)) continue;
                ScanForBypassRepoDirs(searchDir, ctx, ct);
            }
        }, ct);
    }

    private void ScanForBypassRepoDirs(string parentDir, ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(parentDir))
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(dir);
                foreach (var repoName in BypassRepoDirNames)
                {
                    if (!string.Equals(dirName, repoName, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"BattlEye-Bypass-Repository-Ordner gefunden: {dirName}",
                        Risk     = RiskLevel.High,
                        Location = dir,
                        Reason   = $"Ein Ordner mit dem Namen '{dirName}' wurde gefunden. " +
                                   "Dieser Name entspricht einem bekannten BattlEye-Bypass-Repository " +
                                   "das typischerweise von GitHub geklont wird. " +
                                   "Solche Repositories enthalten Quellcode und Werkzeuge zur " +
                                   "Umgehung des BattlEye-Anti-Cheat-Systems.",
                        Detail   = $"Verzeichnis: {dir} | Elternordner: {parentDir}"
                    });
                    break;
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        catch { }
    }

    // --------------------------------------------------------------------------
    // 8. Script-based bypass in PowerShell history
    // --------------------------------------------------------------------------

    private async Task CheckPowerShellHistoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var historyPath = Path.Combine(
            AppDataRoaming,
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

        if (!File.Exists(historyPath)) return;

        ctx.IncrementFiles();

        try
        {
            string content;
            using var fs = new FileStream(historyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();

            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var rawLine in lines)
            {
                ct.ThrowIfCancellationRequested();
                var line = rawLine.Trim();
                if (string.IsNullOrWhiteSpace(line)) continue;

                CheckScriptLineForBePatterns(line, historyPath, "ConsoleHost_history.txt", ctx);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private void CheckScriptLineForBePatterns(
        string line, string filePath, string fileName, ScanContext ctx)
    {
        foreach (var (keywords, description, risk) in ScriptPatterns)
        {
            bool allMatch = true;
            foreach (var kw in keywords)
            {
                if (!line.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    allMatch = false;
                    break;
                }
            }
            if (!allMatch) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"BattlEye-Bypass-Befehl im Skript: {description}",
                Risk     = risk,
                Location = filePath,
                FileName = fileName,
                Reason   = $"Ein Skript oder Verlauf enthält den Befehl: '{description}'. " +
                           "Dieser Befehl zielt darauf ab den BattlEye-Dienst oder " +
                           "Kerneltreiber zu stoppen, zu löschen oder zu deaktivieren. " +
                           "Dies ist ein direkter Versuch den BattlEye-Schutz zu umgehen.",
                Detail   = $"Datei: {filePath} | Zeile: {line[..Math.Min(300, line.Length)]}"
            });
            return; // One finding per line
        }
    }

    // --------------------------------------------------------------------------
    // Scan .bat, .cmd, .ps1 files in common user directories for the same patterns
    // --------------------------------------------------------------------------

    private async Task ScanScriptFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var scriptDirs = new[]
        {
            Desktop,
            Downloads,
            Documents,
        };
        var scriptExtensions = new[] { "*.bat", "*.cmd", "*.ps1" };

        foreach (var dir in scriptDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            foreach (var ext in scriptExtensions)
            {
                ct.ThrowIfCancellationRequested();
                await ScanScriptFilesInDirAsync(dir, ext, ctx, ct);
            }
        }
    }

    private async Task ScanScriptFilesInDirAsync(
        string dir, string pattern, ScanContext ctx, CancellationToken ct)
    {
        List<string> files;
        try
        {
            files = Directory.EnumerateFiles(dir, pattern, SearchOption.TopDirectoryOnly).ToList();
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            try
            {
                string content;
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();

                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var rawLine in lines)
                {
                    ct.ThrowIfCancellationRequested();
                    var line = rawLine.Trim();
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    CheckScriptLineForBePatterns(line, file, Path.GetFileName(file), ctx);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // --------------------------------------------------------------------------
    // 9. BYOVD vulnerable driver files
    // --------------------------------------------------------------------------

    private async Task ScanByovdDriverFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            foreach (var dir in SuspiciousSearchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                ScanDirForByovdDrivers(dir, ctx, ct);
            }
        }, ct);
    }

    private void ScanDirForByovdDrivers(string dir, ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*.sys", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                CheckByovdDriverFile(file, fileName, ctx);
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        catch { }

        // One level of subdirectories
        try
        {
            foreach (var subDir in Directory.EnumerateDirectories(dir))
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(subDir, "*.sys", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        CheckByovdDriverFile(file, fileName, ctx);
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        catch { }
    }

    private void CheckByovdDriverFile(string filePath, string fileName, ScanContext ctx)
    {
        foreach (var (driverFileName, description) in ByovdDrivers)
        {
            if (!string.Equals(fileName, driverFileName, StringComparison.OrdinalIgnoreCase)) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"BYOVD-Treiber in verdächtigem Pfad gefunden: {fileName}",
                Risk     = RiskLevel.Critical,
                Location = filePath,
                FileName = fileName,
                Reason   = $"Der bekannte anfällige Treiber '{fileName}' wurde in einem " +
                           "verdächtigen Verzeichnis gefunden. {description}. " +
                           "BYOVD-Angriffe (Bring Your Own Vulnerable Driver) nutzen solche " +
                           "Treiber um Kernelschutz-Mechanismen wie BattlEye zu umgehen.",
                Detail   = $"Treiber: {fileName} | Beschreibung: {description} | Pfad: {filePath}"
            });
            return;
        }
    }

    // --------------------------------------------------------------------------
    // 9b. BYOVD driver registry service check
    // --------------------------------------------------------------------------

    private async Task CheckByovdDriverRegistryServicesAsync(ScanContext ctx, CancellationToken ct)
    {
        var system32DriversPath = Path.Combine(SystemRoot, @"System32\drivers");

        await Task.Run(() =>
        {
            foreach (var (driverFileName, description) in ByovdDrivers)
            {
                ct.ThrowIfCancellationRequested();
                // Strip the .sys extension to get the service name
                var svcName = Path.GetFileNameWithoutExtension(driverFileName);
                CheckByovdServiceRegistry(svcName, driverFileName, description, system32DriversPath, ctx);
            }
        }, ct);
    }

    private void CheckByovdServiceRegistry(
        string svcName, string driverFileName, string description,
        string system32DriversPath, ScanContext ctx)
    {
        var keyPath = $@"SYSTEM\CurrentControlSet\Services\{svcName}";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            var imagePathRaw = key.GetValue("ImagePath");
            var imagePath = imagePathRaw?.ToString() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(imagePath)) return;

            // Normalize path
            var normalized = imagePath.Trim().Trim('"');
            if (normalized.StartsWith(@"\??\", StringComparison.Ordinal))
                normalized = normalized[4..];
            if (normalized.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                normalized = Path.Combine(SystemRoot, normalized[@"\SystemRoot\".Length..]);

            // Flag if the registered BYOVD driver is OUTSIDE System32\drivers
            bool insideSystem32;
            try
            {
                insideSystem32 = Path.GetFullPath(normalized)
                    .StartsWith(Path.GetFullPath(system32DriversPath), StringComparison.OrdinalIgnoreCase);
            }
            catch { insideSystem32 = false; }

            if (!insideSystem32)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"BYOVD-Treiber außerhalb System32\\drivers registriert: {driverFileName}",
                    Risk     = RiskLevel.Critical,
                    Location = $@"HKLM\{keyPath}",
                    FileName = driverFileName,
                    Reason   = $"Der bekannte anfällige Treiber '{driverFileName}' ist als Windows-Dienst " +
                               $"registriert, aber der ImagePath zeigt NICHT in System32\\drivers. " +
                               $"{description}. " +
                               "Ein außerhalb des System-Treiberordners registrierter BYOVD-Treiber " +
                               "ist ein starkes Indiz für einen aktiven Kernel-Bypass-Versuch.",
                    Detail   = $"ImagePath: {imagePath} | Erwartet unter: {system32DriversPath}"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // --------------------------------------------------------------------------
    // 10. Network-level BE evasion — HOSTS file check
    // --------------------------------------------------------------------------

    private async Task CheckHostsFileAsync(ScanContext ctx, CancellationToken ct)
    {
        var hostsPath = Path.Combine(SystemRoot, @"System32\drivers\etc\hosts");

        if (!File.Exists(hostsPath)) return;

        ctx.IncrementFiles();

        try
        {
            string content;
            using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();

            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var rawLine in lines)
            {
                ct.ThrowIfCancellationRequested();
                var line = rawLine.Trim();
                // Skip comments and blank lines
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;

                foreach (var domain in BeDomains)
                {
                    if (!line.Contains(domain, StringComparison.OrdinalIgnoreCase)) continue;

                    // Check if redirected to localhost or null route
                    bool isBlocked =
                        line.StartsWith("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
                        line.StartsWith("127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                        line.StartsWith("::1", StringComparison.OrdinalIgnoreCase);

                    if (!isBlocked) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"BattlEye-Domain in HOSTS-Datei blockiert: {domain}",
                        Risk     = RiskLevel.High,
                        Location = hostsPath,
                        FileName = "hosts",
                        Reason   = $"Die BattlEye-Domain '{domain}' wird in der Windows-HOSTS-Datei " +
                                   "auf eine lokale Adresse umgeleitet. Dies blockiert die Netzwerk-" +
                                   "kommunikation von BattlEye mit seinen Servern. Bypass-Tools " +
                                   "nutzen diese Technik um BattlEye-Bans-Meldungen und Update-" +
                                   "Verbindungen zu verhindern.",
                        Detail   = $"HOSTS-Eintrag: '{line}' | Domain: {domain}"
                    });
                    break; // One finding per domain per line
                }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // --------------------------------------------------------------------------
    // 10b. DNS cache registry configuration check
    // --------------------------------------------------------------------------

    private async Task CheckDnsCacheRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var keyPath = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                if (key is null) return;
                ctx.IncrementRegistryKeys();

                var serverPriorityList = key.GetValue("ServerPriorityList");
                if (serverPriorityList is not null)
                {
                    var val = serverPriorityList.ToString() ?? string.Empty;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Ungewöhnliche DNS-ServerPriorityList konfiguriert",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{keyPath}",
                        Reason   = "In der DNS-Cache-Konfiguration wurde ein ServerPriorityList-Wert " +
                                   "gefunden. Bypass-Tools können benutzerdefinierte DNS-Server konfigurieren " +
                                   "um BattlEye-Domainabfragen abzufangen oder umzuleiten.",
                        Detail   = $"ServerPriorityList: {val}"
                    });
                }

                var dnsQueryIpMatching = key.GetValue("DnsQueryIpMatching");
                if (dnsQueryIpMatching is not null)
                {
                    var val = dnsQueryIpMatching.ToString() ?? string.Empty;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Ungewöhnliche DnsQueryIpMatching-Konfiguration gefunden",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{keyPath}",
                        Reason   = "Der Registry-Wert DnsQueryIpMatching im DNS-Cache-Schlüssel wurde " +
                                   "modifiziert. Diese Einstellung kann zur Umgehung von BattlEye " +
                                   "DNS-Validierung missbraucht werden.",
                        Detail   = $"DnsQueryIpMatching: {val}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }, ct);
    }

    // --------------------------------------------------------------------------
    // 11. Wireshark/packet capture running during BE sessions
    // --------------------------------------------------------------------------

    private async Task ScanPcapFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var pcapDirs = new[]
            {
                Desktop,
                Downloads,
                Documents,
                TempDir,
            };

            foreach (var dir in pcapDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.pcap",
                        SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Paketerfassungsdatei gefunden: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = "Eine .pcap-Paketerfassungsdatei wurde in einem Benutzerverzeichnis " +
                                       "gefunden. Das Aufzeichnen von Netzwerkpaketen während Gaming-Sitzungen " +
                                       "kann zur Analyse des BattlEye-Netzwerkprotokolls und zur Entwicklung " +
                                       "von Bypass-Methoden verwendet werden.",
                            Detail   = $"Datei: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
                catch { }

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.pcapng",
                        SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Paketerfassungsdatei (pcapng) gefunden: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = "Eine .pcapng-Paketerfassungsdatei wurde in einem Benutzerverzeichnis " +
                                       "gefunden. Das Aufzeichnen von Netzwerkpaketen während Gaming-Sitzungen " +
                                       "kann zur Analyse des BattlEye-Netzwerkprotokolls und zur Entwicklung " +
                                       "von Bypass-Methoden verwendet werden.",
                            Detail   = $"Datei: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
                catch { }
            }
        }, ct);
    }

    // --------------------------------------------------------------------------
    // 11b. Packet capture software registry check
    // --------------------------------------------------------------------------

    private async Task CheckPacketCaptureRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check for WinPcap installation
            CheckPcapSoftwareKey(@"SOFTWARE\WinPcap", "WinPcap", ctx);
            ct.ThrowIfCancellationRequested();

            // Check for Npcap installation
            CheckPcapSoftwareKey(@"SOFTWARE\Npcap", "Npcap", ctx);
            ct.ThrowIfCancellationRequested();

            // Check Downloads directory for pcap installer executables
            if (Directory.Exists(Downloads))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "WinPcap_*.exe",
                        SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"WinPcap-Installer in Downloads: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Low,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = "Ein WinPcap-Installer wurde im Downloads-Ordner gefunden. " +
                                       "Paketerfassungssoftware kann zur Analyse des BattlEye-" +
                                       "Netzwerkverkehrs verwendet werden.",
                            Detail   = $"Datei: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
                catch { }

                ct.ThrowIfCancellationRequested();

                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "npcap-*.exe",
                        SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Npcap-Installer in Downloads: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Low,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = "Ein Npcap-Installer wurde im Downloads-Ordner gefunden. " +
                                       "Paketerfassungssoftware kann zur Analyse des BattlEye-" +
                                       "Netzwerkverkehrs verwendet werden.",
                            Detail   = $"Datei: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
                catch { }
            }
        }, ct);
    }

    private void CheckPcapSoftwareKey(string keyPath, string softwareName, ScanContext ctx)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
            if (key is null) return;
            ctx.IncrementRegistryKeys();
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Paketerfassungssoftware installiert: {softwareName}",
                Risk     = RiskLevel.Medium,
                Location = $@"HKLM\{keyPath}",
                Reason   = $"Die Paketerfassungssoftware '{softwareName}' ist auf dem System installiert " +
                           "(Registry-Schlüssel vorhanden). Diese Software kann zur Aufzeichnung und " +
                           "Analyse des BattlEye-Netzwerkdatenverkehrs verwendet werden.",
                Detail   = $"Registry: HKLM\\{keyPath}"
            });
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // --------------------------------------------------------------------------
    // 12. DayZ-specific BEClient.dll replacement check
    // --------------------------------------------------------------------------

    private async Task CheckDayzBeclientDllAsync(ScanContext ctx, CancellationToken ct)
    {
        var dayzBeclientPath =
            @"C:\Program Files (x86)\Steam\steamapps\common\DayZ\BattlEye\BEClient.dll";

        if (!File.Exists(dayzBeclientPath)) return;

        ctx.IncrementFiles();

        try
        {
            var fi = new FileInfo(dayzBeclientPath);

            // Flag if file is suspiciously small — likely a stub replacement
            if (fi.Length < 10000)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "DayZ BEClient.dll verdächtig klein (möglicher Stub)",
                    Risk     = RiskLevel.High,
                    Location = dayzBeclientPath,
                    FileName = "BEClient.dll",
                    Reason   = $"Die DayZ BEClient.dll ist nur {fi.Length} Bytes groß. " +
                               "Eine legitime BEClient.dll ist deutlich größer. " +
                               "Eine so kleine Datei deutet darauf hin, dass die originale DLL " +
                               "durch einen Stub ersetzt wurde um BattlEye zu deaktivieren.",
                    Detail   = $"Dateigröße: {fi.Length} Bytes | Erwartet: > 50.000 Bytes"
                });
            }
            else if (fi.Length < 50000)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "DayZ BEClient.dll kleiner als erwartet",
                    Risk     = RiskLevel.Medium,
                    Location = dayzBeclientPath,
                    FileName = "BEClient.dll",
                    Reason   = $"Die DayZ BEClient.dll ist nur {fi.Length} Bytes groß, was kleiner als " +
                               "die erwartete Mindestgröße von 50 KB ist. Dies könnte auf eine " +
                               "modifizierte oder unvollständige DLL hinweisen.",
                    Detail   = $"Dateigröße: {fi.Length} Bytes"
                });
            }

            // Read file content to check for bypass keywords and MZ header
            string content;
            using var fs = new FileStream(dayzBeclientPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();

            // Check for bypass keywords in the file content
            foreach (var keyword in BeclientBypassKeywords)
            {
                if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"DayZ BEClient.dll enthält Bypass-Keyword: '{keyword}'",
                    Risk     = RiskLevel.Critical,
                    Location = dayzBeclientPath,
                    FileName = "BEClient.dll",
                    Reason   = $"Die DayZ BEClient.dll enthält den String '{keyword}'. " +
                               "Legitime BattlEye-Binärdateien enthalten keine solchen Begriffe. " +
                               "Dies ist ein starkes Indiz dafür, dass die originale DLL durch eine " +
                               "gefälschte Bypass-Implementierung ersetzt wurde.",
                    Detail   = $"Keyword: '{keyword}' | Datei: {dayzBeclientPath} | Größe: {fi.Length} Bytes"
                });
                break; // One finding for content bypass keyword
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // --------------------------------------------------------------------------
    // 13. BattlEye process artifact — BEService.exe running status
    // --------------------------------------------------------------------------

    private async Task CheckBeProcessArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var snapshot = ctx.GetProcessSnapshot();

            // Collect names of all running processes for cross-checks
            var runningProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var proc in snapshot)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();
                try
                {
                    runningProcessNames.Add(proc.ProcessName);
                }
                catch { }
            }

            bool beServiceRunning =
                runningProcessNames.Contains("BEService") ||
                runningProcessNames.Contains("BEService_x64") ||
                runningProcessNames.Contains("BattlEyeService");

            // Check if BattlEye-protected games are running
            var beProtectedGameProcesses = new[]
            {
                "TslGame",         // PUBG
                "DayZ",            // DayZ
                "ArmA3",           // Arma 3
                "RainbowSix",      // Rainbow Six Siege
                "ShooterGame",     // ARK Survival
                "PUBG",            // PUBG (alternative)
                "arma3",
                "r6s",
            };

            bool beGameRunning = false;
            string? runningGameProcess = null;
            foreach (var gameProcName in beProtectedGameProcesses)
            {
                if (!runningProcessNames.Contains(gameProcName)) continue;
                beGameRunning = true;
                runningGameProcess = gameProcName;
                break;
            }

            // If a BE-protected game is running but BEService is not, flag it
            if (beGameRunning && !beServiceRunning)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "BEService läuft nicht während BattlEye-Spiel aktiv ist",
                    Risk     = RiskLevel.Medium,
                    Location = $"Prozess: {runningGameProcess}",
                    FileName = runningGameProcess + ".exe",
                    Reason   = $"Das BattlEye-geschützte Spiel '{runningGameProcess}' läuft, aber " +
                               "BEService.exe ist nicht als aktiver Prozess sichtbar. " +
                               "Dies kann bedeuten, dass BattlEye deaktiviert, gestoppt oder " +
                               "durch einen Bypass-Mechanismus umgangen wird.",
                    Detail   = $"Aktiver Spielprozess: {runningGameProcess} | BEService aktiv: Nein"
                });
            }
        }, ct);
    }

    // --------------------------------------------------------------------------
    // 14. Timing-based injection marker files
    // --------------------------------------------------------------------------

    private async Task CheckInjectionMarkerFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        // Directories to search for injection marker files
        var markerDirs = new[]
        {
            Desktop,
            Downloads,
            AppDataRoaming,
            AppDataLocal,
        };

        await Task.Run(() =>
        {
            foreach (var dir in markerDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                ScanDirForInjectionMarkers(dir, ctx, ct);
            }
        }, ct);

        // Separately scan .ini and .cfg files for injection-timing keywords
        await ScanInjectionConfigFilesAsync(ctx, ct);
    }

    private void ScanDirForInjectionMarkers(string dir, ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                foreach (var markerName in InjectionMarkerFileNames)
                {
                    if (!string.Equals(fileName, markerName, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Injection-Timing-Marker gefunden: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Die Datei '{fileName}' ist ein bekannter Injection-Timing-Marker. " +
                                   "Cheat-Loader verwenden solche Dateien um den Injektionszeitpunkt zu " +
                                   "koordinieren — der Cheat wartet auf diese Datei bevor er sich in ein " +
                                   "BattlEye-geschütztes Spiel injiziert, um die Erkennung durch " +
                                   "BattlEye zu vermeiden.",
                        Detail   = $"Datei: {file} | Verzeichnis: {dir}"
                    });
                    break;
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        catch { }
    }

    private async Task ScanInjectionConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configDirs = new[]
        {
            Desktop,
            Downloads,
            AppDataRoaming,
            AppDataLocal,
        };
        var configExtensions = new[] { "*.ini", "*.cfg" };

        foreach (var dir in configDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            foreach (var ext in configExtensions)
            {
                ct.ThrowIfCancellationRequested();
                await ScanConfigFilesInDirAsync(dir, ext, ctx, ct);
            }
        }
    }

    private async Task ScanConfigFilesInDirAsync(
        string dir, string pattern, ScanContext ctx, CancellationToken ct)
    {
        List<string> files;
        try
        {
            files = Directory.EnumerateFiles(dir, pattern, SearchOption.TopDirectoryOnly).ToList();
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            try
            {
                string content;
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();

                foreach (var keyword in InjectionConfigKeywords)
                {
                    if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Injection-Timing-Config-Keyword in Datei: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Die Konfigurationsdatei '{Path.GetFileName(file)}' enthält das " +
                                   $"Keyword '{keyword}'. Cheat-Loader nutzen solche Konfigurationsdateien " +
                                   "um den optimalen Zeitpunkt für die Injektion nach der BattlEye-" +
                                   "Initialisierung zu bestimmen.",
                        Detail   = $"Keyword: '{keyword}' | Datei: {file}"
                    });
                    break; // One finding per file (first matching keyword)
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }
}
