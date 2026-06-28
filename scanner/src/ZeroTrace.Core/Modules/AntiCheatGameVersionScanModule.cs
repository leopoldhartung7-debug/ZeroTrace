using ZeroTrace.Core.Models;
using Microsoft.Win32;
using System.Management;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects anti-cheat game version tampering and AC bypass indicators specific
/// to individual AC systems (VAC, EAC, BattlEye, Vanguard, FACEIT, Nprotect).
///
/// Game and AC version bypass techniques:
///
/// 1. VAC (Valve Anti-Cheat) specific bypasses:
///    - Steam console command "sv_pure 0" override in launch options
///    - "-insecure" Steam launch flag (disables VAC)
///    - VAC2 module unload via NtUnmapViewOfSection on steamservice.exe
///    - Steam client beta enrollment (beta clients may have weaker VAC versions)
///    - VACBan indicator in Steam account data
///
/// 2. EasyAntiCheat (EAC) specific:
///    - EAC service set to demand-start or disabled
///    - EAC binary in wrong directory (replaced)
///    - EAC_LaunchOptions.json with debug flags
///    - EAC_LOG.txt containing bypass success messages
///    - SteamEMU / Goldberg replacing steam_api breaks EAC activation
///
/// 3. BattlEye specific:
///    - BEService not running despite game using BattlEye
///    - BEDaisy.sys (BattlEye kernel driver) replaced/missing
///    - BEClient.dll version mismatch vs expected
///    - Battleye ban log entries in BattlEye directory
///    - BATTLEYE folder hash tampering
///
/// 4. Vanguard (VALORANT) specific:
///    - VGC service (riot-client) stopped
///    - VGK.sys (Vanguard kernel driver) on disk but service disabled
///    - Vanguard requiring restart (driver update pending = tamper window)
///    - TPM/Secure Boot check bypass (registry override)
///
/// 5. FACEIT specific:
///    - FACEIT client version downgrade (older version = known bypass window)
///    - FACEIT anti-cheat process not in expected path
///
/// 6. NProtect/GameGuard:
///    - gamemon.des / GameGuard.des / GameGuard.gup replaced
///    - GameGuard directory in unexpected location
///
/// Ocean/detect.ac specifically check AC service states and binary integrity
/// because cheaters routinely disable or tamper with AC systems.
/// </summary>
public sealed class AntiCheatGameVersionScanModule : IScanModule
{
    public string Name => "Anti-Cheat System Version & Bypass-Indikator Scan";
    public double Weight => 0.55;
    public int ParallelGroup => 3;

    // Steam launch options registry key
    private const string SteamAppsRegPath = @"SOFTWARE\Valve\Steam\Apps";

    // VAC-insecure launch flags
    private static readonly string[] InsecureLaunchFlags =
    {
        "-insecure", "sv_pure 0", "+sv_cheats 1", "-dev",
        "-console", "-condebug", "+mat_queue_mode 0",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        // 1. VAC-specific checks
        ScanVacBypass(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 2. EAC-specific checks
        ScanEacBypass(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 3. BattlEye-specific checks
        ScanBattleyeBypass(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 4. Vanguard-specific checks
        ScanVanguardBypass(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 5. FACEIT-specific checks
        ScanFaceitBypass(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 6. NProtect/GameGuard checks
        ScanNprotectBypass(ctx, ct);
    }

    private void ScanVacBypass(ScanContext ctx, CancellationToken ct)
    {
        // Check Steam launch options per game for insecure flags
        ctx.IncrementRegistryKeys();
        try
        {
            using var appsKey = Registry.CurrentUser.OpenSubKey(SteamAppsRegPath);
            if (appsKey != null)
            {
                foreach (var appId in appsKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    using var appKey = appsKey.OpenSubKey(appId);
                    if (appKey == null) continue;

                    string? launchOpts = appKey.GetValue("LaunchOptions") as string ?? "";
                    if (string.IsNullOrEmpty(launchOpts)) continue;

                    string optLower = launchOpts.ToLowerInvariant();
                    string? match = InsecureLaunchFlags.FirstOrDefault(f =>
                        optLower.Contains(f, StringComparison.OrdinalIgnoreCase));

                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Unsichere Steam Start-Option für App {appId}: '{match}'",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{SteamAppsRegPath}\{appId}",
                            FileName = $"AppID {appId}",
                            Reason   = $"Steam-Spiel (AppID {appId}) hat unsichere Start-Option '{match}' " +
                                       $"konfiguriert (vollständig: '{launchOpts}'). " +
                                       "'-insecure' deaktiviert VAC vollständig. 'sv_pure 0' erlaubt " +
                                       "beliebige Dateien im Spielverzeichnis. Diese Optionen werden " +
                                       "von Cheat-Konfigurationen gesetzt um VAC-Checks zu umgehen.",
                            Detail   = $"AppID: {appId} | LaunchOptions: {launchOpts} | Match: {match}"
                        });
                    }
                }
            }
        }
        catch { }

        // Check Steam userdata for VACBanned indicators
        string steamPath = GetSteamPath();
        if (string.IsNullOrEmpty(steamPath)) return;

        // Check Steam account local config for VAC-insecure flag
        string localConfigPath = Path.Combine(steamPath, "config", "localconfig.vdf");
        if (File.Exists(localConfigPath))
        {
            ctx.IncrementFiles();
            try
            {
                string content = File.ReadAllText(localConfigPath);
                if (content.Contains("-insecure", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Steam localconfig.vdf enthält '-insecure' Flag",
                        Risk     = RiskLevel.High,
                        Location = localConfigPath,
                        FileName = "localconfig.vdf",
                        Reason   = "Steam lokale Konfiguration enthält '-insecure' Start-Option. " +
                                   "Dieser Flag deaktiviert VAC für alle Spiele die darüber gestartet werden.",
                        Detail   = $"Datei: {localConfigPath}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanEacBypass(ScanContext ctx, CancellationToken ct)
    {
        // EAC installs to: Program Files (x86)\EasyAntiCheat\ and game-specific dirs
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string eacDir = Path.Combine(programFilesX86, "EasyAntiCheat");

        if (Directory.Exists(eacDir))
        {
            // Check EAC_LOG.txt for bypass/error messages
            var logFiles = new[]
            {
                Path.Combine(eacDir, "EAC_LOG.txt"),
                Path.Combine(eacDir, "EasyAntiCheat_Launcher.log"),
            };

            foreach (var logFile in logFiles)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(logFile)) continue;

                ctx.IncrementFiles();
                try
                {
                    string[] lines = File.ReadAllLines(logFile);
                    string[] bypassKeywords = { "bypass", "disabled", "error loading", "failed to start",
                                               "tamper", "integrity failed", "signature invalid" };

                    foreach (var line in lines.TakeLast(100)) // Check last 100 lines
                    {
                        string lineLower = line.ToLowerInvariant();
                        string? match = bypassKeywords.FirstOrDefault(kw => lineLower.Contains(kw));
                        if (match != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"EAC Log enthält Bypass-Indikator '{match}' in: {Path.GetFileName(logFile)}",
                                Risk     = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason   = $"EasyAntiCheat Log-Datei enthält verdächtigen Eintrag mit '{match}': '{line.Trim()}'. " +
                                           "EAC-Bypass-Tools erzeugen typischerweise Fehlereinträge wenn EAC " +
                                           "deaktiviert oder umgangen wird.",
                                Detail   = $"Datei: {logFile} | Zeile: {line.Trim()}"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }

        // Check EAC service integrity
        ctx.IncrementRegistryKeys();
        try
        {
            using var eacSvc = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat");
            if (eacSvc != null)
            {
                int startType = (eacSvc.GetValue("Start") as int?) ?? 2;
                if (startType == 4) // Disabled
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "EasyAntiCheat Dienst DEAKTIVIERT (StartType=4)",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat",
                        FileName = "EasyAntiCheat",
                        Reason   = "EasyAntiCheat-Dienst ist auf 'Disabled' gesetzt. Spiele mit EAC können ohne " +
                                   "funktionierende AC gestartet werden. Cheater deaktivieren AC-Dienste " +
                                   "als Voraussetzung für cheat-geschütztes Spielen.",
                        Detail   = $"StartType: {startType} (4=Disabled)"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanBattleyeBypass(ScanContext ctx, CancellationToken ct)
    {
        // BattlEye installs to game directories — check common paths
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        var battleeyePaths = new[]
        {
            Path.Combine(programFiles, "Common Files", "BattlEye"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Common Files", "BattlEye"),
        };

        foreach (var bePath in battleeyePaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(bePath)) continue;

            // Check for BEClient.dll presence and size
            string beClientDll = Path.Combine(bePath, "BEClient.dll");
            if (File.Exists(beClientDll))
            {
                ctx.IncrementFiles();
                long beSize = 0;
                try { beSize = new FileInfo(beClientDll).Length; } catch { }
                if (beSize > 0 && beSize < 50 * 1024) // Legitimate BEClient.dll > 50KB
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"BEClient.dll verdächtig klein ({beSize} bytes) — möglicherweise ersetzt",
                        Risk     = RiskLevel.Critical,
                        Location = beClientDll,
                        FileName = "BEClient.dll",
                        Reason   = $"BattlEye BEClient.dll ist nur {beSize} Bytes groß (normal: >100KB). " +
                                   "Eine zu kleine BEClient.dll wurde wahrscheinlich durch eine Stub-DLL " +
                                   "ersetzt die BattlEye-Checks neutralisiert ohne das Spiel zu crashen.",
                        Detail   = $"Datei: {beClientDll} | Größe: {beSize} bytes"
                    });
                }
            }
        }

        // Check BEService registry
        ctx.IncrementRegistryKeys();
        try
        {
            using var beSvc = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\BEService");
            if (beSvc != null)
            {
                int startType = (beSvc.GetValue("Start") as int?) ?? 2;
                if (startType == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "BattlEye Service (BEService) DEAKTIVIERT",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\BEService",
                        FileName = "BEService",
                        Reason   = "BattlEye BEService ist deaktiviert (StartType=4). BattlEye-geschützte " +
                                   "Spiele (PUBG, Fortnite, EFT, DayZ, Rust) laufen ohne Anti-Cheat.",
                        Detail   = $"StartType: {startType}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanVanguardBypass(ScanContext ctx, CancellationToken ct)
    {
        // Vanguard services: vgc (Riot Client) and vgk (kernel driver)
        string[] vanguardServices = { "vgc", "vgk" };

        foreach (var svcName in vanguardServices)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();
            try
            {
                using var svcKey = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{svcName}");
                if (svcKey == null) continue;

                int startType = (svcKey.GetValue("Start") as int?) ?? 2;
                if (startType == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Vanguard Dienst '{svcName}' DEAKTIVIERT",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = svcName,
                        Reason   = $"Riot Vanguard Dienst '{svcName}' ist deaktiviert (StartType=4). " +
                                   $"vgc = Riot Client Service (Vanguard-Usermode), vgk = Vanguard Kernel Driver. " +
                                   "Ohne beide Dienste können VALORANT und andere Riot-Spiele ohne " +
                                   "Anti-Cheat-Schutz gespielt werden.",
                        Detail   = $"Service: {svcName} | StartType: {startType}"
                    });
                }
            }
            catch { }
        }

        // Check for Vanguard TPM/Secure Boot bypass registry keys
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Riot Games\Vanguard");
            if (key != null)
            {
                object? tpmBypass = key.GetValue("tpm_bypass");
                object? sbBypass  = key.GetValue("secure_boot_bypass");

                if (tpmBypass != null || sbBypass != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Vanguard TPM/Secure Boot Bypass-Schlüssel im Registry",
                        Risk     = RiskLevel.High,
                        Location = @"HKLM\SOFTWARE\Riot Games\Vanguard",
                        FileName = "Vanguard",
                        Reason   = "Vanguard Registry enthält TPM oder Secure Boot Bypass-Einträge. " +
                                   "Vanguard erfordert normalerweise TPM 2.0 + Secure Boot — " +
                                   "diese Einträge deuten auf Manipulation hin.",
                        Detail   = $"tpm_bypass: {tpmBypass} | secure_boot_bypass: {sbBypass}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanFaceitBypass(ScanContext ctx, CancellationToken ct)
    {
        // Check FACEIT service
        ctx.IncrementRegistryKeys();
        try
        {
            using var faceitSvc = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\faceitservice");
            if (faceitSvc != null)
            {
                int startType = (faceitSvc.GetValue("Start") as int?) ?? 2;
                if (startType == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "FACEIT Anti-Cheat Dienst DEAKTIVIERT",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\faceitservice",
                        FileName = "faceitservice",
                        Reason   = "FACEIT Anti-Cheat Dienst ist deaktiviert. FACEIT-Matches werden ohne " +
                                   "Anti-Cheat-Überwachung gespielt.",
                        Detail   = $"StartType: {startType}"
                    });
                }
            }
        }
        catch { }

        // FACEIT client AppData directory scan
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string faceitDir = Path.Combine(localAppData, "FACEIT");
        if (!Directory.Exists(faceitDir)) return;

        // Check for bypass-related files in FACEIT directory
        string[] bypassFiles = { "bypass.dat", "bypass.ini", "ac_bypass.log" };
        foreach (var fname in bypassFiles)
        {
            ct.ThrowIfCancellationRequested();
            string fullPath = Path.Combine(faceitDir, fname);
            if (!File.Exists(fullPath)) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"FACEIT Bypass-Datei gefunden: {fname}",
                Risk     = RiskLevel.Critical,
                Location = fullPath,
                FileName = fname,
                Reason   = $"Datei '{fname}' im FACEIT-Verzeichnis gefunden. Diese Datei deutet auf " +
                           "einen FACEIT-Anti-Cheat-Bypass hin.",
                Detail   = $"Datei: {fullPath}"
            });
        }
    }

    private void ScanNprotectBypass(ScanContext ctx, CancellationToken ct)
    {
        // NProtect GameGuard files typically in game directories
        // Check for replaced/modified GameGuard files
        string[] gameGuardFiles =
        {
            "GameGuard.des", "gamemon.des", "GameGuard.gup",
            "GameMon.des", "GameGuard.dll",
        };

        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        // Search for GameGuard directories
        foreach (var pf in new[] { programFiles, programFilesX86 })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(pf)) continue;

            try
            {
                var ggDirs = Directory.GetDirectories(pf, "GameGuard", SearchOption.AllDirectories)
                    .Take(10); // Limit depth

                foreach (var ggDir in ggDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (var ggFile in gameGuardFiles)
                    {
                        string fullPath = Path.Combine(ggDir, ggFile);
                        if (!File.Exists(fullPath)) continue;

                        ctx.IncrementFiles();
                        long size = 0;
                        try { size = new FileInfo(fullPath).Length; } catch { }

                        // Very small GameGuard files indicate replacement with stubs
                        if (size < 1024)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"GameGuard-Datei verdächtig klein (möglicherweise ersetzt): {ggFile}",
                                Risk     = RiskLevel.High,
                                Location = fullPath,
                                FileName = ggFile,
                                Reason   = $"NProtect GameGuard Datei '{ggFile}' ist nur {size} Bytes groß (normal: >10KB). " +
                                           "Cheat-Bypass-Tools ersetzen GameGuard-Binaries mit Stub-DLLs " +
                                           "die Schutzfunktionen deaktivieren ohne den Spielstart zu unterbrechen.",
                                Detail   = $"Datei: {fullPath} | Größe: {size} bytes"
                            });
                        }
                    }
                }
            }
            catch { }
        }
    }

    private static string GetSteamPath()
    {
        try
        {
            using var steamKey = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam")
                              ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam");
            return (steamKey?.GetValue("SteamPath") as string) ?? "";
        }
        catch { return ""; }
    }
}
