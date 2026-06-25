using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class SteamApiHookScanModule : IScanModule
{
    public string Name => "Steam-API-Hook";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    private const string PrefetchDir = @"C:\Windows\Prefetch";

    private const long SteamClientMinBytes = 2L * 1024 * 1024;
    private const long SteamClientMaxBytes = 12L * 1024 * 1024;
    private const long GameOverlayMinBytes = 500L * 1024;
    private const long GameOverlayMaxBytes = 15L * 1024 * 1024;
    private const long SteamApiStubThresholdBytes = 50L * 1024;

    private static readonly string[] SteamEmuFileNames =
    {
        "Goldberg_Lan_Steam_Emu.ini", "steam_interfaces.txt",
        "CreamAPI.ini", "cream_api.ini",
        "SmartSteamEmu.ini", "SmartSteamEmu64.ini",
        "SteamEmu.dll", "SteamEmu64.dll",
    };

    private static readonly string[] SteamEmuDirNames =
    {
        "steam_settings", "ALI213", "CODEX",
    };

    private static readonly string[] SteamIdSpooferExeNames =
    {
        "steamid_changer.exe", "steam_id_spoofer.exe", "steamidspoofer.exe",
        "steam_account_switcher.exe", "steam_cracker.exe", "steam_bypass.exe",
        "steamblocker.exe", "steamvac_bypass.exe", "vacbypass_steam.exe",
    };

    private static readonly string[] SteamIdSpooferDllNames =
    {
        "steamid_spoofer.dll", "steam_bypass.dll",
    };

    private static readonly string[] SteamIdSpooferRegistryPaths =
    {
        @"Software\SteamIDSpoofer",
        @"Software\SteamBypass",
    };

    private static readonly string[] SteamIdConfigFiles =
    {
        "steamid.cfg", "steam_bypass.cfg", "steam_account.json",
    };

    private static readonly string[] CheatGameIds =
    {
        "730", "271590", "1174180",
    };

    private static readonly HashSet<string> SuspectLaunchOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "-novac", "-nosteam", "-nocheat", "-novaccheck",
        "-allowdeveloper", "sv_cheats 1",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var steamInstallPath = ResolveSteamInstallPath();

        ctx.Report(0.0, Name, "Pruefe steamclient.dll / steam_api.dll...");
        await CheckSteamCoreDllSizesAsync(ctx, steamInstallPath, ct).ConfigureAwait(false);

        ctx.Report(0.15, Name, "Suche Steam-Emulator-Artefakte...");
        await ScanForSteamEmulatorArtifactsAsync(ctx, steamInstallPath, ct).ConfigureAwait(false);

        ctx.Report(0.30, Name, "Pruefe GameOverlayRenderer...");
        await CheckGameOverlayRendererAsync(ctx, steamInstallPath, ct).ConfigureAwait(false);

        ctx.Report(0.42, Name, "Suche SteamID-Spoofer...");
        await ScanForSteamIdSpooferArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.55, Name, "Pruefe Steam-Startoptionen...");
        CheckSuspiciousLaunchOptions(ctx, ct);

        ctx.Report(0.67, Name, "Pruefe Steam Achievement Manager...");
        CheckSteamAchievementManager(ctx, ct);

        ctx.Report(0.78, Name, "Pruefe Steam-Workshop-Inhalt...");
        await ScanWorkshopContentAsync(ctx, steamInstallPath, ct).ConfigureAwait(false);

        ctx.Report(0.88, Name, "Pruefe Prefetch-Artefakte...");
        ScanPrefetchForSteamCheats(ctx, ct);

        ctx.Report(1.0, Name, "Steam-API-Hook-Analyse abgeschlossen");
    }

    // -------------------------------------------------------------------------
    // Resolve Steam install path
    // -------------------------------------------------------------------------

    private static string? ResolveSteamInstallPath()
    {
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                    foreach (var subPath in new[] { @"SOFTWARE\Valve\Steam", @"SOFTWARE\WOW6432Node\Valve\Steam" })
                    {
                        using var k = baseKey.OpenSubKey(subPath, writable: false);
                        var val = k?.GetValue("InstallPath") as string;
                        if (!string.IsNullOrEmpty(val) && Directory.Exists(val)) return val;
                    }
                }
                catch { }
            }
        }

        var defaultPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam");
        return Directory.Exists(defaultPath) ? defaultPath : null;
    }

    // -------------------------------------------------------------------------
    // steamclient.dll / steam_api.dll size checks
    // -------------------------------------------------------------------------

    private static async Task CheckSteamCoreDllSizesAsync(ScanContext ctx, string? steamPath, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(steamPath)) return;

        var steamCoreDlls = new[]
        {
            ("steamclient.dll",   SteamClientMinBytes, SteamClientMaxBytes),
            ("steamclient64.dll", SteamClientMinBytes, SteamClientMaxBytes),
            ("steam_api.dll",     1L,                  SteamClientMaxBytes),
            ("steam_api64.dll",   1L,                  SteamClientMaxBytes),
        };

        foreach (var (dllName, minBytes, maxBytes) in steamCoreDlls)
        {
            if (ct.IsCancellationRequested) return;
            var dllPath = Path.Combine(steamPath, dllName);
            if (!File.Exists(dllPath)) continue;

            ctx.IncrementFiles();
            long size = 0;
            try { size = new FileInfo(dllPath).Length; } catch { continue; }

            if (size >= minBytes && size <= maxBytes) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Steam-API-Hook",
                Title = $"Auffaellige Groesse: {dllName}",
                Risk = RiskLevel.High,
                Location = dllPath,
                FileName = dllName,
                Reason = $"'{dllName}' hat eine unerwartete Dateigrösse von {size / 1024} KB " +
                         $"(erwartet: {minBytes / 1024} KB bis {maxBytes / 1024 / 1024} MB). " +
                         "Cheat-Software ersetzt oder patcht Steam-DLLs, was die Dateigrösse stark veraendert.",
                Detail = $"Ist: {size} Bytes | Erwartet: {minBytes}–{maxBytes} Bytes"
            });
        }

        await ScanGameDirsForSteamApiStubsAsync(ctx, ct).ConfigureAwait(false);
    }

    private static async Task ScanGameDirsForSteamApiStubsAsync(ScanContext ctx, CancellationToken ct)
    {
        var steamAppsRoots = GetSteamAppsRoots();
        foreach (var steamApps in steamAppsRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(steamApps)) continue;

            string[] gameDirs;
            try { gameDirs = Directory.GetDirectories(steamApps, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var gameDir in gameDirs)
            {
                if (ct.IsCancellationRequested) return;
                foreach (var apiName in new[] { "steam_api.dll", "steam_api64.dll" })
                {
                    var apiPath = Path.Combine(gameDir, apiName);
                    if (!File.Exists(apiPath)) continue;
                    ctx.IncrementFiles();

                    long size = 0;
                    try { size = new FileInfo(apiPath).Length; } catch { continue; }

                    if (size >= SteamApiStubThresholdBytes) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "Steam-API-Hook",
                        Title = $"Steam-API-Stub im Spielverzeichnis: {Path.GetFileName(gameDir)}",
                        Risk = RiskLevel.Critical,
                        Location = apiPath,
                        FileName = apiName,
                        Reason = $"'{apiName}' im Spielverzeichnis '{Path.GetFileName(gameDir)}' ist nur {size} Bytes gross " +
                                 $"(Schwellwert: {SteamApiStubThresholdBytes} Bytes). " +
                                 "Goldberg, CreamAPI und SmartSteamEmu ersetzen steam_api.dll durch winzige Stubs, " +
                                 "um Steam-DRM und VAC zu umgehen.",
                        Detail = $"Pfad: {apiPath} | Groesse: {size} Bytes"
                    });
                }
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // Steam emulator artifacts
    // -------------------------------------------------------------------------

    private static async Task ScanForSteamEmulatorArtifactsAsync(ScanContext ctx, string? steamPath, CancellationToken ct)
    {
        var gameDirs = GetAllGameDirectoriesFromRegistry();
        var steamAppsRoots = GetSteamAppsRoots();

        foreach (var steamApps in steamAppsRoots)
        {
            if (!Directory.Exists(steamApps)) continue;
            string[] dirs;
            try { dirs = Directory.GetDirectories(steamApps); }
            catch { continue; }
            gameDirs.AddRange(dirs);
        }

        foreach (var gameDir in gameDirs.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(gameDir)) continue;

            await CheckDirectoryForSteamEmuFilesAsync(ctx, gameDir, ct).ConfigureAwait(false);
        }
    }

    private static async Task CheckDirectoryForSteamEmuFilesAsync(
        ScanContext ctx, string gameDir, CancellationToken ct)
    {
        string[] files;
        try { files = Directory.GetFiles(gameDir, "*.*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(file);

            if (!SteamEmuFileNames.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase))) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Steam-API-Hook",
                Title = $"Steam-Emulator-Datei: {fn}",
                Risk = RiskLevel.Critical,
                Location = file,
                FileName = fn,
                Reason = $"Steam-Emulator-Konfigurationsdatei '{fn}' in Spielverzeichnis gefunden. " +
                         "Goldberg, CreamAPI und SmartSteamEmu sind Steam-Emulatoren, die das Spielen ohne " +
                         "legitime Steam-Kopie ermoeglichen und VAC umgehen.",
                Detail = $"Pfad: {file} | Spielverzeichnis: {Path.GetFileName(gameDir)}"
            });
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(gameDir, "*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            var dirName = Path.GetFileName(sub);

            if (!SteamEmuDirNames.Any(d => dirName.Equals(d, StringComparison.OrdinalIgnoreCase))) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Steam-API-Hook",
                Title = $"Steam-Emulator-Verzeichnis: {dirName}",
                Risk = RiskLevel.Critical,
                Location = sub,
                Reason = $"Steam-Emulator-Verzeichnis '{dirName}' in Spielordner '{Path.GetFileName(gameDir)}' gefunden. " +
                         "Dies ist ein typisches Verzeichnis von Steam-Emulator-Software (Goldberg/CreamAPI/CODEX).",
                Detail = $"Pfad: {sub}"
            });
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // GameOverlayRenderer checks
    // -------------------------------------------------------------------------

    private static async Task CheckGameOverlayRendererAsync(ScanContext ctx, string? steamPath, CancellationToken ct)
    {
        if (!string.IsNullOrEmpty(steamPath))
        {
            foreach (var dllName in new[] { "GameOverlayRenderer.dll", "GameOverlayRenderer64.dll" })
            {
                if (ct.IsCancellationRequested) return;
                var dllPath = Path.Combine(steamPath, dllName);
                if (!File.Exists(dllPath)) continue;
                ctx.IncrementFiles();

                long size = 0;
                try { size = new FileInfo(dllPath).Length; } catch { continue; }

                if (size < GameOverlayMinBytes || size > GameOverlayMaxBytes)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Steam-API-Hook",
                        Title = $"GameOverlayRenderer Groessenanomalie: {dllName}",
                        Risk = RiskLevel.High,
                        Location = dllPath,
                        FileName = dllName,
                        Reason = $"'{dllName}' hat eine unerwartete Groesse von {size / 1024} KB " +
                                 $"(erwartet: {GameOverlayMinBytes / 1024} KB bis {GameOverlayMaxBytes / 1024 / 1024} MB). " +
                                 "Cheat-Software hookt GameOverlayRenderer.dll, um ESP-Rendering einzuschleusen, " +
                                 "was die Dateigrösse veraendert.",
                        Detail = $"Ist: {size} Bytes"
                    });
                }
            }
        }

        await ScanGameDirsForGameOverlayProxiesAsync(ctx, steamPath, ct).ConfigureAwait(false);
    }

    private static async Task ScanGameDirsForGameOverlayProxiesAsync(
        ScanContext ctx, string? steamPath, CancellationToken ct)
    {
        var gameDirs = GetAllGameDirectoriesFromRegistry();
        foreach (var steamApps in GetSteamAppsRoots())
        {
            if (!Directory.Exists(steamApps)) continue;
            string[] dirs;
            try { dirs = Directory.GetDirectories(steamApps); }
            catch { continue; }
            gameDirs.AddRange(dirs);
        }

        foreach (var gameDir in gameDirs.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(gameDir)) continue;

            foreach (var overlayDll in new[] { "GameOverlayRenderer.dll", "GameOverlayRenderer64.dll" })
            {
                var dllPath = Path.Combine(gameDir, overlayDll);
                if (!File.Exists(dllPath)) continue;
                ctx.IncrementFiles();

                bool isInSteamRoot = !string.IsNullOrEmpty(steamPath) &&
                    dllPath.StartsWith(steamPath, StringComparison.OrdinalIgnoreCase);
                if (isInSteamRoot) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Steam-API-Hook",
                    Title = $"GameOverlayRenderer ausserhalb Steam-Verzeichnis: {overlayDll}",
                    Risk = RiskLevel.High,
                    Location = dllPath,
                    FileName = overlayDll,
                    Reason = $"'{overlayDll}' ausserhalb des Steam-Hauptverzeichnisses gefunden. " +
                             "Diese DLL gehoert nur in den Steam-Root-Ordner. " +
                             "Cheats kopieren sie in Spielverzeichnisse als Proxy-DLL fuer Hook-Einschleusung.",
                    Detail = $"Pfad: {dllPath}"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // SteamID spoofer artifacts
    // -------------------------------------------------------------------------

    private static async Task ScanForSteamIdSpooferArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            await ScanDirectoryForSpooferFilesAsync(ctx, dir, ct).ConfigureAwait(false);
        }

        foreach (var regPath in SteamIdSpooferRegistryPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                ctx.IncrementRegistryKeys();
                if (k is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Steam-API-Hook",
                    Title = $"SteamID-Spoofer-Registry: {Path.GetFileName(regPath)}",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\" + regPath,
                    Reason = $"Registry-Schluessel '{regPath}' eines bekannten SteamID-Spoofers gefunden. " +
                             "SteamID-Spoofer aendern die Steam-Account-ID, um gebannte Accounts zu umgehen.",
                    Detail = $"Registry: HKCU\\{regPath}"
                });
            }
            catch { }
        }

        CheckSteamIdConfigFiles(ctx, ct);

        var processes = ctx.GetProcessSnapshot();
        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementProcesses();
            var procName = proc.ProcessName;
            if (!SteamIdSpooferExeNames.Any(e =>
                procName.Equals(Path.GetFileNameWithoutExtension(e), StringComparison.OrdinalIgnoreCase))) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Steam-API-Hook",
                Title = $"SteamID-Spoofer laeuft: {procName}",
                Risk = RiskLevel.High,
                Location = $"PID {proc.Id}",
                FileName = procName,
                Reason = $"SteamID-Spoofer-Prozess '{procName}' laeuft aktiv. " +
                         "Ein aktiver Spoofer manipuliert die Steam-Account-ID in Echtzeit.",
                Detail = $"PID: {proc.Id} | Name: {procName}"
            });
        }
    }

    private static async Task ScanDirectoryForSpooferFilesAsync(
        ScanContext ctx, string directory, CancellationToken ct)
    {
        if (!Directory.Exists(directory)) return;

        string[] files;
        try { files = Directory.GetFiles(directory, "*.*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(file);

            bool isSpooferExe = SteamIdSpooferExeNames.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
            bool isSpooferDll = SteamIdSpooferDllNames.Any(d => fn.Equals(d, StringComparison.OrdinalIgnoreCase));
            if (!isSpooferExe && !isSpooferDll) continue;

            long size = 0;
            try { size = new FileInfo(file).Length; } catch { }

            ctx.AddFinding(new Finding
            {
                Module = "Steam-API-Hook",
                Title = $"SteamID-Spoofer-Datei: {fn}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = fn,
                Reason = $"Datei '{fn}' entspricht bekanntem SteamID-Spoofer-Werkzeug. " +
                         "Diese Tools aendern die Steam-Account-ID um VAC-Bans zu umgehen.",
                Detail = $"Pfad: {file} | Groesse: {size} Bytes"
            });
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private static void CheckSteamIdConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in GetUserScanDirectories())
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var configName in SteamIdConfigFiles)
            {
                var configPath = Path.Combine(dir, configName);
                if (!File.Exists(configPath)) continue;
                ctx.IncrementFiles();

                ctx.AddFinding(new Finding
                {
                    Module = "Steam-API-Hook",
                    Title = $"SteamID-Konfigurationsdatei: {configName}",
                    Risk = RiskLevel.Medium,
                    Location = configPath,
                    FileName = configName,
                    Reason = $"SteamID-Spoofer-Konfigurationsdatei '{configName}' gefunden. " +
                             "Diese Datei wird von SteamID-Spoofer-Tools erstellt, um die Account-ID-Substitution zu speichern.",
                    Detail = $"Pfad: {configPath}"
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // Steam launch option checks
    // -------------------------------------------------------------------------

    private static void CheckSuspiciousLaunchOptions(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var appsKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Valve\Steam\Apps", writable: false);
            ctx.IncrementRegistryKeys();
            if (appsKey is null) return;

            foreach (var appIdStr in appsKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var appKey = appsKey.OpenSubKey(appIdStr, writable: false);
                    if (appKey is null) continue;

                    ctx.IncrementRegistryKeys();
                    var launchOptions = appKey.GetValue("LaunchOptions") as string;
                    if (string.IsNullOrWhiteSpace(launchOptions)) continue;

                    var matchedOptions = SuspectLaunchOptions
                        .Where(opt => launchOptions.Contains(opt, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    bool isKnownCheatGame = CheatGameIds.Contains(appIdStr);

                    if (matchedOptions.Count == 0 && !isKnownCheatGame) continue;
                    if (matchedOptions.Count == 0) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "Steam-API-Hook",
                        Title = $"Verdaechtige Startoptionen: Spiel {appIdStr}",
                        Risk = isKnownCheatGame ? RiskLevel.High : RiskLevel.Medium,
                        Location = @"HKCU\SOFTWARE\Valve\Steam\Apps\" + appIdStr,
                        Reason = $"Verdaechtige Startoptionen '{string.Join(", ", matchedOptions)}' fuer Spiel {appIdStr} gefunden. " +
                                 "Anti-Cheat-Umgehungs-Startoptionen wie '-novac' deaktivieren VAC-Pruefungen.",
                        Detail = $"AppID: {appIdStr} | LaunchOptions: {launchOptions}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // Steam Achievement Manager (SAM) artifacts
    // -------------------------------------------------------------------------

    private static void CheckSteamAchievementManager(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Redruber\SAM", writable: false);
            ctx.IncrementRegistryKeys();
            if (k is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Steam-API-Hook",
                    Title = "Steam Achievement Manager (SAM) Registry",
                    Risk = RiskLevel.Medium,
                    Location = @"HKCU\Software\Redruber\SAM",
                    Reason = "Steam Achievement Manager (SAM) Registry-Eintrag gefunden. " +
                             "SAM manipuliert Steam-Achievements und Stats und ist ein Indikator fuer unerlaubte Spielmanipulation.",
                    Detail = "HKCU\\Software\\Redruber\\SAM"
                });
            }
        }
        catch { }

        var samPaths = new[]
        {
            @"C:\Program Files\SAM",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SAM"),
        };

        foreach (var samPath in samPaths)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(samPath)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Steam-API-Hook",
                Title = "Steam Achievement Manager Verzeichnis",
                Risk = RiskLevel.Medium,
                Location = samPath,
                Reason = $"Steam Achievement Manager Verzeichnis in '{samPath}' gefunden. " +
                         "SAM manipuliert Steam-Achievements und -Statistiken.",
                Detail = $"Pfad: {samPath}"
            });
        }

        var processes = ctx.GetProcessSnapshot();
        var samProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "sam", "steam_achievement_manager",
        };

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementProcesses();
            if (!samProcessNames.Contains(proc.ProcessName)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Steam-API-Hook",
                Title = $"SAM-Prozess laeuft: {proc.ProcessName}",
                Risk = RiskLevel.Medium,
                Location = $"PID {proc.Id}",
                FileName = proc.ProcessName,
                Reason = $"Steam Achievement Manager Prozess '{proc.ProcessName}' laeuft aktiv. " +
                         "SAM kann Steam-Statistiken und Achievements manipulieren.",
                Detail = $"PID: {proc.Id}"
            });
        }

        ScanPrefetchForSam(ctx, ct);
    }

    private static void ScanPrefetchForSam(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(PrefetchDir)) return;
        string[] pfFiles;
        try { pfFiles = Directory.GetFiles(PrefetchDir, "*.pf"); }
        catch { return; }

        var samPrefixes = new[] { "SAM", "STEAMACHIEVEMENTMANAGER" };

        foreach (var pfFile in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var pfName = Path.GetFileNameWithoutExtension(pfFile);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            if (!samPrefixes.Any(p => exeName.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;

            DateTime? lastWrite = null;
            try { lastWrite = File.GetLastWriteTime(pfFile); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = "Steam-API-Hook",
                Title = $"SAM in Prefetch: {exeName}",
                Risk = RiskLevel.Medium,
                Location = pfFile,
                FileName = exeName + ".exe",
                Reason = $"Prefetch-Eintrag '{exeName}' weist auf Ausfuehrung von Steam Achievement Manager hin.",
                Detail = lastWrite.HasValue
                    ? $"Prefetch zuletzt aktualisiert: {lastWrite.Value:yyyy-MM-dd HH:mm:ss}"
                    : null
            });
        }
    }

    // -------------------------------------------------------------------------
    // Workshop content scan
    // -------------------------------------------------------------------------

    private static async Task ScanWorkshopContentAsync(ScanContext ctx, string? steamPath, CancellationToken ct)
    {
        var steamAppsRoots = GetSteamAppsRoots();
        if (!string.IsNullOrEmpty(steamPath))
        {
            var steamAppsInSteam = Path.Combine(steamPath, "steamapps");
            if (Directory.Exists(steamAppsInSteam) && !steamAppsRoots.Contains(steamAppsInSteam, StringComparer.OrdinalIgnoreCase))
                steamAppsRoots.Add(steamAppsInSteam);
        }

        var cheatGameIdSet = new HashSet<string>(CheatGameIds, StringComparer.OrdinalIgnoreCase);

        foreach (var steamApps in steamAppsRoots)
        {
            if (ct.IsCancellationRequested) return;
            var workshopRoot = Path.Combine(steamApps, "workshop", "content");
            if (!Directory.Exists(workshopRoot)) continue;

            string[] gameDirs;
            try { gameDirs = Directory.GetDirectories(workshopRoot); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var gameDir in gameDirs)
            {
                if (ct.IsCancellationRequested) return;
                var gameId = Path.GetFileName(gameDir);
                if (!cheatGameIdSet.Contains(gameId)) continue;

                await ScanWorkshopGameDirAsync(ctx, gameDir, gameId, ct).ConfigureAwait(false);
            }
        }
    }

    private static async Task ScanWorkshopGameDirAsync(
        ScanContext ctx, string gameDir, string gameId, CancellationToken ct)
    {
        var cheatKeywordsInFileName = new[]
        {
            "inject", "cheat", "hack", "bypass", "aimbot", "esp", "wallhack", "godmode",
        };

        string[] workshopItems;
        try { workshopItems = Directory.GetDirectories(gameDir); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var itemDir in workshopItems)
        {
            if (ct.IsCancellationRequested) return;

            string[] itemFiles;
            try { itemFiles = Directory.GetFiles(itemDir, "*.*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in itemFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file).ToLowerInvariant();
                var ext = Path.GetExtension(fn).ToLowerInvariant();

                bool isDll = ext == ".dll";
                bool hasSuspectName = cheatKeywordsInFileName.Any(k =>
                    fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!isDll && !hasSuspectName) continue;

                long size = 0;
                try { size = new FileInfo(file).Length; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = "Steam-API-Hook",
                    Title = isDll
                        ? $"DLL in Workshop-Inhalt (Spiel {gameId})"
                        : $"Verdaechtiger Workshop-Dateiname (Spiel {gameId})",
                    Risk = isDll ? RiskLevel.High : RiskLevel.Medium,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = isDll
                        ? $"DLL-Datei '{Path.GetFileName(file)}' in Workshop-Inhalt fuer Spiel {gameId} gefunden. " +
                          "Legitime Workshop-Inhalte fuer CS2 oder GTAV enthalten keine DLL-Dateien."
                        : $"Workshop-Datei '{Path.GetFileName(file)}' enthaelt Cheat-Schluesselwort fuer Spiel {gameId}.",
                    Detail = $"Workshop-Verzeichnis: {Path.GetFileName(itemDir)} | Groesse: {size} Bytes"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // Prefetch scan for Steam cheats
    // -------------------------------------------------------------------------

    private static void ScanPrefetchForSteamCheats(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(PrefetchDir)) return;
        string[] files;
        try { files = Directory.GetFiles(PrefetchDir, "*.pf"); }
        catch { return; }

        var steamCheatPrefixes = new (string[] prefixes, string title, RiskLevel risk, string reason)[]
        {
            (new[] { "SAM", "STEAMACHIEVEMENTMANAGER" },
                "SAM in Prefetch", RiskLevel.Medium,
                "Steam Achievement Manager ermoeglicht die Manipulation von Steam-Statistiken."),
            (new[] { "STEAMID", "STEAMBYPASS", "VACBYPASS_STEAM", "STEAM_CRACKER" },
                "SteamID-Spoofer in Prefetch", RiskLevel.High,
                "SteamID-Spoofer-Tool wurde auf diesem System ausgefuehrt."),
            (new[] { "CREAMAPI", "GOLDBERG", "SMARTSTEAMEMU" },
                "Steam-Emulator in Prefetch", RiskLevel.Critical,
                "Steam-Emulator wurde auf diesem System ausgefuehrt, was auf DRM-Umgehung hinweist."),
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

            foreach (var (prefixes, title, risk, reason) in steamCheatPrefixes)
            {
                if (!prefixes.Any(p => exeName.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;

                DateTime? lastWrite = null;
                try { lastWrite = File.GetLastWriteTime(file); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = "Steam-API-Hook",
                    Title = title,
                    Risk = risk,
                    Location = file,
                    FileName = exeName + ".exe",
                    Reason = $"Prefetch-Datei '{pfName}.pf' weist auf Ausfuehrung von '{exeName}' hin. " + reason,
                    Detail = lastWrite.HasValue
                        ? $"Prefetch zuletzt aktualisiert: {lastWrite.Value:yyyy-MM-dd HH:mm:ss}"
                        : null
                });
                break;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static List<string> GetAllGameDirectoriesFromRegistry()
    {
        var result = new List<string>();
        try
        {
            using var appsKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Valve\Steam\Apps", writable: false);
            if (appsKey is null) return result;

            foreach (var appId in appsKey.GetSubKeyNames())
            {
                try
                {
                    using var appKey = appsKey.OpenSubKey(appId, writable: false);
                    var installDir = appKey?.GetValue("InstallDir") as string;
                    if (!string.IsNullOrEmpty(installDir) && Directory.Exists(installDir))
                        result.Add(installDir);
                }
                catch { }
            }
        }
        catch { }
        return result;
    }

    private static List<string> GetSteamAppsRoots()
    {
        var result = new List<string>();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            foreach (var subPath in new[] { @"SOFTWARE\Valve\Steam", @"SOFTWARE\WOW6432Node\Valve\Steam" })
            {
                using var k = baseKey.OpenSubKey(subPath, writable: false);
                var installPath = k?.GetValue("InstallPath") as string;
                if (string.IsNullOrEmpty(installPath)) continue;

                var steamApps = Path.Combine(installPath, "steamapps");
                if (Directory.Exists(steamApps)) result.Add(steamApps);
            }
        }
        catch { }

        var defaults = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam", "steamapps"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),    "Steam", "steamapps"),
        };
        foreach (var d in defaults)
        {
            if (Directory.Exists(d) && !result.Contains(d, StringComparer.OrdinalIgnoreCase))
                result.Add(d);
        }

        return result;
    }

    private static IEnumerable<string> GetUserScanDirectories()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        return new[]
        {
            Path.Combine(profile, "Desktop"),
            Path.Combine(profile, "Downloads"),
            appData,
            localAppData,
        }.Where(Directory.Exists);
    }
}
