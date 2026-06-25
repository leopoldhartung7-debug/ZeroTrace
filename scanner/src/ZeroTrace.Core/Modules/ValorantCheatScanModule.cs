using System.Diagnostics;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ValorantCheatScanModule : IScanModule
{
    public string Name => "Valorant-Cheat";
    public double Weight => 0.7;
    public int ParallelGroup => 4;

    private static readonly string[] KnownCheatExeNames =
    {
        "val_cheat.exe", "valorant_cheat.exe", "valorant_hack.exe", "valorant_aimbot.exe",
        "valorant_esp.exe", "valorant_wallhack.exe", "valorant_bypass.exe",
        "vanguard_bypass.exe", "vanguard_killer.exe", "vanguard_spoofer.exe",
        "val_loader.exe", "valorant_loader.exe", "valo_cheat.exe", "valo_hack.exe",
        "valo_esp.exe", "radiant_cheat.exe", "radiant_hack.exe", "recoil_valorant.exe",
        "val_triggerbot.exe", "val_aimassist.exe", "valorant_unlocker.exe",
        "crosshair_change.exe"
    };

    private static readonly string[] KnownCheatDllNames =
    {
        "val_cheat.dll", "valorant_cheat.dll", "valorant_hook.dll",
        "vanguard_bypass.dll", "val_esp.dll", "valorant_aimbot.dll"
    };

    private static readonly string[] VanguardBypassToolNames =
    {
        "vanguard_bypass.exe", "vgc_killer.exe", "vgk_bypass.exe", "vanguard_patch.exe"
    };

    private static readonly string[] VanguardBypassPrefetchPatterns =
    {
        "VANGUARD_BYPASS", "VGCKILLER", "VGC_KILLER", "VGK_BYPASS", "VANGUARD_PATCH"
    };

    private static readonly string[] CheatPrefetchPatterns =
    {
        "VALORANT_CHEAT", "VAL_CHEAT", "VANGUARD_BYPASS", "VAL_LOADER",
        "VALORANT_HACK", "VALORANT_AIMBOT", "VALO_CHEAT", "VAL_LOADER",
        "RADIANT_CHEAT", "RECOIL_VALORANT", "VAL_TRIGGERBOT"
    };

    private static readonly string[] VanguardPsHistoryPatterns =
    {
        "sc stop vgc", "sc delete vgc", "net stop vgc",
        "set-service vgc", "disable vgc", "sc stop vgk", "sc delete vgk"
    };

    private static readonly string[] LogCheatKeywords =
    {
        "vanguard", "bypass", "exploit", "inject"
    };

    private static readonly string[] ConfigCheatKeywords =
    {
        "bNovac", "bDisableVanguard", "bNoAntiCheat"
    };

    private static readonly string[] RecoilAhkKeywords =
    {
        "recoil", "spray", "transfer", "aimbot", "triggerbot", "rapidfire"
    };

    private static readonly string[] RecoilPythonKeywords =
    {
        "win32api.mouse_event", "pynput", "pyautogui"
    };

    private static readonly string[] RecoilConfigFileNames =
    {
        "recoil_valorant.cfg", "spray_transfer.cfg",
        "val_recoil.json", "no_recoil_valorant.json"
    };

    private static readonly string[] SuspiciousProcessFlags =
    {
        "--bypass", "--inject", "--novanguard"
    };

    private static readonly string[] KnownCheatProcessNames =
    {
        "val_cheat", "valorant_cheat", "valorant_hack", "valorant_aimbot",
        "valorant_esp", "valorant_wallhack", "valorant_bypass",
        "vanguard_bypass", "vanguard_killer", "vanguard_spoofer",
        "val_loader", "valorant_loader", "valo_cheat", "valo_hack",
        "valo_esp", "radiant_cheat", "radiant_hack", "recoil_valorant",
        "val_triggerbot", "val_aimassist", "valorant_unlocker",
        "crosshair_change", "vgc_killer", "vgk_bypass", "vanguard_patch"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.02, "Valorant-Cheat", "Starte Scan auf Valorant-Cheat-Artefakte");

        await ScanKnownCheatFilesAsync(ctx, ct).ConfigureAwait(false);
        ctx.Report(0.25, "Valorant-Cheat", "Bekannte Cheat-Dateien geprueft");

        ct.ThrowIfCancellationRequested();
        await ScanVanguardBypassArtifactsAsync(ctx, ct).ConfigureAwait(false);
        ctx.Report(0.45, "Valorant-Cheat", "Vanguard-Bypass-Artefakte geprueft");

        ct.ThrowIfCancellationRequested();
        await ScanValorantConfigArtifactsAsync(ctx, ct).ConfigureAwait(false);
        ctx.Report(0.60, "Valorant-Cheat", "Valorant-Konfigurationsartefakte geprueft");

        ct.ThrowIfCancellationRequested();
        await ScanRecoilAimScriptArtifactsAsync(ctx, ct).ConfigureAwait(false);
        ctx.Report(0.75, "Valorant-Cheat", "Recoil/Aim-Skripte geprueft");

        ct.ThrowIfCancellationRequested();
        ScanRunningProcesses(ctx, ct);
        ctx.Report(0.90, "Valorant-Cheat", "Laufende Prozesse geprueft");

        ct.ThrowIfCancellationRequested();
        ScanPrefetchEntries(ctx, ct);
        ctx.Report(1.0, "Valorant-Cheat", "Scan abgeschlossen");
    }

    private async Task ScanKnownCheatFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var temp = Path.GetTempPath();

        var scanDirs = new[]
        {
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            temp,
            Path.Combine(local, "Temp"),
            roaming,
            local,
            Path.Combine(userProfile, "Documents")
        };

        foreach (var dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                foreach (var cheatExe in KnownCheatExeNames)
                {
                    if (!fileName.Equals(cheatExe, StringComparison.OrdinalIgnoreCase)) continue;

                    long fileSize = 0;
                    try { fileSize = new FileInfo(file).Length; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekannte Valorant-Cheat-EXE gefunden: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Die Datei '{fileName}' entspricht dem Namen einer bekannten " +
                                 "Valorant-Cheat-Anwendung. Diese Datei sollte nicht auf dem System " +
                                 "eines ehrlichen Spielers vorhanden sein.",
                        Detail = $"Verzeichnis: {dir} | Dateigröße: {fileSize} Bytes"
                    });
                    break;
                }

                foreach (var cheatDll in KnownCheatDllNames)
                {
                    if (!fileName.Equals(cheatDll, StringComparison.OrdinalIgnoreCase)) continue;

                    long fileSize = 0;
                    try { fileSize = new FileInfo(file).Length; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekannte Valorant-Cheat-DLL gefunden: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Die Datei '{fileName}' entspricht dem Namen einer bekannten " +
                                 "Valorant-Cheat-Bibliothek. DLLs mit diesen Namen werden " +
                                 "typischerweise in den Valorant-Prozess injiziert.",
                        Detail = $"Verzeichnis: {dir} | Dateigröße: {fileSize} Bytes"
                    });
                    break;
                }
            }

            await Task.Yield();
        }

        await ScanSubdirsForCheatFilesAsync(ctx, ct, scanDirs).ConfigureAwait(false);
    }

    private async Task ScanSubdirsForCheatFilesAsync(ScanContext ctx, CancellationToken ct, string[] topDirs)
    {
        foreach (var topDir in topDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(topDir)) continue;

            string[] subdirs;
            try
            {
                subdirs = Directory.GetDirectories(topDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();

                string[] files;
                try
                {
                    files = Directory.GetFiles(subdir, "*.*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);

                    foreach (var cheatExe in KnownCheatExeNames)
                    {
                        if (!fileName.Equals(cheatExe, StringComparison.OrdinalIgnoreCase)) continue;

                        long fileSize = 0;
                        try { fileSize = new FileInfo(file).Length; } catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Bekannte Valorant-Cheat-EXE in Unterverzeichnis: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Die Datei '{fileName}' in '{subdir}' entspricht dem Namen einer bekannten " +
                                     "Valorant-Cheat-Anwendung. Cheats werden oft in Unterordner versteckt.",
                            Detail = $"Dateigröße: {fileSize} Bytes"
                        });
                        break;
                    }

                    foreach (var cheatDll in KnownCheatDllNames)
                    {
                        if (!fileName.Equals(cheatDll, StringComparison.OrdinalIgnoreCase)) continue;

                        long fileSize = 0;
                        try { fileSize = new FileInfo(file).Length; } catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Bekannte Valorant-Cheat-DLL in Unterverzeichnis: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Die Datei '{fileName}' in '{subdir}' entspricht dem Namen einer bekannten " +
                                     "Valorant-Cheat-Bibliothek. Injizierbare DLLs werden oft in Unterordner abgelegt.",
                            Detail = $"Dateigröße: {fileSize} Bytes"
                        });
                        break;
                    }
                }

                await Task.Yield();
            }
        }
    }

    private async Task ScanVanguardBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        CheckVanguardServiceRegistryKeys(ctx);
        ct.ThrowIfCancellationRequested();

        CheckVanguardInstallIntegrity(ctx);
        ct.ThrowIfCancellationRequested();

        await ScanPowerShellHistoryForVanguardCommandsAsync(ctx, ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        await ScanForVanguardBypassToolsAsync(ctx, ct).ConfigureAwait(false);
    }

    private void CheckVanguardServiceRegistryKeys(ScanContext ctx)
    {
        CheckVgcServiceKey(ctx);
        CheckVgkServiceKey(ctx);
    }

    private void CheckVgcServiceKey(ScanContext ctx)
    {
        const string vgcKeyPath = @"SYSTEM\CurrentControlSet\Services\vgc";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(vgcKeyPath, writable: false);
            ctx.IncrementRegistryKeys();

            if (key is null) return;

            var startValue = key.GetValue("Start");
            ctx.IncrementRegistryKeys();

            if (startValue is int startInt && startInt == 4)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Vanguard-Dienst (vgc) deaktiviert",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\" + vgcKeyPath,
                    Reason = "Der Vanguard-Kundendienst (vgc) hat den Startwert 4 (deaktiviert) in der Registry. " +
                             "Das Deaktivieren von vgc ist eine gängige Methode, um Vanguard zu umgehen und " +
                             "Cheats in Valorant auszuführen.",
                    Detail = $"Registry-Wert: HKLM\\{vgcKeyPath}\\Start = {startInt} (Disabled)"
                });
            }

            var imagePath = key.GetValue("ImagePath")?.ToString();
            ctx.IncrementRegistryKeys();

            if (!string.IsNullOrEmpty(imagePath) &&
                !imagePath.Contains("vgc", StringComparison.OrdinalIgnoreCase) &&
                !imagePath.Contains("Riot", StringComparison.OrdinalIgnoreCase) &&
                !imagePath.Contains("Vanguard", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Vanguard-Dienst (vgc) ImagePath möglicherweise manipuliert",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\" + vgcKeyPath,
                    Reason = "Der ImagePath des Vanguard-Dienstes (vgc) verweist nicht auf den erwarteten " +
                             "Vanguard/Riot-Pfad. Dies kann auf eine Manipulation des Diensteintrags hinweisen.",
                    Detail = $"ImagePath: {imagePath}"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }
    }

    private void CheckVgkServiceKey(ScanContext ctx)
    {
        const string vgkKeyPath = @"SYSTEM\CurrentControlSet\Services\vgk";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(vgkKeyPath, writable: false);
            ctx.IncrementRegistryKeys();

            if (key is null) return;

            var startValue = key.GetValue("Start");
            ctx.IncrementRegistryKeys();

            if (startValue is int startInt && startInt == 4)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Vanguard-Kerneltreiber (vgk) deaktiviert",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\" + vgkKeyPath,
                    Reason = "Der Vanguard-Kerneltreiber (vgk.sys) hat den Startwert 4 (deaktiviert) in der Registry. " +
                             "Das Deaktivieren des Kerntreibers ist ein starkes Indiz für Vanguard-Bypass-Aktivitäten.",
                    Detail = $"Registry-Wert: HKLM\\{vgkKeyPath}\\Start = {startInt} (Disabled)"
                });
            }

            var imagePath = key.GetValue("ImagePath")?.ToString();
            ctx.IncrementRegistryKeys();

            if (!string.IsNullOrEmpty(imagePath))
            {
                bool pathSuspicious =
                    !imagePath.Contains("vgk", StringComparison.OrdinalIgnoreCase) &&
                    !imagePath.Contains("Riot", StringComparison.OrdinalIgnoreCase) &&
                    !imagePath.Contains("Vanguard", StringComparison.OrdinalIgnoreCase) &&
                    !imagePath.Contains("Program Files", StringComparison.OrdinalIgnoreCase);

                if (pathSuspicious)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Vanguard-Treiber (vgk) ImagePath möglicherweise ersetzt",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\" + vgkKeyPath,
                        Reason = "Der ImagePath des Vanguard-Kerneltreibers (vgk) zeigt nicht auf den erwarteten " +
                                 "Installationspfad von Riot Vanguard. Ein ersetzter Kerneltreibereintrag ist " +
                                 "ein starkes Indiz für einen Vanguard-Bypass.",
                        Detail = $"ImagePath: {imagePath}"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }
    }

    private void CheckVanguardInstallIntegrity(ScanContext ctx)
    {
        const string vanguardDir = @"C:\Program Files\Riot Vanguard";
        if (!Directory.Exists(vanguardDir)) return;

        CheckVgkSysFile(ctx, vanguardDir);
        CheckVgcExeFile(ctx, vanguardDir);
    }

    private void CheckVgkSysFile(ScanContext ctx, string vanguardDir)
    {
        var vgkPath = Path.Combine(vanguardDir, "vgk.sys");
        if (!File.Exists(vgkPath)) return;

        ctx.IncrementFiles();

        long fileSize = 0;
        try { fileSize = new FileInfo(vgkPath).Length; } catch { return; }

        const long minNormalSize = 100 * 1024;
        const long maxNormalSize = 2 * 1024 * 1024;

        if (fileSize < 10 * 1024)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "vgk.sys ungewöhnlich klein — möglicherweise ersetzt",
                Risk = RiskLevel.High,
                Location = vgkPath,
                FileName = "vgk.sys",
                Reason = $"Die Vanguard-Kerneltreiberdatei vgk.sys ist nur {fileSize} Bytes groß. " +
                         $"Legitime vgk.sys-Dateien sind typischerweise {minNormalSize / 1024}–{maxNormalSize / (1024 * 1024)} MB groß. " +
                         "Eine extrem kleine Datei deutet darauf hin, dass der Treiber durch eine Stub-Datei " +
                         "ersetzt wurde, um Vanguard zu deaktivieren.",
                Detail = $"Dateigröße: {fileSize} Bytes | Erwarteter Bereich: {minNormalSize / 1024} KB – {maxNormalSize / (1024 * 1024)} MB"
            });
        }
        else if (fileSize > maxNormalSize)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "vgk.sys ungewöhnlich groß — möglicherweise manipuliert",
                Risk = RiskLevel.High,
                Location = vgkPath,
                FileName = "vgk.sys",
                Reason = $"Die Vanguard-Kerneltreiberdatei vgk.sys ist {fileSize / (1024 * 1024.0):F1} MB groß. " +
                         $"Legitime vgk.sys-Dateien sind typischerweise unter {maxNormalSize / (1024 * 1024)} MB. " +
                         "Eine übermäßig große Datei könnte auf eine mit bösartigem Code gepatschte Datei hinweisen.",
                Detail = $"Dateigröße: {fileSize} Bytes | Erwartete Maximalgröße: {maxNormalSize / (1024 * 1024)} MB"
            });
        }
    }

    private void CheckVgcExeFile(ScanContext ctx, string vanguardDir)
    {
        var vgcPath = Path.Combine(vanguardDir, "vgc.exe");
        ctx.IncrementFiles();

        if (!File.Exists(vgcPath))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "vgc.exe in Riot-Vanguard-Verzeichnis fehlt",
                Risk = RiskLevel.High,
                Location = vanguardDir,
                FileName = "vgc.exe",
                Reason = "Das Riot-Vanguard-Verzeichnis existiert, aber vgc.exe fehlt. " +
                         "Dies kann bedeuten, dass der Vanguard-Dienst-Starter entfernt wurde, " +
                         "um die Anti-Cheat-Funktionalität zu deaktivieren.",
                Detail = $"Erwarteter Pfad: {vgcPath}"
            });
            return;
        }

        long fileSize = 0;
        try { fileSize = new FileInfo(vgcPath).Length; } catch { }

        if (fileSize < 50 * 1024)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "vgc.exe möglicherweise durch Stub-Datei ersetzt",
                Risk = RiskLevel.High,
                Location = vgcPath,
                FileName = "vgc.exe",
                Reason = $"Die Vanguard-Dienst-Datei vgc.exe ist nur {fileSize} Bytes groß — " +
                         "deutlich kleiner als erwartet. Dies kann darauf hinweisen, dass die " +
                         "originale Datei durch eine leere oder deaktivierte Stub-Datei ersetzt wurde.",
                Detail = $"Dateigröße: {fileSize} Bytes"
            });
        }
    }

    private async Task ScanPowerShellHistoryForVanguardCommandsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var historyPath = Path.Combine(roaming,
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (!File.Exists(historyPath)) return;

        string content;
        try
        {
            using var fs = new FileStream(historyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        ctx.IncrementFiles();

        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var line in lines)
        {
            ct.ThrowIfCancellationRequested();
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;

            foreach (var pattern in VanguardPsHistoryPatterns)
            {
                if (!trimmed.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;
                if (!seen.Add(pattern)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"PowerShell-Verlauf: Vanguard-Deaktivierungsbefehl",
                    Risk = RiskLevel.Medium,
                    Location = historyPath,
                    Reason = $"Der PowerShell-Befehlsverlauf enthält den Befehl '{pattern}', " +
                             "der zum Stoppen oder Deaktivieren des Vanguard-Anti-Cheat-Dienstes " +
                             "verwendet wird. Dies ist ein gängiger erster Schritt bei Valorant-Cheat-Setups.",
                    Detail = $"Gefundene Zeile: {TruncateString(trimmed, 200)}"
                });
                break;
            }
        }
    }

    private async Task ScanForVanguardBypassToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var temp = Path.GetTempPath();

        var scanDirs = new[]
        {
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            temp,
            Path.Combine(local, "Temp"),
            roaming,
            local,
            Path.Combine(userProfile, "Documents")
        };

        foreach (var dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            await ScanDirForVanguardBypassToolsAsync(ctx, ct, dir, recursive: false).ConfigureAwait(false);

            string[] subdirs;
            try
            {
                subdirs = Directory.GetDirectories(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                await ScanDirForVanguardBypassToolsAsync(ctx, ct, subdir, recursive: false).ConfigureAwait(false);
            }
        }
    }

    private async Task ScanDirForVanguardBypassToolsAsync(ScanContext ctx, CancellationToken ct, string dir, bool recursive)
    {
        string[] files;
        try
        {
            files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            foreach (var toolName in VanguardBypassToolNames)
            {
                if (!fileName.Equals(toolName, StringComparison.OrdinalIgnoreCase)) continue;

                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Vanguard-Bypass-Tool gefunden: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes Werkzeug zum Umgehen oder " +
                             "Deaktivieren von Riot Vanguard. Das Vorhandensein dieser Datei ist " +
                             "ein starkes Indiz für den Versuch, Vanguard zu deaktivieren und Cheats in Valorant einzusetzen.",
                    Detail = $"Dateigröße: {fileSize} Bytes | Pfad: {dir}"
                });
                break;
            }
        }

        await Task.Yield();
    }

    private async Task ScanValorantConfigArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        await ScanValorantLocalAppDataDirAsync(ctx, ct, local).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        await ScanValorantConfigFilesAsync(ctx, ct, local).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        await ScanRiotGamesLogsAsync(ctx, ct, roaming).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();

        await ScanRiotClientUxRenderLogAsync(ctx, ct, local).ConfigureAwait(false);
    }

    private async Task ScanValorantLocalAppDataDirAsync(ScanContext ctx, CancellationToken ct, string localAppData)
    {
        var valorantDir = Path.Combine(localAppData, "VALORANT");
        if (!Directory.Exists(valorantDir)) return;

        string[] files;
        try
        {
            files = Directory.GetFiles(valorantDir, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }

        var recentModified = new List<string>();

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            try
            {
                var writeTime = File.GetLastWriteTimeUtc(file);
                if ((DateTime.UtcNow - writeTime).TotalDays <= 7)
                    recentModified.Add(file);
            }
            catch (IOException) { }
        }

        if (recentModified.Count > 0 && recentModified.Count <= 3)
        {
            foreach (var f in recentModified.Take(3))
            {
                ct.ThrowIfCancellationRequested();
                DateTime writeTime = default;
                try { writeTime = File.GetLastWriteTimeUtc(f); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Kürzlich geänderte Datei im VALORANT-AppData-Verzeichnis",
                    Risk = RiskLevel.Low,
                    Location = f,
                    FileName = Path.GetFileName(f),
                    Reason = "Eine Datei im lokalen VALORANT-AppData-Verzeichnis wurde in den letzten 7 Tagen geändert. " +
                             "Cheats modifizieren manchmal Valorant-Konfigurationsdateien, um Vorteile zu erlangen.",
                    Detail = writeTime != default ? $"Zuletzt geändert: {writeTime:yyyy-MM-dd HH:mm:ss} UTC" : null
                });
            }
        }

        await Task.Yield();
    }

    private async Task ScanValorantConfigFilesAsync(ScanContext ctx, CancellationToken ct, string localAppData)
    {
        var configDir = Path.Combine(localAppData, "Riot Games", "VALORANT", "Saved", "Config");
        if (!Directory.Exists(configDir)) return;

        string[] configFiles;
        try
        {
            configFiles = Directory.GetFiles(configDir, "*.ini", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var cfgFile in configFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync().ConfigureAwait(false);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var keyword in ConfigCheatKeywords)
            {
                if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdächtiges Cheat-Schlüsselwort in Valorant-Konfiguration: {keyword}",
                    Risk = RiskLevel.High,
                    Location = cfgFile,
                    FileName = Path.GetFileName(cfgFile),
                    Reason = $"Die Valorant-Konfigurationsdatei enthält das Schlüsselwort '{keyword}', " +
                             "das auf eine manipulierte Konfiguration hinweist. Solche Einstellungen " +
                             "können die Anti-Cheat-Schutzmechanismen deaktivieren oder Cheat-Funktionen aktivieren.",
                    Detail = $"Schlüsselwort: {keyword} | Konfigurationsdatei: {Path.GetFileName(cfgFile)}"
                });
                break;
            }
        }
    }

    private async Task ScanRiotGamesLogsAsync(ScanContext ctx, CancellationToken ct, string roamingAppData)
    {
        var riotGamesDir = Path.Combine(roamingAppData, "Riot Games");
        if (!Directory.Exists(riotGamesDir)) return;

        string[] logFiles;
        try
        {
            logFiles = Directory.GetFiles(riotGamesDir, "*.log", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var logFile in logFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            long fileSize = 0;
            try { fileSize = new FileInfo(logFile).Length; } catch { continue; }

            const long maxReadBytes = 256 * 1024;
            string content;

            try
            {
                using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

                if (fileSize > maxReadBytes)
                    fs.Seek(-maxReadBytes, SeekOrigin.End);

                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync().ConfigureAwait(false);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var keyword in LogCheatKeywords)
            {
                if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                var context = ExtractContextAroundKeyword(content, keyword, 120);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdächtiges Schlüsselwort in Riot-Games-Log: {keyword}",
                    Risk = RiskLevel.Medium,
                    Location = logFile,
                    FileName = Path.GetFileName(logFile),
                    Reason = $"Die Riot-Games-Protokolldatei enthält das Schlüsselwort '{keyword}'. " +
                             "Cheat-Injektoren und Bypass-Tools hinterlassen oft Spuren in den " +
                             "Anwendungsprotokollen von Riot Games.",
                    Detail = string.IsNullOrEmpty(context) ? null : $"Kontext: {context}"
                });
                break;
            }
        }
    }

    private async Task ScanRiotClientUxRenderLogAsync(ScanContext ctx, CancellationToken ct, string localAppData)
    {
        var logPath = Path.Combine(localAppData, "Riot Games", "Riot Client", "UxRender.log");
        if (!File.Exists(logPath)) return;

        ctx.IncrementFiles();

        long fileSize = 0;
        try { fileSize = new FileInfo(logPath).Length; } catch { return; }

        const long maxReadBytes = 256 * 1024;
        string content;

        try
        {
            using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fileSize > maxReadBytes)
                fs.Seek(-maxReadBytes, SeekOrigin.End);

            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        var crashPatterns = new[]
        {
            "exception", "crash", "fatal", "access violation", "segfault",
            "injected", "hook detected", "integrity check failed",
            "module verification failed", "tamper"
        };

        foreach (var pattern in crashPatterns)
        {
            ct.ThrowIfCancellationRequested();
            if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

            var context = ExtractContextAroundKeyword(content, pattern, 150);

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Riot-Client-UxRender-Log: Absturzmuster gefunden ({pattern})",
                Risk = RiskLevel.Medium,
                Location = logPath,
                FileName = "UxRender.log",
                Reason = $"Das Riot-Client-UxRender-Protokoll enthält das Muster '{pattern}', " +
                         "das auf Abstürze durch Cheat-Injektion oder Anti-Cheat-Konflikte " +
                         "hinweisen kann. Cheat-Injektoren destabilisieren oft den Client-Renderer.",
                Detail = string.IsNullOrEmpty(context) ? null : $"Kontext: {context}"
            });
            break;
        }

        await Task.Yield();
    }

    private async Task ScanRecoilAimScriptArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var scanDirs = new[]
        {
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Documents")
        };

        foreach (var dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            await ScanDirForRecoilScriptsAsync(ctx, ct, dir).ConfigureAwait(false);
        }
    }

    private async Task ScanDirForRecoilScriptsAsync(ScanContext ctx, CancellationToken ct, string dir)
    {
        await ScanAhkFilesInDirAsync(ctx, ct, dir).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        await ScanPythonFilesInDirAsync(ctx, ct, dir).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        await ScanRecoilConfigFilesInDirAsync(ctx, ct, dir).ConfigureAwait(false);
    }

    private async Task ScanAhkFilesInDirAsync(ScanContext ctx, CancellationToken ct, string dir)
    {
        string[] ahkFiles;
        try
        {
            ahkFiles = Directory.GetFiles(dir, "*.ahk", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var ahkFile in ahkFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(ahkFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync().ConfigureAwait(false);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            bool hasValorant = content.Contains("valorant", StringComparison.OrdinalIgnoreCase);
            if (!hasValorant) continue;

            foreach (var keyword in RecoilAhkKeywords)
            {
                if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Valorant-Recoil/Aim-AHK-Skript: {Path.GetFileName(ahkFile)}",
                    Risk = RiskLevel.Medium,
                    Location = ahkFile,
                    FileName = Path.GetFileName(ahkFile),
                    Reason = $"Das AutoHotkey-Skript '{Path.GetFileName(ahkFile)}' enthält sowohl 'valorant' " +
                             $"als auch '{keyword}'. AHK-Skripte mit diesen Schlüsselwörtern werden " +
                             "häufig für Recoil-Kontrolle, Spray-Transfer oder Triggerbot-Automatisierung " +
                             "in Valorant eingesetzt.",
                    Detail = $"Valorant + '{keyword}' gefunden in: {Path.GetFileName(ahkFile)}"
                });
                break;
            }
        }
    }

    private async Task ScanPythonFilesInDirAsync(ScanContext ctx, CancellationToken ct, string dir)
    {
        string[] pyFiles;
        try
        {
            pyFiles = Directory.GetFiles(dir, "*.py", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var pyFile in pyFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(pyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync().ConfigureAwait(false);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            bool hasValorant = content.Contains("valorant", StringComparison.OrdinalIgnoreCase);
            if (!hasValorant) continue;

            foreach (var keyword in RecoilPythonKeywords)
            {
                if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Valorant-Recoil-Python-Skript: {Path.GetFileName(pyFile)}",
                    Risk = RiskLevel.Medium,
                    Location = pyFile,
                    FileName = Path.GetFileName(pyFile),
                    Reason = $"Das Python-Skript '{Path.GetFileName(pyFile)}' enthält sowohl 'valorant' " +
                             $"als auch '{keyword}'. Python-Skripte mit Mauseingabe-APIs und " +
                             "Valorant-Referenzen werden typischerweise für Recoil-Makros oder " +
                             "Triggerbot-Implementierungen verwendet.",
                    Detail = $"Valorant + '{keyword}' gefunden in: {Path.GetFileName(pyFile)}"
                });
                break;
            }
        }
    }

    private async Task ScanRecoilConfigFilesInDirAsync(ScanContext ctx, CancellationToken ct, string dir)
    {
        string[] allFiles;
        try
        {
            allFiles = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var file in allFiles)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(file);

            foreach (var cfgName in RecoilConfigFileNames)
            {
                if (!fileName.Equals(cfgName, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();

                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                string contentPreview = string.Empty;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    contentPreview = TruncateString(await sr.ReadToEndAsync().ConfigureAwait(false), 300);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Valorant-Recoil-Konfigurationsdatei: {fileName}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Die Datei '{fileName}' ist eine bekannte Konfigurationsdatei für " +
                             "Valorant-Recoil-Steuerungs- oder Spray-Transfer-Skripte. " +
                             "Diese Dateien enthalten typischerweise Einstellungen für automatisierte " +
                             "Rückstoß-Kompensation oder Mausbewegungsmuster.",
                    Detail = fileSize > 0 ? $"Dateigröße: {fileSize} Bytes" : null
                });
                break;
            }
        }

        await Task.Yield();
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        Process[] processes;
        try
        {
            processes = ctx.GetProcessSnapshot();
        }
        catch
        {
            return;
        }

        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            string procName;
            try { procName = proc.ProcessName; }
            catch { continue; }

            if (string.IsNullOrEmpty(procName)) continue;

            foreach (var cheatProcName in KnownCheatProcessNames)
            {
                if (!procName.Equals(cheatProcName, StringComparison.OrdinalIgnoreCase)) continue;

                int pid = 0;
                try { pid = proc.Id; } catch { }

                string? imagePath = null;
                try { imagePath = proc.MainModule?.FileName; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Bekannter Valorant-Cheat-Prozess läuft: {procName}",
                    Risk = RiskLevel.Critical,
                    Location = imagePath ?? procName,
                    FileName = procName + ".exe",
                    Reason = $"Der laufende Prozess '{procName}' (PID {pid}) entspricht dem Namen " +
                             "einer bekannten Valorant-Cheat-Anwendung. Das gleichzeitige Ausführen " +
                             "eines Cheat-Prozesses neben Valorant ist ein eindeutiges Cheat-Indiz.",
                    Detail = $"PID: {pid}" + (imagePath != null ? $" | Pfad: {imagePath}" : "")
                });
                break;
            }

            CheckValorantProcessCommandLine(ctx, proc, procName);
        }
    }

    private void CheckValorantProcessCommandLine(ScanContext ctx, Process proc, string procName)
    {
        bool nameContainsValorant = procName.Contains("valorant", StringComparison.OrdinalIgnoreCase)
            || procName.Contains("valo", StringComparison.OrdinalIgnoreCase);

        if (!nameContainsValorant) return;

        string? commandLine = null;
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {proc.Id}");
            using var results = searcher.Get();
            foreach (System.Management.ManagementObject mo in results)
            {
                commandLine = mo["CommandLine"]?.ToString();
                break;
            }
        }
        catch { return; }

        if (string.IsNullOrEmpty(commandLine)) return;

        foreach (var flag in SuspiciousProcessFlags)
        {
            if (!commandLine.Contains(flag, StringComparison.OrdinalIgnoreCase)) continue;

            int pid = 0;
            try { pid = proc.Id; } catch { }

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Valorant-Prozess mit verdächtigen Kommandozeilen-Flags: {procName}",
                Risk = RiskLevel.High,
                Location = $"PID {pid} · {procName}",
                FileName = procName + ".exe",
                Reason = $"Der Valorant-bezogene Prozess '{procName}' (PID {pid}) wurde mit dem " +
                         $"verdächtigen Flag '{flag}' gestartet. Solche Flags werden von Cheat-Loadern " +
                         "verwendet, um Cheats zu injizieren oder die Anti-Cheat-Überprüfung zu umgehen.",
                Detail = $"Kommandozeile: {TruncateString(commandLine, 220)}"
            });
            break;
        }
    }

    private void ScanPrefetchEntries(ScanContext ctx, CancellationToken ct)
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        string[] prefetchFiles;
        try
        {
            prefetchFiles = Directory.GetFiles(prefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var pfFile in prefetchFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(pfFile);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            var exeNameUpper = exeName.ToUpperInvariant();

            foreach (var pattern in CheatPrefetchPatterns)
            {
                if (!exeNameUpper.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                DateTime lastWrite = default;
                try { lastWrite = File.GetLastWriteTime(pfFile); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Prefetch-Eintrag: Valorant-Cheat ausgeführt — {exeName}.exe",
                    Risk = DeterminePrefetchRisk(exeNameUpper),
                    Location = pfFile,
                    FileName = exeName + ".exe",
                    Reason = $"Die Prefetch-Datei deutet auf die Ausführung von '{exeName}.exe' hin, " +
                             "das dem Namensmuster eines bekannten Valorant-Cheats oder Vanguard-Bypass-Tools " +
                             "entspricht. Prefetch-Einträge bleiben auch nach dem Löschen der Originaldatei erhalten.",
                    Detail = lastWrite != default
                        ? $"Prefetch zuletzt aktualisiert: {lastWrite:yyyy-MM-dd HH:mm:ss}"
                        : null
                });
                break;
            }

            foreach (var pattern in VanguardBypassPrefetchPatterns)
            {
                if (!exeNameUpper.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                if (CheatPrefetchPatterns.Any(cp =>
                    exeNameUpper.StartsWith(cp, StringComparison.OrdinalIgnoreCase)))
                    break;

                DateTime lastWrite = default;
                try { lastWrite = File.GetLastWriteTime(pfFile); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Prefetch-Eintrag: Vanguard-Bypass-Tool ausgeführt — {exeName}.exe",
                    Risk = RiskLevel.High,
                    Location = pfFile,
                    FileName = exeName + ".exe",
                    Reason = $"Die Prefetch-Datei deutet auf die Ausführung von '{exeName}.exe' hin, " +
                             "das dem Namensmuster eines bekannten Vanguard-Bypass-Tools entspricht. " +
                             "Dies zeigt, dass das Tool zu einem früheren Zeitpunkt auf dem System ausgeführt wurde.",
                    Detail = lastWrite != default
                        ? $"Prefetch zuletzt aktualisiert: {lastWrite:yyyy-MM-dd HH:mm:ss}"
                        : null
                });
                break;
            }
        }
    }

    private static RiskLevel DeterminePrefetchRisk(string exeNameUpper)
    {
        if (exeNameUpper.StartsWith("VANGUARD_BYPASS", StringComparison.OrdinalIgnoreCase) ||
            exeNameUpper.StartsWith("VGCKILLER", StringComparison.OrdinalIgnoreCase) ||
            exeNameUpper.StartsWith("VGC_KILLER", StringComparison.OrdinalIgnoreCase) ||
            exeNameUpper.StartsWith("VGK_BYPASS", StringComparison.OrdinalIgnoreCase))
            return RiskLevel.High;

        if (exeNameUpper.StartsWith("VAL_LOADER", StringComparison.OrdinalIgnoreCase) ||
            exeNameUpper.StartsWith("VALORANT_LOADER", StringComparison.OrdinalIgnoreCase))
            return RiskLevel.High;

        return RiskLevel.High;
    }

    private static string ExtractContextAroundKeyword(string content, string keyword, int contextLength)
    {
        var idx = content.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return string.Empty;

        var start = Math.Max(0, idx - contextLength / 2);
        var end = Math.Min(content.Length, idx + keyword.Length + contextLength / 2);
        var extracted = content.Substring(start, end - start)
            .Replace('\n', ' ')
            .Replace('\r', ' ');

        return TruncateString(extracted.Trim(), contextLength);
    }

    private static string TruncateString(string s, int maxLength)
        => s.Length <= maxLength ? s : s.Substring(0, maxLength) + "…";
}
