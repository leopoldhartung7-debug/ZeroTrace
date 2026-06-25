using System.Diagnostics;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AntiCheatBypassArtifactScanModule : IScanModule
{
    public string Name => "Anti-Cheat Bypass Artefakte";
    public double Weight => 0.8;
    public int ParallelGroup => 4;

    private static readonly HashSet<string> VacBypassExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "vacbypass.exe", "vac_bypass.exe", "vacblocker.exe", "vac-killer.exe",
        "steamvac_bypass.exe", "valve_bypass.exe", "svac_bypass.exe",
        "vacundetect.exe", "valve_anti_cheat_bypass.exe"
    };

    private static readonly HashSet<string> VacBypassDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "vacbypass.dll", "vac_bypass.dll", "steam_bypass.dll", "valve_bypass.dll"
    };

    private static readonly HashSet<string> EacBypassExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "eacbypass.exe", "eac_bypass.exe", "eac-killer.exe", "easy_bypass.exe",
        "easyac_bypass.exe", "eac_spoofer.exe", "eac_patcher.exe",
        "eac_disabler.exe", "eacoff.exe"
    };

    private static readonly HashSet<string> EacBypassDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "eacbypass.dll", "eac_bypass.dll", "eac_patch.dll", "EasyAntiCheat_bypass.dll"
    };

    private static readonly HashSet<string> BattleEyeBypassExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "battleye_bypass.exe", "be_bypass.exe", "bebypass.exe", "battleye_killer.exe",
        "battleye_patch.exe", "beservice_killer.exe", "beservice_bypass.exe"
    };

    private static readonly HashSet<string> BattleEyeBypassDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "battleye_bypass.dll", "be_bypass.dll", "bebypass.dll"
    };

    private static readonly HashSet<string> FiveMBypassExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cfx_bypass.exe", "cfxbypass.exe", "citizenfx_bypass.exe",
        "fivem_bypass.exe", "fivem_anticheats_bypass.exe", "cfxantidetect.exe"
    };

    private static readonly HashSet<string> FiveMBypassDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cfx_bypass.dll", "cfxbypass.dll", "citizenfx_hook.dll"
    };

    private static readonly HashSet<string> RicochetBypassExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ricochet_bypass.exe", "ricochet_patch.exe", "cod_bypass.exe"
    };

    private static readonly HashSet<string> FaceitBypassExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "faceit_bypass.exe", "faceit_patch.exe", "faceit_spoofer.exe"
    };

    private static readonly HashSet<string> AllBypassExeNames;
    private static readonly HashSet<string> AllBypassDllNames;

    static AntiCheatBypassArtifactScanModule()
    {
        AllBypassExeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in VacBypassExeNames) AllBypassExeNames.Add(name);
        foreach (var name in EacBypassExeNames) AllBypassExeNames.Add(name);
        foreach (var name in BattleEyeBypassExeNames) AllBypassExeNames.Add(name);
        foreach (var name in FiveMBypassExeNames) AllBypassExeNames.Add(name);
        foreach (var name in RicochetBypassExeNames) AllBypassExeNames.Add(name);
        foreach (var name in FaceitBypassExeNames) AllBypassExeNames.Add(name);

        AllBypassDllNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in VacBypassDllNames) AllBypassDllNames.Add(name);
        foreach (var name in EacBypassDllNames) AllBypassDllNames.Add(name);
        foreach (var name in BattleEyeBypassDllNames) AllBypassDllNames.Add(name);
        foreach (var name in FiveMBypassDllNames) AllBypassDllNames.Add(name);
    }

    private static readonly string[] AntiCheatServiceStopPatterns =
    {
        "sc stop vgc", "sc stop faceit", "sc stop easyanticheat", "sc stop beservice",
        "sc delete", "net stop vgc", "sc stop battleye", "sc stop vanguard",
        "sc stop faceitclient", "net stop easyanticheat", "net stop battleeye"
    };

    private static readonly string[] PrefetchBypassPatterns =
    {
        "VACBYPASS", "EACBYPASS", "BEBYPASS", "CFXBYPASS",
        "BATTLEYE_BYPASS", "EAC_BYPASS", "VAC_BYPASS", "BE_BYPASS",
        "FACEIT_BYPASS", "RICOCHET_BYPASS", "COD_BYPASS", "CFXANTIDETECT",
        "EACOFF", "VACBLOCKER", "BESERVICE_KILLER", "CITIZENFX_BYPASS",
        "FIVEM_BYPASS", "FACEIT_PATCH", "FACEIT_SPOOFER"
    };

    private static readonly string[] FiveMBypassLuaFiles =
    {
        "bypass.lua", "anti_detect.lua", "noban.lua", "disable_ac.lua"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanFilesystemForBypassToolsAsync(ctx, ct);
        ctx.Report(0.18, "Bypass-Dateien", "Bypass-Tool-Dateien gesucht");

        await ScanVacSpecificArtifactsAsync(ctx, ct);
        ctx.Report(0.30, "VAC Artefakte", "VAC-Bypass-Artefakte geprueft");

        await ScanEacSpecificArtifactsAsync(ctx, ct);
        ctx.Report(0.42, "EAC Artefakte", "EAC-Bypass-Artefakte geprueft");

        await ScanBattleEyeSpecificArtifactsAsync(ctx, ct);
        ctx.Report(0.54, "BattlEye Artefakte", "BattlEye-Bypass-Artefakte geprueft");

        await ScanFiveMBypassArtifactsAsync(ctx, ct);
        ctx.Report(0.63, "FiveM Bypass", "FiveM-Bypass-Artefakte geprueft");

        ScanPrefetchArtifacts(ctx, ct);
        ctx.Report(0.72, "Prefetch", "Prefetch-Artefakte geprueft");

        await ScanPowerShellHistoryForAcStopAsync(ctx, ct);
        ctx.Report(0.82, "PowerShell-History", "PowerShell-Verlauf auf AC-Stop-Befehle geprueft");

        ScanScheduledTasksForBypass(ctx, ct);
        ctx.Report(0.90, "Geplante Aufgaben", "Geplante Aufgaben auf Bypass-Persistenz geprueft");

        ScanRegistryArtifacts(ctx, ct);
        ctx.Report(0.96, "Registry", "Registry-Bypass-Artefakte geprueft");

        ScanRunningProcesses(ctx, ct);
        ctx.Report(1.0, "Prozesse", "Laufende Bypass-Prozesse geprueft");
    }

    private async Task ScanFilesystemForBypassToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetSearchDirectories();

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            string[] exeFiles = Array.Empty<string>();
            string[] dllFiles = Array.Empty<string>();

            try { exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { }
            catch { }

            try { dllFiles = Directory.GetFiles(dir, "*.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { }
            catch { }

            foreach (var file in exeFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (!AllBypassExeNames.Contains(fileName)) continue;

                var acSystem = IdentifyAntiCheatSystem(fileName);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Anti-Cheat-Bypass-Tool ({acSystem}): {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes Tool zum Umgehen des " +
                             $"Anti-Cheat-Systems '{acSystem}'. Das Vorhandensein auf dem Datentraeger " +
                             "ist ein starkes Indiz fuer den Versuch, die Cheat-Erkennung zu umgehen.",
                    Detail = $"Anti-Cheat: {acSystem}, Gefunden in: {dir}"
                });
            }

            foreach (var file in dllFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (!AllBypassDllNames.Contains(fileName)) continue;

                var acSystem = IdentifyAntiCheatSystem(fileName);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Anti-Cheat-Bypass-DLL ({acSystem}): {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Die DLL '{fileName}' ist ein bekanntes Tool zum Umgehen des " +
                             $"Anti-Cheat-Systems '{acSystem}'. DLL-basierte Bypasses werden direkt " +
                             "in den Spielprozess oder das Anti-Cheat-System injiziert.",
                    Detail = $"Anti-Cheat: {acSystem}, Gefunden in: {dir}"
                });
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanVacSpecificArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var steamClientPaths = new[]
        {
            @"C:\Program Files (x86)\Steam\steamclient.dll",
            @"C:\Program Files\Steam\steamclient.dll"
        };

        foreach (var steamClientPath in steamClientPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!File.Exists(steamClientPath)) continue;

            ctx.IncrementFiles();
            try
            {
                var info = new FileInfo(steamClientPath);
                var sizeMb = info.Length / (1024.0 * 1024.0);

                if (sizeMb < 2.0 || sizeMb > 8.0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Steam-Kerndatei mit unerwarteter Groesse (VAC-Manipulation)",
                        Risk = RiskLevel.High,
                        Location = steamClientPath,
                        FileName = "steamclient.dll",
                        Reason = $"steamclient.dll hat eine ungewoehnliche Groesse ({sizeMb:F2} MB). " +
                                 "Die legitime Datei liegt typischerweise zwischen 2 MB und 8 MB. " +
                                 "Eine modifizierte steamclient.dll kann das VAC3-Anti-Cheat-System " +
                                 "deaktivieren oder manipulieren.",
                        Detail = $"Dateigroesse: {info.Length} Bytes ({sizeMb:F2} MB)"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }

    private async Task ScanEacSpecificArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var eacLauncherPaths = new List<string>();

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        foreach (var baseDir in new[] { programFiles, programFilesX86 })
        {
            if (!Directory.Exists(baseDir)) continue;
            try
            {
                var eacFiles = Directory.GetFiles(baseDir, "EasyAntiCheat_launcher.exe",
                    SearchOption.AllDirectories);
                eacLauncherPaths.AddRange(eacFiles);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }

        foreach (var launcherPath in eacLauncherPaths)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementFiles();

            try
            {
                var info = new FileInfo(launcherPath);
                var sizeKb = info.Length / 1024.0;

                if (sizeKb < 100 || info.Length > 10 * 1024 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "EasyAntiCheat-Launcher mit unerwarteter Groesse (moegliche Manipulation)",
                        Risk = RiskLevel.Critical,
                        Location = launcherPath,
                        FileName = "EasyAntiCheat_launcher.exe",
                        Reason = $"EasyAntiCheat_launcher.exe hat eine ungewoehnliche Groesse " +
                                 $"({sizeKb:F0} KB). Eine zu kleine (<100 KB) oder zu grosse (>10 MB) " +
                                 "Datei deutet auf einen ausgetauschten EAC-Launcher hin, " +
                                 "der die Anti-Cheat-Pruefung deaktiviert oder umgeht.",
                        Detail = $"Dateigroesse: {info.Length} Bytes"
                    });
                }
            }
            catch { }
        }

        CheckEacServiceMissing(ctx);

        await Task.CompletedTask;
    }

    private void CheckEacServiceMissing(ScanContext ctx)
    {
        bool eacGameInstalled = false;
        bool eacServicePresent = false;

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services");
            if (servicesKey != null)
            {
                ctx.IncrementRegistryKeys();
                var serviceNames = servicesKey.GetSubKeyNames();
                eacServicePresent = serviceNames.Any(n =>
                    n.Contains("EasyAntiCheat", StringComparison.OrdinalIgnoreCase) ||
                    n.Equals("EasyAntiCheat", StringComparison.OrdinalIgnoreCase));
            }
        }
        catch { }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        foreach (var baseDir in new[] { programFiles, programFilesX86 })
        {
            if (!Directory.Exists(baseDir)) continue;
            try
            {
                var eacDirs = Directory.GetDirectories(baseDir, "EasyAntiCheat*",
                    SearchOption.AllDirectories);
                if (eacDirs.Length > 0)
                {
                    eacGameInstalled = true;
                    break;
                }
            }
            catch { }
        }

        if (eacGameInstalled && !eacServicePresent)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "EasyAntiCheat-Dienst fehlt trotz installiertem EAC-Spiel",
                Risk = RiskLevel.Medium,
                Location = @"HKLM\SYSTEM\CurrentControlSet\Services",
                Reason = "Ein EAC-Spiel ist installiert, aber der EasyAntiCheat-Dienst fehlt in der " +
                         "Windows-Dienste-Registry. Dies kann darauf hinweisen, dass der EAC-Dienst " +
                         "absichtlich entfernt oder deaktiviert wurde, um die Anti-Cheat-Pruefung " +
                         "zu umgehen.",
                Detail = "EAC-Installation gefunden, aber kein EasyAntiCheat-Dienst in der Registry"
            });
        }
    }

    private async Task ScanBattleEyeSpecificArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var beServicePaths = new[]
        {
            @"C:\Windows\System32\BEService.exe",
            @"C:\Program Files\Common Files\BattlEye\BEService.exe"
        };

        foreach (var bePath in beServicePaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!File.Exists(bePath)) continue;

            ctx.IncrementFiles();
            try
            {
                var info = new FileInfo(bePath);
                var sizeKb = info.Length / 1024.0;

                if (sizeKb < 50 || info.Length > 5 * 1024 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "BattlEye-Dienst mit unerwarteter Groesse",
                        Risk = RiskLevel.Critical,
                        Location = bePath,
                        FileName = "BEService.exe",
                        Reason = $"BEService.exe hat eine ungewoehnliche Groesse ({sizeKb:F0} KB). " +
                                 "Die legitime Datei liegt typischerweise zwischen 200 KB und 600 KB. " +
                                 "Eine zu kleine oder zu grosse Datei deutet auf eine manipulierte " +
                                 "oder ausgetauschte BattlEye-Dienstdatei hin.",
                        Detail = $"Dateigroesse: {info.Length} Bytes, Normale Groesse: 200-600 KB"
                    });
                }
            }
            catch { }
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        foreach (var baseDir in new[] { programFiles, programFilesX86 })
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(baseDir)) continue;

            string[] battleyeDirs = Array.Empty<string>();
            try { battleyeDirs = Directory.GetDirectories(baseDir, "BattlEye", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var beDir in battleyeDirs)
            {
                if (ct.IsCancellationRequested) break;

                string[] beDirFiles = Array.Empty<string>();
                try { beDirFiles = Directory.GetFiles(beDir); }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var beFile in beDirFiles)
                {
                    ctx.IncrementFiles();
                    var beFileName = Path.GetFileName(beFile);

                    if (beFileName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        beFileName.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                        beFileName.Contains("kill", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige Datei im BattlEye-Verzeichnis: {beFileName}",
                            Risk = RiskLevel.Critical,
                            Location = beFile,
                            FileName = beFileName,
                            Reason = $"Die Datei '{beFileName}' im BattlEye-Verzeichnis hat einen Namen, " +
                                     "der auf ein Bypass- oder Patch-Tool hinweist. " +
                                     "Legitime BattlEye-Installationen enthalten keine solchen Dateien.",
                            Detail = $"BattlEye-Verzeichnis: {beDir}"
                        });
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanFiveMBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var citizenFxDir = Path.Combine(roamingAppData, "CitizenFX");

        if (Directory.Exists(citizenFxDir))
        {
            foreach (var luaFileName in FiveMBypassLuaFiles)
            {
                if (ct.IsCancellationRequested) break;

                string[] luaFiles = Array.Empty<string>();
                try { luaFiles = Directory.GetFiles(citizenFxDir, luaFileName, SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var luaFile in luaFiles)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM/CFX Anti-Cheat Bypass Lua-Skript: {luaFileName}",
                        Risk = RiskLevel.Critical,
                        Location = luaFile,
                        FileName = luaFileName,
                        Reason = $"Das Lua-Skript '{luaFileName}' im CitizenFX-Verzeichnis ist ein " +
                                 "bekanntes FiveM Anti-Cheat Bypass-Skript. Solche Skripte werden " +
                                 "verwendet, um den cfx:// Anti-Cheat zu umgehen und Banns zu verhindern.",
                        Detail = $"Gefunden in: {luaFile}"
                    });
                }
            }
        }

        var fiveMCacheDirs = new[]
        {
            Path.Combine(roamingAppData, "CitizenFX", "cache"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FiveM", "FiveM.app", "cache")
        };

        foreach (var cacheDir in fiveMCacheDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(cacheDir)) continue;

            string[] cacheFiles = Array.Empty<string>();
            try { cacheFiles = Directory.GetFiles(cacheDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var cacheFile in cacheFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var cacheFileName = Path.GetFileNameWithoutExtension(cacheFile).ToLowerInvariant();
                if (cacheFileName.Contains("bypass") ||
                    cacheFileName.Contains("antidetect") ||
                    cacheFileName.Contains("noban") ||
                    cacheFileName.Contains("disable_ac"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige Datei im FiveM-Cache: {Path.GetFileName(cacheFile)}",
                        Risk = RiskLevel.High,
                        Location = cacheFile,
                        FileName = Path.GetFileName(cacheFile),
                        Reason = "Eine Datei im FiveM-Ressourcen-Cache hat einen Namen, der auf " +
                                 "ein Anti-Cheat-Bypass-Skript oder -Tool hinweist. " +
                                 "FiveM-Ressourcen mit diesen Namen werden fuer CFX-Bypasses verwendet.",
                        Detail = $"Cache-Datei: {cacheFile}"
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    private void ScanPrefetchArtifacts(ScanContext ctx, CancellationToken ct)
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        string[] pfFiles = Array.Empty<string>();
        try { pfFiles = Directory.GetFiles(prefetchDir, "*.pf"); }
        catch { return; }

        foreach (var pfFile in pfFiles)
        {
            if (ct.IsCancellationRequested) break;

            var pfName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9 ? pfName[..dashIdx] : pfName;

            var matchedPattern = PrefetchBypassPatterns
                .FirstOrDefault(p => exeName.StartsWith(p, StringComparison.OrdinalIgnoreCase) ||
                                     exeName.Contains(p, StringComparison.OrdinalIgnoreCase));

            if (matchedPattern == null) continue;

            var lastRun = DateTime.MinValue;
            try { lastRun = File.GetLastWriteTime(pfFile); } catch { }

            var acSystem = IdentifyAntiCheatSystemFromPattern(matchedPattern);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Prefetch-Artefakt: Anti-Cheat-Bypass-Tool ({acSystem}) ausgefuehrt",
                Risk = RiskLevel.High,
                Location = pfFile,
                FileName = exeName.ToLowerInvariant() + ".exe",
                Reason = $"Die Prefetch-Datei '{pfName}' deutet darauf hin, dass ein " +
                         $"Anti-Cheat-Bypass-Tool ({acSystem}) ausgefuehrt wurde. " +
                         "Prefetch-Dateien bleiben auch nach Loeschung des Tools erhalten " +
                         "und dienen als forensischer Beweis.",
                Detail = lastRun != DateTime.MinValue
                    ? $"Zuletzt ausgefuehrt: {lastRun:yyyy-MM-dd HH:mm:ss}"
                    : null
            });
        }
    }

    private async Task ScanPowerShellHistoryForAcStopAsync(ScanContext ctx, CancellationToken ct)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var historyPath = Path.Combine(roamingAppData,
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (!File.Exists(historyPath)) return;

        string content;
        try
        {
            using var sr = new StreamReader(historyPath);
            content = await sr.ReadToEndAsync();
        }
        catch { return; }

        ctx.IncrementFiles();

        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int emitted = 0;

        foreach (var line in lines)
        {
            if (ct.IsCancellationRequested) break;
            if (emitted >= 20) break;

            var trimmedLine = line.Trim();
            if (string.IsNullOrEmpty(trimmedLine)) continue;

            var lineLower = trimmedLine.ToLowerInvariant();
            var matchedPattern = AntiCheatServiceStopPatterns
                .FirstOrDefault(p => lineLower.Contains(p.ToLowerInvariant()));

            if (matchedPattern == null) continue;

            var key = trimmedLine.Substring(0, Math.Min(160, trimmedLine.Length));
            if (!seen.Add(key)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "PowerShell-Verlauf: Anti-Cheat-Dienst gestoppt/geloescht",
                Risk = RiskLevel.Medium,
                Location = historyPath,
                Reason = $"Der PowerShell-Verlauf enthaelt einen Befehl, der einen Anti-Cheat-Dienst " +
                         $"stoppt oder loescht: '{matchedPattern}'. Dies deutet auf einen Versuch hin, " +
                         "das Anti-Cheat-System vor dem Spielen zu deaktivieren.",
                Detail = $"Befehl: {key}"
            });

            emitted++;
        }
    }

    private void ScanScheduledTasksForBypass(ScanContext ctx, CancellationToken ct)
    {
        var taskKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
        };

        foreach (var taskKeyPath in taskKeys)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                using var tasksKey = Registry.LocalMachine.OpenSubKey(taskKeyPath);
                if (tasksKey == null) continue;

                foreach (var taskName in tasksKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;

                    try
                    {
                        using var taskKey = tasksKey.OpenSubKey(taskName);
                        if (taskKey == null) continue;

                        ctx.IncrementRegistryKeys();

                        var actionRaw = taskKey.GetValue("Actions")?.ToString() ??
                                        taskKey.GetValue("Path")?.ToString() ?? string.Empty;

                        if (string.IsNullOrEmpty(actionRaw)) continue;

                        var actionLower = actionRaw.ToLowerInvariant();
                        bool hasAntiCheatRef = actionLower.Contains("vac") ||
                                              actionLower.Contains("eac") ||
                                              actionLower.Contains("battleye") ||
                                              actionLower.Contains("faceit") ||
                                              actionLower.Contains("vanguard") ||
                                              actionLower.Contains("beservice");

                        bool hasBypassRef = actionLower.Contains("bypass") ||
                                           actionLower.Contains("kill") ||
                                           actionLower.Contains("disable") ||
                                           actionLower.Contains("patch");

                        if (hasAntiCheatRef && hasBypassRef)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Geplante Aufgabe mit Anti-Cheat-Bypass-Bezug: {taskName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{taskKeyPath}\{taskName}",
                                Reason = "Eine geplante Windows-Aufgabe verweist auf eine Aktion, " +
                                         "die sowohl Anti-Cheat-Systemname als auch Bypass/Kill/Disable " +
                                         "enthaelt. Bypass-Tools nutzen geplante Aufgaben zur Persistenz " +
                                         "und um vor dem Spielen automatisch ausgefuehrt zu werden.",
                                Detail = $"Aktion/Pfad: {actionRaw.Substring(0, Math.Min(200, actionRaw.Length))}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void ScanRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var hkcuBypassKeys = new[]
        {
            (@"Software\VACBypass", "VAC"),
            (@"Software\SteamBypass", "VAC/Steam"),
            (@"Software\EACBypass", "EAC"),
            (@"Software\EasyAntiCheatBypass", "EAC"),
            (@"Software\BEBypass", "BattlEye"),
            (@"Software\2Take1", "GTA Online (2Take1)")
        };

        foreach (var (keyPath, acSystem) in hkcuBypassKeys)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key == null) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Anti-Cheat-Bypass-Registry-Schluessel vorhanden ({acSystem})",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{keyPath}",
                    Reason = $"Der Registry-Schluessel '{keyPath}' ist typisch fuer ein " +
                             $"{acSystem}-Bypass-Tool und deutet auf eine fruehre oder aktuelle " +
                             "Installation eines solchen Tools hin.",
                    Detail = $"Schluessel: HKCU\\{keyPath}, Anti-Cheat: {acSystem}"
                });
            }
            catch { }
        }

        try
        {
            using var beKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\BattlEye");
            if (beKey != null)
            {
                ctx.IncrementRegistryKeys();
                var status = beKey.GetValue("Status")?.ToString();
                if (!string.IsNullOrEmpty(status) &&
                    (status.Contains("disabled", StringComparison.OrdinalIgnoreCase) ||
                     status == "0"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "BattlEye-Dienst laut Registry deaktiviert",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SOFTWARE\BattlEye",
                        Reason = "Der BattlEye-Status in der Registry zeigt an, dass der Dienst " +
                                 "deaktiviert ist. Dies kann auf einen BattlEye-Bypass hinweisen, " +
                                 "der den Anti-Cheat-Schutz absichtlich deaktiviert hat.",
                        Detail = $"Status-Wert: {status}"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var ricochetDriverKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\wdFilter");
            if (ricochetDriverKey != null)
            {
                ctx.IncrementRegistryKeys();
                var imagePath = ricochetDriverKey.GetValue("ImagePath")?.ToString() ?? string.Empty;
                if (!imagePath.Contains("wdfilter", StringComparison.OrdinalIgnoreCase) &&
                    !imagePath.Contains("windows\\system32", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrEmpty(imagePath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "wdFilter.sys auf ungewoehnlichen Pfad zeigend (Ricochet-Manipulation)",
                        Risk = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\wdFilter",
                        Reason = "Der Windows Defender-Filtertreiber (wdFilter) zeigt auf einen " +
                                 "unerwarteten Pfad. Ricochet (CoD Anti-Cheat) installiert einen " +
                                 "Kernel-Treiber; eine Manipulation dieses Eintrags deutet auf " +
                                 "einen Ricochet-Bypass-Angriff hin.",
                        Detail = $"ImagePath: {imagePath}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();
        var runningBypassExeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementProcesses();

            try
            {
                var procExeName = proc.ProcessName + ".exe";
                if (!AllBypassExeNames.Contains(procExeName)) continue;

                runningBypassExeNames.Add(procExeName);
                var procPath = string.Empty;
                try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                var acSystem = IdentifyAntiCheatSystem(procExeName);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Anti-Cheat-Bypass-Tool ({acSystem}) laeuft aktiv: {procExeName}",
                    Risk = RiskLevel.Critical,
                    Location = procPath.Length > 0 ? procPath : $"PID {proc.Id}",
                    FileName = procExeName,
                    Reason = $"Das Anti-Cheat-Bypass-Tool '{procExeName}' fuer '{acSystem}' ist " +
                             $"aktuell aktiv (PID {proc.Id}). Ein laufendes Bypass-Tool ist ein " +
                             "eindeutiges Zeichen fuer eine aktive Umgehung des Anti-Cheat-Systems.",
                    Detail = $"PID: {proc.Id}, Anti-Cheat: {acSystem}, " +
                             $"Pfad: {(procPath.Length > 0 ? procPath : "unbekannt")}"
                });
            }
            catch { }
        }
    }

    private static string IdentifyAntiCheatSystem(string fileName)
    {
        var lower = fileName.ToLowerInvariant();
        if (lower.Contains("vac") || lower.Contains("valve") || lower.Contains("steam")) return "VAC";
        if (lower.Contains("eac") || lower.Contains("easy")) return "EAC";
        if (lower.Contains("be") || lower.Contains("battleye") || lower.Contains("battle")) return "BattlEye";
        if (lower.Contains("cfx") || lower.Contains("citizenfx") || lower.Contains("fivem")) return "FiveM/CFX";
        if (lower.Contains("ricochet") || lower.Contains("cod")) return "Ricochet (CoD)";
        if (lower.Contains("faceit")) return "FACEIT";
        return "Unbekanntes Anti-Cheat";
    }

    private static string IdentifyAntiCheatSystemFromPattern(string pattern)
    {
        var lower = pattern.ToLowerInvariant();
        if (lower.Contains("vac")) return "VAC";
        if (lower.Contains("eac")) return "EAC";
        if (lower.Contains("be") || lower.Contains("battleye")) return "BattlEye";
        if (lower.Contains("cfx") || lower.Contains("citizenfx") || lower.Contains("fivem")) return "FiveM/CFX";
        if (lower.Contains("faceit")) return "FACEIT";
        if (lower.Contains("ricochet") || lower.Contains("cod")) return "Ricochet (CoD)";
        return "Anti-Cheat";
    }

    private static IEnumerable<string> GetSearchDirectories()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var appDataLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Path.GetTempPath(),
            appDataRoaming,
            appDataLocal,
            documents,
            @"C:\Program Files",
            @"C:\Program Files (x86)"
        };
    }
}
