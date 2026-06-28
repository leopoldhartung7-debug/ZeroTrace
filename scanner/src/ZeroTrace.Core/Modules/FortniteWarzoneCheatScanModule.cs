using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class FortniteWarzoneCheatScanModule : IScanModule
{
    public string Name => "Fortnite-Warzone-Cheat";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    private static readonly string[] FortniteCheatExeNames =
    {
        "fortnite_cheat.exe", "fortnite_hack.exe", "fortnite_aimbot.exe", "fortnite_esp.exe",
        "fortnite_wallhack.exe", "fortnite_loader.exe", "fortnite_bypass.exe",
        "fortnite_external.exe", "fortnite_internal.exe",
        "fn_cheat.exe", "fn_hack.exe", "fn_aimbot.exe", "fn_esp.exe", "fn_loader.exe",
        "epic_bypass.exe", "epicgames_bypass.exe", "eac_fortnite_bypass.exe",
        "fortnite_spoofer.exe", "fn_spoofer.exe",
        "fortnite_unlock.exe", "fn_unlocker.exe",
        "fortnite_skin_changer.exe", "fn_skinchanger.exe",
        "fortnite_vbucks.exe", "fn_vbucks_hack.exe",
    };

    private static readonly string[] FortniteCheatDllNames =
    {
        "fortnite_cheat.dll", "fortnite_esp.dll", "fortnite_aimbot.dll",
        "fn_hook.dll", "epic_bypass.dll",
    };

    private static readonly string[] WarzoneCheatExeNames =
    {
        "warzone_cheat.exe", "warzone_hack.exe", "warzone_aimbot.exe", "warzone_esp.exe",
        "warzone_wallhack.exe", "warzone_loader.exe",
        "cod_cheat.exe", "cod_hack.exe",
        "mw_cheat.exe", "mw2_cheat.exe",
        "wz_cheat.exe", "wz_aimbot.exe", "wz_esp.exe", "wz_loader.exe",
        "ricochet_bypass.exe", "ricochet_kill.exe", "ricochet_patch.exe",
        "wz_bypass.exe", "cod_bypass.exe",
        "cod_external.exe", "warzone_external.exe", "warzone_internal.exe",
        "wz_unlocker.exe", "wz_unlock_all.exe",
    };

    private static readonly string[] WarzoneCheatDllNames =
    {
        "warzone_cheat.dll", "warzone_esp.dll", "warzone_aimbot.dll",
        "wz_hook.dll", "ricochet_bypass.dll",
    };

    private static readonly string[] SkinChangerVbucksExeNames =
    {
        "vbucks_generator.exe", "vbucks_hack.exe", "skin_changer.exe",
        "fortnite_skin_changer.exe", "fn_skin_swap.exe",
    };

    private static readonly string[] AllCheatExeNames = BuildAllCheatExeNames();

    private static string[] BuildAllCheatExeNames()
    {
        var list = new List<string>();
        list.AddRange(FortniteCheatExeNames);
        list.AddRange(WarzoneCheatExeNames);
        list.AddRange(SkinChangerVbucksExeNames);
        return list.ToArray();
    }

    private static readonly string[] FortniteGameExeNames =
    {
        "fortniteclient-win64-shipping.exe", "fortnite.exe",
    };

    private static readonly string[] WarzoneGameExeNames =
    {
        "warzone.exe", "cod.exe", "modernwarfare.exe", "modernwarfare2.exe",
        "mw2.exe", "mw3.exe", "blackops6.exe",
    };

    private static readonly string[] FortniteConfigCheatKeywords =
    {
        "benablecheatmanager=true", "ballowcheats=true", "disableanticheats=true",
        "disableanticheat=true",
    };

    private static readonly string[] LogCheatKeywords =
    {
        "cheat", "inject", "bypass", "aimbot",
    };

    private static readonly string[] WarzoneConfigCheatKeywords =
    {
        "aimbot", "esp", "bypass", "wallhack", "norecoil", "no_recoil",
        "triggerbot", "speedhack", "godmode", "unlimited_ammo",
    };

    private static readonly string[] PrefetchPatterns =
    {
        "FORTNITE_CHEAT", "FN_CHEAT", "WARZONE_CHEAT", "WZ_CHEAT", "COD_CHEAT",
        "RICOCHET_BYPASS", "FN_LOADER", "WZ_LOADER", "WDFILTER_BYPASS", "WZ_BYPASS",
    };

    private static readonly string[] SearchBases = BuildSearchBases();

    private static string[] BuildSearchBases()
    {
        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanFortniteCheatFiles(ctx, ct);
            ScanWarzoneCheatFiles(ctx, ct);
            ScanFortniteAppDataArtifacts(ctx, ct);
            ScanWarzoneAppDataArtifacts(ctx, ct);
            ScanRicochetBypassArtifacts(ctx, ct);
            ScanSkinChangerVbucksFiles(ctx, ct);
            ScanRunningProcesses(ctx, ct);
            ScanPrefetchFiles(ctx, ct);
        }, ct);
    }

    private static void ScanFortniteCheatFiles(ScanContext ctx, CancellationToken ct)
    {
        foreach (var baseDir in SearchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    foreach (var known in FortniteCheatExeNames)
                    {
                        if (!fname.Equals(known, StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Fortnite-Warzone-Cheat",
                            Title = $"Fortnite Cheat-EXE gefunden: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Bekannte Fortnite-Cheat-EXE '{fname}' auf Datentraeger gefunden. " +
                                     "EAC (Easy Anti-Cheat) wird durch dieses Tool umgangen.",
                            Detail = $"Path={file}",
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    foreach (var known in FortniteCheatDllNames)
                    {
                        if (!fname.Equals(known, StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Fortnite-Warzone-Cheat",
                            Title = $"Fortnite Cheat-DLL gefunden: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Bekannte Fortnite-Cheat-DLL '{fname}' gefunden — typische Injector- oder Hook-DLL.",
                            Detail = $"Path={file}",
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void ScanWarzoneCheatFiles(ScanContext ctx, CancellationToken ct)
    {
        foreach (var baseDir in SearchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    foreach (var known in WarzoneCheatExeNames)
                    {
                        if (!fname.Equals(known, StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Fortnite-Warzone-Cheat",
                            Title = $"Warzone/CoD Cheat-EXE gefunden: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Bekannte Warzone/CoD-Cheat-EXE '{fname}' auf Datentraeger gefunden. " +
                                     "Umgeht Ricochet-Kernel-Anti-Cheat.",
                            Detail = $"Path={file}",
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    foreach (var known in WarzoneCheatDllNames)
                    {
                        if (!fname.Equals(known, StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Fortnite-Warzone-Cheat",
                            Title = $"Warzone/CoD Cheat-DLL gefunden: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Bekannte Warzone/CoD-Cheat-DLL '{fname}' gefunden.",
                            Detail = $"Path={file}",
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void ScanFortniteAppDataArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var fortniteConfigDir = Path.Combine(localAppData, "FortniteGame", "Saved", "Config", "WindowsClient");
        ScanFortniteIniFiles(ctx, fortniteConfigDir, ct);

        var fortniteLogDir = Path.Combine(localAppData, "FortniteGame", "Saved", "Logs");
        ScanFortniteLogFiles(ctx, fortniteLogDir, ct);

        var cheatAppDataDirs = new[]
        {
            Path.Combine(appData, "FortniteCheat"),
            Path.Combine(appData, "FN-Cheat"),
        };

        foreach (var dir in cheatAppDataDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;
            ctx.AddFinding(new Finding
            {
                Module = "Fortnite-Warzone-Cheat",
                Title = $"Fortnite Cheat-AppData-Verzeichnis: {Path.GetFileName(dir)}",
                Risk = RiskLevel.High,
                Location = dir,
                Reason = $"Bekanntes Fortnite-Cheat-Konfigurationsverzeichnis '{dir}' gefunden.",
                Detail = $"Dir={dir}",
            });
        }

        var epicLauncherDir = Path.Combine(localAppData, "EpicGamesLauncher");
        if (Directory.Exists(epicLauncherDir))
        {
            try
            {
                foreach (var iniFile in Directory.GetFiles(epicLauncherDir, "*.ini", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(iniFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = sr.ReadToEnd();
                        var lower = content.ToLowerInvariant();
                        if (lower.Contains("bypass") || lower.Contains("cheat") || lower.Contains("inject"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Fortnite-Warzone-Cheat",
                                Title = $"Epic Games Launcher INI mit Cheat-Inhalt: {Path.GetFileName(iniFile)}",
                                Risk = RiskLevel.Medium,
                                Location = iniFile,
                                FileName = Path.GetFileName(iniFile),
                                Reason = "Epic Games Launcher INI-Datei enthaelt Cheat-Schluesselwoerter (bypass/cheat/inject).",
                                Detail = $"Path={iniFile}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanFortniteIniFiles(ScanContext ctx, string configDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!Directory.Exists(configDir)) return;

        var iniFiles = new[] { "Engine.ini", "GameUserSettings.ini" };
        foreach (var iniName in iniFiles)
        {
            var iniPath = Path.Combine(configDir, iniName);
            if (!File.Exists(iniPath)) continue;
            ctx.IncrementFiles();

            try
            {
                using var fs = new FileStream(iniPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = sr.ReadToEnd();
                var lower = content.ToLowerInvariant();

                foreach (var keyword in FortniteConfigCheatKeywords)
                {
                    if (!lower.Contains(keyword.ToLowerInvariant())) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module = "Fortnite-Warzone-Cheat",
                        Title = $"Fortnite Config mit Cheat-Flag: {iniName}",
                        Risk = RiskLevel.Medium,
                        Location = iniPath,
                        FileName = iniName,
                        Reason = $"Fortnite-Konfigurationsdatei '{iniName}' enthaelt Cheat-Flag '{keyword}'. " +
                                 "Deutet auf manuelle Cheat-Aktivierung hin.",
                        Detail = $"Path={iniPath} Keyword={keyword}",
                    });
                    break;
                }

                if (TryExtractResolutionValue(lower, "ResolutionSizeX", out var resX) && resX < 400)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Fortnite-Warzone-Cheat",
                        Title = $"Fortnite Config: Extrem niedrige Aufloesung ({resX}px) — Aimbot-Trick",
                        Risk = RiskLevel.Medium,
                        Location = iniPath,
                        FileName = iniName,
                        Reason = $"Fortnite ist auf eine extrem niedrige X-Aufloesung von {resX}px konfiguriert " +
                                 "(<400px). Wird von Aimbot-Tools genutzt um das Render-FOV zu verkleinern.",
                        Detail = $"Path={iniPath} ResX={resX}",
                    });
                }

                if (TryExtractFloatValue(lower, "fieldofview", out var fov) && (fov < 60.0f || fov > 120.0f))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Fortnite-Warzone-Cheat",
                        Title = $"Fortnite Config: Ungewoehnliches FieldOfView ({fov}) — Cheat-Indikator",
                        Risk = RiskLevel.Medium,
                        Location = iniPath,
                        FileName = iniName,
                        Reason = $"Fortnite-FieldOfView auf {fov} gesetzt (ausserhalb des normalen Bereichs 60-120). " +
                                 "Ungewoehnliche FOV-Werte koennen auf Aimbot-Konfigurationen hinweisen.",
                        Detail = $"Path={iniPath} FOV={fov}",
                    });
                }
            }
            catch (IOException) { }
        }
    }

    private static bool TryExtractResolutionValue(string lowerContent, string key, out int value)
    {
        value = 0;
        var idx = lowerContent.IndexOf(key.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return false;
        var eqIdx = lowerContent.IndexOf('=', idx);
        if (eqIdx < 0) return false;
        var start = eqIdx + 1;
        var end = start;
        while (end < lowerContent.Length && char.IsDigit(lowerContent[end])) end++;
        if (end == start) return false;
        return int.TryParse(lowerContent.AsSpan(start, end - start), out value);
    }

    private static bool TryExtractFloatValue(string lowerContent, string key, out float value)
    {
        value = 0f;
        var idx = lowerContent.IndexOf(key.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return false;
        var eqIdx = lowerContent.IndexOf('=', idx);
        if (eqIdx < 0) return false;
        var start = eqIdx + 1;
        var end = start;
        while (end < lowerContent.Length && (char.IsDigit(lowerContent[end]) || lowerContent[end] == '.' || lowerContent[end] == '-')) end++;
        if (end == start) return false;
        return float.TryParse(lowerContent.AsSpan(start, end - start), System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out value);
    }

    private static void ScanFortniteLogFiles(ScanContext ctx, string logDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!Directory.Exists(logDir)) return;

        try
        {
            foreach (var logFile in Directory.GetFiles(logDir, "*.log", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    const int maxBytes = 128 * 1024;
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var readStart = Math.Max(0, fs.Length - maxBytes);
                    fs.Seek(readStart, SeekOrigin.Begin);
                    var buf = new byte[Math.Min(maxBytes, fs.Length - readStart)];
                    var read = fs.Read(buf, 0, buf.Length);
                    var content = Encoding.UTF8.GetString(buf, 0, read).ToLowerInvariant();

                    foreach (var kw in LogCheatKeywords)
                    {
                        if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Fortnite-Warzone-Cheat",
                            Title = $"Fortnite Log enthaelt Cheat-Keyword '{kw}'",
                            Risk = RiskLevel.Medium,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"Fortnite-Logdatei enthaelt das Cheat-Keyword '{kw}'. " +
                                     "Deutet auf Cheat-Tool-Aktivitaet waehrend einer Spielsitzung hin.",
                            Detail = $"LogFile={logFile} Keyword={kw}",
                        });
                        break;
                    }
                }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private static void ScanWarzoneAppDataArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var battleNetDirs = new[]
        {
            Path.Combine(localAppData, "Battle.net"),
            Path.Combine(appData, "Battle.net"),
            Path.Combine(appData, "Activision"),
            Path.Combine(localAppData, "Activision"),
        };

        var cheatConfigNames = new[] { "wz_config.json", "warzone_settings.json", "cod_config.json" };

        foreach (var dir in battleNetDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var cfgName in cheatConfigNames)
                {
                    var cfgPath = Path.Combine(dir, cfgName);
                    if (!File.Exists(cfgPath)) continue;
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(cfgPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = sr.ReadToEnd();
                        var lower = content.ToLowerInvariant();

                        var found = WarzoneConfigCheatKeywords.FirstOrDefault(k =>
                            lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (found != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Fortnite-Warzone-Cheat",
                                Title = $"Warzone/CoD Cheat-Konfiguration: {cfgName}",
                                Risk = RiskLevel.Medium,
                                Location = cfgPath,
                                FileName = cfgName,
                                Reason = $"Warzone/CoD-Konfigurationsdatei '{cfgName}' enthaelt Cheat-Keyword '{found}'.",
                                Detail = $"Path={cfgPath} Keyword={found}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }

            try
            {
                foreach (var iniFile in Directory.GetFiles(dir, "*.ini", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(iniFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = sr.ReadToEnd();
                        var lower = content.ToLowerInvariant();

                        var found = WarzoneConfigCheatKeywords.FirstOrDefault(k =>
                            lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (found != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Fortnite-Warzone-Cheat",
                                Title = $"Activision/Battle.net INI mit Cheat-Inhalt: {Path.GetFileName(iniFile)}",
                                Risk = RiskLevel.Medium,
                                Location = iniFile,
                                FileName = Path.GetFileName(iniFile),
                                Reason = $"Activision/Battle.net-Konfigurationsdatei enthaelt Cheat-Keyword '{found}'.",
                                Detail = $"Path={iniFile} Keyword={found}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        ScanWarzoneRegistry(ctx, ct);
    }

    private static void ScanWarzoneRegistry(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var regKeys = new[]
        {
            @"Software\Activision",
            @"Software\Blizzard Entertainment",
        };

        foreach (var keyPath in regKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var subName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    using var sub = key.OpenSubKey(subName);
                    if (sub == null) continue;

                    foreach (var valueName in sub.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var val = (sub.GetValue(valueName) as string ?? string.Empty).ToLowerInvariant();
                        if (val.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            val.Contains("cheat", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Fortnite-Warzone-Cheat",
                                Title = $"Activision-Registry mit Cheat-Wert: {valueName}",
                                Risk = RiskLevel.Medium,
                                Location = $@"HKCU\{keyPath}\{subName}",
                                Reason = $"Activision/Battle.net-Registry-Wert '{valueName}' enthaelt Cheat-Keyword.",
                                Detail = $"Key={keyPath}\\{subName} Value={valueName}",
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanRicochetBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var ricochetExeNames = new[] { "ricochet_bypass.exe", "wdfilter_bypass.exe", "ricochet_patch.exe" };

        foreach (var baseDir in SearchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    foreach (var known in ricochetExeNames)
                    {
                        if (!fname.Equals(known, StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Fortnite-Warzone-Cheat",
                            Title = $"Ricochet Anti-Cheat Bypass-Tool: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Ricochet-Bypass-Tool '{fname}' gefunden. " +
                                     "Dieses Tool deaktiviert oder umgeht den Ricochet-Kernel-Anti-Cheat fuer CoD: Warzone.",
                            Detail = $"Path={file}",
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var wdFilterPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "wdFilter.sys");

        if (File.Exists(wdFilterPath))
        {
            ctx.IncrementFiles();
            try
            {
                var info = new FileInfo(wdFilterPath);
                const long minNormalBytes = 50 * 1024;
                if (info.Length < minNormalBytes)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Fortnite-Warzone-Cheat",
                        Title = $"wdFilter.sys anomale Dateigroesse: {info.Length / 1024} KB",
                        Risk = RiskLevel.High,
                        Location = wdFilterPath,
                        FileName = "wdFilter.sys",
                        Reason = $"wdFilter.sys ist nur {info.Length / 1024} KB gross (normal: 400-1000 KB). " +
                                 "Ricochet-Hooks werden in diesem Treiber installiert. Eine untypisch kleine Datei " +
                                 "deutet auf einen moeglichen Austausch durch ein Bypass-Tool hin.",
                        Detail = $"Path={wdFilterPath} Size={info.Length}",
                    });
                }
            }
            catch (IOException) { }
        }

        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var pf in Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var pfName = Path.GetFileName(pf).ToUpperInvariant();
                if (pfName.StartsWith("RICOCHET_BYPASS", StringComparison.OrdinalIgnoreCase) ||
                    pfName.StartsWith("WDFILTER_BYPASS", StringComparison.OrdinalIgnoreCase) ||
                    pfName.StartsWith("WZ_BYPASS", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "Fortnite-Warzone-Cheat",
                        Title = $"Ricochet-Bypass-Prefetch: {Path.GetFileName(pf)}",
                        Risk = RiskLevel.High,
                        Location = pf,
                        FileName = Path.GetFileName(pf),
                        Reason = $"Windows-Prefetch fuer Ricochet-Bypass-Tool gefunden: '{Path.GetFileName(pf)}'. " +
                                 "Beweist die vorherige Ausfuehrung dieses Tools.",
                        Detail = $"PrefetchFile={pf}",
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private static void ScanSkinChangerVbucksFiles(ScanContext ctx, CancellationToken ct)
    {
        var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        foreach (var baseDir in new[] { desktopDir, downloadsDir })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    foreach (var known in SkinChangerVbucksExeNames)
                    {
                        if (!fname.Equals(known, StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Fortnite-Warzone-Cheat",
                            Title = $"Fortnite Skin-Changer / V-Bucks Hack: {fname}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = fname,
                            Reason = $"Datei '{fname}' ist ein bekanntes Fortnite Skin-Changer- oder V-Bucks-Hack-Tool. " +
                                     "Solche Tools sind haeufig Malware und indizieren Betrugsversuche.",
                            Detail = $"Path={file}",
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.py", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file).ToLowerInvariant();
                    if (!fname.Contains("fortnite", StringComparison.OrdinalIgnoreCase)) continue;

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = sr.ReadToEnd();
                        var lower = content.ToLowerInvariant();

                        bool hasVbucksOrSkin = lower.Contains("vbucks") || lower.Contains("skin");
                        bool hasRequest = lower.Contains("request") || lower.Contains("api");

                        if (hasVbucksOrSkin && hasRequest)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Fortnite-Warzone-Cheat",
                                Title = $"Fortnite Python-Cheat-Skript: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Python-Skript '{Path.GetFileName(file)}' enthaelt Fortnite + vbucks/skin + request/api-Muster. " +
                                         "Deutet auf ein V-Bucks-Generator- oder Account-Diebstahl-Skript hin.",
                                Detail = $"Path={file}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var procs = ctx.GetProcessSnapshot();

        bool fortniteRunning = false;
        bool warzoneRunning = false;
        var activeCheatProcesses = new List<(string Name, int Id, string Path)>();

        foreach (var proc in procs)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();
            var pname = proc.ProcessName;
            var pnameLower = pname.ToLowerInvariant();
            var pnameExe = pnameLower + ".exe";

            foreach (var gameExe in FortniteGameExeNames)
            {
                if (pnameExe.Equals(gameExe, StringComparison.OrdinalIgnoreCase))
                {
                    fortniteRunning = true;
                    break;
                }
            }

            foreach (var gameExe in WarzoneGameExeNames)
            {
                if (pnameExe.Equals(gameExe, StringComparison.OrdinalIgnoreCase))
                {
                    warzoneRunning = true;
                    break;
                }
            }

            foreach (var cheatExe in AllCheatExeNames)
            {
                if (!pnameExe.Equals(cheatExe, StringComparison.OrdinalIgnoreCase)) continue;
                string procPath = string.Empty;
                try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                activeCheatProcesses.Add((pname, proc.Id, procPath));
                break;
            }
        }

        foreach (var (name, id, path) in activeCheatProcesses)
        {
            var isFortniteCheat = FortniteCheatExeNames.Any(e =>
                e.Equals(name + ".exe", StringComparison.OrdinalIgnoreCase));
            var isWarzoneCheat = WarzoneCheatExeNames.Any(e =>
                e.Equals(name + ".exe", StringComparison.OrdinalIgnoreCase));

            bool gameActive = (isFortniteCheat && fortniteRunning) || (isWarzoneCheat && warzoneRunning);
            var risk = gameActive ? RiskLevel.Critical : RiskLevel.High;
            var gameContext = gameActive
                ? " — SPIEL IST GLEICHZEITIG AKTIV (aktive Cheat-Sitzung wahrscheinlich)"
                : "";

            ctx.AddFinding(new Finding
            {
                Module = "Fortnite-Warzone-Cheat",
                Title = $"Cheat-Prozess laeuft: {name}",
                Risk = risk,
                Location = path,
                FileName = name + ".exe",
                Reason = $"Bekannter Fortnite/Warzone-Cheat-Prozess '{name}' ist aktiv{gameContext}.",
                Detail = $"PID={id} Path={path} FortniteRunning={fortniteRunning} WarzoneRunning={warzoneRunning}",
            });
        }
    }

    private static void ScanPrefetchFiles(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var pf in Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var pfName = Path.GetFileName(pf).ToUpperInvariant();

                foreach (var pattern in PrefetchPatterns)
                {
                    if (!pfName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module = "Fortnite-Warzone-Cheat",
                        Title = $"Fortnite/Warzone Cheat-Prefetch: {Path.GetFileName(pf)}",
                        Risk = RiskLevel.High,
                        Location = pf,
                        FileName = Path.GetFileName(pf),
                        Reason = $"Windows-Prefetch-Datei '{Path.GetFileName(pf)}' beweist frueheres Ausfuehren " +
                                 $"eines Fortnite/Warzone-Cheat-Tools (Muster: {pattern}).",
                        Detail = $"PrefetchFile={pf} Pattern={pattern}",
                    });
                    break;
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }
}
