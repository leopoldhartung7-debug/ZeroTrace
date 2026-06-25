using System.Diagnostics;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class DirectXHookCheatScanModule : IScanModule
{
    public string Name => "DirectX Hook / ESP Overlay";
    public double Weight => 0.7;
    public int ParallelGroup => 4;

    private static readonly HashSet<string> KnownEspExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "reshade.exe", "reshadesetup.exe", "d3dcompiler_injector.exe", "dxhook.exe",
        "d3dhook.exe", "dx11hook.exe", "dx12hook.exe", "swapchain_hook.exe",
        "present_hook.exe", "overlayrenderer.exe", "esprenderer.exe",
        "wallhack_overlay.exe", "gdi_overlay.exe", "nuklearoverlay.exe",
        "imgui_overlay.exe", "directx_esp.exe", "opengl_esp.exe", "vulkan_esp.exe"
    };

    private static readonly string[] ProxyDllNames =
    {
        "d3d11.dll", "d3d9.dll", "d3d8.dll", "dxgi.dll",
        "opengl32.dll", "vulkan-1.dll"
    };

    private static readonly long ProxyDllSizeThreshold = 500 * 1024; // 500 KB

    private static readonly string[] ReShadeConfigFiles =
    {
        "reshade.ini", "ReShade.log", "dxgi.log"
    };

    private static readonly string[] CheatShaderKeywords =
    {
        "ESP", "wallhack", "aimbot", "cheat", "radar", "bone",
        "PlayerESP", "EnemyESP", "Distance", "Health", "hitbox"
    };

    private static readonly string[] ImGuiCheatWindowNames =
    {
        "ESP Settings", "Aimbot", "Wallhack", "Player ESP", "Bone ESP",
        "Radar", "Triggerbot", "Speedhack", "Bhop"
    };

    private static readonly string[] ImGuiConfigFileNames =
    {
        "imgui.ini", "imgui_settings.ini", "imgui_style.ini",
        "nuklear_config.json", "overlay_config.json", "esp_config.json",
        "d3dhook.ini", "dxhook.cfg", "swapchain.ini"
    };

    private static readonly string[] ProcessCmdLineFlags =
    {
        "--d3d", "--hook", "--inject", "--overlay"
    };

    private static readonly string[] SuspiciousWindowTitleKeywords =
    {
        "ESP", "Overlay", "Hook", "Radar", "Aimbot"
    };

    private static readonly string[] OfficialObsPlugins = new[]
    {
        "obs-browser.dll", "obs-ffmpeg.dll", "obs-filters.dll", "obs-outputs.dll",
        "obs-transitions.dll", "obs-x264.dll", "obs-qsv11.dll", "obs-nvenc.dll",
        "rtmp-services.dll", "win-capture.dll", "win-dshow.dll", "win-mf.dll",
        "frontend-tools.dll", "image-source.dll", "text-freetype2.dll",
        "vlc-video.dll", "coreaudio-encoder.dll", "decklink-captions.dll",
        "decklink-output-ui.dll"
    };

    private static readonly HashSet<string> OfficialObsPluginSet =
        new(OfficialObsPlugins, StringComparer.OrdinalIgnoreCase);

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanUserDirectoriesForEspExeAsync(ctx, ct);
        ctx.Report(0.15, "ESP EXE scan", "Bekannte ESP-Tool-Executables gesucht");

        await ScanGtaVDirectoryAsync(ctx, ct);
        ctx.Report(0.30, "GTA V Proxy DLLs", "GTA V Verzeichnis auf Proxy-DLLs geprueft");

        await ScanFiveMDirectoryAsync(ctx, ct);
        ctx.Report(0.42, "FiveM Proxy DLLs", "FiveM Verzeichnis auf Proxy-DLLs geprueft");

        await ScanCs2DirectoryAsync(ctx, ct);
        ctx.Report(0.50, "CS2 Proxy DLLs", "CS2 Verzeichnis auf Proxy-DLLs geprueft");

        await ScanImGuiConfigFilesAsync(ctx, ct);
        ctx.Report(0.63, "ImGui Configs", "ImGui-Konfigurationsdateien geprueft");

        await ScanReShadeEspShadersAsync(ctx, ct);
        ctx.Report(0.74, "ReShade Shaders", "ReShade ESP-Shader gesucht");

        await ScanObsPluginsAsync(ctx, ct);
        ctx.Report(0.84, "OBS Plugins", "OBS-Plugins auf unbekannte DLLs geprueft");

        ScanRunningProcesses(ctx, ct);
        ctx.Report(0.93, "Prozesse", "Laufende Prozesse auf Hook-Tools geprueft");

        ScanRegistryArtifacts(ctx, ct);
        ctx.Report(1.0, "Registry", "Registry-Artefakte geprueft");
    }

    private async Task ScanUserDirectoriesForEspExeAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetUserSearchDirectories();

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*.exe", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (!KnownEspExeNames.Contains(fileName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Bekanntes DirectX/ESP-Hook-Tool: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes DirectX/Vulkan-Hook- oder " +
                             "ESP-Overlay-Tool. Solche Programme fangen den SwapChain/Present-Aufruf " +
                             "ab und rendern ESP-Overlays ueber das Spiel.",
                    Detail = $"Gefunden in: {dir}"
                });
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanGtaVDirectoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var gtaVPaths = new[]
        {
            @"C:\Program Files\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files (x86)\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files\Epic Games\GTAV"
        };

        foreach (var gtaDir in gtaVPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(gtaDir)) continue;

            await CheckProxyDllsInDirectoryAsync(gtaDir, "GTA V", ctx, ct);
            await CheckReShadeArtifactsAsync(gtaDir, "GTA V", ctx, ct);
            await ScanShaderFilesInDirAsync(gtaDir, "GTA V", ctx, ct);
        }
    }

    private async Task ScanFiveMDirectoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var fiveMPaths = new[]
        {
            @"C:\FiveM",
            @"C:\Games\FiveM",
            Path.Combine(localAppData, "FiveM")
        };

        foreach (var fiveMDir in fiveMPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(fiveMDir)) continue;

            await CheckProxyDllsInDirectoryAsync(fiveMDir, "FiveM", ctx, ct);
            await CheckFiveMCoreDllAsync(fiveMDir, ctx);
        }
    }

    private async Task CheckFiveMCoreDllAsync(string fiveMDir, ScanContext ctx)
    {
        var coreDll = Path.Combine(fiveMDir, "CitizenFX.Core.NativeImpl.dll");
        if (!File.Exists(coreDll)) return;

        ctx.IncrementFiles();
        try
        {
            var info = new FileInfo(coreDll);
            if (info.Length < 50 * 1024)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "FiveM Core-DLL verdaechtig klein (moegliche Proxy-DLL)",
                    Risk = RiskLevel.Critical,
                    Location = coreDll,
                    FileName = "CitizenFX.Core.NativeImpl.dll",
                    Reason = "CitizenFX.Core.NativeImpl.dll ist kleiner als 50 KB. " +
                             "Die legitime Datei ist deutlich groesser. Eine kleine Version " +
                             "deutet auf eine ausgetauschte Proxy-DLL hin, die zum Einschleusen " +
                             "von Cheat-Code in FiveM verwendet wird.",
                    Detail = $"Dateigroesse: {info.Length} Bytes (erwartet: >50 KB)"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }

    private async Task ScanCs2DirectoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var cs2Dir = @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64";
        if (!Directory.Exists(cs2Dir)) return;

        var suspiciousDlls = new[] { "tier0.dll", "vstdlib.dll", "game_shader_generic_vulkan_pc.dll" };
        foreach (var dllName in suspiciousDlls)
        {
            if (ct.IsCancellationRequested) break;
            var dllPath = Path.Combine(cs2Dir, dllName);
            if (!File.Exists(dllPath)) continue;

            ctx.IncrementFiles();
            try
            {
                var info = new FileInfo(dllPath);
                if (info.Length < 100 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige CS2-System-DLL: {dllName} (zu klein)",
                        Risk = RiskLevel.Critical,
                        Location = dllPath,
                        FileName = dllName,
                        Reason = $"Die CS2-Systemdatei '{dllName}' ist kleiner als 100 KB. " +
                                 "Legitime CS2-Systemdateien sind erheblich groesser. " +
                                 "Eine kleine Version deutet auf eine ausgetauschte Proxy-DLL hin, " +
                                 "die zum Einschleusen von Cheat-Code in CS2 verwendet werden kann.",
                        Detail = $"Dateigroesse: {info.Length} Bytes"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }

    private async Task CheckProxyDllsInDirectoryAsync(string gameDir, string gameName, ScanContext ctx, CancellationToken ct)
    {
        foreach (var dllName in ProxyDllNames)
        {
            if (ct.IsCancellationRequested) break;
            var dllPath = Path.Combine(gameDir, dllName);
            if (!File.Exists(dllPath)) continue;

            ctx.IncrementFiles();
            try
            {
                var info = new FileInfo(dllPath);
                if (info.Length < ProxyDllSizeThreshold)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Proxy-DLL im {gameName}-Verzeichnis: {dllName}",
                        Risk = RiskLevel.Critical,
                        Location = dllPath,
                        FileName = dllName,
                        Reason = $"Die Datei '{dllName}' im {gameName}-Verzeichnis ist kleiner als 500 KB " +
                                 $"({info.Length / 1024} KB). Die echte {dllName} ist deutlich groesser. " +
                                 "Kleine DLLs an diesem Ort sind ein klares Zeichen fuer eine Proxy-DLL, " +
                                 "die DirectX-Aufrufe abfaengt, um ESP/Wallhack-Overlays zu rendern.",
                        Detail = $"Dateigroesse: {info.Length} Bytes, Schwellenwert: {ProxyDllSizeThreshold} Bytes"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }

    private async Task CheckReShadeArtifactsAsync(string gameDir, string gameName, ScanContext ctx, CancellationToken ct)
    {
        foreach (var configFile in ReShadeConfigFiles)
        {
            if (ct.IsCancellationRequested) break;
            var configPath = Path.Combine(gameDir, configFile);
            if (!File.Exists(configPath)) continue;

            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"ReShade-Konfigurationsdatei im {gameName}-Verzeichnis: {configFile}",
                Risk = RiskLevel.High,
                Location = configPath,
                FileName = configFile,
                Reason = $"Die Datei '{configFile}' wurde im {gameName}-Verzeichnis gefunden. " +
                         "ReShade wird haeufig dazu missbraucht, ESP-Shader ueber Spiele zu rendern. " +
                         "ReShade-Konfigurationsdateien neben der Spiel-EXE deuten auf eine " +
                         "aktive ReShade-Installation hin.",
                Detail = $"Pfad: {configPath}"
            });
        }

        await Task.CompletedTask;
    }

    private async Task ScanShaderFilesInDirAsync(string dir, string context, ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(dir)) return;

        string[] shaderFiles = Array.Empty<string>();
        try
        {
            var fxFiles = Directory.GetFiles(dir, "*.fx", SearchOption.AllDirectories);
            var fxhFiles = Directory.GetFiles(dir, "*.fxh", SearchOption.AllDirectories);
            shaderFiles = fxFiles.Concat(fxhFiles).ToArray();
        }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var shaderFile in shaderFiles)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementFiles();

            try
            {
                string content;
                using var sr = new StreamReader(shaderFile);
                content = await sr.ReadToEndAsync();

                var lowerContent = content.ToLowerInvariant();
                var matchedKeywords = CheatShaderKeywords
                    .Where(k => lowerContent.Contains(k.ToLowerInvariant()))
                    .ToList();

                if (matchedKeywords.Count >= 2)
                {
                    var fileName = Path.GetFileName(shaderFile);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"ESP-Shader-Datei im {context}-Bereich: {fileName}",
                        Risk = RiskLevel.High,
                        Location = shaderFile,
                        FileName = fileName,
                        Reason = $"Die Shader-Datei '{fileName}' enthaelt mehrere Schluesselbegriffe, " +
                                 "die auf einen ESP/Wallhack-Shader hinweisen: " +
                                 string.Join(", ", matchedKeywords) + ". " +
                                 "Cheat-Shader nutzen DirectX-Texturoperationen kombiniert mit " +
                                 "UI-Zeichenaufrufen, um Spielerinformationen durchzusehen.",
                        Detail = $"Gefundene Keywords: {string.Join(", ", matchedKeywords)}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private async Task ScanImGuiConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetUserSearchDirectories();

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            foreach (var configName in ImGuiConfigFileNames)
            {
                if (ct.IsCancellationRequested) break;

                string configPath;
                try
                {
                    var matches = Directory.GetFiles(dir, configName, SearchOption.AllDirectories);
                    if (matches.Length == 0) continue;
                    configPath = matches[0];
                }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                ctx.IncrementFiles();

                try
                {
                    string content;
                    using var sr = new StreamReader(configPath);
                    content = await sr.ReadToEndAsync();

                    var matchedWindows = ImGuiCheatWindowNames
                        .Where(w => content.Contains(w, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedWindows.Count > 0)
                    {
                        var fileName = Path.GetFileName(configPath);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ImGui-Konfiguration mit Cheat-Fensternamen: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = configPath,
                            FileName = fileName,
                            Reason = $"Die ImGui-Konfigurationsdatei '{fileName}' enthaelt Fensternamen, " +
                                     "die bekannten Cheat-Benutzeroberflaechen entsprechen: " +
                                     string.Join(", ", matchedWindows) + ". " +
                                     "ImGui-basierte Overlays sind die haeufigste Implementierung " +
                                     "moderner ESP/Aimbot-Cheat-UIs.",
                            Detail = $"Gefundene Cheat-Fenster: {string.Join(", ", matchedWindows)}"
                        });
                    }
                    else if (configName.Equals("imgui.ini", StringComparison.OrdinalIgnoreCase) ||
                             configName.EndsWith("_config.json", StringComparison.OrdinalIgnoreCase))
                    {
                        var espKeywords = new[] { "esp", "aimbot", "wallhack", "radar", "cheat" };
                        var matchedEsp = espKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matchedEsp.Count > 0)
                        {
                            var fileName = Path.GetFileName(configPath);
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"ESP/Overlay-Konfigurationsdatei: {fileName}",
                                Risk = RiskLevel.Medium,
                                Location = configPath,
                                FileName = fileName,
                                Reason = $"Die Konfigurationsdatei '{fileName}' enthaelt Schluesselbegriffe " +
                                         "die auf ein Cheat-Overlay hinweisen: " +
                                         string.Join(", ", matchedEsp) + ".",
                                Detail = $"Gefundene Keywords: {string.Join(", ", matchedEsp)}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
    }

    private async Task ScanReShadeEspShadersAsync(ScanContext ctx, CancellationToken ct)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var reshadeShaderDir = Path.Combine(roamingAppData, "ReShade", "Shaders");

        if (Directory.Exists(reshadeShaderDir))
        {
            await ScanShaderFilesInDirAsync(reshadeShaderDir, "ReShade Shaders", ctx, ct);
        }

        var gtaVPaths = new[]
        {
            @"C:\Program Files\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files (x86)\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files\Epic Games\GTAV"
        };

        foreach (var gtaDir in gtaVPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(gtaDir)) continue;

            var reshadeDir = Path.Combine(gtaDir, "reshade-shaders");
            if (Directory.Exists(reshadeDir))
            {
                await ScanShaderFilesInDirAsync(reshadeDir, "GTA V ReShade", ctx, ct);
            }
        }
    }

    private async Task ScanObsPluginsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var obsPluginsDir = Path.Combine(roamingAppData, "obs-studio", "plugins");

        if (Directory.Exists(obsPluginsDir))
        {
            string[] pluginDlls = Array.Empty<string>();
            try { pluginDlls = Directory.GetFiles(obsPluginsDir, "*.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { }
            catch { }

            foreach (var dllPath in pluginDlls)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var dllName = Path.GetFileName(dllPath);
                if (OfficialObsPluginSet.Contains(dllName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Unbekanntes OBS-Plugin: {dllName}",
                    Risk = RiskLevel.Medium,
                    Location = dllPath,
                    FileName = dllName,
                    Reason = $"Die DLL '{dllName}' im OBS-Plugin-Verzeichnis ist nicht in der Liste " +
                             "bekannter offizieller OBS-Plugins. Cheater nutzen OBS-Plugins, um " +
                             "Cheats nur auf dem lokalen Display zu rendern (nicht im Stream), " +
                             "oder um die Spielaufzeichnung zu manipulieren.",
                    Detail = $"Plugin-Pfad: {dllPath}"
                });
            }
        }

        var obsScenesDir = Path.Combine(roamingAppData, "obs-studio", "basic", "scenes");
        if (Directory.Exists(obsScenesDir))
        {
            string[] sceneFiles = Array.Empty<string>();
            try { sceneFiles = Directory.GetFiles(obsScenesDir, "*.json"); }
            catch (UnauthorizedAccessException) { }
            catch { }

            foreach (var sceneFile in sceneFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                try
                {
                    string content;
                    using var sr = new StreamReader(sceneFile);
                    content = await sr.ReadToEndAsync();

                    var suspiciousPatterns = new[] { "game_capture", "window_capture", "pixel" };
                    var matchedPatterns = suspiciousPatterns
                        .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedPatterns.Count >= 2 &&
                        content.Contains("cheat", StringComparison.OrdinalIgnoreCase))
                    {
                        var fileName = Path.GetFileName(sceneFile);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige OBS-Szenen-Konfiguration: {fileName}",
                            Risk = RiskLevel.Medium,
                            Location = sceneFile,
                            FileName = fileName,
                            Reason = "Die OBS-Szenen-Konfiguration enthaelt verdaechtige Quellen, " +
                                     "die auf Manipulation der Spielaufzeichnung hindeuten koennen.",
                            Detail = $"Gefundene Muster: {string.Join(", ", matchedPatterns)}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }

        await Task.CompletedTask;
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementProcesses();

            try
            {
                var procName = proc.ProcessName + ".exe";
                var procPath = string.Empty;
                var procCmdLine = string.Empty;

                try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                if (KnownEspExeNames.Contains(procName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekanntes ESP/Hook-Tool laeuft: {procName}",
                        Risk = RiskLevel.Critical,
                        Location = procPath.Length > 0 ? procPath : $"PID {proc.Id}",
                        FileName = procName,
                        Reason = $"Der Prozess '{procName}' (PID {proc.Id}) ist ein bekanntes " +
                                 "DirectX/ESP-Hook-Tool, das aktiv laeuft. Dies ist ein starkes " +
                                 "Indiz fuer eine aktive Cheat-Sitzung.",
                        Detail = $"PID: {proc.Id}, Pfad: {(procPath.Length > 0 ? procPath : "unbekannt")}"
                    });
                    continue;
                }

                if (!string.IsNullOrEmpty(procPath))
                {
                    var pathLower = procPath.ToLowerInvariant();
                    var isFromTempOrAppdata = pathLower.Contains(@"\temp\") ||
                                             pathLower.Contains(@"\appdata\local\temp\");

                    if (isFromTempOrAppdata)
                    {
                        try
                        {
                            var mainWindowTitle = proc.MainWindowTitle;
                            if (!string.IsNullOrEmpty(mainWindowTitle))
                            {
                                var matchedTitle = SuspiciousWindowTitleKeywords
                                    .FirstOrDefault(k => mainWindowTitle.Contains(k, StringComparison.OrdinalIgnoreCase));

                                if (matchedTitle != null)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Prozess aus Temp mit verdaechtigem Fenstertitel: {procName}",
                                        Risk = RiskLevel.High,
                                        Location = procPath,
                                        FileName = procName,
                                        Reason = $"Der Prozess '{procName}' laeuft aus einem Temp-Verzeichnis " +
                                                 $"und hat einen Fenstertitel, der auf ein Cheat-Overlay hindeutet: " +
                                                 $"'{mainWindowTitle}'. Cheat-Overlays starten haeufig aus Temp-Pfaden.",
                                        Detail = $"Fenstertitel: '{mainWindowTitle}', Pfad: {procPath}"
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                }

                try
                {
                    var cmdLine = GetProcessCommandLine(proc);
                    if (!string.IsNullOrEmpty(cmdLine))
                    {
                        var matchedFlag = ProcessCmdLineFlags
                            .FirstOrDefault(f => cmdLine.Contains(f, StringComparison.OrdinalIgnoreCase));

                        if (matchedFlag != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Prozess mit Hook/Inject-Befehlszeilen-Flag: {procName}",
                                Risk = RiskLevel.High,
                                Location = procPath.Length > 0 ? procPath : $"PID {proc.Id}",
                                FileName = procName,
                                Reason = $"Der Prozess '{procName}' wurde mit dem verdaechtigen Flag " +
                                         $"'{matchedFlag}' gestartet. Diese Flags werden von DirectX-Hook- " +
                                         "und Inject-Tools verwendet.",
                                Detail = $"Befehlszeile: {cmdLine.Substring(0, Math.Min(200, cmdLine.Length))}"
                            });
                        }
                    }
                }
                catch { }
            }
            catch { }
        }
    }

    private static string GetProcessCommandLine(Process proc)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId={proc.Id}");
            foreach (System.Management.ManagementObject obj in searcher.Get())
            {
                return obj["CommandLine"]?.ToString() ?? string.Empty;
            }
        }
        catch { }
        return string.Empty;
    }

    private void ScanRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        CheckReShadeRegistry(ctx);
        if (ct.IsCancellationRequested) return;

        CheckObsRegistryArtifacts(ctx);
        if (ct.IsCancellationRequested) return;

        CheckNvTweakRegistry(ctx);
    }

    private void CheckReShadeRegistry(ScanContext ctx)
    {
        try
        {
            using var reShadeKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\ReShade");
            if (reShadeKey == null) return;

            ctx.IncrementRegistryKeys();

            var valueNames = reShadeKey.GetValueNames();
            var gamePaths = valueNames
                .Select(n => reShadeKey.GetValue(n)?.ToString())
                .Where(v => !string.IsNullOrEmpty(v) && v!.Contains(".exe", StringComparison.OrdinalIgnoreCase))
                .ToList();

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "ReShade in der Registry registriert",
                Risk = RiskLevel.High,
                Location = @"HKCU\SOFTWARE\ReShade",
                Reason = "ReShade ist in der Benutzerkonfiguration registriert. ReShade wird " +
                         "haeufig dazu missbraucht, ESP/Wallhack-Shader in Spiele zu injizieren. " +
                         "Die Registry-Eintraege zeigen, fuer welche Spiele ReShade konfiguriert ist.",
                Detail = gamePaths.Count > 0
                    ? $"Registrierte Spielpfade: {string.Join("; ", gamePaths.Take(5))}"
                    : $"Schluessel vorhanden mit {valueNames.Length} Wert(en)"
            });
        }
        catch { }
    }

    private void CheckObsRegistryArtifacts(ScanContext ctx)
    {
        try
        {
            using var obsKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\OBS Studio");
            if (obsKey == null) return;

            ctx.IncrementRegistryKeys();

            var valueNames = obsKey.GetValueNames();
            var suspiciousValues = valueNames
                .Where(n => n.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            n.Contains("hook", StringComparison.OrdinalIgnoreCase) ||
                            n.Contains("inject", StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (suspiciousValues.Count > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Verdaechtige OBS-Konfiguration in der Registry",
                    Risk = RiskLevel.Medium,
                    Location = @"HKCU\SOFTWARE\OBS Studio",
                    Reason = "Die OBS Studio-Registry-Konfiguration enthaelt verdaechtige Wertnamen. " +
                             "OBS-Plugins koennen missbraucht werden, um Cheat-Overlays nur " +
                             "lokal anzuzeigen (nicht im Stream).",
                    Detail = $"Verdaechtige Schluessel: {string.Join(", ", suspiciousValues)}"
                });
            }
        }
        catch { }
    }

    private void CheckNvTweakRegistry(ScanContext ctx)
    {
        try
        {
            using var nvTweakKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\NVIDIA Corporation\Global\NvTweak");
            if (nvTweakKey == null) return;

            ctx.IncrementRegistryKeys();

            var overlayEnabled = nvTweakKey.GetValue("Ovlbar")?.ToString();
            if (overlayEnabled != null &&
                (overlayEnabled == "0" || overlayEnabled.Equals("false", StringComparison.OrdinalIgnoreCase)))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "NVIDIA-Overlay deaktiviert (moegliche Anti-Detection-Massnahme)",
                    Risk = RiskLevel.Medium,
                    Location = @"HKCU\SOFTWARE\NVIDIA Corporation\Global\NvTweak",
                    Reason = "Das NVIDIA-Overlay ist in der Registry deaktiviert. Cheater " +
                             "deaktivieren haeufig GeForce Experience-Overlays, um Konflikte " +
                             "mit ihren eigenen Cheat-Overlays zu vermeiden oder um die " +
                             "Anti-Cheat-Erkennung zu umgehen.",
                    Detail = $"Ovlbar-Wert: {overlayEnabled}"
                });
            }
        }
        catch { }
    }

    private static IEnumerable<string> GetUserSearchDirectories()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var appDataLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(Path.GetTempPath()),
            appDataRoaming,
            appDataLocal,
            documents,
            @"C:\Program Files",
            @"C:\Program Files (x86)"
        };
    }
}
