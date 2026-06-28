using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class GameRecordingCheatEvidenceForensicScanModule : IScanModule
{
    public string Name => "Game Recording Cheat Evidence Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] RecordingOutputDirs = { @"Videos\Captures", @"Videos\Medal", @"Videos\Plays.gg", @"Videos\AMD ReLive", @"Videos\Intel" };
    private static readonly string[] RecordingAppDirs = { @"NVIDIA Corporation\NvBackend", @"obs-studio", @"slobs-client", @"Medal", @"Plays.gg", @"Insights", @"Overwolf" };
    private static readonly string[] GameRecordingPatterns = { "GTA5_", "FiveM_", "RAGEMP_", "altv_", "GrandTheftAuto", "FiveM", "RAGE_" };
    private static readonly string[] VideoExtensions = { ".mp4", ".mkv", ".avi", ".flv", ".webm", ".mov", ".wmv" };
    private static readonly string[] RecordingRegistryKeys = { @"Software\NVIDIA Corporation\NvBackend", @"Software\Medal", @"Software\Plays.gg", @"Software\Overwolf", @"Software\AMD\DVR" };
    private static readonly string[] RecordingBypassToolNames = { "block_obs.dll", "obs_bypass.dll", "capture_bypass.dll", "recording_blocker.exe" };
    private static readonly string[] RecordingBypssRegKeys = { @"Software\OBSBypass", @"Software\RecordingBlocker", @"Software\CaptureBypass" };
    private static readonly string[] OBSSceneGameSources = { "GTA5.exe", "FiveM.exe", "RAGE Multiplayer.exe", "altv.exe", "RageMP.exe" };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckNVIDIAGeForceRecordingArtifacts(ctx, ct),
            CheckXboxGameBarArtifacts(ctx, ct),
            CheckOBSStudioArtifacts(ctx, ct),
            CheckShadowPlayRecordingHistory(ctx, ct),
            CheckDiscordVideoArtifacts(ctx, ct),
            CheckStreamlabsArtifacts(ctx, ct),
            CheckShadowRecorderArtifacts(ctx, ct),
            CheckMedalTVArtifacts(ctx, ct),
            CheckPlaysGGArtifacts(ctx, ct),
            CheckInnReplayArtifacts(ctx, ct),
            CheckDeletedRecordingArtifacts(ctx, ct),
            CheckWindowsClipArtifacts(ctx, ct),
            CheckRecordingMetadataArtifacts(ctx, ct),
            CheckStreamingPlatformArtifacts(ctx, ct),
            CheckAMDReliveArtifacts(ctx, ct),
            CheckIntelArcControlArtifacts(ctx, ct),
            CheckRecordingHidingToolsArtifacts(ctx, ct),
            CheckVideoFileNamingPatternArtifacts(ctx, ct)
        );
    }

    private Task CheckNVIDIAGeForceRecordingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        string[] videoDirs = new[]
        {
            Path.Combine(userProfile, "Videos"),
            Path.Combine(@"C:\Users\Public", "Videos")
        };

        foreach (string videoDir in videoDirs)
        {
            if (!Directory.Exists(videoDir)) continue;
            try
            {
                foreach (string file in Directory.GetFiles(videoDir, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    string ext = Path.GetExtension(file);
                    if (!VideoExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase))) continue;

                    string fileName = Path.GetFileName(file);
                    bool isGameRecording = GameRecordingPatterns.Any(p =>
                        fileName.StartsWith(p, StringComparison.OrdinalIgnoreCase)) ||
                        fileName.StartsWith("Desktop ", StringComparison.OrdinalIgnoreCase);

                    if (isGameRecording)
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"NVIDIA GeForce Game Recording Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = "NVIDIA GeForce Experience (Shadowplay) recording of GTA5 or FiveM gameplay detected. GeForce Experience automatically records game highlights and may have captured cheat usage during the session.",
                            Detail = $"Path: {file} | Size: {new FileInfo(file).Length} bytes"
                        });
                    }
                }
            }
            catch { }
        }

        try
        {
            string nvBackendConfig = Path.Combine(roamingAppData, "NVIDIA Corporation", "NvBackend");
            if (Directory.Exists(nvBackendConfig))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "NVIDIA GeForce Experience NvBackend Config Directory Found",
                    Risk = RiskLevel.Medium,
                    Location = nvBackendConfig,
                    FileName = "NvBackend",
                    Reason = "NVIDIA GeForce Experience NvBackend configuration directory found. NvBackend manages Shadowplay recording settings; its presence confirms GeForce Experience is or was installed and may have been recording gameplay sessions.",
                    Detail = $"Path: {nvBackendConfig}"
                });
            }
        }
        catch { }

        try
        {
            using var nvKey = Registry.CurrentUser.OpenSubKey(@"Software\NVIDIA Corporation\NvBackend", writable: false);
            ctx.IncrementRegistryKeys();
            if (nvKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "NVIDIA GeForce Experience NvBackend Registry Key Found",
                    Risk = RiskLevel.Medium,
                    Location = @"HKCU\Software\NVIDIA Corporation\NvBackend",
                    FileName = null,
                    Reason = "NVIDIA GeForce Experience NvBackend registry key found. This key records GeForce Experience configuration including Shadowplay recording settings and may reflect enabled recording during GTA5 or FiveM sessions.",
                    Detail = @"Registry: HKCU\Software\NVIDIA Corporation\NvBackend"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckXboxGameBarArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        string capturesDir = Path.Combine(userProfile, "Videos", "Captures");
        try
        {
            if (Directory.Exists(capturesDir))
            {
                foreach (string file in Directory.GetFiles(capturesDir, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    string ext = Path.GetExtension(file);
                    if (!VideoExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase))) continue;

                    string fileName = Path.GetFileName(file);
                    bool isGameRecording = GameRecordingPatterns.Any(p =>
                        fileName.Contains(p, StringComparison.OrdinalIgnoreCase));

                    ctx.IncrementFiles();
                    if (isGameRecording)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Xbox Game Bar GTA/FiveM Capture Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = "Xbox Game Bar (Win+G) video capture of GTA5 or FiveM gameplay found. These recordings may capture cheat tools, menus, or gameplay indicators visible during the recorded session.",
                            Detail = $"Path: {file} | Captures directory: {capturesDir}"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            string gamingOverlayPkg = Path.Combine(localAppData, "Packages",
                "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe");
            if (Directory.Exists(gamingOverlayPkg))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Xbox Gaming Overlay (Game Bar) Package Data Found",
                    Risk = RiskLevel.Low,
                    Location = gamingOverlayPkg,
                    FileName = "Microsoft.XboxGamingOverlay_8wekyb3d8bbwe",
                    Reason = "Xbox Gaming Overlay package data directory found. Xbox Game Bar captures game recordings and screenshots; its presence confirms the recording feature was available during game sessions.",
                    Detail = $"Path: {gamingOverlayPkg}"
                });
            }
        }
        catch { }

        try
        {
            using var gameDvrKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\GameDVR", writable: false);
            ctx.IncrementRegistryKeys();
            if (gameDvrKey is not null)
            {
                string appCaptureEnabled = (gameDvrKey.GetValue("AppCaptureEnabled") as string) ?? string.Empty;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Xbox GameDVR Registry Key Found",
                    Risk = RiskLevel.Medium,
                    Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR",
                    FileName = null,
                    Reason = $"Xbox GameDVR registry key found with AppCaptureEnabled='{appCaptureEnabled}'. GameDVR records game sessions via Win+G; recordings of GTA5 or FiveM sessions may contain forensic evidence of cheat usage.",
                    Detail = $"AppCaptureEnabled: {appCaptureEnabled}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckOBSStudioArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string obsDir = Path.Combine(roamingAppData, "obs-studio");

        if (!Directory.Exists(obsDir)) return;

        string scenesDir = Path.Combine(obsDir, "basic", "scenes");
        try
        {
            if (Directory.Exists(scenesDir))
            {
                foreach (string sceneFile in Directory.GetFiles(scenesDir, "*.json", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(sceneFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        string matchedSource = OBSSceneGameSources.FirstOrDefault(s =>
                            content.Contains(s, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                        if (!string.IsNullOrEmpty(matchedSource))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"OBS Scene Config Captures Game: {Path.GetFileName(sceneFile)}",
                                Risk = RiskLevel.Medium,
                                Location = sceneFile,
                                FileName = Path.GetFileName(sceneFile),
                                Reason = $"OBS Studio scene configuration file contains a game capture source for '{matchedSource}'. This confirms OBS was configured to record or stream GTA5 or FiveM gameplay, and existing recordings may contain evidence of cheat usage.",
                                Detail = $"Scene file: {sceneFile} | Game source: {matchedSource}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        string profilesDir = Path.Combine(obsDir, "basic", "profiles");
        try
        {
            if (Directory.Exists(profilesDir))
            {
                foreach (string iniFile in Directory.GetFiles(profilesDir, "basic.ini", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(iniFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (string line in lines)
                        {
                            if (line.StartsWith("RecFilePath=", StringComparison.OrdinalIgnoreCase) ||
                                line.StartsWith("FilenameFormatting=", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"OBS Recording Output Path Found: {Path.GetFileName(iniFile)}",
                                    Risk = RiskLevel.Medium,
                                    Location = iniFile,
                                    FileName = Path.GetFileName(iniFile),
                                    Reason = $"OBS Studio profile configuration specifies a recording output path: '{line.Trim()}'. OBS recording output directories may contain game session recordings capturing cheat activity.",
                                    Detail = $"Profile: {iniFile} | Setting: {line.Trim()}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        string globalIniPath = Path.Combine(obsDir, "global.ini");
        try
        {
            if (File.Exists(globalIniPath))
            {
                ctx.IncrementFiles();
                using var fs = new FileStream(globalIniPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                if (content.Contains("RecFilePath", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("OutputPath", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "OBS Studio Global Config with Recording Path Found",
                        Risk = RiskLevel.Medium,
                        Location = globalIniPath,
                        FileName = "global.ini",
                        Reason = "OBS Studio global.ini configuration file found with recording output path settings. The configured output path may contain recordings of FiveM or GTA5 sessions that captured cheat tool usage.",
                        Detail = $"Path: {globalIniPath}"
                    });
                }
            }
        }
        catch { }

        string logsDir = Path.Combine(obsDir, "logs");
        try
        {
            if (Directory.Exists(logsDir))
            {
                string[] logFiles = Directory.GetFiles(logsDir, "*.txt", SearchOption.TopDirectoryOnly);
                if (logFiles.Length > 0)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"OBS Studio Log Files Found ({logFiles.Length} logs)",
                        Risk = RiskLevel.Low,
                        Location = logsDir,
                        FileName = Path.GetFileName(logFiles[0]),
                        Reason = $"OBS Studio log files found ({logFiles.Length} total). OBS logs record all recording and streaming sessions with timestamps; log entries correlating with known cheat usage times constitute forensic evidence of cheat activity being recorded.",
                        Detail = $"Log directory: {logsDir} | Log count: {logFiles.Length}"
                    });
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckShadowPlayRecordingHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        string[] shadowPlayDirs = new[]
        {
            Path.Combine(userProfile, "Videos"),
            Path.Combine(programData, "NVIDIA Corporation")
        };

        foreach (string dir in shadowPlayDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (string file in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    string ext = Path.GetExtension(file);
                    if (!VideoExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase))) continue;

                    string fileName = Path.GetFileName(file);
                    bool isGameRecording = GameRecordingPatterns.Any(p =>
                        fileName.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (isGameRecording)
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"NVIDIA Shadowplay Game Recording Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = "NVIDIA Shadowplay shadow replay buffer clip or recording of GTA5 or FiveM found. Shadowplay clips capture the last minutes of gameplay continuously and may contain footage of cheat menus, aimbot behavior, or other cheat indicators.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch { }
        }

        try
        {
            using var nvNodeKey = Registry.CurrentUser.OpenSubKey(
                @"Software\NVIDIA Corporation\NvNode\Application", writable: false);
            ctx.IncrementRegistryKeys();
            if (nvNodeKey is not null)
            {
                foreach (string subKeyName in nvNodeKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    bool isGameApp = OBSSceneGameSources.Any(s =>
                        subKeyName.Contains(s.Replace(".exe", string.Empty), StringComparison.OrdinalIgnoreCase)) ||
                        GameRecordingPatterns.Any(p =>
                        subKeyName.Contains(p.TrimEnd('_'), StringComparison.OrdinalIgnoreCase));

                    if (isGameApp)
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"NVIDIA Shadowplay Recorded Game Session: {subKeyName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\Software\NVIDIA Corporation\NvNode\Application\{subKeyName}",
                            FileName = null,
                            Reason = $"NVIDIA Shadowplay NvNode registry records a session for game application '{subKeyName}'. This confirms NVIDIA Shadowplay tracked and potentially recorded this game session; recordings may contain cheat evidence.",
                            Detail = $"Registry subkey: {subKeyName}"
                        });
                    }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDiscordVideoArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        string discordCacheDir = Path.Combine(roamingAppData, "discord", "Cache");
        try
        {
            if (Directory.Exists(discordCacheDir))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Discord Cache Directory Found",
                    Risk = RiskLevel.Low,
                    Location = discordCacheDir,
                    FileName = "Cache",
                    Reason = "Discord cache directory found. Discord caches media from shared content including game clips; cached video thumbnails or metadata may reference GTA5 or FiveM streams shared in Discord that captured cheat usage.",
                    Detail = $"Path: {discordCacheDir}"
                });
            }
        }
        catch { }

        string discordLocalStorage = Path.Combine(roamingAppData, "discord", "Local Storage");
        try
        {
            if (Directory.Exists(discordLocalStorage))
            {
                foreach (string file in Directory.GetFiles(discordLocalStorage, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasGameRef = GameRecordingPatterns.Any(p =>
                            content.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (hasGameRef)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Discord Local Storage References Game Recording: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Discord local storage data references GTA5 or FiveM game content. Discord local storage may contain references to shared game clips or screen captures of cheat usage shared in Discord servers.",
                                Detail = $"Path: {file}"
                            });
                            break;
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckStreamlabsArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string slobsDir = Path.Combine(roamingAppData, "slobs-client");

        if (Directory.Exists(slobsDir))
        {
            try
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Streamlabs Desktop (SLOBS) Config Directory Found",
                    Risk = RiskLevel.Medium,
                    Location = slobsDir,
                    FileName = "slobs-client",
                    Reason = "Streamlabs Desktop (formerly Streamlabs OBS) configuration directory found. Streamlabs is used for game streaming and recording; its presence indicates GTA5 or FiveM sessions may have been recorded or streamed, capturing cheat usage.",
                    Detail = $"Path: {slobsDir}"
                });

                string[] sceneFiles = Directory.GetFiles(slobsDir, "*.json", SearchOption.AllDirectories);
                foreach (string sceneFile in sceneFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(sceneFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        string matchedSource = OBSSceneGameSources.FirstOrDefault(s =>
                            content.Contains(s, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                        if (!string.IsNullOrEmpty(matchedSource))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Streamlabs Scene Config Captures Game: {Path.GetFileName(sceneFile)}",
                                Risk = RiskLevel.Medium,
                                Location = sceneFile,
                                FileName = Path.GetFileName(sceneFile),
                                Reason = $"Streamlabs scene configuration captures game source '{matchedSource}'. This confirms Streamlabs was configured to record or stream GTA5 or FiveM, potentially recording cheat tool usage during streaming sessions.",
                                Detail = $"Scene file: {sceneFile} | Game source: {matchedSource}"
                            });
                            break;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        try
        {
            using var slobsKey = Registry.CurrentUser.OpenSubKey(@"Software\Streamlabs", writable: false);
            ctx.IncrementRegistryKeys();
            if (slobsKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Streamlabs Registry Key Found",
                    Risk = RiskLevel.Medium,
                    Location = @"HKCU\Software\Streamlabs",
                    FileName = null,
                    Reason = "Streamlabs registry key found. Streamlabs registry entries confirm the application was installed and may contain recording output paths and session history for correlation with cheat tool activity timelines.",
                    Detail = @"Registry: HKCU\Software\Streamlabs"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckShadowRecorderArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] shadowDirs = new[]
        {
            Path.Combine(roamingAppData, "Shadow"),
            Path.Combine(localAppData, "Shadow")
        };

        foreach (string shadowDir in shadowDirs)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                if (Directory.Exists(shadowDir))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Shadow.tech Client Data Found: {shadowDir}",
                        Risk = RiskLevel.Medium,
                        Location = shadowDir,
                        FileName = "Shadow",
                        Reason = "Shadow.tech cloud gaming client data found. Shadow.tech records cloud gaming sessions; client-side artifacts may reference game session history including GTA5 or FiveM sessions where cheat tools were used.",
                        Detail = $"Path: {shadowDir}"
                    });
                }
            }
            catch { }
        }

        string downloadsDir = Path.Combine(userProfile, "Downloads");
        try
        {
            if (Directory.Exists(downloadsDir))
            {
                foreach (string file in Directory.GetFiles(downloadsDir, "Shadow_*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    string ext = Path.GetExtension(file);
                    if (!VideoExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase))) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Shadow.tech Exported Clip Found: {Path.GetFileName(file)}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "Shadow.tech exported video clip found in Downloads. Shadow.tech clip exports preserve recordings from cloud gaming sessions and may contain footage of gameplay during which cheat tools were active.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMedalTVArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] medalDirs = new[]
        {
            Path.Combine(roamingAppData, "Medal"),
            Path.Combine(localAppData, "Medal")
        };

        foreach (string medalDir in medalDirs)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                if (Directory.Exists(medalDir))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Medal.tv Client Data Found: {medalDir}",
                        Risk = RiskLevel.Medium,
                        Location = medalDir,
                        FileName = "Medal",
                        Reason = "Medal.tv gaming clip platform client data found. Medal.tv automatically records game highlights; if configured for GTA5 or FiveM, recorded highlight clips may capture cheat usage moments.",
                        Detail = $"Path: {medalDir}"
                    });

                    string medalLog = Path.Combine(medalDir, "Medal_log.txt");
                    if (File.Exists(medalLog))
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(medalLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            bool hasGameRef = GameRecordingPatterns.Any(p =>
                                content.Contains(p, StringComparison.OrdinalIgnoreCase));

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Medal.tv Log File Found",
                                Risk = hasGameRef ? RiskLevel.High : RiskLevel.Medium,
                                Location = medalLog,
                                FileName = "Medal_log.txt",
                                Reason = hasGameRef
                                    ? "Medal.tv log file references GTA5 or FiveM game sessions. Medal.tv was actively recording these game sessions and highlight clips of cheat activity may exist in the Medal clip library."
                                    : "Medal.tv log file found. Log entries reveal Medal.tv recording session history that may correlate with known cheat tool usage times.",
                                Detail = $"Path: {medalLog} | Game reference found: {hasGameRef}"
                            });
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        string medalClipDir = Path.Combine(userProfile, "Videos", "Medal");
        try
        {
            if (Directory.Exists(medalClipDir))
            {
                string[] clipFiles = Directory.GetFiles(medalClipDir, "*", SearchOption.AllDirectories);
                int videoCount = clipFiles.Count(f =>
                    VideoExtensions.Any(e => e.Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase)));

                if (videoCount > 0)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Medal.tv Clip Library Found ({videoCount} videos)",
                        Risk = RiskLevel.High,
                        Location = medalClipDir,
                        FileName = "Medal",
                        Reason = $"Medal.tv clip library found with {videoCount} video files. Medal.tv clip libraries contain automatically recorded gaming highlights; clips from GTA5 or FiveM sessions may contain direct visual evidence of cheat usage.",
                        Detail = $"Clip directory: {medalClipDir} | Video count: {videoCount}"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var medalKey = Registry.CurrentUser.OpenSubKey(@"Software\Medal", writable: false);
            ctx.IncrementRegistryKeys();
            if (medalKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Medal.tv Registry Key Found",
                    Risk = RiskLevel.Medium,
                    Location = @"HKCU\Software\Medal",
                    FileName = null,
                    Reason = "Medal.tv registry key found. Medal.tv registry entries confirm the application was installed and configured; registry data may reveal which games were being recorded including GTA5 and FiveM.",
                    Detail = @"Registry: HKCU\Software\Medal"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckPlaysGGArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string playsDir = Path.Combine(roamingAppData, "Plays.gg");
        try
        {
            if (Directory.Exists(playsDir))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Plays.gg Client Config Directory Found",
                    Risk = RiskLevel.Medium,
                    Location = playsDir,
                    FileName = "Plays.gg",
                    Reason = "Plays.gg (formerly Plays.tv) game DVR client configuration directory found. Plays.gg automatically records game sessions; configuration may reveal GTA5 or FiveM as tracked games with existing clip library.",
                    Detail = $"Path: {playsDir}"
                });

                string[] configFiles = Directory.GetFiles(playsDir, "*.json", SearchOption.TopDirectoryOnly);
                foreach (string configFile in configFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasGameRef = GameRecordingPatterns.Any(p =>
                            content.Contains(p, StringComparison.OrdinalIgnoreCase)) ||
                            OBSSceneGameSources.Any(s =>
                            content.Contains(s, StringComparison.OrdinalIgnoreCase));

                        if (hasGameRef)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Plays.gg Config References GTA/FiveM: {Path.GetFileName(configFile)}",
                                Risk = RiskLevel.High,
                                Location = configFile,
                                FileName = Path.GetFileName(configFile),
                                Reason = "Plays.gg configuration file references GTA5 or FiveM as a tracked game. Plays.gg was actively recording these game sessions and clip recordings may contain direct evidence of cheat activity.",
                                Detail = $"Config file: {configFile}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        string playsClipDir = Path.Combine(userProfile, "Videos", "Plays.gg");
        try
        {
            if (Directory.Exists(playsClipDir))
            {
                string[] clipFiles = Directory.GetFiles(playsClipDir, "*", SearchOption.AllDirectories);
                int videoCount = clipFiles.Count(f =>
                    VideoExtensions.Any(e => e.Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase)));

                if (videoCount > 0)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Plays.gg Clip Library Found ({videoCount} videos)",
                        Risk = RiskLevel.High,
                        Location = playsClipDir,
                        FileName = "Plays.gg",
                        Reason = $"Plays.gg clip library found with {videoCount} video files. Plays.gg automatically records game sessions; clips from GTA5 or FiveM sessions are forensic artifacts that may visually capture cheat tool usage.",
                        Detail = $"Clip directory: {playsClipDir} | Video count: {videoCount}"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var playsKey = Registry.CurrentUser.OpenSubKey(@"Software\Plays.gg", writable: false);
            ctx.IncrementRegistryKeys();
            if (playsKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Plays.gg Registry Key Found",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\Plays.gg",
                    FileName = null,
                    Reason = "Plays.gg registry key found. Plays.gg registry entries confirm installation and may contain recording library paths and game session metadata for correlation with cheat tool activity.",
                    Detail = @"Registry: HKCU\Software\Plays.gg"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckInnReplayArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        string insightsDir = Path.Combine(roamingAppData, "Insights");
        try
        {
            if (Directory.Exists(insightsDir))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Insights Game Recording Client Found",
                    Risk = RiskLevel.Medium,
                    Location = insightsDir,
                    FileName = "Insights",
                    Reason = "Insights game recording client data directory found. Insights auto-clips game sessions; its presence indicates game recording was active and may have captured cheat tool usage in GTA5 or FiveM sessions.",
                    Detail = $"Path: {insightsDir}"
                });
            }
        }
        catch { }

        string overwolfDir = Path.Combine(localAppData, "Overwolf");
        try
        {
            if (Directory.Exists(overwolfDir))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Overwolf Client Data Found",
                    Risk = RiskLevel.Medium,
                    Location = overwolfDir,
                    FileName = "Overwolf",
                    Reason = "Overwolf client data directory found. Overwolf Outplayed automatically records game sessions as highlights; GTA5 and FiveM recordings created by Outplayed may contain footage of cheat usage captured during gameplay.",
                    Detail = $"Path: {overwolfDir}"
                });

                string outplayedDir = Path.Combine(overwolfDir, "Outplayed");
                if (Directory.Exists(outplayedDir))
                {
                    string[] clipFiles = Directory.GetFiles(outplayedDir, "*", SearchOption.AllDirectories);
                    int videoCount = clipFiles.Count(f =>
                        VideoExtensions.Any(e => e.Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase)));

                    if (videoCount > 0)
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Overwolf Outplayed Clip Library Found ({videoCount} clips)",
                            Risk = RiskLevel.High,
                            Location = outplayedDir,
                            FileName = "Outplayed",
                            Reason = $"Overwolf Outplayed clip library found with {videoCount} video recordings. Outplayed automatically records game highlights; clips from GTA5 or FiveM sessions are direct forensic evidence of gameplay during which cheat tools may have been visible.",
                            Detail = $"Clip directory: {outplayedDir} | Clip count: {videoCount}"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            using var overwolfKey = Registry.CurrentUser.OpenSubKey(@"Software\Overwolf", writable: false);
            ctx.IncrementRegistryKeys();
            if (overwolfKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Overwolf Registry Key Found",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\Overwolf",
                    FileName = null,
                    Reason = "Overwolf registry key found. Overwolf registry entries confirm Outplayed or other Overwolf recording apps were installed; recording history for GTA5 or FiveM sessions may be accessible from this key.",
                    Detail = @"Registry: HKCU\Software\Overwolf"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDeletedRecordingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string systemDrive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.System)) ?? @"C:\";
        string recycleBinPath = Path.Combine(systemDrive, "$Recycle.Bin");

        try
        {
            if (Directory.Exists(recycleBinPath))
            {
                foreach (string sidDir in Directory.GetDirectories(recycleBinPath))
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        foreach (string file in Directory.GetFiles(sidDir, "*", SearchOption.TopDirectoryOnly))
                        {
                            if (ct.IsCancellationRequested) return;
                            string ext = Path.GetExtension(file);
                            if (!VideoExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase))) continue;

                            string fileName = Path.GetFileName(file);
                            bool isGameRecording = GameRecordingPatterns.Any(p =>
                                fileName.Contains(p, StringComparison.OrdinalIgnoreCase));

                            if (isGameRecording)
                            {
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Deleted Game Recording Found in Recycle Bin: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = "Deleted game recording video file found in the Recycle Bin matching GTA5 or FiveM naming patterns. Cheaters commonly delete recordings of themselves cheating, but Recycle Bin entries constitute forensic evidence of the recording's existence and the deliberate attempt to destroy evidence.",
                                    Detail = $"Recycle Bin path: {file} | SID directory: {sidDir}"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string[] thumbcachePaths;
        try
        {
            string explorerCacheDir = Path.Combine(localAppData, "Microsoft", "Windows", "Explorer");
            thumbcachePaths = Directory.Exists(explorerCacheDir)
                ? Directory.GetFiles(explorerCacheDir, "thumbcache_*.db", SearchOption.TopDirectoryOnly)
                : Array.Empty<string>();
        }
        catch { thumbcachePaths = Array.Empty<string>(); }

        foreach (string thumbcache in thumbcachePaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                ctx.IncrementFiles();
                FileInfo fi = new FileInfo(thumbcache);
                if (fi.Length > 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Windows Thumbnail Cache Found: {Path.GetFileName(thumbcache)}",
                        Risk = RiskLevel.Medium,
                        Location = thumbcache,
                        FileName = Path.GetFileName(thumbcache),
                        Reason = "Windows Explorer thumbnail cache database found. Thumbnail caches retain image previews of files that have since been deleted; thumbnails of deleted game recording videos may persist here as forensic evidence that such recordings existed.",
                        Detail = $"Path: {thumbcache} | Size: {fi.Length} bytes"
                    });
                }
            }
            catch { }
        }

        string autoDestDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "Recent", "AutomaticDestinations");
        try
        {
            if (Directory.Exists(autoDestDir))
            {
                foreach (string jlFile in Directory.GetFiles(autoDestDir, "*.automaticDestinations-ms", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(jlFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Unicode, detectEncodingFromByteOrderMarks: false);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasVideoRef = VideoExtensions.Any(e =>
                            content.Contains(e, StringComparison.OrdinalIgnoreCase)) &&
                            GameRecordingPatterns.Any(p =>
                            content.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (hasVideoRef)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Jump List References Deleted Game Recording: {Path.GetFileName(jlFile)}",
                                Risk = RiskLevel.Critical,
                                Location = jlFile,
                                FileName = Path.GetFileName(jlFile),
                                Reason = "Windows Jump List entry references a game recording video file matching GTA5 or FiveM naming patterns. Jump List entries persist after file deletion and prove recent access to game recording files, providing forensic evidence that recordings existed even if subsequently deleted.",
                                Detail = $"Jump List file: {jlFile}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckWindowsClipArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        string screenshotsDir = Path.Combine(userProfile, "Pictures", "Screenshots");
        try
        {
            if (Directory.Exists(screenshotsDir))
            {
                string[] screenshotFiles = Directory.GetFiles(screenshotsDir, "*", SearchOption.TopDirectoryOnly);
                if (screenshotFiles.Length > 0)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Windows Screenshots Directory Found ({screenshotFiles.Length} files)",
                        Risk = RiskLevel.Medium,
                        Location = screenshotsDir,
                        FileName = Path.GetFileName(screenshotFiles[0]),
                        Reason = $"Windows screenshot directory contains {screenshotFiles.Length} screenshot files. Screenshots taken during GTA5 or FiveM gameplay sessions may capture cheat UI elements, aimbot indicators, or other visual evidence of cheat tool usage.",
                        Detail = $"Screenshot directory: {screenshotsDir} | File count: {screenshotFiles.Length}"
                    });
                }
            }
        }
        catch { }

        string xboxCapturesDir = Path.Combine(userProfile, "Videos", "Captures");
        try
        {
            if (Directory.Exists(xboxCapturesDir))
            {
                string[] screenshotFiles = Directory.GetFiles(xboxCapturesDir, "*.png", SearchOption.TopDirectoryOnly);
                if (screenshotFiles.Length > 0)
                {
                    foreach (string screenshot in screenshotFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        string fileName = Path.GetFileName(screenshot);
                        bool isGameScreenshot = GameRecordingPatterns.Any(p =>
                            fileName.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (isGameScreenshot)
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Xbox Capture Screenshot of Game Session: {fileName}",
                                Risk = RiskLevel.Medium,
                                Location = screenshot,
                                FileName = fileName,
                                Reason = "Xbox Game Bar screenshot of a GTA5 or FiveM session found. Screenshots taken during cheat-assisted gameplay may capture cheat menus, overlays, or gameplay statistics that reveal cheat tool usage.",
                                Detail = $"Path: {screenshot}"
                            });
                        }
                    }
                }
            }
        }
        catch { }

        string explorerCacheDir = Path.Combine(localAppData, "Microsoft", "Windows", "Explorer");
        try
        {
            if (Directory.Exists(explorerCacheDir))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Windows Explorer Cache Directory Found",
                    Risk = RiskLevel.Low,
                    Location = explorerCacheDir,
                    FileName = "Explorer",
                    Reason = "Windows Explorer cache directory found. This directory stores thumbnail caches and icon overlays for recently viewed files including screenshots and video recordings; forensic analysis of these caches may reveal evidence of deleted game recordings.",
                    Detail = $"Path: {explorerCacheDir}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRecordingMetadataArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] scanDirs = new[]
        {
            Path.Combine(userProfile, "Videos"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads")
        };

        int totalFound = 0;

        foreach (string scanDir in scanDirs)
        {
            if (!Directory.Exists(scanDir)) continue;
            try
            {
                foreach (string file in Directory.GetFiles(scanDir, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    string ext = Path.GetExtension(file);
                    if (!VideoExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase))) continue;

                    string fileName = Path.GetFileName(file);
                    bool isGameRecording = GameRecordingPatterns.Any(p =>
                        fileName.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (isGameRecording)
                    {
                        ctx.IncrementFiles();
                        totalFound++;
                        FileInfo fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Game Session Recording File Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Video recording file matching GTA5/FiveM/RAGEMP/AltV naming pattern found. File metadata (creation date: {fi.CreationTimeUtc:u}, last write: {fi.LastWriteTimeUtc:u}) can be correlated with known cheat tool usage timestamps from other module findings to establish concurrent recording of cheat activity.",
                            Detail = $"Path: {file} | Created: {fi.CreationTimeUtc:u} | Modified: {fi.LastWriteTimeUtc:u} | Size: {fi.Length} bytes"
                        });
                    }
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckStreamingPlatformArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] streamKeyFiles = new[]
        {
            Path.Combine(roamingAppData, "obs-studio", "basic", "profiles"),
            Path.Combine(roamingAppData, "slobs-client", "basic", "profiles")
        };

        foreach (string profileRoot in streamKeyFiles)
        {
            if (!Directory.Exists(profileRoot)) continue;
            try
            {
                foreach (string iniFile in Directory.GetFiles(profileRoot, "*.ini", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(iniFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasTwitchStream = content.Contains("live.twitch.tv", StringComparison.OrdinalIgnoreCase) ||
                                              content.Contains("rtmp://", StringComparison.OrdinalIgnoreCase);
                        bool hasYouTubeStream = content.Contains("youtube.com", StringComparison.OrdinalIgnoreCase) ||
                                               content.Contains("a.rtmp.youtube.com", StringComparison.OrdinalIgnoreCase);

                        if (hasTwitchStream || hasYouTubeStream)
                        {
                            string platform = hasTwitchStream ? "Twitch" : "YouTube";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Streaming Config Found with {platform} RTMP Settings: {Path.GetFileName(iniFile)}",
                                Risk = RiskLevel.Medium,
                                Location = iniFile,
                                FileName = Path.GetFileName(iniFile),
                                Reason = $"Streaming configuration file found with {platform} RTMP streaming endpoint. If the user was streaming GTA5 or FiveM gameplay live to {platform} while using cheats, VOD archives of the stream may contain cheat evidence on the platform.",
                                Detail = $"Config file: {iniFile} | Platform: {platform}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        string[] recordingOutputDirs = new[]
        {
            Path.Combine(userProfile, "Videos"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads")
        };

        foreach (string outputDir in recordingOutputDirs)
        {
            if (!Directory.Exists(outputDir)) continue;
            try
            {
                foreach (string file in Directory.GetFiles(outputDir, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    string ext = Path.GetExtension(file);
                    if (!ext.Equals(".flv", StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FLV Stream Recording File Found: {Path.GetFileName(file)}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "FLV format recording file found. FLV (Flash Video) files are produced by streaming software as raw recording output; their presence indicates active recording or streaming sessions that may have captured gameplay including cheat usage.",
                        Detail = $"Path: {file} | Size: {new FileInfo(file).Length} bytes"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckAMDReliveArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string amdReliveProgramDir = Path.Combine(programFiles, "AMD", "ReLive");
        try
        {
            if (Directory.Exists(amdReliveProgramDir))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "AMD Radeon ReLive Installation Found",
                    Risk = RiskLevel.Medium,
                    Location = amdReliveProgramDir,
                    FileName = "ReLive",
                    Reason = "AMD Radeon ReLive installation directory found. AMD ReLive records game sessions automatically; its presence indicates game recording was available during GTA5 or FiveM sessions and cheat usage may have been captured.",
                    Detail = $"Path: {amdReliveProgramDir}"
                });
            }
        }
        catch { }

        string amdReliveVideoDir = Path.Combine(userProfile, "Videos", "AMD ReLive");
        try
        {
            if (Directory.Exists(amdReliveVideoDir))
            {
                string[] videoFiles = Directory.GetFiles(amdReliveVideoDir, "*", SearchOption.AllDirectories);
                int videoCount = videoFiles.Count(f =>
                    VideoExtensions.Any(e => e.Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase)));

                bool hasGameRecording = videoFiles.Any(f =>
                    GameRecordingPatterns.Any(p =>
                    Path.GetFileName(f).Contains(p, StringComparison.OrdinalIgnoreCase)));

                if (videoCount > 0)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AMD ReLive Recording Library Found ({videoCount} videos)",
                        Risk = hasGameRecording ? RiskLevel.High : RiskLevel.Medium,
                        Location = amdReliveVideoDir,
                        FileName = "AMD ReLive",
                        Reason = hasGameRecording
                            ? "AMD ReLive recording library contains video files matching GTA5 or FiveM naming patterns. These recordings are direct forensic evidence of gameplay sessions during which cheat tools may have been visually captured."
                            : $"AMD ReLive recording library found with {videoCount} video files. ReLive continuously records game sessions; videos from GTA5 or FiveM sessions may contain cheat evidence.",
                        Detail = $"ReLive directory: {amdReliveVideoDir} | Video count: {videoCount} | GTA/FiveM recordings: {hasGameRecording}"
                    });
                }
            }
        }
        catch { }

        string amdConfigDir = Path.Combine(roamingAppData, "AMD");
        try
        {
            if (Directory.Exists(amdConfigDir))
            {
                foreach (string configFile in Directory.GetFiles(amdConfigDir, "*.ini", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasReliveConfig = content.Contains("ReLive", StringComparison.OrdinalIgnoreCase) ||
                                              content.Contains("Record", StringComparison.OrdinalIgnoreCase);
                        if (hasReliveConfig)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"AMD ReLive Config File Found: {Path.GetFileName(configFile)}",
                                Risk = RiskLevel.Medium,
                                Location = configFile,
                                FileName = Path.GetFileName(configFile),
                                Reason = "AMD Radeon ReLive configuration file found. ReLive configuration specifies recording output paths and enabled games; this data can identify whether GTA5 or FiveM was being recorded and where recordings are stored.",
                                Detail = $"Config path: {configFile}"
                            });
                            break;
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            using var amdDvrKey = Registry.CurrentUser.OpenSubKey(@"Software\AMD\DVR", writable: false);
            ctx.IncrementRegistryKeys();
            if (amdDvrKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "AMD ReLive DVR Registry Key Found",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\AMD\DVR",
                    FileName = null,
                    Reason = "AMD Radeon ReLive DVR registry key found. The AMD DVR registry key stores ReLive recording configuration and may contain references to recorded game applications including GTA5 and FiveM, confirming game session recording was enabled.",
                    Detail = @"Registry: HKCU\Software\AMD\DVR"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckIntelArcControlArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string arcControlDir = Path.Combine(localAppData, "Intel", "Arc Control");
        try
        {
            if (Directory.Exists(arcControlDir))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Intel Arc Control Data Directory Found",
                    Risk = RiskLevel.Medium,
                    Location = arcControlDir,
                    FileName = "Arc Control",
                    Reason = "Intel Arc Control application data directory found. Intel Arc Control includes game capture and recording features for Intel Arc GPU users; its presence indicates game recording capability was available and may have captured GTA5 or FiveM sessions.",
                    Detail = $"Path: {arcControlDir}"
                });

                foreach (string configFile in Directory.GetFiles(arcControlDir, "*.json", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasGameRef = GameRecordingPatterns.Any(p =>
                            content.Contains(p, StringComparison.OrdinalIgnoreCase)) ||
                            OBSSceneGameSources.Any(s =>
                            content.Contains(s, StringComparison.OrdinalIgnoreCase));

                        if (hasGameRef)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Intel Arc Control Config References Game: {Path.GetFileName(configFile)}",
                                Risk = RiskLevel.Medium,
                                Location = configFile,
                                FileName = Path.GetFileName(configFile),
                                Reason = "Intel Arc Control configuration file references GTA5 or FiveM. This confirms Intel Arc Control was configured to record or capture these game sessions, and recordings may exist at the configured output location.",
                                Detail = $"Config file: {configFile}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        string intelVideoDir = Path.Combine(userProfile, "Videos", "Intel");
        try
        {
            if (Directory.Exists(intelVideoDir))
            {
                string[] videoFiles = Directory.GetFiles(intelVideoDir, "*", SearchOption.AllDirectories);
                int videoCount = videoFiles.Count(f =>
                    VideoExtensions.Any(e => e.Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase)));

                if (videoCount > 0)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Intel Game Capture Recording Library Found ({videoCount} videos)",
                        Risk = RiskLevel.Medium,
                        Location = intelVideoDir,
                        FileName = "Intel",
                        Reason = $"Intel game capture recording library found with {videoCount} video files. Intel Arc Control recordings of GTA5 or FiveM sessions may contain footage during which cheat tools were active and visible.",
                        Detail = $"Video directory: {intelVideoDir} | Video count: {videoCount}"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var arcKey = Registry.CurrentUser.OpenSubKey(@"Software\Intel\Arc Control", writable: false);
            ctx.IncrementRegistryKeys();
            if (arcKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Intel Arc Control Registry Key Found",
                    Risk = RiskLevel.Medium,
                    Location = @"HKCU\Software\Intel\Arc Control",
                    FileName = null,
                    Reason = "Intel Arc Control registry key found. Registry entries for Intel Arc Control may contain recording configuration and game session data that identifies whether GTA5 or FiveM recording was enabled.",
                    Detail = @"Registry: HKCU\Software\Intel\Arc Control"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRecordingHidingToolsArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] searchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
        };

        foreach (string searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (string toolName in RecordingBypassToolNames)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    string fullPath = Path.Combine(searchPath, toolName);
                    if (File.Exists(fullPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Recording Bypass Tool Found: {toolName}",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = toolName,
                            Reason = $"Recording bypass tool '{toolName}' found. Anti-recording tools are specifically used to prevent OBS, NVIDIA Share, or other capture software from recording cheat UI elements or gameplay during cheat usage, demonstrating deliberate awareness and concealment of cheat activity.",
                            Detail = $"Path: {fullPath}"
                        });
                    }
                }
                catch { }
            }
        }

        foreach (string regKeyPath in RecordingBypssRegKeys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var bypassKey = Registry.CurrentUser.OpenSubKey(regKeyPath, writable: false);
                ctx.IncrementRegistryKeys();
                if (bypassKey is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Recording Bypass Registry Key Found: {regKeyPath.Split('\\').Last()}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKCU\{regKeyPath}",
                        FileName = null,
                        Reason = $"Recording bypass tool registry key found at 'HKCU\\{regKeyPath}'. Registry presence of OBS bypass or recording blocker software confirms the installation of tools specifically designed to prevent capture of cheat usage by recording software, constituting deliberate evidence concealment.",
                        Detail = $"Registry: HKCU\\{regKeyPath}"
                    });
                }
            }
            catch { }

            try
            {
                using var bypassKeyLM = Registry.LocalMachine.OpenSubKey(regKeyPath, writable: false);
                ctx.IncrementRegistryKeys();
                if (bypassKeyLM is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Recording Bypass Registry Key Found (HKLM): {regKeyPath.Split('\\').Last()}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{regKeyPath}",
                        FileName = null,
                        Reason = $"Recording bypass tool registry key found at 'HKLM\\{regKeyPath}'. System-level recording bypass registry entries indicate a deeply installed tool designed to prevent all users' recording software from capturing cheat activity.",
                        Detail = $"Registry: HKLM\\{regKeyPath}"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVideoFileNamingPatternArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] scanDirs = new[]
        {
            Path.Combine(userProfile, "Videos"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads")
        };

        string[] namingPatterns = { "GTA5_", "FiveM_", "Desktop ", "Capture_", "Clip_", "Highlight_", "Recording_" };

        int totalGameVideos = 0;
        var foundFiles = new List<string>();

        foreach (string scanDir in scanDirs)
        {
            if (!Directory.Exists(scanDir)) continue;
            try
            {
                foreach (string file in Directory.GetFiles(scanDir, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    string ext = Path.GetExtension(file);
                    if (!VideoExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase))) continue;

                    string fileName = Path.GetFileName(file);
                    bool matchesPattern = namingPatterns.Any(p =>
                        fileName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                    if (matchesPattern)
                    {
                        ctx.IncrementFiles();
                        totalGameVideos++;
                        foundFiles.Add(file);
                    }
                }
            }
            catch { }
        }

        if (totalGameVideos > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Large Collection of Game Session Recordings Found ({totalGameVideos} files)",
                Risk = RiskLevel.High,
                Location = string.Join("; ", scanDirs.Where(Directory.Exists)),
                FileName = foundFiles.Count > 0 ? Path.GetFileName(foundFiles[0]) : null,
                Reason = $"{totalGameVideos} video files matching game recording software naming conventions (GTA5_, FiveM_, Capture_, Highlight_, Recording_, etc.) found across Videos, Desktop, and Downloads. A large collection of game session recordings alongside cheat artifacts found by other modules indicates the user habitually recorded gameplay while cheating, and these recordings may constitute direct visual evidence of cheat usage.",
                Detail = $"Total game recording files: {totalGameVideos} | Sample files: {string.Join(", ", foundFiles.Take(5).Select(Path.GetFileName))}"
            });
        }

        foreach (string dir in RecordingOutputDirs)
        {
            if (ct.IsCancellationRequested) return;
            string fullDirPath = Path.Combine(userProfile, dir);
            try
            {
                if (Directory.Exists(fullDirPath))
                {
                    string[] videoFiles = Directory.GetFiles(fullDirPath, "*", SearchOption.AllDirectories);
                    int count = videoFiles.Count(f =>
                        VideoExtensions.Any(e => e.Equals(Path.GetExtension(f), StringComparison.OrdinalIgnoreCase)));

                    if (count > 0)
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Game Recording Output Directory Contains Videos: {dir} ({count} files)",
                            Risk = RiskLevel.High,
                            Location = fullDirPath,
                            FileName = dir.Split('\\').Last(),
                            Reason = $"Recording software output directory '{fullDirPath}' contains {count} video files. This is a known output location for game recording software; videos stored here from GTA5 or FiveM sessions may directly capture cheat tool usage as forensic evidence.",
                            Detail = $"Directory: {fullDirPath} | Video count: {count}"
                        });
                    }
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);
}
