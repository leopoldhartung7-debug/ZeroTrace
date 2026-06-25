using Microsoft.Win32;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class OverwatchCheatScanModule : IScanModule
{
    public string Name => "Overwatch 2 Cheat Detection";
    public double Weight => 3.9;
    public int ParallelGroup => 4;

    // Known cheat process names targeting Overwatch 2
    private static readonly HashSet<string> CheatProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "OW2Cheat", "OverwatchCheat", "OW2Aimbot", "OverwatchESP", "OW2External",
        "OW2Internal", "OWHack", "OW2Hack", "OverwatchHack", "OW2Loader",
        "OverwatchLoader", "OW2Inject", "OverwatchInject", "OW2Trigger",
        "OverwatchTrigger", "OW2Wallhack", "OverwatchWallhack", "OW2Radar",
        "OverwatchRadar", "OW2Overlay", "OverwatchOverlay", "OW2Spoofer",
        "OverwatchSpoofer", "OWSpoofer", "WardenBypass", "OW2WardenBypass",
        "BlizzardBypass", "BNetBypass", "OW2NoRecoil", "OverwatchNoRecoil",
        "OW2SilentAim", "OverwatchSilentAim", "OW2GodMode", "OW2ESP",
        "OW2BoneAim", "OverwatchBoneAim", "OW2Pixel", "OWPixelbot",
        "OW2Triggerbot", "OverwatchTriggerbot", "OW2DMA", "OverwatchDMA",
        "OW2HeroAim", "OW2HeroESP", "OW2HitScan", "OverwatchHitScan",
        "OW2Unlocker", "OverwatchUnlocker", "OW2Skinchanger", "OWMemoryEdit"
    };

    // Known cheat file names for Overwatch 2
    private static readonly HashSet<string> CheatFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "OW2Cheat.exe", "OverwatchCheat.exe", "OW2Aimbot.exe", "OverwatchESP.exe",
        "OW2External.exe", "OW2Internal.dll", "OWHack.exe", "OW2Hack.exe",
        "OverwatchHack.exe", "OW2Loader.exe", "OverwatchLoader.exe",
        "OW2Inject.dll", "OverwatchInject.dll", "OW2Trigger.exe",
        "OverwatchTrigger.exe", "OW2Wallhack.exe", "OverwatchWallhack.exe",
        "OW2Radar.exe", "OverwatchRadar.exe", "OW2Overlay.exe",
        "OverwatchOverlay.exe", "OW2Spoofer.exe", "OWSpoofer.exe",
        "WardenBypass.exe", "WardenBypass.dll", "OW2WardenBypass.exe",
        "BlizzardBypass.dll", "BNetBypass.dll", "OW2NoRecoil.dll",
        "OW2SilentAim.dll", "OW2GodMode.dll", "OW2ESP.dll",
        "OW2BoneAim.dll", "OW2Pixel.exe", "OWPixelbot.exe",
        "OW2Triggerbot.exe", "OverwatchTriggerbot.exe", "OW2DMA.exe",
        "OW2HeroAim.exe", "OW2HeroESP.dll", "OW2Unlocker.exe",
        "OverwatchUnlocker.exe", "warden_patch.dll", "warden_bypass.dll",
        "ow2_bypass.dll", "ow_hack.dll", "battlenet_bypass.dll",
        "bnet_patch.dll", "warden.mpq.bak", "warden_fake.mpq"
    };

    // Keywords in OW2 cheat file names (partial matches)
    private static readonly string[] CheatFileKeywords =
    {
        "ow2cheat", "overwatchesp", "ow2aimbot", "ow2hack", "owcheat",
        "ow2bypass", "owbypass", "wardenbypass", "ow2warden", "bnetbypass",
        "ow2triggerbot", "owtrigger", "ow2pixel", "ow2dma", "ow2spoof",
        "ow2internal", "ow2external", "overwatchhack", "ow2loader"
    };

    // Warden (Blizzard anti-cheat) bypass artifact file names
    private static readonly HashSet<string> WardenBypassFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "warden.mpq", "warden_patch.dll", "warden_bypass.dll", "warden_hook.dll",
        "warden_fake.dll", "warden_null.dll", "warden_stub.dll",
        "battle.net.dll", "bnet_bypass.dll", "battlenet_bypass.dll",
        "bnet_patch.dll", "bnet_hook.dll", "agent_bypass.dll"
    };

    // OW2 cheat config keywords — hero-specific aimbot, ESP, triggerbot settings
    private static readonly string[] Ow2CheatConfigKeywords =
    {
        "hero_aim", "aimbot_hero", "headshot_only", "trigger_key_ow",
        "ow2_aimbot", "ow2_esp", "hero_esp", "hero_select", "hero_switch",
        "aim_hero", "esp_hero", "hero_filter", "hero_predict",
        "tracer_aim", "widow_aim", "ana_aim", "ashe_aim", "hanzo_aim",
        "cassidy_aim", "genji_deflect", "reaper_aim", "soldier_aim",
        "enable_triggerbot_ow", "triggerbot_key_ow", "triggerbot_delay_ow",
        "triggerbot_color_ow", "pixel_triggerbot", "pixel_color_ow",
        "screen_capture_ow", "ow2_radar", "ow2_wallhack", "ow2_no_recoil",
        "ow2_silent_aim", "ow2_bone_aim", "ow2_aim_fov", "ow2_aim_smoothing",
        "ow2_stream_proof", "ow2_spoofer", "ow2_hwid_spoof",
        "warden_bypass_cfg", "bnet_bypass_cfg", "ability_predict",
        "ability_system_ow", "playercontroller_ow", "heroentity_ow",
        "ow2_loot_box", "ow2_menu_key", "ow2_panic_key", "ow2_inject_key"
    };

    // OW2-specific memory offset identifiers (class names in cheat source/headers)
    private static readonly string[] Ow2OffsetIdentifiers =
    {
        "PlayerController", "HeroEntity", "AbilitySystem",
        "OW2PlayerManager", "HeroComponent", "HealthComponent",
        "CameraComponent", "AbilityComponent", "UltimateAbility",
        "HeroPhysicsEntity", "PlayerSpawn", "TeamComponent",
        "SpectatorComponent", "OverwatchGame", "MatchController",
        "ObjectiveComponent", "UltCharge", "HeroSelectManager",
        "BattleNetPlayer", "OWPlayerEntity", "HeroAbilityManager",
        "OverwatchRenderer", "OWGameManager", "HeroBone",
        "OWHeroSkeleton", "OWEntityList", "OWCameraManager"
    };

    // Battle.net launcher directories that Warden operates from
    private static readonly string[] BnetLauncherRelativePaths =
    {
        "Agent", "Battle.net", "Blizzard Entertainment"
    };

    // Pixel triggerbot script patterns (autohotkey, python, lua screen-capture)
    private static readonly string[] PixelTriggerbotPatterns =
    {
        "PixelGetColor", "PixelSearch", "ImageSearch", "GetPixel(",
        "pyautogui", "screenshot", "PIL.ImageGrab", "ImageGrab.grab",
        "mss.mss()", "d3dshot", "win32gui", "FindWindow",
        "overwatch", "ow2", "GetDC(", "ReleaseDC(", "GetPixel",
        "trigger_color", "enemy_color", "target_color",
        "red_threshold", "green_threshold", "aim_color",
        "SendInput", "mouse_event", "keybd_event",
        "triggerbot", "pixel_aim", "color_aim"
    };

    // OW2 executable names
    private static readonly string[] Ow2GameExecutables =
    {
        "Overwatch.exe", "OverwatchLauncher.exe", "Overwatch_retail.exe",
        "Battle.net.exe", "Battle.net Launcher.exe", "Agent.exe"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Initialisierung...");

        var ow2InstallPaths = FindOverwatchInstallPaths();
        ctx.Report(0.05, Name, $"{ow2InstallPaths.Count} Overwatch 2-Installationspfade gefunden");

        ScanRunningProcesses(ctx, ct);
        ctx.Report(0.15, Name, "Prozessueberpruefung abgeschlossen");

        await ScanCheatFilesInCommonLocations(ctx, ct);
        ctx.Report(0.35, Name, "Dateisuche in allgemeinen Verzeichnissen abgeschlossen");

        foreach (var installPath in ow2InstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            await ScanOverwatchInstallDirectory(ctx, installPath, ct);
        }
        ctx.Report(0.55, Name, "Spielverzeichnis-Pruefung abgeschlossen");

        await ScanBnetLauncherPaths(ctx, ct);
        ctx.Report(0.65, Name, "Battle.net-Launcher-Verzeichnis geprueft");

        await ScanCheatConfigFiles(ctx, ct);
        ctx.Report(0.75, Name, "Cheat-Konfigurationsdateien geprueft");

        await ScanMemoryOffsetFiles(ctx, ct);
        ctx.Report(0.83, Name, "Speicher-Offset-Dateien geprueft");

        await ScanPixelTriggerbotScripts(ctx, ct);
        ctx.Report(0.91, Name, "Pixel-Triggerbot-Skripte geprueft");

        CheckWardenRegistry(ctx);
        ctx.Report(1.0, Name, "Overwatch 2-Cheat-Scan abgeschlossen");
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();
        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            string procName;
            try { procName = proc.ProcessName; }
            catch { continue; }

            if (CheatProcessNames.Contains(procName))
            {
                string location = string.Empty;
                try { location = proc.MainModule?.FileName ?? string.Empty; }
                catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Overwatch 2-Cheat-Prozess aktiv: {procName}",
                    Risk = RiskLevel.Critical,
                    Location = string.IsNullOrEmpty(location) ? $"PID {proc.Id}" : location,
                    FileName = procName + ".exe",
                    Reason = $"Der Prozess '{procName}' ist ein bekanntes Overwatch 2-Cheat-Tool. " +
                             "Ein aktiver Cheat-Prozess ist der starkste Hinweis auf aktiven Cheat-Einsatz."
                });
                continue;
            }

            string? mainPath = null;
            try { mainPath = proc.MainModule?.FileName; }
            catch { }

            if (mainPath is null) continue;

            var fileName = Path.GetFileName(mainPath);
            foreach (var keyword in CheatFileKeywords)
            {
                if (fileName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiger OW2-bezogener Prozess: {procName}",
                        Risk = RiskLevel.High,
                        Location = mainPath,
                        FileName = fileName,
                        Reason = $"Der Prozess '{procName}' enthaelt das Schluessenwort '{keyword}' " +
                                 "im Pfad, das auf ein Overwatch 2-Cheat-Tool hindeutet."
                    });
                    break;
                }
            }
        }
    }

    private async Task ScanCheatFilesInCommonLocations(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new List<string>();

        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var tempPath = Path.GetTempPath();
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        foreach (var p in new[] { desktop, downloads, appData, localAppData, tempPath, documents })
        {
            if (!string.IsNullOrEmpty(p) && Directory.Exists(p))
                searchRoots.Add(p);
        }

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForCheatFiles(ctx, root, maxDepth: 3, ct);
        }
    }

    private async Task ScanDirectoryForCheatFiles(
        ScanContext ctx, string directory, int maxDepth, CancellationToken ct)
    {
        if (maxDepth < 0) return;

        string[] files = Array.Empty<string>();
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);

            if (CheatFileNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Bekannte OW2-Cheat-Datei: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes Overwatch 2-Cheat-Tool. " +
                             "Die Datei ist namentlich als Cheat-Werkzeug bekannt."
                });
                continue;
            }

            if (WardenBypassFileNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Warden-Bypass-Datei gefunden: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes Warden-Bypass-Artefakt. " +
                             "Warden ist Blizzards Anti-Cheat-Modul fuer Overwatch 2. " +
                             "Bypass-Dateien sollen die Erkennung durch Warden verhindern."
                });
                continue;
            }

            var fileNameLower = fileName.ToLowerInvariant();
            foreach (var keyword in CheatFileKeywords)
            {
                if (fileNameLower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige OW2-bezogene Datei: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                        Reason = $"Die Datei '{fileName}' enthaelt das Schluessenwort '{keyword}', " +
                                 "das auf ein Overwatch 2-Cheat-Tool hindeutet."
                    });
                    break;
                }
            }

            var ext = Path.GetExtension(fileName);
            if (ext.Equals(".ahk", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".py", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".lua", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".js", StringComparison.OrdinalIgnoreCase))
            {
                await ScanScriptFileForPixelTriggerbot(ctx, file, ct);
            }
        }

        if (maxDepth <= 0) return;

        string[] subDirs = Array.Empty<string>();
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var sub in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForCheatFiles(ctx, sub, maxDepth - 1, ct);
        }
    }

    private async Task ScanOverwatchInstallDirectory(ScanContext ctx, string installPath, CancellationToken ct)
    {
        if (!Directory.Exists(installPath)) return;

        await CheckWardenMpqIntegrity(ctx, installPath, ct);
        await CheckSuspiciousDllsInInstallDir(ctx, installPath, ct);
    }

    private async Task CheckWardenMpqIntegrity(ScanContext ctx, string installPath, CancellationToken ct)
    {
        // Warden module is loaded from Battle.net/Overwatch install paths as MPQ archives.
        // A missing or replaced warden.mpq is a Warden bypass artifact.
        var wardenMpqPath = Path.Combine(installPath, "warden.mpq");
        var wardenMpqPathAlt = Path.Combine(installPath, "Warden.mpq");

        if (File.Exists(wardenMpqPath) || File.Exists(wardenMpqPathAlt))
        {
            var actualPath = File.Exists(wardenMpqPath) ? wardenMpqPath : wardenMpqPathAlt;

            // Check file size: a zero-byte or extremely small warden.mpq is suspicious
            try
            {
                var fi = new FileInfo(actualPath);
                if (fi.Length < 512)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Verdaechtig kleine warden.mpq-Datei (moeglicher Bypass)",
                        Risk = RiskLevel.Critical,
                        Location = actualPath,
                        FileName = Path.GetFileName(actualPath),
                        Sha256 = HashUtil.TryComputeSha256(actualPath, 1024 * 1024),
                        Reason = $"Die Datei 'warden.mpq' im Overwatch-Verzeichnis ist ungewoehnlich " +
                                 $"klein ({fi.Length} Bytes). Eine gueltige warden.mpq-Datei ist deutlich " +
                                 "groesser. Eine zu kleine oder leere Datei deutet auf einen " +
                                 "Warden-Bypass hin (gestutztes oder ersetztes MPQ-Archiv).",
                        Detail = $"Dateigroesse: {fi.Length} Bytes"
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        // Check for warden backup/renamed files
        string[] installFiles = Array.Empty<string>();
        try { installFiles = Directory.GetFiles(installPath); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var f in installFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(f);
            if (fileName.Contains("warden", StringComparison.OrdinalIgnoreCase)
                && !fileName.Equals("warden.mpq", StringComparison.OrdinalIgnoreCase)
                && !fileName.Equals("Warden.mpq", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtige Warden-bezogene Datei: {fileName}",
                    Risk = RiskLevel.High,
                    Location = f,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(f, 64 * 1024 * 1024),
                    Reason = $"Die Datei '{fileName}' im Overwatch-Installationsverzeichnis enthaelt " +
                             "'warden' im Namen, ist aber keine legitime warden.mpq. Dies koennte " +
                             "eine Sicherungskopie eines bypassed Warden-Moduls oder ein Bypass-Artefakt sein."
                });
            }
        }

        await Task.CompletedTask;
    }

    private async Task CheckSuspiciousDllsInInstallDir(ScanContext ctx, string installPath, CancellationToken ct)
    {
        string[] installFiles = Array.Empty<string>();
        try { installFiles = Directory.GetFiles(installPath); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var f in installFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(f);
            var ext = Path.GetExtension(fileName);

            if (!ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                && !ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)) continue;

            if (WardenBypassFileNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Warden-Bypass-Datei im OW2-Installationsverzeichnis: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = f,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(f, 128 * 1024 * 1024),
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes Warden-Bypass-Artefakt " +
                             "und wurde direkt im Overwatch 2-Installationsverzeichnis gefunden. " +
                             "Dort platzierte Bypass-DLLs werden beim Spielstart automatisch geladen."
                });
                continue;
            }

            var fileNameLower = fileName.ToLowerInvariant();
            foreach (var keyword in CheatFileKeywords)
            {
                if (fileNameLower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige Datei im OW2-Verzeichnis: {fileName}",
                        Risk = RiskLevel.High,
                        Location = f,
                        FileName = fileName,
                        Sha256 = HashUtil.TryComputeSha256(f, 128 * 1024 * 1024),
                        Reason = $"Die Datei '{fileName}' im Overwatch 2-Installationsverzeichnis " +
                                 $"enthaelt das Schluessenwort '{keyword}' und koennte eine " +
                                 "Injektionsbibliothek oder ein Cheat-Tool sein."
                    });
                    break;
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanBnetLauncherPaths(ScanContext ctx, CancellationToken ct)
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var bnetSearchRoots = new List<string>();

        foreach (var root in new[] { programFiles, programFilesX86 })
        {
            foreach (var rel in BnetLauncherRelativePaths)
            {
                var p = Path.Combine(root, rel);
                if (Directory.Exists(p)) bnetSearchRoots.Add(p);
            }
        }

        var localBnet = Path.Combine(localAppData, "Battle.net");
        if (Directory.Exists(localBnet)) bnetSearchRoots.Add(localBnet);

        foreach (var bnetRoot in bnetSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            await ScanBnetDirectoryForBypass(ctx, bnetRoot, maxDepth: 3, ct);
        }
    }

    private async Task ScanBnetDirectoryForBypass(
        ScanContext ctx, string directory, int maxDepth, CancellationToken ct)
    {
        if (maxDepth < 0) return;

        string[] files = Array.Empty<string>();
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);

            if (WardenBypassFileNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Warden/BNET-Bypass-Datei im Launcher-Verzeichnis: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes Warden- oder " +
                             "Battle.net-Bypass-Artefakt, gefunden im Battle.net-Launcher-Verzeichnis. " +
                             "Diese Dateien sollen die Erkennung durch Blizzards Warden-Anti-Cheat " +
                             "im Launcher-Kontext verhindern."
                });
                continue;
            }

            // Battle.net.dll replacement check - a non-Blizzard battle.net.dll is a bypass
            if (fileName.Equals("Battle.net.dll", StringComparison.OrdinalIgnoreCase))
            {
                bool signed = false;
                string? signer = null;
                try
                {
                    var sigResult = SignatureChecker.CheckDetailed(file);
                    signed = sigResult.IsTrusted;
                    signer = sigResult.Signer;
                }
                catch { }

                bool fromBlizzard = signed && signer is not null &&
                    (signer.Contains("Blizzard", StringComparison.OrdinalIgnoreCase)
                     || signer.Contains("Activision", StringComparison.OrdinalIgnoreCase));

                if (!fromBlizzard)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Unsignierte/ersetzende Battle.net.dll im Launcher-Verzeichnis",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                        Signed = signed,
                        Reason = "Die Datei 'Battle.net.dll' im Launcher-Verzeichnis ist nicht von " +
                                 "Blizzard/Activision signiert. Eine ersetzende Battle.net.dll ist ein " +
                                 "klassisches Muster zum Umgehen von Warden-Erkennung im Battle.net-Launcher.",
                        Detail = signer is null ? "Unsigniert" : $"Signierer: {signer}"
                    });
                }
            }

            var ext = Path.GetExtension(fileName);
            if (ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".ini", StringComparison.OrdinalIgnoreCase))
            {
                await ScanFileForBnetBypassConfig(ctx, file, ct);
            }
        }

        if (maxDepth <= 0) return;

        string[] subDirs = Array.Empty<string>();
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var sub in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            await ScanBnetDirectoryForBypass(ctx, sub, maxDepth - 1, ct);
        }
    }

    private async Task ScanFileForBnetBypassConfig(ScanContext ctx, string filePath, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        if (content.Length > 512 * 1024) return;

        var bypassIndicators = new[]
        {
            "warden_bypass", "warden_disable", "warden_patch",
            "bypass_bnet", "disable_warden", "patch_warden",
            "anticheat_disable", "ac_bypass", "skip_warden",
            "warden_hook", "battlenet_bypass", "bnet_disable"
        };

        foreach (var indicator in bypassIndicators)
        {
            if (content.Contains(indicator, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Battle.net/Warden-Bypass-Konfiguration: {Path.GetFileName(filePath)}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = Path.GetFileName(filePath),
                    Reason = $"Die Konfigurationsdatei im Battle.net-Verzeichnis enthaelt den " +
                             $"Bypass-Bezeichner '{indicator}'. Diese Einstellung deutet auf eine " +
                             "gezielte Deaktivierung oder Umgehung des Warden-Anti-Cheat hin.",
                    Detail = $"Treffer: {indicator}"
                });
                return;
            }
        }
    }

    private async Task ScanCheatConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new List<string>();

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        foreach (var p in new[] { appData, localAppData, documents, desktop, downloads })
        {
            if (!string.IsNullOrEmpty(p) && Directory.Exists(p))
                searchRoots.Add(p);
        }

        var configExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".cfg", ".json", ".ini", ".txt", ".xml", ".yaml", ".yml" };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForOw2Configs(ctx, root, configExtensions, maxDepth: 3, ct);
        }
    }

    private async Task ScanDirectoryForOw2Configs(
        ScanContext ctx, string directory, HashSet<string> extensions, int maxDepth, CancellationToken ct)
    {
        if (maxDepth < 0) return;

        string[] files = Array.Empty<string>();
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(file);
            if (!extensions.Contains(ext)) continue;

            ctx.IncrementFiles();
            await ScanFileForOw2CheatConfig(ctx, file, ct);
        }

        if (maxDepth <= 0) return;

        string[] subDirs = Array.Empty<string>();
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var sub in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForOw2Configs(ctx, sub, extensions, maxDepth - 1, ct);
        }
    }

    private async Task ScanFileForOw2CheatConfig(ScanContext ctx, string filePath, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        if (content.Length > 1024 * 1024) return;

        var hitKeywords = new List<string>();
        foreach (var keyword in Ow2CheatConfigKeywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                hitKeywords.Add(keyword);
        }

        if (hitKeywords.Count >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Overwatch 2-Cheat-Konfigurationsdatei: {Path.GetFileName(filePath)}",
                Risk = hitKeywords.Count >= 4 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = Path.GetFileName(filePath),
                Reason = $"Die Datei enthaelt {hitKeywords.Count} OW2-cheat-spezifische Schluesselbegriffe " +
                         "(hero-spezifischer Aimbot, ESP, Triggerbot, Warden-Bypass-Parameter).",
                Detail = "Treffer: " + string.Join(", ", hitKeywords.Take(10))
            });
        }
    }

    private async Task ScanMemoryOffsetFiles(ScanContext ctx, CancellationToken ct)
    {
        var searchPaths = new List<string>();

        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var p in new[] { desktop, downloads, documents, appData, localAppData })
        {
            if (!string.IsNullOrEmpty(p) && Directory.Exists(p))
                searchPaths.Add(p);
        }

        var offsetExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".json", ".hpp", ".h", ".txt", ".cs", ".cpp", ".py" };

        foreach (var root in searchPaths)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForOffsetFiles(ctx, root, offsetExtensions, maxDepth: 3, ct);
        }
    }

    private async Task ScanDirectoryForOffsetFiles(
        ScanContext ctx, string directory, HashSet<string> extensions, int maxDepth, CancellationToken ct)
    {
        if (maxDepth < 0) return;

        string[] files = Array.Empty<string>();
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(file);
            if (!extensions.Contains(ext)) continue;

            ctx.IncrementFiles();
            await ScanFileForOffsetIdentifiers(ctx, file, ct);
        }

        if (maxDepth <= 0) return;

        string[] subDirs = Array.Empty<string>();
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var sub in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForOffsetFiles(ctx, sub, extensions, maxDepth - 1, ct);
        }
    }

    private async Task ScanFileForOffsetIdentifiers(ScanContext ctx, string filePath, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        if (content.Length > 512 * 1024) return;

        var hitIdentifiers = new List<string>();
        foreach (var identifier in Ow2OffsetIdentifiers)
        {
            if (content.Contains(identifier, StringComparison.OrdinalIgnoreCase))
                hitIdentifiers.Add(identifier);
        }

        if (hitIdentifiers.Count >= 3)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Overwatch 2-Speicher-Offset-Datei: {Path.GetFileName(filePath)}",
                Risk = hitIdentifiers.Count >= 5 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = Path.GetFileName(filePath),
                Reason = $"Die Datei enthaelt {hitIdentifiers.Count} OW2-spezifische Speicher-Klassen-" +
                         "Bezeichner (z.B. PlayerController, HeroEntity, AbilitySystem). " +
                         "Solche Dateien enthalten Speicheradressen fuer OW2-Cheat-Software.",
                Detail = "Bezeichner: " + string.Join(", ", hitIdentifiers.Take(8))
            });
        }
    }

    private async Task ScanPixelTriggerbotScripts(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new List<string>();

        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        foreach (var p in new[] { desktop, downloads, documents, appData })
        {
            if (!string.IsNullOrEmpty(p) && Directory.Exists(p))
                searchRoots.Add(p);
        }

        var scriptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".ahk", ".py", ".lua", ".js", ".ps1", ".vbs", ".bas" };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForScripts(ctx, root, scriptExtensions, maxDepth: 3, ct);
        }
    }

    private async Task ScanDirectoryForScripts(
        ScanContext ctx, string directory, HashSet<string> extensions, int maxDepth, CancellationToken ct)
    {
        if (maxDepth < 0) return;

        string[] files = Array.Empty<string>();
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(file);
            if (!extensions.Contains(ext)) continue;

            ctx.IncrementFiles();
            await ScanScriptFileForPixelTriggerbot(ctx, file, ct);
        }

        if (maxDepth <= 0) return;

        string[] subDirs = Array.Empty<string>();
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var sub in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForScripts(ctx, sub, extensions, maxDepth - 1, ct);
        }
    }

    private async Task ScanScriptFileForPixelTriggerbot(ScanContext ctx, string filePath, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        if (content.Length > 512 * 1024) return;

        var hitPatterns = new List<string>();
        foreach (var pattern in PixelTriggerbotPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                hitPatterns.Add(pattern);
        }

        if (hitPatterns.Count < 3) return;

        // Require at least one OW2-specific reference
        bool hasOw2Reference = content.Contains("overwatch", StringComparison.OrdinalIgnoreCase)
            || content.Contains("ow2", StringComparison.OrdinalIgnoreCase)
            || content.Contains("trigger_color", StringComparison.OrdinalIgnoreCase)
            || content.Contains("enemy_color", StringComparison.OrdinalIgnoreCase)
            || content.Contains("aim_color", StringComparison.OrdinalIgnoreCase)
            || content.Contains("pixel_aim", StringComparison.OrdinalIgnoreCase);

        if (!hasOw2Reference) return;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"OW2-Pixel-Triggerbot-Skript: {Path.GetFileName(filePath)}",
            Risk = RiskLevel.High,
            Location = filePath,
            FileName = Path.GetFileName(filePath),
            Reason = $"Das Skript enthaelt {hitPatterns.Count} Muster, die typisch fuer " +
                     "Pixel-Color-Reading-Triggerbots in Overwatch 2 sind (Bildschirmerfassung, " +
                     "Farbanalyse, automatische Mauseingabe). Diese Technik umgeht traditionelle " +
                     "Speicher-basierte Anti-Cheat-Erkennungen.",
            Detail = "Muster: " + string.Join(", ", hitPatterns.Take(8))
        });
    }

    private void CheckWardenRegistry(ScanContext ctx)
    {
        // Warden-related registry entries used by Blizzard games
        var wardenRegistryPaths = new[]
        {
            @"SOFTWARE\Blizzard Entertainment",
            @"SOFTWARE\WOW6432Node\Blizzard Entertainment",
            @"SOFTWARE\Battle.net",
            @"SOFTWARE\WOW6432Node\Battle.net"
        };

        foreach (var regPath in wardenRegistryPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    if (valueName.Contains("warden", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("disable_ac", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = key.GetValue(valueName)?.ToString();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger Warden/BNET-Registry-Wert: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{regPath}\{valueName}",
                            Reason = $"Der Registry-Wert '{valueName}' im Blizzard/Battle.net-Schluessel " +
                                     "enthaelt einen Bezeichner (warden/bypass/disable_ac), der auf eine " +
                                     "Manipulation des Warden-Anti-Cheat-Systems hindeutet.",
                            Detail = val
                        });
                    }
                }
            }
            catch { }
        }

        // Check HKCU Blizzard/Battle.net entries
        var hkcuPaths = new[]
        {
            @"Software\Blizzard Entertainment",
            @"Software\Battle.net"
        };

        foreach (var regPath in hkcuPaths)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    if (valueName.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("disable_warden", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("warden_off", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = key.GetValue(valueName)?.ToString();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger BNET-Benutzer-Registry-Wert: {valueName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{regPath}\{valueName}",
                            Reason = $"Der Registry-Wert '{valueName}' im Battle.net-Benutzerschluessel " +
                                     "deutet auf eine versuchte Manipulation des Warden-Anti-Cheat hin.",
                            Detail = val
                        });
                    }
                }
            }
            catch { }
        }

        // Check for Blizzard Anti-Cheat service tampering
        var blizzardAcService = @"SYSTEM\CurrentControlSet\Services\BlizzardAnticheat";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(blizzardAcService);
            if (key is not null)
            {
                ctx.IncrementRegistryKeys();

                var startValue = key.GetValue("Start");
                if (startValue is int startInt && startInt == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Blizzard Anti-Cheat-Dienst deaktiviert",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{blizzardAcService}\Start",
                        Reason = "Der Blizzard Anti-Cheat-Dienst ist in der Registry deaktiviert " +
                                 "(Start=4). Dies deutet auf einen gezielten Bypass des " +
                                 "Warden-Anti-Cheat-Systems hin, das Overwatch 2 schuetzt.",
                        Detail = $"Start-Wert: {startInt} (4 = deaktiviert)"
                    });
                }
            }
        }
        catch { }
    }

    private static List<string> FindOverwatchInstallPaths()
    {
        var paths = new List<string>();

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        // Standard Battle.net/Overwatch install paths
        var candidatePaths = new[]
        {
            Path.Combine(programFiles, "Overwatch"),
            Path.Combine(programFilesX86, "Overwatch"),
            Path.Combine(programFiles, "Overwatch 2"),
            Path.Combine(programFilesX86, "Overwatch 2"),
            Path.Combine(programFiles, "Battle.net", "Overwatch"),
            Path.Combine(programFilesX86, "Battle.net", "Overwatch"),
            Path.Combine(programFiles, "Battle.net", "Overwatch 2"),
            Path.Combine(programFilesX86, "Battle.net", "Overwatch 2"),
            Path.Combine(programFiles, "Blizzard Entertainment", "Overwatch"),
            Path.Combine(programFilesX86, "Blizzard Entertainment", "Overwatch"),
            Path.Combine(programFiles, "Blizzard Entertainment", "Overwatch 2"),
            Path.Combine(programFilesX86, "Blizzard Entertainment", "Overwatch 2"),
            @"C:\Overwatch",
            @"C:\Overwatch 2",
            @"D:\Overwatch",
            @"D:\Overwatch 2"
        };

        foreach (var p in candidatePaths)
        {
            if (Directory.Exists(p) && !paths.Contains(p, StringComparer.OrdinalIgnoreCase))
                paths.Add(p);
        }

        // Registry-based path detection
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Blizzard Entertainment\Overwatch");
            var installDir = key?.GetValue("InstallPath")?.ToString()
                             ?? key?.GetValue("Install Dir")?.ToString();
            if (!string.IsNullOrEmpty(installDir) && Directory.Exists(installDir))
            {
                if (!paths.Contains(installDir!, StringComparer.OrdinalIgnoreCase))
                    paths.Add(installDir!);
            }
        }
        catch { }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Blizzard Entertainment\Overwatch 2");
            var installDir = key?.GetValue("InstallPath")?.ToString()
                             ?? key?.GetValue("Install Dir")?.ToString();
            if (!string.IsNullOrEmpty(installDir) && Directory.Exists(installDir))
            {
                if (!paths.Contains(installDir!, StringComparer.OrdinalIgnoreCase))
                    paths.Add(installDir!);
            }
        }
        catch { }

        return paths;
    }
}
