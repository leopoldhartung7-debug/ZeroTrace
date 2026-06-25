using Microsoft.Win32;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class WarzoneCheatDeepScanModule : IScanModule
{
    public string Name => "Warzone / MW2 / MW3 Cheat Detection";
    public double Weight => 4.1;
    public int ParallelGroup => 4;

    // Known cheat process names for Warzone / CoD titles
    private static readonly HashSet<string> CheatProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "WarzoneCheat", "CODCheat", "WZCheat", "WarzoneESP", "WarzoneAimbot",
        "WZ2Cheat", "MW2Cheat", "MW3Cheat", "CodExternal", "WZExternal",
        "WZInternal", "CodHack", "Chiller", "Lucent", "Tempest",
        "Aurora", "Slumber", "Swift", "WZLoader", "CODLoader",
        "WarzoneLoader", "WZInject", "CODInject", "WarzoneInject",
        "WZTrigger", "CODTrigger", "WarzoneTrigger", "WZRadar",
        "CODRadar", "WarzoneRadar", "WZSpoofer", "CODSpoofer",
        "WarzoneSpoofer", "WZOverlay", "CODOverlay", "WarzoneOverlay",
        "RicochetBypass", "WZRicochetBypass", "CODRicochetBypass",
        "WZDMAReader", "WZDMA", "CODMemoryEdit", "WZMemoryEdit",
        "WZSilentAim", "CODSilentAim", "WZBoneAim", "CODBoneAim",
        "WZGodMode", "CODGodMode", "WZNoRecoil", "CODNoRecoil",
        "WZWallhack", "CODWallhack", "WZUnlocker", "CODUnlocker",
        "WZOffsetDumper", "CODOffsetDumper", "WZDumper", "CODDumper",
        "BNetCODBypass", "WZBNetBypass", "RicochetSpoofer", "rc_bypass"
    };

    // Known cheat file names for Warzone / CoD titles
    private static readonly HashSet<string> CheatFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "WarzoneCheat.exe", "CODCheat.exe", "WZCheat.exe", "WarzoneESP.exe",
        "WarzoneAimbot.exe", "WZ2Cheat.exe", "MW2Cheat.exe", "MW3Cheat.exe",
        "CodExternal.exe", "WZExternal.exe", "WZInternal.dll", "CodHack.exe",
        "Chiller.exe", "Lucent.exe", "Tempest.exe", "Aurora.exe",
        "Slumber.exe", "Swift.exe", "WZLoader.exe", "CODLoader.exe",
        "WarzoneLoader.exe", "WZInject.dll", "CODInject.dll",
        "WarzoneInject.dll", "WZTrigger.exe", "CODTrigger.exe",
        "WZRadar.exe", "CODRadar.exe", "WarzoneRadar.exe",
        "WZSpoofer.exe", "CODSpoofer.exe", "WarzoneSpoofer.exe",
        "WZOverlay.exe", "CODOverlay.exe", "WarzoneOverlay.exe",
        "ricochet_bypass.exe", "ricochet_spoofer.exe", "rc_bypass.dll",
        "ricochet_bypass.dll", "rc_spoofer.dll", "ricochet_patch.dll",
        "WZDMAReader.exe", "WZDMA.exe", "CODMemoryEdit.exe",
        "WZSilentAim.dll", "CODSilentAim.dll", "WZBoneAim.dll",
        "WZGodMode.dll", "WZNoRecoil.dll", "WZWallhack.dll",
        "WZUnlocker.exe", "CODUnlocker.exe", "WZOffsetDumper.exe",
        "cod_bypass.dll", "cod_inject.dll", "wz_cheat.dll",
        "mw2_cheat.dll", "mw3_cheat.dll", "wz_esp.dll",
        "wz_aimbot.dll", "RicochetBypass.exe", "RicochetBypass.dll",
        "wz_dma.exe", "cod_dma.exe", "wz_external.exe", "cod_radar.exe"
    };

    // Keywords in file names for Warzone/CoD cheats (partial matches)
    private static readonly string[] CheatFileKeywords =
    {
        "warzonecheat", "codcheat", "wzcheat", "wzhack", "codhack",
        "warzonehack", "wzbypass", "codbypass", "ricochetbypass",
        "wzdma", "coddma", "wzspoof", "codspoof", "wztrigger",
        "wzradar", "codradar", "wzaimbot", "codesp", "wzesp",
        "mw2cheat", "mw3cheat", "wzexternal", "codexternal",
        "wzinternal", "codinternal", "wzloader", "codloader"
    };

    // RICOCHET (CoD anti-cheat) bypass specific file names
    private static readonly HashSet<string> RicochetBypassFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ricochet_bypass.exe", "ricochet_spoofer.exe", "rc_bypass.dll",
        "ricochet_bypass.dll", "rc_spoofer.dll", "ricochet_patch.dll",
        "ricochet_hook.dll", "ricochet_null.dll", "ricochet_stub.dll",
        "ricochet_loader.dll", "ricochet_inject.dll", "ricochet_patcher.exe",
        "ricochet_disable.exe", "rc_hook.dll", "rc_null.dll", "rc_patcher.dll"
    };

    // Warzone/CoD cheat config keywords (50+)
    private static readonly string[] WzCheatConfigKeywords =
    {
        "aimbot_smoothing", "enemy_esp", "vehicle_esp", "loot_esp",
        "radar_hack", "no_recoil_wz", "silent_aim_wz", "bone_aim",
        "aimbot_fov", "wz_aimbot", "wz_esp", "cod_aimbot", "cod_esp",
        "wz_radar", "cod_radar", "wz_no_recoil", "cod_no_recoil",
        "wz_silent_aim", "cod_silent_aim", "wz_bone_aim", "cod_bone_aim",
        "wz_triggerbot", "cod_triggerbot", "wz_wallhack", "cod_wallhack",
        "wz_spoofer", "cod_spoofer", "wz_hwid_spoof", "cod_hwid_spoof",
        "wz_stream_proof", "cod_stream_proof", "wz_godmode", "cod_godmode",
        "wz_speed", "cod_speed", "aimbot_prediction", "aimbot_target_bone",
        "aimbot_key", "esp_key", "menu_key_wz", "panic_key_wz",
        "enemy_snap_line", "enemy_box_esp", "enemy_health_bar",
        "enemy_distance_esp", "enemy_name_esp", "skeleton_esp",
        "vehicle_type_esp", "loot_filter", "loot_distance",
        "ground_loot_esp", "chest_esp", "airdrop_esp",
        "minimap_radar", "minimap_hack", "compass_hack",
        "ricochet_bypass_cfg", "bnet_bypass_wz", "aim_assist_wz",
        "enable_aimbot_wz", "enable_esp_wz", "enable_radar_wz"
    };

    // CoD-specific memory offset identifiers
    private static readonly string[] CodOffsetIdentifiers =
    {
        "CGame", "CgPlayer", "RefDef", "cg_entities",
        "ClientGame", "CGameState", "PlayerState", "ClientEntity",
        "CgDrawing", "CameraView", "ViewAngles", "PlayerAngles",
        "LocalPlayer", "EntityList", "NameArray",
        "CgSnapshot", "ClientSnapshot", "WorldModel",
        "ClientDObj", "ClientDObjNum", "BoneMatrix",
        "ViewMatrix", "ProjectionMatrix", "W2S_Matrix",
        "ModernWarfarePlayer", "WarzonePlayer", "CodPlayerManager",
        "CgWeapon", "WeaponDef", "AmmoCount",
        "TeamNum", "IsAlive", "IsValid",
        "PlayerFlags", "EntityFlags", "CharacterInfo",
        "CgPlayerState", "CgEnt", "CgEntNum",
        "CgPlayerBones", "BoneArray", "BoneCount"
    };

    // DMA external cheat identifiers (radar configs and external process readers)
    private static readonly string[] DmaCheatIdentifiers =
    {
        "cod.exe", "ModernWarfare.exe", "ModernWarfare2.exe", "ModernWarfare3.exe",
        "CodMW.exe", "Warzone.exe", "MWII.exe", "MWIII.exe",
        "dma_read", "dma_write", "scatter_read", "scatter_write",
        "vmm_init", "vmm_read", "vmm_write", "FPGA",
        "pcileech", "leechcore", "memmap", "mem_map",
        "process_memory", "rpm", "wpm", "read_process_memory",
        "write_process_memory", "external_esp", "external_aimbot",
        "radar_server", "radar_client", "radar_port",
        "ws://localhost", "radar_esp", "web_radar",
        "socket_radar", "tcp_radar", "udp_radar"
    };

    // Known Warzone-targeting DMA/radar cheat server identifiers
    private static readonly string[] WzDmaRadarKeywords =
    {
        "warzone_radar", "wz_radar_server", "cod_radar_server",
        "radar_wz", "external_wz", "dma_wz", "wz_dma",
        "warzone_external", "cod_external", "wz_server",
        "radar_overlay", "web_radar_wz", "websocket_radar"
    };

    // CoD game executable names
    private static readonly string[] CodGameExecutables =
    {
        "cod.exe", "ModernWarfare.exe", "ModernWarfare2.exe", "ModernWarfare3.exe",
        "MWII.exe", "MWIII.exe", "Warzone.exe", "CodMW.exe",
        "BlackOps.exe", "BlackOps2.exe", "BlackOps3.exe", "BlackOps4.exe",
        "BlackOpsColdWar.exe", "vanguard.exe", "Vanguard.exe"
    };

    // RICOCHET driver system service name
    private const string RicochetServiceName = "ricochet";
    private const string RicochetDriverName = "ricochet.sys";

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Initialisierung...");

        var codInstallPaths = FindCodInstallPaths();
        ctx.Report(0.04, Name, $"{codInstallPaths.Count} CoD/Warzone-Installationspfade gefunden");

        ScanRunningProcesses(ctx, ct);
        ctx.Report(0.12, Name, "Prozessueberpruefung abgeschlossen");

        await ScanCheatFilesInCommonLocations(ctx, ct);
        ctx.Report(0.28, Name, "Dateisuche in allgemeinen Verzeichnissen abgeschlossen");

        foreach (var installPath in codInstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            await ScanCodInstallDirectory(ctx, installPath, ct);
        }
        ctx.Report(0.45, Name, "Spielverzeichnis-Pruefungen abgeschlossen");

        await ScanCheatConfigFiles(ctx, ct);
        ctx.Report(0.58, Name, "Cheat-Konfigurationsdateien geprueft");

        await ScanMemoryOffsetFiles(ctx, ct);
        ctx.Report(0.68, Name, "Speicher-Offset-Dateien geprueft");

        await ScanDmaAndRadarArtifacts(ctx, ct);
        ctx.Report(0.78, Name, "DMA/Radar-Artefakte geprueft");

        CheckRicochetRegistry(ctx);
        ctx.Report(0.88, Name, "RICOCHET-Registry geprueft");

        CheckRicochetDriverIntegrity(ctx);
        ctx.Report(0.95, Name, "RICOCHET-Treiberintegritaet geprueft");

        CheckBnetCodRegistry(ctx);
        ctx.Report(1.0, Name, "Warzone/MW/CoD-Cheat-Scan abgeschlossen");
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
                    Title = $"Warzone/CoD-Cheat-Prozess aktiv: {procName}",
                    Risk = RiskLevel.Critical,
                    Location = string.IsNullOrEmpty(location) ? $"PID {proc.Id}" : location,
                    FileName = procName + ".exe",
                    Reason = $"Der Prozess '{procName}' ist ein bekanntes Warzone- oder " +
                             "Call of Duty-Cheat-Tool. Ein aktiver Cheat-Prozess ist der " +
                             "starkste Hinweis auf aktiven Cheat-Einsatz."
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
                        Title = $"Verdaechtiger WZ/CoD-bezogener Prozess: {procName}",
                        Risk = RiskLevel.High,
                        Location = mainPath,
                        FileName = fileName,
                        Reason = $"Der Prozess '{procName}' enthaelt das Schluessenwort '{keyword}' " +
                                 "im Pfad, das auf ein Warzone/CoD-Cheat-Tool hindeutet."
                    });
                    break;
                }
            }

            // Named cheat loaders — exact string matches against well-known release names
            string procNameLower = procName.ToLowerInvariant();
            if (procNameLower.Equals("chiller", StringComparison.OrdinalIgnoreCase)
                || procNameLower.Equals("lucent", StringComparison.OrdinalIgnoreCase)
                || procNameLower.Equals("tempest", StringComparison.OrdinalIgnoreCase)
                || procNameLower.Equals("aurora", StringComparison.OrdinalIgnoreCase)
                || procNameLower.Equals("slumber", StringComparison.OrdinalIgnoreCase)
                || procNameLower.Equals("swift", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Bekannter Warzone-Cheat-Release aktiv: {procName}",
                    Risk = RiskLevel.Critical,
                    Location = mainPath ?? $"PID {proc.Id}",
                    FileName = procName + ".exe",
                    Reason = $"Der Prozess '{procName}' entspricht dem Namen eines bekannten " +
                             "kommerziellen Warzone-Cheat-Produkts (Chiller, Lucent, Tempest, " +
                             "Aurora, Slumber oder Swift). Diese Produkte bieten ESP, Aimbot und " +
                             "RICOCHET-Bypass an."
                });
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

        // Battle.net local CoD paths
        var bnetCodPath = Path.Combine(localAppData, "Battle.net", "Games", "Call of Duty");
        if (Directory.Exists(bnetCodPath)) searchRoots.Add(bnetCodPath);

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
                    Title = $"Bekannte Warzone/CoD-Cheat-Datei: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes Warzone/CoD-Cheat-Tool. " +
                             "Die Datei ist namentlich als Cheat-Werkzeug bekannt."
                });
                continue;
            }

            if (RicochetBypassFileNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RICOCHET-Bypass-Datei: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes RICOCHET-Bypass-Artefakt. " +
                             "RICOCHET ist das Kernel-Level-Anti-Cheat von Call of Duty/Warzone. " +
                             "Bypass-Tools sollen die RICOCHET-Erkennung verhindern."
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
                        Title = $"Verdaechtige WZ/CoD-bezogene Datei: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                        Reason = $"Die Datei '{fileName}' enthaelt das Schluessenwort '{keyword}', " +
                                 "das auf ein Warzone/CoD-Cheat-Tool hindeutet."
                    });
                    break;
                }
            }

            var ext = Path.GetExtension(fileName);
            if (ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".ini", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".txt", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".yaml", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".yml", StringComparison.OrdinalIgnoreCase))
            {
                await ScanFileForCheatConfig(ctx, file, ct);
                await ScanFileForDmaRadarConfig(ctx, file, ct);
            }

            if (ext.Equals(".hpp", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".h", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".cs", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".cpp", StringComparison.OrdinalIgnoreCase))
            {
                await ScanFileForCodOffsets(ctx, file, ct);
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

    private async Task ScanCodInstallDirectory(ScanContext ctx, string installPath, CancellationToken ct)
    {
        if (!Directory.Exists(installPath)) return;

        await CheckRicochetBypassInInstallDir(ctx, installPath, ct);
        await CheckSuspiciousDllsInInstallDir(ctx, installPath, ct);
    }

    private async Task CheckRicochetBypassInInstallDir(ScanContext ctx, string installPath, CancellationToken ct)
    {
        string[] gameFiles = Array.Empty<string>();
        try { gameFiles = Directory.GetFiles(installPath); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var f in gameFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(f);

            if (RicochetBypassFileNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RICOCHET-Bypass im CoD-Spielverzeichnis: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = f,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(f, 64 * 1024 * 1024),
                    Reason = $"Die RICOCHET-Bypass-Datei '{fileName}' wurde direkt im " +
                             "Call of Duty/Warzone-Installationsverzeichnis gefunden. " +
                             "Dort abgelegte Bypass-Dateien werden beim Spielstart geladen " +
                             "und sollen die Kernel-Treiber-Erkennung durch RICOCHET verhindern."
                });
                continue;
            }

            // Check for ricochet.sys replacement or a stripped version alongside game
            if (fileName.Equals(RicochetDriverName, StringComparison.OrdinalIgnoreCase))
            {
                bool signed = false;
                string? signer = null;
                try
                {
                    var sigResult = SignatureChecker.CheckDetailed(f);
                    signed = sigResult.IsTrusted;
                    signer = sigResult.Signer;
                }
                catch { }

                bool fromActivision = signed && signer is not null &&
                    (signer.Contains("Activision", StringComparison.OrdinalIgnoreCase)
                     || signer.Contains("Infinity Ward", StringComparison.OrdinalIgnoreCase)
                     || signer.Contains("Treyarch", StringComparison.OrdinalIgnoreCase)
                     || signer.Contains("Sledgehammer", StringComparison.OrdinalIgnoreCase));

                if (!fromActivision)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Verdaechtige ricochet.sys-Datei im Spielverzeichnis",
                        Risk = RiskLevel.Critical,
                        Location = f,
                        FileName = fileName,
                        Sha256 = HashUtil.TryComputeSha256(f, 64 * 1024 * 1024),
                        Signed = signed,
                        Reason = "Die Datei 'ricochet.sys' im CoD-Spielverzeichnis ist nicht von " +
                                 "Activision/Infinity Ward signiert. Eine ersetzte oder nicht " +
                                 "authentisch signierte ricochet.sys ist ein starkes Indiz fuer " +
                                 "einen RICOCHET-Kernel-Treiber-Bypass.",
                        Detail = signer is null ? "Unsigniert" : $"Signierer: {signer}"
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task CheckSuspiciousDllsInInstallDir(ScanContext ctx, string installPath, CancellationToken ct)
    {
        string[] gameFiles = Array.Empty<string>();
        try { gameFiles = Directory.GetFiles(installPath); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var f in gameFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(f);
            var ext = Path.GetExtension(fileName);

            if (!ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                && !ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)) continue;

            var fileNameLower = fileName.ToLowerInvariant();
            foreach (var keyword in CheatFileKeywords)
            {
                if (fileNameLower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige Datei im CoD-Spielverzeichnis: {fileName}",
                        Risk = RiskLevel.High,
                        Location = f,
                        FileName = fileName,
                        Sha256 = HashUtil.TryComputeSha256(f, 128 * 1024 * 1024),
                        Reason = $"Die Datei '{fileName}' im CoD/Warzone-Installationsverzeichnis " +
                                 $"enthaelt das Schluessenwort '{keyword}', das auf eine " +
                                 "Cheat-Injektionsbibliothek oder einen Loader hindeutet."
                    });
                    break;
                }
            }
        }

        await Task.CompletedTask;
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

        // CoD-specific document paths
        foreach (var p in GetCodDocumentPaths())
        {
            if (Directory.Exists(p) && !searchRoots.Contains(p, StringComparer.OrdinalIgnoreCase))
                searchRoots.Add(p);
        }

        var configExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".cfg", ".json", ".ini", ".txt", ".xml", ".yaml", ".yml" };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForConfigFiles(ctx, root, configExtensions, maxDepth: 3, ct);
        }
    }

    private async Task ScanDirectoryForConfigFiles(
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
            await ScanFileForCheatConfig(ctx, file, ct);
        }

        if (maxDepth <= 0) return;

        string[] subDirs = Array.Empty<string>();
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var sub in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForConfigFiles(ctx, sub, extensions, maxDepth - 1, ct);
        }
    }

    private async Task ScanFileForCheatConfig(ScanContext ctx, string filePath, CancellationToken ct)
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
        foreach (var keyword in WzCheatConfigKeywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                hitKeywords.Add(keyword);
        }

        if (hitKeywords.Count >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Warzone/CoD-Cheat-Konfigurationsdatei: {Path.GetFileName(filePath)}",
                Risk = hitKeywords.Count >= 5 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = Path.GetFileName(filePath),
                Reason = $"Die Datei enthaelt {hitKeywords.Count} Warzone/CoD-cheat-spezifische " +
                         "Schluesselbegriffe (Aimbot, ESP, Radar, RICOCHET-Bypass, No-Recoil-Parameter).",
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
            { ".json", ".hpp", ".h", ".txt", ".cs", ".cpp", ".py", ".rs" };

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
            await ScanFileForCodOffsets(ctx, file, ct);
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

    private async Task ScanFileForCodOffsets(ScanContext ctx, string filePath, CancellationToken ct)
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
        foreach (var identifier in CodOffsetIdentifiers)
        {
            if (content.Contains(identifier, StringComparison.OrdinalIgnoreCase))
                hitIdentifiers.Add(identifier);
        }

        if (hitIdentifiers.Count >= 3)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Warzone/CoD-Speicher-Offset-Datei: {Path.GetFileName(filePath)}",
                Risk = hitIdentifiers.Count >= 5 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = Path.GetFileName(filePath),
                Reason = $"Die Datei enthaelt {hitIdentifiers.Count} CoD/Warzone-spezifische " +
                         "Speicher-Klassen-Bezeichner (z.B. CGame, CgPlayer, RefDef, cg_entities). " +
                         "Solche Dateien enthalten Speicheradressen und Offset-Tabellen fuer " +
                         "Warzone/CoD-Cheat-Software.",
                Detail = "Bezeichner: " + string.Join(", ", hitIdentifiers.Take(8))
            });
        }
    }

    private async Task ScanDmaAndRadarArtifacts(ScanContext ctx, CancellationToken ct)
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

        var dmaExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".json", ".cfg", ".ini", ".txt", ".yaml", ".yml", ".cs", ".cpp", ".py", ".rs" };

        foreach (var root in searchPaths)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForDmaRadar(ctx, root, dmaExtensions, maxDepth: 3, ct);
        }
    }

    private async Task ScanDirectoryForDmaRadar(
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
            await ScanFileForDmaRadarConfig(ctx, file, ct);
        }

        if (maxDepth <= 0) return;

        string[] subDirs = Array.Empty<string>();
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var sub in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForDmaRadar(ctx, sub, extensions, maxDepth - 1, ct);
        }
    }

    private async Task ScanFileForDmaRadarConfig(ScanContext ctx, string filePath, CancellationToken ct)
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

        var hitDmaKeywords = new List<string>();
        foreach (var identifier in DmaCheatIdentifiers)
        {
            if (content.Contains(identifier, StringComparison.OrdinalIgnoreCase))
                hitDmaKeywords.Add(identifier);
        }

        if (hitDmaKeywords.Count >= 3)
        {
            bool hasWzReference = WzDmaRadarKeywords.Any(k =>
                content.Contains(k, StringComparison.OrdinalIgnoreCase));

            bool hasCodExeReference = content.Contains("cod.exe", StringComparison.OrdinalIgnoreCase)
                || content.Contains("ModernWarfare", StringComparison.OrdinalIgnoreCase)
                || content.Contains("Warzone", StringComparison.OrdinalIgnoreCase)
                || content.Contains("MWII", StringComparison.OrdinalIgnoreCase)
                || content.Contains("MWIII", StringComparison.OrdinalIgnoreCase);

            if (!hasWzReference && !hasCodExeReference) return;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Warzone DMA/Radar-Cheat-Konfiguration: {Path.GetFileName(filePath)}",
                Risk = hitDmaKeywords.Count >= 6 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = Path.GetFileName(filePath),
                Reason = $"Die Datei enthaelt {hitDmaKeywords.Count} DMA/Radar-Cheat-Bezeichner " +
                         "mit direktem Bezug auf Warzone/Call of Duty (cod.exe, ModernWarfare, MWII). " +
                         "DMA-Cheats lesen den Spielspeicher ueber externe Hardware (z.B. FPGA/PCILeech) " +
                         "und senden die Daten an einen separaten Radar-Client.",
                Detail = "Treffer: " + string.Join(", ", hitDmaKeywords.Take(8))
            });
        }
    }

    private void CheckRicochetRegistry(ScanContext ctx)
    {
        // RICOCHET kernel driver service
        var ricochetServicePath = $@"SYSTEM\CurrentControlSet\Services\{RicochetServiceName}";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ricochetServicePath);
            if (key is not null)
            {
                ctx.IncrementRegistryKeys();

                var startValue = key.GetValue("Start");
                if (startValue is int startInt && startInt == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RICOCHET-Kernel-Treiber deaktiviert",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{ricochetServicePath}\Start",
                        Reason = "Der RICOCHET-Kernel-Anti-Cheat-Treiber ist in der Registry deaktiviert " +
                                 "(Start=4). RICOCHET ist das Kernel-Level-Anti-Cheat-System fuer " +
                                 "Call of Duty: Warzone, MW2 und MW3. Eine Deaktivierung deutet auf " +
                                 "einen gezielten Bypass des Anti-Cheat-Schutzes hin.",
                        Detail = $"Start-Wert: {startInt} (4 = deaktiviert)"
                    });
                }

                // Check for image path tampering
                var imagePath = key.GetValue("ImagePath")?.ToString();
                if (!string.IsNullOrEmpty(imagePath)
                    && !imagePath!.Contains("ricochet", StringComparison.OrdinalIgnoreCase)
                    && !imagePath.Contains("system32", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RICOCHET-Treiber-Pfad manipuliert",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{ricochetServicePath}\ImagePath",
                        Reason = "Der RICOCHET-Treiber-Eintrag in der Registry verweist auf einen " +
                                 "untypischen Pfad. Ein manipulierter ImagePath-Wert kann dazu dienen, " +
                                 "den echten RICOCHET-Treiber durch eine gefaelschte Version zu ersetzen.",
                        Detail = $"ImagePath: {imagePath}"
                    });
                }
            }
        }
        catch { }

        // Check for RICOCHET bypass registry artifacts
        var ricochetBypassPaths = new[]
        {
            @"SOFTWARE\Ricochet",
            @"SOFTWARE\WOW6432Node\Ricochet",
            @"SOFTWARE\Activision\Ricochet",
            @"SOFTWARE\WOW6432Node\Activision\Ricochet"
        };

        foreach (var regPath in ricochetBypassPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    if (valueName.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("disable", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("patch", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("hook", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = key.GetValue(valueName)?.ToString();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger RICOCHET-Registry-Wert: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{regPath}\{valueName}",
                            Reason = $"Der Registry-Wert '{valueName}' im RICOCHET-Schluessel " +
                                     "enthaelt ein Schluessenwort (bypass/disable/patch/hook), " +
                                     "das auf einen Anti-Cheat-Bypass-Mechanismus hindeutet.",
                            Detail = val
                        });
                    }
                }
            }
            catch { }
        }

        // Check kernel callback removal artifacts in registry
        var kernelCallbackPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(kernelCallbackPath);
            if (key is null) return;

            ctx.IncrementRegistryKeys();

            var obCallbackPath = key.GetValue("ObCallbackPath")?.ToString();
            if (!string.IsNullOrEmpty(obCallbackPath))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Kernel-ObCallback-Pfad gesetzt (RICOCHET-Bypass-Artefakt)",
                    Risk = RiskLevel.Critical,
                    Location = $@"HKLM\{kernelCallbackPath}\ObCallbackPath",
                    Reason = "Ein 'ObCallbackPath'-Wert im Kernel-Schluessel kann darauf hindeuten, " +
                             "dass ein Kernel-Callback-Removal-Tool die RICOCHET-Treiber-Callbacks " +
                             "entfernt hat, um die Cheat-Erkennung auf Kernel-Ebene zu verhindern.",
                    Detail = $"ObCallbackPath: {obCallbackPath}"
                });
            }
        }
        catch { }
    }

    private void CheckRicochetDriverIntegrity(ScanContext ctx)
    {
        // Check if ricochet.sys exists in the expected system driver location
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var expectedDriverPaths = new[]
        {
            Path.Combine(systemRoot, "System32", "drivers", RicochetDriverName),
            Path.Combine(systemRoot, "SysWOW64", "drivers", RicochetDriverName)
        };

        foreach (var driverPath in expectedDriverPaths)
        {
            if (!File.Exists(driverPath)) continue;

            ctx.IncrementFiles();

            bool signed = false;
            string? signer = null;
            try
            {
                var sigResult = SignatureChecker.CheckDetailed(driverPath);
                signed = sigResult.IsTrusted;
                signer = sigResult.Signer;
            }
            catch { }

            bool fromActivision = signed && signer is not null &&
                (signer.Contains("Activision", StringComparison.OrdinalIgnoreCase)
                 || signer.Contains("Infinity Ward", StringComparison.OrdinalIgnoreCase));

            if (!fromActivision)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RICOCHET-Kernel-Treiber nicht von Activision signiert",
                    Risk = RiskLevel.Critical,
                    Location = driverPath,
                    FileName = RicochetDriverName,
                    Sha256 = HashUtil.TryComputeSha256(driverPath, 64 * 1024 * 1024),
                    Signed = signed,
                    Reason = "Der RICOCHET-Anti-Cheat-Kernel-Treiber 'ricochet.sys' im System-Treiber-" +
                             "Verzeichnis ist nicht von Activision/Infinity Ward signiert. " +
                             "Ein nicht authentisch signierter oder ersetzter Kernel-Treiber ist ein " +
                             "kritisches Indiz fuer einen RICOCHET-Bypass auf Kernel-Ebene.",
                    Detail = signer is null ? "Unsigniert" : $"Signierer: {signer}"
                });
            }
        }

        // Check for ricochet.sys in user-accessible locations (should not exist there)
        var userSuspectPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
        };

        foreach (var userPath in userSuspectPaths)
        {
            if (string.IsNullOrEmpty(userPath)) continue;
            var suspect = Path.Combine(userPath, RicochetDriverName);
            if (!File.Exists(suspect)) continue;

            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"ricochet.sys in Benutzerpfad gefunden (verdaechtig)",
                Risk = RiskLevel.Critical,
                Location = suspect,
                FileName = RicochetDriverName,
                Sha256 = HashUtil.TryComputeSha256(suspect, 64 * 1024 * 1024),
                Reason = "Die Datei 'ricochet.sys' wurde in einem Benutzerpfad gefunden. " +
                         "Kernel-Treiber gehoeren ausschliesslich in Systemverzeichnisse. " +
                         "Ein ricochet.sys im Benutzerpfad ist ein starkes Indiz fuer ein " +
                         "RICOCHET-Bypass-Tool, das den Treiber ersetzen oder manipulieren will."
            });
        }
    }

    private void CheckBnetCodRegistry(ScanContext ctx)
    {
        // Battle.net client bypass configs for CoD
        var bnetCodPaths = new[]
        {
            @"SOFTWARE\Activision",
            @"SOFTWARE\WOW6432Node\Activision",
            @"SOFTWARE\Activision\Call of Duty",
            @"SOFTWARE\WOW6432Node\Activision\Call of Duty",
            @"SOFTWARE\Activision\Modern Warfare",
            @"SOFTWARE\WOW6432Node\Activision\Modern Warfare",
            @"SOFTWARE\Battle.net",
            @"SOFTWARE\WOW6432Node\Battle.net"
        };

        foreach (var regPath in bnetCodPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    if (valueName.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("disable_ac", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("ricochet_off", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("anticheat_off", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = key.GetValue(valueName)?.ToString();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger Activision/BNET-CoD-Registry-Wert: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{regPath}\{valueName}",
                            Reason = $"Der Registry-Wert '{valueName}' im Activision/Battle.net-Schluessel " +
                                     "enthaelt ein Schluessenwort (bypass/disable_ac/ricochet_off), " +
                                     "das auf einen gezielten RICOCHET-Bypass-Mechanismus hindeutet.",
                            Detail = val
                        });
                    }
                }
            }
            catch { }
        }

        // HKCU CoD/Warzone entries
        var hkcuCodPaths = new[]
        {
            @"Software\Activision",
            @"Software\Activision\Call of Duty",
            @"Software\Activision\Modern Warfare"
        };

        foreach (var regPath in hkcuCodPaths)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    if (valueName.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("disable_ac", StringComparison.OrdinalIgnoreCase)
                        || valueName.Contains("cheat", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = key.GetValue(valueName)?.ToString();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger CoD-Benutzer-Registry-Wert: {valueName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{regPath}\{valueName}",
                            Reason = $"Der Registry-Wert '{valueName}' im Activision-Benutzerschluessel " +
                                     "enthaelt einen Bezeichner, der auf einen Anti-Cheat-Bypass hindeutet.",
                            Detail = val
                        });
                    }
                }
            }
            catch { }
        }

        // Check if CoD/Warzone-related services are tampered
        var codRelatedServices = new[] { "wz_service", "cod_service", "ricochet_svc", "mw2_service" };
        foreach (var serviceName in codRelatedServices)
        {
            var svcPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(svcPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtiger CoD-bezogener Dienst in Registry: {serviceName}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{svcPath}",
                    Reason = $"Ein Dienst mit dem Namen '{serviceName}' wurde in der Registry gefunden. " +
                             "Dieser Dienstname entspricht einem bekannten Warzone/CoD-Cheat-Tool oder " +
                             "-Service-Namen, der von Cheat-Loadern registriert wird."
                });
            }
            catch { }
        }
    }

    private static List<string> FindCodInstallPaths()
    {
        var paths = new List<string>();

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // Battle.net CoD paths
        var bnetCodPath = Path.Combine(localAppData, "Battle.net", "Games", "Call of Duty");
        if (Directory.Exists(bnetCodPath)) paths.Add(bnetCodPath);

        // Steam CoD paths
        var steamAppsPath = FindSteamAppsPath();
        if (steamAppsPath is not null)
        {
            var steamCommonPath = Path.Combine(steamAppsPath, "common");
            if (Directory.Exists(steamCommonPath))
            {
                string[] subDirs = Array.Empty<string>();
                try { subDirs = Directory.GetDirectories(steamCommonPath); }
                catch { }

                foreach (var sub in subDirs)
                {
                    var dirName = Path.GetFileName(sub);
                    if (dirName.Contains("Call of Duty", StringComparison.OrdinalIgnoreCase)
                        || dirName.Contains("Warzone", StringComparison.OrdinalIgnoreCase)
                        || dirName.Contains("Modern Warfare", StringComparison.OrdinalIgnoreCase)
                        || dirName.StartsWith("CoD", StringComparison.OrdinalIgnoreCase)
                        || dirName.Contains("Black Ops", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!paths.Contains(sub, StringComparer.OrdinalIgnoreCase))
                            paths.Add(sub);
                    }
                }
            }
        }

        // %PROGRAMFILES%\Call of Duty and variants
        var explicitPaths = new[]
        {
            Path.Combine(programFiles, "Call of Duty"),
            Path.Combine(programFilesX86, "Call of Duty"),
            Path.Combine(programFiles, "Call of Duty Modern Warfare"),
            Path.Combine(programFilesX86, "Call of Duty Modern Warfare"),
            Path.Combine(programFiles, "Call of Duty Modern Warfare II"),
            Path.Combine(programFilesX86, "Call of Duty Modern Warfare II"),
            Path.Combine(programFiles, "Call of Duty Modern Warfare III"),
            Path.Combine(programFilesX86, "Call of Duty Modern Warfare III"),
            Path.Combine(programFiles, "Call of Duty Warzone"),
            Path.Combine(programFilesX86, "Call of Duty Warzone"),
            Path.Combine(programFiles, "Activision", "Call of Duty"),
            Path.Combine(programFilesX86, "Activision", "Call of Duty"),
            @"C:\Call of Duty",
            @"D:\Call of Duty"
        };

        foreach (var p in explicitPaths)
        {
            if (Directory.Exists(p) && !paths.Contains(p, StringComparer.OrdinalIgnoreCase))
                paths.Add(p);
        }

        // Registry-based path detection
        var regPaths = new[]
        {
            @"SOFTWARE\Activision\Call of Duty",
            @"SOFTWARE\WOW6432Node\Activision\Call of Duty",
            @"SOFTWARE\Activision\Modern Warfare",
            @"SOFTWARE\WOW6432Node\Activision\Modern Warfare"
        };

        foreach (var regPath in regPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                var installDir = key?.GetValue("InstallPath")?.ToString()
                                 ?? key?.GetValue("Install Dir")?.ToString();
                if (!string.IsNullOrEmpty(installDir) && Directory.Exists(installDir))
                {
                    if (!paths.Contains(installDir!, StringComparer.OrdinalIgnoreCase))
                        paths.Add(installDir!);
                }
            }
            catch { }
        }

        return paths;
    }

    private static string? FindSteamAppsPath()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
            var steamPath = key?.GetValue("SteamPath")?.ToString();
            if (!string.IsNullOrEmpty(steamPath))
            {
                var appsPath = Path.Combine(steamPath!, "steamapps");
                if (Directory.Exists(appsPath)) return appsPath;
            }
        }
        catch { }

        var defaultSteam = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Steam", "steamapps");
        return Directory.Exists(defaultSteam) ? defaultSteam : null;
    }

    private static IEnumerable<string> GetCodDocumentPaths()
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        yield return Path.Combine(docs, "Call of Duty");
        yield return Path.Combine(docs, "Call of Duty Modern Warfare");
        yield return Path.Combine(docs, "Call of Duty Modern Warfare 2");
        yield return Path.Combine(docs, "Call of Duty Modern Warfare 3");
        yield return Path.Combine(docs, "Call of Duty Warzone");
        yield return Path.Combine(docs, "Activision");
    }
}
