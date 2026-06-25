using Microsoft.Win32;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class BattlefieldCheatScanModule : IScanModule
{
    public string Name => "Battlefield Series Cheat Detection";
    public double Weight => 3.9;
    public int ParallelGroup => 4;

    // Known cheat process names targeting the Battlefield series
    private static readonly HashSet<string> CheatProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "BF2042Cheat", "BattlefieldCheat", "BF_Aimbot", "BF1Hack", "BFVCheat", "BF4Cheat",
        "BattlefieldESP", "BF2042External", "BF2042Internal", "BFVExternal", "BF1External",
        "BF4External", "BF4Aimbot", "BFVAimbot", "BF1Aimbot", "BF2042Hack", "BFHack",
        "BFLoader", "BattlefieldLoader", "BFInject", "BF2042Inject", "BFVInject",
        "BF4Radar", "BFRadar", "BF2042Radar", "BattlefieldRadar", "BFSpoofer",
        "BF2042Spoofer", "BFOverlay", "BF2042Overlay", "BattlefieldOverlay",
        "BFTrigger", "BF2042Trigger", "BFWallhack", "BF2042Wallhack",
        "BFNoRecoil", "BF2042NoRecoil", "BFUnlocker", "BF2042Unlocker",
        "EACBypassBF", "EACBypass2042", "PBBypass", "PunkBusterBypass",
        "BFDMAReader", "BF2042DMA", "BFExternalESP", "BF2042ExternalESP",
        "FrostbiteCheat", "FrostbiteHack", "FrostbiteESP", "FrostbiteAimbot",
        "OriginBypass", "EABypass", "EAAntiCheatBypass", "EAACBypass",
        "BFSilentAim", "BF2042SilentAim", "BFBoneAim", "BF2042BoneAim",
        "BFGodMode", "BF2042GodMode", "BFSpeedHack", "BF2042SpeedHack",
        "BFMemoryEditor", "BF2042Memory", "BFOffsetDumper", "BF2042Dumper"
    };

    // Known cheat file names (executables, DLLs, loaders)
    private static readonly HashSet<string> CheatFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "BF2042Cheat.exe", "BattlefieldCheat.exe", "BF_Aimbot.exe", "BF1Hack.exe",
        "BFVCheat.exe", "BF4Cheat.exe", "BattlefieldESP.exe", "BF2042External.exe",
        "BF2042Internal.dll", "BFVExternal.exe", "BF1External.exe", "BF4External.exe",
        "BF4Aimbot.exe", "BFVAimbot.exe", "BF1Aimbot.exe", "BF2042Hack.exe",
        "BFHack.exe", "BFLoader.exe", "BattlefieldLoader.exe", "BFInject.dll",
        "BF2042Inject.dll", "BFVInject.dll", "BF4Radar.exe", "BFRadar.exe",
        "BF2042Radar.exe", "BattlefieldRadar.exe", "BFSpoofer.exe", "BF2042Spoofer.exe",
        "BFOverlay.exe", "BF2042Overlay.exe", "BattlefieldOverlay.exe",
        "BFTrigger.exe", "BF2042Trigger.exe", "BFWallhack.exe", "BF2042Wallhack.exe",
        "BFNoRecoil.dll", "BF2042NoRecoil.dll", "BFUnlocker.exe", "BF2042Unlocker.exe",
        "EACBypassBF.exe", "EACBypassBF.dll", "PBBypass.dll", "PunkBusterBypass.dll",
        "BFDMAReader.exe", "BF2042DMA.exe", "FrostbiteCheat.exe", "FrostbiteHack.dll",
        "FrostbiteESP.dll", "FrostbiteAimbot.dll", "OriginBypass.dll", "EABypass.dll",
        "EAACBypass.dll", "BFSilentAim.dll", "BF2042SilentAim.dll",
        "BFBoneAim.dll", "BF2042BoneAim.dll", "BFMemoryEditor.exe",
        "BF2042Memory.exe", "BFOffsetDumper.exe", "BF2042Dumper.exe",
        "eac_launcher_bf.exe", "ricochet_bf.dll", "bf_anticheat_bypass.exe"
    };

    // Keywords found in cheat file names (partial matches)
    private static readonly string[] CheatFileKeywords =
    {
        "bf2042cheat", "bfcheat", "battlefield_cheat", "bfaimbot", "bfvesp",
        "bf1esp", "bf4esp", "bfhack", "bfbypass", "bfspoof", "frostbitecheat",
        "eacbypassbf", "pbbypass", "bfdma", "bfoverlay", "bftrigger"
    };

    // EAC bypass DLL names placed alongside BF2042 executable
    private static readonly HashSet<string> EacBypassDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "EasyAntiCheat.dll", "EasyAntiCheat_EOS.dll", "eac_launch_helper.dll",
        "EasyAntiCheat_x64.dll", "EasyAntiCheat_x86.dll", "eac_client.dll",
        "eac_core.dll", "eac_hooks.dll", "eac_bypass.dll", "eac_patcher.dll",
        "eac_loader.dll", "anticheat_helper.dll", "eac_inject.dll"
    };

    // PunkBuster bypass artifact file names
    private static readonly HashSet<string> PbBypassFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "pbcl.dll", "pbsv.dll", "pbag.dll", "pb_client.dll", "pb_server.dll",
        "pnkbstrA.exe", "pnkbstrB.exe", "pbhook.dll", "pbbypass.dll",
        "pbnull.dll", "pbpatch.dll", "pbloader.dll"
    };

    // Keywords in cheat config files (JSON, INI, CFG) specific to Battlefield
    private static readonly string[] BfCheatConfigKeywords =
    {
        "vehicle_esp", "soldier_esp", "ammo_esp", "bf_aimbot", "bf_esp",
        "bf2042_aimbot", "bf2042_esp", "frostbite_offset", "clientgamecontext",
        "clientplayer", "clientsoldierentity", "clientvehicleentity",
        "bf_radar", "bf_no_recoil", "bf_silent_aim", "bf_bone_aim",
        "bf_triggerbot", "bf_wallhack", "bf_godmode", "bf_speedhack",
        "bf_spoofer", "bf_hwid_spoof", "bf_aim_fov", "bf_aim_smoothing",
        "bf_aim_bone", "bf_aim_prediction", "bf_stream_proof",
        "bf_loot_esp", "bf_health_bar", "bf_distance_esp",
        "soldier_health", "vehicle_health", "ammo_count",
        "enable_aimbot_bf", "enable_esp_bf", "enable_radar_bf",
        "bf_aimkey", "bf_espkey", "bf_menukey", "bf_panickey"
    };

    // BF-specific memory offset file identifiers (class names in offset headers/JSON)
    private static readonly string[] BfOffsetIdentifiers =
    {
        "ClientGameContext", "ClientPlayer", "ClientSoldierEntity", "ClientVehicleEntity",
        "ClientProjectile", "ClientLevel", "ClientCharacterPhysicsEntity",
        "ClientControllableEntity", "BFClientPlayerManager", "FrostbiteGame",
        "FrostbiteRenderer", "ClientSpottingTargetComponent", "ClientHealthComponent",
        "EntryComponent", "UIManager", "RenderView", "GameRenderer",
        "ClientBulletEntity", "ClientExplosionEntity", "SpectatorCamEntity",
        "BF2042PlayerManager", "BF1PlayerManager", "BFVPlayerManager"
    };

    // Battlefield game executable names
    private static readonly string[] BfGameExecutables =
    {
        "BF2042.exe", "bf2042.exe", "Battlefield2042.exe",
        "bf1.exe", "Battlefield1.exe",
        "bfv.exe", "BFV.exe", "Battlefield5.exe",
        "bf4.exe", "bf4_x64.exe", "Battlefield4.exe",
        "bf3.exe", "Battlefield3.exe",
        "bf1942.exe", "Battlefield1942.exe"
    };

    // DX12/Vulkan hook DLL names that appear alongside BF titles
    private static readonly HashSet<string> DxHookDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "d3d12.dll", "dxgi.dll", "d3d11.dll", "vulkan-1.dll",
        "d3dhook.dll", "dx12hook.dll", "dxgi_hook.dll", "dxgihook.dll",
        "d3d12hook.dll", "bf_dx12hook.dll", "bf_dxgihook.dll",
        "reshade.dll", "ReShade64.dll", "dxgi_bf.dll", "d3d12_bf.dll"
    };

    // Registry service names for PunkBuster services
    private static readonly string[] PbServiceNames =
    {
        "PnkBstrA", "PnkBstrB", "PunkBuster", "PunkBusterA", "PunkBusterB"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Initialisierung...");

        var bfInstallPaths = FindBattlefieldInstallPaths();
        ctx.Report(0.05, Name, $"{bfInstallPaths.Count} Battlefield-Installationspfade gefunden");

        ScanRunningProcesses(ctx, ct);
        ctx.Report(0.15, Name, "Prozessueberpruefung abgeschlossen");

        await ScanCheatFilesInCommonLocations(ctx, ct);
        ctx.Report(0.40, Name, "Dateisuche abgeschlossen");

        foreach (var installPath in bfInstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            await ScanBattlefieldInstallDirectory(ctx, installPath, ct);
        }
        ctx.Report(0.65, Name, "Spielverzeichnis-Pruefungen abgeschlossen");

        await ScanCheatConfigFiles(ctx, ct);
        ctx.Report(0.75, Name, "Cheat-Konfigurationsdateien geprueft");

        await ScanMemoryOffsetFiles(ctx, ct);
        ctx.Report(0.85, Name, "Speicher-Offset-Dateien geprueft");

        CheckPunkBusterRegistry(ctx);
        ctx.Report(0.92, Name, "PunkBuster-Registry geprueft");

        CheckEAAntiCheatRegistry(ctx);
        ctx.Report(1.0, Name, "Battlefield-Cheat-Scan abgeschlossen");
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
                    Title = $"Battlefield-Cheat-Prozess aktiv: {procName}",
                    Risk = RiskLevel.Critical,
                    Location = string.IsNullOrEmpty(location) ? $"PID {proc.Id}" : location,
                    FileName = procName + ".exe",
                    Reason = $"Der Prozess '{procName}' ist ein bekanntes Battlefield-Cheat-Tool. " +
                             "Ein aktiver Cheat-Prozess ist der starkste Hinweis auf aktiven Cheat-Einsatz " +
                             "waehrend einer Spielsitzung."
                });
            }
            else
            {
                string? mainPath = null;
                try { mainPath = proc.MainModule?.FileName; }
                catch { }

                if (mainPath is not null)
                {
                    var fileName = Path.GetFileName(mainPath);
                    foreach (var keyword in CheatFileKeywords)
                    {
                        if (fileName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Verdaechtiger Battlefield-bezogener Prozess: {procName}",
                                Risk = RiskLevel.High,
                                Location = mainPath,
                                FileName = fileName,
                                Reason = $"Der Prozess '{procName}' enthaelt das Schluessenwort '{keyword}' " +
                                         "im Dateipfad, das auf ein Battlefield-Cheat-Tool hindeutet."
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    private async Task ScanCheatFilesInCommonLocations(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new List<string>();

        var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloadsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var tempPath = Path.GetTempPath();
        var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        foreach (var p in new[] { desktopPath, downloadsPath, appDataPath, localAppDataPath, tempPath, documentsPath })
        {
            if (!string.IsNullOrEmpty(p) && Directory.Exists(p))
                searchRoots.Add(p);
        }

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForCheatFiles(ctx, root, root, maxDepth: 3, ct);
        }
    }

    private async Task ScanDirectoryForCheatFiles(
        ScanContext ctx, string directory, string rootLabel, int maxDepth, CancellationToken ct)
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
                    Title = $"Bekannte Battlefield-Cheat-Datei: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes Battlefield-Cheat-Tool. " +
                             "Die Datei wurde in einer cheat-typischen Ablage gefunden."
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
                        Title = $"Verdaechtige Battlefield-bezogene Datei: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                        Reason = $"Die Datei '{fileName}' enthaelt das Schluessenwort '{keyword}', " +
                                 "das auf ein Battlefield-Cheat-Tool hindeutet."
                    });
                    break;
                }
            }

            var ext = Path.GetExtension(fileName);
            if (ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".ini", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
            {
                await ScanFileForCheatConfig(ctx, file, ct);
            }

            if (ext.Equals(".hpp", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".h", StringComparison.OrdinalIgnoreCase)
                || ext.Equals(".json", StringComparison.OrdinalIgnoreCase))
            {
                await ScanFileForOffsetIdentifiers(ctx, file, ct);
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
            await ScanDirectoryForCheatFiles(ctx, sub, rootLabel, maxDepth - 1, ct);
        }
    }

    private async Task ScanBattlefieldInstallDirectory(ScanContext ctx, string installPath, CancellationToken ct)
    {
        if (!Directory.Exists(installPath)) return;

        await CheckEacIntegrity(ctx, installPath, ct);
        await CheckPbBypassArtifacts(ctx, installPath, ct);
        await CheckDxHookDlls(ctx, installPath, ct);
        await CheckSuspiciousDllsAlongsideGame(ctx, installPath, ct);
    }

    private async Task CheckEacIntegrity(ScanContext ctx, string installPath, CancellationToken ct)
    {
        // BF2042 uses EAC (Easy Anti-Cheat). Check the EAC subfolder.
        var eacFolder = Path.Combine(installPath, "EasyAntiCheat");
        bool eacFolderMissing = !Directory.Exists(eacFolder);

        if (eacFolderMissing && ContainsBf2042Executable(installPath))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "EasyAntiCheat-Verzeichnis fehlt in BF2042-Installation",
                Risk = RiskLevel.Critical,
                Location = installPath,
                Reason = "Das EasyAntiCheat-Verzeichnis fehlt im BF2042-Installationsordner. " +
                         "BF2042 erfordert EAC. Ein fehlendes EAC-Verzeichnis ist ein starkes " +
                         "Indiz fuer eine tamperierte oder manipulierte Installation."
            });
            return;
        }

        if (!eacFolderMissing)
        {
            string[] eacFiles = Array.Empty<string>();
            try { eacFiles = Directory.GetFiles(eacFolder); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var f in eacFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(f);
                if (EacBypassDllNames.Contains(fileName))
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

                    if (!signed)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Unsignierte/suspekte EAC-DLL in BF-Verzeichnis: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = f,
                            FileName = fileName,
                            Sha256 = HashUtil.TryComputeSha256(f, 128 * 1024 * 1024),
                            Signed = false,
                            Reason = $"Die Datei '{fileName}' im EasyAntiCheat-Verzeichnis von Battlefield " +
                                     "ist nicht vertrauenswuerdig signiert. EAC-DLLs sind normalerweise " +
                                     "von Easy Anti-Cheat Solutions Ltd. signiert. Eine unsignierte oder " +
                                     "ersetzende DLL ist ein typischer EAC-Bypass-Mechanismus.",
                            Detail = signer is null ? "Kein Signierer" : $"Signierer: {signer}"
                        });
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task CheckPbBypassArtifacts(ScanContext ctx, string installPath, CancellationToken ct)
    {
        // PunkBuster files in BF4, BF3, BF1, BFV installs
        var pbFolder = Path.Combine(installPath, "pb");
        if (!Directory.Exists(pbFolder)) return;

        string[] pbFiles = Array.Empty<string>();
        try { pbFiles = Directory.GetFiles(pbFolder); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var f in pbFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(f);
            if (!PbBypassFileNames.Contains(fileName)) continue;

            bool signed = false;
            string? signer = null;
            try
            {
                var sigResult = SignatureChecker.CheckDetailed(f);
                signed = sigResult.IsTrusted;
                signer = sigResult.Signer;
            }
            catch { }

            if (!signed)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Unsignierte PunkBuster-Datei: {fileName}",
                    Risk = RiskLevel.High,
                    Location = f,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(f, 64 * 1024 * 1024),
                    Signed = false,
                    Reason = $"Die PunkBuster-Datei '{fileName}' im Battlefield-PB-Ordner ist " +
                             "nicht vertrauenswuerdig signiert. Legitime PB-Dateien sind von " +
                             "Even Balance Inc. signiert. Eine ersetzende oder unsignierte Datei " +
                             "deutet auf einen PunkBuster-Bypass hin.",
                    Detail = signer is null ? "Kein Signierer" : $"Signierer: {signer}"
                });
            }
        }

        await Task.CompletedTask;
    }

    private async Task CheckDxHookDlls(ScanContext ctx, string installPath, CancellationToken ct)
    {
        // Frostbite uses DX12. Hook DLLs placed in the game folder intercept rendering.
        string[] gameFiles = Array.Empty<string>();
        try { gameFiles = Directory.GetFiles(installPath); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var f in gameFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(f);
            if (!DxHookDllNames.Contains(fileName)) continue;

            bool signed = false;
            string? signer = null;
            try
            {
                var sigResult = SignatureChecker.CheckDetailed(f);
                signed = sigResult.IsTrusted;
                signer = sigResult.Signer;
            }
            catch { }

            // A DX12/DXGI DLL signed by Microsoft is expected in the system.
            // One placed in the game's install directory and not from Microsoft is suspicious.
            bool fromMicrosoft = signed && signer is not null &&
                signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);

            if (!fromMicrosoft)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtige DX/DXGI-Hook-DLL im BF-Spielverzeichnis: {fileName}",
                    Risk = signed ? RiskLevel.Medium : RiskLevel.High,
                    Location = f,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(f, 128 * 1024 * 1024),
                    Signed = signed,
                    Reason = $"Die DLL '{fileName}' im Battlefield-Spielverzeichnis ist eine bekannte " +
                             "DirectX/DXGI-DLL, die jedoch nicht von Microsoft stammt. Battlefield nutzt " +
                             "Frostbite + DX12. Eine nicht von Microsoft signierte DX-DLL im Spielordner " +
                             "ist ein typisches Rendering-Hook-Muster fuer ESP/Wallhack-Cheats.",
                    Detail = signer is null ? "Unsigniert" : $"Signierer: {signer}"
                });
            }
        }

        await Task.CompletedTask;
    }

    private async Task CheckSuspiciousDllsAlongsideGame(ScanContext ctx, string installPath, CancellationToken ct)
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
            var fileNameLower = fileName.ToLowerInvariant();
            var ext = Path.GetExtension(fileName);

            if (!ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                && !ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)) continue;

            foreach (var keyword in CheatFileKeywords)
            {
                if (fileNameLower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige Datei im Battlefield-Spielverzeichnis: {fileName}",
                        Risk = RiskLevel.High,
                        Location = f,
                        FileName = fileName,
                        Sha256 = HashUtil.TryComputeSha256(f, 128 * 1024 * 1024),
                        Reason = $"Die Datei '{fileName}' im Battlefield-Spielverzeichnis enthaelt " +
                                 $"das Schluessenwort '{keyword}', das auf ein Cheat-Tool oder eine " +
                                 "Injektionsbibliothek hinweist."
                    });
                    break;
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanCheatConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        var configSearchPaths = new List<string>();

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        foreach (var p in new[] { appData, localAppData, documents, desktop, downloads })
        {
            if (!string.IsNullOrEmpty(p) && Directory.Exists(p))
                configSearchPaths.Add(p);
        }

        // Also check BF-specific config locations
        foreach (var p in GetBfDocumentPaths())
        {
            if (Directory.Exists(p)) configSearchPaths.Add(p);
        }

        var configExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".cfg", ".json", ".ini", ".txt", ".xml", ".yaml", ".yml" };

        foreach (var root in configSearchPaths)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForConfigKeywords(ctx, root, configExtensions, maxDepth: 3, ct);
        }
    }

    private async Task ScanDirectoryForConfigKeywords(
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
            await ScanDirectoryForConfigKeywords(ctx, sub, extensions, maxDepth - 1, ct);
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

        if (content.Length > 1024 * 1024) return; // skip files > 1 MB for config scanning

        var hitKeywords = new List<string>();
        foreach (var keyword in BfCheatConfigKeywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                hitKeywords.Add(keyword);
        }

        if (hitKeywords.Count >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Battlefield-Cheat-Konfigurationsdatei: {Path.GetFileName(filePath)}",
                Risk = hitKeywords.Count >= 4 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = Path.GetFileName(filePath),
                Reason = $"Die Datei enthaelt {hitKeywords.Count} Battlefield-cheat-spezifische " +
                         "Schluesselbegriffe, die typisch fuer Cheat-Konfigurationsdateien sind " +
                         "(Aimbot, ESP, Radar, Spoofer-Parameter).",
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

        if (content.Length > 512 * 1024) return; // skip very large files for offset scanning

        var hitIdentifiers = new List<string>();
        foreach (var identifier in BfOffsetIdentifiers)
        {
            if (content.Contains(identifier, StringComparison.OrdinalIgnoreCase))
                hitIdentifiers.Add(identifier);
        }

        if (hitIdentifiers.Count >= 3)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Battlefield-Speicher-Offset-Datei: {Path.GetFileName(filePath)}",
                Risk = hitIdentifiers.Count >= 5 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = Path.GetFileName(filePath),
                Reason = $"Die Datei enthaelt {hitIdentifiers.Count} Battlefield-spezifische " +
                         "Speicher-Klassen-Bezeichner (z.B. ClientGameContext, ClientSoldierEntity). " +
                         "Solche Dateien enthalten Speicheradressen und Offset-Tabellen fuer " +
                         "Battlefield-Cheat-Software.",
                Detail = "Bezeichner: " + string.Join(", ", hitIdentifiers.Take(8))
            });
        }
    }

    private void CheckPunkBusterRegistry(ScanContext ctx)
    {
        // Check if PunkBuster services are disabled (bypass artifact)
        foreach (var serviceName in PbServiceNames)
        {
            var keyPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                var startValue = key.GetValue("Start");
                if (startValue is int startInt && startInt == 4) // 4 = Disabled
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PunkBuster-Dienst deaktiviert: {serviceName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{keyPath}\Start",
                        Reason = $"Der PunkBuster-Dienst '{serviceName}' ist in der Registry als " +
                                 "deaktiviert (Start=4) eingetragen. Battlefield-Titel (BF4, BF1, BFV) " +
                                 "nutzen PunkBuster als Anti-Cheat. Ein deaktivierter PB-Dienst ist " +
                                 "ein typisches Muster zum Umgehen der Anti-Cheat-Erkennung.",
                        Detail = $"Start-Wert: {startInt} (4 = deaktiviert)"
                    });
                }
            }
            catch { }
        }

        // Check for PunkBuster bypass registry artifacts
        var pbBypassRegPaths = new[]
        {
            @"SOFTWARE\PunkBuster",
            @"SOFTWARE\EvenBalance",
            @"SOFTWARE\WOW6432Node\PunkBuster",
            @"SOFTWARE\WOW6432Node\EvenBalance"
        };

        foreach (var regPath in pbBypassRegPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                var disableValue = key.GetValue("Disabled") ?? key.GetValue("Bypass");
                if (disableValue is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PunkBuster-Bypass-Registry-Wert gefunden",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{regPath}",
                        Reason = "Ein 'Disabled' oder 'Bypass' Registry-Wert im PunkBuster-Schluessel " +
                                 "weist auf eine gezielte Deaktivierung des Anti-Cheat-Systems hin.",
                        Detail = $"Wert: {disableValue}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckEAAntiCheatRegistry(ScanContext ctx)
    {
        // EA Anti-Cheat (EAAC) service used by BF2042
        var eaacServicePath = @"SYSTEM\CurrentControlSet\Services\EAAntiCheat";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(eaacServicePath);
            if (key is not null)
            {
                ctx.IncrementRegistryKeys();

                var startValue = key.GetValue("Start");
                if (startValue is int startInt && startInt == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "EA Anti-Cheat-Dienst deaktiviert (BF2042)",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{eaacServicePath}\Start",
                        Reason = "Der EA Anti-Cheat-Dienst (EAAntiCheat) ist in der Registry deaktiviert. " +
                                 "BF2042 setzt EA Anti-Cheat als primares Anti-Cheat-System ein. " +
                                 "Ein deaktivierter EAAC-Dienst ist ein starkes Indiz fuer " +
                                 "Anti-Cheat-Bypass-Aktivitaet.",
                        Detail = $"Start-Wert: {startInt} (4 = deaktiviert)"
                    });
                }
            }
        }
        catch { }

        // Check for EAC bypass registry entries
        var eacBypassPaths = new[]
        {
            @"SOFTWARE\EasyAntiCheat",
            @"SOFTWARE\WOW6432Node\EasyAntiCheat"
        };

        foreach (var regPath in eacBypassPaths)
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
                        || valueName.Contains("patch", StringComparison.OrdinalIgnoreCase))
                    {
                        var val = key.GetValue(valueName)?.ToString();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger EAC-Registry-Wert: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{regPath}\{valueName}",
                            Reason = $"Der Registry-Wert '{valueName}' im EasyAntiCheat-Schluessel " +
                                     "enthaelt ein Schluessenwort (bypass/disable/patch), das auf " +
                                     "einen EAC-Bypass-Mechanismus hindeutet.",
                            Detail = val
                        });
                    }
                }
            }
            catch { }
        }
    }

    private static List<string> FindBattlefieldInstallPaths()
    {
        var paths = new List<string>();

        // EA App paths (newer EA launcher)
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var eaAppRoots = new[]
        {
            Path.Combine(programFiles, "EA Games"),
            Path.Combine(programFilesX86, "EA Games"),
            Path.Combine(programFiles, "Electronic Arts"),
            Path.Combine(programFilesX86, "Electronic Arts")
        };

        foreach (var eaRoot in eaAppRoots)
        {
            if (!Directory.Exists(eaRoot)) continue;

            string[] subDirs = Array.Empty<string>();
            try { subDirs = Directory.GetDirectories(eaRoot); }
            catch { continue; }

            foreach (var sub in subDirs)
            {
                var dirName = Path.GetFileName(sub);
                if (dirName.Contains("Battlefield", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("BF2042", StringComparison.OrdinalIgnoreCase)
                    || dirName.StartsWith("BF", StringComparison.OrdinalIgnoreCase))
                {
                    paths.Add(sub);
                }
            }
        }

        // Origin paths (legacy)
        var originRoots = new[]
        {
            Path.Combine(programFiles, "Origin Games"),
            Path.Combine(programFilesX86, "Origin Games")
        };

        foreach (var originRoot in originRoots)
        {
            if (!Directory.Exists(originRoot)) continue;

            string[] subDirs = Array.Empty<string>();
            try { subDirs = Directory.GetDirectories(originRoot); }
            catch { continue; }

            foreach (var sub in subDirs)
            {
                var dirName = Path.GetFileName(sub);
                if (dirName.Contains("Battlefield", StringComparison.OrdinalIgnoreCase)
                    || dirName.StartsWith("BF", StringComparison.OrdinalIgnoreCase))
                {
                    paths.Add(sub);
                }
            }
        }

        // Steam paths for BF1, BFV, BF4 etc.
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
                    if (dirName.Contains("Battlefield", StringComparison.OrdinalIgnoreCase)
                        || dirName.StartsWith("BF", StringComparison.OrdinalIgnoreCase))
                    {
                        paths.Add(sub);
                    }
                }
            }
        }

        // Well-known explicit paths
        var explicitPaths = new[]
        {
            Path.Combine(programFiles, "EA Games", "Battlefield 2042"),
            Path.Combine(programFilesX86, "Origin Games", "Battlefield 2042"),
            Path.Combine(programFiles, "Origin Games", "Battlefield 1"),
            Path.Combine(programFilesX86, "Origin Games", "Battlefield 1"),
            Path.Combine(programFiles, "Origin Games", "Battlefield V"),
            Path.Combine(programFilesX86, "Origin Games", "Battlefield V"),
            Path.Combine(programFiles, "Origin Games", "Battlefield 4"),
            Path.Combine(programFilesX86, "Origin Games", "Battlefield 4")
        };

        foreach (var p in explicitPaths)
        {
            if (Directory.Exists(p) && !paths.Contains(p, StringComparer.OrdinalIgnoreCase))
                paths.Add(p);
        }

        // Registry-based path detection
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\EA Games\Battlefield 2042");
            var installDir = key?.GetValue("Install Dir")?.ToString();
            if (!string.IsNullOrEmpty(installDir) && Directory.Exists(installDir))
            {
                if (!paths.Contains(installDir, StringComparer.OrdinalIgnoreCase))
                    paths.Add(installDir!);
            }
        }
        catch { }

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

    private static bool ContainsBf2042Executable(string directory)
    {
        return BfGameExecutables.Any(exe =>
        {
            var fullPath = Path.Combine(directory, exe);
            return File.Exists(fullPath);
        });
    }

    private static IEnumerable<string> GetBfDocumentPaths()
    {
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        yield return Path.Combine(docs, "Battlefield 2042");
        yield return Path.Combine(docs, "Battlefield 1");
        yield return Path.Combine(docs, "Battlefield V");
        yield return Path.Combine(docs, "Battlefield 4");
        yield return Path.Combine(docs, "Battlefield 3");
    }
}
