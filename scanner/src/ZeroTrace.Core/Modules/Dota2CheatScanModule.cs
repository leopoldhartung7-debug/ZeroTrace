using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class Dota2CheatScanModule : IScanModule
{
    public string Name => "Dota 2 Cheat Detection";
    public double Weight => 3.7;
    public int ParallelGroup => 4;

    // ---------------------------------------------------------------------------
    // Known cheat executable and DLL names
    // ---------------------------------------------------------------------------
    private static readonly HashSet<string> CheatFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "dota2cheat.exe", "dotahack.exe", "dotaaimbot.exe", "dota2external.exe",
        "dota2internal.dll", "maphack.exe", "dota2maphack.exe", "dota_maphack.exe",
        "gabe_cheat.exe", "pasha_cheat.exe", "dota2esp.exe", "dota2bot.exe",
        "dota2script.exe", "dota2hack.exe", "dotaexternal.exe", "dotabot.exe",
        "dotaesp.exe", "dotascript.exe", "dota_aimbot.exe", "dota_esp.exe",
        "dota_hack.exe", "dota_bot.exe", "d2cheat.exe", "d2hack.exe",
        "d2maphack.exe", "d2esp.exe", "d2aimbot.exe", "d2loader.exe",
        "dota2loader.exe", "dota2injector.exe", "dotainjector.exe",
        "dota2bypass.exe", "dota_bypass.exe", "dota2spoofer.exe",
        "dotaspoofer.exe", "dota_spoofer.exe", "valve_bypass.exe",
        "vac_bypass_dota.exe", "vac_dota.exe", "dota_vac_bypass.exe",
        "steamhook.dll", "steamwhore.dll", "dota2hook.dll", "dotahook.dll",
        "dota_hook.dll", "d2hook.dll", "dota2overlay.exe", "dota_overlay.exe",
        "dota2radar.exe", "dota_radar.exe", "dota2wallhack.exe",
        "dota_wallhack.exe", "dota2triggerbot.exe", "dota_triggerbot.exe",
        "dota2combo.exe", "dota_combo.exe", "dota2orbwalk.exe",
        "dota_orbwalk.exe", "courier_hack.exe", "rune_hack.exe",
        "minimap_hack.exe", "fogofwar_bypass.exe"
    };

    // ---------------------------------------------------------------------------
    // VAC bypass / game-integrity compromise DLL names
    // ---------------------------------------------------------------------------
    private static readonly HashSet<string> VacBypassDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "steamwhore.dll", "steamhook.dll", "vac_bypass.dll", "vacbypass.dll",
        "be_bypass.dll", "bypass.dll", "inject.dll", "loader.dll",
        "steam_api_bypass.dll", "steam_bypass.dll", "steamapi_hook.dll",
        "anti_vac.dll", "antivac.dll", "d2hook.dll", "dota2hook.dll"
    };

    // ---------------------------------------------------------------------------
    // Suspicious replacement DLLs inside the Dota2 binary tree
    // ---------------------------------------------------------------------------
    private static readonly HashSet<string> SuspiciousGameDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "panorama.dll", "tier0.dll", "steam_api64.dll", "steam_api.dll",
        "gameoverlayrenderer64.dll", "gameoverlayrenderer.dll"
    };

    // ---------------------------------------------------------------------------
    // Cheat config keyword patterns (maphack, ESP, automation)
    // ---------------------------------------------------------------------------
    private static readonly string[] CheatConfigKeywords =
    {
        "maphack_enable", "esp_heroes", "esp_creeps", "hero_esp",
        "courier_esp", "ward_esp", "rune_esp", "item_esp_dota",
        "auto_lasthit", "auto_deny", "aimbot_dota", "orbwalker_dota",
        "combo_executor", "auto_disable", "projectile_dodge",
        "creep_stack", "camp_stack", "maphack_alpha", "maphack_color",
        "esp_enemy_only", "esp_visible_only", "esp_range",
        "hero_model_esp", "item_pickup_esp", "shrine_esp",
        "tree_esp", "ward_vision_esp", "scan_esp",
        "camera_hack", "zoom_hack", "speed_hack_dota",
        "auto_attack_dota", "auto_courier", "courier_auto_upgrade",
        "ancient_stack", "jungle_timer_dota", "respawn_timer",
        "buyback_timer", "roshan_timer", "roshan_esp",
        "illusion_esp", "blink_prediction", "hex_prediction",
        "stun_prediction", "pull_timer", "auto_item_dota",
        "auto_blink", "auto_shadow_amulet", "linken_sphere_break"
    };

    // ---------------------------------------------------------------------------
    // Memory offset indicators: strings appearing in cheat headers / JSON configs
    // ---------------------------------------------------------------------------
    private static readonly string[] MemoryOffsetKeywords =
    {
        "C_DOTAPlayer", "C_BaseNPC_Hero", "m_iHealth", "m_iTeamNum",
        "m_iTaggedAsVisibleByTeam", "m_bIsWaitingToSpawn",
        "m_hAbilities", "m_hItems", "CDOTABaseAbility",
        "m_iCurrentXP", "m_iDamageMin", "m_iDamageMax",
        "m_fCooldown", "m_flMana", "m_flMaxMana",
        "m_vecNetworkOrigin", "C_DOTAGameManager",
        "m_hGameEntity", "CDOTAGamerules",
        "m_nGameState", "m_fGameTime", "dota_local_player_index",
        "GetLocalPlayer", "GetEntityList", "C_DOTABaseNPC"
    };

    // ---------------------------------------------------------------------------
    // Suspicious Lua / Python script patterns
    // ---------------------------------------------------------------------------
    private static readonly string[] CheatScriptKeywords =
    {
        "maphack", "map_hack", "fogofwar", "fog_of_war_bypass",
        "reveal_map", "GetHeroList", "GetNearbyHeroes",
        "GetNearbyCreeps", "auto_lasthit", "auto_deny",
        "orbwalk", "orb_walk", "combo_key", "aimbot",
        "triggerbot", "ProjectileDodge", "blink_dagger",
        "auto_courier_upgrade", "stolen_items",
        "courier_tracking", "ward_esp", "courier_esp",
        "EntityList", "GetLocalHero", "GetUnitAbilityList",
        "ExecuteOrder", "lua_State", "GetCVar", "SetCVar",
        "SendCommand", "dota_camera_distance"
    };

    // ---------------------------------------------------------------------------
    // Dota2 install path candidates
    // ---------------------------------------------------------------------------
    private static IEnumerable<string> GetDota2Roots()
    {
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // Common Steam library paths
        var steamPaths = new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\dota 2 beta",
            @"C:\Program Files\Steam\steamapps\common\dota 2 beta",
            @"D:\Steam\steamapps\common\dota 2 beta",
            @"D:\SteamLibrary\steamapps\common\dota 2 beta",
            @"E:\Steam\steamapps\common\dota 2 beta",
            @"E:\SteamLibrary\steamapps\common\dota 2 beta",
            @"F:\Steam\steamapps\common\dota 2 beta",
            @"F:\SteamLibrary\steamapps\common\dota 2 beta",
            Path.Combine(localApp, "dota2"),
            Path.Combine(localApp, "Steam", "steamapps", "common", "dota 2 beta"),
        };

        // Also probe Steam library folders from registry
        foreach (var regPath in GetSteamLibraryPathsFromRegistry())
        {
            yield return Path.Combine(regPath, "steamapps", "common", "dota 2 beta");
        }

        foreach (var p in steamPaths)
            yield return p;
    }

    private static IEnumerable<string> GetSteamLibraryPathsFromRegistry()
    {
        var regKeys = new[]
        {
            @"SOFTWARE\Valve\Steam",
            @"SOFTWARE\WOW6432Node\Valve\Steam"
        };
        foreach (var keyPath in regKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key is null) continue;
                var installPath = key.GetValue("InstallPath")?.ToString();
                if (!string.IsNullOrEmpty(installPath))
                    yield return installPath;
            }
            catch { }
        }
    }

    // ---------------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------------
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // Phase 1: check running processes for known cheat process names
        ctx.Report(0.0, "Prozesse", "Dota2-Cheat-Prozesse werden geprueft");
        CheckRunningProcesses(ctx);
        ctx.Report(0.10, "Prozesse", "Prozess-Pruefung abgeschlossen");
        ct.ThrowIfCancellationRequested();

        // Phase 2: locate Dota2 installation roots and scan file system
        var dota2Roots = GetDota2Roots()
            .Where(Directory.Exists)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        ctx.Report(0.12, "Installationspfade", $"{dota2Roots.Count} Dota2-Installation(en) gefunden");

        if (dota2Roots.Count == 0)
        {
            ctx.Report(0.20, "Installation", "Keine Dota2-Installation gefunden; Datei-Pruefungen uebersprungen");
        }
        else
        {
            int rootIdx = 0;
            foreach (var root in dota2Roots)
            {
                ct.ThrowIfCancellationRequested();
                double baseProgress = 0.12 + (double)rootIdx / dota2Roots.Count * 0.40;
                await ScanDota2InstallationAsync(ctx, root, baseProgress, ct).ConfigureAwait(false);
                rootIdx++;
            }
        }

        ctx.Report(0.55, "Game-Verzeichnis", "Installations-Scan abgeschlossen");
        ct.ThrowIfCancellationRequested();

        // Phase 3: scan AppData / script directories
        await ScanScriptDirectoriesAsync(ctx, ct).ConfigureAwait(false);
        ctx.Report(0.72, "Skripte", "Skript-Verzeichnisse abgeschlossen");
        ct.ThrowIfCancellationRequested();

        // Phase 4: scan config files across known cheat config locations
        await ScanCheatConfigLocationsAsync(ctx, ct).ConfigureAwait(false);
        ctx.Report(0.85, "Configs", "Cheat-Config-Pruefung abgeschlossen");
        ct.ThrowIfCancellationRequested();

        // Phase 5: registry checks
        CheckRegistry(ctx);
        ctx.Report(1.0, "Registry", "Dota2-Cheat-Erkennung abgeschlossen");
    }

    // ---------------------------------------------------------------------------
    // Phase 1 – Running processes
    // ---------------------------------------------------------------------------
    private void CheckRunningProcesses(ScanContext ctx)
    {
        var procs = ctx.GetProcessSnapshot();
        foreach (var proc in procs)
        {
            ctx.IncrementProcesses();
            try
            {
                var procName = proc.ProcessName;
                var exeName = procName + ".exe";

                if (CheatFileNames.Contains(exeName))
                {
                    string location;
                    try { location = proc.MainModule?.FileName ?? procName; }
                    catch { location = procName; }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Dota2-Cheat-Prozess aktiv: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = location,
                        FileName = exeName,
                        Reason = $"Der Prozess '{exeName}' (PID {proc.Id}) ist eine bekannte Dota2-Cheat-Anwendung " +
                                 "und lauft aktiv. Dies ist ein starker Hinweis auf aktiven Cheat-Einsatz.",
                        Detail = $"PID: {proc.Id}"
                    });
                    continue;
                }

                // Generic heuristic: process name contains dota and cheat keywords
                if (ContainsDota2CheatKeywords(procName))
                {
                    string location;
                    try { location = proc.MainModule?.FileName ?? procName; }
                    catch { location = procName; }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiger Prozess mit Dota2-Bezug: {exeName}",
                        Risk = RiskLevel.High,
                        Location = location,
                        FileName = exeName,
                        Reason = $"Prozessname '{procName}' enthaelt Schluesselwoerter, die auf ein Dota2-Cheat-Tool " +
                                 "hindeuten. Kontext und Herkunft der Datei pruefen.",
                        Detail = $"PID: {proc.Id}"
                    });
                }
            }
            catch { }
        }
    }

    private static bool ContainsDota2CheatKeywords(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        bool hasDota = name.Contains("dota", StringComparison.OrdinalIgnoreCase) ||
                       name.Contains("d2cheat", StringComparison.OrdinalIgnoreCase);
        bool hasCheat = name.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("maphack", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("esp", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("bypass", StringComparison.OrdinalIgnoreCase);
        return hasDota && hasCheat;
    }

    // ---------------------------------------------------------------------------
    // Phase 2 – Installation directory scan
    // ---------------------------------------------------------------------------
    private async Task ScanDota2InstallationAsync(ScanContext ctx, string root, double baseProgress, CancellationToken ct)
    {
        // 2a: top-level suspicious executables / DLLs
        await ScanDirectoryForCheatFilesAsync(ctx, root, shallow: false, baseProgress, ct).ConfigureAwait(false);

        // 2b: VAC bypass DLLs anywhere in the install tree
        await ScanForVacBypassDllsAsync(ctx, root, ct).ConfigureAwait(false);

        // 2c: suspicious replacement DLLs in the binary directory
        var binDir64 = Path.Combine(root, "game", "dota", "bin", "win64");
        var binDir32 = Path.Combine(root, "game", "dota", "bin", "win32");
        foreach (var binDir in new[] { binDir64, binDir32 })
        {
            if (Directory.Exists(binDir))
                await ScanBinaryDirForReplacementsAsync(ctx, binDir, ct).ConfigureAwait(false);
        }

        // 2d: vscripts directory for cheat scripts
        var vscriptsDir = Path.Combine(root, "game", "dota", "scripts", "vscripts");
        if (Directory.Exists(vscriptsDir))
            await ScanScriptDirAsync(ctx, vscriptsDir, "vscripts (Dota2-Install)", ct).ConfigureAwait(false);

        // 2e: custom game directories
        var customGamesDir = Path.Combine(root, "game", "dota_addons");
        if (Directory.Exists(customGamesDir))
            await ScanCustomGameDirAsync(ctx, customGamesDir, ct).ConfigureAwait(false);

        // 2f: console command injection configs
        var cfgDir = Path.Combine(root, "game", "dota", "cfg");
        if (Directory.Exists(cfgDir))
            await ScanCfgDirAsync(ctx, cfgDir, ct).ConfigureAwait(false);
    }

    private async Task ScanDirectoryForCheatFilesAsync(ScanContext ctx, string dir, bool shallow, double baseProgress, CancellationToken ct)
    {
        string[] files;
        try
        {
            files = Directory.GetFiles(dir, "*.*",
                shallow ? SearchOption.TopDirectoryOnly : SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        int total = Math.Max(files.Length, 1);
        int processed = 0;

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            processed++;

            if (processed % 50 == 0)
                ctx.Report(baseProgress + 0.05 * processed / total, dir, $"{processed}/{total} Dateien");

            var fileName = Path.GetFileName(file);
            if (CheatFileNames.Contains(fileName))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Bekannte Dota2-Cheat-Datei gefunden: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                    Reason = $"Die Datei '{fileName}' ist eine bekannte Dota2-Cheat-Anwendung oder -Komponente. " +
                             "Ihr Vorhandensein ist ein starkes Indiz fuer Cheat-Nutzung.",
                    Detail = $"Pfad: {file}"
                });
                continue;
            }

            // Heuristic: file name suggests dota2 cheat
            if (IsSuspiciousDota2FileName(fileName))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtiger Dateiname mit Dota2-Bezug: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                    Reason = $"Der Dateiname '{fileName}' enthaelt Muster, die auf ein Dota2-Cheat-Tool hindeuten. " +
                             "Datei pruefen und ggf. entfernen.",
                    Detail = $"Pfad: {file}"
                });
                continue;
            }

            // Content-scan text-based files for memory offsets and cheat config patterns
            var ext = Path.GetExtension(fileName);
            if (IsTextLikeExtension(ext))
            {
                await ScanFileContentAsync(ctx, file, ct).ConfigureAwait(false);
            }
        }
    }

    private static bool IsSuspiciousDota2FileName(string fileName)
    {
        if (string.IsNullOrEmpty(fileName)) return false;
        var lower = fileName.ToLowerInvariant();
        bool hasDota = lower.Contains("dota") || lower.Contains("d2cheat") || lower.Contains("dotahack");
        bool hasCheat = lower.Contains("cheat") || lower.Contains("hack") || lower.Contains("maphack") ||
                        lower.Contains("aimbot") || lower.Contains("esp") || lower.Contains("inject") ||
                        lower.Contains("bypass") || lower.Contains("orbwalk") || lower.Contains("loader");
        return hasDota && hasCheat;
    }

    private static bool IsTextLikeExtension(string ext)
    {
        return ext.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".ini", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".txt", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".lua", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".py", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".hpp", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".h", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".xml", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".yaml", StringComparison.OrdinalIgnoreCase) ||
               ext.Equals(".toml", StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------------------
    // VAC bypass DLL scan
    // ---------------------------------------------------------------------------
    private async Task ScanForVacBypassDllsAsync(ScanContext ctx, string root, CancellationToken ct)
    {
        string[] files;
        try { files = Directory.GetFiles(root, "*.dll", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(file);

            if (VacBypassDllNames.Contains(fileName))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"VAC-Bypass-DLL im Dota2-Verzeichnis: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                    Reason = $"Die DLL '{fileName}' ist eine bekannte Steam/VAC-Bypass-Komponente und wurde im " +
                             "Dota2-Spielverzeichnis gefunden. Dies deutet auf einen Versuch hin, " +
                             "die Anti-Cheat-Erkennung zu umgehen.",
                    Detail = $"Pfad: {file}"
                });
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Binary directory replacement check
    // ---------------------------------------------------------------------------
    private async Task ScanBinaryDirForReplacementsAsync(ScanContext ctx, string binDir, CancellationToken ct)
    {
        string[] files;
        try { files = Directory.GetFiles(binDir, "*.dll", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(file);
            ctx.IncrementFiles();

            if (SuspiciousGameDllNames.Contains(fileName))
            {
                // Check if the file is signed by Valve
                var sig = SignatureChecker.CheckDetailed(file);
                bool isValveSigned = sig.IsTrusted && sig.Signer is not null &&
                    (sig.Signer.Contains("Valve", StringComparison.OrdinalIgnoreCase) ||
                     sig.Signer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase));

                if (!isValveSigned)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Moegliche Dota2-DLL-Ersetzung: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Sha256 = HashUtil.TryComputeSha256(file, 128 * 1024 * 1024),
                        Signed = sig.IsTrusted,
                        Detail = sig.Signer is null ? "Nicht signiert" : $"Signierer: {sig.Signer}",
                        Reason = $"Die Datei '{fileName}' im Dota2-Bin-Verzeichnis ist nicht von Valve signiert. " +
                                 "Eine nicht von Valve signierte Kopie dieser Systemdatei deutet auf eine " +
                                 "Manipulation hin (z.B. Maphack-Overlay in panorama.dll oder Client-DLL-Ersatz)."
                    });
                }
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // ---------------------------------------------------------------------------
    // Script directory scan (Lua, Python)
    // ---------------------------------------------------------------------------
    private async Task ScanScriptDirAsync(ScanContext ctx, string dir, string label, CancellationToken ct)
    {
        string[] files;
        try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(file);
            if (!ext.Equals(".lua", StringComparison.OrdinalIgnoreCase) &&
                !ext.Equals(".py", StringComparison.OrdinalIgnoreCase) &&
                !ext.Equals(".js", StringComparison.OrdinalIgnoreCase) &&
                !ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
                continue;

            string content;
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync().ConfigureAwait(false);
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            ctx.IncrementFiles();

            foreach (var keyword in CheatScriptKeywords)
            {
                if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiges Skript ({label}): {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Skript-Datei '{Path.GetFileName(file)}' enthaelt das Muster '{keyword}', " +
                                 "das typischerweise in Dota2-Cheat-Skripten verwendet wird (Maphack, ESP, Automatisierung).",
                        Detail = $"Fundstelle: '{keyword}'"
                    });
                    break;
                }
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Custom game (addon) directory scan
    // ---------------------------------------------------------------------------
    private async Task ScanCustomGameDirAsync(ScanContext ctx, string addonsDir, CancellationToken ct)
    {
        string[] subDirs;
        try { subDirs = Directory.GetDirectories(addonsDir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var addonDir in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            var vscriptsDir = Path.Combine(addonDir, "scripts", "vscripts");
            if (Directory.Exists(vscriptsDir))
                await ScanScriptDirAsync(ctx, vscriptsDir, $"custom_game:{Path.GetFileName(addonDir)}", ct).ConfigureAwait(false);
        }
    }

    // ---------------------------------------------------------------------------
    // Config file (CFG) scan for console command injection
    // ---------------------------------------------------------------------------
    private async Task ScanCfgDirAsync(ScanContext ctx, string cfgDir, CancellationToken ct)
    {
        string[] files;
        try { files = Directory.GetFiles(cfgDir, "*.cfg", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        var consoleInjectionPatterns = new[]
        {
            "dota_camera_distance", "dota_minimap_misclick_treshold",
            "sv_cheats", "mat_wireframe", "r_drawothermodels",
            "fog_override", "fog_enable", "r_fog_post_process",
            "developer", "con_enable", "net_graph",
            "zoom_sensitivity_ratio_mouse", "bind"
        };

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            string content;
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync().ConfigureAwait(false);
            }
            catch (IOException) { continue; }

            ctx.IncrementFiles();

            // Check for sv_cheats enabled or suspicious FOV/wireframe combos
            if (content.Contains("sv_cheats 1", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("r_drawothermodels 2", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("mat_wireframe 2", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("fog_override 1", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtige Dota2-CFG: {Path.GetFileName(file)}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = "Dota2-Konfigurationsdatei enthaelt Konsolenbefehle, die typischerweise fuer " +
                             "Cheats verwendet werden (z.B. sv_cheats, Wallhack-Variablen, Fog-Override).",
                    Detail = GetMatchingLines(content, consoleInjectionPatterns, maxLines: 3)
                });
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Phase 3 – AppData script directories
    // ---------------------------------------------------------------------------
    private async Task ScanScriptDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var scriptPaths = new[]
        {
            Path.Combine(appData, "Dota2", "scripts"),
            Path.Combine(appData, "Dota2", "scripts", "vscripts"),
            Path.Combine(appData, "dota2", "scripts"),
            Path.Combine(localApp, "Dota2", "scripts"),
            Path.Combine(appData, "dotacheat"),
            Path.Combine(appData, "dota2cheat"),
            Path.Combine(appData, "dota2hack"),
            Path.Combine(localApp, "dotacheat"),
        };

        foreach (var path in scriptPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(path)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Verdaechtiges Dota2-Skript-Verzeichnis gefunden: {Path.GetFileName(path)}",
                Risk = RiskLevel.High,
                Location = path,
                Reason = $"Das Verzeichnis '{path}' ist ein bekannter Speicherort fuer Dota2-Cheat-Skripte " +
                         "oder -Konfigurationen.",
                Detail = $"Pfad: {path}"
            });

            await ScanScriptDirAsync(ctx, path, "AppData-Skripte", ct).ConfigureAwait(false);
        }
    }

    // ---------------------------------------------------------------------------
    // Phase 4 – Cheat config file locations
    // ---------------------------------------------------------------------------
    private async Task ScanCheatConfigLocationsAsync(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var downloads = Path.Combine(userProfile, "Downloads");

        var configDirs = new[]
        {
            appData, localApp, desktop, docs, downloads,
            Path.Combine(userProfile, "dota2"),
            Path.Combine(userProfile, ".dota2"),
        };

        var configExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".json", ".cfg", ".ini", ".txt", ".xml", ".yaml", ".toml", ".lua", ".py", ".hpp", ".h"
        };

        foreach (var dir in configDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!configExtensions.Contains(ext)) continue;

                await ScanFileContentAsync(ctx, file, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task ScanFileContentAsync(ScanContext ctx, string file, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        ctx.IncrementFiles();

        // Check cheat config keywords
        int configHits = 0;
        var foundConfigKeys = new List<string>();
        foreach (var keyword in CheatConfigKeywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                configHits++;
                foundConfigKeys.Add(keyword);
                if (configHits >= 3) break;
            }
        }

        if (configHits >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Dota2-Cheat-Konfiguration erkannt: {Path.GetFileName(file)}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = Path.GetFileName(file),
                Reason = $"Datei '{Path.GetFileName(file)}' enthaelt {configHits} Dota2-Cheat-Konfigurationsschluesselbegriffe " +
                         "(Maphack, ESP, Auto-Lasthit, Orbwalker usw.).",
                Detail = $"Gefundene Begriffe: {string.Join(", ", foundConfigKeys)}"
            });
            return;
        }

        // Check memory offset keywords
        int offsetHits = 0;
        var foundOffsets = new List<string>();
        foreach (var keyword in MemoryOffsetKeywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                offsetHits++;
                foundOffsets.Add(keyword);
                if (offsetHits >= 3) break;
            }
        }

        if (offsetHits >= 3)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Dota2-Speicher-Offsets in Datei: {Path.GetFileName(file)}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = Path.GetFileName(file),
                Reason = $"Datei '{Path.GetFileName(file)}' enthaelt {offsetHits} Dota2-Speicher-Offset-Bezeichner " +
                         "(C_DOTAPlayer, m_iHealth, m_vecNetworkOrigin usw.). Dies deutet auf ein Cheat-Entwicklungsprojekt " +
                         "oder eine Cheat-Konfigurationsdatei hin.",
                Detail = $"Gefundene Bezeichner: {string.Join(", ", foundOffsets)}"
            });
        }
    }

    // ---------------------------------------------------------------------------
    // Phase 5 – Registry checks
    // ---------------------------------------------------------------------------
    private void CheckRegistry(ScanContext ctx)
    {
        CheckDota2RegistryPaths(ctx);
        CheckVacBypassRegistryArtifacts(ctx);
        CheckUninstallRegistryForCheats(ctx);
    }

    private void CheckDota2RegistryPaths(ScanContext ctx)
    {
        // Check Steam/Dota2 related registry entries for anomalies
        var keysToCheck = new[]
        {
            (@"HKCU\SOFTWARE\Valve\Steam", "SteamPath"),
            (@"HKLM\SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath"),
        };

        foreach (var (keyPath, valueName) in keysToCheck)
        {
            try
            {
                using var key = keyPath.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase)
                    ? Registry.CurrentUser.OpenSubKey(keyPath.Substring(5))
                    : Registry.LocalMachine.OpenSubKey(keyPath.Substring(5));
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                var val = key.GetValue(valueName)?.ToString();
                if (!string.IsNullOrEmpty(val))
                {
                    // Look for suspicious steam install paths (redirected paths can indicate bypasses)
                    if (val.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("fake", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("hook", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Verdaechtiger Steam-Registrierungspfad",
                            Risk = RiskLevel.High,
                            Location = $"{keyPath}\\{valueName}",
                            Reason = $"Der Steam-Registrierungspfad '{valueName}' enthaelt verdaechtige Begriffe, " +
                                     "die auf eine manipulierte Steam-Installation hindeuten koennen.",
                            Detail = $"Wert: {val}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private void CheckVacBypassRegistryArtifacts(ScanContext ctx)
    {
        // Check for known VAC bypass registry artifacts
        var suspiciousKeys = new[]
        {
            @"SOFTWARE\vacbypass",
            @"SOFTWARE\steamhook",
            @"SOFTWARE\dota2cheat",
            @"SOFTWARE\dotahack",
            @"SOFTWARE\maphack",
        };

        foreach (var keyPath in suspiciousKeys)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat-Registrierungsschluessel gefunden: {keyPath}",
                    Risk = RiskLevel.Critical,
                    Location = $"HKCU\\{keyPath}",
                    Reason = $"Der Registrierungsschluessel 'HKCU\\{keyPath}' ist mit einem bekannten Dota2-Cheat- " +
                             "oder VAC-Bypass-Tool assoziiert.",
                    Detail = $"Schluessel: HKCU\\{keyPath}"
                });
            }
            catch { }
        }

        foreach (var keyPath in suspiciousKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat-Registrierungsschluessel (HKLM) gefunden: {keyPath}",
                    Risk = RiskLevel.Critical,
                    Location = $"HKLM\\{keyPath}",
                    Reason = $"Der Registrierungsschluessel 'HKLM\\{keyPath}' ist mit einem bekannten Dota2-Cheat- " +
                             "oder VAC-Bypass-Tool assoziiert.",
                    Detail = $"Schluessel: HKLM\\{keyPath}"
                });
            }
            catch { }
        }
    }

    private void CheckUninstallRegistryForCheats(ScanContext ctx)
    {
        // Scan installed software registry for cheat tool names
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        foreach (var uninstallPath in uninstallPaths)
        {
            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(uninstallPath);
                if (baseKey is null) continue;

                foreach (var subKeyName in baseKey.GetSubKeyNames())
                {
                    try
                    {
                        using var subKey = baseKey.OpenSubKey(subKeyName);
                        if (subKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        var displayName = subKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var installLocation = subKey.GetValue("InstallLocation")?.ToString() ?? string.Empty;

                        if (IsDota2CheatSoftwareName(displayName) || IsDota2CheatSoftwareName(installLocation))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Dota2-Cheat-Software installiert: {displayName}",
                                Risk = RiskLevel.Critical,
                                Location = $"HKLM\\{uninstallPath}\\{subKeyName}",
                                Reason = $"In der Softwareliste ist '{displayName}' eingetragen, das mit Dota2-Cheat-Tools " +
                                         "assoziiert ist. Deinstallation und vollstaendige Bereinigung empfohlen.",
                                Detail = $"Installationspfad: {installLocation}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private static bool IsDota2CheatSoftwareName(string name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        bool hasDota = name.Contains("dota", StringComparison.OrdinalIgnoreCase);
        bool hasCheat = name.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("maphack", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("esp", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("inject", StringComparison.OrdinalIgnoreCase);
        return hasDota && hasCheat;
    }

    // ---------------------------------------------------------------------------
    // Utility
    // ---------------------------------------------------------------------------
    private static string GetMatchingLines(string content, string[] patterns, int maxLines)
    {
        var result = new List<string>();
        foreach (var line in content.Split('\n'))
        {
            if (result.Count >= maxLines) break;
            foreach (var pattern in patterns)
            {
                if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(line.Trim());
                    break;
                }
            }
        }
        return string.Join(" | ", result);
    }
}
