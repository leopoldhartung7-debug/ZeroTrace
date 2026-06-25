using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CounterStrike2CheatScanModule : IScanModule
{
    public string Name => "Counter-Strike 2 Cheat Detection";
    public double Weight => 4.2;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Environment paths
    // -------------------------------------------------------------------------
    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    private static readonly string Downloads =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string TempDir = Path.GetTempPath();

    private static readonly string ProgramFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

    private static readonly string ProgramFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

    // -------------------------------------------------------------------------
    // CS2/CSGO cheat EXE/DLL names (exact matches)
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> CheatFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Named CS2/CSGO cheats
        "cs2cheat.exe",
        "csgocheat.exe",
        "cshook.exe",
        "cs2external.exe",
        "cs2internal.exe",
        "cs2aimbot.exe",
        "csgohvh.exe",
        "cs2hvh.exe",
        "legitbot.exe",
        "ragebot.exe",
        "triggerbot.exe",
        "backtrack.exe",
        "resolver.exe",
        "cs2dll.exe",
        "cs2inject.exe",
        "fatality.exe",
        "skeet.exe",
        "neverlose.exe",
        "overdrive.exe",
        "onetap.exe",
        "gamesense.exe",
        "aimware.exe",
        "primordial.exe",
        "interwebz.exe",
        "sapphire.exe",
        "nitrogen.exe",
        "skinchanger.exe",
        "inventorychanger.exe",
        "cs2inv.exe",
        "cs2dumper.exe",
        "cs2_offset_dumper.exe",
        // Generic cheat loader patterns often used for CS2
        "cs2loader.exe",
        "cs2hack.exe",
        "cs2esp.exe",
        "cs2wallhack.exe",
        "cs2spoofer.exe",
        "cs2bypass.exe",
        "csgoesp.exe",
        "csgowallhack.exe",
        "csgoloader.exe",
        "csgospoofer.exe",
        "csgobypass.exe",
        "csgoskinchanger.exe",
        "cs2radar.exe",
        "cs2trigger.exe",
        "cs2bhop.exe",
        "cs2norecoil.exe",
        "cs2silentaim.exe",
        "csgonorecoil.exe",
        "csgosilentaim.exe",
        "csgotrigger.exe",
        "hvhcheat.exe",
        "hvhloader.exe",
        "antiaimbot.exe",
        "antiaim.exe",
        "cs2antiaim.exe",
        "cs2resolver.exe",
        "cs2legit.exe",
        "legitcs2.exe",
        "cs2ragebot.exe",
        "resolvercs2.exe",
        "fatalitycs2.exe",
        "skeetcs2.exe",
        "onetapcs2.exe",
        "aimsware.exe",
        "cs2aimsware.exe",
        "projectx.exe",
        "supremebot.exe",
        "cs2supreme.exe",
        // DLL variants
        "cs2cheat.dll",
        "csgocheat.dll",
        "cs2inject.dll",
        "cs2hook.dll",
        "steamhack.dll",
        "steambypass.dll",
        "cs2bypass.dll",
        "hvhhook.dll",
        "aimbotcs2.dll",
    };

    // -------------------------------------------------------------------------
    // CS2 cheat config keywords (found in .cfg, .json, .ini, .txt files)
    // -------------------------------------------------------------------------
    private static readonly string[] CheatConfigKeywords =
    {
        "ragebot_hitchance",
        "legitbot_smooth",
        "aimbot_fov_cs2",
        "hvh_resolver",
        "backtrack_ticks",
        "antiaim_pitch",
        "antiaim_yaw",
        "triggerbot_delay",
        "bunnyhop_cs2",
        "noflash_cs2",
        "chams_enemy",
        "wallhack_cs2",
        "esp_box",
        "esp_health",
        "esp_name",
        "esp_distance",
        "radar_hack",
        "aimbot_smooth",
        "aimbot_fov",
        "legit_aimbot",
        "rage_aimbot",
        "silent_aim",
        "triggerbot_enabled",
        "triggerbot_key",
        "bhop_enabled",
        "bhop_key",
        "no_recoil",
        "no_spread",
        "no_flash",
        "esp_enabled",
        "esp_skeleton",
        "esp_weapon",
        "esp_ammo",
        "esp_flag",
        "glow_enabled",
        "chams_enabled",
        "wallhack_enabled",
        "spinbot_enabled",
        "skinchanger_enabled",
        "skin_id",
        "knife_skin",
        "hvh_enabled",
        "resolver_enabled",
        "backtrack_enabled",
        "fake_duck",
        "fake_walk",
        "aa_enabled",
        "antiaim_enabled",
        "desync_enabled",
        "inventory_changer",
        "override_skin",
        "cs2_aimbot",
        "cs2_esp",
    };

    // -------------------------------------------------------------------------
    // CS2 memory offset identifiers (found in hpp/json/ini offset files)
    // -------------------------------------------------------------------------
    private static readonly string[] MemoryOffsetKeywords =
    {
        "dwEntityList",
        "dwViewMatrix",
        "dwLocalPlayer",
        "dwForceAttack",
        "m_iHealth",
        "m_vecOrigin",
        "m_fFlags",
        "dwForceJump",
        "m_iTeamNum",
        "m_vecVelocity",
        "dwClientState",
        "dwClientState_ViewAngles",
        "m_bDormant",
        "m_bSpotted",
        "m_flFlashDuration",
        "m_hActiveWeapon",
        "m_iClip1",
        "m_iItemDefinitionIndex",
        "m_nFallbackPaintKit",
        "m_flFallbackWear",
        "m_iEntityQuality",
        "cs2_offset",
        "csgo_offset",
        "dwForceAim",
        "dwLocalPlayerController",
        "dwGameRules",
        "dwGlobalVars",
        "m_pGameSceneNode",
        "m_vecAbsOrigin",
        "m_angEyeAngles",
        "dwPlantedC4",
    };

    // -------------------------------------------------------------------------
    // VAC / Steam bypass DLL/EXE names
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> VacBypassFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "steamhack.dll",
        "steambypass.dll",
        "vac_bypass.dll",
        "vac_bypass.exe",
        "vacbypass.dll",
        "vacbypass.exe",
        "steamemu.dll",
        "steamclient_bypass.dll",
        "steam_api_bypass.dll",
        "novac.dll",
        "novac.exe",
        "steamfix.dll",
        "vac_unload.exe",
        "vac_killer.exe",
        "steamdrm_bypass.dll",
        "steamapi_bypass.dll",
        "vac_disable.exe",
    };

    // -------------------------------------------------------------------------
    // DLL hijack names placed inside CS2 game directory
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> Cs2DllHijackNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.dll",
        "tier0.dll",
        "vstdlib.dll",
        "steam_api64.dll",
        "steam_api.dll",
        "gameoverlayrenderer64.dll",
        "gameoverlayrenderer.dll",
        "d3d11.dll",
        "d3d9.dll",
        "dxgi.dll",
        "version.dll",
        "winmm.dll",
        "wininet.dll",
        "ws2_32.dll",
        "xinput1_3.dll",
        "xinput1_4.dll",
        "dbghelp.dll",
        "iphlpapi.dll",
    };

    // -------------------------------------------------------------------------
    // Cheat-related autoexec / cfg bind keywords
    // -------------------------------------------------------------------------
    private static readonly string[] AimCfgKeywords =
    {
        "aimbot",
        "triggerbot",
        "wallhack",
        "bunnyhop",
        "bhop",
        "norecoil",
        "no_recoil",
        "spinbot",
        "esp_enabled",
        "cheat_enabled",
        "ragebot",
        "legitbot",
        "silentaim",
        "silent_aim",
        "hvh",
        "antiaim",
        "resolver",
        "backtrack",
        "skinchanger",
        "sv_cheats 1",
    };

    // -------------------------------------------------------------------------
    // PowerShell / shell history patterns targeting CS2/VAC
    // -------------------------------------------------------------------------
    private static readonly (string Pattern, RiskLevel Risk, string Title)[] ShellHistoryPatterns =
    {
        ("vac_bypass",          RiskLevel.Critical, "VAC Bypass Command in Shell History"),
        ("vacbypass",           RiskLevel.Critical, "VAC Bypass Command in Shell History"),
        ("steambypass",         RiskLevel.Critical, "Steam Bypass Command in Shell History"),
        ("cs2cheat",            RiskLevel.Critical, "CS2 Cheat Reference in Shell History"),
        ("cs2inject",           RiskLevel.High,     "CS2 Injector Reference in Shell History"),
        ("cs2dump",             RiskLevel.High,     "CS2 Offset Dumper Reference in Shell History"),
        ("cs2_offset_dumper",   RiskLevel.High,     "CS2 Offset Dumper Reference in Shell History"),
        ("csgocheat",           RiskLevel.Critical, "CSGO Cheat Reference in Shell History"),
        ("skeet.cc",            RiskLevel.Critical, "Skeet Cheat Reference in Shell History"),
        ("fatality.win",        RiskLevel.Critical, "Fatality Cheat Reference in Shell History"),
        ("neverlose.cc",        RiskLevel.Critical, "Neverlose Cheat Reference in Shell History"),
        ("onetap.su",           RiskLevel.Critical, "Onetap Cheat Reference in Shell History"),
        ("aimware.net",         RiskLevel.Critical, "Aimware Cheat Reference in Shell History"),
        ("gamesense.pub",       RiskLevel.Critical, "Gamesense Cheat Reference in Shell History"),
    };

    // -------------------------------------------------------------------------
    // Known cheat/bypass directory names
    // -------------------------------------------------------------------------
    private static readonly string[] CheatRepoDirNames =
    {
        "cs2-cheat",
        "cs2cheat",
        "cs2-hack",
        "cs2hack",
        "csgo-cheat",
        "csgocheat",
        "cs2-aimbot",
        "cs2aimbot",
        "cs2-esp",
        "cs2esp",
        "cs2-hvh",
        "cs2hvh",
        "cs2bypass",
        "cs2-bypass",
        "vac-bypass",
        "vacbypass",
        "cs2dumper",
        "cs2-dumper",
        "cs2_offset_dumper",
        "cs2skinchanger",
        "cs2-skinchanger",
        "cs2-internal",
        "cs2internal",
        "cs2-external",
        "cs2external",
    };

    // =========================================================================
    // Entry point
    // =========================================================================
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting CS2 cheat detection");

        await ScanCheatFilesAsync(ctx, ct);
        ctx.Report(0.15, Name, "Cheat file scan complete");

        await ScanCs2GameDirectoryAsync(ctx, ct);
        ctx.Report(0.28, Name, "CS2 game directory scan complete");

        await ScanSteamDirectoryForVacBypassAsync(ctx, ct);
        ctx.Report(0.38, Name, "Steam VAC bypass scan complete");

        await ScanCheatConfigFilesAsync(ctx, ct);
        ctx.Report(0.50, Name, "Cheat config file scan complete");

        await ScanMemoryOffsetFilesAsync(ctx, ct);
        ctx.Report(0.60, Name, "Memory offset file scan complete");

        await ScanCfgFilesForAimbotBindsAsync(ctx, ct);
        ctx.Report(0.70, Name, "CS2 cfg file scan complete");

        await ScanShellHistoryAsync(ctx, ct);
        ctx.Report(0.80, Name, "Shell history scan complete");

        await ScanCheatRepoDirsAsync(ctx, ct);
        ctx.Report(0.88, Name, "Cheat repository scan complete");

        await CheckCheatProcessesAsync(ctx, ct);
        ctx.Report(0.93, Name, "Process scan complete");

        CheckVacRegistryAsync(ctx, ct);
        ctx.Report(1.0, Name, "CS2 cheat detection complete");
    }

    // =========================================================================
    // 1. Cheat EXE/DLL file scan across user directories
    // =========================================================================
    private async Task ScanCheatFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] scanRoots =
        {
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataRoaming,
            AppDataLocal,
            Path.Combine(AppDataLocal, "Temp"),
            Path.Combine(UserProfile, "Games"),
            Path.Combine(UserProfile, "source"),
            Path.Combine(UserProfile, "repos"),
        };

        foreach (string root in scanRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();
                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                if (CheatFileNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known CS2/CSGO Cheat File Detected: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"File \"{fileName}\" matches a known Counter-Strike 2 or CS:GO cheat executable or DLL. This software is specifically designed to provide unfair advantages in CS2.",
                        Detail = $"Full path: {filePath}",
                    });
                }
                else if (VacBypassFileNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"VAC Bypass File Detected: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"File \"{fileName}\" matches a known Valve Anti-Cheat (VAC) bypass tool. This software is designed to circumvent Steam's anti-cheat system used in CS2.",
                        Detail = $"Full path: {filePath}",
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 2. CS2 game directory scan for DLL hijack and suspicious files
    // =========================================================================
    private async Task ScanCs2GameDirectoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var cs2Paths = GetCs2InstallPaths();

        foreach (string cs2Root in cs2Paths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cs2Root)) continue;

            // Check for svchost.dll and other hijack DLLs placed directly in the CS2 game dir
            string gameBinDir = Path.Combine(cs2Root, "game", "bin", "win64");
            string altBinDir = Path.Combine(cs2Root, "bin", "win64");
            string cs2ExeDir = cs2Root;

            foreach (string checkDir in new[] { cs2Root, gameBinDir, altBinDir, cs2ExeDir })
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(checkDir)) continue;

                string[] files;
                try { files = Directory.GetFiles(checkDir, "*.dll", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (string filePath in files)
                {
                    ct.ThrowIfCancellationRequested();
                    string fileName = Path.GetFileName(filePath);
                    ctx.IncrementFiles();

                    if (Cs2DllHijackNames.Contains(fileName))
                    {
                        // svchost.dll in game dir is a near-certain DLL hijack
                        RiskLevel risk = fileName.Equals("svchost.dll", StringComparison.OrdinalIgnoreCase)
                            ? RiskLevel.Critical
                            : RiskLevel.High;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious DLL in CS2 Directory: {fileName}",
                            Risk = risk,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"The file \"{fileName}\" was found in the CS2 game directory. This is a known DLL hijacking vector — cheats place system/Steam DLLs here to intercept CS2 function calls before legitimate code can run. " +
                                     (fileName.Equals("svchost.dll", StringComparison.OrdinalIgnoreCase)
                                         ? "svchost.dll has no legitimate reason to exist in the CS2 directory."
                                         : "This DLL should not normally exist in the CS2 game folder."),
                            Detail = $"CS2 install: {cs2Root} | Suspicious file: {filePath}",
                        });
                    }

                    // Also flag cheats placed directly in the CS2 dir
                    if (CheatFileNames.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Known Cheat DLL in CS2 Directory: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"Known cheat DLL \"{fileName}\" found inside the CS2 installation directory. This indicates a loaded or injection-ready cheat component.",
                            Detail = $"CS2 install: {cs2Root}",
                        });
                    }
                }
            }

            // Scan for offset dumper or cheat tools anywhere inside the CS2 tree
            string[] allFiles;
            try { allFiles = Directory.GetFiles(cs2Root, "*.exe", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (string filePath in allFiles)
            {
                ct.ThrowIfCancellationRequested();
                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                if (CheatFileNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Executable Inside CS2 Installation: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"Cheat executable \"{fileName}\" found inside the CS2 installation tree. This is a strong indicator of a cheat being staged for injection or direct use.",
                        Detail = $"CS2 install root: {cs2Root}",
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 3. Steam directory VAC bypass scan
    // =========================================================================
    private async Task ScanSteamDirectoryForVacBypassAsync(ScanContext ctx, CancellationToken ct)
    {
        string? steamPath = Registry.GetValue(
            @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;

        if (string.IsNullOrEmpty(steamPath) || !Directory.Exists(steamPath))
        {
            await Task.CompletedTask;
            return;
        }

        // Check Steam root for VAC bypass DLLs
        string[] steamRootFiles;
        try { steamRootFiles = Directory.GetFiles(steamPath, "*.dll", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { await Task.CompletedTask; return; }

        foreach (string filePath in steamRootFiles)
        {
            ct.ThrowIfCancellationRequested();
            string fileName = Path.GetFileName(filePath);
            ctx.IncrementFiles();

            if (VacBypassFileNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"VAC Bypass DLL in Steam Root: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"VAC bypass DLL \"{fileName}\" found in the Steam installation root. This DLL is positioned to intercept Steam/VAC function calls when CS2 launches.",
                    Detail = $"Steam path: {steamPath}",
                });
            }
        }

        // Check steamapps for CS2 specifically
        string steamApps = Path.Combine(steamPath, "steamapps");
        if (Directory.Exists(steamApps))
        {
            // Look for CS2-specific bypass within steamapps
            string[] steamAppFiles;
            try { steamAppFiles = Directory.GetFiles(steamApps, "steamhack.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { steamAppFiles = Array.Empty<string>(); }

            foreach (string filePath in steamAppFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Steam Hack DLL in SteamApps",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = Path.GetFileName(filePath),
                    Reason = "steamhack.dll found inside the SteamApps directory. This is a known Steam/VAC bypass DLL that intercepts authentication and anti-cheat checks.",
                    Detail = $"Full path: {filePath}",
                });
            }
        }

        // Check Steam userdata for suspicious files
        string userdata = Path.Combine(steamPath, "userdata");
        if (Directory.Exists(userdata))
        {
            string[] userdataFiles;
            try { userdataFiles = Directory.GetFiles(userdata, "*.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { userdataFiles = Array.Empty<string>(); }

            foreach (string filePath in userdataFiles)
            {
                ct.ThrowIfCancellationRequested();
                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                if (VacBypassFileNames.Contains(fileName) || CheatFileNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat/Bypass DLL in Steam Userdata: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"Suspicious DLL \"{fileName}\" found inside Steam userdata. This is an unusual location for a DLL and suggests attempted bypass or injection staging.",
                        Detail = $"Full path: {filePath}",
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 4. Cheat config file scan (.cfg, .json, .ini, .txt in known locations)
    // =========================================================================
    private async Task ScanCheatConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] configRoots =
        {
            AppDataRoaming,
            AppDataLocal,
            Documents,
            Desktop,
            Downloads,
            TempDir,
        };

        string[] configExtensions = { ".json", ".ini", ".cfg", ".txt", ".lua", ".xml" };

        foreach (string root in configRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();
                string ext = Path.GetExtension(filePath);
                bool isConfig = false;
                foreach (string ce in configExtensions)
                {
                    if (ext.Equals(ce, StringComparison.OrdinalIgnoreCase)) { isConfig = true; break; }
                }
                if (!isConfig) continue;

                string content;
                try
                {
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();

                if (string.IsNullOrWhiteSpace(content)) continue;

                foreach (string keyword in CheatConfigKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        string fileName = Path.GetFileName(filePath);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"CS2 Cheat Config File Detected: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"Configuration file \"{fileName}\" contains the CS2 cheat keyword \"{keyword}\". This pattern is characteristic of CS2 cheat configuration files (aimbot, ESP, triggerbot, etc.).",
                            Detail = $"Keyword: {keyword} | Path: {filePath}",
                        });
                        break;
                    }
                }
            }
        }
    }

    // =========================================================================
    // 5. Memory offset file scan (hpp, json, h files with CS2 offsets)
    // =========================================================================
    private async Task ScanMemoryOffsetFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] scanRoots =
        {
            Desktop,
            Downloads,
            Documents,
            AppDataRoaming,
            AppDataLocal,
            UserProfile,
            TempDir,
        };

        string[] offsetExtensions = { ".hpp", ".h", ".json", ".ini", ".txt", ".cpp", ".py" };

        foreach (string root in scanRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();
                string ext = Path.GetExtension(filePath);
                bool isTarget = false;
                foreach (string oe in offsetExtensions)
                {
                    if (ext.Equals(oe, StringComparison.OrdinalIgnoreCase)) { isTarget = true; break; }
                }
                if (!isTarget) continue;

                string content;
                try
                {
                    using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();
                if (string.IsNullOrWhiteSpace(content)) continue;

                int matchCount = 0;
                string? firstMatch = null;
                foreach (string keyword in MemoryOffsetKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        matchCount++;
                        firstMatch ??= keyword;
                        if (matchCount >= 3) break;
                    }
                }

                // Require at least 3 offset keywords to reduce false positives on legitimate code
                if (matchCount >= 3)
                {
                    string fileName = Path.GetFileName(filePath);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Memory Offset File Detected: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"File \"{fileName}\" contains multiple CS2 memory offset identifiers (e.g., \"{firstMatch}\", {matchCount} total matches). Offset files are required by CS2 external cheats to locate game structures in memory.",
                        Detail = $"Match count: {matchCount} | First match: {firstMatch} | Path: {filePath}",
                    });
                }
            }
        }
    }

    // =========================================================================
    // 6. CS2 cfg / autoexec files with aimbot binds
    // =========================================================================
    private async Task ScanCfgFilesForAimbotBindsAsync(ScanContext ctx, CancellationToken ct)
    {
        var cfgLocations = new List<string>();

        // CS2 local cfg path
        string cs2CfgPath = Path.Combine(AppDataLocal, "Counter-Strike Global Offensive", "cfg");
        if (Directory.Exists(cs2CfgPath)) cfgLocations.Add(cs2CfgPath);

        // Steam userdata cfg folders
        string? steamPath = Registry.GetValue(
            @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;
        if (!string.IsNullOrEmpty(steamPath))
        {
            string userdata = Path.Combine(steamPath, "userdata");
            if (Directory.Exists(userdata))
            {
                string[] userDirs;
                try { userDirs = Directory.GetDirectories(userdata); }
                catch (UnauthorizedAccessException) { userDirs = Array.Empty<string>(); }

                foreach (string userDir in userDirs)
                {
                    string gameCfg = Path.Combine(userDir, "730", "local", "cfg"); // 730 = CS2/CSGO app ID
                    if (Directory.Exists(gameCfg)) cfgLocations.Add(gameCfg);
                }
            }

            // Also scan steamapps cfg directories
            foreach (string cs2Root in GetCs2InstallPaths())
            {
                string gameCfg = Path.Combine(cs2Root, "game", "csgo", "cfg");
                if (Directory.Exists(gameCfg)) cfgLocations.Add(gameCfg);
            }
        }

        foreach (string cfgDir in cfgLocations)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cfgDir)) continue;

            string[] cfgFiles;
            try { cfgFiles = Directory.GetFiles(cfgDir, "*.cfg", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (string cfgFile in cfgFiles)
            {
                ct.ThrowIfCancellationRequested();

                string content;
                try
                {
                    using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();
                if (string.IsNullOrWhiteSpace(content)) continue;

                foreach (string keyword in AimCfgKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        string fileName = Path.GetFileName(cfgFile);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious CS2 Config Bind: {fileName}",
                            Risk = RiskLevel.High,
                            Location = cfgFile,
                            FileName = fileName,
                            Reason = $"CS2 configuration file \"{fileName}\" contains the suspicious keyword \"{keyword}\". This may indicate a cheat-related bind or configuration loaded at game startup via autoexec.",
                            Detail = $"Keyword: {keyword} | Config: {cfgFile}",
                        });
                        break;
                    }
                }
            }
        }
    }

    // =========================================================================
    // 7. Shell / PowerShell history scanning
    // =========================================================================
    private async Task ScanShellHistoryAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] historyFiles =
        {
            Path.Combine(AppDataRoaming, @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
            Path.Combine(UserProfile, ".bash_history"),
            Path.Combine(UserProfile, ".zsh_history"),
            Path.Combine(AppDataRoaming, "doskey.log"),
        };

        foreach (string histFile in historyFiles)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(histFile)) continue;

            string content;
            try
            {
                using var fs = new FileStream(histFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException) { continue; }

            ctx.IncrementFiles();
            if (string.IsNullOrWhiteSpace(content)) continue;

            string[] lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (string rawLine in lines)
            {
                ct.ThrowIfCancellationRequested();
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line)) continue;

                foreach (var (pattern, risk, title) in ShellHistoryPatterns)
                {
                    if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = title,
                            Risk = risk,
                            Location = histFile,
                            FileName = Path.GetFileName(histFile),
                            Reason = $"Shell history entry matches CS2/CSGO cheat or VAC bypass pattern \"{pattern}\". This indicates the user executed commands related to CS2 cheating.",
                            Detail = $"Matched line: {line.Substring(0, Math.Min(line.Length, 300))}",
                        });
                        break;
                    }
                }
            }
        }
    }

    // =========================================================================
    // 8. Cheat repository directory detection
    // =========================================================================
    private async Task ScanCheatRepoDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] repoSearchRoots =
        {
            Desktop,
            Downloads,
            Documents,
            UserProfile,
            Path.Combine(UserProfile, "source"),
            Path.Combine(UserProfile, "repos"),
            Path.Combine(UserProfile, "projects"),
            Path.Combine(UserProfile, "git"),
            Path.Combine(UserProfile, "GitHub"),
            Path.Combine(UserProfile, "GitLab"),
        };

        foreach (string root in repoSearchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            string[] subdirs;
            try { subdirs = Directory.GetDirectories(root, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (string subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                string dirName = Path.GetFileName(subdir);

                foreach (string repoName in CheatRepoDirNames)
                {
                    if (dirName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                    {
                        bool hasGit = Directory.Exists(Path.Combine(subdir, ".git"));
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "CS2 Cheat Repository Clone Detected",
                            Risk = RiskLevel.Critical,
                            Location = subdir,
                            FileName = dirName,
                            Reason = $"Directory \"{dirName}\" matches a known CS2/CSGO cheat repository name. This indicates the user cloned cheat source code or bypass tools.",
                            Detail = hasGit
                                ? $"Git repository confirmed (.git folder present). Path: {subdir}"
                                : $"Path: {subdir}",
                        });
                        break;
                    }
                }

                // Also heuristic: directory name combines cs2/csgo with cheat terms
                bool hasGameRef = dirName.Contains("cs2", StringComparison.OrdinalIgnoreCase)
                               || dirName.Contains("csgo", StringComparison.OrdinalIgnoreCase)
                               || dirName.Contains("counterstrike", StringComparison.OrdinalIgnoreCase);
                bool hasCheatRef = dirName.Contains("cheat", StringComparison.OrdinalIgnoreCase)
                                || dirName.Contains("hack", StringComparison.OrdinalIgnoreCase)
                                || dirName.Contains("aimbot", StringComparison.OrdinalIgnoreCase)
                                || dirName.Contains("esp", StringComparison.OrdinalIgnoreCase)
                                || dirName.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                                || dirName.Contains("hvh", StringComparison.OrdinalIgnoreCase)
                                || dirName.Contains("inject", StringComparison.OrdinalIgnoreCase);

                if (hasGameRef && hasCheatRef)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious CS2-Related Cheat Directory: {dirName}",
                        Risk = RiskLevel.High,
                        Location = subdir,
                        FileName = dirName,
                        Reason = $"Directory \"{dirName}\" combines CS2/CSGO game references with cheat-related terms, suggesting cheat tool storage or source code.",
                        Detail = $"Path: {subdir}",
                    });
                }

                // One level deeper
                string[] nestedDirs;
                try { nestedDirs = Directory.GetDirectories(subdir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (string nested in nestedDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    string nestedName = Path.GetFileName(nested);

                    foreach (string repoName in CheatRepoDirNames)
                    {
                        if (nestedName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                        {
                            bool hasGit = Directory.Exists(Path.Combine(nested, ".git"));
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "CS2 Cheat Repository Clone (Nested) Detected",
                                Risk = RiskLevel.Critical,
                                Location = nested,
                                FileName = nestedName,
                                Reason = $"Nested directory \"{nestedName}\" matches a known CS2/CSGO cheat repository name.",
                                Detail = hasGit ? $"Git repo confirmed. Path: {nested}" : $"Path: {nested}",
                            });
                            break;
                        }
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 9. Running process detection
    // =========================================================================
    private async Task CheckCheatProcessesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            System.Diagnostics.Process[] processes;
            try { processes = ctx.GetProcessSnapshot(); }
            catch { return; }

            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();

                string procName;
                try { procName = proc.ProcessName; }
                catch { continue; }

                // Check process name + ".exe" against cheat file names
                string procExeName = procName + ".exe";
                if (CheatFileNames.Contains(procExeName))
                {
                    string? exePath = null;
                    try { exePath = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known CS2 Cheat Process Running: {procName}",
                        Risk = RiskLevel.Critical,
                        Location = exePath ?? $"PID {proc.Id}",
                        FileName = procExeName,
                        Reason = $"Process \"{procName}\" (PID {proc.Id}) matches a known CS2/CSGO cheat or bypass tool process name.",
                        Detail = exePath is not null ? $"Executable: {exePath}" : $"PID: {proc.Id}",
                    });
                }
            }
        }, ct);
    }

    // =========================================================================
    // 10. VAC service registry check
    // =========================================================================
    private void CheckVacRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        // Check VAC service registry state
        string vacServicePath = @"SYSTEM\CurrentControlSet\Services\vac_service";
        ctx.IncrementRegistryKeys();

        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(vacServicePath, writable: false);
            if (key is not null)
            {
                object? startVal = key.GetValue("Start");
                if (startVal is int startInt && startInt == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VAC Service Disabled in Registry",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{vacServicePath}",
                        Reason = "The VAC (Valve Anti-Cheat) service Start value is 4 (Disabled). A bypass tool may have disabled this service to prevent VAC from protecting CS2.",
                        Detail = $"Start = {startInt}",
                    });
                }
                else if (key is not null)
                {
                    // VAC service exists — note its state for context
                    ctx.IncrementRegistryKeys();
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (System.Security.SecurityException) { }

        // Check for Steam DRM bypass registry modifications
        string[] steamRegPaths =
        {
            @"SOFTWARE\Valve\Steam",
            @"SOFTWARE\WOW6432Node\Valve\Steam",
        };

        foreach (string regPath in steamRegPaths)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();

            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                // Check for suspicious overrides in Steam registry
                string? installPath = key.GetValue("InstallPath") as string;
                if (!string.IsNullOrEmpty(installPath))
                {
                    // Verify steam_api64.dll in the Steam root is not replaced
                    string steamApi = Path.Combine(installPath, "steam_api64.dll");
                    if (File.Exists(steamApi))
                    {
                        ctx.IncrementFiles();
                        // Check file size — legitimate steam_api64.dll is typically 200-700 KB
                        try
                        {
                            var fi = new FileInfo(steamApi);
                            if (fi.Length < 50_000 || fi.Length > 5_000_000)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Suspicious steam_api64.dll File Size",
                                    Risk = RiskLevel.High,
                                    Location = steamApi,
                                    FileName = "steam_api64.dll",
                                    Reason = $"steam_api64.dll in the Steam root has an unusual size ({fi.Length / 1024} KB). Bypass tools often replace this DLL with a modified version that disables VAC or spoofs authentication.",
                                    Detail = $"File size: {fi.Length} bytes | Expected range: ~200 KB – 700 KB",
                                });
                            }
                        }
                        catch (IOException) { }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }

        // Check HKCU Steam for bypass overrides
        ctx.IncrementRegistryKeys();
        try
        {
            using RegistryKey? hkcuSteam = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam", writable: false);
            if (hkcuSteam is not null)
            {
                // Check if SteamPath has been redirected to a non-standard location
                string? steamPath = hkcuSteam.GetValue("SteamPath") as string;
                if (!string.IsNullOrEmpty(steamPath))
                {
                    bool isInProgramFiles = steamPath.StartsWith(ProgramFiles, StringComparison.OrdinalIgnoreCase)
                                        || steamPath.StartsWith(ProgramFilesX86, StringComparison.OrdinalIgnoreCase);
                    bool isInCommonSteamDir = steamPath.Contains("Steam", StringComparison.OrdinalIgnoreCase);

                    if (!isInProgramFiles && !isInCommonSteamDir)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Steam Path Registry Points to Non-Standard Location",
                            Risk = RiskLevel.Medium,
                            Location = @"HKCU\Software\Valve\Steam\SteamPath",
                            Reason = $"The Steam registry path \"{steamPath}\" is not in a standard Program Files location. Bypass tools may redirect this to a modified Steam installation that has VAC disabled.",
                            Detail = $"SteamPath: {steamPath}",
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (System.Security.SecurityException) { }

        // Check for VAC whitelist / bypass registry keys used by known bypass tools
        string[] bypassRegistryKeys =
        {
            @"SOFTWARE\vac_bypass",
            @"SOFTWARE\vacbypass",
            @"SOFTWARE\SteamHack",
            @"SOFTWARE\cs2cheat",
            @"SOFTWARE\csgocheat",
            @"SOFTWARE\NoVAC",
        };

        foreach (string bypassKey in bypassRegistryKeys)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();

            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(bypassKey, writable: false)
                                      ?? Registry.CurrentUser.OpenSubKey(bypassKey, writable: false);
                if (key is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2/VAC Bypass Registry Key Present: {bypassKey}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{bypassKey} or HKCU\{bypassKey}",
                        Reason = $"Registry key \"{bypassKey}\" matches a known CS2 cheat or VAC bypass tool registry artifact. This key is created by specific bypass software.",
                        Detail = $"Key path: {bypassKey}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }

        // Check for csgo.exe / cs2.exe under Image File Execution Options (bypass/debugger intercept)
        ctx.IncrementRegistryKeys();
        try
        {
            string[] gameExeNames = { "cs2.exe", "csgo.exe" };
            foreach (string gameExe in gameExeNames)
            {
                ct.ThrowIfCancellationRequested();

                using RegistryKey? ifeo = Registry.LocalMachine.OpenSubKey(
                    $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{gameExe}",
                    writable: false);

                if (ifeo is null) continue;
                ctx.IncrementRegistryKeys();

                string? debugger = ifeo.GetValue("Debugger") as string;
                if (!string.IsNullOrWhiteSpace(debugger))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"IFEO Debugger Set for {gameExe} (CS2 Launch Hijack)",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{gameExe}",
                        Reason = $"An Image File Execution Options debugger is set for \"{gameExe}\". This intercepts every launch of the CS2 executable, allowing a bypass tool to run before the game starts.",
                        Detail = $"Debugger: {debugger}",
                    });
                }

                string? globalFlag = ifeo.GetValue("GlobalFlag") as string;
                if (!string.IsNullOrWhiteSpace(globalFlag) && globalFlag != "0")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"IFEO GlobalFlag Set for {gameExe}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\...\Image File Execution Options\{gameExe}",
                        Reason = $"GlobalFlag is set for \"{gameExe}\" in IFEO. This can be used to modify process behavior at launch, sometimes as part of anti-anti-cheat techniques.",
                        Detail = $"GlobalFlag: {globalFlag}",
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (System.Security.SecurityException) { }
    }

    // =========================================================================
    // Helpers
    // =========================================================================
    private static List<string> GetCs2InstallPaths()
    {
        var paths = new List<string>();

        // From registry
        string? steamPath = Registry.GetValue(
            @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;

        if (!string.IsNullOrEmpty(steamPath))
        {
            string defaultCs2 = Path.Combine(steamPath, "steamapps", "common", "Counter-Strike Global Offensive");
            if (Directory.Exists(defaultCs2)) paths.Add(defaultCs2);

            // Parse libraryfolders.vdf for additional Steam library paths
            string libraryVdf = Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
            if (File.Exists(libraryVdf))
            {
                try
                {
                    string[] vdfLines = File.ReadAllLines(libraryVdf, System.Text.Encoding.UTF8);
                    foreach (string line in vdfLines)
                    {
                        var trimmed = line.Trim();
                        // Match "path" value entries
                        var match = System.Text.RegularExpressions.Regex.Match(
                            trimmed, @"""path""\s+""([^""]+)""");
                        if (match.Success)
                        {
                            string libPath = match.Groups[1].Value.Replace(@"\\", @"\");
                            string cs2In = Path.Combine(libPath, "steamapps", "common", "Counter-Strike Global Offensive");
                            if (Directory.Exists(cs2In) && !paths.Contains(cs2In))
                                paths.Add(cs2In);
                        }
                    }
                }
                catch { }
            }
        }

        // Known fallback paths
        string localCs2 = Path.Combine(AppDataLocal, "cs2");
        if (Directory.Exists(localCs2)) paths.Add(localCs2);

        string[] programFilePaths =
        {
            Path.Combine(ProgramFiles, "Steam", "steamapps", "common", "Counter-Strike Global Offensive"),
            Path.Combine(ProgramFilesX86, "Steam", "steamapps", "common", "Counter-Strike Global Offensive"),
        };

        foreach (string p in programFilePaths)
        {
            if (Directory.Exists(p) && !paths.Contains(p))
                paths.Add(p);
        }

        return paths;
    }

    private static string ProgramFiles =>
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

    private static string ProgramFilesX86 =>
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
}
