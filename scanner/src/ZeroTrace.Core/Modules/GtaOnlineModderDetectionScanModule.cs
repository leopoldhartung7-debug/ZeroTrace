using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class GtaOnlineModderDetectionScanModule : IScanModule
{
    public string Name => "GTA Online Modder & Recovery Tool Detection";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    // ── Known GTA Online mod menu executables and DLLs (70+ entries) ─────────

    private static readonly HashSet<string> KnownModMenuNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // 2Take1
        "2Take1.exe",
        "2Take1Menu.dll",
        "2t1.exe",
        "2t1menu.dll",
        // Stand
        "Stand.exe",
        "Stand.dll",
        "stand_loader.exe",
        // Cherax
        "Cherax.exe",
        "Cherax.dll",
        "cherax_loader.exe",
        // Orbital
        "Orbital.exe",
        "Orbital.dll",
        // Kiddion / Modest Menu
        "Kiddion.exe",
        "KiddionModestMenu.exe",
        "Modest Menu.exe",
        "ModestMenu.exe",
        "kiddion_modest_menu.exe",
        // Menyoo
        "Menyoo.exe",
        "Menyoo.dll",
        "Menyoo PC [Public].asi",
        // Trainer ASI files
        "Enhanced Native Trainer.asi",
        "TrainerV.asi",
        "NativeTrainer.asi",
        "ENT.asi",
        "ScriptHookV.dll",
        "ScriptHookVDotNet.dll",
        "ScriptHookVDotNet2.dll",
        "ScriptHookVDotNet3.dll",
        // BigBase variants
        "BigBaseV2.dll",
        "BigBaseV5.dll",
        "BigBase.dll",
        // Lynx
        "Lynx.exe",
        "lynx_menu.exe",
        // Hamster
        "Hamster.exe",
        "hamster_menu.exe",
        // Evolution
        "Evolution.exe",
        "evolution_menu.exe",
        // Eulen
        "Eulen.exe",
        "Eulen.dll",
        // SkipTheWait
        "SkipTheWait.exe",
        // Susanoo
        "Susanoo.exe",
        "susanoo_menu.exe",
        // Luna
        "Luna.exe",
        "Luna.dll",
        "LunaMenu.exe",
        // Midnight
        "Midnight.exe",
        "Midnight.dll",
        "MidnightMenu.exe",
        // Phantom
        "Phantom.dll",
        "PhantomMenu.exe",
        "PhantomGTA.exe",
        // Lumia
        "Lumia.exe",
        "LumiaMenu.exe",
        "Lumia.dll",
        // Brezi
        "Brezi.exe",
        "BReZi.exe",
        "brezi_menu.exe",
        // Impulse
        "Impulse.exe",
        "Impulse_GTA.exe",
        "ImpulseMenu.exe",
        // Rage
        "Rage.exe",
        "RageMenu.exe",
        "rage_menu_gta.exe",
        // Disturbed
        "Disturbed.dll",
        "Disturbed.exe",
        "DisturbedMenu.exe",
        // GTA Bypass artifacts
        "GrandTheftAuto_Bypass.exe",
        "GTAO_Bypass.dll",
        "GTA5_Bypass.exe",
        "gtabypass.exe",
        // YimMenu
        "YimMenu.dll",
        "yimmenu.asi",
        // Lambda / Absolute
        "LambdaMenu.exe",
        "AbsoluteMenu.exe",
        "lambda_menu.exe",
        // Celestial / Hyperion
        "Celestial.exe",
        "CelestialMenu.exe",
        "Hyperion.exe",
        "HyperionMenu.exe",
        // Spectre
        "SpectreMenu.exe",
        "SpectrMenu.dll",
        "Spectre.dll",
        // Other named mod menus
        "VoidCheats.exe",
        "NSAWare.exe",
        "Reaper.exe",
        "ReaperMenu.exe",
        "NexusMenu.exe",
        "NexusmenuGTA.exe",
        "Scarlet.exe",
        "ScarletMenu.exe",
        "PrimordialMenu.exe",
        "PhoenixMenu.exe",
        "SunsetMenu.exe",
    };

    // ── Known money recovery / drop tools ────────────────────────────────────

    private static readonly HashSet<string> KnownRecoveryToolNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "MoneyDrop.exe",
        "MoneyRecovery.exe",
        "GtaMoneyDrop.exe",
        "recovery_tool.exe",
        "GTA5_Recovery.exe",
        "GTAOnlineRecovery.exe",
        "GTAO_Recovery.exe",
        "GtaRecovery.exe",
        "RecoveryTool.exe",
        "GTA_Recovery_Tool.exe",
        "CashRecovery.exe",
        "UnlockAll.exe",
        "UnlockAllStats.exe",
        "UnlockAllGTA.exe",
        "GTA5_UnlockAll.exe",
        "GTAUnlocker.exe",
        "StatEditor.exe",
        "GTA5StatEditor.exe",
        "GTAV_StatEditor.exe",
        "GTAStatEditor.exe",
        "GTA5StatsEditor.exe",
        "SaveEditor.exe",
        "GTASaveEditor.exe",
        "GTA5SaveEditor.exe",
    };

    // ── Known Social Club bypass DLL names ───────────────────────────────────

    private static readonly HashSet<string> KnownSocialClubBypassNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "SocialClub.dll",
        "socialclub_bypass.dll",
        "launcher_bypass.dll",
        "rgsc_bypass.dll",
        "steam_api64.dll",     // Steam emu replacing RSC auth
        "steam_api.dll",
        "RGSC.dll",
        "RockstarService.dll",
    };

    // ── Known cheat ASI plugin names ─────────────────────────────────────────

    private static readonly HashSet<string> KnownCheatAsiNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "aimbot.asi",
        "esp.asi",
        "godmode.asi",
        "spinbot.asi",
        "teleport.asi",
        "bunnyhop.asi",
        "noclip.asi",
        "moneyloop.asi",
        "moneydrop.asi",
        "orbitalcannon.asi",
        "carspawner.asi",
        "vehiclemod.asi",
        "weaponmod.asi",
    };

    // ── Config keys that indicate money recovery configuration ────────────────

    private static readonly string[] RecoveryConfigKeys =
    {
        "money_drop_amount",
        "recovery_amount",
        "give_cash",
        "set_stat_money",
        "drop_amount",
        "cash_amount",
        "money_amount",
        "wallet_balance",
        "bank_balance",
        "mp0_wallet_balance",
        "mp0_bank_balance",
        "mp1_wallet_balance",
        "rp_amount",
        "level_amount",
        "unlock_all",
        "stat_money",
        "recovery_service",
        "\"service\": \"recovery\"",
        "\"type\": \"money_drop\"",
        "\"service\":\"recovery\"",
        "\"type\":\"money_drop\"",
        "service=recovery",
        "type=money_drop",
    };

    // ── Stat IDs used in GTA Online stat editors ──────────────────────────────

    private static readonly string[] GtaStatIds =
    {
        "MP0_WALLET_BALANCE",
        "MP0_BANK_BALANCE",
        "MP0_CHAR_TOTAL_CASH",
        "MP1_WALLET_BALANCE",
        "MP1_BANK_BALANCE",
        "MP0_CHAR_FM_CRIMEORGANISATION_ASSET_VALUE",
        "MP0_CHAR_TOTAL_BUSINESS_CASH",
        "MPPLY_TOTAL_CASH_EARNED",
        "MP0_CHAR_DEATHSTAT",
        "MP0_CHAR_KILLSTAT",
        "MP0_CHAR_TUNEABLES_DATA_GLOBALINT",
        "MPPLY_SAT_EXPERIENCE_GAINED_ALL",
        "MPPLY_CHAR_RP_GAINED",
        "MP0_CHAR_RANK_LP",
        "MP0_CHAR_FM_STATS_CHEAT",
        "MPPLY_MONEY_PICKUP",
    };

    // ── Text extensions to scan for config / script content ──────────────────

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cfg", ".config", ".ini", ".conf", ".json", ".xml", ".yaml", ".yml",
        ".txt", ".log", ".bat", ".cmd", ".ps1", ".lua", ".js",
        ".stats", ".xml",
    };

    // ── Suspicious script folder names ────────────────────────────────────────

    private static readonly HashSet<string> SuspiciousScriptFolderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "scripts",
        "plugins",
        "mods",
        "asi_plugins",
        "cheat_scripts",
        "menu_scripts",
    };

    // ── Discord webhook URL fragment (recovery services use these to verify purchases) ──

    private const string DiscordWebhookFragment = "discord.com/api/webhooks/";

    // =========================================================================
    // Entry point
    // =========================================================================

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting GTA Online modder detection");

        // Phase 1: Registry – installed software and Rockstar service entries
        ScanRegistry(ctx, ct);
        ctx.Report(0.08, Name, "Registry scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 2: Running processes – mod menus often stay resident
        ScanRunningProcesses(ctx, ct);
        ctx.Report(0.15, Name, "Process scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 3: GTA V install directory – ASI loaders, mod menus in root
        await ScanGtaVInstallDirectoryAsync(ctx, ct);
        ctx.Report(0.35, Name, "GTA V directory scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 4: Rockstar AppData – suspicious DLLs, scripts, configs
        await ScanRockstarAppDataAsync(ctx, ct);
        ctx.Report(0.55, Name, "Rockstar AppData scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 5: User filesystem – recovery tools, stat editors, mod archives
        await ScanUserFilesystemAsync(ctx, ct);
        ctx.Report(0.85, Name, "User filesystem scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 6: GTA Online save/profile directory for stat editor artifacts
        await ScanGtaProfilesDirectoryAsync(ctx, ct);
        ctx.Report(1.0, Name, "GTA Online modder detection complete");
    }

    // =========================================================================
    // Phase 1 – Registry
    // =========================================================================

    private void ScanRegistry(ScanContext ctx, CancellationToken ct)
    {
        // Check installed programs for known mod menu / recovery tool names
        var uninstallKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (var keyPath in uninstallKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key is null) continue;

                foreach (var subName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    try
                    {
                        using var sub = key.OpenSubKey(subName);
                        if (sub is null) continue;

                        var displayName = sub.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var installLoc = sub.GetValue("InstallLocation")?.ToString() ?? string.Empty;

                        if (IsGtaModTool(displayName))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"GTA Online mod tool in installed programs: {displayName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}\{subName}",
                                Reason = $"Installed software '{displayName}' matches a known GTA Online " +
                                         "mod menu, money recovery tool, or stat editor. This software " +
                                         "is used to cheat in GTA Online.",
                                Detail = string.IsNullOrEmpty(installLoc) ? null : $"Install path: {installLoc}",
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }

        // Check Rockstar Games Launcher bypass registry artifacts
        CheckRockstarBypassRegistry(ctx, ct);

        // Check for ScriptHookV registration
        CheckScriptHookVRegistry(ctx, ct);
    }

    private void CheckRockstarBypassRegistry(ScanContext ctx, CancellationToken ct)
    {
        var bypassKeys = new[]
        {
            (@"SOFTWARE\Rockstar Games\Launcher", "bypass", "Rockstar Launcher bypass configuration"),
            (@"SOFTWARE\Rockstar Games\GTAV", "bypass", "GTA V bypass configuration"),
            (@"SOFTWARE\WOW6432Node\Rockstar Games\Launcher", "bypass", "Rockstar Launcher bypass (WOW64)"),
        };

        foreach (var (keyPath, _, label) in bypassKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath)
                             ?? Registry.CurrentUser.OpenSubKey(keyPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (val.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("crack", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("patch", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Rockstar Games bypass registry value: {valueName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{keyPath}\{valueName}",
                            Reason = $"Registry value '{valueName}' under Rockstar Games key contains " +
                                     $"bypass/crack/patch content ('{val}'). This suggests Social Club " +
                                     "or Rockstar launcher authentication was bypassed.",
                            Detail = $"{valueName} = {val}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void CheckScriptHookVRegistry(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\ScriptHookV")
                         ?? Registry.CurrentUser.OpenSubKey(@"SOFTWARE\ScriptHookV");
            if (key is null) return;

            ctx.IncrementRegistryKeys();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "ScriptHookV registry key present",
                Risk = RiskLevel.Medium,
                Location = @"HKLM\SOFTWARE\ScriptHookV",
                Reason = "ScriptHookV registry key detected. ScriptHookV is an ASI loader/runtime " +
                         "used by virtually all GTA V mod menus. Alone it does not confirm cheating, " +
                         "but is a prerequisite for running .asi cheat plugins in GTA V.",
            });
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // =========================================================================
    // Phase 2 – Running processes
    // =========================================================================

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var proc in ctx.GetProcessSnapshot())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();

                string procName;
                try { procName = proc.ProcessName; } catch { continue; }

                var exeName = procName + ".exe";

                if (KnownModMenuNames.Contains(exeName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"GTA Online mod menu running: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = $"PID {proc.Id} - {procName}",
                        FileName = exeName,
                        Reason = $"Process '{exeName}' (PID {proc.Id}) matches a known GTA Online " +
                                 "mod menu. The menu is actively running on this system.",
                    });
                    continue;
                }

                if (KnownRecoveryToolNames.Contains(exeName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"GTA Online recovery/stat editor running: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = $"PID {proc.Id} - {procName}",
                        FileName = exeName,
                        Reason = $"Process '{exeName}' (PID {proc.Id}) matches a known GTA Online " +
                                 "money recovery tool or stat editor. These tools illegitimately " +
                                 "modify GTA Online character statistics and wallet balances.",
                    });
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }

    // =========================================================================
    // Phase 3 – GTA V install directory
    // =========================================================================

    private async Task ScanGtaVInstallDirectoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var gtaVPaths = FindGtaVInstallPaths();

        foreach (var gtaVRoot in gtaVPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(gtaVRoot)) continue;

            ctx.Report(0.15, gtaVRoot, $"Scanning GTA V install: {gtaVRoot}");

            // Scan root directory files (mod menus, bypass DLLs placed next to GTA5.exe)
            await ScanDirectoryFilesAsync(ctx, gtaVRoot, depth: 0, ct);

            // Scan scripts/ subfolder
            var scriptsDir = Path.Combine(gtaVRoot, "scripts");
            if (Directory.Exists(scriptsDir))
                await ScanScriptsFolderAsync(ctx, scriptsDir, ct);

            // Scan plugins/ subfolder
            var pluginsDir = Path.Combine(gtaVRoot, "plugins");
            if (Directory.Exists(pluginsDir))
                await ScanDirectoryFilesAsync(ctx, pluginsDir, depth: 2, ct);

            // Scan mods/ subfolder
            var modsDir = Path.Combine(gtaVRoot, "mods");
            if (Directory.Exists(modsDir))
                await ScanDirectoryFilesAsync(ctx, modsDir, depth: 3, ct);

            // Check for Social Club bypass DLLs in the GTA V root
            CheckSocialClubBypassDlls(ctx, gtaVRoot);
        }
    }

    private async Task ScanDirectoryFilesAsync(ScanContext ctx, string dir, int depth, CancellationToken ct)
    {
        var files = new List<string>();
        CollectFiles(dir, files, depth, ct);

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            if (KnownModMenuNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"GTA Online mod menu file detected: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"File '{fileName}' is a known GTA Online mod menu executable or DLL. " +
                             "Its presence in the GTA V directory indicates the game was modded for " +
                             "use in GTA Online.",
                });
                continue;
            }

            if (KnownRecoveryToolNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"GTA Online recovery/unlock tool detected: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"File '{fileName}' is a known GTA Online money recovery tool or " +
                             "stat unlocker. These tools illegitimately modify in-game currency " +
                             "and stats.",
                });
                continue;
            }

            if (KnownCheatAsiNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known cheat ASI plugin detected: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"ASI plugin '{fileName}' is a known cheat script loaded by ScriptHookV " +
                             "into GTA V. ASI cheats provide aimbot, ESP, god mode, money drops " +
                             "and other illegal advantages in GTA Online.",
                });
                continue;
            }

            if (!TextExtensions.Contains(ext)) continue;

            FileInfo fi;
            try { fi = new FileInfo(file); } catch { continue; }
            if (fi.Length > 2 * 1024 * 1024) continue;

            try
            {
                await InspectConfigFileAsync(ctx, file, fileName, ct);
            }
            catch (IOException) { }
        }
    }

    private async Task ScanScriptsFolderAsync(ScanContext ctx, string scriptsDir, CancellationToken ct)
    {
        string[] files;
        try { files = Directory.GetFiles(scriptsDir, "*", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // Known mod menu / cheat names
            if (KnownModMenuNames.Contains(fileName) || KnownCheatAsiNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat script/plugin in GTA V scripts folder: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known cheat file '{fileName}' found in the GTA V scripts directory. " +
                             "Script folder is scanned by ScriptHookV on game launch, meaning " +
                             "this script was loaded into GTA V.",
                });
                continue;
            }

            // .cetrainer files (Cheat Engine trainer saved scripts)
            if (ext.Equals(".cetrainer", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat Engine trainer file in GTA V scripts: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Cheat Engine trainer file '{fileName}' (.cetrainer) found in GTA V " +
                             "scripts directory. Cheat Engine trainers automate memory manipulation " +
                             "to apply cheats such as god mode, unlimited ammo, or money hacks.",
                });
                continue;
            }

            // Scan Lua scripts for suspicious patterns
            if (ext.Equals(".lua", StringComparison.OrdinalIgnoreCase))
            {
                try { await InspectLuaScriptAsync(ctx, file, fileName, ct); }
                catch (IOException) { }
                continue;
            }

            // Scan config files for recovery keys
            if (TextExtensions.Contains(ext))
            {
                try { await InspectConfigFileAsync(ctx, file, fileName, ct); }
                catch (IOException) { }
            }
        }
    }

    private void CheckSocialClubBypassDlls(ScanContext ctx, string gtaVRoot)
    {
        string[] files;
        try { files = Directory.GetFiles(gtaVRoot, "*.dll", SearchOption.TopDirectoryOnly); }
        catch { return; }

        foreach (var file in files)
        {
            var fileName = Path.GetFileName(file);

            if (!KnownSocialClubBypassNames.Contains(fileName)) continue;

            // Check if file appears to be a replacement (unexpected hash/origin)
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Potential Social Club bypass DLL in GTA V root: {fileName}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = fileName,
                Reason = $"DLL '{fileName}' found in the GTA V root directory. If this is a " +
                         "replacement or emulated version of the genuine Rockstar Social Club / " +
                         "launcher DLL, it bypasses authentication and DRM. Replacement Social Club " +
                         "DLLs allow playing without legitimate ownership and suppress anti-cheat checks.",
            });
        }
    }

    // =========================================================================
    // Phase 4 – Rockstar AppData
    // =========================================================================

    private async Task ScanRockstarAppDataAsync(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var rockstarRoots = new[]
        {
            Path.Combine(appData, "Rockstar Games"),
            Path.Combine(localAppData, "Rockstar Games"),
        };

        foreach (var root in rockstarRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            ctx.Report(0.36, root, $"Scanning Rockstar AppData: {root}");

            // Check for suspicious DLL files directly under Rockstar Games subdirs
            var files = new List<string>();
            try { CollectFiles(root, files, maxDepth: 5, ct); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);

                if (KnownModMenuNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"GTA mod menu file in Rockstar AppData: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Known GTA Online mod menu file '{fileName}' found in the Rockstar " +
                                 "Games AppData directory. Mod menus frequently cache configuration " +
                                 "and loader artifacts in AppData.",
                    });
                    continue;
                }

                if (KnownRecoveryToolNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Recovery tool artifact in Rockstar AppData: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Known GTA Online recovery or stat editor file '{fileName}' found " +
                                 "in Rockstar Games AppData. Recovery tools store configs and " +
                                 "session keys in AppData directories.",
                    });
                    continue;
                }

                if (ext.Equals(".cetrainer", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Engine trainer in Rockstar AppData: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Cheat Engine trainer script '{fileName}' found in Rockstar Games " +
                                 "AppData. This trainer script was likely used to modify GTA V " +
                                 "memory values (money, health, ammo) while the game was running.",
                    });
                    continue;
                }

                // Scan suspicious scripts folder
                if (file.Contains("scripts", StringComparison.OrdinalIgnoreCase) ||
                    file.Contains("plugins", StringComparison.OrdinalIgnoreCase))
                {
                    if (ext.Equals(".lua", StringComparison.OrdinalIgnoreCase))
                    {
                        try { await InspectLuaScriptAsync(ctx, file, fileName, ct); }
                        catch (IOException) { }
                        continue;
                    }
                }

                if (TextExtensions.Contains(ext))
                {
                    FileInfo fi;
                    try { fi = new FileInfo(file); } catch { continue; }
                    if (fi.Length > 2 * 1024 * 1024) continue;

                    try { await InspectConfigFileAsync(ctx, file, fileName, ct); }
                    catch (IOException) { }
                }
            }

            // Check for Rockstar Editor exploit artifacts
            CheckRockstarEditorArtifacts(ctx, root, ct);
        }
    }

    private void CheckRockstarEditorArtifacts(ScanContext ctx, string rockstarRoot, CancellationToken ct)
    {
        var editorDir = Path.Combine(rockstarRoot, "GTA V", "Rockstar Editor");
        if (!Directory.Exists(editorDir)) return;

        string[] files;
        try { files = Directory.GetFiles(editorDir, "*", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        // Rockstar Editor clips used as exploit delivery vectors have anomalous file sizes
        // or names not matching the standard timestamp pattern
        int suspiciousCount = 0;
        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var fi = new FileInfo(file);
            if (fi.Length < 1024 && Path.GetExtension(file).Equals(".clip", StringComparison.OrdinalIgnoreCase))
            {
                suspiciousCount++;
                if (suspiciousCount == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Suspiciously small Rockstar Editor clip files detected",
                        Risk = RiskLevel.Medium,
                        Location = editorDir,
                        Reason = "Rockstar Editor clip files smaller than 1 KB detected. " +
                                 "Malformed or crafted .clip files have been used as exploit " +
                                 "delivery vectors in GTA Online. These warrant manual inspection.",
                        Detail = $"Example: {Path.GetFileName(file)} ({fi.Length} bytes)",
                    });
                }
            }
        }
    }

    // =========================================================================
    // Phase 5 – User filesystem (Downloads, Desktop, Temp)
    // =========================================================================

    private async Task ScanUserFilesystemAsync(ScanContext ctx, CancellationToken ct)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var scanDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.GetTempPath(),
        };

        var allFiles = new List<string>();
        foreach (var dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;
            try { CollectFiles(dir, allFiles, maxDepth: 4, ct); }
            catch (UnauthorizedAccessException) { }
        }

        int total = Math.Max(allFiles.Count, 1);
        int idx = 0;

        foreach (var file in allFiles)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            ctx.IncrementFiles();

            if (idx % 100 == 0)
                ctx.Report(0.55 + 0.28 * ((double)idx / total), file, $"{idx}/{allFiles.Count} user files scanned");

            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            if (KnownModMenuNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"GTA Online mod menu in user directory: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known GTA Online mod menu file '{fileName}' found in user directory. " +
                             "Mod menus are downloaded before being moved to the GTA V directory; " +
                             "finding one here confirms active possession of cheating software.",
                });
                continue;
            }

            if (KnownRecoveryToolNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"GTA Online recovery/stat tool in user directory: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known GTA Online money recovery tool or stat editor '{fileName}' " +
                             "found in a user directory. Recovery tools are used to fraudulently " +
                             "restore or inflate GTA Online wallet balances and reputation.",
                });
                continue;
            }

            // Heuristic: file name suggests GTA modding
            var lowerName = fileName.ToLowerInvariant();
            if ((lowerName.Contains("gta") || lowerName.Contains("gtav") || lowerName.Contains("gtaonline")) &&
                (lowerName.Contains("mod") || lowerName.Contains("cheat") || lowerName.Contains("hack") ||
                 lowerName.Contains("recovery") || lowerName.Contains("money") || lowerName.Contains("unlock")))
            {
                var extLower = ext.ToLowerInvariant();
                if (extLower is ".exe" or ".dll" or ".asi" or ".zip" or ".rar" or ".7z")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious GTA-related file: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"File '{fileName}' has a name suggesting GTA Online cheating " +
                                 "activity (contains GTA + cheat/mod/recovery/money keywords). " +
                                 "Manual inspection is recommended.",
                    });
                    continue;
                }
            }

            if (!TextExtensions.Contains(ext)) continue;

            FileInfo fi;
            try { fi = new FileInfo(file); } catch { continue; }
            if (fi.Length > 2 * 1024 * 1024) continue;

            try
            {
                await InspectConfigFileAsync(ctx, file, fileName, ct);

                // Also check for Discord webhook URLs (recovery service purchase verification)
                await CheckDiscordWebhookInFileAsync(ctx, file, fileName, ct);
            }
            catch (IOException) { }
        }
    }

    // =========================================================================
    // Phase 6 – GTA V save/profile directory
    // =========================================================================

    private async Task ScanGtaProfilesDirectoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var profilesPath = Path.Combine(docPath, "Rockstar Games", "GTA V", "Profiles");

        if (!Directory.Exists(profilesPath)) return;

        ctx.Report(0.84, profilesPath, "Scanning GTA V profiles for stat editor artifacts");

        string[] files;
        try { files = Directory.GetFiles(profilesPath, "*", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // stats.xml or stats.json
            if ((fileName.Equals("stats.xml", StringComparison.OrdinalIgnoreCase) ||
                 fileName.Equals("stats.json", StringComparison.OrdinalIgnoreCase)) &&
                new FileInfo(file).Length < 5 * 1024 * 1024)
            {
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException) { continue; }

                var matchedStats = GtaStatIds
                    .Where(s => content.Contains(s, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matchedStats.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"GTA Online stat editor artifacts in profile: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Profile file '{fileName}' contains multiple GTA Online internal " +
                                 "stat IDs (MP0_WALLET_BALANCE, MPPLY_*, etc.). These identifiers " +
                                 "are used by stat editors to modify GTA Online character data " +
                                 "such as money, reputation, and unlock flags.",
                        Detail = $"Matched stat IDs: {string.Join(", ", matchedStats.Take(5))}",
                    });
                }
                continue;
            }

            // Check for backup save files that look like edited saves
            if (ext.Equals(".bak", StringComparison.OrdinalIgnoreCase) ||
                fileName.Contains("_backup", StringComparison.OrdinalIgnoreCase) ||
                fileName.Contains("_edited", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Backup save file in GTA V profiles: {fileName}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = fileName,
                    Reason = $"File '{fileName}' in GTA V Profiles directory has a name suggesting " +
                             "it is a backup of an edited save file. Save editors create backup " +
                             "copies before modifying GTA Online profile data.",
                });
            }
        }
    }

    // =========================================================================
    // File content inspection helpers
    // =========================================================================

    private async Task InspectConfigFileAsync(ScanContext ctx, string filePath, string fileName, CancellationToken ct)
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

        ct.ThrowIfCancellationRequested();

        foreach (var key in RecoveryConfigKeys)
        {
            if (!content.Contains(key, StringComparison.OrdinalIgnoreCase)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"GTA Online recovery/money config key in: {fileName}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fileName,
                Reason = $"File '{fileName}' contains configuration key '{key}' associated with " +
                         "GTA Online money recovery services, money drop tools, or stat editors. " +
                         "These services violate Rockstar's Terms of Service and result in bans.",
                Detail = ExtractContext(content, key, 120),
            });
            return;
        }

        // Check stat IDs in config files
        var statMatches = GtaStatIds
            .Where(s => content.Contains(s, StringComparison.OrdinalIgnoreCase))
            .Take(3)
            .ToList();

        if (statMatches.Count >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"GTA Online stat ID references in config: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"Configuration file '{fileName}' references multiple GTA Online internal " +
                         "stat identifiers. This pattern is produced by stat editor tools targeting " +
                         "GTA Online character data modification.",
                Detail = $"Matched: {string.Join(", ", statMatches)}",
            });
        }
    }

    private async Task InspectLuaScriptAsync(ScanContext ctx, string filePath, string fileName, CancellationToken ct)
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

        ct.ThrowIfCancellationRequested();

        var cheatPatterns = new[]
        {
            "NETWORK_GIVE_PED_SCALEFORM_MOVIE_HELMET",
            "GIVE_DELAYED_WEAPON_TO_PED",
            "ADD_VEHICLE_WEAPON",
            "SET_PED_COMPONENT_VARIATION",
            "NETWORK_SESSION_KICK_PLAYER",
            "STAT_SET_INT",
            "STAT_GET_INT",
            "money_drop",
            "moneydrop",
            "give_cash",
            "wallet_balance",
            "godmode",
            "god_mode",
            "noclip",
            "no_clip",
            "aimbot",
            "aim_bot",
            "esp_draw",
            "wallhack",
            "spinbot",
            "spin_bot",
            "orbital_cannon",
            "orb_cannon",
            "crash_player",
            "kick_player",
            "freeze_player",
        };

        var hits = cheatPatterns.Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase)).ToList();

        if (hits.Count >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"GTA Online cheat Lua script detected: {fileName}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fileName,
                Reason = $"Lua script '{fileName}' contains multiple GTA Online cheat patterns " +
                         "(money drops, god mode, aimbot, player crash commands). This script " +
                         "was loaded into GTA V and used to cheat in GTA Online.",
                Detail = $"Matched patterns: {string.Join(", ", hits.Take(6))}",
            });
        }
    }

    private async Task CheckDiscordWebhookInFileAsync(ScanContext ctx, string filePath, string fileName, CancellationToken ct)
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

        ct.ThrowIfCancellationRequested();

        if (!content.Contains(DiscordWebhookFragment, StringComparison.OrdinalIgnoreCase)) return;

        // Make sure it's a GTA-related file by checking for GTA keywords alongside
        bool hasGtaContext = content.Contains("gta", StringComparison.OrdinalIgnoreCase) ||
                             content.Contains("recovery", StringComparison.OrdinalIgnoreCase) ||
                             content.Contains("money", StringComparison.OrdinalIgnoreCase) ||
                             content.Contains("rockstar", StringComparison.OrdinalIgnoreCase) ||
                             content.Contains("online", StringComparison.OrdinalIgnoreCase);

        if (!hasGtaContext) return;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Discord webhook in GTA-related config file: {fileName}",
            Risk = RiskLevel.High,
            Location = filePath,
            FileName = fileName,
            Reason = $"File '{fileName}' contains a Discord webhook URL alongside GTA Online " +
                     "related content. GTA Online recovery services use Discord webhooks to " +
                     "verify purchases, confirm HWID, and deliver session keys for money drops.",
            Detail = ExtractContext(content, DiscordWebhookFragment, 80),
        });

        await Task.CompletedTask;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static List<string> FindGtaVInstallPaths()
    {
        var paths = new List<string>();

        // Steam default path
        var steamApps = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Steam", "steamapps", "common", "Grand Theft Auto V");
        if (Directory.Exists(steamApps)) paths.Add(steamApps);

        // Epic Games default path
        var epicGames = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Epic Games", "GTAV");
        if (Directory.Exists(epicGames)) paths.Add(epicGames);

        // Rockstar Games Launcher default path
        var rockstarDefault = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Rockstar Games", "Grand Theft Auto V");
        if (Directory.Exists(rockstarDefault)) paths.Add(rockstarDefault);

        var rockstarDefaultX86 = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Rockstar Games", "Grand Theft Auto V");
        if (Directory.Exists(rockstarDefaultX86)) paths.Add(rockstarDefaultX86);

        // Registry lookup for install path
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Rockstar Games\Grand Theft Auto V")
                ?? Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Rockstar Games\Grand Theft Auto V");
            if (key is not null)
            {
                var installPath = key.GetValue("InstallFolder")?.ToString()
                               ?? key.GetValue("InstallFolderSteam")?.ToString();
                if (!string.IsNullOrEmpty(installPath) && Directory.Exists(installPath))
                    paths.Add(installPath);
            }
        }
        catch { }

        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static bool IsGtaModTool(string displayName)
    {
        if (string.IsNullOrEmpty(displayName)) return false;
        var lower = displayName.ToLowerInvariant();
        return lower.Contains("2take1") || lower.Contains("cherax") || lower.Contains("stand menu") ||
               lower.Contains("kiddion") || lower.Contains("modest menu") || lower.Contains("menyoo") ||
               lower.Contains("gta mod") || lower.Contains("gta cheat") || lower.Contains("gta hack") ||
               lower.Contains("gta recovery") || lower.Contains("money recovery") ||
               lower.Contains("gta stat editor") || lower.Contains("unlock all gta") ||
               lower.Contains("gtav trainer") || lower.Contains("gta trainer") ||
               lower.Contains("lua menu") || lower.Contains("yimmenu") ||
               lower.Contains("eulen menu") || lower.Contains("lynx menu") ||
               lower.Contains("orbital menu") || lower.Contains("midnight menu") ||
               lower.Contains("luna menu") || lower.Contains("lumia menu") ||
               lower.Contains("brezi menu") || lower.Contains("disturbed menu") ||
               lower.Contains("celestial menu") || lower.Contains("void cheats");
    }

    private static void CollectFiles(string root, List<string> sink, int maxDepth, CancellationToken ct)
    {
        var stack = new Stack<(string dir, int depth)>();
        stack.Push((root, 0));

        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) return;
            var (dir, depth) = stack.Pop();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var f in files) sink.Add(f);

            if (depth >= maxDepth) continue;

            string[] subs = Array.Empty<string>();
            try { subs = Directory.GetDirectories(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var s in subs) stack.Push((s, depth + 1));
        }
    }

    private static string ExtractContext(string content, string keyword, int maxLen)
    {
        var idx = content.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return string.Empty;
        var start = Math.Max(0, idx - 30);
        var end = Math.Min(content.Length, idx + keyword.Length + maxLen);
        var snippet = content[start..end].Replace('\n', ' ').Replace('\r', ' ');
        return snippet.Length > maxLen + 60 ? snippet[..(maxLen + 60)] + "..." : snippet;
    }
}
