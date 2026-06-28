using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class LeagueOfLegendsCheatScanModule : IScanModule
{
    public string Name => "League of Legends Cheat Detection";
    public double Weight => 3.8;
    public int ParallelGroup => 4;

    private static readonly string[] CheatExeNames =
    [
        "lolcheat.exe", "leaguecheat.exe", "leaguehack.exe", "lolhack.exe",
        "lolaimbot.exe", "lolesp.exe", "leagueesp.exe", "lolexternal.exe",
        "lol_hack.exe", "lol_maphack.exe", "lol_script.exe",
        "lol_orbwalker.exe", "lol_jungle_timer.exe", "evade.exe",
        "lol_evade.exe", "lol_skin.exe", "lolbot.exe", "lolscript.exe",
        "lol_champion_esp.exe", "lol_ward_esp.exe", "lolauto.exe",
        "lol_auto_smite.exe", "lol_combo.exe", "lolcombo.exe",
        "leagueauto.exe", "leaguebot.exe", "leaguescript.exe",
        "leaguemaphack.exe", "lol_aware.exe", "lolaware.exe",
        "lol_timers.exe", "looltimers.exe", "lol_tracker.exe",
        "loltracker.exe", "lol_cs.exe", "lol_waveclear.exe",
        "lol_jungle.exe", "lol_gank.exe", "lolprediction.exe",
        "lol_predict.exe", "leagueprediction.exe", "lol_ward.exe",
        "lolward.exe", "lol_recall.exe", "lolrecall.exe",
        "lol_flash.exe", "lolflash.exe", "cheatengine_lol.exe",
        "lol_bypass.exe", "lolbypass.exe", "vanguard_bypass_lol.exe",
        "lol_skin_changer.exe", "lolskinchanger.exe", "league_skin.exe",
        "lol_champion_select.exe", "lolchampion.exe", "leaguechampion.exe",
        "lol_internal.dll", "leagueinternal.dll", "lolinternal.dll",
        "lol_inject.exe", "lolinject.exe", "leagueinject.exe",
    ];

    private static readonly string[] CheatConfigKeywords =
    [
        "orbwalker_mode", "combo_key", "harass_key", "jungle_clear",
        "evade_enabled", "skillshot_dodge", "maphack_lol",
        "champion_esp", "ward_esp_lol", "jungle_timer",
        "item_esp_lol", "auto_smite", "auto_ignite", "auto_flash",
        "skin_changer_lol", "champion_clone", "tower_esp", "turret_range",
        "attack_range", "auto_cs", "last_hit", "auto_deny_lol",
        "spell_evade", "dodge_enabled", "flee_enabled",
        "orbit_mode", "orb_walk", "orbwalk", "orbwalker",
        "combo_mode", "harass_mode", "laneclear_mode", "lasthit_mode",
        "auto_level", "auto_skill", "auto_item", "auto_potion",
        "auto_ult", "ultimate_auto", "auto_q", "auto_w", "auto_e",
        "aimbot_lol", "prediction_lol", "collision_lol", "delay_lol",
        "lol_aimbot", "lol_esp", "lol_wallhack",
    ];

    private static readonly string[] OffsetKeywords =
    [
        "ObjectManager", "LocalPlayer", "HeroList", "JungleObjectManager",
        "m_team", "m_health", "m_pos", "m_mana", "m_level",
        "m_name", "m_spells", "m_items", "m_buffs",
        "League of Legends.exe", "LeagueOfLegends.exe",
        "GameObjectManager", "PlayerController", "ChampionList",
        "EffectEmitter", "AttackableUnit", "AIHeroClient",
        "MissileClient", "MinionClient", "TurretClient",
        "InhibitorClient", "NexusClient", "DragonClient",
    ];

    private static readonly string[] ScriptPaths =
    [
        "LeagueSharp",
        "LSSharp",
        "RSharp",
        "Ensoul",
        "GB_Studio",
        "Marksman",
        "AimTec",
        "EloBuddy",
        "L#",
        "SimpleBuddy",
        "Hellsing",
        "PerfectWard",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>
        {
            ScanLolInstallPathsAsync(ctx, ct),
            ScanProcessesAsync(ctx, ct),
            ScanScriptDirectoriesAsync(ctx, ct),
            ScanConfigFilesAsync(ctx, ct),
            ScanOffsetFilesAsync(ctx, ct),
            ScanRegistryAsync(ctx, ct),
            ScanAppDataAsync(ctx, ct),
            ScanVanguardBypassAsync(ctx, ct),
        };
        await Task.WhenAll(tasks);
    }

    private async Task ScanLolInstallPathsAsync(ScanContext ctx, CancellationToken ct)
    {
        var lolPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Riot Games", "League of Legends"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Riot Games", "League of Legends"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot Games", "League of Legends"),
            @"C:\Riot Games\League of Legends",
            @"D:\Riot Games\League of Legends",
            @"E:\Riot Games\League of Legends",
        };

        foreach (var lolRoot in lolPaths)
        {
            if (!Directory.Exists(lolRoot)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(lolRoot, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (CheatExeNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "LoL Cheat Tool in Game Directory",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Cheat tool '{fn}' found inside League of Legends installation",
                        Detail = $"Path: {file}"
                    });
                }

                // Unexpected DLLs injected into LoL game folder
                var ext = Path.GetExtension(fn).ToLowerInvariant();
                if (ext == ".dll" && !fn.StartsWith("league", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var scriptPath in ScriptPaths)
                    {
                        if (file.Contains(scriptPath, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "LoL Cheat Script DLL",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Scripting framework DLL in LoL path: {scriptPath}",
                                Detail = "Script-based cheats inject into LoL via DLL"
                            });
                            break;
                        }
                    }
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanProcessesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var processes = ctx.GetProcessSnapshot();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();
                var pname = proc.ProcessName + ".exe";

                if (CheatExeNames.Any(c => pname.Equals(c, StringComparison.OrdinalIgnoreCase)))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "LoL Cheat Process Running",
                        Risk = RiskLevel.Critical,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Known LoL cheat process '{pname}' is currently running",
                        Detail = $"PID: {proc.Id}"
                    });
                }
            }
        }, ct);
    }

    private async Task ScanScriptDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var scriptName in ScriptPaths)
        {
            var dirs = new[]
            {
                Path.Combine(appData, scriptName),
                Path.Combine(localAppData, scriptName),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), scriptName),
            };

            foreach (var dir in dirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "LoL Cheat Script Framework Directory",
                    Risk = RiskLevel.Critical,
                    Location = dir,
                    FileName = Path.GetFileName(dir),
                    Reason = $"Known LoL cheat scripting framework directory found: {scriptName}",
                    Detail = $"Path: {dir} — script-based cheats allow combo automation, evade, maphack"
                });

                // Scan contents
                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();

                    if (ext == ".dll" || ext == ".exe")
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "LoL Script Cheat Assembly",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Script cheat executable/DLL in {scriptName} framework directory",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
        }
    }

    private async Task ScanConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Riot Games", "League of Legends"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot Games", "League of Legends"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "League of Legends"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var dir in configPaths)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".ini" && ext != ".cfg" && ext != ".json" && ext != ".txt" && ext != ".xml") continue;

                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var hits = CheatConfigKeywords.Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)).ToList();
                if (hits.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "LoL Cheat Configuration",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"{hits.Count} LoL cheat config keywords detected",
                        Detail = "Keywords: " + string.Join(", ", hits.Take(8))
                    });
                }
                else if (hits.Count == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "LoL Cheat Config Keyword",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"File contains LoL cheat keyword: {hits[0]}",
                        Detail = $"File: {file}"
                    });
                }
            }
        }
    }

    private async Task ScanOffsetFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        foreach (var baseDir in searchDirs)
        {
            if (!Directory.Exists(baseDir)) continue;

            string[] files;
            try { files = Directory.GetFiles(baseDir, "*.*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".json" && ext != ".hpp" && ext != ".h" && ext != ".cpp") continue;

                var fn = Path.GetFileName(file);
                if (!fn.Contains("lol", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("league", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("offset", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("dump", StringComparison.OrdinalIgnoreCase)) continue;

                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var hits = OffsetKeywords.Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)).ToList();
                if (hits.Count >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "League of Legends Memory Offset File",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"File contains {hits.Count} LoL memory offset identifiers",
                        Detail = "Offsets: " + string.Join(", ", hits.Take(8))
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check Riot Games registry
            var riotKeys = new[]
            {
                @"SOFTWARE\Riot Games",
                @"SOFTWARE\Riot Games\League of Legends",
                @"SOFTWARE\LeagueOfLegends",
            };

            foreach (var riotKey in riotKeys)
            {
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(riotKey);
                    if (k == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valName in k.GetValueNames())
                    {
                        if (valName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("script", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious Riot Games Registry Value",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{riotKey}",
                                FileName = "Registry",
                                Reason = $"Suspicious registry value '{valName}' in Riot path",
                                Detail = $"Key: {riotKey}\\{valName}"
                            });
                        }
                    }
                }
                catch { }
            }

            // Scan installed software for LoL cheats
            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            foreach (var uninst in uninstallPaths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(uninst);
                    if (key == null) continue;

                    foreach (var sub in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var entry = key.OpenSubKey(sub);
                            ctx.IncrementRegistryKeys();
                            var dispName = entry?.GetValue("DisplayName") as string ?? string.Empty;
                            if ((dispName.Contains("league", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("lol", StringComparison.OrdinalIgnoreCase)) &&
                                (dispName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("script", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("bot", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "LoL Cheat Software Installed",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\{uninst}\{sub}",
                                    FileName = "Registry",
                                    Reason = $"Installed software '{dispName}' matches LoL cheat pattern",
                                    Detail = $"DisplayName: {dispName}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // UserAssist for LoL cheat tools execution history
            var userAssistPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
            try
            {
                using var ua = Registry.CurrentUser.OpenSubKey(userAssistPath);
                if (ua != null)
                {
                    foreach (var guidKey in ua.GetSubKeyNames())
                    {
                        try
                        {
                            using var countKey = Registry.CurrentUser.OpenSubKey($@"{userAssistPath}\{guidKey}\Count");
                            if (countKey == null) continue;
                            foreach (var valName in countKey.GetValueNames())
                            {
                                ctx.IncrementRegistryKeys();
                                // ROT13 decode
                                var decoded = Rot13(valName);
                                if (CheatExeNames.Any(c => decoded.Contains(c, StringComparison.OrdinalIgnoreCase)) ||
                                    ScriptPaths.Any(s => decoded.Contains(s, StringComparison.OrdinalIgnoreCase)))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "LoL Cheat Tool Execution History",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKCU\{userAssistPath}\{guidKey}\Count",
                                        FileName = "Registry",
                                        Reason = "UserAssist shows LoL cheat tool was executed",
                                        Detail = $"Decoded path: {decoded}"
                                    });
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }, ct);
    }

    private async Task ScanAppDataAsync(ScanContext ctx, CancellationToken ct)
    {
        var lolAppDataPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Riot Games"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot Games"),
        };

        foreach (var dir in lolAppDataPaths)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                // Unexpected DLLs in Riot Games AppData — could be injection artifacts
                if (fn.Contains("hook", StringComparison.OrdinalIgnoreCase) ||
                    fn.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                    fn.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                    fn.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                    fn.Contains("hack", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Suspicious DLL in Riot AppData",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"DLL '{fn}' with cheat-related name found in Riot Games AppData",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }

        // Scan logs for injection/bypass artifacts
        var logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot Games", "logs");
        if (Directory.Exists(logDir))
        {
            string[] logFiles;
            try { logFiles = Directory.GetFiles(logDir, "*.log", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }

            foreach (var logFile in logFiles)
            {
                ct.ThrowIfCancellationRequested();
                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                if (content.Contains("injection", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("cheat", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat/Bypass Keywords in LoL Logs",
                        Risk = RiskLevel.Medium,
                        Location = logFile,
                        FileName = Path.GetFileName(logFile),
                        Reason = "Riot Games log file contains injection/bypass keywords",
                        Detail = $"Log: {logFile}"
                    });
                }
            }
        }
    }

    private async Task ScanVanguardBypassAsync(ScanContext ctx, CancellationToken ct)
    {
        // LoL uses Vanguard since 2024 — check Vanguard service state
        await Task.Run(() =>
        {
            var vanguardServices = new[] { "vgc", "vgk" };
            foreach (var svcName in vanguardServices)
            {
                try
                {
                    using var svc = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svcName}");
                    if (svc == null) continue;
                    ctx.IncrementRegistryKeys();
                    var start = svc.GetValue("Start");
                    if (start is int s && s == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Vanguard Service '{svcName}' Disabled (LoL)",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = "Registry",
                            Reason = $"Vanguard anti-cheat service '{svcName}' is disabled — LoL/Valorant bypass indicator",
                            Detail = "Vanguard is required for League of Legends since 2024"
                        });
                    }
                }
                catch { }
            }

            // Vanguard bypass tools for LoL
            var bypassTools = new[]
            {
                "vgk_bypass.exe", "vanguard_bypass_lol.exe", "lol_vanguard_bypass.exe",
                "vanguard_unload.exe", "riot_bypass.dll", "vgc_bypass.exe",
                "vanguard_spoofer.exe", "vgk_spoofer.exe",
            };

            var searchDirs = new[]
            {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    if (bypassTools.Any(t => fn.Equals(t, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Vanguard Bypass Tool (LoL Context)",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Vanguard bypass tool '{fn}' targeting LoL/Riot anti-cheat",
                            Detail = "Bypasses Vanguard kernel driver to enable cheat injection in LoL"
                        });
                    }
                }
            }
        }, ct);
    }

    private static string Rot13(string input)
    {
        return new string(input.Select(c =>
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) :
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) : c).ToArray());
    }
}
