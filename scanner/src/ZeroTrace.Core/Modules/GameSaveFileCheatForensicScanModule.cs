using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class GameSaveFileCheatForensicScanModule : IScanModule
{
    public string Name => "Game Save File Cheat Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatSaveKeywords = new[]
    {
        "cheat", "hack", "godmode", "noclip", "infinite", "money", "cash", "rp",
        "level", "max_level", "max_money", "unlock_all", "unlocker",
        "trainer", "menu", "bypass", "inject", "exploit",
        "aimbot", "esp", "wallhack", "spinbot", "bhop",
        "teleport", "speedhack", "superjump", "invincible",
        "modded", "modded_account", "recovery", "stat_editor",
        "kiddion", "stand", "eulen", "cherax", "2take1",
        "add_principal", "give_admin", "give_weapon",
        "max_stat", "max_skill", "max_lung", "max_strength",
        "vehicle_spawn", "object_spawn",
        "rep_hack", "reputation_hack",
        "xp_hack", "level_hack", "rank_hack",
    };

    private static readonly string[] SuspiciousSaveValues = new[]
    {
        "2147483647", "999999999", "9999999", "2147483646",
        "0x7FFFFFFF", "0xFFFFFFFF",
        "-1", "2147483648",
    };

    private static readonly string[] KnownGameSavePaths = new[]
    {
        // GTA V
        @"Documents\Rockstar Games\GTA V\Profiles",
        @"AppData\Local\Rockstar Games\GTA V\Profiles",
        // GTA Online (cloud)
        @"AppData\Roaming\Rockstar Games\GTA V",
        // RDR2
        @"Documents\Rockstar Games\Red Dead Redemption 2\Profiles",
        // FiveM
        @"AppData\Roaming\CitizenFX",
        // Rust
        @"AppData\LocalLow\Facepunch Studios\Rust\cfg",
        // CS:GO / CS2
        @"Program Files (x86)\Steam\userdata",
        @"AppData\Local\Counter-Strike Global Offensive",
        // Apex Legends
        @"AppData\Roaming\Respawn\Apex\profile",
        // Escape from Tarkov
        @"AppData\Roaming\Battlestate Games\EscapeFromTarkov",
        // Valorant
        @"AppData\Local\VALORANT\Saved\Logs",
        // Warzone
        @"Documents\Call of Duty",
        @"Documents\Call of Duty Modern Warfare",
        // Fortnite
        @"AppData\Local\FortniteGame\Saved\Config\WindowsClient",
        // Rainbow Six Siege
        @"Documents\My Games\Rainbow Six - Siege",
        // Overwatch
        @"AppData\Local\Battle.net",
        // RageMP
        @"AppData\Roaming\RAGE Multiplayer",
        // alt:V
        @"AppData\Roaming\altv",
        // Minecraft
        @"AppData\Roaming\.minecraft",
    };

    private static readonly string[] CloudSaveServices = new[]
    {
        @"AppData\Roaming\Dropbox",
        @"AppData\Local\Google\Drive",
        @"OneDrive",
        @"AppData\Local\Microsoft\OneDrive",
    };

    private static readonly string[] StatEditorToolNames = new[]
    {
        "stat_editor", "stateditor", "savedit", "gta_stat", "gta5_stat",
        "recovery", "account_recovery", "kiddion_stat",
        "money_drop", "moneydrop", "rp_drop", "cashdrop",
        "modded_lobby", "moddedlobby", "recovery_lobby",
        "save_edit", "saveedit", "cheatsave", "savecheat",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckGTAVSaveFiles(ctx, ct),
            CheckRageMultiplayerSaves(ctx, ct),
            CheckAltVSaveArtifacts(ctx, ct),
            CheckRustCheaterConfig(ctx, ct),
            CheckEscapeFromTarkovSaves(ctx, ct),
            CheckGenericGameSaveCheat(ctx, ct),
            CheckSteamUserDataCheat(ctx, ct),
            CheckCloudSaveCheatSync(ctx, ct),
            CheckStatEditorToolArtifacts(ctx, ct),
            CheckSaveBackupCheat(ctx, ct),
            CheckMinecraftCheatMods(ctx, ct),
            CheckFortniteCheatConfig(ctx, ct),
            CheckWarzoneSaveCheat(ctx, ct),
            CheckApexSaveCheat(ctx, ct),
            CheckSaveFileTimestampAnomaly(ctx, ct),
            CheckSaveEditorRegistryArtifacts(ctx, ct),
            CheckGameProfileCheatData(ctx, ct),
            CheckSaveFileDownloadedCheats(ctx, ct)
        );
    }

    private Task CheckGTAVSaveFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] gtaSavePaths = new[]
        {
            Path.Combine(userProfile, @"Documents\Rockstar Games\GTA V\Profiles"),
            Path.Combine(userProfile, @"AppData\Local\Rockstar Games\GTA V\Profiles"),
        };

        foreach (string savePath in gtaSavePaths)
        {
            if (!Directory.Exists(savePath)) continue;
            foreach (string saveFile in Directory.GetFiles(savePath, "*", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    var info = new FileInfo(saveFile);
                    using var fs = new FileStream(saveFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 1 * 1024 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string cheatKw in CheatSaveKeywords)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "GTA V Save File — Cheat Keyword",
                                Risk = RiskLevel.Critical,
                                Location = saveFile,
                                FileName = Path.GetFileName(saveFile),
                                Reason = $"GTA V save file contains cheat-related keyword: '{cheatKw}'",
                                Detail = "GTA V save files modified by cheats (stat editors, money drops) contain cheat tool signatures"
                            });
                            break;
                        }
                    }

                    foreach (string suspVal in SuspiciousSaveValues)
                    {
                        if (content.Contains(suspVal, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "GTA V Save File — Max/Overflow Stat Values",
                                Risk = RiskLevel.High,
                                Location = saveFile,
                                FileName = Path.GetFileName(saveFile),
                                Reason = $"GTA V save contains suspicious maximum stat value: '{suspVal}'",
                                Detail = "Maximum integer values in save files indicate stat modification by cheat tools"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMultiplayerSaves(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string ragePath = Path.Combine(userProfile, @"AppData\Roaming\RAGE Multiplayer");
        if (!Directory.Exists(ragePath)) return;

        foreach (string file in Directory.GetFiles(ragePath, "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".lua", StringComparison.OrdinalIgnoreCase)))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string cheatKw in CheatSaveKeywords)
                {
                    if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Config — Cheat Artifact",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"RageMP configuration/script file contains cheat keyword: '{cheatKw}'",
                            Detail = "RageMP config and client scripts modified by cheat tools to enable unauthorized gameplay modifications"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckAltVSaveArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string altVPath = Path.Combine(userProfile, @"AppData\Roaming\altv");
        if (!Directory.Exists(altVPath)) return;

        foreach (string file in Directory.GetFiles(altVPath, "*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) ||
                        f.EndsWith(".js", StringComparison.OrdinalIgnoreCase)))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string cheatKw in CheatSaveKeywords)
                {
                    if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Config — Cheat Artifact",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"alt:V configuration file contains cheat keyword: '{cheatKw}'",
                            Detail = "alt:V data files modified by cheat tools contain traces of cheat configuration and usage"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckRustCheaterConfig(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] rustPaths = new[]
        {
            Path.Combine(userProfile, @"AppData\LocalLow\Facepunch Studios\Rust\cfg"),
            Path.Combine(userProfile, @"AppData\LocalLow\Facepunch Studios\Rust"),
        };

        string[] rustCheatKeywords = new[]
        {
            "aimbot", "esp", "wallhack", "speedhack", "bhop", "noclip",
            "stash", "furnace_esp", "ore_esp", "player_esp", "animal_esp",
            "no_recoil", "silent_aim", "triggerbot", "auto_fire",
            "cheat", "hack", "bypass", "inject",
            "silent_farm", "auto_gather", "auto_upgrade",
        };

        foreach (string rustPath in rustPaths)
        {
            if (!Directory.Exists(rustPath)) continue;
            foreach (string cfgFile in Directory.GetFiles(rustPath, "*.cfg", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(rustPath, "*.json", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (string rustKw in rustCheatKeywords)
                    {
                        if (content.Contains(rustKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Rust Config — Cheat Configuration",
                                Risk = RiskLevel.Critical,
                                Location = cfgFile,
                                FileName = Path.GetFileName(cfgFile),
                                Reason = $"Rust configuration file contains cheat keyword: '{rustKw}'",
                                Detail = "Rust client config files modified by cheat tools contain cheat feature settings"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckEscapeFromTarkovSaves(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string tarkovPath = Path.Combine(userProfile, @"AppData\Roaming\Battlestate Games\EscapeFromTarkov");
        if (!Directory.Exists(tarkovPath)) return;

        foreach (string file in Directory.GetFiles(tarkovPath, "*.json", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                string[] tarkovCheatKeywords = new[]
                {
                    "esp", "aimbot", "cheat", "hack", "speedhack", "noclip",
                    "loot_esp", "player_esp", "item_esp", "corpse_esp",
                    "no_recoil", "instant_hit", "no_spread", "no_sway",
                    "wallhack", "see_through", "thermal",
                    "ruble", "rubbles", "money_hack",
                };

                foreach (string tarKw in tarkovCheatKeywords)
                {
                    if (content.Contains(tarKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Escape from Tarkov — Cheat Config",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"EFT config file contains cheat keyword: '{tarKw}'",
                            Detail = "Escape from Tarkov client config modified by cheat tools retains cheat feature settings"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckGenericGameSaveCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string myGamesPath = Path.Combine(userProfile, "Documents", "My Games");
        if (!Directory.Exists(myGamesPath)) return;

        foreach (string file in Directory.GetFiles(myGamesPath, "*.ini", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(myGamesPath, "*.cfg", SearchOption.AllDirectories)))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string cheatKw in CheatSaveKeywords)
                {
                    if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "My Games Config — Cheat Setting",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Game configuration file in My Games contains cheat keyword: '{cheatKw}'",
                            Detail = "Game config files in My Games folder contain cheat-related settings or keywords"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckSteamUserDataCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] steamPaths = new[]
        {
            @"C:\Program Files (x86)\Steam\userdata",
            @"C:\Program Files\Steam\userdata",
        };

        foreach (string steamPath in steamPaths)
        {
            if (!Directory.Exists(steamPath)) continue;
            foreach (string vdfFile in Directory.GetFiles(steamPath, "*.vdf", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(vdfFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (string cheatKw in CheatSaveKeywords)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Steam UserData VDF — Cheat Reference",
                                Risk = RiskLevel.High,
                                Location = vdfFile,
                                FileName = Path.GetFileName(vdfFile),
                                Reason = $"Steam userdata VDF file contains cheat keyword: '{cheatKw}'",
                                Detail = "Steam userdata config files may retain cheat settings from cloud-synced game configs"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckCloudSaveCheatSync(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string cloudRelPath in CloudSaveServices)
        {
            string cloudPath = Path.Combine(userProfile, cloudRelPath);
            if (!Directory.Exists(cloudPath)) continue;

            foreach (string file in Directory.GetFiles(cloudPath, "*.json", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(cloudPath, "*.sav", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 512 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string cheatKw in CheatSaveKeywords)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cloud Storage — Cheat Save File Sync",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cloud storage contains game save/config with cheat keyword: '{cheatKw}'",
                                Detail = "Cheat-modified save files synced to cloud storage indicate deliberate cheat usage across sessions"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckStatEditorToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, @"AppData\Local\Temp"),
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string file in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string fileName = Path.GetFileName(file).ToLowerInvariant();
                foreach (string toolName in StatEditorToolNames)
                {
                    if (fileName.Contains(toolName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Stat Editor / Recovery Tool Found",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Game stat editor or account recovery tool found: '{toolName}'",
                            Detail = "Stat editors and account recovery tools manipulate game save data to provide unfair advantages"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckSaveBackupCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] savePaths = new[]
        {
            Path.Combine(userProfile, @"Documents\Rockstar Games"),
            Path.Combine(userProfile, @"AppData\Local\Rockstar Games"),
        };

        foreach (string savePath in savePaths)
        {
            if (!Directory.Exists(savePath)) continue;
            foreach (string backupFile in Directory.GetFiles(savePath, "*.bak", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(savePath, "*.backup", SearchOption.AllDirectories))
                .Concat(Directory.GetFiles(savePath, "*_original", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(backupFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 512 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string cheatKw in CheatSaveKeywords)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Game Save Backup — Cheat Data Preserved",
                                Risk = RiskLevel.High,
                                Location = backupFile,
                                FileName = Path.GetFileName(backupFile),
                                Reason = $"Game save backup file contains cheat keyword: '{cheatKw}'",
                                Detail = "Backup files created by stat editors preserve the pre-edit save state, revealing cheat tool usage"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckMinecraftCheatMods(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string minecraftPath = Path.Combine(userProfile, @"AppData\Roaming\.minecraft");
        if (!Directory.Exists(minecraftPath)) return;

        string[] mcCheatKeywords = new[]
        {
            "killaura", "kill_aura", "aimbot", "esp", "wallhack",
            "scaffold", "criticals", "velocity", "nohurtcam",
            "bhop", "speed", "fly", "nofall", "antiknockback",
            "autofish", "autoeat", "autoclick", "autocomplete",
            "xray", "fullbright", "tracers", "chest_esp",
            "cheat", "hack", "inject", "bypass", "client",
            "wurst", "meteor", "impact", "inertia", "refraction",
        };

        foreach (string file in Directory.GetFiles(minecraftPath, "*.json", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(minecraftPath, "*.cfg", SearchOption.AllDirectories)))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string mcKw in mcCheatKeywords)
                {
                    if (content.Contains(mcKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Minecraft — Cheat Client Config",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Minecraft config file contains cheat client keyword: '{mcKw}'",
                            Detail = "Minecraft cheat client configuration files (Wurst, Meteor, Impact, etc.) found in .minecraft directory"
                        });
                        break;
                    }
                }
            }
            catch { }
        }

        string modsPath = Path.Combine(minecraftPath, "mods");
        if (Directory.Exists(modsPath))
        {
            foreach (string modFile in Directory.GetFiles(modsPath, "*.jar", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string modName = Path.GetFileName(modFile).ToLowerInvariant();
                foreach (string cheatClient in new[] { "wurst", "meteor", "impact", "inertia", "refraction",
                    "liquidbounce", "future", "nodus", "sigma" })
                {
                    if (modName.Contains(cheatClient, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Minecraft — Known Cheat Client JAR",
                            Risk = RiskLevel.Critical,
                            Location = modFile,
                            FileName = Path.GetFileName(modFile),
                            Reason = $"Known Minecraft cheat client mod found: '{cheatClient}'",
                            Detail = "Known Minecraft cheat client JAR file present in mods directory"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckFortniteCheatConfig(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string fortnitePath = Path.Combine(userProfile, @"AppData\Local\FortniteGame\Saved\Config\WindowsClient");
        if (!Directory.Exists(fortnitePath)) return;

        foreach (string iniFile in Directory.GetFiles(fortnitePath, "*.ini", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(iniFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                string[] fortniteCheatKeywords = new[]
                {
                    "aimbot", "esp", "wallhack", "cheat", "hack", "inject", "bypass",
                    "r.ScreenPercentage", "sg.ShadowQuality=0",
                    "r.Streaming.PoolSize=-1",
                    "FoliageQuality=0.*VisibilityDistance=0",
                };

                foreach (string fnKw in fortniteCheatKeywords)
                {
                    if (content.Contains(fnKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Fortnite Config — Cheat Setting Detected",
                            Risk = RiskLevel.High,
                            Location = iniFile,
                            FileName = Path.GetFileName(iniFile),
                            Reason = $"Fortnite configuration contains cheat/visibility keyword: '{fnKw}'",
                            Detail = "Fortnite config files may be modified to reduce visual clutter (foliage, shadows) for unfair visibility advantage"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckWarzoneSaveCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] warzonePaths = new[]
        {
            Path.Combine(userProfile, @"Documents\Call of Duty"),
            Path.Combine(userProfile, @"Documents\Call of Duty Modern Warfare"),
            Path.Combine(userProfile, @"AppData\Local\Activision\CoDUO"),
        };

        foreach (string wzPath in warzonePaths)
        {
            if (!Directory.Exists(wzPath)) continue;
            foreach (string configFile in Directory.GetFiles(wzPath, "*", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string cheatKw in CheatSaveKeywords)
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Call of Duty / Warzone Config — Cheat Artifact",
                                Risk = RiskLevel.High,
                                Location = configFile,
                                FileName = Path.GetFileName(configFile),
                                Reason = $"CoD/Warzone config contains cheat keyword: '{cheatKw}'",
                                Detail = "Call of Duty config files modified by cheat tools contain cheat setting signatures"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckApexSaveCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string apexPath = Path.Combine(userProfile, @"AppData\Roaming\Respawn\Apex\profile");
        if (!Directory.Exists(apexPath)) return;

        foreach (string file in Directory.GetFiles(apexPath, "*", SearchOption.AllDirectories))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                foreach (string cheatKw in CheatSaveKeywords)
                {
                    if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Apex Legends Profile — Cheat Setting",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Apex Legends profile data contains cheat keyword: '{cheatKw}'",
                            Detail = "Apex Legends local profile data modified by cheat tools contains cheat configuration artifacts"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckSaveFileTimestampAnomaly(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] savePaths = new[]
        {
            Path.Combine(userProfile, @"Documents\Rockstar Games\GTA V\Profiles"),
            Path.Combine(userProfile, @"AppData\Local\Rockstar Games\GTA V\Profiles"),
        };

        foreach (string savePath in savePaths)
        {
            if (!Directory.Exists(savePath)) continue;
            foreach (string saveFile in Directory.GetFiles(savePath, "*", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    var info = new FileInfo(saveFile);
                    if (info.CreationTime > info.LastWriteTime ||
                        (info.LastWriteTime - info.CreationTime).TotalSeconds < 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Game Save File — Timestamp Anomaly",
                            Risk = RiskLevel.Medium,
                            Location = saveFile,
                            FileName = Path.GetFileName(saveFile),
                            Reason = $"Save file timestamp anomaly: Created={info.CreationTime:s}, Modified={info.LastWriteTime:s}",
                            Detail = "Timestamp anomalies in save files may indicate the file was copied, replaced, or timestomped by a cheat tool"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckSaveEditorRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] statEditorRegNames = new[]
        {
            "KiddionsStat", "GTASaveEditor", "GTAOnlineMoney", "StatEditor",
            "SaveEditor", "SaveEdit", "AccountRecovery", "MoneyDrop",
            "RpDrop", "CashDrop", "KiddionsMod", "ModMenu", "Kiddion",
        };

        string[] uninstallKey = new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" };
        foreach (string regPath in uninstallKey)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath) ??
                                Registry.CurrentUser.OpenSubKey(regPath);
                if (key == null) continue;

                foreach (string subKeyName in key.GetSubKeyNames())
                {
                    foreach (string editorName in statEditorRegNames)
                    {
                        if (subKeyName.Contains(editorName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementRegistryKeys();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Registry — Stat Editor Tool Installation",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{regPath}\{subKeyName}",
                                FileName = subKeyName,
                                Reason = $"Stat editor or save modification tool found in uninstall registry: '{editorName}'",
                                Detail = "Uninstall registry entry for a game stat editor or money drop tool — proves installation and use"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }

        try
        {
            using var muiKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
            if (muiKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (string valueName in muiKey.GetValueNames())
                {
                    foreach (string editorName in StatEditorToolNames)
                    {
                        if (valueName.Contains(editorName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "MUICache — Stat Editor Execution",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache\{valueName}",
                                FileName = valueName,
                                Reason = $"MUICache shows execution of stat editor tool: '{editorName}'",
                                Detail = "MUICache records prove that the stat editor executable was run on this system"
                            });
                            break;
                        }
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckGameProfileCheatData(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] profileDirs = new[]
        {
            Path.Combine(userProfile, @"AppData\Local\Rockstar Games"),
            Path.Combine(userProfile, @"AppData\Roaming\Rockstar Games"),
        };

        foreach (string profileDir in profileDirs)
        {
            if (!Directory.Exists(profileDir)) continue;
            foreach (string file in Directory.GetFiles(profileDir, "*.dat", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(profileDir, "*.sav", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 1 * 1024 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string suspVal in SuspiciousSaveValues)
                    {
                        if (content.Contains(suspVal, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Rockstar Profile Data — Suspicious Values",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Profile data file contains suspicious max-value pattern: '{suspVal}'",
                                Detail = "Integer overflow or maximum values in Rockstar profile data indicate stat modification by recovery tools"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckSaveFileDownloadedCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsPath = Path.Combine(userProfile, "Downloads");
        if (!Directory.Exists(downloadsPath)) return;

        foreach (string file in Directory.GetFiles(downloadsPath, "*", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            string fileName = Path.GetFileName(file).ToLowerInvariant();

            string[] savCheatPatterns = new[]
            {
                "save_edit", "saveedit", "stat_edit", "statedit", "save_game_editor",
                "gta_save", "gta5_save", "gtao_save", "recovery_tool",
                "modded_account", "kiddion", "money_drop", "rp_drop",
                "rank_hack", "level_hack", "xp_hack",
            };

            foreach (string pattern in savCheatPatterns)
            {
                if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Downloads — Game Save Cheat Tool",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Downloaded file is a game save editor or cheat tool: '{pattern}'",
                        Detail = "Game save editor or account recovery tool found in Downloads — direct evidence of intent to cheat"
                    });
                    break;
                }
            }
        }
    }, ct);
}
