using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class GameTrainerCheatEngineScanModule : IScanModule
{
    public string Name => "Game Trainer & Cheat Engine Artifact Detection";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    private static readonly string[] TrainerExeNames =
    [
        "cheatengine.exe", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
        "cheatengine-x86_64-SSE4-AVX2.exe", "ce.exe", "cheatengine7.exe",
        "cheatengine6.exe", "cheatengine_portable.exe", "trainer.exe",
        "game_trainer.exe", "universal_trainer.exe", "trainer_maker.exe",
        "trainermaker.exe", "trainer_creator.exe", "trainer_builder.exe",
        "wemod.exe", "WeMod.exe", "flingtrainer.exe", "fling_trainer.exe",
        "megadev.exe", "mega_dev.exe", "gametrainer.exe",
        "trainerfactory.exe", "trainer_factory.exe",
        "arteplus.exe", "artmoney.exe", "art_money.exe",
        "tsearch.exe", "t_search.exe", "gamekiller.exe", "game_killer.exe",
        "sbinjector.exe", "sb_injector.exe", "gameguardian.exe",
        "game_guardian.exe", "paralleldroid.exe",
        "pkhax.exe", "pk_hax.exe", "pktrainer.exe", "pk_trainer.exe",
        "pkhax64.exe", "trainer_x64.exe", "trainer_x86.exe",
        "trainr.exe", "universal_unlocker.exe", "unlocker_trainer.exe",
        "inf_ammo.exe", "inf_health.exe", "inf_money.exe", "godmode.exe",
        "noclip_trainer.exe", "speedhack_trainer.exe", "freeze_trainer.exe",
        "pointer_scan.exe", "pointerscan.exe", "aob_scan.exe", "aobscan.exe",
        "memory_scanner.exe", "memscan.exe", "process_hacker.exe",
        "processhacker.exe", "ph.exe", "ph2.exe", "ph3.exe",
        "reclass.exe", "reclass_ex.exe", "rcex.exe",
        "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "windbg.exe",
        "ida.exe", "ida64.exe", "idaw.exe", "idaw64.exe",
        "ghidra.exe", "ghidrarun.exe", "binja.exe", "binary_ninja.exe",
        "radar.exe", "radar2.exe", "r2.exe",
        "structuredump.exe", "dump_structs.exe", "offset_finder.exe",
        "sig_maker.exe", "sigmaker.exe", "sigscan.exe", "sig_scan.exe",
    ];

    private static readonly string[] CeFileExtensions =
    [
        ".ct", // Cheat Engine table
        ".cetrainer", // CE trainer
    ];

    private static readonly string[] TrainerConfigKeywords =
    [
        "infinite_health", "infinite_ammo", "infinite_money", "infinite_lives",
        "god_mode", "noclip", "speed_multiplier", "freeze_timer",
        "max_stats", "unlock_all", "no_recoil", "no_spread",
        "auto_aim", "aimbot_trainer", "wallhack_trainer",
        "cheat_engine", "pointer_offset", "aob_scan", "sigscan",
        "memory_address", "base_address", "module_base",
        "health_address", "ammo_address", "money_address",
        "speed_address", "freeze_address", "position_address",
        "hotkey_health", "hotkey_ammo", "hotkey_money",
        "trainer_version", "trainer_author", "trainer_game",
        "wemod_enabled", "artmoney_enabled", "ce_enabled",
        "process_name", "game_process", "target_process",
        "enable_trainer", "activate_cheat", "toggle_cheat",
        "ValueType", "MemType", "Hotkey", "Options", "Condition",
    ];

    private static readonly string[] MemoryScannerKeywords =
    [
        "ProcessMemory", "ReadProcessMemory", "WriteProcessMemory",
        "VirtualAllocEx", "CreateRemoteThread", "OpenProcess",
        "NtReadVirtualMemory", "NtWriteVirtualMemory",
        "pointer_chain", "base_address", "module_offset",
        "aob_pattern", "byte_pattern", "signature_scan",
        "struct_offset", "member_offset", "vtable_offset",
        "entity_list", "player_list", "object_manager",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>
        {
            ScanTrainerFilesAsync(ctx, ct),
            ScanCheatEngineTablesAsync(ctx, ct),
            ScanProcessesAsync(ctx, ct),
            ScanRegistryAsync(ctx, ct),
            ScanWeModAsync(ctx, ct),
            ScanTrainerDirectoriesAsync(ctx, ct),
            ScanCheatEngineInstallAsync(ctx, ct),
            ScanDebuggerArtifactsAsync(ctx, ct),
        };
        await Task.WhenAll(tasks);
    }

    private async Task ScanTrainerFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (TrainerExeNames.Any(t => fn.Equals(t, StringComparison.OrdinalIgnoreCase)))
                {
                    var isCe = fn.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                fn.Contains("engine", StringComparison.OrdinalIgnoreCase);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = isCe ? "Cheat Engine Found" : "Game Trainer Tool Found",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Game trainer/memory editor '{fn}' found",
                        Detail = "Game trainers modify memory values to grant infinite health, ammo, money, etc."
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanCheatEngineTablesAsync(ScanContext ctx, CancellationToken ct)
    {
        // Scan for .ct (Cheat Engine table) and .cetrainer files
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.GetTempPath(),
        };

        foreach (var baseDir in searchDirs)
        {
            if (!Directory.Exists(baseDir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(baseDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                var fn = Path.GetFileName(file);

                if (ext == ".ct" || ext == ".cetrainer")
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Engine Table Found",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Cheat Engine table file '{fn}' found",
                        Detail = ".ct files contain memory addresses and cheats for specific games; .cetrainer are compiled CE trainers"
                    });
                    continue;
                }

                // Config files with trainer keywords
                if (ext == ".ini" || ext == ".cfg" || ext == ".json" || ext == ".xml")
                {
                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = TrainerConfigKeywords.Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)).ToList();
                    if (hits.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Game Trainer Configuration",
                            Risk = Risk.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"File contains {hits.Count} trainer/cheat engine keywords",
                            Detail = "Keywords: " + string.Join(", ", hits.Take(8))
                        });
                    }
                }
            }
        }
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

                if (TrainerExeNames.Any(t => pname.Equals(t, StringComparison.OrdinalIgnoreCase)))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Trainer/Memory Editor Running",
                        Risk = Risk.Critical,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Game trainer or memory editor '{pname}' is currently running",
                        Detail = $"PID: {proc.Id} — active trainers are cheating in real-time"
                    });
                }
            }
        }, ct);
    }

    private async Task ScanRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Cheat Engine installation in registry
            var ceKeys = new[]
            {
                @"SOFTWARE\Cheat Engine",
                @"SOFTWARE\WOW6432Node\Cheat Engine",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cheat Engine",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Cheat Engine",
            };

            foreach (var ceKey in ceKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(ceKey) ??
                                    Registry.CurrentUser.OpenSubKey(ceKey);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    var installPath = key.GetValue("InstallLocation") as string ??
                                      key.GetValue("InstallDir") as string ?? string.Empty;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Engine Installation Detected",
                        Risk = Risk.Critical,
                        Location = string.IsNullOrEmpty(installPath) ? ceKey : installPath,
                        FileName = "Registry",
                        Reason = "Cheat Engine is installed on this system",
                        Detail = $"Registry key: {ceKey}"
                    });
                    break;
                }
                catch { }
            }

            // WeMod installation
            var wemodKeys = new[]
            {
                @"SOFTWARE\WeMod",
                @"SOFTWARE\WOW6432Node\WeMod",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WeMod",
            };

            foreach (var wmKey in wemodKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(wmKey) ??
                                    Registry.CurrentUser.OpenSubKey(wmKey);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "WeMod Trainer Platform Installed",
                        Risk = Risk.High,
                        Location = wmKey,
                        FileName = "Registry",
                        Reason = "WeMod trainer platform is installed — provides trainers for hundreds of games",
                        Detail = $"Registry: {wmKey}"
                    });
                    break;
                }
                catch { }
            }

            // Scan installed software for trainer tools
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
                            if (dispName.Contains("Cheat Engine", StringComparison.OrdinalIgnoreCase) ||
                                dispName.Contains("ArtMoney", StringComparison.OrdinalIgnoreCase) ||
                                (dispName.Contains("trainer", StringComparison.OrdinalIgnoreCase) &&
                                 !dispName.Contains("personal", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Game Trainer Software Installed",
                                    Risk = Risk.High,
                                    Location = $@"HKLM\{uninst}\{sub}",
                                    FileName = "Registry",
                                    Reason = $"Game trainer tool '{dispName}' is installed",
                                    Detail = $"DisplayName: {dispName}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }, ct);
    }

    private async Task ScanWeModAsync(ScanContext ctx, CancellationToken ct)
    {
        var wemodPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WeMod"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WeMod"),
        };

        foreach (var wemodDir in wemodPaths)
        {
            if (!Directory.Exists(wemodDir)) continue;
            ct.ThrowIfCancellationRequested();

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "WeMod Trainer Platform Data Directory",
                Risk = Risk.High,
                Location = wemodDir,
                FileName = Path.GetFileName(wemodDir),
                Reason = "WeMod trainer data directory found — enables game cheating via trainer platform",
                Detail = $"Path: {wemodDir}"
            });

            // Check which games have trainers enabled
            var gamesFile = Path.Combine(wemodDir, "games.json");
            if (File.Exists(gamesFile))
            {
                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(gamesFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "WeMod Trainer Games List",
                    Risk = Risk.High,
                    Location = gamesFile,
                    FileName = "games.json",
                    Reason = "WeMod games.json found — contains list of games with active trainers",
                    Detail = $"File size: {new FileInfo(gamesFile).Length} bytes"
                });
            }
        }
    }

    private async Task ScanTrainerDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var ceDocPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Cheat Engine");
        if (Directory.Exists(ceDocPath))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Cheat Engine Documents Directory",
                Risk = Risk.Critical,
                Location = ceDocPath,
                FileName = "Cheat Engine",
                Reason = "Cheat Engine user directory found in Documents",
                Detail = "Contains saved cheat tables (.ct files) and CE trainer scripts"
            });

            string[] ctFiles;
            try { ctFiles = Directory.GetFiles(ceDocPath, "*.ct", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }

            foreach (var ctFile in ctFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat Engine Table in CE Documents",
                    Risk = Risk.Critical,
                    Location = ctFile,
                    FileName = Path.GetFileName(ctFile),
                    Reason = $"Cheat Engine table '{Path.GetFileName(ctFile)}' found in CE directory",
                    Detail = "Cheat Engine tables contain pointers and cheats for specific games"
                });
            }
        }

        // Fling trainer directory
        var flingPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FLiNG Trainer");
        if (Directory.Exists(flingPath))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "FLiNG Trainer Directory Found",
                Risk = Risk.High,
                Location = flingPath,
                FileName = "FLiNG Trainer",
                Reason = "FLiNG game trainer directory found — provides game trainers with multiple cheat features",
                Detail = $"Path: {flingPath}"
            });
        }
        await Task.CompletedTask;
    }

    private async Task ScanCheatEngineInstallAsync(ScanContext ctx, CancellationToken ct)
    {
        // Common CE install paths
        var cePaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine 7.5"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine 7.4"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine 7.3"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine 7.2"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Cheat Engine"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Cheat Engine 7.5"),
            @"C:\Cheat Engine",
            @"D:\Cheat Engine",
        };

        foreach (var cePath in cePaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cePath)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Cheat Engine Installation Directory",
                Risk = Risk.Critical,
                Location = cePath,
                FileName = Path.GetFileName(cePath),
                Reason = $"Cheat Engine installation found at '{cePath}'",
                Detail = "Cheat Engine is a universal memory scanner and trainer tool used for game cheating"
            });
        }

        // ReClass.NET install
        var reclassPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ReClass.NET"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "ReClass.NET"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "ReClass.NET"),
        };

        foreach (var rcPath in reclassPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(rcPath)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "ReClass.NET Memory Analysis Tool",
                Risk = Risk.High,
                Location = rcPath,
                FileName = "ReClass.NET",
                Reason = "ReClass.NET memory reverse engineering tool found",
                Detail = "Used to reverse game memory structures for cheat development"
            });
        }
        await Task.CompletedTask;
    }

    private async Task ScanDebuggerArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        // x64dbg/OllyDBG session files — indicate active game reverse engineering
        var debuggerPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "x64dbg"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "x32dbg"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OllyDBG"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "x64dbg"),
        };

        foreach (var dbgPath in debuggerPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dbgPath)) continue;

            string[] files;
            try { files = Directory.GetFiles(dbgPath, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file);
                var ext = Path.GetExtension(fn).ToLowerInvariant();

                // Session files indicate what was being debugged
                if (ext == ".dd64" || ext == ".dd32" || ext == ".udd" ||
                    ext == ".bp" || fn.Equals("x64dbg.ini", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    // Read the session file to check if a game was being debugged
                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { }

                    var gameKeywords = new[] { "fivem", "gta", "cs2", "csgo", "valorant", "apex", "pubg", "warzone", "battlefront", "cod", "game" };
                    if (gameKeywords.Any(g => content.Contains(g, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Debugger Session with Game Target",
                            Risk = Risk.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Debugger session file '{fn}' references game process — indicates game reverse engineering",
                            Detail = "Debuggers like x64dbg are used to find memory offsets and bypass anti-cheat"
                        });
                    }
                }
            }
        }
    }
}
