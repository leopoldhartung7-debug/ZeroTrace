using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class FiveMModMenuDeepForensicScanModule : IScanModule
{
    public string Name => "FiveM Mod Menu Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] MenuConfigDirs = { "2Take1Menu", "Stand", "YimMenu", "yim-menu", "Eulen", "RedEngine", "Skript", "BrainOBrain", "Midnight", "Cherax", "Kiddions" };
    private static readonly string[] MenuDLLNames = { "2Take1Menu.dll", "Stand.dll", "YimMenu.dll", "Eulen.dll", "RedEngine.dll", "Skript.dll", "BrainOBrain.dll", "Midnight.dll", "Cherax.dll", "modest_menu.exe", "modest_menu_x64.exe" };
    private static readonly string[] MenuRegistryKeys = { @"Software\2Take1Menu", @"Software\Stand", @"Software\YimMenu", @"Software\Eulen", @"Software\RedEngine", @"Software\Skript", @"Software\BrainOBrain", @"Software\Cherax", @"Software\Kiddions", @"Software\Midnight" };
    private static readonly string[] MenuWebDomains = { "2take1.menu", "stand.gg", "yimmenu.net", "eulen.app", "redengine.cc", "skript.gg", "brainobrain.gg", "midnight-software.xyz", "cherax.gg" };
    private static readonly string[] CheatScriptKeywords = { "esp", "aimbot", "godmode", "money", "teleport", "speedhack", "noclip", "freeze", "crash", "kick", "trolling", "recovery", "dropmoney", "bringall", "explosive", "invincible" };
    private static readonly string[] MenuLogKeywords = { "spawned", "teleported", "killed", "crashed", "money dropped", "godmode", "noclip", "kicked player", "griefed", "trolled" };
    private static readonly string[] FiveMAppPaths = { @"citizenfx\FiveM\FiveM.app", @"FiveM\FiveM.app" };

    private static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Downloads => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    private static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static string Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static string Temp => Path.GetTempPath();

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            Check2Take1Artifacts(ctx, ct),
            CheckStandMenuArtifacts(ctx, ct),
            CheckYimMenuArtifacts(ctx, ct),
            CheckEulenArtifacts(ctx, ct),
            CheckRedEngineArtifacts(ctx, ct),
            CheckSkriptMenuArtifacts(ctx, ct),
            CheckBrainOBrainArtifacts(ctx, ct),
            CheckMidnightSoftwareArtifacts(ctx, ct),
            CheckCheraxArtifacts(ctx, ct),
            CheckKiddionsMenuArtifacts(ctx, ct),
            CheckLuaMenuScriptArtifacts(ctx, ct),
            CheckMenuDLLInFiveMDirectory(ctx, ct),
            CheckMenuLogFilesArtifacts(ctx, ct),
            CheckMenuHotkeyConfigArtifacts(ctx, ct),
            CheckMenuRegistryDeep(ctx, ct),
            CheckPrefetchAndMRUForMenuExes(ctx, ct),
            CheckMenuDownloadAndInstallArtifacts(ctx, ct),
            CheckMenuPlayerDatabaseArtifacts(ctx, ct)
        );
    }

    private Task Check2Take1Artifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configDir = Path.Combine(AppData, "2Take1Menu");
        if (Directory.Exists(configDir))
        {
            var knownFiles = new[]
            {
                "settings.json", "hotkeys.json", "players.json",
                "vehicle_list.json", "user.txt", "license.txt"
            };

            foreach (var fileName in knownFiles)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(configDir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "2Take1 Mod Menu — Config File Found",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = "2Take1Menu configuration file found on disk. 2Take1 is a premium FiveM mod menu sold at 2take1.menu. Its presence is strong evidence of mod menu usage.",
                    Detail = $"Config directory: {configDir}"
                });
            }

            var scriptsDir = Path.Combine(configDir, "scripts");
            if (Directory.Exists(scriptsDir))
            {
                try
                {
                    foreach (var lua in Directory.GetFiles(scriptsDir, "*.lua", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "2Take1 Mod Menu — Lua Script Artifact",
                            Risk = RiskLevel.Critical,
                            Location = lua,
                            FileName = Path.GetFileName(lua),
                            Reason = "Lua script found inside the 2Take1Menu scripts directory. These scripts extend cheat functionality and confirm active mod menu configuration.",
                            Detail = $"Script path: {lua}"
                        });
                    }
                }
                catch { }
            }

            var logsDir = Path.Combine(configDir, "logs");
            if (Directory.Exists(logsDir))
            {
                try
                {
                    foreach (var log in Directory.GetFiles(logsDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "2Take1 Mod Menu — Session Log Found",
                            Risk = RiskLevel.Critical,
                            Location = log,
                            FileName = Path.GetFileName(log),
                            Reason = "2Take1Menu session log found. These logs record in-game cheat actions performed during FiveM sessions.",
                            Detail = $"Log directory: {logsDir}"
                        });
                    }
                }
                catch { }
            }
        }

        foreach (var fivemBase in FiveMAppPaths)
        {
            var roots = new[] { AppData, LocalAppData };
            foreach (var root in roots)
            {
                var dllPath = Path.Combine(root, fivemBase, "2Take1Menu.dll");
                if (!File.Exists(dllPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "2Take1 Mod Menu — DLL in FiveM Directory",
                    Risk = RiskLevel.Critical,
                    Location = dllPath,
                    FileName = "2Take1Menu.dll",
                    Reason = "2Take1Menu.dll found inside the FiveM application directory. This DLL is the injected mod menu component that hooks into the FiveM process.",
                    Detail = $"FiveM path root: {Path.Combine(root, fivemBase)}"
                });
            }
        }

        var searchDirs = new[] { Downloads, Desktop };
        var patterns = new[] { "2Take1*.zip", "2take1*.zip", "2Take1*.exe", "2take1*.exe", "2take1*.rar" };
        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var pattern in patterns)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var file in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "2Take1 Mod Menu — Installer/Archive Found",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "2Take1 mod menu installer or archive found in user directories. This indicates acquisition and likely installation of the cheat.",
                            Detail = $"Found in: {dir}"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\2Take1Menu");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "2Take1 Mod Menu — Registry Key Found",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\2Take1Menu",
                    Reason = "2Take1Menu registry key found. The menu writes configuration and license data to the registry during installation and operation.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckStandMenuArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configDir = Path.Combine(AppData, "Stand");
        if (Directory.Exists(configDir))
        {
            var knownFiles = new[] { "config.json", "user.ini", "Stand.dll", "Stand.log" };
            foreach (var fileName in knownFiles)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(configDir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Stand Mod Menu — Config File Found",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = "Stand mod menu artifact found. Stand (stand.gg) is a premium FiveM/GTA Online mod menu with extensive cheat capabilities.",
                    Detail = $"Config directory: {configDir}"
                });
            }

            try
            {
                foreach (var lua in Directory.GetFiles(configDir, "*.lua", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Stand Mod Menu — Lua Script Artifact",
                        Risk = RiskLevel.Critical,
                        Location = lua,
                        FileName = Path.GetFileName(lua),
                        Reason = "Lua script found in Stand menu directory. Stand supports custom Lua scripts for extended cheat functionality.",
                        Detail = $"Script: {lua}"
                    });
                }

                foreach (var tenanted in Directory.GetFiles(configDir, "*.tenanted", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Stand Mod Menu — Tenanted Script Artifact",
                        Risk = RiskLevel.Critical,
                        Location = tenanted,
                        FileName = Path.GetFileName(tenanted),
                        Reason = "Stand .tenanted script file found. These are Stand-specific encrypted scripts that extend cheat features.",
                        Detail = $"File: {tenanted}"
                    });
                }
            }
            catch { }
        }

        var searchDirs = new[] { Downloads, Desktop };
        var patterns = new[] { "Stand*.zip", "Stand*.dll", "Stand*.exe", "stand*.rar" };
        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var pattern in patterns)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var file in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Stand Mod Menu — Download Artifact Found",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Stand mod menu download artifact found. This indicates acquisition of the Stand cheat from stand.gg.",
                            Detail = $"Found in: {dir}"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Stand");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Stand Mod Menu — Registry Key Found",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\Stand",
                    Reason = "Stand mod menu registry key found. Stand writes session and configuration data to the registry.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckYimMenuArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var candidates = new[]
        {
            Path.Combine(AppData, "YimMenu"),
            Path.Combine(AppData, "yim-menu")
        };

        foreach (var configDir in candidates)
        {
            if (!Directory.Exists(configDir)) continue;

            var knownFiles = new[] { "settings.json", "hotkeys.json", "saved_vehicles.json", "player_history.json", "YimMenu.dll" };
            foreach (var fileName in knownFiles)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(configDir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "YimMenu — Config File Found",
                    Risk = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason = "YimMenu mod menu artifact found. YimMenu is an open-source FiveM/GTA mod menu widely distributed on GitHub. Its presence indicates cheat usage.",
                    Detail = $"Config directory: {configDir}"
                });
            }

            var scriptsDir = Path.Combine(configDir, "scripts");
            if (Directory.Exists(scriptsDir))
            {
                try
                {
                    foreach (var script in Directory.GetFiles(scriptsDir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "YimMenu — Script Artifact",
                            Risk = RiskLevel.High,
                            Location = script,
                            FileName = Path.GetFileName(script),
                            Reason = "Script file found in YimMenu scripts directory. These scripts extend YimMenu cheat capabilities.",
                            Detail = $"Scripts dir: {scriptsDir}"
                        });
                    }
                }
                catch { }
            }
        }

        foreach (var fivemBase in FiveMAppPaths)
        {
            var roots = new[] { AppData, LocalAppData };
            foreach (var root in roots)
            {
                var dllPath = Path.Combine(root, fivemBase, "YimMenu.dll");
                if (!File.Exists(dllPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "YimMenu — DLL in FiveM Directory",
                    Risk = RiskLevel.High,
                    Location = dllPath,
                    FileName = "YimMenu.dll",
                    Reason = "YimMenu.dll found inside the FiveM application directory. This DLL is injected into FiveM to provide cheat functionality.",
                    Detail = $"FiveM path: {Path.Combine(root, fivemBase)}"
                });
            }
        }

        var searchDirs = new[] { Downloads, Desktop };
        var patterns = new[] { "YimMenu*.dll", "YimMenu*.zip", "yimmenu*.dll", "yimmenu*.zip" };
        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var pattern in patterns)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var file in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "YimMenu — Download Artifact Found",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "YimMenu download artifact found. YimMenu is freely distributed and widely used for FiveM cheating.",
                            Detail = $"Found in: {dir}"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\YimMenu");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "YimMenu — Registry Key Found",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\YimMenu",
                    Reason = "YimMenu registry key found in HKCU. YimMenu writes configuration data here during operation.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckEulenArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configDir = Path.Combine(AppData, "Eulen");
        if (Directory.Exists(configDir))
        {
            var knownFiles = new[] { "config.json", "settings.ini", "Eulen.dll", "eulen_log.txt" };
            foreach (var fileName in knownFiles)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(configDir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Eulen Mod Menu — Config File Found",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = "Eulen mod menu artifact found. Eulen (eulen.app) is a premium FiveM mod menu with griefing and exploit capabilities.",
                    Detail = $"Config directory: {configDir}"
                });
            }

            try
            {
                foreach (var file in Directory.GetFiles(configDir, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    var ext = Path.GetExtension(file);
                    if (!ext.Equals(".json", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".ini", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".txt", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".log", StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Eulen Mod Menu — Session File Found",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "Eulen mod menu session or configuration file found. These files are created during Eulen cheat operation.",
                        Detail = $"File: {file}"
                    });
                }
            }
            catch { }
        }

        var searchDirs = new[] { Downloads, Desktop };
        var patterns = new[] { "Eulen*.zip", "Eulen*.exe", "eulen*.dll", "eulen*.rar" };
        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var pattern in patterns)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var file in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Eulen Mod Menu — Download Artifact Found",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Eulen mod menu download artifact found in user directories. This indicates acquisition from eulen.app.",
                            Detail = $"Found in: {dir}"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Eulen");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Eulen Mod Menu — Registry Key Found",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\Eulen",
                    Reason = "Eulen mod menu registry key found. Eulen writes license and configuration data to the registry.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRedEngineArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configDir = Path.Combine(AppData, "RedEngine");
        if (Directory.Exists(configDir))
        {
            var knownFiles = new[] { "config.json", "RedEngine.dll", "RedEngine.log" };
            foreach (var fileName in knownFiles)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(configDir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RedEngine Mod Menu — Config File Found",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = "RedEngine mod menu artifact found. RedEngine (redengine.cc) is a premium FiveM cheat with advanced exploit capabilities.",
                    Detail = $"Config directory: {configDir}"
                });
            }

            var licenseFiles = new[] { "license.txt", "license.key", "key.txt" };
            foreach (var licFile in licenseFiles)
            {
                if (ct.IsCancellationRequested) return;
                var lpath = Path.Combine(configDir, licFile);
                if (!File.Exists(lpath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RedEngine Mod Menu — License File Found",
                    Risk = RiskLevel.Critical,
                    Location = lpath,
                    FileName = licFile,
                    Reason = "RedEngine license file found. This proves the user purchased and installed the RedEngine mod menu.",
                    Detail = $"License file: {lpath}"
                });
            }

            var scriptsDir = Path.Combine(configDir, "scripts");
            if (Directory.Exists(scriptsDir))
            {
                try
                {
                    foreach (var script in Directory.GetFiles(scriptsDir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RedEngine Mod Menu — Script Artifact",
                            Risk = RiskLevel.Critical,
                            Location = script,
                            FileName = Path.GetFileName(script),
                            Reason = "Script file found in RedEngine scripts directory. These scripts extend RedEngine cheat capabilities.",
                            Detail = $"Script: {script}"
                        });
                    }
                }
                catch { }
            }
        }

        var searchDirs = new[] { Downloads, Desktop };
        var patterns = new[] { "RedEngine*.zip", "RedEngine*.dll", "redengine*.exe", "redengine*.rar" };
        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var pattern in patterns)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var file in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RedEngine Mod Menu — Download Artifact Found",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "RedEngine mod menu download artifact found. This indicates acquisition of the RedEngine cheat from redengine.cc.",
                            Detail = $"Found in: {dir}"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\RedEngine");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RedEngine Mod Menu — Registry Key Found",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\RedEngine",
                    Reason = "RedEngine registry key found in HKCU. RedEngine writes configuration and session data here.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckSkriptMenuArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configDir = Path.Combine(AppData, "Skript");
        if (Directory.Exists(configDir))
        {
            var knownFiles = new[] { "config.json", "Skript.dll", "Skript.log" };
            foreach (var fileName in knownFiles)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(configDir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Skript Mod Menu — Config File Found",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = "Skript.gg mod menu artifact found. Skript is a premium FiveM mod menu available at skript.gg with griefing and recovery features.",
                    Detail = $"Config directory: {configDir}"
                });
            }

            var scriptsDir = Path.Combine(configDir, "scripts");
            if (Directory.Exists(scriptsDir))
            {
                try
                {
                    foreach (var script in Directory.GetFiles(scriptsDir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Skript Mod Menu — Script Artifact",
                            Risk = RiskLevel.Critical,
                            Location = script,
                            FileName = Path.GetFileName(script),
                            Reason = "Script file found in Skript scripts directory.",
                            Detail = $"Script: {script}"
                        });
                    }
                }
                catch { }
            }
        }

        var searchDirs = new[] { Downloads, Desktop };
        var patterns = new[] { "Skript*.zip", "Skript*.dll", "skript*.exe", "skript*.rar" };
        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var pattern in patterns)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var file in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Skript Mod Menu — Download Artifact Found",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Skript mod menu download artifact found. This indicates acquisition from skript.gg.",
                            Detail = $"Found in: {dir}"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Skript");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Skript Mod Menu — Registry Key Found",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\Skript",
                    Reason = "Skript.gg mod menu registry key found in HKCU.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckBrainOBrainArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configDir = Path.Combine(AppData, "BrainOBrain");
        if (Directory.Exists(configDir))
        {
            var knownFiles = new[] { "config.json", "BrainOBrain.dll", "settings.ini" };
            foreach (var fileName in knownFiles)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(configDir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "BrainOBrain Mod Menu — Config File Found",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = "BrainOBrain mod menu artifact found. BrainOBrain (brainobrain.gg) is a FiveM mod menu with griefing and trolling features.",
                    Detail = $"Config directory: {configDir}"
                });
            }

            try
            {
                foreach (var file in Directory.GetFiles(configDir, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "BrainOBrain Mod Menu — Additional File Found",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "Additional BrainOBrain mod menu file found in config directory.",
                        Detail = $"File: {file}"
                    });
                }
            }
            catch { }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\BrainOBrain");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "BrainOBrain Mod Menu — Registry Key Found",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\BrainOBrain",
                    Reason = "BrainOBrain mod menu registry key found in HKCU. This indicates the cheat was installed and run on this machine.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMidnightSoftwareArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configDir = Path.Combine(AppData, "Midnight");
        if (Directory.Exists(configDir))
        {
            var knownFiles = new[] { "config.json", "Midnight.dll", "midnight_log.txt" };
            foreach (var fileName in knownFiles)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(configDir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Midnight Software Cheat — Config File Found",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = "Midnight Software cheat artifact found. Midnight (midnight-software.xyz) is a FiveM cheat tool with crash and grief capabilities.",
                    Detail = $"Config directory: {configDir}"
                });
            }

            try
            {
                foreach (var file in Directory.GetFiles(configDir, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Midnight Software — Additional Artifact Found",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "Additional Midnight Software cheat file found in config directory.",
                        Detail = $"File: {file}"
                    });
                }
            }
            catch { }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Midnight");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Midnight Software — Registry Key Found",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\Midnight",
                    Reason = "Midnight Software cheat registry key found in HKCU. This confirms the cheat was installed on this machine.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCheraxArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configDir = Path.Combine(AppData, "Cherax");
        if (Directory.Exists(configDir))
        {
            var knownFiles = new[] { "config.json", "Cherax.dll", "cherax.log" };
            foreach (var fileName in knownFiles)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(configDir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cherax Mod Menu — Config File Found",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = "Cherax mod menu artifact found. Cherax (cherax.gg) is a premium FiveM/GTA Online mod menu with advanced griefing and recovery features.",
                    Detail = $"Config directory: {configDir}"
                });
            }

            try
            {
                foreach (var script in Directory.GetFiles(configDir, "*.lua", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cherax Mod Menu — Script Found",
                        Risk = RiskLevel.Critical,
                        Location = script,
                        FileName = Path.GetFileName(script),
                        Reason = "Lua script found in Cherax mod menu directory. These scripts extend Cherax cheat functionality.",
                        Detail = $"Script: {script}"
                    });
                }

                foreach (var playerDb in Directory.GetFiles(configDir, "player*.json", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cherax Mod Menu — Player Database Found",
                        Risk = RiskLevel.Critical,
                        Location = playerDb,
                        FileName = Path.GetFileName(playerDb),
                        Reason = "Cherax player database file found. This file records targeted players and confirms active cheat usage against other users.",
                        Detail = $"Player DB: {playerDb}"
                    });
                }
            }
            catch { }
        }

        var searchDirs = new[] { Downloads, Desktop };
        var patterns = new[] { "Cherax*.zip", "Cherax*.dll", "cherax*.exe", "cherax*.rar" };
        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var pattern in patterns)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var file in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cherax Mod Menu — Download Artifact Found",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Cherax mod menu download artifact found. This indicates acquisition from cherax.gg.",
                            Detail = $"Found in: {dir}"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Cherax");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cherax Mod Menu — Registry Key Found",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\Cherax",
                    Reason = "Cherax mod menu registry key found in HKCU. Cherax writes license and configuration data here.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckKiddionsMenuArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            Path.Combine(AppData, "Kiddions"),
            Documents,
            Desktop
        };

        var knownFileNames = new[]
        {
            "config.json", "settings.json", "kiddions_menu.json",
            "modest_menu.exe", "modest_menu_x64.exe"
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var fileName in knownFileNames)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(dir, fileName);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Kiddion's Modest Menu — Artifact Found",
                    Risk = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason = "Kiddion's Modest Menu artifact found. Kiddion's is a free external FiveM/GTA Online mod menu. Its presence confirms cheat tool usage.",
                    Detail = $"Found in: {dir}"
                });
            }
        }

        var kiddionsDir = Path.Combine(AppData, "Kiddions");
        if (Directory.Exists(kiddionsDir))
        {
            try
            {
                foreach (var file in Directory.GetFiles(kiddionsDir, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Kiddion's Modest Menu — Config Directory File",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "File found in Kiddion's Modest Menu configuration directory. This confirms the cheat was configured and used on this machine.",
                        Detail = $"Config dir: {kiddionsDir}"
                    });
                }
            }
            catch { }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Kiddions");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Kiddion's Modest Menu — Registry Key Found",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\Kiddions",
                    Reason = "Kiddion's Modest Menu registry key found in HKCU.",
                    Detail = $"Subkey count: {key.SubKeyCount}, Value count: {key.ValueCount}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckLuaMenuScriptArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new List<string>();

        foreach (var fivemBase in FiveMAppPaths)
        {
            searchRoots.Add(Path.Combine(AppData, fivemBase, "plugins"));
            searchRoots.Add(Path.Combine(LocalAppData, fivemBase, "plugins"));
            searchRoots.Add(Path.Combine(AppData, fivemBase, "citizen", "scripting", "lua"));
            searchRoots.Add(Path.Combine(LocalAppData, fivemBase, "cache"));
        }

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> luaFiles;
            try
            {
                luaFiles = Directory.GetFiles(root, "*.lua", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var lua in luaFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(lua, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch
                {
                    continue;
                }

                foreach (var kw in CheatScriptKeywords)
                {
                    if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Cheat Lua Script — Keyword '{kw}'",
                        Risk = RiskLevel.Critical,
                        Location = lua,
                        FileName = Path.GetFileName(lua),
                        Reason = $"Lua script in FiveM plugin/cache directory contains cheat keyword '{kw}'. Scripts with these keywords implement ESP, aimbot, godmode, money cheats, teleportation, speedhacks, crash tools, kick tools, or recovery features.",
                        Detail = $"Script root: {root}"
                    });
                    break;
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMenuDLLInFiveMDirectory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var fivemRoots = new List<string>();

        foreach (var fivemBase in FiveMAppPaths)
        {
            fivemRoots.Add(Path.Combine(AppData, fivemBase));
            fivemRoots.Add(Path.Combine(LocalAppData, fivemBase));
            fivemRoots.Add(Path.Combine(AppData, fivemBase, "plugins"));
            fivemRoots.Add(Path.Combine(LocalAppData, fivemBase, "plugins"));
        }

        foreach (var root in fivemRoots)
        {
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.GetFiles(root, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                continue;
            }

            foreach (var dll in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(dll);

                foreach (var menuDll in MenuDLLNames)
                {
                    if (!fileName.Equals(menuDll, StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known Mod Menu DLL in FiveM Directory — {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = dll,
                        FileName = fileName,
                        Reason = $"Known mod menu DLL '{fileName}' found inside the FiveM application directory. This DLL is injected into FiveM to provide cheat functionality and is a direct artifact of mod menu usage.",
                        Detail = $"FiveM directory: {root}"
                    });
                    break;
                }

                bool isKnownMenuDll = MenuDLLNames.Any(m =>
                    fileName.Equals(m, StringComparison.OrdinalIgnoreCase));

                if (!isKnownMenuDll)
                {
                    foreach (var menuName in MenuConfigDirs)
                    {
                        if (fileName.Contains(menuName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious DLL Matching Menu Name in FiveM Directory — {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = dll,
                                FileName = fileName,
                                Reason = $"DLL file '{fileName}' in the FiveM directory contains the name of a known mod menu ('{menuName}'). This is consistent with an injected mod menu component.",
                                Detail = $"FiveM directory: {root}"
                            });
                            break;
                        }
                    }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMenuLogFilesArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logFileNames = new[]
        {
            "menu_log.txt", "cheat_log.txt", "session_log.txt",
            "actions.log", "crash_log.txt", "activity_log.txt",
            "grief_log.txt", "exploit_log.txt"
        };

        var searchRoots = new List<string>();
        searchRoots.Add(AppData);
        searchRoots.Add(LocalAppData);
        searchRoots.Add(Documents);
        searchRoots.Add(Desktop);
        searchRoots.Add(Downloads);

        foreach (var menuDir in MenuConfigDirs)
        {
            searchRoots.Add(Path.Combine(AppData, menuDir));
            searchRoots.Add(Path.Combine(LocalAppData, menuDir));
        }

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var logName in logFileNames)
            {
                if (ct.IsCancellationRequested) return;
                var logPath = Path.Combine(root, logName);
                if (!File.Exists(logPath)) continue;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch
                {
                    continue;
                }

                foreach (var kw in MenuLogKeywords)
                {
                    if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mod Menu Session Log — Active Cheat Action Evidence",
                        Risk = RiskLevel.Critical,
                        Location = logPath,
                        FileName = logName,
                        Reason = $"Log file '{logName}' contains cheat action keyword '{kw}'. This log file records active mod menu actions such as spawning objects, teleporting, killing players, crashing sessions, or dropping money — proving active cheat usage.",
                        Detail = $"Found in: {root}"
                    });
                    break;
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMenuHotkeyConfigArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var hotkeyFileNames = new[]
        {
            "hotkeys.json", "keybinds.json", "bindings.json", "config.ini",
            "keybindings.json", "hotkey_config.json", "keys.json"
        };

        var gameHotkeyPatterns = new[]
        {
            "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
            "NUMPAD", "Numpad", "numpad", "VK_F", "VK_NUMPAD",
            "menu_open", "menu_key", "open_menu", "toggle_menu"
        };

        var searchRoots = new List<string>();
        foreach (var menuDir in MenuConfigDirs)
        {
            searchRoots.Add(Path.Combine(AppData, menuDir));
            searchRoots.Add(Path.Combine(LocalAppData, menuDir));
        }
        searchRoots.Add(AppData);
        searchRoots.Add(LocalAppData);

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var hotkeyFile in hotkeyFileNames)
            {
                if (ct.IsCancellationRequested) return;
                var path = Path.Combine(root, hotkeyFile);
                if (!File.Exists(path)) continue;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch
                {
                    continue;
                }

                bool hasCheatKeyword = CheatScriptKeywords.Any(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                bool hasHotkeyPattern = gameHotkeyPatterns.Any(p =>
                    content.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (hasCheatKeyword && hasHotkeyPattern)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mod Menu Hotkey Config — Cheat Key Bindings Found",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = hotkeyFile,
                        Reason = $"Hotkey configuration file '{hotkeyFile}' contains both cheat-related action keywords and game hotkey patterns (function keys, numpad keys). This file persists mod menu hotkey bindings across sessions and confirms the cheat was actively configured.",
                        Detail = $"Found in: {root}"
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMenuRegistryDeep(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var regKeyPath in MenuRegistryKeys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regKeyPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                var menuName = regKeyPath.Split('\\').Last();
                var sb = new StringBuilder();
                sb.Append($"Subkeys: {key.SubKeyCount}; Values: {key.ValueCount}");

                foreach (var valueName in key.GetValueNames())
                {
                    var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (val.Length > 0)
                        sb.Append($"; {valueName}={val[..Math.Min(val.Length, 60)]}");
                }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Mod Menu Registry Key — {menuName}",
                    Risk = RiskLevel.Critical,
                    Location = $@"HKCU\{regKeyPath}",
                    Reason = $"Registry key for mod menu '{menuName}' found under HKCU. Mod menus write configuration, license, and session data to the registry. The presence of this key confirms the mod menu was installed and executed on this machine.",
                    Detail = sb.ToString()
                });
            }
            catch { }
        }

        try
        {
            using var runKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (runKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var valueName in runKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    var value = runKey.GetValue(valueName)?.ToString() ?? string.Empty;

                    bool matchesMenu = MenuConfigDirs.Any(m =>
                        valueName.Contains(m, StringComparison.OrdinalIgnoreCase) ||
                        value.Contains(m, StringComparison.OrdinalIgnoreCase));

                    if (!matchesMenu) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mod Menu Autostart Entry — {valueName}",
                        Risk = RiskLevel.Critical,
                        Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                        Reason = $"Autostart registry entry '{valueName}' references a known mod menu. This entry causes the mod menu to launch automatically at user logon.",
                        Detail = $"Value: {value}"
                    });
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckPrefetchAndMRUForMenuExes(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var prefetchDir = @"C:\Windows\Prefetch";
        var prefetchPatterns = new[]
        {
            "2TAKE1", "STAND", "YIMMENU", "EULEN", "REDENGINE",
            "CHERAX", "KIDDIONS", "INJECT", "LOADER", "MODMENU",
            "SKRIPT", "BRAINOBRAIN", "MIDNIGHT"
        };

        if (Directory.Exists(prefetchDir))
        {
            IEnumerable<string> pfFiles;
            try
            {
                pfFiles = Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                pfFiles = Array.Empty<string>();
            }

            foreach (var pf in pfFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var pfName = Path.GetFileNameWithoutExtension(pf).ToUpperInvariant();

                foreach (var pattern in prefetchPatterns)
                {
                    if (!pfName.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mod Menu Prefetch Artifact — {Path.GetFileName(pf)}",
                        Risk = RiskLevel.High,
                        Location = pf,
                        FileName = Path.GetFileName(pf),
                        Reason = $"Windows Prefetch file '{Path.GetFileName(pf)}' matches the pattern '{pattern}' associated with FiveM mod menu executables or injectors. Prefetch files persist after the executable is deleted and prove prior execution.",
                        Detail = $"Last modified: {SafeGetLastWriteTime(pf):yyyy-MM-dd HH:mm:ss}"
                    });
                    break;
                }
            }
        }

        try
        {
            using var recentDocsKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs");
            if (recentDocsKey != null)
            {
                ctx.IncrementRegistryKeys();
                var suspiciousExts = new[] { ".dll", ".asi", ".lua" };

                foreach (var ext in suspiciousExts)
                {
                    if (ct.IsCancellationRequested) return;
                    using var extKey = recentDocsKey.OpenSubKey(ext);
                    if (extKey == null) continue;

                    ctx.IncrementRegistryKeys();
                    var mruList = extKey.GetValue("MRUListEx");
                    if (mruList == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Recent Files MRU — {ext} Files Accessed",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\{ext}",
                        Reason = $"Windows MRU (Most Recently Used) list shows recent access to '{ext}' files. Mod menu DLLs (.dll), ASI plugins (.asi), and Lua cheat scripts (.lua) appear in these MRU entries when opened or executed from Windows Explorer or file dialogs.",
                        Detail = $"Extension: {ext}"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var openSaveKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU");
            if (openSaveKey != null)
            {
                ctx.IncrementRegistryKeys();
                var interestingExts = new[] { "dll", "asi", "lua", "exe" };

                foreach (var ext in interestingExts)
                {
                    if (ct.IsCancellationRequested) return;
                    using var extKey = openSaveKey.OpenSubKey(ext);
                    if (extKey == null) continue;
                    ctx.IncrementRegistryKeys();

                    bool foundMenuRef = false;
                    foreach (var valName in extKey.GetValueNames())
                    {
                        if (valName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase)) continue;
                        var val = extKey.GetValue(valName)?.ToString() ?? string.Empty;
                        bool isMenuRef = MenuConfigDirs.Any(m =>
                            val.Contains(m, StringComparison.OrdinalIgnoreCase));
                        if (!isMenuRef) continue;

                        foundMenuRef = true;
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Open/Save Dialog MRU — Mod Menu File Reference",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\{ext}",
                            Reason = $"Open/Save dialog MRU entry references a mod menu-related path. This indicates the user browsed to or opened a mod menu file via a Windows file dialog.",
                            Detail = $"Value name: {valName}"
                        });
                        break;
                    }
                    if (!foundMenuRef) { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMenuDownloadAndInstallArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[] { Downloads, Desktop, Temp };

        var namePatterns = new[]
        {
            "*2take1*", "*stand-menu*", "*standmenu*", "*yimmenu*",
            "*eulen*", "*redengine*", "*skript*", "*cherax*",
            "*brainobrain*", "*midnight*", "*kiddions*", "*modest_menu*"
        };

        var archiveExtensions = new[] { ".zip", ".rar", ".7z", ".tar", ".gz", ".cab" };
        var executableExtensions = new[] { ".exe", ".dll", ".msi", ".bat", ".ps1" };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            foreach (var pattern in namePatterns)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var file in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        var ext = Path.GetExtension(file);
                        bool isArchive = archiveExtensions.Any(a =>
                            ext.Equals(a, StringComparison.OrdinalIgnoreCase));
                        bool isExecutable = executableExtensions.Any(e =>
                            ext.Equals(e, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Mod Menu {(isArchive ? "Archive" : isExecutable ? "Executable" : "File")} — {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"File matching mod menu name pattern found in '{dir}'. {(isArchive ? "Archive files often contain mod menu installers and their DLL components." : isExecutable ? "Executable/DLL files are the core mod menu injector or loader components." : "This file matches a known mod menu naming convention.")} The file name pattern matches: {pattern}",
                            Detail = $"Found in: {dir}, Last modified: {SafeGetLastWriteTime(file):yyyy-MM-dd HH:mm:ss}"
                        });
                    }
                }
                catch { }
            }

            foreach (var menuName in MenuConfigDirs)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    var extractedDir = Path.Combine(dir, menuName);
                    if (!Directory.Exists(extractedDir)) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mod Menu Extracted Folder — {menuName}",
                        Risk = RiskLevel.Critical,
                        Location = extractedDir,
                        FileName = menuName,
                        Reason = $"Folder named after known mod menu '{menuName}' found in '{dir}'. This is consistent with a mod menu archive being extracted in a temporary or download location.",
                        Detail = $"Extracted folder: {extractedDir}"
                    });
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMenuPlayerDatabaseArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var playerDbFileNames = new[]
        {
            "players.json", "player_db.json", "target_list.json",
            "griefer_list.json", "blacklist.json", "whitelist.json",
            "player_list.json", "targets.json", "player_history.json",
            "player_data.json", "saved_players.json"
        };

        var playerIdentifierPatterns = new[]
        {
            "steamid", "steam_id", "license:", "fivem:", "discord:",
            "rockstar:", "xbl:", "live:", "ip:", "player_id",
            "76561", "license:steam"
        };

        var exportedListPatterns = new[]
        {
            "player_export.txt", "players_export.txt", "target_export.txt",
            "griefers.txt", "victim_list.txt", "player_ids.txt"
        };

        var searchRoots = new List<string>();
        foreach (var menuDir in MenuConfigDirs)
        {
            searchRoots.Add(Path.Combine(AppData, menuDir));
            searchRoots.Add(Path.Combine(LocalAppData, menuDir));
        }
        searchRoots.Add(Documents);
        searchRoots.Add(Desktop);
        searchRoots.Add(Downloads);

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var dbFileName in playerDbFileNames)
            {
                if (ct.IsCancellationRequested) return;
                var dbPath = Path.Combine(root, dbFileName);
                if (!File.Exists(dbPath)) continue;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(dbPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch
                {
                    continue;
                }

                bool hasPlayerIds = playerIdentifierPatterns.Any(p =>
                    content.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (hasPlayerIds)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mod Menu Player Database — Targeted Player Records Found",
                        Risk = RiskLevel.Critical,
                        Location = dbPath,
                        FileName = dbFileName,
                        Reason = $"Player database file '{dbFileName}' found containing player identifiers (Steam IDs, FiveM license hashes, or other player IDs). Mod menus maintain these databases of targeted, griefed, or tracked players. The presence of player identifiers in this file proves active cheat usage against specific individuals.",
                        Detail = $"Found in: {root}; Contains player identifiers matching known patterns"
                    });
                }
                else
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mod Menu Player Database — File Found",
                        Risk = RiskLevel.Critical,
                        Location = dbPath,
                        FileName = dbFileName,
                        Reason = $"Player database file '{dbFileName}' found in mod menu configuration directory. Mod menus use these files to store lists of targeted, griefed, or whitelisted/blacklisted players.",
                        Detail = $"Found in: {root}"
                    });
                }
            }

            foreach (var exportFile in exportedListPatterns)
            {
                if (ct.IsCancellationRequested) return;
                var exportPath = Path.Combine(root, exportFile);
                if (!File.Exists(exportPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Mod Menu Exported Player List — {exportFile}",
                    Risk = RiskLevel.Critical,
                    Location = exportPath,
                    FileName = exportFile,
                    Reason = $"Exported player list file '{exportFile}' found. Mod menus export lists of targeted or griefed players to text files. The presence of this file confirms active use of cheat tools against other players.",
                    Detail = $"Found in: {root}; Last modified: {SafeGetLastWriteTime(exportPath):yyyy-MM-dd HH:mm:ss}"
                });
            }

            try
            {
                foreach (var jsonFile in Directory.GetFiles(root, "*player*.json", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    if (playerDbFileNames.Any(n =>
                        Path.GetFileName(jsonFile).Equals(n, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(jsonFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch
                    {
                        continue;
                    }

                    bool hasIds = playerIdentifierPatterns.Any(p =>
                        content.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (!hasIds) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mod Menu Player Data File — {Path.GetFileName(jsonFile)}",
                        Risk = RiskLevel.Critical,
                        Location = jsonFile,
                        FileName = Path.GetFileName(jsonFile),
                        Reason = $"JSON file '{Path.GetFileName(jsonFile)}' in mod menu directory contains player identifiers. This file tracks players encountered or targeted during cheat sessions.",
                        Detail = $"Found in: {root}"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private static DateTime SafeGetLastWriteTime(string path)
    {
        try { return File.GetLastWriteTime(path); }
        catch { return default; }
    }
}
