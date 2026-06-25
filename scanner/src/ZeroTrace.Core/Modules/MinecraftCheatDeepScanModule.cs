using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class MinecraftCheatDeepScanModule : IScanModule
{
    public string Name => "Minecraft Cheat Deep Detection";
    public double Weight => 3.8;
    public int ParallelGroup => 4;

    private static readonly string RoamingAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string[] MinecraftBasePaths =
    {
        Path.Combine(RoamingAppData, ".minecraft"),
        Path.Combine(RoamingAppData, "minecraft"),
        Path.Combine(UserProfile, ".minecraft"),
        Path.Combine(LocalAppData, ".minecraft"),
    };

    private static readonly string[] AlternateLauncherPaths =
    {
        Path.Combine(RoamingAppData, "MultiMC"),
        Path.Combine(RoamingAppData, "multimc"),
        Path.Combine(UserProfile, "MultiMC"),
        Path.Combine(UserProfile, "MultiMC5"),
        Path.Combine(UserProfile, "multimc"),
        Path.Combine(UserProfile, "PrismLauncher"),
        Path.Combine(RoamingAppData, "PrismLauncher"),
        Path.Combine(LocalAppData, "PrismLauncher"),
        Path.Combine(UserProfile, "ATLauncher"),
        Path.Combine(RoamingAppData, "ATLauncher"),
        Path.Combine(LocalAppData, "ATLauncher"),
        Path.Combine(UserProfile, "GDLauncher"),
        Path.Combine(RoamingAppData, "GDLauncher"),
        Path.Combine(UserProfile, "CurseForge"),
        Path.Combine(UserProfile, "FTBApp"),
        Path.Combine(RoamingAppData, "ftblauncher"),
        Path.Combine(LocalAppData, "Programs", "Prism Launcher"),
    };

    private static readonly string[] KnownCheatClientJarPatterns =
    {
        "Wurst",
        "LiquidBounce",
        "Aristois",
        "Meteor",
        "Impact",
        "Future",
        "Novoline",
        "Entropy",
        "Ares",
        "BleachHack",
        "Baritone",
        "EarthHack",
        "Sigma",
        "Drip",
        "Rusherhack",
        "Thunderhack",
        "Blackout",
        "Rise",
        "Voltage",
        "Inertia",
        "Salhack",
        "Motion",
        "SodiumFix",
        "Nodus",
        "Huzuni",
        "Wolfram",
        "Hacked",
        "Zeroday",
        "Ghost",
        "Astolfo",
        "Stardust",
        "Crystal",
        "CrystalAC",
        "Flux",
        "Vertex",
        "Hybrid",
        "Reflex",
        "Autumn",
        "Elysium",
        "Pyro",
        "Quartz",
        "Pyware",
        "Cheatbreaker",
        "Gorilla",
        "Weepcraft",
        "Skilorclient",
        "ForgeHax",
        "ForgeWurst",
        "KillAura",
        "Skippy",
        "Salhack",
        "Vape",
        "VapeV4",
        "LiquidBounceLegacy",
        "LiquidBounce+",
        "ImpactClient",
        "Meteor-Client",
        "MeteorRejects",
        "SigmaHacked",
        "Drip+",
        "DripPlus",
        "Rusherhack",
        "Thunderclient",
        "Blackout-Client",
        "RiseClient",
        "VoltageHacked",
        "WurstClient",
        "AristoisClient",
        "GhostClient",
        "AstolfoClient",
        "StardustClient",
        "FluxClient",
        "VertexClient",
        "HybridClient",
        "NodusMod",
        "HuzuniHack",
        "WolframHacked",
        "ZerodayClient",
        "MotionHack",
        "InertiaClient",
        "EarthHackClient",
        "BaritoneBot",
        "BleachHackClient",
        "NovoxClient",
        "xray",
        "killaura",
        "aimassist",
        "autoclicker",
        "blink",
        "scaffold",
        "speedhack",
        "bhop",
        "criticals",
        "antiknockback",
    };

    private static readonly string[] CheatConfigFolderNames =
    {
        "Wurst",
        "wurst",
        "LiquidBounce",
        "liquidbounce",
        "Meteor",
        "meteor-client",
        "MeteorClient",
        "Future",
        "future",
        "Aristois",
        "aristois",
        "Impact",
        "impact",
        "Sigma",
        "sigma",
        "Drip",
        "drip",
        "Drip+",
        "Rusherhack",
        "rusherhack",
        "BleachHack",
        "bleachhack",
        "Entropy",
        "entropy",
        "Rise",
        "rise",
        "Voltage",
        "voltage",
        "Ghost",
        "ghost",
        "Astolfo",
        "astolfo",
        "Flux",
        "flux",
        "Vertex",
        "vertex",
        "Hybrid",
        "hybrid",
        "Wolfram",
        "wolfram",
        "Vape",
        "vape",
        "Stardust",
        "stardust",
        "baritone",
        "Baritone",
        "EarthHack",
        "earthhack",
    };

    private static readonly string[] CheatConfigFileNames =
    {
        "wurst.json",
        "wurst-options.json",
        "meteor-client.json",
        "meteor-config.json",
        "future.json",
        "future-config.json",
        "aristois.json",
        "impact-config.json",
        "impact.json",
        "liquidbounce.json",
        "lb-config.json",
        "sigma.json",
        "sigma-config.json",
        "drip.json",
        "drip-config.json",
        "rusherhack.json",
        "bleachhack.json",
        "entropy.json",
        "rise.json",
        "voltage.json",
        "ghost.json",
        "astolfo.json",
        "flux.json",
        "vertex.json",
        "hybrid.json",
        "wolfram.json",
        "vape.json",
        "stardust.json",
        "baritone.json",
        "killaura.json",
        "aimassist.json",
        "scaffold.json",
        "bhop.json",
        "xray.json",
        "nofall.json",
        "speed.json",
        "automine.json",
        "autoclicker.json",
        "antiknockback.json",
        "criticals.json",
        "fly.json",
        "noclip.json",
        "cheat-config.json",
        "hacked-config.json",
        "modules.json",
        "cheats.json",
        "hacks.json",
        "settings.json",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "killaura",
        "kill_aura",
        "KillAura",
        "aimassist",
        "aim_assist",
        "AimAssist",
        "autoplace",
        "auto_place",
        "AutoPlace",
        "scaffold",
        "Scaffold",
        "bhop",
        "bunny_hop",
        "BHop",
        "speed",
        "Speed",
        "speedhack",
        "nofall",
        "no_fall",
        "NoFall",
        "xray",
        "Xray",
        "X-Ray",
        "automine",
        "auto_mine",
        "AutoMine",
        "criticals",
        "Criticals",
        "antiknockback",
        "anti_knockback",
        "AntiKnockback",
        "aimbot",
        "Aimbot",
        "triggerbot",
        "TriggerBot",
        "autoclicker",
        "AutoClicker",
        "auto_clicker",
        "fly",
        "Fly",
        "noclip",
        "NoClip",
        "no_clip",
        "blink",
        "Blink",
        "reach",
        "Reach",
        "velocity",
        "Velocity",
        "esp_enabled",
        "player_esp",
        "chest_esp",
        "entity_esp",
        "tracers",
        "Tracers",
        "fullbright",
        "FullBright",
        "full_bright",
        "freecam",
        "FreeCam",
        "jesus",
        "Jesus",
        "timer",
        "Timer",
        "longjump",
        "LongJump",
        "step",
        "Step",
        "strafe",
        "Strafe",
        "autofish",
        "AutoFish",
        "autofarm",
        "AutoFarm",
    };

    private static readonly string[] LogCheatSignatures =
    {
        "Wurst initialized",
        "Wurst loaded",
        "LiquidBounce loaded",
        "LiquidBounce initialized",
        "Meteor Client loaded",
        "Meteor initialized",
        "Future Client loaded",
        "Future initialized",
        "Aristois loaded",
        "Aristois initialized",
        "Impact Client loaded",
        "Impact initialized",
        "Sigma loaded",
        "Sigma initialized",
        "Drip loaded",
        "Rusherhack loaded",
        "BleachHack loaded",
        "KillAura enabled",
        "KillAura activated",
        "Scaffold enabled",
        "Scaffold activated",
        "Xray enabled",
        "Xray activated",
        "ESP enabled",
        "AimAssist enabled",
        "BHop enabled",
        "NoFall enabled",
        "Speed enabled",
        "Fly enabled",
        "Aimbot enabled",
        "AutoClicker enabled",
        "Wolfram Client",
        "Huzuni Client",
        "Nodus Client",
        "Baritone initialized",
        "Baritone loaded",
        "Ghost Client loaded",
        "Astolfo loaded",
        "Flux Client loaded",
        "Vertex Client loaded",
        "Hybrid Client loaded",
        "Stardust loaded",
        "Vape loaded",
        "hacked client",
        "cheat client",
        "[Cheat]",
        "[Hack]",
        "[KillAura]",
        "[Scaffold]",
        "[Fly]",
        "[Speed]",
        "[ESP]",
    };

    private static readonly string[] XrayResourcePackNames =
    {
        "xray",
        "x-ray",
        "x_ray",
        "XRay",
        "X-Ray",
        "X_Ray",
        "Xray Ultimate",
        "XrayUltimate",
        "xray-ultimate",
        "xray_ultimate",
        "xray_vision",
        "XrayVision",
        "ores_xray",
        "OresXray",
        "xray_pack",
        "XrayPack",
        "cave_finder",
        "CaveFinder",
        "ore_finder",
        "OreFinder",
    };

    private static readonly string[] EspShaderPackNames =
    {
        "esp_shader",
        "ESPShader",
        "esp-shaders",
        "entity_esp",
        "EntityESP",
        "player_esp",
        "PlayerESP",
        "wallhack_shader",
        "WallhackShader",
        "outline_esp",
        "OutlineESP",
        "cheat_shaders",
        "CheatShaders",
        "hack_shaders",
        "HackShaders",
    };

    private static readonly string[] CrackedLauncherArtifacts =
    {
        "TLauncher.exe",
        "TLauncher-2.exe",
        "TLauncher.jar",
        "tlauncher.jar",
        "SKLauncher.jar",
        "sklauncher.jar",
        "SKLauncher.exe",
        "sklauncher.exe",
        "authlib-injector.jar",
        "authlib_injector.jar",
        "AuthlibInjector.jar",
        "PCL.exe",
        "PCL2.exe",
        "HMCL.jar",
        "hmcl.jar",
        "BakaXL.exe",
        "bakaxl.exe",
        "LabyMod.exe",
        "labymod.exe",
    };

    private static readonly string[] CrackedLauncherDirNames =
    {
        "TLauncher",
        "tlauncher",
        "SKLauncher",
        "sklauncher",
        "authlib-injector",
        "authlib_injector",
        "HMCL",
        "BakaXL",
        "LabyMod",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.02, Name, "Locating Minecraft installation directories...");
        var mcPaths = CollectMinecraftPaths();

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.06, Name, "Scanning .minecraft mods folder for cheat JAR files...");
        await ScanModsFolderAsync(ctx, ct, mcPaths).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.18, Name, "Scanning .minecraft config folder for cheat configurations...");
        await ScanConfigFolderAsync(ctx, ct, mcPaths).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.30, Name, "Scanning .minecraft versions folder for hacked client JARs...");
        await ScanVersionsFolderAsync(ctx, ct, mcPaths).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.42, Name, "Scanning Minecraft logs for cheat client signatures...");
        await ScanMinecraftLogsAsync(ctx, ct, mcPaths).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.52, Name, "Scanning crash reports for cheat mod references...");
        await ScanCrashReportsAsync(ctx, ct, mcPaths).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.60, Name, "Scanning resource packs for Xray packs...");
        await ScanResourcePacksAsync(ctx, ct, mcPaths).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.68, Name, "Scanning shader packs for ESP shaders...");
        await ScanShaderPacksAsync(ctx, ct, mcPaths).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.75, Name, "Scanning for Baritone bot artifacts...");
        await ScanForBaritoneArtifactsAsync(ctx, ct, mcPaths).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.82, Name, "Scanning for cracked launcher artifacts...");
        await ScanForCrackedLauncherArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.90, Name, "Scanning alternate launcher instances for cheat clients...");
        await ScanAlternateLaunchersAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.96, Name, "Scanning registry for Minecraft cheat entries...");
        ScanRegistry(ctx, ct);

        ctx.Report(1.0, Name, "Minecraft cheat deep scan complete.");
    }

    private List<string> CollectMinecraftPaths()
    {
        var paths = new List<string>();

        foreach (var basePath in MinecraftBasePaths)
        {
            if (Directory.Exists(basePath))
                paths.Add(basePath);
        }

        var driveRoots = new[] { @"C:\", @"D:\", @"E:\", @"F:\" };
        foreach (var drive in driveRoots)
        {
            if (!Directory.Exists(drive)) continue;

            var candidate = Path.Combine(drive, "Users");
            if (!Directory.Exists(candidate)) continue;

            string[] userDirs;
            try
            {
                userDirs = Directory.GetDirectories(candidate, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var userDir in userDirs)
            {
                var mcPath = Path.Combine(userDir, "AppData", "Roaming", ".minecraft");
                if (Directory.Exists(mcPath) && !paths.Contains(mcPath))
                    paths.Add(mcPath);
            }
        }

        return paths;
    }

    private async Task ScanModsFolderAsync(ScanContext ctx, CancellationToken ct, List<string> mcPaths)
    {
        foreach (var mcPath in mcPaths)
        {
            ct.ThrowIfCancellationRequested();
            var modsDir = Path.Combine(mcPath, "mods");
            if (!Directory.Exists(modsDir)) continue;

            string[] jarFiles;
            try
            {
                jarFiles = Directory.GetFiles(modsDir, "*.jar", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var jarFile in jarFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(jarFile);

                foreach (var cheatPattern in KnownCheatClientJarPatterns)
                {
                    if (!fileName.Contains(cheatPattern, StringComparison.OrdinalIgnoreCase)) continue;

                    long fileSize = 0;
                    try { fileSize = new FileInfo(jarFile).Length; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known Minecraft cheat client JAR in mods folder: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = jarFile,
                        FileName = fileName,
                        Reason = $"The JAR file '{fileName}' in the Minecraft mods folder '{modsDir}' " +
                                 $"matches the name of the known cheat client '{cheatPattern}'. Cheat " +
                                 "clients distributed as mods load automatically when Minecraft starts " +
                                 "with a compatible mod loader (Forge, Fabric, Quilt).",
                        Detail = $"Matched pattern: {cheatPattern} | File size: {fileSize} bytes | " +
                                 $"Mods dir: {modsDir}"
                    });
                    break;
                }
            }

            string[] submodDirs;
            try
            {
                submodDirs = Directory.GetDirectories(modsDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                submodDirs = Array.Empty<string>();
            }

            foreach (var subDir in submodDirs)
            {
                ct.ThrowIfCancellationRequested();

                var subDirName = Path.GetFileName(subDir);
                foreach (var cheatPattern in KnownCheatClientJarPatterns)
                {
                    if (!subDirName.Contains(cheatPattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat client subdirectory in mods folder: {subDirName}",
                        Risk = RiskLevel.High,
                        Location = subDir,
                        Reason = $"A subdirectory named '{subDirName}' inside the Minecraft mods directory " +
                                 $"matches the name of the known cheat client '{cheatPattern}'. Some cheat " +
                                 "distributions extract their files into subdirectories within the mods folder.",
                        Detail = $"Mods dir: {modsDir}"
                    });
                    break;
                }

                string[] subJars;
                try
                {
                    subJars = Directory.GetFiles(subDir, "*.jar", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var jarFile in subJars)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(jarFile);

                    foreach (var cheatPattern in KnownCheatClientJarPatterns)
                    {
                        if (!fileName.Contains(cheatPattern, StringComparison.OrdinalIgnoreCase)) continue;

                        long fileSize = 0;
                        try { fileSize = new FileInfo(jarFile).Length; } catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat client JAR in mods subdirectory: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = jarFile,
                            FileName = fileName,
                            Reason = $"The JAR file '{fileName}' in a mods subdirectory matches the known " +
                                     $"cheat client '{cheatPattern}'.",
                            Detail = $"File size: {fileSize} bytes | Path: {subDir}"
                        });
                        break;
                    }
                }
            }

            await Task.Yield();
        }
    }

    private async Task ScanConfigFolderAsync(ScanContext ctx, CancellationToken ct, List<string> mcPaths)
    {
        foreach (var mcPath in mcPaths)
        {
            ct.ThrowIfCancellationRequested();
            var configDir = Path.Combine(mcPath, "config");
            if (!Directory.Exists(configDir)) continue;

            string[] configDirs;
            try
            {
                configDirs = Directory.GetDirectories(configDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var subDir in configDirs)
            {
                ct.ThrowIfCancellationRequested();

                var dirName = Path.GetFileName(subDir);
                foreach (var cheatFolder in CheatConfigFolderNames)
                {
                    if (!dirName.Equals(cheatFolder, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known cheat client config directory found: {dirName}",
                        Risk = RiskLevel.Critical,
                        Location = subDir,
                        Reason = $"A configuration directory named '{dirName}' was found in the Minecraft " +
                                 $"config folder '{configDir}'. This directory is created by the " +
                                 $"'{cheatFolder}' hacked client to store its module settings, keybinds, " +
                                 "and feature configurations.",
                        Detail = $"Config dir: {configDir} | Matched cheat: {cheatFolder}"
                    });
                    break;
                }

                string[] configFiles;
                try
                {
                    configFiles = Directory.GetFiles(subDir, "*.*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var configFile in configFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    if (configFile.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                        configFile.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) ||
                        configFile.EndsWith(".toml", StringComparison.OrdinalIgnoreCase) ||
                        configFile.EndsWith(".ini", StringComparison.OrdinalIgnoreCase))
                    {
                        await InspectConfigFileForCheatKeywordsAsync(ctx, ct, configFile).ConfigureAwait(false);
                    }
                }
            }

            foreach (var knownConfigFile in CheatConfigFileNames)
            {
                var fullPath = Path.Combine(configDir, knownConfigFile);
                if (!File.Exists(fullPath)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known cheat client config file found: {knownConfigFile}",
                    Risk = RiskLevel.Critical,
                    Location = fullPath,
                    FileName = knownConfigFile,
                    Reason = $"The file '{knownConfigFile}' found in the Minecraft config directory " +
                             $"'{configDir}' is a known cheat client configuration file. This file is " +
                             "created by hacked Minecraft clients to persist module settings between sessions.",
                    Detail = $"Config dir: {configDir}"
                });
            }

            await Task.Yield();
        }
    }

    private async Task ScanVersionsFolderAsync(ScanContext ctx, CancellationToken ct, List<string> mcPaths)
    {
        foreach (var mcPath in mcPaths)
        {
            ct.ThrowIfCancellationRequested();
            var versionsDir = Path.Combine(mcPath, "versions");
            if (!Directory.Exists(versionsDir)) continue;

            string[] versionDirs;
            try
            {
                versionDirs = Directory.GetDirectories(versionsDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var versionDir in versionDirs)
            {
                ct.ThrowIfCancellationRequested();

                var versionName = Path.GetFileName(versionDir);
                bool isCheatVersion = false;

                foreach (var cheatPattern in KnownCheatClientJarPatterns)
                {
                    if (!versionName.Contains(cheatPattern, StringComparison.OrdinalIgnoreCase)) continue;
                    isCheatVersion = true;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Hacked Minecraft client version installed: {versionName}",
                        Risk = RiskLevel.Critical,
                        Location = versionDir,
                        Reason = $"A Minecraft version directory named '{versionName}' matches the name of " +
                                 $"the known hacked client '{cheatPattern}'. Hacked clients are often " +
                                 "installed as custom version profiles in the Minecraft launcher, replacing " +
                                 "or wrapping the vanilla game client.",
                        Detail = $"Versions dir: {versionsDir} | Matched cheat: {cheatPattern}"
                    });
                    break;
                }

                string[] versionFiles;
                try
                {
                    versionFiles = Directory.GetFiles(versionDir, "*.jar", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var versionJar in versionFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(versionJar);
                    if (isCheatVersion) continue;

                    foreach (var cheatPattern in KnownCheatClientJarPatterns)
                    {
                        if (!fileName.Contains(cheatPattern, StringComparison.OrdinalIgnoreCase)) continue;

                        long fileSize = 0;
                        try { fileSize = new FileInfo(versionJar).Length; } catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Hacked client JAR in Minecraft versions folder: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = versionJar,
                            FileName = fileName,
                            Reason = $"The JAR file '{fileName}' in the Minecraft versions directory " +
                                     $"matches the known hacked client '{cheatPattern}'. This JAR is " +
                                     "the actual hacked client executable that replaces or wraps the vanilla Minecraft client.",
                            Detail = $"File size: {fileSize} bytes | Version dir: {versionDir}"
                        });
                        break;
                    }
                }
            }

            await Task.Yield();
        }
    }

    private async Task ScanMinecraftLogsAsync(ScanContext ctx, CancellationToken ct, List<string> mcPaths)
    {
        foreach (var mcPath in mcPaths)
        {
            ct.ThrowIfCancellationRequested();
            var logsDir = Path.Combine(mcPath, "logs");
            if (!Directory.Exists(logsDir)) continue;

            string[] logFiles;
            try
            {
                logFiles = Directory.GetFiles(logsDir, "*.log", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var logFile in logFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectLogFileForCheatSignaturesAsync(ctx, ct, logFile).ConfigureAwait(false);
            }

            var latestLog = Path.Combine(logsDir, "latest.log");
            if (File.Exists(latestLog) && !logFiles.Any(f =>
                f.Equals(latestLog, StringComparison.OrdinalIgnoreCase)))
            {
                ctx.IncrementFiles();
                await InspectLogFileForCheatSignaturesAsync(ctx, ct, latestLog).ConfigureAwait(false);
            }

            string[] gzLogs;
            try
            {
                gzLogs = Directory.GetFiles(logsDir, "*.log.gz", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                gzLogs = Array.Empty<string>();
            }

            foreach (var gzLog in gzLogs)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(gzLog);
                foreach (var sig in LogCheatSignatures)
                {
                    if (fileName.Contains(sig, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Minecraft archived log with cheat signature in name: {fileName}",
                            Risk = RiskLevel.Medium,
                            Location = gzLog,
                            FileName = fileName,
                            Reason = $"The compressed log file '{fileName}' has a cheat-related signature in " +
                                     "its filename. Minecraft log rotation compresses older logs; having a " +
                                     "cheat signature in the filename may indicate the log was created " +
                                     "during a cheat session.",
                            Detail = $"Logs dir: {logsDir}"
                        });
                        break;
                    }
                }
            }

            await Task.Yield();
        }
    }

    private async Task InspectLogFileForCheatSignaturesAsync(ScanContext ctx, CancellationToken ct, string logFile)
    {
        string content;
        try
        {
            using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content)) return;

        var matchedSignatures = new List<string>();

        foreach (var sig in LogCheatSignatures)
        {
            if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                matchedSignatures.Add(sig);
        }

        if (matchedSignatures.Count >= 1)
        {
            var fileName = Path.GetFileName(logFile);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Minecraft log file contains hacked client signatures: {fileName}",
                Risk = matchedSignatures.Count >= 3 ? RiskLevel.Critical : RiskLevel.High,
                Location = logFile,
                FileName = fileName,
                Reason = $"The Minecraft log file '{fileName}' contains {matchedSignatures.Count} text " +
                         "signatures associated with hacked client initialization messages. These messages " +
                         "are printed by cheat clients (Wurst, LiquidBounce, Meteor, etc.) when they load " +
                         "and activate their cheat modules.",
                Detail = $"Matched signatures ({matchedSignatures.Count}): {string.Join(", ", matchedSignatures.Take(5))}"
            });
        }

        var cheatClientNames = new[]
        {
            "Wurst", "LiquidBounce", "Meteor", "Future", "Aristois",
            "Impact", "Sigma", "Drip", "Rusherhack", "BleachHack",
            "Wolfram", "Huzuni", "Nodus", "Ghost", "Astolfo",
            "Flux", "Vertex", "Hybrid", "Stardust", "Vape",
        };

        foreach (var clientName in cheatClientNames)
        {
            if (!content.Contains(clientName, StringComparison.OrdinalIgnoreCase)) continue;
            if (matchedSignatures.Any(s => s.Contains(clientName, StringComparison.OrdinalIgnoreCase))) continue;

            var fileName = Path.GetFileName(logFile);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Minecraft log mentions hacked client by name: {clientName}",
                Risk = RiskLevel.High,
                Location = logFile,
                FileName = fileName,
                Reason = $"The Minecraft log file '{fileName}' contains a reference to '{clientName}', " +
                         "which is the name of a known hacked Minecraft client. Hacked clients print their " +
                         "name in game logs during initialization.",
                Detail = $"Client name found in log: {clientName}"
            });
            break;
        }
    }

    private async Task ScanCrashReportsAsync(ScanContext ctx, CancellationToken ct, List<string> mcPaths)
    {
        foreach (var mcPath in mcPaths)
        {
            ct.ThrowIfCancellationRequested();
            var crashDir = Path.Combine(mcPath, "crash-reports");
            if (!Directory.Exists(crashDir)) continue;

            string[] crashFiles;
            try
            {
                crashFiles = Directory.GetFiles(crashDir, "*.txt", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var crashFile in crashFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectCrashReportAsync(ctx, ct, crashFile).ConfigureAwait(false);
            }

            await Task.Yield();
        }
    }

    private async Task InspectCrashReportAsync(ScanContext ctx, CancellationToken ct, string crashFile)
    {
        string content;
        try
        {
            using var fs = new FileStream(crashFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content)) return;

        var matchedClients = new List<string>();

        foreach (var cheatPattern in KnownCheatClientJarPatterns)
        {
            if (content.Contains(cheatPattern, StringComparison.OrdinalIgnoreCase))
                matchedClients.Add(cheatPattern);
        }

        if (matchedClients.Count >= 1)
        {
            var fileName = Path.GetFileName(crashFile);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Minecraft crash report references hacked client mods: {fileName}",
                Risk = RiskLevel.High,
                Location = crashFile,
                FileName = fileName,
                Reason = $"The Minecraft crash report '{fileName}' references {matchedClients.Count} known " +
                         "hacked client names. Crash reports include the full list of loaded mods and " +
                         "their class paths, making them reliable evidence of hacked client usage even " +
                         "after the cheat files have been removed.",
                Detail = $"Referenced cheat clients ({matchedClients.Count}): {string.Join(", ", matchedClients.Take(6))}"
            });
        }
    }

    private async Task ScanResourcePacksAsync(ScanContext ctx, CancellationToken ct, List<string> mcPaths)
    {
        foreach (var mcPath in mcPaths)
        {
            ct.ThrowIfCancellationRequested();
            var resourcePacksDir = Path.Combine(mcPath, "resourcepacks");
            if (!Directory.Exists(resourcePacksDir)) continue;

            string[] packEntries;
            try
            {
                packEntries = Directory.GetFileSystemEntries(resourcePacksDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var entry in packEntries)
            {
                ct.ThrowIfCancellationRequested();

                var entryName = Path.GetFileName(entry);
                bool isFile = File.Exists(entry);
                bool isDir = Directory.Exists(entry);

                if (isFile) ctx.IncrementFiles();

                foreach (var xrayPack in XrayResourcePackNames)
                {
                    if (!entryName.Contains(xrayPack, StringComparison.OrdinalIgnoreCase)) continue;

                    long size = 0;
                    if (isFile) { try { size = new FileInfo(entry).Length; } catch { } }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Xray resource pack detected: {entryName}",
                        Risk = RiskLevel.High,
                        Location = entry,
                        FileName = isFile ? entryName : null,
                        Reason = $"The resource pack '{entryName}' in the Minecraft resource packs directory " +
                                 $"'{resourcePacksDir}' matches the naming pattern of an Xray resource pack " +
                                 $"(matched: '{xrayPack}'). Xray resource packs replace ore and terrain " +
                                 "textures with transparent ones, allowing the player to see through walls " +
                                 "and directly locate valuable ores and structures.",
                        Detail = $"Resource packs dir: {resourcePacksDir}" +
                                 (isFile ? $" | Size: {size} bytes" : " | Type: directory")
                    });
                    break;
                }
            }

            await Task.Yield();
        }
    }

    private async Task ScanShaderPacksAsync(ScanContext ctx, CancellationToken ct, List<string> mcPaths)
    {
        foreach (var mcPath in mcPaths)
        {
            ct.ThrowIfCancellationRequested();
            var shaderDirs = new[]
            {
                Path.Combine(mcPath, "shaderpacks"),
                Path.Combine(mcPath, "shaders"),
            };

            foreach (var shaderDir in shaderDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(shaderDir)) continue;

                string[] shaderEntries;
                try
                {
                    shaderEntries = Directory.GetFileSystemEntries(shaderDir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var entry in shaderEntries)
                {
                    ct.ThrowIfCancellationRequested();

                    var entryName = Path.GetFileName(entry);
                    bool isFile = File.Exists(entry);

                    if (isFile) ctx.IncrementFiles();

                    foreach (var espShader in EspShaderPackNames)
                    {
                        if (!entryName.Contains(espShader, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ESP shader pack detected: {entryName}",
                            Risk = RiskLevel.Critical,
                            Location = entry,
                            FileName = isFile ? entryName : null,
                            Reason = $"The shader pack '{entryName}' in '{shaderDir}' matches the naming " +
                                     $"pattern of an ESP shader (matched: '{espShader}'). ESP shader packs " +
                                     "render players and entities through walls using OpenGL/GLSL rendering " +
                                     "tricks, providing a wallhack that is difficult to distinguish from " +
                                     "legitimate shader usage.",
                            Detail = $"Shader dir: {shaderDir}"
                        });
                        break;
                    }
                }

                await Task.Yield();
            }
        }
    }

    private async Task ScanForBaritoneArtifactsAsync(ScanContext ctx, CancellationToken ct, List<string> mcPaths)
    {
        foreach (var mcPath in mcPaths)
        {
            ct.ThrowIfCancellationRequested();

            var baritoneSettingsPath = Path.Combine(mcPath, "baritone", "settings.txt");
            var baritoneDir = Path.Combine(mcPath, "baritone");

            if (Directory.Exists(baritoneDir))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Baritone auto-mining bot directory found in Minecraft",
                    Risk = RiskLevel.High,
                    Location = baritoneDir,
                    Reason = "A 'baritone' configuration directory was found in the Minecraft directory. " +
                             "Baritone is an automated pathfinding and mining bot for Minecraft that can " +
                             "automatically mine resources, navigate, build structures, and play the game " +
                             "without human input. While open-source, it is widely considered a cheat " +
                             "in multiplayer contexts.",
                    Detail = $"Minecraft path: {mcPath}"
                });

                if (File.Exists(baritoneSettingsPath))
                {
                    ctx.IncrementFiles();
                    await InspectBaritoneSettingsAsync(ctx, ct, baritoneSettingsPath).ConfigureAwait(false);
                }

                string[] baritoneFiles;
                try
                {
                    baritoneFiles = Directory.GetFiles(baritoneDir, "*.txt", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    baritoneFiles = Array.Empty<string>();
                }

                foreach (var bFile in baritoneFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                }
            }

            string[] mcFiles;
            try
            {
                mcFiles = Directory.GetFiles(mcPath, "*baritone*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                mcFiles = Array.Empty<string>();
            }

            foreach (var file in mcFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Baritone bot file found in Minecraft directory: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' with 'baritone' in its name was found in the Minecraft " +
                             $"directory '{mcPath}'. Baritone-related files indicate the use of an automated " +
                             "bot for mining, navigation, or gameplay automation.",
                    Detail = $"Minecraft path: {mcPath}"
                });
            }

            await Task.Yield();
        }
    }

    private async Task InspectBaritoneSettingsAsync(ScanContext ctx, CancellationToken ct, string settingsPath)
    {
        string content;
        try
        {
            using var fs = new FileStream(settingsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content)) return;

        var aggressiveSettings = new[]
        {
            "allowBreak", "allowPlace", "allowSprint", "allowInventory",
            "allowParkour", "mineGoalUpdateInterval", "followRadius",
            "blockPlacementPenalty", "costHeuristic", "backfill",
            "antiCheat", "antiCheatCompatible", "assumeStep",
        };

        var found = new List<string>();
        foreach (var setting in aggressiveSettings)
        {
            if (content.Contains(setting, StringComparison.OrdinalIgnoreCase))
                found.Add(setting);
        }

        if (found.Count >= 3)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Baritone bot settings file found with active configuration",
                Risk = RiskLevel.High,
                Location = settingsPath,
                FileName = "settings.txt",
                Reason = $"The Baritone settings file contains {found.Count} configured parameters, " +
                         "indicating the bot has been actively configured for gameplay automation. " +
                         "Baritone with custom settings is used for automated resource farming, " +
                         "base hunting, and anti-cheat evasion in multiplayer Minecraft.",
                Detail = $"Configured Baritone settings ({found.Count}): {string.Join(", ", found.Take(6))}"
            });
        }
    }

    private async Task ScanForCrackedLauncherArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanLocations = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Documents"),
            RoamingAppData,
            LocalAppData,
            Path.GetTempPath(),
        };

        foreach (var dir in scanLocations)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] dirFiles;
            try
            {
                dirFiles = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in dirFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                foreach (var crackedArtifact in CrackedLauncherArtifacts)
                {
                    if (!fileName.Equals(crackedArtifact, StringComparison.OrdinalIgnoreCase)) continue;

                    long fileSize = 0;
                    try { fileSize = new FileInfo(file).Length; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cracked Minecraft launcher artifact found: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' matches the name of a known cracked or unofficial " +
                                 "Minecraft launcher. Cracked launchers bypass Mojang/Microsoft authentication, " +
                                 "enabling play with pirated accounts. They are also commonly bundled with " +
                                 "hacked clients and cheat software.",
                        Detail = $"Directory: {dir} | File size: {fileSize} bytes"
                    });
                    break;
                }

                if (fileName.Equals("authlib-injector.jar", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Equals("authlib_injector.jar", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"authlib-injector offline mode bypass found: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' is the authlib-injector library, which is used to " +
                                 "redirect Minecraft's authentication to unofficial servers or enable offline " +
                                 "mode. This allows playing with pirated accounts and is commonly used " +
                                 "alongside cracked launchers and hacked clients.",
                        Detail = $"Directory: {dir}"
                    });
                }
            }

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var subDir in subDirs)
            {
                ct.ThrowIfCancellationRequested();

                var subDirName = Path.GetFileName(subDir);
                foreach (var crackedDir in CrackedLauncherDirNames)
                {
                    if (!subDirName.Equals(crackedDir, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cracked Minecraft launcher directory found: {subDirName}",
                        Risk = RiskLevel.High,
                        Location = subDir,
                        Reason = $"A directory named '{subDirName}' was found in '{dir}', matching the name " +
                                 $"of the cracked/unofficial Minecraft launcher '{crackedDir}'. This directory " +
                                 "contains the launcher installation and may include bundled cheat clients.",
                        Detail = $"Parent directory: {dir}"
                    });
                    break;
                }
            }

            await Task.Yield();
        }
    }

    private async Task ScanAlternateLaunchersAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var launcherPath in AlternateLauncherPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(launcherPath)) continue;

            var instancesDir = Path.Combine(launcherPath, "instances");
            if (!Directory.Exists(instancesDir)) continue;

            string[] instanceDirs;
            try
            {
                instanceDirs = Directory.GetDirectories(instancesDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var instanceDir in instanceDirs)
            {
                ct.ThrowIfCancellationRequested();

                var instanceName = Path.GetFileName(instanceDir);

                foreach (var cheatPattern in KnownCheatClientJarPatterns)
                {
                    if (!instanceName.Contains(cheatPattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Hacked Minecraft client instance in alternate launcher: {instanceName}",
                        Risk = RiskLevel.Critical,
                        Location = instanceDir,
                        Reason = $"A launcher instance named '{instanceName}' in '{launcherPath}' matches " +
                                 $"the name of the known hacked client '{cheatPattern}'. Alternate launchers " +
                                 "like MultiMC and Prism Launcher are commonly used to manage and run hacked " +
                                 "Minecraft client instances alongside legitimate ones.",
                        Detail = $"Launcher path: {launcherPath} | Instances dir: {instancesDir}"
                    });
                    break;
                }

                var instanceMcDir = Path.Combine(instanceDir, ".minecraft");
                if (!Directory.Exists(instanceMcDir))
                    instanceMcDir = Path.Combine(instanceDir, "minecraft");

                if (Directory.Exists(instanceMcDir))
                {
                    var instanceMcPaths = new List<string> { instanceMcDir };

                    await ScanModsFolderAsync(ctx, ct, instanceMcPaths).ConfigureAwait(false);
                    await ScanVersionsFolderAsync(ctx, ct, instanceMcPaths).ConfigureAwait(false);
                    await ScanMinecraftLogsAsync(ctx, ct, instanceMcPaths).ConfigureAwait(false);
                }
            }

            await Task.Yield();
        }
    }

    private async Task InspectConfigFileForCheatKeywordsAsync(ScanContext ctx, CancellationToken ct, string filePath)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content)) return;

        var matchedKeywords = new List<string>();

        foreach (var keyword in CheatConfigKeywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                matchedKeywords.Add(keyword);
        }

        if (matchedKeywords.Count >= 3)
        {
            var fileName = Path.GetFileName(filePath);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Minecraft cheat config keywords detected: {fileName}",
                Risk = matchedKeywords.Count >= 5 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"The file '{fileName}' contains {matchedKeywords.Count} keywords associated with " +
                         "Minecraft cheat client module configuration, including KillAura, Scaffold, AimAssist, " +
                         "Xray, NoFall, and other cheat module parameters.",
                Detail = $"Matched cheat config keywords ({matchedKeywords.Count}): {string.Join(", ", matchedKeywords.Take(8))}"
            });
        }
    }

    private void ScanRegistry(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanRunKeyForCrackedLaunchers(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ScanUninstallForCrackedLaunchers(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ScanUninstallForCheatClients(ctx, ct);
    }

    private void ScanRunKeyForCrackedLaunchers(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        var crackedLauncherKeywords = new[]
        {
            "TLauncher", "SKLauncher", "authlib-injector", "authlib_injector",
            "HMCL", "BakaXL", "cracked minecraft", "offline minecraft",
        };

        foreach (var keyPath in runKeys)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                try
                {
                    using var key = hive.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        var value = key.GetValue(valueName)?.ToString() ?? string.Empty;

                        foreach (var kw in crackedLauncherKeywords)
                        {
                            if (!value.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Cracked Minecraft launcher registered in startup: {valueName}",
                                Risk = RiskLevel.High,
                                Location = $@"{keyPath}\{valueName}",
                                Reason = $"The registry startup value '{valueName}' references a cracked " +
                                         $"or unofficial Minecraft launcher (keyword: '{kw}'). Cracked launchers " +
                                         "bypass Microsoft/Mojang authentication and are often bundled with " +
                                         "hacked clients.",
                                Detail = $"Registry value: {TruncateString(value, 200)}"
                            });
                            break;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    private void ScanUninstallForCrackedLaunchers(ScanContext ctx, CancellationToken ct)
    {
        const string uninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

        var crackedLauncherNames = new[]
        {
            "tlauncher", "t-launcher", "sklauncher", "sk launcher",
            "hmcl", "bakaxl", "labymod",
        };

        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            try
            {
                using var key = hive.OpenSubKey(uninstallKey, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        using var subKey = key.OpenSubKey(subKeyName, writable: false);
                        if (subKey is null) continue;

                        ctx.IncrementRegistryKeys();

                        var displayName = subKey.GetValue("DisplayName")?.ToString() ?? string.Empty;

                        foreach (var crackedName in crackedLauncherNames)
                        {
                            if (!displayName.Contains(crackedName, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Cracked Minecraft launcher installed: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"{uninstallKey}\{subKeyName}",
                                Reason = $"The installed program '{displayName}' matches the name of a cracked " +
                                         "or unofficial Minecraft launcher. These launchers bypass account " +
                                         "authentication and are often distributed alongside hacked clients.",
                                Detail = $"Display name: {displayName} | Registry key: {subKeyName}"
                            });
                            break;
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void ScanUninstallForCheatClients(ScanContext ctx, CancellationToken ct)
    {
        const string uninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

        var cheatClientNames = new[]
        {
            "wurst", "liquidbounce", "meteor client", "future client",
            "aristois", "impact client", "sigma", "drip", "rusherhack",
            "bleachhack", "wolfram", "huzuni", "nodus", "ghost client",
            "astolfo", "flux client", "vertex", "hybrid client",
            "stardust", "vape", "baritone", "hacked client", "cheat client",
        };

        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            try
            {
                using var key = hive.OpenSubKey(uninstallKey, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        using var subKey = key.OpenSubKey(subKeyName, writable: false);
                        if (subKey is null) continue;

                        ctx.IncrementRegistryKeys();

                        var displayName = subKey.GetValue("DisplayName")?.ToString() ?? string.Empty;

                        foreach (var cheatName in cheatClientNames)
                        {
                            if (!displayName.Contains(cheatName, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Minecraft hacked client found in installed programs: {displayName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"{uninstallKey}\{subKeyName}",
                                Reason = $"The installed program '{displayName}' matches the name of a known " +
                                         "Minecraft hacked client. This cheat client was formally installed " +
                                         "on this system via an installer.",
                                Detail = $"Display name: {displayName} | Registry key: {subKeyName}"
                            });
                            break;
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static string TruncateString(string input, int maxLength)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return input.Length <= maxLength ? input : input[..maxLength] + "...";
    }
}
