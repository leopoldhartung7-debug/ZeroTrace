using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class MinecraftCheatScanModule : IScanModule
{
    public string Name => "Minecraft Cheat Client Detection";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    private static readonly string[] KnownCheatClientJarNames =
    [
        "wurst.jar", "wurst_client.jar", "wurst-client.jar",
        "impact.jar", "impact_client.jar", "impact-client.jar",
        "meteor.jar", "meteor_client.jar", "meteor-client.jar",
        "sigma.jar", "sigma_client.jar", "sigma-client.jar",
        "aristois.jar", "aristois_client.jar", "aristois-client.jar",
        "inertia.jar", "inertia_client.jar", "inertia-client.jar",
        "liquidbounce.jar", "liquidbounce_next.jar", "liquidbounce-next.jar",
        "rise.jar", "rise_client.jar", "rise-client.jar",
        "future.jar", "future_client.jar", "future-client.jar",
        "rusherhack.jar", "rusher_hack.jar", "rusher-hack.jar",
        "crystal_client.jar", "crystal-client.jar",
        "rainbow.jar", "rainbow_client.jar",
        "vape.jar", "vape_client.jar", "vape-client.jar",
        "v4_client.jar", "v4-client.jar",
        "ghost.jar", "ghost_client.jar", "ghost-client.jar",
        "novoline.jar", "novoline_client.jar", "novoline-client.jar",
        "rectil.jar", "rectil_client.jar", "rectil-client.jar",
        "crest.jar", "crest_client.jar", "crest-client.jar",
        "trap.jar", "trap_client.jar",
        "pandahack.jar", "panda_hack.jar",
        "hacked_client.jar", "hacked-client.jar",
        "cheat_client.jar", "cheat-client.jar",
        "aimbot.jar", "aimbot_client.jar",
        "killaura.jar", "killaura_client.jar", "kill_aura.jar",
        "xray.jar", "xray_client.jar",
        "criticals.jar", "criticals_client.jar",
        "speed_hack.jar", "speedhack.jar",
        "noclip.jar", "no_clip.jar",
        "autoclicker.jar", "auto_clicker.jar",
        "bhop.jar", "bunnyhop.jar", "bunny_hop.jar",
        "flight.jar", "fly_hack.jar", "flyhack.jar",
        "scaffold.jar", "scaffold_client.jar",
        "reach.jar", "reach_hack.jar",
        "anti_kb.jar", "antikb.jar", "antiknockback.jar",
        "esp.jar", "esp_client.jar",
        "wallhack.jar", "wall_hack.jar",
        "nofall.jar", "no_fall.jar",
        "fullbright.jar", "full_bright.jar",
        "autocrystal.jar", "auto_crystal.jar",
        "badlion_hacked.jar", "lunar_hacked.jar",
        "minecraft_cheat.jar", "mc_cheat.jar",
        "mc_hack.jar", "minecraft_hack.jar",
        "cheat_mc.jar", "hack_mc.jar",
        "optifine_cheat.jar",
        "forge_cheat.jar",
        "fabric_cheat.jar",
        "skyclient_cheat.jar",
        "pvpcraft.jar",
        "pvphack.jar", "pvp_hack.jar",
        "combothack.jar", "combo_hack.jar",
        "knockback_hack.jar",
        "strafe.jar", "strafe_hack.jar",
        "tower.jar", "tower_hack.jar",
        "timer.jar", "timer_hack.jar",
        "freecam.jar", "free_cam.jar",
        "tracers.jar", "tracer_hack.jar",
        "chams.jar", "chams_client.jar",
        "radar.jar", "radar_client.jar",
        "triggerbot.jar", "trigger_bot.jar",
        "silent_aim.jar", "silentaim.jar",
        "inject.jar", "injector.jar",
        "payload.jar", "loader.jar",
        "bypass.jar", "bypass_client.jar",
        "undetected.jar",
    ];

    private static readonly string[] KnownCheatClientExeNames =
    [
        "wurst.exe", "wurst_launcher.exe",
        "liquidbounce.exe", "liquidbounce_launcher.exe",
        "rise_client.exe", "rise_launcher.exe",
        "future_client.exe", "future_launcher.exe",
        "vape.exe", "vape_client.exe", "vape_launcher.exe",
        "ghost_client.exe", "ghost_launcher.exe",
        "sigma_client.exe", "sigma_launcher.exe",
        "meteor_client.exe",
        "rusherhack.exe", "rusher_hack.exe",
        "minecraft_cheat.exe", "mc_cheat.exe",
        "mc_hack.exe", "minecraft_hack.exe",
        "killaura.exe", "autoclicker_mc.exe",
        "xray_mc.exe", "esp_mc.exe",
        "inject_mc.exe", "minecraft_inject.exe",
    ];

    private static readonly string[] AutoclickerExeNames =
    [
        "autoclicker.exe", "auto_clicker.exe", "auto-clicker.exe",
        "jitterclick.exe", "jitter_click.exe", "jitter-click.exe",
        "butterfly_click.exe", "butterflyclick.exe", "butterfly-click.exe",
        "drag_click.exe", "dragclick.exe", "drag-click.exe",
        "auto_click.exe", "autoclick.exe", "auto-click.exe",
        "clickmaster.exe", "click_master.exe",
        "rapidclick.exe", "rapid_click.exe", "rapid-click.exe",
        "mouseclick.exe", "mouse_click.exe",
        "clickbot.exe", "click_bot.exe",
        "autofire.exe", "auto_fire.exe",
        "clickspammer.exe", "click_spammer.exe",
        "mcautoclicker.exe", "mc_autoclicker.exe",
        "minecraft_autoclicker.exe",
        "clickaura.exe", "click_aura.exe",
        "doubleclicker.exe", "double_click.exe",
        "leftrightclicker.exe", "left_right_click.exe",
        "cps_booster.exe", "cpsbooster.exe", "cps_hack.exe",
        "superclicker.exe", "super_click.exe",
        "clickassist.exe", "click_assist.exe",
        "fastclick.exe", "fast_click.exe",
        "turboclicker.exe", "turbo_click.exe",
        "macroclicker.exe", "macro_click.exe",
        "clicker_tool.exe", "clickertool.exe",
        "mouseauto.exe", "mouse_auto.exe",
        "clickerhero.exe",
        "gclicker.exe", "ophautoclicker.exe",
    ];

    private static readonly string[] KnownCheatModJarPatterns =
    [
        "KillAura", "killaura", "kill-aura", "kill_aura",
        "Reach", "ReachHack", "reach-hack", "reach_hack",
        "NoFall", "nofall", "no-fall", "no_fall",
        "XRay", "xray", "x-ray",
        "Fullbright", "fullbright", "full-bright", "full_bright",
        "Aimbot", "aimbot", "aim-bot", "aim_bot",
        "AutoClicker", "autoclicker", "auto-clicker", "auto_clicker",
        "AutoCrystal", "autocrystal", "auto-crystal", "auto_crystal",
        "scaffold", "Scaffold", "ScaffoldWalk",
        "criticals", "Criticals", "CritHack",
        "speed", "SpeedHack", "speed-hack", "speed_hack",
        "noSlow", "noslow", "no-slow", "no_slow",
        "antiKB", "antikb", "anti-kb", "anti_kb",
        "antiKnockback", "antiknockback", "anti-knockback",
        "bhop", "bunnyhop", "bunny-hop", "bunny_hop",
        "flyhack", "fly-hack", "fly_hack",
        "noclip", "no-clip", "no_clip",
        "tracers", "Tracers", "PlayerTracer",
        "chams", "Chams", "PlayerChams",
        "wallhack", "wall-hack", "wall_hack",
        "timer", "TimerHack", "SpeedTimer",
        "freecam", "free-cam", "free_cam",
        "triggerbot", "trigger-bot", "trigger_bot",
        "silentaim", "silent-aim", "silent_aim",
        "pvphack", "pvp-hack", "pvp_hack",
        "strafe", "StrafeHack",
        "tower", "TowerHack",
        "esp", "ESP", "PlayerESP",
        "radar", "RadarHack", "MinimapHack",
        "bypass", "Bypass", "BypassClient",
        "undetected", "Undetected",
        "InfiniteJump", "infinitejump",
        "HighJump", "highjump",
        "LongJump", "longjump",
    ];

    private static readonly string[] MinecraftLogCheatSignatures =
    [
        "wurst client", "wurst-client",
        "impact client", "impact-client",
        "meteor client", "meteor-client",
        "sigma client", "sigma-client",
        "liquidbounce", "liquid bounce",
        "rise client", "rise-client",
        "future client", "future-client",
        "rusherhack", "rusher hack",
        "vape client", "vape-client",
        "ghost client", "ghost-client",
        "novoline client",
        "rectil client",
        "crystal client",
        "aristois client",
        "inertia client",
        "pvphack", "pvp hack",
        "cheat client loaded",
        "hacked client",
        "aimbot enabled",
        "killaura enabled",
        "esp enabled",
        "fly hack enabled",
        "speed hack enabled",
        "x-ray enabled",
        "scaffold enabled",
        "autoclicker enabled",
        "autocrystal enabled",
        "antikb enabled",
        "freecam enabled",
        "triggerbot enabled",
        "[cheat]", "[hack]", "[bypass]",
    ];

    private static readonly string[] KnownCheatConfigFileNames =
    [
        "wurst_config.json", "wurst-config.json", "wurst.json",
        "impact_config.json", "impact-config.json", "impact.json",
        "meteor_config.json", "meteor-config.json", "meteor.json",
        "sigma_config.json", "sigma-config.json", "sigma.json",
        "liquidbounce_config.json", "liquidbounce-config.json", "liquidbounce.json",
        "rise_config.json", "rise-config.json",
        "future_config.json", "future-config.json",
        "vape_config.json", "vape-config.json", "vape.json",
        "ghost_config.json", "ghost-config.json",
        "novoline_config.json", "novoline-config.json",
        "cheat_config.json", "cheat-config.json",
        "hack_config.json", "hack-config.json",
        "client_config.json", "hacked_client.json",
        "autoclicker_config.json", "autoclicker.json",
        "killaura_config.json", "killaura.json",
        "esp_config.json", "aimbot_config.json",
    ];

    private static readonly string[] CheatConfigKeywords =
    [
        "killaura", "kill_aura", "kill-aura",
        "reach_distance", "reach-distance", "reachdistance",
        "nofall", "no_fall", "no-fall",
        "xray_enabled", "xray-enabled", "x_ray",
        "fullbright", "full_bright",
        "aimbot_enabled", "aimbot-enabled",
        "autoclicker_cps", "autoclicker-cps", "auto_clicker_cps",
        "autocrystal", "auto_crystal", "auto-crystal",
        "scaffold_enabled", "scaffold-enabled",
        "criticals_mode", "criticals-mode",
        "speed_multiplier", "speed-multiplier",
        "noslow_enabled", "noslow-enabled", "no_slow",
        "antikb_enabled", "antikb-enabled", "anti_kb",
        "antiknockback", "anti_knockback",
        "bunnyhop", "bunny_hop", "bhop_enabled",
        "fly_mode", "fly-mode", "flyhack",
        "noclip", "no_clip",
        "tracer_enabled", "tracers_enabled",
        "chams_enabled", "chams-enabled",
        "wallhack_enabled", "wallhack-enabled",
        "timer_speed", "timer-speed", "timer_multiplier",
        "freecam_enabled", "freecam-enabled",
        "triggerbot_enabled", "triggerbot-enabled",
        "silent_aim", "silentaim",
        "pvp_module", "pvphack",
        "esp_enabled", "esp-enabled",
        "radar_enabled", "radar-enabled",
        "bypass_enabled", "bypass-enabled",
        "strafe_enabled", "strafe-enabled",
        "highjump", "high_jump", "longjump", "long_jump",
        "infinitejump", "infinite_jump",
        "module_enabled", "cheat_module",
        "hacked_client_version",
        "liquidbounce", "wurst_version", "impact_version",
        "meteor_version", "sigma_version",
    ];

    private static readonly string[] BadlionLunarSuspiciousDllPatterns =
    [
        "inject", "hook", "cheat", "hack", "bypass",
        "killaura", "aimbot", "esp", "wallhack",
        "autoclicker", "autoclick",
    ];

    private static readonly string[] MuiCacheCheatFragments =
    [
        "wurst", "liquidbounce", "meteor_client", "impact_client",
        "sigma_client", "rise_client", "future_client", "vape_client",
        "ghost_client", "novoline", "rusherhack", "rusher_hack",
        "killaura", "aimbot", "autoclicker", "auto_clicker",
        "jitterclick", "butterfly_click", "drag_click",
        "minecraft_cheat", "mc_cheat", "mc_hack", "minecraft_hack",
        "pvphack", "pvp_hack", "xray_mc", "esp_mc",
        "inject_mc", "minecraft_inject",
        "cps_booster", "cpsbooster",
        "cheat_mc", "hack_mc",
        "scaffold", "autocrystal", "auto_crystal",
        "pandahack", "panda_hack", "aristois", "inertia_client",
        "crystal_client", "crest_client", "rectil_client",
    ];

    private static readonly string[] UninstallCheatFragments =
    [
        "wurst client", "wurst-client",
        "impact client", "impact-client",
        "meteor client", "meteor-client",
        "sigma client", "sigma-client",
        "liquidbounce", "liquid bounce",
        "rise client", "rise-client",
        "future client", "future-client",
        "rusherhack", "rusher hack",
        "vape client", "vape-client",
        "ghost client", "ghost-client",
        "novoline client",
        "minecraft cheat", "mc cheat",
        "killaura", "autoclicker mc",
        "minecraft hack", "mc hack",
        "cheat client",
    ];

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string[] MinecraftBaseDirs;
    private static readonly string[] SearchRoots;

    static MinecraftCheatScanModule()
    {
        var mcDirs = new List<string>();

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (!string.IsNullOrEmpty(appData))
        {
            mcDirs.Add(Path.Combine(appData, ".minecraft"));
            mcDirs.Add(Path.Combine(appData, "minecraft"));
            mcDirs.Add(Path.Combine(appData, ".minecraft-launcher"));
        }

        if (!string.IsNullOrEmpty(userProfile))
        {
            mcDirs.Add(Path.Combine(userProfile, "AppData", "Roaming", ".minecraft"));
            mcDirs.Add(Path.Combine(userProfile, ".minecraft"));
        }

        MinecraftBaseDirs = [.. mcDirs];

        var roots = new List<string>();
        if (!string.IsNullOrEmpty(appData)) roots.Add(appData);

        string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        if (!string.IsNullOrEmpty(localAppData)) roots.Add(localAppData);

        if (!string.IsNullOrEmpty(userProfile))
        {
            roots.Add(Path.Combine(userProfile, "Desktop"));
            roots.Add(Path.Combine(userProfile, "Downloads"));
            roots.Add(Path.Combine(userProfile, "Documents"));
        }

        SearchRoots = [.. roots];
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckKnownCheatClientJars(ctx, ct),
            CheckKnownCheatClientExes(ctx, ct),
            CheckAutoClickerTools(ctx, ct),
            CheckMinecraftModsDirectory(ctx, ct),
            CheckMinecraftLogs(ctx, ct),
            CheckCheatConfigFiles(ctx, ct),
            CheckBadlionLunarIntegrity(ctx, ct),
            CheckMuiCacheForMinecraftCheats(ctx, ct),
            CheckUninstallEntriesForMinecraftCheats(ctx, ct),
            CheckUserAssistForMinecraftCheats(ctx, ct),
            CheckRunKeysForMinecraftCheats(ctx, ct),
            CheckMinecraftVersionDirectory(ctx, ct)
        ).ConfigureAwait(false);
    }

    private Task CheckKnownCheatClientJars(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchLocations = new List<string>(SearchRoots);
            searchLocations.AddRange(MinecraftBaseDirs);

            foreach (string root in searchLocations)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.jar", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);

                        foreach (string known in KnownCheatClientJarNames)
                        {
                            if (fn.Equals(known, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Known Minecraft Cheat Client JAR: {fn}",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"JAR file '{fn}' matches the name of a known Minecraft hacked/cheat client. " +
                                             "This client provides illegal gameplay advantages including KillAura, " +
                                             "reach hacks, X-Ray, aimbot, autoclicker, and flight hacks.",
                                    Detail = $"Matched cheat client: {known} | Path: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }

                        if (!KnownCheatClientJarNames.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            string fnLower = fn.ToLowerInvariant();
                            bool heuristicHit = KnownCheatModJarPatterns
                                .Any(p => fnLower.Contains(p, StringComparison.OrdinalIgnoreCase))
                                && (fnLower.Contains("hack") || fnLower.Contains("cheat")
                                    || fnLower.Contains("hacked") || fnLower.Contains("bypass")
                                    || fnLower.Contains("client"));

                            if (heuristicHit)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Suspected Minecraft Cheat JAR: {fn}",
                                    Risk = Risk.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"JAR file '{fn}' matches heuristic patterns for a Minecraft cheat client " +
                                             "(cheat module name combined with 'hack', 'cheat', or 'client' keyword). " +
                                             "This is a suspected hacked Minecraft client or cheat mod.",
                                    Detail = $"Path: {file}"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);
    }

    private Task CheckKnownCheatClientExes(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string root in SearchRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);

                        foreach (string known in KnownCheatClientExeNames)
                        {
                            if (fn.Equals(known, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Known Minecraft Cheat Client Executable: {fn}",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"Executable '{fn}' matches a known Minecraft cheat client launcher. " +
                                             "Minecraft cheat client launchers inject or launch hacked game clients " +
                                             "that provide unfair gameplay advantages on multiplayer servers.",
                                    Detail = $"Matched cheat executable: {known} | Path: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);
    }

    private Task CheckAutoClickerTools(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string root in SearchRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);

                        foreach (string known in AutoclickerExeNames)
                        {
                            if (fn.Equals(known, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Minecraft Auto-Clicker/Macro Tool: {fn}",
                                    Risk = Risk.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"Auto-click/macro tool '{fn}' detected. These tools automatically click " +
                                             "the mouse at high CPS rates (jitter-click, butterfly-click, drag-click) " +
                                             "to gain unfair PvP advantages on Minecraft servers by bypassing CPS limits " +
                                             "enforced by anti-cheat plugins.",
                                    Detail = $"Matched auto-clicker: {known} | Path: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }

                        if (!AutoclickerExeNames.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            string fnLower = fn.ToLowerInvariant();
                            bool isAutoclick = (fnLower.Contains("autoclicker") || fnLower.Contains("auto_click")
                                || fnLower.Contains("auto-click") || fnLower.Contains("clickbot")
                                || fnLower.Contains("clickspam") || fnLower.Contains("rapidclick")
                                || fnLower.Contains("jitterclick") || fnLower.Contains("jitter_click")
                                || fnLower.Contains("butterfly") || fnLower.Contains("dragclick")
                                || fnLower.Contains("drag_click") || fnLower.Contains("cps_boost"))
                                && !fnLower.Contains("uninstall") && !fnLower.Contains("setup");

                            if (isAutoclick)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Suspected Auto-Clicker Tool: {fn}",
                                    Risk = Risk.Medium,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"File '{fn}' matches heuristic patterns for an auto-clicker or CPS booster tool " +
                                             "(contains autoclicker, clickbot, jitter, butterfly, or dragclick keywords). " +
                                             "These tools are commonly used to cheat in Minecraft PvP.",
                                    Detail = $"Path: {file}"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);
    }

    private Task CheckMinecraftModsDirectory(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string mcBase in MinecraftBaseDirs)
            {
                if (!Directory.Exists(mcBase)) continue;

                string modsDir = Path.Combine(mcBase, "mods");
                if (!Directory.Exists(modsDir)) continue;

                try
                {
                    foreach (string file in Directory.EnumerateFiles(modsDir, "*.jar", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        string fnLower = fn.ToLowerInvariant();

                        foreach (string known in KnownCheatClientJarNames)
                        {
                            if (fn.Equals(known, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Known Cheat Client JAR in .minecraft/mods: {fn}",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"Known cheat client JAR '{fn}' found in the Minecraft mods directory. " +
                                             "Installing cheat clients as mods is a common technique to use hacked " +
                                             "clients with legitimate Minecraft launchers.",
                                    Detail = $"Mods directory: {modsDir} | File: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }

                        if (!KnownCheatClientJarNames.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            string? matchedPattern = KnownCheatModJarPatterns
                                .FirstOrDefault(p => fnLower.Contains(p, StringComparison.OrdinalIgnoreCase));

                            if (matchedPattern != null)
                            {
                                bool isCheatMod = fnLower.Contains("hack") || fnLower.Contains("cheat")
                                    || fnLower.Contains("killaura") || fnLower.Contains("aimbot")
                                    || fnLower.Contains("xray") || fnLower.Contains("autoclicker")
                                    || fnLower.Contains("autocrystal") || fnLower.Contains("antikb")
                                    || fnLower.Contains("antiknockback") || fnLower.Contains("bhop")
                                    || fnLower.Contains("bunnyhop") || fnLower.Contains("flyhack")
                                    || fnLower.Contains("wallhack") || fnLower.Contains("noclip")
                                    || fnLower.Contains("nofall") || fnLower.Contains("fullbright")
                                    || fnLower.Contains("triggerbot") || fnLower.Contains("scaffold")
                                    || fnLower.Contains("pvphack") || fnLower.Contains("bypass");

                                if (isCheatMod)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Suspected Cheat Mod JAR in .minecraft/mods: {fn}",
                                        Risk = Risk.High,
                                        Location = file,
                                        FileName = fn,
                                        Reason = $"JAR file '{fn}' in the Minecraft mods folder contains cheat-related keywords " +
                                                 $"(matched pattern: '{matchedPattern}'). This is a suspected cheat mod providing " +
                                                 "unfair advantages on Minecraft multiplayer servers.",
                                        Detail = $"Mods directory: {modsDir} | Pattern: {matchedPattern}"
                                    });
                                    ctx.IncrementFiles();
                                }
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);
    }

    private Task CheckMinecraftLogs(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string mcBase in MinecraftBaseDirs)
            {
                if (!Directory.Exists(mcBase)) continue;

                string logsDir = Path.Combine(mcBase, "logs");
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

                foreach (string logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                    }
                    catch (IOException) { }

                    if (string.IsNullOrEmpty(content)) continue;

                    var matchedSigs = new List<string>();
                    foreach (string sig in MinecraftLogCheatSignatures)
                    {
                        if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                            matchedSigs.Add(sig);
                    }

                    if (matchedSigs.Count >= 1)
                    {
                        string fn = Path.GetFileName(logFile);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Minecraft Log Contains Cheat Client Startup: {fn}",
                            Risk = Risk.High,
                            Location = logFile,
                            FileName = fn,
                            Reason = $"Minecraft log file '{fn}' contains {matchedSigs.Count} text signature(s) associated " +
                                     "with known Minecraft cheat clients (wurst, impact, meteor, sigma, liquidbounce, etc.). " +
                                     "These signatures appear in the log when a hacked client is launched and initializes its modules.",
                            Detail = $"Matched signatures ({matchedSigs.Count}): {string.Join(", ", matchedSigs.Take(8))}"
                        });
                    }
                }

                string[] gzLogFiles;
                try
                {
                    gzLogFiles = Directory.GetFiles(logsDir, "*.log.gz", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string gzFile in gzLogFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    string fn = Path.GetFileName(gzFile);
                    ctx.IncrementFiles();
                }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);
    }

    private Task CheckCheatConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string mcBase in MinecraftBaseDirs)
            {
                if (!Directory.Exists(mcBase)) continue;

                var configSearchDirs = new List<string> { mcBase };

                try
                {
                    foreach (string subDir in Directory.EnumerateDirectories(mcBase, "*", SearchOption.TopDirectoryOnly))
                    {
                        configSearchDirs.Add(subDir);
                    }
                }
                catch (UnauthorizedAccessException) { }

                foreach (string searchDir in configSearchDirs)
                {
                    if (!Directory.Exists(searchDir)) continue;

                    try
                    {
                        foreach (string file in Directory.EnumerateFiles(searchDir, "*.json", SearchOption.TopDirectoryOnly))
                        {
                            ct.ThrowIfCancellationRequested();
                            string fn = Path.GetFileName(file);

                            bool isKnownConfig = KnownCheatConfigFileNames
                                .Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase));

                            if (isKnownConfig)
                            {
                                string content = string.Empty;
                                try
                                {
                                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                    using var sr = new StreamReader(fs);
                                    content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                                }
                                catch (IOException) { }

                                string? matchedKw = null;
                                if (!string.IsNullOrEmpty(content))
                                {
                                    matchedKw = CheatConfigKeywords
                                        .FirstOrDefault(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                                }

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Known Minecraft Cheat Client Config: {fn}",
                                    Risk = matchedKw != null ? Risk.Critical : Risk.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"Config file '{fn}' matches a known Minecraft cheat client configuration file name. " +
                                             (matchedKw != null
                                                 ? $"Content also contains cheat keyword '{matchedKw}', confirming cheat configuration."
                                                 : "The filename alone is a strong indicator of a cheat client."),
                                    Detail = matchedKw != null
                                        ? $"Cheat keyword: '{matchedKw}' | Path: {file}"
                                        : $"Path: {file}"
                                });
                                ctx.IncrementFiles();
                                continue;
                            }

                            string fnLower = fn.ToLowerInvariant();
                            bool isMcCheatRelated = fnLower.Contains("wurst") || fnLower.Contains("liquidbounce")
                                || fnLower.Contains("meteor") || fnLower.Contains("sigma")
                                || fnLower.Contains("impact") || fnLower.Contains("rise_client")
                                || fnLower.Contains("future_client") || fnLower.Contains("vape")
                                || fnLower.Contains("ghost_client") || fnLower.Contains("novoline")
                                || fnLower.Contains("rusherhack");

                            if (!isMcCheatRelated) continue;

                            string configContent = string.Empty;
                            try
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                configContent = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                            }
                            catch (IOException) { }

                            if (string.IsNullOrEmpty(configContent)) continue;

                            string? hit = CheatConfigKeywords
                                .FirstOrDefault(k => configContent.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (hit != null)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Minecraft Cheat Client Config Keyword: {fn}",
                                    Risk = Risk.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"Minecraft-related JSON config '{fn}' contains cheat keyword '{hit}'. " +
                                             "Cheat clients store module settings like KillAura, reach, autoclicker CPS, " +
                                             "and X-Ray configurations in JSON files.",
                                    Detail = $"Keyword: '{hit}' | Path: {file}"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }

            foreach (string root in SearchRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.json", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);

                        bool isKnownConfig = KnownCheatConfigFileNames
                            .Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase));

                        if (!isKnownConfig) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Minecraft Cheat Config in User Directory: {fn}",
                            Risk = Risk.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known Minecraft cheat client config file '{fn}' found in user directory. " +
                                     "This config file is associated with a Minecraft hacked client.",
                            Detail = $"Path: {file}"
                        });
                        ctx.IncrementFiles();
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);
    }

    private Task CheckBadlionLunarIntegrity(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");

            var launcherDirCandidates = new List<string>();

            if (!string.IsNullOrEmpty(localAppData))
            {
                launcherDirCandidates.Add(Path.Combine(localAppData, "Programs", "BadlionClient"));
                launcherDirCandidates.Add(Path.Combine(localAppData, "Programs", "Badlion Client"));
                launcherDirCandidates.Add(Path.Combine(localAppData, "Programs", "LunarClient"));
                launcherDirCandidates.Add(Path.Combine(localAppData, "Programs", "Lunar Client"));
                launcherDirCandidates.Add(Path.Combine(localAppData, "BadlionClient"));
                launcherDirCandidates.Add(Path.Combine(localAppData, "LunarClient"));
            }

            string appData = AppData;
            if (!string.IsNullOrEmpty(appData))
            {
                launcherDirCandidates.Add(Path.Combine(appData, "BadlionClient"));
                launcherDirCandidates.Add(Path.Combine(appData, "LunarClient"));
                launcherDirCandidates.Add(Path.Combine(appData, ".badlion"));
                launcherDirCandidates.Add(Path.Combine(appData, ".lunarclient"));
            }

            foreach (string launcherDir in launcherDirCandidates)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(launcherDir)) continue;

                try
                {
                    foreach (string file in Directory.EnumerateFiles(launcherDir, "*.dll", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        string fnLower = fn.ToLowerInvariant();

                        string? matchedPattern = BadlionLunarSuspiciousDllPatterns
                            .FirstOrDefault(p => fnLower.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (matchedPattern != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious DLL in Badlion/Lunar Launcher Directory: {fn}",
                                Risk = Risk.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"DLL '{fn}' with cheat-related keyword '{matchedPattern}' found in the " +
                                         $"Badlion/Lunar Client launcher directory '{launcherDir}'. " +
                                         "Injecting cheat DLLs into the launcher directory is a technique used to " +
                                         "bypass Badlion/Lunar Client anti-cheat by loading cheat code within the trusted process.",
                                Detail = $"Launcher directory: {launcherDir} | Matched pattern: {matchedPattern} | File: {file}"
                            });
                            ctx.IncrementFiles();
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);
    }

    private Task CheckMuiCacheForMinecraftCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string muiCacheKey = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(muiCacheKey, writable: false);
                if (key is null) return;

                foreach (string valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    string vLower = valueName.ToLowerInvariant();
                    foreach (string frag in MuiCacheCheatFragments)
                    {
                        if (vLower.Contains(frag, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Minecraft Cheat Tool Execution in MUICache: {Path.GetFileName(valueName)}",
                                Risk = Risk.High,
                                Location = $@"HKCU\{muiCacheKey}",
                                FileName = Path.GetFileName(valueName),
                                Reason = $"MUICache registry entry '{valueName}' matches known Minecraft cheat tool pattern '{frag}'. " +
                                         "MUICache records program execution history, indicating this Minecraft cheat tool " +
                                         "or auto-clicker was previously launched on this system.",
                                Detail = $"Registry value: {valueName} | Matched fragment: {frag}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }, ct);
    }

    private Task CheckUninstallEntriesForMinecraftCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] uninstallKeys =
            [
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ];

            foreach (string uninstallKey in uninstallKeys)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    try
                    {
                        using var key = hive.OpenSubKey(uninstallKey, writable: false);
                        if (key is null) continue;

                        foreach (string subKeyName in key.GetSubKeyNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            try
                            {
                                using var subKey = key.OpenSubKey(subKeyName, writable: false);
                                if (subKey is null) continue;
                                ctx.IncrementRegistryKeys();

                                string displayName = (subKey.GetValue("DisplayName") as string ?? string.Empty);
                                string displayNameLower = displayName.ToLowerInvariant();
                                string publisher = (subKey.GetValue("Publisher") as string ?? string.Empty).ToLowerInvariant();

                                foreach (string frag in UninstallCheatFragments)
                                {
                                    if (displayNameLower.Contains(frag, StringComparison.OrdinalIgnoreCase)
                                        || publisher.Contains(frag, StringComparison.OrdinalIgnoreCase))
                                    {
                                        string hivePrefix = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = $"Minecraft Cheat Software in Installed Programs: {displayName}",
                                            Risk = Risk.Critical,
                                            Location = $@"{hivePrefix}\{uninstallKey}\{subKeyName}",
                                            Reason = $"Installed software '{displayName}' matches a known Minecraft cheat client name '{frag}'. " +
                                                     "This indicates a Minecraft hacked client or cheat tool was formally installed on this system.",
                                            Detail = $"DisplayName: {displayName} | Publisher: {publisher}"
                                        });
                                        break;
                                    }
                                }
                            }
                            catch (UnauthorizedAccessException) { }
                            catch { }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
        }, ct);
    }

    private Task CheckUserAssistForMinecraftCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string userAssistBase = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
                if (baseKey is null) return;

                foreach (string guidName in baseKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var countKey = baseKey.OpenSubKey(guidName + @"\Count", writable: false);
                        if (countKey is null) continue;

                        foreach (string valueName in countKey.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            string decoded = Rot13Decode(valueName);
                            string decodedLower = decoded.ToLowerInvariant();

                            foreach (string frag in MuiCacheCheatFragments)
                            {
                                if (decodedLower.Contains(frag, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Minecraft Cheat Tool in UserAssist History: {Path.GetFileName(decoded)}",
                                        Risk = Risk.High,
                                        Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                        FileName = Path.GetFileName(decoded),
                                        Reason = $"UserAssist entry decodes (ROT13) to '{decoded}', matching Minecraft cheat pattern '{frag}'. " +
                                                 "UserAssist records program execution history. This indicates a Minecraft cheat tool or " +
                                                 "auto-clicker was previously launched on this user account.",
                                        Detail = $"ROT13 encoded: {valueName} | Decoded: {decoded}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }, ct);
    }

    private Task CheckRunKeysForMinecraftCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] runKeys =
            [
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            ];

            string[] cheatFragments =
            [
                "wurst", "liquidbounce", "meteor_client", "impact_client",
                "sigma_client", "rise_client", "future_client", "vape_client",
                "ghost_client", "novoline", "rusherhack", "killaura",
                "autoclicker", "auto_clicker", "jitterclick", "butterfly_click",
                "drag_click", "minecraft_cheat", "mc_cheat", "pvphack",
                "autocrystal", "scaffold_hack",
            ];

            foreach (string runKey in runKeys)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    try
                    {
                        using var key = hive.OpenSubKey(runKey, writable: false);
                        if (key is null) continue;

                        foreach (string valueName in key.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            string valueData = (key.GetValue(valueName) as string ?? string.Empty).ToLowerInvariant();
                            string nameLower = valueName.ToLowerInvariant();

                            foreach (string frag in cheatFragments)
                            {
                                if (valueData.Contains(frag, StringComparison.OrdinalIgnoreCase)
                                    || nameLower.Contains(frag, StringComparison.OrdinalIgnoreCase))
                                {
                                    string hivePrefix = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Minecraft Cheat Tool in Run Key: {valueName}",
                                        Risk = Risk.High,
                                        Location = $@"{hivePrefix}\{runKey}",
                                        Reason = $"Registry Run/RunOnce entry '{valueName}' matches Minecraft cheat pattern '{frag}'. " +
                                                 "This configures a Minecraft cheat tool or auto-clicker to auto-start with Windows.",
                                        Detail = $"Value name: {valueName} | Value data: {key.GetValue(valueName) as string ?? string.Empty} | Key: {hivePrefix}\\{runKey}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
        }, ct);
    }

    private Task CheckMinecraftVersionDirectory(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string mcBase in MinecraftBaseDirs)
            {
                if (!Directory.Exists(mcBase)) continue;

                string versionsDir = Path.Combine(mcBase, "versions");
                if (!Directory.Exists(versionsDir)) continue;

                try
                {
                    foreach (string versionDir in Directory.EnumerateDirectories(versionsDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        string versionName = Path.GetFileName(versionDir).ToLowerInvariant();

                        bool isCheatClient = KnownCheatModJarPatterns
                            .Any(p => versionName.Contains(p, StringComparison.OrdinalIgnoreCase));

                        isCheatClient = isCheatClient || versionName.Contains("wurst") || versionName.Contains("liquidbounce")
                            || versionName.Contains("meteor") || versionName.Contains("sigma")
                            || versionName.Contains("impact") || versionName.Contains("rise_client")
                            || versionName.Contains("future_client") || versionName.Contains("vape")
                            || versionName.Contains("ghost_client") || versionName.Contains("novoline")
                            || versionName.Contains("rusherhack") || versionName.Contains("hacked")
                            || versionName.Contains("cheat") || versionName.Contains("hack");

                        if (isCheatClient)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspected Cheat Client Version Directory: {Path.GetFileName(versionDir)}",
                                Risk = Risk.High,
                                Location = versionDir,
                                Reason = $"Minecraft versions directory contains a version folder named '{Path.GetFileName(versionDir)}' " +
                                         "which matches patterns for known Minecraft cheat clients. " +
                                         "Hacked clients are often installed as custom version profiles in .minecraft/versions.",
                                Detail = $"Versions directory: {versionsDir} | Version profile: {Path.GetFileName(versionDir)}"
                            });
                        }

                        try
                        {
                            foreach (string file in Directory.EnumerateFiles(versionDir, "*.jar", SearchOption.TopDirectoryOnly))
                            {
                                ct.ThrowIfCancellationRequested();
                                string fn = Path.GetFileName(file);
                                bool isKnown = KnownCheatClientJarNames
                                    .Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase));

                                if (isKnown)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Known Cheat Client JAR in .minecraft/versions: {fn}",
                                        Risk = Risk.Critical,
                                        Location = file,
                                        FileName = fn,
                                        Reason = $"Known Minecraft cheat client JAR '{fn}' found in the versions directory. " +
                                                 "The versions directory stores game JAR files; a cheat client JAR here " +
                                                 "is used as a profile that launches the hacked game.",
                                        Detail = $"Version directory: {versionDir} | File: {file}"
                                    });
                                    ctx.IncrementFiles();
                                }
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            await Task.CompletedTask.ConfigureAwait(false);
        }, ct);
    }

    private static string Rot13Decode(string input)
    {
        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (c >= 'a' && c <= 'z')
                sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z')
                sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }
}
