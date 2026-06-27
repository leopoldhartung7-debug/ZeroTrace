using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RageMPHealthHackScanModule : IScanModule
{
    public string Name => "RageMP Health & Armor Hack Forensic Scan";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
    private static readonly string TempPath =
        Path.GetTempPath();

    private static readonly string[] RageMPDataPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RAGEMP"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RAGEMP"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ragemp"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ragemp"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "rage-multiplayer"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "rage-multiplayer"),
    ];

    private static readonly string[] HealthHackExecutables =
    [
        "HealthHack.exe",
        "healthhack.exe",
        "health_hack.exe",
        "health_cheat.exe",
        "healthcheat.exe",
        "GodMode.exe",
        "godmode.exe",
        "god_mode.exe",
        "ArmorHack.exe",
        "armorhack.exe",
        "armor_hack.exe",
        "armor_cheat.exe",
        "armorcheat.exe",
        "ArmourHack.exe",
        "armourhack.exe",
        "armour_hack.exe",
        "FullHealth.exe",
        "fullhealth.exe",
        "full_health.exe",
        "MaxHealth.exe",
        "maxhealth.exe",
        "max_health.exe",
        "InfiniteHealth.exe",
        "infinitehealth.exe",
        "infinite_health.exe",
        "ImmortalHack.exe",
        "immortalhack.exe",
        "immortal_hack.exe",
        "immortal_ragemp.exe",
        "ImmortalRageMP.exe",
        "HealthBypass.exe",
        "healthbypass.exe",
        "health_bypass.exe",
        "healthhack_ragemp.exe",
        "HealthHackRageMP.exe",
        "health_hack_ragemp.exe",
        "health_cheat_ragemp.exe",
        "HealthCheatRageMP.exe",
        "armor_hack_ragemp.exe",
        "ArmorHackRageMP.exe",
        "armour_hack_ragemp.exe",
        "godmode_ragemp.exe",
        "GodModeRageMP.exe",
        "god_mode_ragemp.exe",
        "immortal_ragemp.exe",
        "health_bypass_ragemp.exe",
        "HealthBypassRageMP.exe",
        "full_health_ragemp.exe",
        "FullHealthRageMP.exe",
        "ragemp_health.exe",
        "ragemp_godmode.exe",
        "ragemp_armor.exe",
        "ragemp_armour.exe",
        "ragemp_health_hack.exe",
        "ragemp_godmode_hack.exe",
        "ragemp_immortal.exe",
        "ragemp_invincible.exe",
        "invincible_ragemp.exe",
        "InvincibleRageMP.exe",
        "PlayerHealth.exe",
        "playerhealth.exe",
        "player_health.exe",
        "HealthSetter.exe",
        "healthsetter.exe",
        "SetHealth.exe",
        "sethealth.exe",
        "set_health.exe",
        "SetArmour.exe",
        "setarmour.exe",
        "set_armour.exe",
        "SetArmor.exe",
        "setarmor.exe",
        "HealthTrainer.exe",
        "healthtrainer.exe",
        "health_trainer.exe",
        "ArmorTrainer.exe",
        "armortrainer.exe",
        "NoDamage.exe",
        "nodamage.exe",
        "no_damage.exe",
        "DmgBypass.exe",
        "dmgbypass.exe",
        "damage_bypass.exe",
        "HealthBoost.exe",
        "healthboost.exe",
        "MaxArmor.exe",
        "maxarmor.exe",
        "InfiniteArmor.exe",
        "infinitearmor.exe",
        "ragemp_health_cheat.exe",
        "ragemp_armor_cheat.exe",
        "ragemp_no_damage.exe",
        "ragemp_invulnerable.exe",
    ];

    private static readonly string[] HealthHackDlls =
    [
        "health_hack.dll",
        "healthhack.dll",
        "godmode.dll",
        "god_mode.dll",
        "armor_hack.dll",
        "armorhack.dll",
        "armour_hack.dll",
        "full_health.dll",
        "fullhealth.dll",
        "immortal.dll",
        "immortal_hack.dll",
        "health_bypass.dll",
        "healthbypass.dll",
        "ragemp_health.dll",
        "ragemp_godmode.dll",
        "ragemp_armor.dll",
        "ragemp_armour.dll",
        "ragemp_health_hook.dll",
        "ragemp_godmode_hook.dll",
        "ragemp_armor_hook.dll",
        "ragemp_health_bypass.dll",
        "ragemp_invincible.dll",
        "ragemp_nodamage.dll",
        "health_hook.dll",
        "armor_hook.dll",
        "armour_hook.dll",
        "godmode_hook.dll",
        "health_inject.dll",
        "armor_inject.dll",
        "health_cheat.dll",
        "armor_cheat.dll",
        "nodamage.dll",
        "no_damage.dll",
        "dmg_bypass.dll",
        "damage_bypass.dll",
        "health_exploit.dll",
        "armor_exploit.dll",
        "invincible.dll",
        "invincible_hook.dll",
        "player_health.dll",
        "max_health.dll",
        "infinite_health.dll",
        "max_armor.dll",
        "infinite_armor.dll",
    ];

    private static readonly string[] HealthHackConfigFiles =
    [
        "health_hack_config.json",
        "healthhack_config.json",
        "godmode_config.json",
        "armor_hack_config.json",
        "health_offsets.json",
        "health_offsets.txt",
        "armor_offsets.txt",
        "armor_offsets.json",
        "health_addresses.txt",
        "armor_addresses.txt",
        "godmode_offsets.txt",
        "health_bypass_config.json",
        "ragemp_health_config.json",
        "ragemp_godmode_config.json",
        "ragemp_armor_config.json",
        "health_config.json",
        "armor_config.json",
        "godmode_config.txt",
        "immortal_config.json",
        "health_cheat_config.json",
        "ragemp_health_offsets.txt",
        "ragemp_armor_offsets.txt",
        "player_health_offsets.json",
        "ped_health_offsets.txt",
        "max_health_config.json",
        "infinite_health_config.json",
        "nodamage_config.json",
    ];

    private static readonly string[] HealthHackDownloadArtifacts =
    [
        "healthhack_ragemp.zip",
        "health_hack_ragemp.zip",
        "godmode_ragemp.zip",
        "armor_hack_ragemp.zip",
        "immortal_ragemp.zip",
        "health_bypass_ragemp.zip",
        "full_health_ragemp.zip",
        "healthhack_ragemp.rar",
        "health_hack_ragemp.rar",
        "godmode_ragemp.rar",
        "armor_hack_ragemp.rar",
        "immortal_ragemp.rar",
        "healthhack_ragemp.7z",
        "health_hack_ragemp.7z",
        "godmode_ragemp.7z",
        "ragemp_health.zip",
        "ragemp_godmode.zip",
        "ragemp_armor.zip",
        "ragemp_health.rar",
        "ragemp_godmode.rar",
        "ragemp_armor.rar",
        "health_cheat_ragemp.zip",
        "health_cheat_ragemp.rar",
        "armor_cheat_ragemp.zip",
        "health_hack_setup.exe",
        "godmode_setup.exe",
        "armor_hack_setup.exe",
        "ragemp_health_setup.exe",
        "ragemp_godmode_setup.exe",
        "ragemp_health_installer.exe",
        "godmode_installer.exe",
        "health_cheat_setup.exe",
        "armor_hack_setup.exe",
        "immortal_hack_setup.exe",
        "health_bypass_setup.exe",
        "full_health_setup.exe",
        "HealthHack_v2.zip",
        "GodMode_v2.zip",
        "ArmorHack_v2.zip",
        "ragemp_immortal.zip",
        "ragemp_invincible.zip",
        "ragemp_nodamage.zip",
    ];

    private static readonly string[] ClientLogHealthKeywords =
    [
        "health hack ragemp",
        "healthhack ragemp",
        "armor hack ragemp",
        "armour hack ragemp",
        "godmode ragemp",
        "god mode ragemp",
        "immortal ragemp",
        "health cheat ragemp",
        "unlimited health",
        "infinite health",
        "max health",
        "health bypass",
        "armor bypass",
        "godmode enabled",
        "god mode enabled",
        "player invincible",
        "invincible enabled",
        "health set to",
        "armor set to",
        "health override",
        "armor override",
        "setHealth called",
        "setArmour called",
        "setPlayerHealth",
        "health_bypass activated",
        "armor_bypass activated",
        "godmode activated",
        "immortal mode enabled",
        "no damage mode",
        "damage bypass enabled",
        "ragemp health hack",
        "ragemp godmode",
        "ragemp armor hack",
        "ragemp armour hack",
        "ragemp immortal",
        "ragemp health cheat",
        "health_override active",
        "healthhack loaded",
        "godmode loaded",
        "armor hack loaded",
        "health cheat loaded",
        "health exploit",
        "armor exploit",
        "sethealth bypass",
        "setarmour bypass",
        "nativedb health",
        "player health native",
        "ped health override",
    ];

    private static readonly string[] JavaScriptHealthPatterns =
    [
        "mp.players.local.health =",
        "mp.players.local.armour =",
        "mp.players.local.health=",
        "mp.players.local.armour=",
        "health_bypass",
        "armor_exploit",
        "armour_exploit",
        "setHealth(100)",
        "setArmour(100)",
        "setHealth(200)",
        "setArmour(100)",
        "setEntityHealth(",
        "setEntityInvincible(",
        "setEntityMaxHealth(",
        "mp.game.entity.setEntityHealth(",
        "mp.game.entity.setEntityInvincible(",
        "godmode_ragemp",
        "godModeEnabled",
        "infiniteHealth",
        "infinite_health",
        "healthHack",
        "health_hack",
        "armorHack",
        "armor_hack",
        "armourHack",
        "armour_hack",
        "noClipHealth",
        "noDamage",
        "no_damage",
        "damageBypass",
        "damage_bypass",
        "setPlayerHealth bypass",
        "health_override",
        "healthhack",
        "setArmor(100)",
        "maxHealthHack",
        "maxArmorHack",
        "maxArmourHack",
        "player.health = 200",
        "player.armour = 100",
        "player.armour=100",
        "player.health=200",
        "immortalMode",
        "immortal_mode",
        "invincibleMode",
        "invincible_mode",
        "SetPedMaxHealth(",
        "mp.players.local.health += ",
        "mp.players.local.armour += ",
        "healthExploit(",
        "armourExploit(",
        "health_exploit(",
        "armor_exploit(",
    ];

    private static readonly string[] CSharpHealthPatterns =
    [
        "SetEntityHealth(",
        "SetEntityInvincible(",
        "SetEntityMaxHealth(",
        "SetPedMaxHealth(",
        "health_bypass",
        "armor_exploit",
        "armour_exploit",
        "setHealth",
        "setArmour",
        "setArmor",
        "godmode_ragemp",
        "GodModeEnabled",
        "InfiniteHealth",
        "infinite_health",
        "HealthHack",
        "health_hack",
        "ArmorHack",
        "armor_hack",
        "NoDamage",
        "no_damage",
        "DamageBypass",
        "damage_bypass",
        "health_override",
        "healthhack",
        "ArmorBypass",
        "armor_bypass",
        "HealthOverride",
        "ImmortalMode",
        "immortal_mode",
        "InvincibleMode",
        "invincible_mode",
        "PlayerHealth.Set(",
        "PlayerArmour.Set(",
        "NativeDB.Invoke(\"SET_ENTITY_HEALTH\"",
        "NativeDB.Invoke(\"SET_ENTITY_INVINCIBLE\"",
        "NativeDB.Invoke(\"SET_PED_ARMOUR\"",
        "NativeHash.SET_ENTITY_HEALTH",
        "NativeHash.SET_ENTITY_INVINCIBLE",
        "NativeHash.SET_PED_ARMOUR",
        "HealthCheat",
        "GodModeCheat",
        "ArmourCheat",
        "ArmorCheat",
    ];

    private static readonly string[] NativeDbHealthPatterns =
    [
        "SET_ENTITY_HEALTH",
        "SET_ENTITY_INVINCIBLE",
        "SET_PED_ARMOUR",
        "SET_ENTITY_MAX_HEALTH",
        "SET_PED_MAX_HEALTH",
        "GET_ENTITY_HEALTH",
        "GET_PED_ARMOUR",
        "NETWORK_REQUEST_CONTROL_OF_ENTITY",
        "health_bypass_native",
        "armor_native_exploit",
        "armour_native_exploit",
        "native_health_override",
        "native_godmode",
        "native_invincible",
        "nativedb exploit",
        "nativedb health",
        "nativedb armor",
        "nativedb armour",
        "nativedb godmode",
        "health native ragemp",
        "armor native ragemp",
        "ped health native",
        "entity health native",
        "SET_PLAYER_INVINCIBLE",
    ];

    private static readonly string[] DiscordHealthKeywords =
    [
        "ragemp health hack",
        "health hack ragemp",
        "god mode ragemp",
        "godmode ragemp",
        "armor hack ragemp",
        "armour hack ragemp",
        "health cheat ragemp",
        "armor cheat ragemp",
        "ragemp godmode",
        "ragemp immortal",
        "ragemp invincible",
        "ragemp no damage",
        "ragemp health cheat",
        "ragemp armor cheat",
        "unlimited health ragemp",
        "infinite health ragemp",
        "max health ragemp",
        "health bypass ragemp",
        "health exploit ragemp",
        "armor exploit ragemp",
        "ragemp god mode",
        "ragemp full health",
        "ragemp health set",
        "ragemp sethealth",
        "ragemp setarmour",
        "ragemp setarmor",
        "setHealth ragemp",
        "setArmour ragemp",
        "ragemp ped health",
        "ragemp player health",
        "ragemp health override",
        "ragemp armor override",
        "ragemp immortal mode",
        "ragemp invincible hack",
        "ragemp nodamage",
        "ragemp damage bypass",
        "ragemp health inject",
        "ragemp armor inject",
    ];

    private static readonly string[] HealthHackRegistryKeys =
    [
        @"SOFTWARE\RageMP\HealthHack",
        @"SOFTWARE\RageMP\Health Hack",
        @"SOFTWARE\GodModeRageMP",
        @"SOFTWARE\HealthHackRageMP",
        @"SOFTWARE\RageMPGodMode",
        @"SOFTWARE\RageMPHealthHack",
        @"SOFTWARE\RageMPArmourHack",
        @"SOFTWARE\RageMPArmorHack",
        @"SOFTWARE\RageMPImmortal",
        @"SOFTWARE\RageMPInvincible",
        @"SOFTWARE\RageMPHealthBypass",
        @"SOFTWARE\HealthBypassRageMP",
        @"SOFTWARE\ArmorHackRageMP",
        @"SOFTWARE\ArmourHackRageMP",
        @"SOFTWARE\GodModeRage",
        @"SOFTWARE\HealthHackRage",
        @"SOFTWARE\ImmortalRageMP",
        @"SOFTWARE\InvincibleRageMP",
        @"SOFTWARE\NoDamageRageMP",
        @"SOFTWARE\FullHealthRageMP",
        @"SOFTWARE\RageMPNoDamage",
        @"SOFTWARE\RageMPFullHealth",
        @"SOFTWARE\RageMPMaxHealth",
        @"SOFTWARE\RageMPInfiniteHealth",
        @"SOFTWARE\RageMP\GodMode",
        @"SOFTWARE\RageMP\ArmorHack",
        @"SOFTWARE\RageMP\ArmourHack",
        @"SOFTWARE\RageMP\Immortal",
        @"SOFTWARE\RageMP\NoDamage",
        @"SOFTWARE\RageMP\FullHealth",
    ];

    private static readonly string[] HealthHackUserAssistNames =
    [
        "healthhack ragemp",
        "health hack ragemp",
        "godmode ragemp",
        "god mode ragemp",
        "armor hack ragemp",
        "armour hack ragemp",
        "health cheat ragemp",
        "immortal ragemp",
        "invincible ragemp",
        "ragemp health",
        "ragemp godmode",
        "ragemp armor",
        "ragemp armour",
        "ragemp immortal",
        "ragemp invincible",
        "ragemp health hack",
        "ragemp armor hack",
        "ragemp godmode hack",
        "health bypass ragemp",
        "ragemp health bypass",
        "healthhack",
        "godmode hack",
        "armor hack",
        "armour hack",
        "health_hack_ragemp",
        "godmode_ragemp",
        "armor_hack_ragemp",
        "immortal_ragemp",
        "health_bypass_ragemp",
        "full_health_ragemp",
        "healthhack_ragemp",
        "health_cheat_ragemp",
        "armor_cheat_ragemp",
        "ragemp_health",
        "ragemp_godmode",
        "ragemp_armor",
        "ragemp_immortal",
        "ragemp_invincible",
        "ragemp_health_hack",
        "ragemp_armor_hack",
        "nodamage_ragemp",
        "no_damage_ragemp",
        "full_health",
        "max_health",
        "infinite_health",
    ];

    private static readonly string[] HealthHackPackageNames =
    [
        "healthhack",
        "health-hack",
        "health_hack",
        "godmode",
        "god-mode",
        "god_mode",
        "armorhack",
        "armor-hack",
        "armor_hack",
        "armourhack",
        "armour-hack",
        "armour_hack",
        "immortal",
        "immortal-hack",
        "immortal_hack",
        "invincible",
        "invincible-hack",
        "fullhealth",
        "full-health",
        "full_health",
        "maxhealth",
        "max-health",
        "max_health",
        "infinitehealth",
        "infinite-health",
        "infinite_health",
        "healthbypass",
        "health-bypass",
        "health_bypass",
        "nodamage",
        "no-damage",
        "no_damage",
        "damagebbypass",
        "damage-bypass",
        "damage_bypass",
        "healthcheat",
        "health-cheat",
        "health_cheat",
        "armorcheat",
        "armor-cheat",
        "armor_cheat",
        "ragemp-health",
        "ragemp_health",
        "ragemp-godmode",
        "ragemp_godmode",
        "ragemp-armor",
        "ragemp_armor",
        "ragemp-immortal",
        "ragemp_immortal",
    ];

    private static readonly string[] CEFCacheHealthKeywords =
    [
        "healthhack",
        "health_hack",
        "godmode",
        "god_mode",
        "armor_hack",
        "armorhack",
        "armour_hack",
        "immortal_ragemp",
        "health_bypass",
        "health_override",
        "setHealth",
        "setArmour",
        "setArmor",
        "mp.players.local.health",
        "mp.players.local.armour",
        "setEntityInvincible",
        "setEntityHealth",
        "player_health_hack",
        "player_armor_hack",
        "godmode_payload",
        "health_payload",
        "armor_payload",
        "ragemp_health_cef",
        "ragemp_godmode_cef",
        "cef_health_exploit",
        "cef_godmode_exploit",
        "health_cheat_payload",
        "armor_cheat_payload",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckHealthHackFiles(ctx, ct),
            CheckHealthHackDlls(ctx, ct),
            CheckHealthHackConfigArtifacts(ctx, ct),
            CheckHealthHackDownloadArtifacts(ctx, ct),
            CheckRageMPClientLogsForHealthHack(ctx, ct),
            CheckRageMPClientSideJavaScriptFiles(ctx, ct),
            CheckRageMPClientSideCSharpFiles(ctx, ct),
            CheckHealthHackPackageFolders(ctx, ct),
            CheckCEFCacheForHealthPayloads(ctx, ct),
            CheckTempFilesForHealthInjection(ctx, ct),
            CheckPrefetchForHealthHackExecutables(ctx, ct),
            CheckRegistryForHealthHackArtifacts(ctx, ct),
            CheckUserAssistForHealthHackLaunchers(ctx, ct),
            CheckMuiCacheForHealthHackExecutables(ctx, ct),
            CheckDiscordCacheForHealthHackKeywords(ctx, ct),
            CheckNativeDbHealthExploitPatterns(ctx, ct),
            CheckRecentDocumentsForHealthHack(ctx, ct),
            CheckInstalledSoftwareForHealthHack(ctx, ct)
        );
    }

    private Task CheckHealthHackFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(RageMPDataPaths)
        {
            AppData,
            LocalAppData,
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(LocalAppData, "Temp"),
            Path.Combine(UserProfile, "Documents"),
        };

        var healthFileGlobs = new[]
        {
            "healthhack_ragemp*",
            "health_cheat_ragemp*",
            "armor_hack_ragemp*",
            "armour_hack_ragemp*",
            "godmode_ragemp*",
            "immortal_ragemp*",
            "health_bypass_ragemp*",
            "full_health_ragemp*",
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var fnLower = fn.ToLowerInvariant();

                    bool isNameMatch = HealthHackExecutables.Any(k =>
                        fn.Equals(k, StringComparison.OrdinalIgnoreCase));

                    bool isGlobMatch = !isNameMatch && (
                        fnLower.StartsWith("healthhack_ragemp", StringComparison.OrdinalIgnoreCase) ||
                        fnLower.StartsWith("health_cheat_ragemp", StringComparison.OrdinalIgnoreCase) ||
                        fnLower.StartsWith("armor_hack_ragemp", StringComparison.OrdinalIgnoreCase) ||
                        fnLower.StartsWith("armour_hack_ragemp", StringComparison.OrdinalIgnoreCase) ||
                        fnLower.StartsWith("godmode_ragemp", StringComparison.OrdinalIgnoreCase) ||
                        fnLower.StartsWith("immortal_ragemp", StringComparison.OrdinalIgnoreCase) ||
                        fnLower.StartsWith("health_bypass_ragemp", StringComparison.OrdinalIgnoreCase) ||
                        fnLower.StartsWith("full_health_ragemp", StringComparison.OrdinalIgnoreCase));

                    if (isNameMatch || isGlobMatch)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP health hack executable: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known RageMP health/armor hack executable '{fn}' found on disk. " +
                                     "This tool is used to set player health or armor to maximum values, enable god mode, " +
                                     "or make the player invincible on RageMP servers.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckHealthHackDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(RageMPDataPaths)
        {
            AppData,
            LocalAppData,
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(LocalAppData, "Temp"),
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (HealthHackDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP health/armor hack DLL: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known RageMP health or armor hack DLL '{fn}' found on disk. " +
                                     "These DLLs are injected into the GTA:V or RageMP process to override player health, " +
                                     "armor values, or entity invincibility flags using native memory manipulation.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckHealthHackConfigArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(RageMPDataPaths)
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(LocalAppData, "Temp"),
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);

                    if (!HealthHackConfigFiles.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    ctx.IncrementFiles();
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP health hack config file: {fn}",
                        Risk = RiskLevel.High,
                        Location = Path.GetDirectoryName(file) ?? dir,
                        FileName = fn,
                        Reason = $"Health or armor hack configuration file '{fn}' found. " +
                                 "These files contain memory offsets, GTA:V native function addresses, or cheat feature settings " +
                                 "used by RageMP health hack tools to locate and override health and armor values in memory.",
                        Detail = $"Path: {file} | Size: {content.Length} chars",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckHealthHackDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Downloads"),
            Desktop,
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (HealthHackDownloadArtifacts.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP health hack download artifact: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"RageMP health/godmode/armor hack archive or installer '{fn}' found in download area. " +
                                     "This package was downloaded and is a known health hack tool distribution for RageMP.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRageMPClientLogsForHealthHack(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logSearchRoots = new List<string>(RageMPDataPaths)
        {
            AppData,
            LocalAppData,
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var root in logSearchRoots)
        {
            if (!Directory.Exists(root)) continue;
            IEnumerable<string> logFiles;
            try
            {
                logFiles = Directory.EnumerateFiles(root, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.txt", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var logFile in logFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                foreach (var pattern in ClientLogHealthKeywords)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP log: health/godmode hack artifact",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(logFile) ?? root,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"Log file contains health/armor/godmode hack keyword '{pattern}'. " +
                                     "Client-side and server-side logs record cheat tool startup messages, " +
                                     "health override events, and godmode activation confirmations.",
                            Detail = $"Log: {logFile} | Keyword: {pattern}",
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckRageMPClientSideJavaScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scriptSearchRoots = new List<string>();
        foreach (var root in RageMPDataPaths)
        {
            scriptSearchRoots.Add(root);
            scriptSearchRoots.Add(Path.Combine(root, "packages"));
            scriptSearchRoots.Add(Path.Combine(root, "client_packages"));
            scriptSearchRoots.Add(Path.Combine(root, "plugins"));
        }

        var jsExtensions = new[] { "*.js", "*.mjs", "*.cjs", "*.ts" };

        foreach (var searchRoot in scriptSearchRoots)
        {
            if (!Directory.Exists(searchRoot)) continue;
            foreach (var ext in jsExtensions)
            {
                IEnumerable<string> jsFiles;
                try
                {
                    jsFiles = Directory.EnumerateFiles(searchRoot, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var jsFile in jsFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    string content;
                    try
                    {
                        using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    int hits = 0;
                    var matchedPatterns = new List<string>();
                    foreach (var pattern in JavaScriptHealthPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            hits++;
                            matchedPatterns.Add(pattern);
                        }
                    }

                    if (hits >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP JS health hack script: {Path.GetFileName(jsFile)}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(jsFile) ?? searchRoot,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"RageMP client-side JavaScript file contains {hits} health/armor/godmode exploit pattern(s): " +
                                     $"{string.Join(", ", matchedPatterns.Take(5))}. " +
                                     "These patterns indicate a script that directly sets player health, armour, or invincibility " +
                                     "through RageMP's client-side API or native function calls.",
                            Detail = $"File: {jsFile} | Matched: {string.Join(" | ", matchedPatterns)}",
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckRageMPClientSideCSharpFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new List<string>();
        foreach (var root in RageMPDataPaths)
        {
            searchRoots.Add(root);
            searchRoots.Add(Path.Combine(root, "plugins"));
            searchRoots.Add(Path.Combine(root, "scripts"));
        }

        foreach (var searchRoot in searchRoots)
        {
            if (!Directory.Exists(searchRoot)) continue;
            IEnumerable<string> csFiles;
            try
            {
                csFiles = Directory.EnumerateFiles(searchRoot, "*.cs", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var csFile in csFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(csFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                int hits = 0;
                var matchedPatterns = new List<string>();
                foreach (var pattern in CSharpHealthPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        hits++;
                        matchedPatterns.Add(pattern);
                    }
                }

                if (hits >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP C# plugin: health/godmode exploit: {Path.GetFileName(csFile)}",
                        Risk = RiskLevel.High,
                        Location = Path.GetDirectoryName(csFile) ?? searchRoot,
                        FileName = Path.GetFileName(csFile),
                        Reason = $"RageMP C# plugin source file contains {hits} health/armor/godmode exploit pattern(s): " +
                                 $"{string.Join(", ", matchedPatterns.Take(5))}. " +
                                 "C# plugins in RageMP run as server-side or client-side code with direct access to " +
                                 "native GTA:V functions for entity health, armor, and invincibility manipulation.",
                        Detail = $"File: {csFile} | Matched: {string.Join(" | ", matchedPatterns)}",
                    });
                }
            }
        }
    }, ct);

    private Task CheckHealthHackPackageFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var rageMPDir in RageMPDataPaths)
        {
            var packageRoots = new[]
            {
                Path.Combine(rageMPDir, "packages"),
                Path.Combine(rageMPDir, "client_packages"),
                Path.Combine(rageMPDir, "plugins"),
            };

            foreach (var pkgRoot in packageRoots)
            {
                if (!Directory.Exists(pkgRoot)) continue;
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(pkgRoot, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var folderName = Path.GetFileName(dir);
                        if (HealthHackPackageNames.Any(k =>
                            folderName.Equals(k, StringComparison.OrdinalIgnoreCase) ||
                            folderName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"RageMP health hack package folder: {folderName}",
                                Risk = RiskLevel.High,
                                Location = pkgRoot,
                                FileName = folderName,
                                Reason = $"RageMP package/plugin folder '{folderName}' matches a known health or godmode hack resource name. " +
                                         "RageMP packages run as privileged client-side code and can directly invoke GTA:V natives " +
                                         "to set entity health, armor, and invincibility without server validation.",
                                Detail = $"Folder: {dir}",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        var downloadsDir = Path.Combine(UserProfile, "Downloads");
        if (Directory.Exists(downloadsDir))
        {
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(downloadsDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var folderName = Path.GetFileName(dir);
                    bool isHealthHack = HealthHackPackageNames.Any(k =>
                        folderName.Equals(k, StringComparison.OrdinalIgnoreCase)) ||
                        (folderName.Contains("ragemp", StringComparison.OrdinalIgnoreCase) &&
                         (folderName.Contains("health", StringComparison.OrdinalIgnoreCase) ||
                          folderName.Contains("godmode", StringComparison.OrdinalIgnoreCase) ||
                          folderName.Contains("armor", StringComparison.OrdinalIgnoreCase) ||
                          folderName.Contains("armour", StringComparison.OrdinalIgnoreCase) ||
                          folderName.Contains("immortal", StringComparison.OrdinalIgnoreCase) ||
                          folderName.Contains("invincible", StringComparison.OrdinalIgnoreCase)));

                    if (isHealthHack)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP health hack folder in Downloads: {folderName}",
                            Risk = RiskLevel.High,
                            Location = downloadsDir,
                            FileName = folderName,
                            Reason = $"Downloads folder contains a directory '{folderName}' matching RageMP health hack naming patterns. " +
                                     "This indicates the user downloaded a health/godmode/armor hack tool package for RageMP.",
                            Detail = $"Folder: {dir}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckCEFCacheForHealthPayloads(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var cefCacheDirs = new List<string>();
        foreach (var root in RageMPDataPaths)
        {
            cefCacheDirs.Add(Path.Combine(root, "CEF"));
            cefCacheDirs.Add(Path.Combine(root, "cef"));
            cefCacheDirs.Add(Path.Combine(root, "cache", "CEF"));
            cefCacheDirs.Add(Path.Combine(root, "cache", "cef"));
            cefCacheDirs.Add(Path.Combine(root, "data", "CEF"));
            cefCacheDirs.Add(Path.Combine(root, "browser"));
            cefCacheDirs.Add(Path.Combine(root, "browser_cache"));
        }

        foreach (var cefDir in cefCacheDirs)
        {
            if (!Directory.Exists(cefDir)) continue;
            IEnumerable<string> cacheFiles;
            try
            {
                cacheFiles = Directory.EnumerateFiles(cefDir, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f).ToLowerInvariant();
                        return ext is ".js" or ".html" or ".htm" or ".json" or ".dat" or "" or ".cache" or ".log";
                    });
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var cacheFile in cacheFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                int hits = 0;
                var matched = new List<string>();
                foreach (var keyword in CEFCacheHealthKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        hits++;
                        matched.Add(keyword);
                    }
                }

                if (hits >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP CEF cache: health hack payload",
                        Risk = RiskLevel.Medium,
                        Location = Path.GetDirectoryName(cacheFile) ?? cefDir,
                        FileName = Path.GetFileName(cacheFile),
                        Reason = $"RageMP CEF browser cache file contains {hits} health/godmode/armor hack pattern(s): " +
                                 $"{string.Join(", ", matched.Take(5))}. " +
                                 "CEF (Chromium Embedded Framework) in RageMP can execute JavaScript that interacts with " +
                                 "game natives; cached health exploit payloads indicate prior CEF-based cheat delivery.",
                        Detail = $"File: {cacheFile} | Keywords: {string.Join(" | ", matched)}",
                    });
                }
            }
        }
    }, ct);

    private Task CheckTempFilesForHealthInjection(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var tempDirs = new[]
        {
            TempPath,
            Path.Combine(LocalAppData, "Temp"),
        };

        foreach (var tempDir in tempDirs)
        {
            if (!Directory.Exists(tempDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(tempDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var fnLower = fn.ToLowerInvariant();

                    bool isHealthCheat =
                        HealthHackExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)) ||
                        HealthHackDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)) ||
                        HealthHackDownloadArtifacts.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)) ||
                        fnLower.Contains("healthhack") ||
                        fnLower.Contains("health_hack") ||
                        fnLower.Contains("godmode") ||
                        fnLower.Contains("armor_hack") ||
                        fnLower.Contains("armour_hack") ||
                        fnLower.Contains("immortal_ragemp") ||
                        fnLower.Contains("health_bypass") ||
                        fnLower.Contains("full_health") ||
                        fnLower.Contains("ragemp_health") ||
                        fnLower.Contains("ragemp_godmode") ||
                        fnLower.Contains("ragemp_armor") ||
                        fnLower.Contains("ragemp_armour");

                    if (isHealthCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP health hack artifact in Temp: {fn}",
                            Risk = RiskLevel.High,
                            Location = tempDir,
                            FileName = fn,
                            Reason = $"Health/godmode/armor hack artifact '{fn}' found in system Temp directory. " +
                                     "Cheat tools often extract or stage their injection components in Temp directories " +
                                     "as part of the loading process before injecting into the RageMP process.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        foreach (var tempDir in tempDirs)
        {
            if (!Directory.Exists(tempDir)) continue;
            try
            {
                foreach (var subDir in Directory.EnumerateDirectories(tempDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var dirName = Path.GetFileName(subDir).ToLowerInvariant();
                    bool isHealthCheat =
                        dirName.Contains("healthhack") ||
                        dirName.Contains("health_hack") ||
                        dirName.Contains("godmode") ||
                        dirName.Contains("armor_hack") ||
                        dirName.Contains("immortal_ragemp") ||
                        dirName.Contains("ragemp_health") ||
                        dirName.Contains("ragemp_godmode") ||
                        dirName.Contains("health_inject") ||
                        dirName.Contains("health_bypass");

                    if (isHealthCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP health hack temp directory: {Path.GetFileName(subDir)}",
                            Risk = RiskLevel.High,
                            Location = tempDir,
                            FileName = Path.GetFileName(subDir),
                            Reason = $"Temp subdirectory '{Path.GetFileName(subDir)}' matches RageMP health/godmode hack naming. " +
                                     "Cheat loaders often create named temp directories to stage injection payloads.",
                            Detail = $"Directory: {subDir}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPrefetchForHealthHackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var pfFile in Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var pfName = Path.GetFileNameWithoutExtension(pfFile);

                bool isHealthHack =
                    HealthHackExecutables.Any(k =>
                        pfName.StartsWith(k.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase)) ||
                    pfName.Contains("HEALTHHACK", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("HEALTH_HACK", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("GODMODE", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("ARMORHACK", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("ARMOR_HACK", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("ARMOURHACK", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("ARMOUR_HACK", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("IMMORTAL_RAGEMP", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("HEALTH_BYPASS", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("FULL_HEALTH", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("RAGEMP_HEALTH", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("RAGEMP_GODMODE", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("RAGEMP_ARMOR", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("NODAMAGE", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("NO_DAMAGE", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("INVINCIBLE", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("IMMORTAL", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("FULLHEALTH", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("MAXHEALTH", StringComparison.OrdinalIgnoreCase) ||
                    pfName.Contains("INFINITEHEALTH", StringComparison.OrdinalIgnoreCase);

                if (isHealthHack)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Prefetch: RageMP health hack executed: {Path.GetFileName(pfFile)}",
                        Risk = RiskLevel.High,
                        Location = prefetchDir,
                        FileName = Path.GetFileName(pfFile),
                        Reason = $"Windows Prefetch file '{Path.GetFileName(pfFile)}' indicates past execution of a RageMP health or godmode hack executable. " +
                                 "Prefetch files are created by Windows for each launched executable and persist after the file is deleted, " +
                                 "providing reliable forensic evidence of prior cheat tool execution.",
                        Detail = $"Prefetch: {pfFile}",
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckRegistryForHealthHackArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var keyPath in HealthHackRegistryKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP health hack registry key: {keyPath}",
                        Risk = RiskLevel.High,
                        Location = @"HKCU\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"Registry key 'HKCU\\{keyPath}' was written by a RageMP health hack, godmode, or armor hack tool. " +
                                 "These registry keys store cheat configuration, license keys, or installation markers " +
                                 "left behind after the tool was used.",
                        Detail = $"Key: HKCU\\{keyPath}",
                    });
                }
            }
            catch (Exception) { }

            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP health hack registry key (HKLM): {keyPath}",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"System-level registry key 'HKLM\\{keyPath}' was written by a RageMP health hack tool with administrator privileges. " +
                                 "HKLM keys indicate a persistent or privileged cheat installation that affects all users.",
                        Detail = $"Key: HKLM\\{keyPath}",
                    });
                }
            }
            catch (Exception) { }
        }

        var runKeyPaths = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
        };

        foreach (var (runPath, hive, hiveName) in runKeyPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var run = hive.OpenSubKey(runPath);
                if (run == null) continue;
                foreach (var valName in run.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var data = run.GetValue(valName)?.ToString() ?? string.Empty;
                    var dataLower = data.ToLowerInvariant();
                    bool isHealthCheat =
                        HealthHackExecutables.Any(k => dataLower.Contains(k.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase)) ||
                        dataLower.Contains("healthhack") ||
                        dataLower.Contains("health hack") ||
                        dataLower.Contains("health_hack") ||
                        dataLower.Contains("godmode ragemp") ||
                        dataLower.Contains("godmode_ragemp") ||
                        dataLower.Contains("armor hack ragemp") ||
                        dataLower.Contains("armor_hack_ragemp") ||
                        dataLower.Contains("immortal ragemp") ||
                        dataLower.Contains("health bypass") ||
                        dataLower.Contains("health_bypass") ||
                        dataLower.Contains("ragemp_health") ||
                        dataLower.Contains("ragemp_godmode") ||
                        dataLower.Contains("ragemp_armor");

                    if (isHealthCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP health hack autostart (Run key)",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{runPath}",
                            FileName = valName,
                            Reason = $"Windows Run registry key '{valName}' references a RageMP health/godmode/armor hack tool: '{data}'. " +
                                     "Autostart Run keys indicate the cheat was configured for persistent launch at every user logon.",
                            Detail = $"Key: {hiveName}\\{runPath} | Value: {valName} = {data}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }

        var hkcuSoftwareKeywords = new[]
        {
            "healthhack", "health_hack", "godmode", "armorhack", "armor_hack",
            "armourhack", "armour_hack", "immortal_ragemp", "health_bypass",
            "full_health_ragemp", "ragemp_health", "ragemp_godmode", "ragemp_armor",
            "nodamage_ragemp", "invincible_ragemp", "ragemp_invincible",
        };

        try
        {
            ctx.IncrementRegistryKeys();
            using var softKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE");
            if (softKey != null)
            {
                foreach (var subName in softKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    if (hkcuSoftwareKeywords.Any(k => subName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP health hack HKCU SOFTWARE key: {subName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\SOFTWARE\{subName}",
                            FileName = subName,
                            Reason = $"HKCU\\SOFTWARE\\{subName} matches a known RageMP health/godmode/armor hack tool name. " +
                                     "Cheat tools write configuration or license data under HKCU\\Software during installation or first run.",
                            Detail = $"Key: HKCU\\SOFTWARE\\{subName}",
                        });
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckUserAssistForHealthHackLaunchers(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string uaPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            using var ua = Registry.CurrentUser.OpenSubKey(uaPath);
            if (ua == null) return;

            foreach (var guidName in ua.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var count = Registry.CurrentUser.OpenSubKey($@"{uaPath}\{guidName}\Count");
                    if (count == null) continue;

                    foreach (var valName in count.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        var decoded = Rot13Decode(valName);
                        var decodedLower = decoded.ToLowerInvariant();

                        bool isHealthHack =
                            HealthHackUserAssistNames.Any(n => decodedLower.Contains(n, StringComparison.OrdinalIgnoreCase)) ||
                            HealthHackExecutables.Any(k => decodedLower.Contains(k.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));

                        if (isHealthHack)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP health hack execution (UserAssist)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = decoded,
                                Reason = $"Windows UserAssist registry records execution of a RageMP health/godmode/armor hack: '{decoded}'. " +
                                         "UserAssist stores execution history for every GUI program launched by the user and is a " +
                                         "reliable forensic indicator that persists even after the executable is deleted.",
                                Detail = $"ROT13 decoded: {decoded} | Raw: {valName}",
                            });
                        }
                    }
                }
                catch (Exception) { }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckMuiCacheForHealthHackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var muiPaths = new[]
        {
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache",
        };

        foreach (var muiPath in muiPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var mui = Registry.CurrentUser.OpenSubKey(muiPath);
                if (mui == null) continue;

                foreach (var valName in mui.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var valLower = valName.ToLowerInvariant();

                    bool isHealthHack =
                        HealthHackExecutables.Any(k => valLower.Contains(k.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase)) ||
                        HealthHackUserAssistNames.Any(n => valLower.Contains(n, StringComparison.OrdinalIgnoreCase)) ||
                        valLower.Contains("healthhack") ||
                        valLower.Contains("health_hack") ||
                        valLower.Contains("godmode ragemp") ||
                        valLower.Contains("godmode_ragemp") ||
                        valLower.Contains("armor hack ragemp") ||
                        valLower.Contains("armor_hack_ragemp") ||
                        valLower.Contains("immortal_ragemp") ||
                        valLower.Contains("health_bypass_ragemp") ||
                        valLower.Contains("ragemp_health") ||
                        valLower.Contains("ragemp_godmode") ||
                        valLower.Contains("ragemp_armor");

                    if (isHealthHack)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP health hack execution (MUICache)",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = $"Windows MUICache records that a RageMP health/godmode/armor hack executable was run: '{valName}'. " +
                                     "MUICache stores the display name of every EXE ever executed on the system and " +
                                     "persists as a forensic artifact even after the file is removed.",
                            Detail = $"MUICache entry: {valName}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckDiscordCacheForHealthHackKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var discordCacheDirs = new List<string>();
        foreach (var basePath in new[] { AppData, LocalAppData })
        {
            discordCacheDirs.Add(Path.Combine(basePath, "discord", "Cache"));
            discordCacheDirs.Add(Path.Combine(basePath, "discord", "Cache", "Cache_Data"));
            discordCacheDirs.Add(Path.Combine(basePath, "discord", "storage"));
            discordCacheDirs.Add(Path.Combine(basePath, "discordptb", "Cache"));
            discordCacheDirs.Add(Path.Combine(basePath, "discordptb", "Cache", "Cache_Data"));
            discordCacheDirs.Add(Path.Combine(basePath, "discordcanary", "Cache"));
            discordCacheDirs.Add(Path.Combine(basePath, "discordcanary", "Cache", "Cache_Data"));
        }

        foreach (var cacheDir in discordCacheDirs)
        {
            if (!Directory.Exists(cacheDir)) continue;
            IEnumerable<string> cacheFiles;
            try
            {
                cacheFiles = Directory.EnumerateFiles(cacheDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var cacheFile in cacheFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                foreach (var keyword in DiscordHealthKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord cache: RageMP health hack keyword",
                            Risk = RiskLevel.Medium,
                            Location = cacheDir,
                            FileName = Path.GetFileName(cacheFile),
                            Reason = $"Discord cache file contains RageMP health/godmode/armor hack keyword: '{keyword}'. " +
                                     "Discord cache preserves conversation history and file sharing artifacts. " +
                                     "Finding health hack keywords here indicates the user discussed, shared, or downloaded " +
                                     "health cheat tools via Discord.",
                            Detail = $"Cache file: {cacheFile} | Keyword: {keyword}",
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckNativeDbHealthExploitPatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scriptSearchRoots = new List<string>();
        foreach (var root in RageMPDataPaths)
        {
            scriptSearchRoots.Add(root);
            scriptSearchRoots.Add(Path.Combine(root, "packages"));
            scriptSearchRoots.Add(Path.Combine(root, "client_packages"));
            scriptSearchRoots.Add(Path.Combine(root, "plugins"));
            scriptSearchRoots.Add(Path.Combine(root, "scripts"));
        }

        var scriptExtensions = new[] { "*.js", "*.mjs", "*.ts", "*.cs", "*.txt", "*.json" };

        foreach (var searchRoot in scriptSearchRoots)
        {
            if (!Directory.Exists(searchRoot)) continue;
            foreach (var ext in scriptExtensions)
            {
                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(searchRoot, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    int hits = 0;
                    var matched = new List<string>();
                    foreach (var pattern in NativeDbHealthPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            hits++;
                            matched.Add(pattern);
                        }
                    }

                    if (hits >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP NativeDB health exploit patterns: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Medium,
                            Location = Path.GetDirectoryName(file) ?? searchRoot,
                            FileName = Path.GetFileName(file),
                            Reason = $"File contains {hits} GTA:V NativeDB function references used in health/armor/godmode exploits: " +
                                     $"{string.Join(", ", matched.Take(5))}. " +
                                     "These native function names (SET_ENTITY_HEALTH, SET_ENTITY_INVINCIBLE, SET_PED_ARMOUR, etc.) " +
                                     "are the underlying GTA:V game engine calls that health hacks invoke to override player stats.",
                            Detail = $"File: {file} | Patterns: {string.Join(" | ", matched)}",
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckRecentDocumentsForHealthHack(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDir = Path.Combine(AppData, "Microsoft", "Windows", "Recent");
        if (!Directory.Exists(recentDir)) return;

        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recentDir, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var baseName = Path.GetFileNameWithoutExtension(lnk);
                var baseNameLower = baseName.ToLowerInvariant();

                bool isHealthHack =
                    HealthHackExecutables.Any(k =>
                        baseNameLower.Contains(k.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase)) ||
                    HealthHackDownloadArtifacts.Any(a =>
                        baseNameLower.Contains(
                            a.Replace(".zip", "").Replace(".rar", "").Replace(".7z", "").Replace(".exe", ""),
                            StringComparison.OrdinalIgnoreCase)) ||
                    baseNameLower.Contains("healthhack") ||
                    baseNameLower.Contains("health_hack") ||
                    baseNameLower.Contains("godmode_ragemp") ||
                    baseNameLower.Contains("godmode ragemp") ||
                    baseNameLower.Contains("armor_hack_ragemp") ||
                    baseNameLower.Contains("armor hack ragemp") ||
                    baseNameLower.Contains("immortal_ragemp") ||
                    baseNameLower.Contains("immortal ragemp") ||
                    baseNameLower.Contains("health_bypass") ||
                    baseNameLower.Contains("full_health_ragemp");

                if (isHealthHack)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Recent Documents: RageMP health hack artifact: {baseName}",
                        Risk = RiskLevel.Medium,
                        Location = recentDir,
                        FileName = Path.GetFileName(lnk),
                        Reason = $"Windows Recent Documents shortcut '{baseName}' points to a RageMP health/godmode/armor hack file. " +
                                 "Recent Documents links are automatically created when a file is opened and persist as forensic evidence " +
                                 "of user interaction with cheat files.",
                        Detail = $"Shortcut: {lnk}",
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckInstalledSoftwareForHealthHack(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        var cheatKeywords = new[]
        {
            "health hack", "healthhack", "health_hack",
            "godmode", "god mode",
            "armor hack", "armorhack", "armor_hack",
            "armour hack", "armourhack", "armour_hack",
            "immortal ragemp", "immortal_ragemp",
            "health bypass", "health_bypass",
            "full health", "full_health",
            "ragemp health", "ragemp_health",
            "ragemp godmode", "ragemp_godmode",
            "ragemp armor", "ragemp_armor",
            "ragemp immortal", "ragemp_immortal",
            "ragemp invincible",
            "nodamage ragemp", "no damage ragemp",
            "ragemp no damage",
            "infinite health", "max health",
            "unlimited health",
        };

        foreach (var uninstallPath in uninstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var uninst = Registry.LocalMachine.OpenSubKey(uninstallPath);
                if (uninst == null) continue;
                foreach (var subKeyName in uninst.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var sub = uninst.OpenSubKey(subKeyName);
                        if (sub == null) continue;
                        var displayName = sub.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var installLocation = sub.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                        var displayNameLower = displayName.ToLowerInvariant();
                        var installLocationLower = installLocation.ToLowerInvariant();

                        bool isHealthCheat =
                            cheatKeywords.Any(k => displayNameLower.Contains(k, StringComparison.OrdinalIgnoreCase)) ||
                            cheatKeywords.Any(k => installLocationLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (isHealthCheat)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Installed software: RageMP health hack: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"Windows uninstall registry records a formally installed RageMP health/godmode/armor hack: '{displayName}'. " +
                                         "Formal installation records prove the cheat tool was deliberately installed on this system.",
                                Detail = $"Key: {subKeyName} | DisplayName: {displayName} | Location: {installLocation}",
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private static string Rot13Decode(string s)
    {
        return new string(s.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
