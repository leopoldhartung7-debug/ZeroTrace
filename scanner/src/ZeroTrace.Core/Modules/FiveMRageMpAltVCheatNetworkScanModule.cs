using System.Text.RegularExpressions;
using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMRageMpAltVCheatNetworkScanModule : IScanModule
{
    public string Name => "FiveM / RageMP / alt:V Network Cheat Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    private const string ModuleName = "FiveMRageMpAltVCheatNetworkScan";

    // ─── FiveM packet spoofing binary names ─────────────────────────────────
    private static readonly string[] FiveMPacketSpooferExeNames =
    {
        "fivem_packet_spoof.exe", "fivempacketspoof.exe",
        "fivem_spoofer.exe", "fivemspoofer.exe",
        "fivem_bypass.exe", "fivembypass.exe",
        "fivem_patch.exe", "fivempatch.exe",
        "fivem_hack.exe", "fivemhack.exe",
        "fivem_inject.exe", "fiveminject.exe",
        "fivem_loader.exe", "fivemloader.exe",
        "net_obj_spoof.exe", "netobjspoof.exe",
        "playerappearance_spoof.exe",
        "netcull_bypass.exe", "netcullbypass.exe",
        "fivem_net_bypass.exe", "citizenfx_bypass.exe",
    };

    private static readonly string[] FiveMCheatDllNames =
    {
        "fivem_cheat.dll", "fivemcheat.dll",
        "fivem_bypass.dll", "fivembypass.dll",
        "fivem_inject.dll", "fiveminject.dll",
        "fivem_hack.dll", "fivemhack.dll",
        "citizenfx_hook.dll", "net_obj_hook.dll",
        "netcull_patch.dll",
    };

    // ─── FiveM modded builds ─────────────────────────────────────────────────
    private static readonly string[] FiveMModdedBuildNames =
    {
        "FiveM_patch.exe", "FiveM_bypass.exe",
        "FiveM_cracked.exe", "FiveM_modded.exe",
        "FiveM_unlocked.exe", "FiveM_cheats.exe",
        "FiveM_hack.exe", "FiveM_inject.exe",
    };

    // ─── FiveM banned resource names ────────────────────────────────────────
    private static readonly string[] FiveMBannedResourceNames =
    {
        "immortal", "godmode_bypass", "money_dupe", "vehicle_spawner_bypass",
        "tp_all", "freeze_all", "kill_all", "player_blips_bypass",
        "anticheat_bypass", "bans_bypass", "admin_bypass",
        "esx_exploit", "qbcore_exploit", "antiban",
        "money_hack", "vehicle_dupe", "casino_hack",
        "resource_monitor_bypass", "txadmin_bypass",
        "health_bypass", "armor_bypass", "wanted_clear",
        "weapon_bypass", "coords_spoof", "nametag_bypass",
    };

    // ─── FiveM config cheat patterns (key=value) ────────────────────────────
    private static readonly string[] FiveMCheatConfigPatterns =
    {
        "spoofposition=true", "fakecoords=true", "bypassnetcull=true",
        "disableanticheat=true", "bypassanticheat=true",
        "spoofhealth=true", "spoofarmor=true",
        "netbypass=true", "netcull=false",
        "disablenetclip=true", "entitybypass=true",
        "fakeping=", "spoofping=",
        "disablenametags=true",
        "entityspawn_unlimited=true",
        "money_bypass=true",
    };

    // ─── FiveM Lua exploit patterns ──────────────────────────────────────────
    private static readonly string[] FiveMExploitLuaPatterns =
    {
        "triggerserverevent",
        "xplayer.addmoney",
        "xplayer.addbank",
        "setentityinvincible",
        "executecommand(\"god\")",
        "executecommand(\"noclip\")",
        "executecommand(\"heal\")",
        "networkoverridecrimeevidence",
        "setplayerinvincible",
        "addweapontoentity",
        "networkisplayeractive",
        "getplayerped",
        "setentitycoords",
        "networkresurrectlocalplayer",
        "clearplayerwantedlevel",
        "networkrequestcontrolofentity",
        "setvehicleenginehealth",
        "setvehiclefuel",
        "networkobjectflags",
        "txsv_expl",
        "while true do triggerserverevent",
        "citizen.settimeout(0,",
    };

    // ─── FiveM ESX / QBCore trigger-flood patterns (regex) ──────────────────
    private static readonly string[] FiveMEsxQbExploitPatternStrings =
    {
        @"triggerserverevent.*addmoney.*[0-9]{6,}",
        @"triggerserverevent.*bank.*[0-9]{6,}",
        @"triggerserverevent.*cashout.*[0-9]{6,}",
        @"triggerserverevent.*setmoney",
        @"triggerserverevent.*giveitem",
        @"triggerserverevent.*additem",
        @"exports.*addmoney",
        @"triggerserverevent.*admin",
        @"triggerserverevent.*setcoords",
        @"triggerserverevent.*tp",
    };

    private static readonly Regex[] FiveMEsxQbExploitRegexes =
        FiveMEsxQbExploitPatternStrings
            .Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase))
            .ToArray();

    // ─── RageMP packet injection / cheat binaries ────────────────────────────
    private static readonly string[] RageMpCheatExeNames =
    {
        "rage_packet_inject.exe", "ragepacketinject.exe",
        "mp_packet_spoof.exe", "mppacketspoof.exe",
        "ragemp_bypass.exe", "ragempbypass.exe",
        "ragemp_hack.exe", "ragemphack.exe",
        "ragemp_teleport.exe", "ragempteleport.exe",
        "ragemp_money.exe", "ragempmoney.exe",
        "ragemp_loader.exe", "ragemploader.exe",
        "ragemp_inject.exe", "ragempinject.exe",
    };

    private static readonly string[] RageMpCheatDllNames =
    {
        "ragemp_bypass.dll", "ragemp_hook.dll",
        "ragemp_cheat.dll", "ragemphook.dll",
        "mp_cheat_bridge.dll", "rage_bridge.dll",
        "rage_inject.dll", "ragemp_inject.dll",
    };

    // ─── RageMP config cheat patterns ───────────────────────────────────────
    private static readonly string[] RageMpCheatConfigPatterns =
    {
        "teleport_via_packet=true",
        "position_spoof=true",
        "money_sync_exploit=true",
        "bypass_anticheat=true",
        "disable_netcheck=true",
        "fake_position=true",
        "enable_noclip=true",
        "godmode=true",
        "disable_collision=true",
        "unlimited_ammo=true",
        "speed_multiplier=",
        "fly_mode=true",
        "bypass_deathcheck=true",
    };

    // ─── alt:V exploit patterns (client-side JS) ─────────────────────────────
    private static readonly string[] AltVExploitJsPatterns =
    {
        "alt.emitserver",
        "alt.emitServer",
        "alt.setwaypointposition",
        "alt.setWaypointPosition",
        "native.setEntityCoords",
        "native.setentitycoords",
        "native.setPlayerInvincible",
        "native.setplayerinvincible",
        "native.addWeaponToEntity",
        "native.addweapontoentity",
        "native.setEntityHealth",
        "native.setentityhealth",
        "native.clearPlayerWantedLevel",
        "native.networkResurrectLocalPlayer",
        "alt.on(\"connectionComplete\"",
        "native.requestControlOfEntity",
        "setInterval.*alt.emitServer",
        "while.*alt.emitServer",
        "for.*alt.emitServer",
        "alt.game.invoke",
        "native.createVehicle",
        "native.explosion",
    };

    // ─── alt:V banned resource patterns ─────────────────────────────────────
    private static readonly string[] AltVBannedResourcePatterns =
    {
        "mass_spawn", "massspawn", "mass_entity_spawn",
        "player_list_dump", "playerlistdump", "dump_players",
        "godmode", "god_mode", "noclip", "no_clip",
        "esp_resource", "aimbot_resource",
        "money_hack", "moneyhack",
        "tp_all", "tpall", "teleport_all",
        "kill_all", "killall",
        "freeze_all", "freezeall",
        "crash_server", "crashserver",
        "explode_all", "explodeall",
        "bypass_ac", "bypassac",
    };

    // ─── Packet editor / traffic manipulation tools ──────────────────────────
    private static readonly string[] PacketEditorExeNames =
    {
        "packeteditor.exe", "packetsender.exe", "wpe_pro.exe",
        "wpepro.exe", "packet_editor.exe",
        "smartsniff.exe", "networkpacketsniffer.exe",
        "tcp_spoofer.exe", "tcpspoofer.exe",
        "udp_spoofer.exe", "udpspoofer.exe",
        "inject_packet.exe", "injectpacket.exe",
        "rawpacket.exe", "raw_packet.exe",
        "game_packet_editor.exe",
    };

    // ─── Packet capture file extensions ─────────────────────────────────────
    private static readonly string[] PcapExtensions =
    {
        ".pcap", ".pcapng", ".cap", ".pkt",
    };

    // ─── Game-related keywords for PCAP naming heuristic ────────────────────
    private static readonly string[] PcapGameKeywords =
    {
        "fivem", "ragemp", "altv", "alt-v", "gta", "cfx", "citizenfx",
    };

    // ─── Proxy / traffic relay script file names ─────────────────────────────
    private static readonly string[] ProxyScriptFileNames =
    {
        "game_proxy.py", "gta_proxy.py", "fivem_proxy.py",
        "ragemp_proxy.py", "altv_proxy.py",
        "game_relay.py", "tcp_relay.py", "udp_relay.py",
        "game_proxy.js", "gta_proxy.js", "fivem_proxy.js",
        "ragemp_proxy.js", "altv_proxy.js",
        "game_relay.js", "packet_relay.js",
        "proxy_server.py", "traffic_relay.py",
        "mitm_proxy.py", "game_mitm.py",
    };

    // ─── VPN / proxy config keywords indicating game-domain routing ──────────
    private static readonly string[] VpnGameDomainKeywords =
    {
        "cfx.re", "fivem.net", "rage.mp", "alt-mp.net",
        "citizenfx", "rockstargames.com", "socialclub",
    };

    // ─── Cheat config file extensions ────────────────────────────────────────
    private static readonly HashSet<string> ConfigExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cfg", ".ini", ".json", ".toml", ".yaml", ".yml", ".conf", ".config",
    };

    // ─── VPN directive keywords ───────────────────────────────────────────────
    private static readonly string[] VpnDirectiveKeywords =
    {
        "remote ", "server ", "route-nopull", "redirect-gateway",
        "socks-proxy", "http-proxy",
    };

    // ─── VPN config file extensions ──────────────────────────────────────────
    private static readonly HashSet<string> VpnConfigExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ovpn", ".conf", ".cfg", ".json",
    };

    // ─── Known-legitimate RageMP DLL names ──────────────────────────────────
    private static readonly HashSet<string> RageMpLegitDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "ragemp.dll", "ragemp-d.dll", "rage-mp.dll",
        "scripthookv.dll", "scripthookvdotnet.dll",
        "dinput8.dll", "dsound.dll", "version.dll",
    };

    // ─── Known-legitimate alt:V DLL names ───────────────────────────────────
    private static readonly HashSet<string> AltVLegitDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "altv.dll", "altv-client.dll", "altvjs.dll", "csharp-module.dll",
        "js-module.dll", "js-bytecode-module.dll", "dotnet-module.dll",
    };

    // ─── alt:V cheat keyword list (for DLL scanning) ─────────────────────────
    private static readonly string[] AltVCheatDllKeywords =
    {
        "cheat", "hack", "bypass", "inject", "exploit",
        "spoof", "aimbot", "esp", "wallhack", "godmode", "noclip",
    };

    // ─── Search roots ─────────────────────────────────────────────────────────
    private static string[] GetUserSearchRoots()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(profile, "Downloads"),
            Path.Combine(profile, "Documents"),
            appData,
            localAppData,
            Path.GetTempPath(),
        };
    }

    // ─── Entry point ─────────────────────────────────────────────────────────

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanFiveMPacketSpooferBinariesAsync(ctx, ct);
        ctx.Report(0.10, "FiveM binaries", "FiveM packet spoofer binary scan complete");

        await ScanFiveMModdedBuildsInAppDataAsync(ctx, ct);
        ctx.Report(0.20, "FiveM modded builds", "FiveM modded build scan complete");

        await ScanFiveMResourcesAsync(ctx, ct);
        ctx.Report(0.34, "FiveM resources", "FiveM resource and Lua scan complete");

        await ScanFiveMConfigFilesAsync(ctx, ct);
        ctx.Report(0.44, "FiveM configs", "FiveM cheat config file scan complete");

        await ScanRageMpBinariesAsync(ctx, ct);
        ctx.Report(0.53, "RageMP binaries", "RageMP cheat binary scan complete");

        await ScanRageMpConfigFilesAsync(ctx, ct);
        ctx.Report(0.60, "RageMP configs", "RageMP config cheat pattern scan complete");

        await ScanRageMpCustomBridgeDllsAsync(ctx, ct);
        ctx.Report(0.66, "RageMP DLLs", "RageMP custom bridge DLL scan complete");

        await ScanAltVResourceScriptsAsync(ctx, ct);
        ctx.Report(0.74, "alt:V resources", "alt:V exploit resource scan complete");

        await ScanAltVPacketManipulationDllsAsync(ctx, ct);
        ctx.Report(0.80, "alt:V DLLs", "alt:V cheat DLL scan complete");

        await ScanPacketEditorToolsAsync(ctx, ct);
        ctx.Report(0.85, "Packet editors", "Packet editor tool scan complete");

        await ScanPcapFilesAsync(ctx, ct);
        ctx.Report(0.90, "PCAP files", "Packet capture file scan complete");

        await ScanProxyRelayScriptsAsync(ctx, ct);
        ctx.Report(0.95, "Proxy scripts", "Game traffic proxy script scan complete");

        await ScanVpnConfigsForGameDomainsAsync(ctx, ct);
        ctx.Report(0.97, "VPN configs", "VPN/proxy game-domain config scan complete");

        await Task.Run(() => ScanRegistryArtifacts(ctx, ct), ct);
        ctx.Report(1.00, "Registry", "Network cheat registry artifact scan complete");
    }

    // ─── FiveM packet spoofer binaries ──────────────────────────────────────

    private async Task ScanFiveMPacketSpooferBinariesAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in GetUserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fname = Path.GetFileName(file);

                foreach (var knownExe in FiveMPacketSpooferExeNames)
                {
                    if (!fname.Equals(knownExe, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"FiveM Packet Spoofer Binary: {fname}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fname,
                        Reason = $"Known FiveM packet-spoofing executable '{fname}' detected. These tools manipulate CNetworkPlayerMgr and NET_OBJ_PLAYER_APPEARANCE data to falsify player state on the server and bypass network culling (bypassNetCull).",
                        Detail = $"Path={file}",
                        Recommendation = Recommendation.Remove,
                    });
                    break;
                }

                foreach (var knownDll in FiveMCheatDllNames)
                {
                    if (!fname.Equals(knownDll, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"FiveM Cheat DLL: {fname}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fname,
                        Reason = $"Known FiveM cheat injection DLL '{fname}' found. Used to hook CitizenFX network callbacks and manipulate game state synchronisation packets sent to the server.",
                        Detail = $"Path={file}",
                        Recommendation = Recommendation.Remove,
                    });
                    break;
                }
            }
        }
        await Task.CompletedTask;
    }

    // ─── FiveM modded builds in AppData ─────────────────────────────────────

    private async Task ScanFiveMModdedBuildsInAppDataAsync(ScanContext ctx, CancellationToken ct)
    {
        var appDataRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var root in appDataRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fname = Path.GetFileName(file);

                foreach (var moddedName in FiveMModdedBuildNames)
                {
                    if (!fname.Equals(moddedName, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"FiveM Modded Build in AppData: {fname}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fname,
                        Reason = $"Patched or modified FiveM executable '{fname}' found in AppData. Modded FiveM builds bypass CitizenFX integrity checks, certificate pinning on the citizen:// protocol, and network packet authentication.",
                        Detail = $"Path={file}",
                        Recommendation = Recommendation.Remove,
                    });
                    break;
                }
            }
        }
        await Task.CompletedTask;
    }

    // ─── FiveM resources (manifests + Lua) ───────────────────────────────────

    private async Task ScanFiveMResourcesAsync(ScanContext ctx, CancellationToken ct)
    {
        var fivemResourceRoots = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "CitizenFX", "cache", "resources"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FiveM", "FiveM.app", "data", "resources"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "FiveM", "data", "resources"),
        };

        foreach (var resourceRoot in fivemResourceRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(resourceRoot)) continue;

            IEnumerable<string> dirs;
            try
            {
                dirs = Directory.EnumerateDirectories(resourceRoot, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var resourceDir in dirs)
            {
                ct.ThrowIfCancellationRequested();
                var resourceName = Path.GetFileName(resourceDir);

                foreach (var bannedName in FiveMBannedResourceNames)
                {
                    if (!resourceName.Equals(bannedName, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"FiveM Banned Resource: {resourceName}",
                        Risk = RiskLevel.Critical,
                        Location = resourceDir,
                        FileName = resourceName,
                        Reason = $"FiveM resource directory '{resourceName}' matches a banned cheat resource name. Known exploit, money duplication, god-mode, teleport, or mass-kill resource.",
                        Detail = $"ResourceDir={resourceDir}",
                        Recommendation = Recommendation.Remove,
                    });
                    break;
                }

                await ScanFiveMResourceManifestAsync(ctx, resourceDir, resourceName, ct);
                await ScanFiveMLuaFilesInResourceAsync(ctx, resourceDir, resourceName, ct);
            }
        }
    }

    private async Task ScanFiveMResourceManifestAsync(
        ScanContext ctx, string resourceDir, string resourceName, CancellationToken ct)
    {
        var manifestPaths = new[]
        {
            Path.Combine(resourceDir, "fxmanifest.lua"),
            Path.Combine(resourceDir, "__resource.lua"),
            Path.Combine(resourceDir, "resource.json"),
        };

        foreach (var manifestPath in manifestPaths)
        {
            if (!File.Exists(manifestPath)) continue;

            string content;
            try
            {
                using var fs = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { continue; }

            ctx.IncrementFiles(1);

            foreach (var banned in FiveMBannedResourceNames)
            {
                if (!content.Contains(banned, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"FiveM Manifest References Banned Resource: {banned}",
                    Risk = RiskLevel.High,
                    Location = manifestPath,
                    FileName = Path.GetFileName(manifestPath),
                    Reason = $"FiveM resource manifest in '{resourceName}' imports or depends on banned cheat resource '{banned}'. The manifest references a known exploit script.",
                    Detail = $"Manifest={manifestPath}; BannedResource={banned}",
                    Recommendation = Recommendation.Remove,
                });
                break;
            }
        }
    }

    private async Task ScanFiveMLuaFilesInResourceAsync(
        ScanContext ctx, string resourceDir, string resourceName, CancellationToken ct)
    {
        IEnumerable<string> luaFiles;
        try
        {
            luaFiles = Directory.EnumerateFiles(resourceDir, "*.lua", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var luaPath in luaFiles)
        {
            ct.ThrowIfCancellationRequested();

            string content;
            try
            {
                using var fs = new FileStream(luaPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { continue; }

            ctx.IncrementFiles(1);

            foreach (var pattern in FiveMExploitLuaPatterns)
            {
                if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"FiveM Lua Exploit Pattern: {pattern}",
                    Risk = RiskLevel.High,
                    Location = luaPath,
                    FileName = Path.GetFileName(luaPath),
                    Reason = $"FiveM Lua script in resource '{resourceName}' contains exploit pattern '{pattern}'. Indicates server-event flooding, invincibility native calls, or money injection via ESX/QBCore TriggerServerEvent abuse.",
                    Detail = $"LuaFile={luaPath}; Pattern={pattern}",
                    Recommendation = Recommendation.Review,
                });
                break;
            }

            foreach (var regex in FiveMEsxQbExploitRegexes)
            {
                if (!regex.IsMatch(content)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = "FiveM ESX/QBCore Server-Event Money Exploit",
                    Risk = RiskLevel.Critical,
                    Location = luaPath,
                    FileName = Path.GetFileName(luaPath),
                    Reason = $"FiveM Lua script in resource '{resourceName}' matches an ESX/QBCore exploit pattern: TriggerServerEvent flood with large currency values or admin-level server calls (xPlayer.addMoney, large numeric argument).",
                    Detail = $"LuaFile={luaPath}; Regex={regex}",
                    Recommendation = Recommendation.Remove,
                });
                break;
            }
        }
    }

    // ─── FiveM config file scan ───────────────────────────────────────────────

    private async Task ScanFiveMConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configRoots = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CitizenFX"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var root in configRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                if (!ConfigExtensions.Contains(Path.GetExtension(file))) continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles(1);

                foreach (var pattern in FiveMCheatConfigPatterns)
                {
                    if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"FiveM Cheat Config Key: {pattern}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"FiveM configuration file '{Path.GetFileName(file)}' contains cheat setting '{pattern}', which enables position spoofing, fake coordinates, network culling bypass, or anti-cheat circumvention.",
                        Detail = $"File={file}; Pattern={pattern}",
                        Recommendation = Recommendation.Review,
                    });
                    break;
                }
            }
        }
    }

    // ─── RageMP cheat binaries ────────────────────────────────────────────────

    private async Task ScanRageMpBinariesAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in GetUserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fname = Path.GetFileName(file);

                foreach (var known in RageMpCheatExeNames)
                {
                    if (!fname.Equals(known, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"RageMP Cheat Binary: {fname}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fname,
                        Reason = $"Known RageMP cheat executable '{fname}' found. RageMP packet injection tools manipulate position synchronisation, money events, and teleportation at the network layer.",
                        Detail = $"Path={file}",
                        Recommendation = Recommendation.Remove,
                    });
                    break;
                }
            }
        }
        await Task.CompletedTask;
    }

    // ─── RageMP config files ─────────────────────────────────────────────────

    private async Task ScanRageMpConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var rageMpRoots = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "RAGE Multiplayer"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "RAGEMultiplayer"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "RAGE Multiplayer"),
        };

        foreach (var root in rageMpRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                if (!ConfigExtensions.Contains(Path.GetExtension(file))) continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles(1);

                foreach (var pattern in RageMpCheatConfigPatterns)
                {
                    if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"RageMP Cheat Config: {pattern}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"RageMP configuration file '{Path.GetFileName(file)}' contains cheat setting '{pattern}'. Enables packet-level teleportation (teleport_via_packet), money sync exploit, or anti-cheat bypass.",
                        Detail = $"File={file}; Pattern={pattern}",
                        Recommendation = Recommendation.Review,
                    });
                    break;
                }
            }
        }
    }

    // ─── RageMP custom bridge DLLs ──────────────────────────────────────────

    private async Task ScanRageMpCustomBridgeDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var rageMpDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "RAGE Multiplayer"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "RAGEMultiplayer"),
        };

        foreach (var rageMpDir in rageMpDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(rageMpDir)) continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(rageMpDir, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var dll in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fname = Path.GetFileName(dll);

                if (RageMpLegitDlls.Contains(fname)) continue;

                foreach (var knownCheatDll in RageMpCheatDllNames)
                {
                    if (!fname.Equals(knownCheatDll, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"RageMP Custom Cheat Bridge DLL: {fname}",
                        Risk = RiskLevel.Critical,
                        Location = dll,
                        FileName = fname,
                        Reason = $"Known RageMP cheat bridge DLL '{fname}' found inside the RAGE Multiplayer AppData directory. These DLLs hook the RAGE SDK to intercept and manipulate network synchronisation events.",
                        Detail = $"Path={dll}",
                        Recommendation = Recommendation.Remove,
                    });
                    break;
                }
            }
        }
        await Task.CompletedTask;
    }

    // ─── alt:V exploit resource scripts ─────────────────────────────────────

    private async Task ScanAltVResourceScriptsAsync(ScanContext ctx, CancellationToken ct)
    {
        var altVResourceRoots = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "altv", "resources"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "altv", "resources"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "alt-v", "resources"),
        };

        foreach (var root in altVResourceRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> resourceDirs;
            try
            {
                resourceDirs = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var resourceDir in resourceDirs)
            {
                ct.ThrowIfCancellationRequested();
                var resourceName = Path.GetFileName(resourceDir);

                foreach (var bannedPattern in AltVBannedResourcePatterns)
                {
                    if (!resourceName.Contains(bannedPattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"alt:V Banned Resource: {resourceName}",
                        Risk = RiskLevel.Critical,
                        Location = resourceDir,
                        FileName = resourceName,
                        Reason = $"alt:V resource directory '{resourceName}' matches banned cheat pattern '{bannedPattern}'. Performs mass entity spawning, player list dumping, god-mode, or exploit actions.",
                        Detail = $"ResourceDir={resourceDir}; Pattern={bannedPattern}",
                        Recommendation = Recommendation.Remove,
                    });
                    break;
                }

                await ScanAltVJsFilesInResourceAsync(ctx, resourceDir, resourceName, ct);
            }
        }
    }

    private async Task ScanAltVJsFilesInResourceAsync(
        ScanContext ctx, string resourceDir, string resourceName, CancellationToken ct)
    {
        IEnumerable<string> jsFiles;
        try
        {
            jsFiles = Directory.EnumerateFiles(resourceDir, "*.js", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var jsFile in jsFiles)
        {
            ct.ThrowIfCancellationRequested();

            string content;
            try
            {
                using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { continue; }

            ctx.IncrementFiles(1);

            foreach (var pattern in AltVExploitJsPatterns)
            {
                if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                var isLoop = pattern.Contains("setInterval", StringComparison.OrdinalIgnoreCase) ||
                             pattern.Contains("while", StringComparison.OrdinalIgnoreCase) ||
                             pattern.Contains("for", StringComparison.OrdinalIgnoreCase);

                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"alt:V JS Exploit Pattern: {pattern}",
                    Risk = isLoop ? RiskLevel.Critical : RiskLevel.High,
                    Location = jsFile,
                    FileName = Path.GetFileName(jsFile),
                    Reason = $"alt:V client-side JavaScript resource '{resourceName}' contains exploit pattern '{pattern}'. Loop-based patterns indicate server-event flooding; native-call patterns indicate god-mode, teleport, or weapon-spawn cheats.",
                    Detail = $"JsFile={jsFile}; Pattern={pattern}; LoopPattern={isLoop}",
                    Recommendation = Recommendation.Review,
                });
                break;
            }
        }
    }

    // ─── alt:V packet manipulation DLLs ─────────────────────────────────────

    private async Task ScanAltVPacketManipulationDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var altVDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "altv"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "alt-v"),
        };

        foreach (var altVDir in altVDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(altVDir)) continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(altVDir, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var dll in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fname = Path.GetFileName(dll);

                if (AltVLegitDlls.Contains(fname)) continue;

                foreach (var keyword in AltVCheatDllKeywords)
                {
                    if (!fname.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"alt:V Cheat-Keyword DLL: {fname}",
                        Risk = RiskLevel.Critical,
                        Location = dll,
                        FileName = fname,
                        Reason = $"Unexpected DLL '{fname}' with cheat keyword '{keyword}' found in alt:V data directory. Unexpected DLLs in the alt:V directory hook network events and inject game state manipulation code.",
                        Detail = $"Path={dll}; Keyword={keyword}",
                        Recommendation = Recommendation.Remove,
                    });
                    break;
                }
            }
        }
        await Task.CompletedTask;
    }

    // ─── Packet editor tools ─────────────────────────────────────────────────

    private async Task ScanPacketEditorToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in GetUserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fname = Path.GetFileName(file);

                foreach (var knownTool in PacketEditorExeNames)
                {
                    if (!fname.Equals(knownTool, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Packet Editor / Sender Tool: {fname}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fname,
                        Reason = $"Packet editor or sender tool '{fname}' detected. Tools such as WPE Pro, PacketEditor, and PacketSender intercept, modify, and replay game network traffic for position spoofing, money injection, and anti-cheat bypass.",
                        Detail = $"Path={file}",
                        Recommendation = Recommendation.Review,
                    });
                    break;
                }
            }
        }
        await Task.CompletedTask;
    }

    // ─── PCAP / packet capture files ────────────────────────────────────────

    private async Task ScanPcapFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var recentThreshold = DateTime.UtcNow.AddDays(-30);

        foreach (var root in GetUserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                var fname = Path.GetFileName(file);

                var isPcap = false;
                foreach (var pcapExt in PcapExtensions)
                {
                    if (ext.Equals(pcapExt, StringComparison.OrdinalIgnoreCase))
                    {
                        isPcap = true;
                        break;
                    }
                }

                if (!isPcap) continue;

                FileInfo fi;
                try { fi = new FileInfo(file); }
                catch (IOException) { continue; }

                var hasGameKeyword = false;
                foreach (var keyword in PcapGameKeywords)
                {
                    if (fname.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                        file.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        hasGameKeyword = true;
                        break;
                    }
                }

                var isRecent = fi.LastWriteTimeUtc >= recentThreshold;
                if (!hasGameKeyword && !isRecent) continue;

                ctx.IncrementFiles(1);
                ctx.AddFinding(new Finding
                {
                    Module = ModuleName,
                    Title = $"Game Packet Capture File: {fname}",
                    Risk = hasGameKeyword ? RiskLevel.High : RiskLevel.Medium,
                    Location = file,
                    FileName = fname,
                    Reason = $"Packet capture file '{fname}' ({ext}) found. PCAP files of game traffic are used to analyse and reverse-engineer FiveM/RageMP/alt:V network protocols to build packet injection cheats. GameKeyword={hasGameKeyword}; RecentFile(30d)={isRecent}.",
                    Detail = $"Path={file}; LastWrite={fi.LastWriteTimeUtc:u}; Size={fi.Length} bytes",
                    Recommendation = Recommendation.Review,
                });
            }
        }
        await Task.CompletedTask;
    }

    // ─── Custom proxy / relay scripts ────────────────────────────────────────

    private async Task ScanProxyRelayScriptsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in GetUserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!ext.Equals(".py", StringComparison.OrdinalIgnoreCase) &&
                    !ext.Equals(".js", StringComparison.OrdinalIgnoreCase)) continue;

                var fname = Path.GetFileName(file);

                foreach (var proxyName in ProxyScriptFileNames)
                {
                    if (!fname.Equals(proxyName, StringComparison.OrdinalIgnoreCase)) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { break; }

                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"Game Traffic Proxy/Relay Script: {fname}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fname,
                        Reason = $"Custom TCP/UDP proxy or relay script '{fname}' detected. Python/Node scripts named after game proxy patterns act as man-in-the-middle relays for FiveM, RageMP, or alt:V traffic, enabling packet inspection, modification, and replay.",
                        Detail = $"Path={file}; ContentLength={content.Length}",
                        Recommendation = Recommendation.Review,
                    });
                    break;
                }
            }
        }
    }

    // ─── VPN / proxy configs referencing game domains ────────────────────────

    private async Task ScanVpnConfigsForGameDomainsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in GetUserSearchRoots())
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                if (!VpnConfigExtensions.Contains(Path.GetExtension(file))) continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles(1);

                var hasVpnDirective = false;
                foreach (var directive in VpnDirectiveKeywords)
                {
                    if (content.Contains(directive, StringComparison.OrdinalIgnoreCase))
                    {
                        hasVpnDirective = true;
                        break;
                    }
                }

                if (!hasVpnDirective) continue;

                foreach (var domain in VpnGameDomainKeywords)
                {
                    if (!content.Contains(domain, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = ModuleName,
                        Title = $"VPN/Proxy Config with Game Platform Domain: {domain}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"VPN or proxy configuration file '{Path.GetFileName(file)}' references game platform domain '{domain}'. Cheat tools route game traffic through custom VPN/proxy configurations to hide packet manipulation from anti-cheat network monitoring.",
                        Detail = $"File={file}; GameDomain={domain}",
                        Recommendation = Recommendation.Review,
                    });
                    break;
                }
            }
        }
    }

    // ─── Registry artifacts ───────────────────────────────────────────────────

    private void ScanRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ScanUninstallRegistryForNetworkCheatTools(ctx, ct);
        ScanRunKeysForNetworkCheatTools(ctx, ct);
    }

    private void ScanUninstallRegistryForNetworkCheatTools(ScanContext ctx, CancellationToken ct)
    {
        var cheatToolKeywords = new[]
        {
            "fivem cheat", "fivem hack", "fivem bypass", "fivem spoofer",
            "ragemp cheat", "ragemp hack", "ragemp bypass", "rage multiplayer cheat",
            "altv cheat", "altv hack", "alt-v bypass",
            "packet editor", "wpe pro", "packet sender", "packet spoof",
            "gta network cheat", "netcull bypass",
        };

        var uninstallRoots = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (var uninstallKey in uninstallRoots)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var root = baseKey.OpenSubKey(uninstallKey, writable: false);
                if (root is null) continue;

                foreach (var subKeyName in root.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var subKey = root.OpenSubKey(subKeyName, writable: false);
                        if (subKey is null) continue;

                        ctx.IncrementRegistryKeys(1);

                        var displayName = subKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var installLocation = subKey.GetValue("InstallLocation")?.ToString() ?? string.Empty;

                        foreach (var keyword in cheatToolKeywords)
                        {
                            if (!displayName.Contains(keyword, StringComparison.OrdinalIgnoreCase) &&
                                !installLocation.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = ModuleName,
                                Title = $"Network Cheat Tool in Uninstall Registry: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallKey}\{subKeyName}",
                                Reason = $"Windows uninstall registry entry '{displayName}' matches network cheat tool keyword '{keyword}'. Even if uninstalled, this entry confirms prior installation of a packet-injection or cheat tool.",
                                Detail = $"DisplayName={displayName}; InstallLocation={installLocation}",
                                Recommendation = Recommendation.Review,
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

    private void ScanRunKeysForNetworkCheatTools(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        var cheatKeywords = new[]
        {
            "fivem_patch", "fivem_bypass", "fivem_hack", "fivem_cheat",
            "fivem_spoof", "fivempacketspoof", "ragemp_hack", "ragemp_bypass",
            "altv_hack", "altv_bypass", "packet_spoof", "packeteditor",
            "wpe_pro", "netcull_bypass",
        };

        foreach (var runKey in runKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(runKey, writable: false);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys(1);

                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    foreach (var keyword in cheatKeywords)
                    {
                        if (!valueName.Contains(keyword, StringComparison.OrdinalIgnoreCase) &&
                            !value.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = ModuleName,
                            Title = $"Network Cheat Tool in Run Key: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{runKey}\{valueName}",
                            Reason = $"Windows Run key entry '{valueName}' with command '{value}' matches network cheat keyword '{keyword}'. Indicates a packet-injection or protocol-bypass tool configured for automatic startup.",
                            Detail = $"ValueName={valueName}; Value={value}",
                            Recommendation = Recommendation.Remove,
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }
}
