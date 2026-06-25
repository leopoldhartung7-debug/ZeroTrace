using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMRageMpAltVCheatNetworkScanModule : IScanModule
{
    public string Name => "FiveM / RageMP / alt:V Cheat Network Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    private static readonly string LocalApp =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Temp = Path.GetTempPath();

    private static readonly HashSet<string> FiveMBannedResourceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "immortal", "godmode_bypass", "money_dupe", "vehicle_spawner_bypass",
        "tp_all", "freeze_all", "kill_all", "crash_all", "ban_all", "kick_all",
        "money_print", "dupe_money"
    };

    private static readonly HashSet<string> AltVBannedResourceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "esp_resource", "aimbot_resource", "wallhack", "speedhack",
        "vehiclespawn_unlimited", "moneyhack", "money_print", "godmode_altv",
        "crash_server", "kick_all_altv"
    };

    private static readonly HashSet<string> AltVKnownDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "altv-client.dll", "js-module.dll", "csharp-module.dll",
        "voice-module.dll", "bytecodemodule.dll"
    };

    private static readonly HashSet<string> RageMpKnownDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "rage-hook.dll", "rage-client-sdk.dll", "rage-client-bridge.dll",
        "v8.dll", "node.dll", "rage-native.dll"
    };

    private static readonly HashSet<string> PacketEditorToolNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "PacketEditor.exe", "PacketSender.exe", "WPEPro.exe", "wpe_pro.exe",
        "WPE_Pro.exe", "PacketCapture.exe", "RawCap.exe", "NetworkMiner.exe"
    };

    private static readonly string[] CheatNetworkConfigKeywords =
    {
        "bypass_anticheat_net", "spoof_network", "fake_position", "position_desync",
        "packet_intercept", "packet_modify", "packet_replay",
        "netcull_bypass", "network_bypass", "ac_bypass_network"
    };

    private static readonly string[] FiveMPacketSpoofContentStrings =
    {
        "NET_OBJ_PLAYER_APPEARANCE", "CNetworkPlayerMgr", "fivem_packet_spoof",
        "spoofPosition=true", "fakeCoords", "bypassNetCull"
    };

    private static readonly string[] FiveMPacketSpoofFileNames =
    {
        "fivem_spoof.exe", "fivem_packet.exe", "fivem_bypass.exe",
        "FiveM_patch.exe", "FiveM_bypass.exe"
    };

    private static readonly string[] FiveMModdedClientFileNames =
    {
        "FiveM_patch.exe", "FiveM_bypass.exe", "FiveM_hacked.exe",
        "FiveM_mod.exe", "FiveM_spoof.exe"
    };

    private static readonly string[] RageMpPacketInjectionToolNames =
    {
        "rage_packet_inject.exe", "mp_packet_spoof.exe",
        "ragemp_bypass.exe", "rage_spoof.exe"
    };

    private static readonly string[] RageMpConfigKeywords =
    {
        "teleport_via_packet=true", "packet_spoof=true",
        "ragemp_bypass", "position_spoof=true"
    };

    private static readonly string[] AltVBannedResourceFileNames =
    {
        "hack.js", "cheat.js", "exploit.js", "bypass.js",
        "aimbot.js", "esp.js"
    };

    private static readonly string[] GameDomainFragments =
    {
        "fivem", "rage", "altv", "cfx.re", "alt-multiplayer"
    };

    private static readonly string[] TrafficRelayGameKeywords =
    {
        "fivem", "rage", "altv", "gta", "5m", "cfx"
    };

    private static readonly string[] CitizenFxSignerFragments =
    {
        "CitizenFX", "Cfx.re", "Microsoft"
    };

    private static readonly string[] KnownCitizenDllPatterns =
    {
        "citizenfx", "cfx", "scripting", "mono", "chakra",
        "node", "v8", "cef", "libcef", "d3d", "dinput"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting FiveM / RageMP / alt:V cheat network scan...");

        var tasks = new List<Task>
        {
            ScanFiveMCheatNetworkAsync(ctx, ct),
            ScanRageMpCheatArtifactsAsync(ctx, ct),
            ScanAltVCheatArtifactsAsync(ctx, ct),
            ScanCrossPlatformNetworkToolsAsync(ctx, ct),
            ScanCheatNetworkConfigsAsync(ctx, ct),
            ScanWiresharkCaptureFilesAsync(ctx, ct),
            ScanTrafficRelayScriptsAsync(ctx, ct)
        };

        await Task.WhenAll(tasks).ConfigureAwait(false);

        ctx.Report(1.0, Name, "FiveM / RageMP / alt:V cheat network scan complete.");
    }

    // ── FiveM ───────────────────────────────────────────────────────────────────

    private async Task ScanFiveMCheatNetworkAsync(ScanContext ctx, CancellationToken ct)
    {
        var fivemApp = Path.Combine(LocalApp, "FiveM", "FiveM.app");

        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Desktop"),
            Temp,
            AppData
        };

        foreach (var dir in scanDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var file in EnumerateTextFiles(dir, 3,
                new[] { ".exe", ".dll", ".txt", ".cfg", ".ini", ".json", ".lua", ".js" }, ct))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);

                if (FiveMPacketSpoofFileNames.Any(n =>
                    fn.Equals(n, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Packet Spoof Tool: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"File '{fn}' matches a known FiveM packet spoofing tool name. " +
                                 "These tools manipulate GTA network objects to spoof position, " +
                                 "bypass net culling, and desync the player's position on the server.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                if (FiveMModdedClientFileNames.Any(n =>
                    fn.Equals(n, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Modded Client Executable: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"File '{fn}' matches a known FiveM modded/patched client name. " +
                                 "Modified FiveM clients are used to bypass anticheat, inject cheats " +
                                 "at the client binary level, or spoof authentication tokens.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                // Check .exe files in Downloads that contain "FiveM" and bypass/patch/spoof/crack
                var ext = Path.GetExtension(file);
                if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                    dir.Equals(Path.Combine(UserProfile, "Downloads"), StringComparison.OrdinalIgnoreCase))
                {
                    if (fn.Contains("FiveM", StringComparison.OrdinalIgnoreCase) &&
                        (fn.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                         fn.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                         fn.Contains("spoof", StringComparison.OrdinalIgnoreCase) ||
                         fn.Contains("crack", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Bypass/Patch Executable in Downloads: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Executable '{fn}' in Downloads folder contains 'FiveM' and a bypass/patch/spoof/crack " +
                                     "keyword in its filename. This pattern is characteristic of FiveM cheat loaders, " +
                                     "anticheat bypass patchers, and authentication spoofers.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }
                }

                if (!ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync().ConfigureAwait(false);

                        var matched = FiveMPacketSpoofContentStrings.FirstOrDefault(s =>
                            content.Contains(s, StringComparison.OrdinalIgnoreCase));
                        if (matched is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"FiveM Packet Spoof String in File: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"File '{fn}' contains the FiveM packet spoofing string '{matched}'. " +
                                         "This string is associated with tools that manipulate GTA network objects, " +
                                         "fake player coordinates, or bypass network culling checks.",
                                Detail = $"Matched string: {matched} | Path: {file}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
        }

        var resourcesRoot = Path.Combine(fivemApp, "data", "resources");
        var cacheServers = Path.Combine(fivemApp, "cache", "servers");

        if (Directory.Exists(resourcesRoot))
        {
            await ScanFiveMResourcesAsync(ctx, resourcesRoot, ct).ConfigureAwait(false);
            await ScanFiveMBannedResourceNamesAsync(ctx, resourcesRoot, ct).ConfigureAwait(false);
        }

        if (Directory.Exists(cacheServers))
            await ScanFiveMResourcesAsync(ctx, cacheServers, ct).ConfigureAwait(false);

        await ScanFiveMCitizenFolderAsync(ctx, ct).ConfigureAwait(false);
    }

    private async Task ScanFiveMResourcesAsync(ScanContext ctx, string resourcesRoot, CancellationToken ct)
    {
        if (!Directory.Exists(resourcesRoot)) return;

        string[] resourceDirs = Array.Empty<string>();
        try { resourceDirs = Directory.GetDirectories(resourcesRoot); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var resourceDir in resourceDirs)
        {
            if (ct.IsCancellationRequested) return;
            var resourceName = Path.GetFileName(resourceDir);

            foreach (var file in EnumerateTextFiles(resourceDir, 4,
                new[] { ".lua", ".js" }, ct))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                await ScanFiveMResourceFileAsync(ctx, file, resourceName, ct).ConfigureAwait(false);
            }
        }
    }

    private async Task ScanFiveMResourceFileAsync(ScanContext ctx, string filePath,
        string resourceName, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        var fn = Path.GetFileName(filePath);

        // TriggerServerEvent flooding: TriggerServerEvent inside while/for loop
        if (content.Contains("TriggerServerEvent", StringComparison.OrdinalIgnoreCase))
        {
            var lines = content.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                if (ct.IsCancellationRequested) return;
                if (!lines[i].Contains("TriggerServerEvent", StringComparison.OrdinalIgnoreCase))
                    continue;

                int start = Math.Max(0, i - 5);
                int end = Math.Min(lines.Length - 1, i + 5);
                bool hasLoop = false;
                for (int j = start; j <= end; j++)
                {
                    if (lines[j].Contains("while", StringComparison.OrdinalIgnoreCase) ||
                        lines[j].Contains("for ", StringComparison.OrdinalIgnoreCase) ||
                        lines[j].Contains("for(", StringComparison.OrdinalIgnoreCase))
                    {
                        hasLoop = true;
                        break;
                    }
                }

                if (hasLoop)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM TriggerServerEvent Flooding in Resource '{resourceName}': {fn}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fn,
                        Reason = $"File '{fn}' in resource '{resourceName}' contains TriggerServerEvent " +
                                 "called inside a loop structure (within 5 lines of a while/for). " +
                                 "This pattern is used by event-flooding exploits to spam the server " +
                                 "with events, causing denial of service or bypassing rate limiting.",
                        Detail = $"Resource: {resourceName} | File: {fn}"
                    });
                    break;
                }
            }
        }

        // ESX money exploit
        bool hasEsxMoneyTrigger =
            content.Contains("xPlayer.addMoney", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("TriggerServerEvent('esx:setAccountMoney'", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("TriggerServerEvent(\"esx:setAccountMoney\"", StringComparison.OrdinalIgnoreCase);
        if (hasEsxMoneyTrigger && content.Contains("999999", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"ESX Money Exploit Pattern in Resource '{resourceName}': {fn}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fn,
                Reason = $"File '{fn}' in resource '{resourceName}' contains ESX money exploit patterns: " +
                         "xPlayer.addMoney or esx:setAccountMoney combined with a suspicious large value (999999). " +
                         "This is a well-known FiveM ESX economy exploit used to give players unlimited money.",
                Detail = $"Resource: {resourceName} | File: {fn}"
            });
        }

        // QBCore money exploit
        bool hasQbCoreMoney =
            content.Contains("exports['qb-core']:GetCoreObject()", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("exports[\"qb-core\"]:GetCoreObject()", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("QBCore.Functions.GetPlayer", StringComparison.OrdinalIgnoreCase);
        if (hasQbCoreMoney && content.Contains("999999", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"QBCore Money Exploit Pattern in Resource '{resourceName}': {fn}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fn,
                Reason = $"File '{fn}' in resource '{resourceName}' contains QBCore money exploit patterns: " +
                         "QBCore.Functions.GetPlayer or qb-core:GetCoreObject combined with suspicious large values. " +
                         "This pattern is used by QBCore economy dupe and money-injection exploits.",
                Detail = $"Resource: {resourceName} | File: {fn}"
            });
        }

        // Godmode bypass
        bool hasInvincible = content.Contains("SetEntityInvincible", StringComparison.OrdinalIgnoreCase);
        bool hasGodmodeContext =
            content.Contains("true", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("ExecuteCommand", StringComparison.OrdinalIgnoreCase);
        if (hasInvincible && hasGodmodeContext)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Godmode Bypass Pattern in Resource '{resourceName}': {fn}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fn,
                Reason = $"File '{fn}' in resource '{resourceName}' contains SetEntityInvincible " +
                         "combined with 'true' or ExecuteCommand. This is a godmode bypass pattern " +
                         "used to make players invincible on FiveM servers that should block this call.",
                Detail = $"Resource: {resourceName} | File: {fn}"
            });
        }

        // Aimbot pattern: GetPlayerPed + GetEntityCoords + (TaskGoToCoordAnyMeans or SetEntityCoords)
        bool hasAimbotPed = content.Contains("GetPlayerPed", StringComparison.OrdinalIgnoreCase);
        bool hasAimbotCoords = content.Contains("GetEntityCoords", StringComparison.OrdinalIgnoreCase);
        bool hasAimbotAction =
            content.Contains("TaskGoToCoordAnyMeans", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("SetEntityCoords", StringComparison.OrdinalIgnoreCase);
        if (hasAimbotPed && hasAimbotCoords && hasAimbotAction)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Aimbot/Teleport Pattern in Resource '{resourceName}': {fn}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fn,
                Reason = $"File '{fn}' in resource '{resourceName}' contains all three aimbot/teleport " +
                         "indicators: GetPlayerPed, GetEntityCoords, and TaskGoToCoordAnyMeans or SetEntityCoords. " +
                         "This combination is used by FiveM aimbots and teleport cheats that track " +
                         "enemy positions and move the local player or aim toward them.",
                Detail = $"Resource: {resourceName} | File: {fn}"
            });
        }
    }

    private async Task ScanFiveMBannedResourceNamesAsync(ScanContext ctx, string resourcesRoot,
        CancellationToken ct)
    {
        if (!Directory.Exists(resourcesRoot)) return;

        string[] resourceDirs = Array.Empty<string>();
        try { resourceDirs = Directory.GetDirectories(resourcesRoot); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var resourceDir in resourceDirs)
        {
            if (ct.IsCancellationRequested) return;
            var resourceName = Path.GetFileName(resourceDir);

            if (FiveMBannedResourceNames.Contains(resourceName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Banned FiveM Resource Name: '{resourceName}'",
                    Risk = RiskLevel.Critical,
                    Location = resourceDir,
                    FileName = resourceName,
                    Reason = $"A FiveM resource folder named '{resourceName}' was found. " +
                             "This name appears on the known-bad resource list for FiveM cheat resources " +
                             "that provide godmode, money duplication, vehicle spawning bypass, " +
                             "mass teleport, or server crash functionality.",
                    Detail = $"Path: {resourceDir}"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private async Task ScanFiveMCitizenFolderAsync(ScanContext ctx, CancellationToken ct)
    {
        var citizenRoot = Path.Combine(LocalApp, "FiveM", "FiveM.app", "citizen");
        if (!Directory.Exists(citizenRoot)) return;

        // Unexpected DLLs in citizen folder not from CitizenFX/Cfx.re
        foreach (var file in EnumerateTextFiles(citizenRoot, 4, new[] { ".dll" }, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fn = Path.GetFileName(file);
            bool isKnownCitizen = KnownCitizenDllPatterns.Any(p =>
                fn.Contains(p, StringComparison.OrdinalIgnoreCase));

            if (!isKnownCitizen)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Unexpected DLL in FiveM citizen folder: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"DLL '{fn}' found in the FiveM citizen folder does not match any " +
                             "expected CitizenFX/Cfx.re DLL naming pattern. Cheat injectors and " +
                             "anticheat bypass DLLs are sometimes placed in the citizen folder to " +
                             "load automatically when FiveM starts.",
                    Detail = $"Path: {file}"
                });
            }
        }

        // Check scripting/lua folder for modified or unauthorized Lua files
        var luaScriptingDir = Path.Combine(citizenRoot, "scripting", "lua");
        if (!Directory.Exists(luaScriptingDir)) return;

        foreach (var file in EnumerateTextFiles(luaScriptingDir, 3, new[] { ".lua" }, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fn = Path.GetFileName(file);
            bool isKnown = fn.Equals("scripting_gta.lua", StringComparison.OrdinalIgnoreCase) ||
                           fn.Equals("scripting_natives.lua", StringComparison.OrdinalIgnoreCase) ||
                           fn.Equals("scripting_server.lua", StringComparison.OrdinalIgnoreCase) ||
                           fn.Equals("scripting_shared.lua", StringComparison.OrdinalIgnoreCase);

            if (!isKnown)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Unauthorized Lua File in FiveM citizen/scripting/lua: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"Unexpected Lua file '{fn}' found in FiveM citizen/scripting/lua/. " +
                             "This directory contains the official FiveM Lua scripting runtime. " +
                             "Placing unauthorized Lua files here allows cheats to override native " +
                             "mappings and inject code into every FiveM resource.",
                    Detail = $"Path: {file}"
                });
                continue;
            }

            // Size/content anomaly check for known files
            await CheckLuaFileForCheatPatternsAsync(ctx, file, ct).ConfigureAwait(false);
        }
    }

    // ── RageMP ──────────────────────────────────────────────────────────────────

    private async Task ScanRageMpCheatArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Downloads"),
            Temp,
            Path.Combine(UserProfile, "Desktop")
        };

        foreach (var dir in scanDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var file in EnumerateTextFiles(dir, 2,
                new[] { ".exe", ".ini", ".cfg", ".json", ".txt" }, ct))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);

                if (RageMpPacketInjectionToolNames.Any(n =>
                    fn.Equals(n, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Packet Injection Tool: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"File '{fn}' matches a known RageMP packet injection or spoofing tool name. " +
                                 "These tools intercept and modify RageMP network packets to fake positions, " +
                                 "inject money, or bypass server-side anticheat checks.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                var ext = Path.GetExtension(file);
                if (ext.Equals(".ini", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync().ConfigureAwait(false);

                        var matched = RageMpConfigKeywords.FirstOrDefault(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (matched is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"RageMP Cheat Config Keyword in: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Config file '{fn}' contains the RageMP cheat keyword '{matched}'. " +
                                         "This keyword is associated with packet spoofing tools and position " +
                                         "desync exploits targeting the RageMP GTA multiplayer platform.",
                                Detail = $"Matched: {matched} | Path: {file}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
        }

        var rageMpRoot = Path.Combine(AppData, "RAGE Multiplayer");
        if (Directory.Exists(rageMpRoot))
        {
            await ScanRageMpBridgeDllsAsync(ctx, ct).ConfigureAwait(false);

            var packages = Path.Combine(rageMpRoot, "packages");
            var clientPackages = Path.Combine(rageMpRoot, "client_packages");

            if (Directory.Exists(packages))
                await ScanRageMpClientPackagesAsync(ctx, packages, ct).ConfigureAwait(false);
            if (Directory.Exists(clientPackages))
                await ScanRageMpClientPackagesAsync(ctx, clientPackages, ct).ConfigureAwait(false);
        }
    }

    private async Task ScanRageMpBridgeDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var rageMpRoot = Path.Combine(AppData, "RAGE Multiplayer");
        if (!Directory.Exists(rageMpRoot)) return;

        // Check the root folder and immediate subdirs
        var dirsToCheck = new List<string> { rageMpRoot };
        try
        {
            foreach (var sub in Directory.GetDirectories(rageMpRoot))
                dirsToCheck.Add(sub);
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        foreach (var dir in dirsToCheck)
        {
            if (ct.IsCancellationRequested) return;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*.dll"); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);
                if (!RageMpKnownDlls.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious DLL in RageMP Directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"DLL '{fn}' found in the RAGE Multiplayer folder does not match " +
                                 "any known-good RageMP DLL. Unknown DLLs in the RageMP directory " +
                                 "are often custom bridge DLLs used by cheats to hook into the " +
                                 "RageMP client bridge and intercept or modify network communications.",
                        Detail = $"Path: {file} | Expected DLLs: {string.Join(", ", RageMpKnownDlls)}"
                    });
                }
            }
        }

        // Check client_packages for suspicious DLLs (not standard JS/resource files)
        var clientPackages = Path.Combine(rageMpRoot, "client_packages");
        if (!Directory.Exists(clientPackages)) return;

        foreach (var file in EnumerateTextFiles(clientPackages, 3, new[] { ".dll" }, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fn = Path.GetFileName(file);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Suspicious DLL in RageMP client_packages: {fn}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = fn,
                Reason = $"DLL '{fn}' found in RageMP client_packages directory. " +
                         "This directory should contain only JavaScript resource files. " +
                         "DLLs here are not expected and may be cheat bridge components " +
                         "or injectors masquerading as client packages.",
                Detail = $"Path: {file}"
            });
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private async Task ScanRageMpClientPackagesAsync(ScanContext ctx, string packagesRoot,
        CancellationToken ct)
    {
        if (!Directory.Exists(packagesRoot)) return;

        foreach (var file in EnumerateTextFiles(packagesRoot, 4, new[] { ".js" }, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync().ConfigureAwait(false);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            var fn = Path.GetFileName(file);

            // mp.events.add combined with server sync manipulation
            bool hasMpEvents = content.Contains("mp.events.add", StringComparison.OrdinalIgnoreCase);
            bool hasServerSyncManip =
                content.Contains("mp.players.local.position", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("syncedMeta", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("bypassSync", StringComparison.OrdinalIgnoreCase);
            if (hasMpEvents && hasServerSyncManip)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RageMP Server Sync Manipulation in: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"File '{fn}' combines mp.events.add with server synchronisation " +
                             "manipulation patterns (mp.players.local.position, syncedMeta bypass). " +
                             "This is used by RageMP exploits to desync the player's server-side " +
                             "position or manipulate synced metadata for cheating purposes.",
                    Detail = $"Path: {file}"
                });
                continue;
            }

            // mp.players.local.position set via exploit patterns
            if (content.Contains("mp.players.local.position", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RageMP Local Position Override in: {fn}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = fn,
                    Reason = $"File '{fn}' sets mp.players.local.position. Directly manipulating " +
                             "the local player position in client packages is a known technique " +
                             "for position desync exploits and teleport cheats in RageMP.",
                    Detail = $"Path: {file}"
                });
                continue;
            }

            // mp.game.invoke in looping context
            if (content.Contains("mp.game.invoke", StringComparison.OrdinalIgnoreCase))
            {
                bool hasLoop =
                    content.Contains("setInterval", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("while(", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("while (", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("for(", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("for (", StringComparison.OrdinalIgnoreCase);
                if (hasLoop)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Game.Invoke in Loop Context in: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"File '{fn}' calls mp.game.invoke (raw GTA native call) inside a " +
                                 "looping context (setInterval, while, for). This pattern is used " +
                                 "by RageMP cheats to repeatedly invoke game natives for godmode, " +
                                 "speedhack, or aimbot functionality without server authorization.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }

    // ── alt:V ───────────────────────────────────────────────────────────────────

    private async Task ScanAltVCheatArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var altVRoot = Path.Combine(LocalApp, "altv");
        if (!Directory.Exists(altVRoot))
        {
            // Try alternate locations
            var altVRoots = new[]
            {
                Path.Combine(LocalApp, "altv-launcher"),
                Path.Combine(AppData, "altv"),
                Path.Combine(UserProfile, "Documents", "altv"),
                @"C:\altv",
                @"C:\altv-launcher"
            };
            altVRoot = altVRoots.FirstOrDefault(Directory.Exists) ?? altVRoot;
        }

        if (!Directory.Exists(altVRoot)) return;

        var resourcesRoot = Path.Combine(altVRoot, "resources");
        if (Directory.Exists(resourcesRoot))
        {
            await ScanAltVResourcesAsync(ctx, resourcesRoot, ct).ConfigureAwait(false);

            // Check for banned alt:V resource folder names
            string[] resourceDirs = Array.Empty<string>();
            try { resourceDirs = Directory.GetDirectories(resourcesRoot); }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            foreach (var resourceDir in resourceDirs)
            {
                if (ct.IsCancellationRequested) return;
                var resourceName = Path.GetFileName(resourceDir);

                if (AltVBannedResourceNames.Contains(resourceName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Banned alt:V Resource Name: '{resourceName}'",
                        Risk = RiskLevel.Critical,
                        Location = resourceDir,
                        FileName = resourceName,
                        Reason = $"alt:V resource folder '{resourceName}' matches a known cheat resource name. " +
                                 "This resource name is associated with ESP, aimbot, wallhack, speedhack, " +
                                 "unlimited vehicle spawning, money hacks, godmode, server crash, " +
                                 "or mass kick functionality.",
                        Detail = $"Path: {resourceDir}"
                    });
                }

                // Check for banned cheat JS files inside each resource folder
                foreach (var bannedFileName in AltVBannedResourceFileNames)
                {
                    var bannedPath = Path.Combine(resourceDir, bannedFileName);
                    if (!File.Exists(bannedPath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Script in alt:V Resource '{resourceName}': {bannedFileName}",
                        Risk = RiskLevel.Critical,
                        Location = bannedPath,
                        FileName = bannedFileName,
                        Reason = $"File '{bannedFileName}' found inside alt:V resource '{resourceName}'. " +
                                 "Files with this name are strongly associated with cheat functionality " +
                                 "in alt:V resources (ESP, aimbot, exploit, bypass scripts).",
                        Detail = $"Path: {bannedPath}"
                    });
                }
            }
        }

        await ScanAltVDllsAsync(ctx, altVRoot, ct).ConfigureAwait(false);
    }

    private async Task ScanAltVResourcesAsync(ScanContext ctx, string resourcesRoot, CancellationToken ct)
    {
        if (!Directory.Exists(resourcesRoot)) return;

        foreach (var file in EnumerateTextFiles(resourcesRoot, 5, new[] { ".js", ".ts" }, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            await CheckJsFileForCheatPatternsAsync(ctx, file, "alt:V", ct).ConfigureAwait(false);
        }
    }

    private async Task ScanAltVDllsAsync(ScanContext ctx, string altVRoot, CancellationToken ct)
    {
        if (!Directory.Exists(altVRoot)) return;

        foreach (var file in EnumerateTextFiles(altVRoot, 3, new[] { ".dll" }, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fn = Path.GetFileName(file);
            if (!AltVKnownDlls.Contains(fn))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Unexpected DLL in alt:V Directory: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"DLL '{fn}' found in the alt:V directory does not match any expected " +
                             "alt:V module DLL. Unknown DLLs in the alt:V root are characteristic " +
                             "of packet manipulation tools or cheat modules that hook the alt:V " +
                             "client's network layer.",
                    Detail = $"Path: {file} | Expected: {string.Join(", ", AltVKnownDlls)}"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    // ── Cross-platform network tools ─────────────────────────────────────────────

    private async Task ScanCrossPlatformNetworkToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Desktop"),
            Temp
        };

        foreach (var dir in scanDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);

                // Packet editor tool names
                if (PacketEditorToolNames.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Packet Editor Tool Found: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Packet editor tool '{fn}' found in {Path.GetFileName(dir)}. " +
                                 "Packet editing and sending tools are used by cheat developers and users " +
                                 "to manipulate game server traffic, replay packets, or inject crafted " +
                                 "network messages to bypass server-side validation.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                // MITM proxy configs mentioning game domains
                var ext = Path.GetExtension(file);
                if (ext.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".yml", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".yaml", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".conf", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync().ConfigureAwait(false);

                        bool hasProxy = content.Contains("proxy", StringComparison.OrdinalIgnoreCase);
                        if (hasProxy)
                        {
                            var matchedDomain = GameDomainFragments.FirstOrDefault(d =>
                                content.Contains(d, StringComparison.OrdinalIgnoreCase));
                            if (matchedDomain is not null)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"MITM Proxy Config Targeting Game Domain in: {fn}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"File '{fn}' contains both 'proxy' and the game domain keyword '{matchedDomain}'. " +
                                             "MITM proxy configurations targeting FiveM, RageMP, or alt:V server domains " +
                                             "are used to intercept, inspect, and modify encrypted game server traffic " +
                                             "for the purpose of cheating or server exploitation.",
                                    Detail = $"Domain matched: {matchedDomain} | Path: {file}"
                                });
                                continue;
                            }
                        }

                        // mitmproxy config files
                        if (fn.Equals("options.yml", StringComparison.OrdinalIgnoreCase) ||
                            fn.Equals("config.yaml", StringComparison.OrdinalIgnoreCase))
                        {
                            if (content.Contains("upstream_cert", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("upstream", StringComparison.OrdinalIgnoreCase))
                            {
                                var gameDomain = GameDomainFragments.FirstOrDefault(d =>
                                    content.Contains(d, StringComparison.OrdinalIgnoreCase));
                                if (gameDomain is not null)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"mitmproxy Config Targeting Game Server: {fn}",
                                        Risk = RiskLevel.High,
                                        Location = file,
                                        FileName = fn,
                                        Reason = $"mitmproxy config file '{fn}' references upstream proxy settings " +
                                                 $"and the game domain '{gameDomain}'. " +
                                                 "mitmproxy is used by cheat developers to inspect and modify " +
                                                 "HTTPS/TCP game server communications for exploit development.",
                                        Detail = $"Domain: {gameDomain} | Path: {file}"
                                    });
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
        }
    }

    private async Task ScanCheatNetworkConfigsAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Downloads"),
            AppData,
            Temp,
            Path.Combine(UserProfile, "Desktop")
        };

        foreach (var dir in scanDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var file in EnumerateTextFiles(dir, 3,
                new[] { ".ini", ".cfg", ".json", ".xml", ".txt" }, ct))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync().ConfigureAwait(false);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                var fn = Path.GetFileName(file);

                var matched = CheatNetworkConfigKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (matched is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Network Config Keyword in: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Config file '{fn}' contains the cheat network keyword '{matched}'. " +
                                 "These keywords appear in configuration files for network-layer cheat tools " +
                                 "that bypass anticheat network surveillance, spoof packet contents, " +
                                 "or intercept and replay game server messages.",
                        Detail = $"Matched keyword: {matched} | Path: {file}"
                    });
                    continue;
                }

                // OpenVPN configs (.ovpn) with game server domains in remote
                var ext = Path.GetExtension(file);
                if (ext.Equals(".ovpn", StringComparison.OrdinalIgnoreCase))
                {
                    var gameDomain = GameDomainFragments.FirstOrDefault(d =>
                        content.Contains(d, StringComparison.OrdinalIgnoreCase));
                    if (gameDomain is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"OpenVPN Config Referencing Game Domain: {fn}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = fn,
                            Reason = $"OpenVPN config '{fn}' references game domain '{gameDomain}'. " +
                                     "VPN configurations that route traffic through game server IP ranges " +
                                     "can be used to disguise packet injection tools or route cheat traffic " +
                                     "through a controlled intermediary.",
                            Detail = $"Domain matched: {gameDomain} | Path: {file}"
                        });
                        continue;
                    }
                }

                // WireGuard configs (.conf) mentioning game domains
                if (ext.Equals(".conf", StringComparison.OrdinalIgnoreCase) &&
                    (content.Contains("[Interface]", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("[Peer]", StringComparison.OrdinalIgnoreCase)))
                {
                    var gameDomain = GameDomainFragments.FirstOrDefault(d =>
                        content.Contains(d, StringComparison.OrdinalIgnoreCase));
                    if (gameDomain is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"WireGuard Config Referencing Game Domain: {fn}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = fn,
                            Reason = $"WireGuard config '{fn}' references game domain '{gameDomain}'. " +
                                     "WireGuard tunnels targeting game server domains may be used to " +
                                     "route cheat tool traffic through a controlled relay, masking " +
                                     "the cheat operator's identity or enabling packet manipulation.",
                            Detail = $"Domain matched: {gameDomain} | Path: {file}"
                        });
                    }
                }
            }
        }
    }

    private async Task ScanWiresharkCaptureFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Documents")
        };

        foreach (var dir in scanDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var file in EnumerateTextFiles(dir, 2,
                new[] { ".pcap", ".pcapng" }, ct))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Wireshark Capture File Near Game Session Directory: {fn}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = fn,
                    Reason = $"Network capture file '{fn}' (.pcap/.pcapng) found in {Path.GetFileName(dir)}. " +
                             "Wireshark capture files on the Desktop, Downloads, or Documents folder " +
                             "during or after a gaming session indicate that game server network traffic " +
                             "was being captured. This is a prerequisite for packet-based network cheats " +
                             "and ESP tools that decode server-sent entity position data.",
                    Detail = $"Path: {file} | Modified: {SafeGetLastWriteTime(file):yyyy-MM-dd HH:mm}"
                });
            }
        }

        await Task.CompletedTask.ConfigureAwait(false);
    }

    private async Task ScanTrafficRelayScriptsAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Desktop"),
            Temp
        };

        foreach (var dir in scanDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            // Python relay scripts
            foreach (var file in EnumerateTextFiles(dir, 3, new[] { ".py" }, ct))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync().ConfigureAwait(false);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                var fn = Path.GetFileName(file);

                bool hasSocketLib =
                    content.Contains("socket", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("asyncio", StringComparison.OrdinalIgnoreCase);
                bool hasBindListen =
                    content.Contains("bind", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("listen", StringComparison.OrdinalIgnoreCase);
                bool hasForward =
                    content.Contains("sendto", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("forward", StringComparison.OrdinalIgnoreCase);
                bool hasGameKeyword = TrafficRelayGameKeywords.Any(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (hasSocketLib && hasBindListen && hasForward && hasGameKeyword)
                {
                    var matchedGameKw = TrafficRelayGameKeywords.First(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Python Game Traffic Relay Script: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Python script '{fn}' contains patterns indicating a custom TCP/UDP relay " +
                                 $"targeting game platforms (matched keyword: '{matchedGameKw}'). " +
                                 "The combination of socket/asyncio bind/listen with sendto/forward and a " +
                                 "game platform keyword indicates a custom traffic relay or modifier " +
                                 "used to intercept, modify, or replay game server packets.",
                        Detail = $"Game keyword: {matchedGameKw} | Path: {file}"
                    });
                }
            }

            // Node.js relay scripts
            foreach (var file in EnumerateTextFiles(dir, 3, new[] { ".js" }, ct))
            {
                if (ct.IsCancellationRequested) return;

                // Skip altV resource .js files already scanned elsewhere
                if (file.Contains(Path.Combine(LocalApp, "altv"), StringComparison.OrdinalIgnoreCase))
                    continue;

                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync().ConfigureAwait(false);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                var fn = Path.GetFileName(file);

                bool hasNetServer =
                    content.Contains("net.createServer", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("dgram.createSocket", StringComparison.OrdinalIgnoreCase);
                bool hasConnectForward =
                    content.Contains("connect", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("forward", StringComparison.OrdinalIgnoreCase);
                bool hasGameKw = TrafficRelayGameKeywords.Any(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (hasNetServer && hasConnectForward && hasGameKw)
                {
                    var matchedKw = TrafficRelayGameKeywords.First(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Node.js Game Traffic Relay Script: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Node.js script '{fn}' contains patterns matching a custom TCP/UDP relay " +
                                 $"targeting game platforms (keyword: '{matchedKw}'). " +
                                 "net.createServer or dgram.createSocket combined with connect/forward " +
                                 "and a game platform keyword indicates traffic interception or relay " +
                                 "infrastructure used by network-layer cheat tools.",
                        Detail = $"Game keyword: {matchedKw} | Path: {file}"
                    });
                }
            }
        }
    }

    // ── Per-file content checkers ────────────────────────────────────────────────

    private async Task CheckLuaFileForCheatPatternsAsync(ScanContext ctx, string path,
        CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        var fn = Path.GetFileName(path);

        var luaCheatSignals = new[]
        {
            "SetEntityInvincible", "AddExplosion", "SetEntityCoords",
            "GiveWeaponToPed", "NetworkResurrectLocalPlayer",
            "SetPedMaxSpeed", "SetEntityHealth",
            "TriggerServerEvent", "ExecuteCommand",
            "mem.read", "mem.write", "hook.create", "inject",
            "bypass", "aimbot", "esp.", "wallhack"
        };

        var matches = luaCheatSignals
            .Where(s => content.Contains(s, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matches.Count == 0) return;

        var risk = matches.Count >= 3 ? RiskLevel.Critical
                 : matches.Count >= 2 ? RiskLevel.High
                 : RiskLevel.Medium;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Cheat Lua Pattern in FiveM citizen scripting: {fn}",
            Risk = risk,
            Location = path,
            FileName = fn,
            Reason = $"Lua file '{fn}' in the FiveM citizen scripting directory contains " +
                     $"{matches.Count} cheat-associated pattern(s): " +
                     string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                     (matches.Count > 4 ? " ..." : "") +
                     ". Modifications to the citizen scripting Lua files can override native " +
                     "mappings, disable anticheat checks, or inject cheat functionality into " +
                     "every running FiveM resource.",
            Detail = $"Matched ({matches.Count}): {string.Join(", ", matches.Take(6))}"
        });
    }

    private async Task CheckJsFileForCheatPatternsAsync(ScanContext ctx, string path,
        string platform, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        var fn = Path.GetFileName(path);
        var resourceName = TryGetResourceName(path);

        // alt:V specific checks
        if (platform.Equals("alt:V", StringComparison.OrdinalIgnoreCase))
        {
            // alt.emitServer inside setInterval or while loop (server flooding)
            if (content.Contains("alt.emitServer", StringComparison.OrdinalIgnoreCase))
            {
                bool hasLoopContext =
                    content.Contains("setInterval", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("while(", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("while (", StringComparison.OrdinalIgnoreCase);
                if (hasLoopContext)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V Server Event Flooding Pattern in: {fn}",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = fn,
                        Reason = $"File '{fn}' calls alt.emitServer inside a setInterval or while loop. " +
                                 "This pattern is used by alt:V exploit resources to flood the server " +
                                 "with events, bypassing rate limiting or triggering server-side bugs " +
                                 "through repeated event emission.",
                        Detail = $"Platform: alt:V | Resource: {resourceName} | Path: {path}"
                    });
                    return;
                }
            }

            // Position desync exploits: setWaypointPosition or native.setEntityCoords in suspicious context
            bool hasPosDesync =
                content.Contains("alt.setWaypointPosition", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("native.setEntityCoords", StringComparison.OrdinalIgnoreCase);
            if (hasPosDesync)
            {
                bool hasSuspiciousContext =
                    content.Contains("setInterval", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("while", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("exploit", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("bypass", StringComparison.OrdinalIgnoreCase);
                if (hasSuspiciousContext)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V Position Desync Exploit Pattern in: {fn}",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = fn,
                        Reason = $"File '{fn}' uses alt.setWaypointPosition or native.setEntityCoords " +
                                 "in a suspicious context (loop, exploit, bypass keyword). " +
                                 "This pattern is associated with alt:V position desync exploits that " +
                                 "move the player to arbitrary coordinates without server authorization.",
                        Detail = $"Platform: alt:V | Resource: {resourceName} | Path: {path}"
                    });
                    return;
                }
            }

            // Player enumeration combined with dump/external endpoint
            bool hasPlayerEnum =
                content.Contains("alt.getAllPlayers", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("alt.Player.all", StringComparison.OrdinalIgnoreCase);
            if (hasPlayerEnum)
            {
                bool hasExfiltration =
                    content.Contains("dump", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("fetch(", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("XMLHttpRequest", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("https://", StringComparison.OrdinalIgnoreCase);
                if (hasExfiltration)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V Player Data Exfiltration Pattern in: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = path,
                        FileName = fn,
                        Reason = $"File '{fn}' enumerates all players via alt.getAllPlayers or alt.Player.all " +
                                 "and combines this with external data sending (fetch, XMLHttpRequest, HTTP URL, dump). " +
                                 "This pattern is used by alt:V resources to exfiltrate player lists " +
                                 "to external cheat infrastructure or leak player identifiers.",
                        Detail = $"Platform: alt:V | Resource: {resourceName} | Path: {path}"
                    });
                    return;
                }
            }

            // LocalStorage combined with data exfiltration
            if (content.Contains("alt.LocalStorage", StringComparison.OrdinalIgnoreCase))
            {
                bool hasExfil =
                    content.Contains("fetch(", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("https://", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("XMLHttpRequest", StringComparison.OrdinalIgnoreCase);
                if (hasExfil)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V LocalStorage Exfiltration Pattern in: {fn}",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = fn,
                        Reason = $"File '{fn}' accesses alt.LocalStorage and sends data to an external " +
                                 "endpoint. This pattern can be used to exfiltrate stored credentials, " +
                                 "session tokens, or player identifiers from the alt:V local storage " +
                                 "to external cheat operators.",
                        Detail = $"Platform: alt:V | Resource: {resourceName} | Path: {path}"
                    });
                    return;
                }
            }

            // Mass entity spawning in rapid loop
            bool hasSpawnLoop =
                (content.Contains("createVehicle", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("createObject", StringComparison.OrdinalIgnoreCase)) &&
                (content.Contains("setInterval", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("for(", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("for (", StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("while(", StringComparison.OrdinalIgnoreCase));
            if (hasSpawnLoop)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"alt:V Mass Entity Spawn Loop in: {fn}",
                    Risk = RiskLevel.High,
                    Location = path,
                    FileName = fn,
                    Reason = $"File '{fn}' calls createVehicle or createObject inside a rapid loop " +
                             "(setInterval, for, while). This pattern is used by alt:V server crash " +
                             "resources that spawn massive numbers of entities to overload the server " +
                             "or cause client-side lag for all connected players.",
                    Detail = $"Platform: alt:V | Resource: {resourceName} | Path: {path}"
                });
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────

    private IEnumerable<string> EnumerateTextFiles(string dir, int maxDepth,
        string[] extensions, CancellationToken ct)
    {
        var stack = new Stack<(string path, int depth)>();
        stack.Push((dir, 0));

        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) yield break;
            var (current, depth) = stack.Pop();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(current); }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) yield break;
                var ext = Path.GetExtension(file);
                if (extensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase)))
                    yield return file;
            }

            if (depth >= maxDepth) continue;

            string[] subs = Array.Empty<string>();
            try { subs = Directory.GetDirectories(current); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var sub in subs)
                stack.Push((sub, depth + 1));
        }
    }

    private static string TryGetResourceName(string filePath)
    {
        try
        {
            var parts = filePath.Split(Path.DirectorySeparatorChar);
            var resourcesIdx = Array.FindLastIndex(parts, p =>
                p.Equals("resources", StringComparison.OrdinalIgnoreCase));
            if (resourcesIdx >= 0 && resourcesIdx + 1 < parts.Length)
                return parts[resourcesIdx + 1];
        }
        catch { }
        return Path.GetDirectoryName(filePath) ?? string.Empty;
    }

    private static DateTime SafeGetLastWriteTime(string path)
    {
        try { return File.GetLastWriteTime(path); }
        catch { return DateTime.MinValue; }
    }
}
