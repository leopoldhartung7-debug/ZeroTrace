using System.Runtime.Versioning;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class FiveMRageMPAltVDeepForensicScanModule : IScanModule
{
    public string Name => "FiveM / RageMP / alt:V Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] FiveMCheatNames =
    [
        "kiddions", "modest_menu", "kiddion", "eulen", "hammafia", "xforce",
        "redengine", "nightfall", "emperor", "impulse", "outbreak", "cherax",
        "2take1", "midnight", "vanquish", "paragon", "lumia", "stand", "stand_menu",
        "genesis", "desudo", "skript", "lynx", "absolute", "sona", "hexui",
        "dxhook", "luna", "nitro", "matrix", "poka", "lamar", "fivem_bypass",
        "fivem_spoofer", "fivem_injector", "fivem_loader", "fivem_hack",
        "fivem_cheat", "fivem_mod", "fivem_trainer", "be_bypass",
        "battleye_bypass", "battleye_spoofer", "gtav_bypass", "gtav_spoofer",
        "gtav_injector", "gta5_cheat", "gta_online_cheat", "rockstar_bypass",
        "citizen_bypass", "citizengame_bypass", "cfx_bypass", "cfx_hack",
        "rage_hack", "rage_bypass", "rage_cheat", "rageplug", "pluginloader",
        "scripthookv_bypass", "dinput8_spoof", "version_spoof", "winmm_hook",
        "dsound_hook", "d3d11_hook", "dxgi_hook", "d3d9_hook",
        "asiloader_cheat", "openiv_cheat", "menyoo_bypass",
        "enhanced_native_trainer", "sinful_menu", "chaos_menu",
        "executor", "injector", "memhack", "extcheat", "internal_cheat",
        "external_cheat", "memreader", "memwriter", "procinjector",
    ];

    private static readonly string[] RageMPCheatNames =
    [
        "ragemp_cheat", "ragemp_hack", "ragemp_bypass", "ragemp_injector",
        "ragemp_mod", "ragemp_trainer", "ragemp_loader", "ragemp_spoofer",
        "rage_multiplayer_bypass", "rage_mp_cheat", "rage_mp_hack",
        "csharp_cheat", "csharp_hack", "dotnet_inject", "dotnet_hack",
        "resource_loader_cheat", "client_bypass", "client_hook",
        "nodemodule_cheat", "rage_injector",
    ];

    private static readonly string[] AltVCheatNames =
    [
        "altv_cheat", "altv_hack", "altv_bypass", "altv_injector",
        "altv_loader", "altv_spoofer", "altv_mod", "altv_trainer",
        "altv_menu", "altv_internal", "altv_external", "altvmp_cheat",
        "altvmp_hack", "altvmp_bypass", "altv_hook", "altv_exploit",
        "altv_internal_menu", "altv_external_menu",
    ];

    private static readonly string[] CheatKeywords =
    [
        "cheat", "hack", "inject", "bypass", "spoof", "aimbot", "esp",
        "wallhack", "triggerbot", "speedhack", "noclip", "godmode",
        "modmenu", "trainer", "exploit", "readmemory", "writememory",
        "openprocess", "createremotethread", "loadlibrary", "virtualallocex",
        "writeprocessmemory", "readprocessmemory", "bypass_ac",
        "anticheat_bypass", "kiddion", "eulen", "2take1", "stand",
        "cherax", "outbreak", "impulse", "nightfall", "emperor",
        "redengine", "hammafia", "modest menu", "lspdfr_bypass",
        "rph_bypass", "rage_bypass", "cef_bypass", "citizen_hack",
        "citizenmp", "fivepd_bypass",
    ];

    private static readonly string[] BypassProxyDllNames =
    [
        "dinput8.dll", "dsound.dll", "winmm.dll", "version.dll",
        "d3d9.dll", "d3d11.dll", "dxgi.dll", "opengl32.dll",
        "xinput1_3.dll", "xinput1_4.dll", "iphlpapi.dll",
        "nvapi64.dll", "nvapi.dll", "d3d12.dll", "ddraw.dll",
        "ws2_32.dll", "mswsock.dll", "binkw64.dll", "steamapi.dll",
        "steam_api64.dll", "bink2w64.dll",
    ];

    private static readonly string[] CheatServerKeywords =
    [
        "cheat", "hack", "modmenu", "aimbot", "esp", "wallhack",
        "bypass", "spoof", "kiddion", "eulen", "2take1", "stand",
        "cherax", "outbreak", "impulse", "undetected", "godmode",
        "freemoney", "free money", "unlock all", "injector",
    ];

    private static readonly string[] SuspiciousRegistryPaths =
    [
        @"SOFTWARE\FiveM",
        @"SOFTWARE\CitizenFX",
        @"SOFTWARE\RageMP",
        @"SOFTWARE\alt:V",
        @"SOFTWARE\GTAV",
        @"SOFTWARE\Rockstar Games\GTAV",
        @"SOFTWARE\Wow6432Node\FiveM",
    ];

    private static readonly string[] KnownCheatFileExtensions =
    [
        ".asi", ".dll", ".exe", ".sys", ".drv",
    ];

    private static readonly string[] FiveMLogPatterns =
    [
        "injected", "injection", "bypass", "hook installed", "hook active",
        "cheat loaded", "module loaded", "dll injected", "memory patch",
        "anticheat", "anti-cheat", "battleye", "be bypass", "eac bypass",
        "exploit", "aimbot", "esp active", "wallhack", "triggerbot",
        "noclip enabled", "godmode enabled", "speed hack", "money hack",
        "citizengame.exe", "gta5.exe", "gtav.exe",
    ];

    private static readonly string[] KnownFiveMCheatServers =
    [
        "cheatfivem", "modmenu-fivem", "fivem-cheat", "fivem-hack",
        "fivem-bypass", "cfx-bypass", "moddedfivem",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckFiveMCacheArtifacts(ctx, ct),
            CheckFiveMPluginDirectory(ctx, ct),
            CheckFiveMLogFiles(ctx, ct),
            CheckFiveMCrashDumps(ctx, ct),
            CheckFiveMCitizenFXConfig(ctx, ct),
            CheckFiveMRegistryArtifacts(ctx, ct),
            CheckRageMPPackages(ctx, ct),
            CheckRageMPClientArtifacts(ctx, ct),
            CheckAltVResources(ctx, ct),
            CheckAltVClientConfig(ctx, ct),
            CheckGameDirectoryCheatDlls(ctx, ct),
            CheckCheatToolDownloadPaths(ctx, ct),
            CheckCheatPurchaseArtifacts(ctx, ct),
            CheckFiveMBypassArtifacts(ctx, ct),
            CheckServerHistoryForCheatServers(ctx, ct),
            CheckMenyooAndScriptHookArtifacts(ctx, ct),
            CheckFiveMDataDirectory(ctx, ct),
            CheckGameModDirectories(ctx, ct)
        );
    }

    private Task CheckFiveMCacheArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var cachePaths = new[]
        {
            Path.Combine(localAppData, "FiveM", "FiveM.app", "cache"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "data"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "crashes"),
        };

        foreach (var cacheRoot in cachePaths)
        {
            if (!Directory.Exists(cacheRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(cacheRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (KnownCheatFileExtensions.Contains(ext))
                    {
                        foreach (var sig in FiveMCheatNames)
                        {
                            if (name.Contains(sig, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "FiveM Cache: Cheat Binary Artifact",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Known cheat binary name '{sig}' in FiveM cache",
                                    Detail = $"Path: {file}"
                                });
                                break;
                            }
                        }
                    }

                    if (ext is ".log" or ".txt" or ".json")
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);
                            foreach (var kw in CheatKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "FiveM Cache Log: Cheat Keyword",
                                        Risk = RiskLevel.High, Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Cheat keyword '{kw}' in FiveM cache file",
                                        Detail = content.Length > 300 ? content[..300] : content
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckFiveMPluginDirectory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var pluginPaths = new[]
        {
            Path.Combine(localAppData, "FiveM", "FiveM.app", "plugins"),
            Path.Combine(localAppData, "FiveM", "plugins"),
        };

        foreach (var pluginRoot in pluginPaths)
        {
            if (!Directory.Exists(pluginRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(pluginRoot, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    foreach (var sig in FiveMCheatNames)
                    {
                        if (name.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "FiveM Plugin: Cheat DLL",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cheat DLL '{sig}' in FiveM plugins directory",
                                Detail = $"Plugin path: {file}"
                            });
                            break;
                        }
                    }
                }

                foreach (var file in Directory.EnumerateFiles(pluginRoot, "*.asi", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "FiveM Plugin: ASI File Detected",
                        Risk = RiskLevel.High, Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "ASI plugin files can be used to load cheat modules in FiveM",
                        Detail = $"ASI path: {file}"
                    });
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMLogFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var logPaths = new[]
        {
            Path.Combine(localAppData, "FiveM", "FiveM.app", "logs"),
            Path.Combine(appData, "CitizenFX"),
            Path.Combine(localAppData, "FiveM"),
        };

        foreach (var logRoot in logPaths)
        {
            if (!Directory.Exists(logRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(logRoot, "*.log", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var pattern in FiveMLogPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "FiveM Log: Cheat Activity Pattern",
                                    Risk = RiskLevel.High, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Cheat activity pattern '{pattern}' in FiveM log",
                                    Detail = content.Length > 500 ? content[..500] : content
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckFiveMCrashDumps(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var crashPath = Path.Combine(localAppData, "FiveM", "FiveM.app", "crashes");
        if (!Directory.Exists(crashPath)) return;

        try
        {
            foreach (var file in Directory.EnumerateFiles(crashPath, "*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var name = Path.GetFileName(file).ToLowerInvariant();

                if (name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".log", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var kw in FiveMCheatNames)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "FiveM Crash Dump: Cheat Module Referenced",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Cheat module '{kw}' referenced in FiveM crash dump",
                                    Detail = content.Length > 400 ? content[..400] : content
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
    }, ct);

    private Task CheckFiveMCitizenFXConfig(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var configPaths = new[]
        {
            Path.Combine(appData, "CitizenFX", "fivem.cfg"),
            Path.Combine(appData, "CitizenFX", "fivem_settings.cfg"),
            Path.Combine(appData, "CitizenFX", "servers.json"),
            Path.Combine(appData, "CitizenFX", "favorites.json"),
            Path.Combine(appData, "CitizenFX", "history.json"),
            Path.Combine(appData, "CitizenFX", "server_history.json"),
        };

        foreach (var cfg in configPaths)
        {
            if (!File.Exists(cfg)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(cfg, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                var content = await sr.ReadToEndAsync(ct);
                foreach (var kw in CheatServerKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "FiveM Config: Cheat Server in History",
                            Risk = RiskLevel.High, Location = cfg,
                            FileName = Path.GetFileName(cfg),
                            Reason = $"Cheat-related server keyword '{kw}' in FiveM config/history",
                            Detail = content.Length > 600 ? content[..600] : content
                        });
                        break;
                    }
                }
                foreach (var kw in CheatKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "FiveM Config: Cheat Keyword",
                            Risk = RiskLevel.High, Location = cfg,
                            FileName = Path.GetFileName(cfg),
                            Reason = $"Cheat keyword '{kw}' in FiveM configuration",
                            Detail = content.Length > 600 ? content[..600] : content
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckFiveMRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hkcu = Registry.CurrentUser;
        foreach (var regPath in SuspiciousRegistryPaths)
        {
            try
            {
                using var key = hkcu.OpenSubKey(regPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                var names = key.GetValueNames();
                foreach (var valueName in names)
                {
                    var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    foreach (var kw in CheatKeywords)
                    {
                        if (val.Contains(kw, StringComparison.OrdinalIgnoreCase) ||
                            valueName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "FiveM Registry: Cheat Artifact",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{regPath}\{valueName}",
                                FileName = valueName,
                                Reason = $"Cheat keyword '{kw}' in FiveM registry path",
                                Detail = $"Value: {val}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckRageMPPackages(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var ragePaths = new[]
        {
            Path.Combine(docs, "RAGE Multiplayer"),
            Path.Combine(docs, "RAGEMP"),
            @"C:\RAGEMP",
            @"C:\RageMP",
            Path.Combine(userProfile, "RAGEMP"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RAGEMP"),
        };

        foreach (var rageRoot in ragePaths)
        {
            if (!Directory.Exists(rageRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(rageRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (KnownCheatFileExtensions.Contains(ext))
                    {
                        foreach (var sig in RageMPCheatNames)
                        {
                            if (name.Contains(sig, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "RageMP: Cheat Module Artifact",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Known RageMP cheat '{sig}' artifact found",
                                    Detail = $"Path: {file}"
                                });
                                break;
                            }
                        }
                    }

                    if (ext is ".log" or ".txt" or ".json" or ".cfg")
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);
                            foreach (var kw in CheatKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "RageMP Config/Log: Cheat Keyword",
                                        Risk = RiskLevel.High, Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Cheat keyword '{kw}' in RageMP file",
                                        Detail = content.Length > 400 ? content[..400] : content
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckRageMPClientArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var rageClientPaths = new[]
        {
            @"C:\RAGEMP\client_resources",
            @"C:\RAGEMP\dotnet",
            @"C:\RAGEMP\plugins",
            @"C:\RageMP\client_resources",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RAGEMP", "plugins"),
        };

        foreach (var clientRoot in rageClientPaths)
        {
            if (!Directory.Exists(clientRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(clientRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (KnownCheatFileExtensions.Contains(ext))
                    {
                        foreach (var sig in RageMPCheatNames)
                        {
                            if (name.Contains(sig, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "RageMP Client Resource: Cheat DLL",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Cheat DLL '{sig}' in RageMP client resources",
                                    Detail = $"Path: {file}"
                                });
                                break;
                            }
                        }
                    }

                    if (ext is ".js" or ".cs" or ".ts")
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);
                            var scriptCheatKws = new[] { "aimbot", "esp", "wallhack", "noclip", "godmode", "speedhack", "money", "bypass", "hack", "cheat", "triggerbot" };
                            foreach (var kw in scriptCheatKws)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "RageMP Script: Cheat Code Detected",
                                        Risk = RiskLevel.Critical, Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Cheat keyword '{kw}' in RageMP script file",
                                        Detail = content.Length > 400 ? content[..400] : content
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckAltVResources(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var altVPaths = new[]
        {
            Path.Combine(localAppData, "altv-client"),
            Path.Combine(localAppData, "altv-client", "data"),
            Path.Combine(localAppData, "altv-client", "resources"),
            Path.Combine(localAppData, "altv-client", "logs"),
            @"C:\altv\resources",
            @"C:\alt-v\resources",
        };

        foreach (var altVRoot in altVPaths)
        {
            if (!Directory.Exists(altVRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(altVRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (KnownCheatFileExtensions.Contains(ext))
                    {
                        foreach (var sig in AltVCheatNames)
                        {
                            if (name.Contains(sig, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "alt:V: Cheat Module Artifact",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Known alt:V cheat module '{sig}' detected",
                                    Detail = $"Path: {file}"
                                });
                                break;
                            }
                        }
                    }

                    if (ext is ".js" or ".mjs" or ".ts" or ".lua")
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);
                            var scriptKws = new[] { "aimbot", "esp", "noclip", "godmode", "bypass", "hack", "cheat", "inject", "exploit" };
                            foreach (var kw in scriptKws)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "alt:V Resource: Cheat Script Detected",
                                        Risk = RiskLevel.Critical, Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Cheat keyword '{kw}' in alt:V resource script",
                                        Detail = content.Length > 400 ? content[..400] : content
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckAltVClientConfig(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var configFiles = new[]
        {
            Path.Combine(localAppData, "altv-client", "data", "servers.json"),
            Path.Combine(localAppData, "altv-client", "data", "favorites.json"),
            Path.Combine(localAppData, "altv-client", "altv.cfg"),
            @"C:\altv\altv.cfg",
            @"C:\altv\altv.toml",
        };

        foreach (var cfg in configFiles)
        {
            if (!File.Exists(cfg)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(cfg, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                var content = await sr.ReadToEndAsync(ct);
                foreach (var kw in CheatServerKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "alt:V Config: Cheat Server Reference",
                            Risk = RiskLevel.High, Location = cfg,
                            FileName = Path.GetFileName(cfg),
                            Reason = $"Cheat keyword '{kw}' in alt:V config/server list",
                            Detail = content.Length > 600 ? content[..600] : content
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckGameDirectoryCheatDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var commonGamePaths = new[]
        {
            @"C:\Program Files\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files (x86)\Steam\steamapps\common\Grand Theft Auto V",
            @"D:\SteamLibrary\steamapps\common\Grand Theft Auto V",
            @"E:\SteamLibrary\steamapps\common\Grand Theft Auto V",
            @"C:\Games\Grand Theft Auto V",
            @"D:\Games\Grand Theft Auto V",
        };

        foreach (var gamePath in commonGamePaths)
        {
            if (!Directory.Exists(gamePath)) continue;
            try
            {
                foreach (var dll in Directory.EnumerateFiles(gamePath, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var dllName = Path.GetFileName(dll).ToLowerInvariant();

                    if (BypassProxyDllNames.Contains(dllName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "GTA V Directory: Suspicious Proxy DLL",
                            Risk = RiskLevel.Critical, Location = dll,
                            FileName = Path.GetFileName(dll),
                            Reason = $"Proxy DLL '{dllName}' in GTA V game root — common cheat injection vector",
                            Detail = $"Legitimate game installations do not contain '{dllName}' in the root directory"
                        });
                    }

                    foreach (var sig in FiveMCheatNames)
                    {
                        if (dllName.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "GTA V Directory: Cheat DLL Artifact",
                                Risk = RiskLevel.Critical, Location = dll,
                                FileName = Path.GetFileName(dll),
                                Reason = $"Cheat DLL name '{sig}' found in GTA V game directory",
                                Detail = $"Path: {dll}"
                            });
                            break;
                        }
                    }
                }

                foreach (var asi in Directory.EnumerateFiles(gamePath, "*.asi", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "GTA V Directory: ASI Plugin Present",
                        Risk = RiskLevel.High, Location = asi,
                        FileName = Path.GetFileName(asi),
                        Reason = "ASI files in GTA V root can load arbitrary code (cheat menus, trainers)",
                        Detail = $"ASI: {asi}"
                    });
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
        return Task.CompletedTask;
    }, ct);

    private Task CheckCheatToolDownloadPaths(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchPaths = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(Path.GetTempPath()),
        };

        foreach (var searchRoot in searchPaths)
        {
            if (!Directory.Exists(searchRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(searchRoot, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (KnownCheatFileExtensions.Contains(ext) || ext is ".zip" or ".rar" or ".7z")
                    {
                        var allSigs = FiveMCheatNames.Concat(RageMPCheatNames).Concat(AltVCheatNames);
                        foreach (var sig in allSigs)
                        {
                            if (name.Contains(sig, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Download/Desktop: Cheat Tool File",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Cheat tool artifact '{sig}' found in user downloads/desktop",
                                    Detail = $"Path: {file}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
        return Task.CompletedTask;
    }, ct);

    private Task CheckCheatPurchaseArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchRoots = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
        };

        var purchaseKeywords = new[]
        {
            "license", "key", "serial", "activation", "receipt", "invoice",
            "purchase", "subscription", "hwid", "hwid_reset", "spoofer_key",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileName(file).ToLowerInvariant();

                    bool hasCheatName = FiveMCheatNames.Any(s => name.Contains(s, StringComparison.OrdinalIgnoreCase)) ||
                                        RageMPCheatNames.Any(s => name.Contains(s, StringComparison.OrdinalIgnoreCase));
                    bool hasPurchaseKw = purchaseKeywords.Any(k => name.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (hasCheatName && hasPurchaseKw)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Cheat Purchase Artifact: License/Key File",
                            Risk = RiskLevel.Critical, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "File name matches cheat tool purchase artifact (license/key/receipt)",
                            Detail = $"Path: {file}"
                        });
                    }
                    else if (hasCheatName)
                    {
                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext is ".txt" or ".json" or ".xml")
                        {
                            try
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                var content = await sr.ReadToEndAsync(ct);
                                foreach (var pk in purchaseKeywords)
                                {
                                    if (content.Contains(pk, StringComparison.OrdinalIgnoreCase))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name, Title = "Cheat Purchase Artifact: License Data in File",
                                            Risk = RiskLevel.Critical, Location = file,
                                            FileName = Path.GetFileName(file),
                                            Reason = $"Cheat purchase data ('{pk}') found in cheat-related file",
                                            Detail = content.Length > 400 ? content[..400] : content
                                        });
                                        break;
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckFiveMBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var fiveMBypassPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM", "FiveM.app", "data", "cache", "priv"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM", "FiveM.app", "data", "game-storage"),
        };

        foreach (var bypassPath in fiveMBypassPaths)
        {
            if (!Directory.Exists(bypassPath)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(bypassPath, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    foreach (var sig in FiveMCheatNames)
                    {
                        if (name.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "FiveM Bypass: Cheat DLL in Private Cache",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cheat DLL '{sig}' in FiveM private cache — potential active bypass",
                                Detail = $"Path: {file}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
        return Task.CompletedTask;
    }, ct);

    private Task CheckServerHistoryForCheatServers(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var historyFiles = new[]
        {
            Path.Combine(appData, "CitizenFX", "servers.json"),
            Path.Combine(appData, "CitizenFX", "server_history.json"),
            Path.Combine(appData, "CitizenFX", "favorites.json"),
        };

        foreach (var histFile in historyFiles)
        {
            if (!File.Exists(histFile)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(histFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                var content = await sr.ReadToEndAsync(ct);
                foreach (var serverKw in KnownFiveMCheatServers)
                {
                    if (content.Contains(serverKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "FiveM Server History: Known Cheat Server",
                            Risk = RiskLevel.High, Location = histFile,
                            FileName = Path.GetFileName(histFile),
                            Reason = $"Known cheat server URL pattern '{serverKw}' in FiveM server history",
                            Detail = content.Length > 600 ? content[..600] : content
                        });
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckMenyooAndScriptHookArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var menyooPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Rockstar Games", "GTA V", "Menyoo Stuff"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "GTA V", "Menyoo Stuff"),
        };

        foreach (var menyooRoot in menyooPaths)
        {
            if (!Directory.Exists(menyooRoot)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "GTA V: Menyoo Trainer Artifacts",
                Risk = RiskLevel.High, Location = menyooRoot,
                FileName = "Menyoo Stuff",
                Reason = "Menyoo PC trainer artifact directory found — used as cheat menu base in FiveM/Story",
                Detail = $"Directory: {menyooRoot}"
            });
        }

        var scriptHookFiles = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Rockstar Games", "GTA V", "scripts"),
        };

        foreach (var scriptsDir in scriptHookFiles)
        {
            if (!Directory.Exists(scriptsDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(scriptsDir, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    foreach (var sig in FiveMCheatNames)
                    {
                        if (name.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "GTA V Scripts: Cheat Script DLL",
                                Risk = RiskLevel.High, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cheat script DLL '{sig}' in GTA V scripts folder",
                                Detail = $"Path: {file}"
                            });
                            break;
                        }
                    }
                }

                foreach (var file in Directory.EnumerateFiles(scriptsDir, "*.cs", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        var cheatCodeKws = new[] { "aimbot", "triggerbot", "esp", "wallhack", "noclip", "godmode", "speedhack", "bypass" };
                        foreach (var kw in cheatCodeKws)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "GTA V Scripts: Cheat Script Source Code",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Cheat keyword '{kw}' in GTA V script source",
                                    Detail = content.Length > 400 ? content[..400] : content
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckFiveMDataDirectory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dataDir = Path.Combine(localAppData, "FiveM", "FiveM.app", "data");
        if (!Directory.Exists(dataDir)) return;

        var suspiciousSubDirs = new[] { "hooks", "injected", "bypass", "hack", "cheat", "mod", "asi" };
        try
        {
            foreach (var subDir in Directory.EnumerateDirectories(dataDir, "*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(subDir).ToLowerInvariant();
                foreach (var suspicious in suspiciousSubDirs)
                {
                    if (dirName.Equals(suspicious, StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "FiveM Data: Suspicious Sub-Directory",
                            Risk = RiskLevel.High, Location = subDir,
                            FileName = dirName,
                            Reason = $"Suspicious directory name '{dirName}' in FiveM data path",
                            Detail = $"Directory: {subDir}"
                        });
                    }
                }
            }

            var gameStoragePath = Path.Combine(dataDir, "game-storage");
            if (Directory.Exists(gameStoragePath))
            {
                foreach (var file in Directory.EnumerateFiles(gameStoragePath, "*.json", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var kw in CheatKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "FiveM Game Storage: Cheat Data",
                                    Risk = RiskLevel.High, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Cheat keyword '{kw}' in FiveM game storage JSON",
                                    Detail = content.Length > 300 ? content[..300] : content
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
    }, ct);

    private Task CheckGameModDirectories(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var modDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Rockstar Games", "GTA V", "mods"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "GTA V", "mods"),
            @"C:\Program Files\Rockstar Games\Grand Theft Auto V\mods",
            @"C:\Program Files (x86)\Steam\steamapps\common\Grand Theft Auto V\mods",
        };

        foreach (var modRoot in modDirs)
        {
            if (!Directory.Exists(modRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(modRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (!KnownCheatFileExtensions.Contains(ext)) continue;
                    foreach (var sig in FiveMCheatNames)
                    {
                        if (name.Contains(sig, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "GTA V Mods: Cheat Mod File",
                                Risk = RiskLevel.High, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cheat mod '{sig}' in GTA V mods directory",
                                Detail = $"Path: {file}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
        return Task.CompletedTask;
    }, ct);
}
