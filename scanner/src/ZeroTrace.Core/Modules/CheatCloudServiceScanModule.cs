using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class CheatCloudServiceScanModule : IScanModule
{
    public string Name => "Cloud-Based Cheat Service Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 3;

    private static readonly string[] KnownCheatCloudExeNames =
    [
        "cloud_cheat.exe", "cheat_cloud.exe", "online_cheat.exe",
        "cheat_service.exe", "cheat_client.exe", "hack_client.exe",
        "hack_cloud.exe", "remote_cheat.exe", "cheat_remote.exe",
        "external_cheat.exe", "external_hack.exe", "overlay_cheat.exe",
        "cheat_overlay.exe", "radar_client.exe", "radar_hack.exe",
        "radar_overlay.exe", "esp_overlay.exe", "aim_overlay.exe",
        "aimbot_overlay.exe", "wallhack_overlay.exe", "esp_client.exe",
        "aimbot_client.exe", "cheat_loader_cloud.exe", "cloud_loader.exe",
        "online_loader.exe", "subscription_cheat.exe", "paid_cheat.exe",
        "license_cheat.exe", "hwid_cheat.exe", "rental_cheat.exe",
        "pastebin_cheat.exe", "github_cheat.exe", "discord_cheat.exe",
        "telegram_cheat.exe", "websocket_cheat.exe", "ws_cheat.exe",
        "stream_cheat.exe", "streaming_cheat.exe", "live_cheat.exe",
        "bypass_cloud.exe", "cloud_bypass.exe", "online_bypass.exe",
        "fivem_cloud.exe", "gta_cloud.exe", "altv_cloud.exe",
        "ragemp_cloud.exe", "apex_cloud.exe", "warzone_cloud.exe",
        "valorant_cloud.exe", "rust_cloud.exe", "tarkov_cloud.exe",
    ];

    private static readonly string[] KnownRadarDomainPatterns =
    [
        "radar.cheat", "cheathub", "cheatcloud", "hackcloud",
        "cheatservice", "hackservice", "espservice", "aimbotservice",
        "cheatstore", "hackstore", "cheatshop", "hackshop",
        "privatecheats", "premiumcheats", "elitecheats",
        "radaroverlay", "espoverlay", "aimbotoverlay",
    ];

    private static readonly int[] KnownRadarPorts =
    [
        28003, 28004, 3000, 3001, 3002, 3003, 3004, 3005,
        7000, 7001, 7002, 8080, 8081, 8082, 8083, 8085,
        9000, 9001, 9002, 5000, 5001, 5002,
        1234, 4321, 6969, 6666, 7777, 8888, 9999,
        31337, 13337, 1337,
    ];

    private static readonly string[] CloudCheatConfigKeywords =
    [
        "cloud_auth", "cloud_token", "auth_token", "cheat_token",
        "hwid_token", "license_key", "cheat_license", "hack_license",
        "subscription_key", "serial_key", "activation_key",
        "server_url", "cheat_server", "radar_server", "esp_server",
        "aimbot_server", "cloud_host", "remote_host", "cheat_host",
        "websocket_url", "ws_url", "wss_url", "radar_url",
        "esp_url", "aimbot_url", "overlay_url", "stream_url",
        "cheat_port", "radar_port", "esp_port", "aimbot_port",
        "cloud_port", "remote_port", "server_port",
        "api_key", "api_token", "api_secret", "client_secret",
        "bypass_cloud", "cloud_bypass", "cloud_inject",
        "discord_webhook", "telegram_token", "discord_token",
        "pastebin_key", "github_token", "gitlab_token",
    ];

    private static readonly string[] CloudCheatWebSocketIndicators =
    [
        "ws://localhost:", "wss://localhost:", "ws://127.0.0.1:",
        "wss://127.0.0.1:", "ws://0.0.0.0:", "new WebSocket(",
        "WebSocket.connect(", "websocket.connect(",
        "io.connect(", "socket.connect(", "SocketIO(",
        "radar_ws", "cheat_ws", "esp_ws", "aimbot_ws",
    ];

    private static readonly string[] UserDirs;

    static CheatCloudServiceScanModule()
    {
        var dirs = new List<string>();
        string? profile = Environment.GetEnvironmentVariable("USERPROFILE");
        string? appData = Environment.GetEnvironmentVariable("APPDATA");
        string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        string? temp = Environment.GetEnvironmentVariable("TEMP");
        string? desktop = profile != null ? Path.Combine(profile, "Desktop") : null;
        string? downloads = profile != null ? Path.Combine(profile, "Downloads") : null;

        foreach (var d in new[] { appData, localAppData, temp, desktop, downloads })
            if (d != null) dirs.Add(d);

        UserDirs = [.. dirs];
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            ScanForCloudCheatExes(ctx, ct),
            ScanConfigsForCloudCheatKeywords(ctx, ct),
            CheckRadarPortListeners(ctx, ct),
            ScanHtmlFilesForWebSocketRadar(ctx, ct),
            CheckKnownCheatServiceRegistryKeys(ctx, ct),
            ScanForCloudCheatAuthFiles(ctx, ct),
            CheckLoopbackConnectionsOnCheatPorts(ctx, ct),
            ScanStartupEntriesForCloudCheats(ctx, ct),
            ScanForCloudCheatLogFiles(ctx, ct),
            ScanMuiCacheForCloudCheats(ctx, ct)
        ).ConfigureAwait(false);
    }

    private Task ScanForCloudCheatExes(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string cloudExe in KnownCheatCloudExeNames)
                        {
                            if (fn.Equals(cloudExe, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cloud-Based Cheat Client Executable Found",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known cloud/subscription-based cheat client executable detected",
                                    Detail = $"Cloud cheat client '{fn}' found at: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanConfigsForCloudCheatKeywords(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext != ".json" && ext != ".cfg" && ext != ".ini" && ext != ".txt"
                            && ext != ".yaml" && ext != ".toml" && ext != ".conf") continue;
                        if (new FileInfo(file).Length > 1_000_000) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            int matchCount = 0;
                            string? firstMatch = null;
                            foreach (string kw in CloudCheatConfigKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    matchCount++;
                                    firstMatch ??= kw;
                                    if (matchCount >= 2) break;
                                }
                            }

                            if (matchCount >= 2)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cloud Cheat Service Configuration Found",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Config contains {matchCount} cloud cheat service keywords (e.g. '{firstMatch}')",
                                    Detail = $"Cloud cheat config in: {file}"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                        catch (IOException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckRadarPortListeners(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                var tcpListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
                foreach (var endpoint in tcpListeners)
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (int radarPort in KnownRadarPorts)
                    {
                        if (endpoint.Port == radarPort)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Known Radar/Cloud Cheat Port Listening",
                                Risk = Risk.High,
                                Location = $"TCP listener on port {radarPort}",
                                FileName = "network",
                                Reason = $"Port {radarPort} is actively listening — known radar/cloud cheat service port",
                                Detail = $"Active TCP listener on {endpoint.Address}:{radarPort}"
                            });
                            break;
                        }
                    }
                }

                var udpListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();
                foreach (var endpoint in udpListeners)
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (int radarPort in KnownRadarPorts)
                    {
                        if (endpoint.Port == radarPort)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Known Radar/Cloud Cheat UDP Port Active",
                                Risk = Risk.High,
                                Location = $"UDP listener on port {radarPort}",
                                FileName = "network",
                                Reason = $"UDP port {radarPort} is active — known radar/cheat stream port",
                                Detail = $"Active UDP listener on {endpoint.Address}:{radarPort}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }, ct);
    }

    private Task ScanHtmlFilesForWebSocketRadar(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.html", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            int wsMatchCount = 0;
                            string? firstWsMatch = null;
                            foreach (string wsIndicator in CloudCheatWebSocketIndicators)
                            {
                                if (content.Contains(wsIndicator, StringComparison.OrdinalIgnoreCase))
                                {
                                    wsMatchCount++;
                                    firstWsMatch ??= wsIndicator;
                                    if (wsMatchCount >= 2) break;
                                }
                            }

                            if (wsMatchCount >= 1 &&
                                (content.Contains("radar", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("player", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("esp", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Radar/ESP WebSocket HTML Overlay Found",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"HTML file contains WebSocket radar/ESP overlay code (pattern: '{firstWsMatch}')",
                                    Detail = $"Radar HTML overlay: {file}"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                        catch (IOException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckKnownCheatServiceRegistryKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] cheatServiceRegKeys =
            [
                @"SOFTWARE\CloudCheat",
                @"SOFTWARE\CheatCloud",
                @"SOFTWARE\OnlineCheat",
                @"SOFTWARE\HackCloud",
                @"SOFTWARE\RadarOverlay",
                @"SOFTWARE\EspOverlay",
                @"SOFTWARE\AimbotCloud",
                @"SOFTWARE\CheatService",
                @"SOFTWARE\HackService",
                @"SOFTWARE\SubscriptionCheat",
            ];

            foreach (string regKey in cheatServiceRegKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(regKey)
                                          ?? Registry.CurrentUser.OpenSubKey(regKey);
                    if (key != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cloud Cheat Service Registry Key Found",
                            Risk = Risk.Critical,
                            Location = regKey,
                            FileName = "registry",
                            Reason = "Known cloud cheat service tool created this registry artifact",
                            Detail = $"Cloud cheat registry key: {regKey}"
                        });
                        ctx.IncrementRegistryKeys();
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForCloudCheatAuthFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] authFileNames =
            [
                "auth.bin", "auth.dat", "auth.key", "license.key",
                "license.dat", "license.bin", "hwid.key", "hwid.dat",
                "token.bin", "token.dat", "token.key", "cheat_token.txt",
                "hack_license.txt", "subscription.key", "subscription.dat",
                "activation.key", "activation.dat", "serial.key",
                "serial.dat", "cloud_auth.json", "cheat_auth.json",
                "hack_auth.json", "remote_auth.json", "api_key.txt",
                "api_token.txt", "client_token.txt", "session_token.txt",
            ];

            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string authFile in authFileNames)
                        {
                            if (fn.Equals(authFile, StringComparison.OrdinalIgnoreCase))
                            {
                                string dirPath = Path.GetDirectoryName(file) ?? string.Empty;
                                string dirName = Path.GetFileName(dirPath);
                                bool inCheatDir = dirName.Contains("cheat", StringComparison.OrdinalIgnoreCase)
                                              || dirName.Contains("hack", StringComparison.OrdinalIgnoreCase)
                                              || dirName.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                                              || dirName.Contains("cloud", StringComparison.OrdinalIgnoreCase)
                                              || dirName.Contains("loader", StringComparison.OrdinalIgnoreCase);

                                if (inCheatDir)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Cloud Cheat Authentication File Found",
                                        Risk = Risk.Critical,
                                        Location = file,
                                        FileName = fn,
                                        Reason = $"Authentication/license file '{fn}' found in cheat directory",
                                        Detail = $"Cloud cheat auth file: {file}"
                                    });
                                    ctx.IncrementFiles();
                                }
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckLoopbackConnectionsOnCheatPorts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                var tcpConns = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections();
                foreach (var conn in tcpConns)
                {
                    ct.ThrowIfCancellationRequested();
                    bool isLoopback = conn.RemoteEndPoint.Address.ToString() == "127.0.0.1"
                                   || conn.RemoteEndPoint.Address.ToString() == "::1";
                    if (!isLoopback) continue;

                    foreach (int radarPort in KnownRadarPorts)
                    {
                        if (conn.RemoteEndPoint.Port == radarPort || conn.LocalEndPoint.Port == radarPort)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Loopback Connection on Known Radar/Cheat Port",
                                Risk = Risk.Critical,
                                Location = $"TCP loopback {conn.LocalEndPoint} → {conn.RemoteEndPoint}",
                                FileName = "network",
                                Reason = $"Active loopback TCP connection on port {radarPort} — radar memory reader to overlay pattern",
                                Detail = $"Connection state: {conn.State} | {conn.LocalEndPoint} ↔ {conn.RemoteEndPoint}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }, ct);
    }

    private Task ScanStartupEntriesForCloudCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] runKeys =
            [
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ];

            foreach (string runKey in runKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using RegistryKey? key = Registry.CurrentUser.OpenSubKey(runKey)
                                          ?? Registry.LocalMachine.OpenSubKey(runKey);
                    if (key == null) continue;

                    foreach (string valName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        string? valData = key.GetValue(valName) as string;
                        if (valData == null) continue;
                        foreach (string cloudExe in KnownCheatCloudExeNames)
                        {
                            if (valData.Contains(cloudExe, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cloud Cheat Client in Windows Startup",
                                    Risk = Risk.Critical,
                                    Location = runKey,
                                    FileName = "registry",
                                    Reason = $"Startup entry '{valName}' launches cloud cheat client",
                                    Detail = $"Startup command: {valData}"
                                });
                                ctx.IncrementRegistryKeys();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForCloudCheatLogFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] cloudCheatLogNames =
            [
                "cloud_cheat.log", "cheat_cloud.log", "online_cheat.log",
                "radar.log", "radar_client.log", "esp_overlay.log",
                "aimbot_overlay.log", "cloud_bypass.log", "bypass_cloud.log",
                "cheat_service.log", "hack_service.log", "remote_cheat.log",
                "subscription.log", "license_check.log", "auth.log",
                "cheat_auth.log", "hack_auth.log", "cloud_auth.log",
            ];

            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string logName in cloudCheatLogNames)
                        {
                            if (fn.Equals(logName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cloud Cheat Service Log File Found",
                                    Risk = Risk.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Cloud cheat/radar service log file found — indicates previous usage",
                                    Detail = $"Cloud cheat log: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanMuiCacheForCloudCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? muiCache = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
                if (muiCache == null) return;

                foreach (string valName in muiCache.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (string cloudExe in KnownCheatCloudExeNames)
                    {
                        if (valName.Contains(cloudExe, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cloud Cheat Client Execution Evidence in MUICache",
                                Risk = Risk.Critical,
                                Location = @"HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                                FileName = "registry",
                                Reason = "MUICache records previous execution of cloud cheat client",
                                Detail = $"MUICache entry: {valName}"
                            });
                            ctx.IncrementRegistryKeys();
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }
}
