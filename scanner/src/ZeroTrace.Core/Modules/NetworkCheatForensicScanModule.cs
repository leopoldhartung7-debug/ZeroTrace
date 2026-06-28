using System.Runtime.Versioning;
using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class NetworkCheatForensicScanModule : IScanModule
{
    public string Name => "Network Cheat Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] ACServerDomains =
    [
        "battleye.com", "battleye.de", "be-guardian.com",
        "easy.ac", "easyanticheat.net", "eac.epicgames.com",
        "cfx.re", "fivem.net", "citizenfx.com", "runtime.fivem.net",
        "keymaster.fivem.net", "globalblocks.fivem.net",
        "nui-game-internal", "nui-cdn.fivem.net",
        "valve.net", "steamgames.com", "steamcommunity.com",
        "vac.valve.net", "vacauth.valve.net",
        "rockstargames.com", "socialclub.rockstargames.com",
        "launcher.rockstargames.com",
        "anticheats.net", "anticheat.io",
        "mhyprot2.mihoyo.com", "zenless.mihoyo.com",
    ];

    private static readonly string[] CheatC2Keywords =
    [
        "cheat", "hack", "bypass", "spoof", "inject", "modmenu",
        "kiddions", "eulen", "2take1", "stand", "cherax", "outbreak",
        "impulse", "redengine", "hammafia", "aimbot", "esp",
        "wallhack", "triggerbot", "undetected", "hwid", "spoofer",
        "license-server", "licenseserver", "cheat-server", "cheatserver",
        "update-server", "updateserver", "cheat-update", "cheatupdate",
        "loader-server", "loaderserver", "key-server", "keyserver",
    ];

    private static readonly string[] VPNRegistryPaths =
    [
        @"SOFTWARE\NordVPN",
        @"SOFTWARE\ExpressVPN",
        @"SOFTWARE\CyberGhost",
        @"SOFTWARE\ProtonVPN",
        @"SOFTWARE\Mullvad VPN",
        @"SOFTWARE\IPVanish",
        @"SOFTWARE\Private Internet Access",
        @"SOFTWARE\Surfshark",
        @"SOFTWARE\HideMyAss",
        @"SOFTWARE\TorGuard",
        @"SOFTWARE\AirVPN",
        @"SOFTWARE\WindScribe",
    ];

    private static readonly string[] FirewallRuleCheatKeywords =
    [
        "block ac", "block anticheat", "block battleye", "block eac",
        "block fivem", "block cfx", "block easy anti", "block vac",
        "battleye block", "eac block", "fivem block", "cfx block",
        "cheat", "hack", "bypass", "spoof",
    ];

    private static readonly string[] ProxyKeywords =
    [
        "cheat", "hack", "bypass", "intercept", "mitm", "proxy_cheat",
        "ac_proxy", "anticheat_proxy",
    ];

    private static readonly string[] HostsFileBlockPatterns =
    [
        "battleye.com", "battleye.de", "easy.ac", "easyanticheat",
        "cfx.re", "fivem.net", "citizenfx.com", "keymaster.fivem",
        "globalblocks.fivem", "runtime.fivem",
        "rockstargames.com", "socialclub.rockstar",
        "vac.valve", "vacauth.valve",
        "anticheat", "anti-cheat", "anticheats",
    ];

    private static readonly string[] PacketSnifferTools =
    [
        "wireshark", "tshark", "tcpdump", "npcap", "winpcap",
        "fiddler", "charles", "burpsuite", "burp_suite",
        "mitmproxy", "mitm_proxy", "proxyman",
        "networkmonitor", "network_monitor", "netmon",
        "rawshark", "dumpcap",
    ];

    private static readonly string[] TorArtifactPaths =
    [
        @"%APPDATA%\Tor Browser",
        @"%LOCALAPPDATA%\Tor Browser",
        @"%USERPROFILE%\Desktop\Tor Browser",
        @"%USERPROFILE%\Downloads\Tor Browser",
    ];

    private static readonly string[] LSPBypassKeys =
    [
        @"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5",
        @"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckHostsFileManipulation(ctx, ct),
            CheckWindowsFirewallBlockRules(ctx, ct),
            CheckVPNArtifacts(ctx, ct),
            CheckPacketSnifferInstalls(ctx, ct),
            CheckProxySettings(ctx, ct),
            CheckTorBrowserArtifacts(ctx, ct),
            CheckNetworkAdapterPromiscuousMode(ctx, ct),
            CheckWinsockLSPBypass(ctx, ct),
            CheckDNSCacheArtifacts(ctx, ct),
            CheckNetworkConnectionLogs(ctx, ct),
            CheckBrowserHistoryForCheatSites(ctx, ct),
            CheckACServerBlockInRegistry(ctx, ct),
            CheckNetworkDriverBypassArtifacts(ctx, ct),
            CheckCheatUpdateServerConnections(ctx, ct),
            CheckIPHelperTableArtifacts(ctx, ct),
            CheckNetBIOSEvasion(ctx, ct),
            CheckCheatLicenseServerArtifacts(ctx, ct),
            CheckNPCAPWinPcapArtifacts(ctx, ct)
        );
    }

    private Task CheckHostsFileManipulation(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
        if (!File.Exists(hostsPath)) return;
        ctx.IncrementFiles();

        try
        {
            using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            var content = await sr.ReadToEndAsync(ct);

            foreach (var domain in HostsFileBlockPatterns)
            {
                if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                {
                    var lines = content.Split('\n').Where(l =>
                        !l.TrimStart().StartsWith('#') &&
                        l.Contains(domain, StringComparison.OrdinalIgnoreCase)).ToList();

                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "Hosts File: Anti-Cheat Server Blocked",
                        Risk = Risk.Critical, Location = hostsPath,
                        FileName = "hosts",
                        Reason = $"Anti-cheat domain '{domain}' blocked in hosts file — prevents AC server communication",
                        Detail = string.Join("; ", lines.Take(5))
                    });
                }
            }

            foreach (var kw in CheatC2Keywords)
            {
                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "Hosts File: Cheat Server Entry",
                        Risk = Risk.High, Location = hostsPath,
                        FileName = "hosts",
                        Reason = $"Cheat-related keyword '{kw}' in hosts file — potential cheat C2 server redirect",
                        Detail = content.Length > 600 ? content[..600] : content
                    });
                    break;
                }
            }

            var lines2 = content.Split('\n').Where(l =>
                !l.TrimStart().StartsWith('#') &&
                !string.IsNullOrWhiteSpace(l)).ToList();

            if (lines2.Count > 50)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "Hosts File: Unusually Large (Possible Block List)",
                    Risk = Risk.Medium, Location = hostsPath,
                    FileName = "hosts",
                    Reason = $"Hosts file has {lines2.Count} non-comment entries — may contain AC server block list",
                    Detail = $"Entry count: {lines2.Count}"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckWindowsFirewallBlockRules(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var firewallRegPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        using var hklm = Registry.LocalMachine;
        try
        {
            using var key = hklm.OpenSubKey(firewallRegPath);
            if (key == null) return;

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                var val = key.GetValue(valueName)?.ToString() ?? string.Empty;

                foreach (var domain in ACServerDomains)
                {
                    if (val.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Firewall Rule: Anti-Cheat Server Blocked",
                            Risk = Risk.Critical,
                            Location = $@"HKLM\{firewallRegPath}\{valueName}",
                            FileName = valueName,
                            Reason = $"Firewall rule blocks anti-cheat domain '{domain}' — active AC communication block",
                            Detail = val.Length > 500 ? val[..500] : val
                        });
                        break;
                    }
                }

                foreach (var kw in FirewallRuleCheatKeywords)
                {
                    if (val.Contains(kw, StringComparison.OrdinalIgnoreCase) ||
                        valueName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Firewall Rule: Cheat-Related Block Rule",
                            Risk = Risk.High,
                            Location = $@"HKLM\{firewallRegPath}\{valueName}",
                            FileName = valueName,
                            Reason = $"Firewall rule with cheat keyword '{kw}' — AC bypass attempt via network block",
                            Detail = val.Length > 500 ? val[..500] : val
                        });
                        break;
                    }
                }
            }
        }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckVPNArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var vpnPath in VPNRegistryPaths)
        {
            foreach (var hive in new[] { hkcu, hklm })
            {
                try
                {
                    using var key = hive.OpenSubKey(vpnPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    var vpnName = vpnPath.Split('\\').Last();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "VPN Artifact: VPN Software Installed",
                        Risk = Risk.Medium,
                        Location = $@"HKCU\{vpnPath}",
                        FileName = vpnName,
                        Reason = $"VPN software '{vpnName}' registry artifact — used to anonymize cheat purchases and C2 traffic",
                        Detail = $"Registry path: {vpnPath}"
                    });
                }
                catch { }
            }
        }

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var vpnDataPaths = new[]
        {
            Path.Combine(appData, "NordVPN"), Path.Combine(localAppData, "NordVPN"),
            Path.Combine(appData, "ExpressVPN"), Path.Combine(localAppData, "ExpressVPN"),
            Path.Combine(appData, "ProtonVPN"), Path.Combine(localAppData, "ProtonVPN"),
            Path.Combine(appData, "Mullvad VPN"), Path.Combine(localAppData, "Mullvad"),
            Path.Combine(appData, "Private Internet Access"),
            Path.Combine(appData, "CyberGhost"),
        };

        foreach (var vpnData in vpnDataPaths)
        {
            if (!Directory.Exists(vpnData)) continue;
            var vpnName = Path.GetFileName(vpnData);
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "VPN Artifact: VPN Data Directory Found",
                Risk = Risk.Medium, Location = vpnData,
                FileName = vpnName,
                Reason = $"VPN client data directory '{vpnName}' found — VPNs used to hide cheat C2 and purchase traffic",
                Detail = $"Path: {vpnData}"
            });
        }
    }, ct);

    private Task CheckPacketSnifferInstalls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };
        using var hklm = Registry.LocalMachine;

        foreach (var uninstallPath in uninstallPaths)
        {
            try
            {
                using var uninstallKey = hklm.OpenSubKey(uninstallPath);
                if (uninstallKey == null) continue;
                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var appKey = uninstallKey.OpenSubKey(subKeyName);
                        if (appKey == null) continue;
                        ctx.IncrementRegistryKeys();
                        var displayName = appKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        foreach (var tool in PacketSnifferTools)
                        {
                            if (displayName.Contains(tool, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Packet Sniffer Installed: AC Traffic Analysis Tool",
                                    Risk = Risk.High,
                                    Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                    FileName = displayName,
                                    Reason = $"Packet sniffer '{displayName}' installed — used to analyze anti-cheat traffic patterns",
                                    Detail = $"Install location: {appKey.GetValue("InstallLocation") ?? "unknown"}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckProxySettings(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var internetSettingsPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
        using var hkcu = Registry.CurrentUser;

        try
        {
            using var key = hkcu.OpenSubKey(internetSettingsPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();

            var proxyEnable = key.GetValue("ProxyEnable")?.ToString();
            var proxyServer = key.GetValue("ProxyServer")?.ToString() ?? string.Empty;
            var proxyOverride = key.GetValue("ProxyOverride")?.ToString() ?? string.Empty;
            var autoConfigUrl = key.GetValue("AutoConfigURL")?.ToString() ?? string.Empty;

            if (proxyEnable == "1" && !string.IsNullOrEmpty(proxyServer))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "Proxy Enabled: Potential AC Traffic Intercept",
                    Risk = Risk.High,
                    Location = $@"HKCU\{internetSettingsPath}",
                    FileName = "ProxyServer",
                    Reason = $"System proxy is enabled ({proxyServer}) — can intercept/modify anti-cheat network communication",
                    Detail = $"Proxy: {proxyServer}, Override: {proxyOverride}"
                });
            }

            if (!string.IsNullOrEmpty(autoConfigUrl))
            {
                foreach (var kw in ProxyKeywords)
                {
                    if (autoConfigUrl.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Auto-Proxy Config: Cheat-Related PAC File",
                            Risk = Risk.Critical,
                            Location = $@"HKCU\{internetSettingsPath}",
                            FileName = "AutoConfigURL",
                            Reason = $"Proxy auto-config URL contains cheat keyword '{kw}'",
                            Detail = $"AutoConfigURL: {autoConfigUrl}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckTorBrowserArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var torPaths = new[]
        {
            Path.Combine(appData, "Tor Browser"),
            Path.Combine(userProfile, "Desktop", "Tor Browser"),
            Path.Combine(userProfile, "Downloads", "Tor Browser"),
            Path.Combine(userProfile, "Documents", "Tor Browser"),
            Path.Combine(userProfile, "Tor Browser"),
        };

        foreach (var torPath in torPaths)
        {
            if (!Directory.Exists(torPath)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "Tor Browser: Anonymous Browsing Artifact",
                Risk = Risk.High, Location = torPath,
                FileName = "Tor Browser",
                Reason = "Tor Browser installation found — used for anonymous cheat purchases and forum access",
                Detail = $"Tor path: {torPath}"
            });
        }

        var torRegistryPaths = new[]
        {
            @"SOFTWARE\Tor",
            @"SOFTWARE\The Tor Project",
        };
        using var hkcu = Registry.CurrentUser;
        foreach (var torReg in torRegistryPaths)
        {
            try
            {
                using var key = hkcu.OpenSubKey(torReg);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "Tor Registry: Tor Software Artifact",
                    Risk = Risk.Medium,
                    Location = $@"HKCU\{torReg}",
                    FileName = "Tor",
                    Reason = "Tor Project registry artifact found — anonymous network usage",
                    Detail = $"Registry: {torReg}"
                });
            }
            catch { }
        }
        return Task.CompletedTask;
    }, ct);

    private Task CheckNetworkAdapterPromiscuousMode(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var npcapRegPath = @"SYSTEM\CurrentControlSet\Services\npcap";
        var winpcapRegPath = @"SYSTEM\CurrentControlSet\Services\npf";
        using var hklm = Registry.LocalMachine;

        foreach (var (path, name) in new[] { (npcapRegPath, "npcap"), (winpcapRegPath, "WinPcap/npf") })
        {
            try
            {
                using var key = hklm.OpenSubKey(path);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = $"Packet Capture Driver: {name} Installed",
                    Risk = Risk.High,
                    Location = $@"HKLM\{path}",
                    FileName = name,
                    Reason = $"Packet capture driver '{name}' installed — enables raw network capture to analyze AC traffic",
                    Detail = $"Service: {name}"
                });
            }
            catch { }
        }
    }, ct);

    private Task CheckWinsockLSPBypass(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        foreach (var lspPath in LSPBypassKeys)
        {
            try
            {
                using var key = hklm.OpenSubKey(lspPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var catalogKey = key.OpenSubKey(subKeyName);
                        if (catalogKey == null) continue;
                        var catalogEntry = catalogKey.GetValue("PackedCatalogItem")?.ToString() ?? string.Empty;
                        var libraryPath = catalogKey.GetValue("LibraryPath")?.ToString() ?? string.Empty;

                        foreach (var kw in new[] { "cheat", "hack", "bypass", "intercept", "proxy" })
                        {
                            if (libraryPath.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Winsock LSP: Suspicious DLL in Network Stack",
                                    Risk = Risk.Critical,
                                    Location = $@"HKLM\{lspPath}\{subKeyName}",
                                    FileName = Path.GetFileName(libraryPath),
                                    Reason = $"Suspicious LSP DLL '{libraryPath}' in Winsock stack — can intercept game network traffic",
                                    Detail = $"Library: {libraryPath}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckDNSCacheArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var dnsCacheRegPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Client\Servers";
        using var hklm = Registry.LocalMachine;

        var altDnsServers = new[]
        {
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "9.9.9.9", "208.67.222.222",
        };

        try
        {
            var interfacePath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
            using var ifKey = hklm.OpenSubKey(interfacePath);
            if (ifKey == null) return;
            ctx.IncrementRegistryKeys();

            foreach (var ifName in ifKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var ifSubKey = ifKey.OpenSubKey(ifName);
                    if (ifSubKey == null) continue;
                    var nameServer = ifSubKey.GetValue("NameServer")?.ToString() ?? string.Empty;
                    var dhcpNameServer = ifSubKey.GetValue("DhcpNameServer")?.ToString() ?? string.Empty;

                    foreach (var dns in new[] { nameServer, dhcpNameServer })
                    {
                        if (string.IsNullOrEmpty(dns)) continue;
                        foreach (var suspicious in new[] { "cheat", "bypass", "hack" })
                        {
                            if (dns.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "DNS Server: Suspicious DNS Configuration",
                                    Risk = Risk.High,
                                    Location = $@"HKLM\{interfacePath}\{ifName}",
                                    FileName = "NameServer",
                                    Reason = $"Custom DNS server '{dns}' contains cheat keyword — may redirect AC DNS queries",
                                    Detail = $"Interface: {ifName}, DNS: {dns}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckNetworkConnectionLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        var networkLogPaths = new[]
        {
            Path.Combine(systemRoot, "System32", "winevt", "Logs", "Microsoft-Windows-NetworkProfile%4Operational.evtx"),
            Path.Combine(systemRoot, "System32", "winevt", "Logs", "Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx"),
        };

        var networkTraceLogs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Wireshark"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Fiddler2"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Charles"),
        };

        foreach (var logDir in networkTraceLogs)
        {
            if (!Directory.Exists(logDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(logDir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not (".log" or ".txt" or ".saz" or ".pcap" or ".pcapng" or ".xml")) continue;

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var domain in ACServerDomains)
                        {
                            if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Network Capture: AC Traffic Recorded",
                                    Risk = Risk.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"AC domain '{domain}' in network capture log — anti-cheat traffic was intercepted/analyzed",
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

    private Task CheckBrowserHistoryForCheatSites(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var browserHistoryPaths = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
            Path.Combine(appData, "Mozilla", "Firefox", "Profiles"),
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
            Path.Combine(localAppData, "Opera Software", "Opera Stable", "History"),
        };

        var cheatShopKeywords = new[]
        {
            "cheat", "hack", "aimbot", "esp", "wallhack", "triggerbot",
            "kiddion", "eulen", "2take1", "stand", "cherax", "outbreak",
            "impulse", "bypass", "modmenu", "mod menu", "undetected",
            "hwid spoofer", "hwid reset", "cheat shop", "cheat buy",
            "buy cheat", "fivem cheat", "ragemp cheat", "altv cheat",
            "gta hack", "gta cheat",
        };

        foreach (var histPath in browserHistoryPaths)
        {
            if (histPath.EndsWith("Profiles", StringComparison.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(histPath)) continue;
                try
                {
                    foreach (var profile in Directory.EnumerateDirectories(histPath))
                    {
                        var placesSqlite = Path.Combine(profile, "places.sqlite");
                        if (!File.Exists(placesSqlite)) continue;
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(placesSqlite, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            var buffer = new byte[Math.Min(fs.Length, 1024 * 1024)];
                            await fs.ReadAsync(buffer, ct);
                            var content = System.Text.Encoding.UTF8.GetString(buffer);
                            foreach (var kw in cheatShopKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "Firefox History: Cheat Site Access",
                                        Risk = Risk.High, Location = placesSqlite,
                                        FileName = "places.sqlite",
                                        Reason = $"Cheat keyword '{kw}' in Firefox browser history database",
                                        Detail = $"Profile: {Path.GetFileName(profile)}"
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { }
                continue;
            }

            if (!File.Exists(histPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var buffer = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
                await fs.ReadAsync(buffer, ct);
                var content = System.Text.Encoding.UTF8.GetString(buffer);
                foreach (var kw in cheatShopKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Browser History: Cheat Shop/Forum Access",
                            Risk = Risk.High, Location = histPath,
                            FileName = Path.GetFileName(histPath),
                            Reason = $"Cheat keyword '{kw}' found in Chrome/Edge browser history database",
                            Detail = $"Path: {histPath}"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckACServerBlockInRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var tcpipSecurityPath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
        var peerNameResPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures";
        using var hklm = Registry.LocalMachine;

        try
        {
            using var key = hklm.OpenSubKey(tcpipSecurityPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            var filterIPs = key.GetValue("SecurityFilters")?.ToString() ?? string.Empty;
            if (!string.IsNullOrEmpty(filterIPs))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "TCP/IP Security Filters: Custom IP Block",
                    Risk = Risk.High,
                    Location = $@"HKLM\{tcpipSecurityPath}",
                    FileName = "SecurityFilters",
                    Reason = "Custom TCP/IP security filters configured — may block anti-cheat server IPs",
                    Detail = $"Filters: {filterIPs}"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckNetworkDriverBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var servicesPath = @"SYSTEM\CurrentControlSet\Services";
        using var hklm = Registry.LocalMachine;
        var suspiciousNetDrivers = new[]
        {
            "ndflt", "ndisbypass", "tdi_bypass", "ndis_hook",
            "wfp_bypass", "wfpblock", "netblock", "ndishook",
            "packetfilter", "rawsocket",
        };

        try
        {
            using var servicesKey = hklm.OpenSubKey(servicesPath);
            if (servicesKey == null) return;
            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                foreach (var drv in suspiciousNetDrivers)
                {
                    if (svcName.Contains(drv, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Network Driver Bypass: Suspicious Service",
                            Risk = Risk.Critical,
                            Location = $@"HKLM\{servicesPath}\{svcName}",
                            FileName = svcName,
                            Reason = $"Suspicious network driver service '{svcName}' — may bypass WFP/TDI network filtering used by AC",
                            Detail = $"Service: {svcName}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckCheatUpdateServerConnections(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var windowsPrefetchPath = @"C:\Windows\Prefetch";
        if (!Directory.Exists(windowsPrefetchPath)) return;

        var networkLogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

        if (!File.Exists(networkLogPath)) return;
        ctx.IncrementFiles();

        try
        {
            using var fs = new FileStream(networkLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            var content = await sr.ReadToEndAsync(ct);
            foreach (var kw in CheatC2Keywords)
            {
                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "PS History: Cheat C2 Server Connection",
                        Risk = Risk.Critical, Location = networkLogPath,
                        FileName = Path.GetFileName(networkLogPath),
                        Reason = $"Cheat C2 keyword '{kw}' in PowerShell history — potential cheat update/license server contact",
                        Detail = content.Length > 500 ? content[..500] : content
                    });
                    break;
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckIPHelperTableArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var routingRegPath = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes";
        using var hklm = Registry.LocalMachine;
        try
        {
            using var key = hklm.OpenSubKey(routingRegPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            var valueNames = key.GetValueNames();
            if (valueNames.Length > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "Persistent Routes: Custom Network Routes",
                    Risk = Risk.Medium,
                    Location = $@"HKLM\{routingRegPath}",
                    FileName = "PersistentRoutes",
                    Reason = "Custom persistent network routes configured — may redirect anti-cheat server traffic",
                    Detail = $"Routes: {string.Join(", ", valueNames.Take(5))}"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckNetBIOSEvasion(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var nbtRegPath = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters";
        using var hklm = Registry.LocalMachine;
        try
        {
            using var key = hklm.OpenSubKey(nbtRegPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            var nodeType = key.GetValue("NodeType")?.ToString();
            if (nodeType == "2")
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "NetBIOS: P-Node Mode (Direct Query Only)",
                    Risk = Risk.Low,
                    Location = $@"HKLM\{nbtRegPath}",
                    FileName = "NodeType",
                    Reason = "NetBIOS P-node mode configured — avoids broadcast-based network discovery (minor evasion)",
                    Detail = $"NodeType: {nodeType}"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckCheatLicenseServerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchPaths = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
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
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not (".txt" or ".json" or ".xml" or ".cfg" or ".ini" or ".key" or ".lic")) continue;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        var licenseServerKws = new[] { "license_server", "licenseserver", "auth_server", "authserver", "key_server", "keyserver", "update_server" };
                        bool hasLicenseServer = licenseServerKws.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool hasCheatKw = CheatC2Keywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hasLicenseServer && hasCheatKw)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "License Server Config: Cheat Authentication Server",
                                Risk = Risk.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "File references cheat license/authentication server — cheat software authentication artifact",
                                Detail = content.Length > 500 ? content[..500] : content
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckNPCAPWinPcapArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var packetCapturePaths = new[]
        {
            @"C:\Windows\System32\Npcap",
            @"C:\Windows\System32\drivers\npcap.sys",
            @"C:\Windows\System32\drivers\npf.sys",
            @"C:\Windows\SysWOW64\Npcap",
        };

        foreach (var path in packetCapturePaths)
        {
            bool exists = File.Exists(path) || Directory.Exists(path);
            if (!exists) continue;
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "Packet Capture Driver: npcap/WinPcap System File",
                Risk = Risk.High, Location = path,
                FileName = Path.GetFileName(path),
                Reason = "Packet capture driver system file present — enables raw network packet capture of anti-cheat traffic",
                Detail = $"Path: {path}"
            });
        }

        using var hklm = Registry.LocalMachine;
        var npcapService = @"SYSTEM\CurrentControlSet\Services\npcap";
        try
        {
            using var key = hklm.OpenSubKey(npcapService);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            var imagePath = key.GetValue("ImagePath")?.ToString() ?? string.Empty;
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "NPCAP Service: Packet Capture Driver Running",
                Risk = Risk.High,
                Location = $@"HKLM\{npcapService}",
                FileName = "npcap",
                Reason = "npcap packet capture service installed — enables Wireshark-style AC traffic capture",
                Detail = $"ImagePath: {imagePath}"
            });
        }
        catch { }
    }, ct);
}
