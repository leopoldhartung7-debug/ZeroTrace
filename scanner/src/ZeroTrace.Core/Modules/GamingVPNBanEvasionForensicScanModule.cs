using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class GamingVPNBanEvasionForensicScanModule : IScanModule
{
    public string Name => "Gaming VPN Ban Evasion Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] VPNRegistryPaths = { @"SOFTWARE\NordVPN", @"SOFTWARE\ExpressVPN", @"SOFTWARE\ProtonVPN", @"SOFTWARE\Mullvad VPN", @"SOFTWARE\Windscribe", @"SOFTWARE\Surfshark", @"SOFTWARE\CyberGhost", @"SOFTWARE\Private Internet Access", @"SOFTWARE\IPVanish", @"SOFTWARE\AirVPN", @"SOFTWARE\PIA", @"SOFTWARE\Hotspot Shield" };
    private static readonly string[] TapAdapterNames = { "TAP-Windows Adapter", "WireGuard Tunnel", "Wintun Userspace Tunnel", "NordVPN TAP", "ExpressVPN", "ProtonVPN" };
    private static readonly string[] ProxyToolNames = { "proxifier.exe", "proxycap.exe", "sockscap.exe", "mitmproxy.exe", "fiddler.exe", "charles.exe" };
    private static readonly string[] MACChangerTools = { "TMAC.exe", "SMAC.exe", "MacShift.exe", "technitium", "macchanger" };
    private static readonly string[] AnonymousEmailDomains = { "protonmail.com", "tutanota.com", "guerrillamail.com", "10minutemail.com", "throwam.com", "temp-mail.org", "mailinator.com", "yopmail.com" };
    private static readonly string[] VPNLogDirectoryNames = { "NordVPN", "ExpressVPN", "ProtonVPN", "Windscribe", "Surfshark", "CyberGhost", "PIA", "IPVanish", "AirVPN", "Mullvad" };
    private static readonly string[] CheatPurchaseHosts = { "elitepvpers", "unknowncheats", "mpgh.net", "hackforums", "leakforums", "nulled.to", "cracked.io", "blackbay" };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckVPNClientInstallArtifacts(ctx, ct),
            CheckVPNConfigFiles(ctx, ct),
            CheckVPNNetworkAdapterHistory(ctx, ct),
            CheckProxyToolArtifacts(ctx, ct),
            CheckTorBrowserArtifacts(ctx, ct),
            CheckVPNLogFiles(ctx, ct),
            CheckDNSBanEvasionArtifacts(ctx, ct),
            CheckIPChangerSpoofingTools(ctx, ct),
            CheckVPNBrowserExtensionArtifacts(ctx, ct),
            CheckAnonymousEmailForCheatPurchase(ctx, ct),
            CheckCryptoWalletCheatPaymentArtifacts(ctx, ct),
            CheckVPNScheduledTaskArtifacts(ctx, ct),
            CheckVPNRegistryAutostart(ctx, ct),
            CheckVPNFirewallBypassArtifacts(ctx, ct),
            CheckGeoBlockBypassPatterns(ctx, ct),
            CheckSSHSocksProxyArtifacts(ctx, ct),
            CheckVPNKillSwitchBypassArtifacts(ctx, ct),
            CheckAnonymizingServiceRecords(ctx, ct)
        );
    }

    private Task CheckVPNClientInstallArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (string regPath in VPNRegistryPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                ctx.IncrementRegistryKeys();
                if (key is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"VPN Client Registry Key Found: {regPath.Split('\\').Last()}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{regPath}",
                        FileName = null,
                        Reason = $"VPN client registry key '{regPath}' detected. In a gaming context, VPN software is a primary indicator of IP-based ban evasion, allowing players to circumvent server-side IP bans and region restrictions.",
                        Detail = $"Registry path: HKLM\\{regPath}"
                    });
                }
            }
            catch { }
        }

        try
        {
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            string[] vpnFolderNames = new[] { "NordVPN", "ExpressVPN", "ProtonVPN", "Mullvad VPN", "Windscribe", "Surfshark", "CyberGhost", "Private Internet Access", "IPVanish", "AirVPN", "Hotspot Shield", "TunnelBear", "hide.me VPN", "Ivacy", "PureVPN", "VyprVPN" };
            string[] searchRoots = new[] { programFiles, programFilesX86 };

            foreach (string root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                foreach (string folderName in vpnFolderNames)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        string fullPath = Path.Combine(root, folderName);
                        if (Directory.Exists(fullPath))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VPN Client Installation Directory Found: {folderName}",
                                Risk = RiskLevel.High,
                                Location = fullPath,
                                FileName = folderName,
                                Reason = $"VPN client installation directory '{folderName}' found in Program Files. Installed VPN software in a gaming context is a strong indicator of IP-based ban evasion infrastructure.",
                                Detail = $"Path: {fullPath}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVPNConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] wireguardPaths = new[]
        {
            Path.Combine(roamingAppData, "WireGuard"),
            Path.Combine(programData, "WireGuard")
        };

        foreach (string wgDir in wireguardPaths)
        {
            if (!Directory.Exists(wgDir)) continue;
            try
            {
                foreach (string confFile in Directory.GetFiles(wgDir, "*.conf", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"WireGuard VPN Config Found: {Path.GetFileName(confFile)}",
                        Risk = RiskLevel.Medium,
                        Location = confFile,
                        FileName = Path.GetFileName(confFile),
                        Reason = "WireGuard VPN configuration file found. WireGuard is a modern VPN protocol commonly used for fast IP rotation in gaming ban evasion due to its low overhead.",
                        Detail = $"Path: {confFile}"
                    });
                }
            }
            catch { }
        }

        string[] ovpnSearchDirs = new[]
        {
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            roamingAppData,
            programData
        };

        string[] banEvasionRegionKeywords = new[] { "us-", "eu-", "na-", "gaming", "game", "low-latency", "fast", "stream" };

        foreach (string searchDir in ovpnSearchDirs)
        {
            if (!Directory.Exists(searchDir)) continue;
            try
            {
                foreach (string ovpnFile in Directory.GetFiles(searchDir, "*.ovpn", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(ovpnFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasRegionKeyword = banEvasionRegionKeywords.Any(k =>
                            Path.GetFileNameWithoutExtension(ovpnFile).Contains(k, StringComparison.OrdinalIgnoreCase) ||
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"OpenVPN Config Found: {Path.GetFileName(ovpnFile)}",
                            Risk = hasRegionKeyword ? RiskLevel.High : RiskLevel.Medium,
                            Location = ovpnFile,
                            FileName = Path.GetFileName(ovpnFile),
                            Reason = hasRegionKeyword
                                ? "OpenVPN configuration file with gaming-region server indicators found. Region-targeted VPN configs are specifically used to bypass region-based game bans and match low-latency gaming server locations."
                                : "OpenVPN configuration file found. OpenVPN configs represent active VPN infrastructure that can be used for IP-based ban evasion in gaming.",
                            Detail = $"Path: {ovpnFile} | Region-targeted: {hasRegionKeyword}"
                        });
                    }
                    catch
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"OpenVPN Config Found: {Path.GetFileName(ovpnFile)}",
                            Risk = RiskLevel.Medium,
                            Location = ovpnFile,
                            FileName = Path.GetFileName(ovpnFile),
                            Reason = "OpenVPN configuration file found. OpenVPN configs represent VPN infrastructure that can be used for IP ban evasion in gaming contexts.",
                            Detail = $"Path: {ovpnFile}"
                        });
                    }
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVPNNetworkAdapterHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}", writable: false);
            ctx.IncrementRegistryKeys();
            if (classKey is not null)
            {
                foreach (string subKeyName in classKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var adapterKey = classKey.OpenSubKey(subKeyName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (adapterKey is null) continue;

                        string driverDesc = (adapterKey.GetValue("DriverDesc") as string) ?? string.Empty;
                        string matchedAdapter = TapAdapterNames.FirstOrDefault(t =>
                            driverDesc.Contains(t, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                        if (!string.IsNullOrEmpty(matchedAdapter))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VPN TAP Adapter Remnant Found: {driverDesc}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Class\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{subKeyName}",
                                FileName = null,
                                Reason = $"VPN TAP network adapter '{driverDesc}' found in adapter class registry. TAP adapters are installed by OpenVPN-based VPN clients and persist as artifacts even after VPN uninstallation, indicating prior or current VPN usage for ban evasion.",
                                Detail = $"DriverDesc: {driverDesc} | Matched pattern: {matchedAdapter}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            using var networkKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Network", writable: false);
            ctx.IncrementRegistryKeys();
            if (networkKey is not null)
            {
                foreach (string subKeyName in networkKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var adapterKey = networkKey.OpenSubKey(subKeyName, writable: false);
                        if (adapterKey is null) continue;

                        string name = (adapterKey.GetValue("Name") as string) ?? string.Empty;
                        string matchedAdapter = TapAdapterNames.FirstOrDefault(t =>
                            name.Contains(t, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                        if (!string.IsNullOrEmpty(matchedAdapter))
                        {
                            ctx.IncrementRegistryKeys();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VPN Network Adapter in Network History: {name}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Network\{subKeyName}",
                                FileName = null,
                                Reason = $"VPN network adapter '{name}' found in network control registry. VPN adapter descriptions persisted in the network registry confirm VPN client installation history.",
                                Detail = $"Adapter name: {name}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckProxyToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        string[] proxyAppDirs = new[]
        {
            Path.Combine(roamingAppData, "Proxifier"),
            Path.Combine(roamingAppData, "mitmproxy"),
            Path.Combine(localAppData, "Programs", "Progress", "Telerik Fiddler Classic"),
            Path.Combine(localAppData, "Programs", "Fiddler"),
            Path.Combine(roamingAppData, "ProxyCap"),
            Path.Combine(localAppData, "Charles")
        };

        foreach (string dir in proxyAppDirs)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                if (Directory.Exists(dir))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Proxy Tool Directory Found: {Path.GetFileName(dir)}",
                        Risk = RiskLevel.High,
                        Location = dir,
                        FileName = Path.GetFileName(dir),
                        Reason = $"Proxy tool application directory '{dir}' found. Proxy interceptors like Proxifier, mitmproxy, and Fiddler are used to route game traffic through proxy servers for ban evasion by masking the player's real IP address.",
                        Detail = $"Path: {dir}"
                    });
                }
            }
            catch { }
        }

        string[] searchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
        };

        foreach (string searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (string toolName in ProxyToolNames)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    string fullPath = Path.Combine(searchPath, toolName);
                    if (File.Exists(fullPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Proxy Tool Executable Found: {toolName}",
                            Risk = RiskLevel.High,
                            Location = fullPath,
                            FileName = toolName,
                            Reason = $"Proxy tool executable '{toolName}' found. Network proxy tools intercept and redirect game traffic through proxy servers, enabling IP-based ban evasion without a full VPN.",
                            Detail = $"Path: {fullPath}"
                        });
                    }
                }
                catch { }
            }
        }

        try
        {
            string proxifierProfileDir = Path.Combine(roamingAppData, "Proxifier", "Profiles");
            if (Directory.Exists(proxifierProfileDir))
            {
                foreach (string ppxFile in Directory.GetFiles(proxifierProfileDir, "*.ppx"))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(ppxFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        string[] gameKeywords = new[] { "game", "steam", "gta", "fivem", "rage", "altv", "valorant", "csgo", "apex", "fortnite" };
                        bool hasGameRule = gameKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Proxifier Profile File Found: {Path.GetFileName(ppxFile)}",
                            Risk = hasGameRule ? RiskLevel.High : RiskLevel.High,
                            Location = ppxFile,
                            FileName = Path.GetFileName(ppxFile),
                            Reason = hasGameRule
                                ? "Proxifier profile file containing gaming-related proxy rules found. Game-specific proxy rules confirm deliberate routing of game traffic through a proxy server for ban evasion."
                                : "Proxifier profile file found. Proxifier profiles configure which applications have their traffic redirected through proxy servers.",
                            Detail = $"Path: {ppxFile} | Contains gaming rules: {hasGameRule}"
                        });
                    }
                    catch
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Proxifier Profile File Found: {Path.GetFileName(ppxFile)}",
                            Risk = RiskLevel.High,
                            Location = ppxFile,
                            FileName = Path.GetFileName(ppxFile),
                            Reason = "Proxifier profile file (.ppx) found. Proxifier profiles define proxy routing rules for specific applications including games.",
                            Detail = $"Path: {ppxFile}"
                        });
                    }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckTorBrowserArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string desktop = Path.Combine(userProfile, "Desktop");
        string downloads = Path.Combine(userProfile, "Downloads");

        string[] torBrowserPaths = new[]
        {
            Path.Combine(desktop, "Tor Browser"),
            Path.Combine(roamingAppData, "Tor Browser"),
            Path.Combine(localAppData, "Tor Browser"),
            Path.Combine(userProfile, "Documents", "Tor Browser"),
            Path.Combine(downloads, "Tor Browser")
        };

        foreach (string torPath in torBrowserPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                if (Directory.Exists(torPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Tor Browser Installation Found",
                        Risk = RiskLevel.High,
                        Location = torPath,
                        FileName = "Tor Browser",
                        Reason = "Tor Browser installation directory found. Tor anonymizes internet traffic by routing it through multiple relays, enabling ban evasion by providing a completely different IP address and identity profile to game servers.",
                        Detail = $"Path: {torPath}"
                    });
                }
            }
            catch { }
        }

        try
        {
            using var torServiceKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\tor", writable: false);
            ctx.IncrementRegistryKeys();
            if (torServiceKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Tor Service Registered in Registry",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\tor",
                    FileName = null,
                    Reason = "Tor service registry key found. A registered Tor service indicates persistent Tor daemon operation, providing a continuously available anonymization channel for game ban evasion.",
                    Detail = @"Registry key: HKLM\SYSTEM\CurrentControlSet\Services\tor"
                });
            }
        }
        catch { }

        string[] torrcSearchPaths = new[]
        {
            Path.Combine(roamingAppData, "tor"),
            Path.Combine(localAppData, "tor"),
            Path.Combine(programData: Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "tor")
        };

        foreach (string torrcDir in torrcSearchPaths)
        {
            if (!Directory.Exists(torrcDir)) continue;
            if (ct.IsCancellationRequested) return;
            try
            {
                string torrcPath = Path.Combine(torrcDir, "torrc");
                if (File.Exists(torrcPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Tor Configuration File Found",
                        Risk = RiskLevel.High,
                        Location = torrcPath,
                        FileName = "torrc",
                        Reason = "Tor configuration file 'torrc' found. This file configures the Tor daemon and its presence confirms active Tor setup for anonymous routing of network traffic.",
                        Detail = $"Path: {torrcPath}"
                    });
                }
            }
            catch { }
        }

        try
        {
            if (Directory.Exists(downloads))
            {
                foreach (string torInstaller in Directory.GetFiles(downloads, "tor-browser*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Tor Browser Installer Found: {Path.GetFileName(torInstaller)}",
                        Risk = RiskLevel.High,
                        Location = torInstaller,
                        FileName = Path.GetFileName(torInstaller),
                        Reason = "Tor Browser installer found in Downloads folder. Downloaded Tor installers indicate intent to use or past use of Tor for anonymous game access and ban evasion.",
                        Detail = $"Path: {torInstaller}"
                    });
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVPNLogFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (string vpnName in VPNLogDirectoryNames)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                string[] logDirCandidates = new[]
                {
                    Path.Combine(localAppData, vpnName, "logs"),
                    Path.Combine(localAppData, vpnName, "Logs"),
                    Path.Combine(localAppData, vpnName, "log"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), vpnName, "logs"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), vpnName, "Logs")
                };

                foreach (string logDir in logDirCandidates)
                {
                    if (!Directory.Exists(logDir)) continue;

                    try
                    {
                        string[] logFiles = Directory.GetFiles(logDir, "*.log", SearchOption.TopDirectoryOnly);
                        if (logFiles.Length == 0)
                            logFiles = Directory.GetFiles(logDir, "*.txt", SearchOption.TopDirectoryOnly);

                        foreach (string logFile in logFiles)
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();

                            try
                            {
                                using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                string content = await sr.ReadToEndAsync(ct);

                                bool hasConnectionEntry = content.Contains("Connected", StringComparison.OrdinalIgnoreCase) ||
                                                          content.Contains("Connection established", StringComparison.OrdinalIgnoreCase) ||
                                                          content.Contains("Tunnel up", StringComparison.OrdinalIgnoreCase);

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"VPN Log File Found: {vpnName}",
                                    Risk = RiskLevel.High,
                                    Location = logFile,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = hasConnectionEntry
                                        ? $"VPN log file for '{vpnName}' found with active connection records. VPN connection logs confirm the VPN was actively used, with timestamps that may correlate with gaming sessions, indicating deliberate IP masking during gameplay."
                                        : $"VPN log file for '{vpnName}' found. VPN client logs provide forensic evidence of VPN usage history relevant to ban evasion investigations.",
                                    Detail = $"Log path: {logFile} | Contains connection records: {hasConnectionEntry}"
                                });
                            }
                            catch
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"VPN Log File Found: {vpnName}",
                                    Risk = RiskLevel.High,
                                    Location = logFile,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"VPN log file for '{vpnName}' found. VPN log files are forensic artifacts proving VPN client usage history.",
                                    Detail = $"Path: {logFile}"
                                });
                            }
                        }
                    }
                    catch { }
                    break;
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDNSBanEvasionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string hostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers", "etc", "hosts");

        try
        {
            if (File.Exists(hostsPath))
            {
                ctx.IncrementFiles();
                using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                string[] gameAuthDomains = new[]
                {
                    "easyanticheat", "battleye", "valve", "steampowered", "faceit",
                    "vac", "riot", "riotgames", "epicgames", "eac", "nprotect",
                    "fivem", "cfx.re", "rage.mp", "altv.mp", "rockstargames",
                    "be.lol", "punkbuster", "gameguard", "wellbia"
                };

                string[] lines = content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    if (ct.IsCancellationRequested) return;
                    string trimmed = line.Trim();
                    if (trimmed.StartsWith('#')) continue;

                    string matchedDomain = gameAuthDomains.FirstOrDefault(d =>
                        trimmed.Contains(d, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                    if (!string.IsNullOrEmpty(matchedDomain))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Game Authentication Server Redirect in Hosts File",
                            Risk = RiskLevel.Critical,
                            Location = hostsPath,
                            FileName = "hosts",
                            Reason = $"Hosts file contains entry redirecting game authentication domain '{matchedDomain}'. DNS-based redirects of anti-cheat or game server domains are used to bypass ban enforcement, spoof game authentication, or block anti-cheat telemetry.",
                            Detail = $"Hosts entry: {trimmed}"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            using var tcpipKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", writable: false);
            ctx.IncrementRegistryKeys();
            if (tcpipKey is not null)
            {
                string nameServer = (tcpipKey.GetValue("NameServer") as string) ?? string.Empty;
                string[] privacyDnsServers = new[] { "8.26.56.26", "8.20.247.20", "195.46.39.39", "195.46.39.40", "208.67.222.222", "208.67.220.220" };

                if (!string.IsNullOrEmpty(nameServer))
                {
                    string matchedDns = privacyDnsServers.FirstOrDefault(d =>
                        nameServer.Contains(d, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                    if (!string.IsNullOrEmpty(matchedDns))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Privacy DNS Server Configured: {nameServer}",
                            Risk = RiskLevel.Medium,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                            FileName = null,
                            Reason = $"Non-standard privacy DNS server '{nameServer}' configured in TCP/IP parameters. When combined with VPN usage, privacy DNS servers that bypass geo-filtering strengthen ban evasion capability by preventing DNS-level detection.",
                            Detail = $"NameServer: {nameServer} | Matched: {matchedDns}"
                        });
                    }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckIPChangerSpoofingTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] searchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.System)
        };

        foreach (string searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (string toolName in MACChangerTools)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    string fullPath = Path.Combine(searchPath, toolName);
                    if (File.Exists(fullPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"MAC Address Changer Tool Found: {toolName}",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = toolName,
                            Reason = $"MAC address changer tool '{toolName}' found. MAC spoofing tools are used to change the hardware address of network adapters, defeating MAC-based hardware ban systems used by game servers and anti-cheat platforms.",
                            Detail = $"Path: {fullPath}"
                        });
                    }
                }
                catch { }
            }

            if (ct.IsCancellationRequested) return;
            try
            {
                string technitiumPath = Path.Combine(searchPath, "Technitium MAC Address Changer");
                if (Directory.Exists(technitiumPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Technitium MAC Address Changer Found",
                        Risk = RiskLevel.Critical,
                        Location = technitiumPath,
                        FileName = "Technitium MAC Address Changer",
                        Reason = "Technitium MAC Address Changer installation directory found. This tool modifies network adapter MAC addresses at the OS level to defeat hardware-based ban systems in gaming.",
                        Detail = $"Path: {technitiumPath}"
                    });
                }
            }
            catch { }
        }

        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}", writable: false);
            ctx.IncrementRegistryKeys();
            if (classKey is not null)
            {
                foreach (string subKeyName in classKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var adapterKey = classKey.OpenSubKey(subKeyName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (adapterKey is null) continue;

                        string networkAddress = (adapterKey.GetValue("NetworkAddress") as string) ?? string.Empty;
                        if (!string.IsNullOrEmpty(networkAddress) && networkAddress.Length >= 12)
                        {
                            string driverDesc = (adapterKey.GetValue("DriverDesc") as string) ?? string.Empty;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Custom MAC Address Set on Adapter: {driverDesc}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Class\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\{subKeyName}",
                                FileName = null,
                                Reason = $"Network adapter '{driverDesc}' has a manually configured MAC address '{networkAddress}' set via the NetworkAddress registry value. This is the primary mechanism used by MAC changer tools to override hardware addresses for ban evasion.",
                                Detail = $"DriverDesc: {driverDesc} | NetworkAddress: {networkAddress}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVPNBrowserExtensionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        string[] vpnExtensionIds = new[]
        {
            "ookjlbkiijinhpmnjffcofjonbfbgoog",
            "bihmplhobchoageeokmgbdihknkjbknd",
            "nlbejmccbhkncgokjcmghpfloaajcffj",
            "omdakjcmkglenbhjadbccaookjlbkiij",
            "eppiocemhmnlbhjplcgkofciiegomcon",
            "fjnehiohnmpcifcgkgcnmhggdeoamdei",
            "lneaocagcijjdpjeangnkbpejbhkonec"
        };

        string[] vpnExtensionNameKeywords = new[] { "betternet", "hola", "hotspot", "tunnelbear", "windscribe", "vpn", "proxy" };

        string[] chromiumExtensionRoots = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Extensions"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Extensions"),
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Extensions")
        };

        foreach (string extensionRoot in chromiumExtensionRoots)
        {
            if (!Directory.Exists(extensionRoot)) continue;
            string browserName = extensionRoot.Contains("Chrome", StringComparison.OrdinalIgnoreCase) ? "Chrome"
                               : extensionRoot.Contains("Edge", StringComparison.OrdinalIgnoreCase) ? "Edge"
                               : "Brave";

            try
            {
                foreach (string extDir in Directory.GetDirectories(extensionRoot))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string extId = Path.GetFileName(extDir).ToLowerInvariant();

                    if (vpnExtensionIds.Any(id => id.Equals(extId, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Known VPN Browser Extension Found in {browserName}: {extId}",
                            Risk = RiskLevel.High,
                            Location = extDir,
                            FileName = extId,
                            Reason = $"Known VPN browser extension ID '{extId}' found in {browserName} extensions. Browser-based VPN extensions are commonly used for free IP rotation in gaming, enabling ban evasion without installing a full VPN client.",
                            Detail = $"Browser: {browserName} | Extension ID: {extId}"
                        });
                        continue;
                    }

                    string nameMatch = vpnExtensionNameKeywords.FirstOrDefault(k =>
                        extId.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                    if (!string.IsNullOrEmpty(nameMatch))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspected VPN Browser Extension in {browserName}: {extId}",
                            Risk = RiskLevel.High,
                            Location = extDir,
                            FileName = extId,
                            Reason = $"Browser extension directory matching VPN keyword '{nameMatch}' found in {browserName}. VPN browser extensions provide lightweight IP proxying that can be used for gaming ban evasion.",
                            Detail = $"Browser: {browserName} | Extension ID: {extId} | Keyword: {nameMatch}"
                        });
                    }
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckAnonymousEmailForCheatPurchase(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        string[] chromiumHistoryPaths = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History")
        };

        foreach (string historyPath in chromiumHistoryPaths)
        {
            if (!File.Exists(historyPath)) continue;
            if (ct.IsCancellationRequested) return;

            string? tempPath = null;
            try
            {
                tempPath = Path.Combine(Path.GetTempPath(), "zt_vpnhist_" + Guid.NewGuid().ToString("N") + ".db");
                File.Copy(historyPath, tempPath, overwrite: true);

                string browserName = historyPath.Contains("Chrome", StringComparison.OrdinalIgnoreCase) ? "Chrome"
                                   : historyPath.Contains("Edge", StringComparison.OrdinalIgnoreCase) ? "Edge"
                                   : "Brave";

                var connectionString = $"Data Source={tempPath};Mode=ReadOnly;";
                using var conn = new Microsoft.Data.Sqlite.SqliteConnection(connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT url, last_visit_time FROM urls ORDER BY last_visit_time;";
                using var reader = cmd.ExecuteReader();

                var visitsByTime = new List<(string url, long time)>();
                while (reader.Read())
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementFiles();
                    string url = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
                    long time = reader.IsDBNull(1) ? 0 : reader.GetInt64(1);
                    if (!string.IsNullOrEmpty(url)) visitsByTime.Add((url, time));
                }

                var anonEmailVisits = visitsByTime.Where(v =>
                    AnonymousEmailDomains.Any(d => v.url.Contains(d, StringComparison.OrdinalIgnoreCase))).ToList();

                var cheatSiteVisits = visitsByTime.Where(v =>
                    CheatPurchaseHosts.Any(h => v.url.Contains(h, StringComparison.OrdinalIgnoreCase))).ToList();

                foreach (var anonVisit in anonEmailVisits)
                {
                    string matchedDomain = AnonymousEmailDomains.First(d =>
                        anonVisit.url.Contains(d, StringComparison.OrdinalIgnoreCase));

                    bool hasNearbyCheatVisit = cheatSiteVisits.Any(cv =>
                        Math.Abs(cv.time - anonVisit.time) < 18_000_000_000L);

                    if (hasNearbyCheatVisit || cheatSiteVisits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Anonymous Email Service Visit Correlated with Cheat Site: {matchedDomain}",
                            Risk = RiskLevel.Medium,
                            Location = historyPath,
                            FileName = Path.GetFileName(historyPath),
                            Reason = $"Browser history in {browserName} shows visit to anonymous email service '{matchedDomain}' in proximity to known cheat site visits. Disposable and anonymous email services are used to create throwaway accounts for cheat purchases, bypassing email-based ban correlation.",
                            Detail = $"Anonymous email domain: {matchedDomain} | Browser: {browserName} | Cheat site visits found: {cheatSiteVisits.Count}"
                        });
                        break;
                    }
                }
            }
            catch { }
            finally
            {
                if (tempPath is not null)
                {
                    try { File.Delete(tempPath); } catch { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCryptoWalletCheatPaymentArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        string[] walletDirs = new[]
        {
            Path.Combine(roamingAppData, "Electrum"),
            Path.Combine(roamingAppData, "Exodus"),
            Path.Combine(roamingAppData, "Atomic"),
            Path.Combine(roamingAppData, "Coinomi"),
            Path.Combine(roamingAppData, "Jaxx Liberty")
        };

        foreach (string walletDir in walletDirs)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                if (Directory.Exists(walletDir))
                {
                    ctx.IncrementFiles();
                    string walletName = Path.GetFileName(walletDir);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cryptocurrency Wallet Found: {walletName}",
                        Risk = RiskLevel.High,
                        Location = walletDir,
                        FileName = walletName,
                        Reason = $"Cryptocurrency wallet '{walletName}' found. Cryptocurrency wallets are used for anonymous cheat purchases as crypto transactions are difficult to trace, enabling players to buy cheats without creating a payment paper trail linking their identity to cheat providers.",
                        Detail = $"Path: {walletDir}"
                    });
                }
            }
            catch { }
        }

        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string[] metamaskExtensionPaths = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Extensions", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Extensions", "ejbalbakoplchlghecdalmeeeajnimhm"),
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Extensions", "nkbihfbeogaeaoehlefnkodbefgpgknn")
        };

        foreach (string metamaskPath in metamaskExtensionPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                if (Directory.Exists(metamaskPath))
                {
                    ctx.IncrementFiles();
                    string browserName = metamaskPath.Contains("Chrome", StringComparison.OrdinalIgnoreCase) ? "Chrome"
                                       : metamaskPath.Contains("Edge", StringComparison.OrdinalIgnoreCase) ? "Edge"
                                       : "Brave";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"MetaMask Crypto Wallet Extension Found in {browserName}",
                        Risk = RiskLevel.High,
                        Location = metamaskPath,
                        FileName = "MetaMask",
                        Reason = $"MetaMask cryptocurrency browser extension found in {browserName}. MetaMask enables anonymous Ethereum transactions and is commonly used to purchase cheats from providers that accept crypto payments to avoid financial tracking.",
                        Detail = $"Extension path: {metamaskPath} | Browser: {browserName}"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVPNScheduledTaskArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string tasksPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "Tasks");

        string[] vpnTaskKeywords = new[] { "vpn_connect", "vpn_auto", "vpn_start", "nordvpn", "expressvpn", "protonvpn", "windscribe", "surfshark", "cyberghost", "vpnconnect", "vpnauto", "openvpn" };

        try
        {
            if (Directory.Exists(tasksPath))
            {
                foreach (string taskFile in Directory.GetFiles(tasksPath, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    if (!string.IsNullOrEmpty(Path.GetExtension(taskFile))) continue;

                    ctx.IncrementFiles();
                    string taskFileName = Path.GetFileName(taskFile).ToLowerInvariant();

                    string matchedKeyword = vpnTaskKeywords.FirstOrDefault(k =>
                        taskFileName.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                    if (!string.IsNullOrEmpty(matchedKeyword))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VPN Auto-Connect Scheduled Task Found: {Path.GetFileName(taskFile)}",
                            Risk = RiskLevel.High,
                            Location = taskFile,
                            FileName = Path.GetFileName(taskFile),
                            Reason = $"Scheduled task '{Path.GetFileName(taskFile)}' matching VPN keyword '{matchedKeyword}' found. VPN auto-connect tasks that trigger at login indicate habitual VPN usage for ban evasion, ensuring the VPN is always active before gaming sessions.",
                            Detail = $"Task file: {taskFile} | Matched keyword: {matchedKeyword}"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            using var taskCacheKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", writable: false);
            ctx.IncrementRegistryKeys();
            if (taskCacheKey is not null)
            {
                foreach (string subKeyName in taskCacheKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var taskKey = taskCacheKey.OpenSubKey(subKeyName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (taskKey is null) continue;

                        string path = (taskKey.GetValue("Path") as string) ?? string.Empty;
                        string matchedKeyword = vpnTaskKeywords.FirstOrDefault(k =>
                            path.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                        if (!string.IsNullOrEmpty(matchedKeyword))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VPN Task Cache Entry Found: {path}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{subKeyName}",
                                FileName = null,
                                Reason = $"Task cache registry entry for VPN task '{path}' found. Task cache entries persist after scheduled task deletion and confirm prior VPN auto-start configuration for ban evasion.",
                                Detail = $"Task path: {path} | Matched keyword: {matchedKeyword}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVPNRegistryAutostart(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] vpnAutostartKeywords = new[] { "nordvpn", "expressvpn", "protonvpn", "windscribe", "surfshark", "cyberghost", "pia", "ipvanish", "airvpn", "mullvad", "openvpn", "wireguard", "vpn" };

        string[] autostartRegPaths = new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        };

        foreach (string regPath in autostartRegPaths)
        {
            if (ct.IsCancellationRequested) return;

            RegistryKey?[] hives = new RegistryKey?[]
            {
                TryOpenKey(Registry.CurrentUser, regPath),
                TryOpenKey(Registry.LocalMachine, regPath)
            };

            foreach (var key in hives)
            {
                if (key is null) continue;
                using (key)
                {
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        foreach (string valueName in key.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            try
                            {
                                string valueData = (key.GetValue(valueName) as string) ?? string.Empty;
                                string nameAndData = (valueName + " " + valueData).ToLowerInvariant();

                                string matchedKeyword = vpnAutostartKeywords.FirstOrDefault(k =>
                                    nameAndData.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                                if (!string.IsNullOrEmpty(matchedKeyword))
                                {
                                    ctx.IncrementRegistryKeys();
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"VPN Autostart Registry Entry Found: {valueName}",
                                        Risk = RiskLevel.High,
                                        Location = $@"{(key.Name.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) ? "HKCU" : "HKLM")}\{regPath}",
                                        FileName = null,
                                        Reason = $"VPN client autostart entry '{valueName}' found in Run registry key. VPN autostart ensures the VPN connects before other applications including games, which is consistent with systematic ban evasion behavior to ensure IP masking is always active during gaming.",
                                        Detail = $"Value name: {valueName} | Data: {valueData} | Matched keyword: {matchedKeyword}"
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVPNFirewallBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] vpnFirewallKeywords = new[] { "vpn", "nordvpn", "expressvpn", "openvpn", "wireguard", "protonvpn", "mullvad", "windscribe", "surfshark", "tapwindows", "tun", "ovpn", "killswitch", "kill_switch" };

        try
        {
            using var firewallRulesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                writable: false);
            ctx.IncrementRegistryKeys();
            if (firewallRulesKey is not null)
            {
                foreach (string ruleName in firewallRulesKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        string ruleData = (firewallRulesKey.GetValue(ruleName) as string) ?? string.Empty;
                        string ruleNameLower = ruleName.ToLowerInvariant();
                        string ruleDataLower = ruleData.ToLowerInvariant();

                        string matchedKeyword = vpnFirewallKeywords.FirstOrDefault(k =>
                            ruleNameLower.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                            ruleDataLower.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                        if (!string.IsNullOrEmpty(matchedKeyword))
                        {
                            bool isKillSwitch = ruleNameLower.Contains("killswitch", StringComparison.OrdinalIgnoreCase) ||
                                               ruleNameLower.Contains("kill_switch", StringComparison.OrdinalIgnoreCase) ||
                                               ruleDataLower.Contains("killswitch", StringComparison.OrdinalIgnoreCase);

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VPN-Related Firewall Rule Found: {ruleName}",
                                Risk = RiskLevel.High,
                                Location = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                                FileName = null,
                                Reason = isKillSwitch
                                    ? $"VPN kill-switch firewall rule '{ruleName}' found. Kill-switch rules block all traffic unless the VPN is active, confirming deliberate VPN-dependent gaming to ensure ban evasion is maintained even if the VPN briefly drops."
                                    : $"VPN-related firewall rule '{ruleName}' found. VPN firewall rules that exempt VPN traffic from network filters indicate configured VPN infrastructure for sustained ban evasion.",
                                Detail = $"Rule: {ruleName} | Matched keyword: {matchedKeyword} | Kill-switch: {isKillSwitch}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckGeoBlockBypassPatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        string[] geoBypassToolNames = new[] { "steam_region_bypass", "gta_region_spoof", "region_bypass", "geo_bypass", "geoblock_bypass" };
        string[] searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            localAppData
        };

        foreach (string searchDir in searchDirs)
        {
            if (!Directory.Exists(searchDir)) continue;
            foreach (string toolName in geoBypassToolNames)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (string ext in new[] { ".exe", ".bat", ".cmd", ".ps1" })
                    {
                        string fullPath = Path.Combine(searchDir, toolName + ext);
                        if (File.Exists(fullPath))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Geo-Block Bypass Tool Found: {Path.GetFileName(fullPath)}",
                                Risk = RiskLevel.High,
                                Location = fullPath,
                                FileName = Path.GetFileName(fullPath),
                                Reason = $"Geographic restriction bypass tool '{Path.GetFileName(fullPath)}' found. These tools specifically circumvent regional game access restrictions and ban enforcement that targets players from specific geographic regions.",
                                Detail = $"Path: {fullPath}"
                            });
                        }
                    }
                }
                catch { }
            }
        }

        try
        {
            using var steamKey = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam", writable: false);
            ctx.IncrementRegistryKeys();
            if (steamKey is not null)
            {
                string clientLanguage = (steamKey.GetValue("CLIENTLANGUAGE") as string) ?? string.Empty;
                if (!string.IsNullOrEmpty(clientLanguage))
                {
                    string[] suspiciousLanguageCombinations = new[] { "schinese", "tchinese", "koreana", "thai", "vietnamese" };
                    bool isSuspiciousRegionOverride = suspiciousLanguageCombinations.Any(l =>
                        clientLanguage.Equals(l, StringComparison.OrdinalIgnoreCase));

                    if (isSuspiciousRegionOverride)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Steam Region Language Override Detected: {clientLanguage}",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\Software\Valve\Steam",
                            FileName = null,
                            Reason = $"Steam client language set to '{clientLanguage}' via registry. Manually overriding the Steam region language can be used to access region-locked games or bypass region-specific ban enforcement systems.",
                            Detail = $"CLIENTLANGUAGE: {clientLanguage}"
                        });
                    }
                }
            }
        }
        catch { }

        string fivemRegionBypassPath = Path.Combine(localAppData, "FiveM", "FiveM.app", "data", "cache", "region_bypass.json");
        try
        {
            if (File.Exists(fivemRegionBypassPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "FiveM Region Bypass Config Found",
                    Risk = RiskLevel.High,
                    Location = fivemRegionBypassPath,
                    FileName = "region_bypass.json",
                    Reason = "FiveM region bypass configuration file found. Region bypass configs for FiveM are used to access servers restricted to specific geographic regions, often to evade bans enforced at the regional server level.",
                    Detail = $"Path: {fivemRegionBypassPath}"
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckSSHSocksProxyArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        try
        {
            using var puttySessionsKey = Registry.CurrentUser.OpenSubKey(@"Software\SimonTatham\PuTTY\Sessions", writable: false);
            ctx.IncrementRegistryKeys();
            if (puttySessionsKey is not null)
            {
                foreach (string sessionName in puttySessionsKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var sessionKey = puttySessionsKey.OpenSubKey(sessionName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (sessionKey is null) continue;

                        int proxyType = (int)(sessionKey.GetValue("ProxyMethod") ?? 0);
                        int localPortForward = (int)(sessionKey.GetValue("PortForwardings")?.ToString()?.Length > 0 ? 1 : 0);
                        string dynForward = (sessionKey.GetValue("PortForwardings") as string) ?? string.Empty;

                        bool hasProxyConfig = proxyType > 0 || dynForward.Contains("D", StringComparison.OrdinalIgnoreCase);

                        if (hasProxyConfig)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"PuTTY Session with Proxy/Tunnel Config: {Uri.UnescapeDataString(sessionName)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\Software\SimonTatham\PuTTY\Sessions\{sessionName}",
                                FileName = null,
                                Reason = $"PuTTY SSH session '{Uri.UnescapeDataString(sessionName)}' found with proxy or tunnel configuration. SSH SOCKS proxying tunnels game traffic through an SSH server to mask the player's real IP address, enabling ban evasion without a traditional VPN.",
                                Detail = $"Session: {Uri.UnescapeDataString(sessionName)} | ProxyMethod: {proxyType} | PortForwardings: {dynForward}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        string sshConfigPath = Path.Combine(userProfile, ".ssh", "config");
        try
        {
            if (File.Exists(sshConfigPath))
            {
                ctx.IncrementFiles();
                using var fs = new FileStream(sshConfigPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                string[] tunnelKeywords = new[] { "DynamicForward", "LocalForward", "ProxyCommand", "ProxyJump", "Tunnel" };
                string matchedDirective = tunnelKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                if (!string.IsNullOrEmpty(matchedDirective))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "SSH Config with Tunnel/Proxy Directives Found",
                        Risk = RiskLevel.High,
                        Location = sshConfigPath,
                        FileName = "config",
                        Reason = $"OpenSSH configuration file contains tunnel directive '{matchedDirective}'. SSH tunnel configurations route network traffic through remote servers, providing IP masking functionally equivalent to a VPN for gaming ban evasion.",
                        Detail = $"Path: {sshConfigPath} | Directive: {matchedDirective}"
                    });
                }
            }
        }
        catch { }

        try
        {
            string puttyCmPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "PuTTY Connection Manager");
            string puttyCmPathX86 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "PuTTY Connection Manager");

            foreach (string cmPath in new[] { puttyCmPath, puttyCmPathX86 })
            {
                if (ct.IsCancellationRequested) return;
                if (Directory.Exists(cmPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PuTTY Connection Manager Found",
                        Risk = RiskLevel.High,
                        Location = cmPath,
                        FileName = "PuTTY Connection Manager",
                        Reason = "PuTTY Connection Manager installation found. This tool manages multiple SSH sessions with proxy and tunnel configurations, and when found alongside gaming artifacts indicates SSH-based game traffic tunneling for ban evasion.",
                        Detail = $"Path: {cmPath}"
                    });
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckVPNKillSwitchBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] scriptNames = new[]
        {
            "bypass_killswitch.ps1", "vpn_reconnect.bat", "killswitch_bypass.cmd",
            "vpn_reconnect.ps1", "bypass_killswitch.bat", "vpn_restore.bat",
            "vpn_restore.ps1", "killswitch_bypass.ps1", "vpn_failsafe.bat",
            "vpn_failsafe.ps1", "reconnect_vpn.bat", "reconnect_vpn.ps1"
        };

        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            userProfile,
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Documents"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        };

        foreach (string searchDir in searchDirs)
        {
            if (!Directory.Exists(searchDir)) continue;
            foreach (string scriptName in scriptNames)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    string fullPath = Path.Combine(searchDir, scriptName);
                    if (File.Exists(fullPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VPN Kill Switch Bypass Script Found: {scriptName}",
                            Risk = RiskLevel.Critical,
                            Location = fullPath,
                            FileName = scriptName,
                            Reason = $"VPN kill switch bypass script '{scriptName}' found. Kill switch bypass scripts indicate the user is aware of VPN detection mechanisms and has taken deliberate steps to maintain VPN connectivity or bypass VPN-enforced kill switches, demonstrating sophisticated and intentional ban evasion behavior.",
                            Detail = $"Path: {fullPath}"
                        });
                    }
                }
                catch { }
            }
        }

        string[] vpnReconnectTaskKeywords = new[] { "vpn_reconnect", "vpn_restore", "vpn_failsafe", "reconnect_vpn", "killswitch_bypass", "bypass_killswitch" };

        string tasksPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "Tasks");

        try
        {
            if (Directory.Exists(tasksPath))
            {
                foreach (string taskFile in Directory.GetFiles(tasksPath, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    if (!string.IsNullOrEmpty(Path.GetExtension(taskFile))) continue;

                    ctx.IncrementFiles();
                    string taskFileName = Path.GetFileName(taskFile).ToLowerInvariant();

                    string matchedKeyword = vpnReconnectTaskKeywords.FirstOrDefault(k =>
                        taskFileName.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                    if (!string.IsNullOrEmpty(matchedKeyword))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VPN Reconnect Scheduled Task Found: {Path.GetFileName(taskFile)}",
                            Risk = RiskLevel.Critical,
                            Location = taskFile,
                            FileName = Path.GetFileName(taskFile),
                            Reason = $"Scheduled task '{Path.GetFileName(taskFile)}' with VPN reconnect keyword '{matchedKeyword}' found. Automated VPN reconnection tasks during gaming sessions indicate awareness of VPN detection and systematic efforts to maintain uninterrupted IP masking for ban evasion.",
                            Detail = $"Task: {taskFile} | Matched keyword: {matchedKeyword}"
                        });
                    }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckAnonymizingServiceRecords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string[] vpnReceiptNames = new[]
        {
            "NordVPN_receipt.pdf", "ExpressVPN_invoice.pdf", "ProtonVPN_receipt.pdf",
            "Mullvad_invoice.pdf", "Windscribe_receipt.pdf", "Surfshark_invoice.pdf",
            "VPN_receipt.pdf", "VPN_invoice.pdf", "vpn_receipt.pdf", "vpn_invoice.pdf"
        };

        string[] cryptoExchangeKeywords = new[] { "binance", "coinbase", "kraken", "bitfinex", "bybit", "okx", "kucoin", "huobi" };

        string downloadsPath = Path.Combine(userProfile, "Downloads");
        if (Directory.Exists(downloadsPath))
        {
            try
            {
                foreach (string receiptName in vpnReceiptNames)
                {
                    if (ct.IsCancellationRequested) return;
                    string fullPath = Path.Combine(downloadsPath, receiptName);
                    if (File.Exists(fullPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VPN Service Receipt Found: {receiptName}",
                            Risk = RiskLevel.Medium,
                            Location = fullPath,
                            FileName = receiptName,
                            Reason = $"VPN service payment receipt '{receiptName}' found in Downloads. VPN subscription receipts confirm paid VPN service usage and provide a timeline of VPN subscription correlated with gaming ban periods.",
                            Detail = $"Path: {fullPath}"
                        });
                    }
                }
            }
            catch { }

            try
            {
                foreach (string pdfFile in Directory.GetFiles(downloadsPath, "*.pdf", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    string pdfName = Path.GetFileName(pdfFile).ToLowerInvariant();

                    string matchedExchange = cryptoExchangeKeywords.FirstOrDefault(k =>
                        pdfName.Contains(k, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                    if (!string.IsNullOrEmpty(matchedExchange))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Crypto Exchange Record Found: {Path.GetFileName(pdfFile)}",
                            Risk = RiskLevel.Medium,
                            Location = pdfFile,
                            FileName = Path.GetFileName(pdfFile),
                            Reason = $"Cryptocurrency exchange record from '{matchedExchange}' found. Crypto exchange records alongside VPN artifacts may indicate a complete anonymous purchase workflow: VPN for IP anonymization and crypto for untraceable cheat payments.",
                            Detail = $"Path: {pdfFile} | Exchange: {matchedExchange}"
                        });
                    }
                }
            }
            catch { }
        }

        string[] chromiumHistoryPaths = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History")
        };

        string[] vpnServiceDomains = new[] { "nordvpn.com", "expressvpn.com", "protonvpn.com", "mullvad.net", "windscribe.com", "surfshark.com", "cyberghostvpn.com", "privateinternetaccess.com", "ipvanish.com", "airvpn.org" };

        foreach (string historyPath in chromiumHistoryPaths)
        {
            if (!File.Exists(historyPath)) continue;
            if (ct.IsCancellationRequested) return;

            string? tempPath = null;
            try
            {
                tempPath = Path.Combine(Path.GetTempPath(), "zt_vpnanon_" + Guid.NewGuid().ToString("N") + ".db");
                File.Copy(historyPath, tempPath, overwrite: true);

                string browserName = historyPath.Contains("Chrome", StringComparison.OrdinalIgnoreCase) ? "Chrome"
                                   : historyPath.Contains("Edge", StringComparison.OrdinalIgnoreCase) ? "Edge"
                                   : "Brave";

                var connectionString = $"Data Source={tempPath};Mode=ReadOnly;";
                using var conn = new Microsoft.Data.Sqlite.SqliteConnection(connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT url FROM urls;";
                using var reader = cmd.ExecuteReader();

                bool foundVpnSite = false;
                bool foundCheatSite = false;

                while (reader.Read())
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementFiles();
                    string url = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
                    if (string.IsNullOrEmpty(url)) continue;

                    if (!foundVpnSite && vpnServiceDomains.Any(d => url.Contains(d, StringComparison.OrdinalIgnoreCase)))
                        foundVpnSite = true;

                    if (!foundCheatSite && CheatPurchaseHosts.Any(h => url.Contains(h, StringComparison.OrdinalIgnoreCase)))
                        foundCheatSite = true;

                    if (foundVpnSite && foundCheatSite) break;
                }

                if (foundVpnSite && foundCheatSite)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"VPN Service and Cheat Site Visits Co-Found in {browserName} History",
                        Risk = RiskLevel.Medium,
                        Location = historyPath,
                        FileName = Path.GetFileName(historyPath),
                        Reason = $"Browser history in {browserName} shows both VPN service website visits and cheat site visits. This combination indicates the user researched or subscribed to VPN services in conjunction with accessing cheat marketplaces, consistent with building an anonymous cheat acquisition and ban evasion infrastructure.",
                        Detail = $"Browser: {browserName} | VPN sites found: {foundVpnSite} | Cheat sites found: {foundCheatSite}"
                    });
                }
            }
            catch { }
            finally
            {
                if (tempPath is not null)
                {
                    try { File.Delete(tempPath); } catch { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private static RegistryKey? TryOpenKey(RegistryKey hive, string path)
    {
        try { return hive.OpenSubKey(path, writable: false); }
        catch { return null; }
    }
}
