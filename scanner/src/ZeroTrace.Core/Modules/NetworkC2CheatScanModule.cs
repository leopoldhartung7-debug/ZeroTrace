using System.Diagnostics;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class NetworkC2CheatScanModule : IScanModule
{
    public string Name => "Network-C2-Cheat";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    private static readonly string[] AntiCheatDomains =
    {
        "vanguard.gg", "battleye.com", "easyanticheat.net", "faceit.com",
        "faceit-client-cdn.faceit.com", "cdn.cfx.re", "runtime.fivem.net",
        "valve.net", "steampowered.com"
    };

    private static readonly string[] CheatLicenseDomainKeywords =
    {
        "cheat", "hack", "bypass", "loader", "license", "auth", "hwid"
    };

    private static readonly string[] KnownCheatDomains =
    {
        "aimware.net", "skeet.cc", "onetap.su", "neverlose.cc", "fatality.win",
        "nixware.cc", "kiddions.com", "gamesense.pub", "eulen.app",
        "lynxclient.com", "hamstercheats.com", "2take1.menu", "cherax.io",
        "evolution-cheat.com", "nighthawk-cheat.com", "epsilon-cheat.com",
        "phantom-cheats.com", "impulse-cheats.com", "baddie.pro", "stand.gg"
    };

    private static readonly string[] GameExeNames =
    {
        "FiveM.exe", "altv.exe", "RageMP.exe", "GTA5.exe", "VALORANT.exe", "cs2.exe"
    };

    private static readonly string[] VpnDisplayNameKeywords =
    {
        "mullvad", "nordvpn", "expressvpn", "privatevpn", "airvpn",
        "protonvpn", "torguard", "ivpn"
    };

    private static readonly string[] VpnProcessNames =
    {
        "mullvad", "nordvpn", "expressvpn", "privatevpn", "airvpn",
        "protonvpn", "torguard", "ivpn", "openvpn", "wireguard"
    };

    private static readonly string[] SuspiciousPayloadNames =
    {
        "update.exe", "patch.exe", "payload.exe", "loader.exe",
        "inject.exe", "client.exe"
    };

    private static readonly string[] CheatArchiveKeywords =
    {
        "cheat", "hack", "aimbot", "esp", "wallhack", "bypass",
        "loader", "inject", "trainer", "mod", "unlocker"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanHostsFileAntiCheatBlocksAsync(ctx, ct);
        ctx.Report(0.15, Name, "Hosts file anti-cheat blocks scanned");

        await ScanHostsFileCheatLicenseRedirectsAsync(ctx, ct);
        ctx.Report(0.25, Name, "Hosts file cheat license redirects scanned");

        ScanFirewallRulesForGameBlocking(ctx);
        ctx.Report(0.40, Name, "Firewall rules scanned");

        ScanDnsCacheRegistryAndExportFiles(ctx);
        ctx.Report(0.55, Name, "DNS cache artifacts scanned");

        ScanProxyAndVpnArtifacts(ctx);
        ctx.Report(0.70, Name, "Proxy and VPN artifacts scanned");

        await ScanNetworkConfigTamperingAsync(ctx, ct);
        ctx.Report(0.82, Name, "Network config tampering scanned");

        ScanTcpipInterfaceDnsSuffix(ctx);
        ctx.Report(0.90, Name, "TCP/IP interface DNS suffixes scanned");

        await ScanSuspiciousPayloadDownloadsAsync(ctx, ct);
        ctx.Report(1.0, Name, "Suspicious payload downloads scanned");
    }

    private async Task ScanHostsFileAntiCheatBlocksAsync(ScanContext ctx, CancellationToken ct)
    {
        var hostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");

        if (!File.Exists(hostsPath)) return;

        ctx.IncrementFiles();
        string content;
        try
        {
            using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var rawLine in lines)
        {
            if (ct.IsCancellationRequested) return;

            var line = rawLine.Trim();
            if (line.StartsWith('#')) continue;
            if (string.IsNullOrWhiteSpace(line)) continue;

            foreach (var domain in AntiCheatDomains)
            {
                if (!line.Contains(domain, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Hosts file blocks anti-cheat domain: {domain}",
                    Risk = RiskLevel.High,
                    Location = hostsPath,
                    FileName = "hosts",
                    Detail = $"Hosts entry: {line.Trim()}",
                    Reason = $"The Windows hosts file at '{hostsPath}' contains an entry redirecting or blocking " +
                             $"'{domain}'. Blocking anti-cheat domains (BattlEye, EasyAntiCheat, Vanguard, FACEIT, " +
                             "Steam, FiveM CDN) prevents anti-cheat systems from communicating with their servers, " +
                             "which is a known technique to disable telemetry and detection capabilities."
                });
                break;
            }
        }
    }

    private async Task ScanHostsFileCheatLicenseRedirectsAsync(ScanContext ctx, CancellationToken ct)
    {
        var hostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");

        if (!File.Exists(hostsPath)) return;

        ctx.IncrementFiles();
        string content;
        try
        {
            using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var rawLine in lines)
        {
            if (ct.IsCancellationRequested) return;

            var line = rawLine.Trim();
            if (line.StartsWith('#')) continue;
            if (string.IsNullOrWhiteSpace(line)) continue;

            foreach (var keyword in CheatLicenseDomainKeywords)
            {
                if (!line.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Hosts file maps cheat-related domain keyword '{keyword}'",
                    Risk = RiskLevel.High,
                    Location = hostsPath,
                    FileName = "hosts",
                    Detail = $"Hosts entry: {line.Trim()}",
                    Reason = $"The Windows hosts file contains an entry whose domain portion contains the keyword " +
                             $"'{keyword}'. Cracked cheat software often redirects cheat license/auth/HWID check " +
                             "servers to localhost or a custom IP to bypass subscription enforcement. This entry " +
                             "may represent such a redirect for a cracked cheat C2 server."
                });
                break;
            }

            foreach (var cheatDomain in KnownCheatDomains)
            {
                if (!line.Contains(cheatDomain, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Hosts file references known cheat domain: {cheatDomain}",
                    Risk = RiskLevel.High,
                    Location = hostsPath,
                    FileName = "hosts",
                    Detail = $"Hosts entry: {line.Trim()}",
                    Reason = $"The Windows hosts file contains an entry for '{cheatDomain}', a known cheat " +
                             "marketplace or provider domain. This may represent a redirect to bypass license " +
                             "checks (cracked cheat) or to block detection of cheat C2 communications."
                });
                break;
            }
        }
    }

    private void ScanFirewallRulesForGameBlocking(ScanContext ctx)
    {
        const string rulesKeyPath =
            @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(rulesKeyPath);
            if (key is null) return;

            var valueNames = key.GetValueNames();
            foreach (var valueName in valueNames)
            {
                ctx.IncrementRegistryKeys();

                var ruleValue = key.GetValue(valueName) as string;
                if (ruleValue is null) continue;

                bool hasBlock = ruleValue.Contains("Action=Block", StringComparison.OrdinalIgnoreCase);
                if (!hasBlock) continue;

                foreach (var gameExe in GameExeNames)
                {
                    if (!ruleValue.Contains(gameExe, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Firewall rule blocks game/anti-cheat executable: {gameExe}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{rulesKeyPath}\{valueName}",
                        Detail = $"Rule value (truncated): {ruleValue[..Math.Min(300, ruleValue.Length)]}",
                        Reason = $"A Windows Firewall rule at '{rulesKeyPath}\\{valueName}' blocks '{gameExe}'. " +
                                 "Blocking game or anti-cheat executables in the firewall can prevent anti-cheat " +
                                 "telemetry from reaching its servers, disabling detection capabilities. This is a " +
                                 "known technique used alongside cheat software to reduce the chance of detection."
                    });
                    break;
                }

                if (!hasBlock) continue;
                bool hasAntiCheatKeyword =
                    ruleValue.Contains("easyanticheat", StringComparison.OrdinalIgnoreCase) ||
                    ruleValue.Contains("battleye", StringComparison.OrdinalIgnoreCase) ||
                    ruleValue.Contains("vanguard", StringComparison.OrdinalIgnoreCase) ||
                    ruleValue.Contains("faceit", StringComparison.OrdinalIgnoreCase);

                if (!hasAntiCheatKeyword) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Firewall rule blocks anti-cheat service communication",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{rulesKeyPath}\{valueName}",
                    Detail = $"Rule value (truncated): {ruleValue[..Math.Min(300, ruleValue.Length)]}",
                    Reason = $"A Windows Firewall rule blocks an anti-cheat service (EasyAntiCheat, BattlEye, " +
                             "Vanguard, or FACEIT). This prevents the anti-cheat from communicating with its " +
                             "cloud backend, disabling detection of known cheat signatures and ban enforcement."
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }
    }

    private void ScanDnsCacheRegistryAndExportFiles(ScanContext ctx)
    {
        const string dnsCacheKeyPath =
            @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(dnsCacheKeyPath);
            if (key is not null)
            {
                ctx.IncrementRegistryKeys();

                var cacheTableKey = key.OpenSubKey("CacheHashTable");
                if (cacheTableKey is not null)
                {
                    var cacheNames = cacheTableKey.GetValueNames();
                    foreach (var name in cacheNames)
                    {
                        ctx.IncrementRegistryKeys();
                        foreach (var cheatDomain in KnownCheatDomains)
                        {
                            if (!name.Contains(cheatDomain, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DNS cache contains known cheat domain: {cheatDomain}",
                                Risk = RiskLevel.Medium,
                                Location = $@"HKLM\{dnsCacheKeyPath}\CacheHashTable",
                                Detail = $"DNS cache entry: {name}",
                                Reason = $"The Windows DNS client cache registry key contains an entry for '{cheatDomain}', " +
                                         "a known cheat marketplace or C2 domain. This indicates the system recently " +
                                         "resolved this domain, suggesting a connection was made to a cheat provider."
                            });
                            break;
                        }
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }

        ScanDnsCacheExportFiles(ctx);
    }

    private void ScanDnsCacheExportFiles(ScanContext ctx)
    {
        var tempPath = Path.GetTempPath();
        var dnsCacheFileNames = new[] { "dnscache.txt", "dns_cache.txt", "dns.txt", "dns_dump.txt" };

        foreach (var fileName in dnsCacheFileNames)
        {
            var filePath = Path.Combine(tempPath, fileName);
            if (!File.Exists(filePath)) continue;

            ctx.IncrementFiles();
            string content;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = sr.ReadToEnd();
            }
            catch (IOException)
            {
                continue;
            }

            foreach (var cheatDomain in KnownCheatDomains)
            {
                if (!content.Contains(cheatDomain, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"DNS cache export file references known cheat domain: {cheatDomain}",
                    Risk = RiskLevel.Medium,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"A DNS cache export file '{filePath}' contains the known cheat domain '{cheatDomain}'. " +
                             "DNS cache export files in Temp may have been generated by cheat tools for diagnostics " +
                             "or by system tools, and their content indicates prior resolution of cheat C2 domains."
                });
                break;
            }
        }
    }

    private void ScanProxyAndVpnArtifacts(ScanContext ctx)
    {
        ScanProxySettings(ctx);
        ScanInstalledVpnSoftware(ctx);
        ScanRunningVpnProcesses(ctx);
    }

    private void ScanProxySettings(ScanContext ctx)
    {
        const string inetSettingsKey =
            @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(inetSettingsKey);
            if (key is null) return;

            ctx.IncrementRegistryKeys();

            var proxyEnable = key.GetValue("ProxyEnable");
            if (proxyEnable is not int proxyInt || proxyInt != 1) return;

            ctx.IncrementRegistryKeys();
            var proxyServer = key.GetValue("ProxyServer") as string;
            if (proxyServer is null) return;

            bool hasSuspiciousPort = false;
            var suspiciousPorts = new[] { ":8080", ":8888", ":3128", ":1080", ":9050", ":9150" };
            foreach (var port in suspiciousPorts)
            {
                if (!proxyServer.Contains(port, StringComparison.OrdinalIgnoreCase)) continue;
                hasSuspiciousPort = true;
                break;
            }

            if (hasSuspiciousPort)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "HTTP proxy enabled with suspicious port in gaming context",
                    Risk = RiskLevel.Medium,
                    Location = $@"HKCU\{inetSettingsKey}",
                    Detail = $"ProxyServer = {proxyServer}",
                    Reason = $"Windows Internet Settings has ProxyEnable=1 with ProxyServer='{proxyServer}'. " +
                             "An active proxy with ports like 8080, 8888, 3128, 1080, or Tor ports (9050/9150) " +
                             "in a gaming context is suspicious. Cheat users sometimes route game traffic through " +
                             "proxies to obscure C2 communications or bypass IP bans."
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }
    }

    private void ScanInstalledVpnSoftware(ScanContext ctx)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        foreach (var uninstallPath in uninstallPaths)
        {
            try
            {
                using var uninstallKey = Registry.LocalMachine.OpenSubKey(uninstallPath);
                if (uninstallKey is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    try
                    {
                        using var appKey = uninstallKey.OpenSubKey(subKeyName);
                        if (appKey is null) continue;

                        ctx.IncrementRegistryKeys();

                        var displayName = appKey.GetValue("DisplayName") as string;
                        if (displayName is null) continue;

                        foreach (var vpnKeyword in VpnDisplayNameKeywords)
                        {
                            if (!displayName.Contains(vpnKeyword, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VPN software installed: {displayName}",
                                Risk = RiskLevel.Medium,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                Detail = $"DisplayName = {displayName}",
                                Reason = $"VPN software '{displayName}' is installed. While VPN use is legal, " +
                                         "it is commonly used in a gaming/cheating context to rotate IP addresses " +
                                         "to evade IP bans, bypass geographic anti-cheat restrictions, or anonymize " +
                                         "cheat C2 communication. Flagged as a contextual indicator."
                            });
                            break;
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (Exception) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }
        }
    }

    private void ScanRunningVpnProcesses(ScanContext ctx)
    {
        Process[] snapshot;
        try
        {
            snapshot = ctx.GetProcessSnapshot();
        }
        catch
        {
            return;
        }

        foreach (var process in snapshot)
        {
            ctx.IncrementProcesses();
            try
            {
                var processName = process.ProcessName;
                foreach (var vpnProc in VpnProcessNames)
                {
                    if (!processName.Contains(vpnProc, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"VPN client process running: {processName}",
                        Risk = RiskLevel.Medium,
                        Location = $"PID {process.Id}",
                        FileName = processName + ".exe",
                        Detail = $"PID: {process.Id}",
                        Reason = $"A VPN client process '{processName}' (PID {process.Id}) is currently running. " +
                                 "Active VPN use during gaming is suspicious in anti-cheat contexts as it can be " +
                                 "used to hide cheat C2 communications, rotate banned IPs, or bypass regional " +
                                 "anti-cheat restrictions. Flagged as a contextual indicator."
                    });
                    break;
                }
            }
            catch { }
        }
    }

    private async Task ScanNetworkConfigTamperingAsync(ScanContext ctx, CancellationToken ct)
    {
        ScanMtuSettings(ctx);
        await ScanPowerShellHistoryForNetshAsync(ctx, ct);
    }

    private void ScanMtuSettings(ScanContext ctx)
    {
        const string tcpipParamsPath =
            @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(tcpipParamsPath);
            if (key is null) return;

            ctx.IncrementRegistryKeys();

            var mtuValue = key.GetValue("MTU");
            if (mtuValue is int mtu)
            {
                const int standardMtu = 1500;
                const int minSuspicious = 100;
                const int maxSuspicious = 9000;

                if (mtu < minSuspicious || mtu > maxSuspicious)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unusual MTU value in TCP/IP parameters: {mtu}",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKLM\{tcpipParamsPath}",
                        Detail = $"MTU = {mtu} (standard: {standardMtu})",
                        Reason = $"The TCP/IP stack has a custom MTU value of {mtu}, which is outside the expected " +
                                 $"range (100–9000). The standard Ethernet MTU is {standardMtu}. Extremely low or " +
                                 "very high MTU values can be used to fragment packets in ways that confuse " +
                                 "network-level anti-cheat detection or deep packet inspection systems."
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }

        ScanInterfaceMtuValues(ctx);
    }

    private void ScanInterfaceMtuValues(ScanContext ctx)
    {
        const string interfacesPath =
            @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

        try
        {
            using var interfacesKey = Registry.LocalMachine.OpenSubKey(interfacesPath);
            if (interfacesKey is null) return;

            ctx.IncrementRegistryKeys();

            foreach (var ifaceGuid in interfacesKey.GetSubKeyNames())
            {
                try
                {
                    using var ifaceKey = interfacesKey.OpenSubKey(ifaceGuid);
                    if (ifaceKey is null) continue;

                    ctx.IncrementRegistryKeys();

                    var mtuValue = ifaceKey.GetValue("MTU");
                    if (mtuValue is not int mtu) continue;

                    if (mtu < 100 || mtu > 9001)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Unusual per-interface MTU on adapter {ifaceGuid}: {mtu}",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKLM\{interfacesPath}\{ifaceGuid}",
                            Detail = $"MTU = {mtu}",
                            Reason = $"Network adapter '{ifaceGuid}' has a custom MTU of {mtu}. " +
                                     "Non-standard MTU values on specific interfaces can be used to affect how " +
                                     "anti-cheat network traffic is fragmented and transmitted."
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }
    }

    private async Task ScanPowerShellHistoryForNetshAsync(ScanContext ctx, CancellationToken ct)
    {
        var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var historyPath = Path.Combine(
            appDataRoaming,
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (!File.Exists(historyPath)) return;

        ctx.IncrementFiles();
        string content;
        try
        {
            using var fs = new FileStream(historyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var rawLine in lines)
        {
            if (ct.IsCancellationRequested) return;
            var line = rawLine.Trim();

            bool hasNetsh = line.Contains("netsh advfirewall", StringComparison.OrdinalIgnoreCase) ||
                            line.Contains("netsh firewall", StringComparison.OrdinalIgnoreCase);
            if (!hasNetsh) continue;

            foreach (var gameExe in GameExeNames)
            {
                if (!line.Contains(gameExe.Replace(".exe", "", StringComparison.OrdinalIgnoreCase),
                        StringComparison.OrdinalIgnoreCase) &&
                    !line.Contains(gameExe, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"PowerShell history: netsh firewall rule targeting game/AC '{gameExe}'",
                    Risk = RiskLevel.Medium,
                    Location = historyPath,
                    FileName = Path.GetFileName(historyPath),
                    Detail = $"Command: {line[..Math.Min(200, line.Length)]}",
                    Reason = $"The PowerShell history file contains a 'netsh advfirewall' command that references " +
                             $"'{gameExe}'. Using netsh to configure firewall rules for game or anti-cheat processes " +
                             "is a known technique to block anti-cheat telemetry and server connections."
                });
                break;
            }

            bool hasAntiCheatRef =
                line.Contains("easyanticheat", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("battleye", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("vanguard", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("faceit", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("vac", StringComparison.OrdinalIgnoreCase);

            if (!hasAntiCheatRef) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "PowerShell history: netsh command targeting anti-cheat service",
                Risk = RiskLevel.Medium,
                Location = historyPath,
                FileName = Path.GetFileName(historyPath),
                Detail = $"Command: {line[..Math.Min(200, line.Length)]}",
                Reason = $"The PowerShell history file contains a netsh firewall command referencing an anti-cheat " +
                         "service (EasyAntiCheat, BattlEye, Vanguard, FACEIT, or VAC). This is commonly used to " +
                         "block anti-cheat communications while retaining the ability to play the game."
            });
        }
    }

    private void ScanTcpipInterfaceDnsSuffix(ScanContext ctx)
    {
        const string interfacesPath =
            @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

        try
        {
            using var interfacesKey = Registry.LocalMachine.OpenSubKey(interfacesPath);
            if (interfacesKey is null) return;

            ctx.IncrementRegistryKeys();

            foreach (var ifaceGuid in interfacesKey.GetSubKeyNames())
            {
                try
                {
                    using var ifaceKey = interfacesKey.OpenSubKey(ifaceGuid);
                    if (ifaceKey is null) continue;

                    ctx.IncrementRegistryKeys();

                    var dnsSuffix = ifaceKey.GetValue("DhcpDomain") as string
                                   ?? ifaceKey.GetValue("Domain") as string;
                    if (dnsSuffix is null) continue;

                    foreach (var keyword in CheatLicenseDomainKeywords)
                    {
                        if (!dnsSuffix.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"TCP/IP interface DNS suffix contains cheat keyword: {dnsSuffix}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{interfacesPath}\{ifaceGuid}",
                            Detail = $"DNS suffix: {dnsSuffix}, Interface GUID: {ifaceGuid}",
                            Reason = $"Network interface '{ifaceGuid}' has a DNS suffix override of '{dnsSuffix}' " +
                                     $"which contains the keyword '{keyword}'. A custom DNS suffix pointing to a " +
                                     "cheat-associated domain on a specific network adapter may indicate the adapter " +
                                     "is configured to route traffic to a cheat C2 server."
                        });
                        break;
                    }

                    foreach (var cheatDomain in KnownCheatDomains)
                    {
                        if (!dnsSuffix.Contains(cheatDomain, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"TCP/IP interface DNS suffix is known cheat domain: {cheatDomain}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{interfacesPath}\{ifaceGuid}",
                            Detail = $"DNS suffix: {dnsSuffix}, Interface GUID: {ifaceGuid}",
                            Reason = $"Network interface '{ifaceGuid}' has its DNS suffix set to '{dnsSuffix}', " +
                                     $"which matches the known cheat domain '{cheatDomain}'. This is an unusual " +
                                     "configuration that may route DNS queries for this domain to a specific server."
                        });
                        break;
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }
    }

    private async Task ScanSuspiciousPayloadDownloadsAsync(ScanContext ctx, CancellationToken ct)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloadsDir = Path.Combine(userProfile, "Downloads");
        var tempDir = Path.GetTempPath();

        await ScanDirectoryForSuspiciousPayloadsAsync(ctx, downloadsDir, ct);
        await ScanDirectoryForSuspiciousPayloadsAsync(ctx, tempDir, ct);
    }

    private async Task ScanDirectoryForSuspiciousPayloadsAsync(ScanContext ctx, string dir, CancellationToken ct)
    {
        if (!Directory.Exists(dir)) return;

        var payloadSet = new HashSet<string>(SuspiciousPayloadNames, StringComparer.OrdinalIgnoreCase);
        var cutoffDate = DateTime.UtcNow.AddDays(-30);

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            if (!payloadSet.Contains(fileName)) continue;

            try
            {
                var fileInfo = new FileInfo(file);
                if (fileInfo.CreationTimeUtc < cutoffDate) continue;

                var parentDir = Path.GetDirectoryName(file) ?? string.Empty;
                var parentDirName = Path.GetFileName(parentDir);

                bool parentDirSuspicious = CheatArchiveKeywords.Any(k =>
                    parentDirName.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!parentDirSuspicious) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious payload file in cheat-named directory: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Detail = $"Parent directory: {parentDirName}, Created: {fileInfo.CreationTimeUtc:u}",
                    Reason = $"The file '{fileName}' (a common cheat payload delivery name) was created " +
                             $"within the last 30 days in a directory named '{parentDirName}' which contains " +
                             $"a cheat-related keyword. Files named update.exe, patch.exe, loader.exe, etc. in " +
                             "cheat-named subdirectories are a common pattern for cheat C2 payload delivery."
                });
            }
            catch (IOException) { }
        }

        await ScanDirectoryForCheatArchivesAsync(ctx, dir, ct, cutoffDate);
    }

    private async Task ScanDirectoryForCheatArchivesAsync(
        ScanContext ctx, string dir, CancellationToken ct, DateTime cutoffDate)
    {
        var archiveExtensions = new[] { "*.zip", "*.rar", "*.7z" };

        foreach (var ext in archiveExtensions)
        {
            IEnumerable<string> archives;
            try
            {
                archives = Directory.EnumerateFiles(dir, ext, SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var archive in archives)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var archiveName = Path.GetFileNameWithoutExtension(archive);

                try
                {
                    var fileInfo = new FileInfo(archive);
                    if (fileInfo.CreationTimeUtc < cutoffDate) continue;
                }
                catch (IOException)
                {
                    continue;
                }

                foreach (var keyword in CheatArchiveKeywords)
                {
                    if (!archiveName.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Recently downloaded archive with cheat keyword in name: {Path.GetFileName(archive)}",
                        Risk = RiskLevel.Medium,
                        Location = archive,
                        FileName = Path.GetFileName(archive),
                        Detail = $"Matched keyword: '{keyword}'",
                        Reason = $"An archive file '{Path.GetFileName(archive)}' with the cheat-related keyword " +
                                 $"'{keyword}' was downloaded within the last 30 days. Cheat software is commonly " +
                                 "distributed as ZIP or RAR archives from C2 servers or cheat marketplaces. " +
                                 "The recent creation date and cheat keyword in the filename are suspicious."
                    });
                    break;
                }
            }
        }

        await Task.CompletedTask;
    }
}
