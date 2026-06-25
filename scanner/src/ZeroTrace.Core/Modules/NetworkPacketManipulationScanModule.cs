using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class NetworkPacketManipulationScanModule : IScanModule
{
    public string Name => "Network Packet Manipulation Detection";
    public double Weight => 4.1;
    public int ParallelGroup => 4;

    private static readonly string[] PacketToolNames =
    [
        "wireshark.exe", "tshark.exe", "nmap.exe", "scapy.exe",
        "packet_editor.exe", "packetedit.exe", "packet_inject.exe",
        "packetinjector.exe", "lag_switch.exe", "lagswitch.exe",
        "lag_hack.exe", "laghack.exe", "network_lag.exe",
        "pingspike.exe", "ping_spike.exe", "network_manipulate.exe",
        "net_manipulate.exe", "proxy_cheat.exe", "packet_proxy.exe",
        "game_proxy.exe", "game_packet.exe", "udp_cheat.exe",
        "tcp_cheat.exe", "packet_spoofer.exe", "ip_spoofer.exe",
        "speed_hack_net.exe", "speedhack_net.exe", "net_speedhack.exe",
        "wpe_pro.exe", "wpepro.exe", "cheatengine_net.exe",
        "ce_network.exe", "ethereal.exe", "rawcap.exe",
        "commview.exe", "omnipeek.exe", "netpeek.exe",
        "packetcapture.exe", "netcapture.exe", "network_sniffer.exe",
        "game_sniffer.exe", "game_packet_sniffer.exe",
        "winsock_hook.exe", "ws2_hook.exe", "wsa_hook.exe",
        "recv_hook.exe", "send_hook.exe", "socket_hook.exe",
        "dll_inject_net.exe", "ws2_32_hook.dll", "ws2hook.dll",
        "winsock_proxy.dll", "network_hook.dll", "packet_hook.dll",
        "lag_bot.exe", "lagbot.exe", "wlan_hack.exe",
        "wifi_deauth.exe", "deauth.exe", "network_jam.exe",
        "signal_jam.exe", "wifi_jammer.exe", "network_flood.exe",
        "udp_flood.exe", "tcp_flood.exe", "game_flood.exe",
        "mitm_proxy.exe", "mitmproxy.exe", "bettercap.exe",
        "ettercap.exe", "arpspoof.exe", "netcut.exe",
        "cain.exe", "game_mitm.exe", "ssl_strip.exe",
        "charles_proxy.exe", "fiddler.exe", "burpsuite.exe",
    ];

    private static readonly string[] LagSwitchConfigKeywords =
    [
        "lag_switch", "lagswitch", "lag_hack", "ping_spike",
        "network_lag", "lag_enabled", "lag_key", "lag_toggle",
        "drop_packets", "delay_packets", "packet_delay",
        "artificial_lag", "lag_amount", "lag_duration",
        "lag_interval", "lag_random", "freeze_network",
        "network_freeze", "disconnect_key", "reconnect_key",
        "adapter_disable", "nic_disable", "firewall_block",
        "block_incoming", "block_outgoing", "selective_lag",
        "lag_on_hit", "lag_on_death", "lag_on_shot",
    ];

    private static readonly string[] PacketInjectionKeywords =
    [
        "inject_packet", "send_packet", "craft_packet",
        "forge_packet", "spoof_packet", "fake_packet",
        "raw_socket", "raw_packet", "custom_packet",
        "game_protocol", "packet_structure", "packet_format",
        "opcode", "packet_id", "recv_hook", "send_hook",
        "winsock_hook", "packet_filter", "packet_modify",
        "packet_block", "packet_drop", "packet_replay",
        "position_teleport", "speed_packet", "fly_packet",
        "kill_packet", "damage_packet", "heal_packet",
        "item_packet", "money_packet", "experience_packet",
        "level_packet", "stat_packet", "skill_packet",
    ];

    private static readonly string[] NetworkCheatTools =
    [
        "wpe_pro", "wpepro", "packet_editor", "cheat_engine_network",
        "ollydbg_net", "x64dbg_net", "ida_net_plugin",
        "wireshark_cheat", "tshark_cheat", "network_cheat",
        "game_packet_editor", "game_packet_sniffer",
        "mmo_packet", "fps_packet", "battle_royale_packet",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>
        {
            ScanPacketToolsAsync(ctx, ct),
            ScanLagSwitchToolsAsync(ctx, ct),
            ScanConfigFilesAsync(ctx, ct),
            ScanWinsockHookDllsAsync(ctx, ct),
            ScanRegistryAsync(ctx, ct),
            ScanNetworkCaptureDriversAsync(ctx, ct),
            ScanProxyToolsAsync(ctx, ct),
            ScanProcessesAsync(ctx, ct),
        };
        await Task.WhenAll(tasks);
    }

    private async Task ScanPacketToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                foreach (var tool in PacketToolNames)
                {
                    if (fn.Equals(tool, StringComparison.OrdinalIgnoreCase))
                    {
                        var isCritical = fn.Contains("lag", StringComparison.OrdinalIgnoreCase) ||
                                         fn.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                                         fn.Contains("spoof", StringComparison.OrdinalIgnoreCase) ||
                                         fn.Contains("cheat", StringComparison.OrdinalIgnoreCase);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Network Manipulation Tool",
                            Risk = isCritical ? Risk.Critical : Risk.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Network manipulation tool '{fn}' found",
                            Detail = "Packet manipulation tools can create lag switches, speed hacks, or packet injection cheats"
                        });
                        break;
                    }
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanLagSwitchToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var lagSwitchNames = new[]
        {
            "lag_switch.exe", "lagswitch.exe", "lag_hack.exe", "laghack.exe",
            "network_lag.exe", "pingspike.exe", "ping_spike.exe",
            "lag_bot.exe", "lagbot.exe", "lag_tool.exe", "lag_app.exe",
            "disconnect_tool.exe", "net_freeze.exe", "netfreeze.exe",
            "adapter_disabler.exe", "nic_disabler.exe", "network_freezer.exe",
            "artificial_lag.exe", "selective_lag.exe", "lag_on_hit.exe",
        };

        var allDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var dir in allDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (lagSwitchNames.Any(l => fn.Equals(l, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Lag Switch Tool",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Lag switch tool '{fn}' detected",
                        Detail = "Lag switches give unfair advantage by freezing opponent connections at key moments"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var dir in configDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".ini" && ext != ".cfg" && ext != ".json" && ext != ".txt" && ext != ".xml") continue;

                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var lagHits = LagSwitchConfigKeywords.Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)).ToList();
                if (lagHits.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Lag Switch Configuration File",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Config file contains {lagHits.Count} lag switch keywords",
                        Detail = "Keywords: " + string.Join(", ", lagHits.Take(6))
                    });
                }

                var packetHits = PacketInjectionKeywords.Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)).ToList();
                if (packetHits.Count >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Packet Injection Cheat Config",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Config file contains {packetHits.Count} packet injection keywords",
                        Detail = "Keywords: " + string.Join(", ", packetHits.Take(6))
                    });
                }
            }
        }
    }

    private async Task ScanWinsockHookDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        // Check for Winsock hook DLLs placed next to games
        var winsockHookNames = new[]
        {
            "ws2_32.dll", "wsock32.dll", "wininet.dll", "winhttp.dll",
        };

        // These DLLs should only exist in System32/SysWOW64, not game dirs
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var syswow64 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

        var gameDirs = GetGameDirectories();
        foreach (var gameDir in gameDirs)
        {
            if (!Directory.Exists(gameDir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(gameDir, "*.dll", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var dll in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(dll);

                if (winsockHookNames.Any(w => fn.Equals(w, StringComparison.OrdinalIgnoreCase)))
                {
                    // This shouldn't be in a game directory
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Winsock Hook DLL in Game Directory",
                        Risk = Risk.Critical,
                        Location = dll,
                        FileName = fn,
                        Reason = $"System network DLL '{fn}' placed in game directory — likely Winsock hook for packet manipulation",
                        Detail = "DLL hijacking of network DLLs enables packet sniffing, injection, and lag switching"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private static IEnumerable<string> GetGameDirectories()
    {
        var dirs = new List<string>();
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        dirs.Add(Path.Combine(pf, "Steam", "steamapps", "common"));
        dirs.Add(Path.Combine(pfx86, "Steam", "steamapps", "common"));
        dirs.Add(Path.Combine(pf, "Epic Games"));
        dirs.Add(Path.Combine(pfx86, "Origin Games"));
        dirs.Add(Path.Combine(pf, "Riot Games"));

        try
        {
            using var steamKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam");
            var steamPath = steamKey?.GetValue("InstallPath") as string;
            if (steamPath != null) dirs.Add(Path.Combine(steamPath, "steamapps", "common"));
        }
        catch { }

        return dirs.Where(Directory.Exists);
    }

    private async Task ScanRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // WinPcap / Npcap driver installed (packet capture library)
            var captureServices = new[] { "npf", "npcap", "WinPcap", "npcap_wifi" };
            foreach (var svc in captureServices)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svc}");
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    var start = key.GetValue("Start");
                    var desc = key.GetValue("Description") as string ?? string.Empty;
                    // Npcap/WinPcap alone isn't suspicious but combined with cheat artifacts it is
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Packet Capture Driver Installed: {svc}",
                        Risk = Risk.Medium,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc}",
                        FileName = "Registry",
                        Reason = $"Packet capture driver '{svc}' is installed — used by network sniffers and potential lag switch tools",
                        Detail = "WinPcap/Npcap is required for packet capture/injection tools like Wireshark and lag switches"
                    });
                    break;
                }
                catch { }
            }

            // Windows Firewall rules that block game traffic (lag switch via firewall)
            try
            {
                using var fwKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
                if (fwKey != null)
                {
                    ctx.IncrementRegistryKeys();
                    foreach (var valName in fwKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var val = fwKey.GetValue(valName) as string ?? string.Empty;
                        if (val.Contains("lag", StringComparison.OrdinalIgnoreCase) ||
                            val.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            val.Contains("block_game", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious Firewall Rule (Lag Switch)",
                                Risk = Risk.High,
                                Location = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                                FileName = "Registry",
                                Reason = $"Firewall rule with lag/cheat keyword: {valName}",
                                Detail = "Custom firewall rules can act as software lag switches"
                            });
                        }
                    }
                }
            }
            catch { }

            // Check for raw socket elevation — programs that open raw sockets need admin + IP_HDRINCL
            try
            {
                using var tcpip = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
                if (tcpip != null)
                {
                    ctx.IncrementRegistryKeys();
                    var rawSockets = tcpip.GetValue("DisableRawSockets");
                    if (rawSockets is int r && r == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Raw Sockets Enabled in TCP/IP Stack",
                            Risk = Risk.Medium,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                            FileName = "Registry",
                            Reason = "Raw socket access enabled — allows packet crafting and injection tools",
                            Detail = "Raw sockets required for custom packet injection and IP spoofing tools"
                        });
                    }
                }
            }
            catch { }
        }, ct);
    }

    private async Task ScanNetworkCaptureDriversAsync(ScanContext ctx, CancellationToken ct)
    {
        // WinPcap/Npcap DLL files in system directories
        var captureDriverFiles = new[]
        {
            "wpcap.dll", "packet.dll", "Packet.dll", "npcap.dll",
            "wpcap.dll", "NPcap.dll",
        };

        var sys32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var npcapDir = Path.Combine(sys32, "Npcap");
        var winpcapDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WinPcap");

        // Check for Npcap in user directories (not the official install location)
        var userDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
        };

        foreach (var dir in userDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file);
                if (captureDriverFiles.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Packet Capture DLL in User Directory",
                        Risk = Risk.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Packet capture DLL '{fn}' found outside system directory",
                        Detail = "Indicates portable packet capture tool being used for network manipulation"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanProxyToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        // Proxy/MITM tools used for game packet interception
        var proxyToolDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
        };

        var gameProxyIndicators = new[]
        {
            "mitmproxy", "burpsuite", "charles", "fiddler",
            "game_proxy", "packet_proxy", "game_mitm",
        };

        foreach (var dir in proxyToolDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file).ToLowerInvariant();

                if (gameProxyIndicators.Any(p => fn.Contains(p)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Game Traffic Proxy/MITM Tool",
                        Risk = Risk.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"MITM/proxy tool '{Path.GetFileName(file)}' used for game traffic interception",
                        Detail = "Game packet MITM proxies intercept and modify game protocol traffic"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanProcessesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var processes = ctx.GetProcessSnapshot();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();
                var pname = proc.ProcessName.ToLowerInvariant() + ".exe";

                foreach (var tool in PacketToolNames)
                {
                    if (pname.Equals(tool, StringComparison.OrdinalIgnoreCase))
                    {
                        string procPath = string.Empty;
                        try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Network Manipulation Tool Running",
                            Risk = Risk.Critical,
                            Location = procPath,
                            FileName = pname,
                            Reason = $"Network manipulation tool '{pname}' is currently running",
                            Detail = $"PID: {proc.Id}"
                        });
                        break;
                    }
                }
            }
        }, ct);
    }
}
