using Microsoft.Win32;
using System.Text.Json;
using System.Text.RegularExpressions;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

// Detects techniques used to evade anti-cheat fingerprinting beyond basic HWID
// spoofing. Covers browser fingerprint evasion (canvas/WebGL spoofer extensions),
// process memory evasion (.NET obfuscators, stack spoof tools, PE timestompers),
// Steam account fingerprint bypass, game client hash bypass configs, network
// fingerprint evasion (VPN/proxy for geo-check bypass), and hardware behaviour
// evasion (human-mouse/keyboard randomiser tools).
public sealed class AntiCheatFingerPrintEvasionScanModule : IScanModule
{
    public string Name => "Anti-Cheat Fingerprint Evasion Detection";
    public double Weight => 4.2;
    public int ParallelGroup => 4;

    // Extension names and keywords that appear in canvas/fingerprint spoofer browser extensions
    private static readonly string[] FingerprintSpooferExtensionKeywords =
    {
        "canvas blocker", "canvas fingerprint", "canvas poison", "canvasblocker",
        "canvas fingerprint defender", "fingerprint spoof", "fingerprint blocker",
        "webgl spoof", "webgl fingerprint", "webgl defender", "webgl blocker",
        "user agent spoof", "font fingerprint", "audio fingerprint",
        "fingerprint randomize", "fp blocker", "fp spoofer", "trace",
        "privacy possum", "resistfingerprinting", "anti fingerprint",
        "canvas fingerprint protector", "buster", "gpu spoof",
    };

    // Known browser extension IDs associated with fingerprint spoofing
    private static readonly string[] KnownSpooferExtensionIds =
    {
        "iphoffjbejhfbkcimllhgdnkhiohicoh", // Canvas Blocker
        "lgcmmmomhagnoldinjpkfjfhiocapijk", // Canvas Fingerprint Defender
        "lmmjpihgfhchkiheidlegbcpglmfnaib", // WebGL Fingerprint Defender
        "oboonakemofpalcgghocfoadofidjkkk", // WebRTC Leak Prevent
        "pcbjiidheaempljdefbdplebgdgpjcbe", // Fingerprint Defender
        "jifbbflkpebmejbkgmpmjfbhhgpafmce", // Font Fingerprint
    };

    // Process memory evasion tools: .NET obfuscators, stack spoofers, PE timestompers
    private static readonly string[] MemoryEvasionExecutables =
    {
        "stringencrypt.exe", "obfuscar.exe", "dotnetguard.exe", "confuserex.exe",
        "de4dot.exe", "dnspy.exe", "reflexil.exe", "dotpeek.exe",
        "stack_spoof.exe", "stackspoof.exe", "stack-spoof.exe",
        "return_address_spoof.exe", "returnspoof.exe", "retspoof.exe",
        "pe_timestomp.exe", "timestomp.exe", "timestamper.exe",
        "pe_time.exe", "petimestamp.exe", "timestamp_patch.exe",
        "nethider.exe", "nethide.exe", "net_obfuscator.exe",
        "ilprotector.exe", "smartassembly.exe", "dotfuscator.exe",
        "babel.exe", "xenos.exe", "vmprotect.exe", "themida.exe",
        "enigmavb.exe", "obsidium.exe", "asprotect.exe",
    };

    // Memory evasion config file names: heap encryption, string encryption configs
    private static readonly string[] MemoryEvasionConfigFiles =
    {
        "heap_encrypt.cfg", "heap_encrypt.json", "heap_encrypt.ini",
        "string_encrypt.cfg", "string_encrypt.json",
        "stack_spoof.cfg", "stack_spoof.json", "stack_spoof.ini",
        "pe_config.json", "pe_protect.cfg", "obfuscation.json",
        "evasion.cfg", "evasion.json", "evasion.ini",
        "memory_protect.cfg", "memory_protect.json",
        "anti_scan.cfg", "anti_scan.json", "antiscan.cfg",
    };

    // Steam account / VAC bypass switcher tools
    private static readonly string[] SteamBypassExecutables =
    {
        "vac_switcher.exe", "vacswitcher.exe", "vac-switcher.exe",
        "steam_switcher.exe", "steamswitcher.exe", "steam-switcher.exe",
        "account_switcher.exe", "accountswitcher.exe", "acc_switcher.exe",
        "steam_bypass.dll", "steambypass.dll", "steam-bypass.dll",
        "vac_bypass.exe", "vacbypass.exe", "vac-bypass.exe",
        "steam_unban.exe", "steamunban.exe",
        "steamid_changer.exe", "steamidchanger.exe",
    };

    // Game client hash/integrity bypass config file names
    private static readonly string[] HashBypassConfigFiles =
    {
        "integrity_bypass.json", "integrity_bypass.cfg", "integrity_bypass.ini",
        "hash_bypass.json", "hash_bypass.cfg", "hash_bypass.ini",
        "crc_bypass.json", "crc_bypass.cfg", "crc_bypass.ini",
        "file_hash_override.json", "hash_override.json", "checksum_bypass.json",
        "file_integrity.bypass", "bypass_integrity.json",
        "game_bypass.cfg", "client_bypass.cfg", "ac_bypass.cfg",
    };

    // Network fingerprint evasion executables
    private static readonly string[] NetworkEvasionExecutables =
    {
        "ip_change.bat", "ipchange.bat", "ip-change.bat",
        "mac_change.bat", "macchange.bat", "mac-change.bat",
        "vpn_switch.exe", "vpnswitch.exe", "vpn-switch.exe",
        "proxy_switcher.exe", "proxyswitcher.exe",
        "socks_tunnel.exe", "sockstunnel.exe",
        "ip_ban_bypass.exe", "ipbanbypass.exe", "ip_bypass.exe",
        "network_spoof.exe", "netspoof.exe",
    };

    // Proxy/SOCKS configuration files in suspicious directories
    private static readonly string[] ProxyConfigFileNames =
    {
        "proxy.txt", "proxy_list.txt", "proxylist.txt",
        "socks5.txt", "socks4.txt", "socks_list.txt", "sockslist.txt",
        "proxies.txt", "proxy_chain.txt",
    };

    // Mouse movement injection / human simulation tools
    private static readonly string[] MouseEvasionExecutables =
    {
        "mousemover.exe", "mouse_mover.exe", "mouse-mover.exe",
        "human_mouse.exe", "humanmouse.exe", "human-mouse.exe",
        "mouse_jitter.exe", "mousejitter.exe", "mouse-jitter.exe",
        "aim_humanizer.exe", "aimhumanizer.exe", "aim-humanizer.exe",
        "mouse_humanizer.exe", "mousehumanizer.exe",
        "mouse_simulator.exe", "mousesimulator.exe",
        "human_aim.exe", "humanaim.exe",
        "smooth_aim.exe", "smoothaim.exe", "smoothmouse.exe",
        "mouse_natural.exe", "naturalmouse.exe",
        "mouse_randomize.exe", "mouserandomize.exe",
        "input_simulator.exe", "inputsimulator.exe",
    };

    // Keyboard timing randomiser tools
    private static readonly string[] KeyboardEvasionExecutables =
    {
        "keystroke_delay.exe", "keystrokedelay.exe", "keystroke-delay.exe",
        "key_randomize.exe", "keyrandomize.exe", "key-randomize.exe",
        "keyboard_delay.exe", "keyboarddelay.exe",
        "key_timing.exe", "keytiming.exe", "keyboard_randomize.exe",
        "input_delay.exe", "inputdelay.exe",
        "kb_randomizer.exe", "kbrandomizer.exe",
        "typing_randomize.exe", "typingrandomize.exe",
        "keyboard_humanize.exe", "keyboardhumanize.exe",
    };

    // Common cheat/tool directories to scan for evasion tools
    private static readonly string[] CheatToolSubDirs =
    {
        "cheat", "cheats", "hack", "hacks", "tool", "tools",
        "spoofer", "spoofers", "loader", "loaders", "injector",
        "bypass", "evasion", "evade", "stealth",
    };

    // Regex to detect game-cheat-related comments in VPN/WireGuard configs
    private static readonly Regex GameCheatCommentRegex = new(
        @"#\s*(cheat|ban\s*evad|ban\s*bypass|hwid|spoof|valorant|warzone|rust|escape\s*from\s*tarkov|eft|fortnite|apex|csgo|cs2|battleye|eac|vac|anticheat|anti[\s\-]?cheat)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.00, Name, "Scanning browser extensions for fingerprint spoofers...");
        await Task.Run(() => ScanBrowserExtensionsForFingerprintSpoofers(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.12, Name, "Checking process memory evasion tools...");
        await Task.Run(() => CheckMemoryEvasionTools(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.24, Name, "Checking Steam account fingerprint bypass...");
        await Task.Run(() => CheckSteamFingerprintBypass(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.37, Name, "Scanning Steam directory for bypass artifacts...");
        await Task.Run(() => ScanSteamDirectoryForBypassArtifacts(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.48, Name, "Checking game client integrity bypass configs...");
        await Task.Run(() => CheckGameIntegrityBypassConfigs(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.58, Name, "Checking network fingerprint evasion tools...");
        await Task.Run(() => CheckNetworkEvasionTools(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.68, Name, "Scanning VPN/proxy configs for cheat-related use...");
        await Task.Run(() => ScanVpnConfigsForCheatUse(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.78, Name, "Checking mouse movement evasion tools...");
        await Task.Run(() => CheckMouseEvasionTools(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.88, Name, "Checking keyboard timing evasion tools...");
        await Task.Run(() => CheckKeyboardEvasionTools(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.95, Name, "Scanning common cheat directories for evasion tools...");
        await Task.Run(() => ScanCheatDirectoriesForEvasionTools(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(1.00, Name, "Anti-cheat fingerprint evasion scan complete.");
    }

    // Scans Chrome/Edge/Brave/Firefox extension directories for canvas and WebGL
    // fingerprint spoofer extensions by checking extension name, description, and ID.
    private void ScanBrowserExtensionsForFingerprintSpoofers(ScanContext ctx, CancellationToken ct)
    {
        var localAppData  = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roamingData   = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var chromiumRoots = new (string Browser, string Path)[]
        {
            ("Chrome",   System.IO.Path.Combine(localAppData, "Google", "Chrome", "User Data")),
            ("Edge",     System.IO.Path.Combine(localAppData, "Microsoft", "Edge", "User Data")),
            ("Brave",    System.IO.Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data")),
            ("Vivaldi",  System.IO.Path.Combine(localAppData, "Vivaldi", "User Data")),
            ("Opera",    System.IO.Path.Combine(roamingData, "Opera Software", "Opera Stable")),
            ("Opera GX", System.IO.Path.Combine(roamingData, "Opera Software", "Opera GX Stable")),
        };

        foreach (var (browser, root) in chromiumRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanChromiumProfilesForFingerprintExtensions(ctx, browser, root, ct);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }

        // Firefox extensions
        var firefoxRoot = System.IO.Path.Combine(roamingData, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(firefoxRoot))
        {
            try { ScanFirefoxExtensionsForFingerprintSpoofers(ctx, firefoxRoot, ct); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanChromiumProfilesForFingerprintExtensions(ScanContext ctx, string browser,
        string root, CancellationToken ct)
    {
        string[] profiles;
        try { profiles = Directory.GetDirectories(root); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var profile in profiles)
        {
            if (ct.IsCancellationRequested) return;
            var extsDir = System.IO.Path.Combine(profile, "Extensions");
            if (!Directory.Exists(extsDir)) continue;

            string[] extIdDirs;
            try { extIdDirs = Directory.GetDirectories(extsDir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var extIdDir in extIdDirs)
            {
                if (ct.IsCancellationRequested) return;
                var extId = System.IO.Path.GetFileName(extIdDir);

                // Check by known extension ID first
                if (KnownSpooferExtensionIds.Any(id =>
                    id.Equals(extId, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Known fingerprint spoofer extension found ({browser}): {extId}",
                        Risk     = RiskLevel.High,
                        Location = extIdDir,
                        FileName = extId,
                        Reason   = $"The browser extension ID '{extId}' matches a known canvas/WebGL " +
                                   "fingerprint spoofer extension in the {browser} extensions directory. " +
                                   "These extensions report fake GPU, canvas, and font information to " +
                                   "web-based anti-cheat systems that use browser fingerprinting to " +
                                   "track banned players across accounts.",
                        Detail   = $"Browser: {browser} | Extension ID: {extId}"
                    });
                }

                // Also inspect manifest.json for name/description keywords
                try
                {
                    string[] versionDirs;
                    try { versionDirs = Directory.GetDirectories(extIdDir); }
                    catch { continue; }

                    foreach (var versionDir in versionDirs)
                    {
                        var manifestPath = System.IO.Path.Combine(versionDir, "manifest.json");
                        if (!File.Exists(manifestPath)) continue;
                        try
                        {
                            InspectManifestForFingerprintSpoofer(ctx, browser, manifestPath, extId);
                        }
                        catch (IOException) { }
                        catch { }
                        break;
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
    }

    private void InspectManifestForFingerprintSpoofer(ScanContext ctx, string browser,
        string manifestPath, string extId)
    {
        string content;
        try
        {
            using var fs = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = sr.ReadToEnd();
        }
        catch (IOException) { return; }

        ctx.IncrementFiles();

        string name = extId, description = "";
        try
        {
            using var doc = JsonDocument.Parse(content,
                new JsonDocumentOptions { AllowTrailingCommas = true });
            var root = doc.RootElement;
            if (root.TryGetProperty("name", out var nameProp))
                name = nameProp.GetString() ?? extId;
            if (root.TryGetProperty("description", out var descProp))
                description = descProp.GetString() ?? "";
        }
        catch { return; }

        if (name.StartsWith("__MSG_")) name = extId;
        var combined = (name + " " + description).ToLowerInvariant();

        foreach (var keyword in FingerprintSpooferExtensionKeywords)
        {
            if (combined.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Fingerprint spoofer browser extension ({browser}): {name}",
                    Risk     = RiskLevel.High,
                    Location = manifestPath,
                    FileName = name,
                    Reason   = $"The {browser} extension '{name}' (ID: {extId}) contains the keyword " +
                               $"'{keyword}' in its name or description. Canvas and WebGL fingerprint " +
                               "spoofer extensions intercept browser fingerprinting APIs to report " +
                               "randomised or fake hardware information, defeating web-based anti-cheat " +
                               "fingerprinting that tracks banned users across new accounts.",
                    Detail   = $"Extension: {name} | ID: {extId} | Keyword match: {keyword}"
                });
                return;
            }
        }
    }

    private void ScanFirefoxExtensionsForFingerprintSpoofers(ScanContext ctx, string profilesRoot,
        CancellationToken ct)
    {
        string[] profileDirs;
        try { profileDirs = Directory.GetDirectories(profilesRoot); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var profileDir in profileDirs)
        {
            if (ct.IsCancellationRequested) return;
            var extensionsDir = System.IO.Path.Combine(profileDir, "extensions");
            if (!Directory.Exists(extensionsDir)) continue;

            // Firefox extensions are .xpi files (ZIPs) or unpacked directories
            string[] entries;
            try { entries = Directory.GetFileSystemEntries(extensionsDir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var entry in entries)
            {
                if (ct.IsCancellationRequested) return;
                var entryName = System.IO.Path.GetFileName(entry).ToLowerInvariant();

                foreach (var keyword in FingerprintSpooferExtensionKeywords)
                {
                    if (entryName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Fingerprint spoofer Firefox extension: {System.IO.Path.GetFileName(entry)}",
                            Risk     = RiskLevel.High,
                            Location = entry,
                            FileName = System.IO.Path.GetFileName(entry),
                            Reason   = $"A Firefox extension or XPI package named '{System.IO.Path.GetFileName(entry)}' " +
                                       $"contains the fingerprint-spoofer keyword '{keyword}'. Firefox extensions " +
                                       "with canvas/WebGL spoofing capabilities report false browser fingerprint " +
                                       "data to web-based anti-cheat systems that track banned players.",
                            Detail   = $"Path: {entry} | Keyword: {keyword}"
                        });
                        break;
                    }
                }
            }
        }
    }

    // Checks the user's AppData and common tool directories for .NET obfuscators,
    // stack spoofers, and PE timestamp tampering tools.
    private void CheckMemoryEvasionTools(ScanContext ctx, CancellationToken ct)
    {
        var scanRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)),
            @"C:\Tools", @"C:\Hack", @"C:\Cheats", @"C:\Loaders",
        };

        foreach (var root in scanRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanDirectoryForMemoryEvasionTools(ctx, root, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanDirectoryForMemoryEvasionTools(ScanContext ctx, string directory,
        CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();

            foreach (var evasionExe in MemoryEvasionExecutables)
            {
                if (fileName.Equals(evasionExe, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Process memory evasion tool: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"The file '{System.IO.Path.GetFileName(file)}' is a known process memory " +
                                   "evasion tool. These tools are used to obfuscate .NET cheat binaries, " +
                                   "spoof thread stack return addresses, or tamper with PE file timestamps " +
                                   "to defeat memory-signature and file-integrity scanning performed by " +
                                   "anti-cheat systems such as EAC, BattlEye, and Vanguard.",
                        Detail   = $"Tool: {evasionExe} | Path: {file}"
                    });
                    break;
                }
            }

            foreach (var configFile in MemoryEvasionConfigFiles)
            {
                if (fileName.Equals(configFile, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Memory evasion configuration file: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.Medium,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"The file '{System.IO.Path.GetFileName(file)}' matches a known memory " +
                                   "evasion configuration file name. Configuration files for heap encryption, " +
                                   "string encryption, and stack spoofing tools indicate that a cheat binary " +
                                   "was configured to actively hide its memory signature from anti-cheat " +
                                   "memory scanners.",
                        Detail   = $"Config file: {configFile} | Path: {file}"
                    });
                    break;
                }
            }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanDirectoryForMemoryEvasionTools(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Checks Steam registry for account fingerprint bypass artifacts: mismatched
    // AutoLoginUser vs LastGameNameUsed, and VAC bypass switcher tools.
    private void CheckSteamFingerprintBypass(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            using var steamKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam", writable: false);
            if (steamKey is null) return;
            ctx.IncrementRegistryKeys();

            var autoLoginUser    = steamKey.GetValue("AutoLoginUser") as string ?? "";
            var lastGameNameUsed = steamKey.GetValue("LastGameNameUsed") as string ?? "";
            var rememberedUser   = steamKey.GetValue("RememberPassword") as int? ?? 0;

            // Multiple remembered users with mismatched last-game-used vs auto-login
            // indicates rapid account switching to evade per-account bans.
            if (!string.IsNullOrWhiteSpace(autoLoginUser) &&
                !string.IsNullOrWhiteSpace(lastGameNameUsed) &&
                !autoLoginUser.Equals(lastGameNameUsed, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Steam AutoLoginUser differs from LastGameNameUsed (account switcher pattern)",
                    Risk     = RiskLevel.Medium,
                    Location = @"HKCU\SOFTWARE\Valve\Steam",
                    Reason   = $"The Steam AutoLoginUser ('{autoLoginUser}') differs from " +
                               $"LastGameNameUsed ('{lastGameNameUsed}'). This mismatch is a pattern " +
                               "left by rapid Steam account switcher tools that cycle between accounts " +
                               "to play on banned accounts or use VAC-banned accounts without triggering " +
                               "immediate detection by switching to a clean account for the game session.",
                    Detail   = $"AutoLoginUser = \"{autoLoginUser}\" | LastGameNameUsed = \"{lastGameNameUsed}\""
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        // Check for family sharing bypass via registry flags
        try
        {
            using var steamKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Valve\Steam\ActiveProcess", writable: false);
            if (steamKey is not null)
            {
                ctx.IncrementRegistryKeys();
                var activePid = steamKey.GetValue("pid") as int?;
                var activeUser = steamKey.GetValue("ActiveUser") as int?;

                // Check global Steam settings for family sharing configuration
                using var globalKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Valve\Steam\GlobalAutoLoginUsers", writable: false);
                if (globalKey is not null)
                {
                    var userCount = globalKey.GetSubKeyNames().Length;
                    if (userCount >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"High number of Steam global auto-login users ({userCount}) — possible account switcher",
                            Risk     = RiskLevel.Medium,
                            Location = @"HKCU\SOFTWARE\Valve\Steam\GlobalAutoLoginUsers",
                            Reason   = $"There are {userCount} entries in the Steam GlobalAutoLoginUsers " +
                                       "registry key. A high number of auto-login users is characteristic " +
                                       "of account switcher tools used for ban evasion — cheaters maintain " +
                                       "multiple accounts and rapidly switch between them to continue playing " +
                                       "after bans.",
                            Detail   = $"GlobalAutoLoginUsers count: {userCount}"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // Scans the Steam installation directory for bypass DLLs and VAC bypass switcher tools.
    private void ScanSteamDirectoryForBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        string? steamPath = null;
        try
        {
            steamPath = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Valve\Steam",
                "SteamPath", null) as string;
        }
        catch { }

        if (string.IsNullOrWhiteSpace(steamPath) || !Directory.Exists(steamPath)) return;

        string[] steamFiles;
        try { steamFiles = Directory.GetFiles(steamPath, "*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in steamFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();

            foreach (var bypassExe in SteamBypassExecutables)
            {
                if (fileName.Equals(bypassExe, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Steam/VAC bypass tool in Steam directory: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"The file '{System.IO.Path.GetFileName(file)}' found inside the Steam " +
                                   "installation directory matches a known Steam or VAC bypass tool. " +
                                   "These tools are placed in the Steam directory to hook Steam APIs, " +
                                   "intercept VAC scanning routines, or switch between accounts to " +
                                   "avoid bans from being enforced during game sessions.",
                        Detail   = $"Steam bypass tool: {bypassExe} | Location: {file}"
                    });
                    break;
                }
            }
        }
    }

    // Checks common game directories and user data folders for game client hash/CRC
    // bypass configuration files.
    private void CheckGameIntegrityBypassConfigs(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            @"C:\Games", @"C:\Cheats", @"C:\Hack", @"C:\Tools",
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanForHashBypassConfigs(ctx, root, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanForHashBypassConfigs(ScanContext ctx, string directory,
        CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();

            foreach (var bypassConfig in HashBypassConfigFiles)
            {
                if (fileName.Equals(bypassConfig, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Game client integrity bypass config found: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"The configuration file '{System.IO.Path.GetFileName(file)}' matches a " +
                                   "known game client integrity bypass config file name. These files are " +
                                   "used to override file hash or CRC verification that game launchers " +
                                   "perform before starting the game, allowing modified client binaries " +
                                   "(with cheats injected) to pass integrity checks performed by the " +
                                   "game launcher or anti-cheat system.",
                        Detail   = $"Config file: {bypassConfig} | Path: {file}"
                    });
                    break;
                }
            }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanForHashBypassConfigs(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Checks for network fingerprint evasion tools: IP/MAC changers, VPN switchers,
    // and proxy configuration files in cheat-related directories.
    private void CheckNetworkEvasionTools(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"C:\Tools", @"C:\Hack", @"C:\Cheats",
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanForNetworkEvasionTools(ctx, root, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanForNetworkEvasionTools(ScanContext ctx, string directory,
        CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();

            foreach (var netTool in NetworkEvasionExecutables)
            {
                if (fileName.Equals(netTool, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Network fingerprint evasion tool: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"The file '{System.IO.Path.GetFileName(file)}' matches a known network " +
                                   "fingerprint evasion tool. These tools change IP addresses, cycle MAC " +
                                   "addresses, or rotate proxy/VPN connections to defeat IP ban systems " +
                                   "and geo-restriction checks used by some anti-cheat platforms. They " +
                                   "are typically used in combination with HWID spoofers and new accounts " +
                                   "to complete a ban evasion setup.",
                        Detail   = $"Tool: {netTool} | Path: {file}"
                    });
                    break;
                }
            }

            // Check for proxy list files in directories that also contain cheat tools
            foreach (var proxyFile in ProxyConfigFileNames)
            {
                if (fileName.Equals(proxyFile, StringComparison.OrdinalIgnoreCase))
                {
                    var dirName = System.IO.Path.GetFileName(directory).ToLowerInvariant();
                    var isCheatDir = CheatToolSubDirs.Any(kw =>
                        dirName.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (isCheatDir)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Proxy list file in cheat-related directory: {System.IO.Path.GetFileName(file)}",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = System.IO.Path.GetFileName(file),
                            Reason   = $"The file '{System.IO.Path.GetFileName(file)}' is a proxy configuration " +
                                       $"list found inside the directory '{System.IO.Path.GetFileName(directory)}', " +
                                       "which has a name associated with cheat or hacking tools. Residential " +
                                       "proxy lists stored alongside cheat software are used to rotate IP " +
                                       "addresses through anti-cheat geo-restriction and IP ban systems.",
                            Detail   = $"Proxy file: {proxyFile} | Directory: {directory}"
                        });
                    }
                    break;
                }
            }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanForNetworkEvasionTools(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Scans WireGuard and OpenVPN configuration files in user directories for
    // game-cheat-related comments, indicating VPN use specifically for AC bypass.
    private void ScanVpnConfigsForCheatUse(ScanContext ctx, CancellationToken ct)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var vpnConfigRoots = new[]
        {
            System.IO.Path.Combine(userProfile, "WireGuard"),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WireGuard"),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard"),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OpenVPN"),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OpenVPN Connect"),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OpenVPN", "config"),
            System.IO.Path.Combine(userProfile, ".config", "wireguard"),
        };

        foreach (var vpnRoot in vpnConfigRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(vpnRoot)) continue;
            try
            {
                ScanVpnDirectory(ctx, vpnRoot, ct, maxDepth: 2);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanVpnDirectory(ScanContext ctx, string directory, CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            var ext = System.IO.Path.GetExtension(file).ToLowerInvariant();
            if (ext is not ".conf" and not ".ovpn" and not ".cfg") continue;

            ctx.IncrementFiles();
            try
            {
                string content;
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = sr.ReadToEnd();

                if (GameCheatCommentRegex.IsMatch(content))
                {
                    var match = GameCheatCommentRegex.Match(content);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"VPN config references game/cheat bypass: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"The VPN configuration file '{System.IO.Path.GetFileName(file)}' contains " +
                                   $"a comment referencing '{match.Value.Trim()}'. VPN configuration files " +
                                   "with game or cheat-related comments indicate the VPN tunnel is " +
                                   "specifically configured for anti-cheat geo-check bypass or IP ban " +
                                   "evasion, rather than for general privacy purposes.",
                        Detail   = $"Matched comment: {match.Value.Trim()} | Config: {file}"
                    });
                }
            }
            catch (IOException) { }
            catch { }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanVpnDirectory(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Checks for mouse movement injection and human-mouse simulation tools used
    // to evade mouse-movement behaviour analysis by anti-cheat systems.
    private void CheckMouseEvasionTools(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"C:\Tools", @"C:\Cheats", @"C:\Hack",
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanForMouseEvasionTools(ctx, root, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanForMouseEvasionTools(ScanContext ctx, string directory,
        CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();

            foreach (var mouseTool in MouseEvasionExecutables)
            {
                if (fileName.Equals(mouseTool, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Mouse movement evasion tool: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"The file '{System.IO.Path.GetFileName(file)}' matches a known mouse " +
                                   "movement injection or humanisation tool. Anti-cheat systems analyse " +
                                   "mouse movement patterns to detect aim assistance software; these tools " +
                                   "inject artificial human-like mouse movements or add randomised jitter " +
                                   "to aimbot outputs to defeat this behavioural detection method.",
                        Detail   = $"Tool: {mouseTool} | Path: {file}"
                    });
                    break;
                }
            }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanForMouseEvasionTools(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Checks for keyboard timing randomiser tools used to evade keystroke-timing
    // fingerprinting by anti-cheat systems.
    private void CheckKeyboardEvasionTools(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"C:\Tools", @"C:\Cheats", @"C:\Hack",
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanForKeyboardEvasionTools(ctx, root, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanForKeyboardEvasionTools(ScanContext ctx, string directory,
        CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();

            foreach (var kbTool in KeyboardEvasionExecutables)
            {
                if (fileName.Equals(kbTool, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Keyboard timing evasion tool: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"The file '{System.IO.Path.GetFileName(file)}' matches a known keyboard " +
                                   "timing randomiser or delay injection tool. Some advanced anti-cheat " +
                                   "systems build a keystroke timing fingerprint of the player to detect " +
                                   "scripted macro input or to track players across accounts; these tools " +
                                   "randomise inter-keystroke timing to defeat this analysis.",
                        Detail   = $"Tool: {kbTool} | Path: {file}"
                    });
                    break;
                }
            }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanForKeyboardEvasionTools(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Scans common cheat tool directories (C:\Cheats, Downloads subfolders named
    // "cheat"/"hack"/etc.) for any of the evasion tool categories above.
    private void ScanCheatDirectoriesForEvasionTools(ScanContext ctx, CancellationToken ct)
    {
        var allEvasionTools = MemoryEvasionExecutables
            .Concat(SteamBypassExecutables)
            .Concat(NetworkEvasionExecutables)
            .Concat(MouseEvasionExecutables)
            .Concat(KeyboardEvasionExecutables)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var downloads = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        var suspiciousRoots = new List<string>();
        suspiciousRoots.AddRange(new[] { @"C:\Cheats", @"C:\Hack", @"C:\Hacks",
            @"C:\Tools", @"C:\Loaders", @"C:\Injectors", @"C:\Spoofers" });

        // Also add any cheat-keyword-named subdirectories of Downloads
        if (Directory.Exists(downloads))
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(downloads))
                {
                    var dirName = System.IO.Path.GetFileName(dir).ToLowerInvariant();
                    if (CheatToolSubDirs.Any(kw => dirName.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                        suspiciousRoots.Add(dir);
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }

        foreach (var root in suspiciousRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanCheatDirRecursive(ctx, root, allEvasionTools, ct, maxDepth: 4);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanCheatDirRecursive(ScanContext ctx, string directory,
        HashSet<string> evasionTools, CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file);

            if (evasionTools.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Fingerprint evasion tool in cheat directory: {fileName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"The fingerprint evasion tool '{fileName}' was found in a directory " +
                               $"'{System.IO.Path.GetFileName(directory)}' that is named after or contains " +
                               "cheat/hack tools. The co-location of a fingerprint evasion tool with " +
                               "a cheat toolset is strong evidence that the tool is being used as part " +
                               "of a coordinated anti-cheat bypass setup.",
                    Detail   = $"Tool: {fileName} | Cheat directory: {directory}"
                });
            }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanCheatDirRecursive(ctx, sub, evasionTools, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }
}
