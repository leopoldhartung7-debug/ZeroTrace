using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RageMpPacketSpoofScanModule : IScanModule
{
    public string Name => "RageMP Packet Spoofing Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);

    private static readonly string[] RageMpRoots;

    static RageMpPacketSpoofScanModule()
    {
        var roots = new List<string>
        {
            Path.Combine(LocalApp, "RAGEMP"),
            Path.Combine(AppData, "RAGEMP"),
            Path.Combine(LocalApp, "RageMP"),
            Path.Combine(AppData, "RageMP"),
            Path.Combine(LocalApp, "rage-mp"),
            Path.Combine(AppData, "rage-mp"),
            // Common Steam library locations
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "RAGEMP"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RAGEMP"),
        };
        RageMpRoots = roots.ToArray();
    }

    // Known packet spoof / manipulation EXE and DLL names (40+)
    private static readonly string[] KnownSpoofFileNames =
    {
        "packet_spoofer.exe",
        "packet_spoofer.dll",
        "ragemp_packet.exe",
        "ragemp_packet.dll",
        "packet_inject.dll",
        "packet_inject.exe",
        "packetinjector.dll",
        "packetinjector.exe",
        "packet_hook.dll",
        "packet_hook.exe",
        "packetsend.exe",
        "packetsend.dll",
        "packetmanip.exe",
        "packetmanip.dll",
        "packet_editor.exe",
        "packet_editor.dll",
        "packet_modifier.exe",
        "packet_modifier.dll",
        "netspoof.exe",
        "netspoof.dll",
        "netpatch.exe",
        "netpatch.dll",
        "net_inject.dll",
        "net_inject.exe",
        "ragepacket.dll",
        "ragepacket.exe",
        "rage_packet.dll",
        "rage_packet.exe",
        "mp_packet.dll",
        "mp_packet.exe",
        "gta_packet.dll",
        "gta_packet.exe",
        "send_packet.exe",
        "send_packet.dll",
        "intercept_packet.dll",
        "intercept_packet.exe",
        "packet_bypass.dll",
        "packet_bypass.exe",
        "packet_spoof_v2.dll",
        "packet_spoof_v2.exe",
        "pspoof.exe",
        "pspoof.dll",
        "rage_injector.dll",
        "rage_injector.exe",
        "ragemp_inject.dll",
        "ragemp_inject.exe",
        "wsock_hook.dll",
        "winsock_hook.dll",
        "ws2_hook.dll",
    };

    // Known cheat / hack package directory names (20+)
    private static readonly string[] MaliciousPackageDirNames =
    {
        "packet_hack",
        "speed_hack",
        "teleport_hack",
        "aimbot_package",
        "esp_package",
        "radar_package",
        "wallhack_package",
        "godmode_package",
        "noclip_package",
        "vehicle_hack",
        "weapon_hack",
        "money_hack",
        "player_hack",
        "anti_kick",
        "crash_package",
        "spinbot_package",
        "triggerbot_package",
        "bhop_package",
        "norecoil_package",
        "freecam_package",
        "invisibility_package",
        "bypass_package",
        "inject_package",
        "exploit_package",
        "cheat_package",
        "hack_package",
        "rage_cheat",
        "rage_hack",
        "rage_exploit",
        "griefer_pack",
    };

    // Proxy / hijack DLLs that should not exist in the RageMP directory
    private static readonly string[] ProxyDllNames =
    {
        "dinput8.dll",
        "version.dll",
        "d3d11.dll",
        "d3d9.dll",
        "d3d10.dll",
        "dxgi.dll",
        "winmm.dll",
        "winhttp.dll",
        "dsound.dll",
        "opengl32.dll",
        "ws2_32.dll",
        "msacm32.dll",
        "xinput1_3.dll",
        "xinput9_1_0.dll",
        "steam_api64.dll",
        "tier0.dll",
    };

    // JavaScript client_packages patterns for packet manipulation (25+)
    private static readonly string[] JsPacketPatterns =
    {
        // Direct packet interception / sending
        "sendPacket(",
        "interceptPacket(",
        "injectPacket(",
        "modifyPacket(",
        "spoofPacket(",
        "fakePacket(",
        "packetSend(",
        "packetInject(",
        "rawPacket(",
        "sendRaw(",
        // mp.events network manipulation
        "mp.events.add(\"packetReceive",
        "mp.events.add(\"packetSend",
        "mp.events.add('packetReceive",
        "mp.events.add('packetSend",
        "mp.events.addCommand(",
        // mp.game.invoke packet-related natives
        "mp.game.invoke(",
        "NETWORK_SESSION_KICK_PLAYER(",
        "NETWORK_SESSION_FORCE_CANCEL_SESSION(",
        "NETWORK_SESSION_HOST(",
        // WebSocket packet spoofing
        "new WebSocket(",
        "ws.send(",
        "socket.send(",
        "socket.emit(",
        // UDP/TCP manipulation via net module
        "require('net')",
        "require(\"net\")",
        "net.createSocket(",
        "dgram.createSocket(",
        // eval-based obfuscation
        "eval(atob(",
        "eval(Buffer.from(",
        "Function(atob(",
        // Process memory access
        "process.binding(",
        "process._rawDebug(",
        // Known RAGEMP cheat API patterns
        "mp.players.forEach(",
        "mp.vehicles.new(",
        "mp.game.player.id(",
        "entity.setVariable(",
        "entity.getVariable(",
    };

    // Config file keywords indicating packet manipulation
    private static readonly string[] ConfigCheatKeywords =
    {
        "packet_hook",
        "packet_inject",
        "packet_spoof",
        "bypass_packet",
        "fake_packet",
        "raw_socket",
        "inject_dll",
        "debug_mode",
        "no_verify",
        "skip_verify",
        "disable_anticheat",
        "disable_banning",
        "packet_rate",
        "flood_packets",
        "desync",
    };

    // BepInEx / Harmony injector artifact file names
    private static readonly string[] InjectorArtifacts =
    {
        "BepInEx.dll",
        "BepInEx.Core.dll",
        "0Harmony.dll",
        "Harmony.dll",
        "HarmonyLib.dll",
        "MonoMod.dll",
        "MonoMod.RuntimeDetour.dll",
        "MonoMod.Utils.dll",
        "Doorstop.dll",
        "doorstop_config.ini",
        "winhttp.dll",   // BepInEx uses this as its bootstrap
        "BepInEx.cfg",
        "BepInEx\\core",
        "BepInEx\\plugins",
        "BepInEx\\patchers",
    };

    // CEF / WebSocket packet interception HTML patterns
    private static readonly string[] CefHtmlPacketPatterns =
    {
        "new WebSocket(",
        "ws.onmessage",
        "ws.send(",
        "socket.onmessage",
        "socket.send(",
        "interceptPacket",
        "sendPacket",
        "packetData",
        "packetBuffer",
        "rawPacket",
        "packet.intercept",
        "hookPacket",
        "overridePacket",
        "spoofPosition",
        "fakeCoords",
        "serverSpoof",
        "positionOverride",
        "velocityOverride",
        "healthOverride",
        "armorOverride",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>();

        foreach (var root in RageMpRoots)
        {
            if (!Directory.Exists(root)) continue;

            tasks.Add(CheckKnownSpoofFiles(ctx, root, ct));
            tasks.Add(CheckClientPackagesJs(ctx, root, ct));
            tasks.Add(CheckRageMpExeIntegrity(ctx, root, ct));
            tasks.Add(CheckConfigFiles(ctx, root, ct));
            tasks.Add(CheckProxyDlls(ctx, root, ct));
            tasks.Add(CheckMaliciousPackageDirs(ctx, root, ct));
            tasks.Add(CheckInjectorArtifacts(ctx, root, ct));
            tasks.Add(CheckUpdaterReplacement(ctx, root, ct));
            tasks.Add(CheckCefHtmlFiles(ctx, root, ct));
        }

        if (tasks.Count == 0)
        {
            ctx.Report(1.0, Name, "RageMP installation not found");
            return;
        }

        await Task.WhenAll(tasks);
        ctx.Report(1.0, Name, "RageMP packet spoofing scan complete");
    }

    private Task CheckKnownSpoofFiles(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            // Search recursively for known spoof tool file names
            try
            {
                foreach (var dir in EnumerateDirectoriesSafe(root, ct))
                {
                    ct.ThrowIfCancellationRequested();

                    string[] files;
                    try { files = Directory.GetFiles(dir); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in files)
                    {
                        ct.ThrowIfCancellationRequested();
                        var fileName = Path.GetFileName(file);

                        var matchedName = KnownSpoofFileNames.FirstOrDefault(n =>
                            string.Equals(n, fileName, StringComparison.OrdinalIgnoreCase));

                        if (matchedName is null)
                        {
                            // Check keyword heuristics for unmatched filenames
                            var lower = fileName.ToLowerInvariant();
                            bool hasPacketKeyword = lower.Contains("packet") || lower.Contains("spoof") ||
                                                    lower.Contains("inject") || lower.Contains("hook");
                            bool isExecutable = lower.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                                                lower.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);

                            if (!hasPacketKeyword || !isExecutable) continue;
                        }

                        ctx.IncrementFiles();

                        FileInfo fi;
                        try { fi = new FileInfo(file); }
                        catch (IOException) { continue; }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = matchedName is not null
                                ? $"Known Packet Spoof Tool: {fileName}"
                                : $"Suspected Packet Manipulation Tool: {fileName}",
                            Risk = matchedName is not null ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = matchedName is not null
                                ? $"File '{fileName}' matches a known RageMP packet spoofing/injection tool name. " +
                                  "These tools intercept and manipulate game network packets to spoof player position, " +
                                  "health, vehicle state, or other synchronized game data."
                                : $"File '{fileName}' in RageMP directory matches packet manipulation keyword heuristic. " +
                                  "Files with 'packet', 'spoof', 'inject', or 'hook' in their name in game directories " +
                                  "are strongly associated with network manipulation tools.",
                            Detail = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTimeUtc:u} | Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckClientPackagesJs(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Path.Combine(root, "client_packages"),
                Path.Combine(root, "packages"),
                Path.Combine(root, "dotnet", "packages"),
                Path.Combine(root, "resources"),
            };

            foreach (var searchDir in searchDirs)
            {
                if (!Directory.Exists(searchDir)) continue;

                var jsFiles = new List<string>();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(searchDir, "*.js", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        jsFiles.Add(file);
                    }
                }
                catch (UnauthorizedAccessException) { }

                foreach (var jsFile in jsFiles)
                {
                    ct.ThrowIfCancellationRequested();

                    string content;
                    try
                    {
                        var fi = new FileInfo(jsFile);
                        if (fi.Length > 2 * 1024 * 1024) continue;
                        using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    ctx.IncrementFiles();

                    var matchedPatterns = new List<string>();
                    foreach (var pattern in JsPacketPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            matchedPatterns.Add(pattern);
                    }

                    if (matchedPatterns.Count == 0) continue;

                    var risk = matchedPatterns.Count >= 5 ? RiskLevel.Critical
                             : matchedPatterns.Count >= 3 ? RiskLevel.High
                             : RiskLevel.Medium;

                    // Escalate if direct packet send/intercept patterns present
                    if (matchedPatterns.Any(p =>
                        p.Contains("sendPacket", StringComparison.OrdinalIgnoreCase) ||
                        p.Contains("interceptPacket", StringComparison.OrdinalIgnoreCase) ||
                        p.Contains("injectPacket", StringComparison.OrdinalIgnoreCase) ||
                        p.Contains("spoofPacket", StringComparison.OrdinalIgnoreCase)))
                    {
                        risk = RiskLevel.Critical;
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Packet Manipulation JS: {Path.GetFileName(jsFile)}",
                        Risk = risk,
                        Location = jsFile,
                        FileName = Path.GetFileName(jsFile),
                        Reason = $"RageMP client_packages JavaScript file contains {matchedPatterns.Count} packet manipulation pattern(s): " +
                                 string.Join(", ", matchedPatterns.Take(5).Select(p => $"'{p}'")) +
                                 (matchedPatterns.Count > 5 ? " ..." : "") +
                                 ". These patterns indicate packet interception, spoofing, or injection " +
                                 "capabilities through the RageMP JS scripting environment.",
                        Detail = $"Matched ({matchedPatterns.Count}): {string.Join(", ", matchedPatterns.Take(8))}"
                    });
                }
            }
        }, ct);
    }

    private Task CheckRageMpExeIntegrity(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            // Known ragemp.exe size ranges for different versions
            // These are approximate ranges; significant deviation is flagged
            var exeChecks = new[]
            {
                ("ragemp.exe",    5 * 1024 * 1024L,   80 * 1024 * 1024L),
                ("ragemp-v2.exe", 5 * 1024 * 1024L,   80 * 1024 * 1024L),
                ("PlayGTAV.exe",  100 * 1024L,          5 * 1024 * 1024L),
            };

            foreach (var (exeName, minSize, maxSize) in exeChecks)
            {
                ct.ThrowIfCancellationRequested();

                var fullPath = Path.Combine(root, exeName);
                if (!File.Exists(fullPath)) continue;

                FileInfo fi;
                try { fi = new FileInfo(fullPath); }
                catch (IOException) { continue; }

                ctx.IncrementFiles();

                if (fi.Length < minSize)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Executable Abnormally Small: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = fullPath,
                        FileName = exeName,
                        Reason = $"RageMP executable '{exeName}' is abnormally small ({fi.Length:N0} bytes, expected at least {minSize:N0} bytes). " +
                                 "Cheat-modified clients often replace the legitimate executable with a thin stub or proxy " +
                                 "that loads the actual cheat payload from a separate DLL.",
                        Detail = $"Actual: {fi.Length} bytes | Min expected: {minSize} bytes | Modified: {fi.LastWriteTimeUtc:u}"
                    });
                }
                else if (fi.Length > maxSize)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Executable Abnormally Large: {exeName}",
                        Risk = RiskLevel.High,
                        Location = fullPath,
                        FileName = exeName,
                        Reason = $"RageMP executable '{exeName}' is abnormally large ({fi.Length:N0} bytes, expected under {maxSize:N0} bytes). " +
                                 "Cheat code or an embedded payload may have been appended to or embedded within the binary.",
                        Detail = $"Actual: {fi.Length} bytes | Max expected: {maxSize} bytes | Modified: {fi.LastWriteTimeUtc:u}"
                    });
                }

                // Check for suspicious modification time anomalies
                var age = DateTime.UtcNow - fi.LastWriteTimeUtc;
                if (age.TotalMinutes < 60)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Executable Very Recently Modified: {exeName}",
                        Risk = RiskLevel.High,
                        Location = fullPath,
                        FileName = exeName,
                        Reason = $"RageMP executable '{exeName}' was modified only {age.TotalMinutes:F0} minutes ago. " +
                                 "Recent modification of game executables outside of known update windows " +
                                 "may indicate runtime patching by a cheat loader.",
                        Detail = $"Modified: {fi.LastWriteTimeUtc:u} | Age: {age.TotalMinutes:F0} min"
                    });
                }
            }
        }, ct);
    }

    private Task CheckConfigFiles(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var configFiles = new List<string>();

            // Search for config files in root and one level deep
            try
            {
                foreach (var file in Directory.GetFiles(root, "*.xml"))
                    configFiles.Add(file);
                foreach (var file in Directory.GetFiles(root, "*.json"))
                    configFiles.Add(file);
                foreach (var file in Directory.GetFiles(root, "*.cfg"))
                    configFiles.Add(file);
                foreach (var file in Directory.GetFiles(root, "*.ini"))
                    configFiles.Add(file);
            }
            catch (UnauthorizedAccessException) { }

            foreach (var subdir in EnumerateDirectoriesSafe(root, ct))
            {
                try
                {
                    foreach (var file in Directory.GetFiles(subdir, "config.*"))
                        configFiles.Add(file);
                    foreach (var file in Directory.GetFiles(subdir, "settings.*"))
                        configFiles.Add(file);
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            foreach (var configFile in configFiles)
            {
                ct.ThrowIfCancellationRequested();

                string content;
                try
                {
                    var fi = new FileInfo(configFile);
                    if (fi.Length > 512 * 1024) continue;
                    using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();

                var matchedKeywords = new List<string>();
                foreach (var keyword in ConfigCheatKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        matchedKeywords.Add(keyword);
                }

                if (matchedKeywords.Count == 0) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RageMP Config with Packet Manipulation Keywords: {Path.GetFileName(configFile)}",
                    Risk = RiskLevel.High,
                    Location = configFile,
                    FileName = Path.GetFileName(configFile),
                    Reason = $"RageMP configuration file '{Path.GetFileName(configFile)}' contains {matchedKeywords.Count} keyword(s) associated with packet manipulation: " +
                             string.Join(", ", matchedKeywords.Select(k => $"'{k}'")) +
                             ". These settings may enable packet hooking, injection bypass, or anti-cheat disabling.",
                    Detail = $"Matched keywords: {string.Join(", ", matchedKeywords)}"
                });
            }
        }, ct);
    }

    private Task CheckProxyDlls(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (var proxyName in ProxyDllNames)
            {
                ct.ThrowIfCancellationRequested();

                var fullPath = Path.Combine(root, proxyName);
                if (!File.Exists(fullPath)) continue;

                FileInfo fi;
                try { fi = new FileInfo(fullPath); }
                catch (IOException) { continue; }

                ctx.IncrementFiles();

                var isSmall = fi.Length < 128 * 1024;
                var risk = isSmall ? RiskLevel.Critical : RiskLevel.High;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspected Proxy DLL in RageMP Root: {proxyName}",
                    Risk = risk,
                    Location = fullPath,
                    FileName = proxyName,
                    Reason = $"Known proxy/hijack DLL name '{proxyName}' found in RageMP root directory. " +
                             (isSmall ? $"File size ({fi.Length} bytes) is abnormally small, consistent with a thin proxy wrapper. " : "") +
                             "Proxy DLLs intercept calls to legitimate Windows system libraries, " +
                             "allowing cheat code to execute before the real DLL handles the call. " +
                             "This is a classic DLL hijacking technique for packet interception via ws2_32/winhttp.",
                    Detail = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTimeUtc:u} | Path: {fullPath}"
                });
            }
        }, ct);
    }

    private Task CheckMaliciousPackageDirs(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var packagesDir = Path.Combine(root, "client_packages");
            if (!Directory.Exists(packagesDir))
                packagesDir = Path.Combine(root, "packages");
            if (!Directory.Exists(packagesDir)) return;

            string[] topDirs;
            try { topDirs = Directory.GetDirectories(packagesDir); }
            catch (UnauthorizedAccessException) { return; }

            foreach (var dir in topDirs)
            {
                ct.ThrowIfCancellationRequested();

                var dirName = Path.GetFileName(dir);

                var exactMatch = MaliciousPackageDirNames.FirstOrDefault(n =>
                    string.Equals(n, dirName, StringComparison.OrdinalIgnoreCase));

                if (exactMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known Cheat Package Directory: {dirName}",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = dirName,
                        Reason = $"RageMP client_packages directory '{dirName}' matches a known cheat package name. " +
                                 "These packages are distributed by cheat providers and implement packet spoofing, " +
                                 "speed hacks, teleport hacks, and other game manipulation techniques via the " +
                                 "RageMP JavaScript scripting API.",
                        Detail = $"Matched known name: '{exactMatch}' | Path: {dir}"
                    });
                    continue;
                }

                // Keyword heuristic for unmatched names
                var cheatKeywords = new[]
                {
                    "packet", "spoof", "hack", "cheat", "inject", "exploit",
                    "bypass", "aimbot", "wallhack", "esp", "radar",
                    "teleport", "speedhack", "godmode", "noclip", "triggerbot",
                    "spinbot", "bhop", "norecoil", "freecam", "grief",
                };

                var keyword = cheatKeywords.FirstOrDefault(k =>
                    dirName.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (keyword is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious RageMP Package Directory: {dirName}",
                        Risk = RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason = $"RageMP client_packages directory '{dirName}' contains cheat-related keyword '{keyword}'. " +
                                 "Package directory names are chosen by cheat developers and often reflect their functionality.",
                        Detail = $"Keyword: '{keyword}' | Path: {dir}"
                    });
                }
            }
        }, ct);
    }

    private Task CheckInjectorArtifacts(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            // Check for BepInEx / Harmony artifacts in RageMP directory tree
            foreach (var artifactPath in InjectorArtifacts)
            {
                ct.ThrowIfCancellationRequested();

                var fullPath = Path.Combine(root, artifactPath);
                bool exists = artifactPath.Contains("\\") || artifactPath.Contains("/")
                    ? Directory.Exists(fullPath) || File.Exists(fullPath)
                    : File.Exists(fullPath);

                if (!exists) continue;

                bool isDir = Directory.Exists(fullPath);
                if (!isDir) ctx.IncrementFiles();

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"BepInEx/Harmony Injector Artifact in RageMP: {Path.GetFileName(artifactPath)}",
                    Risk = RiskLevel.Critical,
                    Location = fullPath,
                    FileName = Path.GetFileName(artifactPath),
                    Reason = $"BepInEx or Harmony framework artifact '{Path.GetFileName(artifactPath)}' found in RageMP directory. " +
                             "BepInEx and Harmony are .NET runtime patching frameworks frequently used by cheat developers " +
                             "to inject arbitrary code into RageMP's .NET runtime. " +
                             "These frameworks can intercept game method calls, modify packet construction/parsing functions, " +
                             "and bypass anti-cheat integrity checks at the .NET IL level.",
                    Detail = $"Artifact: {artifactPath} | Full path: {fullPath} | Is directory: {isDir}"
                });
            }

            // Also scan for Harmony/BepInEx DLLs anywhere in the RageMP tree
            try
            {
                foreach (var dir in EnumerateDirectoriesSafe(root, ct))
                {
                    ct.ThrowIfCancellationRequested();

                    string[] dllFiles;
                    try { dllFiles = Directory.GetFiles(dir, "*.dll"); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var dll in dllFiles)
                    {
                        var fn = Path.GetFileName(dll);
                        bool isInjector =
                            fn.Equals("0Harmony.dll", StringComparison.OrdinalIgnoreCase) ||
                            fn.Equals("HarmonyLib.dll", StringComparison.OrdinalIgnoreCase) ||
                            fn.Equals("MonoMod.dll", StringComparison.OrdinalIgnoreCase) ||
                            fn.Equals("MonoMod.RuntimeDetour.dll", StringComparison.OrdinalIgnoreCase) ||
                            fn.StartsWith("BepInEx", StringComparison.OrdinalIgnoreCase);

                        if (!isInjector) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Harmony/BepInEx Injector DLL in RageMP: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = dll,
                            FileName = fn,
                            Reason = $"Harmony or BepInEx injector library '{fn}' found within RageMP directory tree. " +
                                     "These libraries enable runtime patching of .NET methods and are used by cheats " +
                                     "to hook packet processing, spoofing outbound network data sent to RageMP servers.",
                            Detail = $"Path: {dll}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckUpdaterReplacement(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            // RageMP updater.exe is a small launcher; if replaced with something large it's suspicious
            var updaterPath = Path.Combine(root, "updater.exe");
            if (!File.Exists(updaterPath)) return;

            FileInfo fi;
            try { fi = new FileInfo(updaterPath); }
            catch (IOException) { return; }

            ctx.IncrementFiles();

            // Official RageMP updater is typically 200KB - 3MB
            const long minLegitSize = 200 * 1024L;
            const long maxLegitSize = 5 * 1024 * 1024L;

            if (fi.Length < minLegitSize)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RageMP Updater Replaced with Small Stub",
                    Risk = RiskLevel.Critical,
                    Location = updaterPath,
                    FileName = "updater.exe",
                    Reason = $"RageMP updater.exe is abnormally small ({fi.Length:N0} bytes, expected {minLegitSize:N0}–{maxLegitSize:N0} bytes). " +
                             "Cheat loaders replace the legitimate updater with a stub that launches the cheat payload " +
                             "while appearing to be a routine game launcher.",
                    Detail = $"Actual: {fi.Length} bytes | Min expected: {minLegitSize} bytes | Modified: {fi.LastWriteTimeUtc:u}"
                });
            }
            else if (fi.Length > maxLegitSize)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RageMP Updater Unusually Large — Possible Bundled Payload",
                    Risk = RiskLevel.High,
                    Location = updaterPath,
                    FileName = "updater.exe",
                    Reason = $"RageMP updater.exe is unusually large ({fi.Length:N0} bytes, expected under {maxLegitSize:N0} bytes). " +
                             "Cheat loaders may embed their payload within a modified updater binary, " +
                             "using the legitimate update flow as cover for cheat code execution.",
                    Detail = $"Actual: {fi.Length} bytes | Max expected: {maxLegitSize} bytes | Modified: {fi.LastWriteTimeUtc:u}"
                });
            }

            // Check modification time — updater should not have been recently modified without an update
            var age = DateTime.UtcNow - fi.LastWriteTimeUtc;
            var versionFile = Path.Combine(root, "version.txt");
            var changelogFile = Path.Combine(root, "CHANGELOG.txt");
            bool hasUpdateArtifact = File.Exists(versionFile) || File.Exists(changelogFile);

            if (age.TotalHours < 24 && !hasUpdateArtifact)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RageMP Updater Recently Modified Without Version Artifact",
                    Risk = RiskLevel.High,
                    Location = updaterPath,
                    FileName = "updater.exe",
                    Reason = $"RageMP updater.exe was modified {age.TotalHours:F1} hours ago but no version.txt or " +
                             "CHANGELOG.txt exists to confirm a legitimate update. " +
                             "This pattern is consistent with cheat tools silently replacing the updater executable.",
                    Detail = $"Modified: {fi.LastWriteTimeUtc:u} | Age: {age.TotalHours:F1}h | No version artifact found"
                });
            }
        }, ct);
    }

    private Task CheckCefHtmlFiles(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            // RageMP uses CEF for its UI overlay; scan HTML files in the UI directory
            var uiDirs = new[]
            {
                Path.Combine(root, "client_packages", "browser"),
                Path.Combine(root, "client_packages", "ui"),
                Path.Combine(root, "client_packages", "html"),
                Path.Combine(root, "ui"),
                Path.Combine(root, "cef"),
                Path.Combine(root, "browser"),
            };

            var htmlFiles = new List<string>();
            foreach (var uiDir in uiDirs)
            {
                if (!Directory.Exists(uiDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(uiDir, "*.html", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        htmlFiles.Add(file);
                    }
                    foreach (var file in Directory.EnumerateFiles(uiDir, "*.htm", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        htmlFiles.Add(file);
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Also check top-level client_packages for HTML
            var clientPackages = Path.Combine(root, "client_packages");
            if (Directory.Exists(clientPackages))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(clientPackages, "*.html", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!htmlFiles.Contains(file)) htmlFiles.Add(file);
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            foreach (var htmlFile in htmlFiles)
            {
                ct.ThrowIfCancellationRequested();

                string content;
                try
                {
                    var fi = new FileInfo(htmlFile);
                    if (fi.Length > 1024 * 1024) continue;
                    using var fs = new FileStream(htmlFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();

                var matchedPatterns = new List<string>();
                foreach (var pattern in CefHtmlPacketPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        matchedPatterns.Add(pattern);
                }

                if (matchedPatterns.Count == 0) continue;

                // Escalate if WebSocket packet manipulation is directly referenced
                bool hasCriticalPattern =
                    matchedPatterns.Any(p =>
                        p.Contains("interceptPacket", StringComparison.OrdinalIgnoreCase) ||
                        p.Contains("sendPacket", StringComparison.OrdinalIgnoreCase) ||
                        p.Contains("hookPacket", StringComparison.OrdinalIgnoreCase) ||
                        p.Contains("overridePacket", StringComparison.OrdinalIgnoreCase) ||
                        p.Contains("spoofPosition", StringComparison.OrdinalIgnoreCase));

                var risk = hasCriticalPattern ? RiskLevel.Critical
                         : matchedPatterns.Count >= 3 ? RiskLevel.High
                         : RiskLevel.Medium;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RageMP CEF HTML with WebSocket Packet Interception: {Path.GetFileName(htmlFile)}",
                    Risk = risk,
                    Location = htmlFile,
                    FileName = Path.GetFileName(htmlFile),
                    Reason = $"RageMP UI HTML file '{Path.GetFileName(htmlFile)}' contains {matchedPatterns.Count} WebSocket/packet interception pattern(s): " +
                             string.Join(", ", matchedPatterns.Take(5).Select(p => $"'{p}'")) +
                             (matchedPatterns.Count > 5 ? " ..." : "") +
                             ". RageMP's CEF browser overlay can use WebSockets to communicate with the game client; " +
                             "these patterns indicate the UI is being used as a conduit for packet manipulation.",
                    Detail = $"Matched ({matchedPatterns.Count}): {string.Join(", ", matchedPatterns.Take(8))}"
                });
            }
        }, ct);
    }

    private static IEnumerable<string> EnumerateDirectoriesSafe(string root, CancellationToken ct)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) yield break;
            var dir = stack.Pop();
            yield return dir;

            string[] subs;
            try { subs = Directory.GetDirectories(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var sub in subs)
                stack.Push(sub);
        }
    }
}
