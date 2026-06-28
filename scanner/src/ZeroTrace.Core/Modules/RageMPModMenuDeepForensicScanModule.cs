using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class RageMPModMenuDeepForensicScanModule : IScanModule
{
    public string Name => "RageMP Mod Menu Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] RageMPPaths = { @"RAGEMP", @"RAGE Multiplayer" };
    private static readonly string[] CheatDLLPatterns = { "cheat.dll", "rage_cheat.dll", "ragemp_hack.dll", "bypass.dll", "loader.dll", "inject.dll", "internal.dll", "hack.dll" };
    private static readonly string[] CheatExecutablePatterns = { "ragemp_crash.exe", "mp_crash.exe", "crash_mp.exe", "entity_spam.exe", "flood_mp.exe", "ragemp_antiban.exe", "rage_spoofer.exe", "hwid_bypass.exe", "rage_cleaner.exe" };
    private static readonly string[] JSCheatKeywords = { "nativeInvoke", "SetEntityInvincible", "GiveWeaponToPed", "SetEntityCoords", "eval(", "atob(", "Function(", "discord.com/api/webhooks/", "XMLHttpRequest" };
    private static readonly string[] MoneyExploitKeywords = { "giveJobPoints", "giveItems", "addMoney", "setBalance", "giveMoney", "addBank" };
    private static readonly string[] MenuRegistryKeys = { @"Software\RAGEMP", @"Software\YimMenuRageMP", @"Software\Bubba", @"Software\RageMPCheat" };
    private static readonly string[] NativeHashPattern = { "0x", "native_hash", "natives.json", "ragemp_natives.json", "native_list" };

    private static readonly string[] AdditionalCheatDLLNames = { "external.dll", "aimbot.dll", "esp.dll", "wallhack.dll", "noclip.dll", "speedhack.dll", "radar.dll", "triggerbot.dll" };
    private static readonly string[] VehicleSpawnPatterns = { "mp.vehicles.new", "spawnVehicle", "createVehicle", "vehicleSpawn", "spawnFlood" };
    private static readonly string[] LogCheatPatterns = { "anticheat", "ac_detected", "detection", "bypass", "cheat loaded", "injected", "noclip", "godmode", "banned", "kicked by ac" };
    private static readonly string[] BridgeExploitPatterns = { "require('rage-module')", "mp.invoke", "callNative", "bridge.dll", "rage-bridge.dll", "native_invoker" };
    private static readonly string[] WebhookPatterns = { "discord.com/api/webhooks/", "discordapp.com/api/webhooks/" };
    private static readonly string[] CrashToolPatterns = { "ragemp_crash", "mp_crash", "crash_mp", "entity_spam", "flood_mp", "mp.events.callRemote('crash'", "mp.vehicles.new" };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckRageMPCheatDLLArtifacts(ctx, ct),
            CheckRageMPClientPackageCheatArtifacts(ctx, ct),
            CheckRageMPBridgeExploitArtifacts(ctx, ct),
            CheckRageMPYimMenuArtifacts(ctx, ct),
            CheckRageMPBubbaMenuArtifacts(ctx, ct),
            CheckRageMPScriptInjectionArtifacts(ctx, ct),
            CheckRageMPCrashToolArtifacts(ctx, ct),
            CheckRageMPMoneyExploitArtifacts(ctx, ct),
            CheckRageMPAntibanArtifacts(ctx, ct),
            CheckRageMPLogFilesForCheatEvidence(ctx, ct),
            CheckRageMPCEFBrowserExploitArtifacts(ctx, ct),
            CheckRageMPResourcePackArtifacts(ctx, ct),
            CheckRageMPVehicleSpawnFloodArtifacts(ctx, ct),
            CheckRageMPNativeHashAbuse(ctx, ct),
            CheckRageMPRegistryArtifacts(ctx, ct),
            CheckRageMPPrefetchArtifacts(ctx, ct),
            CheckRageMPDiscordWebhookExfil(ctx, ct),
            CheckRageMPUpdaterTampering(ctx, ct)
        );
    }

    private Task CheckRageMPCheatDLLArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var searchRoots = new[]
        {
            Path.Combine(localAppData, "RAGEMP"),
            Path.Combine(appData, "RAGEMP"),
            @"C:\RAGEMP",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(localAppData, "Temp"),
        };

        var allDLLPatterns = CheatDLLPatterns.Concat(AdditionalCheatDLLNames).ToArray();

        foreach (string root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            string[] dllFiles = Array.Empty<string>();
            try { dllFiles = Directory.GetFiles(root, "*.dll", SearchOption.AllDirectories); } catch { continue; }
            foreach (string dllFile in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string fileName = Path.GetFileName(dllFile);
                foreach (string pattern in allDLLPatterns)
                {
                    if (fileName.Equals(pattern, StringComparison.OrdinalIgnoreCase) ||
                        fileName.Contains(Path.GetFileNameWithoutExtension(pattern), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Cheat DLL Artifact",
                            Risk = RiskLevel.Critical,
                            Location = dllFile,
                            FileName = fileName,
                            Reason = $"Known cheat DLL pattern '{pattern}' found in RageMP or staging directory",
                            Detail = $"Cheat DLL artifacts in RageMP paths indicate a mod menu or injection tool was installed. Path: {root}"
                        });
                        break;
                    }
                }
                try
                {
                    using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 128 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);
                    foreach (string pattern in allDLLPatterns)
                    {
                        string patternName = Path.GetFileNameWithoutExtension(pattern);
                        if (content.Contains(patternName, StringComparison.OrdinalIgnoreCase) &&
                            content.Contains("RAGEMP", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP DLL — Cheat Strings Detected",
                                Risk = RiskLevel.Critical,
                                Location = dllFile,
                                FileName = fileName,
                                Reason = $"DLL contains cheat pattern '{patternName}' alongside RAGEMP references",
                                Detail = "DLL binary strings reference both RageMP and known cheat keywords indicating a RageMP cheat module"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPClientPackageCheatArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var packagePaths = new[]
        {
            Path.Combine(localAppData, "RAGEMP", "cs_packages"),
            Path.Combine(localAppData, "RAGEMP", "client_packages"),
        };

        var suspiciousFileNames = new[] { "index.js", "browserMain.js", "rage.dll" };

        foreach (string packageRoot in packagePaths)
        {
            if (!Directory.Exists(packageRoot)) continue;
            string[] jsFiles = Array.Empty<string>();
            try { jsFiles = Directory.GetFiles(packageRoot, "*.js", SearchOption.AllDirectories); } catch { continue; }
            foreach (string jsFile in jsFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    int matchCount = 0;
                    string? lastMatch = null;
                    foreach (string kw in JSCheatKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            lastMatch = kw;
                        }
                    }
                    bool isSuspiciousName = suspiciousFileNames.Any(n =>
                        Path.GetFileName(jsFile).Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (matchCount >= 2 || (matchCount >= 1 && isSuspiciousName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Client Package — Cheat JavaScript",
                            Risk = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"Client package JS contains {matchCount} cheat pattern(s); last match: '{lastMatch}'",
                            Detail = "RageMP client packages execute in the game process — cheat JS here directly implements hacks such as godmode, weapon spawning, and teleportation"
                        });
                    }
                }
                catch { }
            }
            string[] dllFiles = Array.Empty<string>();
            try { dllFiles = Directory.GetFiles(packageRoot, "rage.dll", SearchOption.AllDirectories); } catch { }
            foreach (string dll in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RageMP Client Package — rage.dll Replacement",
                    Risk = RiskLevel.Critical,
                    Location = dll,
                    FileName = "rage.dll",
                    Reason = "rage.dll found inside client_packages or cs_packages directory — possible DLL replacement",
                    Detail = "The legitimate rage.dll should reside in the RageMP root; a copy inside client packages suggests a tampered or injected replacement"
                });
            }
        }
    }, ct);

    private Task CheckRageMPBridgeExploitArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var bridgeDLLNames = new[] { "bridge.dll", "rage-bridge.dll", "native_invoker.dll" };
        var searchPaths = new[]
        {
            Path.Combine(localAppData, "RAGEMP"),
            Path.Combine(localAppData, "RAGEMP", "updater"),
        };

        foreach (string searchRoot in searchPaths)
        {
            if (!Directory.Exists(searchRoot)) continue;
            foreach (string bridgeDll in bridgeDLLNames)
            {
                string bridgePath = Path.Combine(searchRoot, bridgeDll);
                if (!File.Exists(bridgePath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RageMP Bridge DLL — Exploit Artifact",
                    Risk = RiskLevel.Critical,
                    Location = bridgePath,
                    FileName = bridgeDll,
                    Reason = $"Known bridge exploit DLL '{bridgeDll}' found in RageMP directory",
                    Detail = "Bridge DLL replacements intercept the JS-to-native communication layer in RageMP enabling unrestricted native function calls"
                });
            }
            string[] allFiles = Array.Empty<string>();
            try { allFiles = Directory.GetFiles(searchRoot, "*", SearchOption.AllDirectories); } catch { continue; }
            foreach (string file in allFiles)
            {
                if (ct.IsCancellationRequested) return;
                string ext = Path.GetExtension(file);
                if (!ext.Equals(".js", StringComparison.OrdinalIgnoreCase) &&
                    !ext.Equals(".json", StringComparison.OrdinalIgnoreCase) &&
                    !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)) continue;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string pattern in BridgeExploitPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Bridge — Exploit Pattern Detected",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"File contains bridge exploit pattern: '{pattern}'",
                                Detail = "Bridge exploit patterns allow arbitrary native GTA V function calls bypassing RageMP security restrictions"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPYimMenuArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var yimPaths = new[]
        {
            Path.Combine(appData, "YimMenuRageMP"),
            Path.Combine(appData, "YimMenu-RageMP"),
        };

        foreach (string yimPath in yimPaths)
        {
            if (!Directory.Exists(yimPath)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "YimMenu RageMP — Config Directory Found",
                Risk = RiskLevel.Critical,
                Location = yimPath,
                FileName = Path.GetFileName(yimPath),
                Reason = "YimMenu RageMP configuration directory exists on this system",
                Detail = "YimMenu has a RageMP-specific version; this directory proves YimMenu-RageMP was installed and used"
            });
            foreach (string configFile in new[] { "settings.json", "hotkeys.json" })
            {
                string configPath = Path.Combine(yimPath, configFile);
                if (!File.Exists(configPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "YimMenu RageMP — Configuration File",
                    Risk = RiskLevel.Critical,
                    Location = configPath,
                    FileName = configFile,
                    Reason = $"YimMenu RageMP configuration file '{configFile}' found",
                    Detail = "YimMenu RageMP config files contain feature toggles for godmode, ESP, aimbot, and other cheats"
                });
            }
        }

        string downloadsPath = Path.Combine(userProfile, "Downloads");
        if (Directory.Exists(downloadsPath))
        {
            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(downloadsPath, "YimMenu-RageMP*.dll", SearchOption.TopDirectoryOnly); } catch { }
            foreach (string dll in files)
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "YimMenu RageMP — DLL in Downloads",
                    Risk = RiskLevel.Critical,
                    Location = dll,
                    FileName = Path.GetFileName(dll),
                    Reason = "YimMenu-RageMP DLL found in Downloads folder",
                    Detail = "YimMenu-RageMP.dll is the main cheat module injected into the RageMP client process"
                });
            }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\YimMenuRageMP");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "YimMenu RageMP — Registry Key Found",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\YimMenuRageMP",
                    FileName = "YimMenuRageMP",
                    Reason = "YimMenu RageMP registry key exists under HKCU\\Software",
                    Detail = "Registry key left by YimMenu RageMP installation confirming the cheat was present on this system"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckRageMPBubbaMenuArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        string bubbaPath = Path.Combine(appData, "Bubba");
        if (Directory.Exists(bubbaPath))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Bubba Mod Menu — Config Directory Found",
                Risk = RiskLevel.Critical,
                Location = bubbaPath,
                FileName = "Bubba",
                Reason = "Bubba RageMP mod menu configuration directory found",
                Detail = "Bubba is a RageMP-specific mod menu; its AppData directory confirms past or current cheat usage"
            });
            foreach (string configFile in new[] { "config.json", "bubba.log" })
            {
                string configPath = Path.Combine(bubbaPath, configFile);
                if (!File.Exists(configPath)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Bubba Mod Menu — Artifact File",
                    Risk = RiskLevel.Critical,
                    Location = configPath,
                    FileName = configFile,
                    Reason = $"Bubba mod menu artifact file '{configFile}' found",
                    Detail = "Bubba config and log files are left by the mod menu; log files may contain session and feature usage records"
                });
            }
            string scriptsPath = Path.Combine(bubbaPath, "scripts");
            if (Directory.Exists(scriptsPath))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Bubba Mod Menu — Scripts Directory",
                    Risk = RiskLevel.Critical,
                    Location = scriptsPath,
                    FileName = "scripts",
                    Reason = "Bubba mod menu scripts directory found",
                    Detail = "Bubba scripts folder contains cheat Lua or JS scripts that run in the RageMP environment"
                });
            }
        }

        foreach (string dir in new[] { Path.Combine(userProfile, "Downloads"), Path.Combine(userProfile, "Desktop") })
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string pattern in new[] { "Bubba*.zip", "Bubba*.dll" })
            {
                string[] files = Array.Empty<string>();
                try { files = Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly); } catch { continue; }
                foreach (string file in files)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Bubba Mod Menu — Downloaded Archive/DLL",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Bubba mod menu file found in {Path.GetFileName(dir)}",
                        Detail = "Bubba cheat files in user download/staging directories indicate the mod menu was downloaded and likely used"
                    });
                }
            }
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Bubba");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Bubba Mod Menu — Registry Artifact",
                    Risk = RiskLevel.Critical,
                    Location = @"HKCU\Software\Bubba",
                    FileName = "Bubba",
                    Reason = "Bubba mod menu registry key found under HKCU\\Software",
                    Detail = "Registry artifact left by Bubba RageMP mod menu confirming installation on this system"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckRageMPScriptInjectionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string clientPackagesPath = Path.Combine(localAppData, "RAGEMP", "client_packages");
        if (!Directory.Exists(clientPackagesPath)) return;

        var injectionPatterns = new[]
        {
            "XMLHttpRequest", "fetch(", "WebSocket(", "eval(", "Function(", "atob(",
            "require('child_process')", "require(\"child_process\")", "process.env", "os.exec",
        };

        string[] jsFiles = Array.Empty<string>();
        try { jsFiles = Directory.GetFiles(clientPackagesPath, "*.js", SearchOption.AllDirectories); } catch { return; }
        foreach (string jsFile in jsFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);
                int obfuscationHits = 0;
                bool hasEval = content.Contains("eval(", StringComparison.OrdinalIgnoreCase);
                bool hasAtob = content.Contains("atob(", StringComparison.OrdinalIgnoreCase);
                bool hasFunction = content.Contains("Function(", StringComparison.OrdinalIgnoreCase);
                bool hasChildProcess = content.Contains("child_process", StringComparison.OrdinalIgnoreCase);
                bool hasExternalFetch = (content.Contains("XMLHttpRequest", StringComparison.OrdinalIgnoreCase) ||
                                         content.Contains("fetch(", StringComparison.OrdinalIgnoreCase)) &&
                                        !content.Contains("rage-mp.com", StringComparison.OrdinalIgnoreCase);
                if (hasEval) obfuscationHits++;
                if (hasAtob) obfuscationHits++;
                if (hasFunction) obfuscationHits++;
                if (hasChildProcess)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Client Package — OS Process Execution",
                        Risk = RiskLevel.Critical,
                        Location = jsFile,
                        FileName = Path.GetFileName(jsFile),
                        Reason = "Client package JS imports child_process enabling OS-level command execution",
                        Detail = "Using child_process in RageMP client packages allows executing arbitrary OS commands from within the game client"
                    });
                }
                if (obfuscationHits >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Client Package — Obfuscated Script Injection",
                        Risk = RiskLevel.Critical,
                        Location = jsFile,
                        FileName = Path.GetFileName(jsFile),
                        Reason = $"Client JS uses {obfuscationHits} obfuscation techniques (eval/atob/Function) — typical injected cheat payload",
                        Detail = "Multiple obfuscation layers in RageMP client packages are used to hide cheat logic from static analysis"
                    });
                }
                else if (hasExternalFetch)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Client Package — External Network Request",
                        Risk = RiskLevel.Critical,
                        Location = jsFile,
                        FileName = Path.GetFileName(jsFile),
                        Reason = "Client package JS makes external network requests not to RageMP servers",
                        Detail = "Outbound HTTP/WebSocket calls in client packages can exfiltrate player data or download additional cheat payloads"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckRageMPCrashToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            string[] exeFiles = Array.Empty<string>();
            try { exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); } catch { continue; }
            foreach (string exeFile in exeFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string fileName = Path.GetFileName(exeFile);
                foreach (string pattern in CheatExecutablePatterns)
                {
                    if (Path.GetFileNameWithoutExtension(fileName).Contains(
                            Path.GetFileNameWithoutExtension(pattern), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Crash/Griefing Tool",
                            Risk = RiskLevel.Critical,
                            Location = exeFile,
                            FileName = fileName,
                            Reason = $"Known RageMP crash or griefing tool found: '{fileName}'",
                            Detail = "RageMP crash tools are used to disconnect or lag-out other players on servers; their presence is evidence of griefing activity"
                        });
                        break;
                    }
                }
            }
            string[] txtFiles = Array.Empty<string>();
            try { txtFiles = Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(dir, "*.js", SearchOption.TopDirectoryOnly)).ToArray(); } catch { }
            foreach (string textFile in txtFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(textFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string crashPattern in CrashToolPatterns)
                    {
                        if (content.Contains(crashPattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Crash Script — Griefing Payload",
                                Risk = RiskLevel.Critical,
                                Location = textFile,
                                FileName = Path.GetFileName(textFile),
                                Reason = $"File contains RageMP crash/griefing pattern: '{crashPattern}'",
                                Detail = "Script files with RageMP crash event calls or entity spam loops are used for server disruption attacks"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPMoneyExploitArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var searchPaths = new[]
        {
            Path.Combine(localAppData, "RAGEMP", "client_packages"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
        };

        foreach (string searchRoot in searchPaths)
        {
            if (!Directory.Exists(searchRoot)) continue;
            string[] jsFiles = Array.Empty<string>();
            try { jsFiles = Directory.GetFiles(searchRoot, "*.js", SearchOption.AllDirectories); } catch { continue; }
            foreach (string jsFile in jsFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    int hits = 0;
                    string? lastHit = null;
                    foreach (string kw in MoneyExploitKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            hits++;
                            lastHit = kw;
                        }
                    }
                    if (hits >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Money/Economy Exploit Script",
                            Risk = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"Script contains {hits} economy exploit keywords; last: '{lastHit}'",
                            Detail = "Economy exploit scripts for RageMP manipulate server-side money and item systems to grant unauthorized resources"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPAntibanArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var antibanExePatterns = new[] { "ragemp_antiban", "rage_spoofer", "hwid_bypass", "rage_cleaner" };
        var searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(localAppData, "Temp"),
            Path.Combine(userProfile, "AppData", "Roaming"),
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            string[] exeFiles = Array.Empty<string>();
            try { exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); } catch { continue; }
            foreach (string exeFile in exeFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string fileNameLower = Path.GetFileName(exeFile).ToLowerInvariant();
                foreach (string pattern in antibanExePatterns)
                {
                    if (fileNameLower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Anti-Ban Tool",
                            Risk = RiskLevel.Critical,
                            Location = exeFile,
                            FileName = Path.GetFileName(exeFile),
                            Reason = $"RageMP anti-ban or HWID spoofer tool found: '{fileNameLower}'",
                            Detail = "Anti-ban tools for RageMP are used to evade server bans by spoofing hardware identifiers or cleaning cheat traces"
                        });
                        break;
                    }
                }
            }
        }

        string ragempLogsPath = Path.Combine(localAppData, "RAGEMP", "logs");
        if (Directory.Exists(ragempLogsPath))
        {
            string[] logFiles = Array.Empty<string>();
            try { logFiles = Directory.GetFiles(ragempLogsPath, "*.log", SearchOption.TopDirectoryOnly); } catch { }
            if (logFiles.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RageMP Logs — Directory Empty (Possible Cleaner)",
                    Risk = RiskLevel.High,
                    Location = ragempLogsPath,
                    FileName = "logs",
                    Reason = "RageMP logs directory exists but contains no log files — possible cleaner tool ran",
                    Detail = "RageMP anti-ban cleaners delete log files to remove forensic evidence of cheat usage and server ban events"
                });
            }
        }
    }, ct);

    private Task CheckRageMPLogFilesForCheatEvidence(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string ragempLogsPath = Path.Combine(localAppData, "RAGEMP", "logs");
        if (!Directory.Exists(ragempLogsPath)) return;

        string[] logFiles = Array.Empty<string>();
        try { logFiles = Directory.GetFiles(ragempLogsPath, "*.log", SearchOption.AllDirectories); } catch { return; }
        foreach (string logFile in logFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);
                foreach (string cheatPattern in LogCheatPatterns)
                {
                    if (content.Contains(cheatPattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Log — Cheat Activity Evidence",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"RageMP log contains cheat-related pattern: '{cheatPattern}'",
                            Detail = "RageMP log files record session events; cheat-related entries indicate AC detection events, ban triggers, or cheat module loading"
                        });
                        break;
                    }
                }
                int connectCount = 0;
                int disconnectCount = 0;
                foreach (string line in content.Split('\n'))
                {
                    if (line.Contains("connect", StringComparison.OrdinalIgnoreCase)) connectCount++;
                    if (line.Contains("disconnect", StringComparison.OrdinalIgnoreCase)) disconnectCount++;
                }
                if (connectCount > 10 && disconnectCount > 8 && disconnectCount >= connectCount / 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Log — Rapid Connect/Disconnect Pattern",
                        Risk = RiskLevel.High,
                        Location = logFile,
                        FileName = Path.GetFileName(logFile),
                        Reason = $"Log shows {connectCount} connections and {disconnectCount} disconnections — possible ban evasion cycling",
                        Detail = "Rapid connect/disconnect cycles in RageMP logs indicate ban evasion behavior or server-hopping after detection"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckRageMPCEFBrowserExploitArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var cefPaths = new[]
        {
            Path.Combine(localAppData, "RAGEMP", "cache"),
            Path.Combine(appData, "RAGEMP", "CEF"),
        };

        var cefCheatPatterns = new[]
        {
            "cheat", "hack", "aimbot", "esp", "bypass", "inject",
            "discord.com/api/webhooks", "eval(", "atob(",
        };

        foreach (string cefPath in cefPaths)
        {
            if (!Directory.Exists(cefPath)) continue;
            int scanned = 0;
            string[] cacheFiles = Array.Empty<string>();
            try { cacheFiles = Directory.GetFiles(cefPath, "*", SearchOption.AllDirectories); } catch { continue; }
            foreach (string cacheFile in cacheFiles)
            {
                if (ct.IsCancellationRequested || scanned > 300) break;
                string ext = Path.GetExtension(cacheFile);
                if (ext.Equals(".png", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".jpg", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".ico", StringComparison.OrdinalIgnoreCase)) continue;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);
                    foreach (string pattern in cefCheatPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP CEF Cache — Cheat UI Content",
                                Risk = RiskLevel.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason = $"RageMP CEF browser cache contains cheat pattern: '{pattern}'",
                                Detail = "CEF cache artifacts from cheat overlay UIs, exploit payloads, or malicious iframe content loaded by RageMP cheat menus"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPResourcePackArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string clientPackagesPath = Path.Combine(localAppData, "RAGEMP", "client_packages");
        if (!Directory.Exists(clientPackagesPath)) return;

        var backdoorPatterns = new[]
        {
            "exfiltrate", "sendData", "callRemote", "XMLHttpRequest", "fetch(",
            "eval(", "atob(", "Function(",
            "discord.com/api/webhooks", "t.me/", "telegram.org",
        };

        string[] jsFiles = Array.Empty<string>();
        try { jsFiles = Directory.GetFiles(clientPackagesPath, "*.js", SearchOption.AllDirectories); } catch { return; }
        foreach (string jsFile in jsFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);
                bool hasNativeAbuse = content.Contains("mp.game.invoke", StringComparison.OrdinalIgnoreCase) ||
                                      content.Contains("mp.invoke", StringComparison.OrdinalIgnoreCase);
                bool hasObfuscation = content.Contains("eval(", StringComparison.OrdinalIgnoreCase) ||
                                      content.Contains("atob(", StringComparison.OrdinalIgnoreCase);
                bool hasExternalComm = false;
                string? externalPattern = null;
                foreach (string bp in backdoorPatterns)
                {
                    if (content.Contains(bp, StringComparison.OrdinalIgnoreCase))
                    {
                        hasExternalComm = true;
                        externalPattern = bp;
                        break;
                    }
                }
                if (hasNativeAbuse && hasObfuscation)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Resource Pack — Exploit Payload",
                        Risk = RiskLevel.Critical,
                        Location = jsFile,
                        FileName = Path.GetFileName(jsFile),
                        Reason = "Resource pack JS combines native function abuse with obfuscation — exploit payload pattern",
                        Detail = "Resource packs using mp.game.invoke/mp.invoke with eval/atob obfuscation are classic RageMP cheat delivery vectors"
                    });
                }
                else if (hasNativeAbuse && hasExternalComm)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Resource Pack — Backdoor/Exfiltration",
                        Risk = RiskLevel.Critical,
                        Location = jsFile,
                        FileName = Path.GetFileName(jsFile),
                        Reason = $"Resource pack JS calls game natives and makes external network requests ('{externalPattern}')",
                        Detail = "Native abuse paired with external communication indicates a backdoor resource pack exfiltrating player data or server information"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckRageMPVehicleSpawnFloodArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var searchPaths = new[]
        {
            Path.Combine(localAppData, "RAGEMP", "client_packages"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
        };

        foreach (string searchRoot in searchPaths)
        {
            if (!Directory.Exists(searchRoot)) continue;
            string[] jsFiles = Array.Empty<string>();
            try { jsFiles = Directory.GetFiles(searchRoot, "*.js", SearchOption.AllDirectories); } catch { continue; }
            foreach (string jsFile in jsFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    int spawnHits = 0;
                    bool hasLoop = content.Contains("for(", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("while(", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("setInterval(", StringComparison.OrdinalIgnoreCase);
                    foreach (string pattern in VehicleSpawnPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) spawnHits++;
                    }
                    if (spawnHits >= 1 && hasLoop)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Vehicle Spawn Flood Script",
                            Risk = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"Script contains vehicle spawn calls ({spawnHits} pattern(s)) inside loops — spawn flood pattern",
                            Detail = "Vehicle spawn flood scripts create massive numbers of entities to crash or lag RageMP servers and grief other players"
                        });
                    }
                    else if (spawnHits >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Vehicle Spawn Abuse Script",
                            Risk = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"Script contains {spawnHits} vehicle spawn patterns without delay logic",
                            Detail = "Multiple vehicle spawn calls without timing controls indicate a griefing or flood script"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPNativeHashAbuse(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var nativeFileNames = new[] { "natives.json", "ragemp_natives.json", "native_hash.json", "natives_list.txt" };
        var searchDirs = new[]
        {
            Path.Combine(localAppData, "RAGEMP"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string nativeFile in nativeFileNames)
            {
                string[] found = Array.Empty<string>();
                try { found = Directory.GetFiles(dir, nativeFile, SearchOption.AllDirectories); } catch { continue; }
                foreach (string file in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Native Hash List File",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Native hash list file '{nativeFile}' found — used for RageMP exploitation",
                        Detail = "Native hash list files contain GTA V function addresses used by cheat scripts to invoke game functions directly without API restrictions"
                    });
                }
            }
        }

        string clientPackagesPath = Path.Combine(localAppData, "RAGEMP", "client_packages");
        if (Directory.Exists(clientPackagesPath))
        {
            string[] jsFiles = Array.Empty<string>();
            try { jsFiles = Directory.GetFiles(clientPackagesPath, "*.js", SearchOption.AllDirectories); } catch { }
            foreach (string jsFile in jsFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    int hashCount = 0;
                    int searchStart = 0;
                    while (searchStart < content.Length - 18)
                    {
                        int idx = content.IndexOf("0x", searchStart, StringComparison.OrdinalIgnoreCase);
                        if (idx < 0) break;
                        if (idx + 18 <= content.Length)
                        {
                            string candidate = content.Substring(idx + 2, 16);
                            if (candidate.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                                hashCount++;
                        }
                        searchStart = idx + 2;
                    }
                    if (hashCount >= 10)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Client Script — Bulk Native Hash Usage",
                            Risk = RiskLevel.High,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"Script contains {hashCount} native hash patterns (0x + 16 hex digits)",
                            Detail = "Large numbers of GTA V native hashes in client JS indicate a cheat script directly invoking game functions by hash value"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (string menuKey in MenuRegistryKeys)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(menuKey);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RageMP Cheat — Registry Key",
                    Risk = RiskLevel.Critical,
                    Location = $@"HKCU\{menuKey}",
                    FileName = menuKey.Split('\\').Last(),
                    Reason = $"Cheat-specific registry key found: HKCU\\{menuKey}",
                    Detail = "This registry key is created exclusively by RageMP cheat tools and mod menus; its presence is direct forensic evidence"
                });
            }
            catch { }
        }

        try
        {
            using var ragempKey = Registry.CurrentUser.OpenSubKey(@"Software\RAGEMP");
            if (ragempKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (string valueName in ragempKey.GetValueNames())
                {
                    string val = ragempKey.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (val.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        val.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                        valueName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        valueName.Contains("bypass", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Registry — Cheat Configuration Value",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\Software\RAGEMP\{valueName}",
                            FileName = valueName,
                            Reason = $"RAGEMP registry value contains cheat keyword: '{valueName}' = '{val}'",
                            Detail = "RageMP registry configuration modified to include cheat or bypass settings"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            using var runKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
            if (runKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (string valueName in runKey.GetValueNames())
                {
                    string val = runKey.GetValue(valueName)?.ToString() ?? string.Empty;
                    if ((val.Contains("rage", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("ragemp", StringComparison.OrdinalIgnoreCase)) &&
                        (val.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                         val.Contains("bypass", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Cheat — Autostart Registry Entry",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\{valueName}",
                            FileName = valueName,
                            Reason = $"RageMP cheat autostart entry in Run key: '{valueName}' -> '{val}'",
                            Detail = "Autostart entries for RageMP cheat tools ensure they launch automatically with Windows or before the game"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            using var recentKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs");
            if (recentKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (string subKeyName in recentKey.GetSubKeyNames())
                {
                    if (!subKeyName.Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
                        !subKeyName.Equals(".js", StringComparison.OrdinalIgnoreCase)) continue;
                    using var subKey = recentKey.OpenSubKey(subKeyName);
                    if (subKey == null) continue;
                    foreach (string valueName in subKey.GetValueNames())
                    {
                        if (!valueName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase))
                        {
                            byte[]? rawVal = subKey.GetValue(valueName) as byte[];
                            if (rawVal == null) continue;
                            string decoded = Encoding.Unicode.GetString(rawVal);
                            if ((decoded.Contains("rage", StringComparison.OrdinalIgnoreCase) ||
                                 decoded.Contains("ragemp", StringComparison.OrdinalIgnoreCase)) &&
                                (decoded.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                 decoded.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                 decoded.Contains("inject", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "RageMP Cheat — RecentDocs Registry Artifact",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\{subKeyName}\{valueName}",
                                    FileName = valueName,
                                    Reason = $"RecentDocs entry references RageMP cheat file: '{decoded.Trim('\0')}'",
                                    Detail = "RecentDocs entries persist after file deletion and prove the user opened RageMP cheat DLL or JS files"
                                });
                            }
                        }
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckRageMPPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string prefetchPath = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchPath)) return;

        var cheatPrefetchPatterns = new[]
        {
            "BUBBA", "RAGEMP_INJECT", "RAGE_HACK", "RAGE_CHEAT",
            "RAGEMP_ANTIBAN", "RAGE_SPOOFER", "HWID_BYPASS", "RAGE_CLEANER",
            "MP_CRASH", "ENTITY_SPAM", "FLOOD_MP",
        };

        string[] pfFiles = Array.Empty<string>();
        try { pfFiles = Directory.GetFiles(prefetchPath, "*.pf", SearchOption.TopDirectoryOnly); } catch { return; }
        foreach (string pfFile in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            string fileName = Path.GetFileName(pfFile).ToUpperInvariant();
            foreach (string pattern in cheatPrefetchPatterns)
            {
                if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Cheat — Prefetch Execution Artifact",
                        Risk = RiskLevel.High,
                        Location = pfFile,
                        FileName = Path.GetFileName(pfFile),
                        Reason = $"Prefetch file matches RageMP cheat pattern: '{pattern}'",
                        Detail = "Windows Prefetch files are created when a program runs and persist after deletion; this proves the RageMP cheat tool was executed on this system"
                    });
                    break;
                }
            }
        }

        try
        {
            using var bagKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\Shell\BagMRU");
            if (bagKey != null)
            {
                ctx.IncrementRegistryKeys();
                CheckBagMRURecursive(bagKey, @"HKCU\Software\Microsoft\Windows\Shell\BagMRU", ctx);
            }
        }
        catch { }
    }, ct);

    private void CheckBagMRURecursive(RegistryKey key, string keyPath, ScanContext ctx)
    {
        try
        {
            foreach (string valueName in key.GetValueNames())
            {
                if (valueName.Equals("NodeSlot", StringComparison.OrdinalIgnoreCase) ||
                    valueName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase)) continue;
                byte[]? rawVal = key.GetValue(valueName) as byte[];
                if (rawVal == null) continue;
                string decoded = Encoding.Unicode.GetString(rawVal);
                if ((decoded.Contains("ragemp", StringComparison.OrdinalIgnoreCase) ||
                     decoded.Contains("RAGEMP", StringComparison.OrdinalIgnoreCase)) &&
                    (decoded.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                     decoded.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                     decoded.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                     decoded.Contains("bypass", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Cheat — ShellBag Folder Access",
                        Risk = RiskLevel.High,
                        Location = $@"{keyPath}\{valueName}",
                        FileName = valueName,
                        Reason = $"ShellBag entry references RageMP cheat folder: '{decoded.Trim('\0')}'",
                        Detail = "ShellBag entries record folder access history and persist after folder deletion — proves the user navigated to a RageMP cheat directory"
                    });
                }
            }
            foreach (string subKeyName in key.GetSubKeyNames())
            {
                try
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    if (subKey != null)
                        CheckBagMRURecursive(subKey, $@"{keyPath}\{subKeyName}", ctx);
                }
                catch { }
            }
        }
        catch { }
    }

    private Task CheckRageMPDiscordWebhookExfil(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var searchPaths = new[]
        {
            Path.Combine(localAppData, "RAGEMP", "client_packages"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
        };

        foreach (string searchRoot in searchPaths)
        {
            if (!Directory.Exists(searchRoot)) continue;
            string[] jsFiles = Array.Empty<string>();
            try { jsFiles = Directory.GetFiles(searchRoot, "*.js", SearchOption.AllDirectories); } catch { continue; }
            foreach (string jsFile in jsFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string webhookPattern in WebhookPatterns)
                    {
                        if (content.Contains(webhookPattern, StringComparison.OrdinalIgnoreCase))
                        {
                            int urlStart = content.IndexOf(webhookPattern, StringComparison.OrdinalIgnoreCase);
                            string urlSnippet = urlStart >= 0 && urlStart + 80 < content.Length
                                ? content.Substring(urlStart, Math.Min(80, content.Length - urlStart)).Split('"', '\'', ' ', '\n', '\r')[0]
                                : webhookPattern;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP — Discord Webhook Exfiltration",
                                Risk = RiskLevel.Critical,
                                Location = jsFile,
                                FileName = Path.GetFileName(jsFile),
                                Reason = $"Script contains Discord webhook URL for data exfiltration: '{webhookPattern}'",
                                Detail = $"RageMP cheat scripts use Discord webhooks to exfiltrate player lists, server data, or player identifiers. URL snippet: {urlSnippet}"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckRageMPUpdaterTampering(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string updaterPath = Path.Combine(localAppData, "RAGEMP", "updater");
        if (Directory.Exists(updaterPath))
        {
            string updaterExe = Path.Combine(updaterPath, "updater.exe");
            if (File.Exists(updaterExe))
            {
                ctx.IncrementFiles();
                var fileInfo = new FileInfo(updaterExe);
                if (fileInfo.Length > 50 * 1024 * 1024 || fileInfo.Length < 50 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Updater — Unusual File Size",
                        Risk = RiskLevel.Critical,
                        Location = updaterExe,
                        FileName = "updater.exe",
                        Reason = $"RageMP updater.exe has unusual size: {fileInfo.Length / 1024} KB",
                        Detail = "Abnormal updater.exe file size may indicate the legitimate updater was replaced with a cheat loader or trojanized binary"
                    });
                }
            }

            string rageDll = Path.Combine(updaterPath, "rage.dll");
            if (File.Exists(rageDll))
            {
                ctx.IncrementFiles();
                var dllInfo = new FileInfo(rageDll);
                if (dllInfo.Length < 100 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Updater — Suspect rage.dll Size",
                        Risk = RiskLevel.Critical,
                        Location = rageDll,
                        FileName = "rage.dll",
                        Reason = $"rage.dll in updater directory is unusually small: {dllInfo.Length / 1024} KB",
                        Detail = "The legitimate rage.dll is a large core library; a small replacement indicates a stub or trojanized DLL placed by a cheat tool"
                    });
                }
            }

            string[] unexpectedDlls = Array.Empty<string>();
            try { unexpectedDlls = Directory.GetFiles(updaterPath, "*.dll", SearchOption.TopDirectoryOnly); } catch { }
            var legitimateUpdaterDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "rage.dll", "d3dcompiler_47.dll", "libcef.dll", "icudtl.dat"
            };
            foreach (string dll in unexpectedDlls)
            {
                if (ct.IsCancellationRequested) return;
                string dllName = Path.GetFileName(dll);
                if (!legitimateUpdaterDlls.Contains(dllName))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Updater — Unexpected DLL",
                        Risk = RiskLevel.Critical,
                        Location = dll,
                        FileName = dllName,
                        Reason = $"Non-standard DLL '{dllName}' found in RageMP updater directory",
                        Detail = "Additional DLLs placed in the RageMP updater directory are loaded at startup and may be cheat injection components"
                    });
                }
            }
        }

        foreach (string regPath in new[]
        {
            @"Software\RAGE Multiplayer",
            @"SOFTWARE\RAGE Multiplayer",
        })
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                try
                {
                    using var key = hive.OpenSubKey(regPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    string? installPath = key.GetValue("InstallFolder")?.ToString() ??
                                         key.GetValue("Install_Dir")?.ToString() ??
                                         key.GetValue("Path")?.ToString();
                    if (!string.IsNullOrEmpty(installPath))
                    {
                        bool isNonStandard = !installPath.Contains("Program Files", StringComparison.OrdinalIgnoreCase) &&
                                             !installPath.Contains("RAGEMP", StringComparison.OrdinalIgnoreCase) &&
                                             !installPath.Contains("RAGE Multiplayer", StringComparison.OrdinalIgnoreCase);
                        if (isNonStandard)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP — Non-Standard Installation Path",
                                Risk = RiskLevel.Critical,
                                Location = $@"{(hive == Registry.CurrentUser ? "HKCU" : "HKLM")}\{regPath}",
                                FileName = "InstallFolder",
                                Reason = $"RageMP installed at non-standard path: '{installPath}'",
                                Detail = "Cheat loaders sometimes install RageMP to custom directories to control the load environment and inject cheat DLLs at startup"
                            });
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);
}
