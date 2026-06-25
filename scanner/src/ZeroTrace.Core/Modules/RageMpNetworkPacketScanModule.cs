using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RageMpNetworkPacketScanModule : IScanModule
{
    public string Name => "RageMP-Network-Packet";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);
    private static readonly string TempPath = Path.GetTempPath();

    // Native Windows API names accessed via Node FFI that indicate process injection
    private static readonly string[] FfiInjectionSymbols =
    {
        "ReadProcessMemory",
        "WriteProcessMemory",
        "VirtualAllocEx",
        "CreateRemoteThread",
        "OpenProcess",
    };

    // FFI/native binding libraries used in Node.js for process injection
    private static readonly string[] NativeBindingModules =
    {
        "ffi", "koffi", "win32api", "node-ffi", "ffi-napi",
        "node-ffi-napi", "ref-napi", "ref", "bindings",
    };

    // Cheat-related keywords that indicate an exploit config when found in config files
    private static readonly string[] CheatConfigKeywords =
    {
        "aimbot", "esp", "wallhack", "godmode", "noclip", "triggerbot",
        "spinbot", "bhop", "speedhack", "teleport", "norecoil", "rapidfire",
        "silent aim", "silentaim", "unlock all", "money drop", "explosion",
    };

    // Known cheat config file extensions specific to RageMP cheat tools
    private static readonly string[] CheatExtensions = { ".rmp", ".rage", ".evo" };

    // Log file keywords indicating active injection or bypass
    private static readonly string[] InjectionLogKeywords =
    {
        "injected",
        "hook installed",
        "native hooked",
        "bypass active",
        "anticheats disabled",
        "anticheat disabled",
        "cheat loaded",
        "module injected",
    };

    // Known RageMP cheat DLL name fragments for crash dump analysis
    private static readonly string[] KnownRageMpCheatNames =
    {
        "evo", "evolution", "redengine", "dopamine", "phantom", "lynx",
        "outbreak", "skript", "nopixel", "desync", "exodus", "quantum",
        "ragecheat", "mpcheat", "rageinject",
    };

    // Suspicious masterlist domain fragments (anything not official RageMP)
    private static readonly string[] OfficialMasterlistDomains =
    {
        "rage.mp", "ragemp.com",
    };

    // Default GTA V installation paths (root segments)
    private static readonly string[] LegitGtaPathSegments =
    {
        @"SteamApps\common\Grand Theft Auto V",
        @"Steam\steamapps\common\Grand Theft Auto V",
        @"Rockstar Games\Grand Theft Auto V",
        @"Epic Games\GTAV",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Scanning RageMP package dependency graph...");
        await ScanPackageDependencyGraphAsync(ctx, ct);

        ctx.Report(0.25, Name, "Scanning RageMP client_packages for CEF injection...");
        await ScanClientPackagesCefAsync(ctx, ct);

        ctx.Report(0.50, Name, "Scanning for RageMP cheat config files...");
        await ScanCheatConfigFilesAsync(ctx, ct);

        ctx.Report(0.70, Name, "Scanning for process injection log artifacts...");
        await ScanInjectionLogArtifactsAsync(ctx, ct);

        ctx.Report(0.85, Name, "Checking RageMP server list manipulation...");
        await ScanServerListManipulationAsync(ctx, ct);

        ctx.Report(1.0, Name, "RageMP network packet scan complete");
    }

    // ------------------------------------------------------------------
    // 1. RageMP package dependency graph scan
    // ------------------------------------------------------------------
    private async Task ScanPackageDependencyGraphAsync(ScanContext ctx, CancellationToken ct)
    {
        var packagesDir = Path.Combine(AppData, @"RAGEMP\packages");
        if (!Directory.Exists(packagesDir)) return;

        string[] packageDirs;
        try { packageDirs = Directory.GetDirectories(packagesDir); }
        catch { return; }

        int packageCount = 0;
        foreach (var pkgDir in packageDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (packageCount >= 200) break;
            packageCount++;

            var pkgName = Path.GetFileName(pkgDir);

            // Read index.js
            var indexJs = Path.Combine(pkgDir, "index.js");
            if (File.Exists(indexJs))
            {
                ctx.IncrementFiles();
                await AnalyzePackageJsAsync(ctx, ct, indexJs, pkgName);
            }

            // Read package.json
            var packageJson = Path.Combine(pkgDir, "package.json");
            if (File.Exists(packageJson))
            {
                ctx.IncrementFiles();
                await AnalyzePackageJsonAsync(ctx, ct, packageJson, pkgName);
            }
        }
    }

    private async Task AnalyzePackageJsAsync(
        ScanContext ctx, CancellationToken ct, string file, string pkgName)
    {
        if (ct.IsCancellationRequested) return;

        FileInfo fi;
        try { fi = new FileInfo(file); } catch { return; }
        if (fi.Length > 200 * 1024) return;

        string content;
        try
        {
            using var sr = new StreamReader(file);
            content = await sr.ReadToEndAsync();
        }
        catch { return; }

        // Check for FFI/native binding imports of injection-related symbols
        var ffiModuleHit = NativeBindingModules.FirstOrDefault(m =>
            content.Contains($"require('{m}')",    StringComparison.OrdinalIgnoreCase) ||
            content.Contains($"require(\"{m}\")",   StringComparison.OrdinalIgnoreCase) ||
            content.Contains($"from '{m}'",         StringComparison.OrdinalIgnoreCase) ||
            content.Contains($"from \"{m}\"",       StringComparison.OrdinalIgnoreCase));

        if (ffiModuleHit is not null)
        {
            var symbolHit = FfiInjectionSymbols.FirstOrDefault(s =>
                content.Contains(s, StringComparison.OrdinalIgnoreCase));

            if (symbolHit is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"RageMP package uses FFI for process injection: {pkgName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason   = $"RageMP package '{pkgName}' imports the native binding module " +
                               $"'{ffiModuleHit}' and references the Windows API symbol " +
                               $"'{symbolHit}'. This combination is used for process injection — " +
                               "calling kernel-level APIs from within Node.js to manipulate GTA V memory.",
                    Detail   = $"FFI module: {ffiModuleHit} | Symbol: {symbolHit}",
                });
                return;
            }
        }

        // Check for child_process.spawn/exec with suspicious arguments
        bool hasChildProcess = content.Contains("child_process", StringComparison.OrdinalIgnoreCase)
                            && (content.Contains(".spawn(", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains(".exec(",  StringComparison.OrdinalIgnoreCase));

        if (hasChildProcess)
        {
            // Look for suspicious subprocess targets (injectors, loaders)
            bool hasInjectKeyword = content.Contains("inject",   StringComparison.OrdinalIgnoreCase)
                                 || content.Contains("loader",   StringComparison.OrdinalIgnoreCase)
                                 || content.Contains("rundll32", StringComparison.OrdinalIgnoreCase)
                                 || content.Contains("regsvr32", StringComparison.OrdinalIgnoreCase)
                                 || content.Contains("mshta",    StringComparison.OrdinalIgnoreCase)
                                 || content.Contains("powershell", StringComparison.OrdinalIgnoreCase);

            if (hasInjectKeyword)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"RageMP package spawns suspicious subprocess: {pkgName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason   = $"RageMP package '{pkgName}' uses child_process.spawn/exec with " +
                               "suspicious process names or injection keywords. This technique is " +
                               "used to launch DLL injectors or cheat loaders from within the " +
                               "RageMP Node.js runtime, achieving remote code execution in GTA V.",
                    Detail   = "child_process with injection keyword detected",
                });
                return;
            }
        }

        // Check for circular dependency path traversal injection (../../.. more than 4 levels)
        int maxDepth = 0;
        int searchStart = 0;
        while (true)
        {
            int idx = content.IndexOf("../", searchStart, StringComparison.Ordinal);
            if (idx < 0) break;

            int depth = 1;
            int pos = idx + 3;
            while (pos + 3 <= content.Length &&
                   content.Substring(pos, 3).Equals("../", StringComparison.Ordinal))
            {
                depth++;
                pos += 3;
            }
            if (depth > maxDepth) maxDepth = depth;
            searchStart = idx + 1;
        }

        if (maxDepth > 4)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"RageMP package has deep path traversal: {pkgName}",
                Risk     = RiskLevel.High,
                Location = file,
                FileName = Path.GetFileName(file),
                Reason   = $"RageMP package '{pkgName}' contains a require/import path traversal " +
                           $"going {maxDepth} directory levels up (more than 4 '../' segments). " +
                           "This is a circular dependency injection pattern used to access and " +
                           "load modules outside the package sandbox.",
                Detail   = $"Max traversal depth: {maxDepth} levels",
            });
        }
    }

    private async Task AnalyzePackageJsonAsync(
        ScanContext ctx, CancellationToken ct, string file, string pkgName)
    {
        if (ct.IsCancellationRequested) return;

        FileInfo fi;
        try { fi = new FileInfo(file); } catch { return; }
        if (fi.Length > 200 * 1024) return;

        string content;
        try
        {
            using var sr = new StreamReader(file);
            content = await sr.ReadToEndAsync();
        }
        catch { return; }

        // Check if package.json lists known injection-capable native modules as dependencies
        var depHit = NativeBindingModules.FirstOrDefault(m =>
            content.Contains($"\"{m}\"", StringComparison.OrdinalIgnoreCase));

        var symbolHit = FfiInjectionSymbols.FirstOrDefault(s =>
            content.Contains(s, StringComparison.OrdinalIgnoreCase));

        if (depHit is not null && symbolHit is not null)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"RageMP package.json declares injection dependency: {pkgName}",
                Risk     = RiskLevel.Critical,
                Location = file,
                FileName = Path.GetFileName(file),
                Reason   = $"package.json for RageMP package '{pkgName}' declares the native binding " +
                           $"'{depHit}' as a dependency and contains the Windows API symbol " +
                           $"'{symbolHit}'. This package is likely a process injection wrapper.",
                Detail   = $"Dependency: {depHit} | Symbol: {symbolHit}",
            });
        }
    }

    // ------------------------------------------------------------------
    // 2. RageMP .NET injection via CEF
    // ------------------------------------------------------------------
    private async Task ScanClientPackagesCefAsync(ScanContext ctx, CancellationToken ct)
    {
        var clientPkgDir = Path.Combine(AppData, @"RAGEMP\client_packages");
        if (!Directory.Exists(clientPkgDir)) return;

        IEnumerable<string> jsFiles;
        try
        {
            jsFiles = Directory.EnumerateFiles(clientPkgDir, "*.js", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        int count = 0;
        foreach (var file in jsFiles)
        {
            if (ct.IsCancellationRequested) return;
            if (count >= 500) break;

            ctx.IncrementFiles();
            count++;

            var fileName = Path.GetFileName(file);

            FileInfo fi;
            try { fi = new FileInfo(file); } catch { continue; }
            if (fi.Length > 200 * 1024) continue;

            string content;
            try
            {
                using var sr = new StreamReader(file);
                content = await sr.ReadToEndAsync();
            }
            catch { continue; }

            // Count raw native hash invocations (hex strings like 0x...)
            int nativeHashCount = CountOccurrences(content, "mp.game.invoke");

            if (nativeHashCount > 3)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"RageMP client_package abuses raw native hashes: {fileName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"JavaScript file '{fileName}' in RageMP client_packages calls " +
                               $"mp.game.invoke (raw native hash execution) {nativeHashCount} times. " +
                               "Cheat scripts use direct native hash invocations to bypass the RageMP " +
                               "API wrapper and call privileged GTA V engine functions directly.",
                    Detail   = $"mp.game.invoke count: {nativeHashCount}",
                });
                continue;
            }

            // Check for nativeUI / MpMenu combined with mp.game calls
            bool hasNativeUi = content.Contains("nativeUI",  StringComparison.OrdinalIgnoreCase)
                            || content.Contains("MpMenu",    StringComparison.OrdinalIgnoreCase)
                            || content.Contains("NativeMenu", StringComparison.OrdinalIgnoreCase);
            bool hasMpGame  = content.Contains("mp.game", StringComparison.OrdinalIgnoreCase);

            if (hasNativeUi && hasMpGame)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"RageMP client_package uses trainer UI with native calls: {fileName}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"JavaScript file '{fileName}' combines a trainer-style NativeUI/MpMenu " +
                               "with direct mp.game native calls. This combination is characteristic of " +
                               "RageMP cheat menus that present a graphical trainer interface while " +
                               "executing privileged native game functions.",
                    Detail   = "NativeUI/MpMenu + mp.game combination detected",
                });
                continue;
            }

            // Check for coordinate/weapon serialization sent via callRemote (data exfiltration)
            bool hasCoordsSerialization =
                (content.Contains("GetEntityCoords",     StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("GetPlayerCoords",     StringComparison.OrdinalIgnoreCase) ||
                 content.Contains("GetEntityWeapon",     StringComparison.OrdinalIgnoreCase)) &&
                content.Contains("mp.events.callRemote", StringComparison.OrdinalIgnoreCase);

            if (hasCoordsSerialization)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"RageMP client_package exfiltrates player data: {fileName}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"JavaScript file '{fileName}' serializes player coordinates or weapon " +
                               "data and transmits it via mp.events.callRemote. This is used by " +
                               "RageMP cheat tools to relay real-time player telemetry to a remote " +
                               "server for ESP/aimbot targeting assistance.",
                    Detail   = "Coordinate/weapon serialization + callRemote detected",
                });
            }
        }
    }

    // ------------------------------------------------------------------
    // 3. RageMP cheat config files
    // ------------------------------------------------------------------
    private async Task ScanCheatConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Path.Combine(AppData, "RAGEMP"),
            Path.Combine(AppData, @"RAGEMP\packages"),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        var configFileNames = new[]
        {
            "config.json", "settings.ini", "cheat.cfg",
            "aimbot.cfg", "esp.cfg", "rage.cfg",
        };

        int filesScanned = 0;
        const int maxFiles = 2000;

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            // Scan for known config file names
            foreach (var cfgName in configFileNames)
            {
                if (ct.IsCancellationRequested) return;
                if (filesScanned >= maxFiles) return;

                IEnumerable<string> matches;
                try
                {
                    matches = Directory.EnumerateFiles(dir, cfgName, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var file in matches)
                {
                    if (ct.IsCancellationRequested) return;
                    if (filesScanned >= maxFiles) return;

                    ctx.IncrementFiles();
                    filesScanned++;

                    FileInfo fi;
                    try { fi = new FileInfo(file); } catch { continue; }
                    if (fi.Length > 128 * 1024) continue;

                    string content;
                    try
                    {
                        using var sr = new StreamReader(file);
                        content = await sr.ReadToEndAsync();
                    }
                    catch { continue; }

                    var matchedKeyword = CheatConfigKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (matchedKeyword is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"RageMP cheat config detected: {cfgName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = cfgName,
                            Reason   = $"Configuration file '{cfgName}' in the RageMP directory " +
                                       $"contains the cheat keyword '{matchedKeyword}'. This indicates " +
                                       "a cheat tool configuration file storing settings for aimbot, " +
                                       "ESP, or other RageMP exploit features.",
                            Detail   = $"Keyword matched: '{matchedKeyword}'",
                        });
                    }
                }
            }

            // Scan for cheat-specific extensions (.rmp, .rage, .evo)
            foreach (var ext in CheatExtensions)
            {
                if (ct.IsCancellationRequested) return;
                if (filesScanned >= maxFiles) return;

                IEnumerable<string> extFiles;
                try
                {
                    extFiles = Directory.EnumerateFiles(
                        dir, $"*{ext}", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var file in extFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    if (filesScanned >= maxFiles) return;

                    ctx.IncrementFiles();
                    filesScanned++;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"RageMP cheat config extension: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"File with extension '{ext}' found in the RageMP directory. " +
                                   "The extensions .rmp, .rage, and .evo are exclusively used by " +
                                   "known RageMP cheat tools (Evolution cheat suite and derivatives) " +
                                   "for storing cheat configuration and session state.",
                        Detail   = $"Extension: {ext}",
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 4. RageMP process injection log artifacts
    // ------------------------------------------------------------------
    private async Task ScanInjectionLogArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            TempPath,
            Path.Combine(AppData, "RAGEMP"),
        };

        int filesScanned = 0;
        const int maxFiles = 2000;

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            // Scan log files for injection keywords
            IEnumerable<string> logFiles;
            try
            {
                logFiles = Directory.EnumerateFiles(dir, "*.log", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            bool logLimitReached = false;
            foreach (var file in logFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (filesScanned >= maxFiles) { logLimitReached = true; break; }

                ctx.IncrementFiles();
                filesScanned++;

                FileInfo fi;
                try { fi = new FileInfo(file); } catch { continue; }
                if (fi.Length > 128 * 1024) continue;

                string content;
                try
                {
                    using var sr = new StreamReader(file);
                    content = await sr.ReadToEndAsync();
                }
                catch { continue; }

                var matchedKeyword = InjectionLogKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (matchedKeyword is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"RageMP injection log artifact: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Log file '{Path.GetFileName(file)}' contains the injection artifact " +
                                   $"string '{matchedKeyword}'. This indicates a RageMP cheat DLL or " +
                                   "injector tool was active and logged its execution status.",
                        Detail   = $"Keyword: '{matchedKeyword}'",
                    });
                }
            }

            if (logLimitReached) break;
            if (ct.IsCancellationRequested) return;

            // Scan crash dump files for known cheat DLL module names
            IEnumerable<string> dmpFiles;
            try
            {
                dmpFiles = Directory.EnumerateFiles(dir, "*.dmp", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in dmpFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (filesScanned >= maxFiles) break;

                ctx.IncrementFiles();
                filesScanned++;

                // Read the first 64KB of the dump to search for module name strings
                // Full dump parsing is out of scope; string scanning catches embedded module names
                FileInfo fi;
                try { fi = new FileInfo(file); } catch { continue; }
                if (fi.Length == 0) continue;

                string headerContent;
                try
                {
                    using var fs = new FileStream(
                        file, FileMode.Open, FileAccess.Read, FileShare.Read,
                        bufferSize: 4096, useAsync: true);
                    var buf = new byte[Math.Min(65536, fi.Length)];
                    await fs.ReadAsync(buf, 0, buf.Length, ct);
                    // Interpret as ASCII for string scanning
                    headerContent = System.Text.Encoding.ASCII.GetString(buf);
                }
                catch { continue; }

                var cheatNameHit = KnownRageMpCheatNames.FirstOrDefault(n =>
                    headerContent.Contains(n, StringComparison.OrdinalIgnoreCase));

                if (cheatNameHit is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"RageMP cheat DLL crash dump: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Crash dump '{Path.GetFileName(file)}' contains the module name " +
                                   $"'{cheatNameHit}', which is a known RageMP cheat DLL. Crash dumps " +
                                   "from cheat DLLs are left on disk when the cheat crashes and " +
                                   "contain the module list at the time of the crash.",
                        Detail   = $"Cheat name matched: '{cheatNameHit}'",
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. RageMP server list / server history manipulation
    // ------------------------------------------------------------------
    private async Task ScanServerListManipulationAsync(ScanContext ctx, CancellationToken ct)
    {
        var ragempDir = Path.Combine(AppData, "RAGEMP");
        if (!Directory.Exists(ragempDir)) return;

        // Check config.xml and config.json
        var configFiles = new[]
        {
            Path.Combine(ragempDir, "config.xml"),
            Path.Combine(ragempDir, "config.json"),
        };

        foreach (var configFile in configFiles)
        {
            if (ct.IsCancellationRequested) return;
            if (!File.Exists(configFile)) continue;

            ctx.IncrementFiles();

            FileInfo fi;
            try { fi = new FileInfo(configFile); } catch { continue; }
            if (fi.Length > 128 * 1024) continue;

            string content;
            try
            {
                using var sr = new StreamReader(configFile);
                content = await sr.ReadToEndAsync();
            }
            catch { continue; }

            var lowerContent = content.ToLowerInvariant();

            // Check for unofficial masterlist override
            bool hasMasterlist = lowerContent.Contains("masterlist", StringComparison.OrdinalIgnoreCase);
            if (hasMasterlist)
            {
                bool hasOfficialDomain = OfficialMasterlistDomains.Any(d =>
                    lowerContent.Contains(d, StringComparison.OrdinalIgnoreCase));

                // Look for http:// or https:// URLs near 'masterlist' that are not official
                int masterlistIdx = lowerContent.IndexOf("masterlist", StringComparison.OrdinalIgnoreCase);
                if (masterlistIdx >= 0)
                {
                    var slice = lowerContent.Substring(
                        masterlistIdx, Math.Min(300, lowerContent.Length - masterlistIdx));
                    bool hasUrl = slice.Contains("http://", StringComparison.OrdinalIgnoreCase)
                               || slice.Contains("https://", StringComparison.OrdinalIgnoreCase);

                    if (hasUrl && !hasOfficialDomain)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "RageMP config has unofficial masterlist override",
                            Risk     = RiskLevel.Medium,
                            Location = configFile,
                            FileName = Path.GetFileName(configFile),
                            Reason   = "The RageMP configuration file contains a 'masterlist' URL " +
                                       "that does not point to an official RageMP domain (rage.mp / ragemp.com). " +
                                       "Unofficial masterlist overrides are used by anti-ban tools to " +
                                       "redirect server queries through a proxy that masks the player's " +
                                       "real identity and hardware signature.",
                            Detail   = "Non-official masterlist URL detected near 'masterlist' key",
                        });
                    }
                }
            }

            // Check for unusual updateChannel values
            if (lowerContent.Contains("updatechannel", StringComparison.OrdinalIgnoreCase))
            {
                bool hasNonStandard = !lowerContent.Contains("\"release\"", StringComparison.OrdinalIgnoreCase)
                                   && !lowerContent.Contains("'release'",  StringComparison.OrdinalIgnoreCase)
                                   && !lowerContent.Contains("release",    StringComparison.OrdinalIgnoreCase);

                if (hasNonStandard)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "RageMP config has non-standard updateChannel",
                        Risk     = RiskLevel.Medium,
                        Location = configFile,
                        FileName = Path.GetFileName(configFile),
                        Reason   = "The RageMP configuration file specifies an 'updateChannel' that " +
                                   "does not appear to be the standard 'release' channel. Non-standard " +
                                   "update channels may indicate modified or cheat-distributed RageMP " +
                                   "clients that disable anti-cheat validation during updates.",
                        Detail   = "Non-standard updateChannel value detected",
                    });
                }
            }

            // Check for gameDir pointing outside known GTA V paths
            int gameDirIdx = lowerContent.IndexOf("gamedir", StringComparison.OrdinalIgnoreCase);
            if (gameDirIdx < 0)
                gameDirIdx = lowerContent.IndexOf("game_dir", StringComparison.OrdinalIgnoreCase);

            if (gameDirIdx >= 0)
            {
                var slice = lowerContent.Substring(
                    gameDirIdx, Math.Min(300, lowerContent.Length - gameDirIdx));

                bool pointsToKnownPath = LegitGtaPathSegments.Any(seg =>
                    slice.Contains(seg, StringComparison.OrdinalIgnoreCase));

                // Only flag if there's an actual path-like value that's NOT a known GTA path
                bool hasPathValue = slice.Contains(":\\", StringComparison.OrdinalIgnoreCase)
                                 || slice.Contains(":/",  StringComparison.OrdinalIgnoreCase);

                if (hasPathValue && !pointsToKnownPath)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "RageMP config points gameDir outside standard GTA V path",
                        Risk     = RiskLevel.Medium,
                        Location = configFile,
                        FileName = Path.GetFileName(configFile),
                        Reason   = "The RageMP configuration 'gameDir' value points to a path that " +
                                   "is not a standard GTA V installation directory. This may indicate " +
                                   "a modified GTA V client or a patched executable used in conjunction " +
                                   "with RageMP cheat tools.",
                        Detail   = "gameDir value does not match known GTA V installation paths",
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------
    private static int CountOccurrences(string haystack, string needle)
    {
        int count = 0;
        int idx = 0;
        while (true)
        {
            idx = haystack.IndexOf(needle, idx, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) break;
            count++;
            idx += needle.Length;
        }
        return count;
    }
}
