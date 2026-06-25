using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AltVDeepResourceScanModule : IScanModule
{
    public string Name => "AltV-Deep-Resource";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);

    // alt:V native functions that indicate cheat use in C# resources
    private static readonly string[] CSharpNativeCheatPatterns =
    {
        "AltV.Net.Natives.AltNatives.SetPlayerInvincible",
        "GetEntityCoords",
        "SetEntityCoords",
        "AddWeaponToEntity",
        "NetworkIsPlayerActive",
        "GetPlayerServerId",
        "exploit",
        "aimbot",
        "esp",
    };

    // Known cheat C# resource names
    private static readonly string[] KnownCheatCSharpResourceNames =
    {
        "CheatResource", "AimResource", "EspResource",
        "GodResource", "NoclipResource", "SpeedResource",
    };

    // alt:V JS/TS native patterns for cheat functionality
    private static readonly string[] JsNativeCheatPatterns =
    {
        "alt.natives.SetPlayerInvincible",
        "alt.natives.SetEntityCoords",
        "alt.natives.AddWeaponToEntity",
        "alt.natives.GiveWeapon",
        "alt.natives.SetVehicleEngineOn",
        "alt.natives.SetVehicleModKit",
        "alt.natives.NetworkExplodeVehicle",
        "alt.natives.GetEntityCoords",
        "SetPlayerInvincible",
        "SetEntityCoords",
        "AddWeaponToEntity",
        "NetworkExplodeVehicle",
    };

    // Obfuscation indicators in JS/TS
    private static readonly string[] ObfuscationPatterns =
    {
        "eval(",
        "Function(",
        "unescape(",
    };

    // Expected size range for altv.exe (in bytes): 5MB to 100MB
    private const long MinExpectedAltVExeSize = 5L * 1024 * 1024;
    private const long MaxExpectedAltVExeSize = 100L * 1024 * 1024;

    // Expected size range for libcef.dll: 200MB to 300MB
    private const long MinExpectedLibCefSize = 200L * 1024 * 1024;
    private const long MaxExpectedLibCefSize = 300L * 1024 * 1024;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Scanning alt:V resource directory structure...");
        await ScanResourceDirectoryStructureAsync(ctx, ct);

        ctx.Report(0.20, Name, "Scanning C# resources for native abuse...");
        await ScanCSharpResourcesAsync(ctx, ct);

        ctx.Report(0.45, Name, "Scanning JS/TS resources for cheat patterns...");
        await ScanJsResourcesAsync(ctx, ct);

        ctx.Report(0.70, Name, "Checking alt:V update/version manipulation...");
        await ScanUpdateManipulationAsync(ctx, ct);

        ctx.Report(0.83, Name, "Checking alt:V voice exploit artifacts...");
        ScanVoiceExploitArtifacts(ctx, ct);

        ctx.Report(0.92, Name, "Scanning alt:V CEF/browser injection...");
        await ScanCefBrowserInjectionAsync(ctx, ct);

        ctx.Report(1.0, Name, "alt:V deep resource scan complete");
    }

    // ------------------------------------------------------------------
    // 1. alt:V resource directory structure scan
    // ------------------------------------------------------------------
    private async Task ScanResourceDirectoryStructureAsync(ScanContext ctx, CancellationToken ct)
    {
        var resourceRoots = new[]
        {
            Path.Combine(AppData,      @"altv\resources"),
            Path.Combine(AppData,      @"alt-v\resources"),
            Path.Combine(LocalAppData, @"altv\resources"),
        };

        foreach (var root in resourceRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            string[] resourceDirs;
            try { resourceDirs = Directory.GetDirectories(root); }
            catch { continue; }

            foreach (var resourceDir in resourceDirs)
            {
                if (ct.IsCancellationRequested) return;

                var resourceName = Path.GetFileName(resourceDir);

                var cfgPath  = Path.Combine(resourceDir, "resource.cfg");
                var tomlPath = Path.Combine(resourceDir, "resource.toml");

                bool hasCfg  = File.Exists(cfgPath);
                bool hasToml = File.Exists(tomlPath);

                // Flag orphan resource directories (no manifest at all)
                if (!hasCfg && !hasToml)
                {
                    // Check if the directory actually contains scripts (not just assets)
                    bool hasScripts = false;
                    try
                    {
                        hasScripts = Directory.EnumerateFiles(resourceDir, "*.js").Any()
                                  || Directory.EnumerateFiles(resourceDir, "*.cs").Any()
                                  || Directory.EnumerateFiles(resourceDir, "*.ts").Any();
                    }
                    catch { }

                    if (hasScripts)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Orphan alt:V resource (no manifest): {resourceName}",
                            Risk     = RiskLevel.High,
                            Location = resourceDir,
                            FileName = resourceName,
                            Reason   = $"alt:V resource directory '{resourceName}' contains script files " +
                                       "but has no resource.cfg or resource.toml manifest. Unmanifested " +
                                       "resources are a common injection method — cheat scripts are placed " +
                                       "directly in the resource folder and loaded without server consent.",
                            Detail   = "No resource.cfg or resource.toml found",
                        });
                    }
                    continue;
                }

                // Read manifest files for suspicious type declarations and dependency patterns
                var manifestFile = hasToml ? tomlPath : cfgPath;
                ctx.IncrementFiles();

                FileInfo fi;
                try { fi = new FileInfo(manifestFile); } catch { continue; }
                if (fi.Length > 128 * 1024) continue;

                string manifestContent;
                try
                {
                    using var sr = new StreamReader(manifestFile);
                    manifestContent = await sr.ReadToEndAsync();
                }
                catch { continue; }

                // Check for suspicious main script paths in the manifest
                if (manifestContent.Contains("type", StringComparison.OrdinalIgnoreCase))
                {
                    bool isCSharp = manifestContent.Contains("csharp", StringComparison.OrdinalIgnoreCase);
                    bool isJs     = manifestContent.Contains("js",     StringComparison.OrdinalIgnoreCase);

                    // Check for suspicious main paths (absolute paths, temp paths, or traversal)
                    bool hasSuspiciousMain =
                        manifestContent.Contains("main", StringComparison.OrdinalIgnoreCase) &&
                        (manifestContent.Contains("../",       StringComparison.OrdinalIgnoreCase) ||
                         manifestContent.Contains("..\\",      StringComparison.OrdinalIgnoreCase) ||
                         manifestContent.Contains("%temp%",    StringComparison.OrdinalIgnoreCase) ||
                         manifestContent.Contains("\\temp\\",  StringComparison.OrdinalIgnoreCase));

                    if (hasSuspiciousMain)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"alt:V resource manifest has suspicious main path: {resourceName}",
                            Risk     = RiskLevel.High,
                            Location = manifestFile,
                            FileName = Path.GetFileName(manifestFile),
                            Reason   = $"The manifest for alt:V resource '{resourceName}' specifies a " +
                                       "main script path that uses directory traversal or references a " +
                                       "temporary/system path. This is used to load cheat scripts from " +
                                       "outside the resource directory sandbox.",
                            Detail   = $"Type: {(isCSharp ? "csharp" : isJs ? "js" : "unknown")} | Suspicious main path detected",
                        });
                    }
                }

                // Check deps/provides for non-official resource references
                if (manifestContent.Contains("deps", StringComparison.OrdinalIgnoreCase) ||
                    manifestContent.Contains("provides", StringComparison.OrdinalIgnoreCase))
                {
                    // Presence of exploit keywords in deps/provides fields
                    var exploitKeywords = new[] { "exploit", "cheat", "hack", "bypass", "inject" };
                    var depHit = exploitKeywords.FirstOrDefault(k =>
                        manifestContent.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (depHit is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"alt:V resource manifest references exploit dependency: {resourceName}",
                            Risk     = RiskLevel.High,
                            Location = manifestFile,
                            FileName = Path.GetFileName(manifestFile),
                            Reason   = $"The manifest for alt:V resource '{resourceName}' has a " +
                                       $"deps/provides entry containing the keyword '{depHit}'. This " +
                                       "indicates the resource declares a dependency on or provides an " +
                                       "exploit-related service to other resources.",
                            Detail   = $"Exploit keyword in deps/provides: '{depHit}'",
                        });
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 2. alt:V C# resource abuse
    // ------------------------------------------------------------------
    private async Task ScanCSharpResourcesAsync(ScanContext ctx, CancellationToken ct)
    {
        var resourceRoots = new[]
        {
            Path.Combine(AppData,      @"altv\resources"),
            Path.Combine(AppData,      @"alt-v\resources"),
            Path.Combine(LocalAppData, @"altv\resources"),
        };

        foreach (var root in resourceRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            string[] resourceDirs;
            try { resourceDirs = Directory.GetDirectories(root); }
            catch { continue; }

            foreach (var resourceDir in resourceDirs)
            {
                if (ct.IsCancellationRequested) return;

                var resourceName = Path.GetFileName(resourceDir);

                // Check if this is declared as a C# resource
                var tomlPath = Path.Combine(resourceDir, "resource.toml");
                var cfgPath  = Path.Combine(resourceDir, "resource.cfg");
                bool isCSharpResource = false;

                foreach (var mf in new[] { tomlPath, cfgPath })
                {
                    if (!File.Exists(mf)) continue;
                    try
                    {
                        using var sr = new StreamReader(mf);
                        var content = await sr.ReadToEndAsync();
                        if (content.Contains("csharp", StringComparison.OrdinalIgnoreCase))
                        {
                            isCSharpResource = true;
                            break;
                        }
                    }
                    catch { }
                }

                if (!isCSharpResource) continue;

                // Check if there is a known cheat resource name
                var cheatNameHit = KnownCheatCSharpResourceNames.FirstOrDefault(n =>
                    resourceName.Contains(n, StringComparison.OrdinalIgnoreCase));

                if (cheatNameHit is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Known cheat C# resource name: {resourceName}",
                        Risk     = RiskLevel.Critical,
                        Location = resourceDir,
                        FileName = resourceName,
                        Reason   = $"alt:V C# resource directory '{resourceName}' matches the known " +
                                   $"cheat resource name pattern '{cheatNameHit}'. These resource names " +
                                   "are associated with public alt:V cheat frameworks that expose " +
                                   "godmode, aimbot, ESP, and noclip via the C# resource API.",
                        Detail   = $"Matched cheat resource name: '{cheatNameHit}'",
                    });
                }

                // Check for compiled DLLs with accompanying PDB files (debug build injection)
                IEnumerable<string> dllFiles;
                try
                {
                    dllFiles = Directory.EnumerateFiles(resourceDir, "*.dll", SearchOption.AllDirectories);
                }
                catch { continue; }

                foreach (var dll in dllFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var pdbPath = Path.ChangeExtension(dll, ".pdb");
                    if (File.Exists(pdbPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"alt:V C# resource DLL with debug PDB: {Path.GetFileName(dll)}",
                            Risk     = RiskLevel.High,
                            Location = dll,
                            FileName = Path.GetFileName(dll),
                            Reason   = $"Compiled DLL '{Path.GetFileName(dll)}' in alt:V C# resource " +
                                       $"'{resourceName}' has an accompanying PDB debug symbols file. " +
                                       "Debug builds with PDB files are a strong indicator of cheat " +
                                       "injection — legitimate published resources ship release builds " +
                                       "without debug symbols.",
                            Detail   = $"PDB path: {pdbPath}",
                        });
                    }
                }

                // Scan C# source files for native abuse patterns
                IEnumerable<string> csFiles;
                try
                {
                    csFiles = Directory.EnumerateFiles(resourceDir, "*.cs", SearchOption.AllDirectories);
                }
                catch { continue; }

                foreach (var csFile in csFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    FileInfo fi;
                    try { fi = new FileInfo(csFile); } catch { continue; }
                    if (fi.Length > 128 * 1024) continue;

                    string csContent;
                    try
                    {
                        using var sr = new StreamReader(csFile);
                        csContent = await sr.ReadToEndAsync();
                    }
                    catch { continue; }

                    var matchedPatterns = CSharpNativeCheatPatterns
                        .Where(p => csContent.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedPatterns.Count == 0) continue;

                    var risk = matchedPatterns.Count >= 3 ? RiskLevel.Critical : RiskLevel.High;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"alt:V C# resource contains native cheat calls: {Path.GetFileName(csFile)}",
                        Risk     = risk,
                        Location = csFile,
                        FileName = Path.GetFileName(csFile),
                        Reason   = $"C# source file '{Path.GetFileName(csFile)}' in alt:V resource " +
                                   $"'{resourceName}' contains {matchedPatterns.Count} native cheat " +
                                   $"API pattern(s): " +
                                   string.Join(", ", matchedPatterns.Take(4).Select(p => $"'{p}'")) +
                                   ". These calls are used for godmode, teleportation, weapon spawning, " +
                                   "and ESP via the alt:V C# native wrapper.",
                        Detail   = $"Patterns ({matchedPatterns.Count}): {string.Join(", ", matchedPatterns.Take(5))}",
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 3. alt:V JS/TS cheat resource scan
    // ------------------------------------------------------------------
    private async Task ScanJsResourcesAsync(ScanContext ctx, CancellationToken ct)
    {
        var resourceRoots = new[]
        {
            Path.Combine(AppData,      @"altv\resources"),
            Path.Combine(AppData,      @"alt-v\resources"),
            Path.Combine(LocalAppData, @"altv\resources"),
        };

        int totalFilesScanned = 0;
        const int maxFiles = 500;

        foreach (var root in resourceRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> scriptFiles;
            try
            {
                // Enumerate both .js and .ts
                var jsFiles = Directory.EnumerateFiles(root, "*.js", SearchOption.AllDirectories);
                var tsFiles = Directory.EnumerateFiles(root, "*.ts", SearchOption.AllDirectories);
                scriptFiles = jsFiles.Concat(tsFiles);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (totalFilesScanned >= maxFiles) return;

                ctx.IncrementFiles();
                totalFilesScanned++;

                var fileName = Path.GetFileName(file);

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

                int patternCount = 0;
                var matchedPatterns = new List<string>();

                // Count native cheat pattern matches
                foreach (var pattern in JsNativeCheatPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        matchedPatterns.Add(pattern);
                        patternCount++;
                    }
                }

                // Check for alt.onServer handler with immediate native calls
                bool hasOnServerNative =
                    content.Contains("alt.onServer", StringComparison.OrdinalIgnoreCase) &&
                    (content.Contains("SetPlayerInvincible", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("SetEntityCoords",     StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("AddWeaponToEntity",   StringComparison.OrdinalIgnoreCase));
                if (hasOnServerNative) patternCount++;

                // Check for tight setInterval loop (<100ms)
                bool hasTightLoop = false;
                if (content.Contains("alt.emit", StringComparison.OrdinalIgnoreCase) &&
                    content.Contains("setInterval", StringComparison.OrdinalIgnoreCase))
                {
                    // Look for setInterval with a numeric argument <100
                    int siIdx = 0;
                    while (true)
                    {
                        siIdx = content.IndexOf("setInterval", siIdx, StringComparison.OrdinalIgnoreCase);
                        if (siIdx < 0) break;
                        // Find the comma before interval arg
                        int commaIdx = content.IndexOf(',', siIdx);
                        if (commaIdx >= 0 && commaIdx - siIdx < 200)
                        {
                            int closeIdx = content.IndexOf(')', commaIdx);
                            if (closeIdx > commaIdx && closeIdx - commaIdx < 20)
                            {
                                var intervalStr = content.Substring(commaIdx + 1, closeIdx - commaIdx - 1).Trim();
                                if (int.TryParse(intervalStr, out int intervalMs) && intervalMs < 100)
                                {
                                    hasTightLoop = true;
                                    break;
                                }
                            }
                        }
                        siIdx++;
                    }
                }
                if (hasTightLoop) patternCount++;

                // Check obfuscation indicators
                int obfuscationCount = 0;
                foreach (var obf in ObfuscationPatterns)
                {
                    if (content.Contains(obf, StringComparison.OrdinalIgnoreCase))
                        obfuscationCount++;
                }

                // Check for large base64 strings (>200 chars)
                bool hasLargeBase64 = ContainsLongBase64(content, 200);
                if (hasLargeBase64) obfuscationCount++;

                // Check for extended hex escape sequences (>10 in a row)
                bool hasHexEscapes = HasExtendedHexEscapes(content, 10);
                if (hasHexEscapes) obfuscationCount++;

                if (obfuscationCount >= 2) patternCount += 2;
                else if (obfuscationCount == 1) patternCount++;

                if (patternCount == 0) continue;

                var risk = patternCount >= 4 ? RiskLevel.Critical
                         : patternCount >= 2 ? RiskLevel.High
                         : RiskLevel.Medium;

                var reasons = new List<string>();
                if (matchedPatterns.Count > 0)
                    reasons.Add($"{matchedPatterns.Count} native cheat pattern(s)");
                if (hasOnServerNative)
                    reasons.Add("alt.onServer handler with immediate native calls");
                if (hasTightLoop)
                    reasons.Add("alt.emit in tight setInterval loop (<100ms)");
                if (obfuscationCount > 0)
                    reasons.Add($"{obfuscationCount} obfuscation indicator(s)");

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"alt:V JS/TS cheat resource: {fileName}",
                    Risk     = risk,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Script file '{fileName}' in the alt:V resources directory has " +
                               $"{patternCount} cheat signal(s): " +
                               string.Join("; ", reasons) +
                               ". These patterns indicate godmode, ESP, aimbot, or obfuscated cheat " +
                               "logic implemented through the alt:V JS/TS resource API.",
                    Detail   = $"Total signals: {patternCount} | " +
                               $"Patterns: {string.Join(", ", matchedPatterns.Take(5))}",
                });
            }
        }
    }

    // ------------------------------------------------------------------
    // 4. alt:V update/version manipulation
    // ------------------------------------------------------------------
    private async Task ScanUpdateManipulationAsync(ScanContext ctx, CancellationToken ct)
    {
        var altVDirs = new[]
        {
            Path.Combine(AppData,      "altv"),
            Path.Combine(AppData,      "alt-v"),
            Path.Combine(LocalAppData, "altv"),
        };

        foreach (var altVDir in altVDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(altVDir)) continue;

            // Check update.json / altv.json for branch manipulation
            foreach (var jsonName in new[] { "update.json", "altv.json" })
            {
                var jsonPath = Path.Combine(altVDir, jsonName);
                if (!File.Exists(jsonPath)) continue;

                ctx.IncrementFiles();

                FileInfo fi;
                try { fi = new FileInfo(jsonPath); } catch { continue; }
                if (fi.Length > 128 * 1024) continue;

                string content;
                try
                {
                    using var sr = new StreamReader(jsonPath);
                    content = await sr.ReadToEndAsync();
                }
                catch { continue; }

                bool hasBranchKey = content.Contains("branch", StringComparison.OrdinalIgnoreCase);
                if (hasBranchKey)
                {
                    bool isRelease = content.Contains("\"release\"", StringComparison.OrdinalIgnoreCase)
                                  || content.Contains("'release'",  StringComparison.OrdinalIgnoreCase);
                    bool isRc      = content.Contains("\"rc\"",     StringComparison.OrdinalIgnoreCase)
                                  || content.Contains("'rc'",       StringComparison.OrdinalIgnoreCase);

                    if (!isRelease && !isRc)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"alt:V {jsonName} has non-standard branch",
                            Risk     = RiskLevel.Medium,
                            Location = jsonPath,
                            FileName = jsonName,
                            Reason   = $"The alt:V configuration file '{jsonName}' specifies a branch " +
                                       "that is not 'release' or 'rc'. Non-standard branches may indicate " +
                                       "a modified or cheat-patched alt:V client that disables integrity " +
                                       "checks during the update process.",
                            Detail   = "Branch is not 'release' or 'rc'",
                        });
                    }
                }
            }

            // Check for binary patch files in the alt:V directory
            foreach (var patchExt in new[] { "*.patch", "*.diff" })
            {
                if (ct.IsCancellationRequested) return;

                IEnumerable<string> patchFiles;
                try
                {
                    patchFiles = Directory.EnumerateFiles(altVDir, patchExt, SearchOption.TopDirectoryOnly);
                }
                catch { continue; }

                foreach (var pf in patchFiles)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Binary patch file in alt:V directory: {Path.GetFileName(pf)}",
                        Risk     = RiskLevel.Medium,
                        Location = pf,
                        FileName = Path.GetFileName(pf),
                        Reason   = $"A binary patch file '{Path.GetFileName(pf)}' was found in the " +
                                   "alt:V installation directory. Patch files are not distributed by " +
                                   "alt:V and indicate manual binary modification — a technique used " +
                                   "to patch anti-cheat validation out of the alt:V client binary.",
                        Detail   = $"Patch file path: {pf}",
                    });
                }
            }

            // Check altv.exe for unusual file size
            var altVExePath = Path.Combine(altVDir, "altv.exe");
            if (File.Exists(altVExePath))
            {
                ctx.IncrementFiles();
                try
                {
                    var exeFi = new FileInfo(altVExePath);
                    if (exeFi.Length < MinExpectedAltVExeSize || exeFi.Length > MaxExpectedAltVExeSize)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "altv.exe has unexpected file size",
                            Risk     = RiskLevel.Medium,
                            Location = altVExePath,
                            FileName = "altv.exe",
                            Reason   = $"The alt:V launcher executable 'altv.exe' has an unusual size " +
                                       $"of {exeFi.Length / 1024 / 1024}MB (expected between " +
                                       $"{MinExpectedAltVExeSize / 1024 / 1024}MB and " +
                                       $"{MaxExpectedAltVExeSize / 1024 / 1024}MB). This may indicate " +
                                       "the binary has been patched or replaced by a modified version " +
                                       "that disables anti-cheat functionality.",
                            Detail   = $"Actual size: {exeFi.Length} bytes",
                        });
                    }
                }
                catch { }
            }

            // Check data\ directory for modified game data files
            var dataDir = Path.Combine(altVDir, "data");
            if (!Directory.Exists(dataDir)) continue;

            IEnumerable<string> dataFiles;
            try
            {
                dataFiles = Directory.EnumerateFiles(dataDir, "*", SearchOption.AllDirectories);
            }
            catch { continue; }

            int dataFileCount = 0;
            foreach (var df in dataFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (dataFileCount >= 100) break;
                dataFileCount++;
                ctx.IncrementFiles();

                var dfName = Path.GetFileName(df).ToLowerInvariant();
                // Flag non-standard files in data directory (not .dat, .bin, .json, .xml)
                var dfExt = Path.GetExtension(df).ToLowerInvariant();
                bool isKnownDataType = dfExt is ".dat" or ".bin" or ".json" or ".xml"
                                                or ".meta" or ".ymt" or ".rpf";
                if (!isKnownDataType)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Unexpected file type in alt:V data directory: {dfName}",
                        Risk     = RiskLevel.Medium,
                        Location = df,
                        FileName = dfName,
                        Reason   = $"File '{dfName}' with extension '{dfExt}' was found in the alt:V " +
                                   "data directory. This directory should only contain game data files " +
                                   "(.dat, .bin, .json, .xml, .meta, .ymt, .rpf). Unexpected file types " +
                                   "may indicate modified or injected data.",
                        Detail   = $"Extension: {dfExt}",
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. alt:V voice/VoIP exploit artifacts
    // ------------------------------------------------------------------
    private static void ScanVoiceExploitArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var altVDirs = new[]
        {
            Path.Combine(AppData,      "altv"),
            Path.Combine(AppData,      "alt-v"),
            Path.Combine(LocalAppData, "altv"),
        };

        foreach (var altVDir in altVDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(altVDir)) continue;

            var voiceDir = Path.Combine(altVDir, "voice");

            // Check for modified voice.dll
            var voiceDll = Path.Combine(altVDir, "voice.dll");
            if (!File.Exists(voiceDll))
                voiceDll = Path.Combine(voiceDir, "voice.dll");

            if (File.Exists(voiceDll))
            {
                ctx.IncrementFiles();
                // A modified voice.dll would be flagged by the authenticode check elsewhere;
                // here we additionally flag if it exists in the voice subdirectory
                // (legitimate alt:V ships voice.dll in root, not in voice/)
                if (voiceDll.Contains($"{Path.DirectorySeparatorChar}voice{Path.DirectorySeparatorChar}",
                    StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "voice.dll in unexpected location: altv\\voice\\",
                        Risk     = RiskLevel.High,
                        Location = voiceDll,
                        FileName = "voice.dll",
                        Reason   = "The file 'voice.dll' was found inside the alt:V 'voice' " +
                                   "subdirectory rather than the alt:V root. Legitimate alt:V ships " +
                                   "voice.dll in the root directory. A voice.dll placed in the voice " +
                                   "subdirectory may be a modified replacement targeting VoIP exploit " +
                                   "anti-cheat hooks.",
                        Detail   = $"Unexpected path: {voiceDll}",
                    });
                }
            }

            // Check for modified voice-server.js
            var voiceServerJs = Path.Combine(voiceDir, "voice-server.js");
            if (File.Exists(voiceServerJs))
            {
                ctx.IncrementFiles();
                // Flag its presence in voice dir as it shouldn't be user-editable
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "voice-server.js present in alt:V voice directory",
                    Risk     = RiskLevel.Medium,
                    Location = voiceServerJs,
                    FileName = "voice-server.js",
                    Reason   = "The file 'voice-server.js' was found in the alt:V voice directory. " +
                               "This file is not distributed by alt:V and may be a modified voice " +
                               "server component that disables VoIP anti-cheat hooks or injects " +
                               "data into the voice communication channel.",
                    Detail   = $"Path: {voiceServerJs}",
                });
            }
        }
    }

    // ------------------------------------------------------------------
    // 6. alt:V CEF/browser injection
    // ------------------------------------------------------------------
    private async Task ScanCefBrowserInjectionAsync(ScanContext ctx, CancellationToken ct)
    {
        var altVDirs = new[]
        {
            Path.Combine(AppData,      "altv"),
            Path.Combine(AppData,      "alt-v"),
            Path.Combine(LocalAppData, "altv"),
        };

        foreach (var altVDir in altVDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(altVDir)) continue;

            // Check libcef.dll size
            var libCefPath = Path.Combine(altVDir, "libcef.dll");
            if (File.Exists(libCefPath))
            {
                ctx.IncrementFiles();
                try
                {
                    var libCefFi = new FileInfo(libCefPath);
                    if (libCefFi.Length < MinExpectedLibCefSize || libCefFi.Length > MaxExpectedLibCefSize)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "libcef.dll has unexpected file size in alt:V directory",
                            Risk     = RiskLevel.Medium,
                            Location = libCefPath,
                            FileName = "libcef.dll",
                            Reason   = $"The Chromium Embedded Framework library 'libcef.dll' in the " +
                                       $"alt:V directory has an unusual size of " +
                                       $"{libCefFi.Length / 1024 / 1024}MB (expected between " +
                                       $"{MinExpectedLibCefSize / 1024 / 1024}MB and " +
                                       $"{MaxExpectedLibCefSize / 1024 / 1024}MB). A size outside this " +
                                       "range suggests the file has been replaced or patched, which is " +
                                       "a method used to inject code into the alt:V CEF browser sandbox.",
                            Detail   = $"Actual size: {libCefFi.Length} bytes",
                        });
                    }
                }
                catch { }
            }

            // Scan cache and data directories for JS files with 'native' in filename
            var cefSearchDirs = new[]
            {
                Path.Combine(altVDir, "cache"),
                Path.Combine(altVDir, "data"),
            };

            foreach (var cefDir in cefSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(cefDir)) continue;

                IEnumerable<string> jsFiles;
                try
                {
                    jsFiles = Directory.EnumerateFiles(cefDir, "*.js", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                int count = 0;
                foreach (var jsFile in jsFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    if (count >= 200) break;

                    ctx.IncrementFiles();
                    count++;

                    var jsName = Path.GetFileName(jsFile);

                    // Flag JS files with 'native' in the filename
                    if (jsName.Contains("native", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"JS file with 'native' in name in alt:V CEF cache: {jsName}",
                            Risk     = RiskLevel.High,
                            Location = jsFile,
                            FileName = jsName,
                            Reason   = $"JavaScript file '{jsName}' with 'native' in its filename was " +
                                       $"found in the alt:V CEF cache/data directory '{Path.GetFileName(cefDir)}'. " +
                                       "Legitimate CEF cache files do not include 'native' in their names. " +
                                       "This is a characteristic artifact of CEF injection scripts that " +
                                       "call alt:V native functions from within the browser sandbox.",
                            Detail   = $"CEF directory: {cefDir}",
                        });
                        continue;
                    }

                    // Also scan content for native invocation patterns
                    FileInfo fi;
                    try { fi = new FileInfo(jsFile); } catch { continue; }
                    if (fi.Length > 128 * 1024) continue;

                    string jsContent;
                    try
                    {
                        using var sr = new StreamReader(jsFile);
                        jsContent = await sr.ReadToEndAsync();
                    }
                    catch { continue; }

                    bool hasCefNativeCall =
                        jsContent.Contains("alt.natives.",  StringComparison.OrdinalIgnoreCase) ||
                        jsContent.Contains("invokeNative",  StringComparison.OrdinalIgnoreCase) ||
                        jsContent.Contains("alt.emit(",     StringComparison.OrdinalIgnoreCase) ||
                        jsContent.Contains("alt.onServer(", StringComparison.OrdinalIgnoreCase);

                    if (hasCefNativeCall)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Injected JS with native calls in alt:V CEF cache: {jsName}",
                            Risk     = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = jsName,
                            Reason   = $"JavaScript file '{jsName}' in the alt:V CEF cache/data directory " +
                                       "contains alt:V native API calls. JS files in the CEF cache should " +
                                       "not contain game native calls — this is a strong indicator of CEF " +
                                       "injection used to execute privileged alt:V operations from within " +
                                       "the browser sandbox.",
                            Detail   = $"CEF directory: {cefDir}",
                        });
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    // Check if content contains a base64-encoded string longer than minLength characters
    private static bool ContainsLongBase64(string content, int minLength)
    {
        const string b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        int run = 0;
        foreach (char c in content)
        {
            if (b64Chars.IndexOf(c) >= 0)
            {
                run++;
                if (run >= minLength) return true;
            }
            else
            {
                run = 0;
            }
        }
        return false;
    }

    // Check if content contains more than minCount consecutive \x hex escape sequences
    private static bool HasExtendedHexEscapes(string content, int minCount)
    {
        int count = 0;
        int i = 0;
        while (i < content.Length - 3)
        {
            if (content[i] == '\\' && content[i + 1] == 'x' &&
                IsHex(content[i + 2]) && IsHex(content[i + 3]))
            {
                count++;
                if (count >= minCount) return true;
                i += 4;
            }
            else
            {
                count = 0;
                i++;
            }
        }
        return false;
    }

    private static bool IsHex(char c) =>
        (c >= '0' && c <= '9') ||
        (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F');
}
