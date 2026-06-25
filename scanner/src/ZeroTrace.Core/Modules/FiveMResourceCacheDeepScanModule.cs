using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMResourceCacheDeepScanModule : IScanModule
{
    public string Name => "FiveM-ResourceCache-Deep";
    public double Weight => 0.7;
    public int ParallelGroup => 4;

    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);

    // Known exploit resource name keywords
    private static readonly string[] ExploitResourceKeywords =
    {
        "exploit", "bypass", "inject", "hack", "cheat",
        "godmode", "noclip", "esp", "aimbot", "speedhack", "teleport",
    };

    // Known trainer/menu resource names
    private static readonly string[] TrainerResourceNames =
    {
        "menyoo", "simple-trainer", "enhanced-native-trainer", "lambda-menu",
        "runtime-menu", "server-side-trainer", "nativeui", "nativemenu",
    };

    // NUI JS patterns indicating exploit abuse
    private static readonly string[] NuiExploitPatterns =
    {
        "invokeNative",
        "__cfx_nui:",
        "fetch(\"http://localhost:",
        "fetch('http://localhost:",
        "crossOrigin",
        "crossorigin",
        "Access-Control-Allow-Origin",
    };

    // Known cheat/spoof display names
    private static readonly string[] SpoofDisplayNames =
    {
        "admin", "system", "server", "vmenu", "txadmin", "[staff]",
        "moderator", "developer", "dev", "[admin]", "[mod]",
        "owner", "[owner]", "root", "superadmin", "[dev]", "[developer]",
    };

    // FiveM CEF browser cache subdir name
    private const string BrowserCacheSubdir = "browser";

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Scanning FiveM cache directories...");
        await ScanCfxCacheStructureAsync(ctx, ct);

        ctx.Report(0.25, Name, "Scanning NUI cache for exploit patterns...");
        await ScanNuiCacheAsync(ctx, ct);

        ctx.Report(0.50, Name, "Scanning for trainer/menu resources...");
        await ScanTrainerResourcesAsync(ctx, ct);

        ctx.Report(0.70, Name, "Checking server fingerprint spoofing...");
        await ScanServerFingerprintSpoofingAsync(ctx, ct);

        ctx.Report(0.85, Name, "Checking anti-ban artifacts and registry...");
        await ScanAntiBanArtifactsAsync(ctx, ct);

        ctx.Report(1.0, Name, "FiveM resource cache deep scan complete");
    }

    // ------------------------------------------------------------------
    // 1. Cfx.re cache structure scan
    // ------------------------------------------------------------------
    private async Task ScanCfxCacheStructureAsync(ScanContext ctx, CancellationToken ct)
    {
        var cacheRoots = new[]
        {
            Path.Combine(AppData,      @"CitizenFX\cache"),
            Path.Combine(LocalAppData, @"FiveM\FiveM.app\cache"),
        };

        var cacheSubdirs = new[] { "game", "priv", "server-cache-priv" };

        int filesScanned = 0;
        const int maxFiles = 2000;

        foreach (var cacheRoot in cacheRoots)
        {
            if (!Directory.Exists(cacheRoot)) continue;

            foreach (var sub in cacheSubdirs)
            {
                if (ct.IsCancellationRequested) return;

                var subDir = Path.Combine(cacheRoot, sub);
                if (!Directory.Exists(subDir)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(subDir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    if (filesScanned >= maxFiles) return;

                    ctx.IncrementFiles();
                    filesScanned++;

                    var fileName = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    // Detect streamed .rpf patch files that replace game assets
                    if (ext.Equals(".rpf", StringComparison.OrdinalIgnoreCase))
                    {
                        var lowerName = fileName.ToLowerInvariant();
                        var hit = ExploitResourceKeywords.FirstOrDefault(k =>
                            lowerName.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (hit is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Exploit RPF in FiveM cache: {fileName}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Streamed RPF patch file '{fileName}' found in FiveM cache " +
                                           $"subdirectory '{sub}'. The filename matches the exploit keyword " +
                                           $"'{hit}'. Such files can replace game assets to inject aimbot " +
                                           "or ESP resources into the FiveM client.",
                                Detail   = $"Cache root: {cacheRoot} | Subdir: {sub} | Keyword: {hit}",
                            });
                            continue;
                        }
                    }

                    // For Lua/JS resource files, check content against exploit keywords
                    bool isScript = ext.Equals(".lua", StringComparison.OrdinalIgnoreCase)
                                 || ext.Equals(".js",  StringComparison.OrdinalIgnoreCase);

                    if (!isScript) continue;

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

                    var lower = content.ToLowerInvariant();
                    var matchedKeyword = ExploitResourceKeywords.FirstOrDefault(k =>
                        lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (matchedKeyword is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Exploit script in FiveM cache: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Script file '{fileName}' in FiveM cache directory '{sub}' contains " +
                                       $"the exploit keyword '{matchedKeyword}'. This indicates a cheat " +
                                       "resource may have been injected through the asset cache.",
                            Detail   = $"Cache root: {cacheRoot} | Keyword: {matchedKeyword}",
                        });
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 2. NUI exploit detection
    // ------------------------------------------------------------------
    private async Task ScanNuiCacheAsync(ScanContext ctx, CancellationToken ct)
    {
        var nuiCacheDir = Path.Combine(AppData, @"CitizenFX\nui-cache");
        if (!Directory.Exists(nuiCacheDir)) return;

        int filesScanned = 0;
        const int maxFiles = 2000;

        IEnumerable<string> jsFiles;
        try
        {
            jsFiles = Directory.EnumerateFiles(nuiCacheDir, "*.js", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in jsFiles)
        {
            if (ct.IsCancellationRequested) return;
            if (filesScanned >= maxFiles) return;

            ctx.IncrementFiles();
            filesScanned++;

            var fileName = Path.GetFileName(file);

            FileInfo fi;
            try { fi = new FileInfo(file); } catch { continue; }

            // Flag unusually large NUI JS files (>500KB)
            if (fi.Length > 500 * 1024)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Oversized NUI JS file: {fileName}",
                    Risk     = RiskLevel.Medium,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"JavaScript file '{fileName}' in the CitizenFX NUI cache is " +
                               $"{fi.Length / 1024}KB, which is unusually large for a NUI resource. " +
                               "Injected cheat UI bundles often embed obfuscated exploit code and " +
                               "are significantly larger than legitimate NUI resources.",
                    Detail   = $"File size: {fi.Length} bytes | Path: {file}",
                });
                continue;
            }

            if (fi.Length > 128 * 1024) continue;

            string content;
            try
            {
                using var sr = new StreamReader(file);
                content = await sr.ReadToEndAsync();
            }
            catch { continue; }

            var matchedPatterns = NuiExploitPatterns
                .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchedPatterns.Count == 0) continue;

            bool hasInvokeNative = content.Contains("invokeNative", StringComparison.OrdinalIgnoreCase);
            var risk = hasInvokeNative ? RiskLevel.Critical : RiskLevel.High;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"NUI exploit pattern in JS: {fileName}",
                Risk     = risk,
                Location = file,
                FileName = fileName,
                Reason   = $"JavaScript file '{fileName}' in the CitizenFX NUI cache contains " +
                           $"{matchedPatterns.Count} exploit pattern(s): " +
                           string.Join(", ", matchedPatterns.Take(4).Select(p => $"'{p}'")) +
                           ". These patterns indicate native invocation abuse, NUI callback " +
                           "exfiltration, or crossorigin bypass through the FiveM NUI bridge.",
                Detail   = $"Matched patterns: {string.Join(", ", matchedPatterns)}",
            });
        }
    }

    // ------------------------------------------------------------------
    // 3. FiveM trainer/menu detection
    // ------------------------------------------------------------------
    private async Task ScanTrainerResourcesAsync(ScanContext ctx, CancellationToken ct)
    {
        var cacheRoots = new[]
        {
            Path.Combine(AppData,      @"CitizenFX\cache"),
            Path.Combine(LocalAppData, @"FiveM\FiveM.app\cache"),
        };

        int filesScanned = 0;
        const int maxFiles = 2000;

        foreach (var cacheRoot in cacheRoots)
        {
            if (!Directory.Exists(cacheRoot)) continue;

            IEnumerable<string> allFiles;
            try
            {
                allFiles = Directory.EnumerateFiles(cacheRoot, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in allFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (filesScanned >= maxFiles) return;

                ctx.IncrementFiles();
                filesScanned++;

                var fileName = Path.GetFileName(file);
                var lowerName = fileName.ToLowerInvariant();
                var dirName   = Path.GetDirectoryName(file) ?? string.Empty;
                var lowerDir  = dirName.ToLowerInvariant();

                // Check if the containing resource directory name is a known trainer
                var trainerHit = TrainerResourceNames.FirstOrDefault(t =>
                    lowerDir.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                    lowerName.Contains(t, StringComparison.OrdinalIgnoreCase));

                if (trainerHit is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Trainer resource in FiveM cache: {trainerHit}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"File '{fileName}' is associated with the known trainer/menu resource " +
                                   $"'{trainerHit}' found in the FiveM cache. Trainer resources provide " +
                                   "in-game cheat menus with godmode, teleport, weapon, and vehicle spawning.",
                        Detail   = $"Trainer name matched: {trainerHit} | Path: {file}",
                    });
                    continue;
                }

                // Check __resource.lua and fxmanifest.lua for suspicious server-bypass patterns
                bool isManifest = lowerName.Equals("__resource.lua", StringComparison.OrdinalIgnoreCase)
                               || lowerName.Equals("fxmanifest.lua", StringComparison.OrdinalIgnoreCase);

                if (!isManifest) continue;

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

                bool hasNativeExec = content.Contains("exports.cfx_default", StringComparison.OrdinalIgnoreCase)
                                  || content.Contains("TriggerServerEvent", StringComparison.OrdinalIgnoreCase);

                // Detect tight-loop server event abuse pattern: setInterval or Citizen.CreateThread
                // calling TriggerServerEvent indicates server-side rate bypass
                bool hasTightLoop = (content.Contains("setInterval", StringComparison.OrdinalIgnoreCase) ||
                                     content.Contains("Citizen.CreateThread", StringComparison.OrdinalIgnoreCase))
                                 && content.Contains("TriggerServerEvent", StringComparison.OrdinalIgnoreCase);

                if (hasNativeExec || hasTightLoop)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Suspicious resource manifest: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Resource manifest '{fileName}' references server-side script patterns " +
                                   "that indicate unauthorized native execution or server event flooding. " +
                                   "This is characteristic of server-side trainer resources that bypass " +
                                   "FiveM's consent and permission model.",
                        Detail   = $"HasNativeExec: {hasNativeExec} | HasTightLoop: {hasTightLoop}",
                    });
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // 4. FiveM server fingerprint spoofing
    // ------------------------------------------------------------------
    private async Task ScanServerFingerprintSpoofingAsync(ScanContext ctx, CancellationToken ct)
    {
        var cfxAppData = Path.Combine(AppData, "CitizenFX");
        if (!Directory.Exists(cfxAppData)) return;

        if (ct.IsCancellationRequested) return;

        // Check banned_servers.json for suspicious modifications
        var bannedServersFile = Path.Combine(cfxAppData, "banned_servers.json");
        if (File.Exists(bannedServersFile))
        {
            ctx.IncrementFiles();
            try
            {
                var bsFi = new FileInfo(bannedServersFile);
                // A modified banned_servers.json (unusual: empty, tiny, or with 0-byte entries)
                // indicates the file has been tampered with to unban the user from servers.
                if (bsFi.Length == 0 || bsFi.Length < 10)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Empty or truncated banned_servers.json",
                        Risk     = RiskLevel.High,
                        Location = bannedServersFile,
                        FileName = "banned_servers.json",
                        Reason   = "The CitizenFX banned_servers.json file is empty or truncated. " +
                                   "This file is modified by anti-ban tools to remove server bans, " +
                                   "allowing access to servers from which the player has been banned.",
                        Detail   = $"File size: {bsFi.Length} bytes",
                    });
                }
            }
            catch { }
        }

        if (ct.IsCancellationRequested) return;

        // Check settings.json for spoofed display names
        var settingsFile = Path.Combine(cfxAppData, "settings.json");
        if (!File.Exists(settingsFile)) return;

        ctx.IncrementFiles();

        FileInfo settingsFi;
        try { settingsFi = new FileInfo(settingsFile); } catch { return; }
        if (settingsFi.Length > 128 * 1024) return;

        string settingsContent;
        try
        {
            using var sr = new StreamReader(settingsFile);
            settingsContent = await sr.ReadToEndAsync();
        }
        catch { return; }

        var lowerSettings = settingsContent.ToLowerInvariant();

        // Look for "displayName" key and check if its value is a known spoof name
        int displayNameIdx = lowerSettings.IndexOf("\"displayname\"", StringComparison.OrdinalIgnoreCase);
        if (displayNameIdx < 0)
            displayNameIdx = lowerSettings.IndexOf("displayname", StringComparison.OrdinalIgnoreCase);

        if (displayNameIdx >= 0)
        {
            // Extract a substring around the display name value for matching
            var slice = lowerSettings.Substring(
                displayNameIdx, Math.Min(100, lowerSettings.Length - displayNameIdx));

            var spoofHit = SpoofDisplayNames.FirstOrDefault(s =>
                slice.Contains(s, StringComparison.OrdinalIgnoreCase));

            if (spoofHit is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "FiveM settings.json contains spoofed display name",
                    Risk     = RiskLevel.Medium,
                    Location = settingsFile,
                    FileName = "settings.json",
                    Reason   = $"The CitizenFX settings.json 'displayName' field contains the value " +
                               $"'{spoofHit}', which is a commonly used spoof name to impersonate " +
                               "staff or administrators on FiveM servers. This is a social engineering " +
                               "and identity spoofing tactic used alongside cheat tools.",
                    Detail   = $"Matched spoof name: '{spoofHit}'",
                });
            }
        }
    }

    // ------------------------------------------------------------------
    // 5. Cfx.re anti-ban tools
    // ------------------------------------------------------------------
    private async Task ScanAntiBanArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        // Check AppData, Temp, and Downloads directories for HWID spoofer configs
        // referencing FiveM
        var searchDirs = new[]
        {
            AppData,
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        var spooferKeywords = new[] { "hwid", "spoofer", "cleaner" };
        int filesScanned = 0;
        const int maxFilesTotal = 2000;

        bool hitFileLimit = false;
        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (hitFileLimit) break;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> dirFiles;
            try
            {
                dirFiles = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in dirFiles)
            {
                if (ct.IsCancellationRequested) return;
                if (filesScanned >= maxFilesTotal) { hitFileLimit = true; break; }

                ctx.IncrementFiles();
                filesScanned++;

                var lowerName = Path.GetFileName(file).ToLowerInvariant();
                var spooferHit = spooferKeywords.FirstOrDefault(k =>
                    lowerName.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (spooferHit is null) continue;

                // Read the file to check if it references FiveM/CitizenFX
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

                bool referencesFiveM = content.Contains("FiveM",     StringComparison.OrdinalIgnoreCase)
                                    || content.Contains("CitizenFX",  StringComparison.OrdinalIgnoreCase)
                                    || content.Contains("cfx",        StringComparison.OrdinalIgnoreCase)
                                    || content.Contains("citizenfx",  StringComparison.OrdinalIgnoreCase);

                if (referencesFiveM)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"FiveM HWID spoofer config: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"File '{Path.GetFileName(file)}' has a name containing the spoofer " +
                                   $"keyword '{spooferHit}' and its content references FiveM/CitizenFX. " +
                                   "This is a strong indicator of a HWID spoofer configuration targeting " +
                                   "the FiveM anti-cheat system to evade hardware bans.",
                        Detail   = $"Spoofer keyword: {spooferHit} | References FiveM: true",
                    });
                }
            }
        }

        if (ct.IsCancellationRequested) return;

        // Check registry for CitizenFX override values
        ScanCitizenFxRegistry(ctx, ct);

        if (ct.IsCancellationRequested) return;

        // Check CEF browser cache for injected JS files
        await ScanCefBrowserCacheAsync(ctx, ct);
    }

    private static void ScanCitizenFxRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string regPath = @"Software\CitizenFX";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
            if (key is null) return;

            ctx.IncrementRegistryKeys();

            foreach (var valueName in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    var value = key.GetValue(valueName);
                    var lowerName = valueName.ToLowerInvariant();

                    // cacheSize set to 0 indicates cache poisoning or anti-cheat bypass
                    if (lowerName.Equals("cachesize", StringComparison.OrdinalIgnoreCase))
                    {
                        bool isZero = value is int intVal && intVal == 0
                                   || value is long longVal && longVal == 0L
                                   || (value is string strVal &&
                                       (strVal.Equals("0", StringComparison.OrdinalIgnoreCase)));
                        if (isZero)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "FiveM-ResourceCache-Deep",
                                Title    = "CitizenFX registry: cacheSize set to 0",
                                Risk     = RiskLevel.High,
                                Location = $@"HKCU\{regPath}\{valueName}",
                                Reason   = "The CitizenFX registry key 'cacheSize' is set to 0. " +
                                           "Anti-ban tools use this to prevent FiveM from caching " +
                                           "asset integrity data, disrupting the anti-cheat cache " +
                                           "validation mechanism.",
                                Detail   = $"Value: {value}",
                            });
                        }
                    }

                    // disableAntiCheat = 1 is a direct bypass flag
                    if (lowerName.Contains("disableanticheat", StringComparison.OrdinalIgnoreCase))
                    {
                        bool isEnabled = value is int iv && iv != 0
                                      || value is string sv &&
                                         (sv.Equals("1",    StringComparison.OrdinalIgnoreCase) ||
                                          sv.Equals("true", StringComparison.OrdinalIgnoreCase));
                        if (isEnabled)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "FiveM-ResourceCache-Deep",
                                Title    = "CitizenFX registry: disableAntiCheat enabled",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKCU\{regPath}\{valueName}",
                                Reason   = $"The CitizenFX registry value '{valueName}' is set to " +
                                           $"'{value}', which explicitly disables the FiveM anti-cheat " +
                                           "system. This is a deliberate bypass configuration inserted " +
                                           "by cheat or anti-ban software.",
                                Detail   = $"Value name: {valueName} | Value: {value}",
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private async Task ScanCefBrowserCacheAsync(ScanContext ctx, CancellationToken ct)
    {
        var browserCacheDir = Path.Combine(AppData, @"CitizenFX\cache", BrowserCacheSubdir);
        if (!Directory.Exists(browserCacheDir)) return;

        IEnumerable<string> jsFiles;
        try
        {
            jsFiles = Directory.EnumerateFiles(browserCacheDir, "*.js", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        int count = 0;
        foreach (var file in jsFiles)
        {
            if (ct.IsCancellationRequested) return;
            if (count >= 200) break;

            ctx.IncrementFiles();
            count++;

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

            // CEF injection: JS in the browser cache that calls native FiveM APIs
            bool hasNativeCall = content.Contains("invokeNative",  StringComparison.OrdinalIgnoreCase)
                              || content.Contains("__cfx_nui:",    StringComparison.OrdinalIgnoreCase)
                              || content.Contains("mp.trigger",    StringComparison.OrdinalIgnoreCase);

            if (hasNativeCall)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"CEF browser cache contains injected JS: {fileName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"JavaScript file '{fileName}' found in the CitizenFX CEF browser cache " +
                               "contains native FiveM API calls. This is a strong indicator of CEF " +
                               "injection — a technique used by cheats to execute privileged code " +
                               "through the FiveM browser sandbox.",
                    Detail   = $"Path: {file}",
                });
            }
        }
    }
}
