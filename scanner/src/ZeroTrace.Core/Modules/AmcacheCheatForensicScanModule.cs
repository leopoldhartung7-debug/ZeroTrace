using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AmcacheCheatForensicScanModule : IScanModule
{
    public string Name => "Amcache Cheat Execution Forensics";
    public double Weight => 4.7;
    public int ParallelGroup => 5;

    // -------------------------------------------------------------------------
    // Path constants
    // -------------------------------------------------------------------------

    private static readonly string WindowsDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private static readonly string AmcacheHivePath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"AppCompat\Programs\Amcache.hve");

    private static readonly string AmcacheHiveLog1 =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"AppCompat\Programs\Amcache.hve.LOG1");

    private static readonly string AmcacheHiveLog2 =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"AppCompat\Programs\Amcache.hve.LOG2");

    private static readonly string AppCompatProgramsDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            @"AppCompat\Programs");

    private static readonly string AppCompatCacheDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Microsoft\Windows\Caches");

    // -------------------------------------------------------------------------
    // Registry key paths
    // -------------------------------------------------------------------------

    private const string AppCompatCacheKey =
        @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";

    private const string BamStateKey =
        @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";

    private const string DamStateKey =
        @"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings";

    private const string UserAssistGuidRoot =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

    private const string RecentDocsRoot =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";

    // Legacy AppCompatFlags (Windows 8 / pre-Amcache.hve systems)
    private const string LegacyAmcacheLookupKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache\InventoryApplicationFile";

    // AppCompatFlags compatibility layer key
    private const string AppCompatFlagsLayersKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";

    // -------------------------------------------------------------------------
    // Cheat path keyword list
    // -------------------------------------------------------------------------

    private static readonly string[] CheatPathKeywords = new[]
    {
        // Injectors
        "injector",
        "xenos",
        "ghinjector",
        "extremeinjector",
        "winject",
        "dllinjector",
        "manualmapper",
        "reflectiveinject",
        "moduleinject",
        "memoryinjector",
        "injectdll",
        "ghostinject",
        "syringe",
        "apcinjector",
        "earlybird",
        "processhollow",

        // HWID spoofers
        "spoofer",
        "hwid",
        "hwidspoofer",
        "phantomspoofer",
        "crowspoofer",
        "kspoofer",
        "absolutespoofer",
        "tsspoofer",
        "banbypass",
        "spoofandplay",
        "hwid_changer",
        "hwid-bypass",
        "hwidchanger",
        "hwidbypass",
        "serialspoofer",
        "macspoofer",
        "diskspoofer",
        "cpuidspoofer",

        // Bypass / driver tools
        "bypass",
        "kdmapper",
        "drvmap",
        "drivermapper",
        "byovd",
        "eacbypass",
        "bebypass",
        "vanguardbypass",
        "faceitbypass",
        "vacbypass",
        "esbypass",
        "acbypass",
        "battleeyebypass",
        "kernelbypass",
        "kernelmapper",
        "dsebypass",
        "dsefixer",
        "patchguardbypass",
        "ringzeroaccess",

        // Cheat loaders / droppers
        "cheatloader",
        "hackloader",
        "gameloader",
        "payloadloader",
        "steamloader",
        "cheatinjector",
        "cheatlauncher",
        "shellcodeloader",
        "crypterloader",

        // Generic cheat keywords
        "cheat",
        "hack",
        "aimbot",
        "esp",
        "trainer",
        "loader",
        "exploit",
        "modmenu",
        "godmode",
        "bhop",
        "triggerbot",
        "noclip",
        "speedhack",
        "wallhack",
        "spinbot",
        "aimassist",
        "autoshoot",
        "recoil",
        "silentaim",
        "ragebot",
        "hvhbot",
        "closetcheat",
        "legithack",

        // GTA V menus
        "menyoo",
        "stand",
        "cherax",
        "2take1",
        "kiddion",
        "ozark",
        "midnight",
        "orbital",
        "bigbasev",
        "nativetrainer",
        "gtavmenu",
        "modmenu",

        // FiveM cheats
        "eulen",
        "lynx",
        "impulse",
        "phantom",
        "disturbed",
        "hamster",
        "nighthawk",
        "epsilon",
        "fivemcheat",
        "fivemhack",

        // CS2/CSGO cheats
        "aimware",
        "skeet",
        "gamesense",
        "onetap",
        "fatality",
        "nixware",
        "neverlose",
        "interium",
        "lhook",

        // Roblox exploits
        "synapse",
        "synapsex",
        "krnl",
        "fluxus",
        "scriptware",
        "celery",
        "arceus",
        "oxygen",
        "evon",

        // DMA tools
        "pcileech",
        "memproc",
        "dmaread",
        "physmem",
        "fpgaread",
        "dmawrite",

        // Crypto miners
        "xmrig",
        "xmrigcc",
        "phoenixminer",
        "nbminer",
        "lolminer",
        "gminer",
        "ccminer",
        "srbminer",
        "cpuminer",
        "cryptominer",
        "nicehashminer",

        // RATs and stealers
        "asyncrat",
        "njrat",
        "dcrat",
        "redline",
        "raccoon",
        "vidar",
        "amadey",
        "quasar",
        "nanocore",
        "remcos",
        "warzone",
        "formbook",
        "azorult",
        "arkei",
        "masslogger",
        "orcusrat",
        "limerat",
        "bitrat",
        "xworm",
        "stealc",
        "lumma",
        "rhadamanthys",
        "whitesnake",
        "meduza",

        // Analysis tools (dual-use)
        "reclass",
        "cheatengine",
        "processhacker",
        "x64dbg",
        "x32dbg",
        "scyllahide",
        "titanhtide",
        "artmoney",
        "tsearch",
    };

    // Suspicious filesystem locations for BAM/DAM path anomaly detection
    private static readonly string[] SuspiciousLocations = new[]
    {
        @"\temp\",
        @"\tmp\",
        @"\appdata\roaming\",
        @"\downloads\",
        @"\appdata\local\temp\",
        @"\users\public\",
        @"\programdata\temp\",
        @"\recycle",
        @"\$recycle.bin\",
        @"\windows\temp\",
    };

    private static readonly string[] ExecutableExtensions = new[]
    {
        ".exe", ".dll", ".sys", ".drv", ".scr", ".cpl"
    };

    // -------------------------------------------------------------------------
    // IScanModule
    // -------------------------------------------------------------------------

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ctx.Report(0.0, "Initialising Amcache forensics");

        await Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            ctx.Report(0.05, "Checking Amcache.hve file");
            CheckAmcacheHivePresence(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.15, "Scanning AppCompatCache registry");
            CheckAppCompatCacheRegistry(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.22, "Scanning AppCompat cache files");
            ScanAppCompatCacheFiles(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.28, "Scanning legacy AppCompatFlags");
            ScanLegacyAppCompatFlags(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.35, "Scanning AppCompatFlags compatibility layers");
            ScanAppCompatLayers(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.42, "Scanning BAM registry");
            ScanActivityMonitorRegistry(ctx, BamStateKey, "BAM");

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.58, "Scanning DAM registry");
            ScanActivityMonitorRegistry(ctx, DamStateKey, "DAM");

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.67, "Scanning UserAssist");
            ScanUserAssist(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.82, "Scanning RecentDocs");
            ScanRecentDocs(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.93, "Scanning AppCompatFlags Telemetry");
            ScanAppCompatTelemetry(ctx);

            ctx.Report(1.0, "Amcache forensics complete");
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Amcache.hve Presence Check
    // -------------------------------------------------------------------------

    private void CheckAmcacheHivePresence(ScanContext ctx)
    {
        if (File.Exists(AmcacheHivePath))
        {
            ctx.IncrementFiles();
            var hiveInfo = new FileInfo(AmcacheHivePath);
            var age = DateTime.UtcNow - hiveInfo.LastWriteTimeUtc;

            if (age.TotalDays > 90)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Amcache.hve Not Updated in 90+ Days",
                    Risk = RiskLevel.Medium,
                    Location = AmcacheHivePath,
                    FileName = "Amcache.hve",
                    Reason = "The Amcache.hve file has not been modified in over 90 days. Active systems update " +
                             "this hive every time a new program runs. Stale timestamps may indicate the hive " +
                             "was replaced with an older clean copy, or AppCompat tracking was disabled.",
                    Detail = $"Last write: {hiveInfo.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC | " +
                             $"Age: {(int)age.TotalDays} days | Size: {hiveInfo.Length} bytes"
                });
            }

            // A suspiciously tiny Amcache.hve (under 64 KB) on what would be an active system
            // may indicate it was deleted and recreated as an empty hive.
            if (hiveInfo.Length < 65536 && age.TotalDays < 7)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Amcache.hve Abnormally Small",
                    Risk = RiskLevel.High,
                    Location = AmcacheHivePath,
                    FileName = "Amcache.hve",
                    Reason = "Amcache.hve is smaller than 64 KB despite being recently written. " +
                             "A freshly cleared hive or one created by anti-cheat bypass tools to replace " +
                             "the original will appear small. Active systems accumulate many MB in this hive.",
                    Detail = $"Size: {hiveInfo.Length} bytes | Last write: {hiveInfo.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC"
                });
            }
        }
        else
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Amcache.hve File Missing",
                Risk = RiskLevel.High,
                Location = AmcacheHivePath,
                FileName = "Amcache.hve",
                Reason = "The Amcache.hve registry hive is absent. This hive records all program executions " +
                         "including SHA-1 hashes of executables. Its absence strongly suggests it was " +
                         "manually deleted to erase program execution history — a common HWID spoofer and " +
                         "cheat bypass operation.",
                Detail = $"Expected at: {AmcacheHivePath}"
            });
        }

        // Check transaction logs
        bool log1Exists = File.Exists(AmcacheHiveLog1);
        bool log2Exists = File.Exists(AmcacheHiveLog2);

        if (File.Exists(AmcacheHivePath) && (!log1Exists || !log2Exists))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Amcache Transaction Log(s) Missing",
                Risk = RiskLevel.Low,
                Location = AppCompatProgramsDir,
                FileName = "Amcache.hve.LOG1 / LOG2",
                Reason = "One or both Amcache transaction log files are missing despite the hive file being present. " +
                         "These logs are required for hive consistency and are absent only when the logs were " +
                         "selectively deleted, the hive was replaced, or the filesystem is corrupted.",
                Detail = $"LOG1 present: {log1Exists} | LOG2 present: {log2Exists}"
            });
        }

        // Scan AppCompatPrograms dir for unexpected hive-like files
        if (!Directory.Exists(AppCompatProgramsDir)) return;

        try
        {
            foreach (string f in Directory.EnumerateFiles(AppCompatProgramsDir, "*", SearchOption.TopDirectoryOnly))
            {
                ctx.IncrementFiles();
                string fname = Path.GetFileName(f);
                if (fname.Equals("Amcache.hve", StringComparison.OrdinalIgnoreCase)) continue;
                if (fname.StartsWith("Amcache.hve.", StringComparison.OrdinalIgnoreCase)) continue;

                if (fname.Contains("Amcache", StringComparison.OrdinalIgnoreCase) ||
                    (fname.EndsWith(".hve", StringComparison.OrdinalIgnoreCase) && !fname.StartsWith("Amcache", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unexpected File in AppCompat\\Programs: {fname}",
                        Risk = RiskLevel.Medium,
                        Location = f,
                        FileName = fname,
                        Reason = "An unexpected file resembling an Amcache hive or export was found in the " +
                                 "AppCompat\\Programs directory. This may be an exported copy, a backup created " +
                                 "by bypass tools, or a tampered replacement hive.",
                        Detail = $"File: {f}"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Skip if access denied
        }
        catch (IOException)
        {
            // Skip I/O errors
        }
    }

    // -------------------------------------------------------------------------
    // AppCompatCache (ShimCache)
    // -------------------------------------------------------------------------

    private void CheckAppCompatCacheRegistry(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(AppCompatCacheKey, writable: false);
            if (key == null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "AppCompatCache Registry Key Missing",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{AppCompatCacheKey}",
                    Reason = "The AppCompatCache (ShimCache) registry key is absent. This key records all " +
                             "executed programs and is cleared by some cheat bypass and anti-ban tools as a " +
                             "standard part of their anti-forensics routine.",
                    Detail = $"Expected at HKLM\\{AppCompatCacheKey}"
                });
                return;
            }

            ctx.IncrementRegistryKeys();

            byte[]? cacheValue = key.GetValue("AppCompatCache") as byte[];

            if (cacheValue == null || cacheValue.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "AppCompatCache (ShimCache) Value Empty or Deleted",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{AppCompatCacheKey}",
                    FileName = "AppCompatCache",
                    Reason = "The AppCompatCache binary value is absent or zero-length. Clearing ShimCache " +
                             "erases the record of all previously executed programs. This is a documented " +
                             "technique used by HWID spoofers and anti-cheat bypass tools.",
                    Detail = "Value 'AppCompatCache' under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache is null or zero-length."
                });
            }
            else
            {
                // ShimCache header on Windows 10+ is 0x34 bytes; each entry is approximately 88 bytes.
                // A cache smaller than 200 bytes likely contains only the header with 0-1 entries.
                if (cacheValue.Length < 200)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "AppCompatCache (ShimCache) Abnormally Small",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKLM\{AppCompatCacheKey}",
                        FileName = "AppCompatCache",
                        Reason = "The AppCompatCache binary value is present but unusually small. " +
                                 "Normal active systems accumulate hundreds of ShimCache entries over time. " +
                                 "A near-empty cache suggests it was recently cleared.",
                        Detail = $"Cache size: {cacheValue.Length} bytes (expected several KB on active systems)"
                    });
                }
                else
                {
                    // Cache is present and reasonably sized — scan its content for cheat executable names.
                    // The ShimCache on Win10+ stores NT device paths as UTF-16LE strings.
                    string cacheContent = System.Text.Encoding.Unicode.GetString(cacheValue);
                    ScanShimCacheContent(ctx, cacheContent, cacheValue.Length);
                }

                ctx.IncrementRegistryKeys();
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "AppCompatCache Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKLM\{AppCompatCacheKey}",
                Reason = "Access denied reading AppCompatCache registry.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "AppCompatCache Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKLM\{AppCompatCacheKey}",
                Reason = "I/O error reading AppCompatCache registry.",
                Detail = ex.Message
            });
        }
    }

    // Search the decoded ShimCache binary blob for cheat-related executable paths.
    private void ScanShimCacheContent(ScanContext ctx, string cacheContent, int cacheBytes)
    {
        foreach (string kw in CheatPathKeywords)
        {
            if (!cacheContent.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

            // Try to extract a context snippet around the match
            int idx = cacheContent.IndexOf(kw, StringComparison.OrdinalIgnoreCase);
            int snippetStart = Math.Max(0, idx - 40);
            int snippetEnd = Math.Min(cacheContent.Length, idx + kw.Length + 80);
            string snippet = cacheContent.Substring(snippetStart, snippetEnd - snippetStart)
                                         .Replace('\0', ' ').Trim();
            if (snippet.Length > 150) snippet = snippet.Substring(0, 150) + "...";

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"ShimCache Records Cheat Executable: '{kw}'",
                Risk = RiskLevel.Critical,
                Location = $@"HKLM\{AppCompatCacheKey}",
                FileName = "AppCompatCache",
                Reason = $"The AppCompatCache (ShimCache) binary value contains a path matching the cheat-related " +
                         $"keyword '{kw}'. ShimCache is written at shutdown and records every executable that was " +
                         "ever run on the system. This entry persists after the cheat executable is deleted.",
                Detail = $"Keyword: {kw} | Cache size: {cacheBytes} bytes | Path context: {snippet}"
            });
            break; // One finding per pass is sufficient; individual keyword hits can produce their own
        }
    }

    // -------------------------------------------------------------------------
    // AppCompat Cache Files
    // -------------------------------------------------------------------------

    private void ScanAppCompatCacheFiles(ScanContext ctx)
    {
        if (!Directory.Exists(AppCompatCacheDir)) return;

        try
        {
            foreach (string f in Directory.EnumerateFiles(AppCompatCacheDir, "*", SearchOption.TopDirectoryOnly))
            {
                ctx.IncrementFiles();
                string fname = Path.GetFileName(f);
                string fnLower = fname.ToLowerInvariant();

                if (fnLower.EndsWith(".db", StringComparison.OrdinalIgnoreCase))
                {
                    var fi = new FileInfo(f);
                    if (fi.Length == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Empty AppCompat Cache File: {fname}",
                            Risk = RiskLevel.Medium,
                            Location = f,
                            FileName = fname,
                            Reason = "An AppCompatCache database file in the Windows Caches directory is zero bytes. " +
                                     "This may indicate the cache was deliberately wiped to erase execution history.",
                            Detail = $"Path: {f} | Last write: {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Skip access-denied directories
        }
        catch (IOException)
        {
            // Skip I/O errors
        }
    }

    // -------------------------------------------------------------------------
    // Legacy AppCompatFlags (Windows 8 / pre-Win10 Amcache)
    // -------------------------------------------------------------------------

    private void ScanLegacyAppCompatFlags(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(LegacyAmcacheLookupKey, writable: false);
            if (key == null) return;

            ctx.IncrementRegistryKeys();

            string[] subKeyNames = key.GetSubKeyNames();
            foreach (string subKeyName in subKeyNames)
            {
                try
                {
                    using RegistryKey? appKey = key.OpenSubKey(subKeyName, writable: false);
                    if (appKey == null) continue;

                    ctx.IncrementRegistryKeys();

                    string? filePath = appKey.GetValue("LowerCaseLongPath") as string
                                    ?? appKey.GetValue("LongPathHash") as string;
                    string? description = appKey.GetValue("FileDescription") as string ?? string.Empty;
                    string? publisher = appKey.GetValue("CompanyName") as string ?? string.Empty;

                    string searchText = $"{filePath} {description} {publisher}";

                    foreach (string kw in CheatPathKeywords)
                    {
                        if (!searchText.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Legacy AppCompatFlags: Cheat Execution Record — '{kw}'",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{LegacyAmcacheLookupKey}\{subKeyName}",
                            FileName = filePath != null ? Path.GetFileName(filePath) : subKeyName,
                            Reason = $"The legacy AppCompatFlags\\Amcache registry records execution of a program " +
                                     $"matching '{kw}'. This key is the pre-Windows-10 equivalent of Amcache.hve " +
                                     "and records program execution with publisher and path information.",
                            Detail = $"Path: {filePath} | Publisher: {publisher} | Description: {description} | Keyword: {kw}"
                        });
                        break;
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    // Skip individual subkeys
                }
                catch (IOException)
                {
                    // Skip I/O errors
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Skip if access denied
        }
        catch (IOException)
        {
            // Skip I/O errors
        }
    }

    // -------------------------------------------------------------------------
    // AppCompatFlags Compatibility Layers
    // -------------------------------------------------------------------------

    private void ScanAppCompatLayers(ScanContext ctx)
    {
        try
        {
            // HKCU layers (user-applied)
            using RegistryKey? userKey = Registry.CurrentUser.OpenSubKey(AppCompatFlagsLayersKey, writable: false);
            if (userKey != null)
            {
                ctx.IncrementRegistryKeys();
                ScanCompatLayerKey(ctx, userKey, $@"HKCU\{AppCompatFlagsLayersKey}");
            }

            // HKLM layers (system-applied / installer-applied)
            using RegistryKey? machineKey = Registry.LocalMachine.OpenSubKey(AppCompatFlagsLayersKey, writable: false);
            if (machineKey != null)
            {
                ctx.IncrementRegistryKeys();
                ScanCompatLayerKey(ctx, machineKey, $@"HKLM\{AppCompatFlagsLayersKey}");
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Skip if access denied
        }
        catch (IOException)
        {
            // Skip I/O errors
        }
    }

    private void ScanCompatLayerKey(ScanContext ctx, RegistryKey key, string displayPath)
    {
        string[] valueNames;
        try { valueNames = key.GetValueNames(); }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        foreach (string valueName in valueNames)
        {
            ctx.IncrementRegistryKeys();

            // The value name IS the path of the executable with a compatibility layer applied
            string execPath = valueName;
            string execPathLower = execPath.ToLowerInvariant();

            foreach (string kw in CheatPathKeywords)
            {
                if (!execPathLower.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                string? layers;
                try { layers = key.GetValue(valueName) as string; }
                catch (IOException) { layers = null; }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"AppCompatFlags Layer Applied to Cheat Executable: '{kw}'",
                    Risk = RiskLevel.High,
                    Location = displayPath,
                    FileName = Path.GetFileName(execPath),
                    Reason = $"A Windows compatibility layer is configured for the executable '{execPath}', " +
                             $"which matches the cheat-related keyword '{kw}'. Compatibility layers indicate " +
                             "this executable was configured to run and may have been executed.",
                    Detail = $"Executable: {execPath} | Layers: {layers ?? "(none)"} | Keyword: {kw}"
                });
                break;
            }
        }
    }

    // -------------------------------------------------------------------------
    // BAM / DAM (Background / Desktop Activity Monitor)
    // -------------------------------------------------------------------------

    private void ScanActivityMonitorRegistry(ScanContext ctx, string rootKeyPath, string sourceLabel)
    {
        try
        {
            using RegistryKey? bamRoot = Registry.LocalMachine.OpenSubKey(rootKeyPath, writable: false);
            if (bamRoot == null) return;

            ctx.IncrementRegistryKeys();

            string[] sidNames;
            try { sidNames = bamRoot.GetSubKeyNames(); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (string sid in sidNames)
            {
                try
                {
                    using RegistryKey? sidKey = bamRoot.OpenSubKey(sid, writable: false);
                    if (sidKey == null) continue;

                    ctx.IncrementRegistryKeys();

                    string[] valueNames;
                    try { valueNames = sidKey.GetValueNames(); }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (string valueName in valueNames)
                    {
                        if (string.IsNullOrWhiteSpace(valueName)) continue;
                        if (valueName.Equals("Version", StringComparison.OrdinalIgnoreCase) ||
                            valueName.Equals("SequenceNumber", StringComparison.OrdinalIgnoreCase))
                            continue;

                        ctx.IncrementRegistryKeys();

                        string execPath = valueName;
                        string execLower = execPath.ToLowerInvariant();

                        bool isCheatPath = false;
                        string matchedKeyword = string.Empty;

                        foreach (string kw in CheatPathKeywords)
                        {
                            if (execLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                isCheatPath = true;
                                matchedKeyword = kw;
                                break;
                            }
                        }

                        bool isSuspiciousLocation = false;
                        string suspiciousLocation = string.Empty;

                        if (!isCheatPath)
                        {
                            foreach (string loc in SuspiciousLocations)
                            {
                                if (execLower.Contains(loc, StringComparison.OrdinalIgnoreCase))
                                {
                                    bool hasExeExt = false;
                                    foreach (string ext in ExecutableExtensions)
                                    {
                                        if (execLower.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                                        {
                                            hasExeExt = true;
                                            break;
                                        }
                                    }
                                    if (hasExeExt)
                                    {
                                        isSuspiciousLocation = true;
                                        suspiciousLocation = loc;
                                        break;
                                    }
                                }
                            }
                        }

                        if (isCheatPath)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"{sourceLabel}: Cheat Executable Execution Record — {Path.GetFileName(execPath)}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{rootKeyPath}\{sid}",
                                FileName = Path.GetFileName(execPath),
                                Reason = $"The {sourceLabel} (Background Activity Monitor) registry records execution of " +
                                         $"'{execPath}', which matches the cheat-related keyword '{matchedKeyword}'. " +
                                         $"{sourceLabel} entries survive reboot and file deletion and are a highly " +
                                         "reliable execution artifact used in forensic investigations.",
                                Detail = $"SID: {sid} | Path: {execPath} | Matched keyword: {matchedKeyword}"
                            });
                        }
                        else if (isSuspiciousLocation)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"{sourceLabel}: Executable Run from Suspicious Location — {Path.GetFileName(execPath)}",
                                Risk = RiskLevel.Medium,
                                Location = $@"HKLM\{rootKeyPath}\{sid}",
                                FileName = Path.GetFileName(execPath),
                                Reason = $"The {sourceLabel} registry records execution of an executable from the " +
                                         $"suspicious location '{suspiciousLocation}'. Legitimate software rarely " +
                                         "executes from Temp, Downloads, or Roaming AppData subdirectories. " +
                                         "Cheat loaders and droppers commonly use these paths to avoid detection.",
                                Detail = $"SID: {sid} | Path: {execPath} | Suspicious location: {suspiciousLocation}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    // Skip individual SID keys we cannot access
                }
                catch (IOException)
                {
                    // Skip I/O errors on individual SID keys
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"{sourceLabel} Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKLM\{rootKeyPath}",
                Reason = $"Access denied reading {sourceLabel} registry. Elevated privileges are required.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"{sourceLabel} Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKLM\{rootKeyPath}",
                Reason = $"I/O error reading {sourceLabel} registry.",
                Detail = ex.Message
            });
        }
    }

    // -------------------------------------------------------------------------
    // UserAssist (GUI program execution — ROT13 encoded)
    // -------------------------------------------------------------------------

    private void ScanUserAssist(ScanContext ctx)
    {
        try
        {
            using RegistryKey? userAssistRoot = Registry.CurrentUser.OpenSubKey(UserAssistGuidRoot, writable: false);
            if (userAssistRoot == null) return;

            ctx.IncrementRegistryKeys();

            string[] guidNames;
            try { guidNames = userAssistRoot.GetSubKeyNames(); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (string guidName in guidNames)
            {
                try
                {
                    using RegistryKey? guidKey = userAssistRoot.OpenSubKey(guidName, writable: false);
                    if (guidKey == null) continue;

                    ctx.IncrementRegistryKeys();

                    using RegistryKey? countKey = guidKey.OpenSubKey("Count", writable: false);
                    if (countKey == null) continue;

                    ctx.IncrementRegistryKeys();

                    string[] valueNames;
                    try { valueNames = countKey.GetValueNames(); }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (string encodedName in valueNames)
                    {
                        if (string.IsNullOrWhiteSpace(encodedName)) continue;

                        ctx.IncrementRegistryKeys();

                        string decoded = Rot13Decode(encodedName);
                        string decodedLower = decoded.ToLowerInvariant();

                        bool matched = false;
                        string matchedKeyword = string.Empty;

                        foreach (string kw in CheatPathKeywords)
                        {
                            if (decodedLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                matched = true;
                                matchedKeyword = kw;
                                break;
                            }
                        }

                        if (!matched) continue;

                        // Read the run count from the binary value data.
                        // UserAssist value structure (Win7+): 4 bytes session ID, 4 bytes run count,
                        // 4 bytes focus count, 4 bytes focus time, 8 bytes last run time.
                        string runCountNote = string.Empty;
                        try
                        {
                            byte[]? valData = countKey.GetValue(
                                encodedName, null,
                                RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];

                            if (valData != null && valData.Length >= 8)
                            {
                                int runCount = BitConverter.ToInt32(valData, 4);
                                if (runCount > 0)
                                    runCountNote = $" | Run count: {runCount}";
                                else
                                    runCountNote = " | Run count: 0 (program accessed but not launched via GUI)";

                                // Also try to decode last-run FILETIME if value is >= 16 bytes
                                if (valData.Length >= 16)
                                {
                                    try
                                    {
                                        long fileTime = BitConverter.ToInt64(valData, 8);
                                        if (fileTime > 0)
                                        {
                                            var lastRun = DateTime.FromFileTimeUtc(fileTime);
                                            runCountNote += $" | Last run: {lastRun:yyyy-MM-dd HH:mm:ss} UTC";
                                        }
                                    }
                                    catch { }
                                }
                            }
                        }
                        catch (IOException) { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"UserAssist: Cheat Program GUI Execution — {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{UserAssistGuidRoot}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"UserAssist records that the GUI program '{decoded}' was launched by the user. " +
                                     $"The decoded path contains the cheat-related keyword '{matchedKeyword}'. " +
                                     "UserAssist entries include a launch counter and last-run timestamp, and " +
                                     "persist after the executable is deleted.",
                            Detail = $"ROT13 encoded: {encodedName} | Decoded: {decoded} | GUID: {guidName}{runCountNote}"
                        });
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    // Skip individual GUID keys
                }
                catch (IOException)
                {
                    // Skip I/O errors
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "UserAssist Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{UserAssistGuidRoot}",
                Reason = "Access denied reading UserAssist registry.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "UserAssist Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{UserAssistGuidRoot}",
                Reason = "I/O error reading UserAssist registry.",
                Detail = ex.Message
            });
        }
    }

    // -------------------------------------------------------------------------
    // RecentDocs
    // -------------------------------------------------------------------------

    private void ScanRecentDocs(ScanContext ctx)
    {
        string[] watchedExtensions = { ".exe", ".dll", ".sys", ".drv", ".scr", ".pf" };

        try
        {
            using RegistryKey? recentDocsRoot = Registry.CurrentUser.OpenSubKey(RecentDocsRoot, writable: false);
            if (recentDocsRoot == null) return;

            ctx.IncrementRegistryKeys();

            string[] extensionSubkeys;
            try { extensionSubkeys = recentDocsRoot.GetSubKeyNames(); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (string ext in extensionSubkeys)
            {
                bool isWatched = false;
                foreach (string watched in watchedExtensions)
                {
                    if (ext.Equals(watched, StringComparison.OrdinalIgnoreCase))
                    {
                        isWatched = true;
                        break;
                    }
                }
                if (!isWatched) continue;

                try
                {
                    using RegistryKey? extKey = recentDocsRoot.OpenSubKey(ext, writable: false);
                    if (extKey == null) continue;

                    ctx.IncrementRegistryKeys();

                    string[] valueNames;
                    try { valueNames = extKey.GetValueNames(); }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (string valueName in valueNames)
                    {
                        if (valueName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.IncrementRegistryKeys();

                        byte[]? data;
                        try
                        {
                            data = extKey.GetValue(valueName, null,
                                RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
                        }
                        catch (IOException) { continue; }

                        if (data == null || data.Length < 2) continue;

                        string fileName = ExtractNullTerminatedUnicode(data);
                        if (string.IsNullOrWhiteSpace(fileName)) continue;

                        string fileNameLower = fileName.ToLowerInvariant();

                        bool matched = false;
                        string matchedKeyword = string.Empty;

                        foreach (string kw in CheatPathKeywords)
                        {
                            if (fileNameLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                matched = true;
                                matchedKeyword = kw;
                                break;
                            }
                        }

                        if (!matched) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RecentDocs: Cheat-Related File Opened — {fileName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{RecentDocsRoot}\{ext}",
                            FileName = fileName,
                            Reason = $"Windows RecentDocs registry records that '{fileName}' ({ext}) was recently opened. " +
                                     $"The filename matches the cheat-related keyword '{matchedKeyword}'. " +
                                     "RecentDocs entries persist after the file is deleted.",
                            Detail = $"Extension: {ext} | Value: {valueName} | Keyword: {matchedKeyword}"
                        });
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    // Skip extension subkeys we cannot access
                }
                catch (IOException)
                {
                    // Skip I/O errors
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "RecentDocs Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{RecentDocsRoot}",
                Reason = "Access denied reading RecentDocs registry.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "RecentDocs Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{RecentDocsRoot}",
                Reason = "I/O error reading RecentDocs registry.",
                Detail = ex.Message
            });
        }
    }

    // -------------------------------------------------------------------------
    // AppCompatFlags Telemetry (Windows 10+ diagnostic data)
    // -------------------------------------------------------------------------

    private void ScanAppCompatTelemetry(ScanContext ctx)
    {
        const string telemetryKey =
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController";

        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(telemetryKey, writable: false);
            if (key == null) return;

            ctx.IncrementRegistryKeys();

            // Enumerate program entries — each subkey is a program with telemetry data
            string[] subKeyNames;
            try { subKeyNames = key.GetSubKeyNames(); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (string progName in subKeyNames)
            {
                ctx.IncrementRegistryKeys();

                string progLower = progName.ToLowerInvariant();
                foreach (string kw in CheatPathKeywords)
                {
                    if (!progLower.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AppCompatFlags Telemetry: Cheat Program Record — '{progName}'",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{telemetryKey}\{progName}",
                        FileName = progName,
                        Reason = $"The AppCompatFlags TelemetryController registry contains an entry for '{progName}', " +
                                 $"which matches the cheat-related keyword '{kw}'. This telemetry key records programs " +
                                 "that triggered compatibility checks when executed.",
                        Detail = $"Program: {progName} | Keyword: {kw}"
                    });
                    break;
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Skip if access denied
        }
        catch (IOException)
        {
            // Skip I/O errors
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    // Apply ROT13 character substitution to decode UserAssist registry value names.
    private static string Rot13Decode(string input)
    {
        char[] chars = input.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c >= 'A' && c <= 'Z')
                chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c >= 'a' && c <= 'z')
                chars[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(chars);
    }

    // Extract a null-terminated UTF-16LE string from a binary registry value blob.
    private static string ExtractNullTerminatedUnicode(byte[] data)
    {
        try
        {
            int nullPos = -1;
            for (int i = 0; i + 1 < data.Length; i += 2)
            {
                if (data[i] == 0 && data[i + 1] == 0)
                {
                    nullPos = i;
                    break;
                }
            }

            int length = nullPos >= 0 ? nullPos : data.Length - (data.Length % 2);
            if (length <= 0) return string.Empty;

            return System.Text.Encoding.Unicode.GetString(data, 0, length);
        }
        catch
        {
            return string.Empty;
        }
    }
}
