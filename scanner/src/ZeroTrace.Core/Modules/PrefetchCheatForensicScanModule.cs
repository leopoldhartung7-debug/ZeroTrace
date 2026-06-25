using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class PrefetchCheatForensicScanModule : IScanModule
{
    public string Name => "Prefetch Cheat Execution Forensics";
    public double Weight => 4.8;
    public int ParallelGroup => 5;

    private static readonly string PrefetchDirectory =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

    private static readonly TimeSpan RecentThreshold = TimeSpan.FromDays(30);

    // Known cheat executable name stems (uppercased, matched against the prefetch filename stem before the dash+hex suffix).
    // Prefetch filenames follow the pattern: EXENAME-XXXXXXXX.pf
    private static readonly HashSet<string> KnownCheatStems = new(StringComparer.OrdinalIgnoreCase)
    {
        // -----------------------------------------------------------------------
        // Injectors
        // -----------------------------------------------------------------------
        "INJECTOR",
        "XENOS",
        "XENOS64",
        "GHINJECTOR",
        "EXTREMEINJECTOR",
        "WINJECT",
        "DLLINJECTOR",
        "MANUALMAPPER",
        "REFLECTIVEINJECT",
        "MODULEINJECT",
        "MEMORYINJECTOR",
        "INJECTDLL",
        "DLLINJECTOR64",
        "PROCESSINJECT",
        "REMOTEINJECT",
        "SHELLCODEINJECTOR",
        "LOADLIBINJECT",
        "MANUALMAP",
        "MANUALMAPPER64",
        "GHOSTINJECT",
        "SYRINGE",
        "SYRINGE64",
        "LOADLIBRARY",
        "REMOTETHREADINJECT",
        "APCINJECTOR",
        "EARLYBIRD",
        "PROCESSHOLLOW",
        "PROCESSHOLLOWING",

        // -----------------------------------------------------------------------
        // HWID spoofers
        // -----------------------------------------------------------------------
        "HWIDSPOOFER",
        "PHANTOMSPOOFER",
        "CROWSPOOFER",
        "KSPOOFER",
        "ABSOLUTESPOOFER",
        "TSSPOOFER",
        "BANBYPASS",
        "SPOOFANDPLAY",
        "HWID_CHANGER",
        "HWID-BYPASS",
        "HWIDCHANGER",
        "HWIDBYPASS",
        "SERIALSPOOFER",
        "MACSPOOFER",
        "DISKSPOOFER",
        "CPUIDSPOOFER",
        "VOLUMESPOOFER",
        "GPUSPOOFER",
        "NICSPOOFER",
        "BIOSIDSPOOFER",
        "BOARDIDSPOOFER",
        "SMBIOSSPOOFER",
        "PCISPOOFER",
        "REGISTRYSPOOFER",
        "GUIDSPOOFER",
        "UUIDSPOOFER",
        "MUIDSPOOFER",
        "INSTANCEIDSPOOFER",
        "HARDDISKSPOOFER",
        "NETWORKSPOOFER",

        // -----------------------------------------------------------------------
        // Bypass / driver mapping tools
        // -----------------------------------------------------------------------
        "KDMAPPER",
        "DRVMAP",
        "DRIVERMAPPER",
        "BYOVD",
        "EACBYPASS",
        "BEBYPASS",
        "VANGUARDBYPASS",
        "FACEITBYPASS",
        "VACBYPASS",
        "ESBYPASS",
        "ACBYPASS",
        "BATTLEEYEBYPASS",
        "EASYANTICHEATBYPASS",
        "KERNELBYPASS",
        "KERNELMAPPER",
        "KDMAPPER64",
        "DRIVERBYPASS",
        "RINGZEROACCESS",
        "SIGNEDBYPASS",
        "TESTMODEBYPASS",
        "PATCHGUARDBYPASS",
        "DSEBYPASS",
        "DSEFIXER",
        "KPPBYPASS",
        "KSBYPASS",
        "NTOSKRNLPATCH",
        "RTCOREPATCH",
        "GDRVSCAN",
        "CPUZBYPASS",
        "MSIO64BYPASS",
        "NTIOLIB64BYPASS",

        // -----------------------------------------------------------------------
        // Cheat loaders
        // -----------------------------------------------------------------------
        "CHEATLOADER",
        "HACKLOADER",
        "GAMELOADER",
        "PAYLOADLOADER",
        "STEAMLOADER",
        "CHEATINJECTOR",
        "BOOTSTRAPPER",
        "CHEATBOOTSTRAP",
        "CHEATLAUNCHER",
        "HACKLAUNCH",
        "MODLOADER",
        "PAYLOADRUN",
        "SHELLCODELOADER",
        "STUBLOADER",
        "CRYPTERLOADER",
        "PACKERDROP",

        // -----------------------------------------------------------------------
        // FiveM / GTA:Online cheats
        // -----------------------------------------------------------------------
        "EULEN",
        "LYNX",
        "IMPULSE",
        "PHANTOM",
        "DISTURBED",
        "HAMSTER",
        "NIGHTHAWK",
        "EPSILON",
        "FIVEMCHEAT",
        "FIVEMHACK",
        "FIVEMBYPASS",
        "FIVEMSPOOFER",
        "FIVEM-BYPASS",
        "FIVEM-CHEAT",
        "FIVEM-HACK",

        // -----------------------------------------------------------------------
        // GTA V menus
        // -----------------------------------------------------------------------
        "2TAKE1",
        "STAND",
        "CHERAX",
        "ORBITAL",
        "KIDDION",
        "MENYOO",
        "MODEST",
        "BIGBASEV",
        "GTAVMENU",
        "OZARK",
        "MIDNIGHT",
        "NATIVEMENU",
        "MODMENU",
        "GTACHEAT",
        "NATIVETRAINER",
        "SCRIPTDEV",
        "OPENIV",

        // -----------------------------------------------------------------------
        // CS2 / CSGO cheats
        // -----------------------------------------------------------------------
        "AIMWARE",
        "SKEET",
        "GAMESENSE",
        "ONETAP",
        "FATALITY",
        "NIXWARE",
        "NEVERLOSE",
        "INTERIUM",
        "LHOOK",
        "CHEATSHELL",
        "CSGOCHEAT",
        "CS2CHEAT",
        "CSGOHACK",
        "CS2HACK",
        "CSGOSPOOFER",
        "CS2SPOOFER",
        "PRIMECHEAT",

        // -----------------------------------------------------------------------
        // Valorant cheats
        // -----------------------------------------------------------------------
        "VALOAIMBOT",
        "VALORANTCHEAT",
        "VALORANTHACK",
        "VALORANTBYPASS",
        "VALORANTSPOOFER",
        "VALHACK",
        "VALOBOT",
        "VANGUARDBYPASS2",

        // -----------------------------------------------------------------------
        // Analysis and reverse engineering tools (dual-use / red-flag context)
        // -----------------------------------------------------------------------
        "RECLASS",
        "RECLASS64",
        "X64DBG",
        "X32DBG",
        "CHEATENGINE",
        "CHEATENGINE-X86_64",
        "CHEATENGINE-I386",
        "SCYLLAHIDE",
        "TITANHTIDE",
        "PROCESSHACKER",
        "PROCESSHACKER2",
        "PROCESSHACKER3",
        "SYSTEMINFORMER",
        "WINDBG",
        "OLLYDBG",
        "IMMUNITYDEBUGGER",
        "GHIDRA",
        "IDA64",
        "IDAG64",
        "RADARE2",

        // -----------------------------------------------------------------------
        // DMA / physical memory tools
        // -----------------------------------------------------------------------
        "PCILEECH",
        "MEMPROC",
        "DMAREAD",
        "PHYSMEM",
        "FPGAREAD",
        "DMAWRITE",
        "PCIMEM",
        "DMAHACK",
        "MEMREAD",
        "PHYSMEMDRIVER",
        "DMACONTROLLER",
        "DMAFRAMEWORK",

        // -----------------------------------------------------------------------
        // Speed hacks
        // -----------------------------------------------------------------------
        "SPEEDHACK",
        "SPEEDHACK32",
        "SPEEDHACK64",
        "TIMERHACK",
        "GAMESPEED",
        "SPEEDBOOST",
        "CLOCKHACK",
        "TIMEMANIP",
        "SPEEDCHEAT",

        // -----------------------------------------------------------------------
        // Trainers / memory editors
        // -----------------------------------------------------------------------
        "TRAINER",
        "ARTMONEY",
        "TSEARCH",
        "GAMETRAINER",
        "MEMORYEDITOR",
        "MEMEDITOR",
        "MEMEDIT",
        "PWRCHEAT",
        "PWNHACK",
        "UNIVERSALTRAINER",

        // -----------------------------------------------------------------------
        // Roblox exploits
        // -----------------------------------------------------------------------
        "SYNAPSEX",
        "KRNL",
        "FLUXUS",
        "SCRIPTWARE",
        "WAVE",
        "CELERY",
        "ELECTRON",
        "ARCEUS",
        "OXYGEN",
        "VISENYA",
        "EVON",
        "COCO",
        "ROBLOXCHEAT",
        "ROBLOXHACK",
        "ROBLOXEXPLOIT",
        "COMET",
        "SYNX",
        "NIHON",
        "SENTINEL",
        "PROTO",

        // -----------------------------------------------------------------------
        // Fortnite / Apex / Rust / PUBG / Overwatch
        // -----------------------------------------------------------------------
        "FORTNITEBYPASS",
        "FORTNITECHEAT",
        "FORTNITEHACK",
        "APEXCHEAT",
        "APEXHACK",
        "APEXAIMBOT",
        "RUSTCHEAT",
        "RUSTHACK",
        "PUBGCHEAT",
        "PUBGHACK",
        "OVERWATCH2CHEAT",
        "OVERWATCHHACK",
        "WARZONECHEAT",
        "TARKOVCHEAT",
        "R6CHEAT",
        "RAINBOWSIXCHEAT",
        "DOTA2HACK",
        "LOL-HACK",
        "LOLHACK",

        // -----------------------------------------------------------------------
        // Crypto miners
        // -----------------------------------------------------------------------
        "XMRIG",
        "XMRIGCC",
        "PHOENIXMINER",
        "T-REX",
        "TREXMINER",
        "NBMINER",
        "LOLMINER",
        "GMINER",
        "MINIZCUDA",
        "ETHMINER",
        "CGMINER",
        "BFGMINER",
        "CPUMINER",
        "MINERD",
        "CCMINER",
        "SRBMINER",
        "TEAMREDMINER",
        "CLAYMORE",
        "MINER",
        "CRYPTOMINER",
        "HIVEOS",
        "NICEHASH",
        "NICEHASHMINER",

        // -----------------------------------------------------------------------
        // RATs and stealers
        // -----------------------------------------------------------------------
        "ASYNCRAT",
        "NJRAT",
        "DCRAT",
        "REDLINE",
        "RACCOON",
        "VIDAR",
        "AMADEY",
        "QUASAR",
        "NANOCORE",
        "REMCOS",
        "WARZONE",
        "AGENT-TESLA",
        "FORMBOOK",
        "AZORULT",
        "ARKEI",
        "MASSLOGGER",
        "ORCUSRAT",
        "LIMERAT",
        "REVENGE",
        "BITRAT",
        "XWORM",
        "STEALC",
        "LUMA",
        "MEDUZA",
        "RHADAMANTHYS",
        "WHITESNAKE",
        "LUMMA",
        "RECORDSTEALER",

        // -----------------------------------------------------------------------
        // General / generic heuristic stems
        // -----------------------------------------------------------------------
        "HACK",
        "CHEAT",
        "AIMBOT",
        "WALLHACK",
        "NOCLIP",
        "GODMODE",
        "BHOP",
        "TRIGGERBOT",
        "ESP",
        "RADAR",
        "SPINBOT",
        "AIMASSIST",
        "NOFALL",
        "INFINITEAMMO",
        "RAPIDFIRE",
        "SUPERSPRINT",
        "AUTOSHOOT",
        "AUTOCLICKER",
        "RECOILCONTROL",
        "SPREADREDUCTION",
        "NOFLASH",
        "NORECOIL",
        "BUNNYHOP",
        "KNIFEBOT",
        "TRIGGERBOT64",
        "AUTOFIRE",
        "SILENTAIM",
        "AIMLOCK",
        "HEADSHOTBOT",
        "CLOSETCHEATER",
        "LEGITHACK",
        "RAGEBOT",
        "HVHBOT",
    };

    // Broader keyword heuristics — match anywhere in the prefetch stem
    private static readonly string[] CheatKeywords = new[]
    {
        "INJECT",
        "SPOOFER",
        "BYPASS",
        "TRAINER",
        "AIMBOT",
        "WALLHACK",
        "CHEAT",
        "HACK",
        "LOADER",
        "EXPLOIT",
        "MODMENU",
        "GODMODE",
        "BHOP",
        "TRIGGERBOT",
        "NOCLIP",
        "SPEEDHACK",
        "AUTOSHOOT",
        "RECOIL",
        "OVERLAY",
        "LOGGER",
        "STEALER",
        "KEYLOG",
        "RAT-",
        "MINER",
        "CRYPTER",
        "PACKER",
        "DROPER",
        "DROPPER",
        "DOWNLOADER",
        "ROOTKIT",
        "BOOTKIT",
        "RANSOMWARE",
    };

    // Registry paths for prefetch / superfetch control
    private const string PrefetchParamsKey =
        @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";

    // SysMain service key (Superfetch / Prefetch service)
    private const string SysMainServiceKey =
        @"SYSTEM\CurrentControlSet\Services\SysMain";

    // ReadyBoost / ReadyBoot related key
    private const string ReadyBoostKey =
        @"SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot";

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        ctx.Report(0.0, "Initialising prefetch forensics");

        await ScanPrefetchDirectoryAsync(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.80, "Checking PrefetchParameters registry");

        ScanPrefetchRegistry(ctx);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.90, "Checking SysMain service state");

        ScanSysMainService(ctx);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.95, "Checking ReadyBoot autologger");

        ScanReadyBootLogger(ctx);

        ctx.Report(1.0, "Prefetch forensics complete");
    }

    // -------------------------------------------------------------------------
    // Prefetch Directory Scan
    // -------------------------------------------------------------------------

    private async Task ScanPrefetchDirectoryAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(PrefetchDirectory))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Prefetch Directory Missing",
                Risk = RiskLevel.Medium,
                Location = PrefetchDirectory,
                FileName = "Prefetch",
                Reason = "The Windows Prefetch directory does not exist. Prefetch may have been disabled or " +
                         "the directory manually deleted to erase execution evidence. On an active gaming " +
                         "system the Prefetch directory typically contains 100-1000 .pf files.",
                Detail = $"Expected path: {PrefetchDirectory}"
            });
            return;
        }

        FileInfo[] prefetchFiles;
        try
        {
            prefetchFiles = new DirectoryInfo(PrefetchDirectory)
                .GetFiles("*.pf", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Prefetch Directory Access Denied",
                Risk = RiskLevel.Low,
                Location = PrefetchDirectory,
                Reason = "Cannot enumerate the Prefetch directory — elevated privileges may be required.",
                Detail = ex.Message
            });
            return;
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Prefetch Directory Read Error",
                Risk = RiskLevel.Low,
                Location = PrefetchDirectory,
                Reason = "I/O error while reading the Prefetch directory.",
                Detail = ex.Message
            });
            return;
        }

        // Flag a suspiciously empty Prefetch directory on what appears to be an active system
        if (prefetchFiles.Length == 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Prefetch Directory Contains No .pf Files",
                Risk = RiskLevel.High,
                Location = PrefetchDirectory,
                Reason = "The Prefetch directory exists but contains zero .pf files. On any active Windows " +
                         "system, hundreds of prefetch entries accumulate over time. An empty directory " +
                         "strongly suggests the files were manually deleted or Prefetch was disabled and " +
                         "the directory recently recreated, both of which are anti-forensics techniques.",
                Detail = $"Directory: {PrefetchDirectory} | File count: 0"
            });
            return;
        }

        // Flag systems with an unusually low prefetch count (< 10 files) — another evasion indicator
        if (prefetchFiles.Length < 10)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Suspiciously Low Prefetch File Count",
                Risk = RiskLevel.Medium,
                Location = PrefetchDirectory,
                Reason = $"Only {prefetchFiles.Length} prefetch file(s) found. Active Windows systems normally " +
                         "accumulate many more. This may indicate partial clearing of execution history.",
                Detail = $"File count: {prefetchFiles.Length} | Directory: {PrefetchDirectory}"
            });
        }

        var now = DateTime.UtcNow;
        int totalFiles = prefetchFiles.Length;
        int processed = 0;

        foreach (var pf in prefetchFiles)
        {
            ct.ThrowIfCancellationRequested();

            processed++;
            if (processed % 20 == 0)
            {
                double fraction = 0.05 + (processed / (double)totalFiles) * 0.70;
                ctx.Report(fraction, pf.Name);
            }

            ctx.IncrementFiles();

            // Extract the executable name from the prefetch filename.
            // Pattern: EXENAME-XXXXXXXX.pf  (hex suffix is exactly 8 hex digits)
            string pfStem = Path.GetFileNameWithoutExtension(pf.Name);
            string exeName = ExtractExecutableName(pfStem);

            bool isExactMatch = KnownCheatStems.Contains(exeName);
            bool isKeywordMatch = !isExactMatch && ContainsCheatKeyword(exeName);

            bool isRecent = (now - pf.LastWriteTimeUtc) <= RecentThreshold;
            string ageNote = isRecent
                ? $"Recently executed: last write {pf.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC " +
                  $"({(int)(now - pf.LastWriteTimeUtc).TotalDays} days ago)"
                : $"Last write: {pf.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC";

            if (isExactMatch)
            {
                var risk = isRecent ? RiskLevel.Critical : RiskLevel.High;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known Cheat Tool Prefetch Entry: {exeName}",
                    Risk = risk,
                    Location = pf.FullName,
                    FileName = pf.Name,
                    Reason = $"Prefetch file '{pf.Name}' matches the known cheat tool executable name '{exeName}'. " +
                             "Prefetch records confirm this binary was executed on this system. " +
                             "The entry persists even after the executable has since been deleted.",
                    Detail = ageNote + $" | File size: {pf.Length} bytes"
                });
            }
            else if (isKeywordMatch)
            {
                string matchedKeyword = GetMatchedKeyword(exeName);
                var risk = isRecent ? RiskLevel.High : RiskLevel.Medium;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious Prefetch Entry: {exeName}",
                    Risk = risk,
                    Location = pf.FullName,
                    FileName = pf.Name,
                    Reason = $"Prefetch file '{pf.Name}' contains the suspicious keyword '{matchedKeyword}' " +
                             $"in the executable name '{exeName}'. " +
                             "This pattern is associated with cheat tools, injectors, or bypass software.",
                    Detail = ageNote + $" | Matched keyword: {matchedKeyword} | File size: {pf.Length} bytes"
                });
            }
            else if (isRecent)
            {
                // Even if not an exact/keyword match, scan the file content for embedded cheat strings
                await ScanPrefetchFileContentAsync(ctx, pf, exeName, ageNote, ct);
            }
        }

        ctx.Report(0.78, "Prefetch directory scan complete");
    }

    // -------------------------------------------------------------------------
    // Prefetch File Content Scan (embedded referenced-file paths)
    // -------------------------------------------------------------------------

    private async Task ScanPrefetchFileContentAsync(
        ScanContext ctx, FileInfo pf, string exeName, string ageNote, CancellationToken ct)
    {
        try
        {
            using var fs = new FileStream(pf.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            // Read up to 64 KB — enough to capture the referenced-files section of any prefetch file.
            // The MAM-compressed Windows 10+ format stores the referenced files section early in the
            // decompressed output; a 64 KB read captures the header and the first referenced-files block.
            int maxRead = (int)Math.Min(65536L, fs.Length);
            if (maxRead < 4) return;

            byte[] buffer = new byte[maxRead];
            int bytesRead = 0;
            int remaining = maxRead;

            while (remaining > 0)
            {
                int n = await fs.ReadAsync(buffer, bytesRead, remaining, ct);
                if (n == 0) break;
                bytesRead += n;
                remaining -= n;
            }

            if (bytesRead < 4) return;

            // Search for ASCII and Unicode representations of cheat keywords in the raw bytes.
            // We avoid decoding the MAM compression layer and instead do a raw string search —
            // this is sufficient because the referenced-filenames table in older prefetch formats
            // (Win XP through Win 8.1) is stored as uncompressed UTF-16LE strings.
            string asciiContent = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead);
            string utf16Content = System.Text.Encoding.Unicode.GetString(buffer, 0, bytesRead - (bytesRead % 2));

            foreach (string keyword in CheatKeywords)
            {
                if (asciiContent.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                    utf16Content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat-Related String Embedded in Prefetch File: {pf.Name}",
                        Risk = RiskLevel.Medium,
                        Location = pf.FullName,
                        FileName = pf.Name,
                        Reason = $"The prefetch file for '{exeName}' contains embedded references to the keyword " +
                                 $"'{keyword}', suggesting that when this executable ran it accessed or loaded " +
                                 "cheat-related files. Windows prefetch records all DLLs and files opened by a process.",
                        Detail = ageNote + $" | Embedded keyword: {keyword}"
                    });
                    break; // One finding per file to avoid duplicates
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Skip individual prefetch files we cannot read
        }
        catch (IOException)
        {
            // Skip I/O errors on individual prefetch files
        }
    }

    // -------------------------------------------------------------------------
    // Registry: PrefetchParameters
    // -------------------------------------------------------------------------

    private void ScanPrefetchRegistry(ScanContext ctx)
    {
        try
        {
            using RegistryKey? baseKey = Registry.LocalMachine.OpenSubKey(PrefetchParamsKey, writable: false);
            if (baseKey == null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "PrefetchParameters Registry Key Missing",
                    Risk = RiskLevel.Medium,
                    Location = $@"HKLM\{PrefetchParamsKey}",
                    Reason = "The PrefetchParameters registry key is absent. This is unusual and may indicate " +
                             "registry tampering or a stripped OS installation.",
                    Detail = "Expected at HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"
                });
                return;
            }

            ctx.IncrementRegistryKeys();

            // Check EnablePrefetcher
            object? enablePrefetcherVal = baseKey.GetValue("EnablePrefetcher");
            if (enablePrefetcherVal is int enablePrefetcher)
            {
                ctx.IncrementRegistryKeys();
                if (enablePrefetcher == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Prefetcher Disabled (EnablePrefetcher=0)",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{PrefetchParamsKey}",
                        FileName = "EnablePrefetcher",
                        Reason = "EnablePrefetcher=0 fully disables the Windows Prefetcher. New .pf entries will " +
                                 "no longer be written, preventing execution history recording. This is a well-known " +
                                 "anti-forensics technique used by cheat software, HWID spoofers, and anti-ban tools " +
                                 "to ensure no evidence of future cheat executions is recorded.",
                        Detail = "EnablePrefetcher = 0 (0=disabled, 1=app only, 2=boot only, 3=all)"
                    });
                }
                else if (enablePrefetcher == 1 || enablePrefetcher == 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Prefetcher Partially Disabled",
                        Risk = RiskLevel.Low,
                        Location = $@"HKLM\{PrefetchParamsKey}",
                        FileName = "EnablePrefetcher",
                        Reason = $"EnablePrefetcher is set to {enablePrefetcher} (partial). " +
                                 "The default is 3 (fully enabled). Partial disabling may limit execution history.",
                        Detail = $"EnablePrefetcher = {enablePrefetcher}"
                    });
                }
            }
            else if (enablePrefetcherVal == null)
            {
                // Value absent — check if directory is also empty/missing
                bool dirEmpty = !Directory.Exists(PrefetchDirectory) ||
                                new DirectoryInfo(PrefetchDirectory).GetFiles("*.pf").Length == 0;
                if (dirEmpty)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "EnablePrefetcher Value Absent and No Prefetch Files Present",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{PrefetchParamsKey}",
                        Reason = "The EnablePrefetcher registry value is not set and the Prefetch directory " +
                                 "contains no .pf files. This combination strongly suggests prefetch was " +
                                 "deliberately disabled to prevent execution history from being recorded.",
                        Detail = $"Prefetch dir: {PrefetchDirectory}"
                    });
                }
            }

            // Check EnableSuperfetch / SysMain
            object? enableSuperfetchVal = baseKey.GetValue("EnableSuperfetch");
            if (enableSuperfetchVal is int enableSuperfetch)
            {
                ctx.IncrementRegistryKeys();
                if (enableSuperfetch == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Superfetch / SysMain Disabled (EnableSuperfetch=0)",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKLM\{PrefetchParamsKey}",
                        FileName = "EnableSuperfetch",
                        Reason = "EnableSuperfetch=0 disables the SysMain service's prefetch-based memory " +
                                 "management. While not directly hiding execution traces, this is commonly " +
                                 "set alongside Prefetch disabling in anti-forensics configurations.",
                        Detail = $"EnableSuperfetch = {enableSuperfetch}"
                    });
                }
            }

            // Check BootControlEnabled
            object? bootControlVal = baseKey.GetValue("BootControlEnabled");
            if (bootControlVal is int bootControlEnabled && bootControlEnabled == 0)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Prefetch Boot Control Disabled",
                    Risk = RiskLevel.Low,
                    Location = $@"HKLM\{PrefetchParamsKey}",
                    FileName = "BootControlEnabled",
                    Reason = "BootControlEnabled=0 disables prefetch boot tracing, further reducing " +
                             "execution history recorded during system startup.",
                    Detail = "BootControlEnabled = 0"
                });
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "PrefetchParameters Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKLM\{PrefetchParamsKey}",
                Reason = "Access denied reading PrefetchParameters registry key.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "PrefetchParameters Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKLM\{PrefetchParamsKey}",
                Reason = "I/O error reading PrefetchParameters registry.",
                Detail = ex.Message
            });
        }
    }

    // -------------------------------------------------------------------------
    // Registry: SysMain (Superfetch) service state
    // -------------------------------------------------------------------------

    private void ScanSysMainService(ScanContext ctx)
    {
        try
        {
            using RegistryKey? sysMainKey = Registry.LocalMachine.OpenSubKey(SysMainServiceKey, writable: false);
            if (sysMainKey == null) return;

            ctx.IncrementRegistryKeys();

            object? startVal = sysMainKey.GetValue("Start");
            if (startVal is int startType)
            {
                ctx.IncrementRegistryKeys();
                // Start=4 means Disabled; Start=3 means Manual; Start=2 means Automatic
                if (startType == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "SysMain (Superfetch) Service Disabled",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKLM\{SysMainServiceKey}",
                        FileName = "Start",
                        Reason = "The SysMain (Superfetch) service is set to Disabled (Start=4). " +
                                 "While this can be done for performance reasons, disabling SysMain in " +
                                 "combination with other indicators (disabled prefetch, cleared logs) is " +
                                 "consistent with an anti-forensics setup.",
                        Detail = "SysMain Start = 4 (Disabled)"
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
    // Registry: ReadyBoot autologger state
    // -------------------------------------------------------------------------

    private void ScanReadyBootLogger(ScanContext ctx)
    {
        try
        {
            using RegistryKey? rbKey = Registry.LocalMachine.OpenSubKey(ReadyBoostKey, writable: false);
            if (rbKey == null) return;

            ctx.IncrementRegistryKeys();

            object? enabledVal = rbKey.GetValue("Enabled");
            if (enabledVal is int enabled && enabled == 0)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "ReadyBoot ETW Autologger Disabled",
                    Risk = RiskLevel.Low,
                    Location = $@"HKLM\{ReadyBoostKey}",
                    FileName = "Enabled",
                    Reason = "The ReadyBoot ETW autologger is disabled. While not a direct cheat indicator, " +
                             "this logger records boot-time program loads and its disabling reduces " +
                             "the system's execution audit trail.",
                    Detail = "ReadyBoot\\Enabled = 0"
                });
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

    // Extract the executable name portion from a prefetch filename stem.
    // Pattern: EXENAME-XXXXXXXX  (last dash + 8 hex digits = hash suffix)
    private static string ExtractExecutableName(string pfStem)
    {
        int len = pfStem.Length;
        if (len > 9)
        {
            int dashPos = pfStem.LastIndexOf('-');
            if (dashPos >= 0 && dashPos == len - 9)
            {
                string suffix = pfStem.Substring(dashPos + 1);
                if (IsHex8(suffix))
                    return pfStem.Substring(0, dashPos).ToUpperInvariant();
            }
        }
        return pfStem.ToUpperInvariant();
    }

    private static bool IsHex8(string s)
    {
        if (s.Length != 8) return false;
        foreach (char c in s)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
                return false;
        }
        return true;
    }

    private static bool ContainsCheatKeyword(string exeName)
    {
        foreach (string kw in CheatKeywords)
        {
            if (exeName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string GetMatchedKeyword(string exeName)
    {
        foreach (string kw in CheatKeywords)
        {
            if (exeName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return kw;
        }
        return string.Empty;
    }
}
