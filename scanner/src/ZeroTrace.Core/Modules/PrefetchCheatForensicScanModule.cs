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
        // Injectors
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

        // HWID spoofers
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

        // Bypass / driver mapping tools
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

        // Cheat loaders
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

        // FiveM cheats
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

        // GTA V menus
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

        // CS2 / CSGO cheats
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

        // Valorant cheats
        "VALOAIMBOT",
        "VALORANTCHEAT",
        "VALORANTHACK",
        "VALORANTBYPASS",
        "VALORANTSPOOFER",
        "VALHACK",
        "VALOBOT",

        // Analysis and reverse engineering tools (dual-use)
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
        "IMMUNITY",

        // DMA / physical memory tools
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

        // Speed hacks
        "SPEEDHACK",
        "SPEEDHACK32",
        "SPEEDHACK64",
        "TIMERHACK",
        "GAMESPEED",
        "SPEEDBOOST",
        "CLOCKHACK",
        "TIMEMANIP",

        // Trainers / memory editors
        "TRAINER",
        "ARTMONEY",
        "TSEARCH",
        "GAMETRAINER",
        "MEMORYEDITOR",
        "MEMEDITOR",
        "MEMEDIT",

        // Roblox exploits
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

        // Fortnite / Apex / Rust / PUBG
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

        // Crypto miners
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

        // RATs and stealers
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

        // General / generic
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
        "SPEEDRUN",
        "AUTOSHOOT",
        "AUTOCLICKER",
        "RECOILCONTROL",
        "SPREADREDUCTION",
    };

    // Keywords that appear anywhere inside the prefetch filename stem to flag (broader heuristic).
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
    };

    // Registry paths for prefetch/superfetch control
    private const string PrefetchParamsKey =
        @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        ctx.Report(0.0, "Initialising prefetch forensics");

        await ScanPrefetchDirectoryAsync(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.85, "Checking PrefetchParameters registry");

        ScanPrefetchRegistry(ctx);

        ctx.Report(1.0, "Prefetch forensics complete");
    }

    // Scan the Windows Prefetch directory for cheat-related .pf files.
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
                Reason = "The Windows Prefetch directory does not exist. Prefetch may have been disabled or the directory manually deleted to erase execution evidence.",
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

        var now = DateTime.UtcNow;
        int totalFiles = prefetchFiles.Length;
        int processed = 0;

        foreach (var pf in prefetchFiles)
        {
            ct.ThrowIfCancellationRequested();

            processed++;
            if (processed % 20 == 0)
            {
                double fraction = 0.05 + (processed / (double)totalFiles) * 0.75;
                ctx.Report(fraction, pf.Name);
            }

            ctx.IncrementFiles();

            // Extract the executable name from the prefetch filename.
            // Pattern: EXENAME-XXXXXXXX.pf  (hex suffix is exactly 8 hex digits)
            string pfStem = Path.GetFileNameWithoutExtension(pf.Name); // e.g. "CHEATENGINE-X86_64-1A2B3C4D"
            string exeName = ExtractExecutableName(pfStem);            // e.g. "CHEATENGINE-X86_64"

            bool isExactMatch = KnownCheatStems.Contains(exeName);
            bool isKeywordMatch = !isExactMatch && ContainsCheatKeyword(exeName);

            bool isRecent = (now - pf.LastWriteTimeUtc) <= RecentThreshold;
            string ageNote = isRecent
                ? $"Recently executed: last write {pf.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC ({(int)(now - pf.LastWriteTimeUtc).TotalDays} days ago)"
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
                    Reason = $"Prefetch file '{pf.Name}' matches a known cheat tool executable name '{exeName}'. " +
                             "Prefetch records confirm this binary was executed on this system. " +
                             "The entry persists even if the executable has since been deleted.",
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
                    Reason = $"Prefetch file '{pf.Name}' contains the suspicious keyword '{matchedKeyword}' in the executable name '{exeName}'. " +
                             "This pattern is associated with cheat tools, injectors, or bypass software.",
                    Detail = ageNote + $" | Matched keyword: {matchedKeyword} | File size: {pf.Length} bytes"
                });
            }
            else if (isRecent)
            {
                // Even if not an exact/keyword match, still read the file content to scan for embedded cheat strings
                await ScanPrefetchFileContentAsync(ctx, pf, exeName, ageNote, ct);
            }
        }

        ctx.Report(0.82, "Prefetch directory scan complete");
    }

    // Read .pf file binary content and scan for embedded cheat-related strings.
    private async Task ScanPrefetchFileContentAsync(
        ScanContext ctx, FileInfo pf, string exeName, string ageNote, CancellationToken ct)
    {
        try
        {
            using var fs = new FileStream(pf.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            // Read up to 64 KB — enough to capture the referenced-files section of any prefetch file
            byte[] buffer = new byte[Math.Min(65536, (int)Math.Max(0, fs.Length))];
            if (buffer.Length == 0) return;

            int bytesRead = 0;
            int remaining = buffer.Length;
            while (remaining > 0)
            {
                int n = await fs.ReadAsync(buffer, bytesRead, remaining, ct);
                if (n == 0) break;
                bytesRead += n;
                remaining -= n;
            }

            if (bytesRead < 4) return;

            // Check the LNK magic: prefetch files have a signature at offset 4 (version) and 8 (signature "SCCA")
            // but the outer MAM-compressed wrapper starts with the compression signature.
            // We just search for ASCII/UTF-16 cheat keywords in the raw bytes.
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
                        Title = $"Suspicious Content in Prefetch File: {pf.Name}",
                        Risk = RiskLevel.Medium,
                        Location = pf.FullName,
                        FileName = pf.Name,
                        Reason = $"Prefetch file for '{exeName}' contains embedded references to the string '{keyword}', " +
                                 "suggesting the executable accessed or loaded cheat-related files during its run.",
                        Detail = ageNote + $" | Embedded keyword: {keyword}"
                    });
                    break; // One finding per file to avoid duplicates
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            // Access denied to individual prefetch file — skip silently
        }
        catch (IOException)
        {
            // I/O error on individual prefetch file — skip silently
        }
    }

    // Scan the PrefetchParameters registry key for evidence that prefetching was disabled
    // to hide execution history.
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
                    Risk = RiskLevel.Low,
                    Location = $@"HKLM\{PrefetchParamsKey}",
                    Reason = "The PrefetchParameters registry key is absent. This is unusual and may indicate registry tampering.",
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
                        Reason = "The Windows Prefetcher is disabled via EnablePrefetcher=0 in the registry. " +
                                 "Disabling prefetch prevents new execution evidence from being recorded and is a " +
                                 "known anti-forensics technique used by cheat software and cheat users to erase execution history.",
                        Detail = $"EnablePrefetcher = {enablePrefetcher} (0 = disabled, 1 = application only, 2 = boot only, 3 = all)"
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
                        Reason = $"EnablePrefetcher is set to {enablePrefetcher} (partially active). " +
                                 "The default is 3 (fully enabled). Partial disabling may limit execution history recording.",
                        Detail = $"EnablePrefetcher = {enablePrefetcher}"
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
                        Reason = "EnableSuperfetch=0 disables the SysMain service's prefetch-based memory management. " +
                                 "While not directly hiding execution traces, it is commonly disabled alongside Prefetch " +
                                 "in anti-forensics configurations.",
                        Detail = $"EnableSuperfetch = {enableSuperfetch}"
                    });
                }
            }

            // Check for missing EnablePrefetcher value entirely (a different form of disabling)
            if (enablePrefetcherVal == null)
            {
                // The value being absent may mean it's using defaults or was deliberately removed.
                // Only noteworthy if the Prefetch directory is also empty or missing.
                if (!Directory.Exists(PrefetchDirectory) ||
                    (Directory.Exists(PrefetchDirectory) &&
                     new DirectoryInfo(PrefetchDirectory).GetFiles("*.pf").Length == 0))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Prefetch Disabled and No Prefetch Files Present",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{PrefetchParamsKey}",
                        Reason = "The EnablePrefetcher registry value is absent and the Prefetch directory " +
                                 "contains no .pf files. This combination strongly suggests prefetch was " +
                                 "deliberately disabled to prevent execution history recording.",
                        Detail = $"Prefetch dir: {PrefetchDirectory}"
                    });
                }
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
                Reason = "Access denied when reading PrefetchParameters registry key.",
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

    // Extract the executable name portion from a prefetch filename stem.
    // Prefetch stems look like: CHEATENGINE-X86_64-1A2B3C4D
    // The last dash+8-hex-char segment is the hash suffix we need to strip.
    // Returns the stem with the hash suffix removed, uppercased.
    private static string ExtractExecutableName(string pfStem)
    {
        // Find the last dash followed by exactly 8 hex characters (end of string)
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
