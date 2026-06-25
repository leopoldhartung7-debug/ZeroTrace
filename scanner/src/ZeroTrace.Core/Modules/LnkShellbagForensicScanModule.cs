using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class LnkShellbagForensicScanModule : IScanModule
{
    public string Name => "LNK Shortcut & Shellbag Cheat Forensics";
    public double Weight => 4.6;
    public int ParallelGroup => 5;

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    // LNK magic: first 4 bytes of every valid .lnk file (CLSID header)
    private static readonly byte[] LnkMagic = { 0x4C, 0x00, 0x00, 0x00 };

    // Maximum bytes to read from each LNK file for path string extraction
    private const int LnkReadBytes = 8192;

    // Minimum printable string length when extracting embedded strings from binary data
    private const int MinStringLength = 4;

    // -------------------------------------------------------------------------
    // LNK scan directories
    // -------------------------------------------------------------------------

    private static readonly string[] LnkScanDirectories = new[]
    {
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Recent"),
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Recent\AutomaticDestinations"),
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Recent\CustomDestinations"),
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Internet Explorer\Quick Launch"),
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows\Start Menu\Programs"),
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows\Start Menu\Programs\Startup"),
    };

    // -------------------------------------------------------------------------
    // Registry key paths
    // -------------------------------------------------------------------------

    private const string ShellBagMruUser =
        @"SOFTWARE\Microsoft\Windows\Shell\BagMRU";

    private const string ShellBagsUser =
        @"SOFTWARE\Microsoft\Windows\Shell\Bags";

    private const string ShellBagMruClassesLocal =
        @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU";

    private const string ShellBagsClassesLocal =
        @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags";

    private const string TypedPathsKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";

    private const string RunMruKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";

    private const string ComDlgMruKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU";

    private const string LastVisitedPidlKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU";

    private const string RecentDocsLnkKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.lnk";

    // -------------------------------------------------------------------------
    // Cheat keywords — LNK filenames and embedded target paths
    // -------------------------------------------------------------------------

    private static readonly string[] CheatKeywords = new[]
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
        "shellcodeinjector",
        "loadlibinject",

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

        // Loaders / droppers
        "cheatloader",
        "hackloader",
        "gameloader",
        "payloadloader",
        "steamloader",
        "cheatinjector",
        "cheatlauncher",
        "shellcodeloader",
        "crypterloader",
        "packerdrop",

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
        "noflash",
        "norecoil",
        "aimlock",

        // GTA V / FiveM
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
        "2take1",
        "stand",
        "cherax",
        "orbital",
        "kiddion",
        "menyoo",
        "modest",
        "bigbasev",
        "ozark",
        "midnight",
        "nativetrainer",
        "gtavmenu",

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
        "cheatshell",
        "csgocheat",
        "cs2cheat",

        // Valorant
        "valoaimbot",
        "valorantcheat",
        "valoranthack",
        "valorantbypass",
        "valorantspoofer",

        // Roblox exploits
        "synapsex",
        "synapse",
        "krnl",
        "fluxus",
        "scriptware",
        "celery",
        "arceus",
        "oxygen",
        "evon",
        "robloxcheat",
        "robloxhack",
        "robloxexploit",

        // Apex / Rust / PUBG / Fortnite
        "apexcheat",
        "apexhack",
        "rustcheat",
        "rusthack",
        "pubgcheat",
        "pubghack",
        "fortnitecheat",
        "fortnitehack",
        "fortnitebypass",
        "warzonecheat",

        // Analysis tools
        "reclass",
        "cheatengine",
        "processhacker",
        "x64dbg",
        "x32dbg",
        "scyllahide",
        "titanhtide",
        "artmoney",
        "tsearch",
        "ollydbg",
        "immunitydebugger",

        // DMA tools
        "pcileech",
        "memproc",
        "dmaread",
        "physmem",
        "fpgaread",
        "dmawrite",
        "pcimem",

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
        "formbook",
        "azorult",
        "arkei",
        "bitrat",
        "xworm",
        "stealc",
        "lumma",
        "rhadamanthys",
    };

    // Shellbag cheat folder name keywords (slightly stricter subset for folder navigation records)
    private static readonly string[] ShellbagCheatKeywords = new[]
    {
        "injector",
        "cheat",
        "hack",
        "bypass",
        "eulen",
        "lynx",
        "impulse",
        "phantom",
        "2take1",
        "stand",
        "cherax",
        "kiddion",
        "menyoo",
        "synapse",
        "krnl",
        "xenos",
        "kdmapper",
        "spoofer",
        "hwid",
        "aimbot",
        "trainer",
        "loader",
        "dma",
        "pcileech",
        "aimware",
        "skeet",
        "gamesense",
        "onetap",
        "fatality",
        "neverlose",
        "reclass",
        "cheatengine",
        "processhacker",
        "xmrig",
        "asyncrat",
        "redline",
        "exploit",
        "modmenu",
        "fluxus",
        "scriptware",
        "nighthawk",
        "orbital",
        "epsilon",
        "bigbasev",
        "crowspoofer",
        "kspoofer",
        "absolutespoofer",
        "drvmap",
        "drivermapper",
        "ghostinject",
        "syringe",
        "earlybird",
        "processhollow",
        "physmem",
        "fpgaread",
        "raccoon",
        "vidar",
        "njrat",
        "dcrat",
        "quasar",
        "nanocore",
        "remcos",
        "bitrat",
        "xworm",
        "stealc",
        "lumma",
    };

    // -------------------------------------------------------------------------
    // IScanModule
    // -------------------------------------------------------------------------

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ctx.Report(0.0, "Initialising LNK & Shellbag forensics");

        await ScanLnkDirectoriesAsync(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.50, "Scanning Shellbag (User Shell\\BagMRU)");

        await Task.Run(() =>
        {
            ScanShellbagKey(ctx, Registry.CurrentUser, ShellBagMruUser, @"HKCU\Shell\BagMRU");

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.62, "Scanning Shellbag (Classes Local\\BagMRU)");
            ScanShellbagKey(ctx, Registry.CurrentUser, ShellBagMruClassesLocal, @"HKCU\Classes\BagMRU");

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.70, "Scanning TypedPaths");
            ScanTypedPaths(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.78, "Scanning RunMRU");
            ScanRunMru(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.84, "Scanning ComDlg32 OpenSavePidlMRU");
            ScanComDlgMru(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.91, "Scanning LastVisitedPidlMRU");
            ScanLastVisitedPidl(ctx);

            ct.ThrowIfCancellationRequested();
            ctx.Report(0.96, "Scanning RecentDocs .lnk entries");
            ScanRecentDocsLnk(ctx);

            ctx.Report(1.0, "LNK & Shellbag forensics complete");
        }, ct);
    }

    // -------------------------------------------------------------------------
    // LNK / Jump-List Directory Scan
    // -------------------------------------------------------------------------

    private async Task ScanLnkDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        int dirIndex = 0;

        foreach (string dir in LnkScanDirectories)
        {
            ct.ThrowIfCancellationRequested();

            dirIndex++;
            double dirFraction = (dirIndex / (double)LnkScanDirectories.Length) * 0.46;
            ctx.Report(dirFraction, $"Scanning LNK files in {dir}");

            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }
            catch (IOException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                string fileName = Path.GetFileName(filePath);
                string extension = Path.GetExtension(filePath);

                bool isLnk = extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase);
                bool isAutoDest = extension.Equals(".automaticDestinations-ms", StringComparison.OrdinalIgnoreCase);
                bool isCustomDest = extension.Equals(".customDestinations-ms", StringComparison.OrdinalIgnoreCase);

                if (!isLnk && !isAutoDest && !isCustomDest) continue;

                ctx.IncrementFiles();

                // Check the filename itself before reading the file content
                bool fileNameMatch = ContainsKeyword(fileName, CheatKeywords);
                if (fileNameMatch)
                {
                    string kw = GetMatchedKeyword(fileName, CheatKeywords);
                    var fi = new FileInfo(filePath);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Tool LNK Filename: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"The shortcut file '{fileName}' has a filename matching the cheat-related keyword " +
                                 $"'{kw}'. LNK files are created automatically when files are opened via Windows " +
                                 "Explorer and persist after the target executable is deleted.",
                        Detail = $"Directory: {dir} | Keyword: {kw} | " +
                                 $"Last write: {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC"
                    });
                }

                // Read and inspect the binary content for embedded path strings
                await InspectLnkFileAsync(ctx, filePath, fileName, dir, isLnk, fileNameMatch, ct);
            }
        }
    }

    // Read a LNK or jump-list file and scan its binary content for embedded cheat-related strings.
    private async Task InspectLnkFileAsync(
        ScanContext ctx,
        string filePath,
        string fileName,
        string directory,
        bool isLnk,
        bool fileNameAlreadyFlagged,
        CancellationToken ct)
    {
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            if (fs.Length < 4) return;

            int readLen = (int)Math.Min(fs.Length, LnkReadBytes);
            byte[] buffer = new byte[readLen];

            int offset = 0;
            while (offset < readLen)
            {
                int n = await fs.ReadAsync(buffer, offset, readLen - offset, ct);
                if (n == 0) break;
                offset += n;
            }

            if (offset < 4) return;

            // For .lnk files, verify the magic header before parsing
            if (isLnk)
            {
                if (buffer[0] != LnkMagic[0] || buffer[1] != LnkMagic[1] ||
                    buffer[2] != LnkMagic[2] || buffer[3] != LnkMagic[3])
                {
                    return;
                }
            }

            // Extract printable strings from both ASCII and UTF-16LE encodings.
            // LNK files store the target path, working directory, arguments, and icon location
            // as Unicode strings at known offsets, but we do a full binary scan to cover all cases.
            string asciiContent = ExtractAsciiStrings(buffer, offset);
            string unicodeContent = ExtractUnicodeStrings(buffer, offset);
            string combined = asciiContent + " " + unicodeContent;

            // Skip re-flagging files whose filename was already flagged
            if (fileNameAlreadyFlagged) return;

            if (!ContainsKeyword(combined, CheatKeywords)) return;

            string matchedKw = GetMatchedKeyword(combined, CheatKeywords);
            string snippet = ExtractContextSnippet(combined, matchedKw, 150);

            var fileInfo = new FileInfo(filePath);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"LNK Target References Cheat Tool: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"The shortcut file '{fileName}' contains an embedded path or string referencing " +
                         $"'{matchedKw}', a known cheat-related keyword. This indicates the shortcut pointed " +
                         "to a cheat tool or a directory containing cheat software. LNK files persist after " +
                         "the target executable is deleted, making them reliable execution artifacts.",
                Detail = $"Directory: {directory} | Keyword: {matchedKw} | " +
                         $"Content: {snippet} | " +
                         $"Last write: {fileInfo.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC"
            });
        }
        catch (UnauthorizedAccessException)
        {
            // Skip files we cannot read
        }
        catch (IOException)
        {
            // Skip I/O errors on individual files
        }
    }

    // -------------------------------------------------------------------------
    // Shellbag BagMRU Registry Scan
    // -------------------------------------------------------------------------

    private void ScanShellbagKey(ScanContext ctx, RegistryKey hive, string rootKeyPath, string displayRoot)
    {
        try
        {
            using RegistryKey? rootKey = hive.OpenSubKey(rootKeyPath, writable: false);
            if (rootKey == null) return;

            ctx.IncrementRegistryKeys();
            RecurseScanShellbag(ctx, rootKey, displayRoot, depth: 0);
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Shellbag Registry Access Denied: {displayRoot}",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{rootKeyPath}",
                Reason = "Access denied reading Shellbag registry.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Shellbag Registry Read Error: {displayRoot}",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{rootKeyPath}",
                Reason = "I/O error reading Shellbag registry.",
                Detail = ex.Message
            });
        }
    }

    // Recursive BagMRU walker — inspects SHITEMID binary blobs for folder name strings.
    private void RecurseScanShellbag(ScanContext ctx, RegistryKey key, string displayPath, int depth)
    {
        // Guard against pathological recursion (circular references or very deep trees)
        if (depth > 25) return;

        string[] valueNames;
        string[] subKeyNames;

        try
        {
            valueNames = key.GetValueNames();
            subKeyNames = key.GetSubKeyNames();
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }
        catch (IOException)
        {
            return;
        }

        foreach (string valueName in valueNames)
        {
            // Skip well-known administrative values
            if (valueName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase) ||
                valueName.Equals("NodeSlot", StringComparison.OrdinalIgnoreCase) ||
                valueName.Equals("NodeSlots", StringComparison.OrdinalIgnoreCase) ||
                valueName.Equals("Attributes", StringComparison.OrdinalIgnoreCase))
                continue;

            ctx.IncrementRegistryKeys();

            byte[]? data;
            try
            {
                data = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
            }
            catch (IOException)
            {
                continue;
            }

            if (data == null || data.Length < 4) continue;

            // Extract printable strings from the SHITEMID binary blob.
            // Shell item IDs encode folder names as ASCII or Unicode strings at various offsets
            // depending on the item type (file system, drive, virtual folder, etc.).
            string asciiStrings = ExtractAsciiStrings(data, data.Length);
            string unicodeStrings = ExtractUnicodeStrings(data, data.Length);
            string combined = asciiStrings + " " + unicodeStrings;

            if (!ContainsKeyword(combined, ShellbagCheatKeywords)) continue;

            string matchedKw = GetMatchedKeyword(combined, ShellbagCheatKeywords);
            string snippet = ExtractContextSnippet(combined, matchedKw, 100);

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Shellbag: Cheat-Related Folder Accessed — '{matchedKw}'",
                Risk = RiskLevel.High,
                Location = displayPath,
                FileName = valueName,
                Reason = $"The Windows Shellbag registry records that a folder containing '{matchedKw}' was " +
                         "accessed via Windows Explorer or a file dialog. Shellbag entries record every folder " +
                         "a user has navigated to and persist after the folder and its contents are deleted.",
                Detail = $"Registry path: {displayPath} | Value: {valueName} | Keyword: {matchedKw} | Content: {snippet}"
            });
        }

        // Recurse into numeric subkeys representing child nodes in the BagMRU tree
        foreach (string subKeyName in subKeyNames)
        {
            try
            {
                using RegistryKey? subKey = key.OpenSubKey(subKeyName, writable: false);
                if (subKey == null) continue;

                ctx.IncrementRegistryKeys();
                RecurseScanShellbag(ctx, subKey, $"{displayPath}\\{subKeyName}", depth + 1);
            }
            catch (UnauthorizedAccessException)
            {
                // Skip subkeys we cannot access
            }
            catch (IOException)
            {
                // Skip I/O errors
            }
        }
    }

    // -------------------------------------------------------------------------
    // TypedPaths — Explorer address bar history
    // -------------------------------------------------------------------------

    private void ScanTypedPaths(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(TypedPathsKey, writable: false);
            if (key == null) return;

            ctx.IncrementRegistryKeys();

            string[] valueNames;
            try { valueNames = key.GetValueNames(); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (string valueName in valueNames)
            {
                ctx.IncrementRegistryKeys();

                string? pathValue;
                try { pathValue = key.GetValue(valueName) as string; }
                catch (IOException) { continue; }

                if (string.IsNullOrWhiteSpace(pathValue)) continue;

                if (!ContainsKeyword(pathValue, CheatKeywords)) continue;

                string kw = GetMatchedKeyword(pathValue, CheatKeywords);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"TypedPaths: Cheat Directory Navigated — '{kw}'",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{TypedPathsKey}",
                    FileName = valueName,
                    Reason = $"The Windows Explorer TypedPaths registry records that the user manually typed the path " +
                             $"'{pathValue}' into the Explorer address bar. This path contains the cheat-related " +
                             $"keyword '{kw}'. TypedPaths entries persist after the target folder is deleted, " +
                             "providing a reliable record of deliberate navigation to the cheat directory.",
                    Detail = $"Value: {valueName} | Path: {pathValue} | Keyword: {kw}"
                });
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "TypedPaths Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{TypedPathsKey}",
                Reason = "Access denied reading TypedPaths registry.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "TypedPaths Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{TypedPathsKey}",
                Reason = "I/O error reading TypedPaths registry.",
                Detail = ex.Message
            });
        }
    }

    // -------------------------------------------------------------------------
    // RunMRU — Run dialog (Win+R) history
    // -------------------------------------------------------------------------

    private void ScanRunMru(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunMruKey, writable: false);
            if (key == null) return;

            ctx.IncrementRegistryKeys();

            string[] valueNames;
            try { valueNames = key.GetValueNames(); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (string valueName in valueNames)
            {
                if (valueName.Equals("MRUList", StringComparison.OrdinalIgnoreCase)) continue;

                ctx.IncrementRegistryKeys();

                string? runValue;
                try { runValue = key.GetValue(valueName) as string; }
                catch (IOException) { continue; }

                if (string.IsNullOrWhiteSpace(runValue)) continue;

                // RunMRU values have a trailing \x01 separator appended by Windows
                string cleanValue = runValue.TrimEnd('\x01');

                if (!ContainsKeyword(cleanValue, CheatKeywords)) continue;

                string kw = GetMatchedKeyword(cleanValue, CheatKeywords);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RunMRU: Cheat Command in Run Dialog History — '{kw}'",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{RunMruKey}",
                    FileName = valueName,
                    Reason = $"The Windows Run dialog history (RunMRU) records that the user typed '{cleanValue}' " +
                             $"into the Win+R Run dialog. This entry contains the cheat-related keyword '{kw}'. " +
                             "RunMRU entries persist after the referenced program is deleted and indicate " +
                             "deliberate manual execution of the tool.",
                    Detail = $"Value: {valueName} | Command: {cleanValue} | Keyword: {kw}"
                });
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "RunMRU Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{RunMruKey}",
                Reason = "Access denied reading RunMRU registry.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "RunMRU Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{RunMruKey}",
                Reason = "I/O error reading RunMRU registry.",
                Detail = ex.Message
            });
        }
    }

    // -------------------------------------------------------------------------
    // ComDlg32 OpenSavePidlMRU — File open/save dialog history
    // -------------------------------------------------------------------------

    private void ScanComDlgMru(ScanContext ctx)
    {
        try
        {
            using RegistryKey? root = Registry.CurrentUser.OpenSubKey(ComDlgMruKey, writable: false);
            if (root == null) return;

            ctx.IncrementRegistryKeys();

            string[] subKeyNames;
            try { subKeyNames = root.GetSubKeyNames(); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            // Each subkey is a file extension (e.g. "*", ".exe", ".dll") or "LastVisitedPidlMRU"
            foreach (string extName in subKeyNames)
            {
                try
                {
                    using RegistryKey? extKey = root.OpenSubKey(extName, writable: false);
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

                        // Values are binary PIDLs — extract strings from the raw bytes
                        byte[]? data;
                        try
                        {
                            data = extKey.GetValue(valueName, null,
                                RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
                        }
                        catch (IOException) { continue; }

                        if (data == null || data.Length < 4) continue;

                        string asciiContent = ExtractAsciiStrings(data, data.Length);
                        string unicodeContent = ExtractUnicodeStrings(data, data.Length);
                        string combined = asciiContent + " " + unicodeContent;

                        if (!ContainsKeyword(combined, CheatKeywords)) continue;

                        string kw = GetMatchedKeyword(combined, CheatKeywords);
                        string snippet = ExtractContextSnippet(combined, kw, 120);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ComDlg32 File Dialog: Cheat Path in Open/Save History — '{kw}'",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{ComDlgMruKey}\{extName}",
                            FileName = valueName,
                            Reason = $"The Windows common file dialog MRU (OpenSavePidlMRU) records that a " +
                                     $"file matching the cheat-related keyword '{kw}' was selected in a file " +
                                     "open or save dialog. This indicates the user directly interacted with a " +
                                     "cheat-related file through a GUI dialog. Entries persist after file deletion.",
                            Detail = $"Extension group: {extName} | Value: {valueName} | Keyword: {kw} | Content: {snippet}"
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
                Title = "ComDlg32 OpenSavePidlMRU Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{ComDlgMruKey}",
                Reason = "Access denied reading ComDlg32 OpenSavePidlMRU registry.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "ComDlg32 OpenSavePidlMRU Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{ComDlgMruKey}",
                Reason = "I/O error reading ComDlg32 OpenSavePidlMRU registry.",
                Detail = ex.Message
            });
        }
    }

    // -------------------------------------------------------------------------
    // LastVisitedPidlMRU — Most recently visited folder in file dialogs
    // -------------------------------------------------------------------------

    private void ScanLastVisitedPidl(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(LastVisitedPidlKey, writable: false);
            if (key == null) return;

            ctx.IncrementRegistryKeys();

            string[] valueNames;
            try { valueNames = key.GetValueNames(); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (string valueName in valueNames)
            {
                if (valueName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase)) continue;

                ctx.IncrementRegistryKeys();

                byte[]? data;
                try
                {
                    data = key.GetValue(valueName, null,
                        RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
                }
                catch (IOException) { continue; }

                if (data == null || data.Length < 4) continue;

                string asciiContent = ExtractAsciiStrings(data, data.Length);
                string unicodeContent = ExtractUnicodeStrings(data, data.Length);
                string combined = asciiContent + " " + unicodeContent;

                if (!ContainsKeyword(combined, CheatKeywords)) continue;

                string kw = GetMatchedKeyword(combined, CheatKeywords);
                string snippet = ExtractContextSnippet(combined, kw, 100);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"LastVisitedPidlMRU: Cheat Folder Visited in File Dialog — '{kw}'",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{LastVisitedPidlKey}",
                    FileName = valueName,
                    Reason = $"The LastVisitedPidlMRU registry records that a folder containing '{kw}' was " +
                             "navigated to in a Windows file open/save dialog. This indicates the user " +
                             "was browsing to or from a cheat-related directory. Entries persist after deletion.",
                    Detail = $"Value: {valueName} | Keyword: {kw} | Content: {snippet}"
                });
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "LastVisitedPidlMRU Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{LastVisitedPidlKey}",
                Reason = "Access denied reading LastVisitedPidlMRU registry.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "LastVisitedPidlMRU Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{LastVisitedPidlKey}",
                Reason = "I/O error reading LastVisitedPidlMRU registry.",
                Detail = ex.Message
            });
        }
    }

    // -------------------------------------------------------------------------
    // RecentDocs .lnk subkey
    // -------------------------------------------------------------------------

    private void ScanRecentDocsLnk(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RecentDocsLnkKey, writable: false);
            if (key == null) return;

            ctx.IncrementRegistryKeys();

            string[] valueNames;
            try { valueNames = key.GetValueNames(); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (string valueName in valueNames)
            {
                if (valueName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase)) continue;

                ctx.IncrementRegistryKeys();

                byte[]? data;
                try
                {
                    data = key.GetValue(valueName, null,
                        RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
                }
                catch (IOException) { continue; }

                if (data == null || data.Length < 2) continue;

                // RecentDocs values begin with a null-terminated Unicode filename
                string fileName = ExtractNullTerminatedUnicode(data);
                if (string.IsNullOrWhiteSpace(fileName)) continue;

                if (!ContainsKeyword(fileName, CheatKeywords)) continue;

                string kw = GetMatchedKeyword(fileName, CheatKeywords);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RecentDocs .lnk: Cheat Shortcut Recently Opened — {fileName}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{RecentDocsLnkKey}",
                    FileName = fileName,
                    Reason = $"The Windows RecentDocs registry records that a .lnk shortcut named '{fileName}' " +
                             $"was recently opened. The shortcut name contains the cheat-related keyword '{kw}'. " +
                             "This indicates the user recently interacted with a cheat tool shortcut. " +
                             "The entry persists after the shortcut and its target are deleted.",
                    Detail = $"Value: {valueName} | Shortcut: {fileName} | Keyword: {kw}"
                });
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "RecentDocs .lnk Registry Access Denied",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{RecentDocsLnkKey}",
                Reason = "Access denied reading RecentDocs .lnk registry.",
                Detail = ex.Message
            });
        }
        catch (IOException ex)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "RecentDocs .lnk Registry Read Error",
                Risk = RiskLevel.Low,
                Location = $@"HKCU\{RecentDocsLnkKey}",
                Reason = "I/O error reading RecentDocs .lnk registry.",
                Detail = ex.Message
            });
        }
    }

    // -------------------------------------------------------------------------
    // String extraction helpers
    // -------------------------------------------------------------------------

    // Extract printable ASCII strings of length >= MinStringLength from a byte array.
    private static string ExtractAsciiStrings(byte[] data, int length)
    {
        var sb = new System.Text.StringBuilder();
        var current = new System.Text.StringBuilder();

        for (int i = 0; i < length; i++)
        {
            byte b = data[i];
            if (b >= 0x20 && b < 0x7F)
            {
                current.Append((char)b);
            }
            else
            {
                if (current.Length >= MinStringLength)
                {
                    sb.Append(current);
                    sb.Append(' ');
                }
                current.Clear();
            }
        }

        if (current.Length >= MinStringLength)
        {
            sb.Append(current);
        }

        return sb.ToString();
    }

    // Extract printable UTF-16LE strings of length >= MinStringLength from a byte array.
    private static string ExtractUnicodeStrings(byte[] data, int length)
    {
        var sb = new System.Text.StringBuilder();
        var current = new System.Text.StringBuilder();
        int alignedLen = length - (length % 2);

        for (int i = 0; i < alignedLen; i += 2)
        {
            ushort wchar = (ushort)(data[i] | (data[i + 1] << 8));
            if (wchar >= 0x20 && wchar < 0x7F)
            {
                current.Append((char)wchar);
            }
            else
            {
                if (current.Length >= MinStringLength)
                {
                    sb.Append(current);
                    sb.Append(' ');
                }
                current.Clear();
            }
        }

        if (current.Length >= MinStringLength)
        {
            sb.Append(current);
        }

        return sb.ToString();
    }

    // Extract a null-terminated UTF-16LE string from the start of a binary blob.
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

    // Return true if text contains any keyword from the array (case-insensitive).
    private static bool ContainsKeyword(string text, string[] keywords)
    {
        foreach (string kw in keywords)
        {
            if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    // Return the first matching keyword found in text, or empty string.
    private static string GetMatchedKeyword(string text, string[] keywords)
    {
        foreach (string kw in keywords)
        {
            if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return kw;
        }
        return string.Empty;
    }

    // Extract a snippet of context around the matched keyword for Detail fields.
    private static string ExtractContextSnippet(string text, string keyword, int maxLength)
    {
        if (string.IsNullOrEmpty(keyword)) return string.Empty;

        int idx = text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return string.Empty;

        int start = Math.Max(0, idx - 35);
        int end = Math.Min(text.Length, idx + keyword.Length + 80);
        string snippet = text.Substring(start, end - start).Replace('\0', ' ').Trim();

        if (snippet.Length > maxLength)
            snippet = snippet.Substring(0, maxLength) + "...";

        return snippet;
    }
}
