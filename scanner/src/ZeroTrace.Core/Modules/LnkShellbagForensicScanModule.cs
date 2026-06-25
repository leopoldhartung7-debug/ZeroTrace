using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class LnkShellbagForensicScanModule : IScanModule
{
    public string Name => "LNK Shortcut & Shellbag Cheat Forensics";
    public double Weight => 4.6;
    public int ParallelGroup => 5;

    // LNK magic bytes: the first 4 bytes of every .lnk file
    private static readonly byte[] LnkMagic = { 0x4C, 0x00, 0x00, 0x00 };

    // Maximum bytes to read from each LNK file for path string extraction
    private const int LnkReadBytes = 4096;

    // LNK scan directories
    private static readonly string[] LnkScanDirectories = new[]
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Recent"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Recent\AutomaticDestinations"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Recent\CustomDestinations"),
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Internet Explorer\Quick Launch"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows\Start Menu\Programs"),
    };

    // Registry paths for shellbag, TypedPaths, and RunMRU
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

    // Cheat keywords to match against LNK filenames and embedded paths
    private static readonly string[] CheatKeywords = new[]
    {
        "injector",
        "cheat",
        "hack",
        "bypass",
        "spoofer",
        "hwid",
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
        "radar",
        "spinbot",
        "aimassist",
        "nofall",
        "autoshoot",
        "recoil",
        "eulen",
        "lynx",
        "impulse",
        "phantom",
        "disturbed",
        "hamster",
        "nighthawk",
        "epsilon",
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
        "aimware",
        "skeet",
        "gamesense",
        "onetap",
        "fatality",
        "nixware",
        "neverlose",
        "interium",
        "lhook",
        "synapsex",
        "synapse",
        "krnl",
        "fluxus",
        "scriptware",
        "celery",
        "xenos",
        "ghinjector",
        "extremeinjector",
        "winject",
        "dllinjector",
        "manualmapper",
        "kdmapper",
        "drvmap",
        "drivermapper",
        "eacbypass",
        "bebypass",
        "vanguardbypass",
        "faceitbypass",
        "vacbypass",
        "hwidspoofer",
        "crowspoofer",
        "kspoofer",
        "absolutespoofer",
        "tsspoofer",
        "spoofandplay",
        "pcileech",
        "memproc",
        "dmaread",
        "physmem",
        "xmrig",
        "asyncrat",
        "njrat",
        "dcrat",
        "redline",
        "raccoon",
        "vidar",
        "reclass",
        "cheatengine",
        "processhacker",
        "x64dbg",
        "x32dbg",
        "artmoney",
        "tsearch",
        "scyllahide",
        "apexcheat",
        "rustcheat",
        "pubgcheat",
        "fortnitebypass",
        "valoaimbot",
        "valorantcheat",
    };

    // Shellbag cheat folder name keywords (stricter subset for folder access records)
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
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ctx.Report(0.0, "Initialising LNK & Shellbag forensics");

        await ScanLnkDirectoriesAsync(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.55, "Scanning Shellbag registry (User Shell)");

        await Task.Run(() =>
        {
            ScanShellbagKey(ctx, Registry.CurrentUser, ShellBagMruUser, "HKCU\\Shell\\BagMRU");
            ct.ThrowIfCancellationRequested();
            ctx.Report(0.65, "Scanning Shellbag registry (Classes Local)");

            ScanShellbagKey(ctx, Registry.CurrentUser, ShellBagMruClassesLocal, "HKCU\\Classes\\BagMRU");
            ct.ThrowIfCancellationRequested();
            ctx.Report(0.75, "Scanning TypedPaths");

            ScanTypedPaths(ctx);
            ct.ThrowIfCancellationRequested();
            ctx.Report(0.87, "Scanning RunMRU");

            ScanRunMru(ctx);
            ctx.Report(1.0, "LNK & Shellbag forensics complete");
        }, ct);
    }

    // Enumerate all LNK scan directories and inspect .lnk files.
    private async Task ScanLnkDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        int dirIndex = 0;
        foreach (string dir in LnkScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            dirIndex++;
            double dirFraction = (dirIndex / (double)LnkScanDirectories.Length) * 0.50;
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

                // Scan .lnk files — but also scan AutomaticDestinations (.automaticDestinations-ms)
                // and CustomDestinations (.customDestinations-ms) for embedded target paths.
                bool isLnk = extension.Equals(".lnk", StringComparison.OrdinalIgnoreCase);
                bool isJumpList = extension.Equals(".automaticDestinations-ms", StringComparison.OrdinalIgnoreCase) ||
                                  extension.Equals(".customDestinations-ms", StringComparison.OrdinalIgnoreCase);

                if (!isLnk && !isJumpList) continue;

                ctx.IncrementFiles();

                // First check the filename itself
                bool fileNameMatch = ContainsCheatKeyword(fileName, CheatKeywords);
                if (fileNameMatch)
                {
                    string kw = GetMatchedKeyword(fileName, CheatKeywords);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Tool LNK Filename: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"The LNK shortcut file '{fileName}' has a filename matching the cheat-related keyword '{kw}'. " +
                                 "LNK files are created automatically when files are opened and persist after the target is deleted.",
                        Detail = $"Directory: {dir} | Matched keyword: {kw}"
                    });
                }

                // Read and inspect the binary content of the LNK/jump list file
                await InspectLnkFileAsync(ctx, filePath, fileName, dir, isLnk, ct);
            }
        }
    }

    // Read a LNK or jump-list file and scan its binary content for cheat-related embedded paths.
    private async Task InspectLnkFileAsync(
        ScanContext ctx, string filePath, string fileName, string directory,
        bool isLnk, CancellationToken ct)
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

            // For .lnk files, verify the magic header
            if (isLnk)
            {
                if (buffer[0] != LnkMagic[0] || buffer[1] != LnkMagic[1] ||
                    buffer[2] != LnkMagic[2] || buffer[3] != LnkMagic[3])
                {
                    // Not a valid LNK file despite the extension
                    return;
                }
            }

            // Extract printable strings from both ASCII and UTF-16LE encodings
            string asciiContent = ExtractAsciiStrings(buffer, offset);
            string unicodeContent = ExtractUnicodeStrings(buffer, offset);

            // Combine for a single-pass keyword search
            string combined = asciiContent + " " + unicodeContent;

            // Skip checking the filename again if we already flagged it
            bool fileNameAlreadyFlagged = ContainsCheatKeyword(fileName, CheatKeywords);
            if (fileNameAlreadyFlagged) return;

            bool contentMatch = ContainsCheatKeyword(combined, CheatKeywords);
            if (!contentMatch) return;

            string matchedKw = GetMatchedKeyword(combined, CheatKeywords);

            // Extract the best matching snippet for the Detail field
            string snippet = ExtractContextSnippet(combined, matchedKw, 120);

            var fi = new FileInfo(filePath);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"LNK Target References Cheat Tool: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"The LNK shortcut file '{fileName}' contains an embedded path or string referencing " +
                         $"'{matchedKw}', a known cheat-related keyword. This indicates the shortcut pointed to " +
                         "a cheat tool or a directory containing cheat software. The LNK persists after the target is deleted.",
                Detail = $"Directory: {directory} | Matched keyword: {matchedKw} | " +
                         $"Snippet: {snippet} | Last write: {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss} UTC"
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

    // Recursively scan a Shellbag BagMRU registry key and its subkeys for cheat-related folder names.
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
                Reason = "Access denied reading Shellbag registry. Elevated privileges may be required.",
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

    // Recursive helper that walks all BagMRU subkeys and inspects binary value data for folder name strings.
    private void RecurseScanShellbag(ScanContext ctx, RegistryKey key, string displayPath, int depth)
    {
        // Guard against pathological recursion or circular references
        if (depth > 20) return;

        // Inspect the binary values at this key level — they encode shell item ID list (SHITEMID) data
        // which contains folder names as embedded strings.
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
            if (valueName.Equals("MRUListEx", StringComparison.OrdinalIgnoreCase) ||
                valueName.Equals("NodeSlot", StringComparison.OrdinalIgnoreCase) ||
                valueName.Equals("NodeSlots", StringComparison.OrdinalIgnoreCase))
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

            // Extract ASCII and Unicode strings from the SHITEMID binary blob
            string asciiStrings = ExtractAsciiStrings(data, data.Length);
            string unicodeStrings = ExtractUnicodeStrings(data, data.Length);
            string combined = asciiStrings + " " + unicodeStrings;

            if (!ContainsCheatKeyword(combined, ShellbagCheatKeywords)) continue;

            string matchedKw = GetMatchedKeyword(combined, ShellbagCheatKeywords);
            string snippet = ExtractContextSnippet(combined, matchedKw, 100);

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Shellbag: Cheat-Related Folder Access — '{matchedKw}'",
                Risk = RiskLevel.High,
                Location = displayPath,
                FileName = valueName,
                Reason = $"The Shellbag registry records that a folder containing '{matchedKw}' was accessed via " +
                         "Windows Explorer. Shellbag entries record every folder a user has navigated to and " +
                         "persist after the folder and its contents are deleted.",
                Detail = $"Registry path: {displayPath} | Value: {valueName} | Keyword: {matchedKw} | Content: {snippet}"
            });
        }

        // Recurse into numeric subkeys (0, 1, 2, ... representing child nodes)
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

    // Scan HKCU\...\Explorer\TypedPaths for cheat-related paths typed into the Explorer address bar.
    private void ScanTypedPaths(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(TypedPathsKey, writable: false);
            if (key == null) return;

            ctx.IncrementRegistryKeys();

            string[] valueNames = key.GetValueNames();
            foreach (string valueName in valueNames)
            {
                ctx.IncrementRegistryKeys();

                string? pathValue;
                try
                {
                    pathValue = key.GetValue(valueName) as string;
                }
                catch (IOException)
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(pathValue)) continue;

                if (!ContainsCheatKeyword(pathValue, CheatKeywords)) continue;

                string kw = GetMatchedKeyword(pathValue, CheatKeywords);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"TypedPaths: Cheat Directory Navigated — '{kw}'",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{TypedPathsKey}",
                    FileName = valueName,
                    Reason = $"The Windows Explorer TypedPaths registry records that the user manually typed the path " +
                             $"'{pathValue}' into the Explorer address bar. This path contains the cheat-related keyword " +
                             $"'{kw}'. TypedPaths entries persist after the target folder is deleted.",
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

    // Scan HKCU\...\Explorer\RunMRU for cheat-related commands typed into the Run dialog.
    private void ScanRunMru(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.CurrentUser.OpenSubKey(RunMruKey, writable: false);
            if (key == null) return;

            ctx.IncrementRegistryKeys();

            string[] valueNames = key.GetValueNames();
            foreach (string valueName in valueNames)
            {
                if (valueName.Equals("MRUList", StringComparison.OrdinalIgnoreCase)) continue;

                ctx.IncrementRegistryKeys();

                string? runValue;
                try
                {
                    runValue = key.GetValue(valueName) as string;
                }
                catch (IOException)
                {
                    continue;
                }

                if (string.IsNullOrWhiteSpace(runValue)) continue;

                // RunMRU values have a trailing \1 suffix appended by Windows — strip it
                string cleanValue = runValue.TrimEnd('\x01');

                if (!ContainsCheatKeyword(cleanValue, CheatKeywords)) continue;

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
                             "RunMRU entries persist after the referenced program is deleted.",
                    Detail = $"Value name: {valueName} | Command: {cleanValue} | Keyword: {kw}"
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

    // Extract printable ASCII strings (length >= 4) from a byte array.
    private static string ExtractAsciiStrings(byte[] data, int length)
    {
        var sb = new System.Text.StringBuilder();
        var current = new System.Text.StringBuilder();

        for (int i = 0; i < length; i++)
        {
            byte b = data[i];
            if (b >= 0x20 && b < 0x7F) // printable ASCII
            {
                current.Append((char)b);
            }
            else
            {
                if (current.Length >= 4)
                {
                    sb.Append(current);
                    sb.Append(' ');
                }
                current.Clear();
            }
        }
        if (current.Length >= 4)
        {
            sb.Append(current);
        }
        return sb.ToString();
    }

    // Extract printable Unicode (UTF-16LE) strings (length >= 4 chars) from a byte array.
    private static string ExtractUnicodeStrings(byte[] data, int length)
    {
        var sb = new System.Text.StringBuilder();
        var current = new System.Text.StringBuilder();
        int alignedLen = length - (length % 2);

        for (int i = 0; i < alignedLen; i += 2)
        {
            ushort wchar = (ushort)(data[i] | (data[i + 1] << 8));
            if (wchar >= 0x20 && wchar < 0x7F) // printable ASCII range in Unicode
            {
                current.Append((char)wchar);
            }
            else
            {
                if (current.Length >= 4)
                {
                    sb.Append(current);
                    sb.Append(' ');
                }
                current.Clear();
            }
        }
        if (current.Length >= 4)
        {
            sb.Append(current);
        }
        return sb.ToString();
    }

    // Check if the text contains any of the provided cheat keywords (case-insensitive).
    private static bool ContainsCheatKeyword(string text, string[] keywords)
    {
        foreach (string kw in keywords)
        {
            if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    // Return the first matching cheat keyword found in the text, or empty string.
    private static string GetMatchedKeyword(string text, string[] keywords)
    {
        foreach (string kw in keywords)
        {
            if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return kw;
        }
        return string.Empty;
    }

    // Extract a context snippet around the matched keyword for the Detail field.
    private static string ExtractContextSnippet(string text, string keyword, int maxLength)
    {
        if (string.IsNullOrEmpty(keyword)) return string.Empty;

        int idx = text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return string.Empty;

        int start = Math.Max(0, idx - 30);
        int end = Math.Min(text.Length, idx + keyword.Length + 70);
        string snippet = text.Substring(start, end - start).Trim();

        if (snippet.Length > maxLength)
            snippet = snippet.Substring(0, maxLength) + "...";

        return snippet;
    }
}
