using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class MemoryCheatSignatureScanModule : IScanModule
{
    public string Name => "Memory-Cheat-Signature";
    public double Weight => 0.75;
    public int ParallelGroup => 4;

    private static readonly string[] CheatBrandStrings =
    {
        "eulen", "lynxclient", "hamster", "aimware", "skeet.cc", "gamesense",
        "onetap", "fatality", "nixware", "neverlose", "kiddion", "2take1",
        "stand menu", "cherax", "menyoo", "evolution cheat", "nighthawk",
        "epsilon cheat", "phantom cheat", "baddie", "impulse cheat"
    };

    private static readonly string[] AntiAcBypassStrings =
    {
        "bypass anti-cheat", "vanguard bypass", "eac bypass", "battleye bypass",
        "vac bypass", "disable anticheat", "anticheat killed"
    };

    private static readonly string[] CheatFeatureStrings =
    {
        "aimbot active", "esp enabled", "wallhack on", "godmode enabled",
        "triggerbot active", "speedhack", "noclip active", "bhop active",
        "aimlock"
    };

    private static readonly string[] CheatMenuStrings =
    {
        "esp settings", "aimbot settings", "wallhack settings", "misc settings",
        "rage aimbot", "legit aimbot", "backtrack", "resolver"
    };

    private static readonly string[] C2AuthStrings =
    {
        "hwid check", "license check", "subscription expired", "auth failed",
        "bypass hwid"
    };

    private static readonly string[] FivemCheatStrings =
    {
        "cfx bypass", "citizenfx bypass", "fivem cheat", "lua executor", "nui inject"
    };

    private static readonly string[] CheatDllExportNames =
    {
        "InitCheat", "StartCheat", "LoadCheat", "EnableCheat", "InjectCheat",
        "StartAimbot", "EnableESP", "BypassAC", "DisableVanguard", "DisableEAC",
        "DisableBE", "PatchAntiCheat"
    };

    private static readonly string[] CheatConfigKeys =
    {
        "aimbot", "esp", "wallhack", "triggerbot", "speedhack", "bhop", "radar",
        "noclip", "godmode", "spinbot", "autofire", "backtrack", "resolver",
        "fov", "smooth", "aimkey", "aimbone", "drawbox", "drawesp", "drawname", "drawhp"
    };

    private static readonly string[] ConfigExtensions =
    {
        ".json", ".ini", ".cfg"
    };

    private static readonly string[] BrowserProfileDirKeywords =
    {
        "chrome", "chromium", "firefox", "edge", "brave", "opera", "vivaldi",
        "google\\chrome", "mozilla\\firefox", "microsoft\\edge"
    };

    private static readonly string[] GameDirKeywords =
    {
        "steam\\steamapps", "epic games", "riot games", "battlenet",
        "fivem.app", "altv", "ragemp"
    };

    private const int MaxFilesScanned = 500;
    private const long MaxFileSizeBytes = 100L * 1024 * 1024;
    private const long MaxReadBytes = 2L * 1024 * 1024;
    private const long MaxConfigReadBytes = 64 * 1024;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanPeHeaderAndBrandStringsAsync(ctx, ct);
        ctx.Report(0.30, Name, "PE header and brand string scan complete");

        await ScanCheatBinaryStringSignaturesAsync(ctx, ct);
        ctx.Report(0.55, Name, "Cheat binary string scan complete");

        await ScanCheatDllExportNamesAsync(ctx, ct);
        ctx.Report(0.70, Name, "Cheat DLL export name scan complete");

        await ScanObfuscatedCheatLoadersAsync(ctx, ct);
        ctx.Report(0.85, Name, "Obfuscated loader scan complete");

        await ScanCheatConfigFileSignaturesAsync(ctx, ct);
        ctx.Report(1.0, Name, "Cheat config file scan complete");
    }

    private async Task ScanPeHeaderAndBrandStringsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetBinarySearchDirs();
        int filesChecked = 0;

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f);
                        return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                               ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);
                    });
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                if (filesChecked >= MaxFilesScanned) return;

                ctx.IncrementFiles();
                filesChecked++;

                try
                {
                    var fileInfo = new FileInfo(file);
                    if (fileInfo.Length > MaxFileSizeBytes) continue;

                    byte[] header = new byte[512];
                    int bytesRead;
                    using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        bytesRead = await fs.ReadAsync(header, 0, header.Length, ct);
                    }

                    if (bytesRead < 2) continue;
                    if (header[0] != 0x4D || header[1] != 0x5A) continue;

                    var headerAscii = ExtractAsciiStrings(header, bytesRead);
                    string headerLower = headerAscii.ToLowerInvariant();

                    foreach (var brand in CheatBrandStrings)
                    {
                        if (!headerLower.Contains(brand, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat brand string in PE header region: '{brand}' in {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"The PE file '{file}' has a valid MZ/PE header and contains the cheat brand " +
                                     $"string '{brand}' in the first 512 bytes of the file. Cheat brand names " +
                                     "embedded in the early bytes of a binary — near the PE header — are a strong " +
                                     "indicator that this file belongs to a known cheat tool or loader."
                        });
                        break;
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanCheatBinaryStringSignaturesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetBinarySearchDirs();
        int filesChecked = 0;

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f);
                        return ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                               ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);
                    });
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                if (filesChecked >= MaxFilesScanned) return;

                ctx.IncrementFiles();
                filesChecked++;

                try
                {
                    var fileInfo = new FileInfo(file);
                    if (fileInfo.Length > MaxFileSizeBytes) continue;

                    long readLength = Math.Min(fileInfo.Length, MaxReadBytes);
                    byte[] buffer = new byte[readLength];
                    int bytesRead;
                    using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        bytesRead = await fs.ReadAsync(buffer, 0, (int)readLength, ct);
                    }

                    if (bytesRead < 2) continue;
                    if (buffer[0] != 0x4D || buffer[1] != 0x5A) continue;

                    var asciiContent = ExtractAsciiStrings(buffer, bytesRead);
                    string asciiLower = asciiContent.ToLowerInvariant();

                    int brandHits = CountMatches(asciiLower, CheatBrandStrings);
                    int bypassHits = CountMatches(asciiLower, AntiAcBypassStrings);
                    int featureHits = CountMatches(asciiLower, CheatFeatureStrings);
                    int menuHits = CountMatches(asciiLower, CheatMenuStrings);
                    int authHits = CountMatches(asciiLower, C2AuthStrings);
                    int fivemHits = CountMatches(asciiLower, FivemCheatStrings);

                    if (brandHits > 0 && bypassHits > 0)
                    {
                        var matchedBrand = FindFirstMatch(asciiLower, CheatBrandStrings);
                        var matchedBypass = FindFirstMatch(asciiLower, AntiAcBypassStrings);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PE file with cheat brand AND anti-cheat bypass strings: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Detail = $"Brand match: '{matchedBrand}', Bypass match: '{matchedBypass}'",
                            Reason = $"The file '{file}' contains both a cheat brand string ('{matchedBrand}') and " +
                                     $"an anti-cheat bypass string ('{matchedBypass}'). The combination of a known " +
                                     "cheat tool's branding with explicit anti-cheat bypass references is a definitive " +
                                     "indicator of a cheat tool targeting a protected game."
                        });
                        continue;
                    }

                    int totalFeatureHits = featureHits + menuHits + authHits + fivemHits;
                    if (totalFeatureHits >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PE file with multiple cheat feature strings ({totalFeatureHits} matches): {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Detail = $"Feature hits: {featureHits}, Menu hits: {menuHits}, Auth hits: {authHits}, FiveM hits: {fivemHits}",
                            Reason = $"The file '{file}' contains {totalFeatureHits} cheat-specific strings across " +
                                     "feature categories (ESP settings, aimbot settings, license checks, HWID bypass, etc.). " +
                                     "Finding 3 or more distinct cheat feature strings in a single binary is a strong " +
                                     "indicator that the file is cheat software or a cheat configuration payload."
                        });
                        continue;
                    }

                    if (brandHits > 0)
                    {
                        var matchedBrand = FindFirstMatch(asciiLower, CheatBrandStrings);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PE file contains cheat brand string: '{matchedBrand}' in {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Detail = $"Matched brand: '{matchedBrand}'",
                            Reason = $"The file '{file}' contains the cheat brand string '{matchedBrand}'. " +
                                     "Cheat brands embedded in binary files are characteristic watermarks left " +
                                     "by cheat developers and are a strong indicator of cheat software even " +
                                     "when the file has been renamed."
                        });
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    private async Task ScanCheatDllExportNamesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetBinarySearchDirs();

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    var fileInfo = new FileInfo(file);
                    if (fileInfo.Length > MaxFileSizeBytes) continue;

                    const int exportScanBytes = 8192;
                    byte[] buffer = new byte[exportScanBytes];
                    int bytesRead;
                    using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length, ct);
                    }

                    if (bytesRead < 2) continue;
                    if (buffer[0] != 0x4D || buffer[1] != 0x5A) continue;

                    var asciiContent = ExtractAsciiStrings(buffer, bytesRead);

                    foreach (var exportName in CheatDllExportNames)
                    {
                        if (!asciiContent.Contains(exportName, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DLL with cheat export function name '{exportName}': {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Detail = $"Export name found in first 8KB: '{exportName}'",
                            Reason = $"The DLL '{file}' contains the string '{exportName}' in its first 8 KB, " +
                                     "where PE export name tables reside. Export function names like InitCheat, " +
                                     "StartAimbot, EnableESP, BypassAC, DisableVanguard, etc. are characteristic " +
                                     "of cheat DLLs designed to be loaded and invoked by a cheat loader or injector."
                        });
                        break;
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    private async Task ScanObfuscatedCheatLoadersAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetBinarySearchDirs();

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var ext = Path.GetExtension(file);
                var fileName = Path.GetFileName(file);

                bool isImageOrDocument =
                    ext.Equals(".jpg", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".jpeg", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".png", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".gif", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".pdf", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".bmp", StringComparison.OrdinalIgnoreCase);

                if (isImageOrDocument)
                {
                    await CheckPeHeaderMismatchAsync(ctx, file, ext, ct);
                    continue;
                }

                bool isExeOrDll =
                    ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);

                if (!isExeOrDll) continue;

                await CheckObfuscatedLoaderHeuristicsAsync(ctx, file, ct);
                CheckHexFilenamePattern(ctx, file, fileName, ext);
            }
        }
    }

    private async Task CheckPeHeaderMismatchAsync(ScanContext ctx, string file, string ext, CancellationToken ct)
    {
        try
        {
            byte[] header = new byte[4];
            int bytesRead;
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            bytesRead = await fs.ReadAsync(header, 0, header.Length, ct);

            if (bytesRead < 2) return;
            if (header[0] != 0x4D || header[1] != 0x5A) return;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"PE executable disguised with non-executable extension: {Path.GetFileName(file)}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = Path.GetFileName(file),
                Detail = $"File extension: '{ext}', actual content: MZ/PE executable",
                Reason = $"The file '{file}' has extension '{ext}' (indicating an image or document) but " +
                         "starts with the MZ magic bytes (0x4D 0x5A) identifying it as a Windows PE executable. " +
                         "Hiding executables with non-executable extensions is a common technique used by cheat " +
                         "loaders and malware droppers to evade detection by file type filters."
            });
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private async Task CheckObfuscatedLoaderHeuristicsAsync(ScanContext ctx, string file, CancellationToken ct)
    {
        try
        {
            var fileInfo = new FileInfo(file);
            const long minSize = 50 * 1024;
            const long maxSize = 5L * 1024 * 1024;

            if (fileInfo.Length < minSize || fileInfo.Length > maxSize) return;

            var cutoffDate = DateTime.UtcNow.AddDays(-90);
            if (fileInfo.CreationTimeUtc < cutoffDate) return;

            const int checkBytes = 4096;
            byte[] buffer = new byte[checkBytes];
            int bytesRead;
            using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length, ct);
            }

            if (bytesRead < 2) return;
            if (buffer[0] != 0x4D || buffer[1] != 0x5A) return;

            var asciiContent = ExtractAsciiStrings(buffer, bytesRead);

            bool hasNoVersionInfo =
                !asciiContent.Contains("ProductName", StringComparison.OrdinalIgnoreCase) &&
                !asciiContent.Contains("CompanyName", StringComparison.OrdinalIgnoreCase) &&
                !asciiContent.Contains("FileDescription", StringComparison.OrdinalIgnoreCase);

            if (!hasNoVersionInfo) return;

            var importKeywords = new[]
            {
                "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
                "msvcrt.dll", "vcruntime", "ucrtbase"
            };
            int namedImports = importKeywords.Count(k =>
                asciiContent.Contains(k, StringComparison.OrdinalIgnoreCase));

            if (namedImports >= 5) return;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Suspicious obfuscated PE loader (no version info, few imports): {Path.GetFileName(file)}",
                Risk = RiskLevel.Medium,
                Location = file,
                FileName = Path.GetFileName(file),
                Detail = $"Size: {fileInfo.Length / 1024} KB, Created: {fileInfo.CreationTimeUtc:u}, Named imports visible: {namedImports}",
                Reason = $"The PE executable '{file}' ({fileInfo.Length / 1024} KB) was created within 90 days " +
                         "and has no version information strings (ProductName, CompanyName, FileDescription) and " +
                         $"fewer than 5 named imports visible in the first 4 KB ({namedImports} found). " +
                         "This heuristic matches obfuscated or packed cheat loaders that strip version info " +
                         "and hide import tables to evade static analysis."
            });
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static void CheckHexFilenamePattern(ScanContext ctx, string file, string fileName, string ext)
    {
        var nameWithoutExt = Path.GetFileNameWithoutExtension(fileName);
        if (nameWithoutExt.Length < 8 || nameWithoutExt.Length > 16) return;

        bool allHex = nameWithoutExt.All(c =>
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));

        if (!allHex) return;

        try
        {
            var fileInfo = new FileInfo(file);
            var cutoffDate = DateTime.UtcNow.AddDays(-90);
            if (fileInfo.CreationTimeUtc < cutoffDate) return;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"PE file with random hex filename in temp/download dir: {fileName}",
                Risk = RiskLevel.Medium,
                Location = file,
                FileName = fileName,
                Detail = $"Hex filename: '{nameWithoutExt}' ({nameWithoutExt.Length} chars), Created: {fileInfo.CreationTimeUtc:u}",
                Reason = $"The executable '{fileName}' has a {nameWithoutExt.Length}-character hexadecimal filename " +
                         $"('{nameWithoutExt}') in a temp or download directory, created within the last 90 days. " +
                         "Cheat loaders and dropper stages are commonly written to disk with randomized hex names " +
                         "to avoid detection by filename-based rules while staging payload delivery."
            });
        }
        catch (IOException) { }
    }

    private async Task ScanCheatConfigFileSignaturesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetConfigSearchDirs();

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f);
                        return ConfigExtensions.Any(ce => ce.Equals(ext, StringComparison.OrdinalIgnoreCase));
                    });
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                if (IsInBrowserProfileDir(file) || IsInGameDir(file)) continue;

                try
                {
                    var fileInfo = new FileInfo(file);
                    if (fileInfo.Length > MaxConfigReadBytes * 2) continue;

                    long readLength = Math.Min(fileInfo.Length, MaxConfigReadBytes);
                    string content;
                    using (var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        var buffer = new byte[readLength];
                        int bytesRead = await fs.ReadAsync(buffer, 0, (int)readLength, ct);
                        content = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    }

                    string contentLower = content.ToLowerInvariant();
                    int matchCount = CheatConfigKeys.Count(k =>
                        contentLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (matchCount < 3) continue;

                    RiskLevel risk = matchCount >= 5 ? RiskLevel.Medium : RiskLevel.Low;

                    var matchedKeys = CheatConfigKeys
                        .Where(k => contentLower.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .Take(8)
                        .ToList();

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Config file with {matchCount} cheat configuration keys: {Path.GetFileName(file)}",
                        Risk = risk,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Detail = $"Matched keys ({matchCount}): {string.Join(", ", matchedKeys)}",
                        Reason = $"The configuration file '{file}' contains {matchCount} keys or sections matching " +
                                 "known cheat configuration terms: " +
                                 $"{string.Join(", ", matchedKeys.Take(5))}. " +
                                 "Cheat tools store their settings (aimbot FOV, ESP box drawing, triggerbot key, etc.) " +
                                 "in config files. A config file with 3 or more of these terms present is indicative " +
                                 "of a cheat software configuration file."
                    });
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    private static string[] GetBinarySearchDirs()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Path.GetTempPath(),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Temp"),
        };
    }

    private static string[] GetConfigSearchDirs()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };
    }

    private static bool IsInBrowserProfileDir(string path)
    {
        return BrowserProfileDirKeywords.Any(k =>
            path.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsInGameDir(string path)
    {
        return GameDirKeywords.Any(k =>
            path.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private static string ExtractAsciiStrings(byte[] buffer, int length)
    {
        var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++)
        {
            byte b = buffer[i];
            if (b >= 0x20 && b < 0x7F)
                sb.Append((char)b);
            else if (b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0D)
                sb.Append(' ');
            else
                sb.Append(' ');
        }
        return sb.ToString();
    }

    private static int CountMatches(string content, string[] patterns)
    {
        int count = 0;
        foreach (var pattern in patterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                count++;
        }
        return count;
    }

    private static string? FindFirstMatch(string content, string[] patterns)
    {
        foreach (var pattern in patterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return pattern;
        }
        return null;
    }
}
