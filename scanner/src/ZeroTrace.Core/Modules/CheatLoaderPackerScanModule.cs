using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CheatLoaderPackerScanModule : IScanModule
{
    public string Name => "Cheat Loader & Packer Detection";
    public double Weight => 4.2;
    public int ParallelGroup => 4;

    private static readonly string[] KnownLoaderNames =
    {
        "loader.exe", "cheat_loader.exe", "inject_loader.exe", "stub_loader.exe",
        "crypter.exe", "crypt.exe", "encryptor.exe", "obfuscator.exe",
        "packer.exe", "protector.exe", "fud_loader.exe", "fud_crypter.exe",
        "fud_stub.exe", "native_loader.exe", "shellcode_loader.exe", "pe_loader.exe",
        "reflective_loader.exe", "loadlibrary_loader.exe", "manual_map_loader.exe",
        "map_loader.exe", "driver_loader.exe", "kernel_loader.exe", "kdm_loader.exe",
        "kdmapper_loader.exe", "capcom_loader.exe", "gdrv_loader.exe",
        "rtcore_loader.exe", "iqvw64e_loader.exe", "loaddll.exe", "loadpe.exe",
        "easybypass.exe", "bypass_loader.exe", "evasion_loader.exe", "ghost_loader.exe",
        "phantom_loader.exe", "chimera_loader.exe", "arc_loader.exe", "xenon_loader.exe",
        "skyfade_loader.exe", "nexon_loader.exe", "novaload.exe", "supremeload.exe",
        "aioload.exe", "multiload.exe", "undetected_loader.exe", "ud_loader.exe",
        "ud_crypter.exe", "private_loader.exe", "premium_loader.exe", "vip_loader.exe",
        "stub.exe", "inject_stub.exe", "loader_stub.exe",
        "update.exe", "updater.exe", "selfupdate.exe",
        "inject.exe", "injector.exe", "dll_injector.exe", "cheat_inject.exe",
        "payload_loader.exe", "payload.exe", "dropper.exe", "downloader.exe",
        "bootstrapper.exe", "bootstrap.exe", "stage1.exe", "stage2.exe",
        "shellcode.exe", "mapper.exe", "mmap.exe", "mmap_loader.exe",
        "krnl_loader.exe", "ring0_loader.exe", "bypass.exe", "anti_ac.exe",
        "anticac.exe", "kernel_bypass.exe", "kernel_cheat.exe", "kcheat.exe",
    };

    private static readonly string[] StubFileNames =
    {
        "stub.exe", "stub.dll", "inject_stub.exe", "loader_stub.exe",
        "stub32.exe", "stub64.exe", "crypt_stub.exe", "fud_stub.exe",
        "stub_x64.exe", "stub_x86.exe",
    };

    private static readonly string[] CheatConfigFileNames =
    {
        "loader.json", "cheat_config.json", "auth.json", "hwid.json",
        "license.json", "config.json", "settings.json", "cheat.json",
        "inject.json", "loader_cfg.json", "bypass_cfg.json",
    };

    private static readonly string[] HwidArtifactFileNames =
    {
        "hwid.txt", "machine_id.txt", "spoofer_key.txt", "license.txt",
        "key.txt", "auth.txt", "activation.txt", "hwid_lock.txt",
        "serial.txt", "device_id.txt",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "\"cheat\":", "\"bypass\":", "\"inject\":", "\"aimbot\":", "\"esp\":",
        "\"wallhack\":", "\"triggerbot\":", "\"spoof\":", "\"undetected\":",
        "\"fud\":", "\"loader\":", "\"payload\":", "\"kernel\":", "\"ring0\":",
        "cheat_key", "bypass_mode", "inject_method", "loader_version",
        "hwid_lock", "license_key", "auth_token", "cheat_module",
        "aimbot_enabled", "esp_enabled", "wallhack_enabled",
    };

    private static readonly string[] AntiAnalysisStrings =
    {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "NtSetInformationThread", "NtQuerySystemInformation", "ZwQueryInformationProcess",
        "OutputDebugString", "FindWindow", "CloseHandle",
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
    };

    private static readonly string[] VmDetectionStrings =
    {
        "vmware", "virtualbox", "vbox", "sandbox", "cuckoo", "anyrun",
        "inetsim", "wireshark", "fiddler", "procmon", "filemon",
        "virtual machine", "vm detect", "vmdetect", "sandboxie",
        "joebox", "threatexpert", "comodo", "anubis", "norman",
        "sunbelt", "cwsandbox", "buster", "ttanalyze",
    };

    private static readonly byte[] UpxMagic0 = { 0x55, 0x50, 0x58, 0x30 }; // UPX0
    private static readonly byte[] UpxMagic1 = { 0x55, 0x50, 0x58, 0x31 }; // UPX1
    private static readonly byte[] UpxMagicBang = { 0x55, 0x50, 0x58, 0x21 }; // UPX!
    private static readonly byte[] MzHeader = { 0x4D, 0x5A }; // MZ

    private static readonly string TempPath =
        Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar);
    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string Downloads =
        Path.Combine(UserProfile, "Downloads");

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Scanning for cheat loader executables in temp directories...");
        await ScanTempDirectoriesAsync(ctx, ct);

        ctx.Report(0.25, Name, "Scanning for loader stubs and artifacts...");
        await ScanStubFilesAsync(ctx, ct);

        ctx.Report(0.45, Name, "Scanning for cheat subscription configs and HWID artifacts...");
        await ScanCheatConfigFilesAsync(ctx, ct);

        ctx.Report(0.60, Name, "Scanning for packed binaries with UPX/packer signatures...");
        await ScanPackedBinariesAsync(ctx, ct);

        ctx.Report(0.75, Name, "Checking for anti-analysis and VM detection strings in loaders...");
        await ScanAntiAnalysisArtifactsAsync(ctx, ct);

        ctx.Report(0.88, Name, "Scanning AppData directories for loader remnants...");
        await ScanAppDataDirectoriesAsync(ctx, ct);

        ctx.Report(1.0, Name, "Cheat loader and packer scan complete");
    }

    private async Task ScanTempDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var dirsToScan = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
            Path.Combine(AppDataLocal, "Temp"),
        };

        foreach (var dir in dirsToScan)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                await ScanDirectoryForLoadersAsync(ctx, dir, recursive: false, ct);
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private async Task ScanDirectoryForLoadersAsync(
        ScanContext ctx, string directory, bool recursive, CancellationToken ct)
    {
        IEnumerable<string> files;
        try
        {
            var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            files = Directory.EnumerateFiles(directory, "*.exe", option)
                .Concat(Directory.EnumerateFiles(directory, "*.dll", option));
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var filePath in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(filePath);

            if (KnownLoaderNames.Any(n => n.Equals(fileName, StringComparison.OrdinalIgnoreCase)))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known cheat loader executable: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' matches a known cheat loader or crypter name. " +
                             "These tools are used to load, inject, or encrypt cheats to evade " +
                             "anti-cheat detection. The presence of this file is a strong indicator " +
                             "of cheat activity.",
                    Detail = $"Path: {filePath}"
                });
                continue;
            }

            if (IsRandomHexName(fileName))
            {
                bool hasMz = await HasMzHeaderAsync(filePath);
                if (hasMz)
                {
                    long size = 0;
                    try { size = new FileInfo(filePath).Length; } catch (IOException) { }

                    var risk = size > 0 && size < 204_800 ? RiskLevel.High : RiskLevel.Medium;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Random hex-named executable in temp: {fileName}",
                        Risk = risk,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"Executable '{fileName}' has a random 8-16 hex character name and " +
                                 "a valid MZ header. Loader stubs and crypter droppers are routinely " +
                                 "deployed with randomised names to avoid static filename detection. " +
                                 (size > 0 && size < 204_800
                                     ? $"File is small ({size / 1024} KB), consistent with a loader stub."
                                     : $"File size: {size / 1024} KB."),
                        Detail = $"Size: {size} bytes | Path: {filePath}"
                    });
                }
                continue;
            }

            if (IsSmallUnsignedExe(filePath))
            {
                bool hasMz = await HasMzHeaderAsync(filePath);
                if (hasMz)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Small unsigned executable without version info: {fileName}",
                        Risk = RiskLevel.Medium,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"Small executable '{fileName}' (< 200 KB) found in a temp/download " +
                                 "directory with no version info resource. Cheat loaders and stubs are " +
                                 "frequently tiny, unsigned, and carry no PE version metadata. " +
                                 "This is a heuristic indicator requiring manual review.",
                        Detail = $"Path: {filePath}"
                    });
                }
            }
        }
    }

    private async Task ScanStubFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
            Path.Combine(AppDataLocal, "Temp"),
            UserProfile,
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var stubName in StubFileNames)
                {
                    ct.ThrowIfCancellationRequested();
                    var stubPath = Path.Combine(dir, stubName);
                    if (!File.Exists(stubPath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Loader stub file found: {stubName}",
                        Risk = RiskLevel.High,
                        Location = stubPath,
                        FileName = stubName,
                        Reason = $"File '{stubName}' is a known loader stub artifact. Crypters and " +
                                 "packers use stub executables as the wrapper that decrypts and " +
                                 "loads the actual cheat payload at runtime. These stubs are " +
                                 "typically placed in temp or user directories before injection.",
                        Detail = $"Path: {stubPath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        await ScanForStubsInSubdirsAsync(ctx, AppDataRoaming, ct);
        await ScanForStubsInSubdirsAsync(ctx, AppDataLocal, ct);
    }

    private async Task ScanForStubsInSubdirsAsync(
        ScanContext ctx, string baseDir, CancellationToken ct)
    {
        if (!Directory.Exists(baseDir)) return;

        IEnumerable<string> subdirs;
        try
        {
            subdirs = Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var subdir in subdirs)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var stubName in StubFileNames)
                {
                    var stubPath = Path.Combine(subdir, stubName);
                    if (!File.Exists(stubPath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Loader stub in AppData subdirectory: {stubName}",
                        Risk = RiskLevel.High,
                        Location = stubPath,
                        FileName = stubName,
                        Reason = $"Loader stub '{stubName}' found in AppData subdirectory '{subdir}'. " +
                                 "Cheats frequently deploy their stubs into application subdirectories " +
                                 "to appear as part of legitimate software installations.",
                        Detail = $"Directory: {subdir}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
            await Task.Yield();
        }
    }

    private async Task ScanCheatConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
            UserProfile,
            Path.Combine(AppDataLocal, "Temp"),
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                await ScanDirForCheatConfigsAsync(ctx, dir, recursive: false, ct);
            }
            catch (UnauthorizedAccessException) { }
        }

        await ScanAppDataSubdirsForConfigsAsync(ctx, ct);
        await ScanHwidArtifactsAsync(ctx, ct);
        await ScanUpdaterExecutablesAsync(ctx, ct);
    }

    private async Task ScanDirForCheatConfigsAsync(
        ScanContext ctx, string directory, bool recursive, CancellationToken ct)
    {
        IEnumerable<string> jsonFiles;
        try
        {
            var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            jsonFiles = Directory.EnumerateFiles(directory, "*.json", option)
                .Concat(Directory.EnumerateFiles(directory, "*.cfg", option))
                .Concat(Directory.EnumerateFiles(directory, "*.ini", option));
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var filePath in jsonFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(filePath);
            bool isKnownConfigName = CheatConfigFileNames.Any(n =>
                n.Equals(fileName, StringComparison.OrdinalIgnoreCase));

            string content;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            var matchedKeywords = CheatConfigKeywords
                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchedKeywords.Count == 0) continue;

            var risk = isKnownConfigName && matchedKeywords.Count >= 2
                ? RiskLevel.Critical
                : matchedKeywords.Count >= 3
                    ? RiskLevel.High
                    : RiskLevel.Medium;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Cheat loader configuration file: {fileName}",
                Risk = risk,
                Location = filePath,
                FileName = fileName,
                Reason = $"Config file '{fileName}' contains {matchedKeywords.Count} cheat-related " +
                         $"keywords: {string.Join(", ", matchedKeywords.Take(5))}. " +
                         "Cheat subscription loaders use JSON/INI config files to store " +
                         "authentication tokens, HWID locks, injection settings, and feature flags. " +
                         "The presence of these keywords indicates cheat loader infrastructure.",
                Detail = $"Matched keywords: {string.Join(", ", matchedKeywords)}"
            });
        }
    }

    private async Task ScanAppDataSubdirsForConfigsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var baseDir in new[] { AppDataRoaming, AppDataLocal })
        {
            if (!Directory.Exists(baseDir)) continue;
            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await ScanDirForCheatConfigsAsync(ctx, subdir, recursive: false, ct);
                }
                catch (UnauthorizedAccessException) { }
                await Task.Yield();
            }
        }
    }

    private async Task ScanHwidArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var artifactName in HwidArtifactFileNames)
                {
                    ct.ThrowIfCancellationRequested();
                    var artifactPath = Path.Combine(dir, artifactName);
                    if (!File.Exists(artifactPath)) continue;

                    ctx.IncrementFiles();

                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(artifactPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync();
                    }
                    catch (IOException) { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"HWID-locked loader artifact: {artifactName}",
                        Risk = RiskLevel.High,
                        Location = artifactPath,
                        FileName = artifactName,
                        Reason = $"File '{artifactName}' is a known HWID-lock artifact created by " +
                                 "cheat subscription loaders. These files store hardware fingerprints " +
                                 "used to bind a cheat license to a specific machine, preventing " +
                                 "redistribution. Their presence indicates a cheat loader has been " +
                                 "installed and authenticated on this system.",
                        Detail = content.Length > 0
                            ? $"Content preview: {content.Trim().Replace('\n', ' ').Replace('\r', ' ').Take(120).Aggregate("", (a, c) => a + c)}"
                            : null
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private async Task ScanUpdaterExecutablesAsync(ScanContext ctx, CancellationToken ct)
    {
        var updaterNames = new[]
        {
            "update.exe", "updater.exe", "selfupdate.exe", "autoupdate.exe",
            "launcher_update.exe", "cheat_update.exe", "loader_update.exe",
            "patcher.exe", "autopatch.exe",
        };

        var nonStandardDirs = new[]
        {
            TempPath,
            AppDataRoaming,
            AppDataLocal,
            Desktop,
            Downloads,
        };

        foreach (var dir in nonStandardDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var updaterName in updaterNames)
                {
                    ct.ThrowIfCancellationRequested();
                    var updaterPath = Path.Combine(dir, updaterName);
                    if (!File.Exists(updaterPath)) continue;

                    ctx.IncrementFiles();

                    bool hasMz = await HasMzHeaderAsync(updaterPath);
                    if (!hasMz) continue;

                    bool hasVersionInfo = HasVersionInfo(updaterPath);
                    if (hasVersionInfo) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unsigned updater in non-standard location: {updaterName}",
                        Risk = RiskLevel.High,
                        Location = updaterPath,
                        FileName = updaterName,
                        Reason = $"Unsigned updater executable '{updaterName}' found in a non-standard " +
                                 "directory without version info. Cheat loaders frequently include " +
                                 "auto-update components in user directories to deploy new cheat " +
                                 "versions while the game is running, or to rotate DLLs to stay " +
                                 "ahead of anti-cheat detection.",
                        Detail = $"Path: {updaterPath} | No version info resource present"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        await Task.Yield();
    }

    private async Task ScanPackedBinariesAsync(ScanContext ctx, CancellationToken ct)
    {
        var dirsToScan = new[]
        {
            TempPath,
            Desktop,
            Downloads,
            AppDataRoaming,
            AppDataLocal,
        };

        foreach (var dir in dirsToScan)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> exeFiles;
            try
            {
                exeFiles = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var filePath in exeFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    await CheckForPackerSignaturesAsync(ctx, filePath, ct);
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }

    private async Task CheckForPackerSignaturesAsync(
        ScanContext ctx, string filePath, CancellationToken ct)
    {
        byte[] header = new byte[512];
        int bytesRead = 0;

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            bytesRead = await fs.ReadAsync(header, 0, header.Length, ct);
        }
        catch (IOException) { return; }

        if (bytesRead < 4) return;
        if (header[0] != MzHeader[0] || header[1] != MzHeader[1]) return;

        var fileName = Path.GetFileName(filePath);

        if (ContainsSequence(header, bytesRead, UpxMagic0) ||
            ContainsSequence(header, bytesRead, UpxMagic1) ||
            ContainsSequence(header, bytesRead, UpxMagicBang))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"UPX-packed executable: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"Executable '{fileName}' contains UPX packer signatures (UPX0/UPX1/UPX!) " +
                         "in the first 512 bytes. UPX is the most common open-source packer used " +
                         "to compress cheat payloads and evade static signature detection. " +
                         "While UPX has legitimate uses, its presence in user temp directories " +
                         "alongside other cheat indicators is highly suspicious.",
                Detail = $"UPX signature detected in file header | Path: {filePath}"
            });
            return;
        }

        bool hasTextSection = ContainsSectionName(header, bytesRead, ".text");
        bool hasCodeSection = ContainsSectionName(header, bytesRead, "CODE");
        bool hasUpx0Section = ContainsSectionName(header, bytesRead, "UPX0");

        if (!hasTextSection && !hasCodeSection && hasUpx0Section)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Packed binary without .text section: {fileName}",
                Risk = RiskLevel.Medium,
                Location = filePath,
                FileName = fileName,
                Reason = $"Executable '{fileName}' lacks a .text code section but has UPX-style " +
                         "sections. Packed/crypted binaries compress or encrypt the original code " +
                         "sections and replace them with a small unpacking stub. This structure " +
                         "is typical of packed cheat loaders.",
                Detail = $"Missing .text section | UPX0 section present | Path: {filePath}"
            });
            return;
        }

        if (!hasTextSection && !hasCodeSection)
        {
            long fileSize = 0;
            try { fileSize = new FileInfo(filePath).Length; } catch (IOException) { }

            if (fileSize > 0 && fileSize < 1_048_576)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Small packed-looking binary (no .text section): {fileName}",
                    Risk = RiskLevel.Medium,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"Small executable '{fileName}' ({fileSize / 1024} KB) has no .text code " +
                             "section in its PE header, suggesting the original code has been packed " +
                             "or encrypted. Crypters replace standard sections with their own names. " +
                             "This is a heuristic finding requiring further analysis.",
                    Detail = $"No .text or CODE section | Size: {fileSize} bytes | Path: {filePath}"
                });
            }
        }
    }

    private async Task ScanAntiAnalysisArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var dirsToScan = new[]
        {
            TempPath,
            Desktop,
            Downloads,
            AppDataRoaming,
            AppDataLocal,
        };

        foreach (var dir in dirsToScan)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> exeFiles;
            try
            {
                exeFiles = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.EnumerateFiles(dir, "*.dll", SearchOption.TopDirectoryOnly));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var filePath in exeFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    await CheckAntiAnalysisStringsAsync(ctx, filePath, ct);
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }

    private async Task CheckAntiAnalysisStringsAsync(
        ScanContext ctx, string filePath, CancellationToken ct)
    {
        byte[] buffer = new byte[8192];
        int bytesRead = 0;

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length, ct);
        }
        catch (IOException) { return; }

        if (bytesRead < 2) return;
        if (buffer[0] != MzHeader[0] || buffer[1] != MzHeader[1]) return;

        var headerText = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead);
        var fileName = Path.GetFileName(filePath);

        var matchedAntiAnalysis = AntiAnalysisStrings
            .Where(s => headerText.Contains(s, StringComparison.OrdinalIgnoreCase))
            .ToList();

        var matchedVmDetect = VmDetectionStrings
            .Where(s => headerText.Contains(s, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (matchedAntiAnalysis.Count >= 2 && matchedVmDetect.Count >= 1)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Anti-analysis and VM detection in executable: {fileName}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fileName,
                Reason = $"Executable '{fileName}' contains both anti-debugging API strings " +
                         $"({string.Join(", ", matchedAntiAnalysis.Take(3))}) and VM/sandbox " +
                         $"detection strings ({string.Join(", ", matchedVmDetect.Take(3))}). " +
                         "This combination is characteristic of cheat loaders that check for " +
                         "analysis environments before deploying their payload — a technique " +
                         "used to evade automated anti-cheat sandboxes and security tools.",
                Detail = $"Anti-debug: {string.Join(", ", matchedAntiAnalysis)} | " +
                         $"VM detect: {string.Join(", ", matchedVmDetect)}"
            });
        }
        else if (matchedAntiAnalysis.Count >= 3)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Strong anti-debugging strings in executable: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"Executable '{fileName}' in a user directory references {matchedAntiAnalysis.Count} " +
                         $"anti-debugging APIs: {string.Join(", ", matchedAntiAnalysis.Take(4))}. " +
                         "Cheat loaders embed these to detect ZeroTrace and other anti-cheat tools. " +
                         "Legitimate software rarely combines this many anti-debug techniques " +
                         "in a file found in a temp or user directory.",
                Detail = $"Matched: {string.Join(", ", matchedAntiAnalysis)}"
            });
        }
        else if (matchedVmDetect.Count >= 2 && matchedAntiAnalysis.Count >= 1)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"VM/sandbox detection in executable: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"Executable '{fileName}' contains VM/sandbox detection strings: " +
                         $"{string.Join(", ", matchedVmDetect.Take(4))}. " +
                         "Cheat loaders use environment fingerprinting to abort when running " +
                         "inside anti-cheat analysis sandboxes (VMware, VirtualBox, Cuckoo). " +
                         "This evasion technique is common in private cheat loaders.",
                Detail = $"VM/sandbox: {string.Join(", ", matchedVmDetect)} | " +
                         $"Anti-debug: {string.Join(", ", matchedAntiAnalysis)}"
            });
        }
    }

    private async Task ScanAppDataDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var baseDir in new[] { AppDataRoaming, AppDataLocal })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(subdir).ToLowerInvariant();

                bool isCheatDir = dirName.Contains("cheat", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("loader", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("inject", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("hack", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("aimbot", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("esp", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("crypter", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("packer", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("fud", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("payload", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("stub", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("undetect", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("private", StringComparison.OrdinalIgnoreCase);

                try
                {
                    await ScanDirectoryForLoadersAsync(ctx, subdir, recursive: false, ct);

                    if (isCheatDir)
                    {
                        await ScanDirForCheatConfigsAsync(ctx, subdir, recursive: true, ct);

                        try
                        {
                            foreach (var updaterName in new[] { "update.exe", "updater.exe", "selfupdate.exe" })
                            {
                                var updaterPath = Path.Combine(subdir, updaterName);
                                if (!File.Exists(updaterPath)) continue;

                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Updater in suspected cheat directory: {updaterName}",
                                    Risk = RiskLevel.Critical,
                                    Location = updaterPath,
                                    FileName = updaterName,
                                    Reason = $"Updater executable '{updaterName}' found inside a directory " +
                                             $"with cheat-related name '{dirName}'. Auto-updaters in cheat " +
                                             "directories are used to keep cheat components current with " +
                                             "anti-cheat signature changes, enabling long-term evasion.",
                                    Detail = $"Parent directory name: {dirName} | Path: {updaterPath}"
                                });
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }

                await Task.Yield();
            }
        }
    }

    private static bool IsRandomHexName(string fileName)
    {
        var name = Path.GetFileNameWithoutExtension(fileName);
        if (name.Length < 8 || name.Length > 16) return false;
        return name.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
    }

    private static bool IsSmallUnsignedExe(string filePath)
    {
        try
        {
            var info = new FileInfo(filePath);
            if (info.Length >= 204_800) return false;
            if (info.Length == 0) return false;
            return true;
        }
        catch (IOException) { return false; }
    }

    private static bool HasVersionInfo(string filePath)
    {
        try
        {
            var info = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
            return !string.IsNullOrEmpty(info.FileVersion)
                || !string.IsNullOrEmpty(info.ProductName)
                || !string.IsNullOrEmpty(info.CompanyName);
        }
        catch { return false; }
    }

    private static async Task<bool> HasMzHeaderAsync(string filePath)
    {
        try
        {
            byte[] buf = new byte[2];
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            int read = await fs.ReadAsync(buf, 0, 2);
            return read == 2 && buf[0] == 0x4D && buf[1] == 0x5A;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static bool ContainsSequence(byte[] buffer, int length, byte[] pattern)
    {
        for (int i = 0; i <= length - pattern.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    private static bool ContainsSectionName(byte[] buffer, int length, string sectionName)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(sectionName);
        return ContainsSequence(buffer, length, bytes);
    }

    private static readonly string[] KnownCrypterRegistryKeys =
    {
        @"SOFTWARE\CrypterSoftware",
        @"SOFTWARE\FUDCrypter",
        @"SOFTWARE\PrivateCrypter",
        @"SOFTWARE\PremiumCrypter",
        @"SOFTWARE\CheatLoader",
        @"SOFTWARE\LoaderSoftware",
        @"SOFTWARE\InjectLoader",
        @"SOFTWARE\StealthLoader",
        @"SOFTWARE\UDLoader",
        @"SOFTWARE\VIPLoader",
        @"SOFTWARE\PremiumLoader",
        @"SOFTWARE\NativeLoader",
        @"SOFTWARE\ShellcodeLoader",
        @"SOFTWARE\ReflectiveLoader",
        @"SOFTWARE\ManualMapLoader",
        @"SOFTWARE\KernelLoader",
        @"SOFTWARE\GhostLoader",
        @"SOFTWARE\PhantomLoader",
        @"SOFTWARE\ChimeraLoader",
        @"SOFTWARE\ArcLoader",
        @"SOFTWARE\XenonLoader",
        @"SOFTWARE\BypassLoader",
        @"SOFTWARE\EvasionLoader",
        @"SOFTWARE\FUDStub",
        @"SOFTWARE\PayloadLoader",
        @"SOFTWARE\DropperLoader",
    };

    private static readonly string[] SuspiciousScheduledTaskKeywords =
    {
        "loader", "inject", "crypter", "packer", "cheat",
        "bypass", "payload", "stub", "dropper", "shellcode",
        "fud", "undetect", "private", "premium", "vip",
        "aimbot", "esp", "wallhack", "trigger",
    };

    private static readonly string[] LoaderParentDirKeywords =
    {
        "cheat", "loader", "inject", "hack", "bypass", "aimbot",
        "esp", "crypter", "packer", "fud", "payload", "stub",
        "undetect", "private", "premium", "vip", "ghost", "phantom",
        "chimera", "xenon", "arc", "nova", "supreme", "multi",
        "kernel", "ring0", "driver", "native", "shellcode", "mapper",
    };

    public async Task RunRegistryAndScheduledTasksAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanCrypterRegistryKeysAsync(ctx, ct);
        await ScanScheduledTasksForLoadersAsync(ctx, ct);
        await ScanDownloadsDeepAsync(ctx, ct);
    }

    private async Task ScanCrypterRegistryKeysAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var regPath in KnownCrypterRegistryKeys)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();

            foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                    using var key = baseKey.OpenSubKey(regPath, writable: false);
                    if (key is null) continue;

                    var hiveStr = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat loader/crypter registry key: {regPath.Split('\\').Last()}",
                        Risk = RiskLevel.High,
                        Location = $@"{hiveStr}\{regPath}",
                        Reason = $"Registry key '{regPath}' associated with a cheat loader or crypter " +
                                 "was found. Loaders and crypter tools create registry keys during " +
                                 "installation for configuration persistence, license storage, and " +
                                 "component path tracking. This key indicates the software was installed " +
                                 "on this machine.",
                        Detail = $"Registry: {hiveStr}\\{regPath}"
                    });
                }
                catch { }
            }
        }

        await Task.Yield();
    }

    private async Task ScanScheduledTasksForLoadersAsync(ScanContext ctx, CancellationToken ct)
    {
        const string tasksDir = @"C:\Windows\System32\Tasks";
        if (!Directory.Exists(tasksDir)) return;

        IEnumerable<string> taskFiles;
        try
        {
            taskFiles = Directory.EnumerateFiles(tasksDir, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var taskFile in taskFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(taskFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            var lowerContent = content.ToLowerInvariant();

            var matchedKeywords = SuspiciousScheduledTaskKeywords
                .Where(k => lowerContent.Contains(k, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchedKeywords.Count < 2) continue;

            bool referencesUserWritablePath = lowerContent.Contains(@"\temp\", StringComparison.OrdinalIgnoreCase)
                || lowerContent.Contains(@"\appdata\", StringComparison.OrdinalIgnoreCase)
                || lowerContent.Contains(@"\downloads\", StringComparison.OrdinalIgnoreCase)
                || lowerContent.Contains(@"\desktop\", StringComparison.OrdinalIgnoreCase);

            if (!referencesUserWritablePath) continue;

            var taskName = Path.GetFileName(taskFile);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Scheduled task with loader keywords: {taskName}",
                Risk = RiskLevel.High,
                Location = taskFile,
                FileName = taskName,
                Reason = $"Scheduled task '{taskName}' references a user-writable path and contains " +
                         $"{matchedKeywords.Count} loader/cheat keywords: " +
                         $"{string.Join(", ", matchedKeywords.Take(5))}. " +
                         "Cheat loaders create scheduled tasks to auto-launch on system startup, " +
                         "on user logon, or on a timer to reload cheat components after anti-cheat " +
                         "signature updates. Scheduled tasks in user directories are particularly " +
                         "suspicious.",
                Detail = $"Matched keywords: {string.Join(", ", matchedKeywords)}"
            });
        }
    }

    private async Task ScanDownloadsDeepAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(Downloads)) return;

        IEnumerable<string> subdirs;
        try
        {
            subdirs = Directory.EnumerateDirectories(Downloads, "*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var subdir in subdirs)
        {
            ct.ThrowIfCancellationRequested();
            var dirName = Path.GetFileName(subdir).ToLowerInvariant();

            bool isLoaderDir = LoaderParentDirKeywords.Any(kw =>
                dirName.Contains(kw, StringComparison.OrdinalIgnoreCase));

            if (!isLoaderDir) continue;

            try
            {
                await ScanDirectoryForLoadersAsync(ctx, subdir, recursive: true, ct);
                await ScanDirForCheatConfigsAsync(ctx, subdir, recursive: true, ct);

                IEnumerable<string> archiveFiles;
                try
                {
                    archiveFiles = Directory.EnumerateFiles(subdir, "*.zip", SearchOption.TopDirectoryOnly)
                        .Concat(Directory.EnumerateFiles(subdir, "*.rar", SearchOption.TopDirectoryOnly))
                        .Concat(Directory.EnumerateFiles(subdir, "*.7z", SearchOption.TopDirectoryOnly));
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var archivePath in archiveFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var archiveName = Path.GetFileName(archivePath);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Archive in suspected cheat loader directory: {archiveName}",
                        Risk = RiskLevel.Medium,
                        Location = archivePath,
                        FileName = archiveName,
                        Reason = $"Archive file '{archiveName}' found in Downloads subdirectory " +
                                 $"'{dirName}' which has a cheat loader-related name. Cheat loaders " +
                                 "are commonly distributed as ZIP/RAR archives and extracted to " +
                                 "directories named after the cheat. The archive may contain the " +
                                 "loader executable, stub, and configuration files.",
                        Detail = $"Parent directory: {dirName} | Archive: {archivePath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }

            await Task.Yield();
        }
    }
}
