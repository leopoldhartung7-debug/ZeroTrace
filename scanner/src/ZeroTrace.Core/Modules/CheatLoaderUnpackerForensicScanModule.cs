using System.IO.Compression;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class CheatLoaderUnpackerForensicScanModule : IScanModule
{
    public string Name => "Cheat Loader/Unpacker Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] PackerBypassToolNames = { "Extreme.exe", "ExtremeDumper.exe", "TitanHide.exe", "PhantOm.dll", "vmpdump.exe", "VMP_Unlocker.exe", "ScyllaHide.dll", "ScyllaHide64.dll", "HideDebugger.dll" };
    private static readonly string[] KnownVulnerableDrivers = { "capcom.sys", "gdrv.sys", "dbutil_2_3.sys", "mhyprot.sys", "iqvw64e.sys", "rtcore64.sys", "cpuz141.sys", "AsrDrv103.sys", "DirectIo64.sys", "HW64.sys", "kprocesshacker.sys", "WinIo64.sys", "WinRing0x64.sys" };
    private static readonly string[] InjectionToolNames = { "Xenos.exe", "extreme_injector.exe", "ManualMap.exe", "DllInjector.exe", "SharpDllLoader.exe", "inject.exe", "injector.exe", "GuidedHacking.exe" };
    private static readonly string[] CheatLoaderKeywords = { "_loader.exe", "_injector.exe", "_bypass.exe", "cheat_loader", "hack_loader", "esp_loader", "aimbot_loader", "menu_loader" };
    private static readonly string[] CheatDllKeywords = { "hack", "cheat", "esp", "aimbot", "wallhack", "bypass", "inject", "trainer" };
    private static readonly string[] CheatZipNameKeywords = { "cheat", "hack", "esp", "aimbot", "bypass", "trainer", "menu", "mod_menu", "fivem_hack", "gta_cheat", "ragemp_hack", "altv_cheat" };
    private static readonly string[] SuspiciousAutorunDomainKeywords = { "cdn.cheat", "download.hack", "release.mod", "update.esp", "files.trainer" };

    private static readonly string[] ConfigFileNames = { "loader_config.json", "cheat_config.ini", "loader_settings.json", "injection_config.json", "bypass_config.json", "config_cheat.ini", "settings_cheat.json" };
    private static readonly string[] ConfigKeywords = { "inject", "bypass", "anticheat", "target_process", "dll_path", "hook_method" };
    private static readonly string[] AntiDebugFileNames = { "ScyllaHide.ini", "ScyllaHide.dll", "ScyllaHide64.dll", "TitanHide.exe", "PhantOm.dll", "HideDebugger.dll", "antidbg_bypass.dll" };
    private static readonly string[] SandboxEvasionFileNames = { "vm_bypass.dll", "sandbox_bypass.dll", "antidebug_bypass.dll" };
    private static readonly string[] UpdaterFileNames = { "updater.exe", "auto_update.exe", "cheat_update.exe", "update_client.exe" };
    private static readonly string[] UpdaterConfigNames = { "update.json", "updater_config.json" };
    private static readonly string[] CheatKeyFileNames = { "license.key", "activation.key", "serial.key", "product.key", "cheat_key.txt", "license.txt" };
    private static readonly string[] SuspiciousServiceKeywords = { "bypass", "loader", "inject" };

    private static readonly string[] UserScanRoots = BuildUserScanRoots();

    private static string[] BuildUserScanRoots()
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var appDataLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();
        return new[] { desktop, downloads, documents, appDataRoaming, appDataLocal, temp };
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckThemidaPackerArtifacts(ctx, ct),
            CheckVMProtectUnpackerArtifacts(ctx, ct),
            CheckCheatLoaderConfigFiles(ctx, ct),
            CheckCheatLoaderExecutables(ctx, ct),
            CheckCheatDLLPayloads(ctx, ct),
            CheckCheatDriverPayloads(ctx, ct),
            CheckPackerToolArtifacts(ctx, ct),
            CheckInjectionToolArtifacts(ctx, ct),
            CheckCheatZipArchives(ctx, ct),
            CheckAntiDebugBypassArtifacts(ctx, ct),
            CheckCheatMemoryDumps(ctx, ct),
            CheckCheatSourceDLLs(ctx, ct),
            CheckTemporaryCheatDroppers(ctx, ct),
            CheckCheatLicenseKeyFiles(ctx, ct),
            CheckProtectionBypassRegistryKeys(ctx, ct),
            CheckCheatUpdateMechanismArtifacts(ctx, ct),
            CheckSandboxEvasionArtifacts(ctx, ct),
            CheckObfuscatedCheatScripts(ctx, ct)
        );
    }

    private Task CheckThemidaPackerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
        };

        var bypassFolders = new[] { "themida_bypass", "winlicense_bypass" };
        var dumpPatterns = new[] { "themida_dump.exe" };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                var dirName = Path.GetDirectoryName(file) ?? string.Empty;

                var inBypassFolder = bypassFolders.Any(f => dirName.Contains(f, StringComparison.OrdinalIgnoreCase));

                var isThemidaUnpacked = fileName.StartsWith("themida_unpacked_", StringComparison.OrdinalIgnoreCase)
                    && fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

                var isKnownDump = dumpPatterns.Any(p => fileName.Equals(p, StringComparison.OrdinalIgnoreCase));

                var isPackerBypassTool = PackerBypassToolNames.Any(t =>
                    fileName.Equals("Extreme.exe", StringComparison.OrdinalIgnoreCase)
                    || fileName.Equals("ExtremeDumper.exe", StringComparison.OrdinalIgnoreCase)
                    || fileName.Equals("TitanHide.exe", StringComparison.OrdinalIgnoreCase)
                    || fileName.Equals("ScyllaHide.dll", StringComparison.OrdinalIgnoreCase));

                if (!isThemidaUnpacked && !isKnownDump && !inBypassFolder && !isPackerBypassTool) continue;

                var reason = isThemidaUnpacked ? "File name matches Themida unpacked dump pattern (themida_unpacked_*.exe)."
                    : isKnownDump ? "File name matches known Themida dump output filename."
                    : inBypassFolder ? $"File found inside a Themida/WinLicense bypass folder: {dirName}"
                    : $"Known Themida/packer bypass tool found: {fileName}";

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Themida/WinLicense Packer Bypass Artifact",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = reason,
                    Detail = $"Full path: {file}"
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckVMProtectUnpackerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var vmpToolNames = new[] { "vmp_unpacked.exe", "vmp_dump.exe", "VMP_Unlocker.exe", "vmpdump.exe", "vmprotect_bypass.exe" };
        var bypassFolder = "vmprotect_bypass";

        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                var dirName = Path.GetDirectoryName(file) ?? string.Empty;
                var ext = Path.GetExtension(file);

                var isVmpTool = vmpToolNames.Any(t => fileName.Equals(t, StringComparison.OrdinalIgnoreCase));
                var isInBypassFolder = dirName.Contains(bypassFolder, StringComparison.OrdinalIgnoreCase);
                var isVmpFile = ext.Equals(".vmp", StringComparison.OrdinalIgnoreCase);

                if (!isVmpTool && !isInBypassFolder && !isVmpFile) continue;

                var reason = isVmpTool ? $"Known VMProtect unpacker/bypass tool found: {fileName}."
                    : isInBypassFolder ? $"File found inside a VMProtect bypass folder: {dirName}"
                    : $"File with .vmp extension found in user directory: {file}";

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "VMProtect Unpacker/Bypass Artifact",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = reason,
                    Detail = $"Full path: {file}"
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatLoaderConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;

                var fileName = Path.GetFileName(file);
                if (!ConfigFileNames.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase))) continue;

                ctx.IncrementFiles();

                if (!File.Exists(file)) continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch { continue; }

                var hitKeyword = ConfigKeywords.FirstOrDefault(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat Loader Configuration File Found",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = hitKeyword is not null
                        ? $"Cheat loader config file '{fileName}' found containing keyword '{hitKeyword}'."
                        : $"Cheat loader config file '{fileName}' found by name match.",
                    Detail = hitKeyword is not null ? $"Matched keyword: {hitKeyword}" : null
                });
            }
        }
    }, ct);

    private Task CheckCheatLoaderExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var standaloneNames = new[] { "Loader.exe", "inject.exe", "bypass.exe" };
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*.exe", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                var isKeywordMatch = CheatLoaderKeywords.Any(k =>
                    fileName.Contains(k, StringComparison.OrdinalIgnoreCase));

                var isStandaloneName = standaloneNames.Any(n =>
                    fileName.Equals(n, StringComparison.OrdinalIgnoreCase))
                    && !file.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase);

                if (!isKeywordMatch && !isStandaloneName) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat Loader Executable Artifact",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = isKeywordMatch
                        ? $"Executable name contains cheat loader keyword pattern: {fileName}"
                        : $"Known cheat loader executable found outside system directories: {fileName}",
                    Detail = $"Full path: {file}"
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatDLLPayloads(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var suspiciousExactNames = new[] { "internal.dll", "payload.dll" };
        var d3dNames = new[] { "d3d9.dll", "d3d11.dll", "d3d12.dll" };
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*.dll", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                var isKeywordDll = CheatDllKeywords.Any(k =>
                    fileName.Contains(k, StringComparison.OrdinalIgnoreCase));

                var isSuspiciousExact = suspiciousExactNames.Any(n =>
                    fileName.Equals(n, StringComparison.OrdinalIgnoreCase));

                var isD3dOutsideGame = d3dNames.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase))
                    && !file.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase)
                    && !file.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase)
                    && !file.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase);

                if (!isKeywordDll && !isSuspiciousExact && !isD3dOutsideGame) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat DLL Payload Artifact",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = isKeywordDll
                        ? $"DLL name contains known cheat keyword: {fileName}"
                        : isD3dOutsideGame
                            ? $"D3D DLL found outside system/game directories, possible proxy DLL: {fileName}"
                            : $"Suspicious DLL name found: {fileName}",
                    Detail = $"Full path: {file}"
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatDriverPayloads(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userSearchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
        };

        var windowsTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");
        var extraRoots = new[] { windowsTemp, Path.GetTempPath() };
        var allRoots = userSearchRoots.Concat(extraRoots).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        foreach (var root in allRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*.sys", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                var isKnownVulnerable = KnownVulnerableDrivers.Any(d =>
                    fileName.Equals(d, StringComparison.OrdinalIgnoreCase));

                var risk = isKnownVulnerable ? RiskLevel.Critical : RiskLevel.High;
                var reason = isKnownVulnerable
                    ? $"Known vulnerable/abused driver payload found: {fileName}. This driver is commonly exploited by cheats for kernel-level access."
                    : $"Unexpected .sys driver file found in user/temp directory: {fileName}";

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = isKnownVulnerable ? "Known Vulnerable Cheat Driver Payload" : "Suspicious Driver File in User Directory",
                    Risk = risk,
                    Location = file,
                    FileName = fileName,
                    Reason = reason,
                    Detail = $"Full path: {file}"
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckPackerToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var packerToolNames = new[] { "upx.exe", "mpress.exe", "pecompact.exe", "execryptor.exe", "enigma_protector.exe", "asprotect.exe", "aspack.exe" };
        var upxMarkers = new[] { "UPX0", "UPX1" };
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                if (packerToolNames.Any(t => fileName.Equals(t, StringComparison.OrdinalIgnoreCase))
                    && !file.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Packer/Protector Tool Found",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Known packer or protector tool '{fileName}' found outside system directories. This is commonly used in cheat development to protect payloads.",
                        Detail = $"Full path: {file}"
                    });
                    continue;
                }

                var ext = Path.GetExtension(file);
                if (!ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                    && !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)) continue;

                if (!File.Exists(file)) continue;

                try
                {
                    var header = new byte[100];
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var read = await fs.ReadAsync(header, 0, 100, ct);
                    if (read < 4) continue;

                    var headerStr = Encoding.ASCII.GetString(header, 0, read);
                    if (upxMarkers.Any(m => headerStr.Contains(m, StringComparison.Ordinal)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "UPX-Packed Binary Artifact",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"File '{fileName}' contains UPX packer header markers (UPX0/UPX1). UPX packing is commonly used to obfuscate cheat payloads.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckInjectionToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var sessionFilePatterns = new[]
        {
            ("Process Hacker", "*.phsess"),
            ("x64dbg", "*.dd64"),
            ("Cheat Engine", "*.cetrainer")
        };

        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var (toolName, pattern) in sessionFilePatterns)
            {
                string[] sessionFiles;
                try { sessionFiles = Directory.GetFiles(root, pattern, SearchOption.AllDirectories); }
                catch { continue; }

                foreach (var file in sessionFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"{toolName} Session/Config File Found",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"{toolName} session or configuration file found: '{Path.GetFileName(file)}'. This indicates active use of a reverse engineering or injection tool.",
                        Detail = $"Full path: {file}"
                    });
                }
            }

            string[] exeFiles;
            try { exeFiles = Directory.GetFiles(root, "*.exe", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in exeFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (!InjectionToolNames.Any(t => fileName.Equals(t, StringComparison.OrdinalIgnoreCase))) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "DLL Injection Tool Binary Found",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known DLL injection tool '{fileName}' found. This tool is used to inject cheat payloads into game processes.",
                    Detail = $"Full path: {file}"
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatZipArchives(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (!Directory.Exists(downloads)) return;

        var archiveExtensions = new[] { ".zip", ".rar", ".7z" };

        string[] files;
        try { files = Directory.GetFiles(downloads, "*", SearchOption.AllDirectories); }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;

            var ext = Path.GetExtension(file);
            if (!archiveExtensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase))) continue;

            ctx.IncrementFiles();
            var fileName = Path.GetFileName(file);

            var nameHit = CheatZipNameKeywords.FirstOrDefault(k =>
                fileName.Contains(k, StringComparison.OrdinalIgnoreCase));

            if (nameHit is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat Archive Found in Downloads",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Archive file name '{fileName}' matches cheat-related keyword '{nameHit}'.",
                    Detail = $"Full path: {file}"
                });
                continue;
            }

            if (!ext.Equals(".zip", StringComparison.OrdinalIgnoreCase)) continue;

            if (!File.Exists(file)) continue;

            try
            {
                using var zip = ZipFile.OpenRead(file);
                int seen = 0;
                foreach (var entry in zip.Entries)
                {
                    if (++seen > 2000) break;
                    if (string.IsNullOrEmpty(entry.Name)) continue;

                    var entryHit = CheatZipNameKeywords.FirstOrDefault(k =>
                        entry.Name.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (entryHit is null)
                    {
                        entryHit = CheatDllKeywords.FirstOrDefault(k =>
                            entry.Name.Contains(k, StringComparison.OrdinalIgnoreCase));
                    }

                    if (entryHit is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Archive Contents Match",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"ZIP archive '{fileName}' contains entry '{entry.FullName}' matching cheat keyword '{entryHit}'.",
                        Detail = $"Archive entry: {entry.FullName}"
                    });
                    break;
                }
            }
            catch { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckAntiDebugBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (!AntiDebugFileNames.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase))) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Anti-Debug Bypass Tool Artifact Found",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known anti-debug bypass artifact '{fileName}' found. This file is associated with tools that hide debugger presence from anti-cheat systems.",
                    Detail = $"Full path: {file}"
                });
            }
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\ScyllaHide", writable: false);
            ctx.IncrementRegistryKeys();
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "ScyllaHide Registry Installation Detected",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\ScyllaHide",
                    Reason = "Registry key HKLM\\SOFTWARE\\ScyllaHide exists, indicating ScyllaHide anti-debug bypass plugin is or was installed.",
                    Detail = null
                });
            }
        }
        catch { }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\ScyllaHide", writable: false);
            ctx.IncrementRegistryKeys();
            if (key is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "ScyllaHide Registry Installation Detected (HKCU)",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\ScyllaHide",
                    Reason = "Registry key HKCU\\Software\\ScyllaHide exists, indicating ScyllaHide anti-debug bypass plugin is or was installed for the current user.",
                    Detail = null
                });
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatMemoryDumps(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var dumpSearchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath()
        };

        var dumpKeywords = new[] { "gta", "fivem", "ragemp", "game", "dump_", "process_dump" };
        var dropperPrefixes = new[] { "dump_", "minidump_" };
        const long minDumpSize = 1024 * 1024;

        foreach (var root in dumpSearchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;

                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);

                if (ext.Equals(".dmp", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();

                    var nameHit = dumpKeywords.FirstOrDefault(k =>
                        fileName.Contains(k, StringComparison.OrdinalIgnoreCase));

                    long fileSize = 0;
                    try { fileSize = new FileInfo(file).Length; } catch { }

                    if (nameHit is not null && fileSize > minDumpSize)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious Game Memory Dump File",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Memory dump file '{fileName}' matches game/cheat keyword '{nameHit}' and is larger than 1MB ({fileSize / 1024 / 1024}MB). Consistent with cheat process dumper output.",
                            Detail = $"File size: {fileSize} bytes"
                        });
                    }
                    continue;
                }

                if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    var isDumperExe = dropperPrefixes.Any(p =>
                        fileName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                    if (!isDumperExe) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Dumper Executable Artifact",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Executable '{fileName}' matches cheat memory dumper naming pattern (dump_*/minidump_*).",
                        Detail = $"Full path: {file}"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatSourceDLLs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var pdbKeywords = new[] { "cheat.pdb", "hack.pdb", "esp.pdb", "menu.pdb" };
        var buildSubPaths = new[] { @"x64\Release", @"x64\Debug" };
        var vsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Visual Studio");
        var vsPath2 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "VisualStudio");

        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] allFiles;
            try { allFiles = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in allFiles)
            {
                if (ct.IsCancellationRequested) return;

                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);
                var dirPath = Path.GetDirectoryName(file) ?? string.Empty;

                if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    var isInBuildPath = buildSubPaths.Any(bp =>
                        dirPath.Contains(bp, StringComparison.OrdinalIgnoreCase));

                    if (!isInBuildPath) continue;

                    var isVsPath = dirPath.StartsWith(vsPath, StringComparison.OrdinalIgnoreCase)
                        || dirPath.StartsWith(vsPath2, StringComparison.OrdinalIgnoreCase);

                    if (isVsPath) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Compiled Cheat DLL Build Artifact",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"DLL found in build output path '{dirPath}' matching x64/Release or x64/Debug pattern outside Visual Studio directories. Indicates locally compiled cheat DLL.",
                        Detail = $"Full path: {file}"
                    });
                    continue;
                }

                if (ext.Equals(".pdb", StringComparison.OrdinalIgnoreCase))
                {
                    var isPdbHit = pdbKeywords.Any(p =>
                        fileName.Equals(p, StringComparison.OrdinalIgnoreCase));

                    if (!isPdbHit) continue;

                    var isVsPath = dirPath.StartsWith(vsPath, StringComparison.OrdinalIgnoreCase)
                        || dirPath.StartsWith(vsPath2, StringComparison.OrdinalIgnoreCase);

                    if (isVsPath) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Source PDB Debug Symbol File",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"PDB debug symbol file '{fileName}' matches known cheat project name pattern, found outside Visual Studio paths.",
                        Detail = $"Full path: {file}"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckTemporaryCheatDroppers(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var tempRoots = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp")
        };

        var dropperPrefixes = new[] { "tmp_", "~tmp", "update_" };
        const long maxDropperSize = 500 * 1024;
        var randomNameRegex = new Regex(@"^[a-zA-Z0-9]{8,16}\.(exe|dll)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        foreach (var root in tempRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;

                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);

                if (!ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                    && !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();

                var isRandomName = randomNameRegex.IsMatch(fileName);
                var isDropperPrefix = dropperPrefixes.Any(p =>
                    fileName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                if (!isRandomName && !isDropperPrefix) continue;

                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                var isSmall = fileSize > 0 && fileSize < maxDropperSize;

                var reason = isDropperPrefix
                    ? $"File '{fileName}' in Temp matches dropper stub naming pattern ({string.Join(", ", dropperPrefixes)}) and is {(isSmall ? "small (<500KB)" : "present")}."
                    : $"File '{fileName}' in Temp has a random alphanumeric name (8-16 chars) consistent with dropped cheat stub.";

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Suspected Cheat Dropper in Temp Directory",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = reason,
                    Detail = fileSize > 0 ? $"File size: {fileSize} bytes" : null
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatLicenseKeyFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var hexKeyRegex = new Regex(@"[0-9a-fA-F]{64}", RegexOptions.Compiled);
        var uuidRegex = new Regex(@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", RegexOptions.Compiled);
        var keyFormatRegex = new Regex(@"[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}", RegexOptions.Compiled);

        var keySearchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
        };

        foreach (var root in keySearchRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;

                var fileName = Path.GetFileName(file);
                if (!CheatKeyFileNames.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase))) continue;

                ctx.IncrementFiles();

                if (!File.Exists(file)) continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch { continue; }

                string? matchedPattern = null;
                if (hexKeyRegex.IsMatch(content)) matchedPattern = "64-char hex key";
                else if (uuidRegex.IsMatch(content)) matchedPattern = "UUID format key";
                else if (keyFormatRegex.IsMatch(content)) matchedPattern = "XXXX-XXXX-XXXX-XXXX key format";

                if (matchedPattern is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat License/Activation Key File Found",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"File '{fileName}' appears to contain a cheat license or activation key (matched pattern: {matchedPattern}). This indicates purchase or registration of a cheat service.",
                    Detail = $"Key pattern matched: {matchedPattern}"
                });
            }
        }
    }, ct);

    private Task CheckProtectionBypassRegistryKeys(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var clsidKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Classes\CLSID", writable: false);
            ctx.IncrementRegistryKeys();
            if (clsidKey is not null)
            {
                foreach (var subName in clsidKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var sub = clsidKey.OpenSubKey(subName, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (sub is null) continue;
                        var defaultVal = sub.GetValue(null) as string;
                        if (defaultVal is null) continue;
                        if (CheatDllKeywords.Any(k => defaultVal.Contains(k, StringComparison.OrdinalIgnoreCase))
                            || defaultVal.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                            || defaultVal.Contains("loader", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious CLSID Entry with Cheat Name",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SOFTWARE\Classes\CLSID\{subName}",
                                Reason = $"CLSID registry entry '{subName}' has a suspicious default value: '{defaultVal}'.",
                                Detail = $"CLSID: {subName}, Value: {defaultVal}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        try
        {
            using var scyllaKey = Registry.CurrentUser.OpenSubKey(@"Software\ScyllaHide", writable: false);
            ctx.IncrementRegistryKeys();
            if (scyllaKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "ScyllaHide Registry Key Found (HKCU)",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\ScyllaHide",
                    Reason = "HKCU\\Software\\ScyllaHide registry key exists, indicating ScyllaHide anti-debug bypass tool configuration.",
                    Detail = null
                });
            }
        }
        catch { }

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", writable: false);
            ctx.IncrementRegistryKeys();
            if (servicesKey is not null)
            {
                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    if (SuspiciousServiceKeywords.Any(k =>
                        svcName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious Service Name Matching Bypass/Loader Pattern",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            Reason = $"Service '{svcName}' contains a suspicious keyword (bypass/loader/inject) associated with cheat infrastructure.",
                            Detail = $"Service name: {svcName}"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            using var msSettingsKey = Registry.CurrentUser.OpenSubKey(@"Software\Classes\ms-settings", writable: false);
            ctx.IncrementRegistryKeys();
            if (msSettingsKey is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "UAC Bypass Registry Artifact Detected",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\Classes\ms-settings",
                    Reason = "HKCU\\Software\\Classes\\ms-settings key exists, a known UAC bypass artifact used by privilege escalation techniques in cheat loaders.",
                    Detail = null
                });
            }
        }
        catch { }

        try
        {
            using var knownDllsKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs", writable: false);
            ctx.IncrementRegistryKeys();
            if (knownDllsKey is not null)
            {
                var expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    { "ntdll", "ntdll.dll" },
                    { "kernel32", "kernel32.dll" },
                    { "user32", "user32.dll" },
                    { "advapi32", "advapi32.dll" }
                };

                foreach (var valueName in knownDllsKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    if (!expected.TryGetValue(valueName, out var expectedValue)) continue;
                    var actualValue = knownDllsKey.GetValue(valueName) as string;
                    if (actualValue is null) continue;
                    if (!actualValue.Equals(expectedValue, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "KnownDLLs Registry Entry Tampered",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs\{valueName}",
                            Reason = $"KnownDLLs entry '{valueName}' has unexpected value '{actualValue}' (expected '{expectedValue}'). This may indicate DLL hijacking setup by a cheat.",
                            Detail = $"Name: {valueName}, Expected: {expectedValue}, Actual: {actualValue}"
                        });
                    }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatUpdateMechanismArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;

                var fileName = Path.GetFileName(file);

                if (UpdaterFileNames.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase)))
                {
                    var isSystemPath = file.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase)
                        || file.StartsWith(programFiles, StringComparison.OrdinalIgnoreCase)
                        || file.StartsWith(programFilesX86, StringComparison.OrdinalIgnoreCase);

                    if (isSystemPath) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Auto-Update Mechanism Executable Found",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Cheat updater executable '{fileName}' found in non-standard path. This is consistent with cheat software auto-update mechanisms.",
                        Detail = $"Full path: {file}"
                    });
                    continue;
                }

                if (!UpdaterConfigNames.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase))) continue;

                ctx.IncrementFiles();

                if (!File.Exists(file)) continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch { continue; }

                var domainHit = SuspiciousAutorunDomainKeywords.FirstOrDefault(d =>
                    content.Contains(d, StringComparison.OrdinalIgnoreCase));

                if (domainHit is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cheat Update Config with Suspicious Domain",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Update config file '{fileName}' contains a URL pointing to suspected cheat distribution domain matching pattern '{domainHit}'.",
                    Detail = $"Matched domain keyword: {domainHit}"
                });
            }
        }
    }, ct);

    private Task CheckSandboxEvasionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var root in UserScanRoots)
        {
            if (!Directory.Exists(root)) continue;

            string[] files;
            try { files = Directory.GetFiles(root, "*.dll", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (!SandboxEvasionFileNames.Any(n => fileName.Equals(n, StringComparison.OrdinalIgnoreCase))) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Sandbox/VM Evasion Bypass Artifact Found",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known sandbox or VM detection bypass file '{fileName}' found. This is used to evade anti-cheat sandbox detection.",
                    Detail = $"Full path: {file}"
                });
            }
        }

        var prefetchDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(prefetchDir))
        {
            await Task.CompletedTask;
            return;
        }

        string[] prefetchFiles;
        try { prefetchFiles = Directory.GetFiles(prefetchDir, "*.pf"); }
        catch
        {
            await Task.CompletedTask;
            return;
        }

        var vmPrefetchNames = new[] { "VBOX", "VMWARE" };
        var cheatPrefetchKeywords = new[] { "CHEAT", "HACK", "INJECT", "LOADER", "BYPASS" };

        var hasVmPrefetch = prefetchFiles.Any(f =>
            vmPrefetchNames.Any(n => Path.GetFileName(f).StartsWith(n, StringComparison.OrdinalIgnoreCase)));

        var hasCheatPrefetch = prefetchFiles.Any(f =>
            cheatPrefetchKeywords.Any(k => Path.GetFileName(f).Contains(k, StringComparison.OrdinalIgnoreCase)));

        if (hasVmPrefetch && hasCheatPrefetch)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "VM Tool and Cheat Tool Prefetch Entries Co-Present",
                Risk = RiskLevel.Medium,
                Location = prefetchDir,
                Reason = "Both VM-related prefetch entries (VBOX*/VMWARE*) and cheat tool prefetch entries were found. This pattern is consistent with anti-VM evasion testing by cheat developers.",
                Detail = $"Prefetch directory: {prefetchDir}"
            });
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckObfuscatedCheatScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var fivemScriptDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM", "FiveM.app", "citizen", "scripting", "lua");
        var ragempScriptDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RAGEMP", "resources");
        var altvScriptDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv", "resources");
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        var scriptRoots = new[] { fivemScriptDir, ragempScriptDir, altvScriptDir, downloads }
            .Where(Directory.Exists)
            .ToArray();

        var hexEscapeRegex = new Regex(@"\\x[0-9a-fA-F]{2}", RegexOptions.Compiled);
        var base64AtobRegex = new Regex(@"atob\s*\(\s*""[A-Za-z0-9+/=]{40,}""", RegexOptions.Compiled);
        var luaLoadstringB64Regex = new Regex(@"loadstring\s*\(\s*[""'](?:[A-Za-z0-9+/=]{40,})[""']", RegexOptions.Compiled);
        var obfuscatedGRegex = new Regex(@"_G\[\\x[0-9a-fA-F]{2}", RegexOptions.Compiled);
        var evalAtobRegex = new Regex(@"eval\s*\(\s*atob\s*\(", RegexOptions.Compiled);

        var scriptExtensions = new[] { ".lua", ".js" };

        foreach (var root in scriptRoots)
        {
            string[] files;
            try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;

                var ext = Path.GetExtension(file);
                if (!scriptExtensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase))) continue;

                ctx.IncrementFiles();

                if (!File.Exists(file)) continue;

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch { continue; }

                if (content.Length == 0) continue;

                var hexMatches = hexEscapeRegex.Matches(content);
                var hexRatio = content.Length > 0 ? (double)(hexMatches.Count * 4) / content.Length : 0.0;
                var isHeavilyHexEncoded = hexRatio > 0.80;

                var hasBase64Atob = base64AtobRegex.IsMatch(content);
                var hasLuaLoadstringB64 = luaLoadstringB64Regex.IsMatch(content);
                var hasObfuscatedG = obfuscatedGRegex.IsMatch(content);
                var hasEvalAtob = evalAtobRegex.IsMatch(content);

                if (!isHeavilyHexEncoded && !hasBase64Atob && !hasLuaLoadstringB64 && !hasObfuscatedG && !hasEvalAtob) continue;

                var patterns = new List<string>();
                if (isHeavilyHexEncoded) patterns.Add($"heavily hex-encoded content ({hexRatio:P0} hex escapes)");
                if (hasBase64Atob) patterns.Add("atob() base64 decoding");
                if (hasLuaLoadstringB64) patterns.Add("Lua loadstring() with base64");
                if (hasObfuscatedG) patterns.Add("obfuscated _G[] accessor");
                if (hasEvalAtob) patterns.Add("eval(atob(...)) pattern");

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Heavily Obfuscated Cheat Script Detected",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = $"Script file '{Path.GetFileName(file)}' shows signs of heavy obfuscation consistent with cheat script loaders: {string.Join(", ", patterns)}.",
                    Detail = $"Obfuscation patterns matched: {string.Join("; ", patterns)}"
                });
            }
        }
    }, ct);
}
