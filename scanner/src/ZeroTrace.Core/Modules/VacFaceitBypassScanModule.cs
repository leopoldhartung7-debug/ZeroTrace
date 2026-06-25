using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class VacFaceitBypassScanModule : IScanModule
{
    public string Name => "VAC / FACEIT Bypass Detection";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    // Common base paths
    private static readonly string SteamDefaultPath = @"C:\Program Files (x86)\Steam\";
    private static readonly string EpicDefaultPath = @"C:\Program Files\Epic Games\";

    // Steam emulator config filenames mapped to risk levels
    private static readonly (string FileName, RiskLevel Risk, string Reason)[] SteamEmuConfigFiles =
    [
        ("SmartSteamEmu.ini",      RiskLevel.Critical, "SmartSteamEmu config file — Steam VAC bypass emulator"),
        ("SSE.ini",                RiskLevel.Critical, "SmartSteamEmu (SSE) config file — Steam VAC bypass emulator"),
        ("cream_api.ini",          RiskLevel.Critical, "CreamAPI config — Steam DRM and VAC bypass emulator"),
        ("SmokeAPI.ini",           RiskLevel.High,     "SmokeAPI config — Steam DLC/license bypass emulator"),
        ("Koaloader.ini",          RiskLevel.High,     "Koaloader config — proxy DLL loader used by Steam emulators"),
        ("steam_interfaces.txt",   RiskLevel.High,     "Goldberg Steam Emulator interface list artifact"),
        ("user_steam_id.txt",      RiskLevel.High,     "Goldberg Steam Emulator saved user ID artifact"),
        ("local_save.txt",         RiskLevel.Medium,   "Goldberg Steam Emulator local save artifact"),
        ("DLLInjector.ini",        RiskLevel.Critical, "GreenLuma DLLInjector config — Steam authentication bypass"),
    ];

    // Steam emulator DLL filenames — all Critical
    private static readonly string[] SteamEmuDlls =
    [
        "SmartSteamEmu64.dll",
        "SmartSteamEmu.dll",
        "GreenLuma.dll",
        "CreamAPI.dll",
        "cream_api.dll",
        "steam_api_emu.dll",
        "Goldberg_steam_api.dll",
        "goldberg_steam_api64.dll",
        "ALI213_steam_api.dll",
        "skidrow_steam_api.dll",
        "RELOADED_steam_api.dll",
        "SmokeAPI.dll",
        "SmokeAPI64.dll",
        "Koaloader.dll",
        "Koaloader64.dll",
        "valve_native.dll",
    ];

    // DLLs that are suspicious when found next to steam_api.dll / steam_api64.dll
    private static readonly string[] SuspiciousProxyDlls =
    [
        "version.dll",
        "winmm.dll",
        "winhttp.dll",
    ];

    // Fake Steam API DLL names
    private static readonly string[] FakeSteamApiDlls =
    [
        "vcruntime_bypass.dll",
        "steamapi_bypass.dll",
        "steam_api64_bypass.dll",
        "steam_api_bypass.dll",
        "steamclient_bypass.dll",
        "steam_bypass.dll",
    ];

    // VAC scan window / bypass config strings
    private static readonly (string Pattern, RiskLevel Risk, string Reason)[] VacConfigPatterns =
    [
        ("safe_window=120",  RiskLevel.Critical, "VAC safe scan window configuration — cheat evasion timing exploit"),
        ("vac_safe=true",    RiskLevel.Critical, "VAC safe mode flag — explicit VAC bypass configuration"),
        ("disable_vac",      RiskLevel.Critical, "Explicit VAC disable directive in config file"),
        ("vac_bypass=1",     RiskLevel.Critical, "VAC bypass enabled flag in config file"),
        ("vac_window",       RiskLevel.High,     "VAC scan window manipulation directive"),
        ("vac_timing",       RiskLevel.High,     "VAC timing manipulation directive"),
    ];

    // VAC module hiding config strings
    private static readonly (string Pattern, RiskLevel Risk, string Reason)[] VacHidingPatterns =
    [
        ("unmap_steam",       RiskLevel.Critical, "Steam module unmapping directive — hides cheat from VAC scan"),
        ("unmap_steamclient", RiskLevel.Critical, "SteamClient module unmapping — evades VAC memory scan"),
        ("hide_from_vac",     RiskLevel.Critical, "Explicit hide-from-VAC directive in cheat config"),
        ("steam_unmap",       RiskLevel.Critical, "Steam unmap directive — manual module hiding from VAC"),
        ("steamclient_hide",  RiskLevel.Critical, "SteamClient hide directive — VAC evasion artifact"),
        ("module_unload",     RiskLevel.High,     "Module unload directive combined with Steam reference — possible VAC evasion"),
    ];

    // Trust factor bypass tool names
    private static readonly string[] TrustBypassNames =
    [
        "trust_factor_bypass",
        "trustfactor_bypass",
        "tf_bypass",
        "playtime_inflator",
        "playtime_booster",
        "vac_trust_bypass",
        "TrustFactorBypass.exe",
        "PlaytimeBooster.exe",
        "TrustFactor.exe",
        "fake_playtime.exe",
    ];

    // FACEIT bypass executable/DLL filenames
    private static readonly string[] FaceitBypassFiles =
    [
        "faceit_bypass.exe",
        "faceit_spoofer.exe",
        "faceit_unloader.exe",
        "FC_Bypass.dll",
        "faceit_bypass.dll",
        "faceit-bypass.exe",
        "faceit-bypass.dll",
        "faceitbypass.exe",
        "faceitbypass.dll",
        "FaceitFix.exe",
        "FaceitPatch.exe",
        "faceit_killer.exe",
        "faceit_off.exe",
        "faceit_disable.exe",
        "nofaceit.exe",
        "faceit_emu.dll",
        "faceit_hook.dll",
    ];

    // FACEIT bypass GitHub repo folder names
    private static readonly string[] FaceitBypassRepoNames =
    [
        "faceit-bypass",
        "faceit-ac-bypass",
        "faceit-cheat",
        "FaceitBypass",
        "faceit_bypass_src",
        "faceit-anticheat-bypass",
        "open-faceit",
        "faceit-emu",
        "FACEITEmulator",
    ];

    // FACEIT evasion config patterns
    private static readonly (string Pattern, RiskLevel Risk, string Reason)[] FaceitConfigPatterns =
    [
        ("bypass_faceit",        RiskLevel.Critical, "FACEIT bypass directive — explicit anti-cheat evasion"),
        ("faceit_safe",          RiskLevel.Critical, "FACEIT safe mode directive — anti-cheat evasion config"),
        ("disable_faceit_ac",    RiskLevel.Critical, "FACEIT AC disable directive in config file"),
        ("faceit_bypass=true",   RiskLevel.Critical, "FACEIT bypass enabled flag in config"),
        ("faceit_mode=bypass",   RiskLevel.Critical, "FACEIT bypass mode directive in config file"),
        ("faceit_unload",        RiskLevel.High,     "FACEIT AC unload directive — evasion attempt"),
        ("fc_bypass",            RiskLevel.High,     "FC_Bypass reference in config — FACEIT evasion artifact"),
    ];

    // PowerShell / script patterns for FACEIT/VAC tampering
    private static readonly (string[] Tokens, RiskLevel Risk, string Reason)[] PowerShellPatterns =
    [
        (["sc stop faceit"],                     RiskLevel.Critical, "PowerShell command to stop FACEIT service — manual AC bypass"),
        (["net stop faceit"],                    RiskLevel.Critical, "net stop command targeting FACEIT service — manual AC bypass"),
        (["sc delete faceit"],                   RiskLevel.Critical, "PowerShell command to delete FACEIT service — AC removal"),
        (["sc stop faceitservice"],              RiskLevel.Critical, "PowerShell command to stop FACEITService — manual AC bypass"),
        (["sc stop vac"],                        RiskLevel.High,     "PowerShell command targeting VAC service"),
        (["taskkill", "faceit"],                 RiskLevel.High,     "taskkill command targeting FACEIT process — anti-cheat evasion"),
        (["taskkill", "faceitservice"],          RiskLevel.High,     "taskkill command targeting FACEITService process"),
        (["taskkill", "steam.exe"],              RiskLevel.Medium,   "taskkill targeting Steam.exe — possible cheat-context Steam kill"),
    ];

    // CS2/CSGO autoexec suspicious cfg patterns
    private static readonly (string Pattern, RiskLevel Risk, string Reason)[] AutoexecPatterns =
    [
        ("sv_cheats 1",          RiskLevel.Critical, "sv_cheats 1 in autoexec.cfg — server-side cheat enable command"),
        ("r_drawothermodels 2",  RiskLevel.Critical, "r_drawothermodels 2 in autoexec — wallhack/ESP rendering command"),
        ("enable_skeleton_draw", RiskLevel.High,     "enable_skeleton_draw in autoexec — skeleton ESP rendering command"),
        ("mat_wireframe",        RiskLevel.Medium,   "mat_wireframe in autoexec — wireframe rendering command"),
    ];

    // CS2/CSGO paths to check
    private static readonly string[] CsgoGameinfoPaths =
    [
        @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\gameinfo.gi",
        @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike 2\game\csgo\gameinfo.gi",
    ];

    private static readonly string[] CsgoAutoexecPaths =
    [
        @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\cfg\autoexec.cfg",
        @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike 2\game\csgo\cfg\autoexec.cfg",
    ];

    private static readonly string[] CsgoWorkshopPaths =
    [
        @"C:\Program Files (x86)\Steam\steamapps\workshop\content\730\",
    ];

    // Directories to scan for emulator configs / bypass tools
    private static string[] GetCommonScanRoots()
    {
        var roots = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(userProfile, "Downloads");
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var temp = Path.GetTempPath();

        if (!string.IsNullOrEmpty(desktop)) roots.Add(desktop);
        if (!string.IsNullOrEmpty(downloads)) roots.Add(downloads);
        if (!string.IsNullOrEmpty(documents)) roots.Add(documents);
        if (!string.IsNullOrEmpty(appData)) roots.Add(appData);
        if (!string.IsNullOrEmpty(localAppData)) roots.Add(localAppData);
        if (!string.IsNullOrEmpty(temp)) roots.Add(temp);
        roots.Add(@"C:\Program Files (x86)\Steam\steamapps\common\");
        roots.Add(@"C:\Program Files\Epic Games\");

        return roots.Where(Directory.Exists).ToArray();
    }

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ctx.Report(0.00, "Starting VAC/FACEIT bypass scan");

        await ScanSteamEmulatorConfigFilesAsync(ctx, ct);
        ctx.Report(0.07, "Steam emulator config files scanned");

        await ScanSteamEmulatorDllsAsync(ctx, ct);
        ctx.Report(0.14, "Steam emulator DLLs scanned");

        await ScanVacConfigPatternsAsync(ctx, ct);
        ctx.Report(0.21, "VAC config patterns scanned");

        await ScanVacModuleHidingArtifactsAsync(ctx, ct);
        ctx.Report(0.28, "VAC module hiding artifacts scanned");

        await ScanTrustFactorBypassToolsAsync(ctx, ct);
        ctx.Report(0.34, "Trust factor bypass tools scanned");

        await ScanSteamInsecureLaunchOptionsAsync(ctx, ct);
        ctx.Report(0.41, "Steam launch options scanned");

        await ScanFaceitServiceRegistryAsync(ctx, ct);
        ctx.Report(0.48, "FACEIT service registry scanned");

        await ScanFaceitBypassFilesAsync(ctx, ct);
        ctx.Report(0.54, "FACEIT bypass executables scanned");

        await ScanFaceitBypassReposAsync(ctx, ct);
        ctx.Report(0.59, "FACEIT bypass repo folders scanned");

        await ScanFaceitEvasionConfigsAsync(ctx, ct);
        ctx.Report(0.64, "FACEIT evasion configs scanned");

        await ScanFakeSteamApiDllsAsync(ctx, ct);
        ctx.Report(0.69, "Fake Steam API DLLs scanned");

        await ScanGameoverlayrendererOutsideSteamAsync(ctx, ct);
        ctx.Report(0.73, "gameoverlayrenderer location scanned");

        await ScanPowerShellHistoryAsync(ctx, ct);
        ctx.Report(0.78, "PowerShell history scanned");

        await ScanCsgoGameSpecificFilesAsync(ctx, ct);
        ctx.Report(0.84, "CS2/CSGO specific files scanned");

        await ScanWorkshopVpkFilesAsync(ctx, ct);
        ctx.Report(0.88, "CS2/CSGO workshop VPK files scanned");

        await ScanSteamRegistryArtifactsAsync(ctx, ct);
        ctx.Report(0.93, "Steam registry artifacts scanned");

        await ScanCsgoCfgDirectoryPayloadsAsync(ctx, ct);
        ctx.Report(1.00, "CS2/CSGO cfg directory payloads scanned");
    }

    // -------------------------------------------------------------------------
    // 1. Steam emulator config files
    // -------------------------------------------------------------------------

    private async Task ScanSteamEmulatorConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetCommonScanRoots();

        // Check for GreenLuma folder variants
        var greenLumaFolders = new[] { "GreenLumaReborn", "GreenLuma2024", "GreenLuma" };
        var creamInstallerFolder = "CreamInstaller";
        var steamSettingsFolder = "steam_settings";
        var ali213Folder = "ALI213";

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();

            // Enumerate top-level and one level deep
            IEnumerable<string> dirsToCheck;
            try
            {
                dirsToCheck = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly)
                    .Prepend(root);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var dir in dirsToCheck)
            {
                ct.ThrowIfCancellationRequested();

                // Check for special named folders
                var dirName = Path.GetFileName(dir);

                foreach (var glFolder in greenLumaFolders)
                {
                    if (dirName.Equals(glFolder, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "GreenLuma Emulator Folder",
                            Risk = RiskLevel.Critical,
                            Location = dir,
                            FileName = dirName,
                            Reason = "GreenLuma Steam emulator folder found — bypasses Steam authentication and VAC",
                            Detail = $"Folder: {dir}",
                        });
                    }
                }

                if (dirName.Equals(creamInstallerFolder, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "CreamInstaller Folder",
                        Risk = RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason = "CreamInstaller folder found — tool used to install CreamAPI/SmokeAPI Steam bypasses",
                        Detail = $"Folder: {dir}",
                    });
                }

                if (dirName.Equals(steamSettingsFolder, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Goldberg Steam Emulator Settings Folder",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = dirName,
                        Reason = "Goldberg Steam Emulator steam_settings folder found — bypasses Steam DRM and VAC",
                        Detail = $"Folder: {dir}",
                    });
                }

                // Check for ALI213\Profile.ini
                if (dirName.Equals(ali213Folder, StringComparison.OrdinalIgnoreCase))
                {
                    var profileIni = Path.Combine(dir, "Profile.ini");
                    if (File.Exists(profileIni))
                    {
                        await ReadAndReportEmuConfigAsync(ctx, profileIni,
                            "ALI213 Steam Emulator Profile",
                            RiskLevel.Critical,
                            "ALI213 Steam emulator Profile.ini found — bypasses Steam authentication and VAC");
                    }
                }

                // Check for GreenLuma DLLInjector.ini next to steam_api.dll
                var dllInjectorIni = Path.Combine(dir, "DLLInjector.ini");
                var steamApiDll = Path.Combine(dir, "steam_api.dll");
                var steamApi64Dll = Path.Combine(dir, "steam_api64.dll");
                if (File.Exists(dllInjectorIni) && (File.Exists(steamApiDll) || File.Exists(steamApi64Dll)))
                {
                    await ReadAndReportEmuConfigAsync(ctx, dllInjectorIni,
                        "GreenLuma DLLInjector Config",
                        RiskLevel.Critical,
                        "GreenLuma DLLInjector.ini found next to steam_api.dll — Steam authentication bypass");
                }

                // Check for named emulator config files
                foreach (var (fileName, risk, reason) in SteamEmuConfigFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var filePath = Path.Combine(dir, fileName);
                    if (!File.Exists(filePath)) continue;

                    await ReadAndReportEmuConfigAsync(ctx, filePath,
                        $"Steam Emulator Config: {fileName}",
                        risk,
                        reason);
                }
            }
        }
    }

    // Helper: read an emulator config file and report a finding
    private async Task ReadAndReportEmuConfigAsync(ScanContext ctx, string path, string title, RiskLevel risk, string reason)
    {
        ctx.IncrementFiles();
        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            // Swallow silently
            content = string.Empty;
        }
        catch (UnauthorizedAccessException)
        {
            content = string.Empty;
        }

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = title,
            Risk = risk,
            Location = path,
            FileName = Path.GetFileName(path),
            Reason = reason,
            Detail = content.Length > 0
                ? $"File size: {content.Length} bytes. First 200 chars: {content[..Math.Min(200, content.Length)]}"
                : "File present but could not be read.",
        });
    }

    // -------------------------------------------------------------------------
    // 2. Steam emulator DLLs
    // -------------------------------------------------------------------------

    private async Task ScanSteamEmulatorDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetCommonScanRoots();

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                // Check known emulator DLLs
                foreach (var emuDll in SteamEmuDlls)
                {
                    if (fileName.Equals(emuDll, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Steam Emulator DLL: {emuDll}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known Steam emulator DLL '{emuDll}' found — bypasses Steam DRM and VAC",
                            Detail = $"Found at: {file}",
                        });
                        break;
                    }
                }

                // Check proxy DLLs when steam_api exists in same dir
                var dir = Path.GetDirectoryName(file) ?? string.Empty;
                bool hasSteamApi = File.Exists(Path.Combine(dir, "steam_api.dll"))
                                || File.Exists(Path.Combine(dir, "steam_api64.dll"));

                if (hasSteamApi)
                {
                    foreach (var proxyDll in SuspiciousProxyDlls)
                    {
                        if (fileName.Equals(proxyDll, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Proxy DLL Next to Steam API: {proxyDll}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = $"'{proxyDll}' found alongside steam_api.dll — common emulator proxy DLL injection technique",
                                Detail = $"Found at: {file}",
                            });
                            break;
                        }
                    }

                    // steamclient.dll in game dir is suspicious (should only be in Steam install dir)
                    if (fileName.Equals("steamclient.dll", StringComparison.OrdinalIgnoreCase)
                        && !dir.StartsWith(SteamDefaultPath, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "steamclient.dll in Game Directory",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "steamclient.dll found in game directory (not in Steam install) — possible emulator injection point",
                            Detail = $"Found at: {file}",
                        });
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // -------------------------------------------------------------------------
    // 3. VAC scan window exploit configs
    // -------------------------------------------------------------------------

    private async Task ScanVacConfigPatternsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetCommonScanRoots();
        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".ini", ".cfg", ".json", ".txt" };

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!extensions.Contains(ext)) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException)
                {
                    continue;
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                var contentLower = content.ToLowerInvariant();

                foreach (var (pattern, risk, reason) in VacConfigPatterns)
                {
                    if (contentLower.Contains(pattern.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VAC Bypass Config Pattern: {pattern}",
                            Risk = risk,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = reason,
                            Detail = $"Pattern '{pattern}' found in file: {file}",
                        });
                    }
                }

                // Special case: safe_period + vac combination
                if (contentLower.Contains("safe_period", StringComparison.OrdinalIgnoreCase)
                    && contentLower.Contains("vac", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VAC Safe Period Configuration",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "Config file contains 'safe_period' combined with 'vac' — VAC evasion timing configuration",
                        Detail = $"Found in: {file}",
                    });
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 4. VAC module hiding artifacts
    // -------------------------------------------------------------------------

    private async Task ScanVacModuleHidingArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetCommonScanRoots();
        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".ini", ".cfg", ".json", ".txt", ".lua", ".xml" };

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!extensions.Contains(ext)) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException)
                {
                    continue;
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                var contentLower = content.ToLowerInvariant();

                foreach (var (pattern, risk, reason) in VacHidingPatterns)
                {
                    var patternLower = pattern.ToLowerInvariant();

                    // Special case: module_unload must also contain "steam"
                    if (patternLower == "module_unload")
                    {
                        if (contentLower.Contains("module_unload", StringComparison.OrdinalIgnoreCase)
                            && contentLower.Contains("steam", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "VAC Hiding: module_unload + steam",
                                Risk = risk,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = reason,
                                Detail = $"Found in: {file}",
                            });
                        }
                        continue;
                    }

                    if (contentLower.Contains(patternLower, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VAC Module Hiding Artifact: {pattern}",
                            Risk = risk,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = reason,
                            Detail = $"Pattern '{pattern}' found in file: {file}",
                        });
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // -------------------------------------------------------------------------
    // 5. Trust factor manipulation tools
    // -------------------------------------------------------------------------

    private async Task ScanTrustFactorBypassToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetCommonScanRoots();

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();

            // Check files
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                foreach (var bypassName in TrustBypassNames)
                {
                    if (fileName.Equals(bypassName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Trust Factor Bypass Tool: {bypassName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known trust factor bypass tool '{bypassName}' found — manipulates CS2/CSGO matchmaking trust rating",
                            Detail = $"Found at: {file}",
                        });
                        break;
                    }
                }
            }

            // Also check directory names
            IEnumerable<string> dirs;
            try
            {
                dirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var dir in dirs)
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(dir);

                foreach (var bypassName in TrustBypassNames)
                {
                    var baseName = Path.GetFileNameWithoutExtension(bypassName);
                    if (dirName.Equals(baseName, StringComparison.OrdinalIgnoreCase)
                        || dirName.Equals(bypassName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Trust Factor Bypass Folder: {dirName}",
                            Risk = RiskLevel.High,
                            Location = dir,
                            FileName = dirName,
                            Reason = $"Trust factor bypass tool folder '{dirName}' found — manipulates CS2/CSGO matchmaking trust rating",
                            Detail = $"Found at: {dir}",
                        });
                        break;
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // -------------------------------------------------------------------------
    // 6. Steam -insecure launch option check
    // -------------------------------------------------------------------------

    private async Task ScanSteamInsecureLaunchOptionsAsync(ScanContext ctx, CancellationToken ct)
    {
        var localConfigPaths = new List<string>();

        // APPDATA path
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var appDataUserdataRoot = Path.Combine(appData, "Steam", "userdata");
        if (Directory.Exists(appDataUserdataRoot))
        {
            try
            {
                foreach (var userDir in Directory.EnumerateDirectories(appDataUserdataRoot))
                {
                    ct.ThrowIfCancellationRequested();
                    var vdfPath = Path.Combine(userDir, "config", "localconfig.vdf");
                    if (File.Exists(vdfPath)) localConfigPaths.Add(vdfPath);
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        // Default Steam install path
        var steamUserdataRoot = @"C:\Program Files (x86)\Steam\userdata";
        if (Directory.Exists(steamUserdataRoot))
        {
            try
            {
                foreach (var userDir in Directory.EnumerateDirectories(steamUserdataRoot))
                {
                    ct.ThrowIfCancellationRequested();
                    var vdfPath = Path.Combine(userDir, "config", "localconfig.vdf");
                    if (File.Exists(vdfPath) && !localConfigPaths.Contains(vdfPath, StringComparer.OrdinalIgnoreCase))
                        localConfigPaths.Add(vdfPath);
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        foreach (var vdfPath in localConfigPaths)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(vdfPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            if (content.Contains("-insecure", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Steam -insecure Launch Option",
                    Risk = RiskLevel.Critical,
                    Location = vdfPath,
                    FileName = Path.GetFileName(vdfPath),
                    Reason = "-insecure flag in Steam localconfig.vdf — disables VAC for CS2/CSGO",
                    Detail = $"File: {vdfPath}",
                });
            }

            if (content.Contains("sv_cheats 1", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "sv_cheats 1 in Steam Launch Options",
                    Risk = RiskLevel.Critical,
                    Location = vdfPath,
                    FileName = Path.GetFileName(vdfPath),
                    Reason = "sv_cheats 1 in Steam localconfig.vdf launch options — enables server-side cheats",
                    Detail = $"File: {vdfPath}",
                });
            }

            if (content.Contains("-allowdebug", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Steam -allowdebug Launch Option",
                    Risk = RiskLevel.High,
                    Location = vdfPath,
                    FileName = Path.GetFileName(vdfPath),
                    Reason = "-allowdebug flag in Steam launch options — enables debug mode which can be abused to bypass anti-cheat",
                    Detail = $"File: {vdfPath}",
                });
            }

            // -dev combined with CS AppID context (730 = CS2/CSGO)
            if (content.Contains("-dev", StringComparison.OrdinalIgnoreCase)
                && (content.Contains("\"730\"", StringComparison.OrdinalIgnoreCase)
                    || content.Contains("counter-strike", StringComparison.OrdinalIgnoreCase)))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Steam -dev Launch Option in CS Context",
                    Risk = RiskLevel.Medium,
                    Location = vdfPath,
                    FileName = Path.GetFileName(vdfPath),
                    Reason = "-dev launch option found in CS2/CSGO context — developer mode may weaken anti-cheat protections",
                    Detail = $"File: {vdfPath}",
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 7. FACEIT AC service/driver check
    // -------------------------------------------------------------------------

    private async Task ScanFaceitServiceRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // Check FACEIT service registry keys
        var faceitServiceKeys = new[] { "faceit", "FACEITService" };

        foreach (var serviceName in faceitServiceKeys)
        {
            ct.ThrowIfCancellationRequested();
            var keyPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";

            await Task.Run(() =>
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                    ctx.IncrementRegistryKeys();

                    if (key == null) return;

                    var startValue = key.GetValue("Start");
                    if (startValue is int startInt && startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FACEIT Service Disabled: {serviceName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}",
                            FileName = null,
                            Reason = $"FACEIT service '{serviceName}' is set to Start=4 (Disabled) — anti-cheat driver has been manually disabled",
                            Detail = $"Registry key: HKLM\\{keyPath}, Start value: 4",
                        });
                    }

                    // Validate ImagePath exists on disk
                    var imagePath = key.GetValue("ImagePath") as string;
                    if (!string.IsNullOrEmpty(imagePath))
                    {
                        // Strip kernel path prefix if present
                        var cleanPath = imagePath.TrimStart('\\').Replace("SystemRoot\\", @"C:\Windows\", StringComparison.OrdinalIgnoreCase);
                        if (imagePath.Contains("faceit.sys", StringComparison.OrdinalIgnoreCase))
                        {
                            var sysPath = cleanPath;
                            if (!File.Exists(sysPath))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FACEIT Driver File Missing",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKLM\{keyPath}",
                                    FileName = "faceit.sys",
                                    Reason = "FACEIT service points to faceit.sys driver that does not exist on disk — driver may have been removed to bypass FACEIT",
                                    Detail = $"ImagePath: {imagePath}",
                                });
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception) { }
            }, ct);
        }

        // Process check: look for FACEIT client processes
        await Task.Run(() =>
        {
            var faceitProcessNames = new[] { "faceit-client-container", "faceit-anticheat", "FACEITClient" };
            bool anyFaceitRunning = false;

            foreach (var procName in faceitProcessNames)
            {
                try
                {
                    var procs = System.Diagnostics.Process.GetProcessesByName(procName);
                    ctx.IncrementProcesses((long)procs.Length);

                    if (procs.Length > 0)
                    {
                        anyFaceitRunning = true;
                    }
                }
                catch { }
            }

            if (!anyFaceitRunning)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "FACEIT Client Process Not Running",
                    Risk = RiskLevel.Low,
                    Location = "Process list",
                    FileName = null,
                    Reason = "No FACEIT client process detected — FACEIT may not be installed, or may have been bypassed/unloaded",
                    Detail = "Processes checked: faceit-client-container, faceit-anticheat, FACEITClient",
                });
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // 8. FACEIT bypass executables/DLLs
    // -------------------------------------------------------------------------

    private async Task ScanFaceitBypassFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();

        var searchRoots = new[] { desktop, downloads, appData, localAppData, temp }
            .Where(Directory.Exists)
            .ToArray();

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                foreach (var bypassFile in FaceitBypassFiles)
                {
                    if (fileName.Equals(bypassFile, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FACEIT Bypass File: {bypassFile}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known FACEIT bypass executable/DLL '{bypassFile}' found — used to disable or circumvent FACEIT anti-cheat",
                            Detail = $"Found at: {file}",
                        });
                        break;
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // -------------------------------------------------------------------------
    // 9. FACEIT bypass GitHub repos (folder names)
    // -------------------------------------------------------------------------

    private async Task ScanFaceitBypassReposAsync(ScanContext ctx, CancellationToken ct)
    {
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var searchRoots = new[] { desktop, downloads, documents, appData }
            .Where(Directory.Exists)
            .ToArray();

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();

            IEnumerable<string> dirs;
            try
            {
                dirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var dir in dirs)
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(dir);

                foreach (var repoName in FaceitBypassRepoNames)
                {
                    if (dirName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FACEIT Bypass Repo Folder: {repoName}",
                            Risk = RiskLevel.High,
                            Location = dir,
                            FileName = dirName,
                            Reason = $"Known FACEIT bypass project folder '{repoName}' found — indicates presence of FACEIT anti-cheat bypass source or build",
                            Detail = $"Found at: {dir}",
                        });
                        break;
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // -------------------------------------------------------------------------
    // 10. FACEIT evasion config files
    // -------------------------------------------------------------------------

    private async Task ScanFaceitEvasionConfigsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetCommonScanRoots();
        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".json", ".ini", ".cfg", ".txt" };

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!extensions.Contains(ext)) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException)
                {
                    continue;
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var (pattern, risk, reason) in FaceitConfigPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FACEIT Evasion Config: {pattern}",
                            Risk = risk,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = reason,
                            Detail = $"Pattern '{pattern}' found in: {file}",
                        });
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 11. Fake Steam API DLLs
    // -------------------------------------------------------------------------

    private async Task ScanFakeSteamApiDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetCommonScanRoots();

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                foreach (var fakeDll in FakeSteamApiDlls)
                {
                    if (fileName.Equals(fakeDll, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Fake Steam API DLL: {fakeDll}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Fake/bypass Steam API DLL '{fakeDll}' found — replaces legitimate Steam API to bypass VAC and DRM",
                            Detail = $"Found at: {file}",
                        });
                        break;
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // -------------------------------------------------------------------------
    // 12. Modified gameoverlayrenderer64.dll outside Steam
    // -------------------------------------------------------------------------

    private async Task ScanGameoverlayrendererOutsideSteamAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchNames = new[] { "gameoverlayrenderer64.dll", "gameoverlayrenderer.dll" };
        var roots = GetCommonScanRoots();

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();

            // Skip if this root is inside or is the Steam install directory
            if (root.StartsWith(SteamDefaultPath, StringComparison.OrdinalIgnoreCase)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                // Skip files that are actually in the Steam dir
                if (file.StartsWith(SteamDefaultPath, StringComparison.OrdinalIgnoreCase)) continue;

                foreach (var searchName in searchNames)
                {
                    if (fileName.Equals(searchName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"gameoverlayrenderer Outside Steam: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"'{fileName}' found outside Steam installation directory — commonly abused as DLL injection point for cheats",
                            Detail = $"Found at: {file} (Steam install: {SteamDefaultPath})",
                        });
                        break;
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // -------------------------------------------------------------------------
    // 13. PowerShell history for FACEIT/VAC commands
    // -------------------------------------------------------------------------

    private async Task ScanPowerShellHistoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var psHistoryPath = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (File.Exists(psHistoryPath))
        {
            await ScanScriptFileForTamperingAsync(ctx, psHistoryPath, ct);
        }

        // Also scan .bat, .cmd, .ps1 files on Desktop and Downloads
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var scriptRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
        };

        var scriptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".bat", ".cmd", ".ps1" };

        foreach (var root in scriptRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!scriptExtensions.Contains(ext)) continue;

                await ScanScriptFileForTamperingAsync(ctx, file, ct);
            }
        }
    }

    // Helper: scan a script/history file for FACEIT/VAC tampering commands
    private async Task ScanScriptFileForTamperingAsync(ScanContext ctx, string filePath, CancellationToken ct)
    {
        ctx.IncrementFiles();
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (var rawLine in lines)
        {
            ct.ThrowIfCancellationRequested();
            var line = rawLine.Trim();
            var lineLower = line.ToLowerInvariant();

            foreach (var (tokens, risk, reason) in PowerShellPatterns)
            {
                bool allMatch = tokens.All(t => lineLower.Contains(t.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));
                if (!allMatch) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FACEIT/VAC Tampering Command in Script",
                    Risk = risk,
                    Location = filePath,
                    FileName = Path.GetFileName(filePath),
                    Reason = reason,
                    Detail = $"Command: {line.Truncate(200)} | File: {filePath}",
                });
                break;
            }
        }
    }

    // -------------------------------------------------------------------------
    // 14. CS2/CSGO specific checks
    // -------------------------------------------------------------------------

    private async Task ScanCsgoGameSpecificFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        // gameinfo.gi checks
        foreach (var gameinfoPath in CsgoGameinfoPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(gameinfoPath)) continue;

            ctx.IncrementFiles();
            string content;
            try
            {
                using var fs = new FileStream(gameinfoPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            if (content.Contains("sv_cheats 1", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "sv_cheats 1 in CS2/CSGO gameinfo.gi",
                    Risk = RiskLevel.Critical,
                    Location = gameinfoPath,
                    FileName = Path.GetFileName(gameinfoPath),
                    Reason = "sv_cheats 1 found in gameinfo.gi — enables server-side cheats and disables VAC protection",
                    Detail = $"File: {gameinfoPath}",
                });
            }

            if (content.Contains("insecure", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "insecure Flag in CS2/CSGO gameinfo.gi",
                    Risk = RiskLevel.High,
                    Location = gameinfoPath,
                    FileName = Path.GetFileName(gameinfoPath),
                    Reason = "'insecure' found in gameinfo.gi — VAC insecure mode configured in game info file",
                    Detail = $"File: {gameinfoPath}",
                });
            }

            // Check for paths that go outside Steam install dir
            var lines = content.Split('\n');
            foreach (var line in lines)
            {
                ct.ThrowIfCancellationRequested();
                var lineTrimmed = line.Trim();
                // Look for path entries that don't start with game or csgo paths
                if (lineTrimmed.StartsWith("Game", StringComparison.OrdinalIgnoreCase)
                    && (lineTrimmed.Contains(@"..\..", StringComparison.OrdinalIgnoreCase)
                        || lineTrimmed.Contains(@"C:\Users", StringComparison.OrdinalIgnoreCase)
                        || lineTrimmed.Contains(@"%APPDATA%", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Custom Game Path in CS2/CSGO gameinfo.gi",
                        Risk = RiskLevel.High,
                        Location = gameinfoPath,
                        FileName = Path.GetFileName(gameinfoPath),
                        Reason = "Custom game path pointing outside Steam directory found in gameinfo.gi — could load unauthorized game content",
                        Detail = $"Line: {lineTrimmed}",
                    });
                    break;
                }
            }
        }

        // autoexec.cfg checks
        foreach (var autoexecPath in CsgoAutoexecPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(autoexecPath)) continue;

            ctx.IncrementFiles();
            string content;
            try
            {
                using var fs = new FileStream(autoexecPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException)
            {
                continue;
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var (pattern, risk, reason) in AutoexecPatterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious autoexec.cfg Command: {pattern}",
                        Risk = risk,
                        Location = autoexecPath,
                        FileName = Path.GetFileName(autoexecPath),
                        Reason = reason,
                        Detail = $"Pattern '{pattern}' in {autoexecPath}",
                    });
                }
            }

            // Check for bind commands with cheat keywords
            var cheatBindKeywords = new[] { "aimbot", "wallhack", "esp", "triggerbot", "bhop", "speedhack", "norecoil", "spinbot" };
            var bindLines = content.Split('\n').Where(l => l.TrimStart().StartsWith("bind", StringComparison.OrdinalIgnoreCase));
            foreach (var bindLine in bindLines)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var kw in cheatBindKeywords)
                {
                    if (bindLine.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Keyword Bind in autoexec.cfg",
                            Risk = RiskLevel.Medium,
                            Location = autoexecPath,
                            FileName = Path.GetFileName(autoexecPath),
                            Reason = $"bind command with cheat keyword '{kw}' in autoexec.cfg",
                            Detail = $"Line: {bindLine.Trim().Truncate(200)}",
                        });
                        break;
                    }
                }
            }
        }

        // Steam shortcut checks for -insecure
        await ScanSteamShortcutsForInsecureAsync(ctx, ct);
    }

    // Helper: scan Steam shortcut files for -insecure flag
    private async Task ScanSteamShortcutsForInsecureAsync(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var shortcutRoots = new[]
        {
            Path.Combine(appData, "Steam"),
            @"C:\Program Files (x86)\Steam\userdata",
        };

        foreach (var root in shortcutRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);

                bool isShortcutFile = fileName.Equals("shortcuts.vdf", StringComparison.OrdinalIgnoreCase)
                    || ext.Equals(".url", StringComparison.OrdinalIgnoreCase);
                if (!isShortcutFile) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                }
                catch (IOException)
                {
                    continue;
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                if (content.Contains("-insecure", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "-insecure Flag in Steam Shortcut",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = "-insecure flag found in Steam shortcut file — disables VAC for targeted game",
                        Detail = $"File: {file}",
                    });
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 15. Steam Workshop VPK abuse
    // -------------------------------------------------------------------------

    private async Task ScanWorkshopVpkFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var cheatKeywords = new[] { "cheat", "hack", "bypass", "aimbot", "wallhack", "esp", "inject" };

        foreach (var workshopPath in CsgoWorkshopPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(workshopPath)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(workshopPath, "*.vpk", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                var fileNameLower = fileName.ToLowerInvariant();

                // Check for suspicious keywords in VPK filename
                foreach (var kw in cheatKeywords)
                {
                    if (fileNameLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious Workshop VPK: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"CS2/CSGO workshop VPK file with suspicious name containing '{kw}' — may contain unauthorized game modification or cheat payload",
                            Detail = $"File: {file}",
                        });
                        break;
                    }
                }

                // Also scan VPK header content for embedded executable references
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    // Read first 4KB — VPK header with file list
                    var buffer = new char[4096];
                    int read = await sr.ReadAsync(buffer, 0, buffer.Length);
                    var header = new string(buffer, 0, read);

                    var suspiciousEmbeddedExtensions = new[] { ".exe", ".dll", ".bat", ".ps1" };
                    foreach (var suspExt in suspiciousEmbeddedExtensions)
                    {
                        if (header.Contains(suspExt, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Executable Extension in Workshop VPK: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"CS2/CSGO workshop VPK contains reference to '{suspExt}' — potential executable payload embedded in game content",
                                Detail = $"Extension '{suspExt}' found in VPK header of: {file}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 16. HKLM/HKCU registry checks for FACEIT/VAC bypass artifacts
    // -------------------------------------------------------------------------

    private async Task ScanSteamRegistryArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        await Task.Run(() =>
        {
            // HKCU\SOFTWARE\FACEIT — flag if missing when FACEIT might be installed
            try
            {
                using var faceitKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\FACEIT");
                ctx.IncrementRegistryKeys();
                // Low informational if key is missing
                if (faceitKey == null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FACEIT Registry Key Absent",
                        Risk = RiskLevel.Low,
                        Location = @"HKCU\SOFTWARE\FACEIT",
                        Reason = "FACEIT registry key not found — FACEIT may not be installed or registry entries were tampered with",
                        Detail = "Key: HKCU\\SOFTWARE\\FACEIT",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }

            // HKCU\SOFTWARE\Valve\Steam — validate SteamExe path
            try
            {
                using var steamKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam");
                ctx.IncrementRegistryKeys();
                if (steamKey != null)
                {
                    var steamExePath = steamKey.GetValue("SteamExe") as string;
                    if (!string.IsNullOrEmpty(steamExePath) && !File.Exists(steamExePath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Steam Executable Path Invalid",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\SOFTWARE\Valve\Steam",
                            Reason = "SteamExe registry value points to a path that does not exist on disk — Steam may have been removed while emulator remnants remain",
                            Detail = $"SteamExe value: {steamExePath}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }

            // HKCU\SOFTWARE\Valve\Steam\ActiveProcess — flag if pid present but Steam not running
            try
            {
                using var activeProcessKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam\ActiveProcess");
                ctx.IncrementRegistryKeys();
                if (activeProcessKey != null)
                {
                    var pid = activeProcessKey.GetValue("pid");
                    if (pid != null)
                    {
                        int pidInt = Convert.ToInt32(pid);
                        bool steamRunning = false;
                        try
                        {
                            var steamProcs = System.Diagnostics.Process.GetProcessesByName("Steam");
                            steamRunning = steamProcs.Length > 0;
                        }
                        catch { }

                        if (!steamRunning && pidInt != 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Stale Steam ActiveProcess PID",
                                Risk = RiskLevel.Medium,
                                Location = @"HKCU\SOFTWARE\Valve\Steam\ActiveProcess",
                                Reason = "Steam ActiveProcess PID is set in registry but Steam.exe is not running — possible ghost process or emulator artifact",
                                Detail = $"PID value: {pidInt}",
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }

            // HKLM\SOFTWARE\Valve\Steam — validate InstallPath
            try
            {
                using var steamHklmKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam")
                    ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam");
                ctx.IncrementRegistryKeys();
                if (steamHklmKey != null)
                {
                    var installPath = steamHklmKey.GetValue("InstallPath") as string;
                    if (!string.IsNullOrEmpty(installPath) && !Directory.Exists(installPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Steam InstallPath Missing from Disk",
                            Risk = RiskLevel.Medium,
                            Location = @"HKLM\SOFTWARE\Valve\Steam",
                            Reason = "Steam InstallPath in registry points to a directory that does not exist — Steam was removed but emulator remnants may remain",
                            Detail = $"InstallPath value: {installPath}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // 17. CS2/CSGO injector payloads in cfg directories
    // -------------------------------------------------------------------------

    private async Task ScanCsgoCfgDirectoryPayloadsAsync(ScanContext ctx, CancellationToken ct)
    {
        var cfgDirSuffixes = new[]
        {
            @"game\csgo\cfg",
            @"csgo\cfg",
            @"cstrike\cfg",
        };

        var csgoBasePaths = new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive",
            @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike 2",
        };

        var executableExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".dll", ".exe", ".sys", ".bin"
        };

        var cfgPayloadPatterns = new[] { "loadlibrary", "inject", "shellcode", "payload" };

        foreach (var basePath in csgoBasePaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(basePath)) continue;

            foreach (var suffix in cfgDirSuffixes)
            {
                ct.ThrowIfCancellationRequested();
                var cfgDir = Path.Combine(basePath, suffix);
                if (!Directory.Exists(cfgDir)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(cfgDir, "*.*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(file);
                    var fileName = Path.GetFileName(file);

                    // Check for executable files hidden in cfg directory
                    if (executableExtensions.Contains(ext))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Executable File in CS2/CSGO cfg Directory: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Executable file '{fileName}' found in CS2/CSGO cfg directory — likely injector or cheat payload hidden in game config folder",
                            Detail = $"Found at: {file}",
                        });
                        continue;
                    }

                    // For .cfg files, check for injection-related content
                    if (!ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase)) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync();
                    }
                    catch (IOException)
                    {
                        continue;
                    }
                    catch (UnauthorizedAccessException)
                    {
                        continue;
                    }

                    foreach (var pattern in cfgPayloadPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Injection Payload Pattern in CS2/CSGO cfg: {pattern}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Config file in CS2/CSGO cfg directory contains '{pattern}' — indicates injector or shellcode payload in game configuration",
                                Detail = $"Pattern '{pattern}' found in: {file}",
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
}

// String extension helper for safe truncation
file static class StringExtensions
{
    public static string Truncate(this string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return value;
        return value.Length <= maxLength ? value : value[..maxLength];
    }
}
