using System.IO;
using System.Text;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class GameFileIntegrityScanModule : IScanModule
{
    public string Name => "Game-File-Integrity";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    private static readonly string[] GtaVStaticPaths =
    {
        @"C:\Program Files\Rockstar Games\Grand Theft Auto V",
        @"C:\Program Files (x86)\Rockstar Games\Grand Theft Auto V",
        @"D:\Rockstar Games\Grand Theft Auto V",
        @"D:\Grand Theft Auto V",
        @"C:\Games\Grand Theft Auto V",
        @"C:\Program Files\Epic Games\GTAV",
        @"E:\Rockstar Games\Grand Theft Auto V",
    };

    private static readonly string[] Cs2WeaponScriptCheatValues =
    {
        "recoil_variance 0", "spread_alt 0",
        "recoil_variance -1", "spread_alt -1",
        "recoil_variance-1", "spread_alt-1",
    };

    private static readonly string[] ValorWarningIniKeywords =
    {
        "bEnableAntiCheat=False", "VanguardEnabled=False",
        "bEnableAntiCheat=false", "vanguardenabled=false",
    };

    private static readonly HashSet<string> FiveMKnownGoodDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "FiveM.exe", "FiveM_b1604_GTAProcess.exe",
        "CitizenFX.Core.dll", "CoreRT.dll", "clrcompression.dll",
        "steam_api64.dll",
    };

    private static readonly HashSet<string> FiveMSuspiciousProxyDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "d3d11.dll", "dxgi.dll", "dinput8.dll", "version.dll", "winhttp.dll",
    };

    private static readonly HashSet<string> MinecraftCheatClientNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "hacked_client", "wurst", "meteor", "liquidbounce", "rusherhack",
        "aristois", "impact",
    };

    private static readonly string[] MinecraftCheatJarPatterns =
    {
        "wurst", "meteor", "liquidbounce", "rusherhack", "aristois",
        "impact", "xray", "blink", "killaura", "aimassist", "scaffold",
    };

    private static readonly string[] ReshadeDepthHackKeywords =
    {
        "depth < threshold", "depth <", "getdepth", "depthbuffer", "gbuffer_depth",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanCs2GameFileIntegrity(ctx, ct);
            ScanGtaVGameFileIntegrity(ctx, ct);
            ScanFiveMFileIntegrity(ctx, ct);
            ScanValorantFileIntegrity(ctx, ct);
            ScanMinecraftCheatClients(ctx, ct);
            ScanReshadeShaders(ctx, ct);
        }, ct);
    }

    private static void ScanCs2GameFileIntegrity(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var steamApps = FindSteamAppsPath();
        if (steamApps == null) return;

        var cs2GameBase = Path.Combine(steamApps, "common",
            "Counter-Strike Global Offensive", "game");
        if (!Directory.Exists(cs2GameBase)) return;

        ScanCs2ClientDllIntegrity(ctx, cs2GameBase, ct);
        ScanCs2MaterialsForCheatTextures(ctx, cs2GameBase, ct);
        ScanCs2WeaponScripts(ctx, cs2GameBase, ct);
        ScanCs2RadarHudFiles(ctx, cs2GameBase, ct);
        ScanCs2UnknownVpkFiles(ctx, cs2GameBase, ct);
    }

    private static void ScanCs2ClientDllIntegrity(ScanContext ctx, string cs2GameBase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var clientDll = Path.Combine(cs2GameBase, "bin", "win64", "client.dll");
        if (!File.Exists(clientDll)) return;

        ctx.IncrementFiles();
        long fileSize;
        try { fileSize = new FileInfo(clientDll).Length; }
        catch (IOException) { return; }

        const long minExpectedBytes = 10L * 1024 * 1024;
        const long maxExpectedBytes = 200L * 1024 * 1024;

        if (fileSize < minExpectedBytes || fileSize > maxExpectedBytes)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = "CS2 client.dll has anomalous file size",
                Risk = RiskLevel.High,
                Location = clientDll,
                FileName = "client.dll",
                Reason = $"CS2 client.dll file size is {fileSize / (1024 * 1024)} MB, which is outside the expected range " +
                         "of 10–200 MB (legitimate file is 50–120 MB). " +
                         "A dramatically different size suggests the file was replaced or tampered with by a cheat modification.",
                Detail = $"Path={clientDll} SizeBytes={fileSize} SizeMB={fileSize / (1024 * 1024)}",
            });
        }
    }

    private static void ScanCs2MaterialsForCheatTextures(ScanContext ctx, string cs2GameBase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var materialsDir = Path.Combine(cs2GameBase, "csgo", "materials");
        if (!Directory.Exists(materialsDir)) return;

        var cheatTextureKeywords = new[] { "wireframe", "wallhack", "esp", "glow", "cheat" };

        string[] allEntries;
        try
        {
            allEntries = Directory.GetFileSystemEntries(materialsDir, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var entry in allEntries)
        {
            ct.ThrowIfCancellationRequested();
            var nameOnly = Path.GetFileName(entry).ToLowerInvariant();
            var matchedKeyword = cheatTextureKeywords.FirstOrDefault(k => nameOnly.Contains(k));
            if (matchedKeyword == null) continue;

            var isDir = Directory.Exists(entry);
            if (!isDir) ctx.IncrementFiles();

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"CS2 material with cheat texture name: {Path.GetFileName(entry)}",
                Risk = RiskLevel.High,
                Location = entry,
                FileName = isDir ? null : Path.GetFileName(entry),
                Reason = $"CS2 materials directory contains a {(isDir ? "subdirectory" : "file")} named '{Path.GetFileName(entry)}' " +
                         $"with cheat keyword '{matchedKeyword}'. " +
                         "Custom textures named wireframe/wallhack/esp/glow are used by visual cheats to see enemies through walls.",
                Detail = $"Path={entry} Keyword={matchedKeyword}",
            });
        }
    }

    private static void ScanCs2WeaponScripts(ScanContext ctx, string cs2GameBase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var scriptsDir = Path.Combine(cs2GameBase, "csgo", "scripts");
        if (!Directory.Exists(scriptsDir)) return;

        string[] weaponFiles;
        try
        {
            weaponFiles = Directory.GetFiles(scriptsDir, "*.txt", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var weaponFile in weaponFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(weaponFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = sr.ReadToEnd();
            }
            catch (IOException) { continue; }

            var lower = content.ToLowerInvariant();
            var matchedValues = Cs2WeaponScriptCheatValues
                .Where(v => lower.Contains(v.ToLowerInvariant()))
                .ToList();

            if (matchedValues.Count == 0) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"CS2 weapon script with zero recoil values: {Path.GetFileName(weaponFile)}",
                Risk = RiskLevel.Medium,
                Location = weaponFile,
                FileName = Path.GetFileName(weaponFile),
                Reason = $"CS2 weapon script '{Path.GetFileName(weaponFile)}' contains recoil/spread values of 0 or negative: " +
                         $"{string.Join(", ", matchedValues)}. " +
                         "These values eliminate weapon recoil or spread, providing an unfair accuracy advantage in CS2.",
                Detail = $"File={weaponFile} Values={string.Join("|", matchedValues)}",
            });
        }
    }

    private static void ScanCs2RadarHudFiles(ScanContext ctx, string cs2GameBase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var hudDir = Path.Combine(cs2GameBase, "csgo", "resource", "ui");
        if (!Directory.Exists(hudDir)) return;

        string[] hudFiles;
        try
        {
            hudFiles = Directory.GetFiles(hudDir, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var hudFile in hudFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fname = Path.GetFileName(hudFile).ToLowerInvariant();
            if (!fname.Contains("radar") && !fname.Contains("minimap") && !fname.Contains("hud")) continue;

            string content;
            try
            {
                using var fs = new FileStream(hudFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = sr.ReadToEnd();
            }
            catch (IOException) { continue; }

            var lower = content.ToLowerInvariant();
            if (!lower.Contains("wallhack") && !lower.Contains("esp") && !lower.Contains("radar_hack")) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"CS2 HUD/radar file with cheat keywords: {Path.GetFileName(hudFile)}",
                Risk = RiskLevel.High,
                Location = hudFile,
                FileName = Path.GetFileName(hudFile),
                Reason = $"CS2 HUD file '{Path.GetFileName(hudFile)}' contains radar hack or ESP keywords in its content. " +
                         "Modified HUD files can implement radar hacks that reveal all enemy positions on the minimap.",
                Detail = $"File={hudFile}",
            });
        }
    }

    private static void ScanCs2UnknownVpkFiles(ScanContext ctx, string cs2GameBase, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        string[] vpkFiles;
        try
        {
            vpkFiles = Directory.GetFiles(cs2GameBase, "*.vpk", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var vpkFile in vpkFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fname = Path.GetFileName(vpkFile).ToLowerInvariant();

            if (fname.Contains("pak01") || fname.Contains("client") ||
                fname.Contains("english") || fname.Contains("voice") ||
                fname.Contains("motd") || fname.Contains("texture")) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Unrecognized VPK file in CS2 game directory: {Path.GetFileName(vpkFile)}",
                Risk = RiskLevel.Medium,
                Location = vpkFile,
                FileName = Path.GetFileName(vpkFile),
                Reason = $"Unrecognized VPK package file '{Path.GetFileName(vpkFile)}' found in the CS2 game directory. " +
                         "Custom VPK files can inject modified textures, models, or scripts that provide visual cheating advantages.",
                Detail = $"File={vpkFile}",
            });
        }
    }

    private static void ScanGtaVGameFileIntegrity(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var gtaVDir = GtaVStaticPaths.FirstOrDefault(Directory.Exists);
        if (gtaVDir == null) return;

        ScanGtaVExecutable(ctx, gtaVDir, ct);
        ScanGtaVAsiFiles(ctx, gtaVDir, ct);
        ScanGtaVNonOfficialDlcPacks(ctx, gtaVDir, ct);
        ScanGtaVCoreRpfFiles(ctx, gtaVDir, ct);
    }

    private static void ScanGtaVExecutable(ScanContext ctx, string gtaVDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var gtaExe = Path.Combine(gtaVDir, "GTA5.exe");
        if (!File.Exists(gtaExe)) return;

        ctx.IncrementFiles();
        long fileSize;
        try { fileSize = new FileInfo(gtaExe).Length; }
        catch (IOException) { return; }

        const long minExpectedBytes = 50L * 1024 * 1024;
        const long maxExpectedBytes = 100L * 1024 * 1024;

        if (fileSize < minExpectedBytes || fileSize > maxExpectedBytes)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = "GTA5.exe has anomalous file size",
                Risk = RiskLevel.High,
                Location = gtaExe,
                FileName = "GTA5.exe",
                Reason = $"GTA5.exe file size is {fileSize / (1024 * 1024)} MB, outside the expected 50–100 MB range. " +
                         "A dramatically different executable size indicates the file may have been replaced or tampered with.",
                Detail = $"Path={gtaExe} SizeBytes={fileSize} SizeMB={fileSize / (1024 * 1024)}",
            });
        }
    }

    private static void ScanGtaVAsiFiles(ScanContext ctx, string gtaVDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        string[] asiFiles;
        try { asiFiles = Directory.GetFiles(gtaVDir, "*.asi", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var asiFile in asiFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"ASI file in GTA V directory: {Path.GetFileName(asiFile)}",
                Risk = RiskLevel.Medium,
                Location = asiFile,
                FileName = Path.GetFileName(asiFile),
                Reason = $"ASI plugin file '{Path.GetFileName(asiFile)}' found in the GTA V installation directory. " +
                         "ASI files are loaded by ScriptHookV to inject code into GTA V; mod menus and cheats frequently exploit this mechanism.",
                Detail = $"Path={asiFile}",
            });
        }
    }

    private static void ScanGtaVNonOfficialDlcPacks(ScanContext ctx, string gtaVDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var dlcPacksDir = Path.Combine(gtaVDir, "update", "x64", "dlcpacks");
        if (!Directory.Exists(dlcPacksDir)) return;

        var officialDlcNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "patchday1ng", "patchday2ng", "patchday3ng", "patchday4ng", "patchday5ng",
            "patchday6ng", "patchday7ng", "patchday8ng", "patchday9ng", "patchday10ng",
            "patchday11ng", "patchday12ng", "patchday13ng", "patchday14ng", "patchday15ng",
            "patchday16ng", "patchday17ng", "patchday18ng", "patchday19ng", "patchday20ng",
            "mpbeach", "mpbusiness", "mpbusiness2", "mphipster", "mpluxe", "mpluxe2",
            "mprealestate", "mpsecurity", "mpsport", "mplts", "mphalloween",
            "mpchristmas2", "mpvalentines", "mpindependence", "mppilot", "mpapartment",
            "mpjanuaray2016", "mpjanuary2016", "mplowrider", "mphalloween2", "mpexecutive",
            "mpstunt", "mpbiker", "mpimportexport", "mpspecialraces", "mpgunrunning",
            "mpsmuggler", "mpbattle", "mpchristmas2017", "mpassets", "mpheist3",
            "mpdlc_2019", "mpvinewood", "mphipster2", "mpsum", "mptuner",
            "mpcrimewv", "mpcayoperico", "mpg9ec", "mpheist4",
        };

        string[] dlcDirs;
        try { dlcDirs = Directory.GetDirectories(dlcPacksDir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var dlcDir in dlcDirs)
        {
            ct.ThrowIfCancellationRequested();
            var dlcName = Path.GetFileName(dlcDir);
            if (officialDlcNames.Contains(dlcName)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Non-official GTA V DLC pack: {dlcName}",
                Risk = RiskLevel.High,
                Location = dlcDir,
                Reason = $"Non-official DLC pack directory '{dlcName}' found in GTA V update\\x64\\dlcpacks\\. " +
                         "Custom DLC packs can inject modified game content, script hooks, or cheat functionality " +
                         "that loads automatically when GTA V or GTA Online starts.",
                Detail = $"Dir={dlcDir}",
            });
        }
    }

    private static void ScanGtaVCoreRpfFiles(ScanContext ctx, string gtaVDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var coreRpfNames = new[] { "common.rpf", "x64a.rpf", "x64b.rpf", "x64c.rpf", "x64d.rpf" };

        foreach (var rpfName in coreRpfNames)
        {
            ct.ThrowIfCancellationRequested();
            var rpfPath = Path.Combine(gtaVDir, rpfName);
            if (!File.Exists(rpfPath)) continue;

            ctx.IncrementFiles();
            long fileSize;
            try { fileSize = new FileInfo(rpfPath).Length; }
            catch (IOException) { continue; }

            const long minRpfBytes = 100L * 1024 * 1024;
            if (fileSize >= minRpfBytes) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"GTA V core RPF is suspiciously small: {rpfName}",
                Risk = RiskLevel.High,
                Location = rpfPath,
                FileName = rpfName,
                Reason = $"GTA V core RPF archive '{rpfName}' is only {fileSize / (1024 * 1024)} MB, " +
                         "below the 100 MB minimum expected for a core game archive. " +
                         "This may indicate the file was replaced with a modified or stripped version by a cheat tool.",
                Detail = $"Path={rpfPath} SizeBytes={fileSize} SizeMB={fileSize / (1024 * 1024)}",
            });
        }
    }

    private static void ScanFiveMFileIntegrity(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var fiveMAppDir = Path.Combine(localAppData, "FiveM", "FiveM.app");
        if (!Directory.Exists(fiveMAppDir)) return;

        ScanFiveMExecutableSize(ctx, fiveMAppDir, ct);
        ScanFiveMCriticalDlls(ctx, fiveMAppDir, ct);
        ScanFiveMCoreDlls(ctx, fiveMAppDir, ct);
        ScanFiveMExtraDlls(ctx, fiveMAppDir, ct);
    }

    private static void ScanFiveMExecutableSize(ScanContext ctx, string fiveMAppDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var fiveMExe = Path.Combine(fiveMAppDir, "FiveM.exe");
        if (!File.Exists(fiveMExe)) return;

        ctx.IncrementFiles();
        long fileSize;
        try { fileSize = new FileInfo(fiveMExe).Length; }
        catch (IOException) { return; }

        const long minExpectedBytes = 5L * 1024 * 1024;
        const long maxExpectedBytes = 500L * 1024 * 1024;

        if (fileSize < minExpectedBytes || fileSize > maxExpectedBytes)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = "FiveM.exe has anomalous file size",
                Risk = RiskLevel.High,
                Location = fiveMExe,
                FileName = "FiveM.exe",
                Reason = $"FiveM.exe is {fileSize / (1024 * 1024)} MB, outside the expected range of 5–500 MB. " +
                         "An anomalous executable size may indicate tampering by a FiveM bypass or cheat loader.",
                Detail = $"Path={fiveMExe} SizeBytes={fileSize} SizeMB={fileSize / (1024 * 1024)}",
            });
        }
    }

    private static void ScanFiveMCriticalDlls(ScanContext ctx, string fiveMAppDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var citizenFxDll = Path.Combine(fiveMAppDir, "CitizenFX.Core.dll");
        if (!File.Exists(citizenFxDll)) return;

        ctx.IncrementFiles();
        long fileSize;
        try { fileSize = new FileInfo(citizenFxDll).Length; }
        catch (IOException) { return; }

        const long minExpectedBytes = 500L * 1024;

        if (fileSize >= minExpectedBytes) return;

        ctx.AddFinding(new Finding
        {
            Module = "Game-File-Integrity",
            Title = "FiveM CitizenFX.Core.dll is suspiciously small",
            Risk = RiskLevel.High,
            Location = citizenFxDll,
            FileName = "CitizenFX.Core.dll",
            Reason = $"FiveM's CitizenFX.Core.dll is only {fileSize / 1024} KB, below the expected minimum of 500 KB. " +
                     "The legitimate file is 1–3 MB; a stripped replacement may indicate anti-cheat bypass tampering.",
            Detail = $"Path={citizenFxDll} SizeBytes={fileSize} MinExpected=512000",
        });
    }

    private static void ScanFiveMCoreDlls(ScanContext ctx, string fiveMAppDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var coreDllNames = new[] { "CoreRT.dll", "clrcompression.dll" };

        foreach (var dllName in coreDllNames)
        {
            ct.ThrowIfCancellationRequested();

            string[] foundFiles;
            try
            {
                foundFiles = Directory.GetFiles(fiveMAppDir, dllName, SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dllPath in foundFiles)
            {
                ctx.IncrementFiles();
                long fileSize;
                try { fileSize = new FileInfo(dllPath).Length; }
                catch (IOException) { continue; }

                if (fileSize >= 50 * 1024) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Game-File-Integrity",
                    Title = $"FiveM runtime DLL has anomalous size: {dllName}",
                    Risk = RiskLevel.High,
                    Location = dllPath,
                    FileName = dllName,
                    Reason = $"FiveM runtime DLL '{dllName}' is only {fileSize / 1024} KB, far below its expected size. " +
                             "Cheats sometimes replace runtime DLLs with proxy versions to intercept FiveM's .NET runtime calls.",
                    Detail = $"Path={dllPath} SizeBytes={fileSize}",
                });
            }
        }
    }

    private static void ScanFiveMExtraDlls(ScanContext ctx, string fiveMAppDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        string[] rootDlls;
        try
        {
            rootDlls = Directory.GetFiles(fiveMAppDir, "*.dll", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var dllFile in rootDlls)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fname = Path.GetFileName(dllFile);

            if (FiveMKnownGoodDlls.Contains(fname)) continue;

            var isSuspiciousProxy = FiveMSuspiciousProxyDlls.Contains(fname);
            var risk = isSuspiciousProxy ? RiskLevel.High : RiskLevel.Medium;
            var reason = isSuspiciousProxy
                ? $"Known proxy injection DLL '{fname}' found in FiveM.app root. " +
                  "Proxy DLLs like dinput8.dll, dxgi.dll, and winhttp.dll are used to inject cheat code into FiveM at startup."
                : $"Unrecognized DLL '{fname}' found in FiveM.app root directory. " +
                  "Extra DLLs in the FiveM application directory may be injection payloads or hook libraries placed by a cheat.";

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Extra DLL in FiveM.app root: {fname}",
                Risk = risk,
                Location = dllFile,
                FileName = fname,
                Reason = reason,
                Detail = $"Path={dllFile} IsKnownProxy={isSuspiciousProxy}",
            });
        }
    }

    private static void ScanValorantFileIntegrity(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var valorantLive = Path.Combine(localAppData, "Riot Games", "VALORANT", "live");
        if (!Directory.Exists(valorantLive)) return;

        ScanValorantExecutable(ctx, valorantLive, ct);
        ScanValorantBinaries(ctx, valorantLive, ct);
        ScanValorantPakFiles(ctx, valorantLive, ct);
        ScanValorantIniFiles(ctx, valorantLive, ct);
    }

    private static void ScanValorantExecutable(ScanContext ctx, string valorantLive, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var valorantExe = Path.Combine(valorantLive, "VALORANT.exe");
        if (!File.Exists(valorantExe)) return;

        ctx.IncrementFiles();
        long fileSize;
        try { fileSize = new FileInfo(valorantExe).Length; }
        catch (IOException) { return; }

        const long minExpectedBytes = 50L * 1024 * 1024;
        const long maxExpectedBytes = 500L * 1024 * 1024;

        if (fileSize < minExpectedBytes || fileSize > maxExpectedBytes)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = "VALORANT.exe has anomalous file size",
                Risk = RiskLevel.High,
                Location = valorantExe,
                FileName = "VALORANT.exe",
                Reason = $"VALORANT.exe is {fileSize / (1024 * 1024)} MB, outside the expected range of 50–500 MB. " +
                         "This may indicate the executable was replaced or tampered with to bypass Vanguard anti-cheat.",
                Detail = $"Path={valorantExe} SizeBytes={fileSize} SizeMB={fileSize / (1024 * 1024)}",
            });
        }
    }

    private static void ScanValorantBinaries(ScanContext ctx, string valorantLive, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var win64BinDir = Path.Combine(valorantLive, "ShooterGame", "Binaries", "Win64");
        if (!Directory.Exists(win64BinDir)) return;

        string[] dllFiles;
        try { dllFiles = Directory.GetFiles(win64BinDir, "*.dll", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        var expectedDllPatterns = new[] { "valorant", "shootergame", "unrealcef", "chromium", "riot", "vanguard" };

        foreach (var dllFile in dllFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fname = Path.GetFileName(dllFile);
            var fnameLower = fname.ToLowerInvariant();

            if (expectedDllPatterns.Any(p => fnameLower.Contains(p))) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Extra DLL in VALORANT Win64 binaries: {fname}",
                Risk = RiskLevel.High,
                Location = dllFile,
                FileName = fname,
                Reason = $"Unrecognized DLL '{fname}' found in VALORANT\\ShooterGame\\Binaries\\Win64\\. " +
                         "VALORANT's Vanguard anti-cheat should prevent unauthorized DLLs here; " +
                         "finding one indicates Vanguard was bypassed or disabled.",
                Detail = $"Path={dllFile}",
            });
        }
    }

    private static void ScanValorantPakFiles(ScanContext ctx, string valorantLive, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var paksDir = Path.Combine(valorantLive, "ShooterGame", "Content", "Paks");
        if (!Directory.Exists(paksDir)) return;

        string[] pakFiles;
        try { pakFiles = Directory.GetFiles(paksDir, "*.pak", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var pakFile in pakFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fname = Path.GetFileName(pakFile);
            var fnameLower = fname.ToLowerInvariant();

            if (fnameLower.StartsWith("shootergame-", StringComparison.OrdinalIgnoreCase) ||
                fnameLower.StartsWith("valorant-", StringComparison.OrdinalIgnoreCase)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Extra PAK file in VALORANT content: {fname}",
                Risk = RiskLevel.High,
                Location = pakFile,
                FileName = fname,
                Reason = $"Extra PAK content file '{fname}' found in VALORANT's Paks directory. " +
                         "VALORANT does not support user mods; extra PAK files indicate custom content injection " +
                         "which can provide visual advantages or attempt to bypass anti-cheat detection.",
                Detail = $"Path={pakFile}",
            });
        }
    }

    private static void ScanValorantIniFiles(ScanContext ctx, string valorantLive, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var configDir = Path.Combine(valorantLive, "ShooterGame", "Saved", "Config", "WindowsNoEditor");
        if (!Directory.Exists(configDir)) return;

        string[] iniFiles;
        try { iniFiles = Directory.GetFiles(configDir, "*.ini", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var iniFile in iniFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(iniFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = sr.ReadToEnd();
            }
            catch (IOException) { continue; }

            var lower = content.ToLowerInvariant();
            var matchedKeywords = ValorWarningIniKeywords
                .Where(k => lower.Contains(k.ToLowerInvariant()))
                .ToList();

            if (matchedKeywords.Count == 0) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"VALORANT config with anti-cheat disabled: {Path.GetFileName(iniFile)}",
                Risk = RiskLevel.Medium,
                Location = iniFile,
                FileName = Path.GetFileName(iniFile),
                Reason = $"VALORANT config file '{Path.GetFileName(iniFile)}' contains anti-cheat disabling flags: " +
                         $"{string.Join(", ", matchedKeywords)}. " +
                         "These settings can disable or bypass Vanguard anti-cheat protection.",
                Detail = $"File={iniFile} Keywords={string.Join("|", matchedKeywords)}",
            });
        }
    }

    private static void ScanMinecraftCheatClients(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var minecraftDir = Path.Combine(appData, ".minecraft");
        if (!Directory.Exists(minecraftDir)) return;

        ScanMinecraftVersions(ctx, minecraftDir, ct);
        ScanMinecraftMods(ctx, minecraftDir, ct);
        ScanMinecraftCheatConfigs(ctx, minecraftDir, ct);
        ScanJavaCheatProcesses(ctx, ct);
    }

    private static void ScanMinecraftVersions(ScanContext ctx, string minecraftDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var versionsDir = Path.Combine(minecraftDir, "versions");
        if (!Directory.Exists(versionsDir)) return;

        string[] versionDirs;
        try { versionDirs = Directory.GetDirectories(versionsDir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var versionDir in versionDirs)
        {
            ct.ThrowIfCancellationRequested();
            var versionName = Path.GetFileName(versionDir).ToLowerInvariant();

            var matchedClient = MinecraftCheatClientNames
                .FirstOrDefault(c => versionName.Contains(c.ToLowerInvariant()));
            if (matchedClient == null) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Minecraft cheat client version installed: {Path.GetFileName(versionDir)}",
                Risk = RiskLevel.Critical,
                Location = versionDir,
                Reason = $"Minecraft versions directory contains a cheat client version '{Path.GetFileName(versionDir)}' " +
                         $"matching known cheat client name '{matchedClient}'. " +
                         "These are complete Minecraft cheat clients providing aimbot, ESP, X-ray, killaura, and other features.",
                Detail = $"Dir={versionDir} CheatClient={matchedClient}",
            });
        }
    }

    private static void ScanMinecraftMods(ScanContext ctx, string minecraftDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var modsDir = Path.Combine(minecraftDir, "mods");
        if (!Directory.Exists(modsDir)) return;

        string[] jarFiles;
        try { jarFiles = Directory.GetFiles(modsDir, "*.jar", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var jarFile in jarFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fname = Path.GetFileName(jarFile).ToLowerInvariant();

            var matchedPattern = MinecraftCheatJarPatterns
                .FirstOrDefault(p => fname.Contains(p.ToLowerInvariant()));
            if (matchedPattern == null) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Minecraft cheat mod JAR: {Path.GetFileName(jarFile)}",
                Risk = RiskLevel.Critical,
                Location = jarFile,
                FileName = Path.GetFileName(jarFile),
                Reason = $"Minecraft mod file '{Path.GetFileName(jarFile)}' matches known cheat mod pattern '{matchedPattern}'. " +
                         "This is a recognized Minecraft cheat mod providing X-ray, killaura, aimassist, scaffold, or other unfair advantages.",
                Detail = $"File={jarFile} Pattern={matchedPattern}",
            });
        }
    }

    private static void ScanMinecraftCheatConfigs(ScanContext ctx, string minecraftDir, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var configDir = Path.Combine(minecraftDir, "config");
        if (!Directory.Exists(configDir)) return;

        string[] configSubDirs;
        try { configSubDirs = Directory.GetDirectories(configDir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var subDir in configSubDirs)
        {
            ct.ThrowIfCancellationRequested();
            var subDirName = Path.GetFileName(subDir).ToLowerInvariant();

            var matchedClient = MinecraftCheatClientNames
                .FirstOrDefault(c => subDirName.Contains(c.ToLowerInvariant()));
            if (matchedClient == null) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Minecraft cheat client config directory: {Path.GetFileName(subDir)}",
                Risk = RiskLevel.High,
                Location = subDir,
                Reason = $"Minecraft config directory contains a subdirectory for known cheat client '{matchedClient}'. " +
                         "Config directories for cheat clients confirm the cheat was installed and previously run.",
                Detail = $"Dir={subDir} CheatClient={matchedClient}",
            });
        }
    }

    private static void ScanJavaCheatProcesses(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var snapshot = ctx.GetProcessSnapshot();

        foreach (var proc in snapshot)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            var procName = proc.ProcessName.ToLowerInvariant();
            if (procName != "java" && procName != "javaw") continue;

            string procPath;
            try { procPath = proc.MainModule?.FileName ?? string.Empty; }
            catch { procPath = string.Empty; }

            var pathLower = procPath.ToLowerInvariant();
            var matchedCheat = MinecraftCheatJarPatterns
                .FirstOrDefault(p => pathLower.Contains(p.ToLowerInvariant()));
            if (matchedCheat == null) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Minecraft cheat client actively running in Java: {matchedCheat}",
                Risk = RiskLevel.Critical,
                Location = procPath.Length > 0 ? procPath : $"PID {proc.Id}",
                FileName = proc.ProcessName,
                Reason = $"Java process (PID {proc.Id}) is running with a path referencing Minecraft cheat client '{matchedCheat}'. " +
                         "This indicates the cheat client is actively being used.",
                Detail = $"PID={proc.Id} ProcessName={proc.ProcessName} Path={procPath} Cheat={matchedCheat}",
            });
        }
    }

    private static void ScanReshadeShaders(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var reshadeShaderDirs = new[]
        {
            Path.Combine(appData, "ReShade", "Shaders"),
            Path.Combine(localAppData, "ReShade", "Shaders"),
        };

        foreach (var shaderDir in reshadeShaderDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(shaderDir)) continue;

            string[] fxFiles;
            try { fxFiles = Directory.GetFiles(shaderDir, "*.fx", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var fxFile in fxFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                AnalyzeReshadeShader(ctx, fxFile, ct);
            }
        }

        ScanGameLocalReshadeShaders(ctx, ct);
    }

    private static void AnalyzeReshadeShader(ScanContext ctx, string fxFile, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var fname = Path.GetFileName(fxFile);

        long fileSize;
        try { fileSize = new FileInfo(fxFile).Length; }
        catch (IOException) { return; }

        if (fileSize > 500L * 1024)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"Unusually large ReShade shader: {fname}",
                Risk = RiskLevel.Medium,
                Location = fxFile,
                FileName = fname,
                Reason = $"ReShade shader '{fname}' is {fileSize / 1024} KB, exceeding the 500 KB threshold for typical shaders. " +
                         "Unusually large shaders may contain complex cheat rendering logic for ESP, wallhack, or radar overlays.",
                Detail = $"File={fxFile} SizeKB={fileSize / 1024}",
            });
        }

        string content;
        try
        {
            using var fs = new FileStream(fxFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = sr.ReadToEnd();
        }
        catch (IOException) { return; }

        var lower = content.ToLowerInvariant();
        var hasTex2D = lower.Contains("tex2d");
        var hasDepth = ReshadeDepthHackKeywords.Any(k => lower.Contains(k.ToLowerInvariant()));
        var hasDiscard = lower.Contains("discard");
        var hasVsOutput = lower.Contains("vs_output") || lower.Contains("vs_out");

        if (hasTex2D && hasDepth && hasDiscard)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"ReShade depth-based wallhack shader pattern: {fname}",
                Risk = RiskLevel.Medium,
                Location = fxFile,
                FileName = fname,
                Reason = $"ReShade shader '{fname}' contains the depth-based wallhack pattern: " +
                         "tex2D sampling combined with depth buffer reading and a conditional discard statement. " +
                         "This pattern renders objects through walls by discarding pixels based on depth comparison.",
                Detail = $"File={fxFile} tex2D={hasTex2D} DepthRead={hasDepth} Discard={hasDiscard}",
            });
        }

        if (hasVsOutput && lower.Contains(".pos") && lower.Contains("esp"))
        {
            ctx.AddFinding(new Finding
            {
                Module = "Game-File-Integrity",
                Title = $"ReShade shader with ESP position injection: {fname}",
                Risk = RiskLevel.Medium,
                Location = fxFile,
                FileName = fname,
                Reason = $"ReShade shader '{fname}' contains VS_OUTPUT.pos manipulation combined with 'esp' keyword. " +
                         "This pattern is used by ESP shaders that inject player position rendering into the graphics pipeline.",
                Detail = $"File={fxFile} VSOutput={hasVsOutput}",
            });
        }
    }

    private static void ScanGameLocalReshadeShaders(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var steamApps = FindSteamAppsPath();
        if (steamApps == null) return;

        var commonDir = Path.Combine(steamApps, "common");
        if (!Directory.Exists(commonDir)) return;

        string[] gameDirs;
        try { gameDirs = Directory.GetDirectories(commonDir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var gameDir in gameDirs)
        {
            ct.ThrowIfCancellationRequested();
            var reshadeShaderDir = Path.Combine(gameDir, "reshade-shaders");
            if (!Directory.Exists(reshadeShaderDir)) continue;

            string[] fxFiles;
            try { fxFiles = Directory.GetFiles(reshadeShaderDir, "*.fx", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var fxFile in fxFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                AnalyzeReshadeShader(ctx, fxFile, ct);
            }
        }
    }

    private static string? FindSteamAppsPath()
    {
        try
        {
            using var steamKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam");
            var steamPath = steamKey?.GetValue("SteamPath") as string;
            if (!string.IsNullOrEmpty(steamPath))
            {
                var candidate = Path.Combine(steamPath, "steamapps");
                if (Directory.Exists(candidate)) return candidate;
            }
        }
        catch { }

        var fallbackPaths = new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps",
            @"C:\Program Files\Steam\steamapps",
            @"D:\Steam\steamapps",
            @"D:\SteamLibrary\steamapps",
            @"E:\Steam\steamapps",
        };

        return fallbackPaths.FirstOrDefault(Directory.Exists);
    }
}
