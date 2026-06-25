using System.Security.Cryptography;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Comprehensive scan of known cheat tool installation directories and file artifacts.
/// Checks standard installation paths (Desktop, Documents, AppData, ProgramData, Temp)
/// for cheat tool folder names, DLL files, configuration files, and known cheat tool
/// executables. Also scans for remnant artifacts left after deletion (empty directories
/// with cheat names, config files, log files). This module is specifically tuned to
/// detect the most common external cheats: Kiddion's Modest Menu, 2Take1, Cherax,
/// Menyoo, Skeet.cc, Aimware, Fatality, Neverlose, and DMA-based tools.
/// </summary>
public sealed class CheatToolFileArtifactScanModule : IScanModule
{
    public string Name => "Cheat Tool File Artifacts";
    public double Weight => 0.85;
    public int ParallelGroup => 4;

    private static readonly string[] CheatFolderNames =
    {
        // GTA V cheats
        "kiddion", "kiddions", "modest_menu", "2take1", "cherax", "menyoo",
        "stand", "lunar", "ozark", "force", "executor_gta", "gtav_cheat",
        // CS2/CSGO cheats
        "skeet", "aimware", "fatality", "neverlose", "gamesense", "lucid",
        "onetap", "supremacy", "legitbot", "cs2cheat", "csgo_hack",
        "hvh_cheat", "rage_cheat", "legit_cheat", "silentaim",
        // Apex Legends cheats
        "apexhack", "apex_cheat", "r5apex_cheat", "apexaimbot",
        // Warzone/CoD cheats
        "warzone_cheat", "wzhack", "codcheat",
        // EFT cheats
        "eftcheat", "eftaimbot", "tarkov_cheat", "escape_from_tarkov_hack",
        // DMA tools
        "memprocfs", "pcileech", "dmalib", "dma_cheat", "dma_esp",
        "leechcore", "fpga_cheat",
        // Generic
        "cheat_loader", "injector", "cheat_menu", "esp_hack", "wallhack",
        "aimbot_tool", "triggerbot", "bhop_script", "spoofer",
        "hwid_spoofer", "ban_bypass", "vac_bypass", "eac_bypass", "be_bypass",
        "anticheat_bypass", "fakelag", "bunnyhop",
        // Common packer/loader names used by cheats
        "cheatengine-x86_64", // installed Cheat Engine
        "processhacker",      // Process Hacker used by cheaters
        "extremeinjector",    // popular DLL injector
        "xenos",              // Xenos injector
        "manualmap",          // manual map injectors
        "unknowncheats",      // UC-distributed tools
    };

    private static readonly string[] CheatFileNames =
    {
        // Cheat DLLs
        "cheat.dll", "hack.dll", "esp.dll", "aimbot.dll", "wallhack.dll",
        "triggerbot.dll", "silentaim.dll", "bhop.dll", "norecoil.dll",
        "skeet.dll", "aimware.dll", "fatality.dll", "neverlose.dll",
        "onetap.dll", "gamesense.dll", "hvh.dll",
        // Injectors
        "injector.exe", "inject.exe", "loader.exe", "cheat_loader.exe",
        "extremeinjector.exe", "xenos.exe", "xenos64.exe",
        "ghostinjector.exe", "nemesis.exe",
        // GTA V specific
        "kiddion.exe", "kiddions.exe", "modest_menu.exe",
        "2take1.exe", "cherax.exe", "menyoo.exe", "menyoopc.asi",
        // DMA tools
        "memprocfs.exe", "pcileech.exe", "leechcore.dll", "vmm.dll",
        "vmmdll.dll", "fpgamodule.dll",
        // BYOVD drivers
        "mhyprot2.sys", "dbutil_2_3.sys", "gdrv.sys", "capcom.sys",
        "rtcore64.sys", "speedfan.sys", "physmem.sys", "winring0x64.sys",
        "asrdrv10.sys", "ene.sys", "hwinfo64a.sys",
        // Config/log files
        "cheat.cfg", "aimbot.cfg", "esp.cfg", "hack.ini", "cheat.json",
        "bypass.dll", "bypass.cfg", "spoofer.exe", "hwid_changer.exe",
        // Screenshot/recording artifacts from cheat use
        "noclip.log", "aimbot.log", "esp.log", "cheat.log",
    };

    private static readonly string[] SuspiciousExtensions =
    {
        ".asi",   // ASI loader scripts (used for GTA modding and cheating)
        ".luac",  // compiled Lua (cheat scripts)
    };

    // Known cheat configuration file content markers
    private static readonly string[] ConfigKeywords =
    {
        "aimbot", "wallhack", "esp_enabled", "triggerbot", "bhop",
        "silent_aim", "norecoil", "fov_hack", "radar_hack",
        "license_key", "hwid_bypass", "auth_key",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = GetSearchRoots();

        await Task.Run(() =>
        {
            foreach (var root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                try { ScanDirectory(root, ctx, ct, depth: 0); }
                catch { /* skip inaccessible */ }
            }
        }, ct);
    }

    private void ScanDirectory(string path, ScanContext ctx, CancellationToken ct, int depth)
    {
        if (depth > 4) return;
        if (!Directory.Exists(path)) return;

        ct.ThrowIfCancellationRequested();
        ctx.IncrementFiles();

        // Check directory name
        string dirName = Path.GetFileName(path).ToLowerInvariant();
        bool isDirCheat = CheatFolderNames.Any(cn => dirName.Contains(cn));
        if (isDirCheat)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Cheat Tool File Artifacts",
                Title = $"Cheat-Tool Verzeichnis gefunden: {Path.GetFileName(path)}",
                Risk = RiskLevel.High,
                Location = path,
                Reason = $"Verzeichnis '{Path.GetFileName(path)}' entspricht bekanntem Cheat-Tool Ordner-Muster",
                Detail = $"Pfad: {path} — bekannte Cheat-Tool Installation oder Ueberreste"
            });
        }

        // Enumerate files in this directory
        try
        {
            foreach (var file in Directory.EnumerateFiles(path))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                CheckFile(file, ctx);
            }
        }
        catch { }

        // Recurse into subdirectories
        try
        {
            foreach (var subDir in Directory.EnumerateDirectories(path))
            {
                ct.ThrowIfCancellationRequested();
                ScanDirectory(subDir, ctx, ct, depth + 1);
            }
        }
        catch { }
    }

    private static void CheckFile(string filePath, ScanContext ctx)
    {
        string fileName = Path.GetFileName(filePath).ToLowerInvariant();
        string ext      = Path.GetExtension(filePath).ToLowerInvariant();

        // Check exact filename match
        bool isCheatFile = CheatFileNames.Any(cf =>
            cf.Equals(fileName, StringComparison.OrdinalIgnoreCase));

        if (isCheatFile)
        {
            string sha256 = TryComputeHash(filePath);
            ctx.AddFinding(new Finding
            {
                Module = "Cheat Tool File Artifacts",
                Title = $"Bekannte Cheat-Datei: {fileName}",
                Risk = fileName.EndsWith(".sys") ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Sha256 = sha256,
                Reason = $"Datei '{fileName}' entspricht bekanntem Cheat-Tool, Injector oder BYOVD-Treiber",
                Detail = $"Pfad: {filePath}{(sha256 != null ? $" | SHA-256: {sha256}" : "")}"
            });
            return;
        }

        // Check suspicious extensions (ASI, compiled Lua)
        if (ext == ".asi")
        {
            string sha256 = TryComputeHash(filePath);
            ctx.AddFinding(new Finding
            {
                Module = "Cheat Tool File Artifacts",
                Title = $"ASI-Datei gefunden: {fileName}",
                Risk = RiskLevel.Medium,
                Location = filePath,
                FileName = fileName,
                Sha256 = sha256,
                Reason = "ASI-Dateien werden von ASI-Loadern (dsound.dll, dinput8.dll) geladen " +
                         "und haeufig fuer GTA V / Spielmodifikationen und Cheats verwendet",
                Detail = $"Pfad: {filePath}"
            });
            return;
        }

        // Check config files for cheat keywords (small files only)
        if ((ext == ".cfg" || ext == ".ini" || ext == ".json") && fileName.Length < 100)
        {
            try
            {
                long fileSize = new FileInfo(filePath).Length;
                if (fileSize < 50 * 1024) // only small config files
                {
                    string content = File.ReadAllText(filePath);
                    var matches = ConfigKeywords
                        .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matches.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat Tool File Artifacts",
                            Title = $"Cheat-Konfigurationsdatei: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"Konfigurationsdatei enthaelt {matches.Count} Cheat-Schluesselwoerter",
                            Detail = $"Schluesselwoerter: {string.Join(", ", matches)} | Datei: {filePath}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private static string? TryComputeHash(string path)
    {
        try
        {
            using var fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length > 200L * 1024 * 1024) return null;
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(fs);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch { return null; }
    }

    private static List<string> GetSearchRoots()
    {
        var roots = new List<string>();
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData= Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string desktop     = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string documents   = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        string downloads   = Path.Combine(userProfile, "Downloads");
        string temp        = Path.GetTempPath();
        string publicDesk  = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);

        // Also scan program data and common tool install locations
        string progData  = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        foreach (var root in new[] {
            desktop, publicDesk, downloads, documents,
            temp,
            Path.Combine(localAppData, "Temp"),
            appData, localAppData,
            Path.Combine(progData, "cheat"),  // intentional test path
            progFiles, progFiles86
        })
        {
            if (!string.IsNullOrEmpty(root) && Directory.Exists(root))
                roots.Add(root);
        }

        // Game-specific additional locations
        var gameRoots = new[]
        {
            Path.Combine(progFiles, "Steam", "steamapps", "common"),
            Path.Combine(progFiles86, "Steam", "steamapps", "common"),
            Path.Combine(localAppData, "Packages"), // UWP store games
        };
        foreach (var gr in gameRoots)
        {
            if (!string.IsNullOrEmpty(gr) && Directory.Exists(gr))
                roots.Add(gr);
        }

        return roots;
    }
}
