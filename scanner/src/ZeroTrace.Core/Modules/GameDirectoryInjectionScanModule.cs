using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans game installation directories for DLL proxy injection files.
///
/// One of the most common cheat injection techniques is placing a proxy DLL
/// with the same name as a legitimate Windows/DirectX DLL in the game directory.
/// Windows loads the local DLL first (DLL search order), so the cheat DLL is
/// loaded before the real system DLL.
///
/// Common proxy DLL names used for injection:
///   - version.dll   — most common; loaded by virtually every game (DirectX, Steam)
///   - dinput8.dll   — DirectInput 8; loaded by most games for controller support
///   - d3d9.dll      — Direct3D 9; loaded by DX9 games
///   - d3d11.dll     — Direct3D 11
///   - d3d12.dll     — Direct3D 12
///   - dxgi.dll      — DXGI swap chain; loaded by all DirectX games
///   - dsound.dll    — DirectSound; loaded by many older games
///   - winmm.dll     — Windows Multimedia; loaded by many games
///   - xinput1_3.dll — XInput; loaded by controller-using games
///   - opengl32.dll  — OpenGL games
///   - d3dcompiler_47.dll — Shader compiler; loaded by many modern games
///
/// These proxy DLLs:
///   1. Load the real system DLL and forward all exports to it (transparent proxy)
///   2. Execute their own payload (cheat injection, trainer, overlay)
///   3. Are often digitally unsigned or have stolen/expired signatures
///
/// Detection:
///   1. Enumerate Steam game installation directories from registry
///   2. For each game, check for known proxy DLL names in the root directory
///   3. Compare against known-good game files (vendor, size, signature)
/// </summary>
public sealed class GameDirectoryInjectionScanModule : IScanModule
{
    private static readonly string _name = "Spielverzeichnis-DLL-Injektion";
    public string Name => _name;
    public double Weight => 1.1;
    public int ParallelGroup => 0;

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    // Proxy DLL names — if found in a game directory, likely injectors
    private static readonly HashSet<string> ProxyDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "version.dll", "dinput8.dll", "d3d9.dll", "d3d10.dll",
        "d3d11.dll", "d3d12.dll", "dxgi.dll", "dsound.dll",
        "winmm.dll", "opengl32.dll",
        "xinput1_3.dll", "xinput1_4.dll", "xinput9_1_0.dll",
        "d3dcompiler_43.dll", "d3dcompiler_46.dll", "d3dcompiler_47.dll",
        "d3dx9_43.dll",
        "steam_api.dll", "steam_api64.dll",      // Steam API spoofs
        "tier0.dll", "vstdlib.dll",              // Source engine DLLs
        "msacm32.dll", "wbemprox.dll",
        "cryptbase.dll", "wldp.dll",
        "iphlpapi.dll", "comctl32.dll",
        "ws2_32.dll",
    };

    // DLLs that may legitimately appear in some game directories (reduce FP)
    private static readonly HashSet<string> AllowedInGameDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        // Redistributables that games bundle
        "d3d9.dll",     // Some games include their own DX9 runtime
        "steam_api.dll", "steam_api64.dll",  // Games bundle their Steam API
        "tier0.dll", "vstdlib.dll",          // Source engine games include these
        "d3dcompiler_47.dll",                // Many games bundle this
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook",
        "asi", "scripthook", "dinput", "proxy",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var gameDirs = FindGameDirectories();

        foreach (var gameDir in gameDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(gameDir)) continue;
            hits += await ScanGameDirectory(gameDir, ctx, ct).ConfigureAwait(false);
        }

        ctx.Report(1.0, Name, $"{gameDirs.Count} Spielverzeichnisse geprüft, {hits} verdächtige DLLs");
    }

    private static List<string> FindGameDirectories()
    {
        var dirs = new List<string>();

        // Steam library folders
        try
        {
            var steamInstalls = GetSteamLibraryPaths();
            foreach (var lib in steamInstalls)
            {
                var appsDir = Path.Combine(lib, "steamapps", "common");
                if (!Directory.Exists(appsDir)) continue;

                foreach (var gameDir in Directory.EnumerateDirectories(appsDir))
                    dirs.Add(gameDir);
            }
        }
        catch { }

        // Epic Games installs
        try
        {
            var epicManifestDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Epic", "EpicGamesLauncher", "Data", "Manifests");

            if (Directory.Exists(epicManifestDir))
            {
                foreach (var manifest in Directory.EnumerateFiles(epicManifestDir, "*.item"))
                {
                    try
                    {
                        var content = File.ReadAllText(manifest);
                        var match = System.Text.RegularExpressions.Regex.Match(
                            content, @"""InstallLocation""\s*:\s*""([^""]+)""");
                        if (match.Success && Directory.Exists(match.Groups[1].Value))
                            dirs.Add(match.Groups[1].Value);
                    }
                    catch { }
                }
            }
        }
        catch { }

        // Common game installation paths
        var commonPaths = new[]
        {
            @"C:\Program Files (x86)\Riot Games",
            @"C:\Riot Games",
            @"C:\Games",
            @"D:\Games",
        };
        foreach (var p in commonPaths)
        {
            if (Directory.Exists(p))
                dirs.AddRange(Directory.EnumerateDirectories(p));
        }

        return dirs;
    }

    private static List<string> GetSteamLibraryPaths()
    {
        var paths = new List<string>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Valve\Steam", writable: false)
                ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam", writable: false);

            var steamPath = key?.GetValue("InstallPath") as string;
            if (!string.IsNullOrEmpty(steamPath)) paths.Add(steamPath);

            // Read libraryfolders.vdf
            if (!string.IsNullOrEmpty(steamPath))
            {
                var vdf = Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
                if (File.Exists(vdf))
                {
                    var content = File.ReadAllText(vdf);
                    var matches = System.Text.RegularExpressions.Regex.Matches(
                        content, @"""path""\s+""([^""]+)""");
                    foreach (System.Text.RegularExpressions.Match m in matches)
                        paths.Add(m.Groups[1].Value);
                }
            }
        }
        catch { }
        return paths;
    }

    private static async Task<int> ScanGameDirectory(string gameDir,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var gameName = Path.GetFileName(gameDir);

        try
        {
            // Check first-level DLLs in game directory (proxy DLLs go here)
            foreach (var file in Directory.EnumerateFiles(gameDir, "*.dll",
                SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var fname = Path.GetFileName(file);
                if (!ProxyDllNames.Contains(fname)) continue;

                // If the DLL is in the allowlist, still check its signature
                var fi = new FileInfo(file);
                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    fname.ToLowerInvariant().Contains(k, StringComparison.OrdinalIgnoreCase));

                // Check if it's a legitimate bundled DLL by looking for its version info
                bool isSigned = await Task.Run(() => CheckIsSigned(file), ct);
                bool isKnownAllowed = AllowedInGameDirs.Contains(fname) && isSigned;

                if (isKnownAllowed && cheatKw is null) continue;

                string? sha256 = null;
                try { sha256 = Util.HashUtil.ComputeSha256(file); } catch { }

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = $"Proxy-DLL in Spielverzeichnis: {fname} ({gameName})",
                    Risk     = cheatKw is not null || !isSigned ? RiskLevel.Critical : RiskLevel.High,
                    Location = file,
                    FileName = fname,
                    Sha256   = sha256,
                    Reason   = $"DLL '{fname}' im Spielverzeichnis '{gameName}' gefunden. " +
                               "Diese DLL wird normalerweise aus System32 geladen. " +
                               "Eine Kopie im Spielverzeichnis wird zuerst geladen (DLL-Suchreihenfolge) " +
                               "und ist eine klassische Cheat-Injektionsmethode (Proxy-DLL). " +
                               (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                               (!isSigned ? "DLL ist nicht authentifiziert signiert. " : "") +
                               $"Dateigröße: {fi.Length} Bytes.",
                    Detail   = $"Datei: {file} | Signiert: {isSigned} | Keyword: {cheatKw ?? "keins"}" +
                               (sha256 is not null ? $" | SHA256: {sha256[..16]}..." : "")
                });
            }
        }
        catch { }
        return hits;
    }

    private static bool CheckIsSigned(string filePath)
    {
        try
        {
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
            return cert is not null;
        }
        catch { return false; }
    }
}
