using ZeroTrace.Core.Models;
using System.Text;
using System.Text.RegularExpressions;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects cheat license key, keygen, and activation artifacts across multiple
/// forensic sources.
///
/// Cheat vendors distribute software via:
///   1. License keys (UUID-format, alphanumeric, hardware-bound): stored in
///      .lic / .token / .key files OR encoded in config JSON/INI files
///   2. HWID-bound activation: key is paired to hardware fingerprint at activation
///      time — cheaters use HWID spoofers to activate on multiple machines
///   3. Loader executables that fetch and cache license tokens locally
///   4. Browser-stored credentials (autofill for cheat shop logins)
///   5. Discord DMs / Telegram messages containing purchased key strings
///
/// Key file formats used by known cheat vendors:
///   - Gamesense: hwid_token.json (JSON with token + hwid hash)
///   - OT (Onetap): license.lic (plain UUID)
///   - Fatality: auth.json / auth.dat
///   - Aimware: aw_token.dat
///   - Neverlose: nl_auth.json
///   - Kiddion: modest_menu/settings.json (GTA V menu — no explicit license but
///     "auth_key" field)
///   - 2Take1: 2t1_auth.token
///   - Skeet.cc: .skeettoken / skeet_auth
///   - Stand (GTA V): %APPDATA%\Stand\license
///   - Cherax: cherax.lic / cherax_key.txt
///   - Ozark: ozark_token / .ozark
///   - Wurst (Minecraft): license.txt in config dir
///
/// License regex patterns:
///   - UUID format: 8-4-4-4-12 hex (common for subscription services)
///   - Alphanumeric: 4-4-4-4 or 5-5-5-5 groups
///   - Base64 JWT tokens: eyJ... (JSON Web Token header)
///   - 64-char hex strings (SHA-256 HWID tokens)
///
/// Ocean/detect.ac search for these token files because:
///   - License files survive cheat uninstallation (some cheats store them in AppData/Roaming)
///   - HWID-bound tokens are perfect evidence: the token is computationally bound to this machine
///   - Keygens leave intermediate files (cracked_keys.txt, trial_key.txt)
/// </summary>
public sealed class CheatLicenseKeygenScanModule : IScanModule
{
    public string Name => "Cheat-Lizenzschlüssel und Keygen-Artefakt-Erkennung";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    // Known cheat vendor license file names and their vendor names
    private static readonly (string FileName, string VendorName)[] KnownLicenseFiles =
    {
        ("hwid_token.json",      "Gamesense"),
        ("hwid_token.dat",       "Gamesense"),
        ("license.lic",          "Onetap/Generic"),
        ("auth.json",            "Fatality/Generic"),
        ("auth.dat",             "Fatality/Generic"),
        ("aw_token.dat",         "Aimware"),
        ("aw_auth.dat",          "Aimware"),
        ("nl_auth.json",         "Neverlose"),
        ("nl_token.json",        "Neverlose"),
        ("2t1_auth.token",       "2Take1"),
        (".skeettoken",          "Skeet.cc"),
        ("skeet_auth",           "Skeet.cc"),
        ("skeet_token",          "Skeet.cc"),
        ("license",              "Stand/Generic"),
        ("cherax.lic",           "Cherax"),
        ("cherax_key.txt",       "Cherax"),
        ("ozark_token",          "Ozark"),
        (".ozark",               "Ozark"),
        ("ozark.lic",            "Ozark"),
        ("fatality_auth.json",   "Fatality"),
        ("onetap.lic",           "Onetap"),
        ("onetap_token",         "Onetap"),
        ("aimware_token",        "Aimware"),
        ("gamesense_token",      "Gamesense"),
        ("cheat_token",          "Generic Cheat"),
        ("loader_token",         "Generic Loader"),
        ("hwid.txt",             "HWID Token"),
        ("token.dat",            "Generic Token"),
        ("auth_token",           "Generic Auth"),
        ("injector.key",         "Injector Key"),
        ("cracked_keys.txt",     "Keygen Output"),
        ("trial_key.txt",        "Trial Key"),
        ("keygen.exe",           "Keygen"),
        ("crack.exe",            "Crack Executable"),
        ("patcher.exe",          "Patcher"),
        ("unlocker.exe",         "DRM Unlocker"),
    };

    // Directories to search for license files
    private static readonly string[] SearchDirs = new[]
    {
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
    };

    // Known cheat vendor AppData subdirectory names where license files live
    private static readonly string[] CheatVendorDirs =
    {
        "Gamesense", "gamesense", "onetap", "fatality", "aimware", "neverlose",
        "skeet", "skeet.cc", "2take1", "kiddion", "cherax", "ozark", "stand",
        "evade", "midnight", "zenith", "synapse", "krnl", "jjsploit", "fluxus",
        "script-ware", "coco-z", "valyrian", "pandora", "solara",
        "calamari", "supremacy", "interwebz", "esp32", "nt-cheat", "wurst",
        "liquidbounce", "meteor", "impact", "aristois",
    };

    // Patterns that look like license keys in config/JSON files
    private static readonly Regex[] LicensePatterns = new[]
    {
        // JWT token: eyJhbGci... (base64 header)
        new Regex(@"eyJ[A-Za-z0-9+/]{20,}", RegexOptions.Compiled),
        // UUID format: 8-4-4-4-12
        new Regex(@"""[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}""",
            RegexOptions.Compiled | RegexOptions.IgnoreCase),
        // 64-char hex HWID token
        new Regex(@"""[0-9a-f]{64}""", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        // License key in common key-value formats
        new Regex(@"""(?:license_key|auth_key|token|hwid_token|api_key|cheat_key)""\s*:\s*""[^""]{16,}""",
            RegexOptions.Compiled | RegexOptions.IgnoreCase),
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        // 1. Scan known cheat vendor AppData directories for any files
        ScanCheatVendorDirectories(ctx, ct);

        // 2. Scan common directories for known license file names
        ScanForKnownLicenseFiles(ctx, ct);

        // 3. Scan cheat config files for embedded license key patterns
        ScanConfigFilesForKeyPatterns(ctx, ct);
    }

    private void ScanCheatVendorDirectories(ScanContext ctx, CancellationToken ct)
    {
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var baseDir in new[] { appData, localAppData })
        {
            foreach (var vendorDir in CheatVendorDirs)
            {
                ct.ThrowIfCancellationRequested();
                string fullPath = Path.Combine(baseDir, vendorDir);
                if (!Directory.Exists(fullPath)) continue;

                // Directory exists — already reported by CheatFileArtifacts or AppData scan
                // Here we specifically look for license/token files inside
                try
                {
                    var files = Directory.GetFiles(fullPath, "*", SearchOption.TopDirectoryOnly);
                    foreach (var file in files)
                    {
                        ctx.IncrementFiles();
                        string fname = Path.GetFileName(file).ToLowerInvariant();
                        string ext   = Path.GetExtension(file).ToLowerInvariant();

                        bool isLicenseExt = ext is ".lic" or ".token" or ".key" or ".dat" or ".json";
                        bool hasLicenseName = fname.Contains("license") || fname.Contains("auth") ||
                                             fname.Contains("token") || fname.Contains("hwid") ||
                                             fname.Contains("key");

                        if (isLicenseExt || hasLicenseName)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Cheat-Lizenz/Token-Datei in Vendor-Verzeichnis '{vendorDir}': {Path.GetFileName(file)}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"Lizenz/Token-Datei '{Path.GetFileName(file)}' in bekanntem Cheat-Vendor-" +
                                           $"Verzeichnis '{vendorDir}'. Diese Datei enthält den Hardware-gebundenen " +
                                           "Aktivierungsnachweis für das Cheat-Abonnement. HWID-gebundene Token " +
                                           "beweisen dass diese Hardware für das Cheat aktiviert wurde.",
                                Detail   = $"Datei: {file} | Vendor: {vendorDir}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
    }

    private void ScanForKnownLicenseFiles(ScanContext ctx, CancellationToken ct)
    {
        foreach (var baseDir in SearchDirs)
        {
            if (!Directory.Exists(baseDir)) continue;

            foreach (var (licFileName, vendorName) in KnownLicenseFiles)
            {
                ct.ThrowIfCancellationRequested();

                // Search recursively up to depth 4
                try
                {
                    SearchForFile(baseDir, licFileName, vendorName, ctx, ct, maxDepth: 4, currentDepth: 0);
                }
                catch { }
            }
        }
    }

    private void SearchForFile(string dir, string targetName, string vendorName,
        ScanContext ctx, CancellationToken ct, int maxDepth, int currentDepth)
    {
        if (currentDepth > maxDepth) return;
        if (!Directory.Exists(dir)) return;

        ct.ThrowIfCancellationRequested();

        try
        {
            // Check files in current directory
            var files = Directory.GetFiles(dir)
                .Where(f => Path.GetFileName(f).Equals(targetName, StringComparison.OrdinalIgnoreCase) ||
                           Path.GetFileName(f).ToLowerInvariant().Contains(targetName.ToLowerInvariant()));

            foreach (var file in files)
            {
                ctx.IncrementFiles();
                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                if (fileSize > 0 && fileSize < 10 * 1024) // License files are small (<10KB)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekannte Cheat-Lizenz-Datei gefunden ({vendorName}): {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Bekannte Cheat-Lizenz-Datei '{Path.GetFileName(file)}' gefunden " +
                                   $"(erwartet von: {vendorName}). Lizenz-Dateien sind Hardware-gebunden " +
                                   "und beweisen aktive Cheat-Nutzung auf dieser Hardware. " +
                                   "Ocean/detect.ac suchen diese Dateien als primäre Echtheitsnachweise.",
                        Detail   = $"Datei: {file} | Vendor: {vendorName} | Größe: {fileSize} bytes"
                    });
                }
            }

            // Recurse into subdirectories
            if (currentDepth < maxDepth)
            {
                foreach (var subDir in Directory.GetDirectories(dir))
                {
                    SearchForFile(subDir, targetName, vendorName, ctx, ct, maxDepth, currentDepth + 1);
                }
            }
        }
        catch { }
    }

    private void ScanConfigFilesForKeyPatterns(ScanContext ctx, CancellationToken ct)
    {
        // Scan known cheat config file locations for embedded license key strings
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var vendorDir in CheatVendorDirs)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var baseDir in new[] { appData, localAppData })
            {
                string fullPath = Path.Combine(baseDir, vendorDir);
                if (!Directory.Exists(fullPath)) continue;

                try
                {
                    var configFiles = Directory.GetFiles(fullPath, "*.json")
                        .Concat(Directory.GetFiles(fullPath, "*.ini"))
                        .Concat(Directory.GetFiles(fullPath, "*.cfg"));

                    foreach (var configFile in configFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();

                        try
                        {
                            long size = new FileInfo(configFile).Length;
                            if (size > 500 * 1024) continue; // Skip huge files

                            string content = File.ReadAllText(configFile, Encoding.UTF8);

                            foreach (var pattern in LicensePatterns)
                            {
                                var match = pattern.Match(content);
                                if (match.Success)
                                {
                                    string matchPreview = match.Value.Length > 40
                                        ? match.Value[..37] + "..."
                                        : match.Value;

                                    ctx.AddFinding(new Finding
                                    {
                                        Module   = Name,
                                        Title    = $"Lizenzschlüssel-Muster in '{vendorDir}' Konfiguration: {Path.GetFileName(configFile)}",
                                        Risk     = RiskLevel.High,
                                        Location = configFile,
                                        FileName = Path.GetFileName(configFile),
                                        Reason   = $"Cheat-Konfigurationsdatei '{Path.GetFileName(configFile)}' " +
                                                   $"in '{vendorDir}'-Verzeichnis enthält ein Lizenzschlüssel-Muster: {matchPreview}. " +
                                                   "Eingebettete HWID-Token oder API-Schlüssel beweisen aktive Nutzung.",
                                        Detail   = $"Datei: {configFile} | Pattern: {pattern} | Match: {matchPreview}"
                                    });
                                    break; // One finding per file
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
    }
}
