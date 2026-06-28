using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects staged cheat payload artifacts in user-accessible directories.
///
/// Cheat loaders follow a predictable staging pattern:
///   1. Download encrypted archive (.zip/.rar) to Downloads or Temp
///   2. Extract to a temp subdirectory (often a random GUID-named folder)
///   3. Drop main DLL(s) to %TEMP% or %APPDATA% for injection
///   4. Delete archive after extraction (but extraction folder remains)
///   5. Injector reads DLL from Temp, injects into game, may delete DLL after use
///
/// Staged artifact indicators:
///   - DLL files in %TEMP% with cheat-keyword names
///   - Unsigned .exe files in %TEMP% named like "loader.exe", "inject.exe", "game_hack.exe"
///   - Config JSON/INI files in %TEMP% with cheat CVars (aimbot_fov, esp_enabled, etc.)
///   - Extracted archives with cheat keyword names in Downloads (partially extracted)
///   - Log files in Temp with cheat output patterns (injected=true, loading..., etc.)
///   - Cheat license/key files (.lic, .key, .token) in Temp/AppData
///
/// Ocean and detect.ac scan Temp/Downloads for these artifacts because:
///   - Loaders routinely fail to clean up Temp extraction directories
///   - Config files often remain even after the cheat DLL is deleted
///   - License tokens are kept for re-authentication across sessions
/// </summary>
public sealed class CheatPayloadStagingScanModule : IScanModule
{
    public string Name => "Cheat Payload Staging und Injector-Artefakt Scan";
    public double Weight => 0.55;
    public int ParallelGroup => 4;

    private static readonly string[] CheatPayloadFileNames =
    {
        // Known cheat loader / injector executables
        "loader.exe", "inject.exe", "injector.exe", "launch.exe",
        "cheat.exe", "hack.exe", "bypass.exe", "spoofer.exe",
        "installer.exe", "setup.exe",    // generic but in Temp = suspicious
        // DLL names staged for injection
        "cheat.dll", "hack.dll", "aimbot.dll", "esp.dll",
        "wallhack.dll", "triggerbot.dll", "bhop.dll",
        "inject.dll", "payload.dll", "core.dll",
        "internal.dll", "external.dll",
        // License/token files
        "license.lic", "license.key", "auth.token", "cheat.token",
        "key.txt", "hwid.txt", "token.txt",
        // Specific known cheat artifacts
        "kiddion.exe", "kiddionsbmod.exe",
        "2take1.exe", "2t1.exe",
        "cherax.exe", "cherax.dll",
        "ozark.exe", "ozark.dll",
        "stand.exe",
        "synapse x.exe", "sxlib.dll",
        "krnl.exe", "krnl.dll",
        "jjsploit.exe",
        "fluxus.exe",
        "scriptware.exe",
        "neverlose.exe",
        "onetap.exe",
        "gamesense.exe",
    };

    private static readonly string[] SuspiciousExtensions =
    {
        ".dll", ".exe", ".sys", ".asi",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "aimbot", "esp", "wallhack", "triggerbot", "spinbot",
        "bhop", "no_recoil", "norecoil", "bypass", "inject",
        "sv_cheats", "r_drawothermodels", "license_key", "hwid",
        "silent_aim", "rage_bot", "legit_bot", "anti_aim",
        "resolver", "hitchance", "prediction", "backtrack",
    };

    private static readonly string[] CheatLogPatterns =
    {
        "injected successfully", "injection failed", "dll loaded",
        "cheat loaded", "bypass active", "ac bypassed",
        "license valid", "hwid matched", "authenticated",
        "aimbot enabled", "esp enabled", "wallhack enabled",
        "loading modules", "initializing cheat",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string sysTemp     = System.IO.Path.GetTempPath();
        string userTemp    = System.IO.Path.Combine(localApp, "Temp");

        var scanDirs = new[]
        {
            sysTemp,
            userTemp,
            System.IO.Path.Combine(userProfile, "Downloads"),
            System.IO.Path.Combine(userProfile, "Desktop"),
            appData,
            localApp,
        };

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(dir)) continue;
            ScanDirectory(ctx, dir, ct, 0);
        }
    }

    private void ScanDirectory(ScanContext ctx, string dir, CancellationToken ct, int depth)
    {
        if (depth > 4) return;
        ct.ThrowIfCancellationRequested();

        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(dir,
                "*", System.IO.SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string fileName = System.IO.Path.GetFileName(file);
                string fileNameLower = fileName.ToLowerInvariant();
                string ext = System.IO.Path.GetExtension(fileNameLower);

                // Check exact filename matches
                if (CheatPayloadFileNames.Any(n => fileNameLower.Equals(n, StringComparison.OrdinalIgnoreCase)))
                {
                    long size = 0;
                    try { size = new System.IO.FileInfo(file).Length; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat Payload-Datei in Staging-Verzeichnis: {fileName}",
                        Risk     = fileNameLower.Contains("cheat") || fileNameLower.Contains("hack") ||
                                   fileNameLower.Contains("aimbot") || fileNameLower.Contains("inject")
                            ? RiskLevel.Critical : RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Datei '{fileName}' in Staging-Verzeichnis '{dir}' ist ein bekannter " +
                                   "Cheat-Payload-Name. Cheat-Loader stagen DLLs und Executables im Temp-" +
                                   "Verzeichnis vor der Injektion. Ocean/detect.ac scannen Temp/Downloads " +
                                   "auf gestagete Cheat-Payloads.",
                        Detail   = $"Datei: {file} | Größe: {size} Bytes"
                    });
                    continue;
                }

                // Check for suspicious DLLs/EXEs in Temp that contain cheat keywords in name
                if (SuspiciousExtensions.Contains(ext))
                {
                    string? matchedKw = CheatConfigKeywords.FirstOrDefault(kw =>
                        fileNameLower.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (matchedKw != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat-Keyword in Payload-Dateiname: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Datei '{fileName}' enthält Cheat-Keyword '{matchedKw}' im Dateinamen " +
                                       $"und liegt in Staging-Verzeichnis. {ext}-Dateien mit Cheat-Namen in " +
                                       "Temp/Downloads sind Injektions-Staging-Artefakte.",
                            Detail   = $"Datei: {file} | Keyword: '{matchedKw}'"
                        });
                        continue;
                    }
                }

                // Scan config/text files for cheat CVars
                if (ext is ".json" or ".ini" or ".cfg" or ".txt" or ".xml" or ".log")
                {
                    try
                    {
                        var info = new System.IO.FileInfo(file);
                        if (info.Length == 0 || info.Length > 512 * 1024) continue;

                        string text = System.IO.File.ReadAllText(file).ToLowerInvariant();

                        // Check config keywords
                        string? cfgMatch = CheatConfigKeywords.FirstOrDefault(kw =>
                            text.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        if (cfgMatch != null)
                        {
                            int idx = text.IndexOf(cfgMatch, StringComparison.OrdinalIgnoreCase);
                            int start = Math.Max(0, idx - 20);
                            int end = Math.Min(text.Length, idx + cfgMatch.Length + 50);
                            string snippet = text.Substring(start, end - start)
                                .Replace('\n', ' ').Trim();

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Cheat-Konfiguration in Staging-Datei: '{cfgMatch}' in {fileName}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Konfig-Datei '{fileName}' in Staging-Verzeichnis enthält " +
                                           $"Cheat-Schlüsselwort '{cfgMatch}'. Cheat-Konfig-Dateien im " +
                                           "Temp-Verzeichnis belegen gestagete Cheat-Aktivierung.",
                                Detail   = $"Datei: {file} | Keyword: '{cfgMatch}' | Kontext: \"{snippet}\""
                            });
                            continue;
                        }

                        // Check log patterns (injection success/failure messages)
                        if (ext is ".log" or ".txt")
                        {
                            string? logMatch = CheatLogPatterns.FirstOrDefault(p =>
                                text.Contains(p, StringComparison.OrdinalIgnoreCase));
                            if (logMatch != null)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Cheat-Injektions-Log in Staging-Verzeichnis: {fileName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason   = $"Log-Datei '{fileName}' enthält Cheat-Injektions-Muster " +
                                               $"'{logMatch}'. Injektions-Logs sind direkter Beweis für " +
                                               "erfolgreiche Cheat-DLL-Injektion in Game-Prozesse.",
                                    Detail   = $"Datei: {file} | Muster: '{logMatch}'"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }

            // Recurse into subdirectories
            if (depth < 4)
            {
                try
                {
                    foreach (string subDir in System.IO.Directory.GetDirectories(dir))
                    {
                        ct.ThrowIfCancellationRequested();
                        string subName = System.IO.Path.GetFileName(subDir).ToLowerInvariant();

                        // Skip known-safe dirs
                        if (subName is "node_modules" or ".git" or "windows" or "microsoft") continue;

                        // Flag suspicious Temp subdirectory names
                        bool isSuspiciousDir = CheatConfigKeywords.Any(kw =>
                            subName.Contains(kw, StringComparison.OrdinalIgnoreCase)) ||
                            CheatPayloadFileNames.Any(n =>
                            System.IO.Path.GetFileNameWithoutExtension(n)
                                .Equals(subName, StringComparison.OrdinalIgnoreCase));

                        if (isSuspiciousDir && depth == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Cheat-Verzeichnis in Staging-Pfad: {subName}",
                                Risk     = RiskLevel.High,
                                Location = subDir,
                                FileName = subName,
                                Reason   = $"Unterverzeichnis '{subName}' in '{dir}' enthält einen Cheat-Namen. " +
                                           "Cheat-Loader erstellen benannte Verzeichnisse in Temp/Downloads " +
                                           "beim Extrahieren verschlüsselter Payloads.",
                                Detail   = $"Pfad: {subDir}"
                            });
                        }

                        ScanDirectory(ctx, subDir, ct, depth + 1);
                    }
                }
                catch { }
            }
        }
        catch { }
    }
}
