using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Correlates Steam user data with known cheat indicators.
///
/// Ocean and detect.ac perform Steam-level forensics because:
///   - Steam stores game launch parameters and recent launch history in localconfig.vdf
///   - Friends list can contain banned accounts or accounts with cheat-keyword names
///   - Steam game library manifests reveal installed cheat-adjacent tools
///   - "Steam_api.dll" replacements and cracked game copies are a common cheat vector
///
/// Files and registries scanned:
///   %LOCALAPPDATA%\Steam\userdata\<steamid>\config\localconfig.vdf
///   %ProgramFiles(x86)%\Steam\config\loginusers.vdf
///   %ProgramFiles(x86)%\Steam\userdata\<steamid>\config\localconfig.vdf
///   %ProgramFiles(x86)%\Steam\steamapps\*.acf (manifest files for installed apps)
///   Launch parameters in localconfig.vdf for known cheat-injection flags
///
/// Keywords in launch parameters: -insecure, -unsafe, -allowthirdpartysoftware
/// Cheat-keyword app names in library: "cheat", "hack", "aimbot", "wallhack"
/// </summary>
public sealed class SteamCheatCorrelationScanModule : IScanModule
{
    public string Name => "Steam Cheat-Korrelation Scan";
    public double Weight => 0.55;
    public int ParallelGroup => 4;

    private static readonly string[] SuspiciousLaunchParams =
    {
        "-insecure",
        "-unsafe",
        "-allowthirdpartysoftware",
        "-cheat",
        "-nocheatcheck",
        "+sv_cheats",
        "-noac",        // disable anti-cheat
        "-novac",
        "-textmode",    // sometimes used to bypass EAC/BE
    };

    private static readonly string[] CheatRelatedAppNames =
    {
        "cheat", "hack", "aimbot", "wallhack", "esp",
        "triggerbot", "injector", "loader",
        "spoofer", "bypass", "undetected",
        "bhop", "spinbot", "rage hack",
    };

    private static readonly string[] CheatAcfKeywords =
    {
        "cheat", "hack", "injector", "bypass",
        "spoofer", "aimbot", "wallhack",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var steamRoots = new[]
        {
            System.IO.Path.Combine(progFiles86, "Steam"),
            System.IO.Path.Combine(local, "Steam"),
            @"D:\Steam",
            @"E:\Steam",
        };

        foreach (string root in steamRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(root)) continue;

            // loginusers.vdf — enumerate all Steam accounts that have logged in
            string loginUsers = System.IO.Path.Combine(root, "config", "loginusers.vdf");
            if (System.IO.File.Exists(loginUsers))
                ScanLoginUsers(ctx, loginUsers, ct);

            // userdata per Steam ID
            string userdata = System.IO.Path.Combine(root, "userdata");
            if (System.IO.Directory.Exists(userdata))
            {
                try
                {
                    foreach (string userDir in System.IO.Directory.GetDirectories(userdata))
                    {
                        ct.ThrowIfCancellationRequested();
                        string localconfig = System.IO.Path.Combine(userDir, "config", "localconfig.vdf");
                        if (System.IO.File.Exists(localconfig))
                            ScanLocalConfig(ctx, localconfig, ct);
                    }
                }
                catch { }
            }

            // steamapps manifests
            ScanSteamApps(ctx, System.IO.Path.Combine(root, "steamapps"), ct);

            // Library folders (additional drives)
            ScanLibraryFolders(ctx, root, ct);
        }
    }

    private void ScanLoginUsers(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            ctx.IncrementFiles();
            string content = System.IO.File.ReadAllText(path);
            // VDF format: look for suspicious "PersonaName" values
            ScanVdfForKeywords(ctx, path, content, "Steam loginusers.vdf (Account-Name)", ct);
        }
        catch { }
    }

    private void ScanLocalConfig(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            ctx.IncrementFiles();
            var info = new System.IO.FileInfo(path);
            if (info.Length > 32 * 1024 * 1024) return;

            string content = System.IO.File.ReadAllText(path);
            string lower = content.ToLowerInvariant();

            // Check launch parameters for -insecure and similar
            foreach (string param in SuspiciousLaunchParams)
            {
                ct.ThrowIfCancellationRequested();
                if (!lower.Contains(param.ToLowerInvariant())) continue;

                // Extract surrounding VDF context (game name)
                int idx = lower.IndexOf(param.ToLowerInvariant(), StringComparison.Ordinal);
                int start = Math.Max(0, idx - 200);
                string ctx200 = content.Substring(start, Math.Min(400, content.Length - start))
                                       .Replace('\n', ' ').Replace('\r', ' ').Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdächtiger Steam-Startparameter: {param}",
                    Risk     = RiskLevel.High,
                    Location = path,
                    FileName = "localconfig.vdf",
                    Reason   = $"Steam localconfig.vdf enthält Startparameter '{param}', der typischerweise " +
                               "verwendet wird, um Anti-Cheat-Schutz zu umgehen oder Cheat-Injektion zu " +
                               "ermöglichen. Ocean und detect.ac flaggen diese Parameter als direktes " +
                               "Indiz für absichtliche Sicherheits-Deaktivierung.",
                    Detail   = $"Parameter: {param} | Datei: {path} | Kontext: \"{ctx200}\""
                });
            }

            // Also scan for cheat keywords in the VDF (app names, friend names, etc.)
            ScanVdfForKeywords(ctx, path, content, "Steam localconfig.vdf", ct);
        }
        catch { }
    }

    private void ScanVdfForKeywords(ScanContext ctx, string path, string content,
        string label, CancellationToken ct)
    {
        string lower = content.ToLowerInvariant();
        string fileName = System.IO.Path.GetFileName(path);

        foreach (string kw in CheatRelatedAppNames)
        {
            ct.ThrowIfCancellationRequested();
            if (!lower.Contains(kw)) continue;

            int idx = lower.IndexOf(kw, StringComparison.Ordinal);
            int start = Math.Max(0, idx - 50);
            int end = Math.Min(content.Length, idx + kw.Length + 80);
            string snippet = content.Substring(start, end - start)
                                    .Replace('\n', ' ').Replace('\r', ' ').Trim();

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Cheat-Schlüsselwort in {label}: '{kw}'",
                Risk     = RiskLevel.Medium,
                Location = path,
                FileName = fileName,
                Reason   = $"Steam-Datei '{fileName}' enthält Cheat-Schlüsselwort '{kw}'. " +
                           $"Dies kann auf einen App-Namen, Friend-Namen oder installierten " +
                           "Cheat-Tool-Eintrag in der Steam-Konfiguration hinweisen.",
                Detail   = $"Quelle: {label} | Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
            });
            return; // one finding per file
        }
    }

    private void ScanSteamApps(ScanContext ctx, string steamappsDir, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(steamappsDir)) return;
        try
        {
            foreach (string acf in System.IO.Directory.EnumerateFiles(steamappsDir, "*.acf"))
            {
                ct.ThrowIfCancellationRequested();
                var info = new System.IO.FileInfo(acf);
                if (info.Length == 0 || info.Length > 1024 * 1024) continue;
                ctx.IncrementFiles();

                string content = System.IO.File.ReadAllText(acf);
                string lower   = content.ToLowerInvariant();
                string fileName = System.IO.Path.GetFileName(acf);

                foreach (string kw in CheatAcfKeywords)
                {
                    if (!lower.Contains(kw)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-App in Steam-Bibliothek: '{kw}' in {fileName}",
                        Risk     = RiskLevel.High,
                        Location = acf,
                        FileName = fileName,
                        Reason   = $"Steam App-Manifest '{fileName}' enthält Cheat-Schlüsselwort '{kw}' " +
                                   "im App-Namen oder Installationspfad. Cheat-Tools werden manchmal als " +
                                   "Steam-Non-Steam-Games oder Software-Einträge hinzugefügt.",
                        Detail   = $"Datei: {acf} | Schlüsselwort: '{kw}'"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private void ScanLibraryFolders(ScanContext ctx, string steamRoot, CancellationToken ct)
    {
        string libraryFolders = System.IO.Path.Combine(steamRoot, "config", "libraryfolders.vdf");
        if (!System.IO.File.Exists(libraryFolders)) return;
        try
        {
            string content = System.IO.File.ReadAllText(libraryFolders);
            // Extract paths like "path" "/some/path"
            var lines = content.Split('\n');
            foreach (string line in lines)
            {
                ct.ThrowIfCancellationRequested();
                string l = line.Trim().ToLowerInvariant();
                if (!l.StartsWith("\"path\"")) continue;
                int q1 = line.IndexOf('"', 6);
                int q2 = line.IndexOf('"', q1 + 1);
                if (q1 < 0 || q2 <= q1) continue;
                string libPath = line.Substring(q1 + 1, q2 - q1 - 1)
                                     .Replace("\\\\", "\\");
                string appsDir = System.IO.Path.Combine(libPath, "steamapps");
                if (System.IO.Directory.Exists(appsDir))
                    ScanSteamApps(ctx, appsDir, ct);
            }
        }
        catch { }
    }
}
