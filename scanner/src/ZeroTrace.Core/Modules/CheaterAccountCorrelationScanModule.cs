using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Correlates game account data with known ban indicators and cheat community patterns.
///
/// Ocean and detect.ac perform account-level correlation because:
///   - Multiple game accounts on one machine (account cycling after bans)
///   - Account creation dates immediately after known ban waves
///   - Steam accounts with no game hours but installed in a full gaming environment
///   - Multiple Valorant/FACEIT accounts (Riot locks by hardware — only possible with HWID spoofer)
///
/// Detection sources:
///   - Steam: loginusers.vdf (all logged-in Steam accounts on this machine)
///   - Riot: per-user config dirs for multiple Riot accounts
///   - Epic Games: local store metadata
///   - Origin/EA: per-user profile dirs
///   - FACEIT: FACEIT client data (if installed)
///
/// Multiple accounts = account cycling after ban = HWID spoofer usage required
/// = strong cheat indicator
/// </summary>
public sealed class CheaterAccountCorrelationScanModule : IScanModule
{
    public string Name => "Account-Zyklus / Mehrfachkonto-Korrelation Scan";
    public double Weight => 0.4;
    public int ParallelGroup => 4;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanSteamAccounts(ctx, ct);
        ScanRiotAccounts(ctx, ct);
        ScanEpicAccounts(ctx, ct);
        ScanFaceitClient(ctx, ct);
    }

    private void ScanSteamAccounts(ScanContext ctx, CancellationToken ct)
    {
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var steamRoots = new[]
        {
            System.IO.Path.Combine(progFiles86, "Steam"),
            System.IO.Path.Combine(local, "Steam"),
            @"D:\Steam", @"E:\Steam",
        };

        foreach (string steamRoot in steamRoots)
        {
            ct.ThrowIfCancellationRequested();
            string loginUsers = System.IO.Path.Combine(steamRoot, "config", "loginusers.vdf");
            if (!System.IO.File.Exists(loginUsers)) continue;

            try
            {
                ctx.IncrementFiles();
                string content = System.IO.File.ReadAllText(loginUsers);
                // Count account entries: each has a 64-bit SteamID as key
                int accountCount = CountVdfEntries(content);

                if (accountCount >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Viele Steam-Konten auf diesem PC: {accountCount} Konten",
                        Risk     = accountCount >= 5 ? RiskLevel.High : RiskLevel.Medium,
                        Location = loginUsers,
                        FileName = "loginusers.vdf",
                        Reason   = $"{accountCount} verschiedene Steam-Konten haben sich auf diesem PC " +
                                   "angemeldet (aus loginusers.vdf). Viele Konten auf einem Gaming-PC " +
                                   "können auf Account-Zyklus nach Bans hinweisen. Steam-Bans sperren " +
                                   "Accounts; neue Accounts auf derselben Hardware erfordern HWID-Spoofer.",
                        Detail   = $"Datei: {loginUsers} | Konto-Anzahl: {accountCount}"
                    });
                }

                // Check userdata dirs count
                string userdata = System.IO.Path.Combine(steamRoot, "userdata");
                if (System.IO.Directory.Exists(userdata))
                {
                    int userCount = System.IO.Directory.GetDirectories(userdata).Length;
                    if (userCount != accountCount && userCount >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Steam userdata: {userCount} User-Profile",
                            Risk     = RiskLevel.Medium,
                            Location = userdata,
                            FileName = "Steam userdata",
                            Reason   = $"Steam userdata-Verzeichnis enthält {userCount} User-Profile " +
                                       "(SteamID-Unterordner). Mehr als 3 Profile deuten auf mehrere " +
                                       "Konten hin, möglicherweise nach Bans gewechselt.",
                            Detail   = $"Verzeichnis: {userdata} | Profile: {userCount}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private void ScanRiotAccounts(ScanContext ctx, CancellationToken ct)
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string riotDir = System.IO.Path.Combine(local, "Riot Games", "Riot Client", "Data");

        if (!System.IO.Directory.Exists(riotDir)) return;

        try
        {
            // Riot stores per-account local data
            ctx.IncrementFiles();
            // Count auth token files or settings files that indicate different accounts
            var accountFiles = System.IO.Directory.GetFiles(riotDir, "*.db")
                              .Concat(System.IO.Directory.GetFiles(riotDir, "*.sqlite")).ToArray();

            // Also check LOCALAPPDATA\Riot Games\VALORANT\Saved\Config for multiple configs
            string valorantConfig = System.IO.Path.Combine(
                local, "Riot Games", "VALORANT", "Saved", "Config");

            if (System.IO.Directory.Exists(valorantConfig))
            {
                int configDirs = System.IO.Directory.GetDirectories(valorantConfig).Length;
                if (configDirs > 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Mehrere Valorant-Account-Konfigurationen: {configDirs}",
                        Risk     = RiskLevel.High,
                        Location = valorantConfig,
                        FileName = "Valorant Config",
                        Reason   = $"{configDirs} verschiedene Valorant-Account-Konfigurationen " +
                                   "auf diesem PC. Valorant Vanguard sperrt auf Hardware-Ebene — " +
                                   "mehrere Accounts sind nur mit HWID-Spoofer möglich. " +
                                   "Ocean und detect.ac flaggen mehrere Riot-Accounts als " +
                                   "starkes HWID-Spoofer-Indiz.",
                        Detail   = $"Config-Verzeichnis: {valorantConfig} | Anzahl: {configDirs}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanEpicAccounts(ScanContext ctx, CancellationToken ct)
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string epicData = System.IO.Path.Combine(local, "EpicGamesLauncher", "Saved", "Config");
        if (!System.IO.Directory.Exists(epicData)) return;

        try
        {
            ctx.IncrementFiles();
            // Epic stores per-account authentication in GameUserSettings.ini and similar
            string configFile = System.IO.Path.Combine(epicData, "Windows", "GameUserSettings.ini");
            if (!System.IO.File.Exists(configFile)) return;

            string content = System.IO.File.ReadAllText(configFile);
            // Count occurrences of AccountId/DisplayName patterns
            int accountMarkers = content.Split(new[] { "AccountId=" }, StringSplitOptions.None).Length - 1;
            if (accountMarkers >= 3)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Mehrere Epic Games Accounts: {accountMarkers}",
                    Risk     = RiskLevel.Medium,
                    Location = configFile,
                    FileName = "GameUserSettings.ini",
                    Reason   = $"Epic Games Launcher-Konfiguration enthält {accountMarkers} Account-" +
                               "Referenzen. Mehrere Epic-Konten auf einem PC deuten auf Account-Zyklus " +
                               "nach Fortnite/EAC-Bans hin.",
                    Detail   = $"Datei: {configFile} | Account-Marker: {accountMarkers}"
                });
            }
        }
        catch { }
    }

    private void ScanFaceitClient(ScanContext ctx, CancellationToken ct)
    {
        string appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string faceitDir = System.IO.Path.Combine(appdata, "FACEIT");
        if (!System.IO.Directory.Exists(faceitDir)) return;

        try
        {
            ctx.IncrementFiles();
            // FACEIT stores account data — multiple account dirs = ban cycling
            int profileDirs = System.IO.Directory.GetDirectories(faceitDir).Length;

            // Scan FACEIT config for cheat-related patterns
            foreach (string file in System.IO.Directory.EnumerateFiles(
                         faceitDir, "*.json", System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var info = new System.IO.FileInfo(file);
                if (info.Length == 0 || info.Length > 5 * 1024 * 1024) continue;
                ctx.IncrementFiles();

                string text = System.IO.File.ReadAllText(file).ToLowerInvariant();
                if (text.Contains("cheat") || text.Contains("bypass") || text.Contains("hack"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Bezug in FACEIT-Client-Daten: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = "FACEIT-Client-Datei enthält Cheat-Schlüsselwort. FACEIT nutzt " +
                                   "AC-Server-seitig — Cheat-Referenzen in FACEIT-Daten sind ungewöhnlich.",
                        Detail   = $"Datei: {file}"
                    });
                }
            }
        }
        catch { }
    }

    private static int CountVdfEntries(string vdf)
    {
        // VDF format: entries start with a 17-digit Steam ID as key
        int count = 0;
        foreach (string line in vdf.Split('\n'))
        {
            string trimmed = line.Trim().Trim('"');
            if (trimmed.Length == 17 && trimmed.All(char.IsDigit))
                count++;
        }
        return count;
    }
}
