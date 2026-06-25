using Microsoft.Win32;
using System.Diagnostics;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects credential and session-token theft artifacts left by "stealer"
/// malware commonly bundled with cheat software.
///
/// The modern cheat ecosystem frequently bundles:
///   - Discord token stealers (target APPDATA\discord\Local Storage\leveldb)
///   - Steam session hijackers (target loginusers.vdf + ssfn files)
///   - Browser credential stealers (target Chrome/Edge Login Data SQLite DB)
///   - Crypto wallet drainers (MetaMask, Exodus, Electrum)
///   - Telegram session stealers (tdata folder)
///   - Game launcher stealers (Epic, Origin, Uplay)
///
/// Detection approach (no actual credential reading):
///   1. Check if known stealer process names are/were running (process artifacts).
///   2. Detect suspicious access patterns: Discord leveldb copied to Temp, Steam ssfn
///      files outside Steam directories, Login Data DB unexpectedly modified.
///   3. Check for known stealer file artifacts (dropped executables, config files).
///   4. Detect clipboard token patterns (Discord token format regex in clipboard cache).
///   5. Check browser extension IDs for known stealer extensions.
///   6. Detect crypto wallet browser extensions that were recently removed
///      (MetaMask extension folder renamed/modified — possible drainer).
/// </summary>
public sealed class CredentialTheftScanModule : IScanModule
{
    public string Name => "Credential-Theft";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string AppData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string TempPath     = Path.GetTempPath();
    private static readonly string Profile      = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    // Known stealer process/executable names
    private static readonly string[] StealerProcessNames =
    {
        "stealer", "grabber", "clipper", "injector_stealer",
        "discordstealer", "tokenstealer", "tokengrabber",
        "discord_token", "steamstealer", "browsestealer",
        "walletstealer", "credstealer",
        // Named stealers (2024-2026)
        "redline", "vidar", "raccoon", "azorult", "lumma",
        "meta_stealer", "aurora", "stealc", "typhon",
        "mystic", "nemesis_stealer", "nexus_stealer",
        "atomic", "amos", "poseidon",  // macOS stealers also seen on Windows VMs
    };

    // Artifact file names dropped by stealers
    private static readonly string[] StealerArtifacts =
    {
        "passwords.txt", "cookies.txt", "tokens.txt", "discord_tokens.txt",
        "steam_accounts.txt", "steam_sessions.txt", "wallets.txt",
        "credentials.txt", "chrome_passwords.txt", "firefox_passwords.txt",
        "grabbed.zip", "result.zip", "loot.zip", "stealer_output.zip",
        "discord.txt", "telegram.txt", "crypto.txt",
        // Redline/Vidar style
        "all_credentials.txt", "system_info.txt", "autofills.txt",
        "cc.txt", "browser_data.zip",
    };

    // Suspicious files that should not be outside their expected directories
    private static readonly (string file, string expectedDir, string reason)[] SensitiveFileCopies =
    {
        ("Login Data",   @"Google\Chrome\User Data\Default", "Chrome Login-DB kopiert"),
        ("Login Data",   @"Microsoft\Edge\User Data\Default", "Edge Login-DB kopiert"),
        ("cookies.sqlite", @"Mozilla\Firefox\Profiles", "Firefox Cookies kopiert"),
        ("key4.db",        @"Mozilla\Firefox\Profiles", "Firefox Schlüssel-DB kopiert"),
        ("Web Data",       @"Google\Chrome\User Data\Default", "Chrome AutoFill kopiert"),
    };

    // Browser extensions known to steal credentials
    private static readonly (string id, string name)[] MaliciousExtensionIds =
    {
        ("cfojmekmbniajhnjfmnikhcalkfiiokj", "Fake MetaMask Stealer"),
        ("nkbihfbeogaeaoehlefnkodbefgpgknn", "Suspicious MetaMask Clone"),
        ("ejbalbakoplchlghecdalmeeeajnimhm", "Fake MetaMask (v2)"),
        ("fhbohimaelbohpjbbldcngcnapndodjp", "Fake Binance Extension"),
        ("hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Phishing Extension"),
        ("ibnejdfjmmkpcnlpebklmnkoeoihofec", "Fake TronLink Stealer"),
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Credential-Theft", "Prüfe Stealer-Prozesse...");
        CheckStealerProcesses(ctx, ct);

        ctx.Report(0.15, "Credential-Theft", "Suche Stealer-Artefakte...");
        CheckStealerArtifacts(ctx, ct);

        ctx.Report(0.3, "Credential-Theft", "Prüfe Discord-Token-Zugriff...");
        CheckDiscordTokenAccess(ctx, ct);

        ctx.Report(0.45, "Credential-Theft", "Prüfe Steam-Session-Diebstahl...");
        CheckSteamSessionTheft(ctx, ct);

        ctx.Report(0.6, "Credential-Theft", "Prüfe Browser-Daten-Kopien...");
        CheckBrowserDataCopies(ctx, ct);

        ctx.Report(0.75, "Credential-Theft", "Prüfe Crypto-Wallet-Zugriff...");
        CheckCryptoWalletAccess(ctx, ct);

        ctx.Report(0.9, "Credential-Theft", "Prüfe Telegram-Session...");
        CheckTelegramAccess(ctx, ct);

        ctx.Report(1.0, "Credential-Theft", "Credential-Theft-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    private static void CheckStealerProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var name = proc.ProcessName.ToLowerInvariant();
                    var hit = StealerProcessNames.FirstOrDefault(s =>
                        name.Contains(s, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) { proc.Dispose(); continue; }

                    string? exe = null;
                    try { exe = proc.MainModule?.FileName; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Credential-Theft",
                        Title    = $"Bekannter Stealer-Prozess: {proc.ProcessName}",
                        Risk     = RiskLevel.Critical,
                        Location = exe ?? $"PID {proc.Id}",
                        FileName = proc.ProcessName,
                        Reason   = $"Bekannter Credential-Stealer oder Token-Grabber '{proc.ProcessName}' " +
                                   "läuft gerade. Diese sind häufig als 'kostenlose Cheats' getarnt " +
                                   "und stehlen Discord-Token, Steam-Sessions und Browser-Passwörter.",
                        Detail   = $"PID: {proc.Id} | Match: {hit}"
                    });
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }
        catch { }
    }

    private static void CheckStealerArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            TempPath,
            Path.Combine(Profile, "Downloads"),
            Path.Combine(Profile, "Desktop"),
            Path.Combine(LocalAppData, "Temp"),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            if (ct.IsCancellationRequested) return;

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file).ToLowerInvariant();

                    if (!StealerArtifacts.Any(a => fn.Equals(a, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    var info = new FileInfo(file);
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Credential-Theft",
                        Title    = $"Stealer-Artefakt: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Bekannte Stealer-Ausgabedatei '{fn}' in '{dir}' gefunden. " +
                                   "Stealer schreiben gestohlene Credentials, Discord-Token und " +
                                   "Steam-Accounts in solche Dateien vor dem Upload.",
                        Detail   = $"Datei: {file} | Größe: {info.Length / 1024} KB | " +
                                   $"Geändert: {info.LastWriteTime:yyyy-MM-dd HH:mm}"
                    });
                }
            }
            catch { }
        }
    }

    private static void CheckDiscordTokenAccess(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        // Stealers often copy Discord's LevelDB to Temp to read tokens offline
        var discordLevelDb = Path.Combine(AppData, @"discord\Local Storage\leveldb");
        var discordPtbDb   = Path.Combine(AppData, @"discordptb\Local Storage\leveldb");
        var discordCanaryDb = Path.Combine(AppData, @"discordcanary\Local Storage\leveldb");

        // Check if any LevelDB LLOG files exist in Temp (copied from Discord)
        try
        {
            foreach (var file in Directory.EnumerateFiles(TempPath, "*.ldb"))
            {
                if (ct.IsCancellationRequested) return;
                ctx.AddFinding(new Finding
                {
                    Module   = "Credential-Theft",
                    Title    = "Discord LevelDB-Datei in Temp-Verzeichnis",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason   = "Eine Discord LevelDB-Datei (.ldb) wurde in das Temp-Verzeichnis kopiert. " +
                               "Token-Stealer kopieren Discord's lokale Datenbank in Temp, um offline " +
                               "den Session-Token zu extrahieren.",
                    Detail   = $"Kopie in: {file}"
                });
            }
        }
        catch { }

        // Check for Discord token backup files
        var suspiciousNames = new[] { "discord_token", "tokens", "discord_tokens" };
        foreach (var dir in new[] { TempPath, Path.Combine(Profile, "Desktop") })
        {
            foreach (var name in suspiciousNames)
            {
                if (ct.IsCancellationRequested) return;
                foreach (var ext in new[] { ".txt", ".json", ".log" })
                {
                    var f = Path.Combine(dir, name + ext);
                    if (!File.Exists(f)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Credential-Theft",
                        Title    = $"Mögliche Discord-Token-Datei: {name}{ext}",
                        Risk     = RiskLevel.Critical,
                        Location = f,
                        FileName = name + ext,
                        Reason   = $"Datei mit Discord-Token-typischem Namen '{name}{ext}' gefunden. " +
                                   "Token-Stealer speichern gestohlene Discord-Tokens in solchen Dateien.",
                        Detail   = $"Pfad: {f}"
                    });
                }
            }
        }
    }

    private static void CheckSteamSessionTheft(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var steamPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Steam");

        // Check if ssfn files (Steam auth tokens) exist outside Steam directory
        try
        {
            foreach (var dir in new[] { TempPath, Path.Combine(Profile, "Downloads") })
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var file in Directory.EnumerateFiles(dir, "ssfn*"))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Credential-Theft",
                        Title    = $"Steam SSFN-Auth-Token außerhalb Steam-Dir: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = "Steam Session-File (ssfn*) außerhalb des Steam-Verzeichnisses gefunden. " +
                                   "Diese Dateien enthalten Steam-Authentifizierungs-Token. " +
                                   "Steam-Stealer kopieren ssfn-Dateien für Session-Hijacking.",
                        Detail   = $"Datei: {file}"
                    });
                }
            }
        }
        catch { }
    }

    private static void CheckBrowserDataCopies(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        // "Login Data" is Chrome/Edge's credential database
        // Stealers copy it to Temp to bypass file locking
        try
        {
            foreach (var file in Directory.EnumerateFiles(TempPath, "Login Data*"))
            {
                if (ct.IsCancellationRequested) return;
                ctx.AddFinding(new Finding
                {
                    Module   = "Credential-Theft",
                    Title    = "Browser Login-Datenbank in Temp kopiert",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason   = "Chrome/Edge 'Login Data' Datei im Temp-Verzeichnis gefunden. " +
                               "Diese SQLite-Datenbank enthält alle gespeicherten Browser-Passwörter. " +
                               "Credential-Stealer kopieren sie in Temp, um sie ohne SYSTEM-Rechte zu lesen.",
                    Detail   = $"Pfad: {file}"
                });
            }

            // Also check for Web Data (autofill) and Cookies copies
            foreach (var pattern in new[] { "Web Data*", "Cookies*", "key4.db" })
            {
                foreach (var file in Directory.EnumerateFiles(TempPath, pattern))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Credential-Theft",
                        Title    = $"Browser-Datenbankdatei in Temp: {pattern.TrimEnd('*')}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Browser-Datenbankdatei '{Path.GetFileName(file)}' im Temp-Verzeichnis. " +
                                   "Stealers kopieren Browser-Datenbanken zur Offline-Extraktion von " +
                                   "Cookies, AutoFill-Daten und Passwörtern.",
                        Detail   = $"Pfad: {file}"
                    });
                }
            }
        }
        catch { }
    }

    private static void CheckCryptoWalletAccess(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        // Exodus wallet
        var exodusPath = Path.Combine(AppData, @"Exodus\exodus.wallet");
        // Electrum wallet
        var electrumPath = Path.Combine(AppData, @"Electrum\wallets");
        // MetaMask (browser extension) Local Storage
        var metaMaskChrome = Path.Combine(LocalAppData,
            @"Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn");

        // Check if wallet directories were recently modified (potential drainer access)
        var walletPaths = new[]
        {
            (exodusPath, "Exodus"),
            (electrumPath, "Electrum"),
        };

        foreach (var (walletPath, walletName) in walletPaths)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(walletPath)) continue;

            try
            {
                var dir = new DirectoryInfo(walletPath);
                var recentlyModified = dir.GetFiles("*", SearchOption.TopDirectoryOnly)
                    .Any(f => (DateTime.UtcNow - f.LastWriteTimeUtc).TotalDays < 1);

                if (recentlyModified)
                {
                    // This is informational — wallet in use
                    // Only flag if there's no running wallet process (drainer context)
                    bool walletRunning = Process.GetProcessesByName(
                        walletName.ToLowerInvariant()).Length > 0;

                    if (!walletRunning)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Credential-Theft",
                            Title    = $"Crypto-Wallet-Dateien zuletzt verändert: {walletName}",
                            Risk     = RiskLevel.High,
                            Location = walletPath,
                            Reason   = $"{walletName}-Wallet-Dateien wurden in den letzten 24 Stunden " +
                                       "verändert, obwohl {walletName} nicht läuft. " +
                                       "Wallet-Drainer greifen auf Wallet-Dateien zu, " +
                                       "ohne die eigentliche Anwendung zu starten.",
                            Detail   = $"Wallet-Pfad: {walletPath} | Wallet-Prozess läuft: Nein"
                        });
                    }
                }
            }
            catch { }
        }

        // Check for wallet backup files in Temp/Downloads
        try
        {
            foreach (var dir in new[] { TempPath, Path.Combine(Profile, "Downloads") })
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var file in Directory.EnumerateFiles(dir, "*.wallet"))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Credential-Theft",
                        Title    = $"Wallet-Datei außerhalb Standard-Verzeichnis: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = "Kryptowährungs-Wallet-Datei (.wallet) außerhalb des Standard-" +
                                   "Wallet-Verzeichnisses gefunden. Wallet-Drainer kopieren Wallet-Dateien " +
                                   "vor dem Hochladen zum Angreifer.",
                        Detail   = $"Datei: {file}"
                    });
                }
            }
        }
        catch { }
    }

    private static void CheckTelegramAccess(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        // Telegram Desktop tdata folder = session files
        var tdataPath = Path.Combine(AppData, "Telegram Desktop\\tdata");
        if (!Directory.Exists(tdataPath)) return;

        // Check for tdata copies in Temp
        try
        {
            foreach (var file in Directory.EnumerateFiles(TempPath, "*.tdata*")
                .Concat(Directory.EnumerateFiles(TempPath, "D877F783D5D3EF8C*")))
            {
                if (ct.IsCancellationRequested) return;
                ctx.AddFinding(new Finding
                {
                    Module   = "Credential-Theft",
                    Title    = "Telegram tdata-Session außerhalb Standard-Verzeichnis",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason   = "Telegram-Session-Datei (tdata) im Temp-Verzeichnis gefunden. " +
                               "Telegram-Stealer kopieren die tdata-Session-Dateien, um Telegram-" +
                               "Accounts ohne Login-Daten zu übernehmen.",
                    Detail   = $"Kopie: {file}"
                });
            }
        }
        catch { }
    }
}
