using System.Runtime.Versioning;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class FiveMTxAdminAbuseDeepForensicScanModule : IScanModule
{
    public string Name => "FiveM txAdmin Abuse Deep Forensic";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    // ─── Keyword lists ────────────────────────────────────────────────────────

    private static readonly string[] CredentialStealerNames = new[]
    {
        "txadmin_grab", "txadmin_stealer", "txadmin_steal", "panel_stealer",
        "panel_grab", "cfx_token_steal", "cfxtoken_grab", "cfx_stealer",
        "txadmin_dumper", "admin_stealer", "admincred_grab", "fivem_stealer",
        "txadmin_cred", "txadmin_harvest", "cfxre_stealer", "panel_dump",
        "txadmin_extract", "admin_cred_steal", "cfx_harvest", "fivem_credential",
    };

    private static readonly string[] SessionTokenKeywords = new[]
    {
        "txadmin_token", "txadmin_session", "txAdmin_session",
        "cfx_token", "cfxre_token", "cfx.re_token",
        "admin_session_token", "txadmin_auth_token", "txadmin_cookie",
        "TXADMIN_TOKEN", "TXADMIN_SESSION", "CFX_TOKEN", "CFX_AUTH_TOKEN",
        "txadmin_jwt", "txadmin_bearer", "admin_bearer_token",
        "set-cookie.*txadmin", "authorization.*txadmin",
        "cfxre_session", "citizenfx_token",
    };

    private static readonly string[] ApiAbuseEndpoints = new[]
    {
        "/api/auth", "/api/players/ban", "/api/commands",
        "/api/server", "/api/whitelist", "/api/admins",
        "txadmin/api", "txAdmin/api", "txadmin/auth",
        "/api/players/kick", "/api/resources", "/api/server/stop",
        "/api/server/start", "/api/server/restart",
        "txadmin/ban", "txadmin/kick", "txadmin/whitelist",
    };

    private static readonly string[] ApiAbuseCheatContext = new[]
    {
        "cheat", "hack", "exploit", "bypass", "abuse",
        "ban_bomb", "massBan", "mass_ban", "fake_ban",
        "impersonat", "spoof", "inject", "steal", "grab",
        "bruteforce", "brute_force", "flood", "crash",
    };

    private static readonly string[] VMenuPermissionPatterns = new[]
    {
        "add_ace identifier", "add_principal identifier",
        "add_ace.*all\\.x", "add_ace.*everyone",
        "allow all.x", "add_ace group.everyone",
        "add_principal.*admin", "remove_ace.*inherit",
        "vMenu.Everything", "vMenu.God",
        "permissions.cfg", "vMenu.cfg",
        "add_ace.*vMenu", "vmenu.everything",
        "allow.*vMenu.God", "vMenu.NoClip",
    };

    private static readonly string[] TxAdminLogToolKeywords = new[]
    {
        "txadmin_log", "txadmin log", "txadmin.log",
        "log_exfil", "log_steal", "log_grab", "log_dump",
        "txadmin_monitor", "remote_log_read", "remotelog",
        "txadmin_parser", "log_parser.*txadmin", "txadmin.*log.*parser",
        "exfiltrat.*log", "steal.*log", "grab.*log",
        "read.*txadmin.*log", "fetch.*txadmin.*log",
    };

    private static readonly string[] RconExploitKeywords = new[]
    {
        "rcon_password", "rcon password", "rconpassword",
        "rcon_exploit", "rcon.*fivem", "fivem.*rcon",
        "rcon.*stop", "rcon.*start", "rcon.*restart",
        "rcon.*kick", "rcon.*ban", "rcon.*quit",
        "rcon.*resource", "rcon.*inject",
        "RconCommand", "send_rcon", "rcon_send",
        "source_rcon", "srcds_rcon",
    };

    private static readonly string[] DatabaseManipulationKeywords = new[]
    {
        "citizen.db", "players.db", "txadmin.db",
        "DELETE FROM bans", "DELETE FROM players",
        "UPDATE bans SET", "DROP TABLE bans",
        "remove_ban", "delete_ban", "unban_player",
        "INSERT INTO players", "UPDATE players SET",
        "ALTER TABLE bans", "txadmin.*sqlite",
        "ban_removal", "db_manipulat", "database.*ban",
    };

    private static readonly string[] EsxQbAdminPatterns = new[]
    {
        "addToGroup", "add_to_group", "setGroup",
        "setJob.*admin", "set_job.*admin",
        "addPermission.*admin", "addPermission.*superadmin",
        "esx_addToGroup", "qb_addToGroup",
        "TriggerServerEvent.*addToGroup",
        "SetPlayerAce.*admin", "addAce.*admin",
        "admin_job_exploit", "setrank.*admin",
        "ESX.SetPlayerJob.*admin", "player.setGroup",
        "addPrincipal.*admin", "set_player_group",
    };

    private static readonly string[] FalseBanKeywords = new[]
    {
        "ban_bomb", "mass_ban", "massBan", "bulk_ban",
        "fake_ban", "false_ban", "ban_all", "ban_everyone",
        "ban_exploit", "banall", "ban_flood",
        "txadmin.*ban.*loop", "loop.*ban",
        "fabricate.*ban", "fake_evidence",
        "ban_evidence", "forge_ban", "ban_grief",
        "api.*ban.*mass", "batch_ban",
    };

    private static readonly string[] ImpersonationPatterns = new[]
    {
        "spoof.*identifier", "fake.*identifier", "fake_license",
        "license.*spoof", "identifier_spoof", "spoof_admin",
        "fake_admin_id", "admin_impersonat",
        "generate.*license", "fake_license_hash",
        "SetPlayerIdentifier", "spoofLicense",
        "identifier.*bypass", "license_bypass",
        "cfx_identifier_spoof", "steam_identifier_fake",
        "discord_identifier_fake", "ip_identifier_spoof",
    };

    private static readonly string[] BruteForceKeywords = new[]
    {
        "txadmin.*brute", "brute.*txadmin",
        "txadmin.*wordlist", "txadmin.*password.*list",
        "txadmin_bruteforce", "txadmin_crack",
        "panel_bruteforce", "admin_bruteforce",
        "txadmin_default_password", "txadmin_password_crack",
        "cfxre_brute", "txadmin.*hydra", "txadmin.*medusa",
        "txadmin_login_flood", "login.*flood.*txadmin",
        "password_spray.*txadmin",
    };

    private static readonly string[] ServerCrashKeywords = new[]
    {
        "crash.*txadmin", "txadmin.*crash",
        "crash.*server.*command", "command_injection.*txadmin",
        "resource_stop.*loop", "loop.*resource.*stop",
        "malformed.*command.*txadmin", "txadmin.*inject.*command",
        "crash_server_via_api", "txadmin_dos",
        "denial_of_service.*fivem", "fivem.*dos.*txadmin",
        "txadmin.*null.*command", "txadmin.*overflow",
        "stop.*all.*resources", "resource.*stop.*bomb",
    };

    private static readonly string[] BrowserHistoryAttackKeywords = new[]
    {
        "txadmin exploit", "bypass txadmin", "txadmin api abuse",
        "fivem admin panel hack", "txadmin vulnerability",
        "txadmin token steal", "txadmin session steal",
        "txadmin brute force", "txadmin crack",
        "how to hack txadmin", "txadmin bypass",
        "txadmin password crack", "fivem panel exploit",
        "txadmin csrf", "txadmin rce",
        "txadmin auth bypass", "cfx admin exploit",
        "txadmin zero day", "fivem admin hack",
    };

    private static readonly string[] WebhookAbuseKeywords = new[]
    {
        "txadmin_webhook", "txadmin.*webhook.*fake",
        "fake.*ban.*webhook", "discord.*webhook.*txadmin",
        "webhook_abuse", "webhook_flood",
        "txadmin.*discord.*token", "forge.*webhook",
        "fake_notification.*txadmin", "ban_notification.*fake",
        "webhook_spam", "txadmin_webhook_steal",
        "TXADMIN_DISCORD_WEBHOOK", "discord_webhook.*cfx",
    };

    private static readonly string[] ServerConfigStealKeywords = new[]
    {
        "server.cfg", "resources.cfg", "server-data",
        "download.*server.cfg", "steal.*server.cfg",
        "exfiltrat.*server.cfg", "grab.*server.cfg",
        "fetch.*server.cfg", "read.*server.cfg",
        "server_cfg_steal", "config_dump",
        "server_data_dump", "server_resources_steal",
        "copy.*server.cfg", "extract.*server.cfg",
        "download.*resources.cfg",
    };

    private static readonly string[] SessionHijackKeywords = new[]
    {
        "txadmin.*cookie.*steal", "session_hijack.*txadmin",
        "txadmin.*browser.*cookie", "steal.*session.*txadmin",
        "cookie_grabber.*txadmin", "txadmin_session_steal",
        "chrome.cookies.*txadmin", "browser_session.*txadmin",
        "extension.*txadmin.*cookie", "content_script.*txadmin",
        "document.cookie.*txadmin", "localStorage.*txadmin",
        "sessionStorage.*txadmin", "IndexedDB.*txadmin",
    };

    private static readonly string[] ExploitDownloadNames = new[]
    {
        "txadmin_exploit", "txadmin_poc", "panel_bypass",
        "admin_stealer", "txadmin_hack", "txadmin_crack",
        "fivem_admin_exploit", "cfx_exploit", "txadmin_rce",
        "txadmin_cve", "panel_hack", "txadmin_vuln",
        "fivem_panel_hack", "txadmin_bypass",
        "admin_panel_exploit", "cfxre_exploit",
        "txadmin_zero_day", "txadmin-exploit",
        "panel-bypass", "admin-stealer",
    };

    private static readonly string[] RegistryExploitToolNames = new[]
    {
        "txadmin_exploit", "panel_stealer", "admin_stealer",
        "txadmin_crack", "txadmin_bypass", "cfx_token_steal",
        "txadmin_hack", "panel_bypass", "fivem_admin_hack",
        "txadmin_brute", "txadmin_rce", "admin_impersonator",
        "txadmin_grab", "cfxre_exploit", "txadmin_poc",
    };

    private static readonly string[] TxAdminEnvFileKeywords = new[]
    {
        "TXADMIN_TOKEN", "TXADMIN_SESSION", "TXADMIN_PASSWORD",
        "CFX_TOKEN", "CFX_AUTH_TOKEN", "CFXRE_TOKEN",
        "TXADMIN_SECRET", "TXADMIN_KEY", "ADMIN_TOKEN",
        "txadmin_token=", "txadmin_session=", "cfx_token=",
    };

    // ─── RunAsync ─────────────────────────────────────────────────────────────

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckCredentialStealerTools(ctx, ct),
            CheckSessionTokenArtifacts(ctx, ct),
            CheckApiAbuseScripts(ctx, ct),
            CheckVMenuPermissionBypass(ctx, ct),
            CheckLogAccessTools(ctx, ct),
            CheckRconExploitation(ctx, ct),
            CheckDatabaseManipulationTools(ctx, ct),
            CheckEsxQbCoreAdminExploitation(ctx, ct),
            CheckFalseBanCreationTools(ctx, ct),
            CheckAdminImpersonationArtifacts(ctx, ct),
            CheckBruteForceArtifacts(ctx, ct),
            CheckServerCrashArtifacts(ctx, ct),
            CheckBrowserHistoryForAttackResearch(ctx, ct),
            CheckWebhookAbuseScripts(ctx, ct),
            CheckServerConfigStealing(ctx, ct),
            CheckSessionHijackingTools(ctx, ct),
            CheckRegistryTracesForAbuseTools(ctx, ct),
            CheckExploitDownloadHistory(ctx, ct)
        );
    }

    // ─── Sub-checks ──────────────────────────────────────────────────────────

    // Check 1 — txAdmin credential stealing tools
    private Task CheckCredentialStealerTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string temp        = Environment.GetEnvironmentVariable("TEMP") ??
                             Environment.GetEnvironmentVariable("TMP") ??
                             Path.Combine(userProfile, "AppData", "Local", "Temp");
        string desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string downloads   = Path.Combine(userProfile, "Downloads");

        string[] searchDirs = new[] { downloads, desktop, temp };
        string[] execExtensions = new[] { ".exe", ".bat", ".cmd", ".ps1", ".py", ".vbs", ".js" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string ext      = Path.GetExtension(file);
                bool isExec     = execExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase);
                string fileName = Path.GetFileName(file);

                foreach (string stealerName in CredentialStealerNames)
                {
                    if (!fileName.Contains(stealerName, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin Credential Stealer — Ausfuehrbares Werkzeug",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Dateiname entspricht bekanntem txAdmin-Credential-Stealing-Werkzeug: '{stealerName}'. " +
                                   "Solche Werkzeuge extrahieren txAdmin-Sitzungstoken, Admin-Panel-Zugangsdaten " +
                                   "oder cfx.re-Authentifizierungstoken vom lokalen System.",
                        Detail   = $"Verzeichnis: {dir} | Erweiterung: {ext} | Typ: {(isExec ? "ausfuehrbar" : "Skript")}"
                    });
                    break;
                }

                if (!isExec) continue;

                // Deep content scan for executables and scripts
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasStealerKeyword = CredentialStealerNames.Any(n =>
                        content.Contains(n, StringComparison.OrdinalIgnoreCase));
                    bool hasTxAdminRef = content.Contains("txadmin", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("txAdmin", StringComparison.OrdinalIgnoreCase);
                    bool hasTokenRef   = content.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("cookie", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("credential", StringComparison.OrdinalIgnoreCase);

                    if (hasStealerKeyword && hasTxAdminRef && hasTokenRef)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "txAdmin Credential Stealer — Inhalt erkannt",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = "Dateiinhalt enthaelt Kombination aus txAdmin-Referenzen, " +
                                       "Credential-Stealer-Mustern und Token-/Cookie-Zugriffen. " +
                                       "Starker Hinweis auf ein txAdmin-Credential-Harvesting-Werkzeug.",
                            Detail   = $"Verzeichnis: {dir}"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    // Check 2 — txAdmin session token artifacts
    private Task CheckSessionTokenArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appDataLocal  = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appDataRoam   = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string desktop       = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string documents     = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        string temp          = Environment.GetEnvironmentVariable("TEMP") ??
                               Path.Combine(appDataLocal, "Temp");

        string[] searchDirs = new[]
        {
            desktop, documents, temp,
            Path.Combine(userProfile, "Downloads"),
            appDataLocal,
            appDataRoam,
        };

        string[] tokenExtensions = new[]
        {
            ".txt", ".json", ".log", ".ini", ".cfg", ".env",
            ".xml", ".yaml", ".yml", ".toml", ".conf",
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string ext      = Path.GetExtension(file);
                string fileName = Path.GetFileName(file);

                // Always scan .env files for TXADMIN_TOKEN
                bool isEnvFile = fileName.Equals(".env", StringComparison.OrdinalIgnoreCase) ||
                                 fileName.StartsWith(".env.", StringComparison.OrdinalIgnoreCase) ||
                                 ext.Equals(".env", StringComparison.OrdinalIgnoreCase);

                if (!isEnvFile && !tokenExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
                    continue;

                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    // .env file — check for TXADMIN_TOKEN specifically
                    if (isEnvFile)
                    {
                        foreach (string envKw in TxAdminEnvFileKeywords)
                        {
                            if (!content.Contains(envKw, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = ".env-Datei — TXADMIN_TOKEN erkannt",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason   = $".env-Datei enthaelt txAdmin-Authentifizierungsschluessel: '{envKw}'. " +
                                           "txAdmin-Token in Konfigurationsdateien ausserhalb des Servers " +
                                           "deuten auf Credential-Diebstahl oder unerlaubte Konfiguration hin.",
                                Detail   = $"Schluessel: {envKw} | Verzeichnis: {dir}"
                            });
                            break;
                        }
                        continue;
                    }

                    // General token artifact scan
                    foreach (string tokenKw in SessionTokenKeywords)
                    {
                        if (!content.Contains(tokenKw, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "txAdmin Sitzungstoken-Artefakt erkannt",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Datei enthaelt txAdmin-Sitzungstoken-Muster: '{tokenKw}'. " +
                                       "txAdmin-Session-Cookies und Admin-Token ausserhalb des Servers " +
                                       "sind Indikatoren fuer Credential-Harvesting oder Token-Diebstahl.",
                            Detail   = $"Muster: {tokenKw} | Verzeichnis: {dir}"
                        });
                        break;
                    }
                }
                catch { }
            }
        }
    }, ct);

    // Check 3 — txAdmin API abuse scripts
    private Task CheckApiAbuseScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string documents   = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        string temp        = Environment.GetEnvironmentVariable("TEMP") ??
                             Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");

        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"), desktop, documents, temp,
        };

        string[] scriptExtensions = new[]
        {
            ".ps1", ".py", ".js", ".ts", ".sh", ".bat", ".cmd", ".rb",
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
            catch { continue; }

            int scanned = 0;
            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;
                if (scanned > 400) break;

                string ext = Path.GetExtension(file);
                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                scanned++;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasApiEndpoint = ApiAbuseEndpoints.Any(ep =>
                        content.Contains(ep, StringComparison.OrdinalIgnoreCase));
                    if (!hasApiEndpoint) continue;

                    bool hasCheatContext = ApiAbuseCheatContext.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    bool hasTxAdminRef = content.Contains("txadmin", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("cfx.re", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("fivem", StringComparison.OrdinalIgnoreCase);

                    if (!hasTxAdminRef && !hasCheatContext) continue;

                    string matchedEndpoint = ApiAbuseEndpoints.First(ep =>
                        content.Contains(ep, StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin API-Missbrauch-Skript erkannt",
                        Risk     = hasCheatContext ? RiskLevel.Critical : RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Skript ruft txAdmin-REST-API-Endpunkt auf: '{matchedEndpoint}'. " +
                                   (hasCheatContext
                                       ? "Datei enthaelt zusaetzlich Cheat-/Missbrauchskontext. "
                                       : "") +
                                   "Skripte die txAdmin-API-Endpunkte automatisiert aufrufen deuten " +
                                   "auf Versuche hin, das Admin-Panel unbefugt zu steuern.",
                        Detail   = $"Endpunkt: {matchedEndpoint} | Erweiterung: {ext} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 4 — vMenu permission bypass artifacts
    private Task CheckVMenuPermissionBypass(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, @"AppData\Local\FiveM"),
            Path.Combine(userProfile, @"AppData\Roaming\CitizenFX"),
        };

        string[] cfgExtensions = new[] { ".cfg", ".lua", ".txt", ".ini", ".conf" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
            catch { continue; }

            int scanned = 0;
            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;
                if (scanned > 300) break;

                string ext      = Path.GetExtension(file);
                string fileName = Path.GetFileName(file);
                bool isCfgFile  = fileName.Equals("permissions.cfg", StringComparison.OrdinalIgnoreCase) ||
                                  fileName.Equals("vMenu.cfg", StringComparison.OrdinalIgnoreCase) ||
                                  fileName.Equals("vmenu.cfg", StringComparison.OrdinalIgnoreCase) ||
                                  cfgExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase);

                if (!isCfgFile) continue;
                scanned++;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (string pattern in VMenuPermissionPatterns)
                    {
                        if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "vMenu Permission-Bypass-Artefakt erkannt",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Konfigurationsdatei enthaelt vMenu-Berechtigungs-Missbrauchmuster: '{pattern}'. " +
                                       "Ace-Berechtigungen die 'all.x' oder 'everyone' an Nicht-Admin-Identifikatoren " +
                                       "vergeben, sind typische Muster fuer vMenu-Privilege-Escalation-Angriffe.",
                            Detail   = $"Muster: {pattern} | Datei: {fileName} | Verzeichnis: {dir}"
                        });
                        break;
                    }
                }
                catch { }
            }
        }
    }, ct);

    // Check 5 — txAdmin log access tools
    private Task CheckLogAccessTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string temp        = Environment.GetEnvironmentVariable("TEMP") ??
                             Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");
        string desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string downloads   = Path.Combine(userProfile, "Downloads");

        string[] searchDirs = new[] { downloads, desktop, temp };
        string[] scriptExtensions = new[] { ".ps1", ".py", ".js", ".bat", ".cmd", ".sh", ".rb", ".go" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string ext      = Path.GetExtension(file);
                string fileName = Path.GetFileName(file);

                // Name-based check first
                bool nameMatch = TxAdminLogToolKeywords.Any(kw =>
                    fileName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (nameMatch)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin Log-Zugriffswerkzeug — Dateiname",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = "Dateiname entspricht Muster eines txAdmin-Log-Zugriffs- oder " +
                                   "Log-Exfiltrationswerkzeugs. Solche Werkzeuge lesen txAdmin-Protokolle " +
                                   "aus der Ferne oder uebertragen sie ohne Genehmigung.",
                        Detail   = $"Verzeichnis: {dir}"
                    });
                    continue;
                }

                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasLogTool = TxAdminLogToolKeywords.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    bool hasTxAdmin = content.Contains("txadmin", StringComparison.OrdinalIgnoreCase);

                    if (!hasLogTool || !hasTxAdmin) continue;

                    string matchedKw = TxAdminLogToolKeywords.First(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin Log-Zugriffswerkzeug — Inhalt erkannt",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Skript enthaelt Muster eines txAdmin-Log-Zugriffs- oder Exfiltrationswerkzeugs: '{matchedKw}'. " +
                                   "Werkzeuge die txAdmin-Logs remote lesen oder exfiltrieren umgehen " +
                                   "Zugriffskontrollen auf vertrauliche Serverprotokolle.",
                        Detail   = $"Muster: {matchedKw} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 6 — FiveM RCON exploitation
    private Task CheckRconExploitation(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetEnvironmentVariable("TEMP") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        string[] scriptExtensions = new[] { ".py", ".ps1", ".js", ".bat", ".cmd", ".sh", ".rb", ".go", ".txt", ".cfg" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string ext = Path.GetExtension(file);
                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasRcon    = content.Contains("rcon", StringComparison.OrdinalIgnoreCase);
                    bool hasFiveM   = content.Contains("fivem", StringComparison.OrdinalIgnoreCase) ||
                                     content.Contains("cfx", StringComparison.OrdinalIgnoreCase) ||
                                     content.Contains("citizenfx", StringComparison.OrdinalIgnoreCase);

                    if (!hasRcon || !hasFiveM) continue;

                    string? matchedKw = RconExploitKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "FiveM RCON-Exploit-Skript erkannt",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Skript enthaelt RCON-Exploitationsmuster fuer FiveM: '{matchedKw}'. " +
                                   "RCON-Skripte fuer FiveM werden zum unerlaubten Senden von Server-Befehlen " +
                                   "verwendet (Ressourcen stoppen/starten, Spieler kicken/bannen).",
                        Detail   = $"Muster: {matchedKw} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 7 — txAdmin database manipulation tools
    private Task CheckDatabaseManipulationTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        string[] dataExtensions = new[]
        {
            ".py", ".sql", ".ps1", ".bat", ".cmd", ".js", ".sh", ".rb", ".txt",
        };

        // Also check for SQLite DB files with suspicious names
        string[] suspiciousDbNames = new[]
        {
            "citizen.db", "players.db", "txadmin.db",
            "bans.db", "fivem_players.db",
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string fileName = Path.GetFileName(file);
                string ext      = Path.GetExtension(file);

                // Check for suspicious DB file copies
                bool isSuspiciousDb = suspiciousDbNames.Any(db =>
                    fileName.Equals(db, StringComparison.OrdinalIgnoreCase));

                if (isSuspiciousDb)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin/FiveM Datenbank-Kopie ausserhalb des Servers",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"SQLite-Datenbankdatei '{fileName}' ausserhalb des FiveM-Serververzeichnisses gefunden. " +
                                   "citizen.db/players.db enthalten Spieler-Bans und -Daten — " +
                                   "Kopien ausserhalb des Servers deuten auf Datenbankextraktion hin.",
                        Detail   = $"Verzeichnis: {dir}"
                    });
                    continue;
                }

                if (!dataExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string? matchedKw = DatabaseManipulationKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    bool hasDbName = suspiciousDbNames.Any(db =>
                        content.Contains(db, StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin Datenbankmanipulations-Skript erkannt",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Skript enthaelt SQL/Datenbankmanipulationsmuster fuer txAdmin-Datenbanken: '{matchedKw}'. " +
                                   "Skripte die Bans aus citizen.db/players.db loeschen oder Spielerdaten " +
                                   "manipulieren, werden fuer illegale Ban-Umgehung eingesetzt.",
                        Detail   = $"Muster: {matchedKw} | Datenbankreferenz: {(hasDbName ? "ja" : "nein")} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 8 — ESX/QBCore admin permission exploitation
    private Task CheckEsxQbCoreAdminExploitation(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        string[] scriptExtensions = new[] { ".lua", ".py", ".js", ".sql", ".ps1", ".bat", ".sh" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
            catch { continue; }

            int scanned = 0;
            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;
                if (scanned > 300) break;

                string ext = Path.GetExtension(file);
                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                scanned++;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string? matchedKw = EsxQbAdminPatterns.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    bool hasEsxQb = content.Contains("ESX", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("QBCore", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("qb-core", StringComparison.OrdinalIgnoreCase) ||
                                   content.Contains("esx_", StringComparison.OrdinalIgnoreCase);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "ESX/QBCore Admin-Berechtigungs-Exploit erkannt",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Skript enthaelt ESX/QBCore-Admin-Berechtigungs-Exploitmuster: '{matchedKw}'. " +
                                   "Solche Skripte gewaehren sich selbst Admin-Rang/-Job ueber Datenbankmanipulation " +
                                   "oder API-Aufrufe — klassische Privilege-Escalation in FiveM-Frameworks.",
                        Detail   = $"Muster: {matchedKw} | ESX/QBCore-Referenz: {(hasEsxQb ? "ja" : "nein")} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 9 — False ban creation tools
    private Task CheckFalseBanCreationTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetEnvironmentVariable("TEMP") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        string[] scriptExtensions = new[] { ".py", ".js", ".ps1", ".bat", ".cmd", ".sh", ".rb", ".lua" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string ext      = Path.GetExtension(file);
                string fileName = Path.GetFileName(file);

                bool nameMatch = FalseBanKeywords.Any(kw =>
                    fileName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (nameMatch)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Massenbann-/Falschbann-Werkzeug erkannt",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = "Dateiname entspricht Massenban- oder Falschbann-Werkzeugmuster. " +
                                   "Ban-Bombing-Werkzeuge missbrauchen die txAdmin-API um Spieler " +
                                   "massenhaft zu bannen oder gefaelschte Bannbeweise zu fabrizieren.",
                        Detail   = $"Verzeichnis: {dir}"
                    });
                    continue;
                }

                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string? matchedKw = FalseBanKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    bool hasTxAdmin = content.Contains("txadmin", StringComparison.OrdinalIgnoreCase) ||
                                     content.Contains("/api/players/ban", StringComparison.OrdinalIgnoreCase);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Massenbann-/Falschbann-Skript — Inhalt erkannt",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Skript enthaelt Massenbann- oder Falschbann-Muster: '{matchedKw}'. " +
                                   (hasTxAdmin
                                       ? "Skript referenziert txAdmin-API — Massenbann-Angriff ueber Panel-API. "
                                       : "") +
                                   "Ban-Bombing-Werkzeuge sabotieren Server durch massenhaftes Bannen von Spielern.",
                        Detail   = $"Muster: {matchedKw} | txAdmin-Referenz: {(hasTxAdmin ? "ja" : "nein")} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 10 — Admin impersonation artifacts
    private Task CheckAdminImpersonationArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        string[] scriptExtensions = new[] { ".py", ".js", ".lua", ".ps1", ".bat", ".sh", ".rb" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
            catch { continue; }

            int scanned = 0;
            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;
                if (scanned > 300) break;

                string ext      = Path.GetExtension(file);
                string fileName = Path.GetFileName(file);

                bool nameMatch = ImpersonationPatterns.Any(kw =>
                    fileName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (nameMatch)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Admin-Identitaets-Spoofing-Werkzeug — Dateiname",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = "Dateiname entspricht Admin-Impersonations- oder Identifier-Spoofing-Muster. " +
                                   "Werkzeuge zum Faelschen von FiveM-Identifikatoren werden genutzt, um " +
                                   "Admin-Zugangsberechtigungen zu umgehen.",
                        Detail   = $"Verzeichnis: {dir}"
                    });
                    continue;
                }

                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;
                scanned++;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string? matchedKw = ImpersonationPatterns.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Admin-Impersonations-Artefakt — Inhalt erkannt",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Skript enthaelt Identifier-Spoofing- oder Admin-Impersonationsmuster: '{matchedKw}'. " +
                                   "Fake-Lizenz-Hash-Generatoren und Identifier-Spoofing-Skripte taeuschen " +
                                   "FiveM-Server ueber die Identitaet des Spielers hinweg.",
                        Detail   = $"Muster: {matchedKw} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 11 — txAdmin password brute-force artifacts
    private Task CheckBruteForceArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetEnvironmentVariable("TEMP") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        string[] scriptExtensions = new[] { ".py", ".bat", ".cmd", ".ps1", ".sh", ".rb", ".go" };
        string[] wordlistExtensions = new[] { ".txt", ".lst", ".wordlist", ".dict" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string ext      = Path.GetExtension(file);
                string fileName = Path.GetFileName(file);

                // Name-based check
                bool nameMatch = BruteForceKeywords.Any(kw =>
                    fileName.Contains(kw, StringComparison.OrdinalIgnoreCase));
                if (nameMatch)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin Brute-Force-Artefakt — Dateiname",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = "Dateiname entspricht txAdmin-Passwort-Brute-Force-Werkzeugmuster. " +
                                   "Brute-Force-Skripte versuchen txAdmin-Login-Zugangsdaten durch " +
                                   "automatisierte Passworttests zu erraten.",
                        Detail   = $"Verzeichnis: {dir}"
                    });
                    continue;
                }

                // Wordlist check: text files containing txAdmin default credentials
                if (wordlistExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasTxAdminCred = (content.Contains("txadmin", StringComparison.OrdinalIgnoreCase) ||
                                               content.Contains("changeme", StringComparison.OrdinalIgnoreCase)) &&
                                              content.Contains("admin", StringComparison.OrdinalIgnoreCase);
                        bool isWordlist = content.Split('\n').Length > 10;

                        if (hasTxAdminCred && isWordlist)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "txAdmin Brute-Force-Woerterbuch erkannt",
                                Location = file,
                                FileName = fileName,
                                Risk     = RiskLevel.High,
                                Reason   = "Woerterbuchdatei enthaelt txAdmin-Standardpasswoerter oder " +
                                           "Admin-Panel-Credential-Eintraege. Wird fuer txAdmin-Passwort-Angriffe verwendet.",
                                Detail   = $"Verzeichnis: {dir} | Eintraege (ca.): {content.Split('\n').Length}"
                            });
                        }
                    }
                    catch { }
                    continue;
                }

                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;
                ctx.IncrementFiles();

                try
                {
                    using var fs2 = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr2 = new StreamReader(fs2);
                    string content2 = await sr2.ReadToEndAsync(ct);

                    string? matchedKw = BruteForceKeywords.FirstOrDefault(kw =>
                        content2.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin Brute-Force-Skript — Inhalt erkannt",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Skript enthaelt txAdmin-Brute-Force-Muster: '{matchedKw}'. " +
                                   "Automatisierte Login-Angriffe auf das txAdmin-Panel gefaehrden " +
                                   "die Sicherheit des gesamten FiveM-Servers.",
                        Detail   = $"Muster: {matchedKw} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 12 — Server crash via txAdmin artifacts
    private Task CheckServerCrashArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetEnvironmentVariable("TEMP") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        string[] scriptExtensions = new[] { ".py", ".js", ".ps1", ".bat", ".cmd", ".sh", ".lua", ".rb" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string ext = Path.GetExtension(file);
                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string? matchedKw = ServerCrashKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    bool hasTxAdmin = content.Contains("txadmin", StringComparison.OrdinalIgnoreCase) ||
                                     content.Contains("fivem", StringComparison.OrdinalIgnoreCase);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Server-Crash-via-txAdmin-Artefakt erkannt",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Skript enthaelt Server-Crash-Muster via txAdmin: '{matchedKw}'. " +
                                   "Skripte die txAdmin fuer Command-Injection, Ressourcen-Stop-Schleifen " +
                                   "oder DoS-Angriffe missbrauchen, gefaehrden den gesamten Server.",
                        Detail   = $"Muster: {matchedKw} | txAdmin/FiveM-Referenz: {(hasTxAdmin ? "ja" : "nein")} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 13 — Browser history for txAdmin attack research
    private Task CheckBrowserHistoryForAttackResearch(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData  = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // Chromium-family history databases
        var historyDbs = new List<(string browser, string path)>();

        var chromiumRoots = new[]
        {
            ("Chrome",   Path.Combine(localAppData,  "Google", "Chrome", "User Data")),
            ("Edge",     Path.Combine(localAppData,  "Microsoft", "Edge", "User Data")),
            ("Brave",    Path.Combine(localAppData,  "BraveSoftware", "Brave-Browser", "User Data")),
            ("Vivaldi",  Path.Combine(localAppData,  "Vivaldi", "User Data")),
        };

        foreach (var (browser, root) in chromiumRoots)
        {
            if (!Directory.Exists(root)) continue;
            string[] profiles = Array.Empty<string>();
            try { profiles = Directory.GetDirectories(root); } catch { continue; }
            foreach (string prof in profiles)
            {
                var db = Path.Combine(prof, "History");
                if (File.Exists(db)) historyDbs.Add((browser, db));
            }
        }

        // Firefox
        string ffProfiles = Path.Combine(roamingAppData, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(ffProfiles))
        {
            string[] profs = Array.Empty<string>();
            try { profs = Directory.GetDirectories(ffProfiles); } catch { }
            foreach (string prof in profs)
            {
                var db = Path.Combine(prof, "places.sqlite");
                if (File.Exists(db)) historyDbs.Add(("Firefox", db));
            }
        }

        // Read history as plain text (copy-then-read to handle locked file)
        foreach (var (browser, dbPath) in historyDbs)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            string? tmpPath = null;
            try
            {
                tmpPath = Path.Combine(
                    Path.GetTempPath(),
                    "zt_txadm_hist_" + Guid.NewGuid().ToString("N") + ".tmp");

                File.Copy(dbPath, tmpPath, overwrite: true);

                using var fs = new FileStream(tmpPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, System.Text.Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: true,
                    bufferSize: 4096,
                    leaveOpen: false);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string kw in BrowserHistoryAttackKeywords)
                {
                    if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Browser-Verlauf — txAdmin-Angriffsrecherche: '{kw}'",
                        Risk     = RiskLevel.High,
                        Location = dbPath,
                        FileName = Path.GetFileName(dbPath),
                        Reason   = $"Browser-Verlauf enthaelt Suchanfrage/URL mit txAdmin-Angriffsrecherche-Muster: '{kw}'. " +
                                   "Besuche von Seiten zu txAdmin-Exploits, API-Missbrauch oder Panel-Hacking " +
                                   "deuten auf Vorbereitung eines Angriffs hin.",
                        Detail   = $"Browser: {browser} | Verlaufsdatei: {dbPath}"
                    });
                    break;
                }
            }
            catch { }
            finally
            {
                if (tmpPath is not null)
                    try { File.Delete(tmpPath); } catch { }
            }
        }
    }, ct);

    // Check 14 — txAdmin webhook abuse
    private Task CheckWebhookAbuseScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        string[] scriptExtensions = new[] { ".py", ".js", ".ps1", ".bat", ".sh", ".lua", ".rb", ".txt", ".json" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string ext      = Path.GetExtension(file);
                string fileName = Path.GetFileName(file);
                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasWebhook = content.Contains("webhook", StringComparison.OrdinalIgnoreCase) &&
                                     content.Contains("discord.com/api/webhooks", StringComparison.OrdinalIgnoreCase);

                    string? matchedKw = WebhookAbuseKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null && !hasWebhook) continue;

                    bool hasTxAdmin = content.Contains("txadmin", StringComparison.OrdinalIgnoreCase) ||
                                     content.Contains("ban_notification", StringComparison.OrdinalIgnoreCase);

                    if (matchedKw is null && !hasTxAdmin) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin Webhook-Missbrauch-Artefakt erkannt",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = (matchedKw is not null
                            ? $"Skript enthaelt txAdmin-Webhook-Missbrauchsmuster: '{matchedKw}'. "
                            : "Skript sendet Discord-Webhook-Anfragen mit txAdmin-Kontext. ") +
                                   "Gefälschte Ban-Benachrichtigungen via txAdmin-Webhooks " +
                                   "oder extrahierte Webhook-URLs werden fuer Social-Engineering missbraucht.",
                        Detail   = $"Muster: {matchedKw ?? "webhook + txadmin"} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 15 — FiveM server config stealing
    private Task CheckServerConfigStealing(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetEnvironmentVariable("TEMP") ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        string[] scriptExtensions = new[] { ".py", ".js", ".ps1", ".bat", ".sh", ".rb", ".go", ".lua" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string ext      = Path.GetExtension(file);
                string fileName = Path.GetFileName(file);
                if (!scriptExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string? matchedKw = ServerConfigStealKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    bool hasStealContext = content.Contains("steal", StringComparison.OrdinalIgnoreCase) ||
                                          content.Contains("exfiltrat", StringComparison.OrdinalIgnoreCase) ||
                                          content.Contains("download", StringComparison.OrdinalIgnoreCase) ||
                                          content.Contains("grab", StringComparison.OrdinalIgnoreCase) ||
                                          content.Contains("dump", StringComparison.OrdinalIgnoreCase);

                    if (!hasStealContext) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "FiveM Server-Config-Diebstahl-Skript erkannt",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Skript enthaelt Server-Konfigurationsdiebstahl-Muster: '{matchedKw}' " +
                                   "kombiniert mit Datenexfiltrations-Kontext. Skripte die server.cfg oder " +
                                   "resources.cfg ohne Genehmigung herunterladen, stehlen vertrauliche " +
                                   "Serverkonfigurationen inklusive Passwoerter und API-Schluessel.",
                        Detail   = $"Muster: {matchedKw} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 16 — txAdmin panel session hijacking tools
    private Task CheckSessionHijackingTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        // Browser extension paths
        var extensionPaths = new List<string>();

        string[] browserExtDirs = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Extensions"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Extensions"),
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Extensions"),
        };

        foreach (string extDir in browserExtDirs)
        {
            if (!Directory.Exists(extDir)) continue;
            string[] extSubDirs = Array.Empty<string>();
            try { extSubDirs = Directory.GetDirectories(extDir); } catch { continue; }
            extensionPaths.AddRange(extSubDirs);
        }

        // Scan extension manifests and content scripts
        foreach (string extPath in extensionPaths)
        {
            if (ct.IsCancellationRequested) return;

            string[] extFiles = Array.Empty<string>();
            try { extFiles = Directory.GetFiles(extPath, "*", SearchOption.AllDirectories); } catch { continue; }

            foreach (string file in extFiles)
            {
                if (ct.IsCancellationRequested) return;

                string ext      = Path.GetExtension(file);
                string fileName = Path.GetFileName(file);
                bool isJs       = ext.Equals(".js", StringComparison.OrdinalIgnoreCase);
                bool isJson     = ext.Equals(".json", StringComparison.OrdinalIgnoreCase);
                if (!isJs && !isJson) continue;

                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string? matchedKw = SessionHijackKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Browser-Erweiterung — txAdmin Session-Hijacking",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Browser-Erweiterungsskript enthaelt txAdmin-Session-Hijacking-Muster: '{matchedKw}'. " +
                                   "Boeswillige Browsererweiterungen koennen txAdmin-Sitzungscookies " +
                                   "aus dem Browser des Administrators stehlen.",
                        Detail   = $"Erweiterungspfad: {extPath} | Muster: {matchedKw}"
                    });
                    break;
                }
                catch { }
            }
        }

        // Also scan Downloads and Desktop for standalone session hijack scripts
        string[] standaloneSearchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        foreach (string dir in standaloneSearchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*.js", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string? matchedKw = SessionHijackKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin Session-Hijacking-Skript erkannt",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"JavaScript-Datei enthaelt txAdmin-Session-Hijacking-Muster: '{matchedKw}'. " +
                                   "Standalone-Session-Hijacking-Skripte zielen darauf ab, " +
                                   "txAdmin-Sitzungsdaten aus dem Browser zu extrahieren.",
                        Detail   = $"Muster: {matchedKw} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    // Check 17 — Registry traces for txAdmin abuse tools
    private Task CheckRegistryTracesForAbuseTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        // UserAssist (encoded program execution history under HKCU)
        CheckUserAssistForTxAdminTools(ctx);

        // MuiCache (recently executed programs)
        CheckMuiCacheForTxAdminTools(ctx);

        // Run / RunOnce keys
        CheckRunKeysForTxAdminTools(ctx);
    }, ct);

    private void CheckUserAssistForTxAdminTools(ScanContext ctx)
    {
        const string userAssistPath =
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

        try
        {
            using var userAssistKey = Registry.CurrentUser.OpenSubKey(userAssistPath);
            if (userAssistKey is null) return;

            foreach (string guidName in userAssistKey.GetSubKeyNames())
            {
                try
                {
                    using var guidKey = userAssistKey.OpenSubKey(guidName + @"\Count");
                    if (guidKey is null) continue;

                    foreach (string valueName in guidKey.GetValueNames())
                    {
                        ctx.IncrementRegistryKeys();

                        // UserAssist values are ROT13-encoded
                        string decodedName = Rot13(valueName);

                        bool isMatch = RegistryExploitToolNames.Any(toolName =>
                            decodedName.Contains(toolName, StringComparison.OrdinalIgnoreCase));

                        if (!isMatch) continue;

                        string matchedTool = RegistryExploitToolNames.First(t =>
                            decodedName.Contains(t, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "UserAssist — txAdmin-Exploit-Werkzeug ausgefuehrt",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{userAssistPath}\{guidName}\Count",
                            FileName = decodedName,
                            Reason   = $"UserAssist-Registry enthaelt Ausfuehrungshistorie fuer txAdmin-Exploit-Werkzeug: '{matchedTool}'. " +
                                       "UserAssist protokolliert in Windows automatisch ausgefuehrte Programme — " +
                                       "ein Eintrag beweist, dass das Werkzeug auf diesem System gestartet wurde.",
                            Detail   = $"UserAssist-Pfad: {userAssistPath}\\{guidName} | Dekodiert: {decodedName}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckMuiCacheForTxAdminTools(ScanContext ctx)
    {
        const string muiCachePath =
            @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

        try
        {
            using var muiKey = Registry.CurrentUser.OpenSubKey(muiCachePath);
            if (muiKey is null) return;

            foreach (string valueName in muiKey.GetValueNames())
            {
                ctx.IncrementRegistryKeys();

                bool isMatch = RegistryExploitToolNames.Any(toolName =>
                    valueName.Contains(toolName, StringComparison.OrdinalIgnoreCase));

                if (!isMatch) continue;

                string matchedTool = RegistryExploitToolNames.First(t =>
                    valueName.Contains(t, StringComparison.OrdinalIgnoreCase));

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "MuiCache — txAdmin-Exploit-Werkzeug in Ausfuehrungshistorie",
                    Risk     = RiskLevel.High,
                    Location = $@"HKCU\{muiCachePath}",
                    FileName = valueName,
                    Reason   = $"MuiCache-Registryeintrag enthaelt txAdmin-Exploit-Werkzeug: '{matchedTool}'. " +
                               "MuiCache speichert Anzeigenamen ausgefuehrter Anwendungen und beweist " +
                               "die Ausfuehrung des Werkzeugs auf diesem System.",
                    Detail   = $"MuiCache-Wert: {valueName}"
                });
            }
        }
        catch { }
    }

    private void CheckRunKeysForTxAdminTools(ScanContext ctx)
    {
        var runKeyPaths = new[]
        {
            (@"Software\Microsoft\Windows\CurrentVersion\Run",     Registry.CurrentUser),
            (@"Software\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     Registry.LocalMachine),
        };

        foreach (var (keyPath, hive) in runKeyPaths)
        {
            try
            {
                using var key = hive.OpenSubKey(keyPath);
                if (key is null) continue;

                foreach (string valueName in key.GetValueNames())
                {
                    ctx.IncrementRegistryKeys();

                    string val = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    bool nameMatch = RegistryExploitToolNames.Any(t =>
                        valueName.Contains(t, StringComparison.OrdinalIgnoreCase));
                    bool valMatch  = RegistryExploitToolNames.Any(t =>
                        val.Contains(t, StringComparison.OrdinalIgnoreCase));

                    if (!nameMatch && !valMatch) continue;

                    string matchedTool = RegistryExploitToolNames.FirstOrDefault(t =>
                        valueName.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                        val.Contains(t, StringComparison.OrdinalIgnoreCase)) ?? string.Empty;

                    string hiveAbbr = ReferenceEquals(hive, Registry.CurrentUser) ? "HKCU" : "HKLM";

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Run-Key — txAdmin-Exploit-Werkzeug als Autostart eingetragen",
                        Risk     = RiskLevel.Critical,
                        Location = $@"{hiveAbbr}\{keyPath}\{valueName}",
                        FileName = valueName,
                        Reason   = $"Autostart-Registry-Key enthaelt Eintrag fuer txAdmin-Exploit-Werkzeug: '{matchedTool}'. " +
                                   "Ein Run-Key-Eintrag beweist aktive Persistenz — das Werkzeug wird " +
                                   "bei jedem Systemstart automatisch ausgefuehrt.",
                        Detail   = $"Pfad: {hiveAbbr}\\{keyPath} | Wert: {val.Truncate(200)}"
                    });
                }
            }
            catch { }
        }
    }

    // Check 18 — txAdmin exploit download history
    private Task CheckExploitDownloadHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloads   = Path.Combine(userProfile, "Downloads");
        string desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string documents   = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        string[] searchDirs = new[] { downloads, desktop, documents };
        string[] archiveExtensions = new[] { ".zip", ".rar", ".7z", ".tar", ".gz", ".cab" };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            // Scan for downloaded exploit archives by name
            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) return;

                string fileName = Path.GetFileName(file);
                string ext      = Path.GetExtension(file);
                bool isArchive  = archiveExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase);

                bool nameMatch = ExploitDownloadNames.Any(n =>
                    fileName.Contains(n, StringComparison.OrdinalIgnoreCase));

                if (nameMatch)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"txAdmin-Exploit-Download erkannt: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = "Heruntergeladene Datei entspricht Namensschema eines txAdmin-Exploit-Archivs " +
                                   "oder Panel-Bypass-Werkzeugs. Exploit-Archive und Proof-of-Concept-Downloads " +
                                   "sind starke Indikatoren fuer Angriffsvorbereitung.",
                        Detail   = $"Typ: {(isArchive ? "Archiv" : "Datei")} | Verzeichnis: {dir}"
                    });
                    continue;
                }

                // For non-archive scripts check content too
                if (isArchive) continue;

                string scriptExt = ext;
                bool isScript = new[] { ".py", ".js", ".bat", ".ps1", ".sh", ".rb", ".lua", ".txt" }
                    .Contains(scriptExt, StringComparer.OrdinalIgnoreCase);
                if (!isScript) continue;

                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasExploitKw = ExploitDownloadNames.Any(n =>
                        content.Contains(n, StringComparison.OrdinalIgnoreCase));

                    bool hasTxAdmin = content.Contains("txadmin", StringComparison.OrdinalIgnoreCase) ||
                                     content.Contains("cfx.re", StringComparison.OrdinalIgnoreCase);

                    if (!hasExploitKw || !hasTxAdmin) continue;

                    string matchedKw = ExploitDownloadNames.First(n =>
                        content.Contains(n, StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "txAdmin-Exploit-Inhalt in Skriptdatei erkannt",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Skriptdatei enthaelt txAdmin-Exploit-Referenzen: '{matchedKw}'. " +
                                   "Heruntergeladene Skripte mit Exploit-Inhalten fuer txAdmin oder cfx.re " +
                                   "sind Indikatoren fuer geplante oder durchgefuehrte Panel-Angriffe.",
                        Detail   = $"Muster: {matchedKw} | Verzeichnis: {dir}"
                    });
                }
                catch { }
            }

            // Scan for GitHub clone directories with txAdmin vulnerability PoCs
            string[] subDirs = Array.Empty<string>();
            try { subDirs = Directory.GetDirectories(dir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (string subDir in subDirs)
            {
                if (ct.IsCancellationRequested) return;

                string dirName = Path.GetFileName(subDir);

                bool dirNameMatch = ExploitDownloadNames.Any(n =>
                    dirName.Contains(n, StringComparison.OrdinalIgnoreCase));

                if (!dirNameMatch) continue;

                // Check if it is a git repo (has .git folder)
                bool isGitRepo = Directory.Exists(Path.Combine(subDir, ".git"));

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"txAdmin-Exploit-{(isGitRepo ? "GitHub-Klon" : "Verzeichnis")} erkannt",
                    Risk     = RiskLevel.Critical,
                    Location = subDir,
                    FileName = dirName,
                    Reason   = $"Verzeichnis '{dirName}' entspricht Namensschema eines txAdmin-Exploit-Repositories" +
                               (isGitRepo ? " und ist ein Git-Repository (GitHub-Klon). " : ". ") +
                               "GitHub-Klone von txAdmin-Schwachstellen-PoCs beweisen gezieltes " +
                               "Herunterladen von Angriffswerkzeugen.",
                    Detail   = $"Typ: {(isGitRepo ? "Git-Repository" : "Verzeichnis")} | Pfad: {subDir}"
                });
            }
        }
    }, ct);

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static string Rot13(string input)
    {
        return new string(input.Select(c =>
        {
            if (c >= 'a' && c <= 'z') return (char)('a' + (c - 'a' + 13) % 26);
            if (c >= 'A' && c <= 'Z') return (char)('A' + (c - 'A' + 13) % 26);
            return c;
        }).ToArray());
    }
}

internal static class StringExtensions
{
    internal static string Truncate(this string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return value;
        return value.Length <= maxLength ? value : value[..maxLength] + "…";
    }
}
