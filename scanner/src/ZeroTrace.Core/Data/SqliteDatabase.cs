using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;
using Microsoft.Data.Sqlite;

namespace ZeroTrace.Core.Data;

/// <summary>
/// Owns the SQLite connection string, creates the schema on first run,
/// verifies integrity, and seeds the built-in heuristic indicators.
/// No network access is performed at any point.
/// </summary>
public sealed class SqliteDatabase
{
    public string ConnectionString { get; }
    public string Path { get; }

    public SqliteDatabase(string? path = null)
    {
        Path = path ?? KnownPaths.DatabasePath;
        ConnectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared
        }.ToString();
    }

    public SqliteConnection OpenConnection()
    {
        var conn = new SqliteConnection(ConnectionString);
        conn.Open();
        using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;";
            pragma.ExecuteNonQuery();
        }
        return conn;
    }

    /// <summary>Creates tables if missing. Idempotent.</summary>
    public void EnsureCreated()
    {
        using var conn = OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = SchemaSql;
        cmd.ExecuteNonQuery();
    }

    /// <summary>Runs PRAGMA integrity_check; returns true if the database is sound.</summary>
    public bool VerifyIntegrity()
    {
        try
        {
            using var conn = OpenConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "PRAGMA integrity_check;";
            var result = cmd.ExecuteScalar() as string;
            return string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Seeds the built-in, fully editable heuristic indicators if the
    /// indicators table is empty: file-name/path keywords plus a small set of
    /// content-string signatures (cheat watermarks / menu strings). These are
    /// starting points, not a complete cheat catalogue, and every entry can be
    /// edited, disabled or removed by the administrator.
    /// </summary>
    public void SeedDefaultsIfEmpty()
    {
        using var conn = OpenConnection();
        using (var check = conn.CreateCommand())
        {
            check.CommandText = "SELECT COUNT(*) FROM indicators;";
            var count = Convert.ToInt64(check.ExecuteScalar());
            if (count > 0) return;
        }

        var seeds = new (IndicatorType type, string pattern, RiskLevel risk, string category, string desc)[]
        {
            (IndicatorType.FileNameKeyword, "injector",  RiskLevel.Medium, "Injector", "Dateiname enthaelt 'injector' (DLL-Injection-Werkzeuge)."),
            (IndicatorType.FileNameKeyword, "loader",    RiskLevel.Low,    "Loader",   "Dateiname enthaelt 'loader' (oft legitim, daher Low)."),
            (IndicatorType.FileNameKeyword, "aimbot",    RiskLevel.High,   "Aimbot",   "Dateiname enthaelt 'aimbot'."),
            (IndicatorType.FileNameKeyword, "cheat",     RiskLevel.Medium, "Generic",  "Dateiname enthaelt 'cheat'."),
            (IndicatorType.FileNameKeyword, "trainer",   RiskLevel.Low,    "Trainer",  "Dateiname enthaelt 'trainer' (Single-Player-Trainer oft legitim)."),
            (IndicatorType.FilePathKeyword, "menyoo",    RiskLevel.Low,    "Mod Menu", "Pfad enthaelt 'menyoo' (Mod-Menu-Komponente)."),
            (IndicatorType.FileNameKeyword, "executor",  RiskLevel.Medium, "Executor", "Dateiname enthaelt 'executor' (Script-Executor)."),
            (IndicatorType.FileNameKeyword, "spoofer",   RiskLevel.High,   "Spoofer",  "Dateiname enthaelt 'spoofer' (HWID-Spoofing)."),

            // Content-string signatures: searched inside the raw file bytes
            // (ASCII + UTF-16LE). These catch a cheat even after it is renamed,
            // because the characteristic watermark/menu string stays in the
            // binary. Distinctive brand tokens are High; generic cheat-UI words
            // are Medium. All of these are fully editable/removable by the admin.
            (IndicatorType.ContentString, "redengine",     RiskLevel.High,   "Cheat-Signatur", "Bekanntes FiveM-Cheat-Wasserzeichen 'RedENGINE' im Datei-Inhalt."),
            (IndicatorType.ContentString, "skript.gg",     RiskLevel.High,   "Cheat-Signatur", "FiveM-Cheat-Token 'skript.gg' im Datei-Inhalt."),
            (IndicatorType.ContentString, "hxcheats",      RiskLevel.High,   "Cheat-Signatur", "Cheat-Token 'hxcheats' im Datei-Inhalt."),
            (IndicatorType.ContentString, "cherax",        RiskLevel.High,   "Cheat-Signatur", "GTA-Mod-Menu-Token 'Cherax' im Datei-Inhalt."),
            (IndicatorType.ContentString, "hwidspoofer",   RiskLevel.High,   "Spoofer",        "HWID-Spoofer-Token im Datei-Inhalt."),
            (IndicatorType.ContentString, "aimbot",        RiskLevel.High,   "Aimbot",         "String 'aimbot' im Datei-Inhalt."),
            (IndicatorType.ContentString, "triggerbot",    RiskLevel.High,   "Aimbot",         "String 'triggerbot' im Datei-Inhalt."),
            (IndicatorType.ContentString, "silentaim",     RiskLevel.High,   "Aimbot",         "String 'silentaim' im Datei-Inhalt."),
            (IndicatorType.ContentString, "wallhack",      RiskLevel.Medium, "ESP/Wallhack",   "String 'wallhack' im Datei-Inhalt."),
            (IndicatorType.ContentString, "norecoil",      RiskLevel.Medium, "Recoil",         "String 'norecoil' im Datei-Inhalt."),
            (IndicatorType.ContentString, "godmode",       RiskLevel.Medium, "Generic",        "String 'godmode' im Datei-Inhalt."),
            (IndicatorType.ContentString, "unknowncheats", RiskLevel.Medium, "Generic",        "Forum-Wasserzeichen 'unknowncheats' im Datei-Inhalt."),
            (IndicatorType.ContentString, "tsunami.gg",     RiskLevel.High,   "Cheat-Signatur", "FiveM-Cheat-Token 'tsunami.gg' im Datei-Inhalt."),
            (IndicatorType.ContentString, "esp_render",     RiskLevel.Medium, "ESP/Wallhack",   "ESP-Render-Token im Datei-Inhalt."),
            (IndicatorType.FileNameKeyword, "dumper",       RiskLevel.Medium, "Dumper",         "Dateiname enthaelt 'dumper' (Speicher-/Code-Dumper)."),
            (IndicatorType.FileNameKeyword, "bypass",       RiskLevel.Low,    "Bypass",         "Dateiname enthaelt 'bypass' (oft legitim, daher Low)."),
            (IndicatorType.FileNameKeyword, "spoofer",      RiskLevel.High,   "HWID-Spoofer",   "Dateiname enthaelt 'spoofer' (HWID-Ban-Umgehung)."),
            (IndicatorType.FileNameKeyword, "kdmapper",     RiskLevel.High,   "Manual-Mapper",  "Bekannter Treiber-Mapper zum Umgehen der Signaturpruefung."),
            (IndicatorType.FileNameKeyword, "manualmap",    RiskLevel.High,   "Manual-Mapper",  "Manuelles DLL/Treiber-Mapping (Signatur-/AC-Bypass)."),
            (IndicatorType.FileNameKeyword, "dsefix",       RiskLevel.High,   "DSE-Bypass",     "Werkzeug zum Abschalten der Treiber-Signaturpruefung (DSE)."),
            (IndicatorType.ContentString,   "hwid spoof",   RiskLevel.High,   "HWID-Spoofer",   "Inhalts-Token 'hwid spoof' (Ban-Umgehung)."),
            (IndicatorType.ContentString,   "vac bypass",   RiskLevel.High,   "AC-Bypass",      "Inhalts-Token 'vac bypass' (Anti-Cheat-Umgehung)."),
            (IndicatorType.ContentString,   "manual map",   RiskLevel.Medium, "Manual-Mapper",  "Inhalts-Token 'manual map' (Injektion ohne LoadLibrary)."),

            // URL-domain signatures: matched against the HOST of visited URLs in
            // the local browser history. Only matching hosts are recorded; the
            // rest of the history is never stored. Distinctive cheat/reseller
            // brand domains -> editable starting points, not a complete list.
            (IndicatorType.UrlDomainKeyword, "redengine",     RiskLevel.High,   "Cheat-Shop", "Besuch einer RedENGINE-Domain (FiveM-Cheat)."),
            (IndicatorType.UrlDomainKeyword, "skript.gg",     RiskLevel.High,   "Cheat-Shop", "Besuch von skript.gg (FiveM-Cheat)."),
            (IndicatorType.UrlDomainKeyword, "eulen",         RiskLevel.High,   "Cheat-Shop", "Besuch einer Eulen-Domain (FiveM-Cheat)."),
            (IndicatorType.UrlDomainKeyword, "hxcheats",      RiskLevel.High,   "Cheat-Shop", "Besuch einer Hx-Cheats-Domain."),
            (IndicatorType.UrlDomainKeyword, "cherax",        RiskLevel.High,   "Cheat-Shop", "Besuch einer Cherax-Domain (GTA-Mod-Menu)."),
            (IndicatorType.UrlDomainKeyword, "unknowncheats", RiskLevel.Medium, "Cheat-Forum", "Besuch von unknowncheats (Cheat-Forum)."),
            (IndicatorType.UrlDomainKeyword, "elitepvpers",   RiskLevel.Low,    "Cheat-Forum", "Besuch von elitepvpers (Handels-/Cheat-Forum).")
        };

        using var tx = conn.BeginTransaction();
        foreach (var s in seeds)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
INSERT INTO indicators (type, pattern, risk, category, description, source, enabled, created_utc)
VALUES ($type, $pattern, $risk, $category, $description, 'builtin-heuristic', 1, $created);";
            cmd.Parameters.AddWithValue("$type", (int)s.type);
            cmd.Parameters.AddWithValue("$pattern", s.pattern);
            cmd.Parameters.AddWithValue("$risk", (int)s.risk);
            cmd.Parameters.AddWithValue("$category", s.category);
            cmd.Parameters.AddWithValue("$description", s.desc);
            cmd.Parameters.AddWithValue("$created", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    /// <summary>The full DDL. Mirrored as docs-only Schema.sql for reference.</summary>
    public const string SchemaSql = @"
CREATE TABLE IF NOT EXISTS indicators (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    type         INTEGER NOT NULL,
    pattern      TEXT    NOT NULL,
    risk         INTEGER NOT NULL,
    category     TEXT    NOT NULL DEFAULT 'General',
    description  TEXT    NOT NULL DEFAULT '',
    source       TEXT    NOT NULL DEFAULT 'manual',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_utc  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_indicators_type    ON indicators(type);
CREATE INDEX IF NOT EXISTS ix_indicators_enabled ON indicators(enabled);

CREATE TABLE IF NOT EXISTS scans (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    started_utc          TEXT    NOT NULL,
    finished_utc         TEXT    NOT NULL,
    files_scanned        INTEGER NOT NULL DEFAULT 0,
    processes_scanned    INTEGER NOT NULL DEFAULT 0,
    registry_keys_scanned INTEGER NOT NULL DEFAULT 0,
    result               INTEGER NOT NULL DEFAULT 3,
    machine_name         TEXT    NOT NULL DEFAULT '',
    os_version           TEXT    NOT NULL DEFAULT '',
    elevated             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL,
    module          TEXT    NOT NULL,
    title           TEXT    NOT NULL,
    risk            INTEGER NOT NULL,
    location        TEXT    NOT NULL DEFAULT '',
    file_name       TEXT,
    sha256          TEXT,
    reason          TEXT    NOT NULL DEFAULT '',
    signed          INTEGER,
    detail          TEXT,
    recommendation  INTEGER NOT NULL DEFAULT 1,
    detected_utc    TEXT    NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS ix_findings_risk ON findings(risk);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
";
}
