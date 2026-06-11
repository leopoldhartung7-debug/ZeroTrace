-- ZeroTrace - SQLite-Schema (Referenz)
-- Dieses Skript spiegelt SqliteDatabase.SchemaSql. Die App erzeugt die Tabellen
-- beim ersten Start automatisch; dieses File dient nur der Dokumentation/Inspektion.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Lokale, admin-pflegbare Erkennungsindikatoren
CREATE TABLE IF NOT EXISTS indicators (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    type         INTEGER NOT NULL,         -- IndicatorType: 0=Sha256Hash,1=FileName,2=FileNameKeyword,
                                           --                3=FilePathKeyword,4=ProcessName,5=RegistryValueKeyword,
                                           --                6=ContentString (String im Datei-Inhalt, ASCII+UTF-16LE),
                                           --                7=UrlDomainKeyword (Host im Browser-Verlauf)
    pattern      TEXT    NOT NULL,
    risk         INTEGER NOT NULL,         -- RiskLevel: 0=Low,1=Medium,2=High,3=Critical
    category     TEXT    NOT NULL DEFAULT 'General',
    description  TEXT    NOT NULL DEFAULT '',
    source       TEXT    NOT NULL DEFAULT 'manual',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_utc  TEXT    NOT NULL          -- ISO-8601 UTC
);

CREATE INDEX IF NOT EXISTS ix_indicators_type    ON indicators(type);
CREATE INDEX IF NOT EXISTS ix_indicators_enabled ON indicators(enabled);

-- Ein Eintrag pro durchgefuehrtem Scan
CREATE TABLE IF NOT EXISTS scans (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    started_utc           TEXT    NOT NULL,
    finished_utc          TEXT    NOT NULL,
    files_scanned         INTEGER NOT NULL DEFAULT 0,
    processes_scanned     INTEGER NOT NULL DEFAULT 0,
    registry_keys_scanned INTEGER NOT NULL DEFAULT 0,
    result                INTEGER NOT NULL DEFAULT 3,  -- ScanPhase: 3=Completed,4=Cancelled,5=Failed
    machine_name          TEXT    NOT NULL DEFAULT '',
    os_version            TEXT    NOT NULL DEFAULT '',
    elevated              INTEGER NOT NULL DEFAULT 0
);

-- Funde, jeweils einem Scan zugeordnet
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
    signed          INTEGER,                 -- NULL=ungeprueft, 0=unsigniert, 1=signiert
    detail          TEXT,
    recommendation  INTEGER NOT NULL DEFAULT 1,  -- Recommendation: 0=Ignore,1=Review,2=Remove
    detected_utc    TEXT    NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS ix_findings_risk ON findings(risk);

-- Schluessel/Wert-Einstellungen (u. a. JSON-serialisierte ScanOptions unter 'scan_options')
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
