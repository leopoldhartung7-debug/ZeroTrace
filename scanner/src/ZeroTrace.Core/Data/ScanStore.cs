using ZeroTrace.Core.Models;
using Microsoft.Data.Sqlite;

namespace ZeroTrace.Core.Data;

/// <summary>Persists scans and their findings, and reads them back for the UI.</summary>
public sealed class ScanStore
{
    private readonly SqliteDatabase _db;

    public ScanStore(SqliteDatabase db) => _db = db;

    /// <summary>Persists a completed report and its findings in one transaction.</summary>
    public long Save(ScanReport report)
    {
        using var conn = _db.OpenConnection();
        using var tx = conn.BeginTransaction();

        long scanId;
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = @"
INSERT INTO scans (started_utc, finished_utc, files_scanned, processes_scanned,
    registry_keys_scanned, result, machine_name, os_version, elevated)
VALUES ($start, $finish, $files, $procs, $reg, $result, $machine, $os, $elev);
SELECT last_insert_rowid();";
            cmd.Parameters.AddWithValue("$start", report.StartedUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$finish", report.FinishedUtc.ToString("O"));
            cmd.Parameters.AddWithValue("$files", report.FilesScanned);
            cmd.Parameters.AddWithValue("$procs", report.ProcessesScanned);
            cmd.Parameters.AddWithValue("$reg", report.RegistryKeysScanned);
            cmd.Parameters.AddWithValue("$result", (int)report.Result);
            cmd.Parameters.AddWithValue("$machine", report.MachineName);
            cmd.Parameters.AddWithValue("$os", report.OsVersion);
            cmd.Parameters.AddWithValue("$elev", report.Elevated ? 1 : 0);
            scanId = Convert.ToInt64(cmd.ExecuteScalar());
        }

        foreach (var f in report.Findings)
        {
            f.ScanId = scanId;
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
INSERT INTO findings (scan_id, module, title, risk, location, file_name, sha256,
    reason, signed, detail, recommendation, detected_utc)
VALUES ($scan, $module, $title, $risk, $loc, $file, $sha, $reason, $signed, $detail, $rec, $detected);";
            cmd.Parameters.AddWithValue("$scan", scanId);
            cmd.Parameters.AddWithValue("$module", f.Module);
            cmd.Parameters.AddWithValue("$title", f.Title);
            cmd.Parameters.AddWithValue("$risk", (int)f.Risk);
            cmd.Parameters.AddWithValue("$loc", f.Location);
            cmd.Parameters.AddWithValue("$file", (object?)f.FileName ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$sha", (object?)f.Sha256 ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$reason", f.Reason);
            cmd.Parameters.AddWithValue("$signed", f.Signed is null ? DBNull.Value : (f.Signed.Value ? 1 : 0));
            cmd.Parameters.AddWithValue("$detail", (object?)f.Detail ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$rec", (int)f.Recommendation);
            cmd.Parameters.AddWithValue("$detected", f.DetectedUtc.ToString("O"));
            cmd.ExecuteNonQuery();
        }

        tx.Commit();
        report.Id = scanId;
        return scanId;
    }

    public List<ScanReport> GetRecentScans(int limit = 50)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM scans ORDER BY id DESC LIMIT $limit;";
        cmd.Parameters.AddWithValue("$limit", limit);

        var list = new List<ScanReport>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(ReadScan(r));
        return list;
    }

    public ScanReport? GetScan(long id)
    {
        using var conn = _db.OpenConnection();
        ScanReport? report;
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "SELECT * FROM scans WHERE id=$id;";
            cmd.Parameters.AddWithValue("$id", id);
            using var r = cmd.ExecuteReader();
            if (!r.Read()) return null;
            report = ReadScan(r);
        }
        report.Findings = GetFindings(id);
        return report;
    }

    public List<Finding> GetFindings(long scanId)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM findings WHERE scan_id=$id ORDER BY risk DESC, module;";
        cmd.Parameters.AddWithValue("$id", scanId);

        var list = new List<Finding>();
        using var r = cmd.ExecuteReader();
        while (r.Read()) list.Add(ReadFinding(r));
        return list;
    }

    public void DeleteScan(long id)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM scans WHERE id=$id;"; // cascades to findings
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    private static ScanReport ReadScan(SqliteDataReader r) => new()
    {
        Id = r.GetInt64(r.GetOrdinal("id")),
        StartedUtc = DateTime.Parse(r.GetString(r.GetOrdinal("started_utc"))),
        FinishedUtc = DateTime.Parse(r.GetString(r.GetOrdinal("finished_utc"))),
        FilesScanned = r.GetInt64(r.GetOrdinal("files_scanned")),
        ProcessesScanned = r.GetInt64(r.GetOrdinal("processes_scanned")),
        RegistryKeysScanned = r.GetInt64(r.GetOrdinal("registry_keys_scanned")),
        Result = (ScanPhase)r.GetInt32(r.GetOrdinal("result")),
        MachineName = r.GetString(r.GetOrdinal("machine_name")),
        OsVersion = r.GetString(r.GetOrdinal("os_version")),
        Elevated = r.GetInt32(r.GetOrdinal("elevated")) == 1
    };

    private static Finding ReadFinding(SqliteDataReader r)
    {
        int signedOrd = r.GetOrdinal("signed");
        return new Finding
        {
            Id = r.GetInt64(r.GetOrdinal("id")),
            ScanId = r.GetInt64(r.GetOrdinal("scan_id")),
            Module = r.GetString(r.GetOrdinal("module")),
            Title = r.GetString(r.GetOrdinal("title")),
            Risk = (RiskLevel)r.GetInt32(r.GetOrdinal("risk")),
            Location = r.GetString(r.GetOrdinal("location")),
            FileName = r.IsDBNull(r.GetOrdinal("file_name")) ? null : r.GetString(r.GetOrdinal("file_name")),
            Sha256 = r.IsDBNull(r.GetOrdinal("sha256")) ? null : r.GetString(r.GetOrdinal("sha256")),
            Reason = r.GetString(r.GetOrdinal("reason")),
            Signed = r.IsDBNull(signedOrd) ? null : r.GetInt32(signedOrd) == 1,
            Detail = r.IsDBNull(r.GetOrdinal("detail")) ? null : r.GetString(r.GetOrdinal("detail")),
            Recommendation = (Recommendation)r.GetInt32(r.GetOrdinal("recommendation")),
            DetectedUtc = DateTime.Parse(r.GetString(r.GetOrdinal("detected_utc")))
        };
    }
}
