using Microsoft.Data.Sqlite;

namespace ZeroTrace.Core.Data;

/// <summary>
/// Stores SHA-256 hashes of files confirmed clean by an admin so they are
/// suppressed from future scan results.
/// </summary>
public sealed class HashWhitelistStore
{
    private readonly SqliteDatabase _db;

    public HashWhitelistStore(SqliteDatabase db) => _db = db;

    public bool IsWhitelisted(string sha256)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM hash_whitelist WHERE sha256=$h LIMIT 1;";
        cmd.Parameters.AddWithValue("$h", sha256.ToUpperInvariant());
        return cmd.ExecuteScalar() is not null;
    }

    public List<WhitelistEntry> GetAll()
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, sha256, note, added_by, created_utc FROM hash_whitelist ORDER BY created_utc DESC;";
        using var r = cmd.ExecuteReader();
        var list = new List<WhitelistEntry>();
        while (r.Read())
            list.Add(new WhitelistEntry
            {
                Id         = r.GetInt64(0),
                Sha256     = r.GetString(1),
                Note       = r.IsDBNull(2) ? "" : r.GetString(2),
                AddedBy    = r.IsDBNull(3) ? "" : r.GetString(3),
                CreatedUtc = DateTime.Parse(r.GetString(4))
            });
        return list;
    }

    public WhitelistEntry Add(string sha256, string note = "", string addedBy = "")
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT OR REPLACE INTO hash_whitelist (sha256, note, added_by, created_utc)
VALUES ($h, $n, $b, $t);
SELECT id, sha256, note, added_by, created_utc FROM hash_whitelist WHERE sha256=$h;";
        var h = sha256.ToUpperInvariant();
        var t = DateTime.UtcNow.ToString("o");
        cmd.Parameters.AddWithValue("$h", h);
        cmd.Parameters.AddWithValue("$n", note);
        cmd.Parameters.AddWithValue("$b", addedBy);
        cmd.Parameters.AddWithValue("$t", t);
        using var r = cmd.ExecuteReader();
        r.Read();
        return new WhitelistEntry
        {
            Id         = r.GetInt64(0),
            Sha256     = r.GetString(1),
            Note       = r.IsDBNull(2) ? "" : r.GetString(2),
            AddedBy    = r.IsDBNull(3) ? "" : r.GetString(3),
            CreatedUtc = DateTime.Parse(r.GetString(4))
        };
    }

    public void Remove(long id)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM hash_whitelist WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    public void Remove(string sha256)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM hash_whitelist WHERE sha256=$h;";
        cmd.Parameters.AddWithValue("$h", sha256.ToUpperInvariant());
        cmd.ExecuteNonQuery();
    }

    public void ImportFromJson(string path)
    {
        var json = File.ReadAllText(path);
        var entries = System.Text.Json.JsonSerializer.Deserialize<List<WhitelistEntry>>(json,
            new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        if (entries is null) return;
        foreach (var e in entries)
            if (!string.IsNullOrWhiteSpace(e.Sha256))
                Add(e.Sha256, e.Note, e.AddedBy);
    }
}

public sealed class WhitelistEntry
{
    public long Id { get; set; }
    public string Sha256 { get; set; } = "";
    public string Note { get; set; } = "";
    public string AddedBy { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
}
