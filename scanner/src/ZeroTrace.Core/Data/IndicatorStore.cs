using System.Text.Json;
using ZeroTrace.Core.Models;
using Microsoft.Data.Sqlite;

namespace ZeroTrace.Core.Data;

/// <summary>CRUD for indicators plus the transparent local import/update path.</summary>
public sealed class IndicatorStore
{
    private readonly SqliteDatabase _db;

    public IndicatorStore(SqliteDatabase db) => _db = db;

    public List<Indicator> GetAll()
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM indicators ORDER BY category, pattern;";
        return Read(cmd);
    }

    public List<Indicator> GetEnabled()
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM indicators WHERE enabled = 1;";
        return Read(cmd);
    }

    public long Add(Indicator ind)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO indicators (type, pattern, risk, category, description, source, enabled, created_utc)
VALUES ($type, $pattern, $risk, $category, $description, $source, $enabled, $created);
SELECT last_insert_rowid();";
        Bind(cmd, ind);
        return Convert.ToInt64(cmd.ExecuteScalar());
    }

    public void Update(Indicator ind)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
UPDATE indicators SET type=$type, pattern=$pattern, risk=$risk, category=$category,
    description=$description, source=$source, enabled=$enabled
WHERE id=$id;";
        Bind(cmd, ind);
        cmd.Parameters.AddWithValue("$id", ind.Id);
        cmd.ExecuteNonQuery();
    }

    public void Delete(long id)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM indicators WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.ExecuteNonQuery();
    }

    public int Count()
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM indicators;";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }

    /// <summary>
    /// Imports indicators from a JSON file the operator supplies. This is the
    /// deliberate replacement for "auto-download signatures": updates are
    /// explicit, local, and reviewable. Returns the number imported.
    /// </summary>
    public int ImportFromJson(string filePath, string source)
    {
        var json = File.ReadAllText(filePath);
        var items = JsonSerializer.Deserialize<List<Indicator>>(json,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? new List<Indicator>();

        var imported = 0;
        using var conn = _db.OpenConnection();
        using var tx = conn.BeginTransaction();
        foreach (var ind in items)
        {
            if (string.IsNullOrWhiteSpace(ind.Pattern)) continue;
            ind.Source = source;
            ind.CreatedUtc = DateTime.UtcNow;
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = @"
INSERT INTO indicators (type, pattern, risk, category, description, source, enabled, created_utc)
VALUES ($type, $pattern, $risk, $category, $description, $source, $enabled, $created);";
            Bind(cmd, ind);
            cmd.ExecuteNonQuery();
            imported++;
        }
        tx.Commit();
        return imported;
    }

    public void ExportToJson(string filePath)
    {
        var all = GetAll();
        var json = JsonSerializer.Serialize(all,
            new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(filePath, json);
    }

    private static void Bind(SqliteCommand cmd, Indicator ind)
    {
        cmd.Parameters.AddWithValue("$type", (int)ind.Type);
        cmd.Parameters.AddWithValue("$pattern", ind.Pattern);
        cmd.Parameters.AddWithValue("$risk", (int)ind.Risk);
        cmd.Parameters.AddWithValue("$category", ind.Category);
        cmd.Parameters.AddWithValue("$description", ind.Description);
        cmd.Parameters.AddWithValue("$source", ind.Source);
        cmd.Parameters.AddWithValue("$enabled", ind.Enabled ? 1 : 0);
        cmd.Parameters.AddWithValue("$created", ind.CreatedUtc.ToString("O"));
    }

    private static List<Indicator> Read(SqliteCommand cmd)
    {
        var list = new List<Indicator>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            list.Add(new Indicator
            {
                Id = r.GetInt64(r.GetOrdinal("id")),
                Type = (IndicatorType)r.GetInt32(r.GetOrdinal("type")),
                Pattern = r.GetString(r.GetOrdinal("pattern")),
                Risk = (RiskLevel)r.GetInt32(r.GetOrdinal("risk")),
                Category = r.GetString(r.GetOrdinal("category")),
                Description = r.GetString(r.GetOrdinal("description")),
                Source = r.GetString(r.GetOrdinal("source")),
                Enabled = r.GetInt32(r.GetOrdinal("enabled")) == 1,
                CreatedUtc = DateTime.Parse(r.GetString(r.GetOrdinal("created_utc")))
            });
        }
        return list;
    }
}
