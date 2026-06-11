using System.Text.Json;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Data;

/// <summary>Key/value settings persistence. ScanOptions is stored as a JSON blob.</summary>
public sealed class SettingsStore
{
    private const string OptionsKey = "scan_options";
    private readonly SqliteDatabase _db;

    public SettingsStore(SqliteDatabase db) => _db = db;

    public ScanOptions LoadOptions()
    {
        var json = Get(OptionsKey);
        if (string.IsNullOrWhiteSpace(json)) return new ScanOptions();
        try
        {
            return JsonSerializer.Deserialize<ScanOptions>(json) ?? new ScanOptions();
        }
        catch
        {
            return new ScanOptions();
        }
    }

    public void SaveOptions(ScanOptions options) =>
        Set(OptionsKey, JsonSerializer.Serialize(options));

    public string? Get(string key)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM settings WHERE key=$k;";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void Set(string key, string value)
    {
        using var conn = _db.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
INSERT INTO settings (key, value) VALUES ($k, $v)
ON CONFLICT(key) DO UPDATE SET value=excluded.value;";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
    }
}
