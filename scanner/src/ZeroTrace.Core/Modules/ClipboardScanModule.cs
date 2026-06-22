using System.Text;
using System.Text.Json;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans the Windows Clipboard history store for cheat-related text.
/// Windows 10/11 saves clipboard entries as JSON metadata files under
///   %LOCALAPPDATA%\Microsoft\Windows\Clipboard\&lt;GUID&gt;\metadata.json
/// Each file contains a "text" field (plaintext clipboard item). We scan
/// these for known cheat licence-key patterns, cheat domain strings, and
/// indicator keywords.
/// </summary>
public sealed class ClipboardScanModule : IScanModule
{
    public string Name => "Zwischenablage";
    public double Weight => 0.3;

    private static readonly string ClipboardRoot =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                     "Microsoft", "Windows", "Clipboard");

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(ClipboardRoot))
        {
            ctx.Report(1.0, "Zwischenablage", "Clipboard-Verlauf nicht vorhanden oder deaktiviert");
            return Task.CompletedTask;
        }

        int total = 0, hits = 0;

        try
        {
            foreach (var dir in Directory.EnumerateDirectories(ClipboardRoot))
            {
                if (ct.IsCancellationRequested) break;
                var meta = Path.Combine(dir, "metadata.json");
                if (!File.Exists(meta)) continue;

                total++;
                try
                {
                    var json = File.ReadAllText(meta);
                    // Extract text field
                    string? text = null;
                    try
                    {
                        using var doc = JsonDocument.Parse(json);
                        if (doc.RootElement.TryGetProperty("text", out var t))
                            text = t.GetString();
                        else if (doc.RootElement.TryGetProperty("content", out var c))
                            text = c.GetString();
                    }
                    catch { text = json; }

                    if (string.IsNullOrWhiteSpace(text)) continue;

                    // Use byte-level MatchContent for content-string indicators,
                    // plus text-level matchers for URL/filename keywords.
                    var utf8 = Encoding.UTF8.GetBytes(text);
                    var hit = ctx.Matcher.MatchContent(utf8, utf8.Length)
                              ?? ctx.Matcher.MatchUrlDomain(text)
                              ?? ctx.Matcher.MatchFileNameKeyword(text)
                              ?? ctx.Matcher.MatchPathKeyword(text);
                    if (hit is null) continue;

                    hits++;
                    var preview = text.Length > 200 ? text[..200] + "…" : text;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Clipboard-Treffer: {hit.Pattern}",
                        Risk     = hit.Risk,
                        Location = meta,
                        FileName = Path.GetFileName(dir),
                        Reason   = $"Zwischenablagen-Eintrag enthaelt Indikator '{hit.Pattern}' ({hit.Category}). " +
                                   hit.Description,
                        Detail   = $"Vorschau: {preview}",
                    });

                    if (hits >= 20) break;
                }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        ctx.Report(1.0, "Zwischenablage", $"{total} Clipboard-Eintraege geprueft, {hits} Treffer");
        return Task.CompletedTask;
    }
}
