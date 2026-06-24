using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans %APPDATA% (Roaming) and %LOCALAPPDATA% top-level directory names
/// against cheat indicators. Cheats routinely install themselves as hidden
/// sub-folders of AppData (e.g. %APPDATA%\TsunamiMenu\, %LOCALAPPDATA%\Eulen\).
/// Only the first two directory levels are checked to keep performance fast.
/// </summary>
public sealed class AppDataScanModule : IScanModule
{
    public string Name => "AppData";
    public double Weight => 0.5;
    public int ParallelGroup => 1; // read-only directory walk, safe to parallelise

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int total = 0, hits = 0;

        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),   // %APPDATA%
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), // %LOCALAPPDATA%
        };

        foreach (var root in roots)
        {
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var dir in Directory.EnumerateDirectories(root))
                {
                    if (ct.IsCancellationRequested) return Task.CompletedTask;
                    total++;
                    var name = Path.GetFileName(dir);

                    var hit = ctx.Matcher.MatchFileNameKeyword(name)
                              ?? ctx.Matcher.MatchPathKeyword(name);

                    if (hit is not null)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdaechtiger AppData-Ordner: {name}",
                            Risk     = hit.Risk,
                            Location = dir,
                            FileName = name,
                            Reason   = $"AppData-Verzeichnis '{name}' entspricht Indikator " +
                                       $"'{hit.Pattern}' ({hit.Category}). {hit.Description}",
                        });
                    }

                    // Also scan one level deeper to catch e.g. %LOCALAPPDATA%\Temp\Eulen\
                    try
                    {
                        foreach (var sub in Directory.EnumerateDirectories(dir))
                        {
                            if (ct.IsCancellationRequested) return Task.CompletedTask;
                            total++;
                            var subName = Path.GetFileName(sub);

                            var subHit = ctx.Matcher.MatchFileNameKeyword(subName)
                                         ?? ctx.Matcher.MatchPathKeyword(subName);
                            if (subHit is null) continue;

                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Verdaechtiger AppData-Unterordner: {subName}",
                                Risk     = subHit.Risk,
                                Location = sub,
                                FileName = subName,
                                Reason   = $"AppData-Unterverzeichnis '{subName}' entspricht Indikator " +
                                           $"'{subHit.Pattern}' ({subHit.Category}). {subHit.Description}",
                            });
                        }
                    }
                    catch { }

                    if (hits >= 50) break;
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }

        ctx.Report(1.0, "AppData", $"{total} AppData-Verzeichnisse geprueft, {hits} Treffer");
        return Task.CompletedTask;
    }
}
