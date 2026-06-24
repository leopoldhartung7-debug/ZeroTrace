using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Add/Remove Programs registry hives (HKLM 64-bit, HKLM 32-bit, HKCU)
/// for installed software whose name matches known cheat tools, spoofers, loaders,
/// memory editors, or trainer frameworks.
/// </summary>
public sealed class InstalledSoftwareScanModule : IScanModule
{
    public string Name => "Installierte Software";
    public double Weight => 0.4;
    public int ParallelGroup => 1; // registry-read only

    private static readonly string[] UninstallKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        ScanHive(ctx, Registry.LocalMachine, ref checked_);
        ScanHive(ctx, Registry.CurrentUser, ref checked_);
        ctx.Report(1.0, "Programme", $"{checked_} installierte Programme geprueft");
        return Task.CompletedTask;
    }

    private void ScanHive(ScanContext ctx, RegistryKey hive, ref int count)
    {
        foreach (var keyPath in UninstallKeys)
        {
            try
            {
                using var root = hive.OpenSubKey(keyPath, writable: false);
                if (root is null) continue;
                foreach (var sub in root.GetSubKeyNames())
                {
                    try
                    {
                        using var entry = root.OpenSubKey(sub, writable: false);
                        if (entry is null) continue;
                        var displayName = entry.GetValue("DisplayName") as string;
                        if (string.IsNullOrWhiteSpace(displayName)) continue;
                        count++;

                        var nameHit = ctx.Matcher.MatchFileNameKeyword(displayName)
                                      ?? ctx.Matcher.MatchPathKeyword(displayName);
                        if (nameHit is null) continue;

                        var publisher = entry.GetValue("Publisher") as string;
                        var version   = entry.GetValue("DisplayVersion") as string;
                        var installLoc = entry.GetValue("InstallLocation") as string
                                         ?? entry.GetValue("InstallSource") as string
                                         ?? "";

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Installiertes Tool: {displayName}",
                            Risk     = nameHit.Risk,
                            Location = installLoc.Length > 0 ? installLoc : $"Programme\\{displayName}",
                            FileName = displayName,
                            Reason   = $"Installiertes Programm entspricht Indikator '{nameHit.Pattern}' ({nameHit.Category}). " +
                                       nameHit.Description,
                            Detail   = string.Join(" | ",
                                new[] {
                                    publisher is { Length: > 0 } ? $"Publisher: {publisher}" : null,
                                    version   is { Length: > 0 } ? $"Version: {version}"      : null,
                                }.Where(s => s is not null))
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }
    }
}
