using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects DLL hijacking via the Windows font driver subsystem and
/// malicious font files used for privilege escalation.
///
/// Windows supports custom font drivers that are loaded as kernel modules.
/// The font registry key HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts
/// maps font names to .fon/.ttf/.otf files. However:
///
///   1. Font drivers (HKLM\...\FontDrivers) are kernel-mode DLLs — a malicious
///      font driver runs at ring-0 on first font use.
///   2. GDI+ font loading (AddFontResourceEx) can load DLLs disguised as fonts
///      if the DLL has a valid PE header — used for stealthy DLL loading.
///   3. User-installed fonts (per-user, no admin required) can shadow system
///      fonts if placed in %LOCALAPPDATA%\Microsoft\Windows\Fonts\
///
/// Detection:
///   1. Check HKLM\...\FontDrivers for non-standard entries.
///   2. Check per-user fonts in %LOCALAPPDATA%\Microsoft\Windows\Fonts\
///      for files with cheat keywords or PE (MZ) headers in non-font files.
///   3. Check HKLM\...\Fonts for entries pointing to unexpected paths.
/// </summary>
public sealed class InstalledFontScanModule : IScanModule
{
    public string Name => "Schriftart-Treiber-Analyse";
    public double Weight => 0.3;
    public int ParallelGroup => 1;

    private const string FontsKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts";
    private const string FontDriversKey =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers";

    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);
    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System);
    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows);

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "ozark", "skeet",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckFontDrivers(ctx, ct);
        hits += CheckPerUserFonts(ctx, ct);
        hits += CheckFontRegistryPaths(ctx, ct);

        ctx.Report(1.0, Name, $"Schriftart-Treiber geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckFontDrivers(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(FontDriversKey, writable: false);
            if (key is null) return 0;

            foreach (var name in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                var value = key.GetValue(name) as string ?? "";
                var lower = value.ToLowerInvariant();

                // Font drivers that aren't in system directories are suspicious
                if (!lower.StartsWith(System32.ToLowerInvariant()) &&
                    !lower.StartsWith(WinDir.ToLowerInvariant()) &&
                    !lower.StartsWith(@"win32k") && // built-in
                    !string.IsNullOrEmpty(value))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtiger Schriftart-Treiber: {name}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{FontDriversKey}",
                        FileName = Path.GetFileName(value),
                        Reason   = $"Font-Treiber '{name}' zeigt auf Nicht-System-Pfad: '{value}'. " +
                                   "Font-Treiber laufen als Kernel-Mode-Code (Ring-0). " +
                                   "Ein Nicht-System-Font-Treiber ist ein starker Indikator für " +
                                   "Rootkit-Persistenz über den GDI-Subsystem.",
                        Detail   = $"Treiber: {name} | Pfad: {value}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckPerUserFonts(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var fontDir = Path.Combine(LocalApp, @"Microsoft\Windows\Fonts");
        if (!Directory.Exists(fontDir)) return 0;

        try
        {
            foreach (var file in Directory.EnumerateFiles(fontDir, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file).ToLowerInvariant();
                var ext = Path.GetExtension(fn);

                // Check for cheat keywords in font file name
                var kw = CheatKeywords.FirstOrDefault(k => fn.Contains(k));
                if (kw is not null)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtige Font-Datei: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Font-Datei '{Path.GetFileName(file)}' in per-user Font-Verzeichnis " +
                                   $"enthält cheat-typisches Keyword '{kw}'. " +
                                   "Kann eine umbenannte Cheat-DLL oder ein Injektions-Artifact sein.",
                        Detail   = $"Pfad: {file} | Keyword: {kw}"
                    });
                    continue;
                }

                // Check if a non-font file has PE (MZ) header = disguised DLL
                if (ext != ".exe" && ext != ".dll" && ext != ".sys")
                {
                    try
                    {
                        var header = new byte[2];
                        using var fs = File.OpenRead(file);
                        if (fs.Read(header, 0, 2) == 2 &&
                            header[0] == 0x4D && header[1] == 0x5A) // MZ
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Getarnte PE-Datei als Font: {Path.GetFileName(file)}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"Datei '{Path.GetFileName(file)}' in per-user Fonts-Ordner " +
                                           $"hat PE/MZ-Header (Windows-Executable) trotz Font-Extension '{ext}'. " +
                                           "Dies ist eine klassische Technik um DLLs oder EXEs als " +
                                           "harmlose Fonts zu tarnen.",
                                Detail   = $"Datei: {file} | Header: MZ (PE) | Extension: {ext}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckFontRegistryPaths(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(FontsKey, writable: false);
            if (key is null) return 0;

            foreach (var name in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                var value = key.GetValue(name) as string ?? "";
                if (string.IsNullOrEmpty(value)) continue;

                // Fonts should only point to %SystemRoot%\Fonts or be just a filename
                var lower = value.ToLowerInvariant();
                if (lower.Contains('\\') &&
                    !lower.StartsWith(WinDir.ToLowerInvariant()) &&
                    !lower.StartsWith(System32.ToLowerInvariant()) &&
                    !lower.Contains(@"\windows\fonts\"))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Font-Registry zeigt auf unerwarteten Pfad: {name}",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{FontsKey}",
                        FileName = Path.GetFileName(value),
                        Reason   = $"Font-Eintrag '{name}' zeigt auf Nicht-System-Pfad: '{value}'. " +
                                   "Alle legitimen Windows-Fonts befinden sich in %SystemRoot%\\Fonts.",
                        Detail   = $"Font: {name} | Pfad: {value}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
