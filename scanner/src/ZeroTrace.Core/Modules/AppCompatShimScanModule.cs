using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects application compatibility shim database (SDB) abuse for persistence
/// and DLL injection without admin rights.
///
/// Windows Application Compatibility Infrastructure allows shimming applications
/// with custom SDB (shim database) files. Shims can redirect API calls, inject DLLs,
/// patch memory, and modify process behavior — all without modifying the target executable.
///
/// Cheat tools and malware abuse shims for:
///   1. DLL injection: InjectDll shim loads arbitrary DLLs into target process
///   2. API hooking: RedirectEXE, CorrectFilePaths shims redirect API calls
///   3. Persistence: Shims run automatically when the shimmed executable starts
///   4. UAC bypass: Some shims allow elevation without UAC prompt
///
/// Registry persistence locations:
///   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
///   HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB
///   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom
///
/// File system:
///   %WINDIR%\AppPatch\Custom\   — system-wide custom SDB files
///   %WINDIR%\AppPatch\Custom\Custom64\
/// </summary>
public sealed class AppCompatShimScanModule : IScanModule
{
    public string Name => "AppCompat-Shim-Persistenz";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows);

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook", "dll",
        "gta5", "fivem", "tarkov", "apex", "valorant", "csgo", "cs2",
        "persist", "autorun",
    };

    private const string InstalledSdbKeyLm =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB";
    private const string InstalledSdbKeyHkcu =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB";
    private const string CustomFlagsKeyLm =
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom";

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckInstalledSdbs(Registry.LocalMachine, "HKLM", InstalledSdbKeyLm, ctx, ct);
        hits += CheckInstalledSdbs(Registry.CurrentUser,  "HKCU", InstalledSdbKeyHkcu, ctx, ct);
        hits += CheckCustomFlags(ctx, ct);
        hits += CheckAppPatchDirectory(ctx, ct);

        ctx.Report(1.0, Name, $"AppCompat-Shim-Datenbanken geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckInstalledSdbs(RegistryKey hive, string hiveName,
        string keyPath, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = hive.OpenSubKey(keyPath, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            foreach (var guidName in key.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                using var sdbKey = key.OpenSubKey(guidName, writable: false);
                if (sdbKey is null) continue;

                var sdbPath   = sdbKey.GetValue("DatabasePath") as string ?? "";
                var dbName    = sdbKey.GetValue("DatabaseDescription") as string ?? guidName;
                var dbType    = sdbKey.GetValue("DatabaseType") as int? ?? 0;

                var lower = (sdbPath + " " + dbName).ToLowerInvariant();
                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                bool isSystemPath = sdbPath.ToLowerInvariant()
                    .StartsWith(WinDir.ToLowerInvariant());
                bool exists = File.Exists(sdbPath);

                // Any non-system or cheat-keyword SDB is suspicious
                if (cheatKw is not null || !isSystemPath)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Benutzerdefinierte Shim-Datenbank: {dbName}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"{hiveName}\{keyPath}\{guidName}",
                        FileName = Path.GetFileName(sdbPath),
                        Reason   = $"Benutzerdefinierte SDB-Shim-Datenbank '{dbName}' installiert " +
                                   $"({hiveName}). Pfad: '{sdbPath}'. " +
                                   "Shim-Datenbanken können DLLs in beliebige Prozesse injizieren " +
                                   "und API-Aufrufe umleiten — auch ohne Administratorrechte. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   (!isSystemPath ? "Außerhalb des Windows-Verzeichnisses. " : "") +
                                   (!exists ? "Datei fehlt (Tombstone)." : ""),
                        Detail   = $"GUID: {guidName} | Pfad: {sdbPath} | Typ: {dbType} | Existiert: {exists}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckCustomFlags(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CustomFlagsKeyLm, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            foreach (var exeName in key.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                var exeLower = exeName.ToLowerInvariant();
                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    exeLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (cheatKw is null) continue;

                using var exeKey = key.OpenSubKey(exeName, writable: false);
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"AppCompat-Custom-Flag: {exeName}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{CustomFlagsKeyLm}\{exeName}",
                    FileName = exeName,
                    Reason   = $"AppCompat Custom Flag für Executable '{exeName}' registriert. " +
                               $"Cheat-Keyword: '{cheatKw}'. " +
                               "Custom-Flags wenden Shims auf dieses Binary an und können " +
                               "sein Verhalten zur Laufzeit modifizieren.",
                    Detail   = $"Executable: {exeName} | Keyword: {cheatKw}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckAppPatchDirectory(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var appPatchDirs = new[]
            {
                Path.Combine(WinDir, "AppPatch", "Custom"),
                Path.Combine(WinDir, "AppPatch", "Custom", "Custom64"),
            };

            foreach (var dir in appPatchDirs)
            {
                if (ct.IsCancellationRequested) break;
                if (!Directory.Exists(dir)) continue;

                foreach (var file in Directory.EnumerateFiles(dir, "*.sdb",
                    SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementFiles();

                    var nameLower = Path.GetFileName(file).ToLowerInvariant();
                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        nameLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    // All custom SDB files on disk are notable even without keywords
                    var fi = new FileInfo(file);
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"SDB-Datei in AppPatch: {Path.GetFileName(file)}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.Medium,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Benutzerdefinierte Shim-Datenbank-Datei '{Path.GetFileName(file)}' " +
                                   $"im Windows AppPatch-Verzeichnis gefunden. " +
                                   "Nicht-Microsoft-SDB-Dateien in diesem Verzeichnis sind ein starkes " +
                                   "Persistenz-Indikator. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'." : ""),
                        Detail   = $"Datei: {file} | Größe: {fi.Length} | Geändert: {fi.LastWriteTime:u}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
