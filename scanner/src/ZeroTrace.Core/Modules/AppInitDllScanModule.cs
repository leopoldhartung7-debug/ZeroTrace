using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects DLL injection via the AppInit_DLLs registry mechanism.
///
/// AppInit_DLLs is a Windows registry value that causes the listed DLLs to be
/// loaded into EVERY user-mode process that imports User32.dll. This was a
/// legitimate extensibility feature in early Windows versions but is now
/// almost exclusively used by malware and cheat tools for:
///   1. Global DLL injection without CreateRemoteThread (loads into game process)
///   2. Persistence (DLL is loaded automatically at every process startup)
///   3. Keyloggers / clipboard monitors running in all GUI processes
///
/// Registry locations:
///   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
///   HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
///   HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
///
/// Additional registry check:
///   LoadAppInit_DLLs = 1 enables the feature (default 0 on modern Windows)
///   RequireSignedAppInit_DLLs = 0 allows unsigned DLLs (dangerous)
///
/// Detection:
///   - Any non-empty AppInit_DLLs value with unknown DLLs
///   - LoadAppInit_DLLs = 1 with non-system DLL paths
///   - RequireSignedAppInit_DLLs = 0 (weaker security)
/// </summary>
public sealed class AppInitDllScanModule : IScanModule
{
    public string Name => "AppInit-DLL-Injektion";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private static readonly (string Hive, string Path)[] AppInitKeys =
    {
        ("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
        ("HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"),
        ("HKCU", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
    };

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();
    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        foreach (var (hive, path) in AppInitKeys)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var key = hive == "HKLM"
                    ? Registry.LocalMachine.OpenSubKey(path, writable: false)
                    : Registry.CurrentUser.OpenSubKey(path, writable: false);

                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                var appInitDlls = key.GetValue("AppInit_DLLs") as string ?? "";
                var loadAppInit = key.GetValue("LoadAppInit_DLLs") as int? ?? 0;
                var requireSigned = key.GetValue("RequireSignedAppInit_DLLs") as int? ?? 1;

                // Flag if LoadAppInit_DLLs is enabled
                if (loadAppInit != 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"AppInit_DLLs aktiviert: {hive}",
                        Risk     = RiskLevel.High,
                        Location = $@"{hive}\{path}",
                        Reason   = $"LoadAppInit_DLLs ist aktiviert ({hive}). " +
                                   "AppInit_DLLs injiziert DLLs in JEDEN Prozess der User32.dll importiert. " +
                                   "Diese Funktion ist in modernem Windows standardmäßig deaktiviert " +
                                   "und wird fast ausschließlich von Malware und Cheats genutzt.",
                        Detail   = $"LoadAppInit_DLLs: {loadAppInit} | " +
                                   $"RequireSignedAppInit_DLLs: {requireSigned} | " +
                                   $"DLLs: '{appInitDlls}'"
                    });
                    hits++;
                }

                if (string.IsNullOrWhiteSpace(appInitDlls)) continue;

                // Check each DLL in the list
                var dlls = appInitDlls.Split(new[] { ' ', ',', ';' },
                    StringSplitOptions.RemoveEmptyEntries);

                foreach (var dll in dlls)
                {
                    if (ct.IsCancellationRequested) break;
                    var lower = dll.ToLowerInvariant();

                    // Non-system DLL = highly suspicious
                    bool isSystemDll = lower.StartsWith(System32) ||
                                       lower.StartsWith(WinDir);

                    var keyword = CheatKeywords.FirstOrDefault(k =>
                        lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (keyword is not null || !isSystemDll)
                    {
                        hits++;
                        bool exists = File.Exists(dll);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"AppInit_DLL: {Path.GetFileName(dll)}",
                            Risk     = keyword is not null ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"{hive}\{path}",
                            FileName = Path.GetFileName(dll),
                            Reason   = $"AppInit_DLL '{dll}' in {hive} registriert — " +
                                       "wird in jeden User32-nutzenden Prozess (einschließlich Spiele) geladen. " +
                                       (keyword is not null ? $"Cheat-Keyword: '{keyword}'. " : "") +
                                       (!isSystemDll ? "Pfad außerhalb System32. " : "") +
                                       (!exists ? "Datei fehlt (Tombstone)." : "Datei existiert."),
                            Detail   = $"DLL: {dll} | Keyword: {keyword ?? "keins"} | Existiert: {exists}"
                        });
                    }
                }

                // Flag disabled signature requirement
                if (requireSigned == 0 && !string.IsNullOrWhiteSpace(appInitDlls))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"AppInit_DLL: Signierpflicht deaktiviert ({hive})",
                        Risk     = RiskLevel.High,
                        Location = $@"{hive}\{path}",
                        Reason   = "RequireSignedAppInit_DLLs ist deaktiviert (0) während AppInit_DLLs " +
                                   "aktiv sind. Damit können unsignierte DLLs über AppInit in alle " +
                                   "User32-Prozesse injiziert werden.",
                        Detail   = $"RequireSignedAppInit_DLLs: 0 | DLLs: {appInitDlls}"
                    });
                }
            }
            catch { }
        }

        ctx.Report(1.0, Name, $"AppInit_DLLs geprüft, {hits} verdächtige Einträge");
        return Task.CompletedTask;
    }
}
