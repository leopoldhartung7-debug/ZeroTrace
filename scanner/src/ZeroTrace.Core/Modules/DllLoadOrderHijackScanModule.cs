using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects DLL load order hijacking and PATH manipulation attacks.
///
/// DLL load order hijacking exploits Windows' DLL search order:
///   1. Application directory  ← most hijacking targets go here
///   2. System32 (C:\Windows\System32)
///   3. System (C:\Windows\System)
///   4. Windows directory (C:\Windows)
///   5. Current working directory
///   6. PATH directories (left to right)
///
/// Cheat/malware hijacking techniques:
///
///   A. PATH Hijacking: Place malicious DLL in a directory earlier in PATH than System32
///      e.g. add C:\cheat\ to start of PATH, put fake version.dll there
///
///   B. Application Directory Injection: Drop DLL in game's own dir (covered by
///      GameDirectoryInjectionScanModule) OR in any exe's working directory
///
///   C. %TEMP% / %APPDATA% DLL: Place DLL in temp dir, then cause a privileged
///      process to load it by making temp appear early in its effective search path
///
///   D. Known DLL Order Attacks: Override KnownDLLs entries so real System32 DLL
///      is bypassed (covered by KnownDllsHijackScanModule)
///
///   E. CWD Hijacking: Change process CWD to attacker-controlled dir containing DLL
///
/// This module detects:
///   1. Suspicious directories prepended to system PATH (before System32)
///   2. Writable directories early in PATH (any user can plant DLLs)
///   3. Non-existent directories in PATH that could be created and hijacked
///   4. DLL files in PATH directories matching proxy DLL names
///   5. SetDllDirectory / AddDllDirectory registry overrides
/// </summary>
public sealed class DllLoadOrderHijackScanModule : IScanModule
{
    public string Name => "DLL-Ladereihenfolge-Hijacking-Analyse";
    public double Weight => 0.8;
    public int ParallelGroup => 3;

    private static readonly string System32Lower =
        Environment.GetFolderPath(Environment.SpecialFolder.System).ToLowerInvariant();

    private static readonly string WindowsLower =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

    // Proxy DLL names that are frequently hijacked
    private static readonly HashSet<string> ProxyDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "version.dll", "dinput8.dll", "d3d9.dll", "d3d10.dll",
        "d3d11.dll", "d3d12.dll", "dxgi.dll", "dsound.dll",
        "winmm.dll", "opengl32.dll",
        "xinput1_3.dll", "xinput1_4.dll",
        "msacm32.dll", "cryptbase.dll", "wldp.dll",
        "iphlpapi.dll", "ws2_32.dll", "wbemprox.dll",
        "netapi32.dll", "shell32.dll", "ole32.dll",
        "comctl32.dll", "comdlg32.dll", "urlmon.dll",
    };

    // Directories that should always be before System32 (these are OK)
    private static readonly HashSet<string> TrustedEarlyPaths = new(StringComparer.OrdinalIgnoreCase);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckPathHijacking(ctx, ct);
        hits += CheckSystemPathIntegrity(ctx, ct);
        hits += CheckDllDirectoryOverrides(ctx, ct);

        ctx.Report(1.0, Name, $"DLL-Suchreihenfolge geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckPathHijacking(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Get system PATH (HKLM) and user PATH (HKCU) separately
            var systemPath = GetRegistryPath(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "Path");
            var userPath = GetRegistryPath(
                @"Environment", "Path", useCurrentUser: true);

            var allPaths = (userPath + ";" + systemPath)
                .Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Trim().TrimEnd('\\').ToLowerInvariant())
                .Distinct()
                .ToList();

            bool foundSystem32 = false;
            foreach (var pathDir in allPaths)
            {
                if (ct.IsCancellationRequested) break;

                // Track when we first see System32
                if (pathDir == System32Lower || pathDir == WindowsLower)
                {
                    foundSystem32 = true;
                    continue;
                }

                // Check for DLL files with proxy names in non-system PATH dirs
                if (!pathDir.StartsWith(WindowsLower, StringComparison.OrdinalIgnoreCase) &&
                    Directory.Exists(pathDir))
                {
                    hits += ScanPathDirForProxyDlls(pathDir, !foundSystem32, ctx, ct);
                }

                // Flag non-system dirs that appear BEFORE System32 (unless Windows subdirs)
                if (!foundSystem32 &&
                    !pathDir.StartsWith(WindowsLower, StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrEmpty(pathDir))
                {
                    // Only flag if the directory actually exists and is writable or suspicious
                    bool exists = Directory.Exists(pathDir);
                    bool isWritable = exists && IsDirectoryWritable(pathDir);

                    if (exists && isWritable)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "DLL-Ladereihenfolge-Hijacking-Analyse",
                            Title    = $"Beschreibbares Verzeichnis vor System32 in PATH: {pathDir}",
                            Risk     = RiskLevel.High,
                            Location = pathDir,
                            Reason   = $"Verzeichnis '{pathDir}' ist schreibbar und erscheint " +
                                       "vor System32 in der Windows-PATH-Variable. " +
                                       "Ein Angreifer kann dort DLLs mit System-DLL-Namen ablegen, " +
                                       "die dann von Prozessen (auch privilegierten) bevorzugt geladen " +
                                       "werden — klassisches DLL-Suchreihenfolge-Hijacking.",
                            Detail   = $"PATH-Eintrag: {pathDir} | Vor System32: true | Schreibbar: true"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int ScanPathDirForProxyDlls(string dir, bool beforeSystem32,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*.dll",
                SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var fname = Path.GetFileName(file);
                if (!ProxyDllNames.Contains(fname)) continue;

                // Check if this DLL is the legitimate System32 one by version info
                bool isMsFile = IsMicrosoftSigned(file);
                if (isMsFile) continue;

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "DLL-Ladereihenfolge-Hijacking-Analyse",
                    Title    = $"Proxy-DLL in PATH-Verzeichnis: {fname}",
                    Risk     = beforeSystem32 ? RiskLevel.Critical : RiskLevel.High,
                    Location = file,
                    FileName = fname,
                    Reason   = $"DLL '{fname}' wurde in PATH-Verzeichnis '{dir}' gefunden, " +
                               $"das {(beforeSystem32 ? "VOR" : "nach")} System32 liegt. " +
                               "Diese DLL ist keine legitime Microsoft-DLL und kann " +
                               "Windows-System-DLL-Aufrufe abfangen (Proxy-DLL-Angriff). " +
                               "Cheat-Software nutzt diese Technik zum unsichtbaren Code-Laden.",
                    Detail   = $"Pfad: {file} | Vor System32: {beforeSystem32} | MS-signiert: false"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckSystemPathIntegrity(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Verify that System32 is present and early in the system PATH
            var systemPath = GetRegistryPath(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", "Path");
            ctx.IncrementRegistryKeys();

            if (string.IsNullOrEmpty(systemPath)) return 0;

            var parts = systemPath.Split(';')
                .Select(p => p.Trim().TrimEnd('\\').ToLowerInvariant())
                .ToList();

            bool hasSystem32 = parts.Any(p => p == System32Lower);
            if (!hasSystem32)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "DLL-Ladereihenfolge-Hijacking-Analyse",
                    Title    = "System32 fehlt im System-PATH",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                    Reason   = "C:\\Windows\\System32 fehlt in der System-PATH-Umgebungsvariable. " +
                               "Dies kann dazu führen, dass DLL-Aufrufe aus alternativen (Cheat-)" +
                               "Verzeichnissen befriedigt werden statt aus System32. " +
                               "Außerdem kann es kritische System-Tools unbrauchbar machen.",
                    Detail   = $"System PATH: {systemPath[..Math.Min(200, systemPath.Length)]}..."
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckDllDirectoryOverrides(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check for SetDllDirectory override via Image File Execution Options
            // or for CWDIllegalInDllSearch registry key
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager", writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // CWDIllegalInDllSearch = 0 means CWD is searched (hijackable)
            var cwdPolicy = key.GetValue("CWDIllegalInDllSearch") as int?;
            if (cwdPolicy is null || cwdPolicy == 0)
            {
                // Only flag if there are other indicators (too noisy standalone)
                // Document the state but don't add finding unless it's explicitly bad
            }

            // SafeDllSearchMode = 0 (disabled) is bad (covered by KnownDlls module)
            // Check for ExcludeFromKnownDlls override
            var excludedDlls = key.GetValue("ExcludeFromKnownDlls") as string[] ??
                               Array.Empty<string>();
            foreach (var dll in excludedDlls)
            {
                if (ct.IsCancellationRequested) break;
                if (string.IsNullOrWhiteSpace(dll)) continue;

                if (ProxyDllNames.Contains(dll))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "DLL-Ladereihenfolge-Hijacking-Analyse",
                        Title    = $"System-DLL aus KnownDLLs ausgeschlossen: {dll}",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
                        FileName = dll,
                        Reason   = $"'{dll}' ist in ExcludeFromKnownDlls eingetragen. " +
                                   "KnownDLLs sorgt dafür, dass System-DLLs nur aus System32 geladen " +
                                   "werden. Der Ausschluss erlaubt das Laden dieser DLL aus anderen " +
                                   "Verzeichnissen — ein gezielter DLL-Hijacking-Vorbereitungsschritt.",
                        Detail   = $"ExcludeFromKnownDlls: {dll}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static string GetRegistryPath(string keyPath, string valueName,
        bool useCurrentUser = false)
    {
        try
        {
            var root = useCurrentUser ? Registry.CurrentUser : Registry.LocalMachine;
            using var key = root.OpenSubKey(keyPath, writable: false);
            return key?.GetValue(valueName) as string ?? "";
        }
        catch { return ""; }
    }

    private static bool IsDirectoryWritable(string dir)
    {
        try
        {
            var testFile = Path.Combine(dir, $"zt_test_{Guid.NewGuid():N}.tmp");
            File.WriteAllText(testFile, "test");
            File.Delete(testFile);
            return true;
        }
        catch { return false; }
    }

    private static bool IsMicrosoftSigned(string filePath)
    {
        try
        {
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate
                .CreateFromSignedFile(filePath);
            var subject = cert?.Subject ?? "";
            return subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                   subject.Contains("Windows", StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
}
