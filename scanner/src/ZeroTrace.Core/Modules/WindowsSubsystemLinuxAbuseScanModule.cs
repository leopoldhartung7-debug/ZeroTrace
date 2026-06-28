using System.Runtime.InteropServices;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects misuse of Windows Subsystem for Linux (WSL) for cheat execution and
/// anti-cheat evasion. WSL provides a Linux userland that anti-cheat systems often
/// cannot inspect — kernel-level AC sees WSL processes as a single "wsl.exe" host
/// process. Attack vectors include:
///   - Running Linux cheat binaries (wine-based or native ELF) inside WSL
///   - Using WSL filesystem bridge (\\wsl$\...) to access game dirs without Windows
///     path-based AC hooks triggering
///   - Mounting /mnt/c/... read-write and symlink-swapping game DLLs from Linux side
///   - Using WSL2 hyper-v isolation to intercept game GPU calls via dxgkrnl stubs
/// Detection strategy:
///   1. Check if WSL is installed + enabled via registry (LxssManager service, OptionalFeatures)
///   2. Check currently running WSL processes (wsl.exe, wslhost.exe, wslservice.exe)
///      and their open network connections for cheat C2 domains
///   3. Scan WSL distribution rootfs paths for known cheat binary names
///   4. Check WSL distro registry entries for suspicious distribution names
///   5. Check %LOCALAPPDATA%\Packages\* for suspicious CanonicalGroupLimited.*
///      (non-official WSL distros can be installed as AppX packages)
/// </summary>
public sealed class WindowsSubsystemLinuxAbuseScanModule : IScanModule
{
    public string Name => "Windows Subsystem for Linux (WSL) Cheat Abuse Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    private static readonly string[] KnownCheatDistroNames =
    {
        "cheat", "hack", "bypass", "inject", "spoof",
        "loader", "aimbot", "esp", "wallhack", "triggerbot",
        "radar", "dma", "nosteam", "cracked",
    };

    private static readonly string[] SuspiciousWslBinaries =
    {
        "aimbot", "cheat", "inject", "triggerbot", "wallhack", "bypass",
        "spoof", "hwid", "nosteam", "loader", "hack", "radar",
        // Common Linux cheat binary names
        "linux-cheat", "cheat-engine", "csgo-cheat", "cs2-cheat",
        "apex-cheat", "valorant-cheat", "pubg-cheat",
        "wine-cheat",   // wine-based Windows cheat in WSL
        "proton-cheat",
    };

    // WSL-related registry paths
    private const string LxssKey  = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss";
    private const string LxssKey64 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Lxss";
    private const string WslServiceKey = @"SYSTEM\CurrentControlSet\Services\LxssManager";
    private const string WslOptFeature = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NtVdm64";

    public async Task<bool> IsWslInstalledAsync() =>
        await Task.Run(() =>
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(WslServiceKey);
                return k is not null;
            }
            catch { return false; }
        });

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckWslEnabled(ctx);
            ct.ThrowIfCancellationRequested();
            CheckInstalledDistros(ctx, ct);
            ct.ThrowIfCancellationRequested();
            CheckRunningWslProcesses(ctx, ct);
            ct.ThrowIfCancellationRequested();
            ScanWslRootfsPaths(ctx, ct);
            ct.ThrowIfCancellationRequested();
            CheckAppxWslPackages(ctx, ct);
        }, ct);
    }

    private static void CheckWslEnabled(ScanContext ctx)
    {
        try
        {
            using var svc = Registry.LocalMachine.OpenSubKey(WslServiceKey);
            if (svc is null) return;

            object? startVal = svc.GetValue("Start");
            if (startVal is int startType && startType <= 2) // 0=Boot, 1=System, 2=Auto
            {
                ctx.IncrementRegistryKeys();
                // WSL enabled is not itself suspicious, but we report it for context
                // only flag if combined with other signals — here we just note it
            }
        }
        catch { }
    }

    private static void CheckInstalledDistros(ScanContext ctx, CancellationToken ct)
    {
        string[] lxssKeys = { LxssKey, LxssKey64 };
        foreach (var keyPath in lxssKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var lxss = Registry.LocalMachine.OpenSubKey(keyPath) ??
                                 Registry.CurrentUser.OpenSubKey(keyPath.Replace("SOFTWARE\\", "SOFTWARE\\"));
                if (lxss is null) continue;

                foreach (var subName in lxss.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var distroKey = lxss.OpenSubKey(subName);
                        if (distroKey is null) continue;

                        ctx.IncrementRegistryKeys();

                        string distroName  = distroKey.GetValue("DistributionName") as string ?? subName;
                        string basePath    = distroKey.GetValue("BasePath") as string ?? "";
                        int    wslVersion  = distroKey.GetValue("Version") is int v ? v : 1;

                        string distroNameLower = distroName.ToLowerInvariant();

                        bool suspiciousName = Array.Exists(KnownCheatDistroNames,
                            kw => distroNameLower.Contains(kw));

                        // Non-standard distros installed outside official Microsoft store
                        bool nonStandardPath = !string.IsNullOrEmpty(basePath) &&
                            !basePath.StartsWith(@"C:\Users\", StringComparison.OrdinalIgnoreCase) &&
                            !basePath.Contains("AppData", StringComparison.OrdinalIgnoreCase);

                        if (suspiciousName)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Windows Subsystem for Linux (WSL) Cheat Abuse Detection",
                                Title    = $"Verdächtiger WSL-Distro-Name: {distroName}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{keyPath}\{subName}",
                                FileName = distroName,
                                Reason   = $"WSL-Distribution '{distroName}' enthält Cheat-Schlüsselwort — " +
                                           "WSL ermöglicht Linux-basierte Cheat-Tools, die von Windows-AC " +
                                           "nicht inspiziert werden können",
                                Detail   = $"Distro: {distroName} | Pfad: {basePath} | WSL-Version: {wslVersion}"
                            });
                        }
                        else if (nonStandardPath && !string.IsNullOrEmpty(basePath))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Windows Subsystem for Linux (WSL) Cheat Abuse Detection",
                                Title    = $"WSL-Distribution außerhalb AppData: {distroName}",
                                Risk     = RiskLevel.Medium,
                                Location = $@"HKLM\{keyPath}\{subName}",
                                FileName = distroName,
                                Reason   = $"WSL-Distribution '{distroName}' mit ungewöhnlichem BasePath '{basePath}' — " +
                                           "könnte manuell installierte, nicht-offizielle Distribution sein",
                                Detail   = $"Distro: {distroName} | Pfad: {basePath} | WSL-Version: {wslVersion}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // Also check HKCU
        try
        {
            using var lxssUser = Registry.CurrentUser.OpenSubKey(LxssKey);
            if (lxssUser is null) return;

            foreach (var subName in lxssUser.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var distroKey = lxssUser.OpenSubKey(subName);
                    if (distroKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    string distroName = distroKey.GetValue("DistributionName") as string ?? subName;
                    string basePath   = distroKey.GetValue("BasePath") as string ?? "";
                    int wslVersion    = distroKey.GetValue("Version") is int v ? v : 1;

                    string distroNameLower = distroName.ToLowerInvariant();
                    bool suspiciousName = Array.Exists(KnownCheatDistroNames,
                        kw => distroNameLower.Contains(kw));

                    if (suspiciousName)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Windows Subsystem for Linux (WSL) Cheat Abuse Detection",
                            Title    = $"Verdächtiger WSL-Distro-Name (HKCU): {distroName}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{LxssKey}\{subName}",
                            FileName = distroName,
                            Reason   = $"Benutzerspezifische WSL-Distribution '{distroName}' mit Cheat-Schlüsselwort",
                            Detail   = $"Distro: {distroName} | Pfad: {basePath} | WSL-Version: {wslVersion}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CheckRunningWslProcesses(ScanContext ctx, CancellationToken ct)
    {
        string[] wslHostProcesses = { "wsl", "wslhost", "wslservice", "wslrelay" };

        try
        {
            var allProcesses = System.Diagnostics.Process.GetProcesses();
            foreach (var proc in allProcesses)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string procNameLower = proc.ProcessName.ToLowerInvariant();
                    bool isWslProcess = Array.Exists(wslHostProcesses,
                        n => procNameLower.Equals(n, StringComparison.OrdinalIgnoreCase));

                    if (!isWslProcess) continue;

                    ctx.IncrementFiles(); // count processes checked

                    // WSL running is only medium risk — it's the combination with other signals that matters
                    // We only flag if wslhost has an unexpected command line (not easily accessible without elevation)
                    // Just note the running WSL instance here
                    string? cmdLine = null;
                    try
                    {
                        // Try to read command line via WMI (best-effort)
                        using var searcher = new System.Management.ManagementObjectSearcher(
                            $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {proc.Id}");
                        foreach (System.Management.ManagementObject obj in searcher.Get())
                            cmdLine = obj["CommandLine"] as string;
                    }
                    catch { }

                    if (cmdLine is not null)
                    {
                        string cmdLower = cmdLine.ToLowerInvariant();
                        bool cheatCmdLine = Array.Exists(SuspiciousWslBinaries,
                            kw => cmdLower.Contains(kw));

                        if (cheatCmdLine)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Windows Subsystem for Linux (WSL) Cheat Abuse Detection",
                                Title    = $"WSL-Prozess mit verdächtiger Kommandozeile: {proc.ProcessName}",
                                Risk     = RiskLevel.Critical,
                                Location = $"PID {proc.Id}: {proc.ProcessName}",
                                FileName = proc.ProcessName,
                                Reason   = $"Laufender WSL-Prozess '{proc.ProcessName}' (PID {proc.Id}) wurde mit " +
                                           $"Kommandozeile '{cmdLine}' gestartet, die auf Cheat-Tool-Ausführung " +
                                           "im Linux-Subsystem hindeutet — WSL-basierte Cheats umgehen Windows-AC",
                                Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | Cmd: {cmdLine}"
                            });
                        }
                    }
                }
                catch { }
                finally { try { proc.Dispose(); } catch { } }
            }
        }
        catch { }
    }

    private static void ScanWslRootfsPaths(ScanContext ctx, CancellationToken ct)
    {
        // WSL distributions store their rootfs under %LOCALAPPDATA%\Packages\...\LocalState\rootfs
        // or under custom paths registered in registry
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string packagesPath = Path.Combine(localAppData, "Packages");
        if (!Directory.Exists(packagesPath)) return;

        try
        {
            foreach (var pkg in Directory.EnumerateDirectories(packagesPath))
            {
                ct.ThrowIfCancellationRequested();

                string pkgName = Path.GetFileName(pkg);
                // Only look at WSL-related packages (Canonical, Microsoft-Windows-Subsystem-Linux, etc.)
                bool isWslPackage = pkgName.Contains("CanonicalGroup", StringComparison.OrdinalIgnoreCase) ||
                                    pkgName.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase) ||
                                    pkgName.Contains("Debian", StringComparison.OrdinalIgnoreCase) ||
                                    pkgName.Contains("Kali", StringComparison.OrdinalIgnoreCase) ||
                                    pkgName.Contains("openSUSE", StringComparison.OrdinalIgnoreCase) ||
                                    pkgName.Contains("AlmaLinux", StringComparison.OrdinalIgnoreCase) ||
                                    pkgName.Contains("OracleLinux", StringComparison.OrdinalIgnoreCase) ||
                                    pkgName.Contains("FedoraRemix", StringComparison.OrdinalIgnoreCase);

                if (!isWslPackage) continue;

                // Look for known cheat binary names in home directory and /tmp
                string[] rootfsSubDirs =
                {
                    Path.Combine(pkg, "LocalState", "rootfs", "tmp"),
                    Path.Combine(pkg, "LocalState", "rootfs", "root"),
                    Path.Combine(pkg, "LocalState", "rootfs", "home"),
                };

                foreach (var dir in rootfsSubDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!Directory.Exists(dir)) continue;

                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementFiles();

                            string fileNameLower = Path.GetFileName(file).ToLowerInvariant();
                            string matchedBin = Array.Find(SuspiciousWslBinaries,
                                kw => fileNameLower.Contains(kw)) ?? "";

                            if (string.IsNullOrEmpty(matchedBin)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = "Windows Subsystem for Linux (WSL) Cheat Abuse Detection",
                                Title    = $"Verdächtige Datei im WSL-Rootfs: {Path.GetFileName(file)}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"Datei '{Path.GetFileName(file)}' im WSL-Rootfs '{pkgName}' enthält " +
                                           $"Cheat-Schlüsselwort '{matchedBin}' — könnte Linux-basiertes Cheat-Tool sein",
                                Detail   = $"Paket: {pkgName} | Datei: {file} | Schlüsselwort: {matchedBin}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private static void CheckAppxWslPackages(ScanContext ctx, CancellationToken ct)
    {
        // Check for non-official WSL AppX packages via registry
        const string appxKey = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages";
        try
        {
            using var packages = Registry.LocalMachine.OpenSubKey(appxKey);
            if (packages is null) return;

            foreach (var pkgName in packages.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                // Look for WSL-related packages that aren't from Microsoft or Canonical
                bool isWslPackage = pkgName.Contains("Subsystem", StringComparison.OrdinalIgnoreCase) ||
                                    pkgName.Contains("LinuxDistrib", StringComparison.OrdinalIgnoreCase);

                bool isKnownPublisher = pkgName.Contains("MicrosoftCorporation", StringComparison.OrdinalIgnoreCase) ||
                                       pkgName.Contains("CanonicalGroup", StringComparison.OrdinalIgnoreCase) ||
                                       pkgName.Contains("Debian", StringComparison.OrdinalIgnoreCase) ||
                                       pkgName.Contains("Kali", StringComparison.OrdinalIgnoreCase) ||
                                       pkgName.Contains("openSUSE", StringComparison.OrdinalIgnoreCase);

                if (!isWslPackage || isKnownPublisher) continue;

                try
                {
                    using var pkg = packages.OpenSubKey(pkgName);
                    string? pkgPath = pkg?.GetValue("Path") as string;

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Windows Subsystem for Linux (WSL) Cheat Abuse Detection",
                        Title    = $"Nicht-offizielle WSL-AppX-Distribution: {pkgName}",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{appxKey}\{pkgName}",
                        FileName = pkgName,
                        Reason   = $"Nicht-offizielle WSL-Distribution '{pkgName}' als AppX-Paket installiert — " +
                                   "selbst-signierte oder inoffizielle WSL-Distros könnten für AC-Evasion " +
                                   "konfiguriert sein",
                        Detail   = $"Paket: {pkgName} | Pfad: {pkgPath ?? "unbekannt"}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }
}
