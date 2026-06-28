using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects malicious LSA (Local Security Authority) authentication packages,
/// Security Support Providers (SSP), and notification packages.
///
/// The Windows LSA loads authentication packages and SSPs at boot. These DLLs
/// run inside lsass.exe (SYSTEM, Protected Process Light) and have access to:
///   - All plaintext credentials during logon
///   - Kerberos tickets and NTLM hashes
///   - LSA secrets
///
/// Attackers abuse LSA packages for:
///   1. Credential theft: register a notification package that receives all
///      passwords during password change events (classic "passfilt.dll" abuse)
///   2. Persistence: LSA packages survive reboots and run as SYSTEM
///   3. Token manipulation: SSPs can forge authentication tokens
///
/// Registry locations:
///   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages
///   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
///   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
///   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
///   HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SecurityProviders
/// </summary>
public sealed class LsaPluginScanModule : IScanModule
{
    private static readonly string _name = "LSA-Plugin-Analyse";
    public string Name => _name;
    public double Weight => 0.8;
    public int ParallelGroup => 3;

    private const string LsaKey = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string SecurityProvidersKey =
        @"SYSTEM\CurrentControlSet\Control\SecurityProviders";

    // Known legitimate LSA packages
    private static readonly HashSet<string> KnownGoodPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "msv1_0", "kerberos", "wdigest", "schannel", "tspkg",
        "pku2u", "livessp", "cloudap", "negoexts",
        "msoidssp", "msnsspc", "msapsspc",
        // Security providers
        "credssp.dll", "schannel.dll", "digest.dll",
        // Notification packages
        "rassfm", "kdcsvc", "wdigest",
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "steal",
        "dump", "cred", "token", "mimikatz",
        "kiddion", "cherax", "spoofer",
    };

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        // Check Authentication Packages
        hits += CheckLsaMultiSzValue("Authentication Packages",
            "Authentifizierungspaket", ctx, ct);

        // Check Security Packages
        hits += CheckLsaMultiSzValue("Security Packages",
            "Security-Paket", ctx, ct);

        // Check Notification Packages
        hits += CheckLsaMultiSzValue("Notification Packages",
            "Benachrichtigungspaket", ctx, ct);

        // Check SSP DLLs
        hits += CheckSecurityProviders(ctx, ct);

        ctx.Report(1.0, Name, $"LSA-Plugins geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckLsaMultiSzValue(string valueName, string typeLabel,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(LsaKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var raw = key.GetValue(valueName);
            string[] packages;
            if (raw is string[] arr)
                packages = arr;
            else if (raw is string s)
                packages = new[] { s };
            else
                return 0;

            foreach (var pkg in packages)
            {
                if (ct.IsCancellationRequested) break;
                if (string.IsNullOrWhiteSpace(pkg)) continue;

                var lower = pkg.ToLowerInvariant();

                if (KnownGoodPackages.Any(g => lower.Equals(g, StringComparison.OrdinalIgnoreCase) ||
                                               lower.Equals(g + ".dll", StringComparison.OrdinalIgnoreCase)))
                    continue;

                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                bool isSystemPath = lower.Contains(System32);
                bool isDll = lower.EndsWith(".dll");

                // Non-system, unknown package is suspicious
                if (cheatKw is not null || !isSystemPath || !isDll)
                {
                    hits++;
                    var dllPath = isDll ? pkg : Path.Combine(System32, pkg + ".dll");
                    bool exists = File.Exists(dllPath);

                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Unbekanntes LSA-{typeLabel}: {pkg}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"HKLM\{LsaKey}\{valueName}",
                        FileName = Path.GetFileName(pkg),
                        Reason   = $"Unbekanntes LSA-{typeLabel} '{pkg}' registriert. " +
                                   "LSA-Pakete laufen in lsass.exe (SYSTEM) und haben Zugriff auf " +
                                   "alle Anmeldedaten. Cheat-Tools missbrauchen LSA-Pakete für " +
                                   "Credential-Dumping und Persistenz. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   (!exists ? "DLL-Datei fehlt." : ""),
                        Detail   = $"Paket: {pkg} | DLL: {dllPath} | Existiert: {exists} | Keyword: {cheatKw ?? "keins"}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckSecurityProviders(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(SecurityProvidersKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var providers = key.GetValue("SecurityProviders") as string ?? "";
            var dlls = providers.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);

            foreach (var dll in dlls)
            {
                if (ct.IsCancellationRequested) break;
                var lower = dll.Trim().ToLowerInvariant();

                if (KnownGoodPackages.Any(g => lower.Contains(g, StringComparison.OrdinalIgnoreCase)))
                    continue;

                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    lower.Contains(k, StringComparison.OrdinalIgnoreCase));
                bool isSystemDll = lower.Contains(System32);

                if (cheatKw is not null || !isSystemDll)
                {
                    hits++;
                    var dllPath = lower.Contains('\\') ? dll
                        : Path.Combine(System32, dll);

                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Unbekannter Security-Provider: {dll}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"HKLM\{SecurityProvidersKey}",
                        FileName = Path.GetFileName(dll),
                        Reason   = $"Unbekannter Security Support Provider '{dll}'. " +
                                   "SSPs laufen in lsass.exe und können Anmeldedaten abfangen. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'." : "Nicht in System32."),
                        Detail   = $"Provider: {dll} | Pfad: {dllPath}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
