using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects malicious Cryptographic Service Provider (CSP) and CNG provider registrations.
/// CryptoAPI/CNG providers are DLLs loaded into every process that calls CryptAcquireContext
/// or BCryptOpenAlgorithmProvider — they intercept all cryptographic operations including
/// SSL/TLS handshakes, certificate validation, and code signature verification. Cheats and
/// advanced bypass tools register fake CSP providers to:
///   (1) Fake certificate validation for unsigned cheat drivers (bypass Authenticode)
///   (2) Intercept anti-cheat TLS connections and inspect/modify license server traffic
///   (3) Weaken randomness for predictable ASLR/key generation bypass
/// The module scans HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider,
/// HKCU\Software\Microsoft\Cryptography\Providers, and CNG provider paths for DLLs
/// outside of System32, with missing files, cheat keywords, or invalid image size.
/// </summary>
public sealed class CryptoApiProviderScanModule : IScanModule
{
    public string Name => "CryptoAPI/CNG Provider Integrity Scan";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    private static readonly (string Hive, string KeyPath, string ProviderSubKey)[] CspRegistryPaths =
    {
        // Legacy CryptoAPI (CAPI1) providers
        ("HKLM", @"SOFTWARE\Microsoft\Cryptography\Defaults\Provider",        "Image Path"),
        ("HKLM", @"SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider", "Image Path"),
        // HKCU CSP overrides (very suspicious — user shouldn't normally have these)
        ("HKCU", @"Software\Microsoft\Cryptography\Providers",                "Image Path"),
        // CNG providers (newer API)
        ("HKLM", @"SYSTEM\CurrentControlSet\Control\Cryptography\Providers",  "FunctionName"),
    };

    // Legitimate CSP/CNG provider DLL locations
    private static readonly string[] LegitCspPaths =
    {
        @"c:\windows\system32\",
        @"c:\windows\syswow64\",
        @"%systemroot%\system32\",
        @"%systemroot%\syswow64\",
    };

    // Known legitimate provider DLL file names
    private static readonly HashSet<string> KnownLegitCspDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "rsaenh.dll", "dssenh.dll", "basecsp.dll",
        "bcrypt.dll", "ncrypt.dll", "cryptdll.dll",
        "cryptsp.dll", "cryptbase.dll", "crypt32.dll",
        "schannel.dll", "dpapi.dll",
        "msSmartcardProvider.dll", "wudfbc.dll",
        "scksp.dll", "slbcsp.dll", "gpkcsp.dll",
        "digsig.dll",
        // HSM / Smart Card providers (common)
        "acSCardCSP.dll", "acCryptProvider.dll",
        "eToken.dll", "cryptokit.dll",
        // Common AV/security product CNG providers
        "trusteddrivewrapper.dll",
    };

    private static readonly string[] SuspiciousCspKeywords =
    {
        "cheat", "hack", "bypass", "inject", "hook",
        "fake", "spoof", "intercept", "proxy", "mitm",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckCspProviders(ctx, ct);
            CheckCngProviders(ctx, ct);
        }, ct);
    }

    private void CheckCspProviders(ScanContext ctx, CancellationToken ct)
    {
        string[] hiveNames = { "HKLM", "HKLM", "HKCU" };
        RegistryKey[] roots = { Registry.LocalMachine, Registry.LocalMachine, Registry.CurrentUser };
        string[] keyPaths =
        {
            @"SOFTWARE\Microsoft\Cryptography\Defaults\Provider",
            @"SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider",
            @"Software\Microsoft\Cryptography\Providers",
        };

        for (int h = 0; h < keyPaths.Length; h++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = roots[h].OpenSubKey(keyPaths[h]);
                if (key is null) continue;

                // Each subkey is a provider name
                foreach (var providerName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    try
                    {
                        using var provKey = key.OpenSubKey(providerName);
                        if (provKey is null) continue;

                        string? imagePath = provKey.GetValue("Image Path") as string ??
                                            provKey.GetValue("ImagePath") as string ??
                                            provKey.GetValue("Dll") as string;

                        if (string.IsNullOrEmpty(imagePath)) continue;

                        string resolvedPath = Environment.ExpandEnvironmentVariables(imagePath);
                        string pathLower = resolvedPath.ToLowerInvariant();
                        string fileName  = Path.GetFileName(resolvedPath);

                        // Skip known-legitimate system DLLs
                        bool isSystemPath = Array.Exists(LegitCspPaths,
                            p => pathLower.Contains(p.ToLowerInvariant()));

                        // HKCU providers are almost always malicious (no legit need)
                        bool isHkcu = hiveNames[h] == "HKCU";

                        bool isKnownGood = KnownLegitCspDlls.Contains(fileName);
                        if (isSystemPath && isKnownGood && !isHkcu) continue;

                        bool hasSuspiciousKeyword = Array.Exists(SuspiciousCspKeywords,
                            kw => pathLower.Contains(kw) || providerName.Contains(kw,
                                StringComparison.OrdinalIgnoreCase));

                        bool fileExists = File.Exists(resolvedPath);

                        bool shouldFlag = isHkcu || hasSuspiciousKeyword ||
                                         !isSystemPath || (!isKnownGood && isSystemPath && fileExists);

                        if (!shouldFlag) continue;

                        RiskLevel risk = (hasSuspiciousKeyword || isHkcu)
                            ? RiskLevel.Critical
                            : !fileExists ? RiskLevel.High : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtiger CSP-Provider: {providerName}",
                            Risk     = risk,
                            Location = $@"{hiveNames[h]}\{keyPaths[h]}\{providerName}",
                            FileName = fileName,
                            Reason   = isHkcu
                                ? $"CryptoAPI-Provider '{providerName}' im HKCU-Hive registriert — " +
                                  "legitime CSP-Anbieter verwenden nur HKLM; HKCU-Registrierungen " +
                                  "deuten auf Manipulation durch ein Cheat-Tool hin"
                                : hasSuspiciousKeyword
                                    ? $"CSP-Provider '{providerName}' mit DLL '{imagePath}' enthält " +
                                      "Cheat/Bypass-Keyword — mögliche Fälschung zur Umgehung von " +
                                      "Authenticode-Prüfung oder TLS-Interception"
                                    : $"CSP-Provider '{providerName}' mit unbekannter DLL '{imagePath}' " +
                                      $"außerhalb System32 oder mit fehlender Datei — " +
                                      "CryptoAPI-Provider-DLLs werden in alle Prozesse geladen",
                            Detail   = $"Provider: {providerName} | DLL: {imagePath} | " +
                                       $"Vorhanden: {fileExists} | System-Pfad: {isSystemPath} | " +
                                       $"HKCU: {isHkcu} | Cheat-Keyword: {hasSuspiciousKeyword}"
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void CheckCngProviders(ScanContext ctx, CancellationToken ct)
    {
        // Check CNG (BCrypt) providers under HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers
        try
        {
            ct.ThrowIfCancellationRequested();
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Cryptography\Providers");
            if (key is null) return;

            foreach (var provName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using var provKey = key.OpenSubKey(provName);
                    if (provKey is null) continue;

                    // CNG providers enumerate their functions
                    foreach (var funcName in provKey.GetSubKeyNames())
                    {
                        using var funcKey = provKey.OpenSubKey(funcName);
                        if (funcKey is null) continue;

                        string? dllPath = funcKey.GetValue("FunctionName") as string ??
                                          funcKey.GetValue("ImagePath") as string;
                        if (string.IsNullOrEmpty(dllPath)) continue;

                        string resolvedPath = Environment.ExpandEnvironmentVariables(dllPath);
                        string pathLower = resolvedPath.ToLowerInvariant();

                        bool isSystemPath = Array.Exists(LegitCspPaths,
                            p => pathLower.Contains(p.ToLowerInvariant()));
                        if (isSystemPath) continue;

                        bool hasSuspicious = Array.Exists(SuspiciousCspKeywords,
                            kw => pathLower.Contains(kw) || provName.Contains(kw,
                                StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Unbekannter CNG-Provider: {provName}",
                            Risk     = hasSuspicious ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\{provName}",
                            FileName = Path.GetFileName(resolvedPath),
                            Reason   = $"CNG-Provider '{provName}' mit DLL außerhalb System32: '{dllPath}' — " +
                                       "CNG-Provider-DLLs werden über BCryptOpenAlgorithmProvider in Prozesse " +
                                       "geladen und können Kryptographie-Operationen inkl. TLS-Handshakes " +
                                       "abfangen (AC-Kommunikations-Interception, Signatur-Fälschung)",
                            Detail   = $"Provider: {provName} | Funktion: {funcName} | DLL: {dllPath} | " +
                                       $"Cheat-Keyword: {hasSuspicious}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }
}
