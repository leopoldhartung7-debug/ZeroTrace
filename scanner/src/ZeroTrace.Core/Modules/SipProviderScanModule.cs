using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Subject Interface Package (SIP) and Trust Provider DLL hijacking
/// used to bypass Authenticode signature verification.
///
/// Windows Code Integrity / WinVerifyTrust delegates the actual signature
/// verification to registered SIP providers and Trust Providers. An attacker
/// who replaces these DLLs can make Windows report any unsigned or tampered
/// binary as "correctly signed" — effectively bypassing the entire PKI chain.
///
/// Used by advanced cheat loaders to:
///   1. Make their unsigned/self-signed DLLs pass signature checks
///   2. Prevent kernel drivers from being blocked by WHQL signature enforcement
///   3. Fool anti-cheat clients that call WinVerifyTrust internally
///
/// Key registry locations:
///   HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\
///     CryptSIPDllVerifyIndirectData\{GUID}\   — PE, Cabinet, CTL, etc.
///     CryptSIPDllGetSignedDataMsg\{GUID}\
///     CryptSIPDllPutSignedDataMsg\{GUID}\
///     CryptSIPDllCreateIndirectData\{GUID}\
///   HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy\{GUID}\
///   HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust\Initialization\{GUID}\
/// </summary>
public sealed class SipProviderScanModule : IScanModule
{
    private static readonly string _name = "SIP-Provider-Analyse";
    public string Name => _name;
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "spoof",
        "patch", "hook", "fake", "dummy", "stub",
    };

    // Well-known SIP DLLs that ship with Windows
    private static readonly HashSet<string> KnownGoodSipDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "wintrust.dll", "mssip32.dll", "mscoree.dll", "clrjit.dll",
        "sfc.dll", "sfc_os.dll", "ntoskrnl.exe",
        "crypt32.dll", "cryptui.dll", "cryptnet.dll",
        "softpub.dll", "winsip.dll",
        "msdxm.ocx", "initpki.dll", "vsrevoke.ocx",
        "gpkcsp.dll", "sccbase.dll", "slbcsp.dll",
        // Catalog SIP
        "mscatadm.dll",
        // Office / CAB
        "mscat32.dll", "cabinet.dll",
    };

    private const string SipRootKey =
        @"SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0";

    private static readonly string[] SipFunctions =
    {
        "CryptSIPDllVerifyIndirectData",
        "CryptSIPDllGetSignedDataMsg",
        "CryptSIPDllPutSignedDataMsg",
        "CryptSIPDllCreateIndirectData",
        "CryptSIPDllIsMyFileType",
        "CryptSIPDllIsMyFileType2",
    };

    private const string TrustProvidersKey =
        @"SOFTWARE\Microsoft\Cryptography\Providers\Trust";

    private static readonly string[] TrustFunctions =
    {
        "Initialization", "Message", "Signature", "Certificate",
        "CertCheck", "PolicyProvider", "FinalPolicy", "Cleanup",
        "DiagnosticPolicy",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckSipFunctions(ctx, ct);
        hits += CheckTrustProviders(ctx, ct);

        ctx.Report(1.0, Name, $"SIP/Trust-Provider geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckSipFunctions(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(SipRootKey, writable: false);
            if (root is null) return 0;

            foreach (var funcName in SipFunctions)
            {
                if (ct.IsCancellationRequested) break;

                using var funcKey = root.OpenSubKey(funcName, writable: false);
                if (funcKey is null) continue;

                foreach (var guidName in funcKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementRegistryKeys();

                    using var guidKey = funcKey.OpenSubKey(guidName, writable: false);
                    if (guidKey is null) continue;

                    var dll = guidKey.GetValue("Dll") as string ?? "";
                    if (string.IsNullOrWhiteSpace(dll)) continue;

                    var dllLower = dll.ToLowerInvariant();
                    var dllName  = Path.GetFileName(dllLower);

                    bool isSystem32Dll = dllLower.StartsWith(System32);
                    bool isKnownGood   = KnownGoodSipDlls.Contains(dllName);

                    if (isSystem32Dll && isKnownGood) continue;

                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        dllLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (cheatKw is not null || !isSystem32Dll || !isKnownGood)
                    {
                        hits++;
                        bool exists = File.Exists(dll);
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"Verdächtiger SIP-Provider: {dllName}",
                            Risk     = cheatKw is not null || !exists ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"HKLM\{SipRootKey}\{funcName}\{guidName}",
                            FileName = dllName,
                            Reason   = $"SIP-Funktion '{funcName}' (GUID {guidName}) ist auf " +
                                       $"unbekannte DLL '{dll}' registriert. " +
                                       "SIP-Provider-Hijacking ermöglicht es, WinVerifyTrust zu täuschen " +
                                       "und unsignierte/manipulierte Dateien als gültig zu melden. " +
                                       "Cheat-Loader nutzen dies, um Treiber-Signaturprüfungen zu umgehen. " +
                                       (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                       (!isSystem32Dll ? "DLL außerhalb System32. " : "") +
                                       (!exists ? "DLL fehlt (möglicherweise bereits entfernt)." : ""),
                            Detail   = $"Funktion: {funcName} | GUID: {guidName} | DLL: {dll} | Existiert: {exists}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckTrustProviders(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(TrustProvidersKey, writable: false);
            if (root is null) return 0;

            foreach (var funcName in TrustFunctions)
            {
                if (ct.IsCancellationRequested) break;

                using var funcKey = root.OpenSubKey(funcName, writable: false);
                if (funcKey is null) continue;

                foreach (var guidName in funcKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementRegistryKeys();

                    using var guidKey = funcKey.OpenSubKey(guidName, writable: false);
                    if (guidKey is null) continue;

                    var dll = guidKey.GetValue("$DLL") as string ?? "";
                    if (string.IsNullOrWhiteSpace(dll)) continue;

                    var dllLower = dll.ToLowerInvariant();
                    var dllName  = Path.GetFileName(dllLower);

                    bool isSystem32Dll = dllLower.StartsWith(System32);
                    bool isKnownGood   = KnownGoodSipDlls.Contains(dllName);

                    if (isSystem32Dll && isKnownGood) continue;

                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        dllLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (cheatKw is not null || !isSystem32Dll || !isKnownGood)
                    {
                        hits++;
                        bool exists = File.Exists(dll.Contains('\\') ? dll
                            : Path.Combine(System32, dll));
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"Verdächtiger Trust-Provider: {dllName}",
                            Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"HKLM\{TrustProvidersKey}\{funcName}\{guidName}",
                            FileName = dllName,
                            Reason   = $"Trust-Provider-Funktion '{funcName}' (GUID {guidName}) verweist " +
                                       $"auf unbekannte DLL '{dll}'. " +
                                       "Trust-Provider steuern, ob WinVerifyTrust eine Signatur als " +
                                       "gültig akzeptiert — Hijacking umgeht Kernel-Codesignierpflicht. " +
                                       (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                       (!isSystem32Dll ? "DLL außerhalb System32." : ""),
                            Detail   = $"Funktion: {funcName} | GUID: {guidName} | DLL: {dll} | Existiert: {exists}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }
}
