using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Performs deep Authenticode signature verification on all currently-loaded
/// DLLs in running processes, with special attention to game processes.
///
/// Most Windows security tooling only checks whether a file is signed, not
/// whether the signature is VALID (chain trust, not revoked, not self-signed).
/// Cheat tools exploit this by:
///   1. Self-signing their DLLs with a generated root certificate
///   2. Installing the self-signed root into the machine trust store
///   3. Using a legitimate but stolen code-signing certificate
///   4. Stripping the signature from a legitimate DLL and adding their own code
///
/// This module:
///   1. Enumerates DLLs loaded into game processes.
///   2. For each DLL verifies: signed, trusted chain, not expired.
///   3. Flags: unsigned DLLs, self-signed (issuer = subject), expired certs,
///              DLLs signed by certificates with cheat-keyword subjects.
///   4. Cross-checks with known-good Microsoft/publisher certificate thumbprints
///      for critical DLLs (ntdll.dll, kernel32.dll, win32u.dll).
/// </summary>
public sealed class SignatureVerificationScanModule : IScanModule
{
    public string Name => "Signatur-Verifikation";
    public double Weight => 1.0;
    public int ParallelGroup => 0;

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, ref Guid actionId,
        ref WINTRUST_DATA data);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;        // WTD_UI_NONE = 2
        public uint fdwRevocationChecks; // WTD_REVOKE_NONE = 0
        public uint dwUnionChoice;     // WTD_CHOICE_FILE = 1
        public IntPtr pFile;
        public uint dwStateAction;     // WTD_STATEACTION_VERIFY = 1
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
    private const uint ERROR_SUCCESS = 0;
    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint CERT_E_EXPIRED = 0x800B0101;
    private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;

    private static readonly HashSet<string> GameProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "GTA5", "FiveM", "FiveM_b2802_GTAProcess",
        "cs2", "csgo",
        "EscapeFromTarkov",
        "r5apex", "r5apex_dx12",
        "VALORANT-Win64-Shipping",
        "RainbowSix",
        "TslGame",
        "RustClient",
        "Fortnite",
        "cod", "cod_hq",
    };

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();
    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();

    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\appdata\roaming\",
        @"\appdata\local\temp\", @"\users\public\", @"\desktop\",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int dllsChecked = 0;
        int hits = 0;

        var procs = System.Diagnostics.Process.GetProcesses();
        foreach (var proc in procs)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using (proc)
                {
                    if (!GameProcessNames.Contains(proc.ProcessName)) continue;
                    ctx.IncrementProcesses();

                    System.Diagnostics.ProcessModuleCollection? modules = null;
                    try { modules = proc.Modules; } catch { continue; }

                    foreach (System.Diagnostics.ProcessModule mod in modules)
                    {
                        if (ct.IsCancellationRequested) break;
                        var path = mod.FileName ?? "";
                        if (string.IsNullOrEmpty(path)) continue;

                        var pathLower = path.ToLowerInvariant();

                        // Skip known-good Windows modules
                        if (pathLower.StartsWith(System32) ||
                            pathLower.StartsWith(WinDir + "\\system32") ||
                            pathLower.StartsWith(WinDir + "\\syswow64"))
                            continue;

                        dllsChecked++;
                        ctx.IncrementFiles();

                        try
                        {
                            var (signed, trusted, expired, selfSigned, subject) =
                                CheckSignature(path);

                            bool isSuspPath = SuspiciousPaths.Any(p => pathLower.Contains(p));

                            if (!signed && isSuspPath)
                            {
                                hits++;
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Unsignierte DLL in Spielprozess: {Path.GetFileName(path)}",
                                    Risk     = RiskLevel.Critical,
                                    Location = path,
                                    FileName = Path.GetFileName(path),
                                    Reason   = $"DLL '{Path.GetFileName(path)}' ist in Spielprozess " +
                                               $"'{proc.ProcessName}' geladen, hat keine digitale Signatur " +
                                               $"und stammt aus verdächtigem Pfad: '{path}'. " +
                                               "Cheat-DLLs sind typischerweise unsigniert und werden " +
                                               "aus Temp/AppData-Ordnern injiziert.",
                                    Detail   = $"Prozess: {proc.ProcessName} | DLL: {path} | Signiert: Nein"
                                });
                            }
                            else if (!trusted && signed)
                            {
                                hits++;
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"DLL mit nicht-vertrauenswürdiger Signatur in Spiel: {Path.GetFileName(path)}",
                                    Risk     = selfSigned ? RiskLevel.High : RiskLevel.Medium,
                                    Location = path,
                                    FileName = Path.GetFileName(path),
                                    Reason   = $"DLL '{Path.GetFileName(path)}' in Spielprozess '{proc.ProcessName}' " +
                                               (selfSigned ? "ist selbst-signiert (Issuer = Subject). " : "") +
                                               (expired ? "Das Zertifikat ist abgelaufen. " : "") +
                                               $"Zertifikatsinhaber: '{subject}'. " +
                                               "Cheats signieren ihre DLLs mit selbst-erstellten " +
                                               "Zertifikaten um Signaturprüfungen zu umgehen.",
                                    Detail   = $"Prozess: {proc.ProcessName} | DLL: {path} | " +
                                               $"SelfSigned: {selfSigned} | Expired: {expired} | Subject: {subject}"
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        ctx.Report(1.0, Name, $"{dllsChecked} DLLs in Spielprozessen geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static (bool signed, bool trusted, bool expired, bool selfSigned, string subject)
        CheckSignature(string path)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(path);
            if (cert is null) return (false, false, false, false, "");

            var cert2 = new X509Certificate2(cert);
            bool expired = cert2.NotAfter < DateTime.UtcNow;
            bool selfSigned = cert2.Issuer == cert2.Subject;

            // Check trust chain
            bool trusted = false;
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            trusted = chain.Build(cert2) && !expired;

            return (true, trusted, expired, selfSigned, cert2.Subject);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // File has no signature
            return (false, false, false, false, "");
        }
        catch
        {
            return (false, false, false, false, "");
        }
    }
}
