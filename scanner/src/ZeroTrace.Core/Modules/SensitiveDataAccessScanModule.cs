using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects artifacts from credential theft and sensitive data access attempts.
///
/// This module looks for files and directories indicating that sensitive Windows
/// credential stores have been accessed, copied, or dumped:
///
///   1. LSASS Memory Dumps: Dumping lsass.exe memory extracts all cached credentials.
///      Tools: procdump, Task Manager, comsvcs.dll MiniDump, nanodump, pypykatz.
///      Look for: *.dmp files, lsass.DMP, files named after LSASS in Temp/Desktop.
///
///   2. SAM Database Copies: The SAM hive contains local account NTLM hashes.
///      Look for: SAM, SYSTEM, SECURITY copies in user-accessible locations.
///      (Volume Shadow Copy access grants read access to locked hive files)
///
///   3. NTDS.dit Copies: Active Directory database containing ALL domain credentials.
///      Look for: ntds.dit, ntds.jfm copies outside system paths.
///
///   4. Credential Manager Exports: Windows Credential Manager vault exports.
///      Look for: .crd, .vcrd files (exported vault items).
///
///   5. Mimikatz Artifacts: Output files, lsadump files, log files from Mimikatz.
///      Look for: mimilog.txt, debug.log with mimikatz content, kirbi tickets.
///
///   6. Kerberos Ticket Files (.kirbi): Stolen Kerberos tickets for Pass-the-Ticket.
///
/// Cheat tools sometimes steal credentials to:
///   - Access cheat forums/markets with the victim's account
///   - Steal game accounts (Steam, Epic, etc.)
///   - Blackmail victims for silence about cheat usage
/// </summary>
public sealed class SensitiveDataAccessScanModule : IScanModule
{
    public string Name => "Zugangsdaten-Zugriff-Analyse";
    public double Weight => 0.9;
    public int ParallelGroup => 4;

    private static readonly string TempPath = Path.GetTempPath().ToLowerInvariant();
    private static readonly string UserProfile = Environment.GetFolderPath(
        Environment.SpecialFolder.UserProfile).ToLowerInvariant();
    private static readonly string Desktop = Environment.GetFolderPath(
        Environment.SpecialFolder.Desktop).ToLowerInvariant();
    private static readonly string Downloads = Path.Combine(UserProfile, "downloads");
    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData).ToLowerInvariant();
    private static readonly string LocalAppData = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData).ToLowerInvariant();

    // Specific suspicious file names (case-insensitive)
    private static readonly HashSet<string> SuspiciousFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // LSASS dumps
        "lsass.dmp", "lsass.DMP", "lsass.exe.dmp",
        "lsasdump.dmp", "procdump.dmp",
        // SAM/SYSTEM hive copies
        "SAM", "SYSTEM", "SECURITY",
        "sam.hiv", "system.hiv", "security.hiv",
        "sam.bak", "system.bak",
        // NTDS
        "ntds.dit", "ntds.jfm",
        // Mimikatz artifacts
        "mimilog.txt", "mimikatz.log", "kerberoast.txt",
        "logonpasswords.txt",
        // Kerberos tickets
        "ticket.kirbi", "admin.kirbi",
        // Credential exports
        "creds.txt", "passwords.txt", "hashes.txt",
        "ntlm.txt", "krb5.ccache",
        // Common stealer output
        "result.txt", "stolen.txt", "loot.txt",
        "autofill.txt", "logins.txt",
    };

    // File name patterns (checked with Contains)
    private static readonly string[] SuspiciousNamePatterns =
    {
        "lsass", "ntds", "mimikatz", "sekurlsa",
        "kerberoast", "kirbi", "dcsync",
        "hashdump", "pwdump", "fgdump",
        "credentialdump", "credump",
        "sam_dump", "samdump",
    };

    // File extensions that are inherently suspicious in user directories
    private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".kirbi",  // Kerberos ticket
        ".ccache", // MIT Kerberos cache
        ".keytab", // Kerberos keytab
        ".dmp",    // Memory dump (may contain credentials)
    };

    // High-risk directories to scan
    private static string[] GetScanDirs() => new[]
    {
        TempPath,
        Desktop,
        Downloads,
        AppData,
        LocalAppData,
        Path.Combine(UserProfile, "Documents"),
        Path.Combine(UserProfile, "OneDrive"),
        "C:\\",  // Root level (SAM/SYSTEM copies sometimes placed here)
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        foreach (var dir in GetScanDirs())
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;
            hits += ScanDirectory(dir, ctx, ct);
        }

        // Check for specific MiniDump via WMI/PowerShell commands in history
        // (already partially done in PowerShellHistoryDeepScanModule)

        ctx.Report(1.0, Name, $"Zugangsdaten-Artefakte geprüft, {hits} gefunden");
        return Task.CompletedTask;
    }

    private static int ScanDirectory(string dir, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Non-recursive for root, recursive for user dirs
            var option = dir.Equals("C:\\", StringComparison.OrdinalIgnoreCase)
                ? SearchOption.TopDirectoryOnly
                : SearchOption.AllDirectories;

            foreach (var file in Directory.EnumerateFiles(dir, "*", option))
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var fname = Path.GetFileName(file);
                var lower = fname.ToLowerInvariant();
                var ext   = Path.GetExtension(lower);

                bool isKnownSuspicious  = SuspiciousFileNames.Contains(fname);
                bool hasSuspiciousExt   = SuspiciousExtensions.Contains(ext);
                string? matchedPattern  = SuspiciousNamePatterns.FirstOrDefault(p =>
                    lower.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (!isKnownSuspicious && !hasSuspiciousExt && matchedPattern is null)
                    continue;

                var fi = new FileInfo(file);
                hits++;

                RiskLevel risk;
                string reason;

                if (isKnownSuspicious)
                {
                    risk   = RiskLevel.Critical;
                    reason = $"Datei '{fname}' ist ein bekanntes Anmeldedaten-Dump-Artefakt. ";
                }
                else if (matchedPattern is not null)
                {
                    risk   = RiskLevel.Critical;
                    reason = $"Dateiname enthält Credential-Dump-Keyword '{matchedPattern}'. ";
                }
                else
                {
                    risk   = RiskLevel.High;
                    reason = $"Datei mit Credential-Dump-Extension '{ext}'. ";
                }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Zugangsdaten-Artefakt: {fname}",
                    Risk     = risk,
                    Location = file,
                    FileName = fname,
                    Reason   = reason +
                               "Credential-Dump-Artefakte weisen auf den Versuch hin, " +
                               "Windows-Anmeldedaten, NTLM-Hashes, Kerberos-Tickets oder " +
                               "LSASS-Speicher zu extrahieren. " +
                               "Cheat-Tools verwenden gestohlene Credentials für Account-Takeover.",
                    Detail   = $"Datei: {file} | Größe: {fi.Length} | " +
                               $"Geändert: {fi.LastWriteTime:u} | Pattern: {matchedPattern ?? fname}"
                });
            }
        }
        catch { }
        return hits;
    }
}
