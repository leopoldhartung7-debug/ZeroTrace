using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans PowerShell history and transcript files for cheat-related commands.
///
/// PowerShell is heavily used in cheat setups for:
///   - Downloading cheat executables: Invoke-WebRequest, curl, wget to cheat domains
///   - Disabling Defender exclusions: Set-MpPreference -ExclusionPath
///   - Elevating privileges for kernel driver loading
///   - Disabling UAC or security features: Set-ItemProperty, bcdedit
///   - Running obfuscated loaders: -EncodedCommand, FromBase64String
///   - Timestomping and artifact removal: Remove-Item, Clear-EventLog
///
/// Ocean and detect.ac mine PowerShell history because:
///   - PSReadLine command history persists at %APPDATA%\...\PSReadLine\ConsoleHost_history.txt
///   - PowerShell transcripts log entire sessions if enabled
///   - Defender exclusion commands in history are direct evidence of cheat setup
///
/// Files scanned:
///   %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
///   %USERPROFILE%\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
///   PowerShell transcript files (if present)
/// </summary>
public sealed class PowerShellCheatHistoryScanModule : IScanModule
{
    public string Name => "PowerShell-Verlauf Cheat-Forensik Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    private static readonly string[] CheatPsKeywords =
    {
        // Cheat download commands
        "invoke-webrequest", "iwr", "wget", "curl",
        // Combined with cheat domains (check for known domains)
        "gamesense", "onetap", "fatality", "aimware",
        "neverlose", "skeet", "unknowncheats", "elitepvpers",
        "2take1", "kiddion", "cherax", "ozark",
        "pcileech", "memprocfs",
        // Defender exclusion (primary cheat setup step)
        "exclud", "exclusionpath", "exclusionprocess",
        "set-mppreference",
        "add-mppreference",
        "disable-windowsoptionalfeature",
        // Disabling security features
        "disablerealtimemonitoring",
        "disablebehaviormonitoring",
        "disableioavprotection",
        // Elevation / driver loading
        "sc create", "sc start",
        "net start", "net stop",
        "bcdedit", "testsigning", "nointegritychecks",
        // Obfuscation (cheat loaders use this to hide commands)
        "frombase64string", "-encodedcommand", "encodedcommand",
        "invoke-expression", "iex",
        // Artifact removal
        "clear-eventlog", "clear-history",
        "remove-item.*cheat", "remove-item.*hack",
        "del.*cheat", "del.*hack",
        // AMSI bypass (used to run cheat scripts without detection)
        "amsi", "amsicontext", "amsibypass",
        "reflection.assembly", "amsiutils",
    };

    private static readonly string[] SuspiciousCommandPatterns =
    {
        // Downloading and immediately executing
        "iwr.*-o.*\\.exe", "wget.*\\.exe",
        // Base64 encoded execution
        "-enc ", "-encodedcommand",
        // Direct cheat-setup patterns
        "set-mppreference.*exclusion",
        "bcdedit.*testsigning",
        "bcdedit.*nointegritychecks",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string docs    = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        // PSReadLine history
        ScanFile(ctx,
            System.IO.Path.Combine(appdata, "Microsoft", "Windows", "PowerShell",
                "PSReadLine", "ConsoleHost_history.txt"),
            "PSReadLine Verlauf", ct);

        // PS profiles (loaded at every PS start — a cheat-setup persistence mechanism)
        ScanFile(ctx,
            System.IO.Path.Combine(docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
            "PowerShell Profil", ct);
        ScanFile(ctx,
            System.IO.Path.Combine(docs, "PowerShell", "Microsoft.PowerShell_profile.ps1"),
            "PowerShell 7 Profil", ct);

        // Transcript files
        string transcriptDir = System.IO.Path.Combine(profile, "Documents");
        ScanTranscripts(ctx, transcriptDir, ct);

        // Also check temp for PS scripts
        ScanTempPsScripts(ctx, ct);
    }

    private void ScanFile(ScanContext ctx, string path, string label, CancellationToken ct)
    {
        if (!System.IO.File.Exists(path)) return;
        try
        {
            var info = new System.IO.FileInfo(path);
            if (info.Length == 0 || info.Length > 50 * 1024 * 1024) return;
            ctx.IncrementFiles();

            string text = System.IO.File.ReadAllText(path);
            string lower = text.ToLowerInvariant();
            string fileName = System.IO.Path.GetFileName(path);

            foreach (string kw in CheatPsKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!lower.Contains(kw.ToLowerInvariant())) continue;

                int idx = lower.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                // Extract the full line
                int lineStart = lower.LastIndexOf('\n', idx) + 1;
                int lineEnd = lower.IndexOf('\n', idx);
                if (lineEnd < 0) lineEnd = Math.Min(lower.Length, idx + 200);
                string line = text.Substring(lineStart, lineEnd - lineStart).Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-PowerShell-Befehl in {label}: '{kw}'",
                    Risk     = GetRiskForKeyword(kw),
                    Location = path,
                    FileName = fileName,
                    Reason   = $"PowerShell-Datei '{fileName}' ({label}) enthält cheat-bezogenen Befehl " +
                               $"'{kw}'. PowerShell-Verlauf ist ein primäres forensisches Signal: " +
                               "Defender-Ausschlüsse, Cheat-Downloads und Treiber-Dienstinstallationen " +
                               "hinterlassen hier Spuren. Ocean und detect.ac scannen PS-History standard.",
                    Detail   = $"Quelle: {label} | Schlüsselwort: '{kw}' | Zeile: \"{line}\""
                });
                return; // one finding per file
            }
        }
        catch { }
    }

    private static RiskLevel GetRiskForKeyword(string kw)
    {
        if (kw is "set-mppreference" or "add-mppreference" or "disablerealtimemonitoring"
            or "bcdedit" or "testsigning" or "nointegritychecks" or "amsibypass"
            or "amsicontext" or "amsiutils")
            return RiskLevel.Critical;
        if (kw is "frombase64string" or "-encodedcommand" or "encodedcommand"
            or "invoke-expression" or "iex" or "clear-eventlog")
            return RiskLevel.High;
        return RiskLevel.Medium;
    }

    private void ScanTranscripts(ScanContext ctx, string dir, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(dir)) return;
        try
        {
            // PowerShell transcripts are named like "PowerShell_transcript.<hostname>.<random>.yyyyMMddHHmmss.txt"
            int count = 0;
            foreach (string file in System.IO.Directory.EnumerateFiles(
                         dir, "PowerShell_transcript.*.txt", System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                if (++count > 20) break; // cap transcript scanning
                ScanFile(ctx, file, "PowerShell Transkript", ct);
            }
        }
        catch { }
    }

    private void ScanTempPsScripts(ScanContext ctx, CancellationToken ct)
    {
        string temp = System.IO.Path.GetTempPath();
        if (!System.IO.Directory.Exists(temp)) return;
        try
        {
            foreach (string ps1 in System.IO.Directory.EnumerateFiles(temp, "*.ps1",
                         System.IO.SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                var info = new System.IO.FileInfo(ps1);
                if (info.Length == 0 || info.Length > 1024 * 1024) continue;
                ctx.IncrementFiles();
                ScanFile(ctx, ps1, "PowerShell-Script in Temp", ct);
            }
        }
        catch { }
    }
}
