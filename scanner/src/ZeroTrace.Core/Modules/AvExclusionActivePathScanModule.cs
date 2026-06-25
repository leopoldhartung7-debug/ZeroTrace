using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Validates Windows Defender exclusion paths for actual suspicious content. The existing
/// AvExclusionScanModule reports that exclusions exist; this module goes further: it walks
/// each excluded directory and checks whether the excluded path actually contains unsigned
/// executables, cheat-keyword files, or known BYOVD/cheat tool file names. A cheat tool
/// that adds an AV exclusion for its own directory leaves a double artifact — the exclusion
/// registry entry AND the actual cheat files are still present. Also detects exclusions for
/// highly suspicious paths (Temp, Downloads, suspicious tool names) even without confirmed
/// file content. Registry paths: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths.
/// </summary>
public sealed class AvExclusionActivePathScanModule : IScanModule
{
    public string Name => "AV Exclusion Active Path Audit";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private const string ExclusionPathsKey =
        @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths";

    private static readonly string[] HighRiskExclusionPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\",
        @"\appdata\local\temp\", @"\appdata\roaming\",
        // Never exclude these normally
        @"\users\", @"\public\",
    };

    private static readonly string[] CheatFileKeywords =
    {
        "cheat", "hack", "esp", "aimbot", "radar", "wallhack",
        "bypass", "inject", "loader", "trainer", "menu",
        "norecoil", "triggerbot", "softaim", "aimassist",
        "spoofer", "hwid", "vac", "eac", "battleye",
        "kiddion", "memprocfs", "cherax", "2take1", "midnight",
        "bigbase", "sxac", "eulen", "ozark", "phantom",
        "nopRecoil", "interception", "windivert", "pcileech",
        "dumper", "memory", "reader", "external",
    };

    private static readonly string[] SuspiciousExtensions =
    { ".sys", ".dll", ".exe" };

    // Known BYOVD driver file names
    private static readonly HashSet<string> ByovdFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "mhyprot2.sys", "RTCore64.sys", "gdrv.sys", "WinRing0x64.sys",
        "WinRing0.sys", "AsIO64.sys", "AsIO.sys", "iqvw64e.sys",
        "cpuz141_x64.sys", "amsdk.sys", "HW64.sys", "dbutil_2_3.sys",
        "fiddrv.sys", "HarddiskVolumeSnapShot.sys", "NICM.sys",
        "pcigenband.sys", "nchgbios2x64.sys", "superbmc.sys",
        "ATSZIO.sys", "kprocesshacker.sys", "kprocesshacker3.sys",
        "windivert.sys", "windivert32.sys", "windivert64.sys",
        "npcap.sys", "npf.sys",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => AuditExclusionPaths(ctx, ct), ct);
    }

    private void AuditExclusionPaths(ScanContext ctx, CancellationToken ct)
    {
        string[] hives = { "HKLM", "HKCU" };
        RegistryKey[] roots = { Registry.LocalMachine, Registry.CurrentUser };

        for (int h = 0; h < hives.Length; h++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = roots[h].OpenSubKey(ExclusionPathsKey);
                if (key is null) continue;

                foreach (string valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    // The value NAME is the excluded path (DWORD value = 0)
                    string excludedPath = valueName;
                    string pathLower = excludedPath.ToLowerInvariant();

                    bool isHighRiskPath = Array.Exists(HighRiskExclusionPaths,
                        p => pathLower.Contains(p));

                    bool hasCheatKeywordInPath = Array.Exists(CheatFileKeywords,
                        kw => pathLower.Contains(kw));

                    // Check if path exists and scan its contents
                    if (Directory.Exists(excludedPath))
                    {
                        ScanExcludedDirectory(excludedPath, ctx, ct, isHighRiskPath, hasCheatKeywordInPath);
                    }
                    else if (File.Exists(excludedPath))
                    {
                        string fileName = Path.GetFileName(excludedPath);
                        bool isByovd    = ByovdFileNames.Contains(fileName);
                        bool fileCheat  = Array.Exists(CheatFileKeywords,
                            kw => fileName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        if (isByovd || fileCheat || hasCheatKeywordInPath)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"AV-Ausnahme für verdächtige Datei: {fileName}",
                                Risk     = isByovd ? RiskLevel.Critical : RiskLevel.High,
                                Location = $@"{hives[h]}\{ExclusionPathsKey}",
                                FileName = fileName,
                                Reason   = isByovd
                                    ? $"Windows Defender hat eine Ausnahme für bekannten BYOVD-Treiber '{fileName}' " +
                                      $"unter '{excludedPath}' — dieser Treiber wird von Cheats zur Kernel-Injection genutzt"
                                    : $"Windows Defender hat eine Ausnahme für verdächtige Datei '{fileName}' " +
                                      $"unter '{excludedPath}' — Cheat-Keyword im Dateinamen oder Pfad",
                                Detail   = $"Ausnahme-Pfad: {excludedPath} | BYOVD: {isByovd} | " +
                                           $"Cheat-Keyword: {fileCheat || hasCheatKeywordInPath}"
                            });
                        }
                    }
                    else if (isHighRiskPath || hasCheatKeywordInPath)
                    {
                        // Path doesn't exist — exclusion may be a remnant after cheat was deleted
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"AV-Ausnahme für verdächtigen Pfad (nicht vorhanden): {Path.GetFileName(excludedPath)}",
                            Risk     = hasCheatKeywordInPath ? RiskLevel.High : RiskLevel.Medium,
                            Location = $@"{hives[h]}\{ExclusionPathsKey}",
                            FileName = Path.GetFileName(excludedPath),
                            Reason   = hasCheatKeywordInPath
                                ? $"Windows Defender-Ausnahme für Pfad '{excludedPath}' enthält Cheat-Keyword — " +
                                  "Cheat-Tool hat sich selbst von AV-Erkennung ausgenommen (Pfad existiert nicht mehr)"
                                : $"Windows Defender-Ausnahme für hochriskanten Pfad '{excludedPath}' " +
                                  "(Temp/Downloads/AppData) — ungewöhnlich und möglicherweise von Malware gesetzt",
                            Detail   = $"Ausnahme-Pfad: {excludedPath} | Existiert: false | " +
                                       $"Cheat-Keyword: {hasCheatKeywordInPath} | Hochrisiko-Pfad: {isHighRiskPath}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private void ScanExcludedDirectory(string dirPath, ScanContext ctx, CancellationToken ct,
        bool isHighRiskPath, bool pathHasCheatKeyword)
    {
        try
        {
            int suspiciousCount = 0;
            var cheatFiles = new List<string>();

            foreach (var file in Directory.EnumerateFiles(dirPath, "*",
                new EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 3 }))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string fileName = Path.GetFileName(file);
                string ext      = Path.GetExtension(file).ToLowerInvariant();

                if (!Array.Exists(SuspiciousExtensions, e => e == ext)) continue;

                bool isByovd   = ByovdFileNames.Contains(fileName);
                bool isCheat   = Array.Exists(CheatFileKeywords,
                    kw => fileName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (isByovd)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"BYOVD-Treiber in AV-Ausnahme: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Bekannter BYOVD-Treiber '{fileName}' gefunden in AV-ausgenommenem Pfad " +
                                   $"'{dirPath}' — Treiber ist für AV geschützt und kann zur " +
                                   "Kernel-Level Cheat-Injection genutzt werden",
                        Detail   = $"Treiber: {file} | AV-Ausnahme-Verzeichnis: {dirPath}"
                    });
                    return;
                }

                if (isCheat)
                {
                    cheatFiles.Add(fileName);
                    suspiciousCount++;
                    if (suspiciousCount >= 3) break;
                }
            }

            if (cheatFiles.Count > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Dateien in AV-Ausnahme: {Path.GetFileName(dirPath)}",
                    Risk     = RiskLevel.Critical,
                    Location = dirPath,
                    FileName = Path.GetFileName(dirPath),
                    Reason   = $"AV-ausgenommenes Verzeichnis '{dirPath}' enthält Dateien mit " +
                               $"Cheat-Keywords: {string.Join(", ", cheatFiles)} — " +
                               "das Cheat-Tool hat sich selbst von Windows Defender ausgenommen um " +
                               "Erkennung seiner DLLs/EXEs zu verhindern",
                    Detail   = $"Ausnahme-Pfad: {dirPath} | Verdächtige Dateien: {string.Join(", ", cheatFiles)}"
                });
            }
            else if (isHighRiskPath || pathHasCheatKeyword)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"AV-Ausnahme für Hochrisiko-Pfad: {Path.GetFileName(dirPath)}",
                    Risk     = pathHasCheatKeyword ? RiskLevel.High : RiskLevel.Medium,
                    Location = dirPath,
                    FileName = Path.GetFileName(dirPath),
                    Reason   = pathHasCheatKeyword
                        ? $"Windows Defender-Ausnahme für Verzeichnis '{dirPath}' mit Cheat-Keyword im Namen — " +
                          "Cheat-Tool hat sein eigenes Verzeichnis von AV-Erkennung ausgenommen"
                        : $"Windows Defender-Ausnahme für Temp/Downloads-Verzeichnis '{dirPath}' — " +
                          "Malware und Cheat-Tools nutzen Ausnahmen für Staging-Verzeichnisse",
                    Detail   = $"Ausnahme-Pfad: {dirPath} | Hochrisiko: {isHighRiskPath} | " +
                               $"Cheat-Keyword: {pathHasCheatKeyword}"
                });
            }
        }
        catch { }
    }
}
