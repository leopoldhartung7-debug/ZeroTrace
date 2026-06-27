using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class WindowsDefenderEventLogForensicScanModule : IScanModule
{
    public string Name => "Windows Defender Event Log Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    // ── Cheat keywords (50+ entries) ─────────────────────────────────────────

    private static readonly string[] CheatKeywords =
    {
        "aimbot", "wallhack", "esp", "cheat", "hack", "bypass", "inject",
        "fivem_cheat", "ragemp_cheat", "altv_cheat", "kdmapper", "mhyprot",
        "hwid_bypass", "hwid spoofer", "spoofer", "loader", "triggerbot",
        "rapidfire", "bunnyhop", "no recoil", "norecoil", "spinbot",
        "kiddion", "2take1", "cherax", "ozark", "tsunami", "rxce",
        "gamesense", "onetap", "neverlose", "fatality", "aimware",
        "fecurity", "valorhack", "apexhack", "memprocfs", "pcileech",
        "leechcore", "evilcheats", "gamerpride", "exvalid", "ohwow",
        "rustez", "predatorlegends", "carbonstrike", "luciddreams",
        "injector", "dllinjector", "manualmap", "manualmapping",
        "processhollowing", "shellcode", "rootkit", "kernelexploit",
        "byovd", "vulnerable driver", "exploiteddriver", "driverexploit",
        "radar hack", "radarhack", "chams", "glowhack", "loot esp",
        "player esp", "bone esp", "health esp", "distance esp",
        "external cheat", "internal cheat", "memorywrite", "writeprocessmemory",
        "readprocessmemory", "virtualallocex", "createremotethread",
        "ntwritevirtualmemory", "ntallocatevirtualmemory",
        "anticheat bypass", "eac bypass", "be bypass", "vac bypass",
        "faceit bypass", "esportal bypass", "gamersclub bypass",
        "unknowncheats", "uc forum", "mpgh", "hackforums",
        "cheatengine", "cheat engine", "artmoney", "tsearch",
        "gameguardian", "luma", "hyperion", "themida bypass",
        "vmprotect bypass", "confuserex", "de4dot",
    };

    // ── Defender event-specific keywords ─────────────────────────────────────

    private static readonly string[] DefenderEventKeywords =
    {
        "bypass", "tamper", "exclusion", "disabled", "protection off",
        "threat detected", "quarantine", "remediation", "scan stopped",
        "real-time protection disabled", "real-time monitoring disabled",
        "spynet disabled", "cloud protection disabled", "network protection disabled",
        "controlled folder access disabled", "asr rule disabled",
        "tamper protection disabled", "wdfilter", "mpssvc",
        "exclusion added", "exclusion path", "exclusion process",
        "disablerealtimemonitoring", "disablebehaviormonitoring",
        "disableonaccessprotection", "disablescriptscanning",
        "disableioavprotection", "disableprivacymode",
        "mpcmdrun", "mpsigstub", "mptaskmanager", "nistapiservice",
        "windows defender disabled", "defender turned off",
        "antimalware service executable", "antimalware platform",
        "protection history cleared", "scan history deleted",
        "threat history removed", "quarantine database",
    };

    // ── MPLog scan patterns ───────────────────────────────────────────────────

    private static readonly (string Keyword, string Description, RiskLevel Risk)[] MpLogPatterns =
    {
        ("ExclusionPath",               "Exclusion path added",                   RiskLevel.High),
        ("DisableRealtimeMonitoring",   "Real-time monitoring disabled",          RiskLevel.Critical),
        ("TamperProtection",            "Tamper protection state change",         RiskLevel.High),
        ("exclusion added",             "Exclusion entry added",                  RiskLevel.High),
        ("bypass",                      "Bypass keyword in Defender log",         RiskLevel.High),
        ("disabled by policy",          "Protection disabled by policy",          RiskLevel.High),
        ("DisableOnAccessProtection",   "On-access protection disabled",          RiskLevel.High),
        ("DisableBehaviorMonitoring",   "Behavior monitoring disabled",           RiskLevel.High),
        ("DisableIOAVProtection",       "IOAV protection disabled",               RiskLevel.High),
        ("real-time protection is off", "Real-time protection reported off",      RiskLevel.Critical),
        ("protection is disabled",      "Protection disabled event logged",       RiskLevel.Critical),
        ("SpynetReporting = 0",         "Cloud reporting disabled in log",        RiskLevel.Medium),
        ("MpCloudBlockLevel = 0",       "Cloud block level set to zero",          RiskLevel.Medium),
        ("EnableNetworkProtection = 0", "Network protection disabled in log",     RiskLevel.Medium),
        ("exclusion process",           "Process exclusion recorded",             RiskLevel.High),
        ("exclusion extension",         "File extension exclusion recorded",      RiskLevel.Medium),
        ("wdfilter disabled",           "WdFilter driver disabled",               RiskLevel.Critical),
        ("antimalware platform",        "Antimalware platform event",             RiskLevel.Low),
    };

    // ── Known bypass tool executable names (20+ entries) ─────────────────────

    private static readonly string[] BypassToolNames =
    {
        "kdmapper.exe", "drvmap.exe", "capcom_loader.exe", "byovd.exe",
        "gdrv_loader.exe", "rtcore64_loader.exe", "dbutil_loader.exe",
        "ene_loader.exe", "cpuz_loader.exe", "asmmap64_loader.exe",
        "hwid_spoofer.exe", "serial_spoofer.exe", "mac_spoofer.exe",
        "disk_spoofer.exe", "smbios_spoofer.exe", "guid_spoofer.exe",
        "memprocfs.exe", "pcileech.exe", "leechcore.dll",
        "dll_injector.exe", "process_injector.exe", "xenos.exe",
        "extreme_injector.exe", "guided_hacking_injector.exe",
        "manual_map.exe", "manualmap_injector.exe",
        "cheat_engine.exe", "cheatengine-x86_64.exe",
        "artmoney.exe", "tsearch.exe",
        "eac_remover.exe", "be_remover.exe", "vac_remover.exe",
        "anti_anticheat.exe", "anticheatkiller.exe",
        "winkdiag.exe", "physmem_loader.exe", "amifldrv64.exe",
        "nvflash.exe", "atikmpag_loader.exe", "nvaudio_loader.exe",
        "mtk_loader.exe", "elby_loader.exe", "procexp_loader.exe",
    };

    // ── Paths ─────────────────────────────────────────────────────────────────

    private static readonly string ProgramData =
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    private static readonly string DefenderBase =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows Defender");

    private static readonly string EvtxLogDir =
        @"C:\Windows\System32\winevt\Logs";

    private static readonly string DefenderOperationalEvtx =
        @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx";

    private static readonly string DefenderWhcEvtx =
        @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4WHC.evtx";

    private static readonly string DefenderScansDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows Defender\Scans");

    private static readonly string DefenderHistoryDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows Defender\Scans\History\Service");

    private static readonly string DefenderDetectionHistoryDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows Defender\Scans\History\Service\DetectionHistory");

    private static readonly string DefenderSupportDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows Defender\Support");

    private static readonly string DefenderQuarantineDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows Defender\Quarantine");

    private static readonly string DefenderPlatformDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            @"Microsoft\Windows Defender\Platform");

    // ── Entry point ──────────────────────────────────────────────────────────

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Windows Defender event log forensic scan");

        await Task.WhenAll(
            CheckDefenderOperationalLogFile(ctx, ct),
            CheckDefenderHistoryXmlFiles(ctx, ct),
            CheckDefenderDetectionDatabase(ctx, ct),
            CheckDefenderMpCmdRunHistory(ctx, ct),
            CheckDefenderExclusionEventArtifacts(ctx, ct),
            CheckDefenderNetworkProtectionRegistry(ctx, ct),
            CheckDefenderCloudProtectionRegistry(ctx, ct),
            CheckDefenderScanHistoryRegistry(ctx, ct),
            CheckDefenderThreatDetectionHistory(ctx, ct),
            CheckDefenderMPSupportFiles(ctx, ct),
            CheckDefenderQuarantineDatabase(ctx, ct),
            CheckDefenderPolicyConflicts(ctx, ct),
            CheckDefenderSmartScreenRegistry(ctx, ct),
            CheckWindowsSecurityHealthRegistry(ctx, ct),
            CheckDefenderSandboxState(ctx, ct)
        );

        ctx.Report(1.0, Name, "Windows Defender event log forensic scan complete");
    }

    // ── 1. Operational EVTX file check ───────────────────────────────────────

    private Task CheckDefenderOperationalLogFile(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            // Check primary operational log
            await CheckEvtxFile(ctx, DefenderOperationalEvtx,
                "Defender Operational", minExpectedBytes: 200 * 1024, ct);

            // Check WHC log
            await CheckEvtxFile(ctx, DefenderWhcEvtx,
                "Defender WHC", minExpectedBytes: 10 * 1024, ct);

            // Check the log directory for recently modified evtx files
            if (ct.IsCancellationRequested) return;
            try
            {
                if (!Directory.Exists(EvtxLogDir)) return;

                var defenderEvtxFiles = Directory.GetFiles(
                    EvtxLogDir, "*Windows Defender*", SearchOption.TopDirectoryOnly);

                ctx.IncrementFiles((long)defenderEvtxFiles.Length);

                int recentCount = 0;
                foreach (var evtx in defenderEvtxFiles)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        var fi = new FileInfo(evtx);
                        if ((DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays <= 3)
                            recentCount++;
                    }
                    catch (IOException) { }
                }

                if (recentCount == 0 && defenderEvtxFiles.Length > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Defender EVTX logs not recently modified",
                        Risk     = RiskLevel.Medium,
                        Location = EvtxLogDir,
                        FileName = "Microsoft-Windows-Windows Defender*.evtx",
                        Reason   = "None of the Windows Defender EVTX log files have been " +
                                   "modified in the last 3 days, which may indicate that " +
                                   "Defender event logging has been suppressed or tampered with.",
                        Detail   = $"Found {defenderEvtxFiles.Length} Defender EVTX file(s), " +
                                   $"0 modified recently."
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private async Task CheckEvtxFile(ScanContext ctx, string path, string label,
        long minExpectedBytes, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        if (!File.Exists(path))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Defender {label} log missing",
                Risk     = RiskLevel.High,
                Location = path,
                FileName = Path.GetFileName(path),
                Reason   = $"The Windows Defender {label} event log file is missing. " +
                           "This file should always exist on a running Windows system with " +
                           "Defender enabled. Its absence indicates the log may have been " +
                           "deliberately deleted to erase evidence of cheat tool detection.",
                Detail   = $"Expected at: {path}"
            });
            return;
        }

        ctx.IncrementFiles();

        try
        {
            var fi = new FileInfo(path);
            long size = fi.Length;

            if (size < minExpectedBytes)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Defender {label} log suspiciously small",
                    Risk     = RiskLevel.Medium,
                    Location = path,
                    FileName = Path.GetFileName(path),
                    Reason   = $"The Windows Defender {label} event log is only {size / 1024} KB, " +
                               $"which is below the expected minimum of {minExpectedBytes / 1024} KB. " +
                               "A small log on an active system suggests the log was cleared or " +
                               "event recording was suppressed to hide cheat tool detections.",
                    Detail   = $"File size: {size / 1024} KB | Last write: {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm} UTC"
                });
            }
        }
        catch (IOException) { }

        // Scan raw EVTX bytes for cheat keywords using UTF8 then Latin1
        if (ct.IsCancellationRequested) return;
        try
        {
            string content;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.Latin1);
            content = await sr.ReadToEndAsync(ct);

            var foundKeywords = new List<string>();
            foreach (var keyword in CheatKeywords)
            {
                if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    foundKeywords.Add(keyword);
            }

            if (foundKeywords.Count > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat keywords found in Defender {label} log",
                    Risk     = RiskLevel.Critical,
                    Location = path,
                    FileName = Path.GetFileName(path),
                    Reason   = $"The Windows Defender {label} event log contains {foundKeywords.Count} " +
                               "cheat-related keyword(s) embedded in event records. This indicates " +
                               "Defender previously detected cheat tools, which may have subsequently " +
                               "been removed or quarantined.",
                    Detail   = $"Keywords found: {string.Join(", ", foundKeywords.Take(20))}"
                });
            }

            // Also scan for Defender event-specific keywords
            var defenderHits = new List<string>();
            foreach (var kw in DefenderEventKeywords)
            {
                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    defenderHits.Add(kw);
            }

            if (defenderHits.Any(k =>
                k.Contains("disabled", StringComparison.OrdinalIgnoreCase) ||
                k.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                k.Contains("tamper", StringComparison.OrdinalIgnoreCase)))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Defender {label} log contains protection-bypass indicators",
                    Risk     = RiskLevel.High,
                    Location = path,
                    FileName = Path.GetFileName(path),
                    Reason   = $"The {label} event log contains keywords associated with " +
                               "Defender protection being disabled or bypassed. Cheat loaders " +
                               "and bypass tools often disable real-time protection before " +
                               "injecting, and these events are recorded in the operational log.",
                    Detail   = $"Indicators: {string.Join(", ", defenderHits.Take(15))}"
                });
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    // ── 2. Defender history XML/bin files ────────────────────────────────────

    private Task CheckDefenderHistoryXmlFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            if (!Directory.Exists(DefenderHistoryDir))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Defender scan history directory missing",
                    Risk     = RiskLevel.Medium,
                    Location = DefenderHistoryDir,
                    Reason   = "The Windows Defender scan history service directory does not exist. " +
                               "This directory should be present on any system that has run Defender. " +
                               "Its absence may indicate deliberate deletion to erase scan records.",
                    Detail   = $"Expected directory: {DefenderHistoryDir}"
                });
                return;
            }

            string[] files;
            try
            {
                files = Directory.GetFiles(DefenderHistoryDir, "*",
                    SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { return; }

            if (files.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Defender history directory is empty",
                    Risk     = RiskLevel.Medium,
                    Location = DefenderHistoryDir,
                    Reason   = "The Windows Defender scan history directory exists but contains no " +
                               "files. On an active system this directory normally contains XML and " +
                               "binary report files. An empty directory suggests history was cleared.",
                    Detail   = $"Directory: {DefenderHistoryDir}"
                });
                return;
            }

            ctx.IncrementFiles((long)files.Length);

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) break;

                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".xml" && ext != ".bin" && ext != "") continue;

                try
                {
                    string content;
                    using var fs = new FileStream(file, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);

                    var cheatHits = new List<string>();
                    foreach (var kw in CheatKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            cheatHits.Add(kw);
                    }

                    bool hasQuarantine = content.Contains("QuarantineAction=True",
                        StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("<Quarantine>", StringComparison.OrdinalIgnoreCase);

                    bool hasRemediation = content.Contains("RemediationAction",
                        StringComparison.OrdinalIgnoreCase);

                    bool hasThreatId = content.Contains("ThreatID",
                        StringComparison.OrdinalIgnoreCase);

                    bool hasBypassTool = false;
                    string? matchedTool = null;
                    foreach (var tool in BypassToolNames)
                    {
                        if (content.Contains(tool, StringComparison.OrdinalIgnoreCase))
                        {
                            hasBypassTool = true;
                            matchedTool = tool;
                            break;
                        }
                    }

                    if (cheatHits.Count > 0 || hasBypassTool)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Cheat detection record found in Defender history",
                            Risk     = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(file) ?? DefenderHistoryDir,
                            FileName = Path.GetFileName(file),
                            Reason   = "A Windows Defender history report file contains cheat-related " +
                                       "keywords, indicating Defender previously detected a cheat tool " +
                                       $"or bypass. {(hasBypassTool ? $"Bypass tool matched: {matchedTool}. " : "")}" +
                                       $"{(hasQuarantine ? "Quarantine action was recorded. " : "")}" +
                                       $"{(hasRemediation ? "Remediation action was recorded." : "")}",
                            Detail   = $"File: {file} | Keywords: {string.Join(", ", cheatHits.Take(10))}" +
                                       $"{(hasThreatId ? " | ThreatID present" : "")}"
                        });
                    }
                    else if (hasQuarantine && hasRemediation)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender history shows quarantine and remediation events",
                            Risk     = RiskLevel.Medium,
                            Location = Path.GetDirectoryName(file) ?? DefenderHistoryDir,
                            FileName = Path.GetFileName(file),
                            Reason   = "A Defender history file records both quarantine and remediation " +
                                       "actions. While not definitive, this pattern often accompanies " +
                                       "cheat tool removal and warrants further review.",
                            Detail   = $"File: {file}" +
                                       $"{(hasThreatId ? " | ThreatID referenced" : "")}"
                        });
                    }
                }
                catch (IOException) { }
            }
        }, ct);

    // ── 3. Defender detection database / cache ───────────────────────────────

    private Task CheckDefenderDetectionDatabase(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            if (!Directory.Exists(DefenderScansDir)) return;

            // Check for mpcache-*.bin (detection cache files)
            string[] cacheFiles;
            try
            {
                cacheFiles = Directory.GetFiles(DefenderScansDir,
                    "mpcache-*.bin", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { cacheFiles = Array.Empty<string>(); }

            ctx.IncrementFiles((long)cacheFiles.Length);

            if (cacheFiles.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "No Defender detection cache files found",
                    Risk     = RiskLevel.Low,
                    Location = DefenderScansDir,
                    FileName = "mpcache-*.bin",
                    Reason   = "No Defender detection cache (mpcache-*.bin) files were found. " +
                               "These files normally accumulate during regular scanning. Their " +
                               "absence may indicate the scan cache was cleared.",
                    Detail   = $"Scans directory: {DefenderScansDir}"
                });
            }

            // Check mpengine log
            string mpEngineLog = Path.Combine(DefenderScansDir, "mpenginedb.db");
            if (File.Exists(mpEngineLog))
            {
                ctx.IncrementFiles();
                try
                {
                    var fi = new FileInfo(mpEngineLog);
                    if (fi.Length < 4096)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender engine database unusually small",
                            Risk     = RiskLevel.Low,
                            Location = DefenderScansDir,
                            FileName = "mpenginedb.db",
                            Reason   = $"The Defender engine database (mpenginedb.db) is only " +
                                       $"{fi.Length} bytes. This file normally contains scan " +
                                       "engine state and should be larger on an active system.",
                            Detail   = $"File: {mpEngineLog} | Size: {fi.Length} bytes"
                        });
                    }
                }
                catch (IOException) { }
            }

            // Check CacheManager directory
            string cacheManagerDir = Path.Combine(DefenderHistoryDir, "CacheManager");
            if (Directory.Exists(cacheManagerDir))
            {
                try
                {
                    var cmFiles = Directory.GetFiles(cacheManagerDir, "*",
                        SearchOption.AllDirectories);
                    ctx.IncrementFiles((long)cmFiles.Length);

                    if (cmFiles.Length == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender CacheManager directory is empty",
                            Risk     = RiskLevel.Low,
                            Location = cacheManagerDir,
                            Reason   = "The Defender CacheManager directory exists but contains no " +
                                       "files. This may indicate detection cache was deliberately cleared.",
                            Detail   = $"Directory: {cacheManagerDir}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            // Scan each cache file for cheat keywords (spot-check a few)
            foreach (var cacheFile in cacheFiles.Take(5))
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    string raw;
                    using var fs = new FileStream(cacheFile, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    raw = sr.ReadToEnd();

                    var hits = CheatKeywords.Where(kw =>
                        raw.Contains(kw, StringComparison.OrdinalIgnoreCase)).Take(5).ToList();

                    if (hits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Cheat keywords in Defender detection cache",
                            Risk     = RiskLevel.High,
                            Location = DefenderScansDir,
                            FileName = Path.GetFileName(cacheFile),
                            Reason   = "A Defender detection cache file (mpcache-*.bin) contains " +
                                       "cheat-related strings, indicating Defender cached a detection " +
                                       "of a cheat tool or associated file.",
                            Detail   = $"Cache file: {cacheFile} | Hits: {string.Join(", ", hits)}"
                        });
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    // ── 4. MpCmdRun prefetch and PS history ──────────────────────────────────

    private Task CheckDefenderMpCmdRunHistory(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            // Check prefetch directory for MpCmdRun.exe-*.pf
            const string prefetchDir = @"C:\Windows\Prefetch";
            if (Directory.Exists(prefetchDir))
            {
                string[] mpPrefetch;
                try
                {
                    mpPrefetch = Directory.GetFiles(prefetchDir,
                        "MPCMDRUN.EXE-*.pf", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { mpPrefetch = Array.Empty<string>(); }

                ctx.IncrementFiles((long)mpPrefetch.Length);

                foreach (var pf in mpPrefetch)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        var fi = new FileInfo(pf);
                        var age = DateTime.UtcNow - fi.LastWriteTimeUtc;

                        if (age.TotalDays <= 30)
                        {
                            // Scan prefetch file for suspicious MpCmdRun arguments
                            string rawContent;
                            using var fs = new FileStream(pf, FileMode.Open,
                                FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs, Encoding.Unicode);
                            rawContent = await sr.ReadToEndAsync(ct);

                            bool hasExclusionAdd = rawContent.Contains("-ExclusionPath",
                                StringComparison.OrdinalIgnoreCase) ||
                                rawContent.Contains("-ExclusionProcess",
                                StringComparison.OrdinalIgnoreCase) ||
                                rawContent.Contains("-ExclusionExtension",
                                StringComparison.OrdinalIgnoreCase);

                            bool hasRemoveThreat = rawContent.Contains("-RemoveDefinitions",
                                StringComparison.OrdinalIgnoreCase) ||
                                rawContent.Contains("-RestoreDefaults",
                                StringComparison.OrdinalIgnoreCase);

                            bool hasDisableProtection = rawContent.Contains(
                                "DisableRealtimeMonitoring",
                                StringComparison.OrdinalIgnoreCase);

                            if (hasExclusionAdd || hasRemoveThreat || hasDisableProtection)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "MpCmdRun.exe used with suspicious arguments",
                                    Risk     = RiskLevel.High,
                                    Location = pf,
                                    FileName = Path.GetFileName(pf),
                                    Reason   = "Prefetch evidence shows MpCmdRun.exe (Defender command-line " +
                                               "tool) was executed recently with arguments that suggest " +
                                               $"{(hasExclusionAdd ? "exclusion additions, " : "")}" +
                                               $"{(hasRemoveThreat ? "threat removal, " : "")}" +
                                               $"{(hasDisableProtection ? "protection disabling" : "")}. " +
                                               "Cheat loaders use MpCmdRun.exe to add exclusions " +
                                               "before injecting DLLs.",
                                    Detail   = $"Prefetch file: {pf} | " +
                                               $"Last executed: {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm} UTC"
                                });
                            }
                            else
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "MpCmdRun.exe recently executed",
                                    Risk     = RiskLevel.Low,
                                    Location = pf,
                                    FileName = Path.GetFileName(pf),
                                    Reason   = "Prefetch shows MpCmdRun.exe was run recently. While " +
                                               "this can be legitimate, it is also used by cheat " +
                                               "infrastructure to add exclusions or remove detections.",
                                    Detail   = $"Last run: {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm} UTC"
                                });
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }

            // Scan PowerShell history for MpCmdRun commands
            if (ct.IsCancellationRequested) return;

            var psHistoryPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

            if (!File.Exists(psHistoryPath)) return;

            ctx.IncrementFiles();
            try
            {
                string histContent;
                using var fs = new FileStream(psHistoryPath, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                histContent = await sr.ReadToEndAsync(ct);

                var suspiciousLines = new List<string>();
                foreach (var line in histContent.Split('\n'))
                {
                    if (ct.IsCancellationRequested) break;
                    if (!line.Contains("MpCmdRun", StringComparison.OrdinalIgnoreCase)) continue;

                    if (line.Contains("-ExclusionPath", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("-ExclusionProcess", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("-RemoveDefinitions", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("-RestoreDefaults", StringComparison.OrdinalIgnoreCase) ||
                        line.Contains("-DisableRealtimeMonitoring",
                            StringComparison.OrdinalIgnoreCase))
                    {
                        suspiciousLines.Add(line.Trim());
                    }
                }

                if (suspiciousLines.Count > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "MpCmdRun.exe suspicious commands in PS history",
                        Risk     = RiskLevel.Critical,
                        Location = psHistoryPath,
                        FileName = "ConsoleHost_history.txt",
                        Reason   = $"PowerShell history contains {suspiciousLines.Count} MpCmdRun.exe " +
                                   "command(s) with arguments used to add exclusions or weaken " +
                                   "Defender protection. This is a strong indicator that cheat " +
                                   "software used PowerShell to prepare Defender for bypass.",
                        Detail   = string.Join(" | ",
                            suspiciousLines.Take(5).Select(l =>
                                l.Length > 200 ? l[..200] + "..." : l))
                    });
                }
            }
            catch (IOException) { }
        }, ct);

    // ── 5. Defender exclusion event artifacts (MPLog) ─────────────────────────

    private Task CheckDefenderExclusionEventArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            if (!Directory.Exists(DefenderSupportDir)) return;

            string[] mpLogFiles;
            try
            {
                mpLogFiles = Directory.GetFiles(DefenderSupportDir,
                    "MPLog-*.log", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { return; }

            if (mpLogFiles.Length == 0) return;

            ctx.IncrementFiles((long)mpLogFiles.Length);

            foreach (var logFile in mpLogFiles)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    string content;
                    using var fs = new FileStream(logFile, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);

                    var hitsByRisk = new Dictionary<RiskLevel, List<string>>();

                    foreach (var (keyword, desc, risk) in MpLogPatterns)
                    {
                        if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            continue;

                        if (!hitsByRisk.TryGetValue(risk, out var list))
                        {
                            list = new List<string>();
                            hitsByRisk[risk] = list;
                        }
                        list.Add(desc);
                    }

                    // Also check for cheat keywords
                    var cheatHits = CheatKeywords.Where(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .Take(10).ToList();

                    if (cheatHits.Count > 0)
                    {
                        hitsByRisk.TryAdd(RiskLevel.Critical, new List<string>());
                        hitsByRisk[RiskLevel.Critical].Add(
                            $"Cheat keywords: {string.Join(", ", cheatHits.Take(5))}");
                    }

                    foreach (var (risk, descriptions) in hitsByRisk)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Defender MPLog: {descriptions.First()}",
                            Risk     = risk,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason   = $"Windows Defender support log contains {descriptions.Count} " +
                                       "indicator(s) of protection bypass or exclusion events: " +
                                       string.Join("; ", descriptions.Take(5)) + ". " +
                                       "Cheat tools frequently log these events when weakening Defender.",
                            Detail   = $"Log file: {logFile} | Indicators: {string.Join(", ", descriptions.Take(8))}"
                        });
                    }
                }
                catch (IOException) { }
            }
        }, ct);

    // ── 6. Network Protection / CFA / ASR registry ───────────────────────────

    private Task CheckDefenderNetworkProtectionRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            // Network Protection
            try
            {
                const string netProtKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection";
                using var key = Registry.LocalMachine.OpenSubKey(netProtKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var val = key.GetValue("EnableNetworkProtection");
                    if (val is int np && np == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender Network Protection disabled",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{netProtKey}",
                            Reason   = "Windows Defender Network Protection is disabled " +
                                       "(EnableNetworkProtection=0). Network Protection blocks " +
                                       "connections to known malicious hosts. Cheat loaders " +
                                       "disable it to allow communication with C2 servers.",
                            Detail   = "EnableNetworkProtection = 0"
                        });
                    }
                }
            }
            catch { }

            // Controlled Folder Access
            if (ct.IsCancellationRequested) return;
            try
            {
                const string cfaKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
                using var key = Registry.LocalMachine.OpenSubKey(cfaKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var val = key.GetValue("EnableControlledFolderAccess");
                    if (val is int cfa && cfa == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender Controlled Folder Access disabled",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{cfaKey}",
                            Reason   = "Controlled Folder Access (ransomware protection) is disabled " +
                                       "(EnableControlledFolderAccess=0). While CFA mainly protects " +
                                       "against ransomware, its disablement also allows unauthorized " +
                                       "programs to modify protected game directories.",
                            Detail   = "EnableControlledFolderAccess = 0"
                        });
                    }
                }
            }
            catch { }

            // ASR Rules
            if (ct.IsCancellationRequested) return;
            try
            {
                const string asrKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
                using var key = Registry.LocalMachine.OpenSubKey(asrKey, writable: false);
                if (key is not null)
                {
                    var names = key.GetValueNames();
                    ctx.IncrementRegistryKeys((long)names.Length);

                    int disabledCount = 0;
                    var disabledRuleIds = new List<string>();

                    foreach (var ruleName in names)
                    {
                        if (ct.IsCancellationRequested) break;
                        var val = key.GetValue(ruleName);
                        if (val is int rv && rv == 0 || val is string sv && sv == "0")
                        {
                            disabledCount++;
                            disabledRuleIds.Add(ruleName);
                        }
                    }

                    if (disabledCount > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Defender ASR rules disabled ({disabledCount})",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{asrKey}",
                            Reason   = $"{disabledCount} Attack Surface Reduction rule(s) are " +
                                       "explicitly disabled (value=0). ASR rules block common " +
                                       "exploit techniques including code injection, credential " +
                                       "theft, and driver abuse that cheat software relies on.",
                            Detail   = $"Disabled rules: {string.Join(", ", disabledRuleIds.Take(10))}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    // ── 7. Cloud protection registry ─────────────────────────────────────────

    private Task CheckDefenderCloudProtectionRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            // SpyNet / MAPS settings
            try
            {
                const string spynetKey = @"SOFTWARE\Microsoft\Windows Defender\SpyNet";
                using var key = Registry.LocalMachine.OpenSubKey(spynetKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();

                    var spynetReporting = key.GetValue("SpynetReporting");
                    if (spynetReporting is int sr && sr == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender MAPS/SpyNet reporting disabled",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{spynetKey}",
                            Reason   = "Windows Defender cloud (MAPS/SpyNet) reporting is disabled " +
                                       "(SpynetReporting=0). Cloud protection is Defender's primary " +
                                       "mechanism for detecting novel cheat tools and zero-day threats. " +
                                       "Disabling it is a common cheat prerequisite step.",
                            Detail   = "SpynetReporting = 0"
                        });
                    }

                    var submitSamples = key.GetValue("SubmitSamplesConsent");
                    if (submitSamples is int ss && ss == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender sample submission disabled",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{spynetKey}",
                            Reason   = "Automatic sample submission to Microsoft is disabled " +
                                       "(SubmitSamplesConsent=0). This prevents novel cheat tools " +
                                       "from being reported for cloud analysis.",
                            Detail   = "SubmitSamplesConsent = 0"
                        });
                    }
                }
            }
            catch { }

            // Cloud block level
            if (ct.IsCancellationRequested) return;
            try
            {
                const string mpEngineKey = @"SOFTWARE\Microsoft\Windows Defender\MpEngine";
                using var key = Registry.LocalMachine.OpenSubKey(mpEngineKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var blockLevel = key.GetValue("MpCloudBlockLevel");
                    if (blockLevel is int bl && bl == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender cloud block level set to zero",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{mpEngineKey}",
                            Reason   = "The Defender cloud block level is set to 0 (disabled). " +
                                       "This means Defender will not use cloud-based heuristics " +
                                       "to block suspicious files in real time. Cheat loaders " +
                                       "set this to prevent cloud-based detection of injectors.",
                            Detail   = "MpCloudBlockLevel = 0"
                        });
                    }
                }
            }
            catch { }

            // DisableCloudProtectedFiles
            if (ct.IsCancellationRequested) return;
            try
            {
                const string rtpKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
                using var key = Registry.LocalMachine.OpenSubKey(rtpKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var disableCloud = key.GetValue("DisableCloudProtectedFiles");
                    if (disableCloud is int dc && dc == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender cloud-protected file scanning disabled",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{rtpKey}",
                            Reason   = "Defender cloud-protected file scanning is disabled " +
                                       "(DisableCloudProtectedFiles=1). This prevents real-time " +
                                       "cloud lookups for files that might be cheat tools.",
                            Detail   = "DisableCloudProtectedFiles = 1"
                        });
                    }

                    var disableRtp = key.GetValue("DisableRealtimeMonitoring");
                    if (disableRtp is int drtp && drtp == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender real-time protection disabled (RTP key)",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{rtpKey}",
                            Reason   = "Windows Defender real-time protection is disabled via the " +
                                       "Real-Time Protection registry key. This is the primary " +
                                       "defense against cheat DLL injection and is intentionally " +
                                       "disabled by bypass tools before they inject.",
                            Detail   = "DisableRealtimeMonitoring = 1"
                        });
                    }

                    var disableBehavior = key.GetValue("DisableBehaviorMonitoring");
                    if (disableBehavior is int dbm && dbm == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender behavior monitoring disabled",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{rtpKey}",
                            Reason   = "Defender behavior monitoring is disabled " +
                                       "(DisableBehaviorMonitoring=1). Behavior monitoring detects " +
                                       "suspicious process activity such as code injection and " +
                                       "kernel driver exploitation used by cheat tools.",
                            Detail   = "DisableBehaviorMonitoring = 1"
                        });
                    }

                    var disableIoav = key.GetValue("DisableIOAVProtection");
                    if (disableIoav is int dioav && dioav == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender IOAV protection disabled",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{rtpKey}",
                            Reason   = "Defender IOAV (downloaded file scanning) protection is " +
                                       "disabled (DisableIOAVProtection=1). This prevents Defender " +
                                       "from scanning cheat tool executables when they are downloaded.",
                            Detail   = "DisableIOAVProtection = 1"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    // ── 8. Defender scan history registry ────────────────────────────────────

    private Task CheckDefenderScanHistoryRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            try
            {
                const string scanKey = @"SOFTWARE\Microsoft\Windows Defender\Scan";
                using var key = Registry.LocalMachine.OpenSubKey(scanKey, writable: false);
                if (key is null) return;

                ctx.IncrementRegistryKeys();

                // Check last scan times
                var lastQuickScan = key.GetValue("LastQuickScanTime");
                var lastFullScan  = key.GetValue("LastFullScanTime");
                var lastScanType  = key.GetValue("LastScanType");

                // If no scans have ever been run, that is suspicious
                if (lastQuickScan is null && lastFullScan is null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "No Defender scan history in registry",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{scanKey}",
                        Reason   = "No LastQuickScanTime or LastFullScanTime values exist in the " +
                                   "Defender scan registry key. This means either Defender has never " +
                                   "completed a scan, or scan history was deleted from the registry.",
                        Detail   = $@"Key: HKLM\{scanKey}"
                    });
                }
                else
                {
                    // Decode FILETIME-based timestamps if present
                    if (lastQuickScan is byte[] qsBytes && qsBytes.Length >= 8)
                    {
                        long ft = BitConverter.ToInt64(qsBytes, 0);
                        if (ft > 0)
                        {
                            var lastQuick = DateTime.FromFileTimeUtc(ft);
                            var daysSince = (DateTime.UtcNow - lastQuick).TotalDays;

                            if (daysSince > 60)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "Defender quick scan not run for >60 days",
                                    Risk     = RiskLevel.Low,
                                    Location = $@"HKLM\{scanKey}",
                                    Reason   = $"Last Defender quick scan was {daysSince:F0} days ago " +
                                               $"({lastQuick:yyyy-MM-dd}). A player who has not run " +
                                               "any Defender scans for months may have deliberately " +
                                               "disabled or avoided scanning.",
                                    Detail   = $"LastQuickScanTime: {lastQuick:yyyy-MM-dd HH:mm} UTC"
                                });
                            }
                        }
                    }
                }

                // Check scan parameters for unusual flags
                var scanParams = key.GetValue("ScanParameters");
                if (scanParams is int sp)
                {
                    ctx.IncrementRegistryKeys();
                    // ScanParameters of 0 can indicate disabled scanning
                    if (sp == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender ScanParameters set to zero",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{scanKey}",
                            Reason   = "The Defender ScanParameters registry value is 0, which " +
                                       "may indicate scan configuration has been tampered with " +
                                       "to disable or weaken scanning behavior.",
                            Detail   = $"ScanParameters = {sp}"
                        });
                    }
                }

                // Check DisableArchiveScanning
                var disableArchive = key.GetValue("DisableArchiveScanning");
                if (disableArchive is int da && da == 1)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Defender archive scanning disabled",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{scanKey}",
                        Reason   = "Defender archive scanning is disabled (DisableArchiveScanning=1). " +
                                   "Cheat tools are frequently distributed in ZIP/RAR archives; " +
                                   "disabling archive scanning allows them to download undetected.",
                        Detail   = "DisableArchiveScanning = 1"
                    });
                }

                // Check DisableScanningNetworkFiles
                var disableNetScan = key.GetValue("DisableScanningNetworkFiles");
                if (disableNetScan is int dnsf && dnsf == 1)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Defender network file scanning disabled",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{scanKey}",
                        Reason   = "Scanning of network files is disabled (DisableScanningNetworkFiles=1). " +
                                   "This allows cheat files to be loaded from network shares or " +
                                   "mapped drives without Defender scanning them.",
                        Detail   = "DisableScanningNetworkFiles = 1"
                    });
                }
            }
            catch { }
        }, ct);

    // ── 9. Threat detection history directory ────────────────────────────────

    private Task CheckDefenderThreatDetectionHistory(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            if (!Directory.Exists(DefenderDetectionHistoryDir)) return;

            string[] subdirs;
            try
            {
                subdirs = Directory.GetDirectories(DefenderDetectionHistoryDir);
            }
            catch (UnauthorizedAccessException) { return; }

            if (subdirs.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Defender threat detection history is empty",
                    Risk     = RiskLevel.Medium,
                    Location = DefenderDetectionHistoryDir,
                    Reason   = "The Windows Defender threat detection history directory exists " +
                               "but contains no subdirectories. On an active system that has " +
                               "used Defender, this directory normally contains per-date folders " +
                               "with detection records. An empty directory may indicate deletion.",
                    Detail   = $"Directory: {DefenderDetectionHistoryDir}"
                });
                return;
            }

            int totalDetectionFiles = 0;
            int cheatDetections = 0;

            foreach (var subdir in subdirs)
            {
                if (ct.IsCancellationRequested) break;

                string[] files;
                try
                {
                    files = Directory.GetFiles(subdir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                totalDetectionFiles += files.Length;
                ctx.IncrementFiles((long)files.Length);

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open,
                            FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        content = await sr.ReadToEndAsync(ct);

                        var hits = new List<string>();
                        foreach (var kw in CheatKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                hits.Add(kw);
                        }

                        bool hasBypassTool = BypassToolNames.Any(t =>
                            content.Contains(t, StringComparison.OrdinalIgnoreCase));

                        if (hits.Count > 0 || hasBypassTool)
                        {
                            cheatDetections++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Cheat tool found in Defender threat detection history",
                                Risk     = RiskLevel.Critical,
                                Location = subdir,
                                FileName = Path.GetFileName(file),
                                Reason   = "A Windows Defender threat detection history entry " +
                                           "contains references to cheat tools or bypass utilities. " +
                                           "These binary records store details of threats Defender " +
                                           "has previously detected and remediated.",
                                Detail   = $"File: {file} | Keywords: {string.Join(", ", hits.Take(8))}" +
                                           $"{(hasBypassTool ? " | Bypass tool name matched" : "")}"
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }

            if (cheatDetections == 0 && totalDetectionFiles > 0)
            {
                // Report informational: history exists but no cheat hits
                ctx.Report(0.65, Name,
                    $"Defender detection history: {totalDetectionFiles} records, no cheat hits");
            }
        }, ct);

    // ── 10. MPSupportFiles and MpWppTracing ──────────────────────────────────

    private Task CheckDefenderMPSupportFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            if (!Directory.Exists(DefenderSupportDir)) return;

            // Check for MPSupportFiles-*.cab
            string[] cabFiles;
            try
            {
                cabFiles = Directory.GetFiles(DefenderSupportDir,
                    "MPSupportFiles-*.cab", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { cabFiles = Array.Empty<string>(); }

            ctx.IncrementFiles((long)cabFiles.Length);

            // Check for MpWppTracing-*.bin
            string[] wppFiles;
            try
            {
                wppFiles = Directory.GetFiles(DefenderSupportDir,
                    "MpWppTracing-*.bin", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { wppFiles = Array.Empty<string>(); }

            ctx.IncrementFiles((long)wppFiles.Length);

            // Scan support log files for cheat patterns
            string[] logFiles;
            try
            {
                logFiles = Directory.GetFiles(DefenderSupportDir,
                    "*.log", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { logFiles = Array.Empty<string>(); }

            ctx.IncrementFiles((long)logFiles.Length);

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    string content;
                    using var fs = new FileStream(logFile, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);

                    var cheatHits = CheatKeywords.Where(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .Take(10).ToList();

                    // Check for Defender reset/reinstall indicators
                    bool hasReset = content.Contains("RestoreDefaults",
                        StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("ResetDefender",
                        StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("protection history cleared",
                        StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("detection history removed",
                        StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("quarantine database deleted",
                        StringComparison.OrdinalIgnoreCase);

                    if (cheatHits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Cheat keywords in Defender support log",
                            Risk     = RiskLevel.High,
                            Location = DefenderSupportDir,
                            FileName = Path.GetFileName(logFile),
                            Reason   = $"A Defender support log contains {cheatHits.Count} cheat-related " +
                                       "keyword(s). Support logs capture detailed Defender operational " +
                                       "data and may record names of detected cheat files.",
                            Detail   = $"Log: {logFile} | Keywords: {string.Join(", ", cheatHits)}"
                        });
                    }

                    if (hasReset)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender support log shows detection history cleared",
                            Risk     = RiskLevel.Critical,
                            Location = DefenderSupportDir,
                            FileName = Path.GetFileName(logFile),
                            Reason   = "A Defender support log records indicators that detection " +
                                       "history, quarantine database, or protection history was " +
                                       "cleared. This is a strong anti-forensics indicator used " +
                                       "after cheat tools are detected and removed to erase evidence.",
                            Detail   = $"Log: {logFile} | Contains history-clearing indicators"
                        });
                    }
                }
                catch (IOException) { }
            }

            // Check WPP tracing files for cheat patterns (binary but contains readable strings)
            foreach (var wppFile in wppFiles.Take(3))
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    string content;
                    using var fs = new FileStream(wppFile, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);

                    var bypassHits = BypassToolNames.Where(t =>
                        content.Contains(t, StringComparison.OrdinalIgnoreCase))
                        .Take(5).ToList();

                    if (bypassHits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Bypass tool name in Defender WPP trace",
                            Risk     = RiskLevel.Critical,
                            Location = DefenderSupportDir,
                            FileName = Path.GetFileName(wppFile),
                            Reason   = "A Defender WPP trace binary file contains names of known " +
                                       "bypass tools. These trace files record low-level Defender " +
                                       "engine activity and their contents indicate prior detection " +
                                       "of a cheat bypass tool.",
                            Detail   = $"Trace: {wppFile} | Tools: {string.Join(", ", bypassHits)}"
                        });
                    }
                }
                catch (IOException) { }
            }
        }, ct);

    // ── 11. Quarantine database ───────────────────────────────────────────────

    private Task CheckDefenderQuarantineDatabase(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            if (!Directory.Exists(DefenderQuarantineDir))
            {
                // Quarantine dir absent is only notable if Defender is installed
                string defenderInstallKey =
                    @"SOFTWARE\Microsoft\Windows Defender";
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        defenderInstallKey, writable: false);
                    if (key is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender quarantine directory missing",
                            Risk     = RiskLevel.Low,
                            Location = DefenderQuarantineDir,
                            Reason   = "Windows Defender is installed but the quarantine directory " +
                                       "does not exist. The quarantine directory is normally created " +
                                       "when Defender first quarantines a file.",
                            Detail   = $"Expected: {DefenderQuarantineDir}"
                        });
                    }
                }
                catch { }
                return;
            }

            string[] quarantineFiles;
            try
            {
                quarantineFiles = Directory.GetFiles(DefenderQuarantineDir,
                    "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { return; }

            ctx.IncrementFiles((long)quarantineFiles.Length);

            if (quarantineFiles.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Defender quarantine directory is empty",
                    Risk     = RiskLevel.Low,
                    Location = DefenderQuarantineDir,
                    Reason   = "The Windows Defender quarantine directory exists but is empty. " +
                               "If a cheat tool was previously quarantined and then the quarantine " +
                               "was cleared (e.g. via 'Remove All' or manually), this directory " +
                               "would appear empty.",
                    Detail   = $"Directory: {DefenderQuarantineDir}"
                });
                return;
            }

            // High number of quarantine entries is suspicious
            if (quarantineFiles.Length > 50)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Defender quarantine contains {quarantineFiles.Length} entries",
                    Risk     = RiskLevel.Medium,
                    Location = DefenderQuarantineDir,
                    Reason   = $"Windows Defender quarantine contains an unusually large number " +
                               $"({quarantineFiles.Length}) of entries. This may indicate a high " +
                               "volume of detections, possibly including cheat tools and their " +
                               "components.",
                    Detail   = $"Quarantine files count: {quarantineFiles.Length}"
                });
            }

            // Scan quarantine files (ResourceData etc.) for cheat keywords
            foreach (var qFile in quarantineFiles.Take(20))
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    string content;
                    using var fs = new FileStream(qFile, FileMode.Open,
                        FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);

                    var cheatHits = CheatKeywords.Where(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .Take(8).ToList();

                    var bypassHits = BypassToolNames.Where(t =>
                        content.Contains(t, StringComparison.OrdinalIgnoreCase))
                        .Take(5).ToList();

                    if (cheatHits.Count > 0 || bypassHits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Cheat tool found in Defender quarantine",
                            Risk     = RiskLevel.Critical,
                            Location = DefenderQuarantineDir,
                            FileName = Path.GetFileName(qFile),
                            Reason   = "A file in the Windows Defender quarantine database contains " +
                                       "cheat-related strings. Quarantine records retain data about " +
                                       "previously detected threats. This confirms Defender previously " +
                                       "detected and quarantined a cheat tool on this system.",
                            Detail   = $"File: {qFile} | Cheat hits: {string.Join(", ", cheatHits.Take(5))}" +
                                       $"{(bypassHits.Count > 0 ? $" | Tools: {string.Join(", ", bypassHits)}" : "")}"
                        });
                    }
                }
                catch (IOException) { }
            }
        }, ct);

    // ── 12. Policy conflicts that weaken Defender ─────────────────────────────

    private Task CheckDefenderPolicyConflicts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            // DisableAntiSpyware via policy
            try
            {
                const string policyKey =
                    @"SOFTWARE\Policies\Microsoft\Windows Defender";
                using var key = Registry.LocalMachine.OpenSubKey(policyKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();

                    var disableAV = key.GetValue("DisableAntiSpyware");
                    if (disableAV is int dav && dav == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender disabled by policy (DisableAntiSpyware=1)",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{policyKey}",
                            Reason   = "Windows Defender anti-spyware protection is disabled via " +
                                       "Group Policy (DisableAntiSpyware=1). This setting completely " +
                                       "disables Defender and is commonly used by cheat loaders to " +
                                       "prevent detection during injection.",
                            Detail   = "DisableAntiSpyware = 1"
                        });
                    }

                    var disableAntiVirus = key.GetValue("DisableAntiVirus");
                    if (disableAntiVirus is int daav && daav == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender antivirus disabled by policy",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{policyKey}",
                            Reason   = "Windows Defender antivirus is disabled via Group Policy " +
                                       "(DisableAntiVirus=1). This is a definitive indicator of " +
                                       "Defender tampering.",
                            Detail   = "DisableAntiVirus = 1"
                        });
                    }

                    var disableRoutinelyTaking = key.GetValue("DisableRoutinelyTakingAction");
                    if (disableRoutinelyTaking is int drta && drta == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender auto-remediation disabled by policy",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{policyKey}",
                            Reason   = "Defender automatic remediation is disabled via policy " +
                                       "(DisableRoutinelyTakingAction=1). This means Defender " +
                                       "will detect but not automatically remove detected threats " +
                                       "including cheat tools.",
                            Detail   = "DisableRoutinelyTakingAction = 1"
                        });
                    }
                }
            }
            catch { }

            // Real-Time Protection policy
            if (ct.IsCancellationRequested) return;
            try
            {
                const string rtpPolicyKey =
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
                using var key = Registry.LocalMachine.OpenSubKey(rtpPolicyKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();

                    var names = key.GetValueNames();
                    foreach (var valueName in names)
                    {
                        if (ct.IsCancellationRequested) break;
                        var val = key.GetValue(valueName);
                        if (val is int intVal && intVal == 1 &&
                            valueName.StartsWith("Disable", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Defender RTP policy override: {valueName}=1",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{rtpPolicyKey}",
                                Reason   = $"Windows Defender Real-Time Protection is weakened by " +
                                           $"policy override: {valueName}=1. This policy setting " +
                                           "disables a Defender protection component and may allow " +
                                           "cheat tools to run undetected.",
                                Detail   = $"{valueName} = 1"
                            });
                        }
                    }
                }
            }
            catch { }

            // Windows Defender Advanced Threat Protection (EDR)
            if (ct.IsCancellationRequested) return;
            try
            {
                const string atpKey =
                    @"SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection";
                using var key = Registry.LocalMachine.OpenSubKey(atpKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();

                    var forceDefenderPassive = key.GetValue("ForceDefenderPassiveMode");
                    if (forceDefenderPassive is int fdpm && fdpm == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender forced into passive mode by ATP policy",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{atpKey}",
                            Reason   = "Windows Defender is forced into passive mode by ATP policy " +
                                       "(ForceDefenderPassiveMode=1). In passive mode, Defender " +
                                       "does not block threats, only reports them. This reduces its " +
                                       "effectiveness against cheat tools and injectors.",
                            Detail   = "ForceDefenderPassiveMode = 1"
                        });
                    }

                    var onboardingState = key.GetValue("OnboardingState");
                    if (onboardingState is int obs && obs == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Windows Defender EDR (ATP) not onboarded",
                            Risk     = RiskLevel.Low,
                            Location = $@"HKLM\{atpKey}",
                            Reason   = "Windows Defender for Endpoint (EDR) is not onboarded " +
                                       "(OnboardingState=0). EDR provides deeper behavioral " +
                                       "detection for cheat tools and kernel-level threats.",
                            Detail   = "OnboardingState = 0"
                        });
                    }
                }
            }
            catch { }

            // Check signature enforcement policy
            if (ct.IsCancellationRequested) return;
            try
            {
                const string signatureKey =
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates";
                using var key = Registry.LocalMachine.OpenSubKey(signatureKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();

                    var disableUpdate = key.GetValue("DisableUpdateOnStartupWithoutEngine");
                    if (disableUpdate is int du && du == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender signature updates disabled by policy",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{signatureKey}",
                            Reason   = "Defender signature updates on startup are disabled via " +
                                       "policy (DisableUpdateOnStartupWithoutEngine=1). Outdated " +
                                       "signatures mean newer cheat tools may go undetected.",
                            Detail   = "DisableUpdateOnStartupWithoutEngine = 1"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    // ── 13. SmartScreen registry ──────────────────────────────────────────────

    private Task CheckDefenderSmartScreenRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            // Explorer SmartScreen
            try
            {
                const string explorerKey =
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";
                using var key = Registry.LocalMachine.OpenSubKey(explorerKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var smartScreenEnabled = key.GetValue("SmartScreenEnabled");
                    if (smartScreenEnabled is string sse &&
                        sse.Equals("Off", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Windows SmartScreen disabled via Explorer key",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{explorerKey}",
                            Reason   = "Windows SmartScreen is disabled (SmartScreenEnabled='Off'). " +
                                       "SmartScreen warns users before running unsigned or suspicious " +
                                       "executables downloaded from the internet. Cheat tools often " +
                                       "arrive as unsigned binaries and disable SmartScreen to " +
                                       "avoid the download warning dialog.",
                            Detail   = "SmartScreenEnabled = Off"
                        });
                    }
                }
            }
            catch { }

            // Policy SmartScreen
            if (ct.IsCancellationRequested) return;
            try
            {
                const string policyKey =
                    @"SOFTWARE\Policies\Microsoft\Windows\System";
                using var key = Registry.LocalMachine.OpenSubKey(policyKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var enableSmartScreen = key.GetValue("EnableSmartScreen");
                    if (enableSmartScreen is int ess && ess == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "SmartScreen disabled by Group Policy",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{policyKey}",
                            Reason   = "Windows SmartScreen is disabled via Group Policy " +
                                       "(EnableSmartScreen=0). This policy prevents SmartScreen " +
                                       "from blocking potentially dangerous downloads, allowing " +
                                       "cheat executables to run without the reputation warning.",
                            Detail   = "EnableSmartScreen = 0"
                        });
                    }
                }
            }
            catch { }

            // IFEO Debugger hijack for smartscreen.exe
            if (ct.IsCancellationRequested) return;
            try
            {
                const string ifeoKey =
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smartscreen.exe";
                using var key = Registry.LocalMachine.OpenSubKey(ifeoKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var debugger = key.GetValue("Debugger") as string;
                    if (!string.IsNullOrEmpty(debugger))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "SmartScreen.exe hijacked via IFEO debugger",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{ifeoKey}",
                            FileName = "smartscreen.exe",
                            Reason   = "A debugger has been registered for smartscreen.exe in Image " +
                                       "File Execution Options. This is a classic technique to " +
                                       "hijack or kill SmartScreen before it can warn about a " +
                                       "malicious file. Cheat loaders use this to silently " +
                                       "bypass the SmartScreen warning dialog.",
                            Detail   = $"Debugger = {debugger}"
                        });
                    }

                    // Also check for GlobalFlag = 0x200 (disable exception handling) or other traps
                    var globalFlag = key.GetValue("GlobalFlag");
                    if (globalFlag is int gf && gf != 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "SmartScreen.exe IFEO GlobalFlag set",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{ifeoKey}",
                            FileName = "smartscreen.exe",
                            Reason   = $"An IFEO GlobalFlag ({gf}) is set for smartscreen.exe. " +
                                       "This can be used to alter SmartScreen behavior or crash it " +
                                       "before it can display reputation warnings for cheat tools.",
                            Detail   = $"GlobalFlag = 0x{gf:X}"
                        });
                    }
                }
            }
            catch { }

            // SmartScreen for Edge/Microsoft Edge
            if (ct.IsCancellationRequested) return;
            try
            {
                const string edgeKey =
                    @"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter";
                using var key = Registry.LocalMachine.OpenSubKey(edgeKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var enabled = key.GetValue("EnabledV9");
                    if (enabled is int ev9 && ev9 == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "SmartScreen disabled for Microsoft Edge",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{edgeKey}",
                            Reason   = "Windows SmartScreen is disabled for Microsoft Edge " +
                                       "(EnabledV9=0). This allows cheat tool downloads via Edge " +
                                       "without reputation warnings.",
                            Detail   = "EnabledV9 = 0"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    // ── 14. Windows Security Health registry ─────────────────────────────────

    private Task CheckWindowsSecurityHealthRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            // Windows Security Health State
            try
            {
                const string healthKey =
                    @"SOFTWARE\Microsoft\Windows Security Health\State";
                using var key = Registry.LocalMachine.OpenSubKey(healthKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();

                    // AppAndBrowser_EdgeSmartScreenOff = 1 means SmartScreen off
                    var edgeSmartScreen = key.GetValue("AppAndBrowser_EdgeSmartScreenOff");
                    if (edgeSmartScreen is int ess && ess == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Security Health: Edge SmartScreen reported off",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{healthKey}",
                            Reason   = "The Windows Security Health state reports Edge SmartScreen " +
                                       "as off (AppAndBrowser_EdgeSmartScreenOff=1). This matches " +
                                       "a configuration commonly seen when cheat users disable " +
                                       "SmartScreen to download and run unsigned cheat executables.",
                            Detail   = "AppAndBrowser_EdgeSmartScreenOff = 1"
                        });
                    }

                    // AccountProtection_MicrosoftAccountSigninRequired = 0
                    var firewall = key.GetValue("Firewall_NetworkFirewallOff");
                    if (firewall is int fw && fw == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Security Health: Windows Firewall reported off",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{healthKey}",
                            Reason   = "The Windows Security Health state reports the Windows Firewall " +
                                       "as off. Cheat tools and loaders frequently disable the firewall " +
                                       "to allow outbound connections to cheat license servers " +
                                       "and C2 infrastructure.",
                            Detail   = "Firewall_NetworkFirewallOff = 1"
                        });
                    }

                    // Antivirus off
                    var avOff = key.GetValue("Antivirus_AllAVsOff");
                    if (avOff is int av && av == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Security Health: All AV products reported off",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{healthKey}",
                            Reason   = "The Windows Security Health state reports all antivirus " +
                                       "products as disabled (Antivirus_AllAVsOff=1). This is a " +
                                       "definitive indicator that all AV protection was disabled, " +
                                       "which is a prerequisite for running most cheat tools.",
                            Detail   = "Antivirus_AllAVsOff = 1"
                        });
                    }
                }
            }
            catch { }

            // SecurityHealthService start type
            if (ct.IsCancellationRequested) return;
            try
            {
                const string svcKey =
                    @"SYSTEM\CurrentControlSet\Services\SecurityHealthService";
                using var key = Registry.LocalMachine.OpenSubKey(svcKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var startVal = key.GetValue("Start");
                    if (startVal is int sv && sv >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Windows Security Health Service disabled",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{svcKey}",
                            Reason   = "The Windows Security Health Service is disabled " +
                                       $"(Start={sv}). This service monitors the security state " +
                                       "of the system. Disabling it hides security warnings in " +
                                       "the Windows Security app and suppresses Defender status " +
                                       "notifications.",
                            Detail   = $"Start = {sv} (4=Disabled)"
                        });
                    }
                }
            }
            catch { }

            // Security notifications suppressed
            if (ct.IsCancellationRequested) return;
            try
            {
                const string notifKey =
                    @"SOFTWARE\Microsoft\Windows Defender Security Center\Notifications";
                using var key = Registry.LocalMachine.OpenSubKey(notifKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var disableNotif = key.GetValue("DisableNotifications");
                    if (disableNotif is int dn && dn == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Windows Defender Security Center notifications disabled",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{notifKey}",
                            Reason   = "Security notifications from the Windows Defender Security " +
                                       "Center are disabled (DisableNotifications=1). Suppressing " +
                                       "these notifications prevents the system owner from being " +
                                       "alerted when Defender detects cheat tools.",
                            Detail   = "DisableNotifications = 1"
                        });
                    }

                    var disableEnhanced = key.GetValue("DisableEnhancedNotifications");
                    if (disableEnhanced is int den && den == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender Security Center enhanced notifications disabled",
                            Risk     = RiskLevel.Low,
                            Location = $@"HKLM\{notifKey}",
                            Reason   = "Enhanced security notifications are disabled " +
                                       "(DisableEnhancedNotifications=1). This reduces the " +
                                       "visibility of Defender threat alerts.",
                            Detail   = "DisableEnhancedNotifications = 1"
                        });
                    }
                }
            }
            catch { }

            // UI lockdown (hides Defender UI)
            if (ct.IsCancellationRequested) return;
            try
            {
                const string uiKey =
                    @"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection";
                using var key = Registry.LocalMachine.OpenSubKey(uiKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var uilocked = key.GetValue("UILockdown");
                    if (uilocked is int ul && ul == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender Security Center UI locked down by policy",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{uiKey}",
                            Reason   = "The Windows Defender Security Center UI is locked down " +
                                       "by policy (UILockdown=1). This hides the Defender interface " +
                                       "and prevents users from seeing or managing protection state, " +
                                       "including threat detections.",
                            Detail   = "UILockdown = 1"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    // ── 15. Defender sandbox state ────────────────────────────────────────────

    private Task CheckDefenderSandboxState(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            if (ct.IsCancellationRequested) return;

            // MP_FORCE_USE_SANDBOX environment variable in registry
            try
            {
                const string envKey =
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
                using var key = Registry.LocalMachine.OpenSubKey(envKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var sandboxVal = key.GetValue("MP_FORCE_USE_SANDBOX") as string;

                    if (sandboxVal is not null)
                    {
                        bool sandboxEnabled = sandboxVal.Equals("1",
                            StringComparison.OrdinalIgnoreCase);
                        bool sandboxDisabled = sandboxVal.Equals("0",
                            StringComparison.OrdinalIgnoreCase);

                        if (sandboxDisabled)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Defender antimalware sandbox explicitly disabled",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{envKey}",
                                Reason   = "The Defender antimalware sandbox is explicitly disabled " +
                                           "(MP_FORCE_USE_SANDBOX=0). Running Defender in a sandbox " +
                                           "provides additional isolation against exploitation of " +
                                           "the antimalware engine itself. Disabling it reduces " +
                                           "protection against advanced cheat loaders that attempt " +
                                           "to exploit Defender.",
                                Detail   = "MP_FORCE_USE_SANDBOX = 0"
                            });
                        }
                        else if (!sandboxEnabled)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Defender sandbox set to unexpected value",
                                Risk     = RiskLevel.Medium,
                                Location = $@"HKLM\{envKey}",
                                Reason   = $"The Defender sandbox environment variable has an " +
                                           $"unexpected value: MP_FORCE_USE_SANDBOX={sandboxVal}. " +
                                           "Valid values are 0 (disabled) and 1 (enabled). " +
                                           "An unexpected value may indicate tampering.",
                                Detail   = $"MP_FORCE_USE_SANDBOX = {sandboxVal}"
                            });
                        }
                    }
                }
            }
            catch { }

            // Check Platform directory for current version
            if (ct.IsCancellationRequested) return;

            if (Directory.Exists(DefenderPlatformDir))
            {
                try
                {
                    var platformVersionDirs = Directory.GetDirectories(DefenderPlatformDir);
                    ctx.IncrementFiles((long)platformVersionDirs.Length);

                    if (platformVersionDirs.Length == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender platform directory empty",
                            Risk     = RiskLevel.Medium,
                            Location = DefenderPlatformDir,
                            Reason   = "The Windows Defender platform directory exists but contains " +
                                       "no version subdirectories. This directory normally contains " +
                                       "the current Defender engine version files. An empty platform " +
                                       "directory may indicate platform files were deleted.",
                            Detail   = $"Directory: {DefenderPlatformDir}"
                        });
                    }
                    else
                    {
                        // Find the most recently modified platform version directory
                        var latestPlatform = platformVersionDirs
                            .Select(d => new DirectoryInfo(d))
                            .OrderByDescending(di => di.LastWriteTimeUtc)
                            .FirstOrDefault();

                        if (latestPlatform is not null)
                        {
                            // Check if MsMpEng.exe exists in the platform directory
                            var msmpeng = Path.Combine(latestPlatform.FullName, "MsMpEng.exe");
                            if (!File.Exists(msmpeng))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "Defender engine (MsMpEng.exe) missing from platform",
                                    Risk     = RiskLevel.Critical,
                                    Location = latestPlatform.FullName,
                                    FileName = "MsMpEng.exe",
                                    Reason   = "The Defender antimalware service executable (MsMpEng.exe) " +
                                               "is missing from the current platform directory. This file " +
                                               "is the core Defender engine and should always be present. " +
                                               "Its absence indicates the platform files may have been " +
                                               "deleted or corrupted to disable Defender.",
                                    Detail   = $"Expected at: {msmpeng} | Platform: {latestPlatform.Name}"
                                });
                            }
                            else
                            {
                                ctx.IncrementFiles();

                                // Check age of platform (very old platform = updates disabled)
                                var platformAge =
                                    DateTime.UtcNow - latestPlatform.LastWriteTimeUtc;
                                if (platformAge.TotalDays > 90)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module   = Name,
                                        Title    = "Defender platform not updated for >90 days",
                                        Risk     = RiskLevel.Medium,
                                        Location = latestPlatform.FullName,
                                        FileName = "MsMpEng.exe",
                                        Reason   = $"The Windows Defender platform directory was last " +
                                                   $"updated {platformAge.TotalDays:F0} days ago. An " +
                                                   "outdated Defender platform lacks recent cheat tool " +
                                                   "signatures and behavioral detection capabilities.",
                                        Detail   = $"Platform version: {latestPlatform.Name} | " +
                                                   $"Last modified: {latestPlatform.LastWriteTimeUtc:yyyy-MM-dd}"
                                    });
                                }
                            }

                            // Check for WdFilter.sys
                            var wdFilter = Path.Combine(latestPlatform.FullName, "WdFilter.sys");
                            if (!File.Exists(wdFilter))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "WdFilter.sys missing from Defender platform",
                                    Risk     = RiskLevel.Critical,
                                    Location = latestPlatform.FullName,
                                    FileName = "WdFilter.sys",
                                    Reason   = "The Windows Defender minifilter driver (WdFilter.sys) is " +
                                               "missing from the current platform directory. WdFilter.sys " +
                                               "is the kernel-mode file system filter that provides real-time " +
                                               "file scanning. Its absence disables file-level protection " +
                                               "and is a strong indicator of deliberate Defender tampering.",
                                    Detail   = $"Expected at: {wdFilter} | Platform: {latestPlatform.Name}"
                                });
                            }
                            else
                            {
                                ctx.IncrementFiles();
                            }

                            // Check for WdBoot.sys (Defender early launch AM driver)
                            var wdBoot = Path.Combine(latestPlatform.FullName, "WdBoot.sys");
                            if (!File.Exists(wdBoot))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "WdBoot.sys missing from Defender platform",
                                    Risk     = RiskLevel.High,
                                    Location = latestPlatform.FullName,
                                    FileName = "WdBoot.sys",
                                    Reason   = "The Windows Defender Early Launch AntiMalware (ELAM) " +
                                               "driver (WdBoot.sys) is missing from the current platform. " +
                                               "ELAM starts before other drivers and detects rootkits " +
                                               "and bootkits at system startup. Its absence allows " +
                                               "malicious kernel drivers to load undetected.",
                                    Detail   = $"Expected at: {wdBoot} | Platform: {latestPlatform.Name}"
                                });
                            }
                            else
                            {
                                ctx.IncrementFiles();
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
            else
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Defender platform directory not found",
                    Risk     = RiskLevel.Medium,
                    Location = DefenderPlatformDir,
                    Reason   = "The Windows Defender platform directory does not exist. " +
                               "This directory contains the current version of the Defender " +
                               "engine and drivers. Its absence may indicate Defender was " +
                               "uninstalled or critical platform files were deleted.",
                    Detail   = $"Expected: {DefenderPlatformDir}"
                });
            }

            // Check WdNisDrv.sys (Network Inspection driver)
            if (ct.IsCancellationRequested) return;
            try
            {
                const string wdNisKey =
                    @"SYSTEM\CurrentControlSet\Services\WdNisDrv";
                using var key = Registry.LocalMachine.OpenSubKey(wdNisKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var start = key.GetValue("Start");
                    if (start is int sv && sv >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender Network Inspection driver disabled",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{wdNisKey}",
                            FileName = "WdNisDrv.sys",
                            Reason   = "The Windows Defender Network Inspection System driver " +
                                       "(WdNisDrv) is disabled (Start=4). This driver inspects " +
                                       "network traffic for exploit payloads and cheat C2 " +
                                       "communication patterns.",
                            Detail   = $"Start = {sv} (4=Disabled)"
                        });
                    }
                }
            }
            catch { }

            // Check WdNisSvc (Network Inspection Service)
            if (ct.IsCancellationRequested) return;
            try
            {
                const string wdNisSvcKey =
                    @"SYSTEM\CurrentControlSet\Services\WdNisSvc";
                using var key = Registry.LocalMachine.OpenSubKey(wdNisSvcKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var start = key.GetValue("Start");
                    if (start is int sv && sv >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender Network Inspection Service disabled",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{wdNisSvcKey}",
                            Reason   = "The Windows Defender Network Inspection Service (WdNisSvc) " +
                                       "is disabled. This service provides network-based threat " +
                                       "detection and its disablement allows cheat tools to " +
                                       "communicate with external servers without interception.",
                            Detail   = $"Start = {sv}"
                        });
                    }
                }
            }
            catch { }

            // Check WinDefend service itself
            if (ct.IsCancellationRequested) return;
            try
            {
                const string winDefendKey =
                    @"SYSTEM\CurrentControlSet\Services\WinDefend";
                using var key = Registry.LocalMachine.OpenSubKey(winDefendKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var start = key.GetValue("Start");
                    if (start is int sv && sv >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Windows Defender service (WinDefend) disabled",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{winDefendKey}",
                            Reason   = "The Windows Defender service (WinDefend) is disabled " +
                                       $"(Start={sv}). Disabling this service completely shuts " +
                                       "down all Defender protection. This is the primary action " +
                                       "taken by bypass tools and cheat loaders to prevent " +
                                       "detection.",
                            Detail   = $"Start = {sv} (4=Disabled, 3=Manual, 2=Auto)"
                        });
                    }

                    // Check for unexpected binary path
                    var imagePath = key.GetValue("ImagePath") as string ?? "";
                    if (imagePath.Length > 0 &&
                        !imagePath.Contains("svchost", StringComparison.OrdinalIgnoreCase) &&
                        !imagePath.Contains("MsMpEng", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "WinDefend service binary path unexpected",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{winDefendKey}",
                            Reason   = "The WinDefend service ImagePath points to an unexpected " +
                                       "binary (not svchost or MsMpEng). A rootkit or bypass tool " +
                                       "may have redirected the Defender service to a different " +
                                       "executable to silently neutralize it.",
                            Detail   = $"ImagePath = {imagePath}"
                        });
                    }
                }
            }
            catch { }
        }, ct);
}
