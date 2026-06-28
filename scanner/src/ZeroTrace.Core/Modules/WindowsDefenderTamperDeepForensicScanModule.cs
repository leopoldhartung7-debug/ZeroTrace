using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class WindowsDefenderTamperDeepForensicScanModule : IScanModule
{
    public string Name => "Windows Defender Tamper Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] DefenderPolicyKeys =
    {
        @"SOFTWARE\Policies\Microsoft\Windows Defender",
        @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        @"SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates",
        @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    };

    private static readonly string[] DefenderServiceNames =
    {
        "WinDefend", "Sense", "WdNisSvc", "WdBoot", "WdFilter", "MsMpEng"
    };

    private static readonly string[] KnownCheatProcessNames =
    {
        "2take1.exe", "stand.exe", "yimmenu.exe", "eulen.exe", "redengine.exe",
        "skript.exe", "menyoo.exe", "trainer.exe", "esp.exe", "aimbot.exe",
        "bypass.exe", "injector.exe", "loader.exe", "krnl.exe", "synapse.exe",
        "sentinel.exe", "jjsploit.exe"
    };

    private static readonly string[] AMSIBypassStrings =
    {
        "amsiInitFailed", "AmsiUtils", "amsiContext", "AmsiScanBuffer",
        "AmsiOpenSession", "System.Management.Automation.AmsiUtils"
    };

    private static readonly string[] DefenderDetectionHistoryPath =
    {
        @"ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory"
    };

    private static readonly string[] CheatToolDetectionKeywords =
    {
        "hack", "cheat", "bypass", "aimbot", "wallhack", "trainer",
        "menyoo", "scripthookv", "krnl", "synapse", "2take1", "stand", "yimmenu"
    };

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private static readonly string ProgramData =
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string[] SuspiciousPathFragments =
    {
        @"\desktop\", @"\downloads\", @"\temp\", @"\tmp\",
        @"\appdata\local\temp\", "cheat", "hack", "inject", "bypass",
        "aimbot", "loader", "trainer", "esp", "wallhack"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Windows Defender tamper deep forensic scan");

        await Task.WhenAll(
            CheckDefenderRealtimeProtectionDisabled(ctx, ct),
            CheckDefenderExclusionArtifacts(ctx, ct),
            CheckDefenderCloudProtectionDisabled(ctx, ct),
            CheckDefenderSignatureUpdateDisabled(ctx, ct),
            CheckDefenderTamperProtectionDisabled(ctx, ct),
            CheckDefenderEventLogTamper(ctx, ct),
            CheckDefenderQuarantineRecords(ctx, ct),
            CheckDefenderProtectionHistoryRecords(ctx, ct),
            CheckDefenderScanLogsForCheats(ctx, ct),
            CheckAMSIBypassArtifacts(ctx, ct),
            CheckDefenderPolicyTamper(ctx, ct),
            CheckSecurityCenterStatusArtifacts(ctx, ct),
            CheckDefenderServiceManipulation(ctx, ct),
            CheckDefenderASEPManipulation(ctx, ct),
            CheckDefenderDatabaseTamper(ctx, ct),
            CheckWindowsFirewallDefenderBlock(ctx, ct),
            CheckDefenderExclusionByProcess(ctx, ct),
            CheckThreatServiceDisabledHistory(ctx, ct)
        );

        ctx.Report(1.0, Name, "Windows Defender tamper deep forensic scan complete");
    }

    private Task CheckDefenderRealtimeProtectionDisabled(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            try
            {
                const string policyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender";
                using var key = Registry.LocalMachine.OpenSubKey(policyKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var disableAS = key.GetValue("DisableAntiSpyware");
                    if (disableAS is int das && das == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender disabled via policy: DisableAntiSpyware=1",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{policyKey}",
                            FileName = "registry",
                            Reason   = "Windows Defender AntiSpyware is fully disabled by Group Policy " +
                                       "(DisableAntiSpyware=1). This setting completely turns off " +
                                       "Defender and is a prerequisite step used by cheat loaders " +
                                       "before injecting DLLs to prevent detection.",
                            Detail   = "DisableAntiSpyware = 1"
                        });
                    }
                }
            }
            catch { }

            if (ct.IsCancellationRequested) return;

            try
            {
                const string rtpKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
                using var key = Registry.LocalMachine.OpenSubKey(rtpKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var disableRtm = key.GetValue("DisableRealtimeMonitoring");
                    if (disableRtm is int drm && drm == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender real-time monitoring disabled (non-policy key)",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{rtpKey}",
                            FileName = "registry",
                            Reason   = "Windows Defender real-time monitoring is disabled directly " +
                                       "in the Defender configuration key (DisableRealtimeMonitoring=1). " +
                                       "This is a strong indicator of tampering: cheat tools disable " +
                                       "real-time protection to avoid having their DLLs flagged during injection.",
                            Detail   = "DisableRealtimeMonitoring = 1"
                        });
                    }
                }
            }
            catch { }

            if (ct.IsCancellationRequested) return;

            try
            {
                const string policyRtpKey =
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
                using var key = Registry.LocalMachine.OpenSubKey(policyRtpKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var disableRtm = key.GetValue("DisableRealtimeMonitoring");
                    if (disableRtm is int drm && drm == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender real-time monitoring disabled by policy",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{policyRtpKey}",
                            FileName = "registry",
                            Reason   = "Windows Defender real-time monitoring is disabled via Group " +
                                       "Policy (DisableRealtimeMonitoring=1 under Policies key). " +
                                       "Policy-based disabling persists across reboots and cannot be " +
                                       "re-enabled from the UI, making it a preferred tamper technique.",
                            Detail   = "DisableRealtimeMonitoring = 1"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckDefenderExclusionArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            try
            {
                const string pathKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths";
                using var key = Registry.LocalMachine.OpenSubKey(pathKey, writable: false);
                if (key is not null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) break;
                        ctx.IncrementRegistryKeys();
                        var lower = valueName.ToLowerInvariant();
                        bool suspicious = SuspiciousPathFragments.Any(f =>
                            lower.Contains(f, StringComparison.OrdinalIgnoreCase));
                        if (!suspicious) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Defender path exclusion covers suspicious location: {Path.GetFileName(valueName)}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{pathKey}",
                            FileName = valueName,
                            Reason   = "A Windows Defender path exclusion covers a user-writable or " +
                                       "cheat-named directory. Cheat loaders add AV path exclusions " +
                                       "before placing injector DLLs on disk so Defender does not flag " +
                                       "the files at rest or during injection.",
                            Detail   = $@"Excluded path: {valueName} | Key: HKLM\{pathKey}"
                        });
                    }
                }
            }
            catch { }

            if (ct.IsCancellationRequested) return;

            try
            {
                const string procKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes";
                using var key = Registry.LocalMachine.OpenSubKey(procKey, writable: false);
                if (key is not null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) break;
                        ctx.IncrementRegistryKeys();
                        var lower = valueName.ToLowerInvariant();
                        bool matchesCheat = KnownCheatProcessNames.Any(p =>
                            lower.Contains(p, StringComparison.OrdinalIgnoreCase));
                        bool genericSuspicious = lower.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                            lower.Contains("loader", StringComparison.OrdinalIgnoreCase) ||
                            lower.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            lower.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            lower.Contains("hack", StringComparison.OrdinalIgnoreCase);
                        if (!matchesCheat && !genericSuspicious) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Defender process exclusion for cheat-related process: {valueName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{procKey}",
                            FileName = valueName,
                            Reason   = "A Windows Defender process exclusion exists for a process name " +
                                       "matching known cheat tool nomenclature. This exclusion means " +
                                       "Defender will not scan or monitor that process, allowing it " +
                                       "to inject into games undetected.",
                            Detail   = $@"Excluded process: {valueName} | Key: HKLM\{procKey}"
                        });
                    }
                }
            }
            catch { }

            if (ct.IsCancellationRequested) return;

            try
            {
                const string extKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions";
                using var key = Registry.LocalMachine.OpenSubKey(extKey, writable: false);
                if (key is not null)
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) break;
                        ctx.IncrementRegistryKeys();
                        var lower = valueName.TrimStart('.').ToLowerInvariant();
                        bool suspicious = lower == "dll" || lower == "sys" || lower == "exe";
                        if (!suspicious) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Defender file extension exclusion for executable type: .{lower}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{extKey}",
                            FileName = valueName,
                            Reason   = $"A Defender exclusion for the .{lower} file extension is present. " +
                                       "Excluding executable file types (.exe, .dll, .sys) from scanning " +
                                       "is extremely suspicious: it means all files of that type are " +
                                       "ignored by Defender, which is how cheat DLLs are hidden from AV.",
                            Detail   = $@"Excluded extension: {valueName} | Key: HKLM\{extKey}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckDefenderCloudProtectionDisabled(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            try
            {
                const string spynetKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Spynet";
                using var key = Registry.LocalMachine.OpenSubKey(spynetKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var reporting = key.GetValue("SpyNetReporting");
                    if (reporting is int r && r == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender cloud protection reporting disabled (SpyNetReporting=0)",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{spynetKey}",
                            FileName = "registry",
                            Reason   = "Windows Defender cloud-based protection (MAPS/SpyNet) reporting " +
                                       "is disabled (SpyNetReporting=0). Cloud protection is Defender's " +
                                       "primary mechanism for detecting novel cheat tools and zero-day " +
                                       "threats. Disabling it allows new and unknown cheat binaries to run.",
                            Detail   = "SpyNetReporting = 0"
                        });
                    }

                    var consent = key.GetValue("SubmitSamplesConsent");
                    if (consent is int sc && sc == 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender sample submission set to never send (SubmitSamplesConsent=2)",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{spynetKey}",
                            FileName = "registry",
                            Reason   = "Defender sample submission is configured to never send samples " +
                                       "(SubmitSamplesConsent=2). This prevents novel cheat executables " +
                                       "from being uploaded to Microsoft for cloud analysis and signature " +
                                       "creation.",
                            Detail   = "SubmitSamplesConsent = 2 (Never send)"
                        });
                    }
                }
            }
            catch { }

            if (ct.IsCancellationRequested) return;

            try
            {
                const string policySpynetKey =
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet";
                using var key = Registry.LocalMachine.OpenSubKey(policySpynetKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var reporting = key.GetValue("SpyNetReporting");
                    if (reporting is int r && r == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender cloud protection disabled by policy (SpyNetReporting=0)",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{policySpynetKey}",
                            FileName = "registry",
                            Reason   = "Windows Defender cloud reporting is disabled via Group Policy " +
                                       "(SpyNetReporting=0 under Policies). Policy-based cloud protection " +
                                       "disablement is persistent and allows all cheat tool uploads to " +
                                       "be suppressed, preventing Microsoft from generating new signatures.",
                            Detail   = "SpyNetReporting = 0 (policy)"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckDefenderSignatureUpdateDisabled(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            try
            {
                const string sigKey =
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates";
                using var key = Registry.LocalMachine.OpenSubKey(sigKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();

                    var disableStartup = key.GetValue("DisableUpdateOnStartupWithoutEngine");
                    if (disableStartup is int dus && dus == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender startup signature update disabled by policy",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{sigKey}",
                            FileName = "registry",
                            Reason   = "Defender is prohibited from updating signatures at startup " +
                                       "when the engine is absent (DisableUpdateOnStartupWithoutEngine=1). " +
                                       "This keeps signatures stale intentionally, allowing cheat tools " +
                                       "with signatures newer than the installed definitions to run " +
                                       "undetected.",
                            Detail   = "DisableUpdateOnStartupWithoutEngine = 1"
                        });
                    }

                    var fallbackOrder = key.GetValue("FallbackOrder");
                    if (fallbackOrder is string fo &&
                        !string.IsNullOrWhiteSpace(fo))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender signature update fallback order altered by policy",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{sigKey}",
                            FileName = "registry",
                            Reason   = "The Defender signature update FallbackOrder is configured " +
                                       "via policy. Altering the update order can direct Defender to " +
                                       "use stale or attacker-controlled update sources, keeping " +
                                       "definitions outdated and cheat tool signatures unknown.",
                            Detail   = $"FallbackOrder = {fo}"
                        });
                    }
                }
            }
            catch { }

            if (ct.IsCancellationRequested) return;

            try
            {
                const string sigUpdateKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Signature Updates";
                using var key = Registry.LocalMachine.OpenSubKey(sigUpdateKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var prevSig = key.GetValue("PreviousSignatureVersion");
                    var sigAge = key.GetValue("SignatureUpdateLastAttemptTime");
                    var ageOn = key.GetValue("AVSignatureApplied");

                    if (ageOn is byte[] bytes && bytes.Length >= 8)
                    {
                        long ft = BitConverter.ToInt64(bytes, 0);
                        if (ft > 0)
                        {
                            var sigDate = DateTime.FromFileTimeUtc(ft);
                            var daysBehind = (DateTime.UtcNow - sigDate).TotalDays;
                            if (daysBehind > 7)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Defender signatures outdated by {daysBehind:F0} days",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKLM\{sigUpdateKey}",
                                    FileName = "registry",
                                    Reason   = $"Windows Defender signature definitions are {daysBehind:F0} days old " +
                                               $"(last applied: {sigDate:yyyy-MM-dd}). Signatures more than 7 days " +
                                               "outdated indicate either deliberate prevention of updates or " +
                                               "disabled update services, allowing newly released cheat tools " +
                                               "to run without detection.",
                                    Detail   = $"AVSignatureApplied timestamp: {sigDate:yyyy-MM-dd HH:mm} UTC | " +
                                               $"Days behind: {daysBehind:F0}"
                                });
                            }
                        }
                    }

                    if (prevSig is string ps && !string.IsNullOrWhiteSpace(ps))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender previous signature version recorded",
                            Risk     = RiskLevel.Low,
                            Location = $@"HKLM\{sigUpdateKey}",
                            FileName = "registry",
                            Reason   = "Defender recorded a previous signature version, which is " +
                                       "normal after an update. Recorded for correlation with update " +
                                       "disable checks.",
                            Detail   = $"PreviousSignatureVersion = {ps}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckDefenderTamperProtectionDisabled(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            try
            {
                const string featuresKey =
                    @"SOFTWARE\Microsoft\Windows Defender\Features";
                using var key = Registry.LocalMachine.OpenSubKey(featuresKey, writable: false);
                if (key is null) return;

                ctx.IncrementRegistryKeys();

                var tp = key.GetValue("TamperProtection");
                if (tp is int tpVal)
                {
                    bool disabled = tpVal == 0 || tpVal == 1;
                    bool policyDisabled = tpVal == 5;

                    if (disabled)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Defender Tamper Protection disabled (TamperProtection={tpVal})",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{featuresKey}",
                            FileName = "registry",
                            Reason   = $"Windows Defender Tamper Protection is disabled " +
                                       $"(TamperProtection={tpVal}). Tamper Protection prevents " +
                                       "unauthorized changes to Defender settings. When disabled, " +
                                       "cheat loaders and bypass tools can freely modify exclusions, " +
                                       "disable real-time protection, and stop services without " +
                                       "triggering alerts.",
                            Detail   = $"TamperProtection = {tpVal} (0 or 1 = disabled)"
                        });
                    }
                    else if (policyDisabled)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Defender Tamper Protection overridden by policy (value=5)",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{featuresKey}",
                            FileName = "registry",
                            Reason   = "Defender Tamper Protection is in policy-controlled state " +
                                       "(TamperProtection=5). When controlled by policy, Tamper " +
                                       "Protection can be silently disabled via GPO without user " +
                                       "consent, which cheat infrastructure exploits to weaken " +
                                       "Defender remotely.",
                            Detail   = "TamperProtection = 5 (policy override active)"
                        });
                    }
                }

                var tpSource = key.GetValue("TamperProtectionSource");
                if (tpSource is int src && src != 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Defender TamperProtectionSource has unusual value ({src})",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{featuresKey}",
                        FileName = "registry",
                        Reason   = $"The TamperProtectionSource value is {src}, which is non-zero. " +
                                   "A non-default source value indicates Tamper Protection state " +
                                   "was modified by an external source such as an MDM policy or " +
                                   "a bypass tool that injected a policy override.",
                        Detail   = $"TamperProtectionSource = {src}"
                    });
                }
            }
            catch { }
        }, ct);

    private Task CheckDefenderEventLogTamper(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            string evtxPath = Path.Combine(
                WinDir,
                @"System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx");

            if (!File.Exists(evtxPath))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Defender Operational event log file missing",
                    Risk     = RiskLevel.Critical,
                    Location = evtxPath,
                    FileName = Path.GetFileName(evtxPath),
                    Reason   = "The Windows Defender Operational event log (EVTX) file is absent. " +
                               "This file records all Defender protection state changes including " +
                               "real-time protection disable events (ID 5001), scan disable events " +
                               "(ID 5010/5012), and malware detections (ID 1116/1117). Its absence " +
                               "indicates deliberate log deletion to erase cheat detection evidence.",
                    Detail   = $"Expected: {evtxPath}"
                });
                return;
            }

            ctx.IncrementFiles();

            try
            {
                var fi = new FileInfo(evtxPath);
                if (fi.Length < 69632)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Defender Operational EVTX suspiciously small",
                        Risk     = RiskLevel.High,
                        Location = evtxPath,
                        FileName = Path.GetFileName(evtxPath),
                        Reason   = $"The Defender Operational EVTX file is only {fi.Length / 1024} KB. " +
                                   "A small log on an active system suggests the log was cleared to " +
                                   "remove Event ID 5001 (real-time protection disabled), 1116 " +
                                   "(malware detected), or 1117 (action taken on malware) records.",
                        Detail   = $"File size: {fi.Length} bytes | Path: {evtxPath}"
                    });
                }
            }
            catch (IOException) { }

            try
            {
                string content;
                using var fs = new FileStream(evtxPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, Encoding.Latin1);
                content = await sr.ReadToEndAsync(ct);

                bool hasDisableEvent = content.Contains("5001", StringComparison.OrdinalIgnoreCase) &&
                    content.Contains("disabled", StringComparison.OrdinalIgnoreCase);
                bool hasScanDisable = content.Contains("5010", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("5012", StringComparison.OrdinalIgnoreCase);
                bool hasMalwareDetect = content.Contains("1116", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("1117", StringComparison.OrdinalIgnoreCase);

                var cheatHits = CheatToolDetectionKeywords
                    .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (hasDisableEvent || hasScanDisable)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Defender EVTX contains real-time protection disabled events",
                        Risk     = RiskLevel.Critical,
                        Location = evtxPath,
                        FileName = Path.GetFileName(evtxPath),
                        Reason   = "The Defender Operational log contains evidence of Event ID 5001 " +
                                   "(real-time protection disabled) or 5010/5012 (scanning disabled). " +
                                   "These events are written when cheat loaders turn off protection " +
                                   "before injecting. Their presence in the log is forensic evidence " +
                                   "of Defender tampering.",
                        Detail   = $"DisableEvent: {hasDisableEvent} | ScanDisable: {hasScanDisable}"
                    });
                }

                if (cheatHits.Count > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Defender EVTX contains cheat tool detection records",
                        Risk     = RiskLevel.High,
                        Location = evtxPath,
                        FileName = Path.GetFileName(evtxPath),
                        Reason   = "The Defender Operational log (Event IDs 1116/1117) contains " +
                                   "references to known cheat tool keywords, indicating Defender " +
                                   "detected and acted on cheat software. These detections are " +
                                   "forensic evidence of prior cheat tool presence on this system.",
                        Detail   = $"Cheat keywords in log: {string.Join(", ", cheatHits.Take(10))}"
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckDefenderQuarantineRecords(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            string quarantineDir = Path.Combine(
                ProgramData, @"Microsoft\Windows Defender\Quarantine");

            if (!Directory.Exists(quarantineDir)) return;

            string entriesDir = Path.Combine(quarantineDir, "Entries");
            string[] quarantineFiles;

            try
            {
                quarantineFiles = Directory.GetFiles(quarantineDir, "*",
                    SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { return; }

            ctx.IncrementFiles((long)quarantineFiles.Length);

            foreach (var qFile in quarantineFiles.Take(30))
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    string content;
                    using var fs = new FileStream(qFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);

                    var cheatHits = CheatToolDetectionKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (cheatHits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Cheat tool artifact found in Defender quarantine",
                            Risk     = RiskLevel.High,
                            Location = quarantineDir,
                            FileName = Path.GetFileName(qFile),
                            Reason   = "A Windows Defender quarantine record contains cheat tool " +
                                       "keywords. This confirms Defender previously detected and " +
                                       "quarantined a cheat tool or associated file on this system. " +
                                       "The file may have been restored or deleted after quarantine " +
                                       "to resume cheat usage.",
                            Detail   = $"File: {qFile} | Cheat keywords: {string.Join(", ", cheatHits.Take(8))}"
                        });
                    }
                }
                catch (IOException) { }
            }

            if (Directory.Exists(entriesDir))
            {
                string[] entryFiles;
                try { entryFiles = Directory.GetFiles(entriesDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { return; }

                ctx.IncrementFiles((long)entryFiles.Length);

                foreach (var entry in entryFiles.Take(20))
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        string content;
                        using var fs = new FileStream(entry, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        content = await sr.ReadToEndAsync(ct);

                        var hits = CheatToolDetectionKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (hits.Count > 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Cheat tool metadata in Defender quarantine Entries",
                                Risk     = RiskLevel.High,
                                Location = entriesDir,
                                FileName = Path.GetFileName(entry),
                                Reason   = "A Defender quarantine Entries metadata file contains " +
                                           "cheat tool keywords. The Entries subfolder stores original " +
                                           "file path and threat information for quarantined items, " +
                                           "confirming a cheat tool was detected and quarantined.",
                                Detail   = $"Entry: {entry} | Keywords: {string.Join(", ", hits.Take(5))}"
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
        }, ct);

    private Task CheckDefenderProtectionHistoryRecords(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            string historyDir = Path.Combine(
                ProgramData,
                @"Microsoft\Windows Defender\Scans\History\Service\DetectionHistory");

            if (!Directory.Exists(historyDir)) return;

            string[] historyFiles;
            try
            {
                historyFiles = Directory.GetFiles(historyDir, "*",
                    SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { return; }

            ctx.IncrementFiles((long)historyFiles.Length);

            foreach (var file in historyFiles)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    string content;
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);

                    var hits = CheatToolDetectionKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count == 0) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Cheat tool detection record in Defender protection history",
                        Risk     = RiskLevel.High,
                        Location = historyDir,
                        FileName = Path.GetFileName(file),
                        Reason   = "A Windows Defender protection history binary record contains " +
                                   "cheat tool keywords. These binary files in DetectionHistory store " +
                                   "details of every threat Defender has processed. Their presence " +
                                   "confirms Defender detected cheat software; the user may have " +
                                   "restored or removed the quarantine to continue using the cheat.",
                        Detail   = $"File: {file} | Keywords: {string.Join(", ", hits.Take(8))}"
                    });
                }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckDefenderScanLogsForCheats(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            var logPaths = new[]
            {
                Path.Combine(WinDir, @"Temp\MpCmdRun.log"),
                Path.Combine(ProgramData, @"Microsoft\Windows Defender\Logs\mplog.log"),
                Path.Combine(ProgramData, @"Microsoft\Windows Defender\Support\MPLog-01.log")
            };

            foreach (var logPath in logPaths)
            {
                if (ct.IsCancellationRequested) break;
                if (!File.Exists(logPath)) continue;

                ctx.IncrementFiles();

                try
                {
                    string content;
                    using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);

                    var hits = CheatToolDetectionKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat tool keywords in Defender scan log: {Path.GetFileName(logPath)}",
                            Risk     = RiskLevel.High,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason   = $"The Defender scan log file contains {hits.Count} cheat-related " +
                                       "keyword(s). Scan logs record detection events, file scan results, " +
                                       "and engine activity. Cheat tool names in these logs indicate " +
                                       "Defender previously encountered and processed a cheat file.",
                            Detail   = $"Log: {logPath} | Keywords: {string.Join(", ", hits.Take(8))}"
                        });
                    }
                }
                catch (IOException) { }
            }

            string cacheManagerDir = Path.Combine(
                ProgramData,
                @"Microsoft\Windows Defender\Scans\History\CacheManager");

            if (!Directory.Exists(cacheManagerDir)) return;

            string[] cacheFiles;
            try
            {
                cacheFiles = Directory.GetFiles(cacheManagerDir, "*",
                    SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { return; }

            ctx.IncrementFiles((long)cacheFiles.Length);

            foreach (var cacheFile in cacheFiles.Take(10))
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    string content;
                    using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);

                    var hits = CheatToolDetectionKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Cheat detection reference in Defender CacheManager",
                            Risk     = RiskLevel.High,
                            Location = cacheManagerDir,
                            FileName = Path.GetFileName(cacheFile),
                            Reason   = "A Defender CacheManager file references cheat tool keywords. " +
                                       "The CacheManager stores scan result records for files " +
                                       "previously processed by the Defender engine, and cheat " +
                                       "tool names here confirm prior detection activity.",
                            Detail   = $"File: {cacheFile} | Keywords: {string.Join(", ", hits.Take(5))}"
                        });
                    }
                }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckAMSIBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            try
            {
                const string amsiRegKey =
                    @"Software\Microsoft\Windows Script\Settings";
                using var key = Registry.CurrentUser.OpenSubKey(amsiRegKey, writable: false);
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var amsiEnable = key.GetValue("AmsiEnable");
                    if (amsiEnable is int ae && ae == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "AMSI disabled for Windows Script host (AmsiEnable=0)",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKCU\{amsiRegKey}",
                            FileName = "registry",
                            Reason   = "AMSI (Antimalware Scan Interface) is disabled for the Windows " +
                                       "Script host via registry (AmsiEnable=0). AMSI is the bridge " +
                                       "between scripting runtimes and security products. Disabling it " +
                                       "allows PowerShell and script-based cheat loaders to execute " +
                                       "malicious code without AV interception.",
                            Detail   = $@"HKCU\{amsiRegKey}\AmsiEnable = 0"
                        });
                    }
                }
            }
            catch { }

            if (ct.IsCancellationRequested) return;

            string psHistoryPath = Path.Combine(
                AppData,
                @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

            if (!File.Exists(psHistoryPath)) return;

            ctx.IncrementFiles();

            try
            {
                string content;
                using var fs = new FileStream(psHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);

                var hits = AMSIBypassStrings
                    .Where(a => content.Contains(a, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (hits.Count > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "AMSI bypass commands found in PowerShell history",
                        Risk     = RiskLevel.Critical,
                        Location = psHistoryPath,
                        FileName = "ConsoleHost_history.txt",
                        Reason   = "PowerShell history contains AMSI bypass technique strings " +
                                   $"({string.Join(", ", hits.Take(4))}). These are hallmarks of " +
                                   "cheat loaders and script-based injection tools that patch AMSI " +
                                   "in memory to prevent PowerShell scripts from being scanned by " +
                                   "Defender during execution.",
                        Detail   = $"AMSI bypass indicators: {string.Join(", ", hits)} | " +
                                   $"History file: {psHistoryPath}"
                    });
                }
            }
            catch (IOException) { }
        }, ct);

    private Task CheckDefenderPolicyTamper(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            string[] disableValueNames =
            {
                "DisableAntiSpyware", "DisableAntiVirus",
                "DisableRoutinelyTakingAction", "DisableBehaviorMonitoring",
                "DisableOnAccessProtection", "DisableScriptScanning",
                "DisableIOAVProtection", "DisableBlockAtFirstSeen",
                "PUAProtection"
            };

            foreach (var policyKeyPath in DefenderPolicyKeys)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(policyKeyPath, writable: false);
                    if (key is null) continue;

                    var valueNames = key.GetValueNames();
                    ctx.IncrementRegistryKeys((long)valueNames.Length);

                    foreach (var valueName in valueNames)
                    {
                        if (ct.IsCancellationRequested) break;

                        bool isDisableKey = disableValueNames.Any(d =>
                            valueName.Equals(d, StringComparison.OrdinalIgnoreCase));
                        if (!isDisableKey) continue;

                        var val = key.GetValue(valueName);
                        if (val is int intVal && intVal == 1)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Defender GPO policy tamper: {valueName}=1",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{policyKeyPath}",
                                FileName = "registry",
                                Reason   = $"Group Policy key '{valueName}' is set to 1 under the " +
                                           "Windows Defender policy hive. Policy-based disabling of " +
                                           "Defender features is a preferred technique by cheat " +
                                           "infrastructure operators as it cannot be undone from the " +
                                           "Defender UI and survives reboots.",
                                Detail   = $@"HKLM\{policyKeyPath}\{valueName} = 1"
                            });
                        }
                    }

                    string policyManagerPath = Path.Combine(policyKeyPath, "Policy Manager");
                    try
                    {
                        using var pmKey = Registry.LocalMachine.OpenSubKey(
                            policyManagerPath, writable: false);
                        if (pmKey is not null)
                        {
                            ctx.IncrementRegistryKeys();
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Defender Policy Manager subkey exists",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{policyManagerPath}",
                                FileName = "registry",
                                Reason   = "The Windows Defender Policy Manager registry subkey " +
                                           "exists. This key is used by MDM or GPO management to " +
                                           "configure Defender and its presence may indicate an " +
                                           "externally managed policy override was applied to weaken " +
                                           "Defender protection.",
                                Detail   = $@"Key: HKLM\{policyManagerPath}"
                            });
                        }
                    }
                    catch { }
                }
                catch { }
            }
        }, ct);

    private Task CheckSecurityCenterStatusArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            var secCenterChecks = new[]
            {
                ("AntiVirusDisableNotify",  "AV disable notifications suppressed"),
                ("FirewallDisableNotify",   "Firewall disable notifications suppressed"),
                ("AntiVirusOverride",       "AV status override active"),
                ("FirewallOverride",        "Firewall status override active")
            };

            const string secCenterKey = @"SOFTWARE\Microsoft\Security Center";

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(secCenterKey, writable: false);
                if (key is null) return;

                ctx.IncrementRegistryKeys();

                foreach (var (valueName, description) in secCenterChecks)
                {
                    if (ct.IsCancellationRequested) break;

                    var val = key.GetValue(valueName);
                    if (val is int intVal && intVal == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Security Center tamper: {valueName}=1",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{secCenterKey}",
                            FileName = "registry",
                            Reason   = $"Windows Security Center has '{valueName}' set to 1 " +
                                       $"({description}). Override and notification-disable values " +
                                       "in the Security Center key are used by cheat bypass tools to " +
                                       "suppress Windows security warnings after disabling Defender, " +
                                       "preventing the taskbar from alerting the user that protection " +
                                       "is off.",
                            Detail   = $@"HKLM\{secCenterKey}\{valueName} = 1"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckDefenderServiceManipulation(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            var serviceChecks = new[]
            {
                ("WinDefend",  "Windows Defender Antivirus Service",        true),
                ("Sense",      "Microsoft Defender ATP (EDR) Service",      false),
                ("WdNisSvc",   "Windows Defender Network Inspection",       true),
                ("WdBoot",     "Windows Defender Boot Driver",              true),
                ("WdFilter",   "Windows Defender Minifilter Driver",        true)
            };

            foreach (var (svcName, svcDisplay, isCritical) in serviceChecks)
            {
                if (ct.IsCancellationRequested) break;

                string serviceRegKey = Path.Combine(
                    @"SYSTEM\CurrentControlSet\Services", svcName);

                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(serviceRegKey, writable: false);
                    if (key is null) continue;

                    ctx.IncrementRegistryKeys();

                    var startVal = key.GetValue("Start");
                    if (startVal is int start)
                    {
                        bool isDisabled = start == 4;
                        bool isManual   = start == 3;

                        if (isDisabled && isCritical)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Core Defender service disabled: {svcName} (Start=4)",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{serviceRegKey}",
                                FileName = "registry",
                                Reason   = $"The {svcDisplay} ({svcName}) is disabled (Start=4) in " +
                                           "the service registry. Disabling core Defender services " +
                                           "prevents the antimalware engine from loading at boot, " +
                                           "meaning cheat tools can run at system startup before any " +
                                           "Defender protection is active.",
                                Detail   = $@"HKLM\{serviceRegKey}\Start = 4 (Disabled)"
                            });
                        }
                        else if (isManual && isCritical)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Core Defender service set to manual: {svcName} (Start=3)",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{serviceRegKey}",
                                FileName = "registry",
                                Reason   = $"The {svcDisplay} ({svcName}) is set to manual startup " +
                                           "(Start=3). A core Defender service on manual will not start " +
                                           "automatically, leaving the system unprotected until the " +
                                           "service is manually started, which cheat users exploit by " +
                                           "never starting it.",
                                Detail   = $@"HKLM\{serviceRegKey}\Start = 3 (Manual)"
                            });
                        }
                        else if (isDisabled && !isCritical)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Defender-related service disabled: {svcName} (Start=4)",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{serviceRegKey}",
                                FileName = "registry",
                                Reason   = $"The {svcDisplay} ({svcName}) is disabled (Start=4). " +
                                           "While not the primary AV service, its disablement reduces " +
                                           "the overall Defender protection stack.",
                                Detail   = $@"HKLM\{serviceRegKey}\Start = 4 (Disabled)"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckDefenderASEPManipulation(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            string[] ifeoTargets = { "MsMpEng.exe", "MpCmdRun.exe", "msmpeng.exe" };
            const string ifeoBase =
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

            foreach (var target in ifeoTargets)
            {
                if (ct.IsCancellationRequested) break;

                string ifeoKey = Path.Combine(ifeoBase, target);

                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(ifeoKey, writable: false);
                    if (key is null) continue;

                    ctx.IncrementRegistryKeys();

                    var debugger = key.GetValue("Debugger");
                    if (debugger is string dbg && !string.IsNullOrWhiteSpace(dbg))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Defender process hijacked via IFEO Debugger: {target}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{ifeoKey}",
                            FileName = "registry",
                            Reason   = $"An Image File Execution Options Debugger value is set for " +
                                       $"{target} pointing to '{dbg}'. This causes Windows to launch " +
                                       "the specified Debugger executable instead of the Defender " +
                                       "process whenever it is invoked. This is a classic technique " +
                                       "to permanently disable Defender by redirecting it to a null " +
                                       "or benign executable.",
                            Detail   = $@"HKLM\{ifeoKey}\Debugger = {dbg}"
                        });
                    }

                    var globalFlag = key.GetValue("GlobalFlag");
                    if (globalFlag is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Defender IFEO GlobalFlag set: {target}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{ifeoKey}",
                            FileName = "registry",
                            Reason   = $"An Image File Execution Options GlobalFlag value exists for " +
                                       $"{target}. GlobalFlag in IFEO can be used to alter process " +
                                       "behavior in ways that destabilize or subvert Defender execution.",
                            Detail   = $@"HKLM\{ifeoKey}\GlobalFlag = {globalFlag}"
                        });
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckDefenderDatabaseTamper(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            string definitionUpdatesDir = Path.Combine(
                ProgramData, @"Microsoft\Windows Defender\Definition Updates");

            if (!Directory.Exists(definitionUpdatesDir))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Defender Definition Updates directory missing",
                    Risk     = RiskLevel.High,
                    Location = definitionUpdatesDir,
                    FileName = null,
                    Reason   = "The Windows Defender Definition Updates directory does not exist. " +
                               "This directory stores the signature database files required for " +
                               "Defender to detect threats. Its absence suggests the signature " +
                               "database was deliberately deleted to prevent cheat tool detection.",
                    Detail   = $"Expected: {definitionUpdatesDir}"
                });
                return;
            }

            string[] defFiles;
            try
            {
                defFiles = Directory.GetFiles(definitionUpdatesDir, "*",
                    SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { return; }

            ctx.IncrementFiles((long)defFiles.Length);

            if (defFiles.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Defender Definition Updates directory is empty",
                    Risk     = RiskLevel.High,
                    Location = definitionUpdatesDir,
                    FileName = null,
                    Reason   = "The Defender Definition Updates directory exists but contains no " +
                               "files. The absence of signature database files means Defender " +
                               "cannot detect any threats. This is consistent with deliberate " +
                               "deletion of signature files to allow cheat tools to run undetected.",
                    Detail   = $"Directory: {definitionUpdatesDir}"
                });
                return;
            }

            int tinyFiles = 0;
            var tinyFileNames = new List<string>();

            foreach (var defFile in defFiles)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var fi = new FileInfo(defFile);
                    if (fi.Length == 0 || (fi.Extension.Equals(".vdm", StringComparison.OrdinalIgnoreCase) &&
                        fi.Length < 1024))
                    {
                        tinyFiles++;
                        tinyFileNames.Add(Path.GetFileName(defFile));
                    }
                }
                catch (IOException) { }
            }

            if (tinyFiles > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Defender signature database files corrupted or empty ({tinyFiles} files)",
                    Risk     = RiskLevel.High,
                    Location = definitionUpdatesDir,
                    FileName = tinyFileNames.FirstOrDefault(),
                    Reason   = $"{tinyFiles} Defender signature database file(s) are zero-byte or " +
                               "abnormally small. Legitimate Defender VDM signature files are several " +
                               "megabytes. Zero-size or corrupt files indicate tampering: cheat tools " +
                               "sometimes truncate signature files to prevent Defender from loading " +
                               "detection logic for specific threat categories.",
                    Detail   = $"Affected files: {string.Join(", ", tinyFileNames.Take(5))}"
                });
            }
        }, ct);

    private Task CheckWindowsFirewallDefenderBlock(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            const string firewallRulesKey =
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

            string[] defenderExecutables =
            {
                "MsMpEng.exe", "MpCmdRun.exe", "MPCMDRUN.EXE",
                "NisSrv.exe", "MsMpLce.exe"
            };

            string[] defenderUpdateDomains =
            {
                "go.microsoft.com", "definitionupdates.microsoft.com",
                "wdcp.microsoft.com", "wdcpalt.microsoft.com"
            };

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(firewallRulesKey, writable: false);
                if (key is null) return;

                var valueNames = key.GetValueNames();
                ctx.IncrementRegistryKeys((long)valueNames.Length);

                foreach (var valueName in valueNames)
                {
                    if (ct.IsCancellationRequested) break;

                    var val = key.GetValue(valueName);
                    if (val is not string ruleStr) continue;

                    var ruleLower = ruleStr.ToLowerInvariant();

                    bool blocksDefenderExe = defenderExecutables.Any(exe =>
                        ruleLower.Contains(exe, StringComparison.OrdinalIgnoreCase));

                    bool blocksUpdateDomain = defenderUpdateDomains.Any(domain =>
                        ruleLower.Contains(domain, StringComparison.OrdinalIgnoreCase));

                    bool isBlockRule = ruleLower.Contains("action=block",
                        StringComparison.OrdinalIgnoreCase);

                    if (!isBlockRule) continue;

                    if (blocksDefenderExe)
                    {
                        string matchedExe = defenderExecutables.First(exe =>
                            ruleLower.Contains(exe, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Firewall rule blocks Defender executable: {matchedExe}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{firewallRulesKey}",
                            FileName = valueName,
                            Reason   = $"A Windows Firewall rule blocks the Defender executable " +
                                       $"'{matchedExe}'. Blocking Defender processes at the firewall " +
                                       "level prevents signature updates and cloud lookups, keeping " +
                                       "Defender blind to new cheat tool signatures from Microsoft.",
                            Detail   = $"Rule name: {valueName} | Blocked: {matchedExe}"
                        });
                    }
                    else if (blocksUpdateDomain)
                    {
                        string matchedDomain = defenderUpdateDomains.First(d =>
                            ruleLower.Contains(d, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Firewall rule blocks Defender update domain: {matchedDomain}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{firewallRulesKey}",
                            FileName = valueName,
                            Reason   = $"A Windows Firewall rule blocks the Defender update domain " +
                                       $"'{matchedDomain}'. Blocking update endpoints prevents Defender " +
                                       "from downloading new cheat tool signatures, allowing recently " +
                                       "released cheats to run without detection.",
                            Detail   = $"Rule name: {valueName} | Blocked domain: {matchedDomain}"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckDefenderExclusionByProcess(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            if (ct.IsCancellationRequested) return;

            const string procExclusionKey =
                @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes";

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(procExclusionKey, writable: false);
                if (key is null) return;

                var valueNames = key.GetValueNames();
                ctx.IncrementRegistryKeys((long)valueNames.Length);

                foreach (var valueName in valueNames)
                {
                    if (ct.IsCancellationRequested) break;

                    bool exactMatch = KnownCheatProcessNames.Any(p =>
                        valueName.Equals(p, StringComparison.OrdinalIgnoreCase));

                    bool substringMatch = KnownCheatProcessNames.Any(p =>
                        valueName.Contains(Path.GetFileNameWithoutExtension(p),
                            StringComparison.OrdinalIgnoreCase));

                    if (!exactMatch && !substringMatch) continue;

                    string matchedCheat = KnownCheatProcessNames.FirstOrDefault(p =>
                        valueName.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                        valueName.Contains(Path.GetFileNameWithoutExtension(p),
                            StringComparison.OrdinalIgnoreCase)) ?? valueName;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Known cheat process in Defender exclusion list: {valueName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{procExclusionKey}",
                        FileName = valueName,
                        Reason   = $"The known cheat tool process '{matchedCheat}' is present in " +
                                   "the Windows Defender process exclusion list. This means Defender " +
                                   "will never scan or monitor this process, allowing it to inject " +
                                   "into games, read game memory, and perform all cheat actions " +
                                   "without any AV interference.",
                        Detail   = $@"HKLM\{procExclusionKey}\{valueName} | Matched: {matchedCheat}"
                    });
                }
            }
            catch { }
        }, ct);

    private Task CheckThreatServiceDisabledHistory(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (ct.IsCancellationRequested) return;

            string systemEvtx = Path.Combine(
                WinDir, @"System32\winevt\Logs\System.evtx");

            if (File.Exists(systemEvtx))
            {
                ctx.IncrementFiles();
                try
                {
                    string content;
                    using var fs = new FileStream(systemEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);

                    bool defenderStopped =
                        content.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase) &&
                        (content.Contains("stopped", StringComparison.OrdinalIgnoreCase) ||
                         content.Contains("7036", StringComparison.OrdinalIgnoreCase));

                    bool winDefendStopped =
                        content.Contains("WinDefend", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("stopped", StringComparison.OrdinalIgnoreCase);

                    if (defenderStopped || winDefendStopped)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "System event log records Windows Defender service stop",
                            Risk     = RiskLevel.Critical,
                            Location = systemEvtx,
                            FileName = Path.GetFileName(systemEvtx),
                            Reason   = "The Windows System event log contains evidence that the " +
                                       "Windows Defender service (WinDefend) entered a stopped state " +
                                       "(Event ID 7036 - Service Control Manager state change). " +
                                       "Cheat loaders and bypass tools stop the Defender service " +
                                       "before injecting to ensure no real-time scanning occurs " +
                                       "during the injection window.",
                            Detail   = $"System EVTX: {systemEvtx} | " +
                                       $"DefenderStopped: {defenderStopped} | WinDefendStopped: {winDefendStopped}"
                        });
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            if (ct.IsCancellationRequested) return;

            string securityEvtx = Path.Combine(
                WinDir, @"System32\winevt\Logs\Security.evtx");

            if (!File.Exists(securityEvtx)) return;

            ctx.IncrementFiles();

            try
            {
                string content;
                using var fs = new FileStream(securityEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, Encoding.Latin1);
                content = await sr.ReadToEndAsync(ct);

                bool msMpEngTerminated =
                    content.Contains("MsMpEng.exe", StringComparison.OrdinalIgnoreCase) &&
                    (content.Contains("4688", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("terminated", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("taskkill", StringComparison.OrdinalIgnoreCase));

                bool auditPolicyChanged =
                    content.Contains("4719", StringComparison.OrdinalIgnoreCase) &&
                    content.Contains("Defender", StringComparison.OrdinalIgnoreCase);

                if (msMpEngTerminated)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Security event log records MsMpEng.exe process termination",
                        Risk     = RiskLevel.Critical,
                        Location = securityEvtx,
                        FileName = Path.GetFileName(securityEvtx),
                        Reason   = "The Windows Security event log contains evidence of MsMpEng.exe " +
                                   "(Defender Antimalware Service Executable) process activity " +
                                   "consistent with forced termination (Event ID 4688 context or " +
                                   "taskkill usage). Cheat bypass tools kill MsMpEng.exe to " +
                                   "immediately halt real-time protection before injecting DLLs.",
                        Detail   = $"Security EVTX: {securityEvtx} | MsMpEng termination evidence found"
                    });
                }

                if (auditPolicyChanged)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Security event log records audit policy change related to Defender",
                        Risk     = RiskLevel.High,
                        Location = securityEvtx,
                        FileName = Path.GetFileName(securityEvtx),
                        Reason   = "The Security event log contains Event ID 4719 (System audit policy " +
                                   "changed) with a Defender-related reference. Changing audit policy " +
                                   "can suppress security event logging to hide subsequent Defender " +
                                   "bypass actions from forensic review.",
                        Detail   = $"Security EVTX: {securityEvtx} | EventID 4719 Defender context found"
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }, ct);
}
