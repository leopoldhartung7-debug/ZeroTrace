using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class AntivirusHistoryScanModule : IScanModule
{
    public string Name => "Antivirus History & Quarantine Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    private static readonly string[] CheatKeywords =
    [
        "cheat", "hack", "bypass", "inject", "aimbot", "wallhack", "esp",
        "triggerbot", "speedhack", "godmode", "noclip", "teleport",
        "radar", "bhop", "bunnyhop", "spinbot", "triggerbot", "recoil",
        "eac_bypass", "be_bypass", "vac_bypass", "hwid_bypass", "hwid_spoof",
        "fivem_hack", "fivem_cheat", "fivem_bypass", "ragemp_hack", "ragemp_cheat",
        "altv_hack", "altv_cheat", "altv_bypass",
        "kdmapper", "manualmapper", "drivermapper", "kernelhack",
        "mhyprot", "iqvw64e", "dbutildrv2", "rtcore64",
        "ezfrags", "skinchanger", "lethalhack", "skidware",
        "lunarstrike", "frostware", "klar_cheat", "predator",
        "weave", "alterware", "superiorware", "impactcheats",
        "neverlose", "fatality", "onetap", "supremacy",
        "skeet", "gamesense", "iniuria", "primordial",
        "cobra", "outbreak", "sensualmods", "carbonhook",
        "trigon", "latency", "ghostware", "hyperion_bypass",
        "hyperion_cheat", "orbit_cheat", "redengine",
        "scripthook", "asiloader", "dinput8", "dsound",
        "d3d11_hook", "d3d9_hook", "opengl32_hook",
        "cleo", "openiv", "lspdfrmod",
        "hacks4free", "unknowncheats", "fearlessrevolution",
        "mpgh", "hackforums", "nexusmods_cheat",
        "cheatautomation", "aimjunkies", "cheathappens",
        "gamehacking", "gamekiller",
        "autohotkey_cheat", "ahk_cheat", "macro_cheat",
        "logitech_macro", "razer_macro_cheat",
        "internal_cheat", "external_cheat", "kernel_cheat",
        "ring0_cheat", "ring3_cheat", "usermode_cheat",
        "dll_inject", "process_inject", "thread_inject",
        "codecave", "hook_cheat", "detour_cheat",
        "vmprotect_bypass", "themida_bypass", "obsidium_bypass",
        "anticheattamper", "driver_bypass"
    ];

    private static readonly string[] DefenderThreatLogPaths =
    [
        @"Microsoft\Windows Defender\Scans\History\Service\DetectionHistory",
        @"Microsoft\Windows Defender\Scans\History\CacheManager",
        @"Microsoft\Windows Defender\Quarantine",
        @"Microsoft\Windows Defender\Scans\mpcache",
        @"Microsoft\Windows Defender\Support",
        @"Microsoft\Windows Defender\Scans\History"
    ];

    private static readonly string[] DefenderMpLogPaths =
    [
        @"Microsoft\Windows Defender\Support\MPLog",
        @"Microsoft\Windows Defender\Support\MpWppTracing"
    ];

    private static readonly string[] ThirdPartyAvPaths =
    [
        @"Avast Software\Avast\log",
        @"Avast Software\Avast\report",
        @"AVG\Antivirus\log",
        @"AVG\Antivirus\report",
        @"Malwarebytes\Malwarebytes\Logs",
        @"Malwarebytes\MBAMService\logs",
        @"ESET\ESET NOD32 Antivirus\Logs",
        @"ESET\ESET Security\Logs",
        @"Kaspersky Lab\AVP21.0\Report",
        @"Kaspersky Lab\Kaspersky Anti-Virus\Report",
        @"Kaspersky Lab\Kaspersky Total Security\Report",
        @"Bitdefender\Desktop\Profiles\Logs",
        @"Bitdefender\Endpoint Security\Logs",
        @"Norton\Norton Security\Logs",
        @"Symantec\Symantec Endpoint Protection\Logs",
        @"McAfee\DesktopProtection\Logs",
        @"McAfee\Endpoint Security\Logs\McAfee Endpoint Security",
        @"Trend Micro\OfficeScan\Logs",
        @"Webroot\WRSA_Logs",
        @"Sophos\Sophos Anti-Virus\Logs",
        @"F-Secure\Logs",
        @"G DATA\AVK\Report",
        @"Emsisoft Emergency Kit\logs",
        @"HitmanPro\Logs",
        @"Zemana\AntiMalware\Logs"
    ];

    private static readonly string[] DefenderRegistryPaths =
    [
        @"SOFTWARE\Microsoft\Windows Defender",
        @"SOFTWARE\Policies\Microsoft\Windows Defender",
        @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        @"SOFTWARE\Microsoft\Windows Defender\Features",
        @"SOFTWARE\Microsoft\Windows Defender\Signature Updates",
        @"SOFTWARE\Microsoft\Windows Defender\SpyNet",
        @"SOFTWARE\Microsoft\Windows Defender\Quarantine",
        @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
    ];

    private static readonly string[] WscRegistryPaths =
    [
        @"SOFTWARE\Microsoft\Security Center",
        @"SOFTWARE\Microsoft\Security Center\Svc",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Security Center"
    ];

    private static readonly string[] ThirdPartyAvRegistryPaths =
    [
        @"SOFTWARE\AVAST Software",
        @"SOFTWARE\AVG",
        @"SOFTWARE\Malwarebytes",
        @"SOFTWARE\ESET",
        @"SOFTWARE\Kaspersky Lab",
        @"SOFTWARE\Bitdefender",
        @"SOFTWARE\Norton",
        @"SOFTWARE\Symantec",
        @"SOFTWARE\McAfee",
        @"SOFTWARE\TrendMicro",
        @"SOFTWARE\Webroot",
        @"SOFTWARE\Sophos",
        @"SOFTWARE\F-Secure"
    ];

    private static readonly string[] DefenderQuarantineExtensions =
    [
        ".quarantine", ".vir", ".000", ".detected"
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckWindowsDefenderThreatHistory(ctx, ct),
            CheckWindowsDefenderQuarantine(ctx, ct),
            CheckWindowsDefenderMpLogs(ctx, ct),
            CheckWindowsDefenderRegistryTampering(ctx, ct),
            CheckWindowsDefenderExclusions(ctx, ct),
            CheckSecurityCenterRegistry(ctx, ct),
            CheckThirdPartyAvLogs(ctx, ct),
            CheckThirdPartyAvRegistry(ctx, ct),
            CheckDefenderSignatureAge(ctx, ct),
            CheckDefenderServiceStatus(ctx, ct),
            CheckAvastAvgQuarantine(ctx, ct),
            CheckMalwarebytesLogs(ctx, ct),
            CheckEsetKasperskyLogs(ctx, ct),
            CheckAvExclusionsForCheats(ctx, ct),
            CheckWindowsDefenderPolicies(ctx, ct)
        );
    }

    private Task CheckWindowsDefenderThreatHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var relPath in DefenderThreatLogPaths)
        {
            var fullPath = Path.Combine(ProgramData, relPath);
            if (!Directory.Exists(fullPath) && !File.Exists(fullPath)) continue;

            if (Directory.Exists(fullPath))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories))
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            foreach (var keyword in CheatKeywords)
                            {
                                if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                                {
                                    var lines = content.Split('\n')
                                        .Where(l => l.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                                        .Take(2)
                                        .ToList();

                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Cheat/Hack Tool Detected in Defender Threat History",
                                        Risk = RiskLevel.Critical,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Windows Defender threat history contains cheat keyword: '{keyword}'",
                                        Detail = string.Join("; ", lines.Select(l => l.Trim()).Take(2))
                                    });
                                    break;
                                }
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckWindowsDefenderQuarantine(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var quarantinePath = Path.Combine(ProgramData, @"Microsoft\Windows Defender\Quarantine");
        if (!Directory.Exists(quarantinePath)) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(quarantinePath, "*", SearchOption.AllDirectories))
            {
                ctx.IncrementFiles();
                var fileName = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                var fullName = Path.GetFileName(file).ToLowerInvariant();

                foreach (var keyword in CheatKeywords)
                {
                    if (fileName.Contains(keyword.ToLowerInvariant()) || fullName.Contains(keyword.ToLowerInvariant()))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Tool Found in Windows Defender Quarantine",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Defender quarantine contains file matching cheat keyword: '{keyword}'",
                            Detail = $"Quarantined file: {file}"
                        });
                        break;
                    }
                }
            }

            var dirCount = 0;
            try { dirCount = Directory.GetFiles(quarantinePath, "*", SearchOption.AllDirectories).Length; }
            catch (IOException) { }

            if (dirCount > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Windows Defender Quarantine Has Files",
                    Risk = RiskLevel.Medium,
                    Location = quarantinePath,
                    FileName = "Quarantine",
                    Reason = $"Windows Defender quarantine contains {dirCount} file(s) — review for cheat/hack tools",
                    Detail = $"Quarantine path: {quarantinePath} ({dirCount} files)"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckWindowsDefenderMpLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var mpLogPatterns = new[] { "MPLog*.log", "MpWppTracing*.log", "MpSupportFiles*.cab", "*.log" };
        var supportDir = Path.Combine(ProgramData, @"Microsoft\Windows Defender\Support");

        if (!Directory.Exists(supportDir)) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(supportDir, "*.log", SearchOption.TopDirectoryOnly))
            {
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in CheatKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            var matchLines = content.Split('\n')
                                .Where(l => l.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                                .Take(3)
                                .ToList();

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat/Hack Tool Detected in Defender MP Log",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Defender MPLog contains cheat-related entry: '{keyword}'",
                                Detail = string.Join("; ", matchLines.Select(l => l.Trim()).Take(2))
                            });
                            break;
                        }
                    }

                    var bypassKeywords = new[] { "bypass", "tamper", "exclusion added", "disabled", "real-time protection off", "signature update failed" };
                    foreach (var bk in bypassKeywords)
                    {
                        if (content.Contains(bk, StringComparison.OrdinalIgnoreCase))
                        {
                            var matchLines = content.Split('\n')
                                .Where(l => l.Contains(bk, StringComparison.OrdinalIgnoreCase))
                                .Take(2)
                                .ToList();

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Defender Tamper/Bypass Evidence in MP Log",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Defender MPLog records tampering/bypass event: '{bk}'",
                                Detail = string.Join("; ", matchLines.Select(l => l.Trim()).Take(2))
                            });
                            break;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckWindowsDefenderRegistryTampering(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var disableValues = new Dictionary<string, string[]>
        {
            [@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"] =
            [
                "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
                "DisableIOAVProtection", "DisableScriptScanning",
                "DisableAntiSpyware", "DisableOnAccessProtection"
            ],
            [@"SOFTWARE\Policies\Microsoft\Windows Defender"] =
            [
                "DisableAntiSpyware", "DisableAntiVirus", "DisableRealtimeMonitoring"
            ],
            [@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"] =
            [
                "DisableRealtimeMonitoring", "DisableOnAccessProtection", "DisableScanOnRealtimeEnable",
                "DisableBehaviorMonitoring", "DisableIOAVProtection"
            ]
        };

        foreach (var kvp in disableValues)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(kvp.Key);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valName in kvp.Value)
                {
                    var val = key.GetValue(valName);
                    if (val is int intVal && intVal == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Defender Protection Disabled via Registry",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{kvp.Key}\{valName}",
                            FileName = "Registry",
                            Reason = $"Defender protection feature disabled: {valName}=1 — indicative of bypass tool action",
                            Detail = $"Key: HKLM\\{kvp.Key}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        try
        {
            using var featKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Features");
            ctx.IncrementRegistryKeys();
            if (featKey != null)
            {
                var tamper = featKey.GetValue("TamperProtection");
                if (tamper is int tp && tp != 5)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Defender Tamper Protection Disabled",
                        Risk = RiskLevel.Critical,
                        Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection",
                        FileName = "Registry",
                        Reason = $"TamperProtection={tp} (expected 5=enabled) — bypass tool likely disabled tamper protection",
                        Detail = $"TamperProtection value: {tp} (5=enabled, 4=disabled by policy, 0=disabled)"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckWindowsDefenderExclusions(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var exclusionKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses"
        };

        foreach (var keyPath in exclusionKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valName in key.GetValueNames())
                {
                    var lower = valName.ToLowerInvariant();
                    foreach (var keyword in CheatKeywords)
                    {
                        if (lower.Contains(keyword.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat/Hack Path in Defender Exclusions",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}\{valName}",
                                FileName = "Registry",
                                Reason = $"Defender exclusion for cheat-related path/process: '{keyword}'",
                                Detail = $"Excluded: {valName}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckSecurityCenterRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var path in WscRegistryPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valName in key.GetValueNames())
                {
                    var val = key.GetValue(valName);
                    var lower = valName.ToLowerInvariant();

                    if ((lower.Contains("avdisablenotify") || lower.Contains("firedisablerequired") ||
                         lower.Contains("auclientdisabled") || lower.Contains("updatesdisablenotify") ||
                         lower.Contains("antispywareoverride") || lower.Contains("antivirusoverride") ||
                         lower.Contains("firewalloverride")) && val is int v && v == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Security Center AV Notifications Suppressed",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{path}\{valName}",
                            FileName = "Registry",
                            Reason = $"Security Center reporting suppressed: {valName}=1 — bypass tool may have done this",
                            Detail = $"Key: HKLM\\{path}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        try
        {
            using var wscKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\wscsvc");
            ctx.IncrementRegistryKeys();
            if (wscKey != null)
            {
                var start = wscKey.GetValue("Start");
                if (start is int s && s == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Security Center Service Disabled",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\wscsvc",
                        FileName = "Registry",
                        Reason = "Security Center service (wscsvc) disabled — bypass tools disable this to hide AV status",
                        Detail = "Start=4 (SERVICE_DISABLED)"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckThirdPartyAvLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var relPath in ThirdPartyAvPaths)
        {
            var fullPath = Path.Combine(ProgramData, relPath);
            if (!Directory.Exists(fullPath)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(fullPath, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(fullPath, "*.txt", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(fullPath, "*.xml", SearchOption.AllDirectories)))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var keyword in CheatKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                var avName = relPath.Split('\\')[0];
                                var matchLines = content.Split('\n')
                                    .Where(l => l.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                                    .Take(2)
                                    .ToList();

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Cheat Tool Detected by {avName}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"{avName} log records cheat detection: '{keyword}'",
                                    Detail = string.Join("; ", matchLines.Select(l => l.Trim()).Take(2))
                                });
                                break;
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckThirdPartyAvRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var path in ThirdPartyAvRegistryPaths)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                try
                {
                    using var key = hive.OpenSubKey(path);
                    ctx.IncrementRegistryKeys();
                    if (key == null) continue;

                    var hivePrefix = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                    var avName = path.Split('\\').Last();

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Third-Party Antivirus Installed: {avName}",
                        Risk = RiskLevel.Low,
                        Location = $@"{hivePrefix}\{path}",
                        FileName = "Registry",
                        Reason = $"Third-party AV product found: {avName} — check its logs and quarantine for cheat detections",
                        Detail = $"Registry key: {hivePrefix}\\{path}"
                    });

                    foreach (var valName in key.GetValueNames())
                    {
                        var val = key.GetValue(valName)?.ToString() ?? "";
                        var lower = val.ToLowerInvariant() + " " + valName.ToLowerInvariant();
                        if (lower.Contains("disabled") || lower.Contains("off") || lower.Contains("0"))
                        {
                            if (valName.Contains("enable", StringComparison.OrdinalIgnoreCase) ||
                                valName.Contains("protect", StringComparison.OrdinalIgnoreCase) ||
                                valName.Contains("realtime", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Third-Party AV Protection May Be Disabled: {avName}",
                                    Risk = RiskLevel.High,
                                    Location = $@"{hivePrefix}\{path}\{valName}",
                                    FileName = "Registry",
                                    Reason = $"{avName} registry suggests protection disabled: {valName}={val}",
                                    Detail = $"Key: {hivePrefix}\\{path}"
                                });
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckDefenderSignatureAge(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var sigKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Signature Updates");
            ctx.IncrementRegistryKeys();
            if (sigKey == null) return;

            var lastUpdate = sigKey.GetValue("SignaturesLastUpdated");
            if (lastUpdate != null)
            {
                if (lastUpdate is byte[] bytes && bytes.Length >= 8)
                {
                    var fileTime = BitConverter.ToInt64(bytes, 0);
                    var updateTime = DateTime.FromFileTimeUtc(fileTime);
                    var daysSince = (DateTime.UtcNow - updateTime).TotalDays;

                    if (daysSince > 30)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Defender Signatures Severely Outdated",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates",
                            FileName = "Registry",
                            Reason = $"Defender signatures last updated {daysSince:F0} days ago — may miss known cheat tools",
                            Detail = $"Last update: {updateTime:u}"
                        });
                    }
                    else if (daysSince > 7)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Defender Signatures Outdated",
                            Risk = RiskLevel.Medium,
                            Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates",
                            FileName = "Registry",
                            Reason = $"Defender signatures {daysSince:F0} days old — update recommended",
                            Detail = $"Last update: {updateTime:u}"
                        });
                    }
                }
            }

            var avEnabled = sigKey.GetValue("AVSignaturesVersion");
            if (avEnabled == null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Defender AV Signature Version Data Missing",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates",
                    FileName = "Registry",
                    Reason = "AV signature version data absent from registry — Defender may have been reinstalled/tampered",
                    Detail = "AVSignaturesVersion value missing"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckDefenderServiceStatus(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var defenderServices = new[]
        {
            ("WinDefend", "Windows Defender Antivirus Service"),
            ("WdNisSvc", "Windows Defender Network Inspection"),
            ("SecurityHealthService", "Windows Security Health Service"),
            ("Sense", "Windows Defender Advanced Threat Protection"),
            ("WdNisDrv", "Windows Defender Network Inspection Driver"),
            ("WdFilter", "Windows Defender Mini-Filter Driver"),
            ("WdBoot", "Windows Defender Boot Driver")
        };

        foreach (var (svcName, svcDesc) in defenderServices)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svcName}");
                ctx.IncrementRegistryKeys();

                if (key == null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Defender Service Key Missing: {svcName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = "Registry",
                        Reason = $"Service key for '{svcDesc}' missing — may have been deleted by bypass tool",
                        Detail = $"Expected service: {svcName}"
                    });
                    continue;
                }

                var start = key.GetValue("Start");
                if (start is int s && (s == 4 || s == 3))
                {
                    var riskLevel = s == 4 ? RiskLevel.Critical : RiskLevel.High;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Defender Service Disabled/Manual: {svcName}",
                        Risk = riskLevel,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = "Registry",
                        Reason = $"'{svcDesc}' Start={s} ({(s == 4 ? "DISABLED" : "MANUAL")}) — bypass tool likely changed this",
                        Detail = $"Start value: {s} (2=auto, 3=manual, 4=disabled)"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAvastAvgQuarantine(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var quarantinePaths = new[]
        {
            Path.Combine(ProgramData, @"Avast Software\Avast\chest"),
            Path.Combine(ProgramData, @"AVG\Antivirus\chest"),
            Path.Combine(ProgramData, @"Avast Software\Avast\report"),
            Path.Combine(ProgramData, @"AVG\Antivirus\report")
        };

        foreach (var qPath in quarantinePaths)
        {
            if (!Directory.Exists(qPath)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(qPath, "*", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file).ToLowerInvariant();

                    foreach (var keyword in CheatKeywords)
                    {
                        if (fileName.Contains(keyword.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Tool Found in Avast/AVG Quarantine",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Avast/AVG quarantine contains file matching cheat keyword: '{keyword}'",
                                Detail = $"Quarantine path: {file}"
                            });
                            break;
                        }
                    }

                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext == ".log" || ext == ".txt" || ext == ".xml")
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            foreach (var keyword in CheatKeywords)
                            {
                                if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Cheat Detection Record in Avast/AVG Log",
                                        Risk = RiskLevel.Critical,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Avast/AVG log records cheat detection: '{keyword}'",
                                        Detail = $"Log file: {file}"
                                    });
                                    break;
                                }
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch (IOException) { }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckMalwarebytesLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var mbPaths = new[]
        {
            Path.Combine(ProgramData, @"Malwarebytes\Malwarebytes\Logs"),
            Path.Combine(ProgramData, @"Malwarebytes\MBAMService\logs"),
            Path.Combine(ProgramData, @"Malwarebytes Anti-Malware\Logs")
        };

        foreach (var logPath in mbPaths)
        {
            if (!Directory.Exists(logPath)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(logPath, "*.xml", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logPath, "*.log", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(logPath, "*.txt", SearchOption.AllDirectories)))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var keyword in CheatKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cheat Tool Detected by Malwarebytes",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Malwarebytes log records cheat/hack detection: '{keyword}'",
                                    Detail = $"Log: {Path.GetFileName(file)}"
                                });
                                break;
                            }
                        }

                        if (content.Contains("quarantine", StringComparison.OrdinalIgnoreCase) &&
                            content.Contains("success", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Malwarebytes Quarantine Action Logged",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Malwarebytes log records successful quarantine action — verify if cheat-related",
                                Detail = $"Log: {Path.GetFileName(file)}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckEsetKasperskyLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logPaths = new Dictionary<string, string>
        {
            [Path.Combine(ProgramData, @"ESET\ESET NOD32 Antivirus\Logs")] = "ESET",
            [Path.Combine(ProgramData, @"ESET\ESET Security\Logs")] = "ESET Security",
            [Path.Combine(ProgramData, @"Kaspersky Lab")] = "Kaspersky",
            [Path.Combine(ProgramData, @"Bitdefender\Desktop\Profiles\Logs")] = "Bitdefender",
            [Path.Combine(ProgramData, @"Bitdefender\Endpoint Security\Logs")] = "Bitdefender ES",
            [Path.Combine(ProgramData, @"Sophos\Sophos Anti-Virus\Logs")] = "Sophos"
        };

        foreach (var kvp in logPaths)
        {
            if (!Directory.Exists(kvp.Key)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(kvp.Key, "*", SearchOption.AllDirectories)
                    .Where(f => f.EndsWith(".log", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                                f.EndsWith(".dat", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var keyword in CheatKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Cheat Tool Detected by {kvp.Value}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"{kvp.Value} log records cheat/hack detection: '{keyword}'",
                                    Detail = $"Log file: {Path.GetFileName(file)}"
                                });
                                break;
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckAvExclusionsForCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var exclusionKeyPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes"
        };

        foreach (var keyPath in exclusionKeyPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valName in key.GetValueNames())
                {
                    var lower = valName.ToLowerInvariant();
                    var isCheatRelated = false;
                    var matchedKeyword = "";

                    foreach (var keyword in CheatKeywords)
                    {
                        if (lower.Contains(keyword.ToLowerInvariant()))
                        {
                            isCheatRelated = true;
                            matchedKeyword = keyword;
                            break;
                        }
                    }

                    if (isCheatRelated)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat/Hack Tool Whitelisted in Defender Exclusions",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}\{valName}",
                            FileName = "Registry",
                            Reason = $"Cheat-related path/process excluded from Defender: '{matchedKeyword}'",
                            Detail = $"Excluded: {valName}"
                        });
                    }
                    else if (lower.Contains("fivem") || lower.Contains("ragemp") || lower.Contains("altv"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM/RageMP/AltV Excluded from Defender",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKLM\{keyPath}\{valName}",
                            FileName = "Registry",
                            Reason = $"Game platform path excluded from Defender scanning — could hide cheat files: {valName}",
                            Detail = $"Excluded entry: {valName}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckWindowsDefenderPolicies(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var policyKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender");
            ctx.IncrementRegistryKeys();
            if (policyKey == null) return;

            var disableAv = policyKey.GetValue("DisableAntiVirus");
            var disableAs = policyKey.GetValue("DisableAntiSpyware");
            var disableRt = policyKey.GetValue("DisableRealtimeMonitoring");

            if (disableAv is int av && av == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Defender AV Disabled via Group Policy",
                    Risk = RiskLevel.Critical,
                    Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiVirus",
                    FileName = "Registry",
                    Reason = "Defender AntiVirus disabled via policy registry key — bypass tool may have set this",
                    Detail = "DisableAntiVirus=1 via Policies key"
                });
            }

            if (disableAs is int aas && aas == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Defender AntiSpyware Disabled via Group Policy",
                    Risk = RiskLevel.Critical,
                    Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
                    FileName = "Registry",
                    Reason = "Defender AntiSpyware disabled via policy — this is a common bypass technique",
                    Detail = "DisableAntiSpyware=1 via Policies key"
                });
            }

            if (disableRt is int rt && rt == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Defender Real-Time Protection Disabled via Group Policy",
                    Risk = RiskLevel.Critical,
                    Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring",
                    FileName = "Registry",
                    Reason = "Defender real-time protection disabled via policy — bypass tool action detected",
                    Detail = "DisableRealtimeMonitoring=1 via Policies key"
                });
            }

            var subKeys = policyKey.GetSubKeyNames();
            foreach (var sub in subKeys)
            {
                ctx.IncrementRegistryKeys();
                if (sub.Contains("Exclusions", StringComparison.OrdinalIgnoreCase) ||
                    sub.Contains("Reporting", StringComparison.OrdinalIgnoreCase) ||
                    sub.Contains("SpyNet", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var subKey = policyKey.OpenSubKey(sub);
                        if (subKey == null) continue;
                        foreach (var valName in subKey.GetValueNames())
                        {
                            var val = subKey.GetValue(valName);
                            if (val is int intVal && intVal == 1 && valName.StartsWith("Disable", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Defender Feature Disabled via Policy Subkey",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\{sub}\{valName}",
                                    FileName = "Registry",
                                    Reason = $"Defender policy subkey disables feature: {sub}\\{valName}=1",
                                    Detail = $"Subkey: {sub}, Value: {valName}"
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);
}
