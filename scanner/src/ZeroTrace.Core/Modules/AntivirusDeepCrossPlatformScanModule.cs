using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class AntivirusDeepCrossPlatformScanModule : IScanModule
{
    public string Name => "Antivirus Deep Cross-Platform Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    private static readonly string ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

    private static readonly string[] CheatKeywords =
    [
        "cheat", "hack", "bypass", "inject", "aimbot", "wallhack", "esp",
        "triggerbot", "speedhack", "godmode", "noclip", "teleport",
        "radar", "bhop", "spinbot", "recoil", "triggerbot",
        "eac_bypass", "be_bypass", "vac_bypass", "hwid_bypass", "hwid_spoof",
        "fivem_hack", "fivem_cheat", "fivem_bypass", "ragemp_hack", "ragemp_cheat",
        "altv_hack", "altv_cheat", "altv_bypass",
        "kdmapper", "manualmapper", "drivermapper", "kernelhack",
        "mhyprot", "iqvw64e", "dbutildrv2", "rtcore64",
        "ezfrags", "skinchanger", "lethalhack",
        "lunarstrike", "frostware", "klar_cheat", "predator",
        "weave", "alterware", "superiorware",
        "neverlose", "fatality", "onetap", "supremacy",
        "skeet", "gamesense", "iniuria", "primordial",
        "trigon", "latency", "ghostware",
        "cheatengine", "cheat engine", "inject dll",
        "trainer hack", "hack tool", "game hack",
        "hacks4free", "unknowncheats", "fearlessrevolution",
        "mpgh", "hackforums", "cheathappens",
        "autohotkey cheat", "ahk_cheat", "macro cheat",
        "internal_cheat", "external_cheat", "kernel_cheat",
        "dll_inject", "reflective dll", "shellcode",
        "vmprotect_bypass", "themida_bypass",
        "disable defender", "kill defender",
        "sc stop easyanticheat", "sc delete easyanticheat",
        "taskkill battleye", "net stop windefend",
        "hyperion_bypass", "orbit_cheat"
    ];

    private static readonly string[] BypassActionKeywords =
    [
        "bypass", "tamper", "disable", "exclusion", "whitelist",
        "quarantine removed", "threat removed", "action taken",
        "real-time protection", "behavior monitoring", "script scanning",
        "PUA detected", "suspicious activity", "blocked",
        "elevated risk", "high risk", "critical threat"
    ];

    private static readonly Dictionary<string, string[]> AvLogPaths = new()
    {
        ["Avast"] = [
            @"Avast Software\Avast\log",
            @"Avast Software\Avast\report",
            @"Avast Software\Avast\Chest",
            @"Avast Software\Avast\Backup",
            @"Avast Software\Avast\Setup"
        ],
        ["AVG"] = [
            @"AVG\Antivirus\log",
            @"AVG\Antivirus\report",
            @"AVG\Antivirus\Chest",
            @"AVG Technologies\AVG\log"
        ],
        ["Malwarebytes"] = [
            @"Malwarebytes\Malwarebytes\Logs",
            @"Malwarebytes\MBAMService\logs",
            @"Malwarebytes Anti-Malware\Logs",
            @"Malwarebytes\Malwarebytes\Quarantine"
        ],
        ["ESET"] = [
            @"ESET\ESET NOD32 Antivirus\Logs",
            @"ESET\ESET Security\Logs",
            @"ESET\ESET Internet Security\Logs",
            @"ESET\ESET Smart Security\Logs",
            @"ESET\ESET Endpoint Antivirus\Logs"
        ],
        ["Kaspersky"] = [
            @"Kaspersky Lab\AVP21.0\Report",
            @"Kaspersky Lab\AVP22.0\Report",
            @"Kaspersky Lab\Kaspersky Anti-Virus\Report",
            @"Kaspersky Lab\Kaspersky Total Security\Report",
            @"Kaspersky Lab\Kaspersky Internet Security\Report",
            @"Kaspersky Lab\Kaspersky Security Cloud\Report"
        ],
        ["Bitdefender"] = [
            @"Bitdefender\Desktop\Profiles\Logs",
            @"Bitdefender\Endpoint Security\Logs",
            @"Bitdefender\Bitdefender Security\Logs",
            @"Bitdefender\Antivirus Free\Logs"
        ],
        ["Norton"] = [
            @"Norton\Norton Security\Logs",
            @"Norton\Norton360\Logs",
            @"Norton\NortonLifeLock\Logs",
            @"NortonData"
        ],
        ["McAfee"] = [
            @"McAfee\DesktopProtection\Logs",
            @"McAfee\Endpoint Security\Logs\McAfee Endpoint Security",
            @"McAfee\Host Intrusion Prevention\Logs",
            @"McAfee\Agent\logs"
        ],
        ["Trend Micro"] = [
            @"Trend Micro\OfficeScan\Logs",
            @"Trend Micro\AMSP\Log",
            @"Trend Micro\Security Agent\Logs"
        ],
        ["Webroot"] = [
            @"Webroot\WRSA_Logs",
            @"Webroot\Security\WRData"
        ],
        ["Sophos"] = [
            @"Sophos\Sophos Anti-Virus\Logs",
            @"Sophos\Health\Logs",
            @"Sophos\Sophos Endpoint Agent\Logs"
        ],
        ["F-Secure"] = [
            @"F-Secure\Logs",
            @"F-Secure\Anti-Virus\Logs",
            @"F-Secure\FSAV\Logs"
        ],
        ["G DATA"] = [
            @"G DATA\AVK\Report",
            @"G DATA\AntiVirus\Report",
            @"G DATA\GravityZone\Logs"
        ],
        ["Emsisoft"] = [
            @"Emsisoft Emergency Kit\logs",
            @"Emsisoft Anti-Malware\logs",
            @"Emsisoft\logs"
        ],
        ["HitmanPro"] = [
            @"HitmanPro\Logs",
            @"HitmanPro.Alert\Logs",
            @"SurfRight\HitmanPro\Logs"
        ],
        ["Zemana"] = [
            @"Zemana\AntiMalware\Logs",
            @"Zemana\AntiLogger\Logs"
        ],
        ["Comodo"] = [
            @"COMODO\Firewall\Logs",
            @"COMODO\Internet Security\Logs",
            @"COMODO\Antivirus\Logs"
        ],
        ["Vipre"] = [
            @"VIPRE Internet Security\Logs",
            @"ThreatTrack Security\VIPRE\Logs"
        ],
        ["Cylance"] = [
            @"Cylance\Desktop\log",
            @"Cylance\Status\Logs"
        ],
        ["CrowdStrike"] = [
            @"CrowdStrike\Falcon Sensor\Logs",
            @"CrowdStrike\Logs"
        ],
        ["SentinelOne"] = [
            @"SentinelOne\Logs",
            @"Sentinel Labs\SentinelOne\Logs"
        ],
        ["Carbon Black"] = [
            @"CarbonBlack\Logs",
            @"Carbon Black\Defense\Logs"
        ],
        ["TotalAV"] = [
            @"TotalAV\Logs",
            @"Protected.net\TotalAV\Logs"
        ],
        ["Panda"] = [
            @"Panda Security\Logs",
            @"Panda Software\Logs"
        ]
    };

    private static readonly Dictionary<string, string[]> AvRegistryPaths = new()
    {
        ["Avast"] = [@"SOFTWARE\AVAST Software\Avast", @"SOFTWARE\WOW6432Node\AVAST Software\Avast"],
        ["AVG"] = [@"SOFTWARE\AVG", @"SOFTWARE\WOW6432Node\AVG Technologies"],
        ["Malwarebytes"] = [@"SOFTWARE\Malwarebytes", @"SOFTWARE\WOW6432Node\Malwarebytes"],
        ["ESET"] = [@"SOFTWARE\ESET", @"SOFTWARE\WOW6432Node\ESET"],
        ["Kaspersky"] = [@"SOFTWARE\KasperskyLab", @"SOFTWARE\WOW6432Node\KasperskyLab"],
        ["Bitdefender"] = [@"SOFTWARE\Bitdefender", @"SOFTWARE\WOW6432Node\Bitdefender"],
        ["Norton"] = [@"SOFTWARE\Norton", @"SOFTWARE\Symantec", @"SOFTWARE\WOW6432Node\Norton"],
        ["McAfee"] = [@"SOFTWARE\McAfee", @"SOFTWARE\WOW6432Node\McAfee"],
        ["Trend Micro"] = [@"SOFTWARE\TrendMicro", @"SOFTWARE\WOW6432Node\TrendMicro"],
        ["Webroot"] = [@"SOFTWARE\WRData", @"SOFTWARE\WOW6432Node\Webroot"],
        ["Sophos"] = [@"SOFTWARE\Sophos", @"SOFTWARE\WOW6432Node\Sophos"],
        ["F-Secure"] = [@"SOFTWARE\F-Secure", @"SOFTWARE\WOW6432Node\F-Secure"],
        ["Comodo"] = [@"SOFTWARE\COMODO", @"SOFTWARE\WOW6432Node\COMODO"],
        ["Cylance"] = [@"SOFTWARE\Cylance", @"SOFTWARE\WOW6432Node\Cylance"],
        ["CrowdStrike"] = [@"SOFTWARE\CrowdStrike", @"SOFTWARE\WOW6432Node\CrowdStrike"],
        ["SentinelOne"] = [@"SOFTWARE\Sentinel Labs", @"SOFTWARE\WOW6432Node\Sentinel Labs"],
        ["Carbon Black"] = [@"SOFTWARE\CarbonBlack", @"SOFTWARE\WOW6432Node\Carbon Black"]
    };

    private static readonly Dictionary<string, string[]> AvQuarantinePaths = new()
    {
        ["Avast"] = [@"Avast Software\Avast\chest", @"Avast Software\Avast\Backup\BaseVirus"],
        ["AVG"] = [@"AVG\Antivirus\chest", @"AVG Technologies\AVG\chest"],
        ["Malwarebytes"] = [@"Malwarebytes\Malwarebytes\Quarantine"],
        ["ESET"] = [@"ESET\ESET NOD32 Antivirus\Quarantine", @"ESET\ESET Security\Quarantine"],
        ["Kaspersky"] = [@"Kaspersky Lab\Quarantine", @"Kaspersky Lab\AVP21.0\Quarantine"],
        ["Bitdefender"] = [@"Bitdefender\Desktop\Quarantine", @"Bitdefender\Quarantine"],
        ["Norton"] = [@"Norton\NortonQuarantine", @"Symantec\Quarantine"],
        ["McAfee"] = [@"McAfee\QuarantineManager\Quarantine", @"McAfee\DesktopProtection\Quarantine"],
        ["Sophos"] = [@"Sophos\Sophos Anti-Virus\Quarantine", @"Sophos\Quarantine"],
        ["Trend Micro"] = [@"Trend Micro\AMSP\Quarantine", @"Trend Micro\OfficeScan\Quarantine"],
        ["Comodo"] = [@"COMODO\Antivirus\Quarantine", @"COMODO\Internet Security\Quarantine"]
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAllAvLogs(ctx, ct),
            CheckAllAvQuarantineFolders(ctx, ct),
            CheckAllAvRegistryKeys(ctx, ct),
            CheckAvServiceDisabled(ctx, ct),
            CheckWindowsDefenderDeepState(ctx, ct),
            CheckAvInstallPaths(ctx, ct),
            CheckCommonAvUninstallRecords(ctx, ct),
            CheckNetworkProtectionLogs(ctx, ct),
            CheckAvStartupKeys(ctx, ct),
            CheckSuspiciousAvExclusions(ctx, ct),
            CheckThirdPartyAvSchedTasks(ctx, ct),
            CheckAvEventLogChannels(ctx, ct),
            CheckEndpointDetectionResponse(ctx, ct),
            CheckAvHardwareBasedProducts(ctx, ct),
            CheckAvDatabaseIntegrity(ctx, ct)
        );
    }

    private Task CheckAllAvLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var avProduct in AvLogPaths)
        {
            foreach (var relPath in avProduct.Value)
            {
                var fullPath = Path.Combine(ProgramData, relPath);
                if (!Directory.Exists(fullPath)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories)
                        .Where(f =>
                            f.EndsWith(".log", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".html", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))
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
                                        .Take(3).ToList();

                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Cheat Tool Detected in {avProduct.Key} Log",
                                        Risk = Risk.Critical,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"{avProduct.Key} log records cheat/hack detection: '{keyword}'",
                                        Detail = string.Join("; ", matchLines.Select(l => l.Trim()).Take(2))
                                    });
                                    break;
                                }
                            }

                            foreach (var bk in BypassActionKeywords)
                            {
                                if (content.Contains(bk, StringComparison.OrdinalIgnoreCase) &&
                                    content.Contains("bypass", StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"AV Bypass/Tamper Event in {avProduct.Key} Log",
                                        Risk = Risk.High,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"{avProduct.Key} log records bypass/tamper event: '{bk}'",
                                        Detail = $"Log: {Path.GetFileName(file)}"
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
    }, ct);

    private Task CheckAllAvQuarantineFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var avProduct in AvQuarantinePaths)
        {
            foreach (var relPath in avProduct.Value)
            {
                var fullPath = Path.Combine(ProgramData, relPath);
                if (!Directory.Exists(fullPath)) continue;
                try
                {
                    var fileCount = 0;
                    foreach (var file in Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories))
                    {
                        ctx.IncrementFiles();
                        fileCount++;
                        var fileName = Path.GetFileName(file).ToLowerInvariant();
                        foreach (var keyword in CheatKeywords)
                        {
                            if (fileName.Contains(keyword.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Cheat Tool in {avProduct.Key} Quarantine",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"{avProduct.Key} quarantine contains file matching cheat keyword: '{keyword}'",
                                    Detail = $"Quarantine path: {file}"
                                });
                                break;
                            }
                        }
                    }

                    if (fileCount > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"{avProduct.Key} Quarantine Has {fileCount} File(s)",
                            Risk = Risk.Medium,
                            Location = fullPath,
                            FileName = "Quarantine",
                            Reason = $"{avProduct.Key} quarantine contains {fileCount} quarantined file(s) — review for cheat tool detections",
                            Detail = $"Quarantine path: {fullPath}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckAllAvRegistryKeys(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var avProduct in AvRegistryPaths)
        {
            foreach (var keyPath in avProduct.Value)
            {
                foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                {
                    try
                    {
                        using var key = hive.OpenSubKey(keyPath);
                        ctx.IncrementRegistryKeys();
                        if (key == null) continue;

                        var hivePrefix = hive == Registry.LocalMachine ? "HKLM" : "HKCU";

                        foreach (var valName in key.GetValueNames())
                        {
                            var val = key.GetValue(valName)?.ToString() ?? "";
                            var lower = valName.ToLowerInvariant() + " " + val.ToLowerInvariant();

                            if ((lower.Contains("enabled") || lower.Contains("protect") || lower.Contains("realtime")) &&
                                (val == "0" || val.Equals("false", StringComparison.OrdinalIgnoreCase) || val.Equals("disabled", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"{avProduct.Key} Protection Feature Disabled",
                                    Risk = Risk.High,
                                    Location = $@"{hivePrefix}\{keyPath}\{valName}",
                                    FileName = "Registry",
                                    Reason = $"{avProduct.Key} registry shows disabled protection: {valName}={val}",
                                    Detail = $"Key: {hivePrefix}\\{keyPath}"
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
        }
    }, ct);

    private Task CheckAvServiceDisabled(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var avServices = new Dictionary<string, string>
        {
            ["avast! Antivirus"] = "avast! Antivirus",
            ["AvastSvc"] = "Avast Service",
            ["avgSvc"] = "AVG Service",
            ["MBAMService"] = "Malwarebytes Service",
            ["ekrn"] = "ESET Service (ekrn)",
            ["AVP"] = "Kaspersky AVP Service",
            ["bdredline"] = "Bitdefender Redline",
            ["NortonSecurity"] = "Norton Security",
            ["McNASvc"] = "McAfee Agent",
            ["TmCCSF"] = "Trend Micro CCSF",
            ["WRSVC"] = "Webroot Service",
            ["SAVService"] = "Sophos AV Service",
            ["F-Secure Gatekeeper"] = "F-Secure Gatekeeper",
            ["AVKWCtl"] = "G DATA AVK",
            ["MsMpSvc"] = "Microsoft Security",
            ["cydevice"] = "Cylance Device",
            ["CSFalconService"] = "CrowdStrike Falcon",
            ["SentinelAgent"] = "SentinelOne Agent",
            ["CbDefense"] = "Carbon Black Defense",
            ["comodo internet security"] = "Comodo Internet Security"
        };

        foreach (var svc in avServices)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svc.Key}");
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                var start = key.GetValue("Start");
                if (start is int s && (s == 4 || s == 3))
                {
                    var risk = s == 4 ? Risk.Critical : Risk.High;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AV Service Disabled/Manual: {svc.Value}",
                        Risk = risk,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc.Key}",
                        FileName = "Registry",
                        Reason = $"AV service '{svc.Value}' Start={s} ({(s == 4 ? "DISABLED" : "MANUAL")}) — bypass tool likely disabled this AV",
                        Detail = $"Service: {svc.Key}, Start={s}"
                    });
                }

                var imagePath = key.GetValue("ImagePath")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(imagePath) && !File.Exists(imagePath.Trim('"').Split(' ')[0]))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AV Service Binary Missing: {svc.Value}",
                        Risk = Risk.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc.Key}",
                        FileName = "Registry",
                        Reason = $"AV service '{svc.Value}' ImagePath points to non-existent binary — AV may have been removed/corrupted",
                        Detail = $"ImagePath: {imagePath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckWindowsDefenderDeepState(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var defenderValueChecks = new Dictionary<string, (string hive, string path, string value, int badValue, string description)>
        {
            ["RT_Monitor"] = ("HKLM", @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 1, "Real-Time Monitoring disabled"),
            ["Behavior"] = ("HKLM", @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring", 1, "Behavior Monitoring disabled"),
            ["IOAV"] = ("HKLM", @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableIOAVProtection", 1, "IOAV Protection disabled"),
            ["Script"] = ("HKLM", @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableScriptScanning", 1, "Script Scanning disabled"),
            ["AntiSpy"] = ("HKLM", @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1, "AntiSpyware disabled via Policy"),
            ["AntiVirus"] = ("HKLM", @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus", 1, "AntiVirus disabled via Policy"),
            ["Tamper"] = ("HKLM", @"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", 4, "TamperProtection set to 4 (disabled by policy)"),
            ["SpyNet"] = ("HKLM", @"SOFTWARE\Microsoft\Windows Defender\SpyNet", "SpynetReporting", 0, "Spynet Reporting disabled"),
            ["Cloud"] = ("HKLM", @"SOFTWARE\Microsoft\Windows Defender\SpyNet", "SubmitSamplesConsent", 2, "Sample submission disabled"),
            ["NetProtect"] = ("HKLM", @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection", "EnableNetworkProtection", 0, "Network Protection disabled"),
            ["CFA"] = ("HKLM", @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access", "EnableControlledFolderAccess", 0, "Controlled Folder Access disabled")
        };

        foreach (var check in defenderValueChecks)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(check.Value.path);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                var val = key.GetValue(check.Value.value);
                if (val is int intVal && intVal == check.Value.badValue)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Windows Defender: {check.Value.description}",
                        Risk = Risk.Critical,
                        Location = $@"HKLM\{check.Value.path}\{check.Value.value}",
                        FileName = "Registry",
                        Reason = $"Defender protection weakened: {check.Value.description} — bypass tool action detected",
                        Detail = $"Value: {check.Value.value}={val}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        try
        {
            using var excPathsKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths");
            ctx.IncrementRegistryKeys();
            if (excPathsKey != null)
            {
                var excCount = excPathsKey.GetValueNames().Length;
                if (excCount > 10)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Defender Has {excCount} Path Exclusions (Excessive)",
                        Risk = Risk.High,
                        Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                        FileName = "Registry",
                        Reason = $"Defender has {excCount} path exclusions — excessive exclusions often added by cheat tools to hide their directories",
                        Detail = $"Exclusion count: {excCount}"
                    });
                }

                foreach (var excPath in excPathsKey.GetValueNames())
                {
                    var lower = excPath.ToLowerInvariant();
                    if (lower.Contains("temp") || lower.Contains("download") || lower.Contains("desktop") ||
                        lower.Contains("appdata") || lower.Contains("users\\public"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Defender Exclusion in High-Risk User Directory",
                            Risk = Risk.Critical,
                            Location = $@"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\{excPath}",
                            FileName = "Registry",
                            Reason = $"Defender excludes user-writable high-risk directory: '{excPath}' — cheat tools use this to hide payloads",
                            Detail = $"Excluded path: {excPath}"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckAvInstallPaths(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var avInstallPaths = new Dictionary<string, string[]>
        {
            ["Avast"] = [
                Path.Combine(ProgramFiles, "Avast Software", "Avast"),
                Path.Combine(ProgramFilesX86, "Avast Software", "Avast")
            ],
            ["AVG"] = [
                Path.Combine(ProgramFiles, "AVG", "Antivirus"),
                Path.Combine(ProgramFilesX86, "AVG", "Antivirus")
            ],
            ["Malwarebytes"] = [
                Path.Combine(ProgramFiles, "Malwarebytes", "Anti-Malware"),
                Path.Combine(ProgramFilesX86, "Malwarebytes", "Anti-Malware")
            ],
            ["ESET"] = [
                Path.Combine(ProgramFiles, "ESET", "ESET NOD32 Antivirus"),
                Path.Combine(ProgramFilesX86, "ESET", "ESET NOD32 Antivirus")
            ],
            ["Kaspersky"] = [
                Path.Combine(ProgramFiles, "Kaspersky Lab"),
                Path.Combine(ProgramFilesX86, "Kaspersky Lab")
            ],
            ["Bitdefender"] = [
                Path.Combine(ProgramFiles, "Bitdefender"),
                Path.Combine(ProgramFilesX86, "Bitdefender")
            ],
            ["CrowdStrike"] = [
                Path.Combine(ProgramFiles, "CrowdStrike"),
                @"C:\Windows\System32\drivers\CrowdStrike"
            ],
            ["SentinelOne"] = [
                Path.Combine(ProgramFiles, "SentinelOne"),
                Path.Combine(ProgramFilesX86, "SentinelOne")
            ]
        };

        foreach (var avProduct in avInstallPaths)
        {
            foreach (var installPath in avProduct.Value)
            {
                if (!Directory.Exists(installPath)) continue;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"{avProduct.Key} Installation Directory Found",
                    Risk = Risk.Low,
                    Location = installPath,
                    FileName = Path.GetFileName(installPath),
                    Reason = $"{avProduct.Key} AV is installed at '{installPath}' — check its quarantine and logs for cheat detections",
                    Detail = $"AV path: {installPath}"
                });

                try
                {
                    var exeFiles = Directory.GetFiles(installPath, "*.exe", SearchOption.TopDirectoryOnly);
                    foreach (var exe in exeFiles)
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            var fi = new FileInfo(exe);
                            if (fi.Length < 10240)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"{avProduct.Key} Executable Suspiciously Small",
                                    Risk = Risk.High,
                                    Location = exe,
                                    FileName = Path.GetFileName(exe),
                                    Reason = $"{avProduct.Key} executable is only {fi.Length} bytes — may be stub/hollowed binary",
                                    Detail = $"File: {exe}, Size: {fi.Length} bytes"
                                });
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckCommonAvUninstallRecords(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var uninstallKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        };

        var avProductNames = new[]
        {
            "avast", "avg", "malwarebytes", "eset", "kaspersky", "bitdefender",
            "norton", "mcafee", "trend micro", "webroot", "sophos", "f-secure",
            "g data", "emsisoft", "hitmanpro", "comodo", "vipre", "cylance",
            "crowdstrike", "sentinelone", "carbon black", "cylance", "panda",
            "zemana", "totalav"
        };

        foreach (var keyPath in uninstallKeys)
        {
            try
            {
                using var uninstallKey = Registry.LocalMachine.OpenSubKey(keyPath);
                ctx.IncrementRegistryKeys();
                if (uninstallKey == null) continue;

                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    try
                    {
                        using var appKey = uninstallKey.OpenSubKey(subKeyName);
                        var displayName = appKey?.GetValue("DisplayName")?.ToString()?.ToLowerInvariant() ?? "";
                        var publisher = appKey?.GetValue("Publisher")?.ToString()?.ToLowerInvariant() ?? "";

                        foreach (var avName in avProductNames)
                        {
                            if (displayName.Contains(avName) || publisher.Contains(avName))
                            {
                                var installDate = appKey?.GetValue("InstallDate")?.ToString() ?? "unknown";
                                var version = appKey?.GetValue("DisplayVersion")?.ToString() ?? "unknown";

                                ctx.IncrementRegistryKeys();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"AV Product in Add/Remove Programs: {appKey?.GetValue("DisplayName")}",
                                    Risk = Risk.Low,
                                    Location = $@"HKLM\{keyPath}\{subKeyName}",
                                    FileName = "Registry",
                                    Reason = $"AV product '{appKey?.GetValue("DisplayName")}' registered in Add/Remove Programs — check logs and quarantine",
                                    Detail = $"Version: {version}, Installed: {installDate}"
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
    }, ct);

    private Task CheckNetworkProtectionLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var networkProtectionLogPaths = new[]
        {
            Path.Combine(ProgramData, @"Microsoft\Windows Defender\Network Inspection System\Support"),
            Path.Combine(ProgramData, @"Microsoft\Windows Defender\Network Inspection"),
            Path.Combine(ProgramData, @"Microsoft\Windows Defender\Support\MpWppTracing-20")
        };

        foreach (var logDir in networkProtectionLogPaths)
        {
            if (!Directory.Exists(logDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(logDir, "*.log", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.TopDirectoryOnly)))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var ck in CheatKeywords)
                        {
                            if (content.Contains(ck, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cheat Tool Referenced in Network Protection Log",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Defender network protection log references cheat tool: '{ck}'",
                                    Detail = $"Log: {Path.GetFileName(file)}"
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
    }, ct);

    private Task CheckAvStartupKeys(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var avAutorunNames = new[]
        {
            "avast", "avg", "malwarebytes", "eset", "kaspersky", "bitdefender",
            "norton", "mcafee", "sophos", "webroot", "comodo", "cylance",
            "crowdstrike", "sentinel", "carbonblack"
        };

        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        };

        foreach (var keyPath in runKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valName in key.GetValueNames())
                {
                    var val = key.GetValue(valName)?.ToString() ?? "";
                    var lower = (valName + " " + val).ToLowerInvariant();

                    foreach (var avName in avAutorunNames)
                    {
                        if (lower.Contains(avName))
                        {
                            var exePath = val.Trim('"').Split(' ')[0];
                            if (!string.IsNullOrEmpty(exePath) && !File.Exists(exePath))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"AV Startup Entry Points to Missing Binary: {avName}",
                                    Risk = Risk.High,
                                    Location = $@"HKLM\{keyPath}\{valName}",
                                    FileName = "Registry",
                                    Reason = $"AV product '{avName}' startup entry points to non-existent binary — AV may have been removed/corrupted by bypass tool",
                                    Detail = $"Path: {val}"
                                });
                            }
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckSuspiciousAvExclusions(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var avExclusionKeys = new Dictionary<string, string>
        {
            [@"SOFTWARE\AVAST Software\Avast\FileExclusions"] = "Avast",
            [@"SOFTWARE\ESET\ESET NOD32 Antivirus\Exclusions\0\Object"] = "ESET",
            [@"SOFTWARE\KasperskyLab\protected\AVP21.0\Data\Settings\ExcludedObjects"] = "Kaspersky",
            [@"SOFTWARE\Malwarebytes\MBAMService\Config\ExcludedFiles"] = "Malwarebytes",
            [@"SOFTWARE\Bitdefender\Firewall\Exclusions"] = "Bitdefender"
        };

        foreach (var kvp in avExclusionKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(kvp.Key);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valName in key.GetValueNames())
                {
                    var val = key.GetValue(valName)?.ToString() ?? "";
                    var lower = (valName + " " + val).ToLowerInvariant();
                    foreach (var ck in CheatKeywords)
                    {
                        if (lower.Contains(ck.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Cheat-Related Exclusion in {kvp.Value}",
                                Risk = Risk.Critical,
                                Location = $@"HKLM\{kvp.Key}\{valName}",
                                FileName = "Registry",
                                Reason = $"{kvp.Value} exclusion references cheat tool: '{ck}'",
                                Detail = $"Exclusion: {val}"
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

    private Task CheckThirdPartyAvSchedTasks(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var taskDir = @"C:\Windows\System32\Tasks";
        if (!Directory.Exists(taskDir)) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(taskDir, "*", SearchOption.AllDirectories))
            {
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file).ToLowerInvariant();
                var isAvTask = new[] { "defender", "malwarebytes", "avast", "avg", "eset", "kaspersky", "bitdefender", "norton", "mcafee", "sophos" }
                    .Any(av => fileName.Contains(av));
                if (!isAvTask) continue;

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    if (content.Contains("Disabled", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("<Enabled>false</Enabled>", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AV Scheduled Task Disabled: {Path.GetFileName(file)}",
                            Risk = Risk.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"AV-related scheduled task is disabled: '{Path.GetFileName(file)}' — bypass tool may have disabled AV update/scan task",
                            Detail = $"Task file: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckAvEventLogChannels(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var avChannels = new Dictionary<string, string>
        {
            ["Microsoft-Windows-Windows Defender/Operational"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational",
            ["Microsoft-Antimalware/Operational"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Antimalware/Operational",
            ["Microsoft-Windows-Security-Essentials/Operational"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Essentials/Operational"
        };

        foreach (var channel in avChannels)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(channel.Value);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                var enabled = key.GetValue("Enabled");
                if (enabled is int e && e == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"AV Event Log Channel Disabled: {channel.Key}",
                        Risk = Risk.Critical,
                        Location = $@"HKLM\{channel.Value}",
                        FileName = "Registry",
                        Reason = $"AV event log channel '{channel.Key}' disabled — AV detection events not recorded",
                        Detail = "Enabled=0 prevents AV detections from being logged"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckEndpointDetectionResponse(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var edrRegistryKeys = new Dictionary<string, string>
        {
            [@"SYSTEM\CurrentControlSet\Services\CSFalconService"] = "CrowdStrike Falcon",
            [@"SYSTEM\CurrentControlSet\Services\SentinelAgent"] = "SentinelOne Agent",
            [@"SYSTEM\CurrentControlSet\Services\CbDefense"] = "Carbon Black Defense",
            [@"SYSTEM\CurrentControlSet\Services\DGService"] = "Digital Guardian",
            [@"SYSTEM\CurrentControlSet\Services\CylanceSvc"] = "Cylance Service",
            [@"SYSTEM\CurrentControlSet\Services\SENSE"] = "Windows Defender ATP/SENSE",
            [@"SOFTWARE\Microsoft\Windows Advanced Threat Protection"] = "Windows ATP"
        };

        foreach (var edr in edrRegistryKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(edr.Key);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                var start = key.GetValue("Start");
                if (start is int s && s == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EDR Service Disabled: {edr.Value}",
                        Risk = Risk.Critical,
                        Location = $@"HKLM\{edr.Key}",
                        FileName = "Registry",
                        Reason = $"EDR/endpoint security service '{edr.Value}' disabled (Start=4) — active bypass of enterprise security monitoring",
                        Detail = $"Service key: HKLM\\{edr.Key}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        try
        {
            using var atpKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status");
            ctx.IncrementRegistryKeys();
            if (atpKey != null)
            {
                var senseOnboarded = atpKey.GetValue("OnboardingState");
                if (senseOnboarded is int os && os == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Defender ATP Not Onboarded",
                        Risk = Risk.Medium,
                        Location = @"HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status\OnboardingState",
                        FileName = "Registry",
                        Reason = "Windows Defender ATP not onboarded — no cloud-based threat detection and investigation",
                        Detail = "OnboardingState=0"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckAvHardwareBasedProducts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var securityCenterKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Security Center\Provider\Av");
            ctx.IncrementRegistryKeys();

            if (securityCenterKey == null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "No AV Registered in Security Center",
                    Risk = Risk.High,
                    Location = @"HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av",
                    FileName = "Registry",
                    Reason = "No antivirus product registered with Windows Security Center — either no AV installed or bypass tool removed registration",
                    Detail = "Security Center AV provider key absent"
                });
                return;
            }

            foreach (var subKey in securityCenterKey.GetSubKeyNames())
            {
                try
                {
                    using var provKey = securityCenterKey.OpenSubKey(subKey);
                    var state = provKey?.GetValue("STATE")?.ToString() ?? "";
                    var productState = provKey?.GetValue("productState");
                    var displayName = provKey?.GetValue("displayName")?.ToString() ?? "";
                    var signatureStatus = provKey?.GetValue("signatureStatus")?.ToString() ?? "";

                    ctx.IncrementRegistryKeys();

                    if (!string.IsNullOrEmpty(displayName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"AV Registered in Security Center: {displayName}",
                            Risk = Risk.Low,
                            Location = $@"HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av\{subKey}",
                            FileName = "Registry",
                            Reason = $"AV product '{displayName}' registered with Security Center — verify logs for cheat detections",
                            Detail = $"GUID: {subKey}, State: {state}, SigStatus: {signatureStatus}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckAvDatabaseIntegrity(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var avDatabasePaths = new Dictionary<string, string>
        {
            [Path.Combine(ProgramData, @"Microsoft\Windows Defender\Definition Updates")] = "Defender",
            [Path.Combine(ProgramData, @"ESET\ESET NOD32 Antivirus\Updfiles")] = "ESET",
            [Path.Combine(ProgramData, @"Avast Software\Avast\defs")] = "Avast",
            [Path.Combine(ProgramData, @"AVG\Antivirus\defs")] = "AVG",
            [Path.Combine(ProgramData, @"Kaspersky Lab\AVP21.0\Data\Bases")] = "Kaspersky",
            [Path.Combine(ProgramData, @"Malwarebytes\MBAMService\updates")] = "Malwarebytes"
        };

        foreach (var dbPath in avDatabasePaths)
        {
            if (!Directory.Exists(dbPath.Key)) continue;
            try
            {
                var dbFiles = Directory.GetFiles(dbPath.Key, "*", SearchOption.AllDirectories);
                if (dbFiles.Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"{dbPath.Value} Signature Database Empty",
                        Risk = Risk.High,
                        Location = dbPath.Key,
                        FileName = Path.GetFileName(dbPath.Key),
                        Reason = $"{dbPath.Value} signature/definition database directory is empty — AV may be non-functional or databases were deleted",
                        Detail = $"Database path: {dbPath.Key}"
                    });
                }
                else
                {
                    var newest = dbFiles.Select(f =>
                    {
                        try { return new FileInfo(f).LastWriteTimeUtc; }
                        catch { return DateTime.MinValue; }
                    }).Max();

                    var daysSinceUpdate = (DateTime.UtcNow - newest).TotalDays;
                    if (daysSinceUpdate > 14)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"{dbPath.Value} Signatures Not Updated in {daysSinceUpdate:F0} Days",
                            Risk = daysSinceUpdate > 30 ? Risk.High : Risk.Medium,
                            Location = dbPath.Key,
                            FileName = Path.GetFileName(dbPath.Key),
                            Reason = $"{dbPath.Value} signature database not updated in {daysSinceUpdate:F0} days — outdated AV may miss recent cheat tools",
                            Detail = $"Newest file in database dir: {newest:u}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);
}
