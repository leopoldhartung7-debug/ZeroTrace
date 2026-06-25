using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class EtwBypassTelemetryScanModule : IScanModule
{
    public string Name => "ETW Bypass & Telemetry Evasion Detection";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32Dir =
        Path.Combine(WinDir, "System32");

    private static readonly string[] EtwPatchTokens =
    {
        "[reflection.assembly]",
        "amsiutils",
        "etweventwrite",
        "etweventwritefull",
        "nttracevent",
        "system.diagnostics.eventing",
        "etwpcreateetwthread",
        "etwnotificationregister",
        "etwenablecallback",
        "etweventregister",
        "[runtime.interopservices.marshal]",
        "0xc3",
        "ret_patch",
        "patch_etw",
        "ntdll.etwEventWrite",
        "amsi.dll",
        "amsiscanbuffer",
        "amsiopenssession",
        "disableamsi",
        "bypas",
        "bypassamsi",
        "amsibypass",
        "disableetw",
        "patchetw",
        "hooketw",
        "etwhook",
        "etwbypass",
        "[system.reflection.assembly]",
        "getmethod",
        "setvalue",
        "getfield",
        "nonpublic",
        "staticgetfield",
        "fieldinfo",
        "bindingflags",
        "writeprocessmemory",
        "virtualprotect",
    };

    private static readonly string[] MpCmdRunAbuse =
    {
        "mpcmdrun -removedefinitions",
        "mpcmdrun -disablerealtimemonitoring",
        "mpcmdrun.exe -removedefinitions",
        "mpcmdrun.exe -disablerealtimemonitoring",
        "mpcmdrun -ufe",
        "mpcmdrun -removeallquarantinedfiles",
        "removedefinitions -all",
        "removedefinitions -dynamicsignatures",
    };

    private static readonly string[] TraceCleanupTokens =
    {
        "tracerpt.exe",
        "tracerpt ",
        "logman delete",
        "logman stop",
        "logman.exe delete",
        "wevtutil cl ",
        "wevtutil.exe cl ",
        "clear-eventlog",
        "remove-eventlog",
        "auditpol /clear",
        "auditpol.exe /clear",
        "fsutil usn deletejournal",
    };

    private static readonly string[] DefenderDisableTokens =
    {
        "set-mppreference -disablerealtimemonitoring",
        "set-mppreference -disablebehaviormonitoring",
        "set-mppreference -disableonaccessprotection",
        "set-mppreference -disableioavprotection",
        "set-mppreference -disablescriptscanning",
        "set-mppreference -disablearchivescanning",
        "set-mppreference -disablescanningnetworkfiles",
        "set-mppreference -disableantispyware",
        "set-mppreference -signatureupdateinterval 0",
        "add-mppreference -exclusionpath",
        "add-mppreference -exclusionprocess",
        "add-mppreference -exclusionextension",
        "sc stop windefend",
        "sc config windefend start= disabled",
        "net stop windefend",
        "sc delete windefend",
    };

    private static readonly string[] ThirdPartyAvServices =
    {
        "malwarebytes",
        "mbam",
        "mbamservice",
        "eset",
        "ekrn",
        "egui",
        "kaspersky",
        "avp",
        "klwtpsk",
        "bdagent",
        "bitdefender",
        "avira",
        "avgnt",
        "avast",
        "avastsvc",
        "avg",
        "avgwdsvc",
        "norton",
        "symantec",
        "ccsvchst",
        "mcafee",
        "mcshield",
        "f-secure",
        "fsavd",
        "fswa",
        "sophos",
        "savservice",
        "cybereason",
        "crowdstrike",
        "csfalconservice",
        "sentinelone",
        "sentinelservice",
        "trendmicro",
        "tmccsf",
        "comodo",
        "cmdagent",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanPsHistoryFilesAsync(ctx, ct);
        ctx.Report(0.20, "PS History", "PowerShell history ETW patterns scanned");

        await ScanPsScriptFilesAsync(ctx, ct);
        ctx.Report(0.38, "PS Scripts", "PowerShell script files scanned");

        await ScanNtdllCopiesAsync(ctx, ct);
        ctx.Report(0.50, "ntdll copies", "Out-of-system ntdll copies checked");

        ScanEtwAutologgerRegistry(ctx, ct);
        ctx.Report(0.62, "ETW Autologger", "ETW autologger registry checked");

        ScanScriptBlockLoggingRegistry(ctx, ct);
        ctx.Report(0.72, "PS Logging", "PowerShell logging policy registry checked");

        ScanDefenderRegistry(ctx, ct);
        ctx.Report(0.82, "Defender", "Windows Defender registry checked");

        ScanTelemetryServiceRegistry(ctx, ct);
        ctx.Report(0.92, "Telemetry", "Diagnostic/telemetry service registry checked");

        ScanThirdPartyAvRegistry(ctx, ct);
        ctx.Report(1.00, "AV services", "Third-party AV service registry checked");
    }

    private async Task ScanPsHistoryFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var historyRoots = new List<string>();

        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        historyRoots.Add(Path.Combine(roaming, "Microsoft", "Windows", "PowerShell", "PSReadLine"));

        var usersDir = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        if (!string.IsNullOrEmpty(usersDir) && Directory.Exists(usersDir))
        {
            try
            {
                foreach (var userDir in Directory.EnumerateDirectories(usersDir))
                {
                    ct.ThrowIfCancellationRequested();
                    var candidate = Path.Combine(userDir, "AppData", "Roaming", "Microsoft",
                        "Windows", "PowerShell", "PSReadLine");
                    if (Directory.Exists(candidate))
                        historyRoots.Add(candidate);
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        foreach (var histDir in historyRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(histDir)) continue;

            string[] files;
            try { files = Directory.GetFiles(histDir, "ConsoleHost_history.txt"); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var histFile in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                await ScanPsHistoryFileAsync(histFile, ctx, ct);
            }
        }
    }

    private async Task ScanPsHistoryFileAsync(string path, ScanContext ctx, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        if (string.IsNullOrWhiteSpace(content)) return;

        var lower = content.ToLowerInvariant();
        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        var etwHits = new List<string>();
        var mpHits = new List<string>();
        var traceHits = new List<string>();
        var defHits = new List<string>();

        foreach (var rawLine in lines)
        {
            ct.ThrowIfCancellationRequested();
            var line = rawLine.Trim();
            if (string.IsNullOrEmpty(line)) continue;
            var lineLow = line.ToLowerInvariant();

            foreach (var token in EtwPatchTokens)
            {
                if (lineLow.Contains(token, StringComparison.OrdinalIgnoreCase) && etwHits.Count < 8)
                {
                    etwHits.Add(Truncate(line, 180));
                    break;
                }
            }

            foreach (var token in MpCmdRunAbuse)
            {
                if (lineLow.Contains(token, StringComparison.OrdinalIgnoreCase) && mpHits.Count < 5)
                {
                    mpHits.Add(Truncate(line, 180));
                    break;
                }
            }

            foreach (var token in TraceCleanupTokens)
            {
                if (lineLow.Contains(token, StringComparison.OrdinalIgnoreCase) && traceHits.Count < 5)
                {
                    traceHits.Add(Truncate(line, 180));
                    break;
                }
            }

            foreach (var token in DefenderDisableTokens)
            {
                if (lineLow.Contains(token, StringComparison.OrdinalIgnoreCase) && defHits.Count < 5)
                {
                    defHits.Add(Truncate(line, 180));
                    break;
                }
            }
        }

        if (etwHits.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "ETW/AMSI bypass patterns in PowerShell history",
                Risk = RiskLevel.Critical,
                Location = path,
                FileName = Path.GetFileName(path),
                Reason = "PowerShell history contains commands consistent with ETW Event Tracing " +
                         "or AMSI patching via reflection. These techniques disable Windows security " +
                         "telemetry and antimalware scanning to blind monitoring tools.",
                Detail = "Matched lines: " + string.Join(" | ", etwHits)
            });
        }

        if (mpHits.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "MpCmdRun.exe abuse in PowerShell history",
                Risk = RiskLevel.High,
                Location = path,
                FileName = Path.GetFileName(path),
                Reason = "PowerShell history contains Windows Defender command-line tool (MpCmdRun.exe) " +
                         "invocations with arguments used to remove definitions or disable real-time " +
                         "protection. This is a common cheat loader preparation step.",
                Detail = "Matched lines: " + string.Join(" | ", mpHits)
            });
        }

        if (traceHits.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Event log / trace cleanup in PowerShell history",
                Risk = RiskLevel.High,
                Location = path,
                FileName = Path.GetFileName(path),
                Reason = "PowerShell history contains commands used to delete Windows event logs, " +
                         "USN journals, or ETW trace sessions. Cheats use these to erase evidence " +
                         "of their execution from the security audit trail.",
                Detail = "Matched lines: " + string.Join(" | ", traceHits)
            });
        }

        if (defHits.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Windows Defender disable commands in PowerShell history",
                Risk = RiskLevel.Critical,
                Location = path,
                FileName = Path.GetFileName(path),
                Reason = "PowerShell history contains Set-MpPreference, Add-MpPreference, or " +
                         "service-control commands used to disable Windows Defender real-time " +
                         "protection, behaviour monitoring, or exclusion manipulation.",
                Detail = "Matched lines: " + string.Join(" | ", defHits)
            });
        }
    }

    private async Task ScanPsScriptFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var scriptRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Path.GetTempPath(),
            Path.Combine(WinDir, "Temp"),
        };

        int scanned = 0;
        const int MaxScriptFiles = 400;

        foreach (var root in scriptRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.ps1", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                if (++scanned > MaxScriptFiles) break;
                ctx.IncrementFiles();

                await ScanPsScriptFileAsync(file, ctx, ct);
            }
        }
    }

    private async Task ScanPsScriptFileAsync(string path, ScanContext ctx, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        if (string.IsNullOrWhiteSpace(content) || content.Length < 20) return;

        var lower = content.ToLowerInvariant();

        var etwMatches = EtwPatchTokens
            .Where(t => lower.Contains(t, StringComparison.OrdinalIgnoreCase))
            .Take(5)
            .ToList();

        if (etwMatches.Count >= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"ETW/AMSI bypass script: {Path.GetFileName(path)}",
                Risk = RiskLevel.Critical,
                Location = path,
                FileName = Path.GetFileName(path),
                Reason = "PowerShell script file contains multiple ETW patching or AMSI bypass " +
                         "keywords. Such scripts use .NET reflection to patch ntdll.dll ETW functions " +
                         "or amsi.dll in memory, disabling security event telemetry for all processes " +
                         "in the session.",
                Detail = "Matched tokens: " + string.Join(", ", etwMatches)
            });
            return;
        }

        var defMatches = DefenderDisableTokens
            .Where(t => lower.Contains(t, StringComparison.OrdinalIgnoreCase))
            .Take(5)
            .ToList();

        if (defMatches.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Defender disable script: {Path.GetFileName(path)}",
                Risk = RiskLevel.High,
                Location = path,
                FileName = Path.GetFileName(path),
                Reason = "PowerShell script contains commands to disable Windows Defender " +
                         "real-time protection or add exclusions. Used by cheat loaders to prevent " +
                         "detection before dropping payload files.",
                Detail = "Matched tokens: " + string.Join(", ", defMatches)
            });
        }
    }

    private async Task ScanNtdllCopiesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
            Path.Combine(WinDir, "Temp"),
        };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "ntdll.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                if (filePath.StartsWith(System32Dir, StringComparison.OrdinalIgnoreCase))
                    continue;

                var syswowDir = Path.Combine(WinDir, "SysWOW64");
                if (filePath.StartsWith(syswowDir, StringComparison.OrdinalIgnoreCase))
                    continue;

                ctx.IncrementFiles();

                bool suspectContent = await CheckNtdllPatchSignaturesAsync(filePath, ct);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"ntdll.dll copy outside System32: {filePath}",
                    Risk = suspectContent ? RiskLevel.Critical : RiskLevel.High,
                    Location = filePath,
                    FileName = "ntdll.dll",
                    Reason = suspectContent
                        ? "A copy of ntdll.dll was found outside System32 with byte patterns " +
                          "suggesting ETW function patching (RET stub or NOP sled at function entry). " +
                          "Cheats replace ntdll in their process load path to blind ETW-based security tools."
                        : "A copy of ntdll.dll was found outside the Windows System32 directory. " +
                          "Cheats sometimes place a patched ntdll.dll in an application directory so " +
                          "the loader picks it up before the real system copy, disabling ETW telemetry.",
                    Detail = suspectContent ? "Patch byte patterns detected in file content" : null
                });
            }
        }
    }

    private static async Task<bool> CheckNtdllPatchSignaturesAsync(string path, CancellationToken ct)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buf = new byte[Math.Min(fs.Length, 65536)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);

            for (int i = 0; i < read - 4; i++)
            {
                if (buf[i] == 0xC3 && buf[i + 1] == 0xC3 && buf[i + 2] == 0xC3)
                    return true;
                if (buf[i] == 0x90 && buf[i + 1] == 0x90 && buf[i + 2] == 0x90 &&
                    buf[i + 3] == 0x90 && i + 8 < read)
                    return true;
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        return false;
    }

    private void ScanEtwAutologgerRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string AutologgerKey = @"SYSTEM\CurrentControlSet\Control\WMI\Autologger";

        var criticalProviderGuids = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}",
            "{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}",
            "{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "{8c416c79-d49b-4f01-a467-e56d3aa8234c}",
            "{16c6501a-ff2d-46ea-868d-8f96cb0cb52d}",
            "{751ef305-6c6e-4fed-b847-02ef79d26aef}",
            "{b7af0f4c-48a4-4e0a-a935-04e7e69e9e5f}",
            "{f8f10121-b617-4a56-868b-9df1b27fe32c}",
            "{85cd1a3d-14f0-4e06-a1ab-27f7b4e56e01}",
            "{9580d7dd-0379-4658-9870-d5be7d52d6de}",
            "{331c3b3a-2005-44c2-ac5e-77220c37d6b4}",
            "{e8109b99-3a2c-4961-aa83-d1a7a148ada8}",
            "{e4af8e82-3c4a-4b0b-bb3e-1b7f55fde5f7}",
        };

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var autologgerRoot = baseKey.OpenSubKey(AutologgerKey, writable: false);
            if (autologgerRoot is null) return;

            foreach (var sessionName in autologgerRoot.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                using var sessionKey = autologgerRoot.OpenSubKey(sessionName, writable: false);
                if (sessionKey is null) continue;

                var sessionStart = sessionKey.GetValue("Start");
                if (sessionStart is int sessionStartInt && sessionStartInt == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"ETW Autologger session disabled: {sessionName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{AutologgerKey}\{sessionName}",
                        Reason = $"The ETW autologger session '{sessionName}' has Start=0 (disabled). " +
                                 "Autologger sessions configured to not start prevent Windows from " +
                                 "collecting security and diagnostic events at boot. Cheats modify " +
                                 "these settings to prevent their actions from being logged.",
                        Detail = $"Session: {sessionName} · Start value: {sessionStartInt}"
                    });
                }

                foreach (var providerGuid in sessionKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    using var providerKey = sessionKey.OpenSubKey(providerGuid, writable: false);
                    if (providerKey is null) continue;

                    var enabled = providerKey.GetValue("Enabled");
                    bool isCritical = criticalProviderGuids.Contains(providerGuid);

                    if (enabled is int enabledInt && enabledInt == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Critical ETW provider disabled in autologger",
                            Risk = isCritical ? RiskLevel.High : RiskLevel.Medium,
                            Location = $@"HKLM\{AutologgerKey}\{sessionName}\{providerGuid}",
                            Reason = $"ETW provider GUID '{providerGuid}' in autologger session " +
                                     $"'{sessionName}' has Enabled=0. " +
                                     (isCritical
                                         ? "This is a known critical security/telemetry provider. "
                                         : "") +
                                     "Disabling ETW providers suppresses security event collection " +
                                     "and can blind endpoint detection tools.",
                            Detail = $"Provider GUID: {providerGuid} · Session: {sessionName}"
                        });
                    }
                }
            }
        }
        catch { }

        const string TracingKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var tracingKey = baseKey.OpenSubKey(TracingKey, writable: false);
            if (tracingKey is null) return;
            ctx.IncrementRegistryKeys();

            foreach (var componentName in tracingKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                using var componentKey = tracingKey.OpenSubKey(componentName, writable: false);
                if (componentKey is null) continue;

                var active = componentKey.GetValue("Active");
                if (active is int activeInt && activeInt == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Windows Tracing component deactivated: {componentName}",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKLM\{TracingKey}\{componentName}",
                        Reason = $"The Windows tracing component '{componentName}' has Active=0. " +
                                 "Systematic deactivation of tracing components is used by advanced " +
                                 "cheat software to reduce security telemetry visibility.",
                        Detail = $"Component: {componentName}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanScriptBlockLoggingRegistry(ScanContext ctx, CancellationToken ct)
    {
        var policyPaths = new[]
        {
            (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"),
            (RegistryHive.CurrentUser,  @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"),
            (RegistryHive.CurrentUser,  @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"),
            (RegistryHive.CurrentUser,  @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"),
        };

        foreach (var (hive, keyPath) in policyPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                var hiveName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                var keyLeaf = keyPath.Split('\\').Last();

                if (keyLeaf.Equals("ScriptBlockLogging", StringComparison.OrdinalIgnoreCase))
                {
                    var val = key.GetValue("EnableScriptBlockLogging");
                    if (val is int v && v == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "PowerShell Script Block Logging disabled via policy",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}\EnableScriptBlockLogging",
                            Reason = "EnableScriptBlockLogging=0 in PowerShell policy prevents Windows " +
                                     "from recording executed PowerShell script blocks in the event log " +
                                     "(Event ID 4104). This disables the primary forensic trail for " +
                                     "malicious PowerShell activity including cheat loaders and ETW bypass scripts.",
                            Detail = $"Key: {hiveName}\\{keyPath}"
                        });
                    }

                    var invLog = key.GetValue("EnableScriptBlockInvocationLogging");
                    if (invLog is int il && il == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "PowerShell invocation logging explicitly disabled",
                            Risk = RiskLevel.Medium,
                            Location = $@"{hiveName}\{keyPath}\EnableScriptBlockInvocationLogging",
                            Reason = "EnableScriptBlockInvocationLogging=0 suppresses the start/stop " +
                                     "events for script block execution, further reducing PowerShell audit coverage.",
                            Detail = $"Key: {hiveName}\\{keyPath}"
                        });
                    }
                }

                if (keyLeaf.Equals("ModuleLogging", StringComparison.OrdinalIgnoreCase))
                {
                    var val = key.GetValue("EnableModuleLogging");
                    if (val is int v && v == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "PowerShell Module Logging disabled via policy",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}\EnableModuleLogging",
                            Reason = "EnableModuleLogging=0 prevents Windows from logging which PowerShell " +
                                     "modules and commands are executed. This hides the command pipeline " +
                                     "used by download cradles and cheat loader scripts.",
                            Detail = $"Key: {hiveName}\\{keyPath}"
                        });
                    }
                }

                if (keyLeaf.Equals("Transcription", StringComparison.OrdinalIgnoreCase))
                {
                    var val = key.GetValue("EnableTranscripting");
                    if (val is int v && v == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "PowerShell Transcription logging disabled via policy",
                            Risk = RiskLevel.Medium,
                            Location = $@"{hiveName}\{keyPath}\EnableTranscripting",
                            Reason = "PowerShell transcription is explicitly disabled by policy. " +
                                     "While transcription is opt-in by default, explicitly setting it " +
                                     "to disabled via Group Policy prevents administrators from enabling " +
                                     "it and may indicate tampering with audit configuration.",
                            Detail = $"Key: {hiveName}\\{keyPath}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private void ScanDefenderRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string WdPolicyKey = @"SOFTWARE\Policies\Microsoft\Windows Defender";
        const string WdKey = @"SOFTWARE\Microsoft\Windows Defender";
        const string WdExclusionsKey = @"SOFTWARE\Microsoft\Windows Defender\Exclusions";
        const string WdSigUpdatesKey = @"SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates";

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);

            using var wdPolicy = baseKey.OpenSubKey(WdPolicyKey, writable: false);
            if (wdPolicy is not null)
            {
                ctx.IncrementRegistryKeys();

                var disableAntiSpyware = wdPolicy.GetValue("DisableAntiSpyware");
                if (disableAntiSpyware is int das && das == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Defender antispyware disabled via Group Policy",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{WdPolicyKey}\DisableAntiSpyware",
                        Reason = "DisableAntiSpyware=1 in the Windows Defender policy key completely " +
                                 "disables Windows Defender. This setting is used by cheat loaders to " +
                                 "prevent their files and processes from being detected or blocked.",
                        Detail = "Value: DisableAntiSpyware = 1"
                    });
                }

                var disableRealtime = wdPolicy.GetValue("DisableRealtimeMonitoring");
                if (disableRealtime is int drm && drm == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Defender real-time monitoring disabled via policy",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{WdPolicyKey}\DisableRealtimeMonitoring",
                        Reason = "DisableRealtimeMonitoring=1 in the Windows Defender policy key " +
                                 "disables on-access file scanning. Cheat loaders set this to prevent " +
                                 "their dropped executables from being quarantined on write.",
                        Detail = "Value: DisableRealtimeMonitoring = 1"
                    });
                }

                var disableBehaviour = wdPolicy.GetValue("DisableBehaviorMonitoring");
                if (disableBehaviour is int dbm && dbm == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Defender behaviour monitoring disabled via policy",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{WdPolicyKey}\DisableBehaviorMonitoring",
                        Reason = "DisableBehaviorMonitoring=1 disables Windows Defender heuristic " +
                                 "behaviour analysis. Without this layer, injection, process hollowing, " +
                                 "and cheat memory manipulation are not flagged at runtime.",
                        Detail = "Value: DisableBehaviorMonitoring = 1"
                    });
                }

                var disableIoav = wdPolicy.GetValue("DisableIOAVProtection");
                if (disableIoav is int diav && diav == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Defender IOAV protection disabled via policy",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{WdPolicyKey}\DisableIOAVProtection",
                        Reason = "DisableIOAVProtection=1 disables scanning of internet-downloaded files " +
                                 "and attachments at point of opening. This prevents Defender from " +
                                 "catching cheat binaries downloaded from distribution sites.",
                        Detail = "Value: DisableIOAVProtection = 1"
                    });
                }

                var disableScript = wdPolicy.GetValue("DisableScriptScanning");
                if (disableScript is int dss && dss == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Defender script scanning disabled via policy",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{WdPolicyKey}\DisableScriptScanning",
                        Reason = "DisableScriptScanning=1 prevents Windows Defender from scanning " +
                                 "scripts at execution time. ETW bypass and cheat loader PowerShell " +
                                 "scripts are not detected with this setting active.",
                        Detail = "Value: DisableScriptScanning = 1"
                    });
                }

                var disableSampling = wdPolicy.GetValue("SpyNetReporting");
                if (disableSampling is int snr && snr == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Defender cloud reporting disabled via policy",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKLM\{WdPolicyKey}\SpyNetReporting",
                        Reason = "SpyNetReporting=0 disables Microsoft Active Protection Service " +
                                 "(MAPS) cloud lookup. This prevents Defender from identifying zero-day " +
                                 "cheat signatures that rely on cloud reputation databases.",
                        Detail = "Value: SpyNetReporting = 0"
                    });
                }
            }

            using var wdExclPaths = baseKey.OpenSubKey(WdExclusionsKey + @"\Paths", writable: false);
            if (wdExclPaths is not null)
            {
                ctx.IncrementRegistryKeys();
                var exclusionNames = wdExclPaths.GetValueNames();

                if (exclusionNames.Length > 10)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Excessive Windows Defender path exclusions: {exclusionNames.Length} entries",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{WdExclusionsKey}\Paths",
                        Reason = $"Windows Defender has {exclusionNames.Length} path exclusions configured. " +
                                 "More than 10 exclusions is unusual for a gaming PC and is a common " +
                                 "technique to hide cheat tool directories from on-access scanning.",
                        Detail = "First 5 excluded paths: " +
                                 string.Join(", ", exclusionNames.Take(5))
                    });
                }
                else
                {
                    foreach (var excl in exclusionNames)
                    {
                        var lowExcl = excl.ToLowerInvariant();
                        if (lowExcl.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            lowExcl.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                            lowExcl.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                            lowExcl.Contains("loader", StringComparison.OrdinalIgnoreCase) ||
                            lowExcl.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            lowExcl.Contains("spoof", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Defender path exclusion: {excl}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{WdExclusionsKey}\Paths",
                                Reason = "A Windows Defender path exclusion contains keywords " +
                                         "associated with cheat tools (cheat, hack, inject, loader, " +
                                         "bypass, spoof). This exclusion was likely added to protect " +
                                         "a cheat installation from antivirus detection.",
                                Detail = $"Excluded path: {excl}"
                            });
                        }
                    }
                }
            }

            using var wdExclProcs = baseKey.OpenSubKey(WdExclusionsKey + @"\Processes", writable: false);
            if (wdExclProcs is not null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var proc in wdExclProcs.GetValueNames())
                {
                    var procLow = proc.ToLowerInvariant();
                    if (procLow.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        procLow.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                        procLow.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                        procLow.Contains("loader", StringComparison.OrdinalIgnoreCase) ||
                        procLow.Contains("trainer", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious Defender process exclusion: {proc}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{WdExclusionsKey}\Processes",
                            Reason = "A Windows Defender process exclusion contains keywords " +
                                     "associated with cheat tools. Excluded processes are never " +
                                     "scanned by Defender even when performing suspicious operations.",
                            Detail = $"Excluded process: {proc}"
                        });
                    }
                }
            }

            using var wdSigKey = baseKey.OpenSubKey(WdSigUpdatesKey, writable: false);
            if (wdSigKey is not null)
            {
                ctx.IncrementRegistryKeys();

                var forceUpdate = wdSigKey.GetValue("ForceUpdateFromMU");
                if (forceUpdate is int fu && fu == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Defender signature update from Microsoft Update blocked",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{WdSigUpdatesKey}\ForceUpdateFromMU",
                        Reason = "ForceUpdateFromMU=0 prevents Windows Defender from obtaining " +
                                 "signature updates from Microsoft Update. Keeping Defender on stale " +
                                 "signatures is a technique to maintain an undetected cheat over time.",
                        Detail = "Value: ForceUpdateFromMU = 0"
                    });
                }

                var disableOnBattery = wdSigKey.GetValue("DisableScheduledSignatureUpdateOnBattery");
                if (disableOnBattery is int dosb && dosb == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Defender signature updates disabled on battery via policy",
                        Risk = RiskLevel.Low,
                        Location = $@"HKLM\{WdSigUpdatesKey}\DisableScheduledSignatureUpdateOnBattery",
                        Reason = "DisableScheduledSignatureUpdateOnBattery=1 combined with other " +
                                 "update blocks may result in consistently stale Defender signatures.",
                        Detail = "Value: DisableScheduledSignatureUpdateOnBattery = 1"
                    });
                }
            }
        }
        catch { }

        const string WerKey = @"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var werKey = baseKey.OpenSubKey(WerKey, writable: false);
            if (werKey is null) return;
            ctx.IncrementRegistryKeys();

            var disabled = werKey.GetValue("Disabled");
            if (disabled is int d && d == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Windows Error Reporting disabled via policy",
                    Risk = RiskLevel.Medium,
                    Location = $@"HKLM\{WerKey}\Disabled",
                    Reason = "Windows Error Reporting is disabled via Group Policy. WER generates " +
                             "crash dumps and telemetry that Microsoft uses to identify crashing cheat " +
                             "software. Disabling it prevents crash reports that could expose cheat activity.",
                    Detail = "Value: Disabled = 1"
                });
            }
        }
        catch { }
    }

    private void ScanTelemetryServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        var telemetryServices = new[]
        {
            (@"SYSTEM\CurrentControlSet\Services\DiagTrack",
             "DiagTrack",
             "Connected User Experiences and Telemetry service",
             RiskLevel.Medium),
            (@"SYSTEM\CurrentControlSet\Services\dmwappushservice",
             "dmwappushservice",
             "WAP Push Message Routing Service (telemetry pipeline)",
             RiskLevel.Low),
            (@"SYSTEM\CurrentControlSet\Services\WerSvc",
             "WerSvc",
             "Windows Error Reporting Service",
             RiskLevel.Medium),
            (@"SYSTEM\CurrentControlSet\Services\WerFaultSecure",
             "WerFaultSecure",
             "Windows Error Reporting secure crash reporting",
             RiskLevel.Low),
            (@"SYSTEM\CurrentControlSet\Services\PcaSvc",
             "PcaSvc",
             "Program Compatibility Assistant (execution telemetry)",
             RiskLevel.Low),
            (@"SYSTEM\CurrentControlSet\Services\CDPSvc",
             "CDPSvc",
             "Connected Devices Platform Service",
             RiskLevel.Low),
        };

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);

            foreach (var (keyPath, serviceName, description, baseRisk) in telemetryServices)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    using var svcKey = baseKey.OpenSubKey(keyPath, writable: false);
                    if (svcKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    var startVal = svcKey.GetValue("Start");
                    if (startVal is int sv && sv == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Telemetry/diagnostic service disabled: {serviceName}",
                            Risk = baseRisk,
                            Location = $@"HKLM\{keyPath}\Start",
                            Reason = $"The Windows service '{serviceName}' ({description}) has " +
                                     "Start=4 (disabled). While some users disable telemetry for " +
                                     "privacy, comprehensive disabling of all diagnostic services " +
                                     "combined with other findings is consistent with anti-detection " +
                                     "preparation for cheat software.",
                            Detail = $"Service: {serviceName} · Start = 4 (Disabled)"
                        });
                    }
                }
                catch { }
            }

            const string TelemetryGpKey = @"SOFTWARE\Policies\Microsoft\Windows\DataCollection";
            try
            {
                using var dcKey = baseKey.OpenSubKey(TelemetryGpKey, writable: false);
                if (dcKey is not null)
                {
                    ctx.IncrementRegistryKeys();
                    var allowTelemetry = dcKey.GetValue("AllowTelemetry");
                    if (allowTelemetry is int at && at == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows telemetry collection disabled via policy",
                            Risk = RiskLevel.Low,
                            Location = $@"HKLM\{TelemetryGpKey}\AllowTelemetry",
                            Reason = "AllowTelemetry=0 in Group Policy disables all Windows diagnostic " +
                                     "data collection. Combined with other ETW bypass findings, this " +
                                     "contributes to a pattern of systematic security telemetry suppression.",
                            Detail = "Value: AllowTelemetry = 0"
                        });
                    }
                }
            }
            catch { }
        }
        catch { }
    }

    private void ScanThirdPartyAvRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string ServicesRoot = @"SYSTEM\CurrentControlSet\Services";

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var svcRoot = baseKey.OpenSubKey(ServicesRoot, writable: false);
            if (svcRoot is null) return;

            var disabledAvServices = new List<string>();

            foreach (var svcName in svcRoot.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();

                var svcLow = svcName.ToLowerInvariant();
                bool isAvService = ThirdPartyAvServices.Any(av =>
                    svcLow.Contains(av, StringComparison.OrdinalIgnoreCase));
                if (!isAvService) continue;

                try
                {
                    using var svcKey = svcRoot.OpenSubKey(svcName, writable: false);
                    if (svcKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    var startVal = svcKey.GetValue("Start");
                    if (startVal is int sv && sv == 4)
                    {
                        disabledAvServices.Add(svcName);
                    }
                }
                catch { }
            }

            if (disabledAvServices.Count > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Third-party antivirus services disabled: {disabledAvServices.Count} found",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{ServicesRoot}",
                    Reason = "One or more third-party antivirus or endpoint security service(s) have " +
                             "Start=4 (disabled) in the registry. Cheats and their loaders commonly " +
                             "disable competing security products to prevent detection and removal.",
                    Detail = "Disabled AV services: " + string.Join(", ", disabledAvServices)
                });
            }
        }
        catch { }
    }

    private static string Truncate(string s, int max)
        => s.Length <= max ? s : s[..max] + "…";
}
