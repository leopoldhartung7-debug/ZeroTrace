using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AntiDebugBypassArtifactScanModule : IScanModule
{
    public string Name => "Anti-Debug Bypass Artifact Detection";
    public double Weight => 4.1;
    public int ParallelGroup => 4;

    // ── Known anti-debug bypass tool executables and DLLs ────────────────────

    private static readonly HashSet<string> KnownBypassToolNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // ScyllaHide family
        "ScyllaHide.exe",
        "ScyllaHide64.dll",
        "scyllahide.dll",
        "scyllahide.dp64",
        "scyllahide.dp32",
        "HideDebugger.dp64",
        "HideDebugger.dp32",
        "antidetect.dp64",
        "antidetect.dp32",
        // TitanHide
        "TitanHide.exe",
        "titanHide.sys",
        "titanhide.sys",
        // OllyDbg plugins / forks
        "OllyAdvanced.exe",
        "OllyDump.exe",
        "OllyExt.dll",
        "PhantomOlly.exe",
        "StrongOD.dll",
        "NtHideOS.sys",
        // IDA Pro bypass plugins (no legitimate name; keyword pattern applied separately)
        "ida_bypass.dll",
        "ida_hide.dll",
        // ReClass.NET memory structure mapping tool
        "ReClass.NET.exe",
        "ReClass64.exe",
        "ReClass.exe",
        // Cheat Engine related kernel bypass artifacts
        "DBKernel.sys",
        "DBK64.sys",
        "cedriver64.sys",
        "cheatengine-x86_64.exe",
        "cheatengine-i386.exe",
        // PE analysis / reconstruction tools
        "PE-bear.exe",
        "pe-sieve.exe",
        "pe_sieve64.exe",
        "pe_sieve32.exe",
        // Frida dynamic instrumentation
        "frida-server.exe",
        "frida-gadget.dll",
        "frida-trace.exe",
        "frida-inject.exe",
        "frida.exe",
        // x64dbg plugins dir items
        "antidbg.dp64",
        "HideOD.dll",
        // misc bypass utilities
        "x64dbg_bypass.dll",
        "dbg_hide.exe",
        "AntiDetect.exe",
        "AntiDetection.exe",
        "bypass_debugger.exe",
        "debugger_hide.exe",
        "stealth_dbg.exe",
        "ProcessHide.exe",
        "KernelHide.exe",
        "NtHide.exe",
    };

    // ── Known .rcnet project file extension ──────────────────────────────────

    private static readonly HashSet<string> KnownBypassExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".rcnet",
        ".dp64",
        ".dp32",
    };

    // ── Config keys indicating IsDebuggerPresent / NtQueryInformationProcess bypass ──

    private static readonly string[] IsDebuggerPresentConfigKeys =
    {
        "patch_debugger_check=true",
        "bypass_debugger_detection=true",
        "anti_debug_bypass=true",
        "debugger_check_bypass=true",
        "patch_isdebugger=true",
        "isdebuggerPresent_bypass=true",
        "is_debugger_present_bypass=true",
        "bypass_isdebuggerpresent=true",
        "ntqueryinformationprocess_bypass=true",
        "processdebugport=0",
        "patch_debugport=true",
        "debugport_bypass=true",
        "bypass_processdebugport=true",
        "ntquery_bypass=true",
    };

    // ── Config keys indicating timing attack bypass ───────────────────────────

    private static readonly string[] TimingBypassConfigKeys =
    {
        "bypass_timing_check=true",
        "rdtsc_bypass=true",
        "timing_bypass=true",
        "gettickcount_hook=true",
        "queryperformancecounter_bypass=true",
        "qpc_bypass=true",
        "qpc_hook=true",
        "gettickcount_bypass=true",
        "tickcount_hook=true",
        "bypass_rdtsc=true",
        "timing_check_bypass=true",
        "anti_timing=true",
        "fake_tickcount=true",
        "fake_qpc=true",
    };

    // ── Config keys indicating exception-based anti-debug bypass ─────────────

    private static readonly string[] ExceptionBypassConfigKeys =
    {
        "bypass_int3=true",
        "exception_bypass=true",
        "veh_abuse=true",
        "addvectoredexceptionhandler=true",
        "bypass_int1=true",
        "single_step_bypass=true",
        "drx_bypass=true",
        "hardware_breakpoint_bypass=true",
        "debug_register_bypass=true",
        "exception_filter_bypass=true",
        "bypass_exception_check=true",
        "seh_bypass=true",
        "veh_bypass=true",
        "bypass_veh=true",
    };

    // ── Config keys indicating heap flag evasion ─────────────────────────────

    private static readonly string[] HeapBypassConfigKeys =
    {
        "patch_heap_flags=true",
        "ntglobalflag_bypass=true",
        "heap_bypass=true",
        "patch_ntglobalflag=true",
        "ntglobal_flag_bypass=true",
        "heapflags_bypass=true",
        "forceflags_bypass=true",
        "bypass_heap=true",
        "heap_flag_bypass=true",
        "debug_heap_bypass=true",
        "bypass_ntglobalflag=true",
    };

    // ── Code / source artifact strings (detect bypass source embedded in files) ─

    private static readonly string[] IsDebuggerPresentCodeArtifacts =
    {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "ProcessDebugPort",
        "ProcessDebugFlags",
        "NtSetInformationThread",
        "ThreadHideFromDebugger",
        "patch_debugger",
        "debugger_bypass",
        "bypass_debugger",
    };

    private static readonly string[] TimingCodeArtifacts =
    {
        "GetTickCount",
        "QueryPerformanceCounter",
        "rdtsc_bypass",
        "timing_bypass",
        "fake_tickcount",
        "fake_qpc",
        "hook_gettickcount",
        "hook_qpc",
        "constant_tick",
    };

    private static readonly string[] ExceptionCodeArtifacts =
    {
        "AddVectoredExceptionHandler",
        "SetUnhandledExceptionFilter",
        "bypass_int3",
        "bypass_int1",
        "single_step_bypass",
        "dr0_bypass",
        "debug_register_clear",
        "veh_bypass",
        "seh_bypass",
    };

    private static readonly string[] HeapCodeArtifacts =
    {
        "NtGlobalFlag",
        "HeapFlags",
        "ForceFlags",
        "patch_ntglobalflag",
        "ntglobalflag_bypass",
        "heap_flag_patch",
        "debug_heap_evasion",
    };

    // ── Directories to scan ───────────────────────────────────────────────────

    private static readonly string[] ScanRootEnvVars =
    {
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
    };

    // ── x64dbg plugin directory fragments ────────────────────────────────────

    private static readonly string[] X64DbgPluginDirFragments =
    {
        "x64dbg",
        "x32dbg",
        "x96dbg",
    };

    // ── IDA Pro plugin directory fragments ───────────────────────────────────

    private static readonly string[] IdaPluginDirFragments =
    {
        "IDA Pro",
        "IDA_Pro",
        "IDAPRO",
        "idapro",
        "IDA\\plugins",
        "ida64\\plugins",
    };

    // ── File extensions considered for config/source scanning ─────────────────

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cfg", ".config", ".ini", ".conf", ".json", ".xml", ".yaml", ".yml",
        ".txt", ".log", ".bat", ".cmd", ".ps1", ".py", ".lua", ".js",
        ".cs", ".cpp", ".h", ".c", ".asm", ".nasm",
        ".au3", ".ahk", ".rb", ".php",
    };

    // ── PowerShell / console history key strings ──────────────────────────────

    private static readonly string[] PsHistoryBypassTerms =
    {
        "NtGlobalFlag",
        "HeapFlags",
        "ScyllaHide",
        "scyllahide",
        "TitanHide",
        "titanhide",
        "bypass_debugger",
        "patch_debugger",
        "IsDebuggerPresent",
        "ProcessDebugPort",
        "AddVectoredExceptionHandler",
        "rdtsc_bypass",
        "frida-server",
        "frida-gadget",
        "DBKernel",
        "ReClass.NET",
    };

    // ── Registry keys that indicate bypass tool installation ─────────────────

    private static readonly (string hive, string subKey, string valueName, string label)[] RegistryChecks =
    {
        (
            "HKLM",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\x64dbg.exe",
            "Debugger",
            "x64dbg IFEO debugger entry"
        ),
        (
            "HKLM",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ollydbg.exe",
            "Debugger",
            "OllyDbg IFEO debugger entry"
        ),
        (
            "HKCU",
            @"SOFTWARE\ScyllaHide",
            "",
            "ScyllaHide configuration registry key"
        ),
        (
            "HKCU",
            @"SOFTWARE\TitanHide",
            "",
            "TitanHide configuration registry key"
        ),
        (
            "HKLM",
            @"SYSTEM\CurrentControlSet\Services\TitanHide",
            "ImagePath",
            "TitanHide kernel driver service"
        ),
        (
            "HKLM",
            @"SYSTEM\CurrentControlSet\Services\NtHideOS",
            "ImagePath",
            "NtHideOS kernel driver service"
        ),
        (
            "HKLM",
            @"SYSTEM\CurrentControlSet\Services\DBKernel",
            "ImagePath",
            "DBKernel (Cheat Engine bypass driver) service"
        ),
        (
            "HKCU",
            @"SOFTWARE\ReClass.NET",
            "",
            "ReClass.NET memory structure tool registry key"
        ),
        (
            "HKLM",
            @"SOFTWARE\Frida",
            "",
            "Frida dynamic instrumentation toolkit registry key"
        ),
    };

    // =========================================================================
    // Entry point
    // =========================================================================

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting anti-debug bypass artifact scan");

        // Phase 1: Registry scan for known bypass tool installation keys
        ScanRegistry(ctx, ct);
        ctx.Report(0.10, Name, "Registry scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 2: Filesystem scan across key user directories
        await ScanFilesystemAsync(ctx, ct);
        ctx.Report(0.80, Name, "Filesystem scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 3: PowerShell history scan for bypass commands
        await ScanPowerShellHistoryAsync(ctx, ct);
        ctx.Report(0.90, Name, "PowerShell history scan complete");
        ct.ThrowIfCancellationRequested();

        // Phase 4: x64dbg and IDA Pro plugin directory inspection
        await ScanDebuggerPluginDirectoriesAsync(ctx, ct);
        ctx.Report(1.0, Name, "Anti-debug bypass artifact scan complete");
    }

    // =========================================================================
    // Phase 1 – Registry
    // =========================================================================

    private void ScanRegistry(ScanContext ctx, CancellationToken ct)
    {
        foreach (var (hive, subKey, valueName, label) in RegistryChecks)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var rootKey = hive.Equals("HKLM", StringComparison.OrdinalIgnoreCase)
                    ? Registry.LocalMachine
                    : Registry.CurrentUser;

                using var key = rootKey.OpenSubKey(subKey);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                string detail;
                if (!string.IsNullOrEmpty(valueName))
                {
                    var val = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrEmpty(val)) continue;
                    detail = $"{valueName} = {val}";
                }
                else
                {
                    detail = $"Key exists: {hive}\\{subKey}";
                }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Anti-debug bypass tool registry artifact: {label}",
                    Risk = RiskLevel.High,
                    Location = $"{hive}\\{subKey}",
                    Reason = $"Registry key '{hive}\\{subKey}' is associated with a known " +
                             $"anti-debug bypass tool ({label}). These tools are used to hide " +
                             "debugger presence from anti-cheat and game integrity checks.",
                    Detail = detail,
                });
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }

        // Also scan IFEO for known bypass tool names as debugger targets
        ScanIFEOForBypassTargets(ctx, ct);
    }

    private void ScanIFEOForBypassTargets(ScanContext ctx, CancellationToken ct)
    {
        var ifeoKeyPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        var bypassTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "windbg.exe",
            "idaq.exe", "idaq64.exe", "ida.exe", "ida64.exe",
            "scylla_x64.exe", "scylla_x86.exe",
            "cheatengine-x86_64.exe", "cheatengine-i386.exe",
            "processhacker.exe", "processhacker2.exe",
            "reclass.net.exe", "reclass64.exe",
            "pe-bear.exe", "pe_sieve64.exe",
        };

        try
        {
            using var ifeoRoot = Registry.LocalMachine.OpenSubKey(ifeoKeyPath);
            if (ifeoRoot is null) return;

            foreach (var subName in ifeoRoot.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                if (!bypassTargets.Contains(subName)) continue;

                try
                {
                    using var sub = ifeoRoot.OpenSubKey(subName);
                    if (sub is null) continue;
                    var dbg = sub.GetValue("Debugger")?.ToString();
                    if (string.IsNullOrWhiteSpace(dbg)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"IFEO debugger redirect for reverse-engineering tool: {subName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{ifeoKeyPath}\{subName}",
                        FileName = subName,
                        Reason = $"Image File Execution Options entry for '{subName}' redirects to " +
                                 $"debugger '{dbg}'. This configuration hijacks analysis tools and " +
                                 "is a technique used to attach anti-debug bypass layers automatically.",
                        Detail = $"Debugger = {dbg}",
                    });
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // =========================================================================
    // Phase 2 – Filesystem
    // =========================================================================

    private async Task ScanFilesystemAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanRoots = BuildScanRoots();
        var allFiles = new List<string>();

        foreach (var root in scanRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;
            try
            {
                CollectFiles(root, allFiles, maxDepth: 6, ct);
            }
            catch (UnauthorizedAccessException) { }
        }

        int total = Math.Max(allFiles.Count, 1);
        int idx = 0;

        foreach (var filePath in allFiles)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            ctx.IncrementFiles();

            if (idx % 50 == 0)
                ctx.Report(0.10 + 0.68 * ((double)idx / total), filePath, $"{idx}/{allFiles.Count} files scanned");

            var fileName = Path.GetFileName(filePath);
            var ext = Path.GetExtension(filePath);

            // Check if file name exactly matches known bypass tool name
            if (KnownBypassToolNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known anti-debug bypass tool detected: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' is a known anti-debugging bypass tool used to " +
                             "hide debugger presence from anti-cheat systems. Its presence on disk " +
                             "is a strong indicator of cheat analysis or debugger evasion activity.",
                });
                continue;
            }

            // Check known bypass-specific extensions (.rcnet, .dp64, .dp32)
            if (KnownBypassExtensions.Contains(ext))
            {
                var risk = ext.Equals(".rcnet", StringComparison.OrdinalIgnoreCase)
                    ? RiskLevel.High
                    : RiskLevel.Critical;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Anti-debug bypass plugin/project file: {fileName}",
                    Risk = risk,
                    Location = filePath,
                    FileName = fileName,
                    Reason = ext.Equals(".rcnet", StringComparison.OrdinalIgnoreCase)
                        ? $"File '{fileName}' is a ReClass.NET project file (.rcnet). ReClass.NET " +
                          "is used to map game memory structures, a prerequisite for developing " +
                          "memory-reading cheats."
                        : $"File '{fileName}' has extension '{ext}' used by x64dbg debugger plugins. " +
                          "Files like ScyllaHide.dp64 are anti-debug bypass plugins that hide " +
                          "debugger presence from game anti-cheat protection.",
                });
                continue;
            }

            // Check IDA Pro plugin directory for bypass/hide keyword files
            if (IsInIdaPluginDirectory(filePath))
            {
                var lowerName = fileName.ToLowerInvariant();
                if (lowerName.Contains("bypass") || lowerName.Contains("hide") ||
                    lowerName.Contains("antidbg") || lowerName.Contains("anti_dbg") ||
                    lowerName.Contains("stealth") || lowerName.Contains("scylla"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious IDA Pro bypass plugin: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"File '{fileName}' is located in an IDA Pro plugins directory and " +
                                 "its name contains keywords associated with anti-debug bypass " +
                                 "techniques (bypass/hide/stealth). IDA Pro bypass plugins are " +
                                 "used to analyse and reverse-engineer anti-cheat protection.",
                    });
                    continue;
                }
            }

            // Scan text-based files for bypass config/code artifacts
            if (!TextExtensions.Contains(ext)) continue;

            FileInfo fi;
            try { fi = new FileInfo(filePath); } catch { continue; }
            if (fi.Length > 4 * 1024 * 1024) continue; // skip files > 4 MB

            try
            {
                await InspectTextFileAsync(ctx, filePath, fileName, ct);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private async Task InspectTextFileAsync(ScanContext ctx, string filePath, string fileName, CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        ct.ThrowIfCancellationRequested();

        // Check IsDebuggerPresent / NtQueryInformationProcess bypass config keys
        foreach (var key in IsDebuggerPresentConfigKeys)
        {
            if (content.Contains(key, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"IsDebuggerPresent bypass config key in: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' contains configuration key '{key}' which enables " +
                             "IsDebuggerPresent or NtQueryInformationProcess bypass, preventing " +
                             "anti-cheat debugger detection from working correctly.",
                    Detail = ExtractContext(content, key, 120),
                });
                return;
            }
        }

        // Check timing bypass config keys
        foreach (var key in TimingBypassConfigKeys)
        {
            if (content.Contains(key, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Timing-based anti-debug bypass config in: {fileName}",
                    Risk = RiskLevel.High,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' contains configuration key '{key}' which enables " +
                             "timing-based anti-debug bypass. GetTickCount and QueryPerformanceCounter " +
                             "hooks return constant values to defeat timing-based debugger detection.",
                    Detail = ExtractContext(content, key, 120),
                });
                return;
            }
        }

        // Check exception-based bypass config keys
        foreach (var key in ExceptionBypassConfigKeys)
        {
            if (content.Contains(key, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Exception-based anti-debug bypass config in: {fileName}",
                    Risk = RiskLevel.High,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' contains configuration key '{key}' which enables " +
                             "exception-based anti-debug bypass. VEH abuse and INT1/INT3 bypass " +
                             "techniques are used to defeat single-step and breakpoint detection.",
                    Detail = ExtractContext(content, key, 120),
                });
                return;
            }
        }

        // Check heap bypass config keys
        foreach (var key in HeapBypassConfigKeys)
        {
            if (content.Contains(key, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Heap flag (NtGlobalFlag) bypass config in: {fileName}",
                    Risk = RiskLevel.High,
                    Location = filePath,
                    FileName = fileName,
                    Reason = $"File '{fileName}' contains configuration key '{key}' which enables " +
                             "NtGlobalFlag / heap flag patching. Debuggers set heap flags that " +
                             "games use to detect them; patching these flags hides the debugger.",
                    Detail = ExtractContext(content, key, 120),
                });
                return;
            }
        }

        // For source-like files, also check code-level artifacts
        var srcExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".cs", ".cpp", ".h", ".c", ".asm", ".nasm", ".py", ".js", ".lua", ".rb" };
        if (!srcExt.Contains(Path.GetExtension(filePath))) return;

        // IsDebuggerPresent code artifact check
        int dbgHits = IsDebuggerPresentCodeArtifacts.Count(a =>
            content.Contains(a, StringComparison.OrdinalIgnoreCase));
        if (dbgHits >= 2)
        {
            var matched = IsDebuggerPresentCodeArtifacts
                .Where(a => content.Contains(a, StringComparison.OrdinalIgnoreCase))
                .Take(4);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Anti-debug bypass source code artifact in: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"Source file '{fileName}' references multiple IsDebuggerPresent / " +
                         "NtQueryInformationProcess bypass patterns. This indicates cheat loader " +
                         "source code or a bypass implementation targeting anti-cheat.",
                Detail = $"Matched patterns: {string.Join(", ", matched)}",
            });
            return;
        }

        // Timing code artifact check
        int timingHits = TimingCodeArtifacts.Count(a =>
            content.Contains(a, StringComparison.OrdinalIgnoreCase));
        if (timingHits >= 2)
        {
            var matched = TimingCodeArtifacts
                .Where(a => content.Contains(a, StringComparison.OrdinalIgnoreCase))
                .Take(4);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Timing bypass source code artifact in: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"Source file '{fileName}' references multiple timing-based anti-debug " +
                         "bypass patterns (GetTickCount/QueryPerformanceCounter hooks, RDTSC bypass). " +
                         "This indicates cheat loader or bypass tool source code.",
                Detail = $"Matched patterns: {string.Join(", ", matched)}",
            });
            return;
        }

        // Exception bypass code artifact check
        int excHits = ExceptionCodeArtifacts.Count(a =>
            content.Contains(a, StringComparison.OrdinalIgnoreCase));
        if (excHits >= 2)
        {
            var matched = ExceptionCodeArtifacts
                .Where(a => content.Contains(a, StringComparison.OrdinalIgnoreCase))
                .Take(4);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Exception-based bypass source code artifact in: {fileName}",
                Risk = RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"Source file '{fileName}' references multiple exception-based anti-debug " +
                         "bypass patterns (VEH, SEH, hardware breakpoint bypass). " +
                         "This suggests cheat analysis tooling or bypass implementation.",
                Detail = $"Matched patterns: {string.Join(", ", matched)}",
            });
            return;
        }

        // Heap/NtGlobalFlag code artifact check
        int heapHits = HeapCodeArtifacts.Count(a =>
            content.Contains(a, StringComparison.OrdinalIgnoreCase));
        if (heapHits >= 2)
        {
            var matched = HeapCodeArtifacts
                .Where(a => content.Contains(a, StringComparison.OrdinalIgnoreCase))
                .Take(4);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"NtGlobalFlag/HeapFlags bypass source artifact in: {fileName}",
                Risk = RiskLevel.Medium,
                Location = filePath,
                FileName = fileName,
                Reason = $"Source file '{fileName}' references multiple NtGlobalFlag / heap flag " +
                         "bypass patterns. Patching these structures hides debug heap allocations " +
                         "that anti-cheat checks use to confirm a debugger is attached.",
                Detail = $"Matched patterns: {string.Join(", ", matched)}",
            });
        }
    }

    // =========================================================================
    // Phase 3 – PowerShell history
    // =========================================================================

    private async Task ScanPowerShellHistoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var historyPaths = new[]
        {
            Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Windows",
                "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
            Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Windows",
                "PowerShell", "PSReadLine", "Visual Studio Code Host_history.txt"),
        };

        foreach (var histPath in historyPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(histPath)) continue;

            string content;
            try
            {
                using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
            }
            catch (IOException) { continue; }
            catch (UnauthorizedAccessException) { continue; }

            ct.ThrowIfCancellationRequested();

            var matchedTerms = PsHistoryBypassTerms
                .Where(t => content.Contains(t, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchedTerms.Count == 0) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Anti-debug bypass commands in PowerShell history: {Path.GetFileName(histPath)}",
                Risk = RiskLevel.High,
                Location = histPath,
                FileName = Path.GetFileName(histPath),
                Reason = $"PowerShell history file '{Path.GetFileName(histPath)}' contains commands " +
                         "associated with anti-debug bypass tools or techniques (ScyllaHide, TitanHide, " +
                         "NtGlobalFlag patching, Frida, ReClass.NET, DBKernel). This indicates the user " +
                         "has been working with debugger-hiding tooling.",
                Detail = $"Matched terms: {string.Join(", ", matchedTerms.Take(8))}",
            });
        }
    }

    // =========================================================================
    // Phase 4 – x64dbg and IDA Pro plugin directories
    // =========================================================================

    private async Task ScanDebuggerPluginDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");

        var searchRoots = new[] { localAppData, appData, programFiles, programFilesX86, desktop, downloads, userProfile };

        foreach (var root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            string[] topDirs;
            try { topDirs = Directory.GetDirectories(root); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var topDir in topDirs)
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(topDir);

                // x64dbg plugin directories
                bool isX64DbgDir = X64DbgPluginDirFragments.Any(f =>
                    dirName.Contains(f, StringComparison.OrdinalIgnoreCase));
                if (isX64DbgDir)
                {
                    await ScanX64DbgDirectoryAsync(ctx, topDir, ct);
                    continue;
                }

                // IDA Pro plugin directories
                bool isIdaDir = IdaPluginDirFragments.Any(f =>
                    topDir.Contains(f, StringComparison.OrdinalIgnoreCase));
                if (isIdaDir)
                {
                    await ScanIdaProDirectoryAsync(ctx, topDir, ct);
                }
            }
        }
    }

    private async Task ScanX64DbgDirectoryAsync(ScanContext ctx, string x64DbgRoot, CancellationToken ct)
    {
        var pluginsDir = Path.Combine(x64DbgRoot, "plugins");
        var pluginsDirs = new[] { pluginsDir, x64DbgRoot };

        foreach (var dir in pluginsDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);

                if (KnownBypassToolNames.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known anti-debug bypass plugin in x64dbg directory: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"File '{fileName}' is a known anti-debug bypass plugin found in " +
                                 $"the x64dbg directory '{dir}'. Plugins like ScyllaHide.dp64 hide " +
                                 "debugger presence from game anti-cheat and integrity checks.",
                    });
                    continue;
                }

                if (!KnownBypassExtensions.Contains(ext)) continue;

                var lowerName = fileName.ToLowerInvariant();
                bool isBypassPlugin = lowerName.Contains("bypass") || lowerName.Contains("hide") ||
                                      lowerName.Contains("scylla") || lowerName.Contains("stealth") ||
                                      lowerName.Contains("antidbg") || lowerName.Contains("anti_dbg") ||
                                      lowerName.Contains("detect") || lowerName.Contains("hider");

                if (isBypassPlugin)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious anti-debug bypass plugin in x64dbg: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"File '{fileName}' ({ext}) in x64dbg plugins directory has a name " +
                                 "matching anti-debug bypass patterns. x64dbg bypass plugins " +
                                 "suppress debugger detection checks used by anti-cheat systems.",
                    });
                    continue;
                }

                // Any .dp64/.dp32 plugin in x64dbg is worth noting
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"x64dbg debugger plugin present: {fileName}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = fileName,
                    Reason = $"x64dbg plugin '{fileName}' detected. x64dbg is used to reverse-engineer " +
                             "and debug applications including games and anti-cheat systems. " +
                             "While not proof of cheating, combined with other findings this " +
                             "indicates active cheat development or analysis.",
                });

                // Also read .ini/.cfg plugin config if present
                var cfgFile = Path.ChangeExtension(file, ".ini");
                if (File.Exists(cfgFile))
                    await InspectTextFileAsync(ctx, cfgFile, Path.GetFileName(cfgFile), ct);
            }
        }
    }

    private async Task ScanIdaProDirectoryAsync(ScanContext ctx, string idaRoot, CancellationToken ct)
    {
        var pluginsDir = Path.Combine(idaRoot, "plugins");
        if (!Directory.Exists(pluginsDir)) return;

        string[] files;
        try { files = Directory.GetFiles(pluginsDir, "*", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            var fileName = Path.GetFileName(file);
            var lowerName = fileName.ToLowerInvariant();

            bool isBypass = lowerName.Contains("bypass") || lowerName.Contains("hide") ||
                            lowerName.Contains("scylla") || lowerName.Contains("stealth") ||
                            lowerName.Contains("antidbg") || lowerName.Contains("hider") ||
                            lowerName.Contains("undetect") || lowerName.Contains("cloak");

            if (!isBypass) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Suspicious IDA Pro bypass plugin: {fileName}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = fileName,
                Reason = $"IDA Pro plugin '{fileName}' in '{pluginsDir}' has a name " +
                         "indicating anti-debug bypass or stealth functionality. IDA bypass " +
                         "plugins are used to analyse game and anti-cheat protection without " +
                         "being detected, a direct precursor to cheat development.",
            });

            await Task.CompletedTask; // keep method async
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static List<string> BuildScanRoots()
    {
        var roots = new List<string>();

        foreach (var envVar in ScanRootEnvVars)
        {
            var path = Environment.GetEnvironmentVariable(envVar);
            if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                roots.Add(path);
        }

        // Also include Downloads
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = Path.Combine(userProfile, "Downloads");
        if (Directory.Exists(downloads)) roots.Add(downloads);

        // Desktop
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        if (Directory.Exists(desktop)) roots.Add(desktop);

        return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static void CollectFiles(string root, List<string> sink, int maxDepth, CancellationToken ct)
    {
        var stack = new Stack<(string dir, int depth)>();
        stack.Push((root, 0));

        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) return;
            var (dir, depth) = stack.Pop();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var f in files) sink.Add(f);

            if (depth >= maxDepth) continue;

            string[] subs = Array.Empty<string>();
            try { subs = Directory.GetDirectories(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var s in subs) stack.Push((s, depth + 1));
        }
    }

    private static bool IsInIdaPluginDirectory(string path)
    {
        return IdaPluginDirFragments.Any(f => path.Contains(f, StringComparison.OrdinalIgnoreCase));
    }

    private static string ExtractContext(string content, string keyword, int maxLen)
    {
        var idx = content.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return string.Empty;
        var start = Math.Max(0, idx - 30);
        var end = Math.Min(content.Length, idx + keyword.Length + maxLen);
        var snippet = content[start..end].Replace('\n', ' ').Replace('\r', ' ');
        return snippet.Length > maxLen + 60 ? snippet[..(maxLen + 60)] + "..." : snippet;
    }
}
