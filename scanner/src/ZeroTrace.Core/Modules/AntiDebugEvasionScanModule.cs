using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AntiDebugEvasionScanModule : IScanModule
{
    public string Name => "Anti-Debug Evasion Artifact Detection";
    public double Weight => 4.2;
    public int ParallelGroup => 4;

    private static readonly string[] AntiDebugToolExeNames =
    [
        "ScyllaHide.exe", "ScyllaHideConsole.exe",
        "TitanHide.exe", "TitanHide64.exe", "TitanHide32.exe",
        "ProcessHacker.exe", "ProcessHacker2.exe", "ProcessHacker3.exe",
        "x64dbg.exe", "x32dbg.exe", "x64dbg_portable.exe", "x32dbg_portable.exe",
        "windbg.exe", "windbgx.exe", "cdb.exe", "ntsd.exe", "kd.exe",
        "OllyDbg.exe", "OllyDbg110.exe", "OllyDbg201.exe",
        "IDA.exe", "ida64.exe", "ida.exe", "idaq.exe", "idaq64.exe", "idaw.exe",
        "radare2.exe", "r2.exe", "r2gui.exe", "Cutter.exe",
        "ghidra.exe", "ghidraRun.exe", "analyzeHeadless.exe",
        "ApiMonitor.exe", "ApiMonitor-x86.exe", "ApiMonitor-x64.exe",
        "ProcessMonitor.exe", "Procmon.exe", "Procmon64.exe",
        "procexp.exe", "procexp64.exe",
        "pe-bear.exe", "PEBear.exe",
        "HxD.exe", "HexEdit.exe", "010editor.exe",
        "ImportREC.exe", "ImpREC.exe", "ImportReconstructor.exe",
        "LordPE.exe", "PEditor.exe",
        "exeinfope.exe", "ExeinfoPE.exe",
        "PEiD.exe", "peid.exe",
        "Wireshark.exe", "tshark.exe",
        "Fiddler.exe", "FiddlerEverywhere.exe",
        "BurpSuiteCommunity.exe", "BurpSuitePro.exe",
        "cheatengine.exe", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
        "dnSpy.exe", "dnSpy-x86.exe", "dnSpyEx.exe",
        "dotPeek.exe", "JustDecompile.exe", "ILSpy.exe",
        "de4dot.exe", "deobfuscator.exe",
        "snowman.exe", "snowmanview.exe",
        "Binary Ninja.exe", "binaryninja.exe",
        "frida.exe", "frida-server.exe", "frida-trace.exe",
        "pin.exe", "pintools.exe",
        "dynamorio.exe",
        "rz-ghidra.exe",
        "pestudio.exe",
        "CFF Explorer.exe", "CFFExplorer.exe",
        "Hiew32.exe", "hiew32.exe",
        "stud_pe.exe", "StudPE.exe",
        "hollows_hunter.exe",
        "pe-sieve.exe", "pesieve.exe",
        "DbgView.exe", "dbgview64.exe",
        "x64dbgpy.exe",
        "HyperDbg.exe", "hyperdbg.exe",
    ];

    private static readonly string[] AntiDebugDllNames =
    [
        "ScyllaHide.dll", "ScyllaHide64.dll", "ScyllaHide32.dll",
        "TitanHide.dll", "TitanHide64.dll",
        "antidbg.dll", "anti_debug.dll", "AntiDebug.dll",
        "debugkiller.dll", "debug_killer.dll", "DebugKiller.dll",
        "IsDebuggerPresent_bypass.dll", "IsDebuggerPresentBypass.dll",
        "CheckRemoteDebuggerPresent_bypass.dll", "CheckRemoteDebuggerPresentBypass.dll",
        "NtQueryInformationProcess_bypass.dll",
        "debugger_bypass.dll", "debugbypass.dll", "DebugBypass.dll",
        "ntdll_patch.dll", "ntdll_hook.dll", "NtdllPatch.dll",
        "unhook.dll", "api_unhook.dll", "unhook_ntdll.dll", "NtdllUnhook.dll",
        "rdtsc_bypass.dll", "timer_spoof.dll", "timing_bypass.dll",
        "memory_cloak.dll", "page_guard_bypass.dll",
        "cpuid_spoof.dll", "vm_detect_bypass.dll",
        "frida-gadget.dll", "frida-agent.dll",
        "dbghelp_hook.dll", "dbgcore_hook.dll",
        "debug_blocker.dll", "DebugBlocker.dll",
        "hw_bp_bypass.dll", "HardwareBpBypass.dll",
        "exception_bypass.dll", "ExceptionBypass.dll",
    ];

    private static readonly string[] AntiDebugConfigFileNames =
    [
        "scyllahide.ini", "scyllahide.cfg", "scyllahide.json", "scyllahide.xml",
        "titanhide.ini", "titanhide.cfg", "titanhide.json",
        "antidebug.cfg", "antidebug.ini", "antidebug.json",
        "debugkiller.ini", "debugkiller.cfg",
        "bypass_debugger.cfg", "bypass_debugger.ini",
        "kill_debugger.cfg", "kill_debugger.ini",
        "suspend_debugger.ini", "suspend_debugger.cfg",
        "anti_debug.cfg", "anti_debug.ini",
        "debugger_bypass.ini", "debugger_bypass.cfg",
        "hide_from_debugger.cfg", "hide_from_debugger.ini",
        "rdtsc_bypass.ini", "rdtsc_bypass.cfg",
        "timing_attack.ini", "timing_attack.cfg",
        "cpuid_spoof.ini", "cpuid_spoof.cfg",
        "antianalysis.ini", "antianalysis.cfg",
        "analysis_bypass.cfg", "analysis_bypass.ini",
    ];

    private static readonly string[] ProcessHollowingToolNames =
    [
        "hollow.exe", "process_hollow.exe", "pe_hollow.exe",
        "RunPE.exe", "runpe.exe", "RunPE64.exe", "runpe64.exe",
        "process_ghost.exe", "ProcessGhost.exe",
        "ghost_process.exe", "GhostProcess.exe",
        "phantom_loader.exe", "PhantomLoader.exe",
        "doppelganger.exe", "process_doppelganging.exe", "Doppelganging.exe",
        "atom_bombing.exe", "AtomBombing.exe",
        "hollow_loader.exe", "HollowLoader.exe",
        "pe_inject.exe", "PeInject.exe",
        "pe_loader.exe", "PeLoader.exe",
        "manual_hollow.exe", "ManualHollow.exe",
        "process_reimager.exe", "ProcessReimagined.exe",
        "reflective_pe.exe", "ReflectivePE.exe",
        "transacted_hollow.exe",
        "mmap_hollow.exe",
    ];

    private static readonly string[] ApiHookBypassToolNames =
    [
        "unhook.exe", "api_unhook.exe", "ntdll_patch.exe",
        "unhook_ntdll.exe", "NtdllUnhook.exe",
        "edr_unhook.exe", "EDRUnhook.exe",
        "hook_bypass.exe", "HookBypass.exe",
        "inline_hook_bypass.exe", "InlineHookBypass.exe",
        "iat_restore.exe", "IATRestore.exe",
        "syscall_patch.exe", "SyscallPatch.exe",
        "manual_syscall.exe", "ManualSyscall.exe",
        "ntdll_restore.exe", "NtdllRestore.exe",
        "api_restore.exe", "ApiRestore.exe",
        "hook_scanner.exe", "HookScanner.exe",
        "direct_syscall.exe", "DirectSyscall.exe",
        "fresh_ntdll.exe", "FreshNtdll.exe",
        "stomp_hook.exe", "StompHook.exe",
        "patch_guard.exe", "PatchGuard.exe",
    ];

    private static readonly string[] TimingBypassToolNames =
    [
        "rdtsc_bypass.exe", "RdtscBypass.exe",
        "timer_spoof.exe", "TimerSpoof.exe",
        "timing_attack_bypass.exe", "TimingAttackBypass.exe",
        "clock_spoof.exe", "ClockSpoof.exe",
        "qpc_spoof.exe", "QPCSpoof.exe",
        "timestamp_spoof.exe", "TimestampSpoof.exe",
        "tsc_spoof.exe", "TSCSpoof.exe",
        "perf_counter_bypass.exe", "PerfCounterBypass.exe",
        "nanotime_bypass.exe", "NanotimeBypass.exe",
        "high_res_timer_bypass.exe", "HighResTimerBypass.exe",
        "get_tick_spoof.exe", "GetTickSpoof.exe",
        "rdtsc_patch.exe", "RdtscPatch.exe",
    ];

    private static readonly string[] AntiMemoryScanToolNames =
    [
        "memory_cloak.exe", "MemoryCloak.exe",
        "page_guard_bypass.exe", "PageGuardBypass.exe",
        "mem_scan_bypass.exe", "MemScanBypass.exe",
        "memory_hide.exe", "MemoryHide.exe",
        "guard_pages.exe", "GuardPages.exe",
        "mem_protection.exe", "MemProtection.exe",
        "pe_cloak.exe", "PECloak.exe",
        "memory_obfuscate.exe", "MemoryObfuscate.exe",
        "section_rename.exe", "SectionRename.exe",
        "working_set_trim.exe", "WorkingSetTrim.exe",
        "heap_cloak.exe", "HeapCloak.exe",
        "teb_hide.exe", "TebHide.exe",
        "peb_hide.exe", "PebHide.exe",
        "vad_hide.exe", "VadHide.exe",
        "page_encrypt.exe", "PageEncrypt.exe",
        "rw_cloak.exe", "RwCloak.exe",
    ];

    private static readonly string[] KernelPatchToolNames =
    [
        "patch_ntoskrnl.exe", "PatchNtoskrnl.exe",
        "nt_patch.exe", "NtPatch.exe",
        "kernel_patch.exe", "KernelPatch.exe",
        "dse_patch.exe", "DSEPatch.exe",
        "dse_disable.exe", "DSEDisable.exe",
        "ci_patch.exe", "CIPatch.exe",
        "kdmapper.exe", "KDMapper.exe",
        "ksm.exe", "kdu.exe",
        "turla_driver_loader.exe", "TurlaDriverLoader.exe",
        "physmem.exe", "physmem_driver.exe",
        "gdrv.exe", "rtcore64.exe",
        "patchguard_bypass.exe", "PatchGuardBypass.exe",
        "dkom_patch.exe", "DKOMPatch.exe",
        "kpp_bypass.exe", "KPPBypass.exe",
        "ci_bypass.exe", "CIBypass.exe",
        "hyperv_patch.exe", "HypervPatch.exe",
    ];

    private static readonly string[] VmDetectBypassToolNames =
    [
        "cpuid_spoof.exe", "CpuidSpoof.exe",
        "vm_detect_bypass.exe", "VmDetectBypass.exe",
        "rdmsr_bypass.exe", "RdmsrBypass.exe",
        "hyperv_bypass.exe", "HypervBypass.exe",
        "vbox_bypass.exe", "VboxBypass.exe",
        "vmware_bypass.exe", "VmwareBypass.exe",
        "antivm.exe", "anti_vm.exe", "AntiVM.exe",
        "sandbox_bypass.exe", "SandboxBypass.exe",
        "sandbox_detect_bypass.exe", "SandboxDetectBypass.exe",
        "vm_artifact_clean.exe", "VmArtifactClean.exe",
        "cpuid_patch.exe", "CpuidPatch.exe",
        "vmexit_bypass.exe", "VmexitBypass.exe",
        "xen_bypass.exe", "XenBypass.exe",
        "kvm_bypass.exe", "KvmBypass.exe",
        "qemu_bypass.exe", "QemuBypass.exe",
    ];

    private static readonly string[] AntiDebugRegistryPaths =
    [
        @"SOFTWARE\ScyllaHide",
        @"SOFTWARE\TitanHide",
        @"SOFTWARE\x64dbg",
        @"SOFTWARE\x32dbg",
        @"SOFTWARE\OllyDbg",
        @"SOFTWARE\Cheat Engine",
        @"SOFTWARE\HxD",
        @"SOFTWARE\SysInternals",
        @"SOFTWARE\ProcessHacker",
        @"SOFTWARE\IDA",
        @"SOFTWARE\Hex-Rays",
        @"SOFTWARE\ApiMonitor",
        @"SOFTWARE\debugger_bypass",
        @"SOFTWARE\anti_debug",
        @"SOFTWARE\AntiDebug",
        @"SOFTWARE\DebugKiller",
        @"SOFTWARE\ApiHookBypass",
        @"SOFTWARE\Frida",
        @"SOFTWARE\HyperDbg",
        @"SOFTWARE\dnSpy",
    ];

    private static readonly string[] AntiDebugContentKeywords =
    [
        "anti_debug", "antidebug", "bypass_debugger", "debugger_bypass",
        "kill_debugger", "suspend_debugger", "debug_killer",
        "hide_from_debugger", "isdebuggerpresent", "checkremotedebugger",
        "scyllahide", "titanhide", "ntglobalflag",
        "heap_flag", "heap_force_flags", "debug_heap",
        "heapsetinformation", "rdtsc_bypass", "timing_attack",
        "cpuid_spoof", "vm_detect_bypass", "anti_vm", "sandbox_bypass",
        "memory_cloak", "page_guard", "api_unhook",
        "ntdll_patch", "ntdll_restore", "unhook_ntdll",
        "debugger_present", "remote_debugger", "kernel_debugger",
        "direct_syscall", "manual_syscall", "syscall_bypass",
        "threadhidefromdebugger", "processdebugport", "processdebugflags",
        "debug_blocker", "hw_bp_bypass", "hardware_breakpoint",
        "exception_bypass", "veh_bypass", "seh_bypass",
        "dr0", "dr1", "dr2", "dr3", "dr7",
    ];

    private static readonly string[] GameExecutableNames =
    [
        "csgo.exe", "cs2.exe", "valorant.exe", "valorant-win64-shipping.exe",
        "r5apex.exe", "RainbowSix.exe", "RainbowSix_DX11.exe",
        "ac_client.exe", "EFT.exe", "pubg.exe", "tslgame.exe",
        "RustClient.exe", "DayZ_x64.exe", "bf1.exe", "bf2042.exe",
        "cod.exe", "modernwarfare.exe", "warzone.exe",
        "FortniteClient-Win64-Shipping.exe",
        "overwatch.exe", "Overwatch.exe",
        "TarkovClient.exe", "battlestate.exe",
        "destiny2.exe", "GTA5.exe", "FiveM.exe",
        "RainbowSix_Siege.exe", "sixservicemanager.exe",
        "PUBG.exe", "PUBG_Lite.exe",
        "DayZDiag_x64.exe",
        "EscapeFromTarkov.exe",
    ];

    private static readonly string[] DebuggerPrefetchKeywords =
    [
        "X64DBG", "X32DBG", "OLLYDBG", "WINDBG", "PROCESSHACKER",
        "SCYLLAHIDE", "TITANHIDE", "CHEATENGINE", "DNSPY",
        "PROCESSMONITOR", "APIMONITOR", "PROCEXP",
        "IDA", "IDAQ", "RADARE2", "GHIDRA",
        "BINARYNINJA", "CUTTER", "PESTUDIO",
        "IMPORTREC", "CFFEXPLORER", "HYPERDBG",
        "FRIDA", "FRIDASERVER",
        "PEBEAR", "PESIEVE", "HOLLOWS",
    ];

    private static readonly string[] HeapDebugArtifactFileNames =
    [
        "heap_debug.log", "heap_debug.txt",
        "debug_heap.log", "debug_heap.txt",
        "heapsetinformation.log",
        "heap_trace.log", "heap_trace.txt",
        "peb_flags.txt", "peb_flags.log",
        "ntglobalflag.txt", "ntglobalflag.log",
        "debug_artifact.log", "debug_artifact.txt",
        "antidebug_trace.log", "antidebug_trace.txt",
        "debug_bypass.log", "debug_bypass.txt",
        "heap_cleanup.log", "heap_cleanup.txt",
        "heap_flag_clear.log",
    ];

    private static readonly string[] SyscallBypassToolNames =
    [
        "syscall_bypass.exe", "SyscallBypass.exe",
        "ntdll_syscall.exe", "NtdllSyscall.exe",
        "syswhispers.exe", "SysWhispers.exe",
        "hell_gate.exe", "HellGate.exe",
        "halos_gate.exe", "HalosGate.exe",
        "tartarus_gate.exe", "TartarusGate.exe",
        "freshycalls.exe", "FreshyCalls.exe",
        "syscall_resolve.exe", "SyscallResolve.exe",
        "indirect_syscall.exe", "IndirectSyscall.exe",
        "veh_syscall.exe", "VehSyscall.exe",
        "edr_syscall_bypass.exe", "EdrSyscallBypass.exe",
        "nt_syscall.exe", "NtSyscall.exe",
        "ntapi_direct.exe", "NtapiDirect.exe",
    ];

    private static readonly string[] ExceptionBypassToolNames =
    [
        "veh_bypass.exe", "VehBypass.exe",
        "seh_bypass.exe", "SehBypass.exe",
        "exception_bypass.exe", "ExceptionBypass.exe",
        "vectored_exception.exe", "VectoredException.exe",
        "exception_handler_bypass.exe",
        "first_chance_bypass.exe", "FirstChanceBypass.exe",
        "debug_exception_bypass.exe",
        "output_debug_string.exe", "OutputDebugString.exe",
        "raise_exception.exe", "RaiseException.exe",
        "set_unhandled.exe",
        "int3_bypass.exe", "Int3Bypass.exe",
        "breakpoint_bypass.exe", "BreakpointBypass.exe",
        "sw_bp_bypass.exe", "SwBpBypass.exe",
        "hw_bp_bypass.exe", "HwBpBypass.exe",
        "dr_bypass.exe", "DrBypass.exe",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAntiDebugToolExesAsync(ctx, ct),
            CheckAntiDebugDllsAsync(ctx, ct),
            CheckScyllaHidePluginsAsync(ctx, ct),
            CheckAntiDebugConfigFilesAsync(ctx, ct),
            CheckIFEOHijacksAsync(ctx, ct),
            CheckNtGlobalFlagRegistryAsync(ctx, ct),
            CheckProcessHollowingToolsAsync(ctx, ct),
            CheckApiHookBypassToolsAsync(ctx, ct),
            CheckTimingBypassToolsAsync(ctx, ct),
            CheckAntiMemoryScanToolsAsync(ctx, ct),
            CheckKernelPatchToolsAsync(ctx, ct),
            CheckVmDetectBypassToolsAsync(ctx, ct),
            CheckAntiDebugRegistryKeysAsync(ctx, ct),
            CheckAppDataAntiDebugConfigsAsync(ctx, ct),
            CheckDebuggerPrefetchArtifactsAsync(ctx, ct),
            CheckHeapDebugArtifactFilesAsync(ctx, ct),
            CheckSyscallBypassToolsAsync(ctx, ct),
            CheckExceptionBypassToolsAsync(ctx, ct)
        );
        ctx.Report(1.0, Name, "Anti-debug evasion artifact scan complete");
    }

    private Task CheckAntiDebugToolExesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, AntiDebugToolExeNames,
                        "Anti-Debug Tool Executable Detected",
                        Risk.Critical,
                        "Known anti-debug or anti-analysis tool binary found in user directory. These tools are used to bypass the debugger detection checks performed by anti-cheat software, allowing cheats to operate while being debugged.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckAntiDebugDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, AntiDebugDllNames,
                        "Anti-Debug Bypass DLL Detected",
                        Risk.Critical,
                        "DLL that bypasses debugger-detection APIs (IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess) found. These bypass the API calls used by anti-cheat software to detect attached debuggers.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckScyllaHidePluginsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var pluginDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "x64dbg", "release", "x64", "plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "x64dbg", "release", "x32", "plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "x64dbg", "release", "x64", "plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "x64dbg", "release", "x32", "plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "x64dbg", "release", "x64", "plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "x64dbg", "release", "x32", "plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OllyDbg", "Plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "OllyDbg", "Plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "OllyDbg 2.0", "Plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "IDA", "plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "IDA", "plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "IDA Pro", "plugins"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "IDA Pro", "plugins"),
            };

            var antiDebugPluginKeywords = new[]
            {
                "ScyllaHide", "scyllahide",
                "TitanHide", "titanhide",
                "antidbg", "anti_debug",
                "xanalyzer", "StrongOD",
                "OllyAdvanced", "OllyExt",
                "HideDebugger", "PhantOm",
                "OllyHeapVis",
                "UnpackMe",
            };

            foreach (var pluginDir in pluginDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(pluginDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(pluginDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fileName = Path.GetFileName(file);
                        var matched = antiDebugPluginKeywords.FirstOrDefault(k =>
                            fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (matched is null) continue;

                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Anti-Debug Debugger Plugin Detected: {fileName}",
                            Risk = Risk.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Anti-debug plugin '{fileName}' (matched keyword: '{matched}') found in debugger plugin directory. Plugins such as ScyllaHide comprehensively hide debugger presence from anti-cheat software by intercepting all standard debugger-detection APIs.",
                            Detail = $"Plugin directory: {pluginDir}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckAntiDebugConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, AntiDebugConfigFileNames,
                        "Anti-Debug Configuration File Detected",
                        Risk.High,
                        "Configuration file for an anti-debug evasion tool found. These files configure tools that bypass the debugger-detection checks used by anti-cheat software.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckIFEOHijacksAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var userWritableRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
            }.Where(r => !string.IsNullOrEmpty(r)).ToArray();

            try
            {
                using var ifeo = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
                if (ifeo is null)
                {
                    await Task.CompletedTask;
                    return;
                }

                foreach (var subName in ifeo.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    bool isGameExe = GameExecutableNames.Any(g =>
                        g.Equals(subName, StringComparison.OrdinalIgnoreCase));

                    try
                    {
                        using var sub = ifeo.OpenSubKey(subName);
                        if (sub is null) continue;

                        var debugger = sub.GetValue("Debugger")?.ToString();
                        if (string.IsNullOrWhiteSpace(debugger)) continue;

                        var expandedDebugger = Environment.ExpandEnvironmentVariables(debugger).Trim('"');

                        bool isUserWritable = userWritableRoots.Any(r =>
                            expandedDebugger.StartsWith(r, StringComparison.OrdinalIgnoreCase));

                        if (isGameExe || isUserWritable)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"IFEO Debugger Hijack on Game Executable: {subName}",
                                Risk = isGameExe ? Risk.Critical : Risk.High,
                                Location = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{subName}",
                                FileName = subName,
                                Reason = isGameExe
                                    ? $"Image File Execution Options 'Debugger' registry value is set for the game executable '{subName}', pointing to '{expandedDebugger}'. This causes a debugger or proxy process to attach whenever the game launches, allowing cheats to run under debugger cover while evading anti-cheat process checks."
                                    : $"IFEO 'Debugger' value for '{subName}' points to a user-writable path '{expandedDebugger}', which is unusual and may indicate a malicious debugger attachment.",
                                Detail = $"Debugger value: {debugger}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckNtGlobalFlagRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            try
            {
                using var sessionMgr = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Session Manager");
                if (sessionMgr is null)
                {
                    await Task.CompletedTask;
                    return;
                }
                ctx.IncrementRegistryKeys();

                var ntGlobalFlagRaw = sessionMgr.GetValue("NtGlobalFlag");
                if (ntGlobalFlagRaw is not null)
                {
                    int ntGlobalFlag = 0;
                    if (ntGlobalFlagRaw is int i) ntGlobalFlag = i;
                    else if (int.TryParse(ntGlobalFlagRaw.ToString(), out var parsed)) ntGlobalFlag = parsed;

                    const int FLG_HEAP_ENABLE_TAIL_CHECK = 0x10;
                    const int FLG_HEAP_ENABLE_FREE_CHECK = 0x20;
                    const int FLG_HEAP_VALIDATE_PARAMETERS = 0x40;
                    const int DebugHeapBits = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;

                    if (ntGlobalFlag != 0)
                    {
                        bool hasDebugHeapFlags = (ntGlobalFlag & DebugHeapBits) != 0;
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "NtGlobalFlag Registry Value Is Non-Zero",
                            Risk = hasDebugHeapFlags ? Risk.High : Risk.Medium,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\NtGlobalFlag",
                            Reason = hasDebugHeapFlags
                                ? $"NtGlobalFlag is set to 0x{ntGlobalFlag:X8} which includes debug heap validation flags (bits 0x70). Anti-cheat software reads this value from the PEB to detect if a process was started under a debugger. A non-zero value with debug heap bits is a strong debugger-presence indicator that evasion tools may attempt to clear or manipulate."
                                : $"NtGlobalFlag is set to a non-zero value (0x{ntGlobalFlag:X8}). This system-global flag is checked by anti-cheat software as part of debugger detection heuristics.",
                            Detail = $"NtGlobalFlag = 0x{ntGlobalFlag:X8} | Debug-heap bits = 0x{ntGlobalFlag & DebugHeapBits:X}"
                        });
                    }
                }

                var globalFlagRaw = sessionMgr.GetValue("GlobalFlag");
                if (globalFlagRaw is not null)
                {
                    int globalFlag = 0;
                    if (globalFlagRaw is int gi) globalFlag = gi;
                    else if (int.TryParse(globalFlagRaw.ToString(), out var p)) globalFlag = p;

                    if (globalFlag != 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Session Manager GlobalFlag Set to Non-Zero Value",
                            Risk = Risk.Medium,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\GlobalFlag",
                            Reason = $"Session Manager GlobalFlag is non-zero (0x{globalFlag:X8}). Cheat evasion tools sometimes manipulate system global flags to disable debug heap checks that anti-cheat software uses as debugger-presence indicators.",
                            Detail = $"GlobalFlag = 0x{globalFlag:X8}"
                        });
                    }
                }
            }
            catch { }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckProcessHollowingToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, ProcessHollowingToolNames,
                        "Process Hollowing Tool Detected",
                        Risk.Critical,
                        "Process hollowing or RunPE tool found. These tools are used by cheats to execute malicious code inside legitimate host processes, bypassing anti-cheat process enumeration and signature scanning.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckApiHookBypassToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, ApiHookBypassToolNames,
                        "API Hook Bypass/Unhook Tool Detected",
                        Risk.Critical,
                        "API unhooking or inline-hook bypass tool found. These tools restore anti-cheat monitoring hooks in ntdll.dll and other system DLLs, disabling API-level telemetry collection that anti-cheat software relies on to detect suspicious behavior.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckTimingBypassToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, TimingBypassToolNames,
                        "Timing-Based Anti-Debug Bypass Tool Detected",
                        Risk.High,
                        "Tool that bypasses RDTSC or high-resolution timer anti-debug checks found. Anti-cheat software measures instruction timing to detect debugger-induced delays; these tools spoof the RDTSC instruction or QueryPerformanceCounter to defeat those measurements.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckAntiMemoryScanToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, AntiMemoryScanToolNames,
                        "Anti-Memory Scan Cloaking Tool Detected",
                        Risk.Critical,
                        "Memory cloaking or guard-page bypass tool found. These tools hide cheat code from anti-cheat memory scans by using guard pages, working set manipulation, or VirtualProtect tricks to temporarily conceal executable memory regions during scan windows.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckKernelPatchToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, KernelPatchToolNames,
                        "Kernel Patch / DSE Bypass Tool Detected",
                        Risk.Critical,
                        "Kernel patching tool (ntoskrnl.exe patching, DSE/PatchGuard bypass) found. These tools modify the Windows kernel in memory to disable code-signing enforcement and remove anti-cheat kernel callbacks, enabling unsigned driver loading for deep evasion.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckVmDetectBypassToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, VmDetectBypassToolNames,
                        "VM / Sandbox Detection Bypass Tool Detected",
                        Risk.High,
                        "Tool that bypasses virtual machine or sandbox detection found (CPUID spoofing, RDMSR bypass, hypervisor artifact cleanup). These tools mask virtualization artifacts to circumvent anti-cheat checks that refuse to run inside virtual machines.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckAntiDebugRegistryKeysAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (var keyPath in AntiDebugRegistryPaths)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                {
                    try
                    {
                        using var key = hive.OpenSubKey(keyPath);
                        if (key is null) continue;
                        ctx.IncrementRegistryKeys();

                        var hiveName = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                        var toolName = keyPath.Contains('\\')
                            ? keyPath.Substring(keyPath.LastIndexOf('\\') + 1)
                            : keyPath;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Anti-Debug Tool Registry Key Present: {toolName}",
                            Risk = Risk.High,
                            Location = $@"{hiveName}\{keyPath}",
                            Reason = $"Registry key '{hiveName}\\{keyPath}' associated with the anti-debug/analysis tool '{toolName}' was found. This key is created on installation or first run, confirming that the tool has been used on this system.",
                            Detail = $"Hive: {hiveName}, Key path: {keyPath}"
                        });
                    }
                    catch { }
                }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckAppDataAntiDebugConfigsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var configRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            };

            var extensions = new[] { "*.cfg", "*.ini", "*.json", "*.xml", "*.txt", "*.conf" };

            foreach (var rootDir in configRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(rootDir)) continue;

                IEnumerable<string> allFiles = Enumerable.Empty<string>();
                foreach (var ext in extensions)
                {
                    try
                    {
                        allFiles = allFiles.Concat(
                            Directory.EnumerateFiles(rootDir, ext, SearchOption.AllDirectories));
                    }
                    catch (UnauthorizedAccessException) { }
                }

                foreach (var file in allFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(file);

                    bool nameHit = AntiDebugContentKeywords.Any(kw =>
                        fileName.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (!nameHit) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var contentHit = AntiDebugContentKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Anti-Debug Config File in AppData: {fileName}",
                        Risk = Risk.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Configuration file '{fileName}' matching anti-debug evasion keyword pattern found in AppData/Temp." +
                                 (contentHit is not null
                                     ? $" File content also contains keyword '{contentHit}', confirming anti-debug tool configuration."
                                     : " Filename matches known anti-debug configuration naming pattern."),
                        Detail = contentHit is not null
                            ? $"Content keyword: '{contentHit}'"
                            : "Filename pattern match only"
                    });
                }
            }
        }, ct);
    }

    private Task CheckDebuggerPrefetchArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var prefetchDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "Prefetch");
            if (!Directory.Exists(prefetchDir))
            {
                await Task.CompletedTask;
                return;
            }

            IEnumerable<string> prefetchFiles;
            try { prefetchFiles = Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { await Task.CompletedTask; return; }
            catch (IOException) { await Task.CompletedTask; return; }

            foreach (var pfFile in prefetchFiles)
            {
                ct.ThrowIfCancellationRequested();
                var pfName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();

                var matched = DebuggerPrefetchKeywords.FirstOrDefault(kw =>
                    pfName.StartsWith(kw, StringComparison.OrdinalIgnoreCase));
                if (matched is null) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Debugger/Anti-Debug Tool Prefetch Entry: {Path.GetFileName(pfFile)}",
                    Risk = Risk.High,
                    Location = pfFile,
                    FileName = Path.GetFileName(pfFile),
                    Reason = $"Windows Prefetch file '{Path.GetFileName(pfFile)}' matches known debugger or anti-debug tool name pattern '{matched}'. Prefetch entries are created when a program is executed and persist as forensic evidence even after the tool has been deleted. This indicates the tool was run on this system.",
                    Detail = $"Prefetch file: {pfFile} | Matched keyword: {matched}"
                });
            }
        }, ct);
    }

    private Task CheckHeapDebugArtifactFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            var artifactNameSet = new HashSet<string>(HeapDebugArtifactFileNames, StringComparer.OrdinalIgnoreCase);

            foreach (var rootDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(rootDir)) continue;

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(rootDir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(file);
                    if (!artifactNameSet.Contains(fileName)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Debug Heap / NtGlobalFlag Artifact File: {fileName}",
                        Risk = Risk.Medium,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Artifact file '{fileName}' associated with debug-heap or NtGlobalFlag manipulation found. These files are produced by tools that inspect or modify the Windows debug heap flags (used by anti-cheat to detect debuggers) or log the results of heap flag cleanup operations.",
                        Detail = $"File path: {file}"
                    });
                }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckSyscallBypassToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, SyscallBypassToolNames,
                        "Direct Syscall / Syscall Bypass Tool Detected",
                        Risk.Critical,
                        "Tool implementing direct syscalls (SysWhispers, Hell's Gate, Halo's Gate, Tartarus Gate) or syscall bypass found. These tools invoke Windows syscalls directly without going through ntdll.dll, bypassing any API-level hooks placed by anti-cheat software on ntdll exports.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckExceptionBypassToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, ExceptionBypassToolNames,
                        "Exception-Based Anti-Debug Bypass Tool Detected",
                        Risk.High,
                        "Tool that bypasses exception-based debugger detection (VEH/SEH bypass, INT3 breakpoint bypass, hardware breakpoint DR register bypass) found. Anti-cheat software uses structured exception handling and vectored exception handlers to detect debugger presence; these tools subvert those checks.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private async Task ScanDirectoryForNamesAsync(
        ScanContext ctx,
        CancellationToken ct,
        string directory,
        string[] targetNames,
        string findingTitle,
        RiskLevel riskLevel,
        string reason)
    {
        var nameSet = new HashSet<string>(targetNames, StringComparer.OrdinalIgnoreCase);
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(file);
            if (!nameSet.Contains(fileName)) continue;

            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"{findingTitle}: {fileName}",
                Risk = riskLevel,
                Location = file,
                FileName = fileName,
                Reason = $"{reason} Matched file: '{file}'.",
                Detail = $"Matched file name: {fileName}"
            });
        }
        await Task.CompletedTask;
    }

    private static string[] GetUserSearchDirectories()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();
        var desktop = Path.Combine(userProfile, "Desktop");
        var downloads = Path.Combine(userProfile, "Downloads");
        var documents = Path.Combine(userProfile, "Documents");
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        return new[]
        {
            userProfile,
            appData,
            localAppData,
            temp,
            desktop,
            downloads,
            documents,
            programFiles,
            programFilesX86,
        };
    }
}
