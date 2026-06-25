using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

// Process injection technique detection module.
// Detects file and config artifacts from DLL injection, manual mapping,
// process hollowing, reflective DLL injection, APC injection, NTDLL unhooking,
// direct syscall stubs, Heaven's Gate, AtomBombing, SetWindowsHookEx abuse,
// cheat loader EXEs, injection remnant DLLs in Temp, and injection config files.
// No P/Invoke — detection is entirely file- and registry-based.
public sealed class ProcessInjectionTechniqueScanModule : IScanModule
{
    public string Name => "Process Injection Technique Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Known DLL injector tool file names
    // -------------------------------------------------------------------------
    private static readonly string[] KnownInjectorFileNames =
    [
        "injector.exe",
        "dll_injector.exe",
        "GHInjector.exe",
        "Xenos.exe",
        "Xenos64.exe",
        "ExtremeInjector.exe",
        "winject.exe",
        "inject32.exe",
        "inject64.exe",
        "syringe.exe",
        "Syringe.exe",
        "RemoteDll.exe",
        "DLLInject.exe",
        "dll_inject.exe",
        "SimpleInjector.exe",
        "NinjaInjector.exe",
        "GameInject.exe",
        "GameInjector.exe",
        "LoaderInject.exe",
        "inject_x64.exe",
        "inject_x86.exe",
    ];

    // -------------------------------------------------------------------------
    // Manual map injector tool file names
    // -------------------------------------------------------------------------
    private static readonly string[] ManualMapInjectorFileNames =
    [
        "manualmapper.exe",
        "ManualMap.exe",
        "mm_inject.exe",
        "ManualMapper.exe",
        "manual_map.exe",
        "mmapper.exe",
        "mm_loader.exe",
        "mmaploader.exe",
        "MapLoader.exe",
        "KernelMapper.exe",
        "kernel_mapper.exe",
        "mm64.exe",
        "mm32.exe",
    ];

    // -------------------------------------------------------------------------
    // Process hollowing tool file names
    // -------------------------------------------------------------------------
    private static readonly string[] ProcessHollowingFileNames =
    [
        "hollower.exe",
        "ProcessHollowing.exe",
        "ph_inject.exe",
        "hollow.exe",
        "process_hollow.exe",
        "PHollow.exe",
        "hollow_inject.exe",
        "phollowing.exe",
        "hollow_loader.exe",
        "RunPE.exe",
        "runpe.exe",
        "RunPE64.exe",
    ];

    // -------------------------------------------------------------------------
    // Reflective DLL injection tool file names
    // -------------------------------------------------------------------------
    private static readonly string[] ReflectiveInjectorFileNames =
    [
        "rdll_inject.exe",
        "ReflectiveDLLInjection.exe",
        "ReflectiveLoader.exe",
        "reflective_inject.exe",
        "rdll_loader.exe",
        "reflect_inject.exe",
        "ReflectiveDLL.exe",
        "rdll64.exe",
    ];

    // -------------------------------------------------------------------------
    // APC injection tool file names
    // -------------------------------------------------------------------------
    private static readonly string[] ApcInjectorFileNames =
    [
        "apc_inject.exe",
        "APCInject.exe",
        "apc_loader.exe",
        "APCLoader.exe",
        "early_bird.exe",
        "EarlyBird.exe",
        "apc_inject64.exe",
        "NtQueueApc.exe",
    ];

    // -------------------------------------------------------------------------
    // AtomBombing tool file names
    // -------------------------------------------------------------------------
    private static readonly string[] AtomBombingFileNames =
    [
        "atombombing.exe",
        "atom_bomb.exe",
        "AtomBomb.exe",
        "AtomBombing.exe",
        "atom_inject.exe",
        "AtomInject.exe",
    ];

    // -------------------------------------------------------------------------
    // Cheat loader EXE names (60+ entries)
    // -------------------------------------------------------------------------
    private static readonly string[] CheatLoaderFileNames =
    [
        "loader32.exe",
        "loader64.exe",
        "cheat_loader.exe",
        "game_loader.exe",
        "hack_loader.exe",
        "payload_loader.exe",
        "steam_loader.exe",
        "cheatloader.exe",
        "CheatLoader.exe",
        "GameLoader.exe",
        "HackLoader.exe",
        "PayloadLoader.exe",
        "SteamLoader.exe",
        "inject_loader.exe",
        "InjectLoader.exe",
        "bypass_loader.exe",
        "BypassLoader.exe",
        "external_loader.exe",
        "ExternalLoader.exe",
        "internal_loader.exe",
        "InternalLoader.exe",
        "cheat_client.exe",
        "CheatClient.exe",
        "hack_client.exe",
        "HackClient.exe",
        "game_hack.exe",
        "GameHack.exe",
        "esp_loader.exe",
        "aimbot_loader.exe",
        "wallhack_loader.exe",
        "csgo_loader.exe",
        "cs2_loader.exe",
        "apex_loader.exe",
        "rust_loader.exe",
        "pubg_loader.exe",
        "valorant_loader.exe",
        "fortnite_loader.exe",
        "warzone_loader.exe",
        "tarkov_loader.exe",
        "dayz_loader.exe",
        "r6_loader.exe",
        "bf_loader.exe",
        "loader_internal.exe",
        "loader_external.exe",
        "UniversalLoader.exe",
        "universal_loader.exe",
        "MultiLoader.exe",
        "multi_loader.exe",
        "loader_v2.exe",
        "loader_v3.exe",
        "loader_final.exe",
        "loader_release.exe",
        "loader_beta.exe",
        "loader_cracked.exe",
        "loader_private.exe",
        "loader_leak.exe",
        "loader_free.exe",
        "AimLoader.exe",
        "aim_loader.exe",
        "CobaltStrikeLoader.exe",
        "cs_loader.exe",
        "beacon_loader.exe",
        "stager_loader.exe",
    ];

    // -------------------------------------------------------------------------
    // GitHub repo dir names for injection technique projects
    // -------------------------------------------------------------------------
    private static readonly string[] InjectionRepoDirNames =
    [
        "ManualMap",
        "manual-mapping",
        "manual_map_injection",
        "Blackbone",
        "BlackBone",
        "GHInjector",
        "XenosInjector",
        "ExtremeInjector",
        "ReflectiveDLLInjection",
        "reflective-dll-injection",
        "ProcessHollowing",
        "process-hollowing",
        "process_hollowing",
        "AtomBombing",
        "atom-bombing",
        "DLL-Injection",
        "dll-injection",
        "DLLInjection",
        "dll_injection",
        "APC-Injection",
        "apc-injection",
        "apc_injection",
        "SyscallStubs",
        "syscall-stubs",
        "direct-syscalls",
        "DirectSyscall",
        "NtdllUnhook",
        "ntdll-unhook",
        "ntdll_unhook",
    ];

    // -------------------------------------------------------------------------
    // Config file injection method keywords
    // -------------------------------------------------------------------------
    private static readonly string[] InjectionConfigKeywords =
    [
        "inject_method=crt",
        "injection=remote_thread",
        "injection=hollowing",
        "injection=reflective",
        "injection=manual_map",
        "inject_method=remote_thread",
        "inject_method=hollowing",
        "inject_method=reflective",
        "inject_method=manual_map",
        "manual_map=true",
        "manualmap=true",
        "map_method=manual",
        "hollow=true",
        "process_hollow=true",
        "NtQueueApcThread",
        "apc_injection=true",
        "heavens_gate=true",
        "heaven_gate=true",
        "direct_syscall=true",
        "syscall_stub=true",
        "ntdll_unhook=true",
        "unhook_ntdll=true",
        "injection_method",
        "inject_mode",
    ];

    // =========================================================================
    // Entry point
    // =========================================================================
    public async Task RunAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await ScanInjectorToolFilesAsync(ctx, ct);
        await ScanManualMapFilesAsync(ctx, ct);
        await ScanManualMapConfigsAsync(ctx, ct);
        await ScanProcessHollowingFilesAsync(ctx, ct);
        await ScanReflectiveInjectionFilesAsync(ctx, ct);
        await CheckReflectiveDllsContentAsync(ctx, ct);
        await ScanApcInjectionFilesAsync(ctx, ct);
        await CheckNtdllUnhookingArtifactsAsync(ctx, ct);
        await ScanDirectSyscallFilesAsync(ctx, ct);
        await CheckHeavensGateArtifactsAsync(ctx, ct);
        await ScanAtomBombingFilesAsync(ctx, ct);
        await CheckSetWindowsHookExAbuseDllsAsync(ctx, ct);
        await ScanCheatLoaderFilesAsync(ctx, ct);
        await ScanTempInjectionRemnantDllsAsync(ctx, ct);
        await ScanInjectionConfigFilesAsync(ctx, ct);
        await CheckInjectionRepoDirsAsync(ctx, ct);
    }

    // =========================================================================
    // 1. DLL injector tool files
    // =========================================================================
    private async Task ScanInjectorToolFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await ScanFileNamesInUserDirsAsync(
            ctx, ct,
            KnownInjectorFileNames,
            "Known DLL Injector Tool Detected",
            "matches a known DLL injection tool. These tools load arbitrary DLLs into running game processes.");
    }

    // =========================================================================
    // 2. Manual map injector files
    // =========================================================================
    private async Task ScanManualMapFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await ScanFileNamesInUserDirsAsync(
            ctx, ct,
            ManualMapInjectorFileNames,
            "Manual Map Injector Tool Detected",
            "matches a known manual-map DLL injector. Manual mapping bypasses standard DLL load-order checks and is used by cheats to avoid detection by anti-cheat modules that watch for loaded DLLs.");
    }

    // =========================================================================
    // 3. Manual map config files
    // =========================================================================
    private async Task ScanManualMapConfigsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs   = BuildUserScanDirectories();
        string[] configExts = ["*.ini", "*.cfg", "*.json", "*.txt", "*.xml"];

        string[] mmKeywords =
        [
            "manual_map",
            "manualmap",
            "map_method=manual",
            "manual_mapping",
            "mm_inject",
            "mm_mode",
        ];

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            foreach (string ext in configExts)
            {
                IEnumerable<string> configFiles;
                try
                {
                    configFiles = Directory.EnumerateFiles(dir, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string configPath in configFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    await InspectConfigForKeywordsAsync(
                        ctx, configPath, mmKeywords,
                        "Config File Contains Manual Map Injection Setting",
                        RiskLevel.High,
                        "Manual map injection is an advanced DLL injection technique that bypasses module list monitoring used by anti-cheat systems.",
                        ct);
                }
            }
        }
    }

    // =========================================================================
    // 4. Process hollowing tool files
    // =========================================================================
    private async Task ScanProcessHollowingFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await ScanFileNamesInUserDirsAsync(
            ctx, ct,
            ProcessHollowingFileNames,
            "Process Hollowing Tool Detected",
            "matches a known process hollowing tool. Process hollowing replaces a legitimate process image with cheat code to hide the injection in a trusted process name.");
    }

    // =========================================================================
    // 5. Reflective DLL injection tool files
    // =========================================================================
    private async Task ScanReflectiveInjectionFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await ScanFileNamesInUserDirsAsync(
            ctx, ct,
            ReflectiveInjectorFileNames,
            "Reflective DLL Injection Tool Detected",
            "matches a known reflective DLL injection tool. Reflective injection loads a DLL from memory without touching disk, bypassing file-based anti-cheat scans.");
    }

    // =========================================================================
    // 6. Reflective DLLs — check first 4KB for ReflectiveLoader export string
    // =========================================================================
    private async Task CheckReflectiveDllsContentAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs = BuildUserScanDirectories();

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string dllPath in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await CheckDllForReflectiveLoaderAsync(ctx, dllPath, ct);
            }
        }
    }

    private async Task CheckDllForReflectiveLoaderAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string dllPath,
        CancellationToken ct)
    {
        byte[] buffer = new byte[4096];
        int bytesRead;

        try
        {
            using var fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            bytesRead = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (bytesRead < 16)
            return;

        // Search for "ReflectiveLoader" ASCII string in first 4KB
        string headerText = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead);

        if (headerText.Contains("ReflectiveLoader", StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "DLL Contains ReflectiveLoader Export in First 4KB",
                Risk     = RiskLevel.Critical,
                Location = dllPath,
                FileName = Path.GetFileName(dllPath),
                Reason   = "The DLL contains the 'ReflectiveLoader' string in its first 4KB, which is the signature export function of reflectively injectable DLLs. These DLLs are designed to load themselves from memory without using standard Windows loader calls.",
                Detail   = $"String found at byte offset within first 4096 bytes",
            });
        }
    }

    // =========================================================================
    // 7. APC injection tool files
    // =========================================================================
    private async Task ScanApcInjectionFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await ScanFileNamesInUserDirsAsync(
            ctx, ct,
            ApcInjectorFileNames,
            "APC Injection Tool Detected",
            "matches a known APC (Asynchronous Procedure Call) injection tool. APC injection queues execution into alertable threads of target processes and is used by cheats to avoid CreateRemoteThread-based detection.");
    }

    // =========================================================================
    // 8. NTDLL unhooking — backup ntdll.dll copies in temp directories
    // =========================================================================
    private async Task CheckNtdllUnhookingArtifactsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string windir   = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";
        string sys32    = Path.Combine(windir, "System32");
        string sysWow64 = Path.Combine(windir, "SysWOW64");

        // Only search temporary/user-writable directories for stray ntdll.dll copies
        string[] tempDirs =
        [
            Path.GetTempPath(),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Temp"),
        ];

        foreach (string tempDir in tempDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(tempDir))
                continue;

            IEnumerable<string> ntdllFiles;
            try
            {
                ntdllFiles = Directory.EnumerateFiles(tempDir, "ntdll.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string ntdllPath in ntdllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    bool inSys32    = ntdllPath.StartsWith(sys32, StringComparison.OrdinalIgnoreCase);
                    bool inSysWow64 = ntdllPath.StartsWith(sysWow64, StringComparison.OrdinalIgnoreCase);

                    if (!inSys32 && !inSysWow64)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "ntdll.dll Copy in Temp Directory (NTDLL Unhooking Artifact)",
                            Risk     = RiskLevel.Critical,
                            Location = ntdllPath,
                            FileName = "ntdll.dll",
                            Reason   = "A copy of ntdll.dll was found in a temporary directory outside System32/SysWOW64. Cheats place an unhooked copy of ntdll.dll here to bypass EDR/anti-cheat hooks by loading the clean version and using it for direct syscalls.",
                            Detail   = $"Path: {ntdllPath}",
                        });
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        // Also check for ntdll copies with alternate names (ntdll_clean.dll, ntdll_fresh.dll etc.)
        string[] altNtdllPatterns =
        [
            "ntdll_clean.dll",
            "ntdll_fresh.dll",
            "ntdll_unhook.dll",
            "ntdll_backup.dll",
            "ntdll_orig.dll",
            "ntdll_original.dll",
            "ntdll_unhooked.dll",
            "clean_ntdll.dll",
        ];

        await ScanFileNamesInUserDirsAsync(
            ctx, ct,
            altNtdllPatterns,
            "Alternate-Named ntdll.dll Copy Detected (Unhooking Artifact)",
            "matches a known alternate name used for a clean ntdll.dll copy stored for NTDLL unhooking. This technique is used by cheats to bypass anti-cheat hooks placed in ntdll.dll.");
    }

    // =========================================================================
    // 9. Direct syscall stub files
    // =========================================================================
    private async Task ScanDirectSyscallFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs   = BuildUserScanDirectories();
        string[] allExts    = ["*.exe", ".dll", "*.sys", "*.bin", "*.dat"];

        string[] syscallFileNamePatterns =
        [
            "syscall_stub",
            "direct_syscall",
            "syscall_stubs",
            "DirectSyscall",
            "SyscallStub",
            "syscalls",
            "SysCalls",
            "ntcall_stub",
            "syscall_bypass",
            "SyscallBypass",
        ];

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    string fileName     = Path.GetFileName(filePath);
                    string fileNameBase = Path.GetFileNameWithoutExtension(filePath);
                    ctx.IncrementFiles();

                    foreach (string pattern in syscallFileNamePatterns)
                    {
                        if (fileNameBase.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Direct Syscall Stub File Detected",
                                Risk     = RiskLevel.High,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File name \"{fileName}\" contains the pattern '{pattern}', indicating it is a direct syscall stub file. Direct syscall stubs bypass anti-cheat hooks on NTDLL by issuing syscalls directly without going through hooked user-mode wrappers.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        // Also scan config files for direct_syscall or syscall_stub keywords
        await ScanConfigsForDirectSyscallAsync(ctx, ct);
    }

    private async Task ScanConfigsForDirectSyscallAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs   = BuildUserScanDirectories();
        string[] configExts = ["*.ini", "*.cfg", "*.json", "*.txt"];

        string[] keywords =
        [
            "direct_syscall",
            "syscall_stub",
            "use_syscalls=true",
            "syscall_mode",
            "ntdll_unhook",
        ];

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            foreach (string ext in configExts)
            {
                IEnumerable<string> configFiles;
                try
                {
                    configFiles = Directory.EnumerateFiles(dir, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string configPath in configFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    await InspectConfigForKeywordsAsync(
                        ctx, configPath, keywords,
                        "Config File References Direct Syscall/NTDLL Unhook",
                        RiskLevel.High,
                        "Direct syscall configuration bypasses anti-cheat hooks placed on NTDLL by invoking kernel syscalls directly, without going through the monitored user-mode wrappers.",
                        ct);
                }
            }
        }
    }

    // =========================================================================
    // 10. Heaven's Gate artifacts
    // =========================================================================
    private async Task CheckHeavensGateArtifactsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs   = BuildUserScanDirectories();
        string[] configExts = ["*.ini", "*.cfg", "*.json", "*.txt", "*.xml"];

        string[] heavensGateKeywords =
        [
            "heavens_gate=true",
            "heaven_gate=true",
            "heavensgate=true",
            "heavengate=true",
            "use_wow64=true",
            "wow64_transition",
            "heaven_gate_mode",
        ];

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            foreach (string ext in configExts)
            {
                IEnumerable<string> configFiles;
                try
                {
                    configFiles = Directory.EnumerateFiles(dir, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string configPath in configFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    await InspectConfigForKeywordsAsync(
                        ctx, configPath, heavensGateKeywords,
                        "Config File Enables Heaven's Gate WoW64 Injection",
                        RiskLevel.High,
                        "Heaven's Gate is a technique that abuses the WoW64 (32-to-64-bit) transition to execute 64-bit code from a 32-bit process, bypassing 32-bit anti-cheat hooks by operating in the 64-bit context.",
                        ct);
                }
            }
        }

        // File name patterns for Heaven's Gate tools
        string[] heavensGateFileNames =
        [
            "heavensgate.exe",
            "HeavensGate.exe",
            "heavens_gate.exe",
            "heaven_gate.exe",
            "wow64_inject.exe",
            "WoW64Inject.exe",
            "wow64_bypass.exe",
        ];

        await ScanFileNamesInUserDirsAsync(
            ctx, ct,
            heavensGateFileNames,
            "Heaven's Gate WoW64 Injection Tool Detected",
            "matches a known Heaven's Gate WoW64 transition abuse tool. This technique uses the 32-to-64-bit WoW64 gateway to execute 64-bit code from a 32-bit injector, bypassing 32-bit anti-cheat hooks.");
    }

    // =========================================================================
    // 11. AtomBombing tool files
    // =========================================================================
    private async Task ScanAtomBombingFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await ScanFileNamesInUserDirsAsync(
            ctx, ct,
            AtomBombingFileNames,
            "AtomBombing Injection Tool Detected",
            "matches a known AtomBombing injection tool. AtomBombing uses the Windows Atom Table to write shellcode into a target process's memory, then uses APC injection to trigger execution — avoiding WriteProcessMemory calls.");
    }

    // =========================================================================
    // 12. SetWindowsHookEx abuse — unusual hook DLLs in system paths
    // =========================================================================
    private async Task CheckSetWindowsHookExAbuseDllsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Check the registry for AppInit_DLLs and HKCU AppInit abuses
            string[] appInitKeys =
            [
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
            ];

            foreach (string keyPath in appInitKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null)
                        continue;

                    object? appInitVal = key.GetValue("AppInit_DLLs");
                    if (appInitVal is string appInitDlls && !string.IsNullOrWhiteSpace(appInitDlls))
                    {
                        // Any AppInit_DLLs entry is suspicious in a gaming context
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "AppInit_DLLs Entry Found (SetWindowsHookEx/Global Injection Vector)",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = "AppInit_DLLs are loaded into every process that loads User32.dll. Cheat tools register hook DLLs here to inject into game processes globally without using CreateRemoteThread.",
                            Detail   = $"AppInit_DLLs = {appInitDlls}",
                        });
                    }

                    // Also check LoadAppInit_DLLs — if it is 1, AppInit is enabled
                    object? loadAppInit = key.GetValue("LoadAppInit_DLLs");
                    if (loadAppInit is int loadVal && loadVal == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "LoadAppInit_DLLs Enabled",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = "LoadAppInit_DLLs is set to 1, enabling automatic loading of AppInit_DLLs into all user-mode processes. This is a known global DLL injection vector used by cheat tools.",
                            Detail   = "LoadAppInit_DLLs = 1",
                        });
                    }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                {
                }
            }

            // Check HKCU AppInit abuse
            const string hkcuAppInit = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
            ctx.IncrementRegistryKeys();

            try
            {
                using RegistryKey? key = Registry.CurrentUser.OpenSubKey(hkcuAppInit, writable: false);
                if (key is not null)
                {
                    object? appInitVal = key.GetValue("AppInit_DLLs");
                    if (appInitVal is string appInitDlls && !string.IsNullOrWhiteSpace(appInitDlls))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "HKCU AppInit_DLLs Entry Found",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{hkcuAppInit}",
                            Reason   = "AppInit_DLLs found in the current user registry hive. This is a per-user global DLL injection vector that loads a DLL into all User32.dll-dependent processes for this user.",
                            Detail   = $"AppInit_DLLs = {appInitDlls}",
                        });
                    }
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
            {
            }
        }, ct);

        // Scan for suspicious hook DLL files in system locations
        await ScanForHookDllsInSystemAsync(ctx, ct);
    }

    private async Task ScanForHookDllsInSystemAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string windir = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";

        string[] systemDirs =
        [
            Path.Combine(windir, "System32"),
            Path.Combine(windir, "SysWOW64"),
        ];

        string[] suspiciousHookPatterns =
        [
            "hook_",
            "_hook",
            "spy_",
            "_spy",
            "inject_",
            "_inject",
            "cheat_",
            "_cheat",
            "hack_",
            "_hack",
            "bypass_",
            "_bypass",
        ];

        foreach (string systemDir in systemDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(systemDir))
                continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(systemDir, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string dllPath in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                try
                {
                    string fileNameBase = Path.GetFileNameWithoutExtension(dllPath);

                    foreach (string pattern in suspiciousHookPatterns)
                    {
                        if (fileNameBase.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Suspicious Hook/Inject DLL Found in System32",
                                Risk     = RiskLevel.Critical,
                                Location = dllPath,
                                FileName = Path.GetFileName(dllPath),
                                Reason   = $"DLL \"{Path.GetFileName(dllPath)}\" in System32/SysWOW64 has a name pattern ('{pattern}') associated with hook or injection DLLs. Placing cheat DLLs in system directories gives them global injection reach via SetWindowsHookEx.",
                                Detail   = $"System directory: {systemDir}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }
    }

    // =========================================================================
    // 13. Cheat loader EXE files
    // =========================================================================
    private async Task ScanCheatLoaderFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await ScanFileNamesInUserDirsAsync(
            ctx, ct,
            CheatLoaderFileNames,
            "Cheat Loader Executable Detected",
            "matches a known cheat loader executable. Cheat loaders are the delivery mechanism that injects cheat DLLs into game processes at launch.");
    }

    // =========================================================================
    // 14. Injection remnant DLLs in %TEMP% (inject_*.dll, payload_*.dll etc.)
    // =========================================================================
    private async Task ScanTempInjectionRemnantDllsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] tempDirs =
        [
            Path.GetTempPath(),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Temp"),
        ];

        string[] remnantPrefixes =
        [
            "inject_",
            "payload_",
            "hook_",
            "cheat_",
            "hack_",
            "loader_",
            "dll_",
            "mod_",
        ];

        foreach (string tempDir in tempDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(tempDir))
                continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(tempDir, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string dllPath in dllFiles)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    string fileName     = Path.GetFileName(dllPath);
                    string fileNameLow  = fileName.ToLowerInvariant();
                    ctx.IncrementFiles();

                    foreach (string prefix in remnantPrefixes)
                    {
                        if (fileNameLow.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Injection Remnant DLL Found in %TEMP%",
                                Risk     = RiskLevel.Critical,
                                Location = dllPath,
                                FileName = fileName,
                                Reason   = $"DLL \"{fileName}\" in a Temp directory starts with '{prefix}', matching the naming pattern of injection remnant DLLs. Cheats write their payloads to Temp before injection and may leave these remnants behind.",
                                Detail   = $"Temp directory: {Path.GetDirectoryName(dllPath)}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 15. Injection config files (inject_method, injection=, etc.)
    // =========================================================================
    private async Task ScanInjectionConfigFilesAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs   = BuildUserScanDirectories();
        string[] configExts = ["*.ini", "*.cfg", "*.json", "*.txt", "*.xml"];

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            foreach (string ext in configExts)
            {
                IEnumerable<string> configFiles;
                try
                {
                    configFiles = Directory.EnumerateFiles(dir, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string configPath in configFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    await InspectConfigForKeywordsAsync(
                        ctx, configPath, InjectionConfigKeywords,
                        "Config File Contains Process Injection Method Setting",
                        RiskLevel.High,
                        "This config file contains an injection method configuration keyword. Such settings are found in cheat loader configs that control how the cheat DLL is injected into the game process.",
                        ct);
                }
            }
        }
    }

    // =========================================================================
    // 16. GitHub injection repository directories
    // =========================================================================
    private async Task CheckInjectionRepoDirsAsync(ZeroTrace.Core.Engine.ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string[] searchRoots =
            [
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            ];

            foreach (string root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrEmpty(root) || !Directory.Exists(root))
                    continue;

                IEnumerable<string> subDirs;
                try
                {
                    subDirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (string subDir in subDirs)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        string dirName = Path.GetFileName(subDir);

                        foreach (string repoName in InjectionRepoDirNames)
                        {
                            if (dirName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "Process Injection Technique Repository Directory Found",
                                    Risk     = RiskLevel.High,
                                    Location = subDir,
                                    Reason   = $"Directory \"{dirName}\" matches a known process injection technique GitHub repository name. The user likely cloned or possesses injection toolkit source code.",
                                    Detail   = $"Matched pattern: {repoName}",
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }, ct);
    }

    // =========================================================================
    // Private shared helpers
    // =========================================================================

    private async Task ScanFileNamesInUserDirsAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        CancellationToken ct,
        string[] targetFileNames,
        string findingTitle,
        string reasonSuffix)
    {
        string[] scanDirs = BuildUserScanDirectories();

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    string fileName = Path.GetFileName(filePath);
                    ctx.IncrementFiles();

                    foreach (string target in targetFileNames)
                    {
                        if (fileName.Equals(target, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = findingTitle,
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File \"{fileName}\" {reasonSuffix}",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException)
                {
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task InspectConfigForKeywordsAsync(
        ZeroTrace.Core.Engine.ScanContext ctx,
        string configPath,
        string[] keywords,
        string findingTitle,
        RiskLevel risk,
        string reasonContext,
        CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        ct.ThrowIfCancellationRequested();

        string fileName = Path.GetFileName(configPath);

        foreach (string keyword in keywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = findingTitle,
                    Risk     = risk,
                    Location = configPath,
                    FileName = fileName,
                    Reason   = $"Config file contains the keyword \"{keyword}\". {reasonContext}",
                    Detail   = ExtractMatchingLine(content, keyword),
                });
                return;
            }
        }
    }

    private static string[] BuildUserScanDirectories()
    {
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string desktop      = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string userProfile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloads    = Path.Combine(userProfile, "Downloads");
        string systemTemp   = Path.GetTempPath();
        string localTemp    = Path.Combine(localAppData, "Temp");

        return
        [
            desktop,
            downloads,
            systemTemp,
            localTemp,
            appData,
            localAppData,
        ];
    }

    private static string ExtractMatchingLine(string content, string pattern)
    {
        foreach (string line in content.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return line.Trim();
        }

        return string.Empty;
    }
}
