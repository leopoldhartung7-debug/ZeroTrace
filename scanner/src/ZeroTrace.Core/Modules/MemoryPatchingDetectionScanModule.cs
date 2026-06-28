using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class MemoryPatchingDetectionScanModule : IScanModule
{
    public string Name => "Memory Patching Detection";
    public double Weight => 4.5;
    public int ParallelGroup => 4;

    private static readonly string[] MemPatchToolExeNames =
    [
        "mem_patch.exe", "memory_patcher.exe", "mem_patcher.exe",
        "game_patcher.exe", "ntdll_patch.exe", "dll_patcher.exe",
        "pe_patcher.exe", "binary_patcher.exe", "patch_tool.exe",
        "hex_patcher.exe", "hex_editor_patch.exe", "memory_editor.exe",
        "mem_editor.exe", "mem_hacker.exe", "memory_hacker.exe",
        "game_hack.exe", "game_memory.exe", "process_memory.exe",
        "proc_memory.exe", "read_write_memory.exe", "rw_memory.exe",
        "write_process_memory.exe", "wpm_tool.exe", "rpm_tool.exe",
        "process_rw.exe", "memory_rw.exe", "mem_rw.exe",
        "trainer_patcher.exe", "game_trainer_patcher.exe",
        "game_freeze.exe", "value_freeze.exe", "memory_freeze.exe",
        "game_speed_hack.exe", "speedhack.exe", "speed_hack.exe",
        "timing_hack.exe", "fps_hack.exe", "timer_patch.exe",
        "anti_cheat_bypass.exe", "ac_patcher.exe", "vac_patcher.exe",
        "be_patcher.exe", "eac_patcher.exe", "xigncode_patch.exe",
        "nprotect_patch.exe", "hackshield_patch.exe", "gameguard_patch.exe",
        "denuvo_patch.exe", "steam_patch.exe", "origin_patch.exe",
        "epicgames_patch.exe", "uplay_patch.exe", "bnet_patch.exe",
        "live_patcher.exe", "crc_bypass.exe", "hash_bypass.exe",
        "checksum_bypass.exe", "integrity_bypass.exe",
        "memory_scan_bypass.exe", "memscan_bypass.exe",
        "page_protect_bypass.exe", "vad_bypass.exe",
        "working_set_bypass.exe", "page_guard_bypass.exe",
        "execute_bypass.exe", "nx_bypass.exe", "dep_bypass.exe",
        "aslr_bypass.exe", "cfg_bypass.exe", "cet_bypass.exe",
    ];

    private static readonly string[] MemPatchToolDllNames =
    [
        "mem_patch.dll", "memory_patcher.dll", "ntdll_patch.dll",
        "dll_patcher.dll", "pe_patcher.dll", "binary_patch.dll",
        "game_patch.dll", "mem_editor.dll", "memory_editor.dll",
        "wpm_hook.dll", "rpm_hook.dll", "memory_hook.dll",
        "process_mem.dll", "patch_lib.dll", "patcher_lib.dll",
        "freeze_lib.dll", "speed_hack.dll", "timer_hack.dll",
        "crc_bypass.dll", "hash_bypass.dll", "checksum_bypass.dll",
        "integrity_bypass.dll", "scan_bypass.dll", "memscan_bypass.dll",
        "page_guard_bypass.dll", "vad_bypass.dll", "nx_bypass.dll",
        "dep_bypass.dll", "aslr_bypass.dll", "cfg_bypass.dll",
    ];

    private static readonly string[] MemPatchConfigKeywords =
    [
        "mem_patch", "memory_patch", "ntdll_patch", "patch_address",
        "patch_offset", "patch_bytes", "patch_value", "write_memory",
        "read_memory", "freeze_value", "freeze_address", "game_speed",
        "speed_multiplier", "timer_patch", "crc_bypass", "hash_bypass",
        "checksum_bypass", "integrity_bypass", "scan_bypass", "memscan_bypass",
        "page_guard_bypass", "vad_bypass", "dep_bypass", "aslr_bypass",
        "cfg_bypass", "cet_bypass", "nx_bypass", "protection_bypass",
        "memory_protection", "vp_bypass", "virtualprotect_bypass",
        "rwe_page", "rwx_page", "shellcode_inject", "payload_inject",
        "game_offset", "cheat_offset", "hack_offset", "memory_offset",
        "actor_offset", "entity_offset", "player_offset", "health_offset",
        "ammo_offset", "money_offset", "speed_offset", "position_offset",
        "aimbot_offset", "esp_offset", "wallhack_offset", "visibility_offset",
        "godmode_offset", "noclip_offset", "fly_offset", "teleport_offset",
    ];

    private static readonly string[] MemPatchDirNames =
    [
        "mem_patch", "memory_patch", "game_patch", "patcher",
        "game_patcher", "memory_editor", "hex_editor_patches",
        "speed_hack", "timer_hack", "freeze_tool",
        "crc_bypass", "hash_bypass", "integrity_bypass",
        "scan_bypass", "protection_bypass", "dep_bypass",
        "trainer_patches", "cheat_patches", "hack_patches",
        "offset_library", "offset_db", "game_offsets",
        "cheat_offsets", "hack_offsets",
    ];

    private static readonly string[] MemPatchLogFileNames =
    [
        "mem_patch.log", "memory_patch.log", "patch.log",
        "patcher.log", "game_patch.log", "hack.log",
        "cheat_patch.log", "offset_dump.txt", "mem_dump.txt",
        "memory_dump.log", "patch_history.log", "patch_record.txt",
        "patcher_log.txt", "bypass_log.txt", "freeze_log.txt",
    ];

    private static readonly string[] OffsetFileExtensions =
    [
        ".offsets", ".offset", ".ofs", ".off",
    ];

    private static readonly string[] UserDirs;

    static MemoryPatchingDetectionScanModule()
    {
        var dirs = new List<string>();
        string? profile = Environment.GetEnvironmentVariable("USERPROFILE");
        string? appData = Environment.GetEnvironmentVariable("APPDATA");
        string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        string? temp = Environment.GetEnvironmentVariable("TEMP");
        string? desktop = profile != null ? Path.Combine(profile, "Desktop") : null;
        string? downloads = profile != null ? Path.Combine(profile, "Downloads") : null;
        string? documents = profile != null ? Path.Combine(profile, "Documents") : null;

        foreach (var d in new[] { appData, localAppData, temp, desktop, downloads, documents })
            if (d != null) dirs.Add(d);

        UserDirs = [.. dirs];
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            ScanForMemPatchExes(ctx, ct),
            ScanForMemPatchDlls(ctx, ct),
            ScanForMemPatchDirs(ctx, ct),
            ScanConfigsForMemPatchKeywords(ctx, ct),
            ScanForOffsetFiles(ctx, ct),
            ScanForPatchLogFiles(ctx, ct),
            CheckMemPatchRegistryArtifacts(ctx, ct),
            CheckNtdllPatchingArtifacts(ctx, ct),
            ScanForShellcodePayloads(ctx, ct),
            CheckGameDirForMemPatchDlls(ctx, ct)
        ).ConfigureAwait(false);
    }

    private Task ScanForMemPatchExes(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string patchExe in MemPatchToolExeNames)
                        {
                            if (fn.Equals(patchExe, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Memory Patching Tool Executable Found",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known memory patching/editing tool detected",
                                    Detail = $"Memory patch tool '{fn}' found at: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForMemPatchDlls(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string patchDll in MemPatchToolDllNames)
                        {
                            if (fn.Equals(patchDll, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Memory Patching DLL Found",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known memory patch/hook DLL found in user directory",
                                    Detail = $"Memory patch library '{fn}' found at: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForMemPatchDirs(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string dir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string dn = Path.GetFileName(dir);
                        foreach (string patchDir in MemPatchDirNames)
                        {
                            if (dn.Equals(patchDir, StringComparison.OrdinalIgnoreCase)
                                || dn.Contains(patchDir, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Memory Patching Tool Directory Found",
                                    Risk = RiskLevel.High,
                                    Location = dir,
                                    FileName = dn,
                                    Reason = "Directory name matches known memory patching tool pattern",
                                    Detail = $"Memory patch directory: {dir}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanConfigsForMemPatchKeywords(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext != ".json" && ext != ".cfg" && ext != ".ini" && ext != ".txt"
                            && ext != ".yaml" && ext != ".toml") continue;
                        if (new FileInfo(file).Length > 2_000_000) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            foreach (string kw in MemPatchConfigKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Memory Patching Config Keyword Found",
                                        Risk = RiskLevel.High,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Config contains memory patching keyword: '{kw}'",
                                        Detail = $"Memory patch config found in: {file}"
                                    });
                                    ctx.IncrementFiles();
                                    break;
                                }
                            }
                        }
                        catch (IOException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForOffsetFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string ext = Path.GetExtension(file).ToLowerInvariant();
                        if (!OffsetFileExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            if (content.Contains("0x", StringComparison.OrdinalIgnoreCase) &&
                                (content.Contains("player", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("entity", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("health", StringComparison.OrdinalIgnoreCase) ||
                                 content.Contains("weapon", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Game Cheat Offset File Found",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "Offset file with game memory addresses found — used by memory patching cheats",
                                    Detail = $"Game offset file: {file}"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                        catch (IOException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForPatchLogFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string logFile in MemPatchLogFileNames)
                        {
                            if (fn.Equals(logFile, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Memory Patching Log File Found",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Memory patch tool log file found — indicates previous patching activity",
                                    Detail = $"Patch log file: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckMemPatchRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] memPatchRegKeys =
            [
                @"SOFTWARE\MemPatcher",
                @"SOFTWARE\MemoryPatcher",
                @"SOFTWARE\GamePatcher",
                @"SOFTWARE\SpeedHack",
                @"SOFTWARE\TimerHack",
                @"SOFTWARE\FreezeTool",
                @"SOFTWARE\CrcBypass",
                @"SOFTWARE\IntegrityBypass",
                @"SOFTWARE\ScanBypass",
                @"SOFTWARE\ProtectionBypass",
            ];

            foreach (string regKey in memPatchRegKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(regKey)
                                          ?? Registry.CurrentUser.OpenSubKey(regKey);
                    if (key != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Memory Patching Tool Registry Key Found",
                            Risk = RiskLevel.High,
                            Location = regKey,
                            FileName = "registry",
                            Reason = "Known memory patching tool left a registry artifact",
                            Detail = $"Memory patcher registry key: {regKey}"
                        });
                        ctx.IncrementRegistryKeys();
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            try
            {
                using RegistryKey? muiCache = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
                if (muiCache != null)
                {
                    foreach (string valName in muiCache.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        foreach (string patchExe in MemPatchToolExeNames)
                        {
                            if (valName.Contains(patchExe, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Memory Patcher Execution Evidence in MUICache",
                                    Risk = RiskLevel.High,
                                    Location = @"HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                                    FileName = "registry",
                                    Reason = "MUICache records previous execution of memory patching tool",
                                    Detail = $"MUICache entry: {valName}"
                                });
                                ctx.IncrementRegistryKeys();
                                break;
                            }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckNtdllPatchingArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (localAppData == null) return;

            string[] ntdllPatchFiles =
            [
                "ntdll_backup.dll", "ntdll_orig.dll", "ntdll_clean.dll",
                "ntdll_patched.dll", "ntdll_hooked.dll", "ntdll_hook.dll",
                "ntdll_replace.dll", "ntdll_bypass.dll",
                "kernel32_backup.dll", "kernel32_orig.dll",
                "user32_backup.dll", "user32_orig.dll",
                "ntdll.dll.bak", "kernel32.dll.bak",
            ];

            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string ntdllFile in ntdllPatchFiles)
                        {
                            if (fn.Equals(ntdllFile, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "ntdll/Kernel DLL Backup/Patch Artifact Found",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Backup or patched copy of system DLL found — ntdll patching cheat technique",
                                    Detail = $"System DLL manipulation artifact: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForShellcodePayloads(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string? temp = Environment.GetEnvironmentVariable("TEMP");
            if (temp == null || !Directory.Exists(temp)) return;

            try
            {
                foreach (string file in Directory.EnumerateFiles(temp, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    string ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext != ".bin" && ext != ".sc" && ext != ".shellcode" && ext != ".raw") continue;

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length < 64 || fi.Length > 5_000_000) continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        byte[] header = new byte[4];
                        fs.Read(header, 0, 4);

                        bool isShellcode = !(header[0] == 0x4D && header[1] == 0x5A);
                        if (isShellcode && ext == ".bin" || ext == ".sc" || ext == ".shellcode" || ext == ".raw")
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Shellcode Payload File in Temp Directory",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Potential shellcode payload file found in %TEMP% — memory injection staging",
                                Detail = $"Shellcode payload: {file} ({fi.Length} bytes)"
                            });
                            ctx.IncrementFiles();
                        }
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckGameDirForMemPatchDlls(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (localAppData == null) return;

            string[] gameDirRoots =
            [
                Path.Combine(localAppData, "FiveM"),
                Path.Combine(localAppData, "RAGEMP"),
                Path.Combine(localAppData, "altv"),
            ];

            foreach (string gameDir in gameDirRoots)
            {
                if (!Directory.Exists(gameDir)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(gameDir, "*.dll", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string patchDll in MemPatchToolDllNames)
                        {
                            if (fn.Equals(patchDll, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Memory Patch DLL Found in Game Directory",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"Memory patching DLL found inside game directory: {Path.GetFileName(gameDir)}",
                                    Detail = $"Patch DLL '{fn}' inside game directory: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }
}
