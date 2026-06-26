using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ValorantAimbotForensicScanModule : IScanModule
{
    public string Name => "Valorant Aimbot & Triggerbot Forensic Scan";
    public double Weight => 4.1;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] AimbotExecutableNames =
    {
        "valorant_aimbot.exe",
        "valorant_aim.exe",
        "valorant_triggerbot.exe",
        "valorant_trigger.exe",
        "valorant_silent_aim.exe",
        "valorant_magic_bullet.exe",
        "valorant_aimassist.exe",
        "valorant_aim_assist.exe",
        "valorant_recoil.exe",
        "valorant_norecoil.exe",
        "valorant_no_recoil.exe",
        "valorant_spread.exe",
        "valorant_nospread.exe",
        "valorant_no_spread.exe",
        "valorant_rapid_fire.exe",
        "valorant_rapidfire.exe",
        "valorant_bhop.exe",
        "valorant_bunny.exe",
        "valorant_speed.exe",
        "valorant_speedhack.exe",
        "valorant_fov.exe",
        "valorant_fov_cheat.exe",
        "valorant_bone.exe",
        "valorant_bone_aim.exe",
        "valorant_headshot.exe",
        "valorant_head_aim.exe",
        "valorant_auto_aim.exe",
        "valorant_auto_fire.exe",
        "aimbot_valorant.exe",
        "triggerbot_valorant.exe",
        "silent_aim_valorant.exe",
        "magic_bullet_valorant.exe",
        "aim_assist_valorant.exe",
        "norecoil_valorant.exe",
        "no_recoil_valorant.exe",
        "nospread_valorant.exe",
        "rapid_fire_valorant.exe",
        "bhop_valorant.exe",
        "speed_valorant.exe",
        "fov_valorant.exe",
        "bone_aim_valorant.exe",
        "headshot_valorant.exe",
        "auto_aim_valorant.exe",
        "auto_fire_valorant.exe",
        "valorant_aimbot_v2.exe",
        "valorant_triggerbot_v2.exe",
        "valorant_silent_aim_v2.exe",
        "valorant_aimbot_v3.exe",
        "valorant_aim_v2.exe",
        "val_aimbot.exe",
        "val_aim.exe",
        "val_triggerbot.exe",
        "val_trigger.exe",
        "val_silent_aim.exe",
        "val_norecoil.exe",
        "val_no_recoil.exe",
        "val_fov.exe",
        "val_bhop.exe",
        "val_speed.exe",
        "val_bone_aim.exe",
        "val_headshot.exe",
        "val_auto_aim.exe",
        "val_aimassist.exe",
        "valorant_cheat.exe",
        "valorant_hack.exe",
        "valorant_loader_aim.exe",
        "valorant_injector_aim.exe",
        "valorant_bypass_aim.exe",
        "valorant_esp_aim.exe",
        "valorant_wallhack_aim.exe",
        "valorant_soft_aim.exe",
        "valorant_legit_aim.exe",
        "valorant_rage_aim.exe",
        "valorant_recoil_control.exe",
        "valorant_spread_control.exe",
        "valorant_aim_key.exe",
        "valorant_triggerkey.exe",
        "valorant_flick.exe",
        "valo_aimbot.exe",
        "valo_triggerbot.exe",
        "valo_silent_aim.exe",
        "valo_norecoil.exe",
        "valo_cheat.exe",
        "valo_hack.exe",
        "valo_aim.exe",
        "valorant_loader.exe",
        "valorant_injector.exe",
        "valorant_bypass.exe",
        "aim_valorant.exe",
        "trigger_valorant.exe",
    };

    private static readonly string[] AimbotDllNames =
    {
        "valorant_aimbot.dll",
        "valorant_aim.dll",
        "valorant_triggerbot.dll",
        "valorant_trigger.dll",
        "valorant_silent_aim.dll",
        "valorant_magic_bullet.dll",
        "valorant_aimassist.dll",
        "valorant_aim_assist.dll",
        "valorant_recoil.dll",
        "valorant_norecoil.dll",
        "valorant_no_recoil.dll",
        "valorant_spread.dll",
        "valorant_nospread.dll",
        "valorant_rapid_fire.dll",
        "valorant_rapidfire.dll",
        "valorant_bhop.dll",
        "valorant_speed.dll",
        "valorant_fov.dll",
        "valorant_bone.dll",
        "valorant_bone_aim.dll",
        "valorant_headshot.dll",
        "valorant_auto_aim.dll",
        "valorant_auto_fire.dll",
        "aimbot_valorant.dll",
        "triggerbot_valorant.dll",
        "silent_aim_valorant.dll",
        "aim_assist_valorant.dll",
        "norecoil_valorant.dll",
        "rapid_fire_valorant.dll",
        "fov_valorant.dll",
        "bone_aim_valorant.dll",
        "headshot_valorant.dll",
        "val_aimbot.dll",
        "val_aim.dll",
        "val_triggerbot.dll",
        "val_silent_aim.dll",
        "val_norecoil.dll",
        "val_fov.dll",
        "val_bone_aim.dll",
        "val_headshot.dll",
        "val_auto_aim.dll",
        "valorant_cheat.dll",
        "valorant_hack.dll",
        "valorant_loader_aim.dll",
        "valorant_injector_aim.dll",
        "valorant_bypass_aim.dll",
        "valo_aimbot.dll",
        "valo_triggerbot.dll",
        "valo_silent_aim.dll",
        "valo_norecoil.dll",
        "aim_valorant.dll",
        "trigger_valorant.dll",
        "recoil_valorant.dll",
        "spread_valorant.dll",
        "bhop_valorant.dll",
        "valorant_esp.dll",
        "valorant_wallhack.dll",
    };

    private static readonly string[] AimbotConfigFileNames =
    {
        "valorant_aimbot.json",
        "valorant_aim_config.json",
        "valorant_triggerbot.json",
        "valorant_trigger_config.json",
        "valorant_norecoil.json",
        "valorant_spread.json",
        "aimbot_config.json",
        "triggerbot_config.json",
        "aim_config.json",
        "trigger_config.json",
        "fov_config.json",
        "bone_config.json",
        "aimbot_settings.json",
        "triggerbot_settings.json",
        "valorant_config.json",
        "valorant_hack_config.json",
        "valorant_cheat_config.json",
        "valorant_aim_settings.json",
        "valorant_recoil_config.json",
        "val_aimbot_config.json",
        "val_aim_config.json",
        "val_triggerbot_config.json",
    };

    private static readonly string[] ConfigKeywords =
    {
        "FOV",
        "smooth",
        "bone",
        "aimbone",
        "triggerKey",
        "delay",
        "RCS",
        "recoil",
        "spread",
        "bhop",
        "speed",
        "aimbot",
        "triggerbot",
        "headshot",
        "autofire",
    };

    private static readonly string[] MacroScriptNamePatterns =
    {
        "valorant",
        "val_",
        "aimbot",
        "triggerbot",
        "norecoil",
        "rapid_fire",
        "bhop",
    };

    private static readonly string[] MacroScriptContentKeywords =
    {
        "MouseClick",
        "Send",
        "mouse_event",
        "SetCursorPos",
        "mouse_move",
        "win32api",
        "pyautogui",
        "keyboard",
        "win32con",
        "GetAsyncKeyState",
        "aimbot",
        "triggerbot",
        "norecoil",
        "rapid_fire",
        "bhop",
        "bunny_hop",
        "FOV",
        "smooth",
        "bone",
        "headshot",
    };

    private static readonly string[] DownloadArchiveNames =
    {
        "valorant_aimbot.zip",
        "valorant_aimbot.rar",
        "valorant_aimbot.7z",
        "valorant_aim.zip",
        "valorant_aim.rar",
        "valorant_aim.7z",
        "valorant_triggerbot.zip",
        "valorant_triggerbot.rar",
        "valorant_triggerbot.7z",
        "valorant_silent_aim.zip",
        "valorant_silent_aim.rar",
        "valorant_silent_aim.7z",
        "valorant_cheat.zip",
        "valorant_cheat.rar",
        "valorant_cheat.7z",
        "valorant_hack.zip",
        "valorant_hack.rar",
        "valorant_hack.7z",
        "valorant_norecoil.zip",
        "valorant_norecoil.rar",
        "valorant_norecoil.7z",
        "valorant_rapid_fire.zip",
        "valorant_rapid_fire.rar",
        "valorant_rapid_fire.7z",
        "valorant_bhop.zip",
        "valorant_bhop.rar",
        "valorant_bhop.7z",
        "valorant_fov.zip",
        "valorant_fov.rar",
        "valorant_fov.7z",
        "valorant_bone_aim.zip",
        "valorant_bone_aim.rar",
        "valorant_bone_aim.7z",
        "valorant_loader.zip",
        "valorant_loader.rar",
        "valorant_loader.7z",
        "valorant_injector.zip",
        "valorant_injector.rar",
        "valorant_injector.7z",
        "valorant_bypass.zip",
        "valorant_bypass.rar",
        "valorant_bypass.7z",
        "val_aimbot.zip",
        "val_aimbot.rar",
        "val_aimbot.7z",
        "val_aim.zip",
        "val_aim.rar",
        "val_aim.7z",
        "val_triggerbot.zip",
        "val_triggerbot.rar",
        "val_triggerbot.7z",
        "val_cheat.zip",
        "val_cheat.rar",
        "val_cheat.7z",
        "valo_aimbot.zip",
        "valo_aimbot.rar",
        "valo_aimbot.7z",
        "valo_cheat.zip",
        "valo_cheat.rar",
        "valo_cheat.7z",
    };

    private static readonly string[] GameLogCheatPatterns =
    {
        "aimbot detected",
        "triggerbot detected",
        "macro detected",
        "aim assist detected",
        "recoil script detected",
        "bhop detected",
        "speed hack detected",
        "cheat detected",
        "hack detected",
        "vanguard ban",
        "kernel ban",
        "aimbot ban",
        "triggerbot ban",
        "cheat ban",
        "hack ban",
        "suspicious aim",
        "suspicious behavior",
        "aim anomaly",
        "inhuman reaction",
        "perfect tracking",
        "snap aim",
        "lock-on",
        "silent aim",
        "magic bullet",
        "no recoil detected",
        "spread manipulation",
        "rapid fire detected",
        "bunnyhop detected",
        "speedhack detected",
        "fov manipulation",
        "bone aim detected",
        "headshot anomaly",
        "auto fire detected",
        "trigger delay",
        "aim smoothing",
        "aimkey detected",
        "recoil control script",
        "aim assist script",
        "triggerbot script",
        "vanguard violation",
        "kernel cheat detected",
    };

    private static readonly string[] UserAssistAimbotNames =
    {
        "valorant_aimbot",
        "valorant_aim",
        "valorant_triggerbot",
        "valorant_trigger",
        "valorant_silent_aim",
        "valorant_magic_bullet",
        "valorant_aimassist",
        "valorant_aim_assist",
        "valorant_norecoil",
        "valorant_no_recoil",
        "valorant_spread",
        "valorant_rapid_fire",
        "valorant_bhop",
        "valorant_speed",
        "valorant_fov",
        "valorant_bone_aim",
        "valorant_headshot",
        "valorant_auto_aim",
        "valorant_cheat",
        "valorant_hack",
        "valorant_loader_aim",
        "valorant_injector_aim",
        "valorant_bypass_aim",
        "val_aimbot",
        "val_aim",
        "val_triggerbot",
        "val_silent_aim",
        "val_norecoil",
        "val_fov",
        "val_bone_aim",
        "val_headshot",
        "val_auto_aim",
        "val_aimassist",
        "aimbot_valorant",
        "triggerbot_valorant",
        "silent_aim_valorant",
        "norecoil_valorant",
        "valo_aimbot",
        "valo_triggerbot",
        "valo_cheat",
    };

    private static readonly string[] MuiCacheAimbotNames =
    {
        "valorant_aimbot",
        "valorant_aim",
        "valorant_triggerbot",
        "valorant_trigger",
        "valorant_silent_aim",
        "valorant_magic_bullet",
        "valorant_aimassist",
        "valorant_aim_assist",
        "valorant_norecoil",
        "valorant_no_recoil",
        "valorant_spread",
        "valorant_rapid_fire",
        "valorant_bhop",
        "valorant_speed",
        "valorant_fov",
        "valorant_bone_aim",
        "valorant_headshot",
        "valorant_auto_aim",
        "valorant_cheat",
        "valorant_hack",
        "valorant_loader_aim",
        "valorant_injector_aim",
        "valorant_bypass_aim",
        "val_aimbot",
        "val_aim",
        "val_triggerbot",
        "val_silent_aim",
        "val_norecoil",
        "val_fov",
        "val_bone_aim",
        "val_headshot",
        "val_auto_aim",
        "val_aimassist",
        "aimbot_valorant",
        "triggerbot_valorant",
    };

    private static readonly string[] UninstallAimbotKeywords =
    {
        "valorant aimbot",
        "valorant aim",
        "valorant triggerbot",
        "valorant trigger",
        "valorant silent aim",
        "valorant magic bullet",
        "valorant no recoil",
        "valorant rapid fire",
        "valorant bhop",
        "valorant speed hack",
        "valorant fov cheat",
        "valorant bone aim",
        "valorant headshot",
        "valorant auto aim",
        "valorant cheat",
        "valorant hack",
        "valorant loader",
        "valorant injector",
        "valorant bypass",
        "val aimbot",
        "val aim",
        "val triggerbot",
        "val cheat",
    };

    private static readonly string[] VanguardBypassKeywords =
    {
        "vgk.sys",
        "vanguard bypass",
        "vanguard spoof",
        "vanguard disable",
        "vanguard kill",
        "anticheat bypass",
        "riot vanguard",
        "trvanguard",
        "vgc.exe",
    };

    private static readonly string[] ShellbagValorantPaths =
    {
        @"valorant\aimbot",
        @"valorant\triggerbot",
        @"valorant\cheat",
        @"valorant\hack",
        @"val\aimbot",
        @"val\triggerbot",
        @"val\cheat",
        @"valorant_aimbot",
        @"valorant_triggerbot",
        @"val_aimbot",
    };

    private static readonly string[] AppCompatValorantCheatNames =
    {
        "valorant_aimbot",
        "valorant_triggerbot",
        "valorant_cheat",
        "valorant_hack",
        "valorant_silent_aim",
        "valorant_norecoil",
        "val_aimbot",
        "val_triggerbot",
        "valo_aimbot",
        "aimbot_valorant",
        "triggerbot_valorant",
    };

    private static readonly string[] PrefetchAimbotNames =
    {
        "VALORANT_AIMBOT",
        "VALORANT_AIM",
        "VALORANT_TRIGGERBOT",
        "VALORANT_TRIGGER",
        "VALORANT_SILENT_AIM",
        "VALORANT_MAGIC_BULLET",
        "VALORANT_AIMASSIST",
        "VALORANT_AIM_ASSIST",
        "VALORANT_NORECOIL",
        "VALORANT_NO_RECOIL",
        "VALORANT_SPREAD",
        "VALORANT_RAPID_FIRE",
        "VALORANT_BHOP",
        "VALORANT_SPEED",
        "VALORANT_FOV",
        "VALORANT_BONE_AIM",
        "VALORANT_HEADSHOT",
        "VALORANT_AUTO_AIM",
        "VALORANT_CHEAT",
        "VALORANT_HACK",
        "VALORANT_LOADER_AIM",
        "VALORANT_INJECTOR_AIM",
        "VALORANT_BYPASS_AIM",
        "VAL_AIMBOT",
        "VAL_AIM",
        "VAL_TRIGGERBOT",
        "VAL_SILENT_AIM",
        "VAL_NORECOIL",
        "VAL_FOV",
        "AIMBOT_VALORANT",
        "TRIGGERBOT_VALORANT",
        "VALO_AIMBOT",
        "VALO_TRIGGERBOT",
    };

    private static readonly string[] EnvVarAimbotKeywords =
    {
        "valorant_aimbot",
        "valorant_triggerbot",
        "valorant_cheat",
        "valorant_hack",
        "val_aimbot",
        "val_triggerbot",
        "val_cheat",
        "valo_aimbot",
        "aimbot_valorant",
        "triggerbot_valorant",
        "valorant_bypass",
        "valorant_loader",
        "valorant_inject",
    };

    private static readonly string[] StartupFolderAimbotPatterns =
    {
        "valorant_aimbot",
        "valorant_triggerbot",
        "valorant_cheat",
        "valorant_hack",
        "valorant_silent_aim",
        "valorant_norecoil",
        "val_aimbot",
        "val_triggerbot",
        "val_cheat",
        "valo_aimbot",
        "aimbot_valorant",
        "triggerbot_valorant",
        "valorant_loader",
        "valorant_injector",
        "valorant_bypass",
    };

    private static readonly string[] ScheduledTaskAimbotKeywords =
    {
        "valorant_aimbot",
        "valorant_triggerbot",
        "valorant_cheat",
        "valorant_hack",
        "val_aimbot",
        "val_triggerbot",
        "valo_aimbot",
        "aimbot_valorant",
        "valorant_loader",
        "valorant_bypass",
        "valorant_inject",
        "valorant_silent_aim",
        "valorant_norecoil",
    };

    private static readonly string[] RecentFilesAimbotPatterns =
    {
        "valorant_aimbot",
        "valorant_triggerbot",
        "valorant_cheat",
        "valorant_hack",
        "valorant_silent_aim",
        "valorant_norecoil",
        "valorant_rapid_fire",
        "valorant_bhop",
        "val_aimbot",
        "val_triggerbot",
        "val_cheat",
        "valo_aimbot",
        "aimbot_valorant",
        "triggerbot_valorant",
        "valorant_fov",
        "valorant_bone_aim",
        "valorant_headshot",
        "valorant_loader",
        "valorant_bypass",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Valorant aimbot forensic scan...");
        return Task.WhenAll(
            CheckValorantAimbotExecutables(ctx, ct),
            CheckValorantAimbotDlls(ctx, ct),
            CheckValorantAimbotConfigFiles(ctx, ct),
            CheckValorantMacroScripts(ctx, ct),
            CheckValorantDownloadArtifacts(ctx, ct),
            CheckValorantGameLogs(ctx, ct),
            CheckValorantRegistryArtifacts(ctx, ct),
            CheckValorantPrefetchArtifacts(ctx, ct),
            CheckValorantStartupFolderArtifacts(ctx, ct),
            CheckValorantScheduledTaskArtifacts(ctx, ct),
            CheckValorantEnvironmentVariables(ctx, ct),
            CheckValorantRecentDocuments(ctx, ct)
        );
    }

    private Task CheckValorantAimbotExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var searchDirs = GetStandardSearchDirectories();
            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (!AimbotExecutableNames.Any(n =>
                            string.Equals(n, fileName, StringComparison.OrdinalIgnoreCase)))
                        continue;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Valorant Aimbot Executable Found: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Valorant aimbot/triggerbot executable '{fileName}' found at '{file}'. " +
                                   "This file matches a known Valorant aimbot or triggerbot cheat executable name. " +
                                   "Such tools are used to automate aim, trigger shots, control recoil, " +
                                   "eliminate spread, automate bunnyhop, or otherwise gain an unfair " +
                                   "advantage in Valorant ranked or unrated matches.",
                        Detail   = $"Path: {file} | File: {fileName}"
                    });
                }
            }
        }, ct);

    private Task CheckValorantAimbotDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var searchDirs = GetStandardSearchDirectories();
            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (!AimbotDllNames.Any(n =>
                            string.Equals(n, fileName, StringComparison.OrdinalIgnoreCase)))
                        continue;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Valorant Aimbot DLL Found: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Valorant aimbot DLL '{fileName}' found at '{file}'. " +
                                   "This DLL matches a known Valorant aimbot, triggerbot, or cheat injection " +
                                   "library name. Such DLLs are injected into the game process or a companion " +
                                   "process to provide aimbot, silent aim, no-recoil, or other cheating " +
                                   "functionality while Valorant is running.",
                        Detail   = $"Path: {file} | File: {fileName}"
                    });
                }
            }
        }, ct);

    private Task CheckValorantAimbotConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var configDirs = GetConfigSearchDirectories();
            foreach (var dir in configDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(dir, "*.json", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (!AimbotConfigFileNames.Any(n =>
                            string.Equals(n, fileName, StringComparison.OrdinalIgnoreCase)))
                        continue;
                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { }
                    var hitKeyword = string.IsNullOrEmpty(content)
                        ? null
                        : ConfigKeywords.FirstOrDefault(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Valorant Aimbot Config File Found: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Valorant aimbot/cheat configuration file '{fileName}' found at '{file}'. " +
                                   (hitKeyword is not null
                                       ? $"File content contains cheat-related keyword '{hitKeyword}'. "
                                       : "File name matches known aimbot config pattern. ") +
                                   "These config files store aimbot settings such as FOV, smoothing, bone " +
                                   "targets, trigger keys, recoil control values, spread parameters, " +
                                   "bhop settings, and speed hack configurations.",
                        Detail   = $"Path: {file} | Keyword: {hitKeyword ?? "name match only"}"
                    });
                }
            }
        }, ct);

    private Task CheckValorantMacroScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var scriptExtensions = new[] { ".ahk", ".py", ".au3" };
            var scriptDirs = GetStandardSearchDirectories();
            foreach (var dir in scriptDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                IEnumerable<string> allFiles = Enumerable.Empty<string>();
                try
                {
                    allFiles = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                foreach (var file in allFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var ext = Path.GetExtension(file);
                    if (!scriptExtensions.Any(e =>
                            string.Equals(e, ext, StringComparison.OrdinalIgnoreCase)))
                        continue;
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    var fileNameLower = fileName.ToLowerInvariant();
                    bool nameMatch = MacroScriptNamePatterns.Any(p =>
                        fileNameLower.Contains(p, StringComparison.OrdinalIgnoreCase));
                    if (!nameMatch) continue;
                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { }
                    if (string.IsNullOrEmpty(content)) continue;
                    var hits = MacroScriptContentKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                    if (hits.Count < 3) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Valorant Macro/Script File Found: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Macro or automation script '{fileName}' found at '{file}' " +
                                   $"with {hits.Count} cheat-related content keywords matched: " +
                                   $"{string.Join(", ", hits.Take(5))}. " +
                                   "Such scripts are used for Valorant aimbot, triggerbot, no-recoil, " +
                                   "rapid-fire, and bhop automation via AutoHotkey, Python, or AutoIt. " +
                                   "The combination of script name and content keywords strongly suggests " +
                                   "this is a cheat automation script targeting Valorant.",
                        Detail   = $"Path: {file} | Matches ({hits.Count}): {string.Join(", ", hits)}"
                    });
                }
            }
        }, ct);

    private Task CheckValorantDownloadArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var archiveExtensions = new[] { ".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".iso" };
            var downloadDirs = GetDownloadSearchDirectories();
            foreach (var dir in downloadDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                IEnumerable<string> allFiles = Enumerable.Empty<string>();
                try
                {
                    allFiles = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                foreach (var file in allFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var ext = Path.GetExtension(file);
                    if (!archiveExtensions.Any(e =>
                            string.Equals(e, ext, StringComparison.OrdinalIgnoreCase)))
                        continue;
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (!DownloadArchiveNames.Any(n =>
                            string.Equals(n, fileName, StringComparison.OrdinalIgnoreCase)))
                        continue;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Valorant Aimbot Archive Found: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Valorant aimbot/cheat archive '{fileName}' found at '{file}'. " +
                                   "This archive matches a known Valorant cheat distribution package name. " +
                                   "Cheat tools are frequently distributed as compressed archives containing " +
                                   "executables, DLLs, and configuration files that are extracted and " +
                                   "used before or during Valorant sessions.",
                        Detail   = $"Path: {file} | File: {fileName}"
                    });
                }
            }
            await Task.CompletedTask;
        }, ct);

    private Task CheckValorantGameLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var riotLogRoot = Path.Combine(localApp, "Riot Games");
            if (!Directory.Exists(riotLogRoot)) return;
            var logDirs = new List<string> { riotLogRoot };
            try
            {
                logDirs.AddRange(Directory.GetDirectories(riotLogRoot, "*",
                    SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { }
            foreach (var logDir in logDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(logDir)) continue;
                string[] logFiles = Array.Empty<string>();
                try
                {
                    logFiles = Directory.GetFiles(logDir, "*.log");
                }
                catch (UnauthorizedAccessException) { continue; }
                foreach (var logFile in logFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    if (string.IsNullOrEmpty(content)) continue;
                    foreach (var pattern in GameLogCheatPatterns)
                    {
                        if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Valorant Game Log Cheat Pattern: {pattern}",
                            Risk     = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason   = $"Valorant game log file '{Path.GetFileName(logFile)}' contains " +
                                       $"cheat-related pattern '{pattern}'. " +
                                       "This indicates the anti-cheat system (Vanguard) or the game itself " +
                                       "detected or logged suspicious behavior consistent with aimbot, " +
                                       "triggerbot, macro usage, recoil scripting, or other forms of cheating " +
                                       "in Valorant. Log evidence persists after the session ends.",
                            Detail   = $"Log: {logFile} | Pattern: {pattern}"
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckValorantRegistryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            CheckUserAssistRegistry(ctx, ct);
            CheckMuiCacheRegistry(ctx, ct);
            CheckRunRegistryKeys(ctx, ct);
            CheckUninstallRegistry(ctx, ct);
            CheckVanguardBypassRegistry(ctx, ct);
            CheckAppCompatRegistry(ctx, ct);
            await Task.CompletedTask;
        }, ct);

    private void CheckUserAssistRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string userAssistBase =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
            if (baseKey is null) return;
            foreach (var guidName in baseKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                    if (countKey is null) continue;
                    foreach (var encodedName in countKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();
                        var decoded = Rot13Decode(encodedName);
                        var decodedLower = decoded.ToLowerInvariant();
                        bool isHit = UserAssistAimbotNames.Any(n =>
                            decodedLower.Contains(n, StringComparison.OrdinalIgnoreCase));
                        if (!isHit) continue;
                        int runCount = 0;
                        DateTime? lastRun = null;
                        try
                        {
                            var data = countKey.GetValue(encodedName) as byte[];
                            if (data is { Length: >= 16 })
                            {
                                runCount = BitConverter.ToInt32(data, 4);
                                var fileTime = BitConverter.ToInt64(data, 8);
                                if (fileTime > 0)
                                    lastRun = DateTime.FromFileTimeUtc(fileTime);
                            }
                        }
                        catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"UserAssist: Valorant Aimbot Executed: {Path.GetFileName(decoded)}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason   = $"Windows UserAssist registry shows execution of Valorant aimbot tool " +
                                       $"'{Path.GetFileName(decoded)}' " +
                                       $"({runCount} execution(s)" +
                                       (lastRun.HasValue
                                           ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC"
                                           : "") +
                                       "). UserAssist entries are ROT13-encoded and persist even after " +
                                       "the file is deleted, making this a reliable forensic indicator " +
                                       "of prior Valorant aimbot or cheat tool execution on this machine.",
                            Detail   = $"Decoded: {decoded} | Runs: {runCount} | " +
                                       $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckMuiCacheRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string muiCacheKey =
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(muiCacheKey, writable: false);
            if (key is null) return;
            foreach (var valueName in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();
                var path = valueName;
                var dotIdx = valueName.LastIndexOf('.');
                if (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                    path = valueName[..dotIdx];
                var pathLower = path.ToLowerInvariant();
                var friendlyName = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                var combined = pathLower + " " + friendlyName;
                bool isHit = MuiCacheAimbotNames.Any(n =>
                    combined.Contains(n, StringComparison.OrdinalIgnoreCase));
                if (!isHit) continue;
                var fn = Path.GetFileName(path);
                bool fileExists = File.Exists(path);
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"MuiCache: Valorant Aimbot Executed: {fn}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKCU\{muiCacheKey}",
                    FileName = fn,
                    Reason   = $"MuiCache registry entry shows execution of Valorant aimbot tool '{fn}'. " +
                               "MuiCache records every application Windows has displayed a name for, " +
                               "persisting even after file deletion. " +
                               (fileExists ? "File is still present on disk. " : "File has been deleted. ") +
                               "This is a reliable forensic artifact of prior Valorant aimbot usage on this system.",
                    Detail   = $"Path: {path} | Description: {friendlyName} | File exists: {fileExists}"
                });
            }
        }
        catch { }
    }

    private void CheckRunRegistryKeys(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine),
        };
        foreach (var (keyPath, hive) in runKeys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = hive.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;
                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    var value = (key.GetValue(valueName) as string ?? string.Empty);
                    var valueLower = value.ToLowerInvariant();
                    var nameLower = valueName.ToLowerInvariant();
                    bool isHit = AimbotExecutableNames.Any(n =>
                        valueLower.Contains(Path.GetFileNameWithoutExtension(n),
                            StringComparison.OrdinalIgnoreCase) ||
                        nameLower.Contains(Path.GetFileNameWithoutExtension(n),
                            StringComparison.OrdinalIgnoreCase));
                    if (!isHit) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Run Key: Valorant Aimbot Autostart: {valueName}",
                        Risk     = RiskLevel.High,
                        Location = $@"{(hive == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}",
                        FileName = valueName,
                        Reason   = $"Registry Run/RunOnce key contains Valorant aimbot autostart entry " +
                                   $"'{valueName}' pointing to: '{value}'. " +
                                   "This indicates the aimbot was configured to start automatically with Windows, " +
                                   "a common persistence mechanism for cheat tools ensuring the aimbot is " +
                                   "loaded and ready each time the user starts their computer.",
                        Detail   = $"Key: {keyPath} | Name: {valueName} | Value: {value}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckUninstallRegistry(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };
        foreach (var uninstallPath in uninstallPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var baseKey = Registry.LocalMachine.OpenSubKey(uninstallPath, writable: false)
                                 ?? Registry.CurrentUser.OpenSubKey(uninstallPath, writable: false);
                if (baseKey is null) continue;
                foreach (var subKeyName in baseKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var subKey = baseKey.OpenSubKey(subKeyName, writable: false);
                        if (subKey is null) continue;
                        var displayName = (subKey.GetValue("DisplayName") as string ?? string.Empty).ToLowerInvariant();
                        var installLocation = (subKey.GetValue("InstallLocation") as string ?? string.Empty).ToLowerInvariant();
                        var publisherName = (subKey.GetValue("Publisher") as string ?? string.Empty).ToLowerInvariant();
                        var combined = displayName + " " + installLocation + " " + publisherName;
                        bool isHit = UninstallAimbotKeywords.Any(k =>
                            combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (!isHit) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Uninstall Key: Valorant Aimbot Installed: {displayName}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                            FileName = subKeyName,
                            Reason   = $"Uninstall registry entry for Valorant aimbot/cheat tool found: '{displayName}'. " +
                                       "This indicates the cheat was formally installed on this system. " +
                                       "Uninstall entries persist until the software is removed through the " +
                                       "system's uninstaller or the registry key is manually deleted, " +
                                       "providing forensic evidence of prior installation.",
                            Detail   = $"DisplayName: {displayName} | Location: {installLocation} | Publisher: {publisherName}"
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private void CheckVanguardBypassRegistry(ScanContext ctx, CancellationToken ct)
    {
        var bypassRegPaths = new[]
        {
            @"SYSTEM\CurrentControlSet\Services\vgk",
            @"SYSTEM\CurrentControlSet\Services\vgc",
            @"SOFTWARE\Riot Games\Vanguard",
        };
        foreach (var regPath in bypassRegPaths)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;
                var start = key.GetValue("Start") as int?;
                var imagePath = (key.GetValue("ImagePath") as string ?? string.Empty).ToLowerInvariant();
                bool bypassSuspected = VanguardBypassKeywords.Any(k =>
                    imagePath.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (start == 4 || bypassSuspected)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Vanguard Anti-Cheat Anomaly: {regPath}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{regPath}",
                        Reason   = $"Vanguard anti-cheat driver registry entry at '{regPath}' shows anomalous " +
                                   $"configuration. StartType: {start?.ToString() ?? "unknown"}. " +
                                   (start == 4 ? "Driver is disabled (StartType=4). " : "") +
                                   (bypassSuspected ? $"ImagePath contains bypass keyword: '{imagePath}'. " : "") +
                                   "Disabling or tampering with Vanguard's kernel driver is a common " +
                                   "technique used by cheat loaders to avoid detection while running aimbot " +
                                   "or triggerbot software in Valorant.",
                        Detail   = $"Key: {regPath} | Start: {start} | ImagePath: {imagePath}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckAppCompatRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string appCompatPath =
            @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
        const string shimCachePath =
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
        try
        {
            using var shimKey = Registry.CurrentUser.OpenSubKey(shimCachePath, writable: false);
            if (shimKey is not null)
            {
                foreach (var valueName in shimKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    var nameLower = valueName.ToLowerInvariant();
                    bool isHit = AppCompatValorantCheatNames.Any(n =>
                        nameLower.Contains(n, StringComparison.OrdinalIgnoreCase));
                    if (!isHit) continue;
                    var value = (shimKey.GetValue(valueName) as string ?? string.Empty);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"AppCompat Shim: Valorant Cheat Compatibility Entry: {Path.GetFileName(valueName)}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\{shimCachePath}",
                        FileName = Path.GetFileName(valueName),
                        Reason   = $"Application Compatibility Flags registry contains entry for " +
                                   $"Valorant-related cheat tool '{Path.GetFileName(valueName)}'. " +
                                   "Cheat tools sometimes register compatibility shims to ensure they " +
                                   "run correctly alongside game processes. This entry persists as a " +
                                   "forensic artifact even after the cheat is removed.",
                        Detail   = $"Path: {valueName} | Flags: {value}"
                    });
                }
            }
        }
        catch { }
    }

    private static string[] GetStandardSearchDirectories()
    {
        var dirs = new List<string>();
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var temp = Path.GetTempPath();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(desktop)) dirs.Add(desktop);
        if (!string.IsNullOrEmpty(downloads)) dirs.Add(downloads);
        if (!string.IsNullOrEmpty(temp)) dirs.Add(temp);
        if (!string.IsNullOrEmpty(appData)) dirs.Add(appData);
        if (!string.IsNullOrEmpty(localAppData)) dirs.Add(localAppData);
        return dirs.ToArray();
    }

    private static string[] GetConfigSearchDirectories()
    {
        var dirs = new List<string>();
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(desktop)) dirs.Add(desktop);
        if (!string.IsNullOrEmpty(downloads)) dirs.Add(downloads);
        if (!string.IsNullOrEmpty(appData)) dirs.Add(appData);
        if (!string.IsNullOrEmpty(localAppData)) dirs.Add(localAppData);
        return dirs.ToArray();
    }

    private static string[] GetDownloadSearchDirectories()
    {
        var dirs = new List<string>();
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (!string.IsNullOrEmpty(desktop)) dirs.Add(desktop);
        if (!string.IsNullOrEmpty(downloads)) dirs.Add(downloads);
        return dirs.ToArray();
    }

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if      (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
