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

public sealed class ApexLegendsMacroForensicScanModule : IScanModule
{
    public string Name => "Apex Legends Macro & Script Cheat Forensic Scan";
    public double Weight => 3.9;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] MacroExecutableNames =
    {
        "apex_macro.exe",
        "apex_script.exe",
        "apex_ahk.exe",
        "apex_recoil_script.exe",
        "apex_norecoil.exe",
        "apex_no_recoil.exe",
        "apex_rapid_fire.exe",
        "apex_rapidfire.exe",
        "apex_bhop.exe",
        "apex_bunny.exe",
        "apex_speed_script.exe",
        "apex_aim_script.exe",
        "apex_aimbot.exe",
        "apex_triggerbot.exe",
        "apex_silent_aim.exe",
        "apex_auto_sprint.exe",
        "apex_auto_fire.exe",
        "apex_logitech_macro.exe",
        "apex_razer_macro.exe",
        "apex_steelseries_macro.exe",
        "apex_hardware_macro.exe",
        "apex_jitter_aim.exe",
        "apex_strafe.exe",
        "apex_crouch_macro.exe",
        "macro_apex.exe",
        "script_apex.exe",
        "recoil_script_apex.exe",
        "norecoil_apex.exe",
        "rapid_fire_apex.exe",
        "bhop_apex.exe",
        "aimbot_apex.exe",
        "triggerbot_apex.exe",
        "silent_aim_apex.exe",
        "auto_sprint_apex.exe",
        "auto_fire_apex.exe",
        "jitter_aim_apex.exe",
        "strafe_apex.exe",
        "crouch_macro_apex.exe",
        "apex_macro_v2.exe",
        "apex_script_v2.exe",
        "apex_norecoil_v2.exe",
        "apex_rapid_fire_v2.exe",
        "apex_aimbot_v2.exe",
        "apex_cheat.exe",
        "apex_hack.exe",
        "apex_loader_macro.exe",
        "apex_injector_macro.exe",
        "apex_bypass_macro.exe",
        "apex_eac_bypass.exe",
        "apex_logitech.exe",
        "apex_razer.exe",
        "apex_steelseries.exe",
        "apex_hardware.exe",
        "apl_macro.exe",
        "apl_script.exe",
        "apl_norecoil.exe",
        "apl_rapid_fire.exe",
        "apl_aimbot.exe",
        "apl_jitter.exe",
        "apl_strafe.exe",
        "apl_bhop.exe",
        "apl_triggerbot.exe",
        "apl_silent_aim.exe",
        "apex_aim_assist.exe",
        "apex_aim.exe",
        "apex_recoil.exe",
        "apex_spread.exe",
    };

    private static readonly string[] MacroDllNames =
    {
        "apex_macro.dll",
        "apex_script.dll",
        "apex_norecoil.dll",
        "apex_no_recoil.dll",
        "apex_rapid_fire.dll",
        "apex_rapidfire.dll",
        "apex_bhop.dll",
        "apex_aim_script.dll",
        "apex_aimbot.dll",
        "apex_triggerbot.dll",
        "apex_silent_aim.dll",
        "apex_auto_fire.dll",
        "apex_jitter_aim.dll",
        "apex_strafe.dll",
        "apex_crouch_macro.dll",
        "macro_apex.dll",
        "script_apex.dll",
        "norecoil_apex.dll",
        "rapid_fire_apex.dll",
        "aimbot_apex.dll",
        "triggerbot_apex.dll",
        "silent_aim_apex.dll",
        "jitter_aim_apex.dll",
        "strafe_apex.dll",
        "apex_cheat.dll",
        "apex_hack.dll",
        "apex_loader_macro.dll",
        "apex_injector_macro.dll",
        "apex_bypass_macro.dll",
        "apex_eac_bypass.dll",
        "apl_macro.dll",
        "apl_script.dll",
        "apl_norecoil.dll",
        "apl_rapid_fire.dll",
        "apl_aimbot.dll",
        "apl_jitter.dll",
        "apl_strafe.dll",
        "apl_bhop.dll",
        "apl_triggerbot.dll",
        "apl_silent_aim.dll",
        "apex_logitech_macro.dll",
        "apex_razer_macro.dll",
        "apex_steelseries_macro.dll",
        "apex_hardware_macro.dll",
        "apex_aim.dll",
        "apex_recoil.dll",
        "apex_spread.dll",
        "apex_aim_assist.dll",
        "apex_input.dll",
        "apex_inject.dll",
    };

    private static readonly string[] MacroScriptNamePatterns =
    {
        "apex",
        "apl_",
        "aimbot",
        "norecoil",
        "rapid_fire",
        "bhop",
        "macro",
        "jitter",
        "strafe",
        "triggerbot",
    };

    private static readonly string[] MacroScriptContentKeywords =
    {
        "MouseClick",
        "Send",
        "mouse_event",
        "SetCursorPos",
        "ControlSend",
        "win32api",
        "pyautogui",
        "mouse_move",
        "GetAsyncKeyState",
        "sleep",
        "aimbot",
        "norecoil",
        "rapid_fire",
        "bhop",
        "jitter_aim",
        "strafe_macro",
        "crouch_macro",
        "auto_sprint",
        "auto_fire",
        "FOV",
        "smooth",
        "bone",
        "headshot",
        "triggerbot",
        "silent_aim",
        "logitech",
        "razer",
        "steelseries",
    };

    private static readonly string[] LogitechLuaNamePatterns =
    {
        "apex",
        "apl",
        "norecoil",
        "no_recoil",
        "rapid_fire",
        "rapidfire",
        "jitter",
        "strafe",
        "recoil",
        "macro",
        "aimbot",
        "triggerbot",
    };

    private static readonly string[] LogitechLuaContentKeywords =
    {
        "apex",
        "norecoil",
        "no_recoil",
        "rapid_fire",
        "recoil",
        "jitter",
        "strafe",
        "aimbot",
        "triggerbot",
        "mouse_event",
        "MoveMouseRelative",
        "MoveMouseTo",
        "PressMouseButton",
        "ReleaseMouseButton",
        "IsMouseButtonPressed",
        "OutputLogMessage",
        "Sleep",
    };

    private static readonly string[] MacroConfigFileNames =
    {
        "apex_macro.json",
        "apex_recoil.json",
        "apex_config.json",
        "apex_settings.json",
        "macro_config.json",
        "norecoil_config.json",
        "apex_norecoil.json",
        "apex_rapid_fire.json",
        "apex_jitter.json",
        "apex_strafe.json",
        "apex_aimbot.json",
        "apex_triggerbot.json",
        "apl_macro.json",
        "apl_config.json",
        "apl_settings.json",
        "apl_norecoil.json",
        "apex_logitech.json",
        "apex_razer.json",
        "apex_hardware.json",
        "recoil_config.json",
        "jitter_config.json",
        "strafe_config.json",
    };

    private static readonly string[] ConfigKeywords =
    {
        "recoil",
        "spread",
        "rapid",
        "bhop",
        "aimbot",
        "triggerbot",
        "macro",
        "jitter",
        "strafe",
        "crouch",
        "sprint",
        "logitech",
        "razer",
        "steelseries",
        "norecoil",
        "rapidfire",
    };

    private static readonly string[] DownloadArchiveNames =
    {
        "apex_macro.zip",
        "apex_macro.rar",
        "apex_macro.7z",
        "apex_script.zip",
        "apex_script.rar",
        "apex_script.7z",
        "apex_norecoil.zip",
        "apex_norecoil.rar",
        "apex_norecoil.7z",
        "apex_no_recoil.zip",
        "apex_no_recoil.rar",
        "apex_no_recoil.7z",
        "apex_rapid_fire.zip",
        "apex_rapid_fire.rar",
        "apex_rapid_fire.7z",
        "apex_bhop.zip",
        "apex_bhop.rar",
        "apex_bhop.7z",
        "apex_aimbot.zip",
        "apex_aimbot.rar",
        "apex_aimbot.7z",
        "apex_triggerbot.zip",
        "apex_triggerbot.rar",
        "apex_triggerbot.7z",
        "apex_silent_aim.zip",
        "apex_silent_aim.rar",
        "apex_silent_aim.7z",
        "apex_jitter_aim.zip",
        "apex_jitter_aim.rar",
        "apex_jitter_aim.7z",
        "apex_strafe.zip",
        "apex_strafe.rar",
        "apex_strafe.7z",
        "apex_cheat.zip",
        "apex_cheat.rar",
        "apex_cheat.7z",
        "apex_hack.zip",
        "apex_hack.rar",
        "apex_hack.7z",
        "apex_logitech_macro.zip",
        "apex_logitech_macro.rar",
        "apex_logitech_macro.7z",
        "apex_razer_macro.zip",
        "apex_razer_macro.rar",
        "apex_razer_macro.7z",
        "apex_eac_bypass.zip",
        "apex_eac_bypass.rar",
        "apex_eac_bypass.7z",
        "apl_macro.zip",
        "apl_macro.rar",
        "apl_macro.7z",
        "apl_script.zip",
        "apl_script.rar",
        "apl_script.7z",
    };

    private static readonly string[] GameLogCheatPatterns =
    {
        "cheat detected",
        "hack detected",
        "macro detected",
        "recoil script detected",
        "rapid fire detected",
        "bhop detected",
        "speed hack detected",
        "aimbot detected",
        "triggerbot detected",
        "aim assist detected",
        "jitter aim detected",
        "strafe macro detected",
        "eac ban",
        "easy anticheat ban",
        "eac kicked",
        "anticheat ban",
        "suspicious input detected",
        "inhuman reaction",
        "perfect recoil",
        "recoil manipulation",
        "rapid fire manipulation",
        "crouch spam detected",
        "auto sprint detected",
        "logitech script detected",
        "razer script detected",
        "hardware macro detected",
        "mouse macro detected",
        "input automation detected",
        "script detected",
        "aim anomaly",
        "suspicious behavior",
        "eac violation",
        "anticheat violation",
        "ban appeal",
        "permanent ban",
        "account banned",
        "cheating violation",
        "unsportsmanlike conduct",
        "suspicious movement",
        "velocity anomaly",
    };

    private static readonly string[] UserAssistMacroNames =
    {
        "ncrk_znpeb",
        "ncrk_fpevcg",
        "ncrk_nux",
        "ncrk_erpbvy_fpevcg",
        "ncrk_aberpbvy",
        "ncrk_encvq_sver",
        "ncrk_oubc",
        "ncrk_nvzoobg",
        "ncrk_gevttreobg",
        "ncrk_fvyrag_nvz",
        "ncrk_whggre_nvz",
        "ncrk_fgensr",
        "ncrk_purng",
        "ncrk_unpx",
        "ncrk_ybtvgrpu_znpeb",
        "ncrk_enmmre_znpeb",
        "ncrk_rnp_olcnff",
        "znpeb_ncrk",
        "fpevcg_ncrk",
        "aberpbvy_ncrk",
        "encvq_sver_ncrk",
        "oubc_ncrk",
        "nvzoobg_ncrk",
        "gevttreobg_ncrk",
        "fvyrag_nvz_ncrk",
        "whggre_nvz_ncrk",
        "fgensf_ncrk",
        "ncy_znpeb",
        "ncy_fpevcg",
        "ncy_aberpbvy",
        "ncy_encvq_sver",
        "ncy_nvzoobg",
        "ncy_whggre",
        "ncy_fgensf",
        "ncy_oubc",
        "ncy_gevttreobg",
        "ncy_fvyrag_nvz",
        "ncrk_znpeb_i2",
        "ncrk_fpevcg_i2",
    };

    private static readonly string[] MuiCacheMacroNames =
    {
        "apex_macro",
        "apex_script",
        "apex_ahk",
        "apex_recoil_script",
        "apex_norecoil",
        "apex_no_recoil",
        "apex_rapid_fire",
        "apex_rapidfire",
        "apex_bhop",
        "apex_aimbot",
        "apex_triggerbot",
        "apex_silent_aim",
        "apex_jitter_aim",
        "apex_strafe",
        "apex_crouch_macro",
        "apex_cheat",
        "apex_hack",
        "apex_logitech_macro",
        "apex_razer_macro",
        "apex_eac_bypass",
        "apl_macro",
        "apl_script",
        "apl_norecoil",
        "apl_rapid_fire",
        "apl_aimbot",
        "apl_jitter",
        "apl_strafe",
        "apl_bhop",
        "apl_triggerbot",
        "apl_silent_aim",
        "macro_apex",
        "norecoil_apex",
        "aimbot_apex",
    };

    private static readonly string[] UninstallMacroKeywords =
    {
        "apex macro",
        "apex script",
        "apex no recoil",
        "apex norecoil",
        "apex rapid fire",
        "apex bhop",
        "apex aimbot",
        "apex triggerbot",
        "apex silent aim",
        "apex jitter aim",
        "apex strafe macro",
        "apex cheat",
        "apex hack",
        "apex logitech macro",
        "apex razer macro",
        "apex eac bypass",
        "apex hardware macro",
        "apl macro",
        "apl script",
        "apl norecoil",
        "apl aimbot",
        "apl triggerbot",
    };

    private static readonly string[] PrefetchMacroNames =
    {
        "APEX_MACRO",
        "APEX_SCRIPT",
        "APEX_AHK",
        "APEX_RECOIL_SCRIPT",
        "APEX_NORECOIL",
        "APEX_NO_RECOIL",
        "APEX_RAPID_FIRE",
        "APEX_RAPIDFIRE",
        "APEX_BHOP",
        "APEX_AIMBOT",
        "APEX_TRIGGERBOT",
        "APEX_SILENT_AIM",
        "APEX_JITTER_AIM",
        "APEX_STRAFE",
        "APEX_CHEAT",
        "APEX_HACK",
        "APEX_LOGITECH_MACRO",
        "APEX_RAZER_MACRO",
        "APEX_EAC_BYPASS",
        "APL_MACRO",
        "APL_SCRIPT",
        "APL_NORECOIL",
        "APL_RAPID_FIRE",
        "APL_AIMBOT",
        "MACRO_APEX",
        "NORECOIL_APEX",
        "AIMBOT_APEX",
    };

    private static readonly string[] EnvVarMacroKeywords =
    {
        "apex_macro",
        "apex_script",
        "apex_norecoil",
        "apex_aimbot",
        "apex_cheat",
        "apex_hack",
        "apl_macro",
        "apl_script",
        "apl_aimbot",
        "apex_bypass",
        "apex_inject",
        "apex_eac",
        "norecoil_apex",
        "aimbot_apex",
    };

    private static readonly string[] StartupFolderMacroPatterns =
    {
        "apex_macro",
        "apex_script",
        "apex_norecoil",
        "apex_rapid_fire",
        "apex_aimbot",
        "apex_cheat",
        "apex_hack",
        "apl_macro",
        "apl_script",
        "apl_aimbot",
        "macro_apex",
        "norecoil_apex",
        "aimbot_apex",
        "apex_logitech",
        "apex_eac_bypass",
    };

    private static readonly string[] ScheduledTaskMacroKeywords =
    {
        "apex_macro",
        "apex_script",
        "apex_norecoil",
        "apex_aimbot",
        "apex_cheat",
        "apex_hack",
        "apl_macro",
        "apl_aimbot",
        "macro_apex",
        "norecoil_apex",
        "apex_bypass",
        "apex_inject",
        "apex_logitech_macro",
        "apex_eac",
    };

    private static readonly string[] RecentFilesMacroPatterns =
    {
        "apex_macro",
        "apex_script",
        "apex_norecoil",
        "apex_rapid_fire",
        "apex_aimbot",
        "apex_cheat",
        "apex_hack",
        "apex_silent_aim",
        "apex_jitter_aim",
        "apex_strafe",
        "apex_bhop",
        "apl_macro",
        "apl_script",
        "apl_aimbot",
        "apl_norecoil",
        "macro_apex",
        "norecoil_apex",
        "aimbot_apex",
        "apex_logitech",
        "apex_eac_bypass",
    };

    private static readonly string[] EacBypassRegistryPaths =
    {
        @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat",
        @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS",
        @"SOFTWARE\EasyAntiCheat",
    };

    private static readonly string[] ApexCheatWatermarkPatterns =
    {
        "apexhack",
        "apex_cheat",
        "apex_hack",
        "apexaimbot",
        "apextrigger",
        "apexnorecoil",
        "apexjitter",
        "apexstrafe",
        "apexmacro",
        "ringone",
        "ringone apex",
        "predator legend apex",
        "blackcell apex",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Apex Legends macro forensic scan...");
        return Task.WhenAll(
            CheckApexMacroExecutables(ctx, ct),
            CheckApexMacroDlls(ctx, ct),
            CheckApexMacroScripts(ctx, ct),
            CheckApexLogitechScripts(ctx, ct),
            CheckApexConfigFiles(ctx, ct),
            CheckApexDownloadArtifacts(ctx, ct),
            CheckApexGameLogs(ctx, ct),
            CheckApexRegistryArtifacts(ctx, ct),
            CheckApexPrefetchArtifacts(ctx, ct),
            CheckApexStartupFolderArtifacts(ctx, ct),
            CheckApexScheduledTaskArtifacts(ctx, ct),
            CheckApexEnvironmentVariables(ctx, ct),
            CheckApexRecentDocuments(ctx, ct),
            CheckApexEacBypassArtifacts(ctx, ct)
        );
    }

    private Task CheckApexMacroExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var searchDirs = GetStandardSearchDirectories();
            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe",
                        SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        var fileNameLower = fileName.ToLowerInvariant();
                        if (!MacroExecutableNames.Any(n =>
                                string.Equals(n, fileNameLower, StringComparison.OrdinalIgnoreCase)))
                            continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Apex Legends Macro Executable Found: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Apex Legends macro/script cheat executable '{fileName}' found at '{file}'. " +
                                       "This file matches a known Apex Legends macro, recoil script, aimbot, " +
                                       "triggerbot, jitter aim, or anti-cheat bypass executable name. " +
                                       "Such tools automate recoil control, rapid fire, bhop, strafe, " +
                                       "or other game inputs to gain an unfair advantage in Apex Legends.",
                            Detail   = $"Path: {file} | File: {fileName}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckApexMacroDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var searchDirs = GetStandardSearchDirectories();
            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.dll",
                        SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        var fileNameLower = fileName.ToLowerInvariant();
                        if (!MacroDllNames.Any(n =>
                                string.Equals(n, fileNameLower, StringComparison.OrdinalIgnoreCase)))
                            continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Apex Legends Macro DLL Found: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Apex Legends macro/cheat DLL '{fileName}' found at '{file}'. " +
                                       "This DLL matches a known Apex Legends macro injection library, " +
                                       "recoil script module, or cheat component. " +
                                       "Such DLLs may be injected into the game or a macro tool process " +
                                       "to provide no-recoil, rapid fire, jitter aim, or other cheat functionality.",
                            Detail   = $"Path: {file} | File: {fileName}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckApexMacroScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var scriptExtensions = new[] { ".ahk", ".py", ".au3", ".lua" };
            var scriptDirs = GetStandardSearchDirectories();
            foreach (var dir in scriptDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*",
                        SearchOption.AllDirectories))
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
                            Title    = $"Apex Legends Macro Script Found: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Macro or automation script '{fileName}' found at '{file}' " +
                                       $"with {hits.Count} cheat-related content keywords matched: " +
                                       $"{string.Join(", ", hits.Take(5))}. " +
                                       "Such scripts are used for Apex Legends no-recoil macros, rapid fire, " +
                                       "jitter aim, strafe macros, bhop scripts, aimbot, and triggerbot " +
                                       "automation via AutoHotkey, Python, AutoIt, or Lua.",
                            Detail   = $"Path: {file} | Matches ({hits.Count}): {string.Join(", ", hits)}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckApexLogitechScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var roamingApp = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var lgHubDirs = new[]
            {
                Path.Combine(localApp, "LGHUB"),
                Path.Combine(roamingApp, "Logitech"),
                Path.Combine(roamingApp, "Logitech Gaming Software"),
                Path.Combine(localApp, "Logitech"),
                Path.Combine(localApp, "Logitech Gaming Software"),
            };
            foreach (var lgDir in lgHubDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(lgDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(lgDir, "*.lua",
                        SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        var fileNameLower = fileName.ToLowerInvariant();
                        bool nameMatch = LogitechLuaNamePatterns.Any(p =>
                            fileNameLower.Contains(p, StringComparison.OrdinalIgnoreCase));
                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read,
                                FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { }
                        bool contentMatch = false;
                        string? hitKeyword = null;
                        if (!string.IsNullOrEmpty(content))
                        {
                            hitKeyword = LogitechLuaContentKeywords.FirstOrDefault(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            contentMatch = hitKeyword is not null;
                        }
                        if (!nameMatch && !contentMatch) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Logitech G Hub Apex Macro Script Found: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Logitech G Hub Lua script '{fileName}' found at '{file}' " +
                                       (nameMatch ? "with Apex Legends-related name " : "") +
                                       (contentMatch ? $"containing macro keyword '{hitKeyword}'. " : ". ") +
                                       "Logitech G Hub allows Lua scripts to control mouse movement at the " +
                                       "hardware driver level, enabling undetectable no-recoil, rapid fire, " +
                                       "jitter aim, and strafe macros in Apex Legends. " +
                                       "Such scripts run in the Logitech G Hub process and send synthetic " +
                                       "mouse input that bypasses game-level input detection.",
                            Detail   = $"Path: {file} | Name match: {nameMatch} | Content keyword: {hitKeyword ?? "n/a"}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckApexConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var configDirs = GetConfigSearchDirectories();
            foreach (var dir in configDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.json",
                        SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        var fileNameLower = fileName.ToLowerInvariant();
                        if (!MacroConfigFileNames.Any(n =>
                                string.Equals(n, fileNameLower, StringComparison.OrdinalIgnoreCase)))
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
                            Title    = $"Apex Legends Macro Config File Found: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Apex Legends macro/cheat configuration file '{fileName}' found at '{file}'. " +
                                       (hitKeyword is not null
                                           ? $"File content contains cheat-related keyword '{hitKeyword}'. "
                                           : "File name matches known Apex macro config pattern. ") +
                                       "These config files store macro settings such as recoil compensation values, " +
                                       "rapid fire rates, jitter patterns, strafe timing, " +
                                       "aimbot parameters, and hardware macro configurations.",
                            Detail   = $"Path: {file} | Keyword: {hitKeyword ?? "n/a"}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckApexDownloadArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var archiveExtensions = new[] { ".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".iso" };
            var downloadDirs = GetDownloadSearchDirectories();
            foreach (var dir in downloadDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*",
                        SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        var ext = Path.GetExtension(file);
                        if (!archiveExtensions.Any(e =>
                                string.Equals(e, ext, StringComparison.OrdinalIgnoreCase)))
                            continue;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        var fileNameLower = fileName.ToLowerInvariant();
                        if (!DownloadArchiveNames.Any(n =>
                                string.Equals(n, fileNameLower, StringComparison.OrdinalIgnoreCase)))
                            continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Apex Legends Macro Archive Found: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Apex Legends macro/cheat archive '{fileName}' found at '{file}'. " +
                                       "This archive matches a known Apex Legends macro, recoil script, " +
                                       "aimbot, or anti-cheat bypass distribution package name. " +
                                       "Cheat tools are frequently distributed as compressed archives " +
                                       "before extraction and use.",
                            Detail   = $"Path: {file} | File: {fileName}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
            await Task.CompletedTask;
        }, ct);

    private Task CheckApexGameLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var apexLogRoot = Path.Combine(localApp, "Respawn", "Apex", "saved", "logs");
            var logDirs = new List<string>();
            if (Directory.Exists(apexLogRoot))
            {
                logDirs.Add(apexLogRoot);
                try
                {
                    logDirs.AddRange(Directory.GetDirectories(apexLogRoot, "*",
                        SearchOption.AllDirectories));
                }
                catch (UnauthorizedAccessException) { }
            }
            var alternateLogPaths = new[]
            {
                Path.Combine(localApp, "Respawn", "Apex"),
                Path.Combine(localApp, "EA Games", "Apex Legends"),
            };
            foreach (var altPath in alternateLogPaths)
            {
                if (Directory.Exists(altPath) && !logDirs.Contains(altPath))
                    logDirs.Add(altPath);
            }
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
                            Title    = $"Apex Legends Game Log Cheat Pattern: {pattern}",
                            Risk     = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason   = $"Apex Legends log file '{Path.GetFileName(logFile)}' contains " +
                                       $"cheat-related pattern '{pattern}'. " +
                                       "This indicates Easy Anti-Cheat (EAC) or the game itself " +
                                       "detected or logged suspicious behavior consistent with macro use, " +
                                       "recoil scripting, aimbot, triggerbot, or other cheating methods.",
                            Detail   = $"Log: {logFile} | Pattern: {pattern}"
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckApexRegistryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            CheckApexUserAssistRegistry(ctx, ct);
            CheckApexMuiCacheRegistry(ctx, ct);
            CheckApexRunRegistryKeys(ctx, ct);
            CheckApexUninstallRegistry(ctx, ct);
            await Task.CompletedTask;
        }, ct);

    private void CheckApexUserAssistRegistry(ScanContext ctx, CancellationToken ct)
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
                        bool isHit = UserAssistMacroNames.Any(n =>
                            decodedLower.Contains(Rot13Decode(n), StringComparison.OrdinalIgnoreCase)) ||
                            MacroExecutableNames.Any(n =>
                                decodedLower.Contains(Path.GetFileNameWithoutExtension(n),
                                    StringComparison.OrdinalIgnoreCase));
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
                            Title    = $"UserAssist: Apex Macro Tool Executed: {Path.GetFileName(decoded)}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason   = $"Windows UserAssist registry shows execution of Apex Legends macro tool " +
                                       $"'{Path.GetFileName(decoded)}' " +
                                       $"({runCount} execution(s)" +
                                       (lastRun.HasValue
                                           ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC"
                                           : "") +
                                       "). UserAssist entries persist even after the file is deleted, " +
                                       "making this a reliable forensic indicator of prior macro or cheat tool usage " +
                                       "in Apex Legends.",
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

    private void CheckApexMuiCacheRegistry(ScanContext ctx, CancellationToken ct)
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
                bool isHit = MuiCacheMacroNames.Any(n =>
                    combined.Contains(n, StringComparison.OrdinalIgnoreCase));
                if (!isHit) continue;
                var fn = Path.GetFileName(path);
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"MuiCache: Apex Macro Tool Executed: {fn}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKCU\{muiCacheKey}",
                    FileName = fn,
                    Reason   = $"MuiCache registry entry shows execution of Apex Legends macro/cheat tool '{fn}'. " +
                               "MuiCache records every application Windows has displayed a name for, " +
                               "persisting even after file deletion. This is a reliable forensic artifact " +
                               "of prior Apex Legends macro, recoil script, or cheat tool usage.",
                    Detail   = $"Path: {path} | Description: {friendlyName}"
                });
            }
        }
        catch { }
    }

    private void CheckApexRunRegistryKeys(ScanContext ctx, CancellationToken ct)
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
                    var value = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                    var nameLower = valueName.ToLowerInvariant();
                    bool isHit = MacroExecutableNames.Any(n =>
                        value.Contains(Path.GetFileNameWithoutExtension(n),
                            StringComparison.OrdinalIgnoreCase) ||
                        nameLower.Contains(Path.GetFileNameWithoutExtension(n),
                            StringComparison.OrdinalIgnoreCase));
                    if (!isHit) continue;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Run Key: Apex Macro Tool Autostart: {valueName}",
                        Risk     = RiskLevel.High,
                        Location = $@"{(hive == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}",
                        FileName = valueName,
                        Reason   = $"Registry Run/RunOnce key contains Apex Legends macro tool autostart entry " +
                                   $"'{valueName}' pointing to: '{value}'. " +
                                   "This indicates the macro or cheat tool was configured to start automatically " +
                                   "with Windows, a common persistence mechanism used by cheat software.",
                        Detail   = $"Key: {keyPath} | Name: {valueName} | Value: {value}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckApexUninstallRegistry(ScanContext ctx, CancellationToken ct)
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
                        var displayName = (subKey.GetValue("DisplayName") as string ?? "").ToLowerInvariant();
                        var installLocation = (subKey.GetValue("InstallLocation") as string ?? "").ToLowerInvariant();
                        var combined = displayName + " " + installLocation;
                        bool isHit = UninstallMacroKeywords.Any(k =>
                            combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (!isHit) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Uninstall Key: Apex Macro Tool Installed: {displayName}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                            FileName = subKeyName,
                            Reason   = $"Uninstall registry entry for Apex Legends macro/cheat tool found: '{displayName}'. " +
                                       "This indicates a macro, recoil script, or cheat tool was formally installed " +
                                       "on this system targeting Apex Legends. " +
                                       "Uninstall entries persist until the software is removed via the " +
                                       "system's uninstaller or the registry key is manually deleted.",
                            Detail   = $"DisplayName: {displayName} | Location: {installLocation}"
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }
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
