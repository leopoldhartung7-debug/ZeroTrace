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

public sealed class AntiCheatBypassForensicScanModule : IScanModule
{
    public string Name => "Anti-Cheat Bypass Tool Forensic Scan";
    public double Weight => 4.5;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string RoamingAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string Downloads =
        Path.Combine(UserProfile, "Downloads");
    private static readonly string Temp =
        Path.GetTempPath();

    private static readonly string[] CommonSearchDirs = new[]
    {
        Desktop,
        Downloads,
        Temp,
        Path.Combine(LocalAppData, "Temp"),
        RoamingAppData,
        LocalAppData,
    };

    private static readonly string[] EacBypassExecutables =
    {
        "eac_bypass.exe",
        "eac_bypass_v2.exe",
        "eac_bypass_v3.exe",
        "eac_disable.exe",
        "eac_spoof.exe",
        "eac_patch.exe",
        "eac_patcher.exe",
        "eac_hook.exe",
        "eac_inject.exe",
        "eac_loader.exe",
        "eac_kill.exe",
        "eac_killer.exe",
        "eac_unload.exe",
        "eac_dumper.exe",
        "eac_dump.exe",
        "eac_scan.exe",
        "easy_anticheat_bypass.exe",
        "easy_anticheat_disable.exe",
        "easy_anticheat_spoof.exe",
        "easy_anticheat_patch.exe",
        "easyanticheat_bypass.exe",
        "easyanticheat_disable.exe",
        "easyanticheat_patch.exe",
        "easyanticheat_kill.exe",
        "bypass_eac.exe",
        "disable_eac.exe",
        "kill_eac.exe",
        "patch_eac.exe",
        "spoof_eac.exe",
        "hook_eac.exe",
        "inject_eac.exe",
        "unload_eac.exe",
        "eac_bypass_tool.exe",
        "eac_bypass_loader.exe",
        "eac_bypass_injector.exe",
        "eac_bypass_patcher.exe",
        "eac_bypass_x64.exe",
        "eac_bypass_x86.exe",
        "eac_stopper.exe",
        "eac_terminator.exe",
        "eac_nullify.exe",
        "eac_subvert.exe",
        "eac_defeat.exe",
        "eac_evade.exe",
        "eac_circumvent.exe",
        "eac_blocker.exe",
        "eac_intercept.exe",
        "eac_redirect.exe",
        "eac_tamper.exe",
        "eac_suspend.exe",
        "eac_shutdown.exe",
        "eac_override.exe",
        "eac_modify.exe",
        "eac_neutered.exe",
        "eac_stomp.exe",
        "eac_nuke.exe",
        "eac_fixer.exe",
        "eac_remover.exe",
        "eac_wipe.exe",
        "eac_crash.exe",
        "eac_exploit.exe",
        "eac_hax.exe",
        "eac_unhook.exe",
        "eac_detach.exe",
        "eac_unprotect.exe",
        "eac_unfuck.exe",
    };

    private static readonly string[] BeBypassExecutables =
    {
        "be_bypass.exe",
        "be_bypass_v2.exe",
        "be_disable.exe",
        "be_spoof.exe",
        "be_patch.exe",
        "be_hook.exe",
        "be_inject.exe",
        "be_loader.exe",
        "be_kill.exe",
        "be_killer.exe",
        "be_unload.exe",
        "be_dumper.exe",
        "battleye_bypass.exe",
        "battleye_disable.exe",
        "battleye_spoof.exe",
        "battleye_patch.exe",
        "battleye_kill.exe",
        "battleyebypass.exe",
        "battleyedisable.exe",
        "battleyepatch.exe",
        "battleyekill.exe",
        "bypass_be.exe",
        "disable_be.exe",
        "kill_be.exe",
        "patch_be.exe",
        "spoof_be.exe",
        "be_bypass_tool.exe",
        "be_bypass_loader.exe",
        "be_bypass_injector.exe",
        "BEDaisy_bypass.exe",
        "BEDaisy_kill.exe",
        "BEDaisy_disable.exe",
        "BEClient_bypass.exe",
        "BEService_bypass.exe",
        "BEService_kill.exe",
        "be_ioctl_bypass.exe",
        "be_driver_bypass.exe",
        "be_kernel_bypass.exe",
        "be_stopper.exe",
        "be_terminator.exe",
        "be_nullify.exe",
        "be_subvert.exe",
        "be_evade.exe",
        "be_circumvent.exe",
        "be_blocker.exe",
        "be_intercept.exe",
        "be_tamper.exe",
        "be_suspend.exe",
        "be_shutdown.exe",
        "be_override.exe",
        "be_modify.exe",
        "be_nuke.exe",
        "be_crash.exe",
        "be_exploit.exe",
    };

    private static readonly string[] VacBypassExecutables =
    {
        "vac_bypass.exe",
        "vac_bypass_v2.exe",
        "vac_bypass_v3.exe",
        "vac_disable.exe",
        "vac_spoof.exe",
        "vac_patch.exe",
        "vac_hook.exe",
        "vac_inject.exe",
        "vac_loader.exe",
        "vac_kill.exe",
        "vac_killer.exe",
        "vac_unload.exe",
        "vac_dumper.exe",
        "vac_dump.exe",
        "vac_scan.exe",
        "valve_ac_bypass.exe",
        "valve_anticheat_bypass.exe",
        "vac3_bypass.exe",
        "vac3_disable.exe",
        "bypass_vac.exe",
        "disable_vac.exe",
        "kill_vac.exe",
        "patch_vac.exe",
        "spoof_vac.exe",
        "vac_bypass_tool.exe",
        "vac_bypass_loader.exe",
        "steamdb_vac_bypass.exe",
        "vac_bypass_injector.exe",
        "vacnet_bypass.exe",
        "vac_network_bypass.exe",
        "vac_stopper.exe",
        "vac_terminator.exe",
        "vac_nullify.exe",
        "vac_subvert.exe",
        "vac_evade.exe",
        "vac_circumvent.exe",
        "vac_blocker.exe",
        "vac_intercept.exe",
        "vac_tamper.exe",
        "vac_suspend.exe",
        "vac_shutdown.exe",
        "vac_override.exe",
        "vac_modify.exe",
        "vac_nuke.exe",
        "vac_crash.exe",
        "vac_exploit.exe",
        "vac_unhook.exe",
        "vac_detach.exe",
        "vac_unprotect.exe",
        "steamvac_bypass.exe",
        "valve_bypass.exe",
        "steam_ac_bypass.exe",
    };

    private static readonly string[] VanguardBypassExecutables =
    {
        "vanguard_bypass.exe",
        "vanguard_disable.exe",
        "vanguard_kill.exe",
        "vanguard_spoof.exe",
        "vanguard_patch.exe",
        "vanguard_hook.exe",
        "vanguard_inject.exe",
        "vanguard_unload.exe",
        "vgk_bypass.exe",
        "vgk_disable.exe",
        "vgk_kill.exe",
        "vgk_spoof.exe",
        "vgk_patch.exe",
        "vgk_hook.exe",
        "vgk_inject.exe",
        "vgtray_bypass.exe",
        "bypass_vanguard.exe",
        "disable_vanguard.exe",
        "kill_vanguard.exe",
        "patch_vanguard.exe",
        "spoof_vanguard.exe",
        "valorant_bypass.exe",
        "valorant_anticheat_bypass.exe",
        "vanguard_bypass_tool.exe",
        "vanguard_bypass_loader.exe",
        "vanguard_stopper.exe",
        "vanguard_terminator.exe",
        "vanguard_nullify.exe",
        "vanguard_subvert.exe",
        "vanguard_evade.exe",
        "vanguard_circumvent.exe",
        "vanguard_blocker.exe",
        "vanguard_intercept.exe",
        "vanguard_tamper.exe",
        "vanguard_suspend.exe",
        "vanguard_shutdown.exe",
        "vgk_unload.exe",
        "vgk_stopper.exe",
        "vgk_terminator.exe",
        "vgk_dumper.exe",
        "vgk_override.exe",
        "vgk_modify.exe",
        "vgk_nuke.exe",
        "vgk_crash.exe",
        "vgk_exploit.exe",
        "vgk_unhook.exe",
        "vgk_detach.exe",
        "riot_vanguard_bypass.exe",
        "riot_bypass.exe",
    };

    private static readonly string[] FaceitBypassExecutables =
    {
        "faceit_bypass.exe",
        "faceit_disable.exe",
        "faceit_kill.exe",
        "faceit_spoof.exe",
        "faceit_patch.exe",
        "faceit_hook.exe",
        "faceit_inject.exe",
        "faceit_ac_bypass.exe",
        "faceit_ac_disable.exe",
        "faceit_anticheat_bypass.exe",
        "bypass_faceit.exe",
        "disable_faceit.exe",
        "kill_faceit.exe",
        "patch_faceit.exe",
        "spoof_faceit.exe",
        "faceIt_bypass.exe",
        "faceIt_kill.exe",
        "faceit_stopper.exe",
        "faceit_terminator.exe",
        "faceit_nullify.exe",
        "faceit_subvert.exe",
        "faceit_evade.exe",
        "faceit_circumvent.exe",
        "faceit_blocker.exe",
        "faceit_intercept.exe",
        "faceit_tamper.exe",
        "faceit_suspend.exe",
        "faceit_shutdown.exe",
        "faceit_unload.exe",
        "faceit_override.exe",
        "faceit_modify.exe",
        "faceit_nuke.exe",
        "faceit_crash.exe",
        "faceit_exploit.exe",
        "faceit_unhook.exe",
        "faceit_detach.exe",
        "faceit_unprotect.exe",
        "faceit_loader.exe",
        "faceit_dumper.exe",
        "faceit_dump.exe",
        "faceit_scan.exe",
        "faceit_patcher.exe",
        "esl_ac_bypass.exe",
    };

    private static readonly string[] BypassDlls =
    {
        "eac_bypass.dll",
        "eac_disable.dll",
        "eac_hook.dll",
        "eac_inject.dll",
        "be_bypass.dll",
        "be_disable.dll",
        "be_hook.dll",
        "be_inject.dll",
        "vac_bypass.dll",
        "vac_disable.dll",
        "vac_hook.dll",
        "vac_inject.dll",
        "vanguard_bypass.dll",
        "vangaurd_disable.dll",
        "vgk_bypass.dll",
        "vgk_hook.dll",
        "faceit_bypass.dll",
        "faceit_disable.dll",
        "faceit_hook.dll",
        "anticheat_bypass.dll",
        "anticheat_disable.dll",
        "anticheat_hook.dll",
        "anticheat_inject.dll",
        "ac_bypass.dll",
        "ac_disable.dll",
        "ac_hook.dll",
        "ac_inject.dll",
        "ac_spoof.dll",
        "bypass_hook.dll",
        "bypass_inject.dll",
        "bypass_dll.dll",
        "bypass_lib.dll",
        "hook_bypass.dll",
        "hook_ac.dll",
        "inject_ac.dll",
        "spoof_ac.dll",
        "kill_ac.dll",
        "disable_ac.dll",
        "eac_dump.dll",
        "be_dump.dll",
        "vac_dump.dll",
        "ac_dump.dll",
        "eac_unload.dll",
        "be_unload.dll",
        "vac_unload.dll",
        "eac_kill.dll",
        "be_kill.dll",
        "vac_kill.dll",
        "eac_patcher.dll",
        "be_patcher.dll",
        "vac_patcher.dll",
        "bypass_eac.dll",
        "bypass_be.dll",
        "bypass_vac.dll",
        "bypass_vanguard.dll",
        "bypass_faceit.dll",
        "fivem_ac_bypass.dll",
        "ragemp_ac_bypass.dll",
        "altv_ac_bypass.dll",
        "vgk_inject.dll",
        "vgk_disable.dll",
        "faceit_inject.dll",
        "anticheat_spoof.dll",
        "ac_tamper.dll",
    };

    private static readonly string[] BypassArchiveNames =
    {
        "eac_bypass",
        "eac_hack",
        "battleye_bypass",
        "be_bypass",
        "vac_bypass",
        "vac_hack",
        "vanguard_bypass",
        "vgk_bypass",
        "faceit_bypass",
        "anticheat_bypass",
        "ac_bypass",
        "bypass_eac",
        "bypass_be",
        "bypass_vac",
        "bypass_battleye",
        "bypass_vanguard",
        "bypass_faceit",
        "anticheat_crack",
        "eac_crack",
        "be_crack",
        "vac_crack",
        "ac_crack",
        "ac_disable",
        "eac_disable",
        "be_disable",
        "vac_disable",
        "eac_kill",
        "be_kill",
        "vac_kill",
        "eac_patch",
        "be_patch",
        "vac_patch",
        "anticheat_kill",
        "anticheat_disable",
        "bypass_anticheat",
        "bypass_ac",
        "easy_anticheat_bypass",
        "easyanticheat_bypass",
        "easyanticheat_crack",
        "easyanticheat_hack",
        "battleye_crack",
        "battleye_hack",
        "battleye_kill",
        "battleyebypass",
        "vacbypass",
        "vanguardbypass",
        "faceitbypass",
        "anticheatbypass",
        "anticheat_spoof",
        "eac_spoof",
        "be_spoof",
        "vac_spoof",
        "ac_spoof",
        "anticheat_remover",
        "ac_remover",
        "fivem_bypass",
        "ragemp_bypass",
        "altv_bypass",
    };

    private static readonly string[] BypassUserAssistKeywords =
    {
        "eac_bypass", "eac_disable", "eac_kill", "eac_hack", "eac_patch",
        "eac_hook", "eac_inject", "eac_loader", "eac_spoof", "eac_patcher",
        "easy_anticheat_bypass", "easyanticheat_bypass", "bypass_eac", "disable_eac",
        "be_bypass", "be_disable", "be_kill", "be_hack", "be_patch",
        "be_hook", "be_inject", "be_loader", "be_spoof", "battleye_bypass",
        "battleye_disable", "battleyebypass", "bypass_be", "disable_be",
        "bedaisy_bypass", "beservice_bypass", "beservice_kill",
        "vac_bypass", "vac_disable", "vac_kill", "vac_hack", "vac_patch",
        "vac_hook", "vac_inject", "valve_ac_bypass", "vac3_bypass", "bypass_vac",
        "vacnet_bypass", "steamdb_vac", "disable_vac",
        "vanguard_bypass", "vanguard_disable", "vanguard_kill", "vgk_bypass",
        "vgk_disable", "vgk_kill", "vgtray_bypass", "bypass_vanguard",
        "valorant_bypass", "valorant_anticheat_bypass",
        "faceit_bypass", "faceit_disable", "faceit_kill", "faceit_ac_bypass",
        "bypass_faceit", "disable_faceit", "faceit_anticheat_bypass",
        "anticheat_bypass", "ac_bypass", "bypass_anticheat", "kill_anticheat",
        "disable_anticheat", "anticheat_disable", "anticheat_kill",
    };

    private static readonly string[] BypassMuiCacheKeywords =
    {
        "eac_bypass", "eac_disable", "eac_kill", "eac_patch", "eac_hook",
        "easy_anticheat_bypass", "easyanticheat_bypass", "bypass_eac",
        "be_bypass", "be_disable", "be_kill", "battleye_bypass", "battleyebypass",
        "bypass_be", "beservice_kill", "bedaisy_bypass",
        "vac_bypass", "vac_disable", "vac_kill", "valve_ac_bypass", "vac3_bypass",
        "bypass_vac", "vacnet_bypass",
        "vanguard_bypass", "vanguard_disable", "vgk_bypass", "vgk_kill",
        "bypass_vanguard", "valorant_bypass",
        "faceit_bypass", "faceit_disable", "faceit_kill",
        "bypass_faceit", "faceit_ac_bypass",
        "anticheat_bypass", "ac_bypass", "bypass_anticheat",
    };

    private static readonly string[] BypassDriverServiceKeywords =
    {
        "eac_bypass", "eac_hook", "eac_inject", "eac_driver",
        "be_bypass", "be_hook", "be_inject", "be_driver",
        "vac_bypass", "vac_hook", "vac_inject", "vac_driver",
        "vgk_bypass", "vgk_hook", "vgk_driver",
        "faceit_bypass", "faceit_hook", "faceit_driver",
        "anticheat_bypass", "ac_bypass", "ac_hook", "ac_driver",
        "bypass_driver", "hook_driver", "inject_driver",
    };

    private static readonly string[] BypassConfigFiles =
    {
        "eac_config.json",
        "be_config.json",
        "vac_config.json",
        "bypass_config.json",
        "anticheat_config.json",
        "ac_config.json",
        "bypass_settings.json",
        "bypass_options.ini",
        "eac_bypass.cfg",
        "be_bypass.cfg",
        "vac_bypass.cfg",
        "vanguard_config.json",
        "vgk_config.json",
        "faceit_config.json",
        "anticheat_settings.ini",
        "ac_settings.ini",
        "bypass.cfg",
        "bypass.ini",
        "bypass.json",
        "ac_bypass.cfg",
        "ac_bypass.json",
        "eac_settings.ini",
        "be_settings.ini",
        "vac_settings.ini",
        "bypass_options.json",
    };

    private static readonly string[] BypassScriptKeywords =
    {
        "Stop-Service EasyAntiCheat",
        "Stop-Service BEService",
        "sc stop EasyAntiCheat",
        "sc stop BEService",
        "taskkill /F /IM EasyAntiCheat",
        "taskkill /F /IM BEService",
        "taskkill /F /IM vgk",
        "reg delete",
        "sfc /disable",
        "bypass",
        "disable_eac",
        "disable_be",
        "disable_vac",
        "kill_eac",
        "kill_be",
        "kill_vac",
        "anticheat_bypass",
        "ac_bypass",
        "bypass_check",
        "Stop-Service vgk",
        "Stop-Service FACEITService",
        "sc stop vgk",
        "sc stop FACEIT",
        "taskkill /F /IM vgtray",
        "taskkill /F /IM FACEIT",
        "disable_vanguard",
        "kill_vanguard",
        "disable_faceit",
        "kill_faceit",
        "bypass_vanguard",
        "bypass_faceit",
        "bypass_battleye",
        "bypass_vac",
        "anticheat_kill",
        "ac_kill",
        "ac_disable",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Anti-Cheat Bypass forensic scan...");

        await Task.WhenAll(
            CheckEACBypassExecutables(ctx, ct),
            CheckBattlEyeBypassExecutables(ctx, ct),
            CheckVACBypassExecutables(ctx, ct),
            CheckVanguardBypassExecutables(ctx, ct),
            CheckFACEITBypassExecutables(ctx, ct),
            CheckAnticheatBypassDlls(ctx, ct),
            CheckAnticheatBypassDownloadArtifacts(ctx, ct),
            CheckAnticheatBypassRegistryArtifacts(ctx, ct),
            CheckAnticheatBypassConfigFiles(ctx, ct),
            CheckAnticheatBypassScripts(ctx, ct)
        ).ConfigureAwait(false);

        ctx.Report(1.0, Name, "Anti-Cheat Bypass forensic scan complete.");
    }

    private Task CheckEACBypassExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in CommonSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        var match = EacBypassExecutables.FirstOrDefault(n =>
                            fn.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        var fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"EAC Bypass Executable Found: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Easy Anti-Cheat bypass tool '{fn}' was found at '{file}'. " +
                                       "This executable is a known EAC bypass/disable/patch tool that circumvents " +
                                       "EasyAntiCheat protection to allow cheats to operate undetected in " +
                                       "protected games (Fortnite, Apex Legends, Rust, EFT, etc.).",
                            Detail   = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm} | " +
                                       $"Created: {fi.CreationTime:yyyy-MM-dd HH:mm} | Match: {match}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckBattlEyeBypassExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in CommonSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        var match = BeBypassExecutables.FirstOrDefault(n =>
                            fn.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        var fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"BattlEye Bypass Executable Found: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"BattlEye anti-cheat bypass tool '{fn}' was found at '{file}'. " +
                                       "This executable is a known BattlEye bypass/disable/kill/patch tool that " +
                                       "circumvents BattlEye protection in games such as DayZ, Arma 3, PUBG, " +
                                       "Rainbow Six Siege, and others. BEDaisy.sys and BEService are common " +
                                       "targets for these bypass tools.",
                            Detail   = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm} | " +
                                       $"Created: {fi.CreationTime:yyyy-MM-dd HH:mm} | Match: {match}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckVACBypassExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in CommonSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        var match = VacBypassExecutables.FirstOrDefault(n =>
                            fn.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        var fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"VAC Bypass Executable Found: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Valve Anti-Cheat (VAC) bypass tool '{fn}' was found at '{file}'. " +
                                       "This executable is designed to bypass VAC scanning, allowing banned or " +
                                       "cheating accounts to play undetected on VAC-secured servers in games such " +
                                       "as CS2, CS:GO, Team Fortress 2, Dota 2, and other Steam titles. " +
                                       "VAC bypass tools typically hook VAC module scanning routines or redirect " +
                                       "the VACNet network check.",
                            Detail   = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm} | " +
                                       $"Created: {fi.CreationTime:yyyy-MM-dd HH:mm} | Match: {match}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckVanguardBypassExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in CommonSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        var match = VanguardBypassExecutables.FirstOrDefault(n =>
                            fn.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        var fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Vanguard (Riot) Bypass Executable Found: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Riot Vanguard anti-cheat bypass tool '{fn}' was found at '{file}'. " +
                                       "Vanguard (vgk.sys) is a kernel-level anti-cheat used by Valorant and " +
                                       "other Riot Games titles. Bypass tools targeting Vanguard typically attempt " +
                                       "to unload vgk.sys, disable the vgc service, or hook its kernel-mode " +
                                       "integrity verification to allow cheats to operate without detection.",
                            Detail   = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm} | " +
                                       $"Created: {fi.CreationTime:yyyy-MM-dd HH:mm} | Match: {match}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckFACEITBypassExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in CommonSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        var match = FaceitBypassExecutables.FirstOrDefault(n =>
                            fn.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        var fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"FACEIT AC Bypass Executable Found: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"FACEIT anti-cheat bypass tool '{fn}' was found at '{file}'. " +
                                       "FACEIT is an ESL-operated anti-cheat used in competitive CS2 and other " +
                                       "games. Bypass tools targeting FACEIT attempt to disable its kernel-mode " +
                                       "driver, intercept its process integrity checks, or spoof the system state " +
                                       "it monitors to allow cheating in FACEIT-protected matches.",
                            Detail   = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm} | " +
                                       $"Created: {fi.CreationTime:yyyy-MM-dd HH:mm} | Match: {match}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckAnticheatBypassDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in CommonSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        var match = BypassDlls.FirstOrDefault(n =>
                            fn.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        var fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Anti-Cheat Bypass DLL Found: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Anti-cheat bypass DLL '{fn}' was found at '{file}'. " +
                                       "Bypass DLLs are injected into processes or loaded by bypass loaders to " +
                                       "hook, patch, or disable anti-cheat scanning routines at runtime. " +
                                       $"The matched DLL '{match}' is associated with bypassing EAC, BattlEye, " +
                                       "VAC, Vanguard, FACEIT, FiveM, RageMP, or alt:V anti-cheat systems.",
                            Detail   = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm} | " +
                                       $"Created: {fi.CreationTime:yyyy-MM-dd HH:mm} | Match: {match}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckAnticheatBypassDownloadArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var archiveDirs = new[] { Downloads, Desktop };
            var archiveExtensions = new[] { ".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".iso", ".tar.gz" };

            foreach (var dir in archiveDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var ext = Path.GetExtension(file);
                        if (!archiveExtensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase)))
                            continue;

                        var fn = Path.GetFileName(file);
                        var fnLower = fn.ToLowerInvariant();

                        var keyword = BypassArchiveNames.FirstOrDefault(k =>
                            fnLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (keyword is null) continue;

                        var fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Anti-Cheat Bypass Archive: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"An archive file '{fn}' matching anti-cheat bypass tool naming patterns " +
                                       $"was found at '{file}'. The keyword '{keyword}' in the filename indicates " +
                                       "this archive likely contains bypass tools for EAC, BattlEye, VAC, Vanguard, " +
                                       "or FACEIT anti-cheat. Archive contents were not unpacked but the filename " +
                                       "is a strong forensic indicator.",
                            Detail   = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm} | " +
                                       $"Keyword match: {keyword}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckAnticheatBypassRegistryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            CheckBypassUserAssist(ctx, ct);
            CheckBypassMuiCache(ctx, ct);
            CheckBypassRunKeys(ctx, ct);
            CheckBypassSoftwareKeys(ctx, ct);
            CheckBypassDriverServices(ctx, ct);
            CheckBypassUninstallKeys(ctx, ct);
        }, ct);

    private static void CheckBypassUserAssist(ScanContext ctx, CancellationToken ct)
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
                        var decoded = Rot13Decode(encodedName).ToLowerInvariant();

                        var hit = BypassUserAssistKeywords.FirstOrDefault(k =>
                            decoded.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        int runCount = 0;
                        DateTime? lastRun = null;
                        try
                        {
                            var data = countKey.GetValue(encodedName) as byte[];
                            if (data is { Length: >= 16 })
                            {
                                runCount = BitConverter.ToInt32(data, 4);
                                long ft = BitConverter.ToInt64(data, 8);
                                if (ft > 0) lastRun = DateTime.FromFileTimeUtc(ft);
                            }
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module   = "Anti-Cheat Bypass Tool Forensic Scan",
                            Title    = $"UserAssist: AC Bypass Tool Executed — {hit}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason   = $"Windows UserAssist registry entry shows execution of anti-cheat bypass " +
                                       $"tool '{Path.GetFileName(decoded)}' ({runCount} time(s)" +
                                       (lastRun.HasValue ? $", last run {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                       $"). Keyword match: '{hit}'. UserAssist entries persist after file deletion.",
                            Detail   = $"Decoded: {decoded} | Executions: {runCount} | " +
                                       $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CheckBypassMuiCache(ScanContext ctx, CancellationToken ct)
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
                var combined = (valueName + " " + (key.GetValue(valueName) as string ?? ""))
                    .ToLowerInvariant();

                var hit = BypassMuiCacheKeywords.FirstOrDefault(k =>
                    combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (hit is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = "Anti-Cheat Bypass Tool Forensic Scan",
                    Title    = $"MuiCache: AC Bypass Tool Executed — {hit}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKCU\{muiCacheKey}",
                    FileName = Path.GetFileName(valueName),
                    Reason   = $"MuiCache entry shows that an anti-cheat bypass tool was executed from " +
                               $"'{valueName}'. Keyword match: '{hit}'. MuiCache persists even after file deletion.",
                    Detail   = $"Registry value: {valueName} | Match: {hit}"
                });
            }
        }
        catch { }
    }

    private static void CheckBypassRunKeys(ScanContext ctx, CancellationToken ct)
    {
        var runKeyPaths = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
        };

        foreach (var (path, hive, hiveName) in runKeyPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = hive.OpenSubKey(path, writable: false);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    var val = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                    var combined = valueName.ToLowerInvariant() + " " + val;

                    var hit = BypassUserAssistKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Anti-Cheat Bypass Tool Forensic Scan",
                        Title    = $"Run Key: AC Bypass Tool Autostart — {valueName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"{hiveName}\{path}",
                        FileName = Path.GetFileName(val.Split(' ')[0].Trim('"')),
                        Reason   = $"Registry Run/RunOnce key contains an anti-cheat bypass tool entry " +
                                   $"'{valueName}' pointing to '{val}'. This means the bypass tool was " +
                                   "configured to start automatically, indicating persistent or repeated use. " +
                                   $"Keyword match: '{hit}'.",
                        Detail   = $"Key: {hiveName}\\{path}\\{valueName} | Value: {val} | Match: {hit}"
                    });
                }
            }
            catch { }
        }
    }

    private static void CheckBypassSoftwareKeys(ScanContext ctx, CancellationToken ct)
    {
        var softwareKeyPaths = new[]
        {
            (@"SOFTWARE\EAC Bypass", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\EAC Bypass", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\BE Bypass", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\BE Bypass", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\VAC Bypass", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\VAC Bypass", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Vanguard Bypass", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Vanguard Bypass", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\FACEIT Bypass", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\FACEIT Bypass", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\AntiCheat Bypass", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\AC Bypass", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\EasyAntiCheat Bypass", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\BattlEye Bypass", Registry.LocalMachine, "HKLM"),
        };

        foreach (var (path, hive, hiveName) in softwareKeyPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = hive.OpenSubKey(path, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                ctx.AddFinding(new Finding
                {
                    Module   = "Anti-Cheat Bypass Tool Forensic Scan",
                    Title    = $"Registry: AC Bypass Tool Installation Key Found — {path}",
                    Risk     = RiskLevel.High,
                    Location = $@"{hiveName}\{path}",
                    Reason   = $"A registry key associated with an anti-cheat bypass tool installation was " +
                               $"found at '{hiveName}\\{path}'. This key indicates the bypass tool was installed " +
                               "or ran on this system and left a configuration/installation artifact.",
                    Detail   = $"Registry key: {hiveName}\\{path}"
                });
            }
            catch { }
        }
    }

    private static void CheckBypassDriverServices(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (services is null) return;

            foreach (var svcName in services.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var svc = services.OpenSubKey(svcName, writable: false);
                    if (svc is null) continue;
                    ctx.IncrementRegistryKeys();

                    var imgPath = (svc.GetValue("ImagePath") as string ?? "").ToLowerInvariant();
                    var type = svc.GetValue("Type") as int? ?? 0;
                    if (type != 1) continue;

                    var svcLower = svcName.ToLowerInvariant();
                    var hit = BypassDriverServiceKeywords.FirstOrDefault(k =>
                        svcLower.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                        imgPath.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = "Anti-Cheat Bypass Tool Forensic Scan",
                        Title    = $"AC Bypass Kernel Driver Service: {svcName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = Path.GetFileName(imgPath),
                        Reason   = $"Kernel driver service '{svcName}' matches anti-cheat bypass driver naming " +
                                   $"patterns. Keyword match: '{hit}'. Bypass drivers operate at kernel level to " +
                                   "hook or disable EAC/BattlEye/VAC/Vanguard/FACEIT integrity verification, " +
                                   "allowing cheats to avoid detection. This is evidence of kernel-level AC bypass.",
                        Detail   = $"Service: {svcName} | ImagePath: {imgPath} | Match: {hit}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private static void CheckBypassUninstallKeys(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", Registry.CurrentUser, "HKCU"),
        };

        foreach (var (path, hive, hiveName) in uninstallPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var uninstall = hive.OpenSubKey(path, writable: false);
                if (uninstall is null) continue;

                foreach (var subKeyName in uninstall.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var entry = uninstall.OpenSubKey(subKeyName, writable: false);
                        if (entry is null) continue;
                        ctx.IncrementRegistryKeys();

                        var displayName = (entry.GetValue("DisplayName") as string ?? "").ToLowerInvariant();
                        var publisher = (entry.GetValue("Publisher") as string ?? "").ToLowerInvariant();
                        var installLoc = (entry.GetValue("InstallLocation") as string ?? "").ToLowerInvariant();
                        var combined = displayName + " " + publisher + " " + installLoc;

                        var hit = BypassUserAssistKeywords.FirstOrDefault(k =>
                            combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = "Anti-Cheat Bypass Tool Forensic Scan",
                            Title    = $"Uninstall Key: AC Bypass Tool Installer Record — {displayName}",
                            Risk     = RiskLevel.High,
                            Location = $@"{hiveName}\{path}\{subKeyName}",
                            Reason   = $"An uninstall registry entry for an anti-cheat bypass tool was found: " +
                                       $"'{displayName}'. Keyword match: '{hit}'. This is an installer remnant " +
                                       "indicating the bypass tool was formally installed on this system.",
                            Detail   = $"DisplayName: {displayName} | Publisher: {publisher} | " +
                                       $"InstallLocation: {installLoc} | Match: {hit}"
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }
    }

    private Task CheckAnticheatBypassConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var configKeywords = new[]
            {
                "bypass", "disable", "kill", "hook", "inject",
                "eac", "battleye", "vac", "vanguard", "faceit",
                "anticheat", "anti_cheat", "anti-cheat",
            };

            var configSearchDirs = new[]
            {
                RoamingAppData,
                LocalAppData,
                Desktop,
                Downloads,
            };

            foreach (var dir in configSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var configName in BypassConfigFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var configPath = Path.Combine(dir, configName);
                    if (!File.Exists(configPath)) continue;

                    ctx.IncrementFiles();
                    try
                    {
                        string content;
                        using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                        var contentLower = content.ToLowerInvariant();
                        var hitKw = configKeywords.FirstOrDefault(k =>
                            contentLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"AC Bypass Config File Found: {configName}",
                            Risk     = hitKw is not null ? RiskLevel.High : RiskLevel.Medium,
                            Location = configPath,
                            FileName = configName,
                            Reason   = $"Anti-cheat bypass configuration file '{configName}' was found at '{configPath}'. " +
                                       (hitKw is not null
                                           ? $"File content contains bypass-related keyword '{hitKw}', confirming " +
                                             "this is a configuration artifact from an active bypass tool."
                                           : "This filename matches known bypass tool configuration file patterns."),
                            Detail   = hitKw is not null
                                ? $"Content keyword match: {hitKw} | Size: {content.Length} chars"
                                : $"File present but content scan inconclusive | Size: {new FileInfo(configPath).Length} bytes"
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }, ct);

    private Task CheckAnticheatBypassScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var scriptExtensions = new[] { ".ps1", ".bat", ".py" };
            var scriptDirs = new[]
            {
                Desktop,
                Downloads,
                Temp,
            };

            foreach (var dir in scriptDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        var ext = Path.GetExtension(file);
                        if (!scriptExtensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase)))
                            continue;

                        ctx.IncrementFiles();
                        try
                        {
                            string content;
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            int matchCount = 0;
                            var matchedKeywords = new List<string>();
                            foreach (var kw in BypassScriptKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    matchCount++;
                                    matchedKeywords.Add(kw);
                                }
                            }

                            if (matchCount >= 4)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"AC Bypass Script Found: {Path.GetFileName(file)}",
                                    Risk     = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason   = $"Script file '{Path.GetFileName(file)}' contains {matchCount} " +
                                               "anti-cheat bypass-related keywords, indicating this script is " +
                                               "designed to disable, kill, or bypass EAC, BattlEye, VAC, Vanguard, " +
                                               "or FACEIT anti-cheat protections. Scripts like this are used to " +
                                               "prepare systems for cheat tool loading.",
                                    Detail   = $"Matched keywords ({matchCount}): {string.Join(", ", matchedKeywords.Take(10))}"
                                });
                            }
                        }
                        catch (IOException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

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
