using Microsoft.Win32;
using System.Diagnostics;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class VanguardBypassScanModule : IScanModule
{
    public string Name => "Vanguard/Riot Anti-Cheat Bypass Detection";
    public double Weight => 4.5;
    public int ParallelGroup => 4;

    // -----------------------------------------------------------------------
    // Known Vanguard bypass executable / DLL names (50+ variants)
    // -----------------------------------------------------------------------
    private static readonly HashSet<string> BypassFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Direct bypass executables
        "vanguard_bypass.exe",
        "vgc_bypass.exe",
        "riot_bypass.exe",
        "vanguard_killer.exe",
        "vgc_killer.exe",
        "vgk_killer.exe",
        "vgc_disable.exe",
        "vgk_disable.exe",
        "vanguard_disable.exe",
        "riot_anticheat_bypass.exe",
        "valorant_bypass.exe",
        "valo_bypass.exe",
        "vangrd_bypass.exe",
        "vgc_spoofer.exe",
        "vanguard_spoof.exe",
        "riot_bypass_v2.exe",
        "vgc_patcher.exe",
        "vgk_patcher.exe",
        "vanguard_patcher.exe",
        "bypass_vanguard.exe",
        "kill_vgc.exe",
        "kill_vgk.exe",
        "vanguard_unload.exe",
        "vgc_unload.exe",
        "vgk_unload.exe",
        "anticheat_bypass.exe",
        "ac_bypass.exe",
        "vanguard_crack.exe",
        "vgc_crack.exe",
        "valorant_hack.exe",
        "valorant_cheat.exe",
        "valorant_aimbot.exe",
        "valorant_wallhack.exe",
        "valorant_esp.exe",
        "valo_hack.exe",
        "riot_hack.exe",
        "vanguard_hook.exe",
        "vgc_hook.exe",
        "vgk_hook.exe",
        "vanguard_patch.exe",
        "bypass_loader.exe",
        "anticheat_killer.exe",
        "riot_killer.exe",
        "vanguard_remover.exe",
        "vgc_remover.exe",
        "vgk_remover.exe",
        "vanguard_fix.exe",
        "noguard.exe",
        "vg_bypass.exe",
        "riotclient_bypass.exe",
        "riot_client_bypass.exe",
        "vgc_stop.exe",
        "vgk_stop.exe",
        "vanguard_stop.exe",
        "riot_stop.exe",
        // DLL variants
        "vanguard_bypass.dll",
        "vgc_bypass.dll",
        "vgk_bypass.dll",
        "riot_bypass.dll",
        "vanguard_hook.dll",
        "vgc_hook.dll",
        "vgk_hook.dll",
        "valorant_bypass.dll",
        "anticheat_bypass.dll",
        "vanguard_patch.dll",
        "vgc_patch.dll",
        "vgk_patch.dll",
        "bypass_vgc.dll",
        "bypass_vgk.dll",
        "vgc_inject.dll",
        "vgk_inject.dll",
        "vanguard_inject.dll",
        "riot_inject.dll",
        "valorant_inject.dll",
        "vg_hook.dll",
        "vg_bypass.dll",
        "vanguard_spoof.dll",
        "vgc_spoof.dll",
        "riot_spoof.dll",
        "vanguard_null.dll",
        "vgk_null.dll",
        "vgc_null.dll",
    };

    // Substrings to match against file names (covers obfuscated/variant names)
    private static readonly string[] BypassFileKeywords =
    {
        "vgc_bypass", "vgk_bypass", "vanguard_bypass", "riot_bypass",
        "vanguard_kill", "vgc_kill", "vgk_kill", "vanguard_disab",
        "vgc_disab", "vgk_disab", "valorant_bypass", "valo_bypass",
        "vanguard_patch", "vgc_patch", "vgk_patch", "vanguard_hook",
        "vgc_hook", "vgk_hook", "vanguard_crack", "vgc_crack",
        "riot_killer", "anticheat_bypass", "ac_bypass",
        "vgc_spoof", "vgk_spoof", "vanguard_spoof",
        "kill_vgc", "kill_vgk", "bypass_vgc", "bypass_vgk",
        "noguard", "vg_bypass", "riotclient_bypass",
        "vgc_remov", "vgk_remov", "vanguard_remov",
        "vanguard_inject", "vgc_inject", "vgk_inject",
    };

    // Known suspicious bypass directory names
    private static readonly string[] BypassDirectoryKeywords =
    {
        "vanguard_bypass", "vgc_bypass", "riot_bypass", "valorant_bypass",
        "vanguard_hack", "vanguard_cheat", "vgc_killer", "vgk_killer",
        "vanguard_crack", "riot_crack", "valorant_cheat", "valorant_hack",
        "anticheat_bypass", "riot_anticheat", "vg_bypass",
        "vanguard_tools", "riot_tools", "vgc_tools",
    };

    // Registry paths to check for Vanguard bypass artifacts
    private static readonly string[] BypassRegistryPaths =
    {
        @"SOFTWARE\Vanguard_bypass",
        @"SOFTWARE\VGC_Bypass",
        @"SOFTWARE\VGK_Bypass",
        @"SOFTWARE\Riot_Bypass",
        @"SOFTWARE\Valorant_Bypass",
        @"SOFTWARE\Vanguard_Killer",
        @"SOFTWARE\VGC_Killer",
        @"SOFTWARE\Riot_Hack",
        @"SOFTWARE\Valorant_Hack",
        @"SOFTWARE\AntiCheat_Bypass",
        @"SOFTWARE\VanguardBypass",
        @"SOFTWARE\VGCBypass",
        @"SOFTWARE\RiotBypass",
        @"SOFTWARE\ValorantBypass",
        @"SOFTWARE\NoGuard",
        @"SOFTWARE\RiotKiller",
        @"SOFTWARE\VanguardPatcher",
        @"SOFTWARE\VGKPatcher",
    };

    // Config file content keywords indicating bypass activity
    private static readonly string[] BypassConfigKeywords =
    {
        "vanguard_bypass", "vgc_disabled", "vgk_disabled", "riot_bypass",
        "vgk_killed", "vgc_killed", "disable_vanguard", "kill_vanguard",
        "bypass_vgc", "bypass_vgk", "vanguard_off", "vgc_off", "vgk_off",
        "anticheat_bypass", "ac_bypass", "riot_anticheat_bypass",
        "valorant_bypass", "valo_bypass", "vg_bypass", "disable_anticheat",
        "patch_vgc", "patch_vgk", "hook_vgc", "hook_vgk",
        "spoof_vgc", "spoof_vgk", "vanguard_spoof", "vanguard_inject",
        "vgc_inject", "vgk_inject", "riot_inject",
        "vanguard_service_disabled", "vgc_service_disabled",
        "riot_ac_bypass", "unload_vgk", "unload_vgc",
    };

    // ROT13 decode for UserAssist analysis
    private static string Rot13(string s)
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

    // Keywords for UserAssist / MUICache decoded name matching
    private static readonly string[] UserAssistBypassKeywords =
    {
        "vanguard_bypass", "vgc_bypass", "vgk_bypass", "riot_bypass",
        "vanguard_killer", "vgc_killer", "vgk_killer", "valorant_bypass",
        "vanguard_hack", "vgc_hack", "vgk_hack", "vg_bypass",
        "anticheat_bypass", "ac_bypass", "riot_hack",
        "vanguard_crack", "vgc_crack", "vgk_crack",
        "valorant_cheat", "valo_bypass", "noguard",
        "riot_killer", "vanguard_patcher", "vgk_patcher",
    };

    // Scan root directories for bypass files
    private static readonly string[] ScanRoots;

    static VanguardBypassScanModule()
    {
        var roots = new List<string>();

        var userProfile    = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localApp       = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roamingApp     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var desktop        = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads      = Path.Combine(userProfile, "Downloads");
        var documents      = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var temp           = Path.GetTempPath();
        var programData    = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var programFiles   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        foreach (var r in new[]
        {
            desktop, downloads, documents, temp, localApp, roamingApp,
            programData, programFiles, programFilesX86,
            Path.Combine(localApp, "Riot Games"),
            Path.Combine(localApp, "Riot Games", "Riot Client"),
            Path.Combine(programFiles, "Riot Vanguard"),
            Path.Combine(programFiles, "Riot Games"),
            Path.Combine(programFilesX86, "Riot Games"),
            Path.Combine(programData, "Riot Games"),
            Path.Combine(localApp, "Temp"),
            Path.Combine(userProfile, "Desktop"),
            "C:\\Users\\Public",
            "C:\\Temp",
            "C:\\Tools",
        })
        {
            if (!string.IsNullOrEmpty(r)) roots.Add(r);
        }

        ScanRoots = roots.ToArray();
    }

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------
    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Vanguard bypass detection...");

        return Task.WhenAll(
            CheckBypassFiles(ctx, ct),
            CheckBypassDirectories(ctx, ct),
            CheckVanguardServiceRegistry(ctx, ct),
            CheckVgkDriverIntegrity(ctx, ct),
            CheckBypassRegistryKeys(ctx, ct),
            CheckBypassConfigFiles(ctx, ct),
            CheckUserAssistBypass(ctx, ct),
            CheckMuiCacheBypass(ctx, ct),
            CheckIfeoVanguardHijack(ctx, ct),
            CheckBypassProcesses(ctx, ct),
            CheckWfpFilterArtifacts(ctx, ct),
            CheckVanguardRunKeys(ctx, ct)
        );
    }

    // -----------------------------------------------------------------------
    // Sub-check: known bypass EXEs / DLLs on disk
    // -----------------------------------------------------------------------
    private Task CheckBypassFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();
            foreach (var root in ScanRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn  = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    bool isExeOrDll = ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                                   || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                                   || ext.Equals(".sys", StringComparison.OrdinalIgnoreCase);
                    if (!isExeOrDll) continue;

                    bool exactMatch   = BypassFileNames.Contains(fn);
                    bool keywordMatch = !exactMatch && BypassFileKeywords.Any(k =>
                        fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!exactMatch && !keywordMatch) continue;

                    var risk = exactMatch ? RiskLevel.Critical : RiskLevel.High;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Vanguard Bypass File: {fn}",
                        Risk     = risk,
                        Location = file,
                        FileName = fn,
                        Reason   = exactMatch
                            ? $"File '{fn}' matches a known Vanguard/Riot anti-cheat bypass tool name exactly. " +
                              "These tools attempt to disable, kill, or bypass Riot's Vanguard kernel driver (vgk.sys) " +
                              "and its user-mode service (vgc.exe) to allow cheating in Valorant and other Riot games."
                            : $"File '{fn}' contains a keyword pattern associated with Vanguard bypass tools. " +
                              "The file name strongly suggests it is designed to circumvent Riot's Vanguard anti-cheat system.",
                        Detail   = $"Path: {file} | Match type: {(exactMatch ? "exact name" : "keyword")} | Extension: {ext}"
                    });
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: suspicious directories named after bypass tools
    // -----------------------------------------------------------------------
    private Task CheckBypassDirectories(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();
            foreach (var root in ScanRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> dirs;
                try
                {
                    dirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var dir in dirs)
                {
                    if (ct.IsCancellationRequested) return;
                    var dirName = Path.GetFileName(dir);

                    bool match = BypassDirectoryKeywords.Any(k =>
                        dirName.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!match) continue;

                    int fileCount = 0;
                    try { fileCount = Directory.GetFiles(dir).Length; }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Vanguard Bypass Directory: {dirName}",
                        Risk     = RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason   = $"Directory '{dirName}' at '{dir}' matches a known Vanguard bypass tool folder name pattern. " +
                                   "Cheat tool packages commonly extract to directories named after the targeted anti-cheat system. " +
                                   $"Directory contains {fileCount} file(s).",
                        Detail   = $"Directory: {dir} | Files inside: {fileCount}"
                    });
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: Vanguard service (vgc, vgk) registry tampering
    //            Detects Start=4 (disabled), deleted services, or altered ImagePath
    // -----------------------------------------------------------------------
    private Task CheckVanguardServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var vanguardServices = new[] { "vgc", "vgk" };
            const string servicesPath = @"SYSTEM\CurrentControlSet\Services";

            foreach (var svc in vanguardServices)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var svcKey = Registry.LocalMachine.OpenSubKey(
                        $@"{servicesPath}\{svc}", writable: false);

                    if (svcKey is null)
                    {
                        // Service key missing — may have been deleted by bypass tool
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Vanguard Service Missing: {svc}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{servicesPath}\{svc}",
                            FileName = $"{svc}.exe",
                            Reason   = $"The Vanguard service registry key 'HKLM\\{servicesPath}\\{svc}' is missing. " +
                                       "Vanguard bypass tools can delete or corrupt the service registration to prevent " +
                                       "Vanguard from loading, enabling cheats to run without detection. " +
                                       "This is expected only if Vanguard was never installed.",
                            Detail   = $"Service: {svc} | Key: HKLM\\{servicesPath}\\{svc} | Status: not found"
                        });
                        continue;
                    }

                    var startVal  = svcKey.GetValue("Start");
                    var imagePath = svcKey.GetValue("ImagePath") as string ?? "";

                    int startInt = startVal is int s ? s : (startVal is null ? -1 : -2);

                    // Start=4 means SERVICE_DISABLED
                    if (startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Vanguard Service Disabled in Registry: {svc}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{servicesPath}\{svc}",
                            FileName = $"{svc}.exe",
                            Reason   = $"The Vanguard service '{svc}' has its Start value set to 4 (SERVICE_DISABLED) " +
                                       "in the registry. This is the primary technique used by Vanguard bypass tools: " +
                                       "by disabling the vgc service (user-mode) or vgk driver (kernel), the anti-cheat " +
                                       "system cannot load when Valorant launches. Legitimate Vanguard installs use Start=2 (automatic).",
                            Detail   = $"Service: {svc} | Start: {startInt} (DISABLED) | ImagePath: {imagePath}"
                        });
                    }
                    else if (startInt == 3 && svc.Equals("vgk", StringComparison.OrdinalIgnoreCase))
                    {
                        // Start=3 (manual) is suspicious for vgk driver which should be boot/system-start
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Vanguard Kernel Driver Start Mode Altered: {svc}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{servicesPath}\{svc}",
                            FileName = "vgk.sys",
                            Reason   = $"The Vanguard kernel driver service '{svc}' has Start=3 (demand-start). " +
                                       "The vgk kernel driver is normally configured as boot-start (Start=0) for proper " +
                                       "anti-cheat protection. A bypass tool may have changed this to prevent " +
                                       "the driver from loading automatically at system boot.",
                            Detail   = $"Service: {svc} | Start: {startInt} (DEMAND_START) | ImagePath: {imagePath}"
                        });
                    }

                    // Check if ImagePath points away from expected Riot Vanguard folder
                    if (!string.IsNullOrWhiteSpace(imagePath))
                    {
                        bool validPath = imagePath.Contains("Riot Vanguard", StringComparison.OrdinalIgnoreCase)
                                      || imagePath.Contains("vgk.sys", StringComparison.OrdinalIgnoreCase)
                                      || imagePath.Contains("vgc.exe", StringComparison.OrdinalIgnoreCase);

                        if (!validPath)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Vanguard Service ImagePath Suspicious: {svc}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{servicesPath}\{svc}",
                                FileName = Path.GetFileName(imagePath),
                                Reason   = $"The Vanguard service '{svc}' has an unexpected ImagePath: '{imagePath}'. " +
                                           "Legitimate Vanguard services point to 'C:\\Program Files\\Riot Vanguard\\'. " +
                                           "An altered ImagePath may indicate a bypass tool has redirected the service " +
                                           "to a fake or null binary to prevent Vanguard from loading.",
                                Detail   = $"Service: {svc} | ImagePath: {imagePath}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: vgk.sys driver file integrity / size anomalies
    // -----------------------------------------------------------------------
    private Task CheckVgkDriverIntegrity(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var vgkPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "Riot Vanguard", "vgk.sys"),
                @"C:\Program Files\Riot Vanguard\vgk.sys",
                @"C:\Windows\System32\drivers\vgk.sys",
            };

            foreach (var vgkPath in vgkPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!File.Exists(vgkPath)) continue;

                ctx.IncrementFiles();

                FileInfo fi;
                try { fi = new FileInfo(vgkPath); }
                catch (IOException) { continue; }

                // Legitimate vgk.sys is typically 200KB–2MB
                if (fi.Length < 50_000)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "vgk.sys Driver Suspiciously Small",
                        Risk     = RiskLevel.Critical,
                        Location = vgkPath,
                        FileName = "vgk.sys",
                        Reason   = $"The Vanguard kernel driver 'vgk.sys' at '{vgkPath}' is only {fi.Length} bytes, " +
                                   "which is far smaller than a legitimate Vanguard driver (typically 200 KB–2 MB). " +
                                   "Bypass tools can replace the real driver with a stub or near-empty file that loads " +
                                   "successfully but performs no anti-cheat detection, effectively nullifying Vanguard.",
                        Detail   = $"Path: {vgkPath} | Size: {fi.Length} bytes | LastWrite: {fi.LastWriteTimeUtc:O}"
                    });
                }
                else if (fi.Length < 150_000)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "vgk.sys Driver Size Anomaly",
                        Risk     = RiskLevel.High,
                        Location = vgkPath,
                        FileName = "vgk.sys",
                        Reason   = $"The Vanguard kernel driver 'vgk.sys' at '{vgkPath}' is {fi.Length} bytes, " +
                                   "smaller than expected for a full Vanguard driver build. " +
                                   "This may indicate patching or replacement by a bypass tool.",
                        Detail   = $"Path: {vgkPath} | Size: {fi.Length} bytes | LastWrite: {fi.LastWriteTimeUtc:O}"
                    });
                }

                // Abnormally recent write time
                if (fi.LastWriteTimeUtc > DateTime.UtcNow.AddHours(-24))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "vgk.sys Modified Very Recently",
                        Risk     = RiskLevel.High,
                        Location = vgkPath,
                        FileName = "vgk.sys",
                        Reason   = $"The Vanguard kernel driver 'vgk.sys' was last modified within the past 24 hours " +
                                   $"({fi.LastWriteTimeUtc:O} UTC). While Riot may push driver updates, a very recent " +
                                   "modification timestamp can indicate tampering by a bypass tool that patches or " +
                                   "replaces the driver binary.",
                        Detail   = $"Path: {vgkPath} | Size: {fi.Length} bytes | LastWrite: {fi.LastWriteTimeUtc:O}"
                    });
                }

                // Scan driver file content for bypass markers
                try
                {
                    using var fs = new FileStream(vgkPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    string content = await sr.ReadToEndAsync(ct);

                    var bypassMarkers = new[]
                    {
                        "BYPASS", "PATCHED", "NULLED", "CRACKED", "DISABLED",
                        "vgk_bypass", "vanguard_bypass", "riot_bypass",
                        "STUB_DRV", "FAKE_VGK", "HOLLOWED",
                    };

                    foreach (var marker in bypassMarkers)
                    {
                        if (content.Contains(marker, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"vgk.sys Contains Bypass Marker: {marker}",
                                Risk     = RiskLevel.Critical,
                                Location = vgkPath,
                                FileName = "vgk.sys",
                                Reason   = $"The Vanguard kernel driver file 'vgk.sys' contains the string '{marker}' " +
                                           "embedded in its binary content. This strongly suggests the file has been " +
                                           "patched or replaced by a bypass tool that embeds identifying strings.",
                                Detail   = $"Path: {vgkPath} | Marker: '{marker}'"
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            // vgk.sys in System32\drivers is unusual (legitimate Vanguard installs to Program Files)
            var sys32Drivers = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");
            var vgkInDrivers = Path.Combine(sys32Drivers, "vgk.sys");

            if (File.Exists(vgkInDrivers))
            {
                ctx.IncrementFiles();
                try
                {
                    var fi2 = new FileInfo(vgkInDrivers);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "vgk.sys Present in System32\\drivers",
                        Risk     = RiskLevel.Medium,
                        Location = vgkInDrivers,
                        FileName = "vgk.sys",
                        Reason   = $"A copy of vgk.sys was found in '{vgkInDrivers}'. " +
                                   "Legitimate Riot Vanguard installs the driver to 'C:\\Program Files\\Riot Vanguard\\'. " +
                                   "A copy in System32\\drivers may be a bypass stub or driver manipulation artifact.",
                        Detail   = $"Path: {vgkInDrivers} | Size: {fi2.Length} bytes | LastWrite: {fi2.LastWriteTimeUtc:O}"
                    });
                }
                catch (IOException) { }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: known bypass registry keys (SOFTWARE\Vanguard_bypass etc.)
    // -----------------------------------------------------------------------
    private Task CheckBypassRegistryKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            foreach (var regPath in BypassRegistryPaths)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false)
                                 ?? Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                    if (key is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Vanguard Bypass Registry Key: {Path.GetFileName(regPath)}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{regPath}",
                        Reason   = $"Registry key '{regPath}' associated with a Vanguard bypass tool was found. " +
                                   "This is typically an installation artifact left by a bypass tool installer. " +
                                   "Such tools register themselves to persist configuration and load on startup.",
                        Detail   = $"Key: HKLM\\{regPath} (or HKCU\\{regPath})"
                    });
                }
                catch { }
            }

            // Also scan all HKLM\SOFTWARE sub-keys for bypass-related names
            try
            {
                using var softwareKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE", writable: false);
                if (softwareKey is not null)
                {
                    foreach (var sub in softwareKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        bool match = BypassFileKeywords.Any(k =>
                            sub.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (!match) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Suspicious Vanguard-Related Registry Key: {sub}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\SOFTWARE\{sub}",
                            Reason   = $"Registry key 'HKLM\\SOFTWARE\\{sub}' contains a keyword pattern " +
                                       "associated with Vanguard bypass tools. This key may be a configuration " +
                                       "or installation remnant of an anti-cheat bypass tool.",
                            Detail   = $"Key name: {sub}"
                        });
                    }
                }
            }
            catch { }

            // Scan HKCU\SOFTWARE as well
            try
            {
                using var hkcuSoftware = Registry.CurrentUser.OpenSubKey(@"SOFTWARE", writable: false);
                if (hkcuSoftware is not null)
                {
                    foreach (var sub in hkcuSoftware.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        bool match = BypassFileKeywords.Any(k =>
                            sub.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (!match) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Suspicious Vanguard Bypass Key (HKCU): {sub}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\SOFTWARE\{sub}",
                            Reason   = $"Registry key 'HKCU\\SOFTWARE\\{sub}' contains a Vanguard bypass keyword. " +
                                       "Per-user bypass tool installations create keys under HKCU to store " +
                                       "their configuration and bypass settings.",
                            Detail   = $"Key name: {sub}"
                        });
                    }
                }
            }
            catch { }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: config files / text files with bypass keywords
    // -----------------------------------------------------------------------
    private Task CheckBypassConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var configExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".cfg", ".config", ".ini", ".json", ".txt", ".xml", ".yaml", ".yml", ".toml", ".lua"
            };

            foreach (var root in ScanRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;

                    var ext = Path.GetExtension(file);
                    if (!configExtensions.Contains(ext)) continue;

                    var fn = Path.GetFileName(file);
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var hitKeyword = BypassConfigKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (hitKeyword is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Vanguard Bypass Config Keyword: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Configuration file '{fn}' contains the keyword '{hitKeyword}' which is " +
                                   "associated with Vanguard anti-cheat bypass activity. Config files are used " +
                                   "by bypass tools to store settings, target service names, and bypass modes.",
                        Detail   = $"File: {file} | Keyword: '{hitKeyword}'"
                    });
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: UserAssist ROT13-decoded execution records of bypass tools
    // -----------------------------------------------------------------------
    private Task CheckUserAssistBypass(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

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

                            var decoded = Rot13(encodedName);

                            var hit = UserAssistBypassKeywords.FirstOrDefault(k =>
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
                                    var fileTime = BitConverter.ToInt64(data, 8);
                                    if (fileTime > 0)
                                        lastRun = DateTime.FromFileTimeUtc(fileTime);
                                }
                            }
                            catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"UserAssist: Vanguard Bypass Executed: {Path.GetFileName(decoded)}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason   = $"Windows UserAssist records (ROT13-decoded) show execution of " +
                                           $"'{Path.GetFileName(decoded)}' which matches Vanguard bypass keyword '{hit}'. " +
                                           $"Executed {runCount} time(s)" +
                                           (lastRun.HasValue ? $", last run {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                           ". UserAssist entries persist even after the file is deleted, " +
                                           "providing forensic evidence of prior bypass tool execution.",
                                Detail   = $"Decoded: {decoded} | Runs: {runCount} | " +
                                           $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")} | " +
                                           $"Keyword: {hit}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: MUICache execution records of bypass tools
    // -----------------------------------------------------------------------
    private Task CheckMuiCacheBypass(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

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

                    // Strip the .FriendlyAppName / .ApplicationCompany suffix
                    var path   = valueName;
                    var dotIdx = valueName.LastIndexOf('.');
                    if (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                        path = valueName[..dotIdx];

                    var friendlyName = key.GetValue(valueName) as string ?? "";
                    var combined     = (path + " " + friendlyName).ToLowerInvariant();

                    var hit = UserAssistBypassKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    var fn     = Path.GetFileName(path);
                    bool exists = File.Exists(path);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"MUICache: Vanguard Bypass Executed: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKCU\{muiCacheKey}",
                        FileName = fn,
                        Reason   = $"Windows MUICache records that '{fn}' was executed on this system. " +
                                   $"The path/description matches Vanguard bypass keyword '{hit}'. " +
                                   (exists
                                       ? "File still present on disk."
                                       : "File has been deleted, but execution is forensically confirmed via MUICache.") +
                                   " MUICache persists execution records even after file deletion.",
                        Detail   = $"Path: {path} | Description: {friendlyName} | Keyword: {hit} | Exists: {exists}"
                    });
                }
            }
            catch { }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: IFEO hijacking of vgc.exe, vgk.exe, or Riot client executables
    // -----------------------------------------------------------------------
    private Task CheckIfeoVanguardHijack(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            const string ifeoKey =
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            const string ifeoWow64 =
                @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

            var vanguardTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "vgc.exe",
                "vgk.exe",
                "VALORANT.exe",
                "VALORANT-Win64-Shipping.exe",
                "RiotClientServices.exe",
                "RiotClientUx.exe",
                "RiotClientUxRender.exe",
                "LeagueClient.exe",
                "LeagueClientUx.exe",
                "RiotGamesHelper.exe",
                "vanguard_service.exe",
                "RiotClientCrashHandler.exe",
            };

            foreach (var hiveRoot in new[] { ifeoKey, ifeoWow64 })
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var root = Registry.LocalMachine.OpenSubKey(hiveRoot, writable: false);
                    if (root is null) continue;

                    foreach (var exeName in root.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        if (!vanguardTargets.Contains(exeName)) continue;

                        using var exeKey = root.OpenSubKey(exeName, writable: false);
                        if (exeKey is null) continue;

                        var debugger     = exeKey.GetValue("Debugger") as string ?? "";
                        var verifierDlls = exeKey.GetValue("VerifierDlls") as string ?? "";
                        var globalFlag   = exeKey.GetValue("GlobalFlag");

                        if (!string.IsNullOrWhiteSpace(debugger))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"IFEO Debugger Hijack of Vanguard Executable: {exeName}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{hiveRoot}\{exeName}",
                                FileName = exeName,
                                Reason   = $"Image File Execution Options (IFEO) debugger hijack detected for '{exeName}'. " +
                                           $"The Debugger value is set to: '{debugger}'. " +
                                           "IFEO hijacking of Vanguard executables is a known technique to redirect the " +
                                           "anti-cheat service to a stub or null binary, effectively killing Vanguard without " +
                                           "triggering its own self-protection mechanisms.",
                                Detail   = $"Exe: {exeName} | Debugger: {debugger} | VerifierDlls: {verifierDlls}"
                            });
                        }

                        if (!string.IsNullOrWhiteSpace(verifierDlls))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"IFEO VerifierDll Injection into Vanguard: {exeName}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{hiveRoot}\{exeName}",
                                FileName = exeName,
                                Reason   = $"IFEO VerifierDlls set for Vanguard executable '{exeName}': '{verifierDlls}'. " +
                                           "Application Verifier DLLs are injected into the target process at startup by " +
                                           "the kernel, bypassing standard injection guards. Injecting into Vanguard processes " +
                                           "can disable or subvert anti-cheat monitoring entirely.",
                                Detail   = $"Exe: {exeName} | VerifierDlls: {verifierDlls}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: running processes matching bypass tool names
    // -----------------------------------------------------------------------
    private Task CheckBypassProcesses(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            try
            {
                foreach (var proc in ctx.GetProcessSnapshot())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementProcesses();

                    string procName;
                    try { procName = proc.ProcessName; }
                    catch { continue; }

                    bool exactMatch   = BypassFileNames.Contains(procName + ".exe");
                    bool keywordMatch = !exactMatch && BypassFileKeywords.Any(k =>
                        procName.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!exactMatch && !keywordMatch) continue;

                    string? exePath = null;
                    try { exePath = proc.MainModule?.FileName; }
                    catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Vanguard Bypass Process Running: {procName}",
                        Risk     = RiskLevel.Critical,
                        Location = $"PID {proc.Id}",
                        FileName = procName + ".exe",
                        Reason   = $"A process named '{procName}' (PID {proc.Id}) is currently running and matches " +
                                   "a known Vanguard bypass tool name. Active bypass tools can disable, hook, or " +
                                   "neutralize the Vanguard anti-cheat system in real time, enabling cheats to " +
                                   "operate without detection in Valorant and other Riot games.",
                        Detail   = $"PID: {proc.Id} | Name: {procName} | Path: {exePath ?? "unknown"}"
                    });
                }
            }
            catch { }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: WFP (Windows Filtering Platform) filter deletion artifacts
    //            Bypass tools may delete WFP filters to remove Vanguard network monitoring
    // -----------------------------------------------------------------------
    private Task CheckWfpFilterArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            // Look for WFP bypass executables on disk
            var wfpBypassKeywords = new[]
            {
                "wfp_bypass", "wfp_delete", "filter_delete", "vanguard_filter",
                "riot_filter", "vgc_filter", "wfp_kill", "netfilter_bypass",
                "wfp_remove", "vgk_filter",
            };

            foreach (var root in ScanRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    bool match = wfpBypassKeywords.Any(k =>
                        fn.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (!match) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"WFP Filter Bypass Tool: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Executable '{fn}' matches WFP (Windows Filtering Platform) filter bypass tool " +
                                   "keyword patterns. WFP filter manipulation tools can remove Vanguard's network " +
                                   "monitoring rules, disable traffic inspection, or unblock cheat communication channels.",
                        Detail   = $"Path: {file}"
                    });
                }
            }

            // Check for BFE (Base Filter Engine) policy key presence
            try
            {
                const string wfpPolicies =
                    @"SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent";
                using var wfpKey = Registry.LocalMachine.OpenSubKey(wfpPolicies, writable: false);
                ctx.IncrementRegistryKeys();
                if (wfpKey is null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "WFP Base Filter Engine Policy Key Missing",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{wfpPolicies}",
                        Reason   = "The Windows Filtering Platform (WFP) Base Filter Engine persistent policy " +
                                   "registry key is missing. Vanguard uses WFP callout filters for network monitoring. " +
                                   "Deletion of WFP policy keys is a technique used by some bypass tools to remove " +
                                   "anti-cheat network inspection rules.",
                        Detail   = $"Missing key: HKLM\\{wfpPolicies}"
                    });
                }
            }
            catch { }

            // Check if the BFE service itself has been disabled
            try
            {
                const string bfePath = @"SYSTEM\CurrentControlSet\Services\BFE";
                using var bfeKey = Registry.LocalMachine.OpenSubKey(bfePath, writable: false);
                ctx.IncrementRegistryKeys();
                if (bfeKey is not null)
                {
                    var startVal = bfeKey.GetValue("Start");
                    int startInt = startVal is int sv ? sv : -1;
                    if (startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Windows Base Filter Engine (BFE) Disabled",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{bfePath}",
                            Reason   = "The Windows Base Filter Engine (BFE) service has been disabled (Start=4). " +
                                       "Disabling BFE removes all WFP-based network filtering, which includes Vanguard's " +
                                       "network monitoring layer. Some bypass tools disable BFE to eliminate Riot's " +
                                       "anti-cheat network inspection capabilities.",
                            Detail   = $"Service: BFE | Start: {startInt} (DISABLED)"
                        });
                    }
                }
            }
            catch { }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: Vanguard run/autostart key tampering and scheduled task bypass
    // -----------------------------------------------------------------------
    private Task CheckVanguardRunKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var runKeyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            };

            foreach (var runPath in runKeyPaths)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                    {
                        using var runKey = hive.OpenSubKey(runPath, writable: false);
                        if (runKey is null) continue;

                        foreach (var valueName in runKey.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementRegistryKeys();

                            var value = runKey.GetValue(valueName) as string ?? "";

                            // Check if any run entries reference bypass tools
                            bool isBypass = BypassFileKeywords.Any(k =>
                                valueName.Contains(k, StringComparison.OrdinalIgnoreCase)
                                || value.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (isBypass)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Vanguard Bypass Autostart Entry: {valueName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM\{runPath}",
                                    FileName = Path.GetFileName(value.Split(' ')[0].Trim('"')),
                                    Reason   = $"Autostart registry entry '{valueName}' in '{runPath}' contains a " +
                                               "Vanguard bypass keyword in its name or value. This indicates a bypass " +
                                               "tool has registered itself to run automatically at startup, ensuring " +
                                               "Vanguard is disabled before the game launches.",
                                    Detail   = $"ValueName: {valueName} | Value: {value}"
                                });
                            }

                            // Check if Vanguard-labelled entries point to unexpected paths
                            bool isVanguardEntry =
                                valueName.Contains("vgc", StringComparison.OrdinalIgnoreCase)
                             || valueName.Contains("Riot", StringComparison.OrdinalIgnoreCase)
                             || valueName.Contains("Vanguard", StringComparison.OrdinalIgnoreCase);

                            if (isVanguardEntry && !isBypass && !string.IsNullOrWhiteSpace(value))
                            {
                                bool validVanguardPath =
                                    value.Contains("Riot Games", StringComparison.OrdinalIgnoreCase)
                                 || value.Contains("Riot Vanguard", StringComparison.OrdinalIgnoreCase)
                                 || value.Contains("RiotClient", StringComparison.OrdinalIgnoreCase);

                                if (!validVanguardPath)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module   = Name,
                                        Title    = $"Suspicious Vanguard Autostart Path: {valueName}",
                                        Risk     = RiskLevel.High,
                                        Location = $@"HKLM\{runPath}",
                                        FileName = Path.GetFileName(value.Split(' ')[0].Trim('"')),
                                        Reason   = $"Autostart entry '{valueName}' references Vanguard/Riot " +
                                                   $"but points to an unexpected path: '{value}'. " +
                                                   "Legitimate Vanguard autostart entries point to the Riot Games " +
                                                   "installation directory. An unexpected path may indicate a bypass " +
                                                   "tool has replaced or hijacked the Vanguard startup entry.",
                                        Detail   = $"ValueName: {valueName} | Value: {value}"
                                    });
                                }
                            }
                        }
                    }
                }
                catch { }
            }

            // Check scheduled tasks cache for bypass tool registrations
            const string tasksKeyPath =
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks";
            try
            {
                using var tasksKey = Registry.LocalMachine.OpenSubKey(tasksKeyPath, writable: false);
                if (tasksKey is not null)
                {
                    foreach (var taskGuid in tasksKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        try
                        {
                            using var taskKey = tasksKey.OpenSubKey(taskGuid, writable: false);
                            if (taskKey is null) continue;

                            var taskPath = taskKey.GetValue("Path") as string ?? "";
                            var uri      = taskKey.GetValue("URI") as string ?? "";
                            var combined = taskPath + " " + uri;

                            bool isBypass = BypassFileKeywords.Any(k =>
                                combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (!isBypass) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Vanguard Bypass Scheduled Task: {uri}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{tasksKeyPath}\{taskGuid}",
                                Reason   = $"Scheduled task '{uri}' (GUID: {taskGuid}) matches Vanguard bypass " +
                                           "keyword patterns. Bypass tools often register scheduled tasks to " +
                                           "disable Vanguard at login or before game launch.",
                                Detail   = $"Task GUID: {taskGuid} | URI: {uri} | Path: {taskPath}"
                            });
                        }
                        catch { }
                    }
                }
            }
            catch { }

            // Check for Riot Vanguard service deletion in the NT service database
            // (absence of vgc/vgk in services is flagged in CheckVanguardServiceRegistry;
            //  here we additionally check for stub/renamed service entries)
            try
            {
                const string servicesPath = @"SYSTEM\CurrentControlSet\Services";
                using var svcRoot = Registry.LocalMachine.OpenSubKey(servicesPath, writable: false);
                if (svcRoot is not null)
                {
                    foreach (var svcName in svcRoot.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        // Look for services that look like renamed or impersonating vgc/vgk
                        bool looksLikeVanguardSpoof =
                            (svcName.Contains("vgc", StringComparison.OrdinalIgnoreCase)
                          || svcName.Contains("vgk", StringComparison.OrdinalIgnoreCase)
                          || svcName.Contains("vanguard", StringComparison.OrdinalIgnoreCase))
                          && !svcName.Equals("vgc", StringComparison.OrdinalIgnoreCase)
                          && !svcName.Equals("vgk", StringComparison.OrdinalIgnoreCase);

                        if (!looksLikeVanguardSpoof) continue;

                        try
                        {
                            using var svcKey = svcRoot.OpenSubKey(svcName, writable: false);
                            if (svcKey is null) continue;

                            var imagePath = svcKey.GetValue("ImagePath") as string ?? "";
                            var typeVal   = svcKey.GetValue("Type") as int? ?? 0;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious Vanguard-Named Service: {svcName}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{servicesPath}\{svcName}",
                                FileName = Path.GetFileName(imagePath),
                                Reason   = $"A Windows service named '{svcName}' was found that impersonates or " +
                                           "references Vanguard service naming conventions but is not the legitimate " +
                                           "'vgc' or 'vgk' service. This may be a fake service registered by a " +
                                           "bypass tool to confuse monitoring or to intercept Vanguard's service calls.",
                                Detail   = $"ServiceName: {svcName} | Type: {typeVal} | ImagePath: {imagePath}"
                            });
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }, ct);
    }
}
