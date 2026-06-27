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

public sealed class AntiForensicScannerEvasionScanModule : IScanModule
{
    public string Name => "Anti-Forensic Scanner Evasion Detection (ZeroTrace/Ocean/detect.ac Bypass)";
    public double Weight => 4.5;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] AntiScannerExecutables =
    {
        "zerotrace-bypass.exe", "zerotrace_bypass.exe", "zerotrace-cleaner.exe",
        "zerotrace_cleaner.exe", "zerotrace-evader.exe", "zerotrace_evader.exe",
        "zerotrace-spoofer.exe", "zerotrace_spoofer.exe",
        "anti-zerotrace.exe", "anti_zerotrace.exe", "antizerotrace.exe",
        "ocean-bypass.exe", "ocean_bypass.exe", "ocean-cleaner.exe",
        "ocean_cleaner.exe", "ocean-evader.exe", "ocean_evader.exe",
        "ocean-spoofer.exe", "ocean_spoofer.exe", "anti-ocean.exe",
        "anti_ocean.exe", "antiocean.exe", "ocean-killer.exe",
        "ocean_killer.exe", "detect-ac-bypass.exe", "detect_ac_bypass.exe",
        "detectac-bypass.exe", "detectac_bypass.exe", "detect-ac-cleaner.exe",
        "detect_ac_cleaner.exe", "detectac-cleaner.exe",
        "detectac_cleaner.exe", "anti-detect-ac.exe", "anti_detect_ac.exe",
        "antidetectac.exe", "anti-detectac.exe", "detect.ac-killer.exe",
        "detectac_killer.exe", "scanner-bypass.exe", "scanner_bypass.exe",
        "scannerbypass.exe", "scanner-cleaner.exe", "scanner_cleaner.exe",
        "scannercleaner.exe", "scanner-evader.exe", "scanner_evader.exe",
        "anti-scanner.exe", "anti_scanner.exe", "antiscanner.exe",
        "forensic-bypass.exe", "forensic_bypass.exe", "forensicbypass.exe",
        "forensic-cleaner.exe", "forensic_cleaner.exe",
        "forensiccleaner.exe", "forensic-evader.exe", "forensic_evader.exe",
        "forensicevader.exe", "anti-forensic.exe", "anti_forensic.exe",
        "antiforensic.exe", "antiforensics.exe",
        "fivem-forensic-bypass.exe", "fivem_forensic_bypass.exe",
        "ragemp-forensic-bypass.exe", "ragemp_forensic_bypass.exe",
        "altv-forensic-bypass.exe", "altv_forensic_bypass.exe",
        "uc-bypass.exe", "uc_bypass.exe", "ucbypass.exe",
        "uc-cleaner.exe", "uc_cleaner.exe", "uccleaner.exe",
        "unknown-cheats-bypass.exe", "unknown_cheats_bypass.exe",
        "unknowncheats-bypass.exe", "trace-eraser.exe", "trace_eraser.exe",
        "traceeraser.exe", "trace-killer.exe", "trace_killer.exe",
        "tracekiller.exe", "evidence-eraser.exe", "evidence_eraser.exe",
        "evidenceeraser.exe", "evidence-killer.exe", "evidence_killer.exe",
        "evidencekiller.exe", "memory-eraser.exe", "memory_eraser.exe",
        "memoryeraser.exe", "memory-wiper.exe", "memory_wiper.exe",
        "memorywiper.exe", "memory-cleaner.exe", "memory_cleaner.exe",
        "memorycleaner.exe", "secure-delete.exe", "secure_delete.exe",
        "securedelete.exe", "sdelete.exe", "sdelete64.exe",
        "ccleaner-portable.exe", "bleachbit.exe", "bleachbit-portable.exe",
        "privazer.exe", "privazerportable.exe", "wipe-bot.exe",
        "wipebot.exe", "wiper-bot.exe", "wiperbot.exe",
        "anti-detect.exe", "anti_detect.exe", "antidetect.exe",
        "stealth-eraser.exe", "stealth_eraser.exe", "stealtheraser.exe",
        "stealth-wiper.exe", "stealth_wiper.exe", "stealthwiper.exe",
        "ghost-eraser.exe", "ghost_eraser.exe", "ghosteraser.exe",
        "ghost-wiper.exe", "ghost_wiper.exe", "ghostwiper.exe",
        "phantom-eraser.exe", "phantom_eraser.exe", "phantomeraser.exe",
        "phantom-wiper.exe", "phantom_wiper.exe", "phantomwiper.exe",
        "shadow-eraser.exe", "shadow_eraser.exe", "shadoweraser.exe",
        "shadow-wiper.exe", "shadow_wiper.exe", "shadowwiper.exe",
        "zerotrack.exe", "zero-track.exe", "zero_track.exe",
        "nullify.exe", "nullifier.exe", "nullify-traces.exe",
        "nullify_traces.exe", "trace-nullify.exe", "trace_nullify.exe",
    };

    private static readonly string[] AntiScannerDlls =
    {
        "zerotrace-bypass.dll", "zerotrace_bypass.dll", "anti-zerotrace.dll",
        "anti_zerotrace.dll", "ocean-bypass.dll", "ocean_bypass.dll",
        "anti-ocean.dll", "anti_ocean.dll", "detect-ac-bypass.dll",
        "detect_ac_bypass.dll", "anti-detect-ac.dll", "anti_detect_ac.dll",
        "scanner-bypass.dll", "scanner_bypass.dll", "anti-scanner.dll",
        "anti_scanner.dll", "forensic-bypass.dll", "forensic_bypass.dll",
        "anti-forensic.dll", "anti_forensic.dll", "antiforensic.dll",
        "trace-eraser.dll", "trace_eraser.dll", "evidence-eraser.dll",
        "evidence_eraser.dll", "memory-eraser.dll", "memory_eraser.dll",
        "stealth-wiper.dll", "stealth_wiper.dll", "ghost-wiper.dll",
        "ghost_wiper.dll", "phantom-wiper.dll", "phantom_wiper.dll",
        "shadow-wiper.dll", "shadow_wiper.dll",
    };

    private static readonly string[] AntiScannerLogKeywords =
    {
        "zerotrace bypassed", "zerotrace evaded", "zerotrace cleaned",
        "zerotrace traces cleared", "anti-zerotrace success",
        "anti zerotrace success", "ocean bypassed", "ocean evaded",
        "ocean cleaned", "anti-ocean success", "anti ocean success",
        "detect.ac bypassed", "detect ac bypassed", "detectac bypassed",
        "detect.ac evaded", "detect ac evaded", "anti-detect.ac success",
        "anti detect ac success", "forensic scanner bypassed",
        "forensic scanner evaded", "forensic scanner cleaned",
        "anti-forensic scan complete", "anti forensic scan complete",
        "scanner evaded", "scanner bypassed", "scanner spoofed",
        "scanner detection cleared", "scanner traces wiped",
        "scanner traces cleared", "forensic traces wiped",
        "forensic evidence wiped", "forensic evidence cleared",
        "anti-detect ready", "anti detect ready", "cleaner v",
        "wiper v", "scanner bypass v", "loader bypass scanner",
        "cheat hidden from scanner", "cheat hidden from forensics",
        "ready for forensic scan", "ready for scanner test",
        "passes forensic scan", "passes ocean", "passes detect.ac",
        "passes zerotrace", "undetected by ocean", "undetected by detect.ac",
        "undetected by zerotrace", "undetected by forensic scanner",
        "udmemorywipe complete", "ud memory wipe complete",
        "ud cleaner complete", "ud bypass complete",
        "fud cleaner complete", "fud bypass complete", "fud loader",
        "fud bypass", "fud cleaner",
    };

    private static readonly string[] AntiScannerBrowserUrls =
    {
        "anti-zerotrace.com", "anti-zerotrace.cc", "anti-zerotrace.gg",
        "antizerotrace.com", "antizerotrace.cc",
        "anti-ocean.com", "anti-ocean.cc", "anti-ocean.gg",
        "antiocean.com", "antiocean.cc", "ocean-bypass.com",
        "ocean-bypass.cc", "oceanbypass.com", "oceanbypass.cc",
        "anti-detect-ac.com", "anti-detect-ac.cc", "anti-detect.ac",
        "antidetectac.com", "antidetectac.cc", "detect-ac-bypass.com",
        "detect-ac-bypass.cc", "detectacbypass.com",
        "anti-forensic.com", "anti-forensic.cc", "anti-forensic.gg",
        "antiforensic.com", "antiforensic.cc",
        "forensic-bypass.com", "forensic-bypass.cc",
        "forensicbypass.com", "forensicbypass.cc",
        "scanner-bypass.com", "scanner-bypass.cc", "scannerbypass.com",
        "scannerbypass.cc", "anti-scanner.com", "anti-scanner.cc",
        "antiscanner.com", "antiscanner.cc",
        "udcleaner.com", "udcleaner.cc", "ud-cleaner.com",
        "ud-cleaner.cc", "fudcleaner.com", "fudcleaner.cc",
        "fud-cleaner.com", "fud-cleaner.cc", "udbypass.com",
        "udbypass.cc", "fudbypass.com", "fudbypass.cc",
        "stealth-wiper.com", "stealth-wiper.cc", "ghost-wiper.com",
        "ghost-wiper.cc", "phantom-wiper.com", "phantom-wiper.cc",
        "shadow-wiper.com", "shadow-wiper.cc",
    };

    private static readonly string[] AntiScannerDiscordKeywords =
    {
        "bypass zerotrace", "bypass ocean", "bypass detect.ac",
        "bypass detectac", "evade zerotrace", "evade ocean",
        "evade detect.ac", "anti zerotrace", "anti ocean",
        "anti detect.ac", "anti detectac", "anti detect ac",
        "undetected by zerotrace", "undetected by ocean",
        "undetected by detect.ac", "undetected forensic scanner",
        "undetected ud bypass", "fud bypass scanner", "fud cleaner scanner",
        "ud bypass scanner", "ud cleaner scanner",
        "passes zerotrace", "passes ocean", "passes detect.ac",
        "clean zerotrace", "clean ocean", "clean detect.ac",
        "clean detectac", "wipe zerotrace traces", "wipe ocean traces",
        "wipe detect.ac traces", "fivem scanner bypass",
        "ragemp scanner bypass", "altv scanner bypass",
        "fivem scanner evader", "ragemp scanner evader",
        "altv scanner evader", "forensic tool bypass",
        "forensic tool evader", "forensic tool spoofer",
    };

    private static readonly string[] AntiScannerRegistryKeyNames =
    {
        "AntiZeroTrace", "ZeroTraceBypass", "ZeroTraceCleaner",
        "ZeroTraceEvader", "AntiOcean", "OceanBypass", "OceanCleaner",
        "OceanEvader", "AntiDetectAC", "DetectACBypass",
        "DetectACCleaner", "AntiDetectac", "DetectacBypass",
        "AntiScanner", "ScannerBypass", "ScannerCleaner",
        "ScannerEvader", "AntiForensic", "AntiForensics",
        "ForensicBypass", "ForensicCleaner", "ForensicEvader",
        "UDCleaner", "UDBypass", "FUDCleaner", "FUDBypass",
        "StealthWiper", "GhostWiper", "PhantomWiper", "ShadowWiper",
        "TraceEraser", "EvidenceEraser", "MemoryEraser",
        "ZeroTrack", "Nullify", "Nullifier", "TraceNullify",
    };

    private static readonly string[] ArchivePatterns =
    {
        "anti-zerotrace", "antizerotrace", "zerotrace-bypass",
        "zerotrace_bypass", "zerotrace-cleaner", "zerotrace_cleaner",
        "zerotrace-evader", "anti-ocean", "antiocean", "ocean-bypass",
        "ocean_bypass", "ocean-cleaner", "ocean_cleaner",
        "anti-detect-ac", "antidetectac", "detect-ac-bypass",
        "detect_ac_bypass", "detectac-bypass", "detectac-cleaner",
        "anti-scanner", "antiscanner", "scanner-bypass",
        "scanner_bypass", "scanner-cleaner", "scanner-evader",
        "anti-forensic", "antiforensic", "antiforensics",
        "forensic-bypass", "forensic_bypass", "forensic-cleaner",
        "forensic-evader", "ud-cleaner", "udcleaner", "ud-bypass",
        "udbypass", "fud-cleaner", "fudcleaner", "fud-bypass",
        "fudbypass", "stealth-wiper", "ghost-wiper", "phantom-wiper",
        "shadow-wiper", "trace-eraser", "evidence-eraser",
        "memory-eraser", "zero-track", "nullify",
    };

    private static readonly string[] ArchiveExtensions =
        { ".zip", ".rar", ".7z", ".gz", ".cab", ".tar", ".iso" };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckExecutables(ctx, ct),
            CheckDlls(ctx, ct),
            CheckLogFiles(ctx, ct),
            CheckBrowserHistory(ctx, ct),
            CheckRegistry(ctx, ct),
            CheckUserAssist(ctx, ct),
            CheckDownloadArchives(ctx, ct),
            CheckMuiCache(ctx, ct),
            CheckPrefetch(ctx, ct),
            CheckRecentDocuments(ctx, ct),
            CheckDiscordCache(ctx, ct),
            CheckSdeleteUsage(ctx, ct),
            CheckShortcuts(ctx, ct),
            CheckScheduledTasks(ctx, ct)
        );
    }

    private static IEnumerable<string> BuildSearchDirectories()
    {
        var dirs = new List<string>();
        string[] envVars = { "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "PUBLIC", "PROGRAMDATA" };

        foreach (var env in envVars)
        {
            var v = Environment.GetEnvironmentVariable(env);
            if (!string.IsNullOrEmpty(v)) dirs.Add(v);
        }

        var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
        if (!string.IsNullOrEmpty(userProfile))
        {
            dirs.Add(Path.Combine(userProfile, "Downloads"));
            dirs.Add(Path.Combine(userProfile, "Desktop"));
            dirs.Add(Path.Combine(userProfile, "Documents"));
        }

        return dirs.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private Task CheckExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in BuildSearchDirectories())
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string name = Path.GetFileName(file);
                    bool matched = AntiScannerExecutables.Any(n =>
                        name.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Forensic Scanner Evasion Tool",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = name,
                        Reason = $"Filename matches anti-forensic-scanner evasion tool: {name}",
                        Detail = "Tool designed specifically to evade ZeroTrace, Ocean, detect.ac, or similar forensic scanners — strong indicator of intentional anti-forensic activity.",
                    });
                }
            }
        }, ct);

    private Task CheckDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in BuildSearchDirectories())
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string name = Path.GetFileName(file);
                    bool matched = AntiScannerDlls.Any(n =>
                        name.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Scanner Evasion DLL",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = name,
                        Reason = $"DLL matches scanner-evasion library: {name}",
                        Detail = "Library used by anti-forensic evasion tooling.",
                    });
                }
            }
        }, ct);

    private Task CheckLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var dirs = BuildSearchDirectories().ToList();
            string[] exts = { ".log", ".txt", ".json", ".cfg", ".md" };

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                foreach (var ext in exts)
                {
                    IEnumerable<string> files;
                    try { files = Directory.EnumerateFiles(dir, "*" + ext, SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in files)
                    {
                        ct.ThrowIfCancellationRequested();
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

                        foreach (var kw in AntiScannerLogKeywords)
                        {
                            if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Anti-Forensic Scanner Activity Log",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Log contains anti-forensic-scanner activity: '{kw}'",
                                Detail = "Log entry shows a tool ran against a forensic scanner (ZeroTrace/Ocean/detect.ac) to wipe traces.",
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    private Task CheckBrowserHistory(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] paths =
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
                Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Vivaldi", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Opera Software", "Opera Stable", "History"),
            };

            foreach (var p in paths)
            {
                if (!File.Exists(p)) continue;
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var u in AntiScannerBrowserUrls)
                {
                    if (!content.Contains(u, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Scanner Domain in Browser History",
                        Risk = RiskLevel.High,
                        Location = p,
                        FileName = Path.GetFileName(p),
                        Reason = $"Browser visited anti-forensic-scanner marketplace: '{u}'",
                        Detail = "Visit to a domain offering bypass / cleaner against forensic scanners.",
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] rootPaths =
            {
                @"SOFTWARE", @"SOFTWARE\WOW6432Node",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            foreach (var root in rootPaths)
            {
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    ct.ThrowIfCancellationRequested();
                    RegistryKey? key;
                    try { key = hive.OpenSubKey(root); }
                    catch (System.Security.SecurityException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }
                    if (key == null) continue;

                    using (key)
                    {
                        string[] subs;
                        try { subs = key.GetSubKeyNames(); }
                        catch (System.Security.SecurityException) { continue; }

                        foreach (var sub in subs)
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            bool matched = AntiScannerRegistryKeyNames.Any(k =>
                                sub.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (!matched) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Anti-Forensic Tool Registry Key",
                                Risk = RiskLevel.Critical,
                                Location = $"{hive.Name}\\{root}\\{sub}",
                                Reason = $"Registry key named after anti-scanner tool: '{sub}'",
                                Detail = "Registry entry for tool that targets forensic scanners.",
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckUserAssist(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string root = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
            RegistryKey? ua;
            try { ua = Registry.CurrentUser.OpenSubKey(root); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (ua == null) return;

            using (ua)
            {
                string[] guids;
                try { guids = ua.GetSubKeyNames(); }
                catch (System.Security.SecurityException) { return; }

                foreach (var guid in guids)
                {
                    ct.ThrowIfCancellationRequested();
                    RegistryKey? count;
                    try { count = ua.OpenSubKey(guid + @"\Count"); }
                    catch (System.Security.SecurityException) { continue; }
                    if (count == null) continue;

                    using (count)
                    {
                        string[] vals;
                        try { vals = count.GetValueNames(); }
                        catch (System.Security.SecurityException) { continue; }

                        foreach (var v in vals)
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            string decoded = Rot13Decode(v).ToLowerInvariant();
                            foreach (var exe in AntiScannerExecutables)
                            {
                                string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                                if (!decoded.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Anti-Forensic Tool Execution (UserAssist)",
                                    Risk = RiskLevel.Critical,
                                    Location = $"HKCU\\{root}\\{guid}\\Count\\{v}",
                                    FileName = decoded,
                                    Reason = $"UserAssist execution record for anti-scanner tool: '{exeBase}'",
                                    Detail = "Anti-forensic tool was launched interactively by the user.",
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }, ct);

    private Task CheckDownloadArchives(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(userProfile)) return;

            string[] dirs =
            {
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "Documents"),
            };

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string ext = Path.GetExtension(file);
                    if (!ArchiveExtensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase))) continue;

                    string name = Path.GetFileName(file);
                    foreach (var pat in ArchivePatterns)
                    {
                        if (!name.Contains(pat, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Scanner Download Archive",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = name,
                            Reason = $"Archive named for anti-scanner tool: '{pat}'",
                            Detail = "Archive contains anti-forensic-scanner tool.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckMuiCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string mui = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
            RegistryKey? key;
            try { key = Registry.CurrentUser.OpenSubKey(mui); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (key == null) return;

            using (key)
            {
                string[] vals;
                try { vals = key.GetValueNames(); }
                catch (System.Security.SecurityException) { return; }

                foreach (var v in vals)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    string vlow = v.ToLowerInvariant();
                    foreach (var exe in AntiScannerExecutables)
                    {
                        string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                        if (!vlow.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Scanner in MuiCache",
                            Risk = RiskLevel.Critical,
                            Location = $"HKCU\\{mui}\\{v}",
                            Reason = $"MuiCache references anti-scanner: '{exeBase}'",
                            Detail = "Execution record for anti-forensic-scanner binary.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckPrefetch(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string prefetch = @"C:\Windows\Prefetch";
            if (!Directory.Exists(prefetch)) return;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(prefetch, "*.pf"); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string fileName = Path.GetFileName(file).ToLowerInvariant();
                foreach (var exe in AntiScannerExecutables)
                {
                    string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                    if (!fileName.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Scanner in Prefetch",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Prefetch records anti-scanner execution: '{exeBase}'",
                        Detail = "Prefetch confirms execution of anti-forensic-scanner binary.",
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckRecentDocuments(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string recent = Path.Combine(appData, "Microsoft", "Windows", "Recent");
            if (!Directory.Exists(recent)) return;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(recent, "*.lnk"); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string name = Path.GetFileName(file);
                foreach (var exe in AntiScannerExecutables)
                {
                    string exeBase = Path.GetFileNameWithoutExtension(exe);
                    if (!name.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Scanner Recent Document Shortcut",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = name,
                        Reason = $"Recent shortcut targets anti-scanner name: '{exeBase}'",
                        Detail = "User recently interacted with an anti-forensic-scanner file.",
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckDiscordCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string[] discords =
            {
                Path.Combine(appData, "discord"),
                Path.Combine(appData, "discordptb"),
                Path.Combine(appData, "discordcanary"),
            };

            foreach (var d in discords)
            {
                if (!Directory.Exists(d)) continue;
                ct.ThrowIfCancellationRequested();

                string cache = Path.Combine(d, "Cache");
                if (!Directory.Exists(cache)) continue;

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(cache, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
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

                    foreach (var kw in AntiScannerDiscordKeywords)
                    {
                        if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Scanner Discord Chat",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Discord cache contains anti-scanner chat: '{kw}'",
                            Detail = "User communicated about bypassing/evading forensic scanners.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckSdeleteUsage(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] sdeleteRegPaths =
            {
                @"SOFTWARE\Sysinternals\SDelete",
                @"SOFTWARE\WOW6432Node\Sysinternals\SDelete",
            };

            foreach (var p in sdeleteRegPaths)
            {
                ct.ThrowIfCancellationRequested();
                RegistryKey? key;
                try { key = Registry.CurrentUser.OpenSubKey(p); }
                catch (System.Security.SecurityException) { continue; }
                catch (UnauthorizedAccessException) { continue; }
                if (key == null) continue;

                using (key)
                {
                    object? eulaValue;
                    try { eulaValue = key.GetValue("EulaAccepted"); }
                    catch (System.Security.SecurityException) { continue; }

                    if (eulaValue != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Sysinternals SDelete EULA Accepted",
                            Risk = RiskLevel.High,
                            Location = $"HKCU\\{p}\\EulaAccepted",
                            Reason = "User accepted SDelete EULA — SDelete was launched at least once.",
                            Detail = "SDelete securely wipes files so forensic recovery is impossible — common pre-scan anti-forensic step.",
                        });
                    }
                    ctx.IncrementRegistryKeys();
                }
            }
        }, ct);

    private Task CheckShortcuts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(userProfile)) return;

            string[] dirs =
            {
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs"),
            };

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*.lnk", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string name = Path.GetFileName(file);
                    foreach (var exe in AntiScannerExecutables)
                    {
                        string exeBase = Path.GetFileNameWithoutExtension(exe);
                        if (!name.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Scanner Shortcut",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = name,
                            Reason = $"Shortcut matches anti-scanner name: '{exeBase}'",
                            Detail = "Desktop or Start Menu shortcut for an anti-forensic-scanner tool.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckScheduledTasks(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string tasks = @"C:\Windows\System32\Tasks";
            if (!Directory.Exists(tasks)) return;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(tasks, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string name = Path.GetFileName(file);
                foreach (var kw in AntiScannerRegistryKeyNames)
                {
                    if (!name.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Scanner Scheduled Task",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = name,
                        Reason = $"Scheduled task named after anti-scanner: '{kw}'",
                        Detail = "Task Scheduler entry with anti-forensic naming — likely automatic trace-wiping.",
                    });
                    break;
                }
            }
        }, ct);

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
