using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CleanerResidueForensicScanModule : IScanModule
{
    public string Name => "Cleaner Residue & Anti-Forensic Tampering Detection";
    public double Weight => 4.4;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckPrefetchTampering(ctx, ct),
            CheckUserAssistTampering(ctx, ct),
            CheckAmCacheTampering(ctx, ct),
            CheckShimCacheTampering(ctx, ct),
            CheckBamTampering(ctx, ct),
            CheckEventLogTampering(ctx, ct),
            CheckUsnJournalDisabled(ctx, ct),
            CheckRecentDocsTampering(ctx, ct),
            CheckJumpListTampering(ctx, ct),
            CheckShellbagsTampering(ctx, ct),
            CheckRecycleBinForCleaning(ctx, ct),
            CheckTimestampAnomalies(ctx, ct),
            CheckCleanerLeftoverArtifacts(ctx, ct),
            CheckMuiCacheGapAnomalies(ctx, ct),
            CheckRegistryLastWriteAnomalies(ctx, ct),
            CheckFiveMRageMPAltVCacheWiped(ctx, ct),
            CheckDiscordCacheCleaned(ctx, ct),
            CheckBrowserHistoryWiped(ctx, ct)
        );
    }

    private Task CheckPrefetchTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string prefetch = @"C:\Windows\Prefetch";
            if (!Directory.Exists(prefetch)) return;

            int count;
            try { count = Directory.EnumerateFiles(prefetch, "*.pf").Count(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            if (count == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Prefetch Directory Empty — Cleaner Activity",
                    Risk = RiskLevel.Critical,
                    Location = prefetch,
                    Reason = "Prefetch contains zero .pf files — Windows always populates Prefetch.",
                    Detail = "Empty Prefetch is a hallmark of a trace cleaner wiping execution history.",
                });
                return;
            }

            if (count < 20)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Suspiciously Small Prefetch",
                    Risk = RiskLevel.High,
                    Location = prefetch,
                    Reason = $"Prefetch contains only {count} .pf entries — typical machines have hundreds.",
                    Detail = "Partial Prefetch wipe — cleaner likely ran but missed some entries.",
                });
            }

            string[] alwaysPresent =
            {
                "POWERSHELL.EXE", "CMD.EXE", "EXPLORER.EXE", "TASKMGR.EXE",
                "NOTEPAD.EXE", "SVCHOST.EXE", "WININIT.EXE", "DLLHOST.EXE",
                "RUNDLL32.EXE", "REGEDIT.EXE",
            };

            int missing = 0;
            foreach (var name in alwaysPresent)
            {
                ct.ThrowIfCancellationRequested();
                IEnumerable<string> matches;
                try { matches = Directory.EnumerateFiles(prefetch, name + "*.pf"); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }
                if (!matches.Any()) missing++;
            }

            if (missing >= 5)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Critical Prefetch Entries Missing",
                    Risk = RiskLevel.Critical,
                    Location = prefetch,
                    Reason = $"{missing} of 10 always-present Prefetch entries are missing (powershell, cmd, explorer, etc.).",
                    Detail = "These should never be absent on a normal machine — strong cleaner indicator.",
                });
            }
        }, ct);

    private Task CheckUserAssistTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string root = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
            RegistryKey? ua;
            try { ua = Registry.CurrentUser.OpenSubKey(root); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (ua == null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "UserAssist Registry Key Missing",
                    Risk = RiskLevel.Critical,
                    Location = $"HKCU\\{root}",
                    Reason = "UserAssist key entirely absent — Windows always populates this.",
                    Detail = "UserAssist tracks every interactive launch. Total absence = cleaner removed the key.",
                });
                return;
            }

            using (ua)
            {
                string[] guids;
                try { guids = ua.GetSubKeyNames(); }
                catch (System.Security.SecurityException) { return; }

                int totalValues = 0;
                foreach (var guid in guids)
                {
                    RegistryKey? count;
                    try { count = ua.OpenSubKey(guid + @"\Count"); }
                    catch (System.Security.SecurityException) { continue; }
                    if (count == null) continue;
                    using (count)
                    {
                        try { totalValues += count.GetValueNames().Length; }
                        catch (System.Security.SecurityException) { continue; }
                    }
                }
                ctx.IncrementRegistryKeys();

                if (totalValues == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "UserAssist Count Values All Empty",
                        Risk = RiskLevel.Critical,
                        Location = $"HKCU\\{root}",
                        Reason = "UserAssist GUIDs exist but all Count subkeys are empty.",
                        Detail = "Cleaner cleared the execution history while leaving the structure intact.",
                    });
                }
                else if (totalValues < 5)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Suspiciously Sparse UserAssist",
                        Risk = RiskLevel.High,
                        Location = $"HKCU\\{root}",
                        Reason = $"UserAssist contains only {totalValues} entries — a real machine has dozens to hundreds.",
                        Detail = "Selective wipe — cleaner removed execution traces.",
                    });
                }
            }
        }, ct);

    private Task CheckAmCacheTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string amcache = @"C:\Windows\AppCompat\Programs\Amcache.hve";
            if (!File.Exists(amcache))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "AMCache Hive Missing",
                    Risk = RiskLevel.Critical,
                    Location = amcache,
                    Reason = "Amcache.hve file is absent — Windows creates this automatically.",
                    Detail = "Total absence indicates deliberate deletion by cleaner.",
                });
                return;
            }
            ctx.IncrementFiles();

            try
            {
                var info = new FileInfo(amcache);
                if (info.Length < 4096)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "AMCache Hive Suspiciously Small",
                        Risk = RiskLevel.High,
                        Location = amcache,
                        Reason = $"Amcache.hve is only {info.Length} bytes — real hive is megabytes.",
                        Detail = "Cleaner truncated or replaced the AMCache.",
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckShimCacheTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string key = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
            RegistryKey? shimKey;
            try { shimKey = Registry.LocalMachine.OpenSubKey(key); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (shimKey == null) return;

            using (shimKey)
            {
                object? data;
                try { data = shimKey.GetValue("AppCompatCache"); }
                catch (System.Security.SecurityException) { return; }

                if (data == null || (data is byte[] b && b.Length < 1024))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ShimCache Cleared",
                        Risk = RiskLevel.Critical,
                        Location = $"HKLM\\{key}\\AppCompatCache",
                        Reason = "AppCompatCache value is missing or truncated.",
                        Detail = "Shim cache tracks every executed binary — cleared = forensic-evasion tool ran.",
                    });
                }
                ctx.IncrementRegistryKeys();
            }
        }, ct);

    private Task CheckBamTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string bam = @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
            RegistryKey? key;
            try { key = Registry.LocalMachine.OpenSubKey(bam); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (key == null) return;

            using (key)
            {
                string[] subs;
                try { subs = key.GetSubKeyNames(); }
                catch (System.Security.SecurityException) { return; }
                ctx.IncrementRegistryKeys();

                if (subs.Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "BAM (Background Activity Moderator) Empty",
                        Risk = RiskLevel.High,
                        Location = $"HKLM\\{bam}",
                        Reason = "BAM UserSettings has no SIDs — Windows always tracks at least the current user.",
                        Detail = "BAM tracks process execution per user — empty = cleaner wiped it.",
                    });
                }
            }
        }, ct);

    private Task CheckEventLogTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string logsDir = Path.Combine(Environment.SystemDirectory, "winevt", "Logs");
            if (!Directory.Exists(logsDir)) return;

            string[] criticalLogs =
            {
                "Security.evtx", "System.evtx", "Application.evtx",
                "Microsoft-Windows-PowerShell%4Operational.evtx",
                "Microsoft-Windows-Sysmon%4Operational.evtx",
            };

            foreach (var log in criticalLogs)
            {
                ct.ThrowIfCancellationRequested();
                string p = Path.Combine(logsDir, log);
                if (!File.Exists(p)) continue;
                ctx.IncrementFiles();

                try
                {
                    var info = new FileInfo(p);
                    if (info.Length < 70000)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Event Log Suspiciously Small",
                            Risk = RiskLevel.High,
                            Location = p,
                            FileName = log,
                            Reason = $"{log} is only {info.Length} bytes — likely cleared.",
                            Detail = "Event log truncated near the empty baseline (~68 KB) — common after wevtutil clear.",
                        });
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckUsnJournalDisabled(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string key = @"SYSTEM\CurrentControlSet\Control\FileSystem";
            RegistryKey? rk;
            try { rk = Registry.LocalMachine.OpenSubKey(key); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (rk == null) return;

            using (rk)
            {
                object? disable;
                try { disable = rk.GetValue("NtfsDisableUsnJournal"); }
                catch (System.Security.SecurityException) { return; }
                ctx.IncrementRegistryKeys();

                if (disable is int i && i == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "USN Journal Disabled",
                        Risk = RiskLevel.Critical,
                        Location = $"HKLM\\{key}\\NtfsDisableUsnJournal",
                        Reason = "NtfsDisableUsnJournal = 1.",
                        Detail = "USN journal tracks file changes for forensic recovery — disabling it kills change history.",
                    });
                }
            }
        }, ct);

    private Task CheckRecentDocsTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string recent = Path.Combine(appData, "Microsoft", "Windows", "Recent");
            if (!Directory.Exists(recent))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Recent Documents Folder Missing",
                    Risk = RiskLevel.High,
                    Location = recent,
                    Reason = "Recent folder is gone — Windows recreates this normally.",
                    Detail = "Cleaner removed the whole Recent folder.",
                });
                return;
            }

            int lnkCount;
            try { lnkCount = Directory.EnumerateFiles(recent, "*.lnk").Count(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            if (lnkCount == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Recent Documents Folder Empty",
                    Risk = RiskLevel.High,
                    Location = recent,
                    Reason = "Recent folder exists but contains no .lnk shortcuts.",
                    Detail = "All recent-document history was wiped.",
                });
            }
        }, ct);

    private Task CheckJumpListTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string auto = Path.Combine(appData, "Microsoft", "Windows", "Recent", "AutomaticDestinations");
            string custom = Path.Combine(appData, "Microsoft", "Windows", "Recent", "CustomDestinations");

            foreach (var dir in new[] { auto, custom })
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;

                int n;
                try { n = Directory.EnumerateFiles(dir).Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (n == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Jump List Folder Empty",
                        Risk = RiskLevel.High,
                        Location = dir,
                        Reason = $"{Path.GetFileName(dir)} contains no entries.",
                        Detail = "Jump lists record per-app file history — empty = cleaner wiped them.",
                    });
                }
            }
        }, ct);

    private Task CheckShellbagsTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] shellbagPaths =
            {
                @"SOFTWARE\Microsoft\Windows\Shell\BagMRU",
                @"SOFTWARE\Microsoft\Windows\Shell\Bags",
                @"SOFTWARE\Microsoft\Windows\ShellNoRoam\BagMRU",
            };

            foreach (var p in shellbagPaths)
            {
                ct.ThrowIfCancellationRequested();
                RegistryKey? key;
                try { key = Registry.CurrentUser.OpenSubKey(p); }
                catch (System.Security.SecurityException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                if (key == null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Shellbag Key Missing",
                        Risk = RiskLevel.Medium,
                        Location = $"HKCU\\{p}",
                        Reason = "Shellbag key absent — Explorer normally populates this.",
                        Detail = "Shellbags track folder access — absence = cleaner removed them.",
                    });
                    continue;
                }

                using (key)
                {
                    string[] subs;
                    try { subs = key.GetSubKeyNames(); }
                    catch (System.Security.SecurityException) { continue; }
                    ctx.IncrementRegistryKeys();

                    if (subs.Length == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Shellbag Key Empty",
                            Risk = RiskLevel.High,
                            Location = $"HKCU\\{p}",
                            Reason = "Shellbag key exists but has no subkeys.",
                            Detail = "Folder-access history wiped.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckRecycleBinForCleaning(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] drives = { "C:", "D:", "E:" };
            foreach (var drive in drives)
            {
                ct.ThrowIfCancellationRequested();
                string recyc = Path.Combine(drive, "$Recycle.Bin");
                if (!Directory.Exists(recyc)) continue;

                IEnumerable<string> sids;
                try { sids = Directory.EnumerateDirectories(recyc); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var sidDir in sids)
                {
                    ct.ThrowIfCancellationRequested();
                    IEnumerable<string> entries;
                    try { entries = Directory.EnumerateFileSystemEntries(sidDir); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    if (entries.Any()) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Recycle Bin User Folder Empty",
                        Risk = RiskLevel.Medium,
                        Location = sidDir,
                        Reason = "Recycle.Bin SID folder contains nothing — including no $I/$R metadata.",
                        Detail = "Recycle Bin emptied (full purge, not normal delete).",
                    });
                }
            }
        }, ct);

    private Task CheckTimestampAnomalies(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            var appData = Environment.GetEnvironmentVariable("APPDATA");

            var dirs = new List<string>();
            if (!string.IsNullOrEmpty(localAppData))
            {
                dirs.Add(Path.Combine(localAppData, "FiveM"));
                dirs.Add(Path.Combine(localAppData, "RAGEMP"));
                dirs.Add(Path.Combine(localAppData, "altv"));
            }
            if (!string.IsNullOrEmpty(appData))
            {
                dirs.Add(Path.Combine(appData, "CitizenFX"));
            }

            DateTime suspiciousEpoch = new(1601, 1, 1);
            DateTime futureCutoff = DateTime.UtcNow.AddYears(5);

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

                    DateTime created, modified;
                    try
                    {
                        created = File.GetCreationTimeUtc(file);
                        modified = File.GetLastWriteTimeUtc(file);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    bool zero = created <= suspiciousEpoch.AddDays(1);
                    bool future = created > futureCutoff || modified > futureCutoff;

                    if (zero || future)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Timestomped File",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = zero
                                ? "File creation timestamp is at NTFS epoch (1601-01-01) — clear timestomp."
                                : $"File timestamp is far in the future ({(created > futureCutoff ? created : modified)}).",
                            Detail = "Timestamp manipulation = cleaner/anti-forensic tool tampered with file metadata.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckCleanerLeftoverArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var temp = Environment.GetEnvironmentVariable("TEMP");
            if (string.IsNullOrEmpty(temp) || !Directory.Exists(temp)) return;

            string[] leftoverNames =
            {
                "cleaner.log", "wiper.log", "spoofer.log", "bypass.log",
                "cleanup.log", "cache_wipe.log", "trace_wipe.log",
                "cleaner_temp.tmp", "wiper_temp.tmp", "spoofer_temp.tmp",
                "cleaner_config.json", "wiper_config.json", "spoofer_config.json",
                "fivem_cleaner.log", "fivem_wiper.log", "fivem_spoofer.log",
                "ragemp_cleaner.log", "ragemp_wiper.log", "ragemp_spoofer.log",
                "altv_cleaner.log", "altv_wiper.log", "altv_spoofer.log",
                "hwid_spoof.log", "hwid_change.log", "mac_spoof.log",
                "smbios_spoof.log", "uuid_spoof.log", "disk_serial_spoof.log",
                "anti_forensic.log", "antiforensic.log",
                "scanner_bypass.log", "ocean_bypass.log", "detectac_bypass.log",
                "zerotrace_bypass.log",
            };

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(temp, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string name = Path.GetFileName(file);
                foreach (var leftover in leftoverNames)
                {
                    if (!name.Equals(leftover, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cleaner Leftover Artifact",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = name,
                        Reason = $"Temp file matches cleaner leftover name: {name}",
                        Detail = "Cleaner ran but failed to delete its own log/config — direct evidence of trace-wiping.",
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckMuiCacheGapAnomalies(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string mui = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
            RegistryKey? key;
            try { key = Registry.CurrentUser.OpenSubKey(mui); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (key == null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "MuiCache Key Missing",
                    Risk = RiskLevel.Critical,
                    Location = $"HKCU\\{mui}",
                    Reason = "MuiCache key absent — Windows populates this on every launch.",
                    Detail = "Cleaner removed the whole MuiCache.",
                });
                return;
            }

            using (key)
            {
                string[] vals;
                try { vals = key.GetValueNames(); }
                catch (System.Security.SecurityException) { return; }
                ctx.IncrementRegistryKeys();

                if (vals.Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "MuiCache Empty",
                        Risk = RiskLevel.Critical,
                        Location = $"HKCU\\{mui}",
                        Reason = "MuiCache key exists but contains zero values.",
                        Detail = "Application execution history wiped.",
                    });
                }
                else if (vals.Length < 10)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "MuiCache Suspiciously Sparse",
                        Risk = RiskLevel.High,
                        Location = $"HKCU\\{mui}",
                        Reason = $"MuiCache contains only {vals.Length} values — real machines have hundreds.",
                        Detail = "Likely a partial cleaner wipe.",
                    });
                }
            }
        }, ct);

    private Task CheckRegistryLastWriteAnomalies(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string ua = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
            RegistryKey? key;
            try { key = Registry.CurrentUser.OpenSubKey(ua); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (key == null) return;

            using (key)
            {
                ctx.IncrementRegistryKeys();
                if (key.SubKeyCount == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "UserAssist Subkey Count Zero",
                        Risk = RiskLevel.Critical,
                        Location = $"HKCU\\{ua}",
                        Reason = "UserAssist exists with zero subkeys — always has at least the GUIDs.",
                        Detail = "Aggressive cleaner deleted execution history.",
                    });
                }
            }
        }, ct);

    private Task CheckFiveMRageMPAltVCacheWiped(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] cachePaths =
            {
                Path.Combine(localAppData, "FiveM", "FiveM.app", "cache"),
                Path.Combine(localAppData, "FiveM", "FiveM.app", "logs"),
                Path.Combine(localAppData, "RAGEMP", "logs"),
                Path.Combine(localAppData, "RAGEMP", "client_resources"),
                Path.Combine(localAppData, "altv", "logs"),
                Path.Combine(localAppData, "altv", "cache"),
            };

            foreach (var cache in cachePaths)
            {
                ct.ThrowIfCancellationRequested();
                string parent = Directory.GetParent(cache)?.FullName ?? "";
                if (!Directory.Exists(parent)) continue;

                if (!Directory.Exists(cache))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Game Cache Directory Missing",
                        Risk = RiskLevel.High,
                        Location = cache,
                        Reason = $"Parent exists but the cache/log subdirectory '{Path.GetFileName(cache)}' is gone.",
                        Detail = "Cleaner removed game cache or log directory.",
                    });
                    continue;
                }

                int entries;
                try { entries = Directory.EnumerateFileSystemEntries(cache).Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (entries == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Game Cache Directory Empty",
                        Risk = RiskLevel.High,
                        Location = cache,
                        Reason = "Cache/log directory exists but is empty.",
                        Detail = "Contents wiped by cleaner — game has been launched and would normally populate this.",
                    });
                }
            }
        }, ct);

    private Task CheckDiscordCacheCleaned(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
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

                int n;
                try { n = Directory.EnumerateFiles(cache).Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (n == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Discord Cache Wiped",
                        Risk = RiskLevel.High,
                        Location = cache,
                        Reason = "Discord installed but Cache folder is empty.",
                        Detail = "Discord normally fills cache rapidly — empty = explicit wipe (cleaner / Discord-Cleaner tool).",
                    });
                }
            }
        }, ct);

    private Task CheckBrowserHistoryWiped(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] historyPaths =
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
                Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
            };

            foreach (var p in historyPaths)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(p)) continue;
                ctx.IncrementFiles();

                try
                {
                    var info = new FileInfo(p);
                    if (info.Length < 20000)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History Suspiciously Small",
                            Risk = RiskLevel.High,
                            Location = p,
                            FileName = Path.GetFileName(p),
                            Reason = $"Browser History database is only {info.Length} bytes — fresh-install baseline.",
                            Detail = "Browser used regularly should have history in the hundreds of KB minimum. Likely wiped.",
                        });
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
}
