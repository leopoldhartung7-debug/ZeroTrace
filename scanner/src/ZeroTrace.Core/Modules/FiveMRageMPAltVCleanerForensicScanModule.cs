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

public sealed class FiveMRageMPAltVCleanerForensicScanModule : IScanModule
{
    public string Name => "FiveM / RageMP / alt:V Cleaner & Trace-Wipe Forensic Scan";
    public double Weight => 4.3;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] CleanerExecutables =
    {
        "fivem-cleaner.exe", "fivemcleaner.exe", "fivem_cleaner.exe",
        "fivem-trace-cleaner.exe", "fivem_trace_cleaner.exe",
        "fivem-wiper.exe", "fivemwiper.exe", "fivem_wiper.exe",
        "fivem-spoofer.exe", "fivemspoofer.exe", "fivem_spoofer.exe",
        "fivem-uncleaner.exe", "fivem-unban.exe", "fivem_unban.exe",
        "fivem-hwid-cleaner.exe", "fivem_hwid_cleaner.exe",
        "fivem-hwid-spoofer.exe", "fivem_hwid_spoofer.exe",
        "fivem-cache-cleaner.exe", "fivem_cache_cleaner.exe",
        "fivem-log-cleaner.exe", "fivem_log_cleaner.exe",
        "fivem-license-cleaner.exe", "fivem_license_cleaner.exe",
        "fivem-license-changer.exe", "fivem_license_changer.exe",
        "fivem-license-spoofer.exe", "fivem_license_spoofer.exe",
        "fivem-discord-cleaner.exe", "fivem_discord_cleaner.exe",
        "fivem-rockstar-cleaner.exe", "fivem_rockstar_cleaner.exe",
        "fivem-socialclub-cleaner.exe", "fivem_socialclub_cleaner.exe",
        "ragemp-cleaner.exe", "ragempcleaner.exe", "ragemp_cleaner.exe",
        "ragemp-trace-cleaner.exe", "ragemp_trace_cleaner.exe",
        "ragemp-wiper.exe", "ragempwiper.exe", "ragemp_wiper.exe",
        "ragemp-spoofer.exe", "ragempspoofer.exe", "ragemp_spoofer.exe",
        "ragemp-uncleaner.exe", "ragemp-unban.exe", "ragemp_unban.exe",
        "ragemp-hwid-cleaner.exe", "ragemp_hwid_cleaner.exe",
        "ragemp-hwid-spoofer.exe", "ragemp_hwid_spoofer.exe",
        "ragemp-cache-cleaner.exe", "ragemp_cache_cleaner.exe",
        "ragemp-log-cleaner.exe", "ragemp_log_cleaner.exe",
        "ragemp-serial-cleaner.exe", "ragemp_serial_cleaner.exe",
        "ragemp-serial-spoofer.exe", "ragemp_serial_spoofer.exe",
        "ragemp-discord-cleaner.exe", "ragemp_discord_cleaner.exe",
        "ragemp-rockstar-cleaner.exe", "ragemp_rockstar_cleaner.exe",
        "ragemp-socialclub-cleaner.exe",
        "altv-cleaner.exe", "altvcleaner.exe", "altv_cleaner.exe",
        "altv-trace-cleaner.exe", "altv_trace_cleaner.exe",
        "altv-wiper.exe", "altvwiper.exe", "altv_wiper.exe",
        "altv-spoofer.exe", "altvspoofer.exe", "altv_spoofer.exe",
        "altv-uncleaner.exe", "altv-unban.exe", "altv_unban.exe",
        "altv-hwid-cleaner.exe", "altv_hwid_cleaner.exe",
        "altv-hwid-spoofer.exe", "altv_hwid_spoofer.exe",
        "altv-cache-cleaner.exe", "altv_cache_cleaner.exe",
        "altv-log-cleaner.exe", "altv_log_cleaner.exe",
        "altv-discord-cleaner.exe", "altv_discord_cleaner.exe",
        "altv-rockstar-cleaner.exe", "altv_rockstar_cleaner.exe",
        "altv-socialclub-cleaner.exe",
        "rockstar-cleaner.exe", "rockstarcleaner.exe", "rockstar_cleaner.exe",
        "rockstar-account-cleaner.exe", "rockstar_account_cleaner.exe",
        "socialclub-cleaner.exe", "socialclubcleaner.exe",
        "social-club-cleaner.exe", "social_club_cleaner.exe",
        "gta-cleaner.exe", "gtacleaner.exe", "gta_cleaner.exe",
        "gta5-cleaner.exe", "gta5cleaner.exe", "gta5_cleaner.exe",
        "discord-cleaner.exe", "discordcleaner.exe", "discord_cleaner.exe",
        "discord-token-cleaner.exe", "discord_token_cleaner.exe",
        "discord-account-cleaner.exe", "discord_account_cleaner.exe",
        "discord-cache-cleaner.exe", "discord_cache_cleaner.exe",
        "system-cleaner.exe", "systemcleaner.exe", "system_cleaner.exe",
        "trace-wiper.exe", "tracewiper.exe", "trace_wiper.exe",
        "evidence-wiper.exe", "evidencewiper.exe", "evidence_wiper.exe",
        "forensic-cleaner.exe", "forensiccleaner.exe", "forensic_cleaner.exe",
        "forensic-wiper.exe", "forensicwiper.exe", "forensic_wiper.exe",
        "log-cleaner.exe", "logcleaner.exe", "log_cleaner.exe",
        "cache-cleaner.exe", "cachecleaner.exe", "cache_cleaner.exe",
        "prefetch-cleaner.exe", "prefetchcleaner.exe", "prefetch_cleaner.exe",
        "userassist-cleaner.exe", "userassist_cleaner.exe",
        "amcache-cleaner.exe", "amcache_cleaner.exe",
        "shimcache-cleaner.exe", "shimcache_cleaner.exe",
        "bam-cleaner.exe", "bam_cleaner.exe",
        "mft-cleaner.exe", "mft_cleaner.exe",
        "usn-journal-cleaner.exe", "usn_journal_cleaner.exe",
        "event-log-cleaner.exe", "event_log_cleaner.exe",
        "registry-cleaner.exe", "registry_cleaner.exe", "regcleaner.exe",
        "hwid-spoofer.exe", "hwidspoofer.exe", "hwid_spoofer.exe",
        "hwid-changer.exe", "hwidchanger.exe", "hwid_changer.exe",
        "smbios-spoofer.exe", "smbiosspoofer.exe", "smbios_spoofer.exe",
        "mac-spoofer.exe", "macspoofer.exe", "mac_spoofer.exe",
        "uuid-spoofer.exe", "uuidspoofer.exe", "uuid_spoofer.exe",
        "tpm-spoofer.exe", "tpmspoofer.exe", "tpm_spoofer.exe",
        "disk-serial-spoofer.exe", "diskserialspoofer.exe",
        "disk_serial_spoofer.exe", "volume-id-spoofer.exe",
        "volumeidspoofer.exe", "volume_id_spoofer.exe",
        "cpu-id-spoofer.exe", "cpuidspoofer.exe", "cpu_id_spoofer.exe",
        "gpu-id-spoofer.exe", "gpuidspoofer.exe", "gpu_id_spoofer.exe",
    };

    private static readonly string[] CleanerDlls =
    {
        "fivem-cleaner.dll", "fivem_cleaner.dll", "fivem-wiper.dll",
        "fivem_wiper.dll", "fivem-spoofer.dll", "fivem_spoofer.dll",
        "fivem-hwid-cleaner.dll", "fivem_hwid_cleaner.dll",
        "fivem-hwid-spoofer.dll", "fivem_hwid_spoofer.dll",
        "ragemp-cleaner.dll", "ragemp_cleaner.dll", "ragemp-wiper.dll",
        "ragemp_wiper.dll", "ragemp-spoofer.dll", "ragemp_spoofer.dll",
        "ragemp-hwid-cleaner.dll", "ragemp_hwid_cleaner.dll",
        "altv-cleaner.dll", "altv_cleaner.dll", "altv-wiper.dll",
        "altv_wiper.dll", "altv-spoofer.dll", "altv_spoofer.dll",
        "altv-hwid-cleaner.dll", "altv_hwid_cleaner.dll",
        "discord-cleaner.dll", "discord_cleaner.dll",
        "trace-wiper.dll", "trace_wiper.dll", "evidence-wiper.dll",
        "evidence_wiper.dll", "forensic-cleaner.dll", "forensic_cleaner.dll",
        "log-cleaner.dll", "log_cleaner.dll", "cache-cleaner.dll",
        "cache_cleaner.dll", "prefetch-cleaner.dll", "prefetch_cleaner.dll",
        "userassist-cleaner.dll", "userassist_cleaner.dll",
        "amcache-cleaner.dll", "amcache_cleaner.dll",
        "shimcache-cleaner.dll", "shimcache_cleaner.dll",
        "bam-cleaner.dll", "bam_cleaner.dll", "mft-cleaner.dll",
        "mft_cleaner.dll", "usn-journal-cleaner.dll",
        "usn_journal_cleaner.dll", "event-log-cleaner.dll",
        "event_log_cleaner.dll", "hwid-spoofer.dll", "hwid_spoofer.dll",
        "smbios-spoofer.dll", "smbios_spoofer.dll", "mac-spoofer.dll",
        "mac_spoofer.dll", "uuid-spoofer.dll", "uuid_spoofer.dll",
        "tpm-spoofer.dll", "tpm_spoofer.dll", "disk-serial-spoofer.dll",
        "disk_serial_spoofer.dll", "volume-id-spoofer.dll",
        "volume_id_spoofer.dll", "cpu-id-spoofer.dll", "cpu_id_spoofer.dll",
        "gpu-id-spoofer.dll", "gpu_id_spoofer.dll",
    };

    private static readonly string[] CleanerLogKeywords =
    {
        "cleaner started", "cleaner completed", "cleaner success",
        "wipe started", "wipe completed", "wipe success",
        "trace wipe", "trace cleaned", "trace cleared",
        "forensic wipe", "forensic cleaned", "forensic cleared",
        "evidence wipe", "evidence cleaned", "evidence cleared",
        "fivem cache cleaned", "fivem logs cleaned", "fivem trace cleaned",
        "ragemp cache cleaned", "ragemp logs cleaned", "ragemp trace cleaned",
        "altv cache cleaned", "altv logs cleaned", "altv trace cleaned",
        "rockstar account cleaned", "social club cleaned",
        "discord token cleaned", "discord account cleaned",
        "discord cache cleaned", "prefetch cleared", "prefetch wiped",
        "userassist cleared", "userassist wiped", "userassist cleaned",
        "amcache cleared", "amcache wiped", "amcache cleaned",
        "shimcache cleared", "shimcache wiped", "shimcache cleaned",
        "bam cleared", "bam wiped", "bam cleaned",
        "mft cleared", "mft wiped", "mft cleaned",
        "usn journal cleared", "usn journal wiped",
        "event logs cleared", "event logs wiped", "event logs cleaned",
        "registry cleaned", "registry wiped", "registry cleared",
        "hwid spoofed", "hwid changed", "hwid randomized",
        "smbios spoofed", "smbios changed", "smbios randomized",
        "mac spoofed", "mac changed", "mac randomized",
        "uuid spoofed", "uuid changed", "uuid randomized",
        "tpm spoofed", "tpm changed", "tpm randomized",
        "disk serial spoofed", "disk serial changed", "disk serial randomized",
        "volume id spoofed", "volume id changed", "volume id randomized",
        "cpu id spoofed", "gpu id spoofed", "fingerprint cleaned",
        "fingerprint wiped", "fingerprint changed", "fingerprint spoofed",
        "ready for rejoin", "ready to reconnect", "ready to bypass",
        "ban evasion ready", "unban ready",
    };

    private static readonly string[] CleanerBrowserUrlPatterns =
    {
        "fivem-cleaner.com", "fivem-cleaner.cc", "fivem-cleaner.gg",
        "fivemcleaner.com", "fivemcleaner.cc", "fivemcleaner.gg",
        "ragemp-cleaner.com", "ragemp-cleaner.cc", "ragemp-cleaner.gg",
        "ragempcleaner.com", "ragempcleaner.cc", "ragempcleaner.gg",
        "altv-cleaner.com", "altv-cleaner.cc", "altv-cleaner.gg",
        "altvcleaner.com", "altvcleaner.cc",
        "hwid-spoofer.com", "hwid-spoofer.cc", "hwid-spoofer.gg",
        "hwidspoofer.com", "hwidspoofer.cc",
        "trace-cleaner.com", "trace-cleaner.cc", "trace-cleaner.gg",
        "tracecleaner.com", "tracecleaner.cc",
        "forensic-cleaner.com", "forensic-cleaner.cc",
        "discord-cleaner.com", "discord-cleaner.cc",
        "discordcleaner.com", "discordcleaner.cc",
        "spoofer.cc", "spoofer.gg", "spoofer.win", "spoofer.club",
        "unban.cc", "unban.gg", "unban.win",
        "cleaner.gg", "cleaner.cc", "cleaner.win",
    };

    private static readonly string[] CleanerRegistryKeyNames =
    {
        "FiveMCleaner", "FiveMWiper", "FiveMSpoofer",
        "FiveMHWIDCleaner", "FiveMHWIDSpoofer", "FiveMTraceCleaner",
        "RageMPCleaner", "RageMPWiper", "RageMPSpoofer",
        "RageMPHWIDCleaner", "RageMPHWIDSpoofer", "RageMPTraceCleaner",
        "AltVCleaner", "AltVWiper", "AltVSpoofer", "AltVHWIDCleaner",
        "AltVHWIDSpoofer", "AltVTraceCleaner", "DiscordCleaner",
        "DiscordTokenCleaner", "DiscordAccountCleaner",
        "RockstarCleaner", "RockstarAccountCleaner",
        "SocialClubCleaner", "GTA5Cleaner", "TraceWiper",
        "EvidenceWiper", "ForensicCleaner", "ForensicWiper",
        "PrefetchCleaner", "UserAssistCleaner", "AmcacheCleaner",
        "ShimcacheCleaner", "BAMCleaner", "MFTCleaner",
        "USNJournalCleaner", "EventLogCleaner", "RegistryCleaner",
        "HWIDSpoofer", "HWIDChanger", "SMBIOSSpoofer",
        "MACSpoofer", "UUIDSpoofer", "TPMSpoofer",
        "DiskSerialSpoofer", "VolumeIDSpoofer", "CPUIDSpoofer",
        "GPUIDSpoofer",
    };

    private static readonly string[] ArchivePatterns =
    {
        "fivem-cleaner", "fivem_cleaner", "fivem-wiper", "fivem_wiper",
        "fivem-spoofer", "fivem_spoofer", "fivem-hwid-cleaner",
        "fivem_hwid_cleaner", "fivem-trace-cleaner",
        "fivem_trace_cleaner", "ragemp-cleaner", "ragemp_cleaner",
        "ragemp-wiper", "ragemp_wiper", "ragemp-spoofer",
        "ragemp_spoofer", "ragemp-hwid-cleaner", "ragemp_hwid_cleaner",
        "ragemp-trace-cleaner", "ragemp_trace_cleaner",
        "altv-cleaner", "altv_cleaner", "altv-wiper", "altv_wiper",
        "altv-spoofer", "altv_spoofer", "altv-hwid-cleaner",
        "altv_hwid_cleaner", "altv-trace-cleaner", "altv_trace_cleaner",
        "discord-cleaner", "discord_cleaner", "discord-token-cleaner",
        "rockstar-cleaner", "rockstar_cleaner", "socialclub-cleaner",
        "trace-cleaner", "trace_cleaner", "trace-wiper",
        "evidence-wiper", "evidence_wiper", "forensic-cleaner",
        "forensic_cleaner", "forensic-wiper", "forensic_wiper",
        "prefetch-cleaner", "userassist-cleaner", "amcache-cleaner",
        "shimcache-cleaner", "bam-cleaner", "mft-cleaner",
        "usn-journal-cleaner", "event-log-cleaner",
        "hwid-spoofer", "hwid_spoofer", "smbios-spoofer",
        "mac-spoofer", "uuid-spoofer", "tpm-spoofer",
        "disk-serial-spoofer", "volume-id-spoofer", "cpu-id-spoofer",
        "gpu-id-spoofer",
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
            CheckEmptyForensicArtifactTimestamps(ctx, ct),
            CheckShortcuts(ctx, ct)
        );
    }

    private static IEnumerable<string> BuildSearchDirectories()
    {
        var dirs = new List<string>();
        string[] envVars = { "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "PUBLIC", "PROGRAMDATA" };

        foreach (var env in envVars)
        {
            var value = Environment.GetEnvironmentVariable(env);
            if (!string.IsNullOrEmpty(value)) dirs.Add(value);
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

                    string fileName = Path.GetFileName(file);
                    bool matched = CleanerExecutables.Any(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cleaner / Trace-Wipe Executable",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Filename matches known FiveM/RageMP/alt:V cleaner or spoofer tool: {fileName}",
                        Detail = "Cleaner / HWID-spoofer / trace-wiper presence indicates active ban evasion or forensic-evidence destruction workflow.",
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

                    string fileName = Path.GetFileName(file);
                    bool matched = CleanerDlls.Any(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cleaner / Trace-Wipe DLL",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Cleaner library matches known name: {fileName}",
                        Detail = "DLL associated with cleaner / HWID spoofer toolkit.",
                    });
                }
            }
        }, ct);

    private Task CheckLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var dirs = BuildSearchDirectories().ToList();
            string[] exts = { ".log", ".txt", ".json", ".cfg" };

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

                        foreach (var kw in CleanerLogKeywords)
                        {
                            if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cleaner Execution Log Trace",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Log/config contains cleaner execution pattern: '{kw}'",
                                Detail = "Log records that a cleaner has wiped traces / spoofed hardware identifiers.",
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

                foreach (var u in CleanerBrowserUrlPatterns)
                {
                    if (!content.Contains(u, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cleaner / Spoofer Domain in Browser History",
                        Risk = RiskLevel.High,
                        Location = p,
                        FileName = Path.GetFileName(p),
                        Reason = $"Browser visited cleaner/spoofer marketplace: '{u}'",
                        Detail = "Visit to a known cleaner / HWID spoofer distribution site.",
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

                            bool matched = CleanerRegistryKeyNames.Any(k =>
                                sub.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (!matched) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cleaner / Spoofer Registry Key",
                                Risk = RiskLevel.Critical,
                                Location = $"{hive.Name}\\{root}\\{sub}",
                                Reason = $"Registry key named after cleaner / spoofer tool: '{sub}'",
                                Detail = "Persistence/installer record for a cleaner or HWID spoofer.",
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
                            foreach (var exe in CleanerExecutables)
                            {
                                string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                                if (!decoded.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cleaner Execution Trace (UserAssist)",
                                    Risk = RiskLevel.Critical,
                                    Location = $"HKCU\\{root}\\{guid}\\Count\\{v}",
                                    FileName = decoded,
                                    Reason = $"UserAssist execution record for cleaner: '{exeBase}'",
                                    Detail = "Cleaner was launched interactively by the user on this machine.",
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
                    if (!ArchiveExtensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    string name = Path.GetFileName(file);
                    foreach (var pat in ArchivePatterns)
                    {
                        if (!name.Contains(pat, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cleaner / Spoofer Download Archive",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = name,
                            Reason = $"Archive named for cleaner / spoofer: '{pat}'",
                            Detail = "Archive contains cleaner or HWID spoofer distribution.",
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
                    foreach (var exe in CleanerExecutables)
                    {
                        string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                        if (!vlow.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cleaner in MuiCache",
                            Risk = RiskLevel.Critical,
                            Location = $"HKCU\\{mui}\\{v}",
                            Reason = $"MuiCache references cleaner: '{exeBase}'",
                            Detail = "Execution record for cleaner / spoofer binary.",
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
                foreach (var exe in CleanerExecutables)
                {
                    string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                    if (!fileName.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cleaner in Prefetch",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Prefetch records cleaner execution: '{exeBase}'",
                        Detail = "Prefetch confirms prior execution of cleaner / spoofer binary.",
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
                foreach (var exe in CleanerExecutables)
                {
                    string exeBase = Path.GetFileNameWithoutExtension(exe);
                    if (!name.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cleaner Recent Document Shortcut",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = name,
                        Reason = $"Recent shortcut targets cleaner name: '{exeBase}'",
                        Detail = "User recently interacted with a file named after a cleaner / spoofer.",
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

                    foreach (var u in CleanerBrowserUrlPatterns)
                    {
                        if (!content.Contains(u, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cleaner URL in Discord Cache",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Discord cache contains cleaner / spoofer URL: '{u}'",
                            Detail = "Cleaner / HWID spoofer link shared or received via Discord.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckEmptyForensicArtifactTimestamps(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string prefetch = @"C:\Windows\Prefetch";
            if (!Directory.Exists(prefetch)) return;

            string[] knownNeverEmpty =
            {
                "POWERSHELL.EXE", "CMD.EXE", "EXPLORER.EXE", "TASKMGR.EXE",
                "NOTEPAD.EXE", "SVCHOST.EXE",
            };

            int found = 0;
            foreach (var name in knownNeverEmpty)
            {
                ct.ThrowIfCancellationRequested();
                IEnumerable<string> matches;
                try { matches = Directory.EnumerateFiles(prefetch, name + "*.pf"); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }
                if (matches.Any()) found++;
            }

            if (found > 0) return;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Empty Prefetch Directory — Possible Cleaner Activity",
                Risk = RiskLevel.High,
                Location = prefetch,
                Reason = "Prefetch contains NO records for common processes (powershell, cmd, explorer, taskmgr, notepad, svchost).",
                Detail = "Prefetch is normally never empty for these. A fully cleared Prefetch is a classic cleaner artifact.",
            });
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
                    foreach (var exe in CleanerExecutables)
                    {
                        string exeBase = Path.GetFileNameWithoutExtension(exe);
                        if (!name.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cleaner Shortcut",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = name,
                            Reason = $"Shortcut matches cleaner name: '{exeBase}'",
                            Detail = "Desktop or Start Menu shortcut for a cleaner / spoofer application.",
                        });
                        break;
                    }
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
