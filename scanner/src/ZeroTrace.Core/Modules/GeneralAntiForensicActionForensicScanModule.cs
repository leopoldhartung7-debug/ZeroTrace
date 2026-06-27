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

public sealed class GeneralAntiForensicActionForensicScanModule : IScanModule
{
    public string Name => "General Anti-Forensic Action Detection (Recycle Bin, Browser, Cookies, Steam, Discord)";
    public double Weight => 4.4;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckRecycleBinEmptied(ctx, ct),
            CheckBrowserHistoryCleared(ctx, ct),
            CheckBrowserCookiesCleared(ctx, ct),
            CheckBrowserCacheCleared(ctx, ct),
            CheckBrowserDownloadHistoryCleared(ctx, ct),
            CheckBrowserAutofillCleared(ctx, ct),
            CheckBrowserSessionCleared(ctx, ct),
            CheckExplorerRunMruCleared(ctx, ct),
            CheckExplorerTypedPathsCleared(ctx, ct),
            CheckSearchHistoryCleared(ctx, ct),
            CheckClipboardHistoryCleared(ctx, ct),
            CheckSteamDownloadCacheCleared(ctx, ct),
            CheckSteamLogsWiped(ctx, ct),
            CheckEpicGamesCacheCleared(ctx, ct),
            CheckRockstarCacheCleared(ctx, ct),
            CheckDiscordHistoryCleared(ctx, ct),
            CheckDiscordTokenCleared(ctx, ct),
            CheckScreenshotsDeleted(ctx, ct),
            CheckGameLauncherCachesWiped(ctx, ct),
            CheckStorageSenseAggressive(ctx, ct),
            CheckDiskCleanupRecentlyUsed(ctx, ct),
            CheckRecentDocsRegistryCleared(ctx, ct),
            CheckRunMruEmpty(ctx, ct),
            CheckTypedURLsEmpty(ctx, ct),
            CheckJumpListsEmpty(ctx, ct),
            CheckThumbcacheDeleted(ctx, ct),
            CheckIconCacheDeleted(ctx, ct),
            CheckSystemRestorePointsDeleted(ctx, ct),
            CheckShadowCopiesDeleted(ctx, ct),
            CheckLnkFilesDeleted(ctx, ct),
            CheckGameDvrFootageDeleted(ctx, ct)
        );
    }

    private Task CheckRecycleBinEmptied(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] drives = { "C:", "D:", "E:", "F:" };
            foreach (var drive in drives)
            {
                ct.ThrowIfCancellationRequested();
                string rb = Path.Combine(drive, "$Recycle.Bin");
                if (!Directory.Exists(rb)) continue;

                IEnumerable<string> sids;
                try { sids = Directory.EnumerateDirectories(rb); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var sid in sids)
                {
                    ct.ThrowIfCancellationRequested();
                    IEnumerable<string> items;
                    try { items = Directory.EnumerateFileSystemEntries(sid); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    int iCount = 0, rCount = 0;
                    foreach (var item in items)
                    {
                        string name = Path.GetFileName(item);
                        if (name.StartsWith("$I", StringComparison.OrdinalIgnoreCase)) iCount++;
                        if (name.StartsWith("$R", StringComparison.OrdinalIgnoreCase)) rCount++;
                    }

                    if (iCount == 0 && rCount == 0)
                    {
                        DateTime mod;
                        try { mod = Directory.GetLastWriteTimeUtc(sid); }
                        catch (IOException) { mod = DateTime.MinValue; }
                        catch (UnauthorizedAccessException) { mod = DateTime.MinValue; }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Recycle Bin Emptied",
                            Risk = RiskLevel.Medium,
                            Location = sid,
                            Reason = $"Recycle Bin folder for SID is empty (no $I/$R metadata) — last modified UTC {mod}.",
                            Detail = "User explicitly emptied the Recycle Bin — removes recently-deleted file recoverability.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckBrowserHistoryCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
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
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(p)) continue;
                ctx.IncrementFiles();

                long len;
                DateTime mod;
                try
                {
                    var info = new FileInfo(p);
                    len = info.Length;
                    mod = info.LastWriteTimeUtc;
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                if (len < 30000)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Browser History Cleared",
                        Risk = RiskLevel.High,
                        Location = p,
                        FileName = Path.GetFileName(p),
                        Reason = $"Browser History DB is only {len} bytes — last modified UTC {mod}.",
                        Detail = "Active browser maintains hundreds of KB of history minimum. User cleared browsing history.",
                    });
                }
            }
        }, ct);

    private Task CheckBrowserCookiesCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] paths =
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Network", "Cookies"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Network", "Cookies"),
                Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Network", "Cookies"),
            };

            foreach (var p in paths)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(p)) continue;
                ctx.IncrementFiles();

                long len;
                try
                {
                    len = new FileInfo(p).Length;
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                if (len < 10000)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Browser Cookies Cleared",
                        Risk = RiskLevel.High,
                        Location = p,
                        FileName = Path.GetFileName(p),
                        Reason = $"Cookies DB is only {len} bytes.",
                        Detail = "Cookie store wiped — anti-forensic step (removes login sessions / site tracking).",
                    });
                }
            }
        }, ct);

    private Task CheckBrowserCacheCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] paths =
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Cache"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Cache"),
                Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Cache"),
                Path.Combine(localAppData, "Mozilla", "Firefox", "Profiles"),
            };

            foreach (var p in paths)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(p)) continue;

                int files;
                try { files = Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories).Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (files < 5)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Browser Cache Cleared",
                        Risk = RiskLevel.High,
                        Location = p,
                        Reason = $"Browser cache folder contains only {files} files.",
                        Detail = "Browser cache wiped — destroys URL/image visit forensics.",
                    });
                }
            }
        }, ct);

    private Task CheckBrowserDownloadHistoryCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedURLs";
            RegistryKey? k;
            try { k = Registry.CurrentUser.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                int n = k.ValueCount;
                if (n == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Internet Explorer TypedURLs Empty",
                        Risk = RiskLevel.Medium,
                        Location = $"HKCU\\{p}",
                        Reason = "TypedURLs key has zero values.",
                        Detail = "All typed URLs were cleared.",
                    });
                }
            }
        }, ct);

    private Task CheckBrowserAutofillCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] paths =
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Web Data"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Web Data"),
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Login Data"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Login Data"),
            };

            foreach (var p in paths)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(p)) continue;
                ctx.IncrementFiles();

                long len;
                try { len = new FileInfo(p).Length; }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                if (len < 20000)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Browser Autofill / Login Cleared",
                        Risk = RiskLevel.Medium,
                        Location = p,
                        FileName = Path.GetFileName(p),
                        Reason = $"Autofill/Login DB is only {len} bytes.",
                        Detail = "Form data / saved passwords cleared.",
                    });
                }
            }
        }, ct);

    private Task CheckBrowserSessionCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] paths =
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Sessions"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Sessions"),
            };

            foreach (var p in paths)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(p)) continue;

                int files;
                try { files = Directory.EnumerateFiles(p, "*").Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (files == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Browser Session Files Empty",
                        Risk = RiskLevel.Medium,
                        Location = p,
                        Reason = "Sessions folder has no entries.",
                        Detail = "Open-tab session history wiped.",
                    });
                }
            }
        }, ct);

    private Task CheckExplorerRunMruCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
            RegistryKey? k;
            try { k = Registry.CurrentUser.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Win+R RunMRU Registry Removed",
                    Risk = RiskLevel.High,
                    Location = $"HKCU\\{p}",
                    Reason = "RunMRU key is gone.",
                    Detail = "Cleaner removed Run dialog history.",
                });
                return;
            }

            using (k)
            {
                ctx.IncrementRegistryKeys();
                if (k.ValueCount == 0 || k.ValueCount == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Win+R RunMRU Cleared",
                        Risk = RiskLevel.High,
                        Location = $"HKCU\\{p}",
                        Reason = $"RunMRU has only {k.ValueCount} values.",
                        Detail = "User cleared Run dialog history.",
                    });
                }
            }
        }, ct);

    private Task CheckExplorerTypedPathsCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";
            RegistryKey? k;
            try { k = Registry.CurrentUser.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                if (k.ValueCount == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Explorer TypedPaths Cleared",
                        Risk = RiskLevel.Medium,
                        Location = $"HKCU\\{p}",
                        Reason = "TypedPaths has no values.",
                        Detail = "Address bar history wiped.",
                    });
                }
            }
        }, ct);

    private Task CheckSearchHistoryCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] keys =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
                @"SOFTWARE\Microsoft\Search Assistant\ACMru\5603",
                @"SOFTWARE\Microsoft\Search Assistant\ACMru\5604",
            };

            foreach (var p in keys)
            {
                ct.ThrowIfCancellationRequested();
                RegistryKey? k;
                try { k = Registry.CurrentUser.OpenSubKey(p); }
                catch (System.Security.SecurityException) { continue; }
                catch (UnauthorizedAccessException) { continue; }
                if (k == null) continue;

                using (k)
                {
                    ctx.IncrementRegistryKeys();
                    if (k.ValueCount == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Search History Cleared",
                            Risk = RiskLevel.Medium,
                            Location = $"HKCU\\{p}",
                            Reason = "Search history MRU has no values.",
                            Detail = "User cleared file-search history.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckClipboardHistoryCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string p = Path.Combine(localAppData, "Microsoft", "Windows", "Clipboard");
            if (!Directory.Exists(p)) return;

            int files;
            try { files = Directory.EnumerateFileSystemEntries(p).Count(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            if (files == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Windows Clipboard History Cleared",
                    Risk = RiskLevel.Medium,
                    Location = p,
                    Reason = "Clipboard folder is empty.",
                    Detail = "Win+V clipboard history wiped.",
                });
            }
        }, ct);

    private Task CheckSteamDownloadCacheCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] candidates =
            {
                @"C:\Program Files (x86)\Steam\depotcache",
                @"C:\Program Files (x86)\Steam\appcache",
                @"D:\Steam\depotcache",
                @"D:\Steam\appcache",
            };

            foreach (var c in candidates)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(c)) continue;

                int files;
                try { files = Directory.EnumerateFileSystemEntries(c).Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (files == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Steam Cache Cleared",
                        Risk = RiskLevel.Medium,
                        Location = c,
                        Reason = "Steam depot/app cache is empty.",
                        Detail = "Steam manifest/depot cache wiped.",
                    });
                }
            }
        }, ct);

    private Task CheckSteamLogsWiped(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] candidates =
            {
                @"C:\Program Files (x86)\Steam\logs",
                @"D:\Steam\logs",
            };

            foreach (var c in candidates)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(c)) continue;

                int files;
                try { files = Directory.EnumerateFiles(c, "*").Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (files == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Steam Logs Wiped",
                        Risk = RiskLevel.High,
                        Location = c,
                        Reason = "Steam logs folder is empty.",
                        Detail = "Steam connection/install/console logs wiped — destroys VAC ban / game install evidence.",
                    });
                }
            }
        }, ct);

    private Task CheckEpicGamesCacheCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string p = Path.Combine(localAppData, "EpicGamesLauncher", "Saved", "Logs");
            if (!Directory.Exists(p)) return;

            int files;
            try { files = Directory.EnumerateFiles(p).Count(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            if (files == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Epic Games Launcher Logs Cleared",
                    Risk = RiskLevel.Medium,
                    Location = p,
                    Reason = "Epic Games log directory empty.",
                    Detail = "EAC + game install evidence wiped.",
                });
            }
        }, ct);

    private Task CheckRockstarCacheCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] paths =
            {
                Path.Combine(localAppData, "Rockstar Games", "Launcher"),
                Path.Combine(localAppData, "Rockstar Games", "Social Club"),
                Path.Combine(localAppData, "Rockstar Games", "GTA V"),
                Path.Combine(localAppData, "Rockstar Games", "Red Dead Redemption 2"),
            };

            foreach (var p in paths)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(p)) continue;

                int files;
                try { files = Directory.EnumerateFileSystemEntries(p, "*", SearchOption.TopDirectoryOnly).Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (files == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Rockstar Cache Cleared",
                        Risk = RiskLevel.High,
                        Location = p,
                        Reason = "Rockstar Games / Social Club folder is empty.",
                        Detail = "Rockstar account/session/log evidence wiped.",
                    });
                }
            }
        }, ct);

    private Task CheckDiscordHistoryCleared(ScanContext ctx, CancellationToken ct) =>
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
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(d)) continue;

                string leveldb = Path.Combine(d, "Local Storage", "leveldb");
                if (Directory.Exists(leveldb))
                {
                    int files;
                    try { files = Directory.EnumerateFiles(leveldb).Count(); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    if (files == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord LevelDB Wiped",
                            Risk = RiskLevel.High,
                            Location = leveldb,
                            Reason = "Discord LevelDB folder is empty.",
                            Detail = "User cleared Discord chat / settings / tokens cache.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckDiscordTokenCleared(ScanContext ctx, CancellationToken ct) =>
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

                string sessionStorage = Path.Combine(d, "sessions");
                if (Directory.Exists(sessionStorage))
                {
                    int files;
                    try { files = Directory.EnumerateFiles(sessionStorage).Count(); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    if (files == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Discord Session / Token Cleared",
                            Risk = RiskLevel.Medium,
                            Location = sessionStorage,
                            Reason = "Discord sessions folder empty.",
                            Detail = "Discord login token / sessions wiped — DM history may also be lost.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckScreenshotsDeleted(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(userProfile)) return;

            string[] screenshotDirs =
            {
                Path.Combine(userProfile, "Pictures", "Screenshots"),
                Path.Combine(userProfile, "Videos", "Captures"),
                Path.Combine(userProfile, "OneDrive", "Pictures", "Screenshots"),
            };

            foreach (var dir in screenshotDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;

                int files;
                try { files = Directory.EnumerateFiles(dir, "*").Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (files == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Screenshots / Captures Deleted",
                        Risk = RiskLevel.Medium,
                        Location = dir,
                        Reason = $"{Path.GetFileName(dir)} folder exists but is empty.",
                        Detail = "Screenshot/game-DVR capture evidence wiped.",
                    });
                }
            }
        }, ct);

    private Task CheckGameLauncherCachesWiped(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] paths =
            {
                Path.Combine(localAppData, "Battle.net"),
                Path.Combine(localAppData, "Riot Games"),
                Path.Combine(localAppData, "Origin"),
                Path.Combine(localAppData, "EA Desktop"),
                Path.Combine(localAppData, "Ubisoft Game Launcher"),
                Path.Combine(localAppData, "GOG.com"),
            };

            foreach (var p in paths)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(p)) continue;

                int files;
                try { files = Directory.EnumerateFileSystemEntries(p).Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (files == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Game Launcher Folder Empty",
                        Risk = RiskLevel.Medium,
                        Location = p,
                        Reason = $"{Path.GetFileName(p)} folder is empty.",
                        Detail = "Launcher cache/logs wiped — destroys game launch evidence.",
                    });
                }
            }
        }, ct);

    private Task CheckStorageSenseAggressive(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy";
            RegistryKey? k;
            try { k = Registry.CurrentUser.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? policy;
                try { policy = k.GetValue("01"); }
                catch (System.Security.SecurityException) { return; }

                if (policy is int p1 && p1 == 1)
                {
                    object? freq;
                    try { freq = k.GetValue("2048"); }
                    catch (System.Security.SecurityException) { freq = null; }

                    int f = freq is int fi ? fi : 0;
                    if (f == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Storage Sense ENABLED with DAILY cleanup",
                            Risk = RiskLevel.High,
                            Location = $"HKCU\\{p}",
                            Reason = "Storage Sense aggressive daily cleanup is active.",
                            Detail = "Auto-empties Recycle Bin / temp files daily — anti-forensic side effect.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckDiskCleanupRecentlyUsed(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                string[] subs;
                try { subs = k.GetSubKeyNames(); }
                catch (System.Security.SecurityException) { return; }

                int activeFlags = 0;
                foreach (var sub in subs)
                {
                    ct.ThrowIfCancellationRequested();
                    RegistryKey? sk;
                    try { sk = k.OpenSubKey(sub); }
                    catch (System.Security.SecurityException) { continue; }
                    if (sk == null) continue;

                    using (sk)
                    {
                        object? lastRun;
                        try { lastRun = sk.GetValue("LastAccess"); }
                        catch (System.Security.SecurityException) { lastRun = null; }
                        if (lastRun != null) activeFlags++;
                    }
                }

                if (activeFlags >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Disk Cleanup Recently Used",
                        Risk = RiskLevel.High,
                        Location = $"HKLM\\{p}",
                        Reason = $"{activeFlags} cleanmgr volume caches show recent activity.",
                        Detail = "cleanmgr.exe was run with multiple cleanup categories — broad trace wipe.",
                    });
                }
            }
        }, ct);

    private Task CheckRecentDocsRegistryCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";
            RegistryKey? k;
            try { k = Registry.CurrentUser.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "RecentDocs Registry Removed",
                    Risk = RiskLevel.High,
                    Location = $"HKCU\\{p}",
                    Reason = "RecentDocs key is missing.",
                    Detail = "Cleaner removed shell recent-files registry.",
                });
                return;
            }

            using (k)
            {
                ctx.IncrementRegistryKeys();
                if (k.SubKeyCount == 0 && k.ValueCount <= 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RecentDocs Registry Empty",
                        Risk = RiskLevel.High,
                        Location = $"HKCU\\{p}",
                        Reason = "RecentDocs key has no per-extension subkeys.",
                        Detail = "Per-file-type recent history wiped.",
                    });
                }
            }
        }, ct);

    private Task CheckRunMruEmpty(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
            RegistryKey? k;
            try { k = Registry.CurrentUser.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                if (k.ValueCount == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Win+R RunMRU Empty (Confirmed)",
                        Risk = RiskLevel.Medium,
                        Location = $"HKCU\\{p}",
                        Reason = "RunMRU has zero values.",
                        Detail = "Win+R Run-history wiped.",
                    });
                }
            }
        }, ct);

    private Task CheckTypedURLsEmpty(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Internet Explorer\TypedURLs";
            RegistryKey? k;
            try { k = Registry.CurrentUser.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                if (k.ValueCount == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "IE TypedURLs Empty",
                        Risk = RiskLevel.Low,
                        Location = $"HKCU\\{p}",
                        Reason = "TypedURLs key empty.",
                        Detail = "IE/Edge typed URL history wiped.",
                    });
                }
            }
        }, ct);

    private Task CheckJumpListsEmpty(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string[] dirs =
            {
                Path.Combine(appData, "Microsoft", "Windows", "Recent", "AutomaticDestinations"),
                Path.Combine(appData, "Microsoft", "Windows", "Recent", "CustomDestinations"),
            };

            foreach (var d in dirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(d)) continue;

                int files;
                try { files = Directory.EnumerateFiles(d).Count(); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                if (files == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Jump List Folder Empty",
                        Risk = RiskLevel.Medium,
                        Location = d,
                        Reason = $"{Path.GetFileName(d)} folder is empty.",
                        Detail = "Per-app recently-used file history wiped.",
                    });
                }
            }
        }, ct);

    private Task CheckThumbcacheDeleted(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string d = Path.Combine(localAppData, "Microsoft", "Windows", "Explorer");
            if (!Directory.Exists(d)) return;

            int tc;
            try { tc = Directory.EnumerateFiles(d, "thumbcache_*.db").Count(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            if (tc == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Thumbcache Files Missing",
                    Risk = RiskLevel.High,
                    Location = d,
                    Reason = "No thumbcache_*.db files exist.",
                    Detail = "Thumbcache normally retains thumbnails of viewed images — deletion = anti-forensic.",
                });
            }
        }, ct);

    private Task CheckIconCacheDeleted(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string d = Path.Combine(localAppData, "Microsoft", "Windows", "Explorer");
            if (!Directory.Exists(d)) return;

            int ic;
            try { ic = Directory.EnumerateFiles(d, "iconcache_*.db").Count(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            if (ic == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Iconcache Files Missing",
                    Risk = RiskLevel.Medium,
                    Location = d,
                    Reason = "No iconcache_*.db files exist.",
                    Detail = "Icon cache deleted (often accompanies thumbcache wipe).",
                });
            }
        }, ct);

    private Task CheckSystemRestorePointsDeleted(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string sr = @"C:\System Volume Information";
            if (!Directory.Exists(sr)) return;

            int entries;
            try { entries = Directory.EnumerateFileSystemEntries(sr).Count(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            if (entries == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "System Volume Information Empty",
                    Risk = RiskLevel.High,
                    Location = sr,
                    Reason = "SVI folder has no entries — restore points / shadow copies wiped.",
                    Detail = "Cleaner wiped all restore points and shadow copies.",
                });
            }
        }, ct);

    private Task CheckShadowCopiesDeleted(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SYSTEM\CurrentControlSet\Services\VSS";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? start;
                try { start = k.GetValue("Start"); }
                catch (System.Security.SecurityException) { return; }

                if (start is int s && s == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Volume Shadow Service DISABLED",
                        Risk = RiskLevel.High,
                        Location = $"HKLM\\{p}\\Start",
                        Reason = "VSS Start = 4 (Disabled).",
                        Detail = "Disabling VSS prevents shadow-copy-based forensic recovery.",
                    });
                }
            }
        }, ct);

    private Task CheckLnkFilesDeleted(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string recent = Path.Combine(appData, "Microsoft", "Windows", "Recent");
            if (!Directory.Exists(recent)) return;

            int lnks;
            try { lnks = Directory.EnumerateFiles(recent, "*.lnk").Count(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            if (lnks == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Recent .lnk Shortcuts All Deleted",
                    Risk = RiskLevel.High,
                    Location = recent,
                    Reason = "Recent folder has zero .lnk files.",
                    Detail = "Shortcut-based recently-opened evidence wiped.",
                });
            }
        }, ct);

    private Task CheckGameDvrFootageDeleted(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(userProfile)) return;

            string captures = Path.Combine(userProfile, "Videos", "Captures");
            if (!Directory.Exists(captures)) return;

            int files;
            try { files = Directory.EnumerateFiles(captures, "*", SearchOption.AllDirectories).Count(); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            if (files == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Xbox Game DVR Footage Deleted",
                    Risk = RiskLevel.Medium,
                    Location = captures,
                    Reason = "Game DVR captures folder is empty.",
                    Detail = "Game recordings wiped — destroys cheating-incident video evidence.",
                });
            }
        }, ct);
}
