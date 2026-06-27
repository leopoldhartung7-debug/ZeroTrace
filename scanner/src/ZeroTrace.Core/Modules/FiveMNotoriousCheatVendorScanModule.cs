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

public sealed class FiveMNotoriousCheatVendorScanModule : IScanModule
{
    public string Name => "FiveM Notorious Cheat Vendor Forensic Scan";
    public double Weight => 4.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] CheatVendorBrands =
    {
        "redengine", "tzx", "tzxhook", "tzxcheats", "skript", "skript.gg",
        "skriptgg", "eulen", "eulen.cc", "eulencheats", "cherax",
        "cherax.lol", "cheraxcheats", "kiddions", "kiddionsmodest", "stand",
        "stand-gta", "standgta", "luna", "lunacheats", "lunadev",
        "luna-cheat", "phantom", "phantomcheats", "phantomoverlay",
        "midnight", "midnightcheats", "midnight-cheat", "fontaine",
        "fontainecheat", "fivemenu", "fivem-menu-cheat", "menyoo",
        "menyoofivem", "fivemcheats", "fivemcheats.com", "fivemhax",
        "fivem-hax", "fivem-cheat", "fivem-cheats", "fivemmodmenu",
        "fivem-mod-menu", "fivemhack", "fivem-hack", "fivem-spoofer",
        "fivem-cleaner", "rocket", "rocket-fivem", "supreme",
        "supreme-fivem", "neptune", "neptune-fivem", "neptunecheats",
        "xenon", "xenon-fivem", "xenoncheats", "predator", "predator-fivem",
        "predatorcheats", "fatality", "fatality-fivem", "fatalitycheats",
        "harmless", "harmless-fivem", "harmlesscheats", "perfectaim",
        "perfectaim-fivem", "perfectaimbot", "interium", "interium-fivem",
        "absolute", "absolute-fivem", "absolutecheats", "absoluteaim",
        "infinite", "infinite-fivem", "infinitecheats", "infinitewallhack",
        "private", "private-fivem", "privatecheats", "privatewallhack",
        "dopamine", "dopamine-fivem", "dopaminecheats", "venlo",
        "venlo-fivem", "venlocheats", "venlohack", "razer",
        "razer-fivem", "razercheats", "razerwallhack", "ghost",
        "ghost-fivem", "ghostcheats", "ghostwallhack",
    };

    private static readonly string[] CheatVendorFileNames =
    {
        "redengine.exe", "redengine_loader.exe", "redengine_launcher.exe",
        "tzx.exe", "tzxhook.exe", "tzxhook_loader.exe", "tzxcheats.exe",
        "skript.exe", "skript_gg.exe", "skript-gg.exe", "skript_loader.exe",
        "eulen.exe", "eulen_loader.exe", "eulen_launcher.exe",
        "eulencheats.exe", "cherax.exe", "cherax_launcher.exe",
        "cheraxlol.exe", "cherax_lol.exe", "kiddions.exe",
        "kiddions_modest.exe", "kiddionsmodest.exe", "stand.exe",
        "stand_launcher.exe", "stand-gta.exe", "luna.exe", "luna_loader.exe",
        "luna_launcher.exe", "lunacheats.exe", "luna-cheat.exe",
        "phantom.exe", "phantom_loader.exe", "phantomoverlay.exe",
        "phantom_overlay.exe", "phantomcheats.exe", "midnight.exe",
        "midnight_loader.exe", "midnightcheats.exe", "midnight-cheat.exe",
        "fontaine.exe", "fontaine_loader.exe", "fontainecheat.exe",
        "fivemenu.exe", "fivem-menu.exe", "menyoo.exe", "menyoofivem.exe",
        "fivemcheats.exe", "fivemhax.exe", "fivem-cheat.exe",
        "fivem-cheats.exe", "fivemmodmenu.exe", "fivem-mod-menu.exe",
        "fivemhack.exe", "fivem-hack.exe", "fivem-spoofer.exe",
        "fivem-cleaner.exe", "rocket.exe", "rocket-fivem.exe",
        "supreme.exe", "supreme-fivem.exe", "neptune.exe",
        "neptune-fivem.exe", "neptunecheats.exe", "xenon.exe",
        "xenon-fivem.exe", "xenoncheats.exe", "predator.exe",
        "predator-fivem.exe", "predatorcheats.exe", "fatality.exe",
        "fatality-fivem.exe", "fatalitycheats.exe", "harmless.exe",
        "harmless-fivem.exe", "harmlesscheats.exe", "perfectaim.exe",
        "perfectaim-fivem.exe", "perfectaimbot.exe", "interium.exe",
        "interium-fivem.exe", "absolute.exe", "absolute-fivem.exe",
        "absolutecheats.exe", "absoluteaim.exe", "infinite.exe",
        "infinite-fivem.exe", "infinitecheats.exe", "infinitewallhack.exe",
        "private.exe", "private-fivem.exe", "privatecheats.exe",
        "privatewallhack.exe", "dopamine.exe", "dopamine-fivem.exe",
        "dopaminecheats.exe", "venlo.exe", "venlo-fivem.exe",
        "venlocheats.exe", "razer.exe", "razer-fivem.exe", "razercheats.exe",
        "ghost.exe", "ghost-fivem.exe", "ghostcheats.exe",
        "ghostwallhack.exe",
    };

    private static readonly string[] CheatVendorDlls =
    {
        "redengine.dll", "redengine_inject.dll", "redengine_hook.dll",
        "tzx.dll", "tzxhook.dll", "tzx_inject.dll", "tzx_hook.dll",
        "skript.dll", "skript_gg.dll", "skript_inject.dll",
        "eulen.dll", "eulen_inject.dll", "eulen_hook.dll",
        "cherax.dll", "cherax_inject.dll", "cherax_hook.dll",
        "kiddions.dll", "kiddions_inject.dll", "kiddions_hook.dll",
        "stand.dll", "stand_inject.dll", "stand_hook.dll",
        "luna.dll", "luna_inject.dll", "luna_hook.dll",
        "phantom.dll", "phantom_inject.dll", "phantom_hook.dll",
        "midnight.dll", "midnight_inject.dll", "midnight_hook.dll",
        "fontaine.dll", "fontaine_inject.dll", "fontaine_hook.dll",
        "fivemenu.dll", "fivem-menu.dll", "menyoo.dll",
        "fivemcheats.dll", "fivemhax.dll", "fivem-cheat.dll",
        "fivemhack.dll", "fivem-hack.dll", "fivem-spoofer.dll",
        "rocket.dll", "supreme.dll", "neptune.dll", "xenon.dll",
        "predator.dll", "fatality.dll", "harmless.dll",
        "perfectaim.dll", "interium.dll", "absolute.dll",
        "infinite.dll", "private.dll", "dopamine.dll", "venlo.dll",
        "razer.dll", "ghost.dll",
    };

    private static readonly string[] CheatVendorLogKeywords =
    {
        "redengine detected", "tzx detected", "tzxhook detected",
        "skript.gg detected", "eulen detected", "cherax detected",
        "kiddions detected", "stand detected", "luna cheat detected",
        "phantom overlay detected", "midnight cheat detected",
        "fontaine detected", "menyoo detected", "fivemcheats detected",
        "fivem mod menu detected", "fivem hack detected",
        "fivem spoofer detected", "rocket cheat detected",
        "supreme cheat detected", "neptune cheat detected",
        "xenon cheat detected", "predator cheat detected",
        "fatality cheat detected", "harmless detected",
        "perfectaim detected", "interium detected", "absolute cheat detected",
        "infinite cheat detected", "private cheat detected",
        "dopamine cheat detected", "venlo cheat detected",
        "razer cheat detected", "ghost cheat detected",
        "loader.gg detected", "cheat.gg detected", "loader detected",
        "loader process injected", "external cheat loader",
        "fivem cheat marketplace", "fivem cheat vendor",
    };

    private static readonly string[] CheatVendorBrowserUrlPatterns =
    {
        "skript.gg", "eulen.cc", "cherax.lol", "kiddions.com",
        "stand-gta.com", "luna-cheat.com", "phantomoverlay.com",
        "fivemcheats.com", "fivemhax.com", "fivem-cheat.com",
        "fivem-cheats.com", "fivemmodmenu.com", "fivem-mod-menu.com",
        "fivemhack.com", "fivem-hack.com", "redengine.cc",
        "redengine.gg", "tzxhook.com", "tzxhook.cc", "fontaine.cc",
        "rocket-cheat.com", "supreme-cheat.com", "neptune-cheat.com",
        "xenon-cheat.com", "predator-cheat.com", "fatality.cc",
        "fatality.win", "perfectaim.cc", "interium.cc", "absolute.cc",
        "infinite-cheat.cc", "private-cheat.cc", "dopamine.cc",
        "venlo.cc", "razer-cheat.cc", "ghost-cheat.cc",
        "fivem-spoofer.com", "fivem-cleaner.com", "cheat.gg",
        "loader.gg", "cheat-marketplace.com",
    };

    private static readonly string[] CheatVendorRegistryKeyNames =
    {
        "RedEngine", "TZX", "TZXHook", "Skript", "SkriptGG", "Eulen",
        "Cherax", "Kiddions", "Stand", "Luna", "LunaCheats", "Phantom",
        "PhantomOverlay", "Midnight", "MidnightCheats", "Fontaine",
        "Menyoo", "FiveMCheats", "FiveMHax", "FiveMHack", "FiveMSpoofer",
        "Rocket", "Supreme", "Neptune", "Xenon", "Predator", "Fatality",
        "Harmless", "PerfectAim", "Interium", "Absolute", "Infinite",
        "PrivateCheat", "Dopamine", "Venlo", "Razer", "GhostCheat",
    };

    private static readonly string[] ArchivePatterns =
    {
        "redengine", "tzxhook", "skript", "eulen", "cherax", "kiddions",
        "stand", "lunacheats", "phantomoverlay", "midnight", "fontaine",
        "menyoo", "fivemcheats", "fivemhax", "fivemmodmenu", "fivemhack",
        "rocket", "supreme", "neptune", "xenon", "predator", "fatality",
        "harmless", "perfectaim", "interium", "absolute", "infinite",
        "dopamine", "venlo", "razer", "ghost",
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
            CheckDownloads(ctx, ct),
            CheckMuiCache(ctx, ct),
            CheckPrefetch(ctx, ct),
            CheckRecentDocuments(ctx, ct),
            CheckDiscordCache(ctx, ct),
            CheckShortcuts(ctx, ct)
        );
    }

    private static IEnumerable<string> BuildSearchDirectories()
    {
        var dirs = new List<string>();
        string[] envVars =
        {
            "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE",
            "PUBLIC", "PROGRAMDATA",
        };

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
            dirs.Add(Path.Combine(userProfile, "Music"));
            dirs.Add(Path.Combine(userProfile, "Videos"));
        }

        var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        if (!string.IsNullOrEmpty(localAppData))
        {
            dirs.Add(Path.Combine(localAppData, "FiveM"));
            dirs.Add(Path.Combine(localAppData, "FiveM", "FiveM.app"));
        }

        var appData = Environment.GetEnvironmentVariable("APPDATA");
        if (!string.IsNullOrEmpty(appData))
        {
            dirs.Add(Path.Combine(appData, "CitizenFX"));
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
                try
                {
                    files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string fileName = Path.GetFileName(file);
                    bool matched = CheatVendorFileNames.Any(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));

                    if (!matched)
                    {
                        bool brandMatched = CheatVendorBrands.Any(b =>
                            fileName.Contains(b, StringComparison.OrdinalIgnoreCase));
                        if (!brandMatched) continue;
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Known FiveM Cheat Vendor Executable",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Executable filename matches a known FiveM cheat vendor brand: {fileName}",
                        Detail = "These vendor brands (RedEngine, TZX, Skript.gg, Eulen, Cherax, etc.) are documented FiveM cheat marketplaces.",
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
                try
                {
                    files = Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string fileName = Path.GetFileName(file);
                    bool matched = CheatVendorDlls.Any(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));

                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Known FiveM Cheat Vendor DLL",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"DLL filename matches known FiveM cheat vendor: {fileName}",
                        Detail = "Injection or hook DLL associated with documented FiveM cheat brand.",
                    });
                }
            }
        }, ct);

    private Task CheckLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            string[] logExts = { ".log", ".txt", ".json" };
            var logDirs = new List<string>();

            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (!string.IsNullOrEmpty(localAppData))
            {
                logDirs.Add(Path.Combine(localAppData, "FiveM"));
                logDirs.Add(Path.Combine(localAppData, "FiveM", "FiveM.app"));
                logDirs.Add(Path.Combine(localAppData, "FiveM", "FiveM.app", "logs"));
                logDirs.Add(Path.Combine(localAppData, "FiveM", "FiveM.app", "cache"));
            }

            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (!string.IsNullOrEmpty(appData))
            {
                logDirs.Add(Path.Combine(appData, "CitizenFX"));
            }

            foreach (var dir in logDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                foreach (var ext in logExts)
                {
                    IEnumerable<string> files;
                    try
                    {
                        files = Directory.EnumerateFiles(dir, "*" + ext, SearchOption.AllDirectories);
                    }
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

                        foreach (var pattern in CheatVendorLogKeywords)
                        {
                            if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Vendor Reference in FiveM Log",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"FiveM log/config contains cheat vendor reference: '{pattern}'",
                                Detail = "Logs that contain detection strings for known FiveM cheats indicate prior cheat activity on this machine.",
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

            string[] historyPaths =
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
                Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Vivaldi", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Opera Software", "Opera Stable", "History"),
            };

            foreach (var path in historyPaths)
            {
                if (!File.Exists(path)) continue;
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var urlPattern in CheatVendorBrowserUrlPatterns)
                {
                    if (!content.Contains(urlPattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Vendor Domain in Browser History",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = Path.GetFileName(path),
                        Reason = $"Browser history contains known FiveM cheat vendor URL pattern: '{urlPattern}'",
                        Detail = "User has visited a known FiveM cheat marketplace/vendor website.",
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();

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

                    RegistryKey? rootKey;
                    try { rootKey = hive.OpenSubKey(root); }
                    catch (System.Security.SecurityException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    if (rootKey == null) continue;
                    using (rootKey)
                    {
                        string[] subs;
                        try { subs = rootKey.GetSubKeyNames(); }
                        catch (System.Security.SecurityException) { continue; }

                        foreach (var sub in subs)
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            bool matched = CheatVendorRegistryKeyNames.Any(k =>
                                sub.Equals(k, StringComparison.OrdinalIgnoreCase) ||
                                sub.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (!matched) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Vendor Registry Key",
                                Risk = RiskLevel.High,
                                Location = $"{hive.Name}\\{root}\\{sub}",
                                Reason = $"Registry key named after known FiveM cheat vendor: '{sub}'",
                                Detail = "Registry persistence/installer record matching a documented cheat brand.",
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckUserAssist(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string userAssistRoot =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            RegistryKey? ua;
            try { ua = Registry.CurrentUser.OpenSubKey(userAssistRoot); }
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

                            string decoded = Rot13Decode(v);
                            string lower = decoded.ToLowerInvariant();

                            foreach (var brand in CheatVendorBrands)
                            {
                                if (!lower.Contains(brand, StringComparison.OrdinalIgnoreCase)) continue;

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM Cheat Vendor in UserAssist",
                                    Risk = RiskLevel.High,
                                    Location = $"HKCU\\{userAssistRoot}\\{guid}\\Count\\{v}",
                                    FileName = decoded,
                                    Reason = $"UserAssist execution record for known FiveM cheat brand: '{brand}'",
                                    Detail = $"Decoded path: {decoded}",
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }, ct);

    private Task CheckDownloads(ScanContext ctx, CancellationToken ct) =>
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

                    string fileName = Path.GetFileName(file);
                    string ext = Path.GetExtension(fileName);
                    bool isArchive = ArchiveExtensions.Any(a =>
                        ext.Equals(a, StringComparison.OrdinalIgnoreCase));
                    if (!isArchive) continue;

                    foreach (var pattern in ArchivePatterns)
                    {
                        if (!fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Cheat Vendor Download Archive",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Downloaded archive name matches FiveM cheat vendor: '{pattern}'",
                            Detail = "Archive downloaded with a known cheat-brand identifier.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckMuiCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string muiRoot =
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

            RegistryKey? mui;
            try { mui = Registry.CurrentUser.OpenSubKey(muiRoot); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }

            if (mui == null) return;
            using (mui)
            {
                string[] vals;
                try { vals = mui.GetValueNames(); }
                catch (System.Security.SecurityException) { return; }

                foreach (var v in vals)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    string vlow = v.ToLowerInvariant();
                    foreach (var brand in CheatVendorBrands)
                    {
                        if (!vlow.Contains(brand, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Cheat Vendor in MuiCache",
                            Risk = RiskLevel.High,
                            Location = $"HKCU\\{muiRoot}\\{v}",
                            Reason = $"MuiCache entry references known FiveM cheat brand: '{brand}'",
                            Detail = "Application execution record for known cheat vendor.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckPrefetch(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string prefetchDir = @"C:\Windows\Prefetch";
            if (!Directory.Exists(prefetchDir)) return;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(prefetchDir, "*.pf"); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string fileName = Path.GetFileName(file).ToLowerInvariant();
                foreach (var brand in CheatVendorBrands)
                {
                    if (!fileName.Contains(brand, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Cheat Vendor in Prefetch",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Prefetch file shows execution of known FiveM cheat brand: '{brand}'",
                        Detail = "Windows Prefetch records confirm prior execution of cheat vendor binary.",
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

            string recentDir = Path.Combine(appData, "Microsoft", "Windows", "Recent");
            if (!Directory.Exists(recentDir)) return;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(recentDir, "*.lnk"); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string fileName = Path.GetFileName(file);
                foreach (var brand in CheatVendorBrands)
                {
                    if (!fileName.Contains(brand, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Cheat Vendor Recent Document Shortcut",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Recent document shortcut for known FiveM cheat brand: '{brand}'",
                        Detail = "User opened a file associated with a cheat vendor recently.",
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

            string[] discordDirs =
            {
                Path.Combine(appData, "discord"),
                Path.Combine(appData, "discordptb"),
                Path.Combine(appData, "discordcanary"),
            };

            foreach (var discord in discordDirs)
            {
                if (!Directory.Exists(discord)) continue;
                ct.ThrowIfCancellationRequested();

                string cache = Path.Combine(discord, "Cache");
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

                    foreach (var urlPattern in CheatVendorBrowserUrlPatterns)
                    {
                        if (!content.Contains(urlPattern, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Vendor URL in Discord Cache",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Discord cache contains known FiveM cheat vendor URL: '{urlPattern}'",
                            Detail = "User received or shared a link to a known FiveM cheat marketplace via Discord.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckShortcuts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(userProfile)) return;

            string[] shortcutDirs =
            {
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs"),
            };

            foreach (var dir in shortcutDirs)
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

                    string fileName = Path.GetFileName(file);
                    foreach (var brand in CheatVendorBrands)
                    {
                        if (!fileName.Contains(brand, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Cheat Vendor Shortcut",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Shortcut file matches known FiveM cheat brand: '{brand}'",
                            Detail = "Desktop or Start Menu shortcut for a known cheat vendor application.",
                        });
                        break;
                    }

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var brand in CheatVendorBrands)
                    {
                        if (!content.Contains(brand, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Vendor Path in Shortcut Target",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Shortcut target path contains known FiveM cheat brand: '{brand}'",
                            Detail = "Shortcut file points to a known cheat vendor executable or directory.",
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
            if (c >= 'a' && c <= 'z')
                sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z')
                sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }
}
