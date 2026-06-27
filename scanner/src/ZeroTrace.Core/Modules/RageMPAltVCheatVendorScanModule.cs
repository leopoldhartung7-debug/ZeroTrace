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

public sealed class RageMPAltVCheatVendorScanModule : IScanModule
{
    public string Name => "RageMP / alt:V Cheat Vendor Forensic Scan";
    public double Weight => 4.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] CheatVendorBrands =
    {
        "ragemp-menu", "ragempmenu", "ragemp-cheat", "ragempcheat",
        "ragemp-hack", "ragemphack", "ragemp-trainer", "ragemptrainer",
        "ragemp-spoofer", "ragempspoofer", "ragemp-cleaner", "ragempcleaner",
        "ragemp-unban", "ragempunban", "ragemp-godmode", "ragempgodmode",
        "ragemp-aimbot", "ragempaimbot", "ragemp-esp", "ragempesp",
        "ragemp-wallhack", "ragempwallhack", "altv-menu", "altvmenu",
        "altv-cheat", "altvcheat", "altv-hack", "altvhack",
        "altv-trainer", "altvtrainer", "altv-spoofer", "altvspoofer",
        "altv-cleaner", "altvcleaner", "altv-unban", "altvunban",
        "altv-godmode", "altvgodmode", "altv-aimbot", "altvaimbot",
        "altv-esp", "altvesp", "altv-wallhack", "altvwallhack",
        "rage-hax", "ragehax", "rage-cheat", "ragecheat",
        "alt-v-hax", "altvhax", "rocket-rage", "rocketrage",
        "supreme-rage", "supremerage", "neptune-rage", "neptunerage",
        "xenon-rage", "xenonrage", "predator-rage", "predatorrage",
        "fatality-rage", "fatalityrage", "private-rage", "privaterage",
        "absolute-rage", "absoluterage", "luna-rage", "lunarage",
        "phantom-rage", "phantomrage", "midnight-rage", "midnightrage",
        "rocket-altv", "rocketaltv", "supreme-altv", "supremealtv",
        "neptune-altv", "neptunealtv", "xenon-altv", "xenonaltv",
        "predator-altv", "predatoraltv", "fatality-altv", "fatalityaltv",
        "private-altv", "privatealtv", "absolute-altv", "absolutealtv",
        "luna-altv", "lunaaltv", "phantom-altv", "phantomaltv",
        "midnight-altv", "midnightaltv", "redengine-rage", "redenginealtv",
        "redengine-altv", "tzx-rage", "tzx-altv",
    };

    private static readonly string[] CheatVendorFileNames =
    {
        "ragemp-menu.exe", "ragempmenu.exe", "ragemp-cheat.exe",
        "ragempcheat.exe", "ragemp-hack.exe", "ragemphack.exe",
        "ragemp-trainer.exe", "ragemptrainer.exe", "ragemp-spoofer.exe",
        "ragempspoofer.exe", "ragemp-cleaner.exe", "ragempcleaner.exe",
        "ragemp-unban.exe", "ragempunban.exe", "ragemp-godmode.exe",
        "ragempgodmode.exe", "ragemp-aimbot.exe", "ragempaimbot.exe",
        "ragemp-esp.exe", "ragempesp.exe", "ragemp-wallhack.exe",
        "ragempwallhack.exe", "altv-menu.exe", "altvmenu.exe",
        "altv-cheat.exe", "altvcheat.exe", "altv-hack.exe", "altvhack.exe",
        "altv-trainer.exe", "altvtrainer.exe", "altv-spoofer.exe",
        "altvspoofer.exe", "altv-cleaner.exe", "altvcleaner.exe",
        "altv-unban.exe", "altvunban.exe", "altv-godmode.exe",
        "altvgodmode.exe", "altv-aimbot.exe", "altvaimbot.exe",
        "altv-esp.exe", "altvesp.exe", "altv-wallhack.exe",
        "altvwallhack.exe", "rage-hax.exe", "ragehax.exe",
        "rage-cheat.exe", "ragecheat.exe", "altvhax.exe",
        "rocket-rage.exe", "rocketrage.exe", "supreme-rage.exe",
        "supremerage.exe", "neptune-rage.exe", "neptunerage.exe",
        "xenon-rage.exe", "xenonrage.exe", "predator-rage.exe",
        "predatorrage.exe", "fatality-rage.exe", "fatalityrage.exe",
        "rocket-altv.exe", "rocketaltv.exe", "supreme-altv.exe",
        "supremealtv.exe", "neptune-altv.exe", "neptunealtv.exe",
        "xenon-altv.exe", "xenonaltv.exe", "predator-altv.exe",
        "predatoraltv.exe", "fatality-altv.exe", "fatalityaltv.exe",
        "redengine-rage.exe", "redenginealtv.exe", "tzx-rage.exe",
        "tzx-altv.exe",
    };

    private static readonly string[] CheatVendorDlls =
    {
        "ragemp-menu.dll", "ragemp-cheat.dll", "ragemp-hack.dll",
        "ragemp-trainer.dll", "ragemp-spoofer.dll", "ragemp-godmode.dll",
        "ragemp-aimbot.dll", "ragemp-esp.dll", "ragemp-wallhack.dll",
        "ragemp_inject.dll", "ragemp_hook.dll", "ragemp_payload.dll",
        "altv-menu.dll", "altv-cheat.dll", "altv-hack.dll",
        "altv-trainer.dll", "altv-spoofer.dll", "altv-godmode.dll",
        "altv-aimbot.dll", "altv-esp.dll", "altv-wallhack.dll",
        "altv_inject.dll", "altv_hook.dll", "altv_payload.dll",
        "rage-hax.dll", "rage-cheat.dll", "altvhax.dll",
        "rocket-rage.dll", "supreme-rage.dll", "neptune-rage.dll",
        "xenon-rage.dll", "predator-rage.dll", "fatality-rage.dll",
        "rocket-altv.dll", "supreme-altv.dll", "neptune-altv.dll",
        "xenon-altv.dll", "predator-altv.dll", "fatality-altv.dll",
        "redengine-rage.dll", "redengine-altv.dll", "tzx-rage.dll",
        "tzx-altv.dll",
    };

    private static readonly string[] CheatVendorLogKeywords =
    {
        "ragemp menu detected", "ragemp cheat detected",
        "ragemp hack detected", "ragemp trainer detected",
        "ragemp spoofer detected", "ragemp godmode detected",
        "ragemp aimbot detected", "ragemp esp detected",
        "ragemp wallhack detected", "altv menu detected",
        "altv cheat detected", "altv hack detected",
        "altv trainer detected", "altv spoofer detected",
        "altv godmode detected", "altv aimbot detected",
        "altv esp detected", "altv wallhack detected",
        "rage-hax detected", "ragehax detected",
        "altvhax detected", "rocket cheat detected",
        "supreme cheat detected", "neptune cheat detected",
        "xenon cheat detected", "predator cheat detected",
        "fatality cheat detected", "redengine rage detected",
        "redengine altv detected", "tzx rage detected",
        "tzx altv detected", "ragemp cheat loader",
        "altv cheat loader", "ragemp cheat injection",
        "altv cheat injection", "external cheat detected ragemp",
        "external cheat detected altv",
    };

    private static readonly string[] CheatVendorBrowserUrlPatterns =
    {
        "ragemp-menu.com", "ragemp-cheat.com", "ragemp-hack.com",
        "ragemp-trainer.com", "ragemp-spoofer.com", "ragemp-cleaner.com",
        "ragemp-unban.com", "ragemp-godmode.com", "ragemp-aimbot.com",
        "ragemp-esp.com", "ragemp-wallhack.com", "altv-menu.com",
        "altv-cheat.com", "altv-hack.com", "altv-trainer.com",
        "altv-spoofer.com", "altv-cleaner.com", "altv-unban.com",
        "altv-godmode.com", "altv-aimbot.com", "altv-esp.com",
        "altv-wallhack.com", "rage-hax.com", "ragehax.cc",
        "altvhax.com", "altvhax.cc", "rocket-rage.com",
        "supreme-rage.com", "neptune-rage.com", "xenon-rage.com",
        "predator-rage.com", "fatality-rage.com", "rocket-altv.com",
        "supreme-altv.com", "neptune-altv.com", "xenon-altv.com",
        "predator-altv.com", "fatality-altv.com", "redengine-rage.com",
        "redengine-altv.com", "ragemp-cheats.gg", "altv-cheats.gg",
        "ragemp-loader.gg", "altv-loader.gg", "ragemp-marketplace.com",
        "altv-marketplace.com",
    };

    private static readonly string[] CheatVendorRegistryKeyNames =
    {
        "RageMPMenu", "RageMPCheat", "RageMPHack", "RageMPTrainer",
        "RageMPSpoofer", "RageMPCleaner", "RageMPUnban", "RageMPGodMode",
        "RageMPAimbot", "RageMPESP", "RageMPWallhack", "AltVMenu",
        "AltVCheat", "AltVHack", "AltVTrainer", "AltVSpoofer",
        "AltVCleaner", "AltVUnban", "AltVGodMode", "AltVAimbot",
        "AltVESP", "AltVWallhack", "RageHax", "AltVHax",
        "RocketRage", "SupremeRage", "NeptuneRage", "XenonRage",
        "PredatorRage", "FatalityRage", "RocketAltV", "SupremeAltV",
        "NeptuneAltV", "XenonAltV", "PredatorAltV", "FatalityAltV",
        "RedEngineRage", "RedEngineAltV", "TZXRage", "TZXAltV",
    };

    private static readonly string[] ArchivePatterns =
    {
        "ragemp-menu", "ragemp-cheat", "ragemp-hack", "ragemp-trainer",
        "ragemp-spoofer", "ragemp-cleaner", "ragemp-unban",
        "ragemp-godmode", "ragemp-aimbot", "ragemp-esp",
        "ragemp-wallhack", "altv-menu", "altv-cheat", "altv-hack",
        "altv-trainer", "altv-spoofer", "altv-cleaner", "altv-unban",
        "altv-godmode", "altv-aimbot", "altv-esp", "altv-wallhack",
        "rage-hax", "ragehax", "altvhax", "rocket-rage",
        "supreme-rage", "neptune-rage", "xenon-rage", "predator-rage",
        "fatality-rage", "rocket-altv", "supreme-altv", "neptune-altv",
        "xenon-altv", "predator-altv", "fatality-altv",
        "redengine-rage", "redengine-altv", "tzx-rage", "tzx-altv",
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
            dirs.Add(Path.Combine(userProfile, "Music"));
            dirs.Add(Path.Combine(userProfile, "Videos"));
        }

        var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        if (!string.IsNullOrEmpty(localAppData))
        {
            dirs.Add(Path.Combine(localAppData, "RAGEMP"));
            dirs.Add(Path.Combine(localAppData, "RAGE Multiplayer"));
            dirs.Add(Path.Combine(localAppData, "altv"));
            dirs.Add(Path.Combine(localAppData, "altV"));
            dirs.Add(Path.Combine(localAppData, "alt-V"));
        }

        var appData = Environment.GetEnvironmentVariable("APPDATA");
        if (!string.IsNullOrEmpty(appData))
        {
            dirs.Add(Path.Combine(appData, "RAGEMP"));
            dirs.Add(Path.Combine(appData, "RAGE Multiplayer"));
            dirs.Add(Path.Combine(appData, "altv"));
            dirs.Add(Path.Combine(appData, "altV"));
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
                        Title = "Known RageMP/alt:V Cheat Vendor Executable",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Executable filename matches known RageMP/alt:V cheat brand: {fileName}",
                        Detail = "Filename matches a documented multiplayer cheat marketplace brand for RAGE Multiplayer or alt:V.",
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
                    bool matched = CheatVendorDlls.Any(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));

                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Known RageMP/alt:V Cheat Vendor DLL",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"DLL filename matches known RageMP/alt:V cheat: {fileName}",
                        Detail = "Injection/hook DLL with a documented cheat brand identifier.",
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
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (!string.IsNullOrEmpty(localAppData))
            {
                logDirs.Add(Path.Combine(localAppData, "RAGEMP"));
                logDirs.Add(Path.Combine(localAppData, "RAGE Multiplayer"));
                logDirs.Add(Path.Combine(localAppData, "altv"));
                logDirs.Add(Path.Combine(localAppData, "altV"));
            }
            if (!string.IsNullOrEmpty(appData))
            {
                logDirs.Add(Path.Combine(appData, "RAGEMP"));
                logDirs.Add(Path.Combine(appData, "RAGE Multiplayer"));
                logDirs.Add(Path.Combine(appData, "altv"));
                logDirs.Add(Path.Combine(appData, "altV"));
            }

            foreach (var dir in logDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                foreach (var ext in logExts)
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

                        foreach (var pattern in CheatVendorLogKeywords)
                        {
                            if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Vendor Reference in RageMP/alt:V Log",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Log contains known cheat vendor pattern: '{pattern}'",
                                Detail = "Log file references a documented RageMP or alt:V cheat brand.",
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
                        Title = "RageMP/alt:V Cheat Vendor Domain in Browser History",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = Path.GetFileName(path),
                        Reason = $"Browser history contains RageMP/alt:V cheat vendor URL: '{urlPattern}'",
                        Detail = "User visited a known cheat marketplace for RageMP or alt:V.",
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
                                Title = "RageMP/alt:V Cheat Vendor Registry Key",
                                Risk = RiskLevel.High,
                                Location = $"{hive.Name}\\{root}\\{sub}",
                                Reason = $"Registry key named after RageMP/alt:V cheat brand: '{sub}'",
                                Detail = "Registry persistence/installer record for documented cheat vendor.",
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
                                    Title = "RageMP/alt:V Cheat in UserAssist",
                                    Risk = RiskLevel.High,
                                    Location = $"HKCU\\{userAssistRoot}\\{guid}\\Count\\{v}",
                                    FileName = decoded,
                                    Reason = $"UserAssist execution record for known cheat: '{brand}'",
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
                            Title = "RageMP/alt:V Cheat Vendor Download Archive",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Downloaded archive matches RageMP/alt:V cheat brand: '{pattern}'",
                            Detail = "Archive downloaded with known cheat identifier.",
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
                            Title = "RageMP/alt:V Cheat in MuiCache",
                            Risk = RiskLevel.High,
                            Location = $"HKCU\\{muiRoot}\\{v}",
                            Reason = $"MuiCache entry references RageMP/alt:V cheat brand: '{brand}'",
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
                        Title = "RageMP/alt:V Cheat in Prefetch",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Prefetch records execution of known cheat brand: '{brand}'",
                        Detail = "Windows Prefetch confirms prior execution of cheat vendor binary.",
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
                        Title = "RageMP/alt:V Cheat Recent Document",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Recent document shortcut for known cheat brand: '{brand}'",
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
                            Title = "RageMP/alt:V Cheat Vendor URL in Discord Cache",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Discord cache contains known cheat vendor URL: '{urlPattern}'",
                            Detail = "User received or shared a link to a known RageMP/alt:V cheat marketplace.",
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
                            Title = "RageMP/alt:V Cheat Vendor Shortcut",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Shortcut file matches known cheat brand: '{brand}'",
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
                            Reason = $"Shortcut target path contains known cheat brand: '{brand}'",
                            Detail = "Shortcut points to a known cheat vendor executable or directory.",
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
