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

public sealed class UniversalCheatLoaderScanModule : IScanModule
{
    public string Name => "Universal Cheat Loader & Injector Forensic Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] LoaderExecutables =
    {
        "loader.exe", "loader_x64.exe", "loader_x86.exe", "loader_v2.exe",
        "loader_v3.exe", "loader_final.exe", "loader_release.exe",
        "loader_debug.exe", "loader_setup.exe", "loader_installer.exe",
        "cheat_loader.exe", "cheatloader.exe", "cheat-loader.exe",
        "hack_loader.exe", "hackloader.exe", "hack-loader.exe",
        "menu_loader.exe", "menuloader.exe", "menu-loader.exe",
        "private_loader.exe", "privateloader.exe", "private-loader.exe",
        "secure_loader.exe", "secureloader.exe", "secure-loader.exe",
        "stealth_loader.exe", "stealthloader.exe", "stealth-loader.exe",
        "elite_loader.exe", "eliteloader.exe", "elite-loader.exe",
        "premium_loader.exe", "premiumloader.exe", "premium-loader.exe",
        "vip_loader.exe", "viploader.exe", "vip-loader.exe",
        "auth_loader.exe", "authloader.exe", "auth-loader.exe",
        "key_loader.exe", "keyloader.exe", "key-loader.exe",
        "license_loader.exe", "licenseloader.exe", "license-loader.exe",
        "key_auth.exe", "keyauth.exe", "key-auth.exe",
        "key-auth_loader.exe", "keyauth_loader.exe", "keyauthloader.exe",
        "auth_gg.exe", "authgg.exe", "auth-gg.exe",
        "loader_gg.exe", "loadergg.exe", "loader-gg.exe",
        "loader_cc.exe", "loadercc.exe", "loader-cc.exe",
        "loader_cheats.exe", "loadercheats.exe", "loader-cheats.exe",
        "cheat_gg.exe", "cheatgg.exe", "cheat-gg.exe",
        "hack_gg.exe", "hackgg.exe", "hack-gg.exe",
        "loader_loader.exe", "loaderloader.exe",
        "injector.exe", "injector_x64.exe", "injector_x86.exe",
        "injector_v2.exe", "injector_v3.exe", "manual_injector.exe",
        "manualinjector.exe", "manual-injector.exe",
        "extreme_injector.exe", "extremeinjector.exe", "extreme-injector.exe",
        "guided_hacking_injector.exe", "ghinjector.exe", "gh_injector.exe",
        "dll_injector.exe", "dllinjector.exe", "dll-injector.exe",
        "kernel_injector.exe", "kernelinjector.exe", "kernel-injector.exe",
        "manualmap_injector.exe", "manualmapinjector.exe",
        "manual_map.exe", "manualmap.exe", "manual-map.exe",
        "process_hollowing.exe", "processhollowing.exe",
        "process-hollowing.exe", "thread_hijack.exe", "threadhijack.exe",
        "reflective_loader.exe", "reflectiveloader.exe",
        "reflective-loader.exe", "rdi_loader.exe", "rdiloader.exe",
        "memory_loader.exe", "memoryloader.exe", "memory-loader.exe",
        "stub.exe", "stub_loader.exe", "stubloader.exe",
        "client.exe", "client_loader.exe", "clientloader.exe",
        "spoofer.exe", "hwid_spoofer.exe", "hwidspoofer.exe",
        "fingerprint_spoofer.exe", "fingerprintspoofer.exe",
        "fp_spoofer.exe", "fpspoofer.exe", "fp-spoofer.exe",
        "ban_evade.exe", "banevade.exe", "ban-evade.exe",
        "cleaner.exe", "trace_cleaner.exe", "tracecleaner.exe",
    };

    private static readonly string[] LoaderDlls =
    {
        "loader.dll", "loader_x64.dll", "loader_x86.dll", "loader_v2.dll",
        "cheat_loader.dll", "cheatloader.dll", "cheat-loader.dll",
        "hack_loader.dll", "hackloader.dll", "menu_loader.dll",
        "menuloader.dll", "private_loader.dll", "privateloader.dll",
        "secure_loader.dll", "secureloader.dll", "stealth_loader.dll",
        "stealthloader.dll", "elite_loader.dll", "eliteloader.dll",
        "premium_loader.dll", "premiumloader.dll",
        "vip_loader.dll", "viploader.dll", "auth_loader.dll",
        "authloader.dll", "key_loader.dll", "keyloader.dll",
        "license_loader.dll", "licenseloader.dll",
        "manualmap_loader.dll", "manualmapper.dll", "rdi_loader.dll",
        "rdiloader.dll", "reflective_loader.dll", "reflectiveloader.dll",
        "memory_loader.dll", "memoryloader.dll", "payload.dll",
        "payload_x64.dll", "payload_x86.dll", "payload_v2.dll",
        "inject.dll", "inject_x64.dll", "inject_x86.dll",
        "hook.dll", "hook_x64.dll", "hook_x86.dll",
        "detour.dll", "detours.dll", "minhook.dll",
        "polyhook.dll", "subhook.dll", "stub.dll",
        "internal.dll", "internal_x64.dll", "internal_v2.dll",
        "external.dll", "external_x64.dll", "external_v2.dll",
        "module.dll", "module_x64.dll", "module_v2.dll",
        "bypass.dll", "bypass_x64.dll", "bypass_v2.dll",
        "ac_bypass.dll", "acbypass.dll", "ac-bypass.dll",
        "anticheat_bypass.dll", "anticheatbypass.dll", "anticheat-bypass.dll",
    };

    private static readonly string[] LoaderLogKeywords =
    {
        "loader started", "loader authenticated", "loader injected",
        "loader auth success", "loader auth failed", "key authenticated",
        "key auth success", "key auth failed", "license validated",
        "license invalid", "subscription valid", "subscription expired",
        "hwid mismatch", "hwid registered", "hwid spoofed",
        "process injected", "dll injected", "module loaded",
        "memory written", "memory mapped", "manual map success",
        "reflective load success", "stub executed", "stub decoded",
        "payload decrypted", "payload executed", "anticheat bypassed",
        "eac bypassed", "be bypassed", "vanguard bypassed",
        "vac bypassed", "ricochet bypassed", "fairfight bypassed",
        "cheat loader v", "cheat menu loaded", "cheat module loaded",
        "external cheat loaded", "internal cheat loaded",
        "kernel driver loaded", "vulnerable driver loaded",
        "byovd loaded", "cheat process attached",
        "cheat process detached", "cheat session started",
        "cheat session ended", "cheat auth check",
        "cheat license check", "cheat update check",
    };

    private static readonly string[] LoaderBrowserUrlPatterns =
    {
        "loader.gg", "loader.cc", "loader-cheats.com", "cheatloader.com",
        "cheat-loader.com", "key-auth.win", "keyauth.win", "keyauth.gg",
        "keyauth.cc", "keyauth.online", "key-auth.com", "keyauth.com",
        "auth.gg", "auth-gg.com", "auth.cheat.gg",
        "cheat.gg", "cheats.gg", "private-cheats.com", "private-cheat.com",
        "elite-cheats.com", "premium-cheats.com", "vip-cheats.com",
        "secure-cheats.com", "stealth-cheats.com", "stealth-cheat.com",
        "extreme-injector", "guidedhacking.com", "guided-hacking.com",
        "unknowncheats.me", "uc.me", "elitepvpers.com", "epvp.com",
        "mpgh.net", "mpgh.com",
    };

    private static readonly string[] ArchivePatterns =
    {
        "loader", "cheat_loader", "cheat-loader", "hack_loader",
        "hack-loader", "menu_loader", "menu-loader", "private_loader",
        "private-loader", "secure_loader", "stealth_loader", "elite_loader",
        "premium_loader", "vip_loader", "auth_loader", "key_loader",
        "license_loader", "keyauth", "key_auth", "key-auth",
        "loader_gg", "loader-gg", "loader_cc", "loader-cc",
        "loader_cheats", "loader-cheats", "auth_gg", "auth-gg",
        "injector", "manual_injector", "manual-injector",
        "extreme_injector", "extreme-injector", "guided_hacking_injector",
        "gh_injector", "dll_injector", "dll-injector",
        "kernel_injector", "kernel-injector", "manualmap",
        "manual_map", "manual-map", "process_hollowing",
        "thread_hijack", "reflective_loader", "rdi_loader",
        "memory_loader", "spoofer", "hwid_spoofer", "fingerprint_spoofer",
        "fp_spoofer", "ban_evade", "trace_cleaner",
    };

    private static readonly string[] ArchiveExtensions =
        { ".zip", ".rar", ".7z", ".gz", ".cab", ".tar", ".iso" };

    private static readonly string[] LoaderRegistryKeyNames =
    {
        "Loader", "CheatLoader", "HackLoader", "MenuLoader",
        "PrivateLoader", "SecureLoader", "StealthLoader", "EliteLoader",
        "PremiumLoader", "VIPLoader", "AuthLoader", "KeyLoader",
        "LicenseLoader", "KeyAuth", "KeyAuthLoader", "AuthGG",
        "LoaderGG", "LoaderCheats", "CheatGG", "HackGG",
        "Injector", "ManualInjector", "ExtremeInjector",
        "GuidedHackingInjector", "DLLInjector", "KernelInjector",
        "ManualMapper", "ReflectiveLoader", "RDILoader",
        "MemoryLoader", "Spoofer", "HWIDSpoofer", "FPSpoofer",
        "BanEvade", "TraceCleaner", "AntiCheatBypass",
    };

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
            CheckCheatEngineCompanionFiles(ctx, ct),
            CheckScheduledTasks(ctx, ct)
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
                    bool matched = LoaderExecutables.Any(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Generic Cheat Loader Executable",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Executable filename matches generic cheat loader/injector pattern: {fileName}",
                        Detail = "Filename matches common cheat loader/injector naming conventions used across multiple cheat distributions.",
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
                    bool matched = LoaderDlls.Any(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Generic Cheat Loader/Injector DLL",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"DLL filename matches generic cheat loader pattern: {fileName}",
                        Detail = "Filename consistent with hooking/injection libraries (MinHook, Detours, payload, internal/external modules).",
                    });
                }
            }
        }, ct);

    private Task CheckLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            string[] logExts = { ".log", ".txt", ".json", ".cfg" };
            var dirs = BuildSearchDirectories().ToList();

            foreach (var dir in dirs)
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

                        foreach (var pattern in LoaderLogKeywords)
                        {
                            if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Loader Log Trace",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Log/config contains cheat loader activity pattern: '{pattern}'",
                                Detail = "Log line indicates a cheat loader has authenticated, injected, or bypassed anti-cheat.",
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

                foreach (var url in LoaderBrowserUrlPatterns)
                {
                    if (!content.Contains(url, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Loader/Marketplace Domain in Browser History",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = Path.GetFileName(path),
                        Reason = $"Browser history contains cheat loader/marketplace URL pattern: '{url}'",
                        Detail = "Visited a domain commonly used for cheat distribution, KeyAuth-based licensing, or known cheat forums.",
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
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
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

                            bool matched = LoaderRegistryKeyNames.Any(k =>
                                sub.Equals(k, StringComparison.OrdinalIgnoreCase));
                            if (!matched) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Loader Registry Key",
                                Risk = RiskLevel.High,
                                Location = $"{hive.Name}\\{root}\\{sub}",
                                Reason = $"Registry key named after generic cheat loader/injector: '{sub}'",
                                Detail = "Registry persistence/installer/uninstall record matching loader naming.",
                            });
                        }

                        string[] vals;
                        try { vals = rootKey.GetValueNames(); }
                        catch (System.Security.SecurityException) { continue; }

                        foreach (var v in vals)
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();
                            object? dataObj;
                            try { dataObj = rootKey.GetValue(v); }
                            catch (System.Security.SecurityException) { continue; }
                            if (dataObj == null) continue;

                            string data = dataObj.ToString() ?? string.Empty;
                            foreach (var keyword in LoaderRegistryKeyNames)
                            {
                                if (!data.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cheat Loader Registry Value",
                                    Risk = RiskLevel.High,
                                    Location = $"{hive.Name}\\{root}\\{v}",
                                    Reason = $"Registry value points to cheat loader path: '{keyword}'",
                                    Detail = $"Value data: {data}",
                                });
                                break;
                            }
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

                            string decoded = Rot13Decode(v).ToLowerInvariant();
                            foreach (var exe in LoaderExecutables)
                            {
                                string exeName = exe.ToLowerInvariant();
                                if (!decoded.Contains(exeName, StringComparison.OrdinalIgnoreCase)) continue;

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cheat Loader Execution Trace (UserAssist)",
                                    Risk = RiskLevel.High,
                                    Location = $"HKCU\\{userAssistRoot}\\{guid}\\Count\\{v}",
                                    FileName = decoded,
                                    Reason = $"UserAssist contains execution record for cheat loader: '{exeName}'",
                                    Detail = "Windows tracks every interactive launch — match here = the loader was executed by this user.",
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
                    if (!ArchiveExtensions.Any(a => ext.Equals(a, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    string name = Path.GetFileName(file);
                    foreach (var pattern in ArchivePatterns)
                    {
                        if (!name.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Loader Download Archive",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = name,
                            Reason = $"Downloaded archive name matches cheat loader pattern: '{pattern}'",
                            Detail = "Archive named for loader/injector — distribution package commonly seen on cheat marketplaces.",
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
                    foreach (var exe in LoaderExecutables)
                    {
                        string exeName = exe.ToLowerInvariant();
                        if (!vlow.Contains(exeName, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Loader in MuiCache",
                            Risk = RiskLevel.High,
                            Location = $"HKCU\\{muiRoot}\\{v}",
                            Reason = $"MuiCache entry references cheat loader: '{exeName}'",
                            Detail = "Application execution record for a generic cheat loader binary.",
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
                foreach (var exe in LoaderExecutables)
                {
                    string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                    if (!fileName.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Loader in Prefetch",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Prefetch records execution of cheat loader: '{exeBase}'",
                        Detail = "Windows Prefetch confirms prior execution of a loader/injector binary.",
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

                string name = Path.GetFileName(file);
                foreach (var exe in LoaderExecutables)
                {
                    string exeBase = Path.GetFileNameWithoutExtension(exe);
                    if (!name.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Loader Recent Document Shortcut",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = name,
                        Reason = $"Recent shortcut points to cheat loader name: '{exeBase}'",
                        Detail = "User recently interacted with a file associated with a cheat loader.",
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

                    foreach (var url in LoaderBrowserUrlPatterns)
                    {
                        if (!content.Contains(url, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Loader URL in Discord Cache",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Discord cache contains cheat loader URL: '{url}'",
                            Detail = "User received or sent a link to a known cheat loader / KeyAuth / marketplace via Discord.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckCheatEngineCompanionFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var dirs = BuildSearchDirectories();
            string[] companionExts = { ".ct", ".cetrainer", ".CT", ".CETRAINER" };
            string[] companionKeywords =
            {
                "loader", "injector", "manualmap", "manual_map", "manual map",
                "anticheat bypass", "ac bypass", "byovd", "vulnerable driver",
                "key_auth", "keyauth", "license_check", "license check",
            };

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                foreach (var ext in companionExts)
                {
                    IEnumerable<string> files;
                    try { files = Directory.EnumerateFiles(dir, "*" + ext, SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in files)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();

                        string fileName = Path.GetFileName(file).ToLowerInvariant();
                        foreach (var kw in companionKeywords)
                        {
                            if (!fileName.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Engine Loader Companion File",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cheat Engine table / trainer file named after loader concept: '{kw}'",
                                Detail = "Cheat Engine companion artifact indicates a loader/injector workflow.",
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    private Task CheckScheduledTasks(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string tasksDir = @"C:\Windows\System32\Tasks";
            if (!Directory.Exists(tasksDir)) return;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(tasksDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string fileName = Path.GetFileName(file);
                foreach (var keyword in LoaderRegistryKeyNames)
                {
                    if (!fileName.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Loader Scheduled Task",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Scheduled task file named after cheat loader: '{keyword}'",
                        Detail = "Task Scheduler entry with loader-related naming — potential persistence.",
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
