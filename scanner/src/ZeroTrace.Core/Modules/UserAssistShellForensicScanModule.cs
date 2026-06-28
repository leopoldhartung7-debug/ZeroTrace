using System.Runtime.Versioning;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class UserAssistShellForensicScanModule : IScanModule
{
    public string Name => "UserAssist / Shell History Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatToolNames =
    [
        "kiddion", "modest_menu", "eulen", "hammafia", "xforce", "redengine",
        "nightfall", "emperor", "impulse", "outbreak", "cherax", "2take1",
        "midnight", "vanquish", "paragon", "lumia", "stand", "genesis",
        "desudo", "skript", "lynx", "absolute", "sona", "hexui", "dxhook",
        "luna", "nitro", "matrix", "poka", "lamar", "fivem_bypass",
        "fivem_spoofer", "fivem_injector", "fivem_loader", "fivem_hack",
        "fivem_cheat", "fivem_mod", "fivem_trainer", "fivem_cleaner",
        "ragemp_cheat", "ragemp_hack", "ragemp_bypass", "altv_cheat",
        "altv_hack", "altv_bypass", "gtav_bypass", "gtav_spoofer",
        "battleye_bypass", "battleye_spoofer", "eac_bypass", "eac_spoofer",
        "vac_bypass", "hwid_spoofer", "hwid_changer", "hwid_reset",
        "be_bypass", "injector", "dll_inject", "manualmapper", "manual_map",
        "reflective", "cheatengine", "cheat_engine", "artmoney",
        "xenos", "extreme_injector", "ghostsuite", "ghost_suite",
        "hwidspoofer", "serialchanger", "macspoofer", "diskspoofer",
        "ccleaner", "bleachbit", "privazer", "eraser",
        "processhacker", "process_hacker", "procexp",
        "wireshark", "fiddler", "burpsuite",
        "dnspy", "ilspy", "dotpeek", "ida", "x64dbg", "x32dbg", "ollydbg",
        "cheatdb", "cheat_db", "themida", "vmprotect", "enigma",
    ];

    private static readonly string[] ShellBagCheatPaths =
    [
        "fivem", "fivem.app", "citizenfx", "ragemp", "altv", "altv-client",
        "kiddion", "eulen", "2take1", "stand", "cherax", "outbreak",
        "impulse", "redengine", "hammafia", "cheat", "hack", "bypass",
        "inject", "spoofer", "hwid", "modmenu", "trainer",
        "cheat engine", "cheatengine", "processhacker",
        "wireshark", "fiddler", "dnspy", "x64dbg",
    ];

    private static readonly string[] LNKCheatKeywords =
    [
        "cheat", "hack", "bypass", "inject", "spoofer", "modmenu",
        "fivem", "ragemp", "altv", "kiddion", "eulen", "2take1",
        "stand", "cherax", "outbreak", "impulse", "trainer",
        "hwid", "unban", "battleye", "easyanticheat",
    ];

    private static readonly string[] JumpListCheatKeywords =
    [
        "cheat", "hack", "bypass", "inject", "fivem", "ragemp",
        "altv", "kiddion", "eulen", "stand", "modmenu", "trainer",
        "spoofer", "hwid", "unban",
    ];

    private static readonly string[] RecentDocsCheatKeywords =
    [
        "cheat", "hack", "bypass", "inject", "fivem", "ragemp", "altv",
        "kiddion", "eulen", "2take1", "stand", "cherax", "outbreak",
        "impulse", "modmenu", "trainer", "spoofer", "hwid", "unban",
        "license", "key", "serial", "crack", "keygen",
    ];

    private static string Rot13Decode(string input)
    {
        return new string(input.Select(c =>
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) :
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) : c).ToArray());
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckUserAssistCheatTools(ctx, ct),
            CheckMUICacheCheatTools(ctx, ct),
            CheckShellBagsCheatPaths(ctx, ct),
            CheckRecentDocumentsCheatFiles(ctx, ct),
            CheckLNKFilesCheatTargets(ctx, ct),
            CheckJumpListCheatTargets(ctx, ct),
            CheckRunMRUCheatCommands(ctx, ct),
            CheckAppPathsCheatTools(ctx, ct),
            CheckTypedPathsCheatURLs(ctx, ct),
            CheckOpenSaveMRUCheatFiles(ctx, ct),
            CheckLastVisitedMRUCheatPaths(ctx, ct),
            CheckWindowsSearchHistoryCheat(ctx, ct),
            CheckPinnedJumpListCheatTools(ctx, ct),
            CheckStartMenuCheatShortcuts(ctx, ct),
            CheckDesktopShortcutsCheat(ctx, ct),
            CheckBrowserBookmarksCheat(ctx, ct),
            CheckUserAssistCounters(ctx, ct),
            CheckRecentApplicationsCheat(ctx, ct)
        );
    }

    private Task CheckUserAssistCheatTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var userAssistPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{75048700-EF1F-11D0-9888-006097DEACF9}\Count",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{5E6AB780-7743-11CF-A12B-00AA004AE837}\Count",
        };

        using var hkcu = Registry.CurrentUser;
        foreach (var uaPath in userAssistPaths)
        {
            try
            {
                using var key = hkcu.OpenSubKey(uaPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var decoded = Rot13Decode(valueName).ToLowerInvariant();
                    foreach (var tool in CheatToolNames)
                    {
                        if (decoded.Contains(tool, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "UserAssist: Cheat Tool Execution History",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\{uaPath}",
                                FileName = Path.GetFileName(decoded.Split('\\').Last()),
                                Reason = $"Cheat tool '{tool}' in UserAssist execution history — confirms tool was run",
                                Detail = $"Decoded path: {decoded}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckMUICacheCheatTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var muiCachePaths = new[]
        {
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache",
        };

        using var hkcu = Registry.CurrentUser;
        foreach (var muiPath in muiCachePaths)
        {
            try
            {
                using var key = hkcu.OpenSubKey(muiPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var nameLower = valueName.ToLowerInvariant();
                    foreach (var tool in CheatToolNames)
                    {
                        if (nameLower.Contains(tool, StringComparison.OrdinalIgnoreCase))
                        {
                            var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "MUICache: Cheat Tool Launch History",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\{muiPath}",
                                FileName = Path.GetFileName(valueName.Split('.')[0]),
                                Reason = $"Cheat tool '{tool}' in MUICache — tool was launched on this system",
                                Detail = $"Key: {valueName}, Value: {val}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckShellBagsCheatPaths(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var shellBagPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\Shell\BagMRU",
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
        };

        using var hkcu = Registry.CurrentUser;
        foreach (var bagPath in shellBagPaths)
        {
            try
            {
                using var key = hkcu.OpenSubKey(bagPath);
                if (key == null) continue;
                ScanShellBagKey(key, bagPath, ctx, ct);
            }
            catch { }
        }
    }, ct);

    private void ScanShellBagKey(RegistryKey key, string path, ScanContext ctx, CancellationToken ct)
    {
        try
        {
            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                foreach (var cheatPath in ShellBagCheatPaths)
                {
                    if (val.Contains(cheatPath, StringComparison.OrdinalIgnoreCase) ||
                        valueName.Contains(cheatPath, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "ShellBag: Cheat Tool Folder Navigation",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{path}",
                            FileName = valueName,
                            Reason = $"ShellBag records navigation to cheat-related folder '{cheatPath}' — user browsed to cheat directory",
                            Detail = $"Value: {val}"
                        });
                        break;
                    }
                }
            }

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var subKey = key.OpenSubKey(subKeyName);
                    if (subKey != null)
                        ScanShellBagKey(subKey, $@"{path}\{subKeyName}", ctx, ct);
                }
                catch { }
            }
        }
        catch { }
    }

    private Task CheckRecentDocumentsCheatFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var recentPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Recent");
        if (!Directory.Exists(recentPath)) return;

        try
        {
            foreach (var file in Directory.EnumerateFiles(recentPath, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                foreach (var kw in RecentDocsCheatKeywords)
                {
                    if (name.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Recent Documents: Cheat File Accessed",
                            Risk = RiskLevel.High, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Recent Documents entry '{name}' contains cheat keyword '{kw}'",
                            Detail = $"LNK: {file}"
                        });
                        break;
                    }
                }

                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var buf = new byte[Math.Min(2048, fs.Length)];
                    await fs.ReadAsync(buf, ct);
                    var content = System.Text.Encoding.Unicode.GetString(buf) + System.Text.Encoding.ASCII.GetString(buf);
                    foreach (var kw in RecentDocsCheatKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Recent Documents LNK: Cheat Target Path",
                                Risk = RiskLevel.High, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Recent LNK file points to cheat-related path ('{kw}')",
                                Detail = $"LNK content contains: {kw}"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
    }, ct);

    private Task CheckLNKFilesCheatTargets(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var lnkSearchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Recent"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Start Menu"),
            Path.Combine(userProfile, "Downloads"),
        };

        foreach (var searchRoot in lnkSearchPaths)
        {
            if (!Directory.Exists(searchRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(searchRoot, "*.lnk", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var lnkName = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    bool hasCheatName = LNKCheatKeywords.Any(k => lnkName.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (hasCheatName)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "LNK File: Cheat Tool Shortcut",
                            Risk = RiskLevel.High, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"LNK shortcut name '{lnkName}' contains cheat keyword — cheat tool was present",
                            Detail = $"Shortcut: {file}"
                        });
                        continue;
                    }

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        var buf = new byte[Math.Min(4096, fs.Length)];
                        await fs.ReadAsync(buf, ct);
                        var asciiContent = System.Text.Encoding.ASCII.GetString(buf);
                        var unicodeContent = System.Text.Encoding.Unicode.GetString(buf);
                        var combined = asciiContent + unicodeContent;

                        foreach (var kw in LNKCheatKeywords)
                        {
                            if (combined.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "LNK File: Points to Cheat Tool Path",
                                    Risk = RiskLevel.High, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"LNK shortcut target path contains cheat keyword '{kw}'",
                                    Detail = $"Shortcut: {file}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckJumpListCheatTargets(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var jumpListPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Recent\AutomaticDestinations"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Recent\CustomDestinations"),
        };

        foreach (var jumpRoot in jumpListPaths)
        {
            if (!Directory.Exists(jumpRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(jumpRoot, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        var buf = new byte[Math.Min(65536, fs.Length)];
                        await fs.ReadAsync(buf, ct);
                        var asciiContent = System.Text.Encoding.ASCII.GetString(buf);
                        var unicodeContent = System.Text.Encoding.Unicode.GetString(buf);
                        var combined = asciiContent + unicodeContent;

                        foreach (var kw in JumpListCheatKeywords)
                        {
                            if (combined.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Jump List: Cheat Tool in Recent Items",
                                    Risk = RiskLevel.High, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Jump list entry contains cheat keyword '{kw}' — cheat tool was recently used",
                                    Detail = $"Jump list: {file}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckRunMRUCheatCommands(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var runMRUPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
        using var hkcu = Registry.CurrentUser;
        try
        {
            using var key = hkcu.OpenSubKey(runMRUPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                foreach (var kw in CheatToolNames)
                {
                    if (val.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Run MRU: Cheat Tool Run Command",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{runMRUPath}",
                            FileName = valueName,
                            Reason = $"Run dialog history contains cheat tool '{kw}' — user ran cheat tool directly",
                            Detail = $"Command: {val}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckAppPathsCheatTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var appPathsRoot = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var hive in new[] { hkcu, hklm })
        {
            try
            {
                using var key = hive.OpenSubKey(appPathsRoot);
                if (key == null) continue;
                foreach (var appName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var appNameLower = appName.ToLowerInvariant();
                    foreach (var tool in CheatToolNames)
                    {
                        if (appNameLower.Contains(tool, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementRegistryKeys();
                            try
                            {
                                using var appKey = key.OpenSubKey(appName);
                                var appPath = appKey?.GetValue(null)?.ToString() ?? string.Empty;
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "App Paths: Cheat Tool Registered",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKLM\{appPathsRoot}\{appName}",
                                    FileName = appName,
                                    Reason = $"Cheat tool '{tool}' registered in App Paths — was installed as application",
                                    Detail = $"Path: {appPath}"
                                });
                            }
                            catch { }
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckTypedPathsCheatURLs(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var typedPathsRoot = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths";
        using var hkcu = Registry.CurrentUser;
        try
        {
            using var key = hkcu.OpenSubKey(typedPathsRoot);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                foreach (var kw in ShellBagCheatPaths)
                {
                    if (val.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Explorer Typed Paths: Cheat Directory Typed",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{typedPathsRoot}",
                            FileName = valueName,
                            Reason = $"Cheat path '{kw}' typed in Explorer address bar — user navigated to cheat directory",
                            Detail = $"Typed path: {val}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckOpenSaveMRUCheatFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var openSaveMRURoot = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU";
        var openSavePathMRU = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU";
        using var hkcu = Registry.CurrentUser;

        foreach (var mruPath in new[] { openSaveMRURoot, openSavePathMRU })
        {
            try
            {
                using var rootKey = hkcu.OpenSubKey(mruPath);
                if (rootKey == null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var extName in rootKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var extKey = rootKey.OpenSubKey(extName);
                        if (extKey == null) continue;
                        foreach (var valueName in extKey.GetValueNames())
                        {
                            var val = extKey.GetValue(valueName)?.ToString() ?? string.Empty;
                            foreach (var kw in RecentDocsCheatKeywords)
                            {
                                if (val.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "Open/Save MRU: Cheat File Dialog History",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKCU\{mruPath}\{extName}",
                                        FileName = valueName,
                                        Reason = $"Open/Save dialog history shows cheat-related file '{kw}' was opened/saved",
                                        Detail = $"Value: {val}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckLastVisitedMRUCheatPaths(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var lvMRUPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU";
        using var hkcu = Registry.CurrentUser;
        try
        {
            using var key = hkcu.OpenSubKey(lvMRUPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                foreach (var kw in LNKCheatKeywords)
                {
                    if (val.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "LastVisited MRU: Cheat Tool Dialog Path",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{lvMRUPath}",
                            FileName = valueName,
                            Reason = $"Last visited folder dialog shows cheat path '{kw}'",
                            Detail = $"Value: {val}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckWindowsSearchHistoryCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchHistoryPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"Microsoft\Windows\Explorer");

        if (!Directory.Exists(searchHistoryPath)) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(searchHistoryPath, "*.db", SearchOption.TopDirectoryOnly)
                .Concat(Directory.EnumerateFiles(searchHistoryPath, "*.log", SearchOption.TopDirectoryOnly)))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var buf = new byte[Math.Min(1024 * 1024, fs.Length)];
                    await fs.ReadAsync(buf, ct);
                    var content = System.Text.Encoding.Unicode.GetString(buf) + System.Text.Encoding.ASCII.GetString(buf);
                    foreach (var kw in JumpListCheatKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Windows Search History: Cheat Tool Search",
                                Risk = RiskLevel.High, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Windows Explorer search history contains cheat keyword '{kw}'",
                                Detail = $"File: {file}"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
    }, ct);

    private Task CheckPinnedJumpListCheatTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var customDestPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\Recent\CustomDestinations");
        if (!Directory.Exists(customDestPath)) return;

        try
        {
            foreach (var file in Directory.EnumerateFiles(customDestPath, "*.customDestinations-ms"))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var buf = new byte[Math.Min(65536, fs.Length)];
                    await fs.ReadAsync(buf, ct);
                    var content = System.Text.Encoding.Unicode.GetString(buf);
                    foreach (var kw in JumpListCheatKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Pinned Jump List: Cheat Tool Pinned",
                                Risk = RiskLevel.High, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cheat keyword '{kw}' in pinned jump list — cheat tool was pinned to taskbar",
                                Detail = $"CustomDestinations: {file}"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
    }, ct);

    private Task CheckStartMenuCheatShortcuts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var startMenuPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\Start Menu"),
        };

        foreach (var startRoot in startMenuPaths)
        {
            if (!Directory.Exists(startRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(startRoot, "*.lnk", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    foreach (var kw in LNKCheatKeywords)
                    {
                        if (name.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Start Menu: Cheat Tool Shortcut",
                                Risk = RiskLevel.High, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cheat tool shortcut '{name}' in Start Menu — cheat tool was installed",
                                Detail = $"Shortcut: {file}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
        return Task.CompletedTask;
    }, ct);

    private Task CheckDesktopShortcutsCheat(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        if (!Directory.Exists(desktopPath)) return Task.CompletedTask;
        try
        {
            foreach (var file in Directory.EnumerateFiles(desktopPath, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                foreach (var kw in LNKCheatKeywords)
                {
                    if (name.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Desktop: Cheat Tool Shortcut",
                            Risk = RiskLevel.High, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Cheat shortcut '{name}' on Desktop — cheat tool was present",
                            Detail = $"Shortcut: {file}"
                        });
                        break;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
        return Task.CompletedTask;
    }, ct);

    private Task CheckBrowserBookmarksCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var bookmarkFiles = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "Bookmarks"),
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "Bookmarks"),
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Bookmarks"),
            Path.Combine(appData, "Mozilla", "Firefox", "Profiles"),
        };

        var cheatSiteKeywords = new[]
        {
            "cheat", "hack", "bypass", "modmenu", "aimbot", "esp",
            "kiddion", "eulen", "2take1", "stand", "cherax", "outbreak",
            "fivem cheat", "ragemp cheat", "altv cheat", "undetected",
            "hwid spoofer", "hwid reset", "unban", "injection",
        };

        foreach (var bookmarkFile in bookmarkFiles)
        {
            if (!File.Exists(bookmarkFile)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(bookmarkFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                var content = await sr.ReadToEndAsync(ct);
                foreach (var kw in cheatSiteKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Browser Bookmarks: Cheat Site Bookmarked",
                            Risk = RiskLevel.High, Location = bookmarkFile,
                            FileName = Path.GetFileName(bookmarkFile),
                            Reason = $"Cheat keyword '{kw}' in browser bookmarks — cheat site was bookmarked",
                            Detail = content.Length > 300 ? content[..300] : content
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckUserAssistCounters(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var uaPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count";
        using var hkcu = Registry.CurrentUser;
        try
        {
            using var key = hkcu.OpenSubKey(uaPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                var decoded = Rot13Decode(valueName).ToLowerInvariant();
                var antiForensicTools = new[] { "eraser", "bleachbit", "privazer", "ccleaner", "fileshredder" };
                foreach (var tool in antiForensicTools)
                {
                    if (decoded.Contains(tool, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "UserAssist: Anti-Forensic Tool Run Count",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{uaPath}",
                            FileName = Path.GetFileName(decoded.Split('\\').Last()),
                            Reason = $"Anti-forensic tool '{tool}' in UserAssist — confirms tool was executed",
                            Detail = $"Decoded: {decoded}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckRecentApplicationsCheat(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentAppsPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store";
        using var hkcu = Registry.CurrentUser;
        try
        {
            using var key = hkcu.OpenSubKey(recentAppsPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                var nameLower = valueName.ToLowerInvariant();
                foreach (var tool in CheatToolNames)
                {
                    if (nameLower.Contains(tool, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "AppCompat Store: Cheat Tool Compatibility Entry",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{recentAppsPath}",
                            FileName = Path.GetFileName(valueName),
                            Reason = $"Cheat tool '{tool}' in AppCompat store — confirms application was executed",
                            Detail = $"Entry: {valueName}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);
}
