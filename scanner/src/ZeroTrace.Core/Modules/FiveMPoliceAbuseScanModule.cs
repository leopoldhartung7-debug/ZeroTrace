using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMPoliceAbuseScanModule : IScanModule
{
    public string Name => "FiveM-PoliceAbuse";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string[] PoliceAbuseScriptFileNames =
    {
        "policeAbuse.lua", "policeAbuse.js", "policeHack.lua", "policeHack.js",
        "copHack.lua", "copHack.js", "copHack.dll", "copHackLoader.exe",
        "arrestAbuse.lua", "arrestAbuse.js", "arrestAbuse.exe",
        "warrant_exploit.lua", "warrant_exploit.js", "warrant_exploit.exe",
        "evidence_plant.lua", "evidence_plant.js",
        "policeMenu.lua", "policeMenu.js", "policeMenu_hack.lua",
        "mdt_exploit.lua", "mdt_exploit.js", "mdt_exploit.exe",
        "mdt_hack.lua", "mdt_hack.js", "mdt_hack.exe",
        "police_corruption.lua", "police_corruption.js",
        "fakeWarrant.lua", "fakeWarrant.js", "fakeWarrant.exe",
        "FakeMDT.exe", "FakeMDT.lua",
        "ArrestAbuser.exe", "ArrestAbuse.exe",
        "WarrantExploit.exe", "WarrantExploit.lua",
        "MDT_Hack.exe", "MDT_Hack.dll",
        "PoliceAbuseTool.exe", "PoliceAbuseTool.dll",
        "policeScriptHack.lua", "policeScriptAbuse.lua",
        "illegalArrest.lua", "fakeArrest.lua",
        "corruptEvidence.lua", "plant_evidence.lua",
    };

    private static readonly string[] PoliceAbuseWildcardPrefixes =
    {
        "copHack", "arrestAbuse", "warrant_exploit", "evidence_plant",
        "policeMenu", "mdt_exploit", "mdt_hack", "police_corruption",
        "policeHack", "policeAbuse",
    };

    private static readonly string[] PoliceAbuseLogKeywords =
    {
        "police abuse", "fake warrant", "evidence plant", "arrest exploit",
        "illegal arrest", "cop hack", "mdt exploit", "police script abuse",
        "fakeArrest", "arrestPlayer bypass", "gdnc_mdt exploit",
        "police_menu hack", "removeAllWeapons police", "setPlayerWanted abuse",
        "corrupt evidence", "warrant bypass", "police corruption exploit",
        "mdt hack", "police menu exploit",
    };

    private static readonly string[] LuaJsKeywordPatterns =
    {
        "setPlayerWanted", "removeAllWeapons police", "fakeArrest",
        "gdnc_mdt exploit", "police_menu hack", "arrestPlayer bypass",
        "TriggerEvent(\"police", "TriggerEvent('police",
        "exports[\"mdt", "exports['mdt",
        "fakeWarrant", "evidencePlant", "plantEvidence",
        "illegalArrest", "corruptEvidence",
        "police_corruption", "policeAbuse", "mdtExploit",
        "copHack", "arrestAbuse", "warrantExploit",
        "SetPedWantedLevel(", "AddBlipForRadius(",
        "NetworkGetPlayerName(PlayerId())", "GetPlayerServerId(",
        "TriggerServerEvent(\"esx:setJob", "TriggerServerEvent('esx:setJob",
        "TriggerServerEvent(\"qb-policejob", "TriggerServerEvent('qb-policejob",
        "police_job:addEvidence", "police:plantEvidence",
        "arrest:bypass", "warrant:fake", "mdt:spoof",
    };

    private static readonly string[] KnownPoliceAbuseExecutables =
    {
        "MDT_Hack.exe", "PoliceAbuseTool.exe", "FakeMDT.exe",
        "WarrantExploit.exe", "ArrestAbuser.exe", "ArrestAbuse.exe",
        "copHackLoader.exe", "policeHack.exe", "policeAbuseLoader.exe",
        "mdt_exploit.exe", "police_corruption.exe", "FakeArrestTool.exe",
    };

    private static readonly string[] DiscordPoliceAbuseKeywords =
    {
        "police abuse", "fivem police hack", "mdt hack", "mdt exploit",
        "fake warrant", "arrest exploit", "cop hack fivem",
        "police menu exploit", "evidence plant fivem", "illegal arrest fivem",
        "police corruption script", "warrant spoof", "fivem cop abuse",
        "police script leak", "mdt spoof", "arrest bypass fivem",
    };

    private static readonly string[] CefCachePoliceKeywords =
    {
        "policeAbuse", "mdt_hack", "fakeWarrant", "arrestExploit",
        "police_corruption", "copHack", "mdt_exploit", "evidence_plant",
        "illegalArrest", "policeMenu_hack",
    };

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting FiveM police-abuse artifact scan...");

        await Task.WhenAll(
            CheckFiveMCacheDirs(ctx, ct),
            CheckAppDataScriptFiles(ctx, ct),
            CheckLogFilesForKeywords(ctx, ct),
            CheckRegistryKeys(ctx, ct),
            CheckTempAndAppDataTools(ctx, ct),
            CheckUserAssistForPoliceAbuseExes(ctx, ct),
            CheckDiscordCacheForPoliceAbuseKeywords(ctx, ct),
            CheckPrefetchForPoliceAbuseExes(ctx, ct),
            CheckRecentDocsForPoliceAbuseScripts(ctx, ct),
            CheckFiveMResourceDirsForLuaJs(ctx, ct),
            CheckCefBrowserCacheForPoliceAbuse(ctx, ct)
        );

        ctx.Report(1.0, Name, "FiveM police-abuse scan complete.");
    }

    private Task CheckFiveMCacheDirs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var candidateDirs = new List<string>
        {
            Path.Combine(appdata, "citizenfx"),
            Path.Combine(localappdata, "FiveM"),
            Path.Combine(localappdata, "FiveM", "FiveM.app"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "cache"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "data"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "citizen"),
            Path.Combine(localappdata, "FiveM", "cache"),
            Path.Combine(localappdata, "FiveM", "data"),
            Path.Combine(appdata, "citizenfx", "logs"),
            Path.Combine(appdata, "citizenfx", "cache"),
        };

        foreach (var dir in candidateDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);

                if (IsKnownPoliceAbuseFile(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM police-abuse script file: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Known police-abuse script file '{fileName}' found in FiveM cache directory '{dir}'. " +
                                 "These files are artifacts left by tools used to abuse FiveM police scripts, " +
                                 "including fake warrants, illegal arrests, and MDT exploitation.",
                        Detail = $"Directory: {dir} | File: {file}"
                    });
                    continue;
                }

                bool isLuaOrJs = ext.Equals(".lua", StringComparison.OrdinalIgnoreCase)
                              || ext.Equals(".luac", StringComparison.OrdinalIgnoreCase)
                              || ext.Equals(".js", StringComparison.OrdinalIgnoreCase);

                if (!isLuaOrJs) continue;

                try
                {
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException)
                    {
                        continue;
                    }

                    foreach (var keyword in LuaJsKeywordPatterns)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"FiveM police-abuse keyword in script: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Script file '{fileName}' in FiveM cache contains police-abuse keyword '{keyword}'. " +
                                         "This pattern is consistent with scripts used to exploit FiveM police jobs, " +
                                         "including fake arrests, MDT manipulation, and warrant spoofing.",
                                Detail = $"Keyword: {keyword} | Path: {file}"
                            });
                            break;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckAppDataScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();

        var searchRoots = new[]
        {
            appdata,
            localappdata,
            temp,
            Path.Combine(appdata, "citizenfx"),
            Path.Combine(localappdata, "FiveM"),
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                if (!IsKnownPoliceAbuseFile(fileName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Police-abuse tool file in AppData: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known police-abuse file '{fileName}' found in AppData/Temp at '{file}'. " +
                             "This is a forensic artifact left by a FiveM police-abuse tool.",
                    Detail = $"Root scanned: {root}"
                });
            }

            IEnumerable<string> subDirs;
            try
            {
                subDirs = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var subDir in subDirs)
            {
                if (ct.IsCancellationRequested) return;
                var dirName = Path.GetFileName(subDir);

                bool isSuspiciousDir = KnownPoliceAbuseExecutables.Any(e =>
                        Path.GetFileNameWithoutExtension(e).Equals(dirName, StringComparison.OrdinalIgnoreCase))
                    || dirName.Contains("MDT_Hack", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("PoliceAbuse", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("FakeMDT", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("WarrantExploit", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("ArrestAbuser", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("copHack", StringComparison.OrdinalIgnoreCase)
                    || dirName.Contains("policeHack", StringComparison.OrdinalIgnoreCase);

                if (isSuspiciousDir)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Police-abuse tool directory in AppData: {dirName}",
                        Risk = RiskLevel.High,
                        Location = subDir,
                        FileName = dirName,
                        Reason = $"Directory '{dirName}' found in AppData at '{subDir}' matches known police-abuse tool directory naming. " +
                                 "These directories are created by tools used to abuse FiveM police frameworks.",
                        Detail = $"Parent: {root} | Suspicious dir: {subDir}"
                    });
                }

                IEnumerable<string> subFiles;
                try
                {
                    subFiles = Directory.EnumerateFiles(subDir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var subFile in subFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var subFileName = Path.GetFileName(subFile);
                    if (!IsKnownPoliceAbuseFile(subFileName)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Police-abuse script in AppData subdir: {subFileName}",
                        Risk = RiskLevel.High,
                        Location = subFile,
                        FileName = subFileName,
                        Reason = $"Known police-abuse script file '{subFileName}' found in AppData subdirectory '{subDir}'. " +
                                 "This is a forensic artifact from a FiveM police-abuse tool.",
                        Detail = $"Parent dir: {subDir}"
                    });
                }

                await Task.Yield();
            }
        }
    }, ct);

    private Task CheckLogFilesForKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var logDirs = new[]
        {
            Path.Combine(appdata, "citizenfx"),
            Path.Combine(appdata, "citizenfx", "logs"),
            Path.Combine(localappdata, "FiveM"),
            Path.Combine(localappdata, "FiveM", "FiveM.app"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "logs"),
            Path.Combine(localappdata, "FiveM", "logs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Local", "FiveM"),
        };

        foreach (var logDir in logDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(logDir)) continue;

            IEnumerable<string> logFiles;
            try
            {
                logFiles = Directory.EnumerateFiles(logDir, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f);
                        return ext.Equals(".log", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".txt", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".json", StringComparison.OrdinalIgnoreCase);
                    });
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                foreach (var keyword in PoliceAbuseLogKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Police-abuse keyword in FiveM log: {Path.GetFileName(logFile)}",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"FiveM log file '{logFile}' contains police-abuse keyword '{keyword}'. " +
                                     "Log entries referencing police exploitation indicate usage or attempted usage " +
                                     "of police-abuse tools on FiveM servers.",
                            Detail = $"Keyword matched: {keyword} | Log: {logFile}"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckRegistryKeys(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var regPaths = new[]
        {
            (@"Software\FiveM\PoliceAbuse", Registry.CurrentUser),
            (@"Software\Scripts\PoliceHack", Registry.CurrentUser),
            (@"Software\FiveM\MDTExploit", Registry.CurrentUser),
            (@"Software\FiveM\WarrantExploit", Registry.CurrentUser),
            (@"Software\FiveM\ArrestAbuse", Registry.CurrentUser),
            (@"Software\FiveM\CopHack", Registry.CurrentUser),
            (@"Software\FiveM\PoliceMenu", Registry.CurrentUser),
            (@"Software\PoliceAbuseTool", Registry.CurrentUser),
            (@"Software\MDT_Hack", Registry.CurrentUser),
            (@"Software\FakeMDT", Registry.CurrentUser),
            (@"Software\WarrantExploit", Registry.CurrentUser),
            (@"Software\ArrestAbuser", Registry.CurrentUser),
            (@"Software\FiveM\PoliceAbuse", Registry.LocalMachine),
            (@"Software\Scripts\PoliceHack", Registry.LocalMachine),
            (@"Software\MDT_Hack", Registry.LocalMachine),
            (@"Software\PoliceAbuseTool", Registry.LocalMachine),
        };

        foreach (var (path, hive) in regPaths)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = hive.OpenSubKey(path, writable: false);
                if (key is null) continue;

                var hiveName = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Police-abuse registry key: {Path.GetFileName(path)}",
                    Risk = RiskLevel.High,
                    Location = $@"{hiveName}\{path}",
                    Reason = $"Registry key '{hiveName}\\{path}' associated with FiveM police-abuse tools found. " +
                             "This key is a forensic remnant of a police-abuse tool installation.",
                    Detail = $"Full path: {hiveName}\\{path} | Value count: {key.ValueCount}"
                });
            }
            catch { }
        }

        var muiCachePath = @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        try
        {
            ctx.IncrementRegistryKeys();
            using var muiKey = Registry.CurrentUser.OpenSubKey(muiCachePath, writable: false);
            if (muiKey is not null)
            {
                foreach (var valueName in muiKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    bool isPoliceAbuse = KnownPoliceAbuseExecutables.Any(e =>
                        valueName.Contains(e, StringComparison.OrdinalIgnoreCase));

                    if (!isPoliceAbuse)
                    {
                        isPoliceAbuse = PoliceAbuseWildcardPrefixes.Any(p =>
                            valueName.Contains(p, StringComparison.OrdinalIgnoreCase));
                    }

                    if (!isPoliceAbuse) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"MuiCache: Police-abuse tool execution trace: {Path.GetFileName(valueName)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{muiCachePath}",
                        FileName = Path.GetFileName(valueName),
                        Reason = $"MuiCache entry '{valueName}' indicates execution of a police-abuse tool. " +
                                 "MuiCache persists program execution history even after deletion.",
                        Detail = $"MuiCache value: {valueName}"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckTempAndAppDataTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchDirs = new List<string>
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                bool isKnownTool = KnownPoliceAbuseExecutables.Any(e =>
                    fileName.Equals(e, StringComparison.OrdinalIgnoreCase));

                bool isWildcardMatch = PoliceAbuseWildcardPrefixes.Any(p =>
                    fileName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                if (!isKnownTool && !isWildcardMatch) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Police-abuse tool artifact: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known FiveM police-abuse tool '{fileName}' found in '{dir}'. " +
                             "This is a forensic artifact from a tool used to abuse FiveM police scripts " +
                             "(fake warrants, illegal arrests, MDT exploitation, evidence planting).",
                    Detail = $"Matched pattern: {(isKnownTool ? "exact filename" : "wildcard prefix")} | Path: {file}"
                });
            }
        }
    }, ct);

    private Task CheckUserAssistForPoliceAbuseExes(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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

                        var decoded = Rot13Decode(encodedName);
                        var decodedLower = decoded.ToLowerInvariant();

                        bool isPoliceAbuseTool = KnownPoliceAbuseExecutables.Any(e =>
                            decodedLower.Contains(e.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));

                        if (!isPoliceAbuseTool)
                        {
                            isPoliceAbuseTool = PoliceAbuseWildcardPrefixes.Any(p =>
                                decodedLower.Contains(p.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));
                        }

                        if (!isPoliceAbuseTool) continue;

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
                            Module = Name,
                            Title = $"UserAssist: Police-abuse tool executed: {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"Windows UserAssist entry shows execution of police-abuse tool '{Path.GetFileName(decoded)}' " +
                                     $"({runCount} time(s)" +
                                     (lastRun.HasValue ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                     "). UserAssist entries persist after the binary is deleted.",
                            Detail = $"Decoded path: {decoded} | Run count: {runCount} | " +
                                     $"Last run: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckDiscordCacheForPoliceAbuseKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var discordClients = new[] { "discord", "discordptb", "discordcanary" };

        foreach (var client in discordClients)
        {
            if (ct.IsCancellationRequested) return;
            var discordRoot = Path.Combine(appdata, client);
            if (!Directory.Exists(discordRoot)) continue;

            var cacheDirs = new[]
            {
                Path.Combine(discordRoot, "Cache", "Cache_Data"),
                Path.Combine(discordRoot, "Cache"),
                Path.Combine(discordRoot, "Local Storage", "leveldb"),
                Path.Combine(discordRoot, "Session Storage"),
                Path.Combine(discordRoot, "Code Cache", "js"),
            };

            foreach (var cacheDir in cacheDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(cacheDir)) continue;

                IEnumerable<string> cacheFiles;
                try
                {
                    cacheFiles = Directory.EnumerateFiles(cacheDir).Take(120);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var cacheFile in cacheFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fi = new FileInfo(cacheFile);
                    if (fi.Length > 10 * 1024 * 1024) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException)
                    {
                        continue;
                    }

                    foreach (var keyword in DiscordPoliceAbuseKeywords)
                    {
                        if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Discord cache: Police-abuse server keyword found",
                            Risk = RiskLevel.Medium,
                            Location = cacheFile,
                            FileName = Path.GetFileName(cacheFile),
                            Reason = $"Discord cache file in '{cacheDir}' contains police-abuse keyword '{keyword}'. " +
                                     "This suggests membership or activity in a Discord server distributing " +
                                     "FiveM police-abuse tools.",
                            Detail = $"Client: {client} | Keyword: {keyword} | Cache: {cacheDir}"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckPrefetchForPoliceAbuseExes(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        IEnumerable<string> pfFiles;
        try
        {
            pfFiles = Directory.EnumerateFiles(prefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var pfFile in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(pfFile);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            bool isPoliceAbuse = KnownPoliceAbuseExecutables.Any(e =>
                exeName.Equals(Path.GetFileNameWithoutExtension(e), StringComparison.OrdinalIgnoreCase));

            if (!isPoliceAbuse)
            {
                isPoliceAbuse = PoliceAbuseWildcardPrefixes.Any(p =>
                    exeName.StartsWith(p, StringComparison.OrdinalIgnoreCase));
            }

            if (!isPoliceAbuse) continue;

            DateTime? lastWrite = null;
            try { lastWrite = File.GetLastWriteTimeUtc(pfFile); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Prefetch: Police-abuse tool executed: {exeName}.exe",
                Risk = RiskLevel.High,
                Location = pfFile,
                FileName = exeName + ".exe",
                Reason = $"Prefetch file indicates execution of police-abuse tool '{exeName}.exe'. " +
                         "Prefetch records persist even after the executable is deleted.",
                Detail = $"Prefetch file: {pfFile}" +
                         (lastWrite.HasValue ? $" | Last write: {lastWrite.Value:yyyy-MM-dd HH:mm} UTC" : "")
            });
        }
    }, ct);

    private Task CheckRecentDocsForPoliceAbuseScripts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string recentDocsPath =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";

        try
        {
            using var recentKey = Registry.CurrentUser.OpenSubKey(recentDocsPath, writable: false);
            if (recentKey is null) return;

            foreach (var subKeyName in recentKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var subKey = recentKey.OpenSubKey(subKeyName, writable: false);
                    if (subKey is null) continue;

                    foreach (var valueName in subKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var data = subKey.GetValue(valueName) as byte[];
                        if (data is null || data.Length < 2) continue;

                        string decoded;
                        try
                        {
                            decoded = Encoding.Unicode.GetString(data)
                                .TrimEnd('\0').Trim();
                        }
                        catch { continue; }

                        bool isPoliceAbuse = PoliceAbuseScriptFileNames.Any(s =>
                            decoded.Contains(s, StringComparison.OrdinalIgnoreCase));

                        if (!isPoliceAbuse)
                        {
                            isPoliceAbuse = PoliceAbuseWildcardPrefixes.Any(p =>
                                decoded.Contains(p, StringComparison.OrdinalIgnoreCase));
                        }

                        if (!isPoliceAbuse) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RecentDocs: Police-abuse script referenced: {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKCU\{recentDocsPath}\{subKeyName}",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"RecentDocs registry entry references police-abuse script '{decoded}'. " +
                                     "This indicates the file was recently opened or accessed on this machine.",
                            Detail = $"Decoded value: {decoded} | Subkey: {subKeyName}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        var recentDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "Recent");

        if (!Directory.Exists(recentDir)) return;

        IEnumerable<string> lnkFiles;
        try
        {
            lnkFiles = Directory.EnumerateFiles(recentDir, "*.lnk");
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var lnk in lnkFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var lnkName = Path.GetFileNameWithoutExtension(lnk);

            bool isPoliceAbuse = PoliceAbuseScriptFileNames.Any(s =>
                lnkName.Contains(Path.GetFileNameWithoutExtension(s), StringComparison.OrdinalIgnoreCase));

            if (!isPoliceAbuse)
            {
                isPoliceAbuse = PoliceAbuseWildcardPrefixes.Any(p =>
                    lnkName.Contains(p, StringComparison.OrdinalIgnoreCase));
            }

            if (!isPoliceAbuse) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Recent docs shortcut: Police-abuse script: {lnkName}",
                Risk = RiskLevel.Medium,
                Location = lnk,
                FileName = lnkName,
                Reason = $"Windows Recent Documents shortcut '{lnkName}.lnk' references a police-abuse script. " +
                         "This artifact persists after the script file is deleted.",
                Detail = $"Shortcut: {lnk}"
            });
        }
    }, ct);

    private Task CheckFiveMResourceDirsForLuaJs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var resourceRoots = new[]
        {
            Path.Combine(localappdata, "FiveM", "FiveM.app", "cache", "priv"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "cache", "game"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "citizen", "resources"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "data", "cache", "mods"),
            Path.Combine(appdata, "citizenfx", "server-cache"),
            Path.Combine(appdata, "citizenfx", "plugins"),
        };

        foreach (var resourceRoot in resourceRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(resourceRoot)) continue;

            IEnumerable<string> scripts;
            try
            {
                scripts = Directory.EnumerateFiles(resourceRoot, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f);
                        return ext.Equals(".lua", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".luac", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".js", StringComparison.OrdinalIgnoreCase);
                    });
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var scriptFile in scripts)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var scriptName = Path.GetFileName(scriptFile);

                if (IsKnownPoliceAbuseFile(scriptName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known police-abuse script in FiveM resources: {scriptName}",
                        Risk = RiskLevel.High,
                        Location = scriptFile,
                        FileName = scriptName,
                        Reason = $"Known police-abuse script '{scriptName}' found in FiveM resource directory '{resourceRoot}'. " +
                                 "This file is a direct artifact of police-abuse scripting tools.",
                        Detail = $"Resource root: {resourceRoot}"
                    });
                    continue;
                }

                string content;
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                foreach (var keyword in LuaJsKeywordPatterns)
                {
                    if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Police-abuse pattern in FiveM resource script: {scriptName}",
                        Risk = RiskLevel.High,
                        Location = scriptFile,
                        FileName = scriptName,
                        Reason = $"FiveM resource script '{scriptName}' contains police-abuse pattern '{keyword}'. " +
                                 "This keyword is associated with scripts used to exploit police job frameworks, " +
                                 "manipulate MDT systems, or perform fake arrests.",
                        Detail = $"Keyword: {keyword} | Script: {scriptFile} | Resource root: {resourceRoot}"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckCefBrowserCacheForPoliceAbuse(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var cefCacheDirs = new[]
        {
            Path.Combine(localappdata, "FiveM", "FiveM.app", "cache", "browser"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "data", "cache", "browser"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "cache", "web-cache"),
            Path.Combine(localappdata, "FiveM", "CEF"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "CEF"),
            Path.Combine(localappdata, "FiveM", "FiveM.app", "cache", "http"),
        };

        foreach (var cefDir in cefCacheDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(cefDir)) continue;

            IEnumerable<string> cefFiles;
            try
            {
                cefFiles = Directory.EnumerateFiles(cefDir, "*", SearchOption.AllDirectories).Take(200);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var cefFile in cefFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fi = new FileInfo(cefFile);
                if (fi.Length > 5 * 1024 * 1024) continue;

                string content;
                try
                {
                    using var fs = new FileStream(cefFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                foreach (var keyword in CefCachePoliceKeywords)
                {
                    if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CEF cache: Police-abuse script reference found",
                        Risk = RiskLevel.Medium,
                        Location = cefFile,
                        FileName = Path.GetFileName(cefFile),
                        Reason = $"FiveM CEF/browser cache file contains police-abuse keyword '{keyword}'. " +
                                 "This indicates the FiveM NUI browser loaded or accessed a police-abuse " +
                                 "script or resource at some point.",
                        Detail = $"CEF dir: {cefDir} | Keyword: {keyword} | File: {cefFile}"
                    });
                    break;
                }
            }
        }
    }, ct);

    private static bool IsKnownPoliceAbuseFile(string fileName)
    {
        if (PoliceAbuseScriptFileNames.Any(s =>
            fileName.Equals(s, StringComparison.OrdinalIgnoreCase)))
            return true;

        var fileNameNoExt = Path.GetFileNameWithoutExtension(fileName);
        if (PoliceAbuseWildcardPrefixes.Any(p =>
            fileNameNoExt.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            return true;

        if (KnownPoliceAbuseExecutables.Any(e =>
            fileName.Equals(e, StringComparison.OrdinalIgnoreCase)))
            return true;

        return false;
    }
}
