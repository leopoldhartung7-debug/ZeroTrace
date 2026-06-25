using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AltVResourceInjectionScanModule : IScanModule
{
    public string Name => "alt:V Resource Injection Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);

    private static readonly string[] AltVRoots;

    static AltVResourceInjectionScanModule()
    {
        var roots = new List<string>
        {
            Path.Combine(LocalApp, "altv"),
            Path.Combine(AppData, "altv"),
            Path.Combine(LocalApp, "alt-v"),
            Path.Combine(AppData, "alt-v"),
        };
        AltVRoots = roots.ToArray();
    }

    // Known proxy/hijack DLL names found in the alt:V root
    private static readonly string[] ProxyDllNames =
    {
        "dinput8.dll",
        "version.dll",
        "d3d11.dll",
        "d3d9.dll",
        "d3d10.dll",
        "dxgi.dll",
        "winmm.dll",
        "winhttp.dll",
        "dsound.dll",
        "opengl32.dll",
        "ws2_32.dll",
        "msacm32.dll",
        "msvfw32.dll",
        "avrt.dll",
        "wsock32.dll",
        "msvcr100.dll",
        "xinput1_3.dll",
        "xinput9_1_0.dll",
        "steam_api.dll",
        "steam_api64.dll",
        "tier0.dll",
        "vstdlib.dll",
        "user32.dll",
        "ntdll.dll",
        "kernel32.dll",
    };

    // Known malicious resource folder names
    private static readonly string[] MaliciousResourceNames =
    {
        "menu",
        "hack_resources",
        "executor",
        "lua_executor",
        "bypass_resource",
        "cheat_resource",
        "inject_resource",
        "exploit_resource",
        "speedhack",
        "godmode",
        "aimbot_resource",
        "esp_resource",
        "radar_resource",
        "spinbot",
        "norecoil",
        "triggerbot",
        "bhop",
        "bunnyhop",
        "wallhack",
        "freecam",
        "invisibility",
        "teleport_hack",
        "vehicle_hack",
        "money_hack",
        "weapon_hack",
        "player_hack",
        "anti_kick",
        "crash_resource",
        "grief_resource",
        "spammer",
    };

    // JavaScript cheat API patterns (30+)
    private static readonly string[] JsCheatPatterns =
    {
        // alt:V native/API abuse
        "alt.emit(",
        "alt.on(",
        "native.invoke(",
        "mp.game.invoke(",
        "CAPI.",
        "natives.",
        "invokeNative(",
        "alt.getResourceExports(",
        "alt.log(",
        // CEF / WebView injection
        "alt.WebView(",
        "new WebView(",
        "webView.emit(",
        "webView.on(",
        "webView.load(",
        "cef.create(",
        // Memory / process manipulation
        "alt.getMeta(",
        "alt.setMeta(",
        "alt.LocalPlayer",
        "alt.Player.local",
        // Network manipulation
        "net.connect(",
        "net.createServer(",
        "require('net')",
        "require(\"net\")",
        "require('http')",
        "require(\"http\")",
        "require('https')",
        "require(\"https\")",
        // Obfuscation
        "eval(atob(",
        "eval(btoa(",
        "Function(atob(",
        "Function(btoa(",
        "atob(unescape(",
        "String.fromCharCode(",
        "\\u0065\\u0076\\u0061\\u006c",
        // Process injection markers
        "VirtualAllocEx",
        "WriteProcessMemory",
        "NtWriteVirtualMemory",
        "CreateRemoteThread",
        // Cheat functionality
        "setEntityCoords(",
        "setEntityHealth(",
        "setEntityInvincible(",
        "setPlayerWantedLevel(",
        "addExplosion(",
        "giveWeaponToPed(",
        "networkResurrect(",
        // External fetch to non-altv servers
        "fetch('http",
        "fetch(\"http",
        "XMLHttpRequest(",
        "axios.get(",
        "axios.post(",
    };

    // Suspicious byte strings to search inside DLL assemblies
    private static readonly string[] SuspiciousDllStrings =
    {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "Assembly.Load",
        "Assembly.LoadFrom",
        "Assembly.LoadFile",
        "ReflectionOnlyLoad",
        "Marshal.Copy",
        "Marshal.AllocHGlobal",
        "GetProcAddress",
        "LoadLibrary",
        "SetWindowsHookEx",
        "NtOpenProcess",
        "OpenProcess",
        "DebugActiveProcess",
        "CheckRemoteDebuggerPresent",
        "IsDebuggerPresent",
        "ZwQueryInformationProcess",
        "LdrLoadDll",
        "RtlCreateUserThread",
        "MinHook",
        "Detours",
        "InlineHook",
        "x86Instruction",
        "shellcode",
        "cobalt_strike",
    };

    // altv.toml suspicious config patterns
    private static readonly string[] SuspiciousTomlPatterns =
    {
        "branch = \"internal\"",
        "branch = \"dev\"",
        "enableDevTools = true",
        "disable-security",
        "noVerify",
        "skipVerify",
        "debugMode = true",
        "serverip",
        "customcdn",
        "allow-insecure",
        "altv.pw",
        "altv.mp",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>();

        foreach (var root in AltVRoots)
        {
            if (!Directory.Exists(root)) continue;

            tasks.Add(CheckResourceManifests(ctx, root, ct));
            tasks.Add(CheckJavaScriptFiles(ctx, root, ct));
            tasks.Add(CheckPluginAssemblies(ctx, root, ct));
            tasks.Add(CheckProxyDlls(ctx, root, ct));
            tasks.Add(CheckMaliciousResourceFolders(ctx, root, ct));
            tasks.Add(CheckAltVConfig(ctx, root, ct));
            tasks.Add(CheckUpdateFileSizes(ctx, root, ct));
            tasks.Add(CheckCefInjectionHtml(ctx, root, ct));
            tasks.Add(CheckSuspiciousAltVSubdirectories(ctx, root, ct));
        }

        tasks.Add(CheckSuspiciousRegistryKeys(ctx, ct));

        if (tasks.Count == 0)
        {
            ctx.Report(1.0, Name, "alt:V installation not found");
            return;
        }

        await Task.WhenAll(tasks);
        ctx.Report(1.0, Name, "alt:V resource injection scan complete");
    }

    private Task CheckResourceManifests(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var resourcesDir = Path.Combine(root, "resources");
            if (!Directory.Exists(resourcesDir)) return;

            var manifestFiles = new List<string>();
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(resourcesDir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var toml = Path.Combine(dir, "resource.toml");
                        if (File.Exists(toml)) manifestFiles.Add(toml);
                        var json = Path.Combine(dir, "resource.json");
                        if (File.Exists(json)) manifestFiles.Add(json);
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }

            foreach (var manifest in manifestFiles)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    string content;
                    try
                    {
                        using var fs = new FileStream(manifest, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    ctx.IncrementFiles();

                    // Check for suspicious client-side script references
                    var suspiciousClientPatterns = new[]
                    {
                        "client-files",
                        "clientFiles",
                        "client_files",
                        "../",
                        "..\\",
                        "http://",
                        "https://",
                        "\\\\",
                        "/proc/",
                        "C:\\",
                        "AppData",
                        "Temp",
                    };

                    foreach (var pattern in suspiciousClientPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious alt:V Resource Manifest",
                                Risk = RiskLevel.High,
                                Location = manifest,
                                FileName = Path.GetFileName(manifest),
                                Reason = $"Resource manifest '{Path.GetFileName(manifest)}' contains suspicious pattern '{pattern}'. " +
                                         "Cheat resources use path traversal or external URLs to load unauthorized client scripts.",
                                Detail = $"Pattern: '{pattern}' | Path: {manifest}"
                            });
                            break;
                        }
                    }

                    // Check for type = "csharp" or type = "js" with suspicious paths
                    if (content.Contains("type = \"csharp\"", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("\"type\": \"csharp\"", StringComparison.OrdinalIgnoreCase))
                    {
                        var resourceDir = Path.GetDirectoryName(manifest) ?? "";
                        var hasDlls = Directory.GetFiles(resourceDir, "*.dll", SearchOption.AllDirectories).Length > 0;
                        if (hasDlls)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V C# Resource with DLL Assemblies",
                                Risk = RiskLevel.Medium,
                                Location = manifest,
                                FileName = Path.GetFileName(manifest),
                                Reason = "Resource manifest declares C# type and contains DLL assemblies. " +
                                         "C# resources can load arbitrary .NET code with full system access. " +
                                         "Verify the resource is from a trusted source.",
                                Detail = $"Resource dir: {resourceDir}"
                            });
                        }
                    }

                    // Look for unknown external server connections
                    if (content.Contains("serverUrl", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("server-url", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("remote-url", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Resource Manifest with External Server URL",
                            Risk = RiskLevel.High,
                            Location = manifest,
                            FileName = Path.GetFileName(manifest),
                            Reason = "Resource manifest references an external server URL. " +
                                     "Cheat resources may connect to external C&C servers for payload delivery.",
                            Detail = $"File: {manifest}"
                        });
                    }
                }
                catch (IOException) { }
            }
        }, ct);
    }

    private Task CheckJavaScriptFiles(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var jsFiles = new List<string>();

            var searchDirs = new[]
            {
                Path.Combine(root, "resources"),
                Path.Combine(root, "client_packages"),
                Path.Combine(root, "packages"),
            };

            foreach (var searchDir in searchDirs)
            {
                if (!Directory.Exists(searchDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(searchDir, "*.js", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        jsFiles.Add(file);
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            foreach (var jsFile in jsFiles)
            {
                ct.ThrowIfCancellationRequested();

                string content;
                try
                {
                    var info = new FileInfo(jsFile);
                    if (info.Length > 2 * 1024 * 1024) continue; // Skip files over 2MB
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();

                var matchedPatterns = new List<string>();
                foreach (var pattern in JsCheatPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        matchedPatterns.Add(pattern);
                }

                if (matchedPatterns.Count == 0) continue;

                var risk = matchedPatterns.Count >= 5 ? RiskLevel.Critical
                         : matchedPatterns.Count >= 3 ? RiskLevel.High
                         : RiskLevel.Medium;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"alt:V JS Cheat Patterns: {Path.GetFileName(jsFile)}",
                    Risk = risk,
                    Location = jsFile,
                    FileName = Path.GetFileName(jsFile),
                    Reason = $"JavaScript file contains {matchedPatterns.Count} cheat API pattern(s): " +
                             string.Join(", ", matchedPatterns.Take(5).Select(p => $"'{p}'")) +
                             (matchedPatterns.Count > 5 ? " ..." : "") +
                             ". These patterns indicate alt:V client-side cheat injection via native calls, " +
                             "CEF WebView manipulation, network tunneling, or obfuscated code execution.",
                    Detail = $"Matched ({matchedPatterns.Count}): {string.Join(", ", matchedPatterns.Take(8))}"
                });
            }
        }, ct);
    }

    private Task CheckPluginAssemblies(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var dllFiles = new List<string>();

            var searchDirs = new[]
            {
                Path.Combine(root, "resources"),
                Path.Combine(root, "plugins"),
                Path.Combine(root, "data", "cache"),
            };

            foreach (var searchDir in searchDirs)
            {
                if (!Directory.Exists(searchDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(searchDir, "*.dll", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        dllFiles.Add(file);
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            foreach (var dllFile in dllFiles)
            {
                ct.ThrowIfCancellationRequested();

                byte[] bytes;
                try
                {
                    var info = new FileInfo(dllFile);
                    if (info.Length > 10 * 1024 * 1024) continue; // Skip files over 10MB
                    using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, System.Text.Encoding.Latin1);
                    var rawContent = await sr.ReadToEndAsync(ct);

                    ctx.IncrementFiles();

                    var matchedStrings = new List<string>();
                    foreach (var suspicious in SuspiciousDllStrings)
                    {
                        if (rawContent.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                            matchedStrings.Add(suspicious);
                    }

                    if (matchedStrings.Count == 0) continue;

                    var risk = matchedStrings.Any(s =>
                        s.Contains("VirtualAllocEx", StringComparison.OrdinalIgnoreCase) ||
                        s.Contains("WriteProcessMemory", StringComparison.OrdinalIgnoreCase) ||
                        s.Contains("CreateRemoteThread", StringComparison.OrdinalIgnoreCase) ||
                        s.Contains("NtCreateThreadEx", StringComparison.OrdinalIgnoreCase))
                        ? RiskLevel.Critical : RiskLevel.High;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious alt:V Plugin DLL: {Path.GetFileName(dllFile)}",
                        Risk = risk,
                        Location = dllFile,
                        FileName = Path.GetFileName(dllFile),
                        Reason = $"DLL assembly in alt:V resources directory contains {matchedStrings.Count} suspicious string(s): " +
                                 string.Join(", ", matchedStrings.Take(5).Select(s => $"'{s}'")) +
                                 (matchedStrings.Count > 5 ? " ..." : "") +
                                 ". These strings indicate process injection, memory manipulation, " +
                                 "dynamic assembly loading, or hooking capabilities.",
                        Detail = $"Suspicious strings ({matchedStrings.Count}): {string.Join(", ", matchedStrings.Take(6))}"
                    });
                }
                catch (IOException) { continue; }
            }
        }, ct);
    }

    private Task CheckProxyDlls(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            if (!Directory.Exists(root)) return;

            foreach (var proxyName in ProxyDllNames)
            {
                ct.ThrowIfCancellationRequested();

                var fullPath = Path.Combine(root, proxyName);
                if (!File.Exists(fullPath)) continue;

                ctx.IncrementFiles();

                // Check file info
                FileInfo fi;
                try { fi = new FileInfo(fullPath); }
                catch (IOException) { continue; }

                // Proxy DLLs are usually small — a legitimate DLL like dinput8.dll in Windows\System32
                // is much larger; a tiny proxy wrapper is suspicious
                var isSmall = fi.Length < 128 * 1024; // under 128KB
                var risk = isSmall ? RiskLevel.Critical : RiskLevel.High;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspected Proxy DLL in alt:V Root: {proxyName}",
                    Risk = risk,
                    Location = fullPath,
                    FileName = proxyName,
                    Reason = $"Known proxy/hijack DLL name '{proxyName}' found in alt:V root directory. " +
                             (isSmall ? $"File is unusually small ({fi.Length} bytes), strongly suggesting a thin proxy wrapper. " : "") +
                             "Attackers place proxy DLLs in game directories to intercept calls to legitimate system DLLs " +
                             "and load cheat code before the actual library is called.",
                    Detail = $"Size: {fi.Length} bytes | Modified: {fi.LastWriteTimeUtc:u} | Path: {fullPath}"
                });
            }
        }, ct);
    }

    private Task CheckMaliciousResourceFolders(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var resourcesDir = Path.Combine(root, "resources");
            if (!Directory.Exists(resourcesDir)) return;

            string[] topLevelDirs;
            try
            {
                topLevelDirs = Directory.GetDirectories(resourcesDir);
            }
            catch (UnauthorizedAccessException) { return; }

            foreach (var dir in topLevelDirs)
            {
                ct.ThrowIfCancellationRequested();

                var dirName = Path.GetFileName(dir);

                // Check exact matches against known malicious resource names
                var exactMatch = MaliciousResourceNames.FirstOrDefault(n =>
                    string.Equals(n, dirName, StringComparison.OrdinalIgnoreCase));

                if (exactMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known Malicious alt:V Resource Folder: {dirName}",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = dirName,
                        Reason = $"alt:V resource folder '{dirName}' matches a known cheat resource name. " +
                                 "Cheat menus and hack resources commonly use these directory names to organize " +
                                 "their injected client-side functionality.",
                        Detail = $"Matched known name: '{exactMatch}' | Path: {dir}"
                    });
                    continue;
                }

                // Also check for keyword matches in name
                var cheatKeywords = new[]
                {
                    "cheat", "hack", "inject", "exploit", "bypass", "aimbot",
                    "wallhack", "esp", "triggerbot", "spinbot", "bhop", "godmode",
                    "noclip", "teleport", "speedhack", "nofall", "radar",
                    "executor", "loader", "injector", "payload",
                };

                var keywordMatch = cheatKeywords.FirstOrDefault(k =>
                    dirName.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (keywordMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious alt:V Resource Folder Name: {dirName}",
                        Risk = RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason = $"alt:V resource folder '{dirName}' contains cheat-related keyword '{keywordMatch}'. " +
                                 "Cheat resources frequently use descriptive names reflecting their functionality.",
                        Detail = $"Keyword: '{keywordMatch}' | Path: {dir}"
                    });
                }
            }
        }, ct);
    }

    private Task CheckAltVConfig(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var configPaths = new[]
            {
                Path.Combine(root, "altv.toml"),
                Path.Combine(root, "altv.cfg"),
                Path.Combine(root, "config.toml"),
                Path.Combine(root, "data", "altv.toml"),
            };

            foreach (var configPath in configPaths)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(configPath)) continue;

                string content;
                try
                {
                    using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();

                var matchedPatterns = new List<string>();
                foreach (var pattern in SuspiciousTomlPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        matchedPatterns.Add(pattern);
                }

                if (matchedPatterns.Count > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious alt:V Config: {Path.GetFileName(configPath)}",
                        Risk = RiskLevel.High,
                        Location = configPath,
                        FileName = Path.GetFileName(configPath),
                        Reason = $"alt:V configuration file contains suspicious settings: " +
                                 string.Join(", ", matchedPatterns.Select(p => $"'{p}'")) +
                                 ". These settings can disable security verification, enable developer bypass modes, " +
                                 "or redirect alt:V to non-official update servers.",
                        Detail = $"Matched patterns: {string.Join(", ", matchedPatterns)}"
                    });
                }

                // Check for abnormal server connection strings — non-official alt:V CDN/update servers
                var lines = content.Split('\n');
                foreach (var line in lines)
                {
                    ct.ThrowIfCancellationRequested();
                    var trimmed = line.Trim();
                    if (!trimmed.StartsWith("url", StringComparison.OrdinalIgnoreCase) &&
                        !trimmed.StartsWith("cdn", StringComparison.OrdinalIgnoreCase) &&
                        !trimmed.StartsWith("update", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (trimmed.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                        trimmed.Contains("https://", StringComparison.OrdinalIgnoreCase))
                    {
                        bool isOfficialUrl = trimmed.Contains("cdn.alt-mp.com", StringComparison.OrdinalIgnoreCase) ||
                                             trimmed.Contains("altv.mp", StringComparison.OrdinalIgnoreCase) ||
                                             trimmed.Contains("alt-mp.com", StringComparison.OrdinalIgnoreCase);

                        if (!isOfficialUrl)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V Config References Non-Official Update Server",
                                Risk = RiskLevel.Critical,
                                Location = configPath,
                                FileName = Path.GetFileName(configPath),
                                Reason = "alt:V configuration specifies a non-official CDN or update server URL. " +
                                         "Cheat providers host modified alt:V clients at custom URLs to deliver " +
                                         "pre-patched executables with built-in bypass capabilities.",
                                Detail = $"Suspicious URL line: {trimmed.Substring(0, Math.Min(trimmed.Length, 200))}"
                            });
                        }
                    }
                }
            }
        }, ct);
    }

    private Task CheckUpdateFileSizes(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var updateFiles = new[]
            {
                ("altv.exe", 5 * 1024 * 1024L, 80 * 1024 * 1024L),         // 5MB - 80MB normal range
                ("altv-client.dll", 1 * 1024 * 1024L, 50 * 1024 * 1024L),
                ("altv-native-ui.dll", 512 * 1024L, 20 * 1024 * 1024L),
                ("AltV.Net.Client.dll", 256 * 1024L, 10 * 1024 * 1024L),
                ("chrome_elf.dll", 200 * 1024L, 5 * 1024 * 1024L),
                ("cef.pak", 1 * 1024 * 1024L, 100 * 1024 * 1024L),
            };

            foreach (var (fileName, minSize, maxSize) in updateFiles)
            {
                ct.ThrowIfCancellationRequested();

                var fullPath = Path.Combine(root, fileName);
                if (!File.Exists(fullPath)) continue;

                FileInfo fi;
                try { fi = new FileInfo(fullPath); }
                catch (IOException) { continue; }

                ctx.IncrementFiles();

                if (fi.Length < minSize)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V Binary Abnormally Small: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = fullPath,
                        FileName = fileName,
                        Reason = $"alt:V binary '{fileName}' is abnormally small ({fi.Length:N0} bytes, expected at least {minSize:N0} bytes). " +
                                 "Cheat modifications often replace legitimate binaries with stripped or proxy versions " +
                                 "that are much smaller than official releases.",
                        Detail = $"Actual size: {fi.Length} bytes | Expected minimum: {minSize} bytes | Modified: {fi.LastWriteTimeUtc:u}"
                    });
                }
                else if (fi.Length > maxSize)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V Binary Abnormally Large: {fileName}",
                        Risk = RiskLevel.High,
                        Location = fullPath,
                        FileName = fileName,
                        Reason = $"alt:V binary '{fileName}' is abnormally large ({fi.Length:N0} bytes, expected under {maxSize:N0} bytes). " +
                                 "Cheat code may be appended or embedded in the binary after patching.",
                        Detail = $"Actual size: {fi.Length} bytes | Expected maximum: {maxSize} bytes | Modified: {fi.LastWriteTimeUtc:u}"
                    });
                }
            }

            // Check for recently modified core binaries (within 7 days and not matching official update pattern)
            var coreFiles = new[] { "altv.exe", "altv-client.dll" };
            foreach (var fileName in coreFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fullPath = Path.Combine(root, fileName);
                if (!File.Exists(fullPath)) continue;

                FileInfo fi;
                try { fi = new FileInfo(fullPath); }
                catch (IOException) { continue; }

                // If core binary was modified very recently (within 48 hours) check for update log
                var updateLog = Path.Combine(root, "data", "update.log");
                var age = DateTime.UtcNow - fi.LastWriteTimeUtc;
                if (age.TotalHours < 48 && !File.Exists(updateLog))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V Core Binary Recently Modified Without Update Log: {fileName}",
                        Risk = RiskLevel.Medium,
                        Location = fullPath,
                        FileName = fileName,
                        Reason = $"alt:V core binary '{fileName}' was modified {age.TotalHours:F1} hours ago " +
                                 "but no official update log was found. " +
                                 "Legitimate alt:V updates always generate an update log file. " +
                                 "Manual binary replacement may indicate a patched/cheat version.",
                        Detail = $"Modified: {fi.LastWriteTimeUtc:u} | Age: {age.TotalHours:F1}h | Update log missing: {updateLog}"
                    });
                }
            }
        }, ct);
    }

    private Task CheckCefInjectionHtml(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            // alt:V uses a CEF overlay; HTML files placed in the resource UI paths can inject
            // WebSocket-based packet hooks or iframe-load cheat UIs.
            var cefPatterns = new[]
            {
                "new WebSocket(",
                "ws.onmessage",
                "ws.send(",
                "socket.send(",
                "interceptPacket",
                "sendPacket(",
                "eval(atob(",
                "eval(btoa(",
                "Function(atob(",
                "atob(unescape(",
                "document.createElement('script')",
                "document.createElement(\"script\")",
                "innerHTML =",
                "innerHTML=",
                "alt.emit(",
                "alt.on(",
                "<iframe src=\"http",
                "<iframe src='http",
                "loadURL('http",
                "loadURL(\"http",
                "fetch('http://",
                "fetch(\"http://",
                "XDomainRequest(",
                "XMLHttpRequest(",
            };

            var htmlFiles = new List<string>();
            var searchDirs = new[]
            {
                Path.Combine(root, "resources"),
                Path.Combine(root, "client_packages"),
                Path.Combine(root, "data", "cache", "browser"),
                Path.Combine(root, "cef"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var f in Directory.EnumerateFiles(dir, "*.html", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        htmlFiles.Add(f);
                    }
                    foreach (var f in Directory.EnumerateFiles(dir, "*.htm", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        htmlFiles.Add(f);
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            foreach (var htmlFile in htmlFiles)
            {
                ct.ThrowIfCancellationRequested();

                string content;
                try
                {
                    var fi = new FileInfo(htmlFile);
                    if (fi.Length > 1024 * 1024) continue;
                    using var fs = new FileStream(htmlFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();

                var matched = new List<string>();
                foreach (var pattern in cefPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        matched.Add(pattern);
                }

                if (matched.Count == 0) continue;

                bool critical = matched.Any(p =>
                    p.Contains("interceptPacket", StringComparison.OrdinalIgnoreCase) ||
                    p.Contains("sendPacket", StringComparison.OrdinalIgnoreCase) ||
                    p.Contains("eval(atob(", StringComparison.OrdinalIgnoreCase));

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"alt:V CEF HTML with Injection Patterns: {Path.GetFileName(htmlFile)}",
                    Risk = critical ? RiskLevel.Critical : RiskLevel.High,
                    Location = htmlFile,
                    FileName = Path.GetFileName(htmlFile),
                    Reason = $"alt:V CEF overlay HTML file contains {matched.Count} suspicious pattern(s): " +
                             string.Join(", ", matched.Take(5).Select(p => $"'{p}'")) +
                             (matched.Count > 5 ? " ..." : "") +
                             ". CEF HTML overlays can use WebSockets or eval-based obfuscation to inject " +
                             "cheat code into the game's browser context, enabling HUD-based ESP, packet hooks, " +
                             "or communication with external C&C servers.",
                    Detail = $"Matched ({matched.Count}): {string.Join(", ", matched.Take(8))}"
                });
            }
        }, ct);
    }

    private Task CheckSuspiciousRegistryKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            // alt:V cheats sometimes register themselves in startup or shell extension keys
            var suspiciousKeyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Classes\altv",
                @"SOFTWARE\Classes\altv\shell\open\command",
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
            };

            var altVKeywords = new[]
            {
                "altv", "alt-v", "altvmp", "altv_inject", "altv_bypass",
                "altv_cheat", "altv_hack", "resource_inject", "altv_loader",
            };

            foreach (var keyPath in suspiciousKeyPaths)
            {
                ct.ThrowIfCancellationRequested();

                RegistryKey? key = null;
                try
                {
                    key = Registry.CurrentUser.OpenSubKey(keyPath, writable: false)
                       ?? Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                }
                catch { }

                if (key is null) continue;

                try
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        var combined = $"{valueName} {value}";

                        var match = altVKeywords.FirstOrDefault(kw =>
                            combined.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious alt:V Registry Entry: {valueName}",
                            Risk = RiskLevel.High,
                            Location = $@"{keyPath}\{valueName}",
                            Reason = $"Registry value '{valueName}' under '{keyPath}' contains alt:V-related keyword '{match}'. " +
                                     "Cheat loaders register auto-start or protocol handler entries to persist across reboots " +
                                     "or to intercept alt:V launch events for DLL injection.",
                            Detail = $"Value: {value.Substring(0, Math.Min(value.Length, 300))}"
                        });
                    }
                }
                catch { }
                finally
                {
                    key?.Dispose();
                }
            }
        }, ct);
    }

    private Task CheckSuspiciousAltVSubdirectories(ScanContext ctx, string root, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            // Directories that should not normally exist in the alt:V data tree
            var unexpectedDirs = new[]
            {
                "injector",
                "inject",
                "loader",
                "bypass",
                "exploit",
                "payload",
                "shellcode",
                "trainer",
                "menu_dll",
                "cheat_dll",
                "hack_dll",
                "internal_cheat",
                "external_cheat",
                "d3d_hook",
                "dx_hook",
                "opengl_hook",
                "wndproc",
                "kmode",
                "kernel",
                "driver_exploit",
                "eac_bypass",
                "be_bypass",
            };

            string[] rootSubDirs;
            try { rootSubDirs = Directory.GetDirectories(root); }
            catch (UnauthorizedAccessException) { return; }

            foreach (var dir in rootSubDirs)
            {
                ct.ThrowIfCancellationRequested();

                var dirName = Path.GetFileName(dir);
                var match = unexpectedDirs.FirstOrDefault(u =>
                    string.Equals(u, dirName, StringComparison.OrdinalIgnoreCase) ||
                    dirName.Contains(u, StringComparison.OrdinalIgnoreCase));

                if (match is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Unexpected Directory in alt:V Root: {dirName}",
                    Risk = RiskLevel.High,
                    Location = dir,
                    FileName = dirName,
                    Reason = $"Directory '{dirName}' found in the alt:V root folder is not part of the official alt:V installation. " +
                             $"The name '{dirName}' matches known cheat component directory patterns (matched: '{match}'). " +
                             "Cheat tools store their payloads, injectors, and bypass modules in custom directories " +
                             "within the alt:V folder to avoid detection by simple file name scanning.",
                    Detail = $"Unexpected dir: {dir}"
                });
            }
        }, ct);
    }

}
