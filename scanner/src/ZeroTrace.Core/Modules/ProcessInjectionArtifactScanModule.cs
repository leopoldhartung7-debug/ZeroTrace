using Microsoft.Win32;
using System.Text;
using System.Xml.Linq;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ProcessInjectionArtifactScanModule : IScanModule
{
    public string Name => "Process Injection Artifact Detection";
    public double Weight => 4.4;
    public int ParallelGroup => 4;

    private static readonly string[] InjectorExeNames =
    [
        "injector.exe", "Injector.exe",
        "dll_injector.exe", "DllInjector.exe", "DLLInjector.exe",
        "manual_map_injector.exe", "ManualMapInjector.exe",
        "manual_mapper.exe", "ManualMapper.exe",
        "reflective_injector.exe", "ReflectiveInjector.exe",
        "reflective_loader.exe", "ReflectiveLoader.exe",
        "apc_injector.exe", "ApcInjector.exe",
        "shellcode_injector.exe", "ShellcodeInjector.exe",
        "shellcode_runner.exe", "ShellcodeRunner.exe",
        "pe_injector.exe", "PeInjector.exe", "PEInjector.exe",
        "process_injector.exe", "ProcessInjector.exe",
        "loadlibrary_injector.exe", "LoadLibraryInjector.exe",
        "hijack_injector.exe", "HijackInjector.exe",
        "thread_hijacker.exe", "ThreadHijacker.exe",
        "remote_thread_injector.exe", "RemoteThreadInjector.exe",
        "create_remote_thread.exe", "CreateRemoteThread.exe",
        "inject.exe", "Inject.exe",
        "inject64.exe", "Inject64.exe",
        "inject32.exe", "Inject32.exe",
        "dll_inject.exe", "DllInject.exe",
        "manual_map.exe", "ManualMap.exe",
        "mmap_injector.exe", "MmapInjector.exe",
        "ntcreatethreadex_inject.exe",
        "queueapc_inject.exe", "QueueApcInject.exe",
        "setwindowshookex_inject.exe", "SetWindowsHookExInject.exe",
        "kdll_inject.exe", "KernelInjector.exe",
        "kernel_injector.exe",
        "driver_inject.exe", "DriverInject.exe",
        "lsass_inject.exe", "LsassInject.exe",
        "csrss_inject.exe", "CsrssInject.exe",
        "svchost_inject.exe",
        "winlogon_inject.exe",
        "explorer_inject.exe",
        "inject_all.exe", "InjectAll.exe",
        "multi_inject.exe", "MultiInject.exe",
        "payload_exec.exe", "PayloadExec.exe",
        "shellcode_exec.exe", "ShellcodeExec.exe",
        "mapper.exe", "Mapper.exe",
        "map_dll.exe", "MapDll.exe",
        "module_mapper.exe", "ModuleMapper.exe",
        "lazy_importer.exe",
        "stomped_loader.exe", "StompedLoader.exe",
        "stomped_inject.exe",
        "transacted_inject.exe",
        "atom_inject.exe", "AtomInject.exe",
    ];

    private static readonly string[] InjectorDllNames =
    [
        "injector.dll", "Injector.dll",
        "manual_map.dll", "ManualMap.dll",
        "mmap.dll", "MMap.dll",
        "reflective_dll.dll", "ReflectiveDll.dll",
        "reflective_loader.dll", "ReflectiveLoader.dll",
        "shellcode_runner.dll", "ShellcodeRunner.dll",
        "apc_inject.dll", "ApcInject.dll",
        "dll_inject.dll", "DllInject.dll",
        "thread_hijack.dll", "ThreadHijack.dll",
        "remote_thread.dll", "RemoteThread.dll",
        "ntcreatethreadex.dll",
        "queueapc.dll", "QueueAPC.dll",
        "setwindowshookex.dll",
        "hijack.dll", "Hijack.dll",
        "loadlibrary_stub.dll",
        "inject_payload.dll", "InjectPayload.dll",
        "injection_helper.dll", "InjectionHelper.dll",
        "pe_inject.dll", "PEInject.dll",
        "process_inject.dll", "ProcessInject.dll",
        "stomped.dll", "Stomped.dll",
        "lazy_loader.dll", "LazyLoader.dll",
        "module_stomping.dll",
        "earlybird_inject.dll",
        "ghost_inject.dll", "GhostInject.dll",
    ];

    private static readonly string[] InjectorDirectoryKeywords =
    [
        "injector", "Injector",
        "manual_map", "ManualMap", "mmap",
        "dll_inject", "DllInject",
        "reflective", "Reflective",
        "shellcode", "Shellcode",
        "apc_inject", "ApcInject",
        "thread_hijack", "ThreadHijack",
        "process_inject", "ProcessInject",
        "payload_stage", "PayloadStage",
        "cheat_loader", "CheatLoader",
        "loader_tool", "LoaderTool",
        "inject_tool", "InjectTool",
        "pe_inject", "PEInject",
        "stomped", "module_stomp",
        "ghost_inject", "GhostInject",
        "earlybird",
        "atom_bomb", "AtomBomb",
        "transacted",
    ];

    private static readonly string[] InjectionConfigKeywords =
    [
        "inject_path", "inject_dll", "dll_to_inject",
        "target_process", "target_pid", "injection_target",
        "injection_method", "inject_method",
        "manual_map", "reflective_load", "reflective_inject",
        "apc_inject", "apc_injection",
        "thread_hijack", "remote_thread",
        "shellcode_path", "shellcode_file",
        "load_library", "loadlibrary",
        "stomping", "module_stomp",
        "earlybird_inject", "early_bird",
        "ghost_inject", "ghost_writing",
        "atom_bomb", "atom_bombing",
        "transacted_hollow",
        "process_hollow", "hollow_path",
        "ntcreatethreadex", "ntmapviewofsection",
        "virtualalloc", "writeprocessmemory",
        "createremotethread",
    ];

    private static readonly string[] ShellcodeExtensions =
    [
        ".bin", ".sc", ".shellcode", ".raw", ".payload",
    ];

    private static readonly string[] InjectorRegistryPaths =
    [
        @"SOFTWARE\ManualMapper",
        @"SOFTWARE\Injector",
        @"SOFTWARE\DllInjector",
        @"SOFTWARE\ProcessInjector",
        @"SOFTWARE\ReflectiveInjector",
        @"SOFTWARE\ShellcodeRunner",
        @"SOFTWARE\ApcInjector",
        @"SOFTWARE\ThreadHijacker",
        @"SOFTWARE\MMapInjector",
        @"SOFTWARE\CheatLoader",
        @"SOFTWARE\PayloadLoader",
    ];

    private static readonly string[] InjectionLogFileNames =
    [
        "injection_log.txt", "inject_log.txt", "inject.log",
        "dll_inject.log", "dll_injection.log",
        "map_log.txt", "mmap_log.txt", "manual_map.log",
        "shellcode.log", "shellcode_log.txt",
        "loader_log.txt", "cheat_log.txt",
        "payload_log.txt", "reflective_log.txt",
        "apc_log.txt", "thread_hijack.log",
        "injection.log", "process_inject.log",
        "inject_debug.log", "inject_debug.txt",
    ];

    private static readonly string[] RootkitStagingDirectoryNames =
    [
        "rootkit", "Rootkit", "RootKit",
        "nt_rootkit", "NtRootkit", "nt_root",
        "r3_rootkit", "R3Rootkit", "ring3_rootkit",
        "ring3root", "Ring3Root",
        "r0_rootkit", "ring0_rootkit",
        "kernel_rootkit", "KernelRootkit",
        "user_rootkit", "UserRootkit",
        "rkloader", "RkLoader",
        "rk_loader",
        "rootkit_loader",
        "rootkit_stage",
        "nt_hook", "NtHook",
    ];

    private static readonly string[] SuspiciousDllSubstrings =
    [
        "virtualalloc", "writeprocess", "createremote", "ntcreatethread",
        "queueapc", "setwindowshook", "mapviewofsection", "ntmapview",
        "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
        "ntwritevirtualmemory", "ntallocatevirtualmemory",
    ];

    private static readonly byte[] MzHeader = { 0x4D, 0x5A };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckInjectorExeFilesAsync(ctx, ct),
            CheckInjectorDllFilesAsync(ctx, ct),
            CheckInjectorDirectoriesAsync(ctx, ct),
            CheckInjectionConfigFilesAsync(ctx, ct),
            CheckShellcodePayloadFilesAsync(ctx, ct),
            CheckInjectorRegistryArtifactsAsync(ctx, ct),
            CheckScheduledTaskInjectionKeywordsAsync(ctx, ct),
            CheckTempMzDllHeuristicAsync(ctx, ct),
            CheckInjectionLogFilesAsync(ctx, ct),
            CheckAppDataInjectorDirectoriesAsync(ctx, ct),
            CheckRootkitStagingDirectoriesAsync(ctx, ct),
            CheckSuspiciousTempPeFilesAsync(ctx, ct),
            CheckUninstallerInjectorEntriesAsync(ctx, ct)
        );
        ctx.Report(1.0, Name, "Process injection artifact scan complete");
    }

    private Task CheckInjectorExeFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, InjectorExeNames,
                        "DLL/Process Injector Executable Detected",
                        Risk.Critical,
                        "Known process or DLL injector executable found in user directory. Injectors are the primary delivery mechanism for cheat DLLs — they load cheat code into game processes to enable aimbot, ESP, and other cheats while evading process-level anti-cheat detection.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckInjectorDllFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = GetUserSearchDirectories();
            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(dir)) continue;
                try
                {
                    await ScanDirectoryForNamesAsync(ctx, ct, dir, InjectorDllNames,
                        "Injector DLL Component Detected",
                        Risk.Critical,
                        "Known injector DLL component found. These DLLs implement injection techniques such as manual mapping, reflective loading, or APC injection and are loaded by injector executables as part of the cheat delivery pipeline.");
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckInjectorDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            var keywordSet = new HashSet<string>(InjectorDirectoryKeywords, StringComparer.OrdinalIgnoreCase);

            foreach (var root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var subDir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var dirName = Path.GetFileName(subDir);
                        if (!keywordSet.Contains(dirName)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Injection Tool Directory Found: {dirName}",
                            Risk = Risk.High,
                            Location = subDir,
                            FileName = dirName,
                            Reason = $"Directory name '{dirName}' matches a known injection tool folder pattern. Cheat injection tools are typically organised in named directories that reflect their injection technique (manual mapping, reflective loading, APC injection, etc.).",
                            Detail = $"Directory: {subDir}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckInjectionConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            var configExtensions = new[] { "*.cfg", "*.ini", "*.json", "*.xml", "*.txt", "*.conf" };

            foreach (var rootDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(rootDir)) continue;

                IEnumerable<string> allFiles = Enumerable.Empty<string>();
                foreach (var ext in configExtensions)
                {
                    try
                    {
                        allFiles = allFiles.Concat(
                            Directory.EnumerateFiles(rootDir, ext, SearchOption.AllDirectories));
                    }
                    catch (UnauthorizedAccessException) { }
                }

                foreach (var file in allFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var matchedKeyword = InjectionConfigKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (matchedKeyword is null) continue;

                    var fileName = Path.GetFileName(file);
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Injection Tool Configuration File: {fileName}",
                        Risk = Risk.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Configuration file '{fileName}' contains injection-related keyword '{matchedKeyword}'. These config files control how DLL injection tools operate, specifying the target process, DLL path, and injection technique to use.",
                        Detail = $"Matched keyword: '{matchedKeyword}'"
                    });
                }
            }
        }, ct);
    }

    private Task CheckShellcodePayloadFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            };

            var extSet = new HashSet<string>(ShellcodeExtensions, StringComparer.OrdinalIgnoreCase);
            const long MaxShellcodeSize = 10 * 1024 * 1024;

            foreach (var rootDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(rootDir)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(rootDir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!extSet.Contains(ext)) continue;

                    FileInfo fi;
                    try { fi = new FileInfo(file); }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    if (fi.Length > MaxShellcodeSize) continue;

                    var fileName = Path.GetFileName(file);
                    bool hasShellcodeKeyword = InjectionConfigKeywords.Any(kw =>
                        fileName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    bool hasMzHeader = false;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        var buf = new byte[2];
                        if (fs.Read(buf, 0, 2) == 2)
                            hasMzHeader = buf[0] == MzHeader[0] && buf[1] == MzHeader[1];
                    }
                    catch (IOException) { continue; }

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Shellcode / Payload Binary File Detected: {fileName}",
                        Risk = hasMzHeader ? Risk.Critical : Risk.High,
                        Location = file,
                        FileName = fileName,
                        Reason = hasMzHeader
                            ? $"File '{fileName}' with shellcode/payload extension ({ext}) has a Windows PE (MZ) header, indicating it contains a full portable executable staged as a raw binary payload. This is a typical pattern for injector payload staging — the injector reads this file and maps it into a target process."
                            : $"File '{fileName}' with shellcode/payload extension ({ext}) found in a staging directory. Raw binary blobs with these extensions in temporary or AppData directories are a common artifact of shellcode injection and manual PE mapping.",
                        Detail = $"File size: {fi.Length} bytes | Has MZ header: {hasMzHeader} | Extension: {ext}"
                    });
                }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckInjectorRegistryArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (var keyPath in InjectorRegistryPaths)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                {
                    try
                    {
                        using var key = hive.OpenSubKey(keyPath);
                        if (key is null) continue;
                        ctx.IncrementRegistryKeys();

                        var hiveName = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                        var toolName = keyPath.Contains('\\')
                            ? keyPath.Substring(keyPath.LastIndexOf('\\') + 1)
                            : keyPath;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Injector Tool Registry Key Present: {toolName}",
                            Risk = Risk.High,
                            Location = $@"{hiveName}\{keyPath}",
                            Reason = $"Registry key '{hiveName}\\{keyPath}' associated with the injection tool '{toolName}' was found. This key is created by the tool on installation or first run, indicating that a process injector has been present on this system.",
                            Detail = $"Hive: {hiveName}, Key: {keyPath}"
                        });
                    }
                    catch { }
                }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckScheduledTaskInjectionKeywordsAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var tasksRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "Tasks");
            if (!Directory.Exists(tasksRoot))
            {
                await Task.CompletedTask;
                return;
            }

            string[] taskFiles;
            try { taskFiles = Directory.GetFiles(tasksRoot, "*", SearchOption.AllDirectories); }
            catch { await Task.CompletedTask; return; }

            foreach (var taskFile in taskFiles)
            {
                ct.ThrowIfCancellationRequested();
                if (!string.IsNullOrEmpty(Path.GetExtension(taskFile))) continue;

                string xml;
                try
                {
                    using var fs = new FileStream(taskFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    xml = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                var matchedKeyword = InjectionConfigKeywords.FirstOrDefault(kw =>
                    xml.Contains(kw, StringComparison.OrdinalIgnoreCase));
                if (matchedKeyword is null) continue;

                XDocument doc;
                try { doc = XDocument.Parse(xml); }
                catch { continue; }

                var commands = doc.Descendants()
                    .Where(e => e.Name.LocalName is "Command" or "Arguments")
                    .Select(e => e.Value.Trim())
                    .Where(v => v.Length > 0)
                    .ToList();

                var taskName = Path.GetFileName(taskFile);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Scheduled Task Contains Injection Keyword: {taskName}",
                    Risk = Risk.Critical,
                    Location = taskFile,
                    FileName = taskName,
                    Reason = $"Scheduled task '{taskName}' XML contains injection-related keyword '{matchedKeyword}'. Persistence via scheduled tasks is a known cheat loader technique — the task re-injects the cheat DLL after reboots or anti-cheat restarts.",
                    Detail = $"Keyword: '{matchedKeyword}' | Commands: {string.Join("; ", commands.Take(3))}"
                });
            }
        }, ct);
    }

    private Task CheckTempMzDllHeuristicAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var tempDir = Path.GetTempPath();
            if (!Directory.Exists(tempDir))
            {
                await Task.CompletedTask;
                return;
            }

            IEnumerable<string> dllFiles;
            try { dllFiles = Directory.EnumerateFiles(tempDir, "*.dll", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { await Task.CompletedTask; return; }

            const long MaxInspectSize = 5 * 1024 * 1024;

            foreach (var file in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                FileInfo fi;
                try { fi = new FileInfo(file); }
                catch (IOException) { continue; }

                if (fi.Length > MaxInspectSize) continue;

                byte[] rawBytes;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    rawBytes = Encoding.Latin1.GetBytes(content);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                if (rawBytes.Length < 2) continue;
                if (rawBytes[0] != MzHeader[0] || rawBytes[1] != MzHeader[1]) continue;

                var contentStr = Encoding.Latin1.GetString(rawBytes);
                bool hasInjectionStrings = SuspiciousDllSubstrings.Any(s =>
                    contentStr.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0);

                if (!hasInjectionStrings) continue;

                var fileName = Path.GetFileName(file);
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious DLL in Temp with Injection Strings: {fileName}",
                    Risk = Risk.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"DLL file '{fileName}' in %TEMP% has a valid PE (MZ) header and contains process-injection API name strings (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, etc.). Injector payload DLLs staged in the temp directory commonly exhibit this pattern before being loaded into a target process.",
                    Detail = $"File size: {fi.Length} bytes | Matched injection strings present | Location: {tempDir}"
                });
            }
        }, ct);
    }

    private Task CheckInjectionLogFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            var logNameSet = new HashSet<string>(InjectionLogFileNames, StringComparer.OrdinalIgnoreCase);

            foreach (var rootDir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(rootDir)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(rootDir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(file);
                    if (!logNameSet.Contains(fileName)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Injection Log File Found: {fileName}",
                        Risk = Risk.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Log file '{fileName}' matching a known injection tool output pattern found. Injection tools frequently write log files recording successful injections, target process names, and injected DLL paths — these are direct evidence artifacts of prior injection activity.",
                        Detail = $"Log file path: {file}"
                    });
                }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckAppDataInjectorDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var appDataRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };

            var injectorKeywordSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "injector", "manual_map", "mmap", "dll_inject", "reflective",
                "shellcode", "apc_inject", "thread_hijack", "process_inject",
                "payload_stage", "cheat_loader", "loader_tool", "inject_tool",
                "pe_inject", "stomped", "module_stomp", "ghost_inject",
                "earlybird", "atom_bomb", "transacted", "inject_helper",
                "dll_loader", "raw_loader", "manual_mapper", "map_loader",
            };

            foreach (var appDataRoot in appDataRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(appDataRoot)) continue;
                try
                {
                    foreach (var subDir in Directory.EnumerateDirectories(appDataRoot, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var dirName = Path.GetFileName(subDir);

                        bool matched = injectorKeywordSet.Any(kw =>
                            dirName.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        if (!matched) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Injector Tool AppData Subdirectory: {dirName}",
                            Risk = Risk.High,
                            Location = subDir,
                            FileName = dirName,
                            Reason = $"AppData subdirectory '{dirName}' contains injection tool keywords. Cheat injectors commonly create folders in AppData to store their payload DLLs, configuration, and logs, using these directories as staging areas for the injection pipeline.",
                            Detail = $"Full path: {subDir}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckRootkitStagingDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            var rootkitNameSet = new HashSet<string>(RootkitStagingDirectoryNames, StringComparer.OrdinalIgnoreCase);

            foreach (var root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var subDir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var dirName = Path.GetFileName(subDir);

                        bool isExactMatch = rootkitNameSet.Contains(dirName);
                        bool isKeywordMatch = !isExactMatch && RootkitStagingDirectoryNames.Any(rk =>
                            dirName.Contains(rk, StringComparison.OrdinalIgnoreCase));

                        if (!isExactMatch && !isKeywordMatch) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"User-Mode Rootkit Staging Directory Detected: {dirName}",
                            Risk = Risk.Critical,
                            Location = subDir,
                            FileName = dirName,
                            Reason = $"Directory '{dirName}' matches a user-mode (Ring-3) rootkit staging directory naming pattern. User-mode rootkits are sometimes combined with process injection to hide cheat DLLs from anti-cheat process and module enumeration by hooking system APIs in userspace.",
                            Detail = $"Full path: {subDir} | Match type: {(isExactMatch ? "exact" : "keyword")}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckSuspiciousTempPeFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var stagingDirs = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            const long MaxInspectSize = 8 * 1024 * 1024;
            var peExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".exe", ".dll", ".scr", ".com"
            };

            foreach (var stagingDir in stagingDirs)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(stagingDir)) continue;

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(stagingDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!peExtensions.Contains(ext)) continue;

                    FileInfo fi;
                    try { fi = new FileInfo(file); }
                    catch (IOException) { continue; }

                    if (fi.Length > MaxInspectSize || fi.Length < 512) continue;

                    byte[] header;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        header = new byte[Math.Min((int)fi.Length, 4096)];
                        _ = fs.Read(header, 0, header.Length);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    if (header.Length < 2 || header[0] != MzHeader[0] || header[1] != MzHeader[1]) continue;

                    var headerStr = Encoding.Latin1.GetString(header);
                    bool hasNoVersionInfo = !headerStr.Contains("VS_VERSION_INFO", StringComparison.OrdinalIgnoreCase) &&
                                           !headerStr.Contains("FileVersion", StringComparison.OrdinalIgnoreCase) &&
                                           !headerStr.Contains("ProductVersion", StringComparison.OrdinalIgnoreCase);

                    bool hasInjectionStrings = SuspiciousDllSubstrings.Any(s =>
                        headerStr.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0);

                    if (!hasNoVersionInfo || !hasInjectionStrings) continue;

                    var fileName = Path.GetFileName(file);
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unsigned PE Without Version Info and With Injection Strings in Temp: {fileName}",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Portable executable '{fileName}' in the Temp directory has no PE version information resource and contains process injection API strings (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, etc.). Legitimate software virtually always carries version information; the absence combined with injection API strings strongly suggests an unpacked injector payload staged for execution.",
                        Detail = $"File size: {fi.Length} bytes | Has injection strings: true | Has PE version info: false"
                    });
                }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private Task CheckUninstallerInjectorEntriesAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            var injectorUninstallKeywords = new[]
            {
                "injector", "manual_map", "mmap", "dll_inject", "reflective_inject",
                "shellcode", "apc_inject", "thread_hijack", "process_inject",
                "payload_loader", "cheat_inject", "dll_loader",
                "manual_mapper", "map_loader", "pe_inject",
            };

            foreach (var uninstallPath in uninstallPaths)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                {
                    try
                    {
                        using var uninstallKey = hive.OpenSubKey(uninstallPath);
                        if (uninstallKey is null) continue;

                        foreach (var appKeyName in uninstallKey.GetSubKeyNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            try
                            {
                                using var appKey = uninstallKey.OpenSubKey(appKeyName);
                                if (appKey is null) continue;

                                var displayName = appKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                                var installLocation = appKey.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                                var uninstallString = appKey.GetValue("UninstallString")?.ToString() ?? string.Empty;

                                var combined = $"{displayName} {installLocation} {uninstallString}";

                                var matched = injectorUninstallKeywords.FirstOrDefault(kw =>
                                    combined.Contains(kw, StringComparison.OrdinalIgnoreCase));
                                if (matched is null) continue;

                                var hiveName = hive == Registry.LocalMachine ? "HKLM" : "HKCU";
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Injector Tool Uninstaller Registry Entry: {displayName}",
                                    Risk = Risk.High,
                                    Location = $@"{hiveName}\{uninstallPath}\{appKeyName}",
                                    Reason = $"Uninstaller registry entry '{displayName}' contains injection-related keyword '{matched}'. This entry was created when the injection tool was installed and persists as evidence even if the tool binary has been deleted.",
                                    Detail = $"DisplayName: {displayName} | InstallLocation: {installLocation} | Keyword: {matched}"
                                });
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            await Task.CompletedTask;
        }, ct);
    }

    private async Task ScanDirectoryForNamesAsync(
        ScanContext ctx,
        CancellationToken ct,
        string directory,
        string[] targetNames,
        string findingTitle,
        RiskLevel riskLevel,
        string reason)
    {
        var nameSet = new HashSet<string>(targetNames, StringComparer.OrdinalIgnoreCase);
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(file);
            if (!nameSet.Contains(fileName)) continue;

            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"{findingTitle}: {fileName}",
                Risk = riskLevel,
                Location = file,
                FileName = fileName,
                Reason = $"{reason} Matched file path: '{file}'.",
                Detail = $"Matched file name: {fileName}"
            });
        }
        await Task.CompletedTask;
    }

    private static string[] GetUserSearchDirectories()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();
        var desktop = Path.Combine(userProfile, "Desktop");
        var downloads = Path.Combine(userProfile, "Downloads");
        var documents = Path.Combine(userProfile, "Documents");
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        return new[]
        {
            userProfile,
            appData,
            localAppData,
            temp,
            desktop,
            downloads,
            documents,
            programFiles,
            programFilesX86,
        };
    }
}
