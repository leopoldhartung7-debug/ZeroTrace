using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ProcessInjectionTechniqueScanModule : IScanModule
{
    public string Name => "Process Injection Technique Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Static path roots
    // -------------------------------------------------------------------------

    private static readonly string TempPath =
        Path.GetTempPath();

    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

    private static readonly string Downloads =
        Path.Combine(UserProfile, "Downloads");

    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

    private static readonly string PsHistory =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

    // -------------------------------------------------------------------------
    // Known-tool name sets
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> ClassicInjectorExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "injector.exe",
        "dll_injector.exe",
        "GHInjector.exe",
        "GHInjector-x64.exe",
        "Xenos.exe",
        "Xenos64.exe",
        "ExtremeInjector.exe",
        "OpenBulletInjector.exe",
        "winject.exe",
        "inject32.exe",
        "inject64.exe",
        "inject_x64.exe",
    };

    private static readonly HashSet<string> ManualMapperExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "manualmapper.exe",
        "ManualMap.exe",
        "mm_inject.exe",
        "manual_map_inject.exe",
        "mapper.exe",
        "Mapperx64.exe",
    };

    private static readonly HashSet<string> HollowingExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "hollower.exe",
        "hollow.exe",
        "ProcessHollowing.exe",
        "ph_inject.exe",
        "process_hollow.exe",
    };

    private static readonly HashSet<string> ApcInjectorExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "apc_inject.exe",
        "thread_hijack.exe",
        "APCInject.exe",
        "APCInjector.exe",
        "early_bird.exe",
        "EarlyBird.exe",
    };

    private static readonly HashSet<string> ReflectiveDllExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "reflective_inject.exe",
        "ReflectiveDLLInjection.exe",
        "rdll_inject.exe",
        "reflectiveloader.exe",
    };

    private static readonly HashSet<string> AtomBombingExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "atombombing.exe",
        "atom_bomb.exe",
        "AtomBombing.exe",
    };

    private static readonly HashSet<string> KnownMultiMethodInjectors = new(StringComparer.OrdinalIgnoreCase)
    {
        "GHInjector-x64.exe",
        "GHInjector-x86.exe",
        "Xenos.exe",
        "Xenos64.exe",
        "ExtremeInjector.exe",
        "ExtremeInjector_v3.exe",
        "inject_x64.exe",
        "inject_x86.exe",
        "winject.exe",
        "inject32.exe",
        "inject64.exe",
        "loader32.exe",
        "loader64.exe",
        "cheat_loader.exe",
        "game_loader.exe",
        "hack_loader.exe",
        "payload_loader.exe",
        "steam_loader.exe",
        "minhook_inject.exe",
        "detours_inject.exe",
        "cobalt_inject.exe",
        "cs_inject.exe",
        "metasploit_inject.exe",
        "blackbone_inject.exe",
        "BlackBone.exe",
        "blackbone.dll",
        "dll_injector.exe",
        "DllInjector.exe",
        "dllinjector.exe",
        "remote_injector.exe",
        "RemoteInjector.exe",
        "remoteinjector.exe",
        "injector64.exe",
        "injector32.exe",
        "Injector64.exe",
        "Injector32.exe",
        "Injector.exe",
        "process_injector.exe",
        "ProcessInjector.exe",
        "ring0helper.exe",
        "ring0_helper.exe",
        "r0inject.exe",
        "iat_inject.exe",
        "IATInject.exe",
        "vmt_inject.exe",
        "VMTInject.exe",
        "thread_inject.exe",
        "ThreadInject.exe",
        "memory_inject.exe",
        "MemoryInject.exe",
        "shellcode_inject.exe",
        "ShellcodeInject.exe",
        "shellcode_loader.exe",
        "stealth_inject.exe",
        "StealthInject.exe",
        "kernel_inject.exe",
        "KernelInject.exe",
        "driver_inject.exe",
        "DriverInject.exe",
        "game_inject.exe",
        "GameInject.exe",
        "ac_bypass_inject.exe",
        "bypass_inject.exe",
    };

    private static readonly HashSet<string> ConfigInjectionExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt",
        ".ini",
        ".cfg",
        ".json",
        ".xml",
    };

    // -------------------------------------------------------------------------
    // Classic injection DLL name patterns (startsWith / contains)
    // -------------------------------------------------------------------------

    private static readonly string[] ClassicDllPrefixes =
    {
        "inject_",
        "payload_",
        "hook_",
    };

    private static readonly string[] ClassicDllKeywords =
    {
        "inject",
        "payload",
    };

    // -------------------------------------------------------------------------
    // Search root helpers
    // -------------------------------------------------------------------------

    private IEnumerable<string> GetPrimaryRoots() =>
        new[]
        {
            TempPath,
            Downloads,
            Desktop,
            AppDataRoaming,
            AppDataLocal,
        }.Where(Directory.Exists);

    private IEnumerable<string> GetSourceCodeRoots() =>
        new[]
        {
            Downloads,
            Documents,
            Desktop,
        }.Where(Directory.Exists);

    // -------------------------------------------------------------------------
    // RunAsync (orchestrator)
    // -------------------------------------------------------------------------

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starte Prozess-Injektionstechnik-Erkennung...");

        await ScanClassicInjectionArtifactsAsync(ctx, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) { ctx.Report(1.0, Name, "Abgebrochen"); return; }
        ctx.Report(0.12, Name, "Klassische Injektion geprüft");

        await ScanManualMapArtifactsAsync(ctx, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) { ctx.Report(1.0, Name, "Abgebrochen"); return; }
        ctx.Report(0.24, Name, "Manual-Map-Injektion geprüft");

        await ScanProcessHollowingArtifactsAsync(ctx, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) { ctx.Report(1.0, Name, "Abgebrochen"); return; }
        ctx.Report(0.36, Name, "Process-Hollowing geprüft");

        await ScanApcInjectionArtifactsAsync(ctx, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) { ctx.Report(1.0, Name, "Abgebrochen"); return; }
        ctx.Report(0.48, Name, "APC-/Thread-Hijacking geprüft");

        await ScanReflectiveDllArtifactsAsync(ctx, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) { ctx.Report(1.0, Name, "Abgebrochen"); return; }
        ctx.Report(0.60, Name, "Reflective-DLL-Injektion geprüft");

        await ScanExoticTechniqueArtifactsAsync(ctx, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) { ctx.Report(1.0, Name, "Abgebrochen"); return; }
        ctx.Report(0.74, Name, "Exotische Injektionstechniken geprüft");

        await ScanKnownInjectorToolsAsync(ctx, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) { ctx.Report(1.0, Name, "Abgebrochen"); return; }
        ctx.Report(0.88, Name, "Bekannte Injektor-Tools geprüft");

        await ScanPowerShellHistoryAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(1.0, Name, "Prozess-Injektionstechnik-Erkennung abgeschlossen");
    }

    // -------------------------------------------------------------------------
    // 1) Classic DLL injection
    // -------------------------------------------------------------------------

    private async Task ScanClassicInjectionArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetPrimaryRoots().ToList();

        foreach (var file in EnumerateFilesInSearchRoots(roots, 3, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // Remnant DLLs with suspicious name patterns
            if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
            {
                var nameLower = fileName.ToLowerInvariant();
                bool matched = false;

                foreach (var prefix in ClassicDllPrefixes)
                {
                    if (nameLower.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        matched = true;
                        break;
                    }
                }

                if (!matched)
                {
                    foreach (var kw in ClassicDllKeywords)
                    {
                        if (nameLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            matched = true;
                            break;
                        }
                    }
                }

                if (matched)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtige Injektor-DLL: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"DLL-Datei '{fileName}' trägt einen typischen Namen für Injektor-Payloads " +
                                   "(Präfix inject_, payload_ oder hook_ bzw. Schlüsselwort inject/payload). " +
                                   "Solche DLLs werden von DLL-Injektoren in Zielprozesse eingeschleust.",
                        Detail   = $"Pfad: {file}"
                    });
                }
                continue;
            }

            // Known classic injector executables
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                ClassicInjectorExeNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Bekanntes Injektor-Tool: {fileName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Ausführbare Datei '{fileName}' ist ein bekanntes DLL-Injektor-Werkzeug. " +
                               "Diese Programme injizieren DLLs in laufende Prozesse über CreateRemoteThread " +
                               "oder ähnliche APIs und werden typischerweise für externe Cheats verwendet.",
                    Detail   = $"Pfad: {file}"
                });
                continue;
            }

            // Config files containing classic injection method markers
            if (ConfigInjectionExtensions.Contains(ext))
            {
                var patterns = new[]
                {
                    "inject_method=crt",
                    "injection=remote_thread",
                    "inject_method=createremotethread",
                };
                await CheckConfigFileForInjectionPatternsAsync(
                    ctx, file, patterns,
                    "Klassische Injektion in Konfig",
                    "Konfigurationsdatei enthält Schlüsselwort für klassische DLL-Injektion via CreateRemoteThread.",
                    ct).ConfigureAwait(false);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 2) Manual map injection
    // -------------------------------------------------------------------------

    private async Task ScanManualMapArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetPrimaryRoots().ToList();

        foreach (var file in EnumerateFilesInSearchRoots(roots, 3, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // Known manual-mapper executables
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                ManualMapperExeNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Manual-Map-Injektor erkannt: {fileName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Ausführbare Datei '{fileName}' ist ein bekanntes Manual-Mapping-Werkzeug. " +
                               "Manual Mapping umgeht Windows-Lader-Mechanismen und PEB-Modul-Listen, " +
                               "was Anti-Cheat-Erkennung erheblich erschwert.",
                    Detail   = $"Pfad: {file}"
                });
                continue;
            }

            // Config files with manual map markers
            if (ConfigInjectionExtensions.Contains(ext))
            {
                var patterns = new[]
                {
                    "manual_map",
                    "manualmap",
                    "map_method=manual",
                    "injection_type=manual",
                    "inject_type=manual_map",
                };
                await CheckConfigFileForInjectionPatternsAsync(
                    ctx, file, patterns,
                    "Manual-Map-Injektion in Konfig",
                    "Konfigurationsdatei enthält Schlüsselwort für Manual-Map-Injection.",
                    ct).ConfigureAwait(false);
                continue;
            }

            // Scattered PE files in Temp (not .exe/.dll/.sys but start with MZ+PE)
            if (file.StartsWith(TempPath, StringComparison.OrdinalIgnoreCase) &&
                !ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
                !ext.Equals(".sys", StringComparison.OrdinalIgnoreCase))
            {
                await CheckFileForPeHeaderAsync(ctx, file, ct).ConfigureAwait(false);
            }
        }

        // Check for GitHub clone directories with manual-map names
        var cloneNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ManualMap",
            "manual-mapping",
            "manual_map_injection",
            "ManualMapper",
            "manualmapper",
        };

        await Task.Run(() =>
        {
            foreach (var root in roots)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        var dirName = Path.GetFileName(dir);
                        if (cloneNames.Contains(dirName))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Manual-Map-Quellcode-Verzeichnis: {dirName}",
                                Risk     = RiskLevel.High,
                                Location = dir,
                                FileName = dirName,
                                Reason   = $"Verzeichnis '{dirName}' entspricht einem bekannten Namen für " +
                                           "Manual-Mapping-Repositories (z. B. GitHub-Klone). " +
                                           "Diese enthalten lauffähigen Injektor-Quellcode.",
                                Detail   = $"Pfad: {dir}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }, ct).ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // 3) Process hollowing
    // -------------------------------------------------------------------------

    private async Task ScanProcessHollowingArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetPrimaryRoots().ToList();

        foreach (var file in EnumerateFilesInSearchRoots(roots, 3, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // Hollowing executables
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                HollowingExeNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Process-Hollowing-Tool erkannt: {fileName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Ausführbare Datei '{fileName}' ist ein bekanntes Process-Hollowing-Werkzeug. " +
                               "Hollowing erzeugt einen suspendierten Prozess, löscht sein Image aus dem Speicher " +
                               "und ersetzt es durch Schadcode — ein klassischer Anti-Detection-Trick.",
                    Detail   = $"Pfad: {file}"
                });
                continue;
            }

            // Config patterns
            if (ConfigInjectionExtensions.Contains(ext) &&
                !ext.Equals(".xml", StringComparison.OrdinalIgnoreCase))
            {
                var patterns = new[]
                {
                    "hollow=true",
                    "process_hollow",
                    "injection=hollowing",
                    "use_hollowing=true",
                    "hollowing=1",
                };
                await CheckConfigFileForInjectionPatternsAsync(
                    ctx, file, patterns,
                    "Process-Hollowing in Konfig",
                    "Konfigurationsdatei enthält Schlüsselwort für Process-Hollowing-Injektion.",
                    ct).ConfigureAwait(false);
                continue;
            }

            // Log files from cheat loaders containing hollowing strings
            if (ext.Equals(".log", StringComparison.OrdinalIgnoreCase) ||
                ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
            {
                var hollowLogPatterns = new[]
                {
                    "Creating suspended process",
                    "NtUnmapViewOfSection",
                    "hollow",
                };
                await CheckConfigFileForInjectionPatternsAsync(
                    ctx, file, hollowLogPatterns,
                    "Process-Hollowing-Log-Eintrag",
                    "Log-Datei enthält Zeichenketten, die auf Process-Hollowing-Aktivität hinweisen.",
                    ct).ConfigureAwait(false);
            }
        }
    }

    // -------------------------------------------------------------------------
    // 4) Thread hijacking / APC injection
    // -------------------------------------------------------------------------

    private async Task ScanApcInjectionArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetPrimaryRoots().ToList();

        foreach (var file in EnumerateFilesInSearchRoots(roots, 3, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // Known APC injector executables
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                ApcInjectorExeNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"APC-/Thread-Hijacking-Tool: {fileName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Ausführbare Datei '{fileName}' ist ein bekanntes APC-Injektions- oder " +
                               "Thread-Hijacking-Werkzeug. APC-Injektion (NtQueueApcThread) oder " +
                               "Early-Bird-APC können unentdeckt Shellcode in Zielprozesse einschleusen.",
                    Detail   = $"Pfad: {file}"
                });
                continue;
            }

            // Config patterns
            if (ConfigInjectionExtensions.Contains(ext))
            {
                var patterns = new[]
                {
                    "apc_inject",
                    "use_apc",
                    "NtQueueApcThread",
                    "queue_apc=true",
                    "early_bird=true",
                    "earlybird=1",
                };
                await CheckConfigFileForInjectionPatternsAsync(
                    ctx, file, patterns,
                    "APC-Injektion in Konfig",
                    "Konfigurationsdatei enthält Schlüsselwort für APC-Injektion oder Thread-Hijacking.",
                    ct).ConfigureAwait(false);
                continue;
            }
        }

        // Source files containing APC injection APIs
        var srcRoots = GetSourceCodeRoots().ToList();
        var srcExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".c", ".cpp", ".h" };
        var apcSrcPatterns = new[] { "NtQueueApcThread", "EarlyBirdApc", "QueueUserAPC" };

        foreach (var file in EnumerateFilesInSearchRoots(srcRoots, 5, ct))
        {
            if (ct.IsCancellationRequested) return;
            var ext = Path.GetExtension(file);
            if (!srcExtensions.Contains(ext)) continue;
            ctx.IncrementFiles();

            await CheckConfigFileForInjectionPatternsAsync(
                ctx, file, apcSrcPatterns,
                "APC-Injektions-Quellcode",
                "Quelldatei enthält APC-bezogene Injektions-APIs (NtQueueApcThread / QueueUserAPC / EarlyBirdApc).",
                ct).ConfigureAwait(false);
        }
    }

    // -------------------------------------------------------------------------
    // 5) Reflective DLL injection
    // -------------------------------------------------------------------------

    private async Task ScanReflectiveDllArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetPrimaryRoots().ToList();

        foreach (var file in EnumerateFilesInSearchRoots(roots, 3, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // Known reflective DLL injector executables
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                ReflectiveDllExeNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Reflective-DLL-Injektor: {fileName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Ausführbare Datei '{fileName}' ist ein bekanntes Reflective-DLL-Injektionswerkzeug. " +
                               "Reflektive Injektion lädt DLLs ohne den Windows-Lader, sodass die Bibliothek " +
                               "nicht in der PEB-Modulliste erscheint.",
                    Detail   = $"Pfad: {file}"
                });
                continue;
            }

            // Config patterns
            if (ConfigInjectionExtensions.Contains(ext))
            {
                var patterns = new[]
                {
                    "reflective=true",
                    "reflect_dll",
                    "use_reflective_injection=true",
                    "reflective_loader=1",
                };
                await CheckConfigFileForInjectionPatternsAsync(
                    ctx, file, patterns,
                    "Reflective-DLL in Konfig",
                    "Konfigurationsdatei enthält Schlüsselwort für Reflective-DLL-Injektion.",
                    ct).ConfigureAwait(false);
                continue;
            }

            // DLLs in Downloads/Temp: scan for "ReflectiveLoader" export string
            if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
                (file.StartsWith(TempPath, StringComparison.OrdinalIgnoreCase) ||
                 file.StartsWith(Downloads, StringComparison.OrdinalIgnoreCase)))
            {
                await CheckFileForReflectiveLoaderAsync(ctx, file, ct).ConfigureAwait(false);
            }
        }

        // Scan source directories containing "ReflectiveDLLInjection" in path
        var srcRoots = GetSourceCodeRoots().ToList();
        var srcExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".c", ".cpp", ".h" };

        await Task.Run(() =>
        {
            foreach (var root in srcRoots)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        if (!dir.Contains("ReflectiveDLLInjection", StringComparison.OrdinalIgnoreCase))
                            continue;

                        bool hasSrcFiles = false;
                        try
                        {
                            foreach (var f in Directory.EnumerateFiles(dir))
                            {
                                var fext = Path.GetExtension(f);
                                if (srcExtensions.Contains(fext)) { hasSrcFiles = true; break; }
                            }
                        }
                        catch (IOException) { }

                        if (hasSrcFiles)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "ReflectiveDLLInjection-Quellcode-Verzeichnis",
                                Risk     = RiskLevel.High,
                                Location = dir,
                                FileName = Path.GetFileName(dir),
                                Reason   = "Verzeichnis mit 'ReflectiveDLLInjection' im Pfad enthält C/C++-Quelldateien. " +
                                           "Dies deutet auf einen lokalen Klon des bekannten ReflectiveDLLInjection-Projekts " +
                                           "(Metasploit/Cobalt Strike Technik) hin.",
                                Detail   = $"Pfad: {dir}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }, ct).ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // 6) SetWindowsHookEx / hook injection
    // -------------------------------------------------------------------------

    private async Task ScanSetHookExArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = GetPrimaryRoots().ToList();
        var hookConfigExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".ini", ".cfg", ".json" };

        foreach (var file in EnumerateFilesInSearchRoots(roots, 3, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var ext = Path.GetExtension(file);
            if (!hookConfigExtensions.Contains(ext)) continue;

            var patterns = new[]
            {
                "hook_method=setwindowshookex",
                "use_wh_hook",
                "SetWindowsHookEx",
            };
            await CheckConfigFileForInjectionPatternsAsync(
                ctx, file, patterns,
                "SetWindowsHookEx-Injektion in Konfig",
                "Konfigurationsdatei enthält Schlüsselwort für SetWindowsHookEx-basierte Hook-Injektion.",
                ct).ConfigureAwait(false);
        }

        // Check Windows system path for unexpected DLLs alongside user32.dll
        await Task.Run(() =>
        {
            try
            {
                var sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
                var user32 = Path.Combine(sysDir, "user32.dll");
                if (!File.Exists(user32)) return;

                var parentDir = Path.GetDirectoryName(user32);
                if (string.IsNullOrEmpty(parentDir)) return;

                string[] dlls;
                try { dlls = Directory.GetFiles(parentDir, "*.dll"); }
                catch (UnauthorizedAccessException) { return; }
                catch { return; }

                // Flag DLLs in System32 whose name contains suspicious hook indicators
                var suspiciousHookNames = new[] { "hook", "inject", "wh_" };
                foreach (var dll in dlls)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var dllName = Path.GetFileName(dll).ToLowerInvariant();

                    foreach (var indicator in suspiciousHookNames)
                    {
                        if (dllName.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Verdächtige DLL neben user32.dll: {Path.GetFileName(dll)}",
                                Risk     = RiskLevel.High,
                                Location = dll,
                                FileName = Path.GetFileName(dll),
                                Reason   = $"DLL '{Path.GetFileName(dll)}' im Windows-Systemverzeichnis enthält " +
                                           $"verdächtigen Namensbaustein ('{indicator}'). Neben user32.dll platzierte " +
                                           "Hook-DLLs werden für SetWindowsHookEx-Injektion verwendet.",
                                Detail   = $"Pfad: {dll} | Systemverzeichnis: {parentDir}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }, ct).ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // 7) Exotic injection techniques
    // -------------------------------------------------------------------------

    private async Task ScanExoticTechniqueArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        // Run SetWindowsHookEx check as part of exotic scan
        await ScanSetHookExArtifactsAsync(ctx, ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested) return;

        var roots = GetPrimaryRoots().ToList();

        foreach (var file in EnumerateFilesInSearchRoots(roots, 3, ct))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // AtomBombing tools
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                AtomBombingExeNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"AtomBombing-Tool erkannt: {fileName}",
                    Risk     = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Ausführbare Datei '{fileName}' ist ein bekanntes AtomBombing-Injektionswerkzeug. " +
                               "AtomBombing missbraucht den Windows-Atom-Table-Mechanismus zur codefreien Injektion " +
                               "und umgeht viele klassische Detektionsansätze.",
                    Detail   = $"Pfad: {file}"
                });
                continue;
            }

            // Heaven's Gate tool executables
            var heavensGateExeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "wow64ext.exe",
                "HeavensGate.exe",
                "gate.exe",
            };
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                heavensGateExeNames.Contains(fileName))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Heaven's-Gate-Tool: {fileName}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Ausführbare Datei '{fileName}' ist ein bekanntes Heaven's-Gate-Werkzeug. " +
                               "Heaven's Gate nutzt den WoW64-Übergang (32→64 Bit), um Syscall-Hooks von " +
                               "Anti-Cheat- und EDR-Software zu umgehen.",
                    Detail   = $"Pfad: {file}"
                });
                continue;
            }

            // NTDLL outside System32/SysWOW64 — backup copy for hook bypass
            if (fileName.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
            {
                var sysDir    = Environment.GetFolderPath(Environment.SpecialFolder.System);
                var syswow64  = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64");

                bool isSystem32  = file.StartsWith(sysDir,   StringComparison.OrdinalIgnoreCase);
                bool isSysWow64  = file.StartsWith(syswow64, StringComparison.OrdinalIgnoreCase);

                if (!isSystem32 && !isSysWow64)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "ntdll.dll außerhalb System32 — EDR-Hook-Bypass",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = "ntdll.dll",
                        Reason   = "Eine Kopie von ntdll.dll wurde außerhalb von C:\\Windows\\System32 und " +
                                   "C:\\Windows\\SysWOW64 gefunden. Dies ist ein bekanntes Muster zum Umgehen " +
                                   "von EDR- und Anti-Cheat-Hooks: Das Cheat-Tool lädt eine saubere ntdll-Kopie " +
                                   "und führt Direct-Syscalls ohne die gepatchten API-Einstiegspunkte aus.",
                        Detail   = $"Gefundener Pfad: {file} | Erwartete Systempfade: {sysDir}, {syswow64}"
                    });
                }
                continue;
            }

            // Config files: Heaven's Gate and fiber injection patterns
            if (ConfigInjectionExtensions.Contains(ext))
            {
                var exoticPatterns = new[]
                {
                    "heavens_gate=true",
                    "use_heavens_gate=1",
                    "wow64_transition",
                    "fiber_inject",
                    "use_fiber_injection",
                };
                await CheckConfigFileForInjectionPatternsAsync(
                    ctx, file, exoticPatterns,
                    "Exotische Injektionstechnik in Konfig",
                    "Konfigurationsdatei enthält Schlüsselwort für Heaven's Gate oder Fiber-Injektion.",
                    ct).ConfigureAwait(false);
                continue;
            }

            // Source files: direct syscall patterns
            var directSyscallExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { ".c", ".cpp", ".asm", ".h" };
            if (directSyscallExtensions.Contains(ext))
            {
                var syscallPatterns = new[]
                {
                    "syscall_stub",
                    "direct_syscall",
                };
                await CheckConfigFileForInjectionPatternsAsync(
                    ctx, file, syscallPatterns,
                    "Direct-Syscall-Quellcode",
                    "Quelldatei enthält Muster für Direct-Syscall-Implementierungen, die zur Umgehung von " +
                    "API-Hooks von Anti-Cheat- oder EDR-Software eingesetzt werden.",
                    ct).ConfigureAwait(false);

                // Also check for NtOpenProcess combined with syscall context
                await CheckNtOpenProcessWithSyscallAsync(ctx, file, ct).ConfigureAwait(false);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Helper: NtOpenProcess + syscall context check
    // -------------------------------------------------------------------------

    private async Task CheckNtOpenProcessWithSyscallAsync(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            string content;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
            }
            catch (IOException) { return; }

            var lower = content.ToLowerInvariant();
            if (lower.Contains("ntopenprocess", StringComparison.OrdinalIgnoreCase) &&
                lower.Contains("syscall", StringComparison.OrdinalIgnoreCase))
            {
                var fileName = Path.GetFileName(path);
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"NtOpenProcess + Syscall in Quelldatei: {fileName}",
                    Risk     = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason   = $"Quelldatei '{fileName}' enthält sowohl 'NtOpenProcess' als auch 'syscall'. " +
                               "Diese Kombination ist ein starkes Indiz für Direct-Syscall-basierten Prozesszugriff, " +
                               "der Anti-Cheat-Hooks auf Ebene der API-Wrappers umgeht.",
                    Detail   = $"Pfad: {path}"
                });
            }
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // 8) Comprehensive multi-method injector list
    // -------------------------------------------------------------------------

    private async Task ScanKnownInjectorToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = new[]
        {
            Downloads,
            TempPath,
            Desktop,
            AppDataRoaming,
            AppDataLocal,
        }.Where(Directory.Exists).ToList();

        await Task.Run(() =>
        {
            foreach (var file in EnumerateFilesInSearchRoots(roots, 3, ct))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                var ext = Path.GetExtension(file);

                bool isExeOrDll =
                    ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);

                if (!isExeOrDll) continue;

                if (KnownMultiMethodInjectors.Contains(fileName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Bekannter Multi-Methoden-Injektor: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Datei '{fileName}' entspricht einem bekannten Injektionswerkzeug aus der " +
                                   "umfassenden Liste von Multi-Methoden-Injektoren. Diese Tools unterstützen " +
                                   "verschiedene Injektionstechniken (Remote-Thread, APC, Manual-Map usw.) und " +
                                   "werden typischerweise für externe Game-Cheats eingesetzt.",
                        Detail   = $"Pfad: {file}"
                    });
                }
            }
        }, ct).ConfigureAwait(false);
    }

    // -------------------------------------------------------------------------
    // 9) PowerShell history scan
    // -------------------------------------------------------------------------

    private async Task ScanPowerShellHistoryAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!File.Exists(PsHistory)) return;

        ctx.IncrementFiles();

        var psInjectionPatterns = new[]
        {
            "WriteProcessMemory",
            "CreateRemoteThread",
            "VirtualAllocEx",
            "Invoke-ReflectivePEInjection",
            "Invoke-Shellcode",
            "Invoke-MimiKatz",
        };

        string content;
        try
        {
            using var fs = new FileStream(PsHistory, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
        }
        catch (IOException) { return; }
        catch { return; }

        var lines = content.Split('\n');
        int lineNumber = 0;

        foreach (var rawLine in lines)
        {
            if (ct.IsCancellationRequested) return;
            lineNumber++;
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line)) continue;

            foreach (var pattern in psInjectionPatterns)
            {
                if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"PowerShell-Injektion: {pattern}",
                        Risk     = RiskLevel.Critical,
                        Location = PsHistory,
                        FileName = "ConsoleHost_history.txt",
                        Reason   = $"PowerShell-Verlauf enthält in Zeile {lineNumber} das Muster '{pattern}'. " +
                                   "Diese Funktion wird für prozessbasierte Code-Injektion über PowerShell-Skripte " +
                                   "verwendet und ist ein starkes Indiz für Cheat-Loader oder Post-Exploitation-Aktivität.",
                        Detail   = $"Zeile {lineNumber}: {line[..Math.Min(300, line.Length)]}"
                    });
                    break;
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // PE header detection helper
    // -------------------------------------------------------------------------

    private async Task<bool> CheckFileForPeHeaderAsync(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            FileInfo fi;
            try { fi = new FileInfo(path); }
            catch { return false; }

            // Skip files >= 50 MB
            if (fi.Length >= 50L * 1024 * 1024) return false;

            byte[] header = new byte[4096];
            int bytesRead;

            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                bytesRead = await fs.ReadAsync(header.AsMemory(0, header.Length), ct).ConfigureAwait(false);
            }
            catch (IOException) { return false; }

            if (bytesRead < 4) return false;

            // Check MZ magic (0x4D 0x5A)
            if (header[0] != 0x4D || header[1] != 0x5A) return false;

            // Check PE signature — located at offset stored at 0x3C (e_lfanew)
            if (bytesRead < 0x40) return false;
            int e_lfanew = BitConverter.ToInt32(header, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 4 > bytesRead) return false;

            // PE\0\0 = 0x50 0x45 0x00 0x00
            if (header[e_lfanew]     != 0x50 ||
                header[e_lfanew + 1] != 0x45 ||
                header[e_lfanew + 2] != 0x00 ||
                header[e_lfanew + 3] != 0x00)
                return false;

            var fileName = Path.GetFileName(path);
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Versteckte PE-Datei (kein .exe/.dll): {fileName}",
                Risk     = RiskLevel.High,
                Location = path,
                FileName = fileName,
                Reason   = $"Datei '{fileName}' im Temp-Verzeichnis beginnt mit MZ-/PE-Magic-Bytes, hat aber " +
                           "keine .exe-, .dll- oder .sys-Erweiterung. Diese Technik wird beim Manual Mapping " +
                           "verwendet, um Payload-Binaries vor dateinamensbasierter Erkennung zu verschleiern.",
                Detail   = $"Pfad: {path} | Dateigröße: {fi.Length / 1024} KB | e_lfanew: 0x{e_lfanew:X}"
            });
            return true;
        }
        catch { return false; }
    }

    // -------------------------------------------------------------------------
    // ReflectiveLoader string detection helper
    // -------------------------------------------------------------------------

    private async Task CheckFileForReflectiveLoaderAsync(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            byte[] header = new byte[4096];
            int bytesRead;

            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                bytesRead = await fs.ReadAsync(header.AsMemory(0, header.Length), ct).ConfigureAwait(false);
            }
            catch (IOException) { return; }

            if (bytesRead < 16) return;

            // Search for ASCII "ReflectiveLoader" in the first 4096 bytes
            var needle = System.Text.Encoding.ASCII.GetBytes("ReflectiveLoader");
            for (int i = 0; i <= bytesRead - needle.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (header[i + j] != needle[j]) { found = false; break; }
                }

                if (found)
                {
                    var fileName = Path.GetFileName(path);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"ReflectiveLoader-Export in DLL: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = path,
                        FileName = fileName,
                        Reason   = $"DLL '{fileName}' enthält in den ersten 4 KB den ASCII-String 'ReflectiveLoader'. " +
                                   "Dies ist der bekannte Export-Name, der von Metasploit, Cobalt Strike und anderen " +
                                   "Frameworks für reflektive DLL-Injektion verwendet wird. Die DLL kann sich selbst " +
                                   "ohne Windows-Lader in einen Prozess einschleusen.",
                        Detail   = $"Pfad: {path} | String-Offset: 0x{i:X}"
                    });
                    return;
                }
            }
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // Config file pattern checker
    // -------------------------------------------------------------------------

    private async Task CheckConfigFileForInjectionPatternsAsync(
        ScanContext ctx,
        string path,
        IEnumerable<string> patterns,
        string techniqueTitle,
        string reason,
        CancellationToken ct)
    {
        try
        {
            string content;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
            }
            catch (IOException) { return; }

            if (string.IsNullOrWhiteSpace(content)) return;

            foreach (var pattern in patterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    var fileName = Path.GetFileName(path);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"{techniqueTitle}: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = path,
                        FileName = fileName,
                        Reason   = $"{reason} Datei '{fileName}' enthält Muster '{pattern}'.",
                        Detail   = $"Pfad: {path} | Muster: {pattern}"
                    });
                    return;
                }
            }
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // Filesystem enumeration helper (bounded depth, per-directory exception handling)
    // -------------------------------------------------------------------------

    private IEnumerable<string> EnumerateFilesInSearchRoots(
        IEnumerable<string> roots,
        int maxDepth,
        CancellationToken ct)
    {
        foreach (var root in roots)
        {
            if (ct.IsCancellationRequested) yield break;
            if (!Directory.Exists(root)) continue;

            foreach (var file in EnumerateFilesRecursive(root, 0, maxDepth, ct))
            {
                if (ct.IsCancellationRequested) yield break;
                yield return file;
            }
        }
    }

    private IEnumerable<string> EnumerateFilesRecursive(
        string directory,
        int currentDepth,
        int maxDepth,
        CancellationToken ct)
    {
        if (ct.IsCancellationRequested) yield break;

        string[] files = Array.Empty<string>();
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { yield break; }
        catch (IOException) { yield break; }
        catch { yield break; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) yield break;
            yield return file;
        }

        if (currentDepth >= maxDepth) yield break;

        string[] subdirs = Array.Empty<string>();
        try { subdirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { yield break; }
        catch (IOException) { yield break; }
        catch { yield break; }

        foreach (var subdir in subdirs)
        {
            if (ct.IsCancellationRequested) yield break;

            foreach (var file in EnumerateFilesRecursive(subdir, currentDepth + 1, maxDepth, ct))
            {
                if (ct.IsCancellationRequested) yield break;
                yield return file;
            }
        }
    }
}
