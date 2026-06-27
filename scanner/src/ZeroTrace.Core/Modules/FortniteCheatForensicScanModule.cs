using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FortniteCheatForensicScanModule : IScanModule
{
    public string Name => "Fortnite Cheat Forensics";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    // Known Fortnite cheat file name keywords
    private static readonly string[] FortniteCheatFileKeywords =
    {
        "fortnite_hack", "fortnite_cheat", "fortnitehack", "fortnitecheat",
        "fn_aimbot", "fn_esp", "fn_hack", "fn_cheat", "fn_bypass",
        "wallhack_fn", "wallhack_fortnite", "fnaimbot", "fnesp",
        "fortnite_bypass", "fortnite_aimbot", "fortnite_esp",
        "fortnite_wallhack", "aimbot_fn", "esp_fn",
        "vbuck_hack", "vbuck_gen", "vbucks_hack", "vbuckgen",
        "fortnitecheats", "fncheat", "fncheats",
        "fn_injector", "fortnite_injector", "fninjector",
        "fn_loader", "fortnite_loader", "fnloader",
        "fn_silent", "silentaim_fn", "fn_silentaim",
        "fn_triggerbot", "triggerbot_fn",
        "fn_nospread", "nospread_fn", "fn_spread",
        "fn_fastbuild", "fastbuild_fn", "fn_build",
        "fortnite_eac", "fn_eac", "eac_bypass_fn",
        "fortnite_eac_bypass", "fn_eac_bypass",
        "pluto_fn", "pluto_fortnite", "fortnitepluto",
        "synapsex_fn", "synapse_fortnite",
        "fortnite_mem", "fnmem", "fn_memory",
        "fn_radar", "radar_fn", "fortnite_radar",
        "fortnite_spoofer", "fn_spoofer", "fnspoofer",
        "fortnitexxx", "fortniteaim"
    };

    // Known Fortnite cheat executable names
    private static readonly string[] FortniteCheatExeNames =
    {
        "fortnite_hack.exe", "fortnitehack.exe", "fnhack.exe",
        "fortnite_cheat.exe", "fortnitecheat.exe", "fncheat.exe",
        "fn_aimbot.exe", "fnaimbot.exe", "fortnite_aimbot.exe",
        "fortniteaimbot.exe", "fn_esp.exe", "fnesp.exe",
        "fortnite_esp.exe", "fortniteesp.exe",
        "vbuck_hack.exe", "vbuckhack.exe", "vbuck_gen.exe",
        "fn_bypass.exe", "fnbypass.exe", "fortnite_bypass.exe",
        "fn_injector.exe", "fninjector.exe", "fn_loader.exe",
        "fnloader.exe", "pluto.exe", "plutofn.exe",
        "fortnite_loader.exe", "fn_internal.exe", "fninternal.exe",
        "fn_external.exe", "fnexternal.exe", "fn_spoofer.exe",
        "fnspoofer.exe", "fortnite_spoofer.exe", "fn_eac.exe"
    };

    // Suspicious DLL names that may be injected into Fortnite
    private static readonly string[] FortniteSuspiciousDllNames =
    {
        "fn_aimbot.dll", "fnaimbot.dll", "fortnite_aimbot.dll",
        "fn_esp.dll", "fnesp.dll", "fortnite_esp.dll",
        "fn_hack.dll", "fnhack.dll", "fortnite_hack.dll",
        "fn_bypass.dll", "fnbypass.dll", "fortnite_bypass.dll",
        "fn_injector.dll", "fninjector.dll", "fn_loader.dll",
        "fn_silent.dll", "silentaim_fn.dll", "fn_nospread.dll",
        "fn_triggerbot.dll", "fn_wallhack.dll", "wallhack_fn.dll",
        "fn_internal.dll", "fninternal.dll", "fn_external.dll",
        "pluto.dll", "vbuck_hack.dll", "fn_mem.dll",
        "fn_fastbuild.dll", "fn_radar.dll", "fortnite_eac.dll",
        "fn_eac_bypass.dll", "eac_bypass_fn.dll"
    };

    // Log content keywords indicating Fortnite cheat activity
    private static readonly string[] FortniteCheatLogKeywords =
    {
        "fortnite hack", "fn aimbot", "fortnite esp", "fn wallhack",
        "vbuck generator", "fortnite cheat", "fn bypass", "eac bypass fn",
        "fn silent aim", "fortnite bypass", "fortnite aimbot",
        "fn esp", "fn hack", "fn cheat", "vbucks hack",
        "fortnite wallhack", "fn triggerbot", "fn no spread",
        "fn fast build", "fortnitecheats", "fncheat",
        "pluto fortnite", "synapse fortnite", "fn injector",
        "fortnite injector", "fn loader", "fortnite loader",
        "fn spoofer", "fortnite spoofer", "fortnitexxx",
        "fn nospread", "fn spread hack", "fn memory patch",
        "fn aimbot silent", "fn radar hack", "fortnite radar"
    };

    // Registry keys associated with Fortnite cheats
    private static readonly string[] FortniteCheatRegistryPaths =
    {
        @"Software\FortniteCheat",
        @"Software\FNHack",
        @"Software\FNCheat",
        @"Software\FNAimbot",
        @"Software\FNESP",
        @"Software\FortniteHack",
        @"Software\FortniteAimbot",
        @"Software\FortniteESP",
        @"Software\FNBypass",
        @"Software\FortniteBypass",
        @"Software\PlutoFN",
        @"Software\FortniteLoader",
        @"Software\FNLoader",
        @"Software\FortniteInjector",
        @"Software\FNInjector",
        @"Software\VBuckHack",
        @"Software\FNSpoofer",
        @"Software\FortniteSpoofer"
    };

    // Discord database keyword patterns for Fortnite cheats
    private static readonly string[] FortniteDiscordKeywords =
    {
        "fortnite hack", "fn esp", "fn aimbot", "fortnite cheat",
        "fn bypass eac", "vbuck hack", "fn wallhack", "fortnite bypass",
        "fn silent aim", "pluto fortnite", "fn injector",
        "fortnite loader", "fn spoofer", "fn nospread",
        "fortnite aimbot", "fn triggerbot", "fortnitecheats",
        "fn radar", "fortnite esp", "fn cheat", "vbuck gen"
    };

    // Prefetch names for Fortnite cheat executables (without extension, uppercase)
    private static readonly string[] FortnitePrefetchNames =
    {
        "FORTNITE_HACK", "FORTNITEHACK", "FNHACK", "FN_HACK",
        "FORTNITE_CHEAT", "FORTNITECHEAT", "FNCHEAT", "FN_CHEAT",
        "FN_AIMBOT", "FNAIMBOT", "FORTNITE_AIMBOT",
        "FN_ESP", "FNESP", "FORTNITE_ESP",
        "VBUCK_HACK", "VBUCKHACK", "VBUCK_GEN",
        "FN_BYPASS", "FNBYPASS", "FORTNITE_BYPASS",
        "FN_INJECTOR", "FNINJECTOR", "FN_LOADER", "FNLOADER",
        "PLUTO", "PLUTOFN", "FN_INTERNAL", "FNINTERNAL",
        "FN_EXTERNAL", "FNEXTERNAL", "FN_SPOOFER", "FNSPOOFER",
        "FN_EAC", "FORTNITE_EAC", "FORTNITEAIMBOT"
    };

    // EAC bypass artifact file names specific to Fortnite
    private static readonly string[] FortniteEacBypassArtifacts =
    {
        "EasyAntiCheat_EOS.dll.bak", "EasyAntiCheat_EOS.dll.orig",
        "EasyAntiCheat_EOS.dll.backup", "EasyAntiCheat_EOS.dll.disabled",
        "EasyAntiCheat_EOS.dll.old", "EasyAntiCheat_x64.dll.bak",
        "EasyAntiCheat_x64.dll.orig", "EasyAntiCheat.dll.bak",
        "EasyAntiCheat.dll.orig", "eac_bypass_fn.dll",
        "fn_eac_bypass.dll", "fortnite_eac_bypass.dll",
        "eac_fn.dll", "eac_loader_fn.dll", "eac_bypass.dll"
    };

    // Cheat Engine table keywords for Fortnite
    private static readonly string[] FortniteCtKeywords =
    {
        "fortnite", "fn_", "fortnitegame", "epicgames", "fncheat",
        "fortnite aimbot", "fortnite esp", "fortnite hack",
        "fortnite no spread", "fortnite fast build", "vbuck"
    };

    // .NET injector / reflection injection artifact patterns
    private static readonly string[] DotNetInjectorKeywords =
    {
        "fn_inject", "fortnite_inject", "reflection_inject",
        "dnspy", "dnlib", "fn_patch", "fortnite_patch",
        "harmony_fn", "minhook_fn", "fn_hook",
        "il2cpp_fn", "fn_il2cpp", "unity_fn",
        "mono_inject", "fn_mono", "fn_assembly",
        "fn_reflection", "reflection_fn"
    };

    // Memory patch artifact keywords for Fortnite
    private static readonly string[] MemoryPatchKeywords =
    {
        "fn_aimbot_patch", "fn_nospread_patch", "fn_fastbuild_patch",
        "fn_memory_patch", "fortnite_memory_patch", "fn_patch",
        "fn_norecoil_patch", "fn_silent_patch", "fn_triggerbot_patch",
        "fn_radar_patch", "fn_wallhack_patch", "fn_esp_patch"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starte Fortnite-Cheat-Forensik...");

        await Task.WhenAll(
            CheckAppDataFiles(ctx, ct),
            CheckTempFiles(ctx, ct),
            CheckProgramFilesArtifacts(ctx, ct),
            CheckFortniteGameDirectory(ctx, ct),
            CheckFortniteConfigFiles(ctx, ct),
            CheckLogFiles(ctx, ct),
            CheckRegistryKeys(ctx, ct),
            CheckEpicGamesLauncherRegistry(ctx, ct),
            CheckPrefetchArtifacts(ctx, ct),
            CheckUserAssist(ctx, ct),
            CheckDiscordArtifacts(ctx, ct),
            CheckEacBypassArtifacts(ctx, ct),
            CheckDotNetInjectorArtifacts(ctx, ct),
            CheckMemoryPatchArtifacts(ctx, ct),
            CheckCheatEngineTables(ctx, ct),
            CheckSuspiciousScripts(ctx, ct),
            CheckDownloadsFolder(ctx, ct),
            CheckDesktopArtifacts(ctx, ct),
            CheckStartupArtifacts(ctx, ct),
            CheckDocumentsArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "Fortnite-Cheat-Forensik abgeschlossen.");
    }

    // --- Per-directory/file helpers -------------------------------------------

    private static bool MatchesCheatKeyword(string text, string[] keywords)
    {
        foreach (var kw in keywords)
        {
            if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static bool IsExactCheatExe(string fileName, string[] exeNames)
    {
        foreach (var name in exeNames)
        {
            if (fileName.Equals(name, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static async Task<bool> FileContentContainsAny(string path, string[] keywords, CancellationToken ct)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = await sr.ReadToEndAsync(ct);
            foreach (var kw in keywords)
            {
                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return false;
    }

    private static async Task<string?> FileContentFirstMatch(string path, string[] keywords, CancellationToken ct)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = await sr.ReadToEndAsync(ct);
            foreach (var kw in keywords)
            {
                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    return kw;
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return null;
    }

    // --- Check methods (each returns Task from Task.Run) -----------------------

    private Task CheckAppDataFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var dirsToScan = new[]
        {
            appdata,
            localAppdata,
            Path.Combine(appdata, "Temp"),
            Path.Combine(localAppdata, "Temp"),
        };

        foreach (var dir in dirsToScan)
        {
            if (!Directory.Exists(dir)) continue;

            string[] entries;
            try { entries = Directory.GetFileSystemEntries(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var entry in entries)
            {
                if (ct.IsCancellationRequested) return;
                var name = Path.GetFileName(entry);

                if (MatchesCheatKeyword(name, FortniteCheatFileKeywords) ||
                    IsExactCheatExe(name, FortniteCheatExeNames))
                {
                    ctx.IncrementFiles();
                    bool isDir = Directory.Exists(entry);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Fortnite-Cheat-Artefakt in AppData: {name}",
                        Risk = RiskLevel.High,
                        Location = entry,
                        FileName = isDir ? null : name,
                        Sha256 = isDir ? null : HashUtil.TryComputeSha256(entry, 64 * 1024 * 1024),
                        Reason = $"[AppData] {(isDir ? "Verzeichnis" : "Datei")} '{name}' in AppData " +
                                 "entspricht bekanntem Fortnite-Cheat-Muster. Fortnite-Cheat-Tools wie Pluto, " +
                                 "FortniteXXX-Loader, Synapse X fuer Fortnite und aehnliche hinterlassen " +
                                 "Konfigurationsdaten und Loader-Dateien im AppData-Verzeichnis."
                    });
                }
            }
        }

        // Check known Fortnite cheat config subdirectories
        var knownSubdirs = new[]
        {
            Path.Combine(appdata, "FortniteCheat"),
            Path.Combine(appdata, "FNHack"),
            Path.Combine(appdata, "FNCheat"),
            Path.Combine(appdata, "PlutoFN"),
            Path.Combine(appdata, "FortniteLoader"),
            Path.Combine(appdata, "FNLoader"),
            Path.Combine(appdata, "FNInjector"),
            Path.Combine(appdata, "FortniteBypass"),
            Path.Combine(localAppdata, "FortniteCheat"),
            Path.Combine(localAppdata, "FNHack"),
            Path.Combine(localAppdata, "PlutoFN"),
            Path.Combine(localAppdata, "FNSpoofer"),
        };

        foreach (var subdir in knownSubdirs)
        {
            if (!Directory.Exists(subdir)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Fortnite-Cheat-Verzeichnis gefunden: {Path.GetFileName(subdir)}",
                Risk = RiskLevel.High,
                Location = subdir,
                Reason = $"[AppData] Das Verzeichnis '{subdir}' ist ein bekanntes Konfigurations- oder " +
                         "Installationsverzeichnis eines Fortnite-Cheat-Tools. Die Existenz dieses " +
                         "Verzeichnisses deutet auf die Nutzung eines Fortnite-Cheats hin."
            });
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckTempFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var tempDirs = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            @"C:\Temp",
            @"C:\tmp"
        };

        foreach (var tempDir in tempDirs)
        {
            if (!Directory.Exists(tempDir)) continue;

            string[] files;
            try { files = Directory.GetFiles(tempDir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (!MatchesCheatKeyword(fn, FortniteCheatFileKeywords) &&
                    !IsExactCheatExe(fn, FortniteCheatExeNames))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Cheat-Artefakt im Temp-Verzeichnis: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"[Temp] Datei '{fn}' im Temp-Verzeichnis entspricht bekanntem Fortnite-Cheat-Muster. " +
                             "Fortnite-Cheat-Loader und -Injektoren extrahieren temporaere Dateien waehrend " +
                             "der Ausfuehrung in Temp-Verzeichnisse."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckProgramFilesArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var programDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        foreach (var progDir in programDirs)
        {
            if (!Directory.Exists(progDir)) continue;

            string[] dirs;
            try { dirs = Directory.GetDirectories(progDir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var subDir in dirs)
            {
                if (ct.IsCancellationRequested) return;
                var dirName = Path.GetFileName(subDir);

                if (!MatchesCheatKeyword(dirName, FortniteCheatFileKeywords)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Cheat-Installation in ProgramFiles: {dirName}",
                    Risk = RiskLevel.Critical,
                    Location = subDir,
                    Reason = $"[ProgramFiles] Verzeichnis '{dirName}' in den Programmdateien entspricht einem " +
                             "bekannten Fortnite-Cheat-Tool-Namen. Dies deutet auf eine vollstaendige " +
                             "Installation eines Fortnite-Cheats hin."
                });

                string[] innerFiles;
                try { innerFiles = Directory.GetFiles(subDir, "*.exe", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var innerFile in innerFiles)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Fortnite-Cheat-Executable in ProgramFiles: {Path.GetFileName(innerFile)}",
                        Risk = RiskLevel.Critical,
                        Location = innerFile,
                        FileName = Path.GetFileName(innerFile),
                        Sha256 = HashUtil.TryComputeSha256(innerFile, 64 * 1024 * 1024),
                        Reason = $"[ProgramFiles] Ausfuehrbare Datei in Fortnite-Cheat-Installationsverzeichnis " +
                                 $"'{dirName}'. Starkes Indiz fuer eine installierte Fortnite-Cheat-Software."
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFortniteGameDirectory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // Common Epic Games / Fortnite install paths
        var fortniteBasePaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FortniteGame"),
            @"C:\Program Files\Epic Games\Fortnite\FortniteGame",
            @"C:\Program Files (x86)\Epic Games\Fortnite\FortniteGame",
            @"C:\Epic Games\Fortnite\FortniteGame",
        };

        // Also check Epic Games install from registry
        var epicPaths = GetEpicGamesFortniteInstallPaths();
        var allPaths = fortniteBasePaths.Concat(epicPaths)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        foreach (var fortniteBase in allPaths)
        {
            var binDir = Path.Combine(fortniteBase, "Binaries", "Win64");
            if (!Directory.Exists(binDir)) continue;

            // Scan Win64 binaries directory for suspicious DLLs
            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(binDir, "*.dll", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            var legitimateDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "EasyAntiCheat_EOS.dll", "FortniteClient-Win64-Shipping.dll",
                "XINPUT1_3.dll", "XINPUT1_4.dll", "d3d11.dll", "d3d12.dll",
                "dxgi.dll", "dbghelp.dll", "version.dll", "winmm.dll"
            };

            foreach (var dll in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(dll);

                if (legitimateDlls.Contains(fn)) continue;

                bool isSuspiciousDll = FortniteSuspiciousDllNames.Any(
                    s => fn.Equals(s, StringComparison.OrdinalIgnoreCase) ||
                         fn.Contains(s.Replace(".dll", ""), StringComparison.OrdinalIgnoreCase));

                if (!isSuspiciousDll && MatchesCheatKeyword(fn, FortniteCheatFileKeywords))
                    isSuspiciousDll = true;

                if (!isSuspiciousDll) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtige DLL im Fortnite-Binaries-Verzeichnis: {fn}",
                    Risk = RiskLevel.Critical,
                    Location = dll,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(dll, 64 * 1024 * 1024),
                    Reason = $"[FortniteBin] DLL '{fn}' im Fortnite-Binaries-Verzeichnis '{binDir}' " +
                             "ist keine bekannte legitime Fortnite-DLL und entspricht einem Cheat-Muster. " +
                             "Injizierte Cheat-DLLs werden oft direkt im Binaries-Verzeichnis platziert."
                });
            }

            // Check for EAC bypass artifacts in Fortnite directory
            await CheckFortniteEacArtifacts(ctx, fortniteBase, binDir, ct);

            // Scan for suspicious executables in Win64 folder
            string[] exeFiles;
            try { exeFiles = Directory.GetFiles(binDir, "*.exe", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            var legitimateFortniteExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "FortniteClient-Win64-Shipping.exe", "FortniteLauncher.exe",
                "CrashReportClient.exe", "EpicGamesLauncher.exe"
            };

            foreach (var exe in exeFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(exe);

                if (legitimateFortniteExes.Contains(fn)) continue;

                if (MatchesCheatKeyword(fn, FortniteCheatFileKeywords) ||
                    IsExactCheatExe(fn, FortniteCheatExeNames))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige EXE im Fortnite-Verzeichnis: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = exe,
                        FileName = fn,
                        Sha256 = HashUtil.TryComputeSha256(exe, 64 * 1024 * 1024),
                        Reason = $"[FortniteBin] Ausfuehrbare Datei '{fn}' im Fortnite-Binaries-Verzeichnis " +
                                 "ist keine bekannte legitime Fortnite-Datei und entspricht einem Cheat-Muster."
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private static async Task CheckFortniteEacArtifacts(
        ScanContext ctx, string fortniteBase, string binDir, CancellationToken ct)
    {
        var suspiciousExtensions = new[] { ".bak", ".orig", ".backup", ".old", ".disabled" };

        foreach (var searchDir in new[] { fortniteBase, binDir })
        {
            if (!Directory.Exists(searchDir)) continue;

            string[] files;
            try { files = Directory.GetFiles(searchDir, "*EasyAntiCheat*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var ext = Path.GetExtension(file);

                if (!suspiciousExtensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase)))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = ctx.CurrentModule.Length > 0 ? ctx.CurrentModule : "Fortnite Cheat Forensics",
                    Title = $"Umbenannte EAC-Datei im Fortnite-Verzeichnis: {Path.GetFileName(file)}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"[ForniteEAC] Umbenannte EasyAntiCheat-Datei '{Path.GetFileName(file)}' " +
                             "im Fortnite-Verzeichnis gefunden. Dies ist ein klassisches EAC-Bypass-Artefakt: " +
                             "die originale Anti-Cheat-DLL wird umbenannt und durch eine manipulierte Version ersetzt."
                });
            }
        }

        await Task.CompletedTask;
    }

    private Task CheckFortniteConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // Fortnite stores user configs in LocalAppData\FortniteGame\Saved\Config\
        var fortniteConfigBase = Path.Combine(localAppdata, "FortniteGame", "Saved", "Config");
        var fortniteConfigPaths = new[]
        {
            Path.Combine(fortniteConfigBase, "WindowsClient"),
            Path.Combine(fortniteConfigBase, "Windows"),
            fortniteConfigBase,
        };

        // Suspicious ini config values indicating modified game settings
        var suspiciousConfigKeywords = new[]
        {
            "bAimAssist=False", "bAimAssistForController=False",
            "PrivacyRadius=0", "FOV=", "bShowFPS=True",
            "cheat", "hack", "aimbot", "esp", "wallhack",
            "nospread", "norecoil", "bypass"
        };

        foreach (var configDir in fortniteConfigPaths)
        {
            if (!Directory.Exists(configDir)) continue;

            string[] iniFiles;
            try { iniFiles = Directory.GetFiles(configDir, "*.ini", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var iniFile in iniFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(iniFile);

                if (MatchesCheatKeyword(fn, FortniteCheatFileKeywords))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige Fortnite-Config-Datei: {fn}",
                        Risk = RiskLevel.High,
                        Location = iniFile,
                        FileName = fn,
                        Reason = $"[FortniteConfig] Config-Datei '{fn}' hat einen Fortnite-Cheat-bezogenen Namen. " +
                                 "Cheat-Tools erstellen oft eigene Konfigurationsdateien im Fortnite-Config-Verzeichnis."
                    });
                    continue;
                }

                string? matchedKeyword = await FileContentFirstMatch(iniFile, suspiciousConfigKeywords, ct);
                if (matchedKeyword == null) continue;

                // Only flag cheat-specific keywords, not legitimate game config changes
                var cheatOnlyKeywords = new[]
                {
                    "cheat", "hack", "aimbot", "esp", "wallhack",
                    "nospread", "norecoil", "bypass"
                };

                if (!cheatOnlyKeywords.Any(k => matchedKeyword.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Config mit Cheat-Begriff: {fn}",
                    Risk = RiskLevel.Medium,
                    Location = iniFile,
                    FileName = fn,
                    Reason = $"[FortniteConfig] Fortnite-Konfigurationsdatei '{fn}' enthaelt den verdaechtigen " +
                             $"Begriff '{matchedKeyword}'. Dies deutet auf modifizierte Spieleinstellungen " +
                             "durch Cheat-Software hin."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckLogFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logDirs = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Logs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Logs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Logs"),
            Path.GetTempPath(),
        };

        // Add Fortnite-specific log locations
        var localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        logDirs.Add(Path.Combine(localAppdata, "FortniteGame", "Saved", "Logs"));

        // Add Epic Games log paths
        foreach (var epicFortniteDir in GetEpicGamesFortniteInstallPaths())
        {
            logDirs.Add(Path.Combine(epicFortniteDir, "Saved", "Logs"));
        }

        foreach (var logDir in logDirs)
        {
            if (!Directory.Exists(logDir)) continue;

            string[] logFiles;
            try { logFiles = Directory.GetFiles(logDir, "*.log", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string? matchedKeyword = await FileContentFirstMatch(logFile, FortniteCheatLogKeywords, ct);
                if (matchedKeyword == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Cheat-Begriff in Log: {Path.GetFileName(logFile)}",
                    Risk = RiskLevel.Medium,
                    Location = logFile,
                    FileName = Path.GetFileName(logFile),
                    Reason = $"[Logs] Log-Datei '{logFile}' enthaelt den verdaechtigen Begriff '{matchedKeyword}'. " +
                             "Dies deutet darauf hin, dass ein Fortnite-Cheat-Tool auf diesem System ausgefuehrt wurde."
                });
            }

            // Also scan text files
            string[] txtFiles;
            try { txtFiles = Directory.GetFiles(logDir, "*.txt", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var txtFile in txtFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string? matchedKeyword = await FileContentFirstMatch(txtFile, FortniteCheatLogKeywords, ct);
                if (matchedKeyword == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Cheat-Begriff in Textdatei: {Path.GetFileName(txtFile)}",
                    Risk = RiskLevel.Medium,
                    Location = txtFile,
                    FileName = Path.GetFileName(txtFile),
                    Reason = $"[Logs] Textdatei '{txtFile}' enthaelt den verdaechtigen Begriff '{matchedKeyword}'. " +
                             "Moegliches Log oder Konfigurationsdatei eines Fortnite-Cheat-Tools."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRegistryKeys(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);

            foreach (var regPath in FortniteCheatRegistryPaths)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var key = hkcu.OpenSubKey(regPath);
                    if (key == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Fortnite-Cheat-Registrierungsschluessel: {regPath}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{regPath}",
                        Reason = $"[Registry] Registrierungsschluessel 'HKCU\\{regPath}' existiert. " +
                                 "Dieser Schluessel wird von bekannten Fortnite-Cheat-Tools fuer " +
                                 "Konfigurationsspeicherung oder Lizenzpruefung verwendet."
                    });
                }
                catch (UnauthorizedAccessException) { }
            }

            // Check uninstall keys for Fortnite cheat software
            ctx.IncrementRegistryKeys();
            using var uninstallKey = hkcu.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall");
            if (uninstallKey != null)
            {
                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var subKey = uninstallKey.OpenSubKey(subKeyName);
                        if (subKey == null) continue;

                        var displayName = subKey.GetValue("DisplayName")?.ToString() ?? "";
                        var publisher = subKey.GetValue("Publisher")?.ToString() ?? "";
                        var installLocation = subKey.GetValue("InstallLocation")?.ToString() ?? "";

                        if (MatchesCheatKeyword(displayName, FortniteCheatFileKeywords) ||
                            MatchesCheatKeyword(publisher, FortniteCheatFileKeywords) ||
                            MatchesCheatKeyword(installLocation, FortniteCheatFileKeywords))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Fortnite-Cheat-Software in Deinstallation: {displayName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{subKeyName}",
                                Reason = $"[Registry] Deinstallationseintrag '{displayName}' " +
                                         $"(Herausgeber: {publisher}) entspricht einem bekannten Fortnite-Cheat-Muster."
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
        catch (UnauthorizedAccessException) { }

        // Check HKLM Uninstall
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            ctx.IncrementRegistryKeys();

            using var uninstallKey = hklm.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall");
            if (uninstallKey != null)
            {
                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var subKey = uninstallKey.OpenSubKey(subKeyName);
                        if (subKey == null) continue;

                        var displayName = subKey.GetValue("DisplayName")?.ToString() ?? "";
                        if (MatchesCheatKeyword(displayName, FortniteCheatFileKeywords))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Fortnite-Cheat-Software (System) in Deinstallation: {displayName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\{subKeyName}",
                                Reason = $"[Registry] Systemweiter Deinstallationseintrag '{displayName}' " +
                                         "entspricht einem bekannten Fortnite-Cheat-Muster."
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
        catch (UnauthorizedAccessException) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckEpicGamesLauncherRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // Check Epic Games Launcher registry for suspicious entries
        var epicRegistryPaths = new[]
        {
            @"Software\Epic Games",
            @"Software\EpicGamesLauncher",
            @"Software\Epic Games\EOS",
        };

        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);

            foreach (var epicPath in epicRegistryPaths)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var key = hkcu.OpenSubKey(epicPath);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName)?.ToString() ?? "";

                        if (!MatchesCheatKeyword(value, FortniteCheatFileKeywords) &&
                            !MatchesCheatKeyword(valueName, FortniteCheatFileKeywords))
                            continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger Epic-Launcher-Registry-Eintrag: {valueName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{epicPath}",
                            Reason = $"[Registry] Epic Games Launcher Registry-Eintrag '{valueName}' = '{value}' " +
                                     "enthaelt verdaechtigen Inhalt, der auf Fortnite-Cheat-Nutzung hindeutet. " +
                                     "Cheat-Tools modifizieren manchmal Epic-Launcher-Eintraege fuer Persistenz oder Bypass."
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
        catch (UnauthorizedAccessException) { }

        // Check for EAC bypass in HKLM Epic entries
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            ctx.IncrementRegistryKeys();

            using var epicKey = hklm.OpenSubKey(@"Software\EasyAntiCheat");
            if (epicKey != null)
            {
                foreach (var subKeyName in epicKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var gameKey = epicKey.OpenSubKey(subKeyName);
                        if (gameKey == null) continue;

                        var gameName = gameKey.GetValue("GameName")?.ToString() ?? "";
                        if (!gameName.Contains("Fortnite", StringComparison.OrdinalIgnoreCase)) continue;

                        foreach (var valueName in gameKey.GetValueNames())
                        {
                            var value = gameKey.GetValue(valueName)?.ToString() ?? "";
                            if (MatchesCheatKeyword(value, FortniteCheatFileKeywords))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Verdaechtiger Fortnite-EAC-Registry-Eintrag: {valueName}",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\Software\EasyAntiCheat\{subKeyName}",
                                    Reason = $"[Registry] EAC-Registrierungseintrag fuer Fortnite '{valueName}' = '{value}' " +
                                             "enthaelt verdaechtigen Inhalt. Moegliche EAC-Konfigurationsmanipulation."
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
        catch (UnauthorizedAccessException) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        string[] pfFiles;
        try { pfFiles = Directory.GetFiles(prefetchDir, "*.pf"); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var pfFile in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var baseName = Path.GetFileNameWithoutExtension(pfFile);
            var dash = baseName.LastIndexOf('-');
            var exeName = (dash > 0 && baseName.Length - dash == 9) ? baseName[..dash] : baseName;

            bool matched = FortnitePrefetchNames.Any(
                n => exeName.Equals(n, StringComparison.OrdinalIgnoreCase));

            if (!matched && MatchesCheatKeyword(exeName, FortniteCheatFileKeywords))
                matched = true;

            if (!matched) continue;

            var lastWrite = SafeFileTime(pfFile);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Fortnite-Cheat-Prefetch: {exeName}.exe",
                Risk = RiskLevel.High,
                Location = pfFile,
                FileName = exeName + ".exe",
                Reason = $"[Prefetch] Prefetch-Datei fuer '{exeName}.exe' gefunden. " +
                         "Dies bedeutet, dass dieses bekannte Fortnite-Cheat-Programm auf diesem System " +
                         "ausgefuehrt wurde, auch wenn die Datei inzwischen geloescht wurde.",
                Detail = lastWrite != default
                    ? $"Prefetch zuletzt aktualisiert: {lastWrite:yyyy-MM-dd HH:mm:ss}"
                    : null
            });
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckUserAssist(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var ua = baseKey.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (ua == null) return;

            foreach (var guid in ua.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                using var count = ua.OpenSubKey($@"{guid}\Count");
                if (count == null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in count.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    var decoded = Rot13Decode(valueName);
                    if (string.IsNullOrWhiteSpace(decoded)) continue;

                    var fn = SafePathFileName(decoded);
                    if (!MatchesCheatKeyword(fn, FortniteCheatFileKeywords) &&
                        !IsExactCheatExe(fn, FortniteCheatExeNames) &&
                        !MatchesCheatKeyword(decoded, FortniteCheatFileKeywords))
                        continue;

                    DateTime? lastRun = null;
                    try
                    {
                        var data = count.GetValue(valueName) as byte[];
                        if (data != null && data.Length >= 72)
                        {
                            var ft = BitConverter.ToInt64(data, 60);
                            if (ft > 0) lastRun = DateTime.FromFileTime(ft);
                        }
                    }
                    catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Fortnite-Cheat-Start via UserAssist: {fn}",
                        Risk = RiskLevel.High,
                        Location = decoded,
                        FileName = fn,
                        Reason = $"[UserAssist] UserAssist-Eintrag '{fn}' (dekodiert aus ROT13) entspricht " +
                                 "einem bekannten Fortnite-Cheat-Muster. UserAssist protokolliert GUI-Programmstarts.",
                        Detail = lastRun.HasValue
                            ? $"Zuletzt gestartet: {lastRun.Value.ToLocalTime():yyyy-MM-dd HH:mm}"
                            : null
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDiscordArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roamingAppdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var discordPaths = new[]
        {
            Path.Combine(roamingAppdata, "discord", "Cache"),
            Path.Combine(roamingAppdata, "discord", "Local Storage", "leveldb"),
            Path.Combine(localAppdata, "Discord", "Cache"),
            Path.Combine(localAppdata, "Discord", "Local Storage", "leveldb"),
        };

        foreach (var discordPath in discordPaths)
        {
            if (!Directory.Exists(discordPath)) continue;

            string[] cacheFiles;
            try { cacheFiles = Directory.GetFiles(discordPath, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var cacheFile in cacheFiles)
            {
                if (ct.IsCancellationRequested) return;

                var ext = Path.GetExtension(cacheFile).ToLowerInvariant();
                if (ext is not ("" or ".log" or ".ldb" or ".dat" or ".tmp")) continue;

                try
                {
                    var info = new FileInfo(cacheFile);
                    if (info.Length > 5 * 1024 * 1024) continue;
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();
                string? matchedKeyword = await FileContentFirstMatch(cacheFile, FortniteDiscordKeywords, ct);
                if (matchedKeyword == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord-Artefakt mit Fortnite-Cheat-Bezug: {Path.GetFileName(cacheFile)}",
                    Risk = RiskLevel.Medium,
                    Location = cacheFile,
                    FileName = Path.GetFileName(cacheFile),
                    Reason = $"[Discord] Discord-Cache-Datei enthaelt den Schluessel-Begriff '{matchedKeyword}'. " +
                             "Dies deutet auf Discord-Kommunikation ueber Fortnite-Cheat-Tools oder -Dienste hin " +
                             "(z.B. Kauf, Nutzung oder Verteilung von Fortnite-Cheats)."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckEacBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var dirsToCheck = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        var eacDirs = new[]
        {
            @"C:\Program Files (x86)\EasyAntiCheat",
            @"C:\Program Files\EasyAntiCheat",
        };
        dirsToCheck.AddRange(eacDirs);
        dirsToCheck.AddRange(GetEpicGamesFortniteInstallPaths());

        foreach (var dir in dirsToCheck)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                foreach (var bypassName in FortniteEacBypassArtifacts)
                {
                    if (!fn.Equals(bypassName, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Fortnite-EAC-Bypass-Artefakt: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                        Reason = $"[EACBypass] Datei '{fn}' ist ein bekanntes EasyAntiCheat-Bypass-Artefakt " +
                                 "fuer Fortnite. EasyAntiCheat EOS schuetzt Fortnite. Das Umbenennen oder " +
                                 "Ersetzen dieser DLL ist eine bekannte Methode zur Cheat-Aktivierung."
                    });
                    break;
                }
            }
        }

        // Also scan for Fortnite-specific EAC bypass DLLs with keyword matching
        foreach (var dir in dirsToCheck)
        {
            if (!Directory.Exists(dir)) continue;

            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dll in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(dll);

                if (!MatchesCheatKeyword(fn, new[] { "eac_bypass", "eac_fn", "fn_eac", "bypass_eac" }))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"EAC-Bypass-DLL fuer Fortnite: {fn}",
                    Risk = RiskLevel.Critical,
                    Location = dll,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(dll, 64 * 1024 * 1024),
                    Reason = $"[EACBypass] DLL '{fn}' hat einen EAC-Bypass-bezogenen Namen und wurde " +
                             "ausserhalb des normalen EAC-Verzeichnisses gefunden. Wahrscheinlicher Fortnite-EAC-Bypass."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDotNetInjectorArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // .NET injector artifacts: dnSpy edits, Harmony patches, reflection injectors
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        // Check for dnSpy project files (indicate assembly editing)
        var dnSpyKeywords = new[]
        {
            "fortnite", "fortniteclient", "fn_", "fncheat", "fnhack"
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            // Check for .NET injector DLLs with known patterns
            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dll in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(dll);

                if (!MatchesCheatKeyword(fn, DotNetInjectorKeywords)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $".NET-Injektor-Artefakt fuer Fortnite: {fn}",
                    Risk = RiskLevel.High,
                    Location = dll,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(dll, 64 * 1024 * 1024),
                    Reason = $"[DotNetInjector] DLL '{fn}' entspricht einem bekannten .NET-Injektor-Muster " +
                             "fuer Fortnite. Fortnite-Cheats nutzen manchmal .NET Reflection oder Harmony-Patches " +
                             "fuer IL-Code-Manipulation und In-Process-Injection."
                });
            }

            // Check for dnSpy-related files (modified assemblies)
            string[] exeFiles;
            try { exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var exe in exeFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(exe);

                if (fn.Equals("dnSpy.exe", StringComparison.OrdinalIgnoreCase) ||
                    fn.Equals("dnSpyEx.exe", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"dnSpy-Assembly-Editor gefunden: {fn}",
                        Risk = RiskLevel.Medium,
                        Location = exe,
                        FileName = fn,
                        Sha256 = HashUtil.TryComputeSha256(exe, 64 * 1024 * 1024),
                        Reason = $"[DotNetInjector] dnSpy '{fn}' ist ein .NET-Assembly-Debugger/-Editor, " +
                                 "der haeufig zur Analyse und Modifikation von Spielcode verwendet wird. " +
                                 "In Verbindung mit Fortnite deutet das auf moegliche IL2CPP-Analyse hin."
                    });
                }
            }

            // Check for injection-related config/script files
            string[] jsonFiles;
            try { jsonFiles = Directory.GetFiles(dir, "*.json", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var json in jsonFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(json);

                if (!MatchesCheatKeyword(fn, FortniteCheatFileKeywords)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtige Fortnite-Cheat-JSON-Konfiguration: {fn}",
                    Risk = RiskLevel.Medium,
                    Location = json,
                    FileName = fn,
                    Reason = $"[DotNetInjector] JSON-Datei '{fn}' hat einen Fortnite-Cheat-bezogenen Namen. " +
                             ".NET-Injektoren und Loader-Tools verwenden oft JSON fuer Konfiguration."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMemoryPatchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // Memory patch artifacts: scripts or configs for aimbot, no-spread, fast-build patches
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (MatchesCheatKeyword(fn, MemoryPatchKeywords))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Fortnite-Memory-Patch-Artefakt: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                        Reason = $"[MemPatch] Datei '{fn}' entspricht einem bekannten Fortnite-Speicher-Patch-Muster. " +
                                 "Solche Dateien werden verwendet, um Spielspeicher-Adressen fuer Aimbot, " +
                                 "No-Spread, Fast-Build oder andere Cheat-Funktionen zu patchen."
                    });
                    continue;
                }

                // Check binary files for memory patch signatures
                var ext = Path.GetExtension(fn).ToLowerInvariant();
                if (ext is not (".dll" or ".exe" or ".bin" or ".dat")) continue;

                if (!MatchesCheatKeyword(fn, FortniteCheatFileKeywords)) continue;

                try
                {
                    var info = new FileInfo(file);
                    if (info.Length > 10 * 1024 * 1024) continue; // Skip > 10MB
                }
                catch (IOException) { continue; }

                // Check content for memory patch indicators
                var memPatchContentKeywords = new[]
                {
                    "AimBotEnabled", "NoSpreadEnabled", "FastBuildEnabled",
                    "WallHackEnabled", "ESPEnabled", "SilentAimEnabled",
                    "TriggerBotEnabled", "RadarHackEnabled",
                    "FortniteClient", "FortniteShooting", "FortniteBuilding"
                };

                string? matchedKeyword = await FileContentFirstMatch(file, memPatchContentKeywords, ct);
                if (matchedKeyword == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Memory-Patch-Inhalt: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"[MemPatch] Datei '{fn}' enthaelt Memory-Patch-Begriff '{matchedKeyword}'. " +
                             "Dies deutet auf ein Tool hin, das Fortnite-Spielspeicher fuer Cheat-Funktionen patcht."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatEngineTables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Cheat Engine"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Cheat Engine"),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] ctFiles;
            try { ctFiles = Directory.GetFiles(dir, "*.CT", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var ctFile in ctFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string? matchedKeyword = await FileContentFirstMatch(ctFile, FortniteCtKeywords, ct);
                if (matchedKeyword == null)
                {
                    var fn = Path.GetFileName(ctFile);
                    if (!MatchesCheatKeyword(fn, FortniteCtKeywords)) continue;
                }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat-Engine-Tabelle fuer Fortnite: {Path.GetFileName(ctFile)}",
                    Risk = RiskLevel.High,
                    Location = ctFile,
                    FileName = Path.GetFileName(ctFile),
                    Reason = $"[CheatEngine] Cheat-Engine-Tabelle '{Path.GetFileName(ctFile)}' " +
                             (matchedKeyword != null ? $"enthaelt Fortnite-Bezug '{matchedKeyword}'. " : "hat Fortnite-bezogenen Namen. ") +
                             "Cheat-Engine-Tabellen koennen zur Manipulation des Fortnite-Spielprozesses " +
                             "verwendet werden (z.B. Aimbot, No-Spread, Fast-Build, Wanddurchsicht)."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckSuspiciousScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var fortniteInjectionKeywords = new[]
        {
            "inject fortnite", "fortnite inject", "fortnite cheat", "fn hack",
            "fn aimbot", "fn esp", "fn bypass", "eac bypass fn",
            "FortniteClient", "FortniteLauncher", "EasyAntiCheat",
            "fn loader", "fortnite loader", "fn injector", "fortnite injector",
            "fn spoofer", "fn nospread", "fn silent aim", "fn triggerbot",
            "vbuck hack", "vbuck gen", "pluto fortnite", "fortnitexxx"
        };

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
        };

        var scriptExtensions = new[] { "*.bat", "*.cmd", "*.ps1", "*.vbs", "*.js", "*.wsf" };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            foreach (var ext in scriptExtensions)
            {
                string[] scriptFiles;
                try { scriptFiles = Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var script in scriptFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(script);

                    if (MatchesCheatKeyword(fn, FortniteCheatFileKeywords))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiges Fortnite-Cheat-Skript: {fn}",
                            Risk = RiskLevel.High,
                            Location = script,
                            FileName = fn,
                            Reason = $"[Scripts] Skript-Datei '{fn}' hat einen Fortnite-Cheat-bezogenen Namen. " +
                                     "Solche Skripte werden fuer Fortnite-Cheat-Injection oder -Loader-Aktivierung verwendet."
                        });
                        continue;
                    }

                    string? matchedKeyword = await FileContentFirstMatch(script, fortniteInjectionKeywords, ct);
                    if (matchedKeyword == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Skript mit Fortnite-Cheat-Inhalt: {fn}",
                        Risk = RiskLevel.High,
                        Location = script,
                        FileName = fn,
                        Reason = $"[Scripts] Skript '{fn}' enthaelt verdaechtigen Begriff '{matchedKeyword}'. " +
                                 "Fortnite-Cheat-Injektions- und Loader-Skripte enthalten oft Verweise auf " +
                                 "den Fortnite-Prozess, EAC oder bekannte Cheat-Werkzeuge."
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDownloadsFolder(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var downloadsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        if (!Directory.Exists(downloadsPath)) return;

        string[] files;
        try { files = Directory.GetFiles(downloadsPath, "*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(file);

            if (!MatchesCheatKeyword(fn, FortniteCheatFileKeywords) &&
                !IsExactCheatExe(fn, FortniteCheatExeNames))
                continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Fortnite-Cheat-Datei im Downloads-Ordner: {fn}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = fn,
                Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                Reason = $"[Downloads] Datei '{fn}' im Downloads-Ordner entspricht einem bekannten " +
                         "Fortnite-Cheat-Muster. Dies deutet darauf hin, dass ein Fortnite-Cheat-Tool " +
                         "heruntergeladen wurde."
            });
        }

        // Check archives for cheat-related names
        var archiveExts = new[] { "*.zip", "*.rar", "*.7z" };
        foreach (var archExt in archiveExts)
        {
            string[] archiveFiles;
            try { archiveFiles = Directory.GetFiles(downloadsPath, archExt, SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var archive in archiveFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(archive);

                if (!MatchesCheatKeyword(fn, FortniteCheatFileKeywords)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Cheat-Archiv im Downloads-Ordner: {fn}",
                    Risk = RiskLevel.High,
                    Location = archive,
                    FileName = fn,
                    Reason = $"[Downloads] Archiv '{fn}' im Downloads-Ordner entspricht einem Fortnite-Cheat-Muster. " +
                             "Fortnite-Cheat-Tools werden oft als komprimierte Archive vertrieben."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDesktopArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        if (!Directory.Exists(desktopPath)) return;

        string[] files;
        try { files = Directory.GetFiles(desktopPath, "*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(file);

            if (!MatchesCheatKeyword(fn, FortniteCheatFileKeywords) &&
                !IsExactCheatExe(fn, FortniteCheatExeNames))
                continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Fortnite-Cheat-Artefakt auf Desktop: {fn}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = fn,
                Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                Reason = $"[Desktop] Datei '{fn}' auf dem Desktop entspricht einem bekannten Fortnite-Cheat-Muster. " +
                         "Fortnite-Cheat-Loader und Verknuepfungen werden oft auf dem Desktop abgelegt."
            });
        }

        // Check shortcuts (.lnk) for cheat targets
        string[] lnkFiles;
        try { lnkFiles = Directory.GetFiles(desktopPath, "*.lnk", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var lnk in lnkFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(lnk);

            if (MatchesCheatKeyword(fn, FortniteCheatFileKeywords) ||
                MatchesCheatKeyword(fn.Replace(".lnk", ""), FortniteCheatFileKeywords))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Cheat-Verknuepfung auf Desktop: {fn}",
                    Risk = RiskLevel.High,
                    Location = lnk,
                    FileName = fn,
                    Reason = $"[Desktop] Desktop-Verknuepfung '{fn}' hat einen Fortnite-Cheat-bezogenen Namen. " +
                             "Fortnite-Cheat-Tools legen oft Desktop-Verknuepfungen fuer einfachen Zugriff an."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckStartupArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var startupDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        };

        foreach (var startupDir in startupDirs)
        {
            if (!Directory.Exists(startupDir)) continue;

            string[] files;
            try { files = Directory.GetFiles(startupDir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (!MatchesCheatKeyword(fn, FortniteCheatFileKeywords) &&
                    !IsExactCheatExe(fn, FortniteCheatExeNames))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Cheat-Autostart-Eintrag: {fn}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"[Startup] Fortnite-Cheat-Artefakt '{fn}' im Autostart-Verzeichnis. " +
                             "Fortnite-Cheat-Tools mit Autostart-Eintraegen sind persistent und starten " +
                             "automatisch bei jedem Windows-Start."
                });
            }
        }

        // Check registry run keys
        var runKeys = new[]
        {
            (@"Software\Microsoft\Windows\CurrentVersion\Run", RegistryHive.CurrentUser),
            (@"Software\Microsoft\Windows\CurrentVersion\RunOnce", RegistryHive.CurrentUser),
        };

        foreach (var (keyPath, hive) in runKeys)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(keyPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    var value = key.GetValue(valueName)?.ToString() ?? "";

                    if (!MatchesCheatKeyword(valueName, FortniteCheatFileKeywords) &&
                        !MatchesCheatKeyword(value, FortniteCheatFileKeywords))
                        continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Fortnite-Cheat-Autostart in Registry: {valueName}",
                        Risk = RiskLevel.Critical,
                        Location = $@"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}",
                        Reason = $"[Registry/Startup] Registry-Autostart-Eintrag '{valueName}' = '{value}' " +
                                 "entspricht einem Fortnite-Cheat-Muster. Dieser Eintrag sorgt dafuer, dass " +
                                 "das Fortnite-Cheat-Tool bei jedem Windows-Start ausgefuehrt wird."
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDocumentsArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (!Directory.Exists(documentsPath)) return;

        var searchExtensions = new[] { "*.exe", "*.dll", "*.bat", "*.ps1", "*.CT", "*.zip", "*.rar", "*.7z" };

        foreach (var pattern in searchExtensions)
        {
            string[] files;
            try { files = Directory.GetFiles(documentsPath, pattern, SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (!MatchesCheatKeyword(fn, FortniteCheatFileKeywords) &&
                    !IsExactCheatExe(fn, FortniteCheatExeNames))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Fortnite-Cheat-Artefakt in Dokumente: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"[Dokumente] Datei '{fn}' im Dokumente-Ordner entspricht einem bekannten " +
                             "Fortnite-Cheat-Muster. Fortnite-Cheat-Tools, Cheat-Engine-Tabellen und " +
                             "Loader speichern oft Dateien im Dokumente-Ordner."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    // --- Utility methods -------------------------------------------------------

    private static string Rot13Decode(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c is >= 'A' and <= 'Z')
                chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c is >= 'a' and <= 'z')
                chars[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(chars);
    }

    private static string SafePathFileName(string path)
    {
        try { return Path.GetFileName(path.TrimEnd('\\', '/')); }
        catch { return path; }
    }

    private static DateTime SafeFileTime(string path)
    {
        try { return File.GetLastWriteTime(path); }
        catch { return default; }
    }

    private static IEnumerable<string> GetEpicGamesFortniteInstallPaths()
    {
        var results = new List<string>();

        // Check registry for Epic Games install paths
        var epicRegistryPaths = new[]
        {
            @"SOFTWARE\WOW6432Node\EpicGames\Unreal Engine",
            @"SOFTWARE\EpicGames\Unreal Engine",
        };

        foreach (var regPath in epicRegistryPaths)
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var key = hklm.OpenSubKey(regPath);
                if (key == null) continue;

                var installDir = key.GetValue("InstalledDirectory")?.ToString();
                if (!string.IsNullOrEmpty(installDir))
                {
                    var fortnitePath = Path.Combine(installDir!, "FortniteGame");
                    if (Directory.Exists(fortnitePath))
                        results.Add(fortnitePath);
                }
            }
            catch { }
        }

        // Check common Epic Games install paths
        var commonPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Epic Games", "Fortnite", "FortniteGame"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Epic Games", "Fortnite", "FortniteGame"),
            @"C:\Epic Games\Fortnite\FortniteGame",
            @"D:\Epic Games\Fortnite\FortniteGame",
            @"E:\Epic Games\Fortnite\FortniteGame",
        };

        foreach (var path in commonPaths)
        {
            if (Directory.Exists(path)) results.Add(path);
        }

        return results;
    }
}
