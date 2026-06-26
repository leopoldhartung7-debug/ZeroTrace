using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RustCheatForensicScanModule : IScanModule
{
    public string Name => "Rust Cheat Forensics";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    // Known Rust cheat file name keywords
    private static readonly string[] RustCheatFileKeywords =
    {
        "rust_hack", "rust_cheat", "rustcheat", "rusthack",
        "rustmagic", "rustcat", "rustxhax", "rust_aimbot",
        "aimbot_rust", "norecoil_rust", "rust_esp", "esp_rust",
        "rust_bypass", "rustbypass", "skript_rust", "skriptgg",
        "scopegg", "cheatgg_rust", "rust_loader", "rustloader",
        "oxide_inject", "oxide_plugin_inject", "carbon_inject",
        "rust_silent", "silentaim_rust", "rust_trigger", "triggerbot_rust",
        "rust_speed", "speedhack_rust", "rust_fly", "flyhack_rust",
        "rust_wallhack", "wallhack_rust", "rust_radar", "radar_rust",
        "skript.dll", "aimware_rust", "aimware_loader_rust",
        "rustinternal", "rust_internal", "rust_external", "rustexternal",
        "rust_mem", "rustmem", "rust_inject", "rustinject",
        "eac_bypass_rust", "rust_eac", "battleye_bypass_rust",
        "rust_be_bypass", "rust_nosteam", "rust_crack"
    };

    // Known Rust cheat executable names
    private static readonly string[] RustCheatExeNames =
    {
        "rustmagic.exe", "rustcat.exe", "rustxhax.exe",
        "rust_hack.exe", "rust_cheat.exe", "rusthack.exe",
        "rustcheat.exe", "norecoil_rust.exe", "rust_aimbot.exe",
        "aimbot_rust.exe", "esp_rust.exe", "rust_esp.exe",
        "rustloader.exe", "rust_loader.exe", "skriptgg.exe",
        "scopegg.exe", "rust_bypass.exe", "rustbypass.exe",
        "aimware_rust.exe", "rust_internal.exe", "rustinternal.exe",
        "rust_external.exe", "rustexternal.exe", "rusthwid.exe",
        "rustspoofer.exe", "rust_spoofer.exe", "rust_injector.exe",
        "rustinjector.exe", "rust_be.exe", "rust_eac.exe"
    };

    // Suspicious DLL names that may be injected into Rust process
    private static readonly string[] RustSuspiciousDllNames =
    {
        "skript.dll", "rustmagic.dll", "rustcat.dll", "norecoil.dll",
        "rust_aimbot.dll", "rust_esp.dll", "esp_rust.dll",
        "rust_hack.dll", "rusthack.dll", "rustcheat.dll",
        "rust_bypass.dll", "aimware.dll", "rust_internal.dll",
        "rust_external.dll", "oxide_inject.dll", "carbon_inject.dll",
        "rust_nosmoke.dll", "rust_nomuzzle.dll", "rust_nospread.dll",
        "rust_silent.dll", "silentaim.dll", "rust_triggerbot.dll"
    };

    // Log content keywords indicating Rust cheat activity
    private static readonly string[] RustCheatLogKeywords =
    {
        "aimbot", "esp hack", "no recoil rust", "rust hack",
        "speedhack rust", "silent aim rust", "rust cheat",
        "wallhack rust", "rust wallhack", "rust esp",
        "rust aimbot", "rust bypass", "eac bypass rust",
        "battleye bypass", "rust radar", "rust triggerbot",
        "rustmagic", "rustcat", "rustxhax", "skript.gg",
        "scope.gg", "cheat.gg", "aimware rust",
        "rust fly hack", "rust speed hack", "rust god mode",
        "rust no recoil", "norecoil rust", "rust silent aim",
        "rust injector", "rust loader", "oxide inject",
        "rust memory hack", "rust mem hack", "rust spinbot"
    };

    // Registry keys associated with Rust cheats
    private static readonly string[] RustCheatRegistryPaths =
    {
        @"Software\RustCheat",
        @"Software\RustHack",
        @"Software\RustMagic",
        @"Software\RustCat",
        @"Software\RustXHax",
        @"Software\SkriptGG",
        @"Software\ScopeGG",
        @"Software\AimwareRust",
        @"Software\RustLoader",
        @"Software\RustInjector",
        @"Software\RustBypass",
        @"Software\RustInternal",
        @"Software\RustExternal",
        @"Software\NoRecoilRust",
        @"Software\RustAimbot",
        @"Software\RustESP"
    };

    // Discord database keyword patterns for Rust cheats
    private static readonly string[] RustDiscordKeywords =
    {
        "rust cheat", "rust hack", "rust esp", "rust aimbot",
        "rustmagic", "norecoil rust", "rust bypass", "skript.gg",
        "scope.gg", "aimware rust", "rust radar", "rust wallhack",
        "rust silent aim", "rustcat", "rustxhax", "rust injector",
        "rust loader", "rust eac bypass", "rust battleye bypass",
        "rust spinbot", "rust triggerbot", "rust god mode", "rust fly"
    };

    // Prefetch names for Rust cheat executables (without extension, uppercase)
    private static readonly string[] RustPrefetchNames =
    {
        "RUSTMAGIC", "RUSTCAT", "RUSTXHAX", "RUST_HACK", "RUSTHACK",
        "RUSTCHEAT", "RUST_CHEAT", "NORECOIL_RUST", "RUST_AIMBOT",
        "RUSTLOADER", "RUST_LOADER", "SKRIPTGG", "SCOPEGG",
        "RUST_BYPASS", "RUSTBYPASS", "AIMWARE_RUST", "RUST_INTERNAL",
        "RUSTINTERNAL", "RUST_EXTERNAL", "RUSTEXTERNAL",
        "RUST_INJECTOR", "RUSTINJECTOR", "RUSTHWID", "RUSTSPOOFER",
        "RUST_SPOOFER", "RUST_BE", "RUST_EAC", "ESP_RUST", "RUST_ESP"
    };

    // EAC/BattlEye bypass artifact file names
    private static readonly string[] EacBypassArtifacts =
    {
        "EasyAntiCheat_x64.dll.bak", "EasyAntiCheat.dll.bak",
        "EasyAntiCheat_x64.dll.orig", "EasyAntiCheat.dll.orig",
        "EasyAntiCheat_EOS.dll.bak", "EasyAntiCheat_EOS.dll.orig",
        "EasyAntiCheat_bypass.dll", "eac_bypass.dll", "eac_loader.dll",
        "BattlEye.dll.bak", "BattlEye.dll.orig", "BEClient.dll.bak",
        "BEClient_x64.dll.bak", "be_bypass.dll", "battleye_bypass.dll",
        "BEClient.dll.orig", "BEClient_x64.dll.orig",
        "beservice_bypass.dll", "be_loader.dll"
    };

    // Cheat Engine table keywords for Rust
    private static readonly string[] RustCtKeywords =
    {
        "rust", "rust_", "rustgame", "facepunch", "rust cheat",
        "rust aimbot", "rust esp", "rust hack", "rust no recoil"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starte Rust-Cheat-Forensik...");

        await Task.WhenAll(
            CheckAppDataFiles(ctx, ct),
            CheckTempFiles(ctx, ct),
            CheckProgramFilesArtifacts(ctx, ct),
            CheckRustGameDirectory(ctx, ct),
            CheckOxidePlugins(ctx, ct),
            CheckCarbonPlugins(ctx, ct),
            CheckLogFiles(ctx, ct),
            CheckRegistryKeys(ctx, ct),
            CheckPrefetchArtifacts(ctx, ct),
            CheckUserAssist(ctx, ct),
            CheckDiscordArtifacts(ctx, ct),
            CheckEacBypassArtifacts(ctx, ct),
            CheckBattleEyeBypassArtifacts(ctx, ct),
            CheckCheatEngineTables(ctx, ct),
            CheckSuspiciousScripts(ctx, ct),
            CheckMemoryDumpArtifacts(ctx, ct),
            CheckDownloadsFolder(ctx, ct),
            CheckDesktopArtifacts(ctx, ct),
            CheckStartupArtifacts(ctx, ct),
            CheckDocumentsArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "Rust-Cheat-Forensik abgeschlossen.");
    }

    // --- Per-directory/file helpers -------------------------------------------

    private static bool MatchesCheatKeyword(string fileName, string[] keywords)
    {
        var lower = fileName.ToLowerInvariant();
        foreach (var kw in keywords)
        {
            if (lower.Contains(kw, StringComparison.OrdinalIgnoreCase))
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

    private static void ScanDirectoryForCheatFiles(
        ScanContext ctx,
        string moduleName,
        string directory,
        string[] fileKeywords,
        string[] exeNames,
        string context,
        CancellationToken ct)
    {
        if (!Directory.Exists(directory)) return;

        string[] files;
        try { files = Directory.GetFiles(directory, "*", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(file);

            bool isExact = IsExactCheatExe(fn, exeNames);
            bool isKeyword = !isExact && MatchesCheatKeyword(fn, fileKeywords);

            if (!isExact && !isKeyword) continue;

            ctx.AddFinding(new Finding
            {
                Module = moduleName,
                Title = $"Rust-Cheat-Artefakt: {fn}",
                Risk = isExact ? RiskLevel.High : RiskLevel.Medium,
                Location = file,
                FileName = fn,
                Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                Reason = $"[{context}] Datei '{fn}' entspricht einem bekannten Rust-Cheat-Muster. " +
                         "Solche Dateien werden von Rust-Cheat-Tools wie RustMagic, RustCat, RustXHax, " +
                         "Skript.gg, Scope.gg oder Aimware fuer Rust hinterlassen."
            });
        }
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

                if (MatchesCheatKeyword(name, RustCheatFileKeywords) ||
                    IsExactCheatExe(name, RustCheatExeNames))
                {
                    ctx.IncrementFiles();
                    bool isDir = Directory.Exists(entry);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Rust-Cheat-Artefakt in AppData: {name}",
                        Risk = RiskLevel.High,
                        Location = entry,
                        FileName = isDir ? null : name,
                        Sha256 = isDir ? null : HashUtil.TryComputeSha256(entry, 64 * 1024 * 1024),
                        Reason = $"[AppData] {(isDir ? "Verzeichnis" : "Datei")} '{name}' in AppData " +
                                 "entspricht bekanntem Rust-Cheat-Muster. Rust-Cheat-Tools wie RustMagic, " +
                                 "RustCat, RustXHax, Skript.gg, Scope.gg und Aimware fuer Rust " +
                                 "legen Konfigurations- und Loader-Dateien im AppData-Verzeichnis ab."
                    });
                }
            }
        }

        // Deeper scan of known cheat config subdirs
        var knownSubdirs = new[]
        {
            Path.Combine(appdata, "RustMagic"),
            Path.Combine(appdata, "RustCat"),
            Path.Combine(appdata, "RustXHax"),
            Path.Combine(appdata, "SkriptGG"),
            Path.Combine(appdata, "ScopeGG"),
            Path.Combine(appdata, "AimwareRust"),
            Path.Combine(appdata, "RustLoader"),
            Path.Combine(appdata, "RustInjector"),
            Path.Combine(appdata, "RustBypass"),
            Path.Combine(localAppdata, "RustMagic"),
            Path.Combine(localAppdata, "RustCat"),
            Path.Combine(localAppdata, "SkriptGG"),
            Path.Combine(localAppdata, "ScopeGG"),
        };

        foreach (var subdir in knownSubdirs)
        {
            if (!Directory.Exists(subdir)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Rust-Cheat-Verzeichnis gefunden: {Path.GetFileName(subdir)}",
                Risk = RiskLevel.High,
                Location = subdir,
                Reason = $"[AppData] Das Verzeichnis '{subdir}' ist ein bekanntes Konfigurations- oder " +
                         "Installationsverzeichnis eines Rust-Cheat-Tools. Die Existenz dieses Verzeichnisses " +
                         "deutet auf die Nutzung eines Rust-Cheats hin."
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

                if (!MatchesCheatKeyword(fn, RustCheatFileKeywords) &&
                    !IsExactCheatExe(fn, RustCheatExeNames))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Rust-Cheat-Artefakt im Temp-Verzeichnis: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"[Temp] Datei '{fn}' im Temp-Verzeichnis entspricht bekanntem Rust-Cheat-Muster. " +
                             "Rust-Cheat-Loader und -Injektoren extrahieren oft temporaere Dateien in " +
                             "Temp-Verzeichnisse waehrend der Ausfuehrung."
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

                if (!MatchesCheatKeyword(dirName, RustCheatFileKeywords)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Rust-Cheat-Installation in ProgramFiles: {dirName}",
                    Risk = RiskLevel.Critical,
                    Location = subDir,
                    Reason = $"[ProgramFiles] Verzeichnis '{dirName}' in den Programmdateien entspricht einem " +
                             "bekannten Rust-Cheat-Tool-Namen. Dies deutet auf eine vollstaendige Installation " +
                             "eines Rust-Cheats hin."
                });

                // Also scan inside for executables
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
                        Title = $"Rust-Cheat-Executable in ProgramFiles: {Path.GetFileName(innerFile)}",
                        Risk = RiskLevel.Critical,
                        Location = innerFile,
                        FileName = Path.GetFileName(innerFile),
                        Sha256 = HashUtil.TryComputeSha256(innerFile, 64 * 1024 * 1024),
                        Reason = $"[ProgramFiles] Ausfuehrbare Datei in Rust-Cheat-Installationsverzeichnis " +
                                 $"'{dirName}'. Dies ist ein starkes Indiz fuer eine installierte Rust-Cheat-Software."
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRustGameDirectory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // Common Steam install paths
        var steamPaths = new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\Rust",
            @"C:\Program Files\Steam\steamapps\common\Rust",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Steam", "steamapps", "common", "Rust"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Steam", "steamapps", "common", "Rust"),
        };

        // Also check Steam library via registry
        var additionalPaths = GetSteamLibraryRustPaths();

        var allPaths = steamPaths.Concat(additionalPaths).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        foreach (var rustDir in allPaths)
        {
            if (!Directory.Exists(rustDir)) continue;

            // Scan root Rust game directory for suspicious DLLs
            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(rustDir, "*.dll", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dll in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(dll);

                bool isSuspiciousDll = false;
                foreach (var suspDll in RustSuspiciousDllNames)
                {
                    if (fn.Equals(suspDll, StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains(suspDll.Replace(".dll", ""), StringComparison.OrdinalIgnoreCase))
                    {
                        isSuspiciousDll = true;
                        break;
                    }
                }

                if (!isSuspiciousDll && MatchesCheatKeyword(fn, RustCheatFileKeywords))
                    isSuspiciousDll = true;

                if (!isSuspiciousDll) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Verdaechtige DLL im Rust-Spielverzeichnis: {fn}",
                    Risk = RiskLevel.Critical,
                    Location = dll,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(dll, 64 * 1024 * 1024),
                    Reason = $"[RustGameDir] DLL '{fn}' im Rust-Spielverzeichnis '{rustDir}' entspricht " +
                             "einem bekannten Rust-Cheat-DLL-Muster. Cheat-DLLs werden oft direkt in das " +
                             "Spielverzeichnis platziert um Injection oder Side-Loading zu ermoeglichen."
                });
            }

            // Check for renamed game files (EAC/BattlEye bypass technique)
            await CheckForRenamedGameFiles(ctx, rustDir, ct);

            // Check for suspicious executables in the game directory
            string[] exeFiles;
            try { exeFiles = Directory.GetFiles(rustDir, "*.exe", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            var legitimateRustExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "RustClient.exe", "Rust.exe", "rust.exe", "RustDedicated.exe"
            };

            foreach (var exe in exeFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(exe);
                if (legitimateRustExes.Contains(fn)) continue;

                if (MatchesCheatKeyword(fn, RustCheatFileKeywords) ||
                    IsExactCheatExe(fn, RustCheatExeNames))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige EXE im Rust-Spielverzeichnis: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = exe,
                        FileName = fn,
                        Sha256 = HashUtil.TryComputeSha256(exe, 64 * 1024 * 1024),
                        Reason = $"[RustGameDir] Ausfuehrbare Datei '{fn}' im Rust-Spielverzeichnis " +
                                 "ist keine bekannte legitime Rust-Datei und entspricht einem Cheat-Muster."
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private static async Task CheckForRenamedGameFiles(ScanContext ctx, string rustDir, CancellationToken ct)
    {
        var suspiciousExtensions = new[] { ".bak", ".orig", ".backup", ".old", ".disabled" };
        var legitimateGameFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "EasyAntiCheat_x64.dll", "EasyAntiCheat.dll",
            "BEClient.dll", "BEClient_x64.dll", "BattlEye.dll"
        };

        string[] allFiles;
        try { allFiles = Directory.GetFiles(rustDir, "*", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in allFiles)
        {
            if (ct.IsCancellationRequested) return;
            var fn = Path.GetFileName(file);
            var ext = Path.GetExtension(fn);

            if (!suspiciousExtensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase)))
                continue;

            var baseName = Path.GetFileNameWithoutExtension(fn);
            if (!legitimateGameFiles.Contains(baseName + ".dll") &&
                !legitimateGameFiles.Contains(baseName))
                continue;

            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = ctx.CurrentModule.Length > 0 ? ctx.CurrentModule : "Rust Cheat Forensics",
                Title = $"Umbenannte Anti-Cheat-Datei in Rust-Verzeichnis: {fn}",
                Risk = RiskLevel.Critical,
                Location = file,
                FileName = fn,
                Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                Reason = $"[RustGameDir] Datei '{fn}' ist eine umbenannte Anti-Cheat-Systemdatei. " +
                         "Das Umbenennen von EAC- oder BattlEye-Dateien ist eine klassische Bypass-Technik, " +
                         "bei der legitime Anti-Cheat-DLLs durch manipulierte Versionen ersetzt werden."
            });
        }

        await Task.CompletedTask;
    }

    private Task CheckOxidePlugins(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var steamPaths = new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\Rust",
            @"C:\Program Files\Steam\steamapps\common\Rust",
        };

        var additionalPaths = GetSteamLibraryRustPaths();
        var allPaths = steamPaths.Concat(additionalPaths).Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var rustDir in allPaths)
        {
            var oxidePluginsDir = Path.Combine(rustDir, "oxide", "plugins");
            if (!Directory.Exists(oxidePluginsDir)) continue;

            string[] pluginFiles;
            try { pluginFiles = Directory.GetFiles(oxidePluginsDir, "*.cs", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var plugin in pluginFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(plugin);

                if (MatchesCheatKeyword(fn, RustCheatFileKeywords))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiges Oxide-Plugin: {fn}",
                        Risk = RiskLevel.High,
                        Location = plugin,
                        FileName = fn,
                        Reason = $"[OxidePlugins] Das Oxide-Plugin '{fn}' entspricht einem bekannten Rust-Cheat-Muster. " +
                                 "Boeswillige Oxide-Plugins koennen zur Injektion oder zur Umgehung von Anti-Cheat-Systemen verwendet werden."
                    });
                    continue;
                }

                // Check content for cheat-related code patterns
                string? matchedKeyword = await FileContentFirstMatch(plugin, RustCheatLogKeywords, ct);
                if (matchedKeyword != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Oxide-Plugin mit Cheat-Inhalt: {fn}",
                        Risk = RiskLevel.High,
                        Location = plugin,
                        FileName = fn,
                        Reason = $"[OxidePlugins] Das Oxide-Plugin '{fn}' enthaelt den verdaechtigen Begriff " +
                                 $"'{matchedKeyword}'. Dies deutet auf cheat-bezogene Funktionalitaet hin."
                    });
                }
            }

            // Check for obfuscated plugins (very short names, hex names, random names)
            string[] allCsFiles;
            try { allCsFiles = Directory.GetFiles(oxidePluginsDir, "*.cs"); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var plugin in allCsFiles)
            {
                if (ct.IsCancellationRequested) return;
                var fn = Path.GetFileNameWithoutExtension(plugin);
                if (fn.Length <= 3 && fn.All(c => char.IsLetterOrDigit(c)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Obfuskiertes Oxide-Plugin: {Path.GetFileName(plugin)}",
                        Risk = RiskLevel.Medium,
                        Location = plugin,
                        FileName = Path.GetFileName(plugin),
                        Reason = $"[OxidePlugins] Das Oxide-Plugin '{Path.GetFileName(plugin)}' hat einen " +
                                 "auffaellig kurzen oder obfuskierten Namen. Cheat-Plugins tarnen sich oft " +
                                 "durch kurze oder zufaellige Namen."
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCarbonPlugins(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var steamPaths = new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\Rust",
            @"C:\Program Files\Steam\steamapps\common\Rust",
        };

        var additionalPaths = GetSteamLibraryRustPaths();
        var allPaths = steamPaths.Concat(additionalPaths).Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var rustDir in allPaths)
        {
            var carbonPluginsDir = Path.Combine(rustDir, "carbon", "plugins");
            var carbonExtDir = Path.Combine(rustDir, "carbon", "extensions");
            var carbonHooksDir = Path.Combine(rustDir, "carbon", "hooks");

            foreach (var dir in new[] { carbonPluginsDir, carbonExtDir, carbonHooksDir })
            {
                if (!Directory.Exists(dir)) continue;

                string[] pluginFiles;
                try { pluginFiles = Directory.GetFiles(dir, "*.cs", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var plugin in pluginFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(plugin);

                    if (MatchesCheatKeyword(fn, RustCheatFileKeywords))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiges Carbon-Plugin: {fn}",
                            Risk = RiskLevel.High,
                            Location = plugin,
                            FileName = fn,
                            Reason = $"[CarbonPlugins] Das Carbon-Plugin '{fn}' entspricht einem bekannten " +
                                     "Rust-Cheat-Muster. Carbon-Plugins koennen zur Injektion oder Anti-Cheat-Umgehung genutzt werden."
                        });
                        continue;
                    }

                    string? matchedKeyword = await FileContentFirstMatch(plugin, RustCheatLogKeywords, ct);
                    if (matchedKeyword != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Carbon-Plugin mit Cheat-Inhalt: {fn}",
                            Risk = RiskLevel.High,
                            Location = plugin,
                            FileName = fn,
                            Reason = $"[CarbonPlugins] Das Carbon-Plugin '{fn}' enthaelt den Schluessel-Begriff " +
                                     $"'{matchedKeyword}'. Dies deutet auf cheat-bezogene Funktionalitaet hin."
                        });
                    }
                }
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

        // Add Rust-specific log locations
        foreach (var rustDir in GetSteamLibraryRustPaths().Concat(new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\Rust",
            @"C:\Program Files\Steam\steamapps\common\Rust"
        }))
        {
            logDirs.Add(Path.Combine(rustDir, "logs"));
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

                string? matchedKeyword = await FileContentFirstMatch(logFile, RustCheatLogKeywords, ct);
                if (matchedKeyword == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Rust-Cheat-Begriff in Log: {Path.GetFileName(logFile)}",
                    Risk = RiskLevel.Medium,
                    Location = logFile,
                    FileName = Path.GetFileName(logFile),
                    Reason = $"[Logs] Log-Datei '{logFile}' enthaelt den verdaechtigen Begriff '{matchedKeyword}'. " +
                             "Dies deutet darauf hin, dass ein Rust-Cheat-Tool auf diesem System ausgefuehrt wurde."
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

                string? matchedKeyword = await FileContentFirstMatch(txtFile, RustCheatLogKeywords, ct);
                if (matchedKeyword == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Rust-Cheat-Begriff in Textdatei: {Path.GetFileName(txtFile)}",
                    Risk = RiskLevel.Medium,
                    Location = txtFile,
                    FileName = Path.GetFileName(txtFile),
                    Reason = $"[Logs] Textdatei '{txtFile}' enthaelt den verdaechtigen Begriff '{matchedKeyword}'. " +
                             "Moegliches Log oder Konfigurationsdatei eines Rust-Cheat-Tools."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRegistryKeys(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // Check HKCU Software paths
        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);

            foreach (var regPath in RustCheatRegistryPaths)
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
                        Title = $"Rust-Cheat-Registrierungsschluessel: {regPath}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{regPath}",
                        Reason = $"[Registry] Registrierungsschluessel 'HKCU\\{regPath}' existiert. " +
                                 "Dieser Schluessel wird von bekannten Rust-Cheat-Tools fuer die " +
                                 "Konfigurationsspeicherung oder Lizenzpruefung verwendet."
                    });
                }
                catch (UnauthorizedAccessException) { }
            }

            // Check uninstall keys for rust cheat software
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

                        if (MatchesCheatKeyword(displayName, RustCheatFileKeywords) ||
                            MatchesCheatKeyword(publisher, RustCheatFileKeywords) ||
                            MatchesCheatKeyword(installLocation, RustCheatFileKeywords))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Rust-Cheat-Software in Deinstallation: {displayName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\{subKeyName}",
                                Reason = $"[Registry] Deinstallationseintrag '{displayName}' (Herausgeber: {publisher}) " +
                                         "entspricht einem bekannten Rust-Cheat-Muster. Dies deutet auf eine " +
                                         "installierte Rust-Cheat-Software hin."
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }
        catch (UnauthorizedAccessException) { }

        // Check HKLM Uninstall (system-wide installs)
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
                        if (MatchesCheatKeyword(displayName, RustCheatFileKeywords))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Rust-Cheat-Software (System) in Deinstallation: {displayName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\{subKeyName}",
                                Reason = $"[Registry] Systemweiter Deinstallationseintrag '{displayName}' " +
                                         "entspricht einem bekannten Rust-Cheat-Muster."
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

            bool matched = false;
            foreach (var knownName in RustPrefetchNames)
            {
                if (exeName.Equals(knownName, StringComparison.OrdinalIgnoreCase))
                {
                    matched = true;
                    break;
                }
            }

            if (!matched && MatchesCheatKeyword(exeName, RustCheatFileKeywords))
                matched = true;

            if (!matched) continue;

            var lastWrite = SafeFileTime(pfFile);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Rust-Cheat-Prefetch: {exeName}.exe",
                Risk = RiskLevel.High,
                Location = pfFile,
                FileName = exeName + ".exe",
                Reason = $"[Prefetch] Prefetch-Datei fuer '{exeName}.exe' gefunden. " +
                         "Dies bedeutet, dass dieses bekannte Rust-Cheat-Programm auf diesem System " +
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
                    if (!MatchesCheatKeyword(fn, RustCheatFileKeywords) &&
                        !IsExactCheatExe(fn, RustCheatExeNames) &&
                        !MatchesCheatKeyword(decoded, RustCheatFileKeywords))
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
                        Title = $"Rust-Cheat-Start via UserAssist: {fn}",
                        Risk = RiskLevel.High,
                        Location = decoded,
                        FileName = fn,
                        Reason = $"[UserAssist] UserAssist-Eintrag '{fn}' (dekodiert aus ROT13) entspricht " +
                                 "einem bekannten Rust-Cheat-Muster. UserAssist protokolliert GUI-Programmstarts " +
                                 "in der Registry.",
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

        // Discord stores cached messages and data in LevelDB
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
                    if (info.Length > 5 * 1024 * 1024) continue; // Skip files > 5MB
                }
                catch (IOException) { continue; }

                ctx.IncrementFiles();
                string? matchedKeyword = await FileContentFirstMatch(cacheFile, RustDiscordKeywords, ct);
                if (matchedKeyword == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord-Artefakt mit Rust-Cheat-Bezug: {Path.GetFileName(cacheFile)}",
                    Risk = RiskLevel.Medium,
                    Location = cacheFile,
                    FileName = Path.GetFileName(cacheFile),
                    Reason = $"[Discord] Discord-Cache-Datei enthaelt den Schluessel-Begriff '{matchedKeyword}'. " +
                             "Dies deutet auf Discord-Kommunikation ueber Rust-Cheat-Tools oder -Dienste hin " +
                             "(z.B. Kauf, Nutzung oder Verteilung von Rust-Cheats)."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckEacBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // EAC bypass artifacts can appear in many locations
        var dirsToCheck = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        // Add EAC directories
        var eacDirs = new[]
        {
            @"C:\Program Files (x86)\EasyAntiCheat",
            @"C:\Program Files\EasyAntiCheat",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "EasyAntiCheat"),
        };
        dirsToCheck.AddRange(eacDirs);

        // Add Rust game directories
        dirsToCheck.AddRange(GetSteamLibraryRustPaths().Concat(new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\Rust",
            @"C:\Program Files\Steam\steamapps\common\Rust"
        }));

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

                foreach (var bypassName in EacBypassArtifacts)
                {
                    if (!fn.Equals(bypassName, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EAC-Bypass-Artefakt: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                        Reason = $"[EACBypass] Datei '{fn}' ist ein bekanntes EasyAntiCheat-Bypass-Artefakt. " +
                                 "Diese Dateien entstehen, wenn Anti-Cheat-DLLs umbenannt oder ersetzt werden, " +
                                 "um Rust ohne aktiven EAC-Schutz zu starten."
                    });
                    break;
                }
            }
        }

        // Check for suspicious EAC-related registry modifications
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            ctx.IncrementRegistryKeys();

            using var eacKey = hklm.OpenSubKey(@"Software\EasyAntiCheat");
            if (eacKey != null)
            {
                foreach (var valueName in eacKey.GetValueNames())
                {
                    var value = eacKey.GetValue(valueName)?.ToString() ?? "";
                    if (MatchesCheatKeyword(value, RustCheatFileKeywords))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger EAC-Registrierungseintrag: {valueName}",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\Software\EasyAntiCheat",
                            Reason = $"[Registry] EAC-Registrierungswert '{valueName}' enthaelt verdaechtigen " +
                                     $"Inhalt '{value}'. Moegliche Manipulation der EAC-Konfiguration."
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckBattleEyeBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // BattlEye bypass artifacts and suspicious files
        var beBypassKeywords = new[]
        {
            "battleye_bypass", "be_bypass", "be_loader", "battleye_loader",
            "beservice_bypass", "be_inject", "battleye_inject",
            "rustbebypass", "rust_be_bypass", "rustbattleye"
        };

        var dirsToCheck = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        dirsToCheck.AddRange(GetSteamLibraryRustPaths().Concat(new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\Rust",
            @"C:\Program Files\Steam\steamapps\common\Rust"
        }));

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
                var fn = Path.GetFileName(file).ToLowerInvariant();

                if (!beBypassKeywords.Any(kw => fn.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"BattlEye-Bypass-Artefakt: {Path.GetFileName(file)}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"[BEBypass] Datei '{Path.GetFileName(file)}' entspricht einem bekannten " +
                             "BattlEye-Bypass-Muster. Rust verwendet BattlEye als Anti-Cheat. " +
                             "Bypass-Dateien werden verwendet, um BattlEye-Schutz zu umgehen."
                });
            }
        }

        // Check BattlEye log for bypass attempts
        var beLogs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "AppData", "Roaming", "BattlEye", "*.log"),
        };

        foreach (var rustDir in GetSteamLibraryRustPaths().Concat(new[]
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\Rust",
            @"C:\Program Files\Steam\steamapps\common\Rust"
        }))
        {
            var beLogDir = Path.Combine(rustDir, "BattlEye");
            if (!Directory.Exists(beLogDir)) continue;

            string[] logFiles;
            try { logFiles = Directory.GetFiles(beLogDir, "*.log"); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var beBypassLogKeywords = new[]
                {
                    "bypass", "inject", "hook", "patch", "cheat", "hack",
                    "violation", "modified", "tampered", "evasion"
                };

                string? matchedKeyword = await FileContentFirstMatch(logFile, beBypassLogKeywords, ct);
                if (matchedKeyword == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"BattlEye-Log mit Verdachts-Eintrag: {Path.GetFileName(logFile)}",
                    Risk = RiskLevel.High,
                    Location = logFile,
                    FileName = Path.GetFileName(logFile),
                    Reason = $"[BELog] BattlEye-Log '{logFile}' enthaelt verdaechtigen Begriff '{matchedKeyword}'. " +
                             "Dies koennte auf erkannte oder versuchte Cheat-Aktivitaet hinweisen."
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

                string? matchedKeyword = await FileContentFirstMatch(ctFile, RustCtKeywords, ct);
                if (matchedKeyword == null)
                {
                    // Also check the filename itself
                    var fn = Path.GetFileName(ctFile);
                    if (!MatchesCheatKeyword(fn, RustCtKeywords)) continue;
                }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat-Engine-Tabelle fuer Rust: {Path.GetFileName(ctFile)}",
                    Risk = RiskLevel.High,
                    Location = ctFile,
                    FileName = Path.GetFileName(ctFile),
                    Reason = $"[CheatEngine] Cheat-Engine-Tabelle '{Path.GetFileName(ctFile)}' " +
                             (matchedKeyword != null ? $"enthaelt Rust-Bezug '{matchedKeyword}'. " : "hat Rust-bezogenen Namen. ") +
                             "Cheat-Engine-Tabellen werden zur Manipulation von Spielspeicher verwendet, " +
                             "z.B. fuer Aimbot, No-Recoil oder ESP in Rust."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckSuspiciousScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // Rust cheat injection scripts (batch, PowerShell)
        var rustInjectionKeywords = new[]
        {
            "inject rust", "rust inject", "rust cheat", "rust hack",
            "rust aimbot", "oxide inject", "carbon inject",
            "eac bypass", "battleye bypass", "rust bypass",
            "RustClient", "rust.exe", "EasyAntiCheat", "BattlEye",
            "rust loader", "rust internal", "rust external",
            "skript.gg", "rustmagic", "rustcat", "norecoil"
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

                    if (MatchesCheatKeyword(fn, RustCheatFileKeywords))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiges Rust-Cheat-Skript: {fn}",
                            Risk = RiskLevel.High,
                            Location = script,
                            FileName = fn,
                            Reason = $"[Scripts] Skript-Datei '{fn}' hat einen Rust-Cheat-bezogenen Namen. " +
                                     "Solche Skripte werden fuer Rust-Cheat-Injection oder -Loader-Aktivierung verwendet."
                        });
                        continue;
                    }

                    string? matchedKeyword = await FileContentFirstMatch(script, rustInjectionKeywords, ct);
                    if (matchedKeyword == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Skript mit Rust-Cheat-Inhalt: {fn}",
                        Risk = RiskLevel.High,
                        Location = script,
                        FileName = fn,
                        Reason = $"[Scripts] Skript '{fn}' enthaelt verdaechtigen Begriff '{matchedKeyword}'. " +
                                 "Rust-Cheat-Injektions- und Loader-Skripte enthalten oft Verweise auf " +
                                 "Rust-Prozesse, Anti-Cheat-Systeme oder bekannte Cheat-Werkzeuge."
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckMemoryDumpArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var rustProcessNames = new[]
        {
            "rust", "rustclient", "rustdedicated", "rust_hack", "rustinternal", "rustexternal"
        };

        var dumpExtensions = new[] { "*.dmp", "*.mdmp", "*.hdmp" };

        var searchDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CrashDumps"),
            @"C:\Windows\Minidump",
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            foreach (var ext in dumpExtensions)
            {
                string[] dumpFiles;
                try { dumpFiles = Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var dumpFile in dumpFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(dumpFile).ToLowerInvariant();

                    bool isRustRelated = rustProcessNames.Any(
                        pn => fn.Contains(pn, StringComparison.OrdinalIgnoreCase));

                    if (!isRustRelated) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Memory-Dump mit Rust-Prozess-Bezug: {Path.GetFileName(dumpFile)}",
                        Risk = RiskLevel.Medium,
                        Location = dumpFile,
                        FileName = Path.GetFileName(dumpFile),
                        Reason = $"[MemDump] Memory-Dump-Datei '{Path.GetFileName(dumpFile)}' hat einen " +
                                 "Rust-Prozess-bezogenen Namen. Solche Dumps koennen bei der Entwicklung " +
                                 "oder Nutzung von Rust-Cheats entstehen (z.B. beim Analysieren von Spielspeicher)."
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

            if (!MatchesCheatKeyword(fn, RustCheatFileKeywords) &&
                !IsExactCheatExe(fn, RustCheatExeNames))
                continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Rust-Cheat-Datei im Downloads-Ordner: {fn}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = fn,
                Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                Reason = $"[Downloads] Datei '{fn}' im Downloads-Ordner entspricht einem bekannten " +
                         "Rust-Cheat-Muster. Dies deutet darauf hin, dass ein Rust-Cheat-Tool " +
                         "heruntergeladen wurde."
            });
        }

        // Also check archives
        string[] archiveFiles;
        try { archiveFiles = Directory.GetFiles(downloadsPath, "*.zip", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var archive in archiveFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(archive);

            if (MatchesCheatKeyword(fn, RustCheatFileKeywords))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Rust-Cheat-Archiv im Downloads-Ordner: {fn}",
                    Risk = RiskLevel.High,
                    Location = archive,
                    FileName = fn,
                    Reason = $"[Downloads] Archiv '{fn}' im Downloads-Ordner entspricht einem Rust-Cheat-Muster. " +
                             "Rust-Cheat-Tools werden oft als ZIP-Archive vertrieben."
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

            if (!MatchesCheatKeyword(fn, RustCheatFileKeywords) &&
                !IsExactCheatExe(fn, RustCheatExeNames))
                continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Rust-Cheat-Artefakt auf Desktop: {fn}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = fn,
                Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                Reason = $"[Desktop] Datei '{fn}' auf dem Desktop entspricht einem bekannten Rust-Cheat-Muster. " +
                         "Rust-Cheat-Loader und Shortcut-Dateien werden oft auf dem Desktop platziert."
            });
        }

        // Check shortcuts (.lnk) on desktop for cheat-related targets
        string[] lnkFiles;
        try { lnkFiles = Directory.GetFiles(desktopPath, "*.lnk", SearchOption.TopDirectoryOnly); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var lnk in lnkFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(lnk);

            if (MatchesCheatKeyword(fn, RustCheatFileKeywords) ||
                MatchesCheatKeyword(fn.Replace(".lnk", ""), RustCheatFileKeywords))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Rust-Cheat-Verknuepfung auf Desktop: {fn}",
                    Risk = RiskLevel.High,
                    Location = lnk,
                    FileName = fn,
                    Reason = $"[Desktop] Verknuepfung '{fn}' auf dem Desktop hat einen Rust-Cheat-bezogenen Namen. " +
                             "Rust-Cheat-Tools legen oft Desktop-Verknuepfungen an."
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckStartupArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        // Check autostart folders for rust cheat entries
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

                if (!MatchesCheatKeyword(fn, RustCheatFileKeywords) &&
                    !IsExactCheatExe(fn, RustCheatExeNames))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Rust-Cheat-Autostart-Eintrag: {fn}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"[Startup] Rust-Cheat-Artefakt '{fn}' im Autostart-Verzeichnis. " +
                             "Rust-Cheat-Tools mit Autostart-Eintraegen sind besonders persistent " +
                             "und starten bei jedem Systemstart automatisch."
                });
            }
        }

        // Check run keys in registry
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

                    if (!MatchesCheatKeyword(valueName, RustCheatFileKeywords) &&
                        !MatchesCheatKeyword(value, RustCheatFileKeywords))
                        continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Rust-Cheat-Autostart in Registry: {valueName}",
                        Risk = RiskLevel.Critical,
                        Location = $@"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}",
                        Reason = $"[Registry/Startup] Registry-Autostart-Eintrag '{valueName}' = '{value}' " +
                                 "entspricht einem Rust-Cheat-Muster. Dieser Eintrag sorgt dafuer, dass " +
                                 "das Rust-Cheat-Tool bei jedem Windows-Start ausgefuehrt wird."
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

                if (!MatchesCheatKeyword(fn, RustCheatFileKeywords) &&
                    !IsExactCheatExe(fn, RustCheatExeNames))
                    continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Rust-Cheat-Artefakt in Dokumente: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Sha256 = HashUtil.TryComputeSha256(file, 64 * 1024 * 1024),
                    Reason = $"[Dokumente] Datei '{fn}' im Dokumente-Ordner entspricht einem bekannten " +
                             "Rust-Cheat-Muster. Rust-Cheat-Tools speichern oft Konfigurationen, " +
                             "Cheat-Engine-Tabellen oder Loader im Dokumente-Ordner."
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

    private static IEnumerable<string> GetSteamLibraryRustPaths()
    {
        var results = new List<string>();
        try
        {
            using var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var steamKey = hkcu.OpenSubKey(@"Software\Valve\Steam");
            var steamPath = steamKey?.GetValue("SteamPath")?.ToString();
            if (steamPath != null)
            {
                var defaultRust = Path.Combine(steamPath, "steamapps", "common", "Rust");
                if (Directory.Exists(defaultRust)) results.Add(defaultRust);

                // Check library folders
                var libraryFolders = Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
                if (File.Exists(libraryFolders))
                {
                    try
                    {
                        var content = File.ReadAllText(libraryFolders);
                        // Simple VDF parsing for "path" entries
                        var lines = content.Split('\n');
                        foreach (var line in lines)
                        {
                            if (!line.Contains("\"path\"", StringComparison.OrdinalIgnoreCase)) continue;
                            var parts = line.Split('"');
                            if (parts.Length >= 4)
                            {
                                var libPath = parts[3].Replace("\\\\", "\\");
                                var rustPath = Path.Combine(libPath, "steamapps", "common", "Rust");
                                if (Directory.Exists(rustPath)) results.Add(rustPath);
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
        return results;
    }
}
