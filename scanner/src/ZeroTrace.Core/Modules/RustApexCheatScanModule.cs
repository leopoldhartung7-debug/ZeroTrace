using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RustApexCheatScanModule : IScanModule
{
    public string Name => "Rust-Apex-Cheat";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    private static readonly HashSet<string> RustCheatExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "rust_cheat.exe", "rust_hack.exe", "rust_aimbot.exe", "rust_esp.exe",
        "rust_wallhack.exe", "rust_loader.exe", "rust_bypass.exe", "rust_external.exe",
        "rust_internal.exe", "recoil_rust.exe", "no_recoil_rust.exe", "rust_silent_aim.exe",
        "rust_radar.exe", "rustrunner.exe", "rustcheater.exe", "nrecoil.exe",
        "silent_aim_rust.exe", "rust_triggerbot.exe", "magicbullet_rust.exe",
        "flyhack_rust.exe", "speedhack_rust.exe", "nospread_rust.exe", "rust_unlocker.exe",
    };

    private static readonly HashSet<string> RustCheatDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "rust_cheat.dll", "rust_esp.dll", "rust_aimbot.dll",
        "rust_hook.dll", "rust_bypass.dll", "eac_bypass_rust.dll",
    };

    private static readonly HashSet<string> ApexCheatExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "apex_cheat.exe", "apex_hack.exe", "apex_aimbot.exe", "apex_esp.exe",
        "apex_wallhack.exe", "apex_loader.exe", "apex_bypass.exe", "apex_external.exe",
        "apex_glow.exe", "apex_silent.exe", "apex_rage.exe", "apex_legit.exe",
        "apexlegends_cheat.exe", "apexloader.exe", "apex_unlocker.exe", "apexhack.exe",
        "r5_cheat.exe", "titanfall_cheat.exe",
    };

    private static readonly HashSet<string> ApexCheatDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "apex_cheat.dll", "apex_esp.dll", "apex_aimbot.dll",
        "apex_glow.dll", "r5apex_hook.dll", "eac_bypass_apex.dll",
    };

    private static readonly HashSet<string> EacBypassExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "eac_rust_bypass.exe", "eac_apex_bypass.exe",
        "r5apex_bypass.exe", "rust_eac_bypass.exe",
    };

    private static readonly string[] RustCheatConfigFiles =
    {
        "rust_hacks.cfg", "rust_config.json", "recoil_profile_rust.json",
    };

    private static readonly string[] RustAppDataSubPaths =
    {
        "Rust", "RustClient",
    };

    private static readonly string[] ApexAppDataSubPaths =
    {
        "Apex Legends",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "aimbot", "esp", "wallhack", "norecoil", "silent", "bypass", "radar", "nospread",
    };

    private static readonly string[] ApexWallhackKeywords =
    {
        "mat_fullbright", "r_drawothermodels",
    };

    private static readonly string[] RustRecoilScriptKeywords =
    {
        "recoil", "spray", "pattern", "norecoil", "akm", "ak47", "thompson", "mp5", "semi", "single",
    };

    private static readonly string[] PrefetchPatterns =
    {
        "RUST_CHEAT", "RUST_HACK", "APEX_CHEAT", "APEX_HACK",
        "RUSTRUNNER", "RECOIL_RUST", "NRECOIL",
    };

    private static readonly string[] KnownRustGameProcessNames =
    {
        "rustclient", "rust",
    };

    private static readonly string[] KnownApexGameProcessNames =
    {
        "r5apex",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ctx.Report(0.0, Name, "Scanning for Rust and Apex cheat EXEs/DLLs on disk...");
            ScanKnownCheatFiles(ctx, ct);

            ctx.Report(0.2, Name, "Scanning Rust AppData artifacts...");
            ScanRustAppDataArtifacts(ctx, ct);

            ctx.Report(0.35, Name, "Scanning Apex Legends AppData artifacts...");
            ScanApexAppDataArtifacts(ctx, ct);

            ctx.Report(0.5, Name, "Scanning for Rust recoil scripts...");
            ScanRustRecoilScripts(ctx, ct);

            ctx.Report(0.65, Name, "Scanning for Razer Synapse Rust profiles...");
            ScanRazerSynapseRustProfiles(ctx, ct);

            ctx.Report(0.72, Name, "Scanning EAC bypass tools and registry...");
            ScanEacBypassAndRegistry(ctx, ct);

            ctx.Report(0.82, Name, "Scanning running processes...");
            ScanRunningProcesses(ctx, ct);

            ctx.Report(0.92, Name, "Scanning Prefetch artifacts...");
            ScanPrefetchArtifacts(ctx, ct);

            ctx.Report(1.0, Name, "Rust/Apex cheat scan complete.");
        }, ct);
    }

    private static void ScanKnownCheatFiles(ScanContext ctx, CancellationToken ct)
    {
        var searchBases = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var baseDir in searchBases)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);

                    if (RustCheatExeNames.Contains(fname))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"Rust cheat EXE on disk: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Known Rust (EAC) cheat executable '{fname}' found on disk. " +
                                     "This file is a recognized cheat tool targeting Rust and its Easy Anti-Cheat protection.",
                            Detail = $"Path={file}",
                        });
                    }
                    else if (ApexCheatExeNames.Contains(fname))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"Apex Legends cheat EXE on disk: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Known Apex Legends (EAC) cheat executable '{fname}' found on disk. " +
                                     "This file is a recognized cheat tool targeting Apex Legends and its Easy Anti-Cheat protection.",
                            Detail = $"Path={file}",
                        });
                    }
                    else if (EacBypassExeNames.Contains(fname))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"EAC bypass tool on disk: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Known Easy Anti-Cheat bypass executable '{fname}' targeting Rust or Apex Legends found on disk. " +
                                     "These tools are designed specifically to evade EAC kernel-mode integrity checks.",
                            Detail = $"Path={file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);

                    if (RustCheatDllNames.Contains(fname))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"Rust cheat DLL on disk: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Known Rust cheat DLL '{fname}' found on disk. " +
                                     "This DLL is associated with Rust injection cheats, ESP overlays, or EAC bypass hooks.",
                            Detail = $"Path={file}",
                        });
                    }
                    else if (ApexCheatDllNames.Contains(fname))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"Apex cheat DLL on disk: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Known Apex Legends cheat DLL '{fname}' found on disk. " +
                                     "This DLL is associated with Apex injection cheats, glow ESP, or EAC bypass hooks.",
                            Detail = $"Path={file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }

    private static void ScanRustAppDataArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var rustDirs = new List<string>();
        foreach (var sub in RustAppDataSubPaths)
        {
            rustDirs.Add(Path.Combine(appData, sub));
            rustDirs.Add(Path.Combine(localAppData, sub));
        }

        foreach (var dir in rustDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Rust-Apex-Cheat",
                Title = $"Rust cheat AppData directory: {Path.GetFileName(dir)}",
                Risk = RiskLevel.High,
                Location = dir,
                FileName = Path.GetFileName(dir),
                Reason = $"Known Rust cheat tool AppData directory found: '{dir}'. " +
                         "Cheat loaders and configuration tools for Rust create data folders in AppData during installation or operation.",
                Detail = $"Directory={dir}",
            });

            try
            {
                foreach (var file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);

                    if (RustCheatConfigFiles.Any(cf => cf.Equals(fname, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"Rust cheat config file: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Known Rust cheat configuration file '{fname}' found. " +
                                     "These files store aimbot, ESP, recoil, and bypass settings for Rust cheats.",
                            Detail = $"Path={file}",
                        });
                        continue;
                    }

                    var ext = Path.GetExtension(fname);
                    if (!ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".json", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".ini", StringComparison.OrdinalIgnoreCase))
                        continue;

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();

                        var hits = CheatConfigKeywords
                            .Where(k => content.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0)
                            .ToList();

                        if (hits.Count >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Rust-Apex-Cheat",
                                Title = $"Rust cheat config keywords in: {fname}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fname,
                                Reason = $"Config file '{fname}' in Rust AppData directory contains {hits.Count} cheat-related keywords: " +
                                         $"{string.Join(", ", hits)}. Indicates active cheat configuration storage.",
                                Detail = $"Keywords={string.Join("|", hits)} Path={file}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanApexAppDataArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var apexDirs = new List<string>();
        foreach (var sub in ApexAppDataSubPaths)
        {
            apexDirs.Add(Path.Combine(appData, sub));
            apexDirs.Add(Path.Combine(localAppData, sub));
        }
        apexDirs.Add(Path.Combine(userProfile, "Saved Games", "Respawn", "Apex"));

        foreach (var dir in apexDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);

                    bool isSettingsCfg = fname.Equals("settings.cfg", StringComparison.OrdinalIgnoreCase);
                    bool isVideoConfig = fname.Equals("videoconfig.txt", StringComparison.OrdinalIgnoreCase);

                    if (!isSettingsCfg && !isVideoConfig) continue;

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();

                        var suspiciousEntries = new List<string>();

                        if (isSettingsCfg)
                        {
                            var fovMatch = Regex.Match(content, @"fov[^\n]*?(\d+)", RegexOptions.IgnoreCase);
                            if (fovMatch.Success && int.TryParse(fovMatch.Groups[1].Value, out int fovVal) && fovVal <= 10)
                            {
                                suspiciousEntries.Add($"FOV={fovVal} (aimbot zoom indicator, normal range 70-110)");
                            }

                            foreach (var kw in ApexWallhackKeywords)
                            {
                                if (content.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0)
                                    suspiciousEntries.Add(kw);
                            }

                            if (content.IndexOf("cheat", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                content.IndexOf("overlay_cheat", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                suspiciousEntries.Add("cheat overlay config entry");
                            }
                        }

                        if (isVideoConfig)
                        {
                            if (content.IndexOf("mat_fullbright", StringComparison.OrdinalIgnoreCase) >= 0)
                                suspiciousEntries.Add("mat_fullbright (wallhack-like render override)");
                        }

                        if (suspiciousEntries.Count > 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Rust-Apex-Cheat",
                                Title = $"Suspicious Apex Legends config: {fname}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fname,
                                Reason = $"Apex Legends config file '{fname}' contains suspicious entries associated with cheat overlays or aim assistance: " +
                                         $"{string.Join("; ", suspiciousEntries)}.",
                                Detail = $"Entries={string.Join("|", suspiciousEntries)} Path={file}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanRustRecoilScripts(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var baseDir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.ahk", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    CheckRustRecoilScriptContent(ctx, file, "AutoHotkey (.ahk)");
                }
            }
            catch (UnauthorizedAccessException) { }

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.py", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    CheckRustRecoilScriptContent(ctx, file, "Python (.py)");
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        ScanLogitechGhubRustProfiles(ctx, ct);
    }

    private static void CheckRustRecoilScriptContent(ScanContext ctx, string file, string scriptType)
    {
        try
        {
            string content;
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = sr.ReadToEnd();

            bool mentionsRust = content.IndexOf("rust", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!mentionsRust) return;

            var recoilHits = RustRecoilScriptKeywords
                .Where(k => content.IndexOf(k, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            if (recoilHits.Count >= 2)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "Rust-Apex-Cheat",
                    Title = $"Rust recoil script detected: {Path.GetFileName(file)}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = $"{scriptType} script mentions 'rust' and contains {recoilHits.Count} recoil-related keywords: " +
                             $"{string.Join(", ", recoilHits)}. Rust recoil scripts automate weapon spray compensation " +
                             "to eliminate recoil, providing an unfair advantage with all weapons.",
                    Detail = $"Keywords={string.Join("|", recoilHits)} Path={file}",
                });
            }
        }
        catch (IOException) { }
    }

    private static void ScanLogitechGhubRustProfiles(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var ghubDir = Path.Combine(appData, "LGHUB", "applications");

        if (!Directory.Exists(ghubDir)) return;

        try
        {
            foreach (var file in Directory.GetFiles(ghubDir, "*.lua", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    string content;
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();

                    bool mentionsRust = content.IndexOf("rust", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (!mentionsRust) continue;

                    bool hasSprayArray = Regex.IsMatch(content, @"\{x\s*=\s*-?\d+,\s*y\s*=\s*-?\d+\}", RegexOptions.IgnoreCase);
                    bool hasMoveMouseRelative = content.IndexOf("moveMouseRelative", StringComparison.OrdinalIgnoreCase) >= 0;

                    if (hasSprayArray || hasMoveMouseRelative)
                    {
                        var indicators = new List<string>();
                        if (hasSprayArray) indicators.Add("spray pattern array ({x=N, y=N})");
                        if (hasMoveMouseRelative) indicators.Add("moveMouseRelative calls");

                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"Logitech G-HUB Rust recoil Lua script: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Logitech G-HUB Lua script referencing Rust contains indicators of a recoil compensation macro: " +
                                     $"{string.Join(", ", indicators)}. G-HUB Lua scripts run at the mouse firmware level, " +
                                     "making them difficult for game-level anti-cheat to detect.",
                            Detail = $"Indicators={string.Join("|", indicators)} Path={file}",
                        });
                    }
                }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private static void ScanRazerSynapseRustProfiles(ScanContext ctx, CancellationToken ct)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var razerDir = Path.Combine(appData, "Razer", "Synapse3", "Profiles");

        if (!Directory.Exists(razerDir)) return;

        var rustWeaponNames = new[]
        {
            "rust", "akm", "ak47", "thompson", "mp5", "semi", "norecoil",
            "recoil", "spray", "sar", "lr300", "m249", "m39",
        };

        try
        {
            foreach (var file in Directory.GetFiles(razerDir, "*.json", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    string content;
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();

                    var hits = rustWeaponNames
                        .Where(w => content.IndexOf(w, StringComparison.OrdinalIgnoreCase) >= 0)
                        .ToList();

                    if (hits.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"Razer Synapse Rust recoil profile: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Razer Synapse 3 profile '{Path.GetFileName(file)}' contains {hits.Count} Rust weapon or recoil keywords: " +
                                     $"{string.Join(", ", hits)}. Razer Synapse macros can emulate per-weapon spray compensation " +
                                     "patterns, bypassing software-level anti-cheat detection.",
                            Detail = $"Keywords={string.Join("|", hits)} Path={file}",
                        });
                    }
                }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private static void ScanEacBypassAndRegistry(ScanContext ctx, CancellationToken ct)
    {
        CheckEacGameBinarySize(ctx, ct, "Rust");
        CheckEacGameBinarySize(ctx, ct, "Apex Legends");

        if (ct.IsCancellationRequested) return;

        var rustCheatRegKeys = new[]
        {
            @"Software\RustCheat",
            @"Software\ApexCheat",
        };

        foreach (var regPath in rustCheatRegKeys)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Rust-Apex-Cheat",
                    Title = $"Cheat tool registry key: HKCU\\{regPath}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{regPath}",
                    Reason = $"Registry key 'HKCU\\{regPath}' associated with a known Rust or Apex Legends cheat tool was found. " +
                             "Cheat loaders write configuration and license data to these keys during installation or first run.",
                    Detail = $"RegistryKey=HKCU\\{regPath}",
                });
            }
            catch { }
        }
    }

    private static void CheckEacGameBinarySize(ScanContext ctx, CancellationToken ct, string gameName)
    {
        if (ct.IsCancellationRequested) return;

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var gameDirNames = gameName.Equals("Rust", StringComparison.OrdinalIgnoreCase)
            ? new[] { "Rust", "RustClient" }
            : new[] { "Apex Legends", "r5apex" };

        var searchRoots = new[] { programFiles, programFilesX86 };

        foreach (var root in searchRoots)
        {
            foreach (var gameDirName in gameDirNames)
            {
                if (ct.IsCancellationRequested) return;
                var gameDir = Path.Combine(root, gameDirName);
                if (!Directory.Exists(gameDir)) continue;

                var eacBinary = Path.Combine(gameDir, "EasyAntiCheat", "EasyAntiCheat_EOS.exe");
                if (!File.Exists(eacBinary)) continue;

                ctx.IncrementFiles();
                try
                {
                    var info = new FileInfo(eacBinary);
                    if (info.Length < 100 * 1024)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"Undersized EAC binary in {gameName} installation: EasyAntiCheat_EOS.exe",
                            Risk = RiskLevel.Critical,
                            Location = eacBinary,
                            FileName = "EasyAntiCheat_EOS.exe",
                            Reason = $"The Easy Anti-Cheat binary in the {gameName} game directory is only {info.Length / 1024} KB, " +
                                     "which is far below the expected size (legitimate binary is several hundred KB). " +
                                     "A replaced or hollowed EAC binary is a hallmark of targeted EAC bypass setups where " +
                                     "the cheat loader substitutes a stub that does not enforce anti-cheat protection.",
                            Detail = $"FileSizeBytes={info.Length} Path={eacBinary}",
                        });
                    }
                }
                catch (IOException) { }
            }
        }
    }

    private static void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var allCheatExeNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var n in RustCheatExeNames) allCheatExeNames.Add(Path.GetFileNameWithoutExtension(n));
        foreach (var n in ApexCheatExeNames) allCheatExeNames.Add(Path.GetFileNameWithoutExtension(n));
        foreach (var n in EacBypassExeNames) allCheatExeNames.Add(Path.GetFileNameWithoutExtension(n));

        bool rustGameRunning = false;
        bool apexGameRunning = false;
        var runningCheats = new List<string>();

        try
        {
            var snapshot = ctx.GetProcessSnapshot();
            foreach (var proc in snapshot)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementProcesses();
                try
                {
                    var procName = proc.ProcessName;

                    if (KnownRustGameProcessNames.Any(g => procName.Equals(g, StringComparison.OrdinalIgnoreCase)))
                        rustGameRunning = true;

                    if (KnownApexGameProcessNames.Any(g => procName.Equals(g, StringComparison.OrdinalIgnoreCase)))
                        apexGameRunning = true;

                    if (allCheatExeNames.Contains(procName))
                    {
                        string? exePath = null;
                        try { exePath = proc.MainModule?.FileName; } catch { }

                        runningCheats.Add(procName);

                        ctx.AddFinding(new Finding
                        {
                            Module = "Rust-Apex-Cheat",
                            Title = $"Rust/Apex cheat process running: {procName}",
                            Risk = RiskLevel.High,
                            Location = exePath ?? $"PID {proc.Id}",
                            FileName = procName,
                            Reason = $"Known Rust or Apex Legends cheat process '{procName}' is currently running. " +
                                     "This is strong evidence of active cheat usage. The game may be currently exploited.",
                            Detail = $"PID={proc.Id} Name={procName} Path={exePath ?? "unknown"}",
                        });
                    }
                }
                catch { }
            }
        }
        catch { }

        if (runningCheats.Count > 0 && (rustGameRunning || apexGameRunning))
        {
            var gameName = rustGameRunning ? "Rust" : "Apex Legends";
            ctx.AddFinding(new Finding
            {
                Module = "Rust-Apex-Cheat",
                Title = $"Active cheat process detected while {gameName} is running",
                Risk = RiskLevel.Critical,
                Location = "Process snapshot",
                Reason = $"Cheat process(es) ({string.Join(", ", runningCheats)}) were found running simultaneously with the {gameName} game process. " +
                         "This is a real-time cheat injection or overlay scenario with the game actively running.",
                Detail = $"Cheats={string.Join("|", runningCheats)} Game={gameName}",
            });
        }
    }

    private static void ScanPrefetchArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var file in Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fname = Path.GetFileName(file).ToUpperInvariant();

                var matchedPattern = PrefetchPatterns.FirstOrDefault(p =>
                    fname.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                if (matchedPattern is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Rust-Apex-Cheat",
                    Title = $"Rust/Apex cheat Prefetch artifact: {Path.GetFileName(file)}",
                    Risk = RiskLevel.Medium,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = $"Windows Prefetch file '{Path.GetFileName(file)}' indicates that a Rust or Apex cheat binary " +
                             $"matching the pattern '{matchedPattern}' was previously executed on this system. " +
                             "Prefetch files persist even after the original executable is deleted, providing forensic evidence of past cheat execution.",
                    Detail = $"Pattern={matchedPattern} Path={file}",
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }
}
