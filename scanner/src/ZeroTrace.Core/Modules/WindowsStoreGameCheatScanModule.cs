using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects cheat artifacts in Xbox/PC Game Pass game directories (C:\XboxGames\),
/// Game Bar overlay abuse, and Game DVR recording bypass. PC Game Pass titles like
/// Halo Infinite have different install paths from Steam/Epic — dedicated scanning required.
/// Also scans per-package LocalState directories for cheat-keyword files.
/// </summary>
public sealed class WindowsStoreGameCheatScanModule : IScanModule
{
    public string Name => "WindowsStoreGameCheat";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    // Proxy DLL names injected via DLL-hijacking into game process
    private static readonly string[] ProxyDllNames = {
        "winhttp.dll",      // BepInEx Doorstop / Unity proxy
        "version.dll",      // Common proxy DLL
        "d3d11.dll",        // D3D11 hook proxy
        "d3d12.dll",        // D3D12 hook
        "dxgi.dll",         // DXGI SwapChain::Present hook
        "dinput8.dll",      // DirectInput input modification
        "dsound.dll",       // Audio DLL proxy
        "xinput1_3.dll",    // XInput wrapper for aim assist
        "xinput1_4.dll",
        "winmm.dll",        // WinMM proxy
        "doorstop_config.ini",  // Unity Doorstop config
    };

    private static readonly string[] CheatKeywords = {
        "aimbot", "wallhack", "esp", "bhop", "nohitbox", "injector",
        "cheat", "hack", "triggerbot", "speedhack", "bypass", "radar"
    };

    // Xbox Game Pass game directory name fragments to target
    private static readonly string[] XboxTargetGameFragments = {
        "Halo", "Sea of Thieves", "Forza", "Deep Rock", "Grounded",
        "Minecraft", "Gears", "Flight Simulator", "Outer Worlds",
        "Back 4 Blood", "The Medium", "Psychonauts", "Ori "
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanXboxGamesDirectory(ctx, ct);
            ScanGameBarOverlayRegistry(ctx, ct);
            ScanGameDvrBypass(ctx, ct);
            ScanWindowsAppsPackageLocalState(ctx, ct);
        }, ct);
    }

    // ─── XboxGames root directories ──────────────────────────────────────────

    private static void ScanXboxGamesDirectory(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var roots = new List<string> { @"C:\XboxGames" };

        // Add alternative roots on other fixed drives
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Fixed && !drive.Name.StartsWith("C", StringComparison.OrdinalIgnoreCase))
                {
                    var alt = Path.Combine(drive.Name, "XboxGames");
                    if (Directory.Exists(alt)) roots.Add(alt);
                }
            }
        }
        catch { }

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var gameDir in Directory.GetDirectories(root, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ScanSingleXboxGameDir(ctx, gameDir, ct);
                }
            }
            catch { }
        }
    }

    private static void ScanSingleXboxGameDir(ScanContext ctx, string gameDir, CancellationToken ct)
    {
        var gameName = Path.GetFileName(gameDir);

        try
        {
            // Check for proxy DLLs in game root and Content subdir
            foreach (var proxyDll in ProxyDllNames)
            {
                ct.ThrowIfCancellationRequested();

                foreach (var searchBase in new[] { gameDir, Path.Combine(gameDir, "Content") })
                {
                    if (!Directory.Exists(searchBase)) continue;
                    var fullPath = Path.Combine(searchBase, proxyDll);
                    if (!File.Exists(fullPath)) continue;

                    ctx.IncrementFiles(1);
                    ctx.AddFinding(new Finding
                    {
                        Module = "WindowsStoreGameCheat",
                        Title = $"Proxy-DLL/Cheat-Datei in Xbox-Game-Dir: {proxyDll}",
                        Risk = RiskLevel.Critical,
                        Location = fullPath,
                        FileName = proxyDll,
                        Reason = $"'{proxyDll}' im Xbox Game Pass Spielverzeichnis '{gameName}' gefunden. " +
                                 "Wird fuer DLL-Hijacking-Injection oder BepInEx-Doorstop-Cheats verwendet.",
                        Detail = $"GameDir={gameDir} File={proxyDll}"
                    });
                }
            }

            // Check for BepInEx framework
            var bepinexDir = Path.Combine(gameDir, "BepInEx");
            if (Directory.Exists(bepinexDir))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "WindowsStoreGameCheat",
                    Title = $"BepInEx Injection-Framework in Xbox-Game: {gameName}",
                    Risk = RiskLevel.High,
                    Location = bepinexDir,
                    Reason = "BepInEx Code-Injection-Framework im Xbox Game Pass Spielverzeichnis gefunden. " +
                             "Wird verwendet um beliebigen Code in Unity-basierte Spiele einzuschleusen.",
                    Detail = $"BepInExDir={bepinexDir}"
                });

                var pluginsDir = Path.Combine(bepinexDir, "plugins");
                if (Directory.Exists(pluginsDir))
                    ScanDirForCheatDlls(ctx, pluginsDir, gameName, ct);
            }

            // Scan game root DLLs for cheat keywords
            ScanDirForCheatDlls(ctx, gameDir, gameName, ct);

            // Also check Content subdir
            var contentDir = Path.Combine(gameDir, "Content");
            if (Directory.Exists(contentDir))
                ScanDirForCheatDlls(ctx, contentDir, gameName, ct);
        }
        catch { }
    }

    private static void ScanDirForCheatDlls(ScanContext ctx, string dir, string gameName, CancellationToken ct)
    {
        try
        {
            foreach (var dll in Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                var fname = Path.GetFileName(dll).ToLowerInvariant();
                foreach (var kw in CheatKeywords)
                {
                    if (fname.Contains(kw))
                    {
                        ctx.IncrementFiles(1);
                        ctx.AddFinding(new Finding
                        {
                            Module = "WindowsStoreGameCheat",
                            Title = $"Cheat-DLL in Xbox-Game-Verzeichnis: {Path.GetFileName(dll)}",
                            Risk = RiskLevel.Critical,
                            Location = dll,
                            FileName = Path.GetFileName(dll),
                            Reason = $"DLL mit Cheat-Keyword '{kw}' im Spielverzeichnis '{gameName}' gefunden.",
                            Detail = $"File={dll}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }

    // ─── Xbox Game Bar overlay / DVR registry ────────────────────────────────

    private static void ScanGameBarOverlayRegistry(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // Game Bar Widgets — third-party overlays register here
        string[] gamingOverlayKeys = {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR\AppExceptions",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\GameUX\Games",
        };

        foreach (var keyPath in gamingOverlayKeys)
        {
            ct.ThrowIfCancellationRequested();
            using var key = Registry.CurrentUser.OpenSubKey(keyPath);
            if (key == null) continue;

            ctx.IncrementRegistryKeys(1);
            foreach (var subName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var sub = key.OpenSubKey(subName);
                if (sub == null) continue;

                var exePath = sub.GetValue("AppPath") as string
                           ?? sub.GetValue("ExecutablePath") as string ?? string.Empty;

                if (string.IsNullOrEmpty(exePath)) continue;

                var lower = exePath.ToLowerInvariant();

                if ((lower.Contains("temp") || lower.Contains("appdata") || lower.Contains("downloads"))
                    && !lower.Contains("windowsapps"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "WindowsStoreGameCheat",
                        Title = "Verdaechtige Xbox Game Bar Registrierung aus Temp/AppData",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{keyPath}\{subName}",
                        Reason = $"Xbox Game Bar hat eine App aus verdaechtigem Pfad registriert: '{exePath}'. " +
                                 "Cheat-Overlays tarnen sich als Game Bar Widgets.",
                        Detail = $"AppPath={exePath}"
                    });
                }

                foreach (var kw in CheatKeywords)
                {
                    if (lower.Contains(kw))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "WindowsStoreGameCheat",
                            Title = "Cheat-Keyword in Xbox Game Bar Eintrag",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{keyPath}\{subName}",
                            Reason = $"Cheat-Keyword '{kw}' in Xbox Game Bar Registrierungseintrag: '{exePath}'.",
                            Detail = $"AppPath={exePath} Keyword={kw}"
                        });
                        break;
                    }
                }
            }
        }
    }

    // ─── Game DVR recording bypass ────────────────────────────────────────────

    private static void ScanGameDvrBypass(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        using var gdvrKey = Registry.CurrentUser.OpenSubKey(@"System\GameConfigStore");
        if (gdvrKey != null)
        {
            ctx.IncrementRegistryKeys(1);
            var gameDvr = gdvrKey.GetValue("GameDVR_Enabled");
            if (gameDvr is int dvr && dvr == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "WindowsStoreGameCheat",
                    Title = "Xbox Game DVR / Spielaufnahme deaktiviert",
                    Risk = RiskLevel.Medium,
                    Location = @"HKCU\System\GameConfigStore!GameDVR_Enabled",
                    Reason = "Xbox Game DVR ist deaktiviert. Verhindert automatische Screenshots und Videobeweise " +
                             "die Xbox/Microsoft fuer Anti-Cheat-Reviews verwendet.",
                    Detail = "GameDVR_Enabled=0"
                });
            }
        }

        using var gdvrPolicyKey = Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Policies\Microsoft\Windows\GameDVR");
        if (gdvrPolicyKey != null)
        {
            ctx.IncrementRegistryKeys(1);
            var allowed = gdvrPolicyKey.GetValue("AllowGameDVR");
            if (allowed is int a && a == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "WindowsStoreGameCheat",
                    Title = "Xbox Game DVR per Gruppenrichtlinie blockiert",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR",
                    Reason = "Game DVR via Gruppenrichtlinie deaktiviert — ungewoehnlich fuer Gaming-PCs, " +
                             "typisch fuer Cheat-Setup das Screenshot-Beweise verhindern will.",
                    Detail = "AllowGameDVR=0 (Policy)"
                });
            }
        }

        // Xbox privacy settings — suppress clip sharing to Microsoft for review
        using var xboxPrivKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\XboxLive");
        if (xboxPrivKey != null)
        {
            ctx.IncrementRegistryKeys(1);
            var shareActivity = xboxPrivKey.GetValue("ShareGameActivity");
            if (shareActivity is int sa && sa == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "WindowsStoreGameCheat",
                    Title = "Xbox Spielaktivitaets-Teilen deaktiviert",
                    Risk = RiskLevel.Low,
                    Location = @"HKCU\Software\Microsoft\XboxLive!ShareGameActivity",
                    Reason = "Xbox Spielaktivitaetsfreigabe deaktiviert — verhindert Xbox Anti-Cheat-Datenuebermittlung.",
                    Detail = "ShareGameActivity=0"
                });
            }
        }
    }

    // ─── Per-package LocalState scan ─────────────────────────────────────────

    private static void ScanWindowsAppsPackageLocalState(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var packagesDir = Path.Combine(localApp, "Packages");
        if (!Directory.Exists(packagesDir)) return;

        string[] targetGlobs = {
            "*Halo*", "*SeaOfThieves*", "*ForzaHorizon*",
            "*Grounded*", "*BackFourBlood*", "*Minecraft*",
            "*GearsTactics*", "*Gears5*", "*DeepRock*"
        };

        try
        {
            foreach (var glob in targetGlobs)
            {
                ct.ThrowIfCancellationRequested();
                // Strip wildcards and just check prefix/contains
                var fragment = glob.Replace("*", "").ToLowerInvariant();

                foreach (var pkgDir in Directory.GetDirectories(packagesDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var pkgName = Path.GetFileName(pkgDir).ToLowerInvariant();
                    if (!pkgName.Contains(fragment)) continue;

                    var localStateDir = Path.Combine(pkgDir, "LocalState");
                    if (!Directory.Exists(localStateDir)) continue;

                    try
                    {
                        foreach (var file in Directory.GetFiles(localStateDir, "*", SearchOption.TopDirectoryOnly))
                        {
                            ct.ThrowIfCancellationRequested();
                            var fname = Path.GetFileName(file).ToLowerInvariant();
                            foreach (var kw in CheatKeywords)
                            {
                                if (fname.Contains(kw))
                                {
                                    ctx.IncrementFiles(1);
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "WindowsStoreGameCheat",
                                        Title = $"Cheat-Datei in Xbox-Paket-LocalState: {Path.GetFileName(file)}",
                                        Risk = RiskLevel.Critical,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Datei mit Cheat-Keyword '{kw}' in Xbox-Game-Paket-LocalState gefunden.",
                                        Detail = $"Path={file} Package={pkgDir}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }
}
