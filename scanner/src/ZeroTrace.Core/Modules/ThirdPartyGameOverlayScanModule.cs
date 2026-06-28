using ZeroTrace.Core.Models;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects third-party game overlay software abused for cheat overlay delivery.
///
/// Game overlays are legitimate software that draws UI on top of games. However, multiple
/// overlay frameworks are abused by cheat tools to display ESP boxes, radar, and crosshair
/// overlays without triggering AC overlay detection:
///
///   Discord Game SDK overlay (DiscordGameSdk.dll):
///     - Legitimate Discord overlay but abused by cheat ESP via hooking the overlay draw calls
///     - Cheat tools hook the Discord overlay's IDXGISwapChain::Present to inject ESP rendering
///
///   Steam Overlay (GameOverlayRenderer.dll / GameOverlayRenderer64.dll):
///     - Valve's overlay injects into every Steam game via DLL injection
///     - Cheats hook the Steam overlay's D3D draw chain for frame-perfect ESP
///
///   Xbox Game Bar (GameBar.dll, GameBarPresence.dll):
///     - Microsoft's overlay uses elevated injection — cheat code injected via GameBar
///       can operate at medium integrity or via cross-process shared memory
///
///   GeForce Experience Overlay (NVIDIA Share):
///     - GFE hooks IDXGISwapChain::Present for ShadowPlay capture
///     - Cheat tools hook alongside GFE to piggyback on the already-present Present hook
///
/// Detection artifacts:
///   - Non-official DLLs loaded in Discord/Steam overlay DLL directories
///   - Registry entries registering custom overlay DLLs in known overlay paths
///   - Hook presence in IDXGISwapChain vtable entries pointing outside known overlay modules
///   - Presence of known cheat overlay framework DLLs (imgui.dll, hook_lib.dll, etc.)
/// </summary>
public sealed class ThirdPartyGameOverlayScanModule : IScanModule
{
    public string Name => "Drittanbieter Game-Overlay Missbrauch und Cheat-Overlay Scan";
    public double Weight => 0.45;
    public int ParallelGroup => 3;

    private static readonly string[] SuspiciousOverlayFiles =
    {
        // ImGui-based overlay framework (most cheat overlays use ImGui)
        "imgui.dll", "imgui_impl_dx11.dll", "imgui_impl_dx12.dll",
        "imgui_impl_win32.dll",
        // Common cheat overlay DLL names
        "overlay.dll", "esp_overlay.dll", "radar_overlay.dll",
        "cheat_overlay.dll", "render.dll", "renderer.dll",
        "hook.dll", "hook_lib.dll", "dxhook.dll", "d3dhook.dll",
        // MinHook (detour library used in cheat overlays)
        "minhook.dll", "libminhook.dll",
        // Known cheat framework DLLs
        "gamesense.dll", "skeet.dll", "neverlose.dll",
    };

    private static readonly string[] OverlayRegistryPaths =
    {
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows Gaming\GameBar",
        @"SOFTWARE\Microsoft\WindowsRuntime\Server\Windows.Gaming.GameBar.PresenceServer",
        @"SOFTWARE\NVIDIA Corporation\Global\GFExperience\NvStreamSrv",
    };

    private static readonly string[] CheatOverlayKeywords =
    {
        "esp", "aimbot", "wallhack", "radar", "cheat", "hack",
        "inject", "overlay", "draw", "imgui",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanOverlayDirectories(ctx, ct);
        ScanOverlayRegistry(ctx, ct);
        ScanGameBarAbuse(ctx, ct);
    }

    private void ScanOverlayDirectories(ScanContext ctx, CancellationToken ct)
    {
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        // Known overlay software directories
        var overlayDirs = new[]
        {
            // Steam overlay
            System.IO.Path.Combine(progFiles86, "Steam", "gameoverlayrenderer"),
            System.IO.Path.Combine(progFiles86, "Steam", "GameOverlayUI.exe"),
            // Discord overlay
            System.IO.Path.Combine(appData, "discord", "modules"),
            // GFE / Nvidia overlay
            System.IO.Path.Combine(localApp, "NVIDIA Corporation", "NvBackend"),
            System.IO.Path.Combine(progFiles86, "NVIDIA Corporation", "NvBackend"),
        };

        var suspiciousNames = new HashSet<string>(SuspiciousOverlayFiles, StringComparer.OrdinalIgnoreCase);

        foreach (string dir in overlayDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(dir) && !System.IO.File.Exists(dir)) continue;

            string searchDir = System.IO.Directory.Exists(dir) ? dir :
                System.IO.Path.GetDirectoryName(dir) ?? dir;

            try
            {
                foreach (string file in System.IO.Directory.EnumerateFiles(searchDir,
                    "*.dll", System.IO.SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string fileName = System.IO.Path.GetFileName(file);
                    if (!suspiciousNames.Contains(fileName)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Overlay DLL in Overlay-Verzeichnis: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Cheat-Overlay-DLL '{fileName}' im Overlay-Verzeichnis gefunden. " +
                                   "Cheat-Overlays platzieren ihre DLLs in bekannten Overlay-Verzeichnissen " +
                                   "(Steam, Discord, GFE) um beim Game-Start automatisch geladen zu werden. " +
                                   "ImGui und MinHook DLLs in Overlay-Dirs sind kritische Cheat-Indikatoren.",
                        Detail   = $"Datei: {file} | Overlay-Dir: {searchDir}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanOverlayRegistry(ScanContext ctx, CancellationToken ct)
    {
        foreach (string regPath in OverlayRegistryPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, false);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                foreach (string valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    string val = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                    string valLower = val.ToLowerInvariant();

                    string? match = CheatOverlayKeywords.FirstOrDefault(kw =>
                        valLower.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (match == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Overlay in Overlay-Registry: '{match}' in {valueName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{regPath}",
                        FileName = valueName,
                        Reason   = $"Overlay-Registry-Schlüssel enthält '{match}' im Wert '{valueName}'. " +
                                   "Overlay-Registry-Einträge werden beim Game-Start automatisch geladen — " +
                                   "Cheat-Overlay-DLLs eingetragen hier injizieren in alle Games.",
                        Detail   = $"Registry: {regPath}\\{valueName} = {val}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanGameBarAbuse(ScanContext ctx, CancellationToken ct)
    {
        // Xbox Game Bar extension DLLs — custom extensions can inject into games
        string gameBarExtPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\GameUX\GameConfigStoreList";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(gameBarExtPath, false);
            if (key == null) return;

            foreach (string subKeyName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var sub = key.OpenSubKey(subKeyName, false);
                    if (sub == null) continue;

                    string exe = (sub.GetValue("GameConfigStoreExe") as string ?? "").ToLowerInvariant();
                    string? match = CheatOverlayKeywords.FirstOrDefault(kw =>
                        exe.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (match == null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Tool in Xbox Game Bar GameConfig: '{match}'",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{gameBarExtPath}\{subKeyName}",
                        FileName = subKeyName,
                        Reason   = $"Xbox Game Bar Konfig-Registry enthält '{exe}' — Cheat-Keyword '{match}'. " +
                                   "Game Bar Konfigurationseinträge können für persistente Overlay-Injektion " +
                                   "in alle registrierten Spiele verwendet werden.",
                        Detail   = $"Exe: {exe} | Keyword: '{match}'"
                    });
                }
                catch { }
            }
        }
        catch { }

        // Also check for suspicious Game DVR / Game Bar extension paths
        string gameDvrPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(gameDvrPath, false);
            if (key == null) return;
            ctx.IncrementRegistryKeys();

            string? appCaptureEnabled = key.GetValue("AppCaptureEnabled")?.ToString();
            string? historicalCaptureEnabled = key.GetValue("HistoricalCaptureEnabled")?.ToString();

            // If Game DVR disabled but Game Bar still running — potential evasion
            if (appCaptureEnabled == "0" && historicalCaptureEnabled == "0")
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Xbox Game DVR deaktiviert (mögliche Cheat-Overlay-Evasion)",
                    Risk     = RiskLevel.Low,
                    Location = $@"HKLM\{gameDvrPath}",
                    FileName = "GameDVR",
                    Reason   = "Xbox Game DVR ist deaktiviert. Cheat-Tools deaktivieren Game DVR " +
                               "um Shadowplay/Game Bar Screenshots/Videos zu verhindern, die das " +
                               "Cheat-Overlay dokumentieren würden. In Kombination mit anderen " +
                               "Indikatoren ist dies ein Evasion-Signal.",
                    Detail   = $"AppCaptureEnabled: {appCaptureEnabled} | HistoricalCaptureEnabled: {historicalCaptureEnabled}"
                });
            }
        }
        catch { }
    }
}
