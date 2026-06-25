using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects DirectX/DXGI debug layer activation and suspicious D3D registry overrides.
/// The D3D11/D3D12 debug layer and DXGI debug interface add validation layers to the
/// graphics pipeline — legitimate only during game development, not on end-user machines.
/// Cheat tools exploit these debug facilities to hook the swap chain (IDXGISwapChain::Present),
/// inject overlay rendering, and intercept GPU resource creation. ForceWARP replaces GPU
/// acceleration with the CPU-based WARP software rasterizer, bypassing GPU-side AC checks.
/// Also scans HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences for cheat-keyword app
/// overrides, and checks for active D3D SDK layer registration outside of SDK paths.
/// </summary>
public sealed class DirectXDebugLayerScanModule : IScanModule
{
    public string Name => "DirectX Debug Layer & Hook Detection";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private static readonly (string Hive, string KeyPath, string ValueName, string Description, bool HighRisk)[]
        DebugLayerChecks =
    {
        // D3D11 debug validation layer — not for end users
        ("HKLM", @"SOFTWARE\Microsoft\Direct3D",        "EnableDebugLayer",   "D3D11 Debug Layer",                   false),
        // D3D12 debug layer
        ("HKLM", @"SOFTWARE\Microsoft\Direct3D",        "EnableD3D12Debug",   "D3D12 Debug Layer",                   false),
        // DXGI debug interface
        ("HKLM", @"SOFTWARE\Microsoft\DXGI",            "DebugLayer",         "DXGI Debug Layer",                    false),
        // WARP software rasterizer forced — disables GPU, can bypass GPU-level AC
        ("HKLM", @"SOFTWARE\Microsoft\Direct3D",        "ForceWARP",          "D3D Software Rasterizer (WARP) Forced", true),
        // Reference rasterizer — extremely slow, used only for debugging
        ("HKLM", @"SOFTWARE\Microsoft\Direct3D",        "ForceRef",           "D3D Reference Rasterizer Forced",     true),
        // Disable DXGI frame stats (hide swap chain metrics from AC)
        ("HKLM", @"SOFTWARE\Microsoft\DXGI",            "DisableFrameStats",  "DXGI Frame Statistics Disabled",      false),
        // D3D GPU-based validation (GBV) — very heavy, only debuggers enable this
        ("HKLM", @"SOFTWARE\Microsoft\Direct3D",        "EnableGPUBasedValidation", "D3D12 GPU-Based Validation",    false),
        // DirectX Diagnostics capture hook
        ("HKLM", @"SOFTWARE\Microsoft\DirectX",         "GraphicsDiagnosticsCaptureEnabled", "Graphics Diagnostics Capture", false),
        // PIX GPU capture (Windows PIX profiler)
        ("HKCU", @"SOFTWARE\Microsoft\PIX",             "CaptureEnabled",     "PIX GPU Capture Enabled",             false),
        // D3D multi-adapter support forced (can be used to redirect rendering to secondary GPU)
        ("HKLM", @"SOFTWARE\Microsoft\Direct3D12",      "UseDriverCompatibilityLevel", "D3D12 Driver Compat Level Override", false),
    };

    private static readonly string[] SuspiciousGpuPrefKeywords =
    {
        "cheat", "hack", "esp", "radar", "aimbot", "inject",
        "bypass", "hook", "overlay", "trainer", "dumper",
        "reshade",    // ReShade can be used for ESP overlays
        "dxvk",       // Vulkan-over-D3D — suspicious outside Wine/Proton
        "wined3d",    // Wine D3D emulation — suspicious on native Windows
    };

    // SDK/tooling paths where debug layer DLLs legitimately live
    private static readonly string[] LegitDebugDllPaths =
    {
        @"\windows kits\",
        @"\visual studio\",
        @"\microsoft visual studio\",
        @"\sdk\",
        @"\directx sdk\",
        @"\program files\windows kits\",
        @"\program files (x86)\windows kits\",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckDebugLayerKeys(ctx, ct);
            CheckUserGpuPreferences(ctx, ct);
            CheckD3DPlugins(ctx, ct);
        }, ct);
    }

    private void CheckDebugLayerKeys(ScanContext ctx, CancellationToken ct)
    {
        foreach (var (hive, keyPath, valueName, desc, highRisk) in DebugLayerChecks)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                RegistryKey root = hive == "HKCU" ? Registry.CurrentUser : Registry.LocalMachine;
                using var key = root.OpenSubKey(keyPath);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                object? val = key.GetValue(valueName);
                if (val is null) continue;

                int intVal = val switch
                {
                    int i    => i,
                    uint u   => (int)u,
                    string s => int.TryParse(s, out int p) ? p : 0,
                    _        => 0,
                };
                if (intVal == 0) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"DirectX Debug/Override aktiv: {valueName}",
                    Risk     = highRisk ? RiskLevel.High : RiskLevel.Medium,
                    Location = $@"{hive}\{keyPath}\{valueName}",
                    FileName = valueName,
                    Reason   = $"{desc} ist auf diesem System aktiviert (Wert={intVal}) — " +
                               (highRisk
                                   ? "ForceWARP/ForceRef ersetzt GPU-Rendering durch Software und kann " +
                                     "GPU-seitige Anti-Cheat-Prüfungen umgehen"
                                   : "Debug-Layer sind nur für Entwickler vorgesehen; auf End-User-Systemen " +
                                     "können sie für Graphics-Pipeline-Hooking und Swap-Chain-Interception " +
                                     "(ESP-Overlay, Cheat-Rendering) missbraucht werden"),
                    Detail   = $"Hive: {hive} | Schlüssel: {keyPath} | Wert: {valueName}={intVal} | " +
                               $"Beschreibung: {desc} | HochRisiko: {highRisk}"
                });
            }
            catch { }
        }
    }

    private void CheckUserGpuPreferences(ScanContext ctx, CancellationToken ct)
    {
        // HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences maps application paths to GPU
        // preference (power-saver/high-performance). Cheats sometimes add entries here.
        try
        {
            ct.ThrowIfCancellationRequested();
            using var key = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\DirectX\UserGpuPreferences");
            if (key is null) return;

            foreach (string valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                string nameLower = valueName.ToLowerInvariant();
                bool hasSuspicious = Array.Exists(SuspiciousGpuPrefKeywords,
                    kw => nameLower.Contains(kw));
                if (!hasSuspicious) continue;

                string? val = key.GetValue(valueName) as string;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdächtiger D3D GPU-Präferenz-Eintrag: {Path.GetFileName(valueName)}",
                    Risk     = RiskLevel.Medium,
                    Location = @"HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences",
                    FileName = Path.GetFileName(valueName),
                    Reason   = $"Verdächtiger Eintrag '{valueName}' in UserGpuPreferences — " +
                               "DXGI-GPU-Präferenz-Einträge für Cheat/Hook-Tools deuten auf " +
                               "versuchte Graphics-Pipeline-Manipulation hin",
                    Detail   = $"App-Pfad: {valueName} | GPU-Präferenz: {val ?? "leer"}"
                });
            }
        }
        catch { }
    }

    private void CheckD3DPlugins(ScanContext ctx, CancellationToken ct)
    {
        // HKLM\SOFTWARE\Microsoft\Direct3D\Drivers can register D3D IHV plugins
        // Cheats rarely use this but it's worth checking for unexpected DLLs
        string[] pluginKeys =
        {
            @"SOFTWARE\Microsoft\Direct3D\Drivers",
            @"SOFTWARE\WOW6432Node\Microsoft\Direct3D\Drivers",
        };

        foreach (string keyPath in pluginKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key is null) continue;

                foreach (string valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    string? dllPath = key.GetValue(valueName) as string;
                    if (string.IsNullOrEmpty(dllPath)) continue;

                    string dllLower = dllPath.ToLowerInvariant();

                    // Check if in a legitimate SDK path
                    bool isLegit = Array.Exists(LegitDebugDllPaths, p => dllLower.Contains(p));
                    if (isLegit) continue;

                    bool fileExists = File.Exists(dllPath);
                    bool isSuspicious = Array.Exists(SuspiciousGpuPrefKeywords,
                        kw => dllLower.Contains(kw));

                    if (!isSuspicious && fileExists &&
                        dllLower.StartsWith(@"c:\windows\")) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Unerwarteter D3D-Treiber-Plugin: {valueName}",
                        Risk     = isSuspicious ? RiskLevel.High : RiskLevel.Medium,
                        Location = $@"HKLM\{keyPath}",
                        FileName = Path.GetFileName(dllPath),
                        Reason   = $"D3D-Plugin-DLL '{dllPath}' unter '{valueName}' registriert außerhalb " +
                                   "des Windows SDK-Pfads — D3D-Plugins werden in jeden DX-Prozess geladen " +
                                   "und können für Swap-Chain-Hooking missbraucht werden",
                        Detail   = $"Schlüssel: {keyPath} | Wert: {valueName} | DLL: {dllPath} | " +
                                   $"Vorhanden: {fileExists} | Cheat-Keyword: {isSuspicious}"
                    });
                }
            }
            catch { }
        }
    }
}
