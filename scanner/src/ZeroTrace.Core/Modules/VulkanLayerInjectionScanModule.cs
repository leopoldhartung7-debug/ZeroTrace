using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects cheat tools installed as Vulkan implicit or explicit layers. Vulkan's layer
/// system is designed for validation and debugging tools (VK_LAYER_KHRONOS_validation)
/// but is routinely abused by cheat overlays (ESP, aimbot crosshair, radar) to inject
/// themselves into every Vulkan-enabled game with full access to the graphics pipeline.
/// Implicit layers are loaded without the application's knowledge or consent. The module
/// reads HKLM and HKCU explicit/implicit layer registry keys, validates each layer's JSON
/// manifest path against known-system locations, and flags non-system layers — particularly
/// those in user directories, temp paths, or with cheat-keyword names in the layer manifest.
/// </summary>
public sealed class VulkanLayerInjectionScanModule : IScanModule
{
    public string Name => "Vulkan Layer Injection Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    private static readonly string[] LayerRegistryPaths =
    {
        @"SOFTWARE\Khronos\Vulkan\ImplicitLayers",
        @"SOFTWARE\Khronos\Vulkan\ExplicitLayers",
        @"SOFTWARE\WOW6432Node\Khronos\Vulkan\ImplicitLayers",
        @"SOFTWARE\WOW6432Node\Khronos\Vulkan\ExplicitLayers",
    };

    private static readonly string[] LegitLayerPaths =
    {
        @"\windows\system32\",
        @"\windows\syswow64\",
        @"\program files\nvidia corporation\",
        @"\program files\amd\",
        @"\program files (x86)\amd\",
        @"\program files\reshade\",        // ReShade is borderline but common
        @"\program files (x86)\reshade\",
        @"\program files\obs\",
        @"\program files\obs-studio\",
        @"\vulkansdk\",
        @"\program files\lunarg\",
        @"\program files (x86)\lunarg\",
        // GPU driver paths
        @"\nvcuda\", @"\nvoptix\",
    };

    private static readonly string[] SuspiciousLayerKeywords =
    {
        "cheat", "hack", "esp", "aimbot", "radar", "overlay",
        "wallhack", "speedhack", "bypass", "inject", "hook",
        "trigger", "norecoil", "aimassist", "softaim",
    };

    // Known cheat layer names
    private static readonly string[] KnownCheatLayers =
    {
        "VK_LAYER_CHEAT",
        "VK_LAYER_ESP",
        "VK_LAYER_RADAR",
        "VK_LAYER_OVERLAY_CHEAT",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            foreach (var path in LayerRegistryPaths)
            {
                ct.ThrowIfCancellationRequested();
                CheckRegistry(Registry.LocalMachine, "HKLM", path, ctx, ct);
                CheckRegistry(Registry.CurrentUser,  "HKCU", path, ctx, ct);
            }
        }, ct);
    }

    private void CheckRegistry(RegistryKey root, string hive, string keyPath,
        ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var key = root.OpenSubKey(keyPath);
            if (key is null) return;

            bool isImplicit = keyPath.Contains("Implicit", StringComparison.OrdinalIgnoreCase);

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                // Value name is the path to the layer JSON file
                string layerJsonPath = valueName;
                string pathLower     = layerJsonPath.ToLowerInvariant();
                string fileName      = Path.GetFileName(layerJsonPath);

                // Check if it's in a legitimate system/vendor location
                bool isLegit = Array.Exists(LegitLayerPaths, lp => pathLower.Contains(lp));
                if (isLegit) continue;

                // Check for cheat keywords in path
                bool hasCheatKeyword = Array.Exists(SuspiciousLayerKeywords,
                    kw => pathLower.Contains(kw));

                // Check for known cheat layer names in JSON content
                bool isKnownCheat = Array.Exists(KnownCheatLayers,
                    n => fileName.Contains(n, StringComparison.OrdinalIgnoreCase));

                // Try to read the JSON to get the layer name
                string? layerName = TryReadLayerName(layerJsonPath);
                bool layerNameIsSuspicious = layerName is not null &&
                    Array.Exists(SuspiciousLayerKeywords,
                        kw => layerName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                // Check if JSON file exists
                bool fileExists = File.Exists(layerJsonPath);

                // Flag if not in a legit path (implicit layers from user paths are always suspicious)
                bool isSuspicious = hasCheatKeyword || isKnownCheat || layerNameIsSuspicious ||
                                    (isImplicit && !fileExists) ||
                                    (isImplicit && pathLower.Contains(@"\appdata\")) ||
                                    (isImplicit && pathLower.Contains(@"\temp\"));

                if (!isSuspicious && !isImplicit && fileExists) continue;
                if (!isSuspicious && isImplicit && isLegit) continue;

                RiskLevel risk = (hasCheatKeyword || isKnownCheat || layerNameIsSuspicious)
                    ? RiskLevel.Critical
                    : isImplicit
                        ? RiskLevel.High
                        : RiskLevel.Medium;

                string reason = isImplicit
                    ? "Impliziter Vulkan-Layer wird ohne Wissen der Anwendung in alle Vulkan-Spiele geladen"
                    : "Expliziter Vulkan-Layer in unerwarteter Lokation";

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdächtiger Vulkan-{(isImplicit ? "Implicit" : "Explicit")}-Layer: {fileName}",
                    Risk     = risk,
                    Location = $@"{hive}\{keyPath}",
                    FileName = fileName,
                    Reason   = $"{reason}: '{layerJsonPath}'" +
                               (layerName is not null ? $" (Layer-Name: {layerName})" : "") +
                               " — Cheat-Overlays (ESP, Radar, Aimbot-Crosshair) können als Vulkan-Layer " +
                               "injiziert werden ohne Prozess-Injektion zu benötigen",
                    Detail   = $"Hive: {hive} | Art: {(isImplicit ? "Implicit" : "Explicit")} | " +
                               $"JSON: {layerJsonPath} | Vorhanden: {fileExists} | " +
                               $"Layer-Name: {layerName ?? "unbekannt"}"
                });
            }
        }
        catch { }
    }

    private static string? TryReadLayerName(string jsonPath)
    {
        try
        {
            if (!File.Exists(jsonPath)) return null;
            string content = File.ReadAllText(jsonPath, System.Text.Encoding.UTF8);

            // Look for "name": "VK_LAYER_..." pattern in JSON
            int nameIdx = content.IndexOf("\"name\"", StringComparison.OrdinalIgnoreCase);
            if (nameIdx < 0) return null;

            int colonIdx = content.IndexOf(':', nameIdx);
            if (colonIdx < 0) return null;

            int openQuote = content.IndexOf('"', colonIdx + 1);
            if (openQuote < 0) return null;

            int closeQuote = content.IndexOf('"', openQuote + 1);
            if (closeQuote < 0) return null;

            string name = content[(openQuote + 1)..closeQuote];
            return name.Length > 0 && name.Length < 128 ? name : null;
        }
        catch { return null; }
    }
}
