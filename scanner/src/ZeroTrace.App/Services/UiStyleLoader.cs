using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;

namespace ZeroTrace.App.Services;

/// <summary>
/// Reads zerotrace-ui.json from the application directory and applies any
/// colour or text overrides to WPF dynamic resources at startup.  Only keys
/// present in the file are updated — fields not listed retain their XAML
/// defaults, so a minimal diff file produced by the dashboard is enough.
/// </summary>
internal static class UiStyleLoader
{
    private static readonly string ConfigPath =
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "zerotrace-ui.json");

    internal static void Apply()
    {
        if (!File.Exists(ConfigPath)) return;

        try
        {
            using var stream = File.OpenRead(ConfigPath);
            var doc = JsonDocument.Parse(stream);
            var root = doc.RootElement;

            if (root.TryGetProperty("colors", out var colors)) ApplyColors(colors);
            if (root.TryGetProperty("text",   out var text))   ApplyText(text);

            if (root.TryGetProperty("version", out var ver) && ver.GetString() is { } v)
                Application.Current.Resources["ScannerVersion"] = v;
        }
        catch
        {
            // style loading is best-effort; don't block startup
        }
    }

    // Maps each dashboard color key to the WPF resource keys it controls.
    private static readonly Dictionary<string, string[]> ColorMap = new()
    {
        ["background"]      = ["ScannerBgColor"],
        ["mutedBackground"] = ["ScannerPanelColor"],
        ["text"]            = ["ScannerTextColor"],
        ["mutedText"]       = ["ScannerMutedColor"],
        ["accent"]          = ["ScannerAccentColor"],
    };

    private static readonly Dictionary<string, string> TextMap = new()
    {
        ["pin"]      = "ScannerTextPin",
        ["scanning"] = "ScannerTextScanning",
        ["finished"] = "ScannerTextFinished",
    };

    private static void ApplyColors(JsonElement colors)
    {
        foreach (var (jsonKey, resourceKeys) in ColorMap)
        {
            if (!colors.TryGetProperty(jsonKey, out var el)) continue;
            var hex = el.GetString();
            if (string.IsNullOrWhiteSpace(hex)) continue;

            try
            {
                var color = (Color)ColorConverter.ConvertFromString(hex);
                foreach (var key in resourceKeys)
                    Application.Current.Resources[key] = color;
            }
            catch { /* skip invalid colour value */ }
        }
    }

    private static void ApplyText(JsonElement text)
    {
        foreach (var (jsonKey, resKey) in TextMap)
        {
            if (text.TryGetProperty(jsonKey, out var el) &&
                el.GetString() is { Length: > 0 } val)
                Application.Current.Resources[resKey] = val;
        }
    }
}
