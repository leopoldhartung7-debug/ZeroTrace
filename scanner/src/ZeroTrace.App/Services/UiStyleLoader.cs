using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;

namespace ZeroTrace.App.Services;

/// <summary>
/// Reads zerotrace-ui.json from the application directory and applies any
/// colour or text overrides to WPF dynamic resources.  Only keys present in
/// the file are updated — fields not listed retain their XAML defaults, so a
/// minimal diff file produced by the dashboard is enough.
///
/// Call Apply() once at startup, then WatchForChanges() to enable hot-reload:
/// the scanner picks up a new/changed file without restarting.
/// </summary>
internal static class UiStyleLoader
{
    private static readonly string ConfigPath =
        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "zerotrace-ui.json");

    private static FileSystemWatcher? _watcher;

    internal static void Apply()
    {
        if (!File.Exists(ConfigPath)) return;

        try
        {
            using var stream = File.OpenRead(ConfigPath);
            var doc = JsonDocument.Parse(stream);
            var root = doc.RootElement;

            if (root.TryGetProperty("colors",     out var colors))     ApplyColors(colors);
            if (root.TryGetProperty("text",       out var text))       ApplyText(text);
            if (root.TryGetProperty("animations", out var animations)) ApplyAnimations(animations);
            if (root.TryGetProperty("introVideo", out var introVideo)) ApplyIntroVideo(introVideo);

            if (root.TryGetProperty("version", out var ver) && ver.GetString() is { } v)
                Application.Current.Resources["ScannerVersion"] = v;
        }
        catch
        {
            // style loading is best-effort; don't block startup
        }
    }

    /// <summary>
    /// Watches zerotrace-ui.json for changes and re-applies the style on the
    /// UI thread whenever the file is written.  Safe to call even if the file
    /// does not exist yet — the watcher will pick it up when it is created.
    /// </summary>
    internal static void WatchForChanges()
    {
        var dir = Path.GetDirectoryName(ConfigPath);
        if (dir == null || !Directory.Exists(dir)) return;

        _watcher = new FileSystemWatcher(dir, Path.GetFileName(ConfigPath))
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
            EnableRaisingEvents = true,
        };

        _watcher.Changed += OnFileEvent;
        _watcher.Created += OnFileEvent;
    }

    private static void OnFileEvent(object _, FileSystemEventArgs __)
    {
        // Brief delay so the file write has a chance to complete before we read it.
        Task.Delay(200).ContinueWith(_ =>
            Application.Current?.Dispatcher.Invoke(Apply));
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

    private static void ApplyAnimations(JsonElement animations)
    {
        if (animations.TryGetProperty("speed", out var sp))
        {
            double ms = sp.GetString() switch
            {
                "instant" => 0.0,
                "fast"    => 200.0,
                "slow"    => 1400.0,
                _         => 550.0,
            };
            Application.Current.Resources["ScannerAnimDurationMs"] = ms;
        }

        if (animations.TryGetProperty("barStyle", out var bs) && bs.GetString() is { Length: > 0 } bsv)
            Application.Current.Resources["ScannerBarStyle"] = bsv;

        if (animations.TryGetProperty("intro", out var intro) && intro.GetString() is { Length: > 0 } iv)
            Application.Current.Resources["ScannerIntroEffect"] = iv;

        if (animations.TryGetProperty("bgEffect", out var bg) && bg.GetString() is { Length: > 0 } bgv)
            Application.Current.Resources["ScannerBgEffect"] = bgv;

        if (animations.TryGetProperty("glowAccent", out var glow))
            Application.Current.Resources["ScannerGlowAccent"] = glow.GetBoolean();

        if (animations.TryGetProperty("glitchText", out var glitch))
            Application.Current.Resources["ScannerGlitchText"] = glitch.GetBoolean();
    }

    private static void ApplyIntroVideo(JsonElement introVideo)
    {
        if (introVideo.TryGetProperty("enabled", out var en))
            Application.Current.Resources["ScannerIntroVideoEnabled"] = en.GetBoolean();

        if (introVideo.TryGetProperty("path", out var path) && path.GetString() is { } pv)
            Application.Current.Resources["ScannerIntroVideoPath"] = pv;
    }
}
