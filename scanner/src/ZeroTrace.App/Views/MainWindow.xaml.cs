using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
using ZeroTrace.Core.Data;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Reporting;

namespace ZeroTrace.App.Views;

/// <summary>
/// Compact, single-card scanner window styled after the ZeroTrace demo:
/// particle background and a step flow (game → PIN → consent → scan → result).
/// The real scan engine runs behind it; the result screen shows an animated
/// green check and closes itself after 5 seconds.
/// </summary>
public partial class MainWindow : Window
{
    private readonly IndicatorStore _indicators;
    private readonly ScanStore _scans;
    private readonly SettingsStore _settings;

    private TextBox[] _boxes = Array.Empty<TextBox>();
    private bool _pinLocked;
    private string _enteredPin = "";
    private string _game = "FiveM";
    private DispatcherTimer? _closeTimer;
    private int _closeSecs;

    public MainWindow(IndicatorStore indicators, ScanStore scans, SettingsStore settings)
    {
        InitializeComponent();
        _indicators = indicators;
        _scans = scans;
        _settings = settings;

        _boxes = new[] { P0, P1, P2, P3, P4, P5 };
        TryLoadEmbeddedPin();
        ShowStep(GameView);
    }

    // ===== Step navigation =====
    private void ShowStep(FrameworkElement step)
    {
        foreach (var s in new FrameworkElement[] { GameView, PinView, ConsentView, ScanView, ResultView })
            s.Visibility = s == step ? Visibility.Visible : Visibility.Collapsed;
    }

    // ===== Window chrome =====
    private void Header_Drag(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
        {
            try { DragMove(); } catch { /* ignore */ }
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    // ===== Game select =====
    private void Game_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button b && b.Tag is string g) _game = g;
        SubText.Text = "Host-Scanner · " + _game;
        ShowStep(PinView);
        UpdatePinState();
        if (!_pinLocked) P0.Focus();
    }

    // ===== PIN handling =====
    private static bool ValidPin(string? s) => Regex.IsMatch(s ?? "", @"^\d{6}$");

    private string CollectPin() => string.Concat(_boxes.Select(x => x.Text));

    private void UpdatePinState() => PinNext.IsEnabled = ValidPin(CollectPin());

    // The website bakes a PIN into the download: either as a command-line
    // argument (--pin=123456) or in a "zerotrace.pin" file next to the exe.
    private void TryLoadEmbeddedPin()
    {
        try
        {
            string? pin = null;
            foreach (var a in Environment.GetCommandLineArgs())
                if (a.StartsWith("--pin=", StringComparison.OrdinalIgnoreCase))
                    pin = a.Substring("--pin=".Length);

            if (pin is null)
            {
                var file = Path.Combine(AppContext.BaseDirectory, "zerotrace.pin");
                if (File.Exists(file)) pin = File.ReadAllText(file).Trim();
            }

            pin = (pin ?? "").Trim();
            if (!ValidPin(pin)) return;

            for (int i = 0; i < _boxes.Length; i++)
            {
                _boxes[i].Text = pin[i].ToString();
                _boxes[i].IsReadOnly = true;
            }
            _pinLocked = true;
        }
        catch { /* the user can still type one in */ }
    }

    private void Pin_GotFocus(object sender, RoutedEventArgs e)
    {
        if (sender is TextBox tb) tb.SelectAll();
    }

    private void Pin_Changed(object sender, TextChangedEventArgs e)
    {
        if (sender is not TextBox tb) return;

        var digits = new string(tb.Text.Where(char.IsDigit).ToArray());
        if (tb.Text != digits)
        {
            tb.Text = digits;
            tb.CaretIndex = tb.Text.Length;
        }

        if (tb.Text.Length == 1)
        {
            int i = Array.IndexOf(_boxes, tb);
            if (i >= 0 && i < _boxes.Length - 1) _boxes[i + 1].Focus();
        }
        PinErr.Text = "";
        UpdatePinState();
    }

    private void Pin_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Back || sender is not TextBox tb) return;
        if (tb.Text.Length == 0)
        {
            int i = Array.IndexOf(_boxes, tb);
            if (i > 0)
            {
                _boxes[i - 1].Focus();
                if (!_boxes[i - 1].IsReadOnly) _boxes[i - 1].Text = "";
                e.Handled = true;
            }
        }
    }

    private void PinNext_Click(object sender, RoutedEventArgs e)
    {
        var pin = CollectPin();
        if (!ValidPin(pin))
        {
            PinErr.Text = "Bitte den 6-stelligen PIN eingeben.";
            return;
        }
        _enteredPin = pin;
        DeclineNote.Text = "";
        ShowStep(ConsentView);
    }

    // ===== Consent =====
    private void Decline_Click(object sender, RoutedEventArgs e)
    {
        DeclineNote.Text = "Abgelehnt – es wird kein Scan durchgeführt und nichts erfasst.";
    }

    private async void Accept_Click(object sender, RoutedEventArgs e)
    {
        ShowStep(ScanView);
        await RunScanAsync();
    }

    // ===== Scan =====
    private async Task RunScanAsync()
    {
        BarScale.ScaleX = 0;
        PctText.Text = "0%";
        NowPath.Text = "…";

        var options = _settings.LoadOptions();
        var matcher = new IndicatorMatcher(_indicators.GetEnabled());
        var engine = new ScanEngine(matcher);
        var progress = new Progress<ScanProgress>(OnProgress);

        ScanReport report;
        try
        {
            using var cts = new CancellationTokenSource();
            report = await Task.Run(() => engine.RunAsync(options, progress, null, cts.Token));
        }
        catch (Exception ex)
        {
            NowPath.Text = "Fehler: " + ex.Message;
            return;
        }

        report.Pin = _enteredPin;
        try { _scans.Save(report); } catch { /* best effort */ }

        // Auto-send to the configured destination (disclosed in the consent step).
        var url = (_settings.Get("webhook_url") ?? "").Trim();
        if (!string.IsNullOrEmpty(url))
        {
            try { await WebhookSender.SendAsync(url, WebhookSender.BuildPayload(report)); }
            catch { /* the result is still shown locally */ }
        }

        ShowResult(report);
    }

    private void OnProgress(ScanProgress p)
    {
        BarScale.ScaleX = Math.Clamp(p.Percent / 100.0, 0, 1);
        PctText.Text = $"{p.Percent:0}%";
        var label = !string.IsNullOrWhiteSpace(p.Module) ? p.Module
                  : !string.IsNullOrWhiteSpace(p.Message) ? p.Message : "…";
        NowPath.Text = label;
    }

    // ===== Result =====
    private void ShowResult(ScanReport report)
    {
        int count = report.Findings.Count;
        if (count > 0)
        {
            YesNo.Text = $"⚠  Auffälligkeiten gefunden: {count}";
            YesNo.Foreground = new SolidColorBrush(Color.FromRgb(0xF9, 0x73, 0x16));
        }
        else
        {
            YesNo.Text = "✓  Keine Auffälligkeiten gefunden";
            YesNo.Foreground = new SolidColorBrush(Color.FromRgb(0x22, 0xCC, 0x66));
        }

        ShowStep(ResultView);
        PlayCheckAnimation();
        StartCloseCountdown(5);
    }

    private void PlayCheckAnimation()
    {
        ResultContent.BeginAnimation(OpacityProperty,
            new DoubleAnimation(0, 1, TimeSpan.FromSeconds(0.35)));

        var pop = new BackEase { Amplitude = 0.7, EasingMode = EasingMode.EaseOut };
        ResultScale.BeginAnimation(ScaleTransform.ScaleXProperty,
            new DoubleAnimation(0.7, 1, TimeSpan.FromSeconds(0.5)) { EasingFunction = pop });
        ResultScale.BeginAnimation(ScaleTransform.ScaleYProperty,
            new DoubleAnimation(0.7, 1, TimeSpan.FromSeconds(0.5)) { EasingFunction = pop });

        CheckPath.BeginAnimation(Shape.StrokeDashOffsetProperty,
            new DoubleAnimation(16, 0, TimeSpan.FromSeconds(0.55))
            {
                BeginTime = TimeSpan.FromSeconds(0.18),
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            });
    }

    private void StartCloseCountdown(int seconds)
    {
        _closeSecs = seconds;
        CountText.Text = $"Fenster schliesst in {_closeSecs} s";
        _closeTimer?.Stop();
        _closeTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _closeTimer.Tick += (_, _) =>
        {
            _closeSecs--;
            if (_closeSecs <= 0)
            {
                _closeTimer?.Stop();
                Application.Current?.Shutdown();
            }
            else CountText.Text = $"Fenster schliesst in {_closeSecs} s";
        };
        _closeTimer.Start();
    }
}
