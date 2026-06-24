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
    private readonly HashWhitelistStore? _whitelist;

    private TextBox[] _boxes = Array.Empty<TextBox>();
    private bool _pinLocked;
    private string _enteredPin = "";
    private string _game = "FiveM";
    private ScanProfile _selectedProfile = ScanProfile.Deep;
    private DispatcherTimer? _closeTimer;
    private int _closeSecs;

    public MainWindow(IndicatorStore indicators, ScanStore scans, SettingsStore settings, HashWhitelistStore? whitelist = null)
    {
        InitializeComponent();
        _indicators = indicators;
        _scans = scans;
        _settings = settings;
        _whitelist = whitelist;

        _boxes = new[] { P0, P1, P2, P3, P4, P5 };
        TryLoadEmbeddedPin();
        // IntroView is visible by default; GameView starts collapsed
    }

    // ===== Step navigation =====
    private void ShowStep(FrameworkElement step)
    {
        foreach (var s in new FrameworkElement[] { IntroView, GameView, PinView, ConsentView, ScanView, ResultView })
            s.Visibility = s == step ? Visibility.Visible : Visibility.Collapsed;
    }

    private void IntroVideo_MediaEnded(object sender, RoutedEventArgs e)
    {
        ShowStep(GameView);
    }

    // ===== Window chrome =====
    // The whole window is draggable: this bubbling handler only fires for clicks
    // on non-interactive areas (background, particle field, labels). Buttons and
    // text boxes mark the event handled, so their clicks keep working.
    private void Window_Drag(object sender, MouseButtonEventArgs e)
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

    private void ProfileComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is ComboBox cb && cb.SelectedItem is ComboBoxItem item && item.Tag is string tag)
        {
            _selectedProfile = tag switch
            {
                "Quick" => ScanProfile.Quick,
                "Deep"  => ScanProfile.Deep,
                _       => ScanProfile.Standard,
            };
        }
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
                var file = System.IO.Path.Combine(AppContext.BaseDirectory, "zerotrace.pin");
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
        NowPath.Text = $"Profil: {_selectedProfile} …";

        var options = ScanProfiles.FromProfile(_selectedProfile);
        options.Profile = _selectedProfile;
        var matcher = new IndicatorMatcher(_indicators.GetEnabled());
        using var cts = new CancellationTokenSource();

        // ---- Phase 1: full scan (profile-selected modules, targeted directories) ----
        // Progress bar: 0 % -> 60 %
        var phase1Progress = new Progress<ScanProgress>(p =>
        {
            p.Percent = Math.Clamp(p.Percent * 0.6, 0, 60);
            OnProgress(p);
        });

        ScanReport report;
        try
        {
            var engine1 = new ScanEngine(matcher, _whitelist);
            report = await Task.Run(() => engine1.RunAsync(options, phase1Progress, null, cts.Token));
        }
        catch (Exception ex)
        {
            NowPath.Text = "Fehler: " + ex.Message;
            return;
        }

        // ---- Phase 2: deep drive scan (DriveScanModule only, every fixed drive) ----
        // Progress bar: 60 % -> 100 %
        // Only DriveScanModule runs; all other modules were already covered in Phase 1.
        // ModuleTimeoutSeconds = 0 disables the per-module time cap so a large drive
        // can be fully scanned without being cut short.
        // Quick profile skips the deep drive scan entirely.
        // Skip Phase 2 if Quick (no deep drive scan wanted) or if Phase 1 already
        // did a full deep drive scan (Deep profile) — no need to scan drives twice.
        bool phase1DeepDrives = options.DeepDriveScan && options.ScanDrives;
        if (_selectedProfile == ScanProfile.Quick || phase1DeepDrives)
        {
            OnProgress(new ScanProgress { Phase = ScanPhase.Completed, Percent = 100, Message = "Scan abgeschlossen" });
            report.Pin = _enteredPin;
            try { _scans.Save(report); } catch { /* best effort */ }

            var urlQ = (_settings.Get("webhook_url") ?? "").Trim();
            if (!string.IsNullOrEmpty(urlQ))
            {
                try { await WebhookSender.SendAsync(urlQ, WebhookSender.BuildPayload(report)); }
                catch { /* best effort */ }
            }

            NowPath.Text = "Scan abgeschlossen – Ergebnis gesendet.";
            await Task.Delay(2000);
            Application.Current?.Shutdown();
            return;
        }

        var deepOptions = new ScanOptions
        {
            DeepDriveScan = true,
            ModuleTimeoutSeconds = 0,
            ScanDrives = true,
            ScanProcesses = false,
            ScanAutostart = false,
            ScanRegistry = false,
            ScanFiveM = false,
            ScanDownloads = false,
            ScanBrowserHistory = false,
            ScanSecurityTimeline = false,
            ScanPowerShell = false,
            ScanKernelDrivers = false,
            ScanExecutionHistory = false,
            ScanDmaRisk = false,
            ScanInventory = false,
            ScanRemnants = false,
            ScanTamper = false,
            ScanForensicTraces = false,
            ScanUsnJournal = false,
            ScanNetwork = false,
            ScanOverlay = false,
            ScanWmiPersistence = false,
            ScanScheduledTasks = false,
            ScanUsbDevices = false,
            ScanDllHijack = false,
            ScanBrowserExtensions = false,
            ScanRootCertificates = false,
            ScanVirtualMachine = false,
            ScanHiddenDrivers = false,
            ScanMemory = false,
            ScanCustomStrings = false,
            Profile = _selectedProfile,
        };

        var phase2Progress = new Progress<ScanProgress>(p =>
        {
            p.Percent = 60 + Math.Clamp(p.Percent * 0.4, 0, 40);
            OnProgress(p);
        });

        ScanReport deepReport;
        try
        {
            var engine2 = new ScanEngine(matcher, _whitelist);
            deepReport = await Task.Run(() => engine2.RunAsync(deepOptions, phase2Progress, null, cts.Token));
        }
        catch
        {
            deepReport = new ScanReport { Findings = new System.Collections.Generic.List<Finding>() };
        }

        // Merge deep-scan findings into the main report and re-sort by risk.
        report.Findings.AddRange(deepReport.Findings);
        report.Findings = report.Findings
            .OrderByDescending(f => f.Risk)
            .ToList();
        report.FilesScanned += deepReport.FilesScanned;
        report.FinishedUtc = DateTime.UtcNow;

        report.Pin = _enteredPin;
        try { _scans.Save(report); } catch { /* best effort */ }

        var url = (_settings.Get("webhook_url") ?? "").Trim();
        if (!string.IsNullOrEmpty(url))
        {
            try { await WebhookSender.SendAsync(url, WebhookSender.BuildPayload(report)); }
            catch { /* best effort */ }
        }

        NowPath.Text = "Scan abgeschlossen – Ergebnis gesendet.";
        await Task.Delay(2000);
        Application.Current?.Shutdown();
    }

    private void OnProgress(ScanProgress p)
    {
        BarScale.ScaleX = Math.Clamp(p.Percent / 100.0, 0, 1);
        PctText.Text = $"{p.Percent:0}%";
        NowPath.Text = string.IsNullOrWhiteSpace(p.Module) ? "…" : p.Module;
    }

    // ===== Result =====
    private void ShowResult(ScanReport report)
    {
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
