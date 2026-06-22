using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Threading;
using ZeroTrace.App.Mvvm;
using ZeroTrace.Core.Data;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Reporting;

namespace ZeroTrace.App.ViewModels;

/// <summary>
/// Drives a live scan: builds the matcher, runs the engine, marshals progress
/// and streamed findings to the UI thread, persists the report, and raises
/// <see cref="ScanCompleted"/> so the rest of the app can refresh.
/// </summary>
public sealed class LiveScanViewModel : ViewModelBase
{
    private readonly IndicatorStore _indicators;
    private readonly ScanStore _scans;
    private readonly SettingsStore _settings;
    private readonly HashWhitelistStore? _whitelist;
    private readonly Dispatcher _dispatcher;

    private CancellationTokenSource? _cts;

    public event Action<ScanReport>? ScanCompleted;

    public ObservableCollection<Finding> LiveFindings { get; } = new();

    private double _progress;
    public double Progress { get => _progress; private set => SetProperty(ref _progress, value); }

    private string _phase = "Bereit";
    public string Phase { get => _phase; private set => SetProperty(ref _phase, value); }

    private string _currentModule = "";
    public string CurrentModule { get => _currentModule; private set => SetProperty(ref _currentModule, value); }

    private string _currentItem = "";
    public string CurrentItem { get => _currentItem; private set => SetProperty(ref _currentItem, value); }

    private long _filesScanned, _processesScanned, _registryKeysScanned;
    public long FilesScanned { get => _filesScanned; private set => SetProperty(ref _filesScanned, value); }
    public long ProcessesScanned { get => _processesScanned; private set => SetProperty(ref _processesScanned, value); }
    public long RegistryKeysScanned { get => _registryKeysScanned; private set => SetProperty(ref _registryKeysScanned, value); }

    private int _findingsCount;
    public int FindingsCount { get => _findingsCount; private set => SetProperty(ref _findingsCount, value); }

    private bool _isScanning;
    public bool IsScanning { get => _isScanning; private set => SetProperty(ref _isScanning, value); }

    private bool _isCompleted;
    public bool IsCompleted { get => _isCompleted; private set => SetProperty(ref _isCompleted, value); }

    private string _lastSendStatus = "";
    public string LastSendStatus { get => _lastSendStatus; private set => SetProperty(ref _lastSendStatus, value); }

    public AsyncRelayCommand StartScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }

    public LiveScanViewModel(IndicatorStore indicators, ScanStore scans, SettingsStore settings, HashWhitelistStore? whitelist = null)
    {
        _indicators = indicators;
        _scans = scans;
        _settings = settings;
        _whitelist = whitelist;
        _dispatcher = Application.Current?.Dispatcher ?? Dispatcher.CurrentDispatcher;

        StartScanCommand = new AsyncRelayCommand(RunScanAsync, () => !IsScanning);
        CancelScanCommand = new RelayCommand(() => _cts?.Cancel(), () => IsScanning);
    }

    private async Task RunScanAsync()
    {
        if (IsScanning) return;

        // Informed consent BEFORE anything is read. A scrollable license/privacy
        // window must be accepted; the scan does not start otherwise. Results are
        // shown afterwards on the "Funde" page and nothing is transmitted unless
        // the user later triggers a send themselves (with a visible preview).
        var dialog = new Views.ConsentWindow
        {
            Owner = System.Windows.Application.Current?.MainWindow
        };
        if (dialog.ShowDialog() != true)
        {
            Phase = "Abgebrochen - keine Einwilligung";
            return;
        }
        var enteredPin = dialog.EnteredPin;

        IsScanning = true;
        IsCompleted = false;
        LiveFindings.Clear();
        FindingsCount = 0;
        FilesScanned = ProcessesScanned = RegistryKeysScanned = 0;
        Progress = 0;
        Phase = "Initialisierung";

        _cts = new CancellationTokenSource();

        var options = _settings.LoadOptions();
        var matcher = new IndicatorMatcher(_indicators.GetEnabled());
        var engine = new ScanEngine(matcher, _whitelist);

        // Created on the UI thread => Report callbacks marshal back automatically.
        var progress = new Progress<ScanProgress>(OnProgress);

        // Findings arrive on a background thread; marshal explicitly.
        void OnFinding(Finding f) =>
            _dispatcher.BeginInvoke(() =>
            {
                LiveFindings.Insert(0, f);
                FindingsCount = LiveFindings.Count;
            });

        ScanReport report;
        try
        {
            report = await Task.Run(() =>
                engine.RunAsync(options, progress, OnFinding, _cts.Token));
        }
        catch (Exception ex)
        {
            Phase = "Fehler: " + ex.Message;
            IsScanning = false;
            return;
        }

        // The scan is associated with the PIN entered/embedded at consent time.
        report.Pin = enteredPin;

        // Persist completed/cancelled scans (cancelled scans still hold partial data).
        try
        {
            _scans.Save(report);
        }
        catch (Exception ex)
        {
            Phase = $"{report.Result} - Speichern fehlgeschlagen: {ex.Message}";
            IsScanning = false;
            return;
        }

        Phase = report.Result switch
        {
            ScanPhase.Completed => "Abgeschlossen",
            ScanPhase.Cancelled => "Abgebrochen",
            ScanPhase.Failed => "Fehlgeschlagen",
            _ => report.Result.ToString()
        };
        Progress = 100;
        IsScanning = false;
        IsCompleted = report.Result == ScanPhase.Completed;

        // Auto-send to the configured destination (disclosed and consented to in the
        // license/consent window). If no destination is set, nothing is sent. The
        // result is surfaced to the user via LastSendStatus and shown on the Funde
        // page, so the person always knows whether a transmission happened.
        LastSendStatus = "";
        if (IsCompleted)
        {
            var url = (_settings.Get("webhook_url") ?? "").Trim();
            if (!string.IsNullOrEmpty(url))
            {
                var res = await WebhookSender.SendAsync(url, WebhookSender.BuildPayload(report));
                LastSendStatus = res.Ok
                    ? $"Ergebnisse gesendet (PIN {report.Pin})"
                    : "Senden fehlgeschlagen: " + res.Message;
            }
        }

        ScanCompleted?.Invoke(report);
    }

    private void OnProgress(ScanProgress p)
    {
        Progress = p.Percent;
        CurrentModule = p.Module;
        CurrentItem = p.CurrentItem;
        FilesScanned = p.FilesScanned;
        ProcessesScanned = p.ProcessesScanned;
        RegistryKeysScanned = p.RegistryKeysScanned;
        if (p.FindingsCount > 0) FindingsCount = p.FindingsCount;
        Phase = p.Phase switch
        {
            ScanPhase.Initializing => "Initialisierung",
            ScanPhase.Running => "Laeuft",
            ScanPhase.Finalizing => "Abschluss",
            ScanPhase.Completed => "Abgeschlossen",
            ScanPhase.Cancelled => "Abgebrochen",
            ScanPhase.Failed => "Fehlgeschlagen",
            _ => Phase
        };
    }
}
