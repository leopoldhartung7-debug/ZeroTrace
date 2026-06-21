using System;
using System.Windows.Threading;
using ZeroTrace.App.Mvvm;
using ZeroTrace.Core.Data;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Reporting;
using ZeroTrace.Core.Util;

namespace ZeroTrace.App.ViewModels;

/// <summary>
/// Root view model. Owns the child page view models, exposes the current page
/// for the content host, and coordinates cross-page refreshes (e.g. after a scan
/// finishes, the findings and reports pages reload).
/// </summary>
public sealed class MainViewModel : ViewModelBase
{
    private ViewModelBase _currentViewModel;
    private string _currentPage = "Dashboard";

    public DashboardViewModel Dashboard { get; }
    public LiveScanViewModel LiveScan { get; }
    public FindingsViewModel Findings { get; }
    public ReportsViewModel Reports { get; }
    public SettingsViewModel Settings { get; }

    public bool IsElevated { get; }
    public string ElevationText => IsElevated
        ? "Mit Administratorrechten gestartet"
        : "Ohne Administratorrechte - einige Bereiche (HKLM, fremde Prozesse) sind eingeschraenkt";

    public RelayCommand NavigateCommand { get; }
    public RelayCommand RemoveCommand { get; }

    public ViewModelBase CurrentViewModel
    {
        get => _currentViewModel;
        private set => SetProperty(ref _currentViewModel, value);
    }

    public string CurrentPage
    {
        get => _currentPage;
        private set => SetProperty(ref _currentPage, value);
    }

    public MainViewModel(
        SqliteDatabase db,
        IndicatorStore indicators,
        ScanStore scans,
        SettingsStore settings)
    {
        IsElevated = PrivilegeChecker.IsElevated();

        Dashboard = new DashboardViewModel(indicators, scans);
        LiveScan = new LiveScanViewModel(indicators, scans, settings);
        Findings = new FindingsViewModel(scans, settings);
        Reports = new ReportsViewModel(scans, settings);
        Settings = new SettingsViewModel(db, indicators, settings);

        // After a scan completes, refresh dependent pages in the background (the
        // results are already sent to the dashboard from LiveScanViewModel) and show
        // only a green check + "Scan abgeschlossen". The program then closes itself
        // after 5 seconds.
        LiveScan.ScanCompleted += report =>
        {
            Dashboard.Refresh();
            Reports.Refresh();
            Findings.Banner = LiveScan.LastSendStatus;
            Findings.LoadScan(report.Id);
            StartShutdown(5);
        };

        // Dashboard "start scan" shortcut.
        Dashboard.StartScanRequested += () =>
        {
            Navigate("LiveScan");
            LiveScan.StartScanCommand.Execute(null);
        };

        NavigateCommand = new RelayCommand(p => Navigate(p as string ?? "Dashboard"));
        RemoveCommand = new RelayCommand(() =>
        {
            // User-triggered, immediate cleanup, then exit.
            SelfUninstaller.RemoveEverything();
            System.Windows.Application.Current?.Shutdown();
        });
        _currentViewModel = Dashboard;
    }

    private DispatcherTimer? _shutdownTimer;

    /// <summary>
    /// Closes the application after the given number of seconds. Used after a scan
    /// finishes so the user only sees the completion screen briefly.
    /// </summary>
    private void StartShutdown(int seconds)
    {
        _shutdownTimer?.Stop();
        _shutdownTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(seconds) };
        _shutdownTimer.Tick += (_, _) =>
        {
            _shutdownTimer?.Stop();
            System.Windows.Application.Current?.Shutdown();
        };
        _shutdownTimer.Start();
    }

    private void Navigate(string page)
    {
        CurrentViewModel = page switch
        {
            "LiveScan" => LiveScan,
            "Findings" => Findings,
            "Reports" => Reports,
            "Settings" => Settings,
            _ => Dashboard
        };
        CurrentPage = page;

        if (page == "Findings") Findings.EnsureLoaded();
        if (page == "Reports") Reports.Refresh();
        if (page == "Dashboard") Dashboard.Refresh();
        if (page == "Settings") Settings.Reload();
    }
}
