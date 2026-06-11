using ZeroTrace.App.Mvvm;
using ZeroTrace.Core.Data;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.App.ViewModels;

/// <summary>Overview page: system facts, indicator count, and the last scan summary.</summary>
public sealed class DashboardViewModel : ViewModelBase
{
    private readonly IndicatorStore _indicators;
    private readonly ScanStore _scans;

    public event Action? StartScanRequested;

    public string MachineName => SystemInfo.MachineName;
    public string UserName => SystemInfo.UserName;
    public string OsVersion => SystemInfo.OsVersion;
    public string Architecture => SystemInfo.Is64BitOs ? "64-bit" : "32-bit";
    public int ProcessorCount => SystemInfo.ProcessorCount;
    public string FiveMStatus => SystemInfo.MpFrameworksSummary;

    private int _indicatorCount;
    public int IndicatorCount { get => _indicatorCount; private set => SetProperty(ref _indicatorCount, value); }

    private string _lastScanText = "Noch kein Scan durchgefuehrt";
    public string LastScanText { get => _lastScanText; private set => SetProperty(ref _lastScanText, value); }

    private int _critical, _high, _medium, _low, _totalFindings;
    public int Critical { get => _critical; private set => SetProperty(ref _critical, value); }
    public int High { get => _high; private set => SetProperty(ref _high, value); }
    public int Medium { get => _medium; private set => SetProperty(ref _medium, value); }
    public int Low { get => _low; private set => SetProperty(ref _low, value); }
    public int TotalFindings { get => _totalFindings; private set => SetProperty(ref _totalFindings, value); }

    private bool _hasLastScan;
    public bool HasLastScan { get => _hasLastScan; private set => SetProperty(ref _hasLastScan, value); }

    public RelayCommand StartScanCommand { get; }

    public DashboardViewModel(IndicatorStore indicators, ScanStore scans)
    {
        _indicators = indicators;
        _scans = scans;
        StartScanCommand = new RelayCommand(() => StartScanRequested?.Invoke());
        Refresh();
    }

    public void Refresh()
    {
        IndicatorCount = _indicators.Count();

        var last = _scans.GetRecentScans(1).FirstOrDefault();
        if (last is null)
        {
            HasLastScan = false;
            LastScanText = "Noch kein Scan durchgefuehrt";
            Critical = High = Medium = Low = TotalFindings = 0;
            return;
        }

        var full = _scans.GetScan(last.Id);
        if (full is null) return;

        HasLastScan = true;
        LastScanText = $"{full.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm} - " +
                       $"{full.FilesScanned:N0} Dateien, {full.ProcessesScanned:N0} Prozesse, " +
                       $"Dauer {full.Duration:hh\\:mm\\:ss} ({full.Result})";
        Critical = full.CriticalCount;
        High = full.HighCount;
        Medium = full.MediumCount;
        Low = full.LowCount;
        TotalFindings = full.Findings.Count;
    }
}
