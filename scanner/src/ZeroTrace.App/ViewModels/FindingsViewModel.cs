using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using ZeroTrace.App.Mvvm;
using ZeroTrace.Core.Data;
using ZeroTrace.Core.Models;

namespace ZeroTrace.App.ViewModels;

/// <summary>
/// Lists findings for a selected scan with text search and risk/module filters
/// via an ICollectionView. Defaults to the most recent scan.
/// </summary>
public sealed class FindingsViewModel : ViewModelBase
{
    private readonly ScanStore _scans;
    private readonly SettingsStore _settings;
    private bool _loadedOnce;

    public ObservableCollection<Finding> Findings { get; } = new();
    public ICollectionView FindingsView { get; }

    // --- Display depth controlled by the organizer (never below the yes/no minimum) ---
    private string _summaryText = "";
    public string SummaryText { get => _summaryText; private set => SetProperty(ref _summaryText, value); }

    private bool _summaryFound;
    public bool SummaryFound { get => _summaryFound; private set => SetProperty(ref _summaryFound, value); }

    private bool _showGrid = true;
    public bool ShowGrid { get => _showGrid; private set => SetProperty(ref _showGrid, value); }

    private bool _showDetail = true;
    public bool ShowDetail { get => _showDetail; private set => SetProperty(ref _showDetail, value); }

    public string[] RiskFilters { get; } = { "Alle", "Critical", "High", "Medium", "Low" };

    private string _selectedRisk = "Alle";
    public string SelectedRisk
    {
        get => _selectedRisk;
        set { if (SetProperty(ref _selectedRisk, value)) FindingsView.Refresh(); }
    }

    private string _searchText = "";
    public string SearchText
    {
        get => _searchText;
        set { if (SetProperty(ref _searchText, value)) FindingsView.Refresh(); }
    }

    private Finding? _selectedFinding;
    public Finding? SelectedFinding { get => _selectedFinding; set => SetProperty(ref _selectedFinding, value); }

    private string _headerText = "Funde";
    public string HeaderText { get => _headerText; private set => SetProperty(ref _headerText, value); }

    private string _banner = "";
    public string Banner { get => _banner; set => SetProperty(ref _banner, value); }

    // --- Auto-close countdown (closes the window only; never deletes anything) ---
    private DispatcherTimer? _closeTimer;
    private int _closeSecs;

    private bool _isClosing;
    public bool IsClosing { get => _isClosing; private set => SetProperty(ref _isClosing, value); }

    private string _closeText = "";
    public string CloseText { get => _closeText; private set => SetProperty(ref _closeText, value); }

    public RelayCommand KeepOpenCommand { get; }

    public void StartAutoClose(int seconds = 10)
    {
        StopAutoClose();
        _closeSecs = seconds;
        CloseText = $"Fenster schliesst in {_closeSecs} s";
        IsClosing = true;
        _closeTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _closeTimer.Tick += (_, _) =>
        {
            _closeSecs--;
            if (_closeSecs <= 0)
            {
                _closeTimer?.Stop();
                Application.Current?.Shutdown();
            }
            else CloseText = $"Fenster schliesst in {_closeSecs} s";
        };
        _closeTimer.Start();
    }

    public void StopAutoClose()
    {
        if (_closeTimer != null) { _closeTimer.Stop(); _closeTimer = null; }
        IsClosing = false;
    }

    public RelayCommand ClearFiltersCommand { get; }

    public FindingsViewModel(ScanStore scans, SettingsStore settings)
    {
        _scans = scans;
        _settings = settings;
        FindingsView = CollectionViewSource.GetDefaultView(Findings);
        FindingsView.Filter = FilterPredicate;
        ClearFiltersCommand = new RelayCommand(() =>
        {
            SearchText = "";
            SelectedRisk = "Alle";
        });
        KeepOpenCommand = new RelayCommand(StopAutoClose);
    }

    public void EnsureLoaded()
    {
        if (_loadedOnce) return;
        var last = _scans.GetRecentScans(1).FirstOrDefault();
        if (last is not null) LoadScan(last.Id);
        _loadedOnce = true;
    }

    public void LoadScan(long scanId)
    {
        Findings.Clear();
        var report = _scans.GetScan(scanId);
        if (report is null)
        {
            HeaderText = "Funde";
            return;
        }
        foreach (var f in report.Findings) Findings.Add(f);
        HeaderText = $"Funde - Scan #{scanId} ({report.StartedUtc.ToLocalTime():yyyy-MM-dd HH:mm}) - " +
                     $"{Findings.Count} Eintraege";

        // Guaranteed minimum the scanned person always sees.
        SummaryFound = Findings.Count > 0;
        SummaryText = SummaryFound
            ? $"Auffaelligkeiten gefunden: Ja ({Findings.Count})"
            : "Auffaelligkeiten gefunden: Nein";

        // Organizer-chosen depth, but never below the yes/no minimum above.
        var level = ReadLevel();
        ShowGrid = level >= DisplayLevel.Categories;
        ShowDetail = level == DisplayLevel.Full;
        if (!ShowDetail) SelectedFinding = null;

        _loadedOnce = true;
        FindingsView.Refresh();
    }

    private DisplayLevel ReadLevel()
    {
        var raw = _settings.Get("display_level");
        return Enum.TryParse<DisplayLevel>(raw, ignoreCase: true, out var lvl)
            ? lvl
            : DisplayLevel.YesNo;
    }

    private bool FilterPredicate(object obj)
    {
        if (obj is not Finding f) return false;

        if (_selectedRisk != "Alle" &&
            !f.Risk.ToString().Equals(_selectedRisk, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.IsNullOrWhiteSpace(_searchText))
        {
            var t = _searchText.Trim();
            bool match =
                f.Title.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                f.Reason.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                f.Location.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                f.Module.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                (f.FileName?.Contains(t, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (f.Sha256?.Contains(t, StringComparison.OrdinalIgnoreCase) ?? false);
            if (!match) return false;
        }

        return true;
    }
}
