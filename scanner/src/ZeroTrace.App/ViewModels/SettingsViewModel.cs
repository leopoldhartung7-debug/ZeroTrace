using System.Collections.ObjectModel;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using ZeroTrace.App.Mvvm;
using ZeroTrace.Core.Data;
using ZeroTrace.Core.Models;
using Microsoft.Win32;

namespace ZeroTrace.App.ViewModels;

/// <summary>
/// Edits scan options (persisted immediately) and manages the local indicator
/// database, including the transparent JSON import/update path.
/// </summary>
public sealed class SettingsViewModel : ViewModelBase
{
    private readonly SqliteDatabase _db;
    private readonly IndicatorStore _indicators;
    private readonly SettingsStore _settings;
    private readonly HashWhitelistStore? _whitelist;
    private ScanOptions _options;
    private bool _suppressSave;

    public string DatabasePath => _db.Path;

    public Array IndicatorTypes => Enum.GetValues(typeof(IndicatorType));
    public Array RiskLevels => Enum.GetValues(typeof(RiskLevel));

    // What the scanned person sees. The organizer picks the depth; the app
    // always shows at least the yes/no summary, so this can never hide everything.
    public Array DisplayLevels => Enum.GetValues(typeof(DisplayLevel));

    public Array ScanProfileValues => Enum.GetValues(typeof(ScanProfile));

    private ScanProfile _selectedProfile = ScanProfile.Deep;
    public ScanProfile SelectedProfile
    {
        get => _selectedProfile;
        set => SetProperty(ref _selectedProfile, value);
    }

    private DisplayLevel _displayLevel = DisplayLevel.YesNo;
    public DisplayLevel UserDisplayLevel
    {
        get => _displayLevel;
        set
        {
            if (SetProperty(ref _displayLevel, value) && !_suppressSave)
                _settings.Set("display_level", value.ToString());
        }
    }

    public ObservableCollection<Indicator> Indicators { get; } = new ObservableCollection<Indicator>();

    private Indicator? _selectedIndicator;
    public Indicator? SelectedIndicator { get => _selectedIndicator; set => SetProperty(ref _selectedIndicator, value); }

    // --- New-indicator form ---
    private IndicatorType _newType = IndicatorType.FileNameKeyword;
    public IndicatorType NewType { get => _newType; set => SetProperty(ref _newType, value); }

    private string _newPattern = "";
    public string NewPattern { get => _newPattern; set => SetProperty(ref _newPattern, value); }

    private RiskLevel _newRisk = RiskLevel.Medium;
    public RiskLevel NewRisk { get => _newRisk; set => SetProperty(ref _newRisk, value); }

    private string _newCategory = "General";
    public string NewCategory { get => _newCategory; set => SetProperty(ref _newCategory, value); }

    private string _newDescription = "";
    public string NewDescription { get => _newDescription; set => SetProperty(ref _newDescription, value); }

    private string _statusText = "";
    public string StatusText { get => _statusText; private set => SetProperty(ref _statusText, value); }

    // --- Scan option properties (auto-persisted) ---
    public bool ScanDrives { get => _options.ScanDrives; set { _options.ScanDrives = value; OnOptionChanged(); } }
    public bool ScanProcesses { get => _options.ScanProcesses; set { _options.ScanProcesses = value; OnOptionChanged(); } }
    public bool ScanAutostart { get => _options.ScanAutostart; set { _options.ScanAutostart = value; OnOptionChanged(); } }
    public bool ScanFiveM { get => _options.ScanFiveM; set { _options.ScanFiveM = value; OnOptionChanged(); } }
    public bool ScanRegistry { get => _options.ScanRegistry; set { _options.ScanRegistry = value; OnOptionChanged(); } }
    public bool ScanDownloads { get => _options.ScanDownloads; set { _options.ScanDownloads = value; OnOptionChanged(); } }
    public bool ScanBrowserHistory { get => _options.ScanBrowserHistory; set { _options.ScanBrowserHistory = value; OnOptionChanged(); } }
    public bool ScanSecurityTimeline { get => _options.ScanSecurityTimeline; set { _options.ScanSecurityTimeline = value; OnOptionChanged(); } }
    public bool ScanPowerShell { get => _options.ScanPowerShell; set { _options.ScanPowerShell = value; OnOptionChanged(); } }
    public bool ScanKernelDrivers { get => _options.ScanKernelDrivers; set { _options.ScanKernelDrivers = value; OnOptionChanged(); } }
    public bool ScanExecutionHistory { get => _options.ScanExecutionHistory; set { _options.ScanExecutionHistory = value; OnOptionChanged(); } }
    public bool ScanDmaRisk { get => _options.ScanDmaRisk; set { _options.ScanDmaRisk = value; OnOptionChanged(); } }
    public bool ScanInventory { get => _options.ScanInventory; set { _options.ScanInventory = value; OnOptionChanged(); } }
    public bool ScanRemnants { get => _options.ScanRemnants; set { _options.ScanRemnants = value; OnOptionChanged(); } }
    public bool ScanTamper { get => _options.ScanTamper; set { _options.ScanTamper = value; OnOptionChanged(); } }
    public bool ScanForensicTraces { get => _options.ScanForensicTraces; set { _options.ScanForensicTraces = value; OnOptionChanged(); } }
    public bool ScanUsnJournal { get => _options.ScanUsnJournal; set { _options.ScanUsnJournal = value; OnOptionChanged(); } }
    public bool ScanNetwork { get => _options.ScanNetwork; set { _options.ScanNetwork = value; OnOptionChanged(); } }
    public bool ScanOverlay { get => _options.ScanOverlay; set { _options.ScanOverlay = value; OnOptionChanged(); } }
    public bool ScanWmiPersistence { get => _options.ScanWmiPersistence; set { _options.ScanWmiPersistence = value; OnOptionChanged(); } }
    public bool ScanMemory { get => _options.ScanMemory; set { _options.ScanMemory = value; OnOptionChanged(); } }
    public bool DeepDriveScan { get => _options.DeepDriveScan; set { _options.DeepDriveScan = value; OnOptionChanged(); } }

    public int MaxDepth
    {
        get => _options.MaxDepth;
        set { _options.MaxDepth = Math.Clamp(value, 1, 64); OnOptionChanged(); OnPropertyChanged(); }
    }

    public string DrivesText
    {
        get => string.Join(", ", _options.Drives);
        set
        {
            _options.Drives = (value ?? "")
                .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim()).ToList();
            OnOptionChanged();
        }
    }

    public string ExtensionsText
    {
        get => string.Join(", ", _options.RelevantExtensions);
        set
        {
            _options.RelevantExtensions = (value ?? "")
                .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim().StartsWith('.') ? s.Trim().ToLowerInvariant() : "." + s.Trim().ToLowerInvariant())
                .Distinct().ToList();
            OnOptionChanged();
        }
    }

    // --- Hash Whitelist ---
    public ObservableCollection<WhitelistEntry> WhitelistEntries { get; } = new ObservableCollection<WhitelistEntry>();

    private WhitelistEntry? _selectedWhitelistEntry;
    public WhitelistEntry? SelectedWhitelistEntry
    {
        get => _selectedWhitelistEntry;
        set => SetProperty(ref _selectedWhitelistEntry, value);
    }

    private string _newWhitelistHash = "";
    public string NewWhitelistHash
    {
        get => _newWhitelistHash;
        set => SetProperty(ref _newWhitelistHash, value);
    }

    private string _newWhitelistNote = "";
    public string NewWhitelistNote
    {
        get => _newWhitelistNote;
        set => SetProperty(ref _newWhitelistNote, value);
    }

    private string _whitelistStatus = "";
    public string WhitelistStatus
    {
        get => _whitelistStatus;
        private set => SetProperty(ref _whitelistStatus, value);
    }

    public RelayCommand AddIndicatorCommand { get; }
    public RelayCommand DeleteIndicatorCommand { get; }
    public RelayCommand SaveAllCommand { get; }
    public RelayCommand ImportCommand { get; }
    public RelayCommand ExportCommand { get; }
    public RelayCommand ApplyProfileCommand { get; }
    public RelayCommand AddWhitelistCommand { get; }
    public RelayCommand DeleteWhitelistCommand { get; }
    public RelayCommand ImportWhitelistCommand { get; }

    public SettingsViewModel(SqliteDatabase db, IndicatorStore indicators, SettingsStore settings, HashWhitelistStore? whitelist = null)
    {
        _db = db;
        _indicators = indicators;
        _settings = settings;
        _whitelist = whitelist;
        _options = settings.LoadOptions();
        if (Enum.TryParse<DisplayLevel>(settings.Get("display_level"), ignoreCase: true, out var lvl))
            _displayLevel = lvl;

        AddIndicatorCommand = new RelayCommand(AddIndicator);
        DeleteIndicatorCommand = new RelayCommand(DeleteIndicator, () => SelectedIndicator is not null);
        SaveAllCommand = new RelayCommand(SaveAll);
        ImportCommand = new RelayCommand(Import);
        ExportCommand = new RelayCommand(Export);
        ApplyProfileCommand = new RelayCommand(ApplyProfile);
        AddWhitelistCommand = new RelayCommand(AddWhitelist, () => _whitelist is not null && !string.IsNullOrWhiteSpace(NewWhitelistHash));
        DeleteWhitelistCommand = new RelayCommand(DeleteWhitelist, () => _whitelist is not null && SelectedWhitelistEntry is not null);
        ImportWhitelistCommand = new RelayCommand(ImportWhitelist, () => _whitelist is not null);

        Reload();
    }

    public void Reload()
    {
        _suppressSave = true;
        _options = _settings.LoadOptions();
        _selectedProfile = _options.Profile;
        OnPropertyChanged(nameof(SelectedProfile));
        // Refresh all option-bound properties.
        foreach (var name in new[]
                 {
                     nameof(ScanDrives), nameof(ScanProcesses), nameof(ScanAutostart),
                     nameof(ScanFiveM), nameof(ScanRegistry), nameof(ScanDownloads),
                     nameof(ScanBrowserHistory), nameof(ScanSecurityTimeline), nameof(ScanPowerShell), nameof(ScanKernelDrivers), nameof(ScanExecutionHistory), nameof(ScanDmaRisk), nameof(ScanInventory), nameof(ScanRemnants), nameof(ScanTamper), nameof(ScanForensicTraces), nameof(ScanUsnJournal), nameof(ScanNetwork), nameof(ScanOverlay), nameof(ScanWmiPersistence), nameof(ScanMemory),
                     nameof(DeepDriveScan), nameof(MaxDepth), nameof(DrivesText), nameof(ExtensionsText)
                 })
            OnPropertyChanged(name);
        _suppressSave = false;

        Indicators.Clear();
        foreach (var ind in _indicators.GetAll()) Indicators.Add(ind);

        WhitelistEntries.Clear();
        if (_whitelist is not null)
            foreach (var e in _whitelist.GetAll()) WhitelistEntries.Add(e);

        StatusText = $"{Indicators.Count} Indikatoren geladen.";
    }

    private void OnOptionChanged()
    {
        if (_suppressSave) return;
        _settings.SaveOptions(_options);
    }

    private void AddIndicator()
    {
        if (string.IsNullOrWhiteSpace(NewPattern))
        {
            StatusText = "Bitte ein Muster angeben.";
            return;
        }
        var ind = new Indicator
        {
            Type = NewType,
            Pattern = NewPattern.Trim(),
            Risk = NewRisk,
            Category = string.IsNullOrWhiteSpace(NewCategory) ? "General" : NewCategory.Trim(),
            Description = NewDescription.Trim(),
            Source = "manual",
            Enabled = true,
            CreatedUtc = DateTime.UtcNow
        };
        ind.Id = _indicators.Add(ind);
        Indicators.Add(ind);
        NewPattern = "";
        NewDescription = "";
        StatusText = $"Indikator hinzugefuegt (#{ind.Id}).";
    }

    private void DeleteIndicator()
    {
        if (SelectedIndicator is null) return;
        var id = SelectedIndicator.Id;
        _indicators.Delete(id);
        Indicators.Remove(SelectedIndicator);
        StatusText = $"Indikator #{id} geloescht.";
    }

    private void SaveAll()
    {
        foreach (var ind in Indicators) _indicators.Update(ind);
        StatusText = $"{Indicators.Count} Indikatoren gespeichert.";
    }

    private void Import()
    {
        var dialog = new OpenFileDialog
        {
            Filter = "JSON (*.json)|*.json|Alle Dateien (*.*)|*.*",
            Title = "Indikatoren importieren"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            var source = "import:" + Path.GetFileNameWithoutExtension(dialog.FileName);
            var count = _indicators.ImportFromJson(dialog.FileName, source);
            Reload();
            StatusText = $"{count} Indikatoren importiert (Quelle: {source}).";
        }
        catch (Exception ex)
        {
            StatusText = "Import fehlgeschlagen: " + ex.Message;
            MessageBox.Show(StatusText, "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Export()
    {
        var dialog = new SaveFileDialog
        {
            Filter = "JSON (*.json)|*.json",
            FileName = "fivemguard_indicators.json",
            Title = "Indikatoren exportieren"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            _indicators.ExportToJson(dialog.FileName);
            StatusText = "Indikatoren exportiert: " + dialog.FileName;
        }
        catch (Exception ex)
        {
            StatusText = "Export fehlgeschlagen: " + ex.Message;
        }
    }

    private void ApplyProfile()
    {
        _suppressSave = true;
        var preset = ScanProfiles.FromProfile(SelectedProfile);
        _options = preset;
        // Notify every option-bound property so the checkboxes update immediately.
        foreach (var name in new[]
                 {
                     nameof(ScanDrives), nameof(ScanProcesses), nameof(ScanAutostart),
                     nameof(ScanFiveM), nameof(ScanRegistry), nameof(ScanDownloads),
                     nameof(ScanBrowserHistory), nameof(ScanSecurityTimeline), nameof(ScanPowerShell),
                     nameof(ScanKernelDrivers), nameof(ScanExecutionHistory), nameof(ScanDmaRisk),
                     nameof(ScanInventory), nameof(ScanRemnants), nameof(ScanTamper),
                     nameof(ScanForensicTraces), nameof(ScanUsnJournal), nameof(ScanNetwork),
                     nameof(ScanOverlay), nameof(ScanWmiPersistence), nameof(ScanMemory),
                     nameof(DeepDriveScan), nameof(MaxDepth), nameof(DrivesText), nameof(ExtensionsText)
                 })
            OnPropertyChanged(name);
        _suppressSave = false;
        _settings.SaveOptions(_options);
        StatusText = $"Profil '{SelectedProfile}' angewendet.";
    }

    // ===== Hash Whitelist methods =====

    private static readonly Regex Sha256Regex = new Regex(@"^[0-9a-fA-F]{64}$", RegexOptions.Compiled);

    private void AddWhitelist()
    {
        if (_whitelist is null) return;
        var hash = NewWhitelistHash.Trim();
        if (!Sha256Regex.IsMatch(hash))
        {
            WhitelistStatus = "Ungueltig: bitte einen 64-stelligen SHA-256-Hash eingeben.";
            return;
        }
        try
        {
            var entry = _whitelist.Add(hash, NewWhitelistNote.Trim());
            WhitelistEntries.Insert(0, entry);
            NewWhitelistHash = "";
            NewWhitelistNote = "";
            WhitelistStatus = $"Hash hinzugefuegt (#{entry.Id}).";
        }
        catch (Exception ex)
        {
            WhitelistStatus = "Fehler: " + ex.Message;
        }
    }

    private void DeleteWhitelist()
    {
        if (_whitelist is null || SelectedWhitelistEntry is null) return;
        var entry = SelectedWhitelistEntry;
        try
        {
            _whitelist.Remove(entry.Id);
            WhitelistEntries.Remove(entry);
            WhitelistStatus = $"Hash #{entry.Id} entfernt.";
        }
        catch (Exception ex)
        {
            WhitelistStatus = "Fehler beim Loeschen: " + ex.Message;
        }
    }

    private void ImportWhitelist()
    {
        if (_whitelist is null) return;
        var dialog = new OpenFileDialog
        {
            Filter = "Textdatei (*.txt)|*.txt|Alle Dateien (*.*)|*.*",
            Title = "SHA-256-Hashes importieren (eine Zeile = ein Hash)"
        };
        if (dialog.ShowDialog() != true) return;
        try
        {
            var lines = File.ReadAllLines(dialog.FileName);
            int added = 0;
            int skipped = 0;
            foreach (var line in lines)
            {
                var hash = line.Trim();
                if (string.IsNullOrEmpty(hash) || hash.StartsWith('#')) continue;
                if (!Sha256Regex.IsMatch(hash)) { skipped++; continue; }
                try
                {
                    _whitelist.Add(hash);
                    added++;
                }
                catch
                {
                    // Duplicate or other constraint violation — skip silently.
                    skipped++;
                }
            }
            // Refresh the displayed list.
            WhitelistEntries.Clear();
            foreach (var e in _whitelist.GetAll()) WhitelistEntries.Add(e);
            WhitelistStatus = $"{added} Hash(es) importiert, {skipped} uebersprungen.";
        }
        catch (Exception ex)
        {
            WhitelistStatus = "Import fehlgeschlagen: " + ex.Message;
        }
    }
}
