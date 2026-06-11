using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using ZeroTrace.App.Mvvm;
using ZeroTrace.Core.Data;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Reporting;
using ZeroTrace.Core.Util;
using Microsoft.Win32;

namespace ZeroTrace.App.ViewModels;

/// <summary>Browse past scans and export the selected one to HTML/JSON/text.</summary>
public sealed class ReportsViewModel : ViewModelBase
{
    private const string WebhookKey = "webhook_url";

    private readonly ScanStore _scans;
    private readonly SettingsStore _settings;

    public ObservableCollection<ScanReport> Scans { get; } = new();

    private ScanReport? _selectedScan;
    public ScanReport? SelectedScan
    {
        get => _selectedScan;
        set
        {
            if (SetProperty(ref _selectedScan, value)) LoadDetail();
        }
    }

    private ScanReport? _detail;
    public ScanReport? Detail
    {
        get => _detail;
        private set
        {
            if (SetProperty(ref _detail, value))
            {
                OnPropertyChanged(nameof(PayloadPreview));
                SendStatus = "";
            }
        }
    }

    // --- Transparent, consent-based sending ---
    private string _webhookUrl = "";
    public string WebhookUrl
    {
        get => _webhookUrl;
        set { if (SetProperty(ref _webhookUrl, value)) _settings.Set(WebhookKey, value ?? ""); }
    }

    private string _sendStatus = "";
    public string SendStatus { get => _sendStatus; private set => SetProperty(ref _sendStatus, value); }

    /// <summary>The exact JSON that a send would transmit - shown to the user beforehand.</summary>
    public string PayloadPreview => Detail is null ? "" : WebhookSender.BuildPayload(Detail);

    public RelayCommand ExportHtmlCommand { get; }
    public RelayCommand ExportJsonCommand { get; }
    public RelayCommand ExportTextCommand { get; }
    public RelayCommand DeleteCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public AsyncRelayCommand SendCommand { get; }

    public ReportsViewModel(ScanStore scans, SettingsStore settings)
    {
        _scans = scans;
        _settings = settings;
        _webhookUrl = settings.Get(WebhookKey) ?? "";
        ExportHtmlCommand = new RelayCommand(() => Export("html"), () => Detail is not null);
        ExportJsonCommand = new RelayCommand(() => Export("json"), () => Detail is not null);
        ExportTextCommand = new RelayCommand(() => Export("txt"), () => Detail is not null);
        DeleteCommand = new RelayCommand(DeleteSelected, () => SelectedScan is not null);
        RefreshCommand = new RelayCommand(Refresh);
        SendCommand = new AsyncRelayCommand(SendAsync, () => Detail is not null);
        Refresh();
    }

    private async Task SendAsync()
    {
        if (Detail is null) return;

        var url = (WebhookUrl ?? "").Trim();
        if (string.IsNullOrEmpty(url))
        {
            SendStatus = "Bitte zuerst eine Ziel-Adresse eingeben.";
            return;
        }

        // Explicit per-send confirmation that names the exact destination and
        // makes clear the full report (incl. paths, hashes, machine name) leaves
        // the computer. Nothing is sent without this Yes.
        var confirm = MessageBox.Show(
            "Der vollständige Bericht von Scan #" + Detail.Id + " wird an folgende Adresse gesendet:\n\n" +
            url + "\n\n" +
            "Übertragen werden u. a. Rechnername, Betriebssystem, Dateipfade, Hashes und alle Funde. " +
            "Die genaue Nutzlast ist im Feld darunter sichtbar.\n\n" +
            "Jetzt senden?",
            "Senden bestätigen", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
        {
            SendStatus = "Abgebrochen - es wurde nichts gesendet.";
            return;
        }

        SendStatus = "Sende an " + url + " …";
        var result = await WebhookSender.SendAsync(url, WebhookSender.BuildPayload(Detail));
        SendStatus = result.Message;
    }

    public void Refresh()
    {
        var current = SelectedScan?.Id;
        Scans.Clear();
        foreach (var s in _scans.GetRecentScans(100)) Scans.Add(s);
        if (current is not null)
            SelectedScan = Scans.FirstOrDefault(s => s.Id == current) ?? Scans.FirstOrDefault();
        else
            SelectedScan ??= Scans.FirstOrDefault();
    }

    private void LoadDetail()
    {
        Detail = SelectedScan is null ? null : _scans.GetScan(SelectedScan.Id);
    }

    private void DeleteSelected()
    {
        if (SelectedScan is null) return;
        var id = SelectedScan.Id;
        if (MessageBox.Show($"Scan #{id} wirklich loeschen?", "Bestaetigen",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        _scans.DeleteScan(id);
        Refresh();
    }

    private void Export(string format)
    {
        if (Detail is null) return;

        var dialog = new SaveFileDialog
        {
            InitialDirectory = KnownPaths.ReportsDir,
            FileName = $"ZeroTrace_Scan_{Detail.Id}_{Detail.StartedUtc.ToLocalTime():yyyyMMdd_HHmmss}.{format}",
            Filter = format switch
            {
                "html" => "HTML-Bericht (*.html)|*.html",
                "json" => "JSON (*.json)|*.json",
                _ => "Textdatei (*.txt)|*.txt"
            }
        };
        if (dialog.ShowDialog() != true) return;

        try
        {
            switch (format)
            {
                case "html": ReportExporter.ExportHtml(Detail, dialog.FileName); break;
                case "json": ReportExporter.ExportJson(Detail, dialog.FileName); break;
                default: ReportExporter.ExportText(Detail, dialog.FileName); break;
            }

            if (format == "html" &&
                MessageBox.Show("Bericht exportiert. Jetzt oeffnen?", "Fertig",
                    MessageBoxButton.YesNo, MessageBoxImage.Information) == MessageBoxResult.Yes)
            {
                Process.Start(new ProcessStartInfo(dialog.FileName) { UseShellExecute = true });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show("Export fehlgeschlagen: " + ex.Message, "Fehler",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
