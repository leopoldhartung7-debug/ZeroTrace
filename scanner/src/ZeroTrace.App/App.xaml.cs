using System.Windows;
using ZeroTrace.App.ViewModels;
using ZeroTrace.App.Views;
using ZeroTrace.Core.Data;

namespace ZeroTrace.App;

/// <summary>
/// Application entry point and composition root. Initialises the local database
/// (create, integrity-check, seed) before constructing the main window. No
/// network access occurs at startup.
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        try
        {
            var db = new SqliteDatabase();
            db.EnsureCreated();

            if (!db.VerifyIntegrity())
            {
                MessageBox.Show(
                    "Die lokale Datenbank hat die Integritaetspruefung nicht bestanden. " +
                    "Sie wird neu erstellt.\n\nPfad: " + db.Path,
                    "ZeroTrace", MessageBoxButton.OK, MessageBoxImage.Warning);

                try { File.Delete(db.Path); } catch { /* best effort */ }
                db = new SqliteDatabase();
                db.EnsureCreated();
            }

            db.SeedDefaultsIfEmpty();

            var indicators = new IndicatorStore(db);
            var scans = new ScanStore(db);
            var settings = new SettingsStore(db);

            var main = new MainViewModel(db, indicators, scans, settings);
            var window = new MainWindow { DataContext = main };
            MainWindow = window;
            window.Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "ZeroTrace konnte nicht gestartet werden:\n\n" + ex,
                "Startfehler", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }
}
