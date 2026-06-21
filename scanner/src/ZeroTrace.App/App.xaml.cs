using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using ZeroTrace.App.ViewModels;
using ZeroTrace.App.Views;
using ZeroTrace.Core.Data;

namespace ZeroTrace.App;

/// <summary>
/// Application entry point and composition root. Initialises the local database
/// (create, integrity-check, seed) before constructing the main window, and
/// installs global exception handlers so an unexpected error is logged and shown
/// clearly instead of crashing the app with a raw .NET dialog. No network access
/// occurs at startup.
/// </summary>
public partial class App : Application
{
    /// <summary>Crash/error log, written to the temp folder (always writable).</summary>
    private static readonly string LogPath =
        Path.Combine(Path.GetTempPath(), "ZeroTrace-error.log");

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Global safety net: never let an unhandled exception take the app down
        // with a raw .NET error. Log it and keep running where possible.
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

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
            Log("Startup", ex);
            MessageBox.Show(
                "ZeroTrace konnte nicht gestartet werden.\n\n" + ex.Message +
                "\n\nDetails wurden gespeichert in:\n" + LogPath,
                "Startfehler", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log("UI", e.Exception);
        MessageBox.Show(
            "Es ist ein unerwarteter Fehler aufgetreten - das Programm laeuft weiter.\n\n" +
            e.Exception.Message + "\n\nDetails: " + LogPath,
            "ZeroTrace", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true; // keep the app alive instead of crashing
    }

    private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex) Log("Domain", ex);
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        Log("Task", e.Exception);
        e.SetObserved(); // a background task fault must not crash the process
    }

    private static void Log(string source, Exception ex)
    {
        try
        {
            File.AppendAllText(LogPath,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {source}: {ex}{Environment.NewLine}{Environment.NewLine}");
        }
        catch { /* logging is best effort */ }
    }
}
