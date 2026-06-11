# Architektur

## Überblick

Zwei Projekte, klare Trennung von Logik und Oberfläche:

```
ZeroTrace.sln
├── src/ZeroTrace.Core   (Klassenbibliothek - gesamte Logik, keine UI-Abhängigkeit)
└── src/ZeroTrace.App    (WPF-Anwendung - MVVM, Dark Theme)
```

Beide zielen auf `net8.0-windows`. `Core` kapselt Scannen, Daten und Reporting; `App`
enthält nur Oberfläche und Bindung.

## Core – Schichten

```
Models/      Datenmodelle: RiskLevel, IndicatorType, Recommendation, ScanPhase,
             Indicator, Finding, ScanOptions, ScanProgress, ScanReport
Detection/   HashUtil (SHA-256), SignatureChecker (Authenticode-Heuristik),
             IndicatorMatcher (DB-Indikatoren), Heuristics (signaturfreie Regeln)
Data/        SqliteDatabase (Schema, Integrität, Seed), IndicatorStore, ScanStore,
             SettingsStore
Engine/      IScanModule + ScanContext, ScanEngine (Orchestrierung), RiskScorer
Modules/     ProcessScanModule, AutostartScanModule, RegistryScanModule,
             FiveMScanModule, DownloadsScanModule, DriveScanModule, FileInspector
Reporting/   ReportExporter (HTML/JSON/TXT), WebhookSender (optionaler, bestaetigungs-
             pflichtiger POST des Berichts an eine benutzerdefinierte Adresse)
Util/        PrivilegeChecker, KnownPaths, SystemInfo
```

## Datenfluss eines Scans

1. **App** lädt `ScanOptions` (SettingsStore) und aktive `Indicator`s (IndicatorStore),
   baut daraus einen `IndicatorMatcher` und einen `ScanEngine`.
2. `ScanEngine.RunAsync` wird in einem Hintergrund-Task ausgeführt. Es stellt aus den
   Optionen die aktiven `IScanModule`s zusammen und führt sie **sequenziell** aus.
3. Jedes Modul erhält einen `ScanContext`:
   - liest `Options` und `Matcher`,
   - meldet Fortschritt über `Report(...)` (gewichtet pro Modul),
   - fügt Funde über `AddFinding(...)` hinzu (setzt automatisch Empfehlung via `RiskScorer`).
4. Fortschritt geht über `IProgress<ScanProgress>` an die UI (Marshalling automatisch, da
   `Progress<T>` auf dem UI-Thread erzeugt wird). Funde werden zusätzlich live über einen
   Callback gestreamt (explizit per `Dispatcher` auf den UI-Thread gebracht).
5. Nach Abschluss baut die Engine einen `ScanReport`; die App persistiert ihn über
   `ScanStore.Save` (eine Transaktion: Scan + alle Funde) und aktualisiert die Seiten.

## Erkennungslogik

- **Heuristiken** (`Heuristics`, `FileInspector`, modul-spezifische Regeln) – signaturfrei,
  bewusst niedrig/mittel gewichtet, immer mit Begründung.
- **Indikatoren** (`IndicatorMatcher`) – aus der lokalen DB: Hash, exakter Dateiname,
  Datei-/Pfad-Schlüsselwort, Prozessname, Registry-Wert-Schlüsselwort.

`FileInspector` vereint beides für dateibasierte Module: Name-/Pfad-/Hash-Treffer plus die
Heuristik „unsigniert in beschreibbarem Pfad". Der stärkste Treffer gewinnt
(Hash > Name > Schlüsselwort > Pfad).

`RiskScorer.Recommend` leitet die Empfehlung transparent ab: Critical→Entfernen,
High→Entfernen (signiert: Prüfen), Medium→Prüfen, Low→Ignorieren (unsigniert: Prüfen).

## Verwendete Windows-APIs (alle dokumentiert)

| Bereich           | API                                                            |
|-------------------|---------------------------------------------------------------|
| Prozesse, Dienste | WMI `Win32_Process`, `Win32_Service` (`System.Management`)     |
| Registry          | `Microsoft.Win32.Registry` (+ 32/64-bit-Views)                |
| Geplante Aufgaben | COM `Schedule.Service` (spätgebunden, kein NuGet)             |
| Verknüpfungen     | COM `WScript.Shell` (`.lnk`-Auflösung)                        |
| Signatur          | `X509Certificate.CreateFromSignedFile` (Authenticode-Präsenz) |
| Rechte            | `WindowsIdentity` / `WindowsPrincipal`                         |

> Es werden **keine** undokumentierten Kernel-APIs, kein Anti-Debug und keine
> Rootkit-Techniken verwendet. Die Signaturprüfung ist eine Präsenz-/Identitätsprüfung,
> keine vollständige Vertrauenskettenvalidierung (kein WinVerifyTrust) – bewusst als
> Heuristik gekennzeichnet.

## MVVM (App)

- `Mvvm/ViewModelBase` (INotifyPropertyChanged), `RelayCommand` / `AsyncRelayCommand`.
- `ViewModels/` je Seite; `MainViewModel` ist Composition Root und Navigation.
- `Views/` sind UserControls, per `DataTemplate` (Window-Ressourcen) an die VMs gebunden.
- `Themes/DarkTheme.xaml` enthält Palette und Control-Styles; `Converters/` die
  Wertkonverter (Risiko→Pinsel, Bool/Null→Sichtbarkeit usw.).

## Entwurfsentscheidungen

- **Sequenzielle Module:** vorhersagbare IO-Last und sinnvoller Fortschrittsbalken.
- **Rohes SQL statt ORM:** das Schema ist Teil der Lieferung und bleibt schlank.
- **Opt-in-Versand statt heimlicher Übertragung:** „Updates" sind lokale JSON-Importe →
  auditierbar, kein Köder. Die einzige ausgehende Verbindung ist `WebhookSender` und läuft
  nur nach ausdrücklicher Pro-Sendung-Bestätigung (Ziel-Adresse + vollständige Nutzlast
  vorab sichtbar). Es gibt keinen automatischen oder versteckten Datenabfluss.
- **Defensive Enumeration:** Zugriffsfehler/Reparse-Points werden je Verzeichnis
  abgefangen; ein gesperrter Pfad bricht nie den gesamten Scan ab.
