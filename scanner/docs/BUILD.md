# Build-Anleitung

ZeroTrace ist eine **Windows-Anwendung** (WPF, `net8.0-windows`). Bauen und Ausführen ist
**nur unter Windows** möglich.

## Voraussetzungen

- **Windows 10 (1809+) oder Windows 11**
- **.NET 8 SDK** – https://dotnet.microsoft.com/download/dotnet/8.0
  (Prüfen mit `dotnet --version`, erwartet `8.x`)
- Optional: **Visual Studio 2022** (17.8+) mit Workload „.NET-Desktopentwicklung",
  oder **JetBrains Rider**

Es werden zwei NuGet-Pakete verwendet (werden beim Build automatisch geladen):
`Microsoft.Data.Sqlite` 8.0.6 und `System.Management` 8.0.0.

## Variante A – Kommandozeile

```powershell
# Im Wurzelverzeichnis der Solution (dort liegt ZeroTrace.sln)
dotnet restore
dotnet build -c Release

# Starten
dotnet run --project src/ZeroTrace.App -c Release
```

> Hinweis: Beim Start über `dotnet run` greift das eingebettete Manifest
> (`requireAdministrator`). Wird ohne erhöhte Rechte gestartet, fordert Windows per UAC die
> Erhöhung an. Startet die UAC nicht, eine **Administrator-PowerShell** verwenden.

## Variante B – Visual Studio

1. `ZeroTrace.sln` öffnen.
2. Als Startprojekt **ZeroTrace.App** festlegen.
3. Konfiguration **Release** (oder Debug) wählen, **F5** zum Starten.

## Veröffentlichen (alles als EINE Datei)

Eine einzige, eigenständige `ZeroTrace.exe` (enthält .NET-Runtime + alle DLLs,
kein separates SDK nötig):

```powershell
dotnet publish src/ZeroTrace.App -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:IncludeNativeLibrariesForSelfExtract=true ^
  -p:EnableCompressionInSingleFile=true -o publish
```

Oder einfach das beiliegende Skript im Wurzelverzeichnis ausführen:

```powershell
.\build-singlefile.cmd
```

Ergebnis: `publish\ZeroTrace.exe` – eine einzelne Datei, die per Doppelklick läuft.
Für eine kleinere Datei mit bereits installierter .NET-8-Runtime stattdessen
`--self-contained false` verwenden.

## Hinweise

- Beim ersten Lauf wird `%LocalAppData%\ZeroTrace\zerotrace.db` erstellt und mit den
  eingebauten Heuristik-Indikatoren befüllt.
- Bauen auf macOS/Linux schlägt fehl (`net8.0-windows`/WPF sind Windows-spezifisch).
