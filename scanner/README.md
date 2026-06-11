# ZeroTrace

**ZeroTrace** ist ein lokales Windows-Analysewerkzeug (Host-Scanner), das einen PC auf
Hinweise für Cheats, Manipulationen und verdächtige Software untersucht und einen
nachvollziehbaren Bericht erstellt.

> **Wichtig:** ZeroTrace ist ein **Analyse- und Hinweis**-Werkzeug. Funde sind *Indizien*,
> kein Beweis für Cheating. Es gibt keine Garantie, dass alle Cheats erkannt werden, und
> False Positives sind möglich. Jede Maßnahme liegt in der Verantwortung des Betreibers.

## Was es tut

- **Prozesse** – laufende Prozesse (über WMI), Eltern-Kind-Beziehungen, unsignierte Images aus Benutzerpfaden
- **Autostart** – Registry-Run-Keys, Autostart-Ordner, geplante Aufgaben, Dienste
- **Registry** – dokumentierte Persistenz-/Hijack-Stellen (AppInit_DLLs, Winlogon, IFEO-Debugger)
- **FiveM** – lokale Integritätshinweise im FiveM-Verzeichnis (unsignierte/untrusted DLLs)
- **Downloads** – ausführbare Dateien und Archive im Downloads-Ordner
- **Laufwerke/Dateien** – gezielte Schlüsselverzeichnisse (Standard) oder vollständiger Tiefen-Scan (optional), SHA-256-Hashing

Jeder Fund erhält ein **Risiko** (Low/Medium/High/Critical), einen **Grund** und eine
**Empfehlung** (Ignorieren/Prüfen/Entfernen).

## Erkennungslogik (bewusst transparent)

Zwei kombinierte Quellen:

1. **Eingebaute Heuristiken** – signaturfrei, z. B. „unsignierte ausführbare Datei in einem
   beschreibbaren Benutzerpfad". Beschreiben Muster, keine konkreten Cheat-Produkte.
2. **Lokale Indikator-Datenbank** – vom Administrator pflegbar (Hashes, Dateinamen,
   Schlüsselwörter, Prozessnamen). Vollständig editierbar in den Einstellungen.

**Updates erfolgen ausschließlich lokal** über JSON-Import. Es werden **keine Signaturen
automatisch aus dem Internet geladen** – das vermeidet False-Positive-Lawinen und
Malware-Köderlisten und hält das Tool seriös und auditierbar.

## Ergebnisse senden (offen & zustimmungsbasiert)

Ist auf der Seite **Berichte** eine Webhook-/Website-Adresse hinterlegt, werden die
Ergebnisse nach Abschluss eines Scans automatisch dorthin gesendet. Das ist **vorab in der
Einwilligung (EULA-/Datenschutzfenster) genannt**, sodass die geprüfte Person vor dem Start
zustimmt. Nach dem Versand erscheint auf der Seite **Funde** der Hinweis **„Ergebnisse
gesendet"**, und die vollständigen Ergebnisse bleiben dort einsehbar – die Person sieht also
sowohl *was* gefunden wurde als auch *dass* es übertragen wurde. Ist keine Adresse hinterlegt,
wird nichts gesendet. Zusätzlich lässt sich ein Bericht jederzeit manuell an eine Adresse
senden (mit sichtbarer Nutzlast-Vorschau) oder als HTML/JSON/TXT exportieren.

## Technik

- **C# / .NET 8**, **WPF** (Dark Theme, MVVM)
- **SQLite** (`Microsoft.Data.Sqlite`, reines SQL) für Indikatoren, Scans und Funde
- **WMI** (`System.Management`) für Prozesse/Dienste, **COM** (Schedule.Service / WScript.Shell)
  für Aufgabenplanung und Verknüpfungen – alles dokumentierte Windows-APIs
- Zwei Projekte: `ZeroTrace.Core` (gesamte Logik) und `ZeroTrace.App` (Oberfläche)

## Schnellstart

```powershell
# .NET 8 SDK vorausgesetzt (siehe docs/BUILD.md)
dotnet build -c Release
dotnet run --project src/ZeroTrace.App
```

Die App fordert beim Start Administratorrechte an (für vollständige Scans). Beim ersten
Start wird die lokale Datenbank unter `%LocalAppData%\ZeroTrace\zerotrace.db` angelegt und
mit Standard-Heuristiken befüllt.

## Dokumentation

- [docs/BUILD.md](docs/BUILD.md) – Bauen mit CLI oder Visual Studio
- [docs/INSTALL.md](docs/INSTALL.md) – Installation und Ausführung
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) – Aufbau, Module, Datenfluss
- [docs/Schema.sql](docs/Schema.sql) – Datenbankschema (Referenz)

## Rechtliches / Ethik

Nur auf eigenen Systemen bzw. mit ausdrücklicher Zustimmung des Eigentümers einsetzen.
Das Tool liest Systeminformationen, verändert aber nichts an Prozessen, Dateien oder der
Registry. Es trifft keine automatischen Maßnahmen.
