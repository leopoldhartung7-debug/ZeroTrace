# Installations- und Nutzungsanleitung

## Installation

ZeroTrace benötigt keine klassische Installation. Es genügt die gebaute bzw.
veröffentlichte `ZeroTrace.exe` (siehe [BUILD.md](BUILD.md)).

1. `ZeroTrace.exe` (und bei *nicht* self-contained Build die .NET-8-Runtime) auf den
   Ziel-PC kopieren.
2. Per Doppelklick starten. Windows fordert über **UAC** Administratorrechte an –
   bestätigen, damit der Scan vollständige Ergebnisse liefert.

> **Warum Administratorrechte?** Ein Host-Scanner muss systemweit lesen (HKLM, fremde
> Prozesse, alle Laufwerke). Ohne Erhöhung laufen viele Prüfungen nur eingeschränkt; die
> App weist oben in der Seitenleiste darauf hin.

## Erster Start

- Die lokale Datenbank wird unter `%LocalAppData%\ZeroTrace\zerotrace.db` angelegt.
- Es werden eingebaute Heuristik-Indikatoren befüllt (editierbar unter *Einstellungen*).
- Eine Integritätsprüfung der Datenbank läuft automatisch.

## Bedienung

1. **Dashboard** – System-Überblick, Indikatoranzahl, letzter Scan. „Scan starten".
2. **Live-Scan** – Fortschritt, Zähler und Funde in Echtzeit; jederzeit abbrechbar.
3. **Funde** – Ergebnisse des gewählten Scans mit Suche und Risiko-Filter; rechts Details
   inkl. Grund und Empfehlung.
4. **Berichte** – frühere Scans ansehen, als **HTML/JSON/TXT** exportieren oder löschen.
5. **Einstellungen** – Module an/aus, Tiefen-Scan, Laufwerke, Endungen; Indikatoren
   anlegen/bearbeiten/löschen und per **JSON importieren/exportieren**.

## Indikatoren aktualisieren (lokal)

„Updates" sind bewusst lokal: In *Einstellungen → Importieren (JSON)* eine geprüfte
Indikatordatei einlesen. Format (Array von Objekten):

```json
[
  {
    "Type": 0,
    "Pattern": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "Risk": 3,
    "Category": "Beispiel-Hash",
    "Description": "Bekannter schaedlicher Loader (Beispiel)."
  },
  {
    "Type": 4,
    "Pattern": "cheatengine",
    "Risk": 1,
    "Category": "Memory-Tool",
    "Description": "Prozessname-Indikator."
  }
]
```

`Type`: 0=Sha256Hash, 1=FileName, 2=FileNameKeyword, 3=FilePathKeyword, 4=ProcessName,
5=RegistryValueKeyword. `Risk`: 0=Low, 1=Medium, 2=High, 3=Critical.

## Deinstallation

`ZeroTrace.exe` löschen. Optional den Datenordner
`%LocalAppData%\ZeroTrace` entfernen (enthält DB und exportierte Berichte).

## Datenschutz

Ist auf der Seite *Berichte* eine Zieladresse hinterlegt, werden die Scan-Ergebnisse nach
Abschluss automatisch dorthin gesendet – das wird **vorab im Einwilligungsfenster genannt**,
und nach dem Versand erscheint der Hinweis „Ergebnisse gesendet". Die Ergebnisse bleiben für
die geprüfte Person unter *Funde* einsehbar. Ist keine Adresse hinterlegt, wird nichts
gesendet. Exportierte Berichte liegen nur dort, wohin du sie exportierst (Standard:
`%LocalAppData%\ZeroTrace\Reports`).
