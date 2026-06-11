# PIN-Workflow (Website ↔ Scanner ↔ Dashboard)

So greift der PIN-Ablauf ineinander. Der **Scanner** ist fertig dafür vorbereitet;
die **Website/Dashboard-Seite** musst du selbst bereitstellen (Backend), da sie auf
deinem Server läuft.

## Ablauf

1. **PIN erzeugen (Website).** Du erstellst auf deiner Seite einen PIN (z. B. 4–8 Ziffern)
   und ordnest ihn einer Person/einem Slot zu. Den PIN in einer DB als „offen" speichern.

2. **Download mit eingebettetem PIN (Website).** Du baust den Download so, dass der PIN
   mitkommt. Der Scanner liest ihn auf zwei Wegen automatisch:
   - **Datei daneben:** lege eine Datei `zerotrace.pin` neben `ZeroTrace.exe` (Inhalt = nur der PIN), **oder**
   - **Kommandozeile:** starte den Scanner mit `ZeroTrace.exe --pin=1234`.
   Ist ein gültiger PIN eingebettet, wird er beim Start vorausgefüllt und gesperrt.

3. **Ohne PIN kein Scan.** Startet jemand den Scanner ohne eingebetteten PIN, muss er im
   ersten Fenster einen gültigen PIN (4–8 Ziffern) eingeben. „Akzeptieren" ist sonst
   deaktiviert – ohne gültigen PIN läuft kein Scan.

4. **Scan + Versand.** Nach dem Scan wird das Ergebnis **zuerst** an deine hinterlegte
   Adresse (Webhook) gesendet – inklusive `pin` im JSON. Erst danach sieht die Person
   das Ergebnis.

5. **Zuordnung + view results (Dashboard).** Dein Backend empfängt das JSON, prüft den
   `pin` gegen die offenen PINs und ordnet das Ergebnis zu. Im Dashboard kannst du den
   vollständigen Bericht über „view results" ansehen.

6. **Was die Person sieht.** Garantiert mindestens „Auffälligkeiten gefunden: ja/nein".
   Wie viel mehr (Kategorien / vollständig) stellst du unter
   *Einstellungen → Anzeige für den gescannten Nutzer* ein. Standard ist **nur Ja/Nein**.

## JSON, das der Scanner sendet (Auszug)

```json
{
  "Pin": "4821",
  "AnomaliesFound": true,
  "CriticalCount": 1, "HighCount": 2, "MediumCount": 2, "LowCount": 1,
  "Findings": [ /* ... */ ]
}
```

## Was dein Backend tun sollte

- **PIN-Prüfung serverseitig:** Ergebnisse nur annehmen, wenn der `pin` von dir stammt und
  noch gültig ist. (Der Scanner prüft lokal nur das Format – die echte Gültigkeit kennt nur
  deine Website.)
- **Einmal-PINs / Ablauf:** PIN nach Eingang entwerten oder mit Zeitlimit versehen.
- **Transport absichern:** HTTPS-Endpoint; optional ein Shared-Secret/Token im Header.

## Hinweis

Der gescannte Nutzer sieht immer ehrlich, ob etwas gefunden wurde (echtes Ja/Nein). Eine
Variante, die der Person fälschlich „nichts gefunden" anzeigt oder das Ergebnis komplett
verbirgt, ist bewusst nicht enthalten.
