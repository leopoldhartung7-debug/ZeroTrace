# Scanner-Verbesserungen (v1.18) — sechs neue Erkennungsquellen

Alles rein lesend, gegen die Indikatoren abgeglichen, modulübergreifend
dedupliziert. Jedes Modul einzeln abschaltbar.

- **NTFS-Aenderungsjournal (USN):** Datei-Erstell-/Lösch-Verlauf mit Zeit –
  findet auch gelöschte Cheats. (Admin + NTFS; sonst still aus.)
- **Forensische Spuren:** RecentDocs, MUICache, zuletzt geöffnete `.lnk`,
  WER-Absturzberichte und **versteckte alternative Datenströme (ADS)** in
  ausführbaren Dateien.
- **Netzwerk:** aktive (established) TCP-Verbindungen, dem Besitzer-Prozess
  zugeordnet – Verbindung eines verdächtigen Prozesses wird gemeldet; zusätzlich
  **DNS-Client-Cache** gegen Cheat-Domains (best effort, undokumentierte API).
- **Overlay / ESP:** bildschirmfüllende, klick-durchlässige Always-on-Top-Fenster
  aus benutzer-schreibbaren Pfaden – typisch für externe ESP-Cheats (Hinweis,
  FP-arm gehalten).
- **WMI-Persistenz:** `__EventFilter`/`__EventConsumer`/`Binding` in
  `root\subscription` – fileless Autostart, der Run-Keys/Tasks/Dienste umgeht.
- **Speicher-Scan des Spiels:** liest (nur lesend) den Arbeitsspeicher der
  erkannten Spielprozesse und sucht Cheat-Strings – findet interne/injizierte
  Cheats **ohne Datei**. Mengen-/Zeit-begrenzt; separat abschaltbar, weil
  langsamer und FP-anfälliger.

**Bewusst NICHT enthalten:** Inline-/IAT-/EAT-Hook-Erkennung. Eine ungetestete
Hook-Erkennung wäre stark fehlalarm-anfällig; das gehört sauber spezifiziert und
auf echtem Windows getestet, nicht blind ausgeliefert.

**Zertifikate:** abgelaufene/zurückgezogene Signaturen werden bereits abgelehnt
(`WinVerifyTrust` → „untrusted"); dafür war kein neues Modul nötig.

Hinweis zum Test: USN, ADS, TCP-Tabelle, `GetWindowLongPtrW` und der Speicher-Scan
nutzen Low-Level-/64-Bit-APIs. Bitte unter 64-Bit-Windows mit Adminrechten
gezielt testen – im Container ist kein Kompilieren möglich.

---



Neues Modul „Scan-Manipulation" (Anti-Tamper, rein lesend, nur melden – der
Scanner wehrt sich nicht und versteckt nichts):

- **Debugger am Scanner:** erkennt, ob waehrend des Scans ein Debugger angehaengt
  war (managed/native/remote) – Versuch, Ergebnisse zu faelschen → hoch.
- **Umgeleitete Verzeichnisse:** ist ein gescannter Ordner (Downloads/Temp/
  FiveM/RageMP/alt:V) ein Junction/Symlink (Reparse-Punkt), kann der Scan auf
  einen leeren Koeder umgeleitet sein, waehrend die echten Dateien woanders
  liegen → hoch.
- **Gehookte/leere Enumeration:** auffaellig wenige sichtbare Prozesse (< 15)
  oder Treiber (< 20) deuten auf manipulierte Listen (Verstecken) → mittel.
- **Systemzeit-Trick:** zukunftsdatierte Dateien in den Scan-Ordnern deuten auf
  eine zurueckgestellte Uhr (kuenstliches „Altern" von Cheat-Spuren) → mittel.
- **Bypass-Tooling:** laufende Spoofer/Mapper/Bypass-Tools werden weiterhin ueber
  die (in v1.16 erweiterten) Indikatoren erkannt.

Abschaltbar in den Einstellungen. Unveraendertes Prinzip: transparent, mit
Einwilligung, Ergebnis wird der gescannten Person gezeigt.

---



Rein defensiv (nur erkennen, nichts umgehen):

- **Test-Signing / Code-Integritaet:** liest ueber `NtQuerySystemInformation`
  (read-only) den Code-Integrity-Status. Ist **Test-Signing aktiv** oder die
  **Code-Integritaet deaktiviert**, wird das hoch gewertet – das ist der
  klassische Weg, die Treiber-Signaturpruefung zu umgehen und unsignierte
  Kernel-Cheats/Spoofer zu laden. Ist beides in Ordnung, gibt es einen
  beruhigenden Low-Hinweis.
- **Mehr Bypass-/Loader-Signaturen** (Indikatoren, editierbar): Dateinamen
  `spoofer`, `kdmapper`, `manualmap`, `dsefix`; Inhalts-Token `hwid spoof`,
  `vac bypass`, `manual map`. Treffer fliessen in die normale Bewertung +
  Dedup ein. (Reine Erkennungs-Signaturen – wie AV-Signaturen, keine Anleitung.)

Damit werden Signatur-Bypass (DSE/Test-Signing), HWID-Spoofer und Manual-Mapper
deutlich zuverlaessiger erkannt.

---



Das Modul „Ausfuehrungsverlauf" nutzt jetzt zusaetzlich (rein lesend):

- **Amcache** (`%WINDIR%\appcompat\Programs\Amcache.hve`, `InventoryApplicationFile`)
  — Pfade ausgefuehrter/bekannter Programme. Hive wird privat per `RegLoadAppKey`
  geladen (nur Lesezugriff). Ist die Datei gesperrt, wird still uebersprungen.
- **ShimCache / AppCompatCache** (`…\Session Manager\AppCompatCache`) — Win10/11-
  Binaerformat wird geparst; die enthaltenen Programmpfade werden gegen die
  Indikatoren geprueft.
- **PCA-Logs** (`%WINDIR%\appcompat\pca\PcaAppLaunchDic.txt` / `PcaGeneralDb*.txt`,
  Win11) — gestartete Anwendungen samt Pfad.
- **EVTX – Dienst-/Treiber-Installationen** (System-Log, Ereignis **7045**) —
  neu installierte Dienste/Treiber mit Image-Pfad; der Pfad laeuft durch die
  volle Datei-Pruefung (Signatur/Hash/Umbenennung) bzw. den Indikator-Abgleich.
  Starkes Signal fuer nachinstallierte Cheat-Treiber.

Wie zuvor: nur Treffer werden erfasst, gefundene Dateien zusaetzlich voll
geprueft, ueber alle Module dedupliziert (v1.14). Amcache/ShimCache/EVTX
brauchen fuer den vollen Umfang Administratorrechte; ohne diese faellt die
jeweilige Quelle still aus. Damit sind die genannten Quellen
(Prefetch, Amcache/ShimCache, BAM, EVTX, PCA) abgedeckt.

---



- **Funde werden modulübergreifend zusammengefasst:** Dieselbe Datei (gleicher
  SHA-256-Hash oder gleicher Datei­pfad), die von mehreren Modulen erkannt wird
  (z. B. Prozess + geladenes Modul + Downloads + Ausführungsverlauf), erscheint
  jetzt **einmal** – als der jeweils **stärkste** Fund, mit Notiz „auch erkannt
  von: …". Vorher wurde ein einzelner Cheat teils 4–5× gelistet.
- **Sicher gehalten:** Funde mit generischem Ort (Registry, Logs, „Plattform")
  werden NIE zusammengefasst – nur echte Datei-Artefakte (Hash/Pfad). Es gehen
  keine Informationen verloren; die zusätzliche Quelle wird im Detail vermerkt.
- Ergebnis: übersichtlichere Liste, weniger Doppel-Alarme, gleiche Trefferzahl
  an echten Artefakten.

(Kein neues Sammelmodul – diesmal bewusst Qualität statt Menge.)

---



- **Neues Modul „Tarnung & Reste":** schliesst zwei Verschleierungs-/Rest-Luecken,
  rein lesend:
  - **hosts-Datei:** erkennt (a) Cheat-Domains, die dort eingetragen sind, und
    (b) Anti-Cheat-/Telemetrie-Domains, die auf eine Null-IP (0.0.0.0/127.0.0.1)
    umgeleitet = geblockt werden (typisches Verschleierungs-Muster, Review).
  - **Papierkorb:** liest aus den `$I`-Metadaten den **Originalnamen/-pfad** und
    die Loeschzeit geloeschter Dateien und gleicht sie gegen die Indikatoren ab.
    Treffer = ein „geloeschter", aber noch **wiederherstellbarer** Cheat. Ist die
    Datei (`$R`) noch da, laeuft sie zusaetzlich durch die volle Datei-Pruefung.
- Abschaltbar in den Einstellungen; nichts wird veraendert oder wiederhergestellt.

**Ehrliche Einordnung zu „findet wirklich alles":** Ein Host-Scanner kann das
nicht garantieren. Kernel-Cheats, die sich tarnen, und vor allem DMA-/Hardware-
Cheats (separates Geraet am PCIe-Bus) hinterlassen auf dem PC oft keine Spur.
Die Abdeckung ist jetzt sehr breit (Prozesse/Module, Datei-/Inhalts-/Hash-
Indikatoren, Umbenennen, Downloads inkl. ZIP, Browser-Verlauf, Autostart/
Registry/Dienste, Kernel-Treiber, Defender-/An-Aus-Verlauf, PowerShell,
Ausfuehrungsverlauf inkl. Geloeschtem, DMA-Heuristik, Host-Inventar, hosts/
Papierkorb) — aber „alles" erfordert zusaetzlich serverseitige Verhaltens-
analyse und ein Kernel-Anticheat.

---



Fuellt die meisten Dashboard-Panels mit echten Daten (vorher leer, weil der
Scanner nur Funde, aber keine Inventare sendete). Neu im Bericht:
`report.Inventory`.

- **Executable List:** alle laufenden Prozesse (Name, PID, Pfad, signiert?,
  Compile-Datum aus dem PE-Header).
- **Admin-Executed Applications:** Prozesse, die mit Admin-Rechten laufen
  (per Token-Elevation-Pruefung, rein lesend).
- **Loaded Drivers:** geladene Kernel-Treiber (Name, Pfad, signiert?, laeuft?) –
  unsignierte fallen so auf.
- **Recording Software:** erkennt OBS/Bandicam/ShadowPlay/Streamlabs u. a. ueber
  Prozessnamen.
- **Virtual Machine Detection:** VMware/VirtualBox/QEMU/KVM/Xen/Hyper-V/Parallels
  ueber Hersteller-/BIOS-/Board-Strings + Hypervisor-Flag.
- **USB Activity:** je Geraet einmal verbundene USB-Speicher (USBSTOR-Verlauf).
- **Compilation dates:** Compile-Datum pro Prozess-Image (Teil der Executable
  List).

Bewusst NICHT umgesetzt (unveraendert):
- **Discord-Konten/-Server:** wuerde das lokale Discord-Token auslesen
  (Token-Diebstahl, Kontouebernahme, Ueberwachung privater Zugehoerigkeiten).
  Nur per freiwilligem Discord-OAuth2 (Scope `guilds`) serverseitig zulaessig.
- **VirusTotal-Lookup:** macht das Dashboard serverseitig mit eigenem API-Key
  aus den im Bericht enthaltenen SHA-256-Hashes; der Scanner macht keinen
  Outbound-Call. (Hinweise stehen in `Inventory.DiscordNote` /
  `Inventory.VirusTotalNote`.)

Alles rein lesend, abschaltbar (Einstellungen → „Inventar"). Hinweis: Treiber-/
USB-Vollstaendigkeit und die Admin-Erkennung profitieren von Adminrechten.

---



- **Read-only PC-Info-Erfassung** fuellt die Dashboard-Felder:
  - **System** (OS-Name + Build + 32/64-bit), **HWID** (stabiler Fingerprint aus
    MachineGuid/Board-/BIOS-/CPU-IDs, **SHA-256-gehasht** — keine Roh-Seriennummern
    werden uebertragen), **Boot Time** und **Install Date** (aus
    `Win32_OperatingSystem`), **lokale IPv4-Adressen**, **VPN** (Heuristik anhand
    der Netzwerkadapter), **Region** (System-Region), **Game** (erkannte
    FiveM/RageMP/alt:V-Installation), **Hardware Stats** (CPU/GPU/RAM).
  - Die Werte stehen jetzt im Bericht (`ScanReport.System`) und damit im
    JSON-Webhook ans Dashboard sowie im Text-Export.
- **Bewusst NICHT erfasst:** keine oeffentliche IP und kein Geo-Land – dafuer
  macht der Scanner keinen Outbound-Call. Beides sollte das Dashboard
  serverseitig aus der eingehenden Verbindung ableiten (Hinweis im Payload-Feld
  `ipNote`).
- Demo-Payload zeigt jetzt einen `pc`-Block, passend zu den Dashboard-Feldern.

---



**Wichtig vorab:** Ein Host-Scanner kann ein DMA-Cheat nicht zuverlaessig
nachweisen. Ein DMA-Geraet liest den Speicher direkt ueber den PCIe-Bus, ohne
Prozess/Datei/Treiber auf dem PC. Dieses Modul liefert daher nur **Hinweise**,
keinen Beweis. „Was auf dem DMA-Geraet laeuft" ist von der Host-Seite nicht
auslesbar (es ist ein fremder Rechner am Bus).

- **Neues Modul „DMA / Hardware (Hinweis)":**
  - **Plattform-DMA-Schutz:** liest, ob der Windows-Kernel-DMA-Schutz aktiv ist
    und ob IOMMU/VT-d vorhanden scheint. Ist der Schutz nicht nachweisbar aktiv,
    gibt es einen Medium-Hinweis mit BIOS/UEFI-Empfehlung (VT-d/IOMMU,
    Kernel-DMA-Schutz aktivieren).
  - **PCIe-/PnP-Geraeteliste:** rein lesende Inventur; markiert FPGA-/Capture-
    aehnliche oder ungewoehnliche Geraete (z. B. FT601/FX3, Xilinx/Lattice,
    Capture) als **„zur Pruefung" (Review, Low)**. Legitime Capture-Karten sehen
    von Host-Seite identisch aus → ausdruecklich KEIN Cheat-Nachweis.
  - Findet es nichts Auffaelliges, wird klar gesagt, dass das ein DMA-Geraet
    NICHT ausschliesst (gute Boards tarnen sich).
- Abschaltbar in den Einstellungen; rein lesend, nichts wird veraendert.

Fazit: verlaesslichen DMA-Schutz liefern nur die Plattform (aktivierter
Kernel-DMA-Schutz/IOMMU) und serverseitige Verhaltensanalyse — nicht ein
Host-Scan.

---



- **Neues Modul „Ausfuehrungsverlauf":** findet Cheats/Loader auch dann, wenn die
  Datei bereits geloescht wurde – ueber Windows' eigene Ausfuehrungs-Spuren
  (rein lesend). Quellen:
  - **Prefetch** (`%WINDIR%\Prefetch\*.pf`) – welche Programme liefen.
  - **BAM/DAM** (`HKLM\SYSTEM\…\bam|dam\State\UserSettings\<SID>`) – letzte
    Ausfuehrungszeit pro Programm (mit Zeitstempel).
  - **UserAssist** (`HKCU\…\Explorer\UserAssist\{GUID}\Count`) – GUI-Starts
    (ROT13-decodiert).
- **Abgleich mit Indikatoren:** der erfasste Programmname/-pfad wird gegen die
  Datei-/Schluesselwort-/Pfad-Indikatoren geprueft. Existiert die Datei noch,
  laeuft sie zusaetzlich durch die volle Datei-Pruefung (Hash/Signatur/
  Umbenennung). Fehlt sie, wird der Namens-Treffer mit Hinweis „evtl. geloescht"
  gemeldet – inkl. letzter Ausfuehrungszeit (BAM).
- **Minimierung:** nur Treffer werden erfasst, nie der gesamte Verlauf. Mehrere
  Quellen brauchen Administratorrechte; ohne diese wird die jeweilige Quelle
  still uebersprungen. Abschaltbar in den Einstellungen.

---



- **Neues Modul „Kernel-Treiber":** prueft installierte/geladene Kernel-Treiber
  (`Win32_SystemDriver`) rein lesend. Jedes Treiber-Image laeuft durch die
  normale Datei-Pruefung (SHA-256-Hash, echte Authenticode-/Katalog-Signatur,
  Selbst-Umbenennung, Indikatoren, untrusted-in-beschreibbarem-Pfad).
- **Geladene Treiber werden hoeher gewertet:** Ein *laufender* Kernel-Treiber ist
  die folgenschwerste Angriffsflaeche (Kernel-Code) — Treffer werden um eine
  Stufe eskaliert.
- **Treiber aus fremdem Pfad:** Ein Treiber-Image ausserhalb von
  `…\System32\drivers`, das nicht vertrauenswuerdig signiert ist, wird eigens
  gemeldet (geladen → hoch). Das ist ein typisches Muster fuer Kernel-Cheats,
  HWID-Spoofer und BYOVD (Missbrauch verwundbarer signierter Treiber).
- Verschiedene Treiber-Pfadformate (`\??\C:\…`, `\SystemRoot\…`, `system32\…`,
  relativ) werden korrekt aufgeloest. Abschaltbar in den Einstellungen.

---



- **Neues Modul „PowerShell / Befehle":** erkennt verdaechtige PowerShell-/
  Befehlszeilen, die bei Cheats/Loadern typisch sind. Zwei rein lesende Quellen:
  - **Laufende Prozesse** (powershell.exe, pwsh.exe, cmd.exe) — die Befehlszeile
    wird via WMI gelesen und gegen Muster geprueft.
  - **PowerShell-Verlauf** (PSReadLine `ConsoleHost_history.txt`) — es wird
    **nur die jeweils betroffene Zeile** erfasst, nie der gesamte Verlauf
    (gleiche Minimierung wie beim Browser-Verlauf).
- **Erkannte Muster (Auszug):** Echtzeitschutz per Skript abschalten
  (`Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`)
  → kritisch/hoch; Download-Cradles (`DownloadString`, `Net.WebClient`,
  `Invoke-Expression`/IEX) → hoch; codierte Befehle (`-EncodedCommand`,
  `FromBase64String`) → hoch; LOLBins (`certutil`, `bitsadmin`, `mshta`) →
  mittel; `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `-NoProfile` →
  mittel/niedrig. Mehrere Treffer ergeben die hoechste Stufe.
- Abschaltbar in den Einstellungen; rein lesend, nichts wird ausgefuehrt.

---



- **Selbst-Umbenennung erkennen:** Jede gepruefte Programmdatei wird nun mit ihrem
  intern hinterlegten Originalnamen (PE-Versionsressource `OriginalFilename`)
  verglichen. Weicht der echte Name vom aktuellen Dateinamen ab (z. B. ein als
  `svchost.exe` getarnter Injektor), gibt es den Fund **„Datei umbenannt"** —
  hoeher gewertet, wenn die Datei zusaetzlich nicht vertrauenswuerdig signiert ist
  oder aus dem Internet stammt. Nur in beschreibbaren Benutzerordnern, um
  Fehlalarme gering zu halten.
- **Schutz-Verlauf (Defender):** Neues Modul „System & Schutz" liest rein lesend
  das Defender-Ereignisprotokoll und meldet, **wann der Echtzeitschutz aus- und
  wieder eingeschaltet** wurde (Ereignisse 5001/5000), inkl. Konfig-Aenderungen
  und blockierter Manipulationsversuche. Schutz ausschalten ist ein typisches
  Muster vor dem Laden eines Cheats → hoch gewertet.
- **System-An/Aus-Zeitleiste:** Aus dem System-Protokoll werden die letzten
  Hochfahr-/Herunterfahr-Zeiten (6005/6006/1074/6008/41) als Einordnung
  aufgelistet (informativ).
- **Mehr Autostarts:** zusaetzliche Run-Schluessel (Explorer\Run, Policies\Run,
  RunServices) und Pruefung in 32- und 64-Bit-Registry-Sicht (Wow6432Node).
- **Loader-Muster:** Ein FiveM-/RageMP-/alt:V-Prozess, der von einer Datei aus
  einem beschreibbaren Benutzerordner gestartet wurde, wird gemeldet (hoch, wenn
  diese Datei nicht vertrauenswuerdig signiert ist).

Hinweis: Der Schutz-/An-Aus-Verlauf benoetigt fuer den vollen Umfang
Administratorrechte; ohne diese faellt das Modul still auf eine kurze Notiz
zurueck. Alles bleibt rein lesend.

---



- **ZIP-Inhalt wird mitgeprüft:** Im Downloads-Ordner liest der Scanner jetzt die
  **Eintragsnamen** in `.zip`-Archiven (ohne Entpacken, rein lesend, auf 5000
  Einträge begrenzt) und gleicht sie gegen die Indikatoren ab. So fällt ein
  harmlos benanntes Archiv auf, das z. B. `injector.dll` oder `aimbot.lua`
  enthält. Inhalte selbst werden weiterhin nicht extrahiert.
- **Demo kompakter:** schmaleres Panel, engere Abstände, kleinere Auswahl-Boxen
  und Listen — passt jetzt besser auf kleine/mobile Fenster.

---



- **Injektions-Eskalation für alle drei Frameworks:** Eine nicht vertrauenswürdige
  DLL, die in einen FiveM-, RageMP- oder alt:V-Prozess geladen ist, wird jetzt um
  eine Stufe höher gewertet (vorher nur FiveM). Erkennung über Prozessnamen
  (`FiveM.exe`/`FiveM_*`, `ragemp_v.exe`, `altv.exe` …) **und** über das Image im
  Framework-Verzeichnis. Der Fund nennt das konkrete Framework.
- **Mehr durchsuchte Ordner:** zusätzlich `modules`, `deps`, `data`, `cache`,
  `dlls`, `bin`, `cef`, `FiveM.app\citizen` u. a. – deckt die typischen Mod-/
  Ressourcen-/Modul-Ordner aller drei Plattformen ab.
- **Mehr Dateitypen:** zusätzlich `.luac` (kompilierte Lua-Skripte) und `.node`
  (alt:V-Native-Module) werden erfasst, gehasht und inhaltlich auf Cheat-Strings
  geprüft. Such-Tiefe im Framework-Baum von 4 auf 5 erhöht.
- **Zusätzliche Start-Indikatoren** (editierbar): Inhalts-Signaturen `tsunami.gg`,
  `esp_render`; Dateinamen-Keywords `dumper`, `bypass`.

---



## A. Browser-Verlauf auf Cheat-/Reseller-Domains prüfen

Neues Modul `BrowserHistoryScanModule` prüft den **lokalen** Verlauf von
Chromium-Browsern (Chrome, Edge, Brave, Opera, Vivaldi) und Firefox auf Besuche
bekannter Cheat-/Reseller-Domains.

**Datensparsamkeit ist eingebaut (wichtig):**
- Der **gesamte** Verlauf wird **niemals** gespeichert, gezählt oder gesendet.
- Jeder Eintrag wird nur **flüchtig im Speicher** geprüft; **nur** Hosts, die auf
  einen Cheat-/Reseller-Domain-Indikator passen, werden zu Funden.
- Ein Fund enthält **nur den Host** (keine vollständige URL, keine Query-Parameter,
  kein Seitentitel) plus eine aggregierte Besuchszahl.
- Die laufende Browser-DB ist meist gesperrt → es wird auf einer **schreibgeschützten
  Kopie** gelesen, die danach gelöscht wird. Rein lesend, kein Netzwerk.

Technik: neuer Indikatortyp **`UrlDomainKeyword` (Typ 7)** + `MatchUrlDomain(host)`
im `IndicatorMatcher`; neue Option `ScanBrowserHistory` (Default an) mit Checkbox
„Browser-Verlauf" in den Einstellungen. Eingebaute Start-Domains (editierbar):
markante Cheat-Marken (redengine, skript.gg, eulen, hxcheats, cherax) als High,
Foren (unknowncheats, elitepvpers) als Medium/Low.

## B. Discord-Server-Mitgliedschaften — **bewusst NICHT umgesetzt**

Die Anfrage, auszulesen, in welchen **Discord-Servern** der Nutzer ist, und
Cheat-/Reseller-Server zu markieren, habe ich **nicht** eingebaut — aus klaren
Sicherheits- und Datenschutzgründen:

- Um lokal zu ermitteln, in welchen Servern jemand ist, müsste man Discords
  **lokales Auth-Token** bzw. den privaten LevelDB-/Cache-Speicher auslesen. Genau
  das ist die Technik von **Discord-Token-Stealern (Malware)** — das Token erlaubt
  die **vollständige Account-Übernahme**. Solchen Code stelle ich nicht bereit,
  unabhängig vom guten Zweck.
- Es würde außerdem die **privaten Community-Mitgliedschaften** einer Person
  überwachen — weit über das Erkennen von Cheat-Software auf dem PC hinaus.

**Zulässige Alternative (einwilligungsbasiert):** Discord-**OAuth2** mit dem Scope
`guilds`. Dabei meldet sich die Person **selbst** über das offizielle Discord-Login
an und gibt ihre Server-Liste ausdrücklich frei; dein Backend gleicht sie dann gegen
deine Liste bekannter Cheat-Server ab. Das nutzt offizielle APIs, ist transparent
und stiehlt kein Token. Diese Funktion gehört auf deine **Website/Dashboard-Seite**,
nicht in den lokalen Scanner — der Scanner liest weiterhin keine Discord-Daten.

---



Diese Version erweitert die Erkennung auf **alle drei großen GTA-V-Multiplayer-
Frameworks** und ergänzt eine **Inhalts-Signaturprüfung** (Strings im
Datei-Inhalt). Die Grundsätze bleiben unverändert: weiterhin **nur lesend**, mit
**Einwilligung**, **Begründung pro Fund** und der **Ja/Nein-Garantie**.

## A. RageMP und alt:V zusätzlich zu FiveM

- Neue Erkennung der Installationspfade in `KnownPaths`:
  `FindRageMpDirectory()`, `FindAltVDirectory()` und der gemeinsame Aufzähler
  `FindMpFrameworks()` (liefert alle gefundenen Frameworks als Name/Pfad).
- Das frühere FiveM-Modul (`FiveMScanModule`, Modulname jetzt **„GTA-MP"**)
  durchläuft nun **FiveM, RageMP und alt:V** nacheinander. Jeder Fund trägt das
  jeweilige Framework als Präfix, z. B. `[RageMP]` / `[alt:V]`.
- Pro Framework eigene **vertrauenswürdige Signierer** (FiveM→CitizenFX/Cfx.re,
  RageMP→RAGE Multiplayer, alt:V→altMP), damit hauseigene DLLs ruhig bleiben und
  echte Fremd-/Injektionskomponenten auffallen.
- Zusätzlich erfasste Endungen im Framework-Baum: `.js`, `.dat` (für die
  JS-basierten Ressourcen von alt:V/RageMP). `.js` ist jetzt auch eine
  „relevante" Endung und wird inhaltsgescannt.
- Die Ziel-Scan-Pfade (`TargetedScanRoots`) enthalten jetzt alle gefundenen
  Framework-Verzeichnisse. UI: Checkbox heißt „FiveM / RageMP / alt:V",
  Dashboard zeigt alle erkannten Frameworks.

## B. Inhalts-Signaturen (Strings im Datei-Inhalt) — „erkennt Cheats schneller"

- Neuer Indikatortyp **`ContentString` (Typ 6)**: ein Muster, das in den
  **Roh-Bytes** einer Datei gesucht wird — **case-insensitiv in ASCII *und*
  UTF-16LE**, also auch in Wide-Strings einer PE-Datei.
- Neuer `ContentSignatureScanner`: liest pro Datei höchstens 32 MiB (gedeckelt,
  speicherschonend), rein lokal, nur lesend. Alle E/A-Fehler ergeben „kein Fund".
- In `IndicatorMatcher` neu: vorgefaltete Bytemuster + `MatchContent(...)` mit
  zwei schlanken Suchroutinen (Stride-1 ASCII, Stride-2 UTF-16LE).
- Eingebunden im gemeinsamen `FileInspector`. Konfidenz-Reihenfolge:
  **Hash → Inhalts-Signatur → exakter Name → Namens-Keyword → Pfad-Keyword**.
  Der Clou: eine Inhalts-Signatur greift **auch wenn die Datei umbenannt wurde**,
  weil das Wasserzeichen/der Menü-String im Binary bleibt.
- **Eingebaute Start-Signaturen** (in `SeedDefaultsIfEmpty`, alle editier-/
  abschaltbar): markante Marken-Token (z. B. `redengine`, `skript.gg`,
  `hxcheats`, `cherax`, `hwidspoofer`) als **High**, generische Cheat-Begriffe
  (`aimbot`, `triggerbot`, `silentaim`, `wallhack`, `norecoil`, `godmode`,
  `unknowncheats`) als High/Medium. Bewusst **distinktiv** gewählt, um
  False Positives zu vermeiden — und jederzeit über die JSON-Import/Export-
  Funktion durch den Admin erweiterbar.

## C. Alles als EINE Datei + Demo

- `build-singlefile.cmd` und ein erweiterter Abschnitt in `BUILD.md` erzeugen per
  `dotnet publish … -p:PublishSingleFile=true` **eine einzige `ZeroTrace.exe`**
  (self-contained, inkl. .NET-Runtime).
- Zusätzlich liegt eine **Demo-Version** als einzelne HTML-Datei bei
  (`ZeroTrace-Demo.html`): zeigt Einwilligung, Live-Scan, Funde mit Begründung
  und die Ja/Nein-Zusammenfassung mit **simulierten** Daten (führt keinen echten
  Scan aus).

## Weiterhin bewusst NICHT geändert

Keine Tarnung/Stealth, kein Anti-Removal, kein heimliches Senden, keine Erfassung
cheat-fremder persönlicher Daten. Die mitgelieferten Signaturen sind ein
**Startpunkt zur Erkennung**, kein vollständiger Cheat-Katalog, und dienen
ausschließlich dem Aufspüren — nicht dem Bauen oder Umgehen von Cheats.

---



Diese Version verbessert **wie genau** und **wie umfassend** ZeroTrace prüft,
ohne die Grundsätze des Werkzeugs zu ändern: weiterhin **nur lesend**, mit
**Einwilligung**, mit **Begründung pro Fund** und mit der **Ja/Nein-Garantie**
für die gescannte Person. Es wird weiterhin **keine** kuratierte Cheat-Liste
mitgeliefert (bewusst — das vermeidet False-Positive-Lawinen und hält das Tool
auditierbar). Verbessert wurde die **Engine**, nicht der Indikatorbestand.

## 1. Echte Signatur-Vertrauensprüfung (größter Präzisionsgewinn)

**Vorher:** „Datei trägt ein Zertifikat" = signiert. Das war doppelt ungenau:
- *False Negative:* selbstsignierte / manipulierte / abgelaufene Datei galt als
  „signiert" und wurde dadurch entschärft.
- *False Positive:* katalog-signierte Windows-DLLs (ohne eingebettetes
  Zertifikat) galten als „unsigniert".

**Jetzt:** `AuthenticodeVerifier` nutzt die dokumentierte Windows-API
`WinVerifyTrust` (eingebettete Signatur) **und** die Katalog-Signaturprüfung
(`CryptCATAdmin*`). Ergebnis ist dreistufig:
- **Trusted** – Windows vertraut der Signatur (eingebettet oder Katalog).
- **SignedUntrusted** – Signatur vorhanden, aber ungültig (selbstsigniert,
  manipuliert, abgelaufen) → wird als **verdächtiger** behandelt als „unsigniert".
- **Unsigned** – keine Signatur.

Läuft komplett **offline** (keine Sperrlisten-Abfragen im Netz → schnell und
passt zur „kein Internet"-Regel). Jeder Fehler fällt sicher auf „Unsigned"
zurück, der Scan bricht nie ab.

## 2. Geladene/injizierte Module je Prozess (größter Abdeckungsgewinn)

Der Prozess-Scan prüfte bisher nur das **Haupt-Image**. Das häufigste
FiveM-Cheat-Muster ist aber eine **injizierte DLL** in einem ansonsten legitimen
Prozess. Neu (`ModuleInspection`):
- Für jeden Prozess werden die geladenen Module aufgelistet.
- Günstiger Vorfilter: nur Module aus **beschreibbaren Pfaden** oder mit
  **Indikator-Treffer** werden tiefer geprüft (kein Hashen tausender System-DLLs).
- Jedes verdächtige Modul wird **einmal** geprüft (Dedupe über Prozesse hinweg)
  und mit der Zahl der Wirtsprozesse versehen.
- Ein verdächtiges Modul **im FiveM-Prozess** wird um eine Stufe **hochgestuft**.

Zusätzlich matcht der Prozess-Scan jetzt den **SHA-256 des Prozess-Images**
gegen Hash-Indikatoren (erkennt umbenannte Cheat-EXEs).

## 3. Mark-of-the-Web als Vertrauenssignal

`MarkOfWeb` liest den NTFS-Stream `Zone.Identifier`. Eine **unsignierte** Datei,
die **nachweislich aus dem Internet** stammt (`ZoneId ≥ 3`), wird eine Stufe
höher eingestuft und die Quelle (HostUrl) im Detail angezeigt — präzisere
Priorisierung ohne mehr Rauschen.

## 4. Breitere, aber kontrollierte Heuristik

`Heuristics` deckt jetzt mehr beschreibbare Orte ab, in denen Loader landen:
`LocalLow`, `ProgramData`, `C:\Users\Public`, Desktop/Documents/Music/Videos/
Pictures — weiterhin **immer** kombiniert mit „nicht vertrauenswürdig", damit
False Positives niedrig bleiben. Neue Unterscheidung: „unsigniert" vs.
„ungültig signiert" (Letzteres = höheres Risiko).

## 5. Präzisere FiveM-Logik

- Gültig signiert **und** CitizenFX/Microsoft/Katalog → **ruhig** (kein Fund).
  Das beseitigt Fehlalarme auf katalog-signierten In-Box-DLLs.
- Gültig signiert, aber Drittanbieter → **Low (informativ)**, nichts wird verborgen.
- Unsigniert → Medium (in Mod-/Plugin-Ordnern High).
- Ungültig signiert (selbstsigniert/manipuliert) → **High**.
- Suchtiefe leicht erhöht (3 → 4 Ebenen).

## 6. Downloads: Archive auch über Namen/Pfad prüfen

Archive werden weiterhin nicht entpackt, aber **Name und Pfad** werden gegen
Indikatoren geprüft (ein als Indikator hinterlegter Archivname wurde vorher
übersehen). Internet-Herkunft (Mark-of-the-Web) wird mit angezeigt.

---

## Geänderte / neue Dateien

| Datei | Art |
|---|---|
| `Detection/AuthenticodeVerifier.cs` | **neu** – WinVerifyTrust + Katalog |
| `Detection/SignatureChecker.cs` | überarbeitet – dreistufige Vertrauensprüfung |
| `Detection/Heuristics.cs` | überarbeitet – mehr Pfade, trust-aware |
| `Util/MarkOfWeb.cs` | **neu** – Zone.Identifier-Auswertung |
| `Modules/ModuleInspection.cs` | **neu** – geladene Module je Prozess |
| `Modules/FileInspector.cs` | überarbeitet – Vertrauen + MotW |
| `Modules/ProcessScanModule.cs` | überarbeitet – Image-Hash + Modul-Scan |
| `Modules/FiveMScanModule.cs` | überarbeitet – präzise Vertrauenslogik |
| `Modules/DownloadsScanModule.cs` | überarbeitet – Archiv-Indikatoren + MotW |

## Bauen & testen (Windows)

```powershell
dotnet build -c Release
dotnet run --project src/ZeroTrace.App
```

> Hinweis: Diese Änderungen verwenden Windows-eigene APIs (WinVerifyTrust,
> WMI, Registry) und lassen sich nur unter Windows bauen/ausführen (siehe
> `docs/BUILD.md`). Bitte den **Katalog-Signaturpfad** in `AuthenticodeVerifier`
> einmal auf einem echten System gegenprüfen (z. B. eine katalog-signierte
> System-DLL muss als *Trusted* erkannt werden, eine selbstsignierte EXE als
> *SignedUntrusted*). Der eingebettete `WinVerifyTrust`-Pfad ist Standard und
> robust; der Katalogpfad fällt bei jedem Fehler sicher auf „Unsigned" zurück.

## Bewusst nicht geändert

- Keine Stealth-/Verschleierungs-Funktionen, kein Schutz gegen Entfernen durch
  den Nutzer, keine verdeckte Übertragung.
- Keine Erfassung von Daten außerhalb des Cheat-Bezugs (keine Passwörter,
  Dokumentinhalte o. Ä.).
- Die Ja/Nein-Garantie und die Einsehbarkeit der Ergebnisse für die gescannte
  Person bleiben unverändert.
