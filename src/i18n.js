/* Centralised German translation layer.
   English text stays as-is; when the language is set to "de" every rendered
   text node / placeholder under #root is swapped for its German equivalent.
   Keys are the exact English source text with whitespace collapsed. */

import { useEffect } from 'react'
import { useStore } from './store.jsx'

const MONTHS = {
  January: 'Januar', February: 'Februar', March: 'März', April: 'April',
  May: 'Mai', June: 'Juni', July: 'Juli', August: 'August',
  September: 'September', October: 'Oktober', November: 'November', December: 'Dezember',
}

export const DE = {
  // ---- Navigation / sidebar / chrome ----
  'Dashboard': 'Übersicht', 'Pins': 'Pins', 'Strings': 'Strings',
  'Cheat Database': 'Cheat-Datenbank', 'Forensic Tools': 'Forensik-Tools',
  'Activity Log': 'Aktivitätsprotokoll', 'Tool Designer': 'Tool-Designer',
  'Support': 'Support', 'Resources': 'Ressourcen', 'Settings': 'Einstellungen',
  'Services': 'Dienste', 'Activity': 'Aktivität', 'Others': 'Sonstiges',
  'Account Settings': 'Kontoeinstellungen', 'Logout': 'Abmelden',
  'Menu': 'Menü', 'Navigation': 'Navigation', 'Quick search': 'Schnellsuche',
  'No commands found.': 'Keine Befehle gefunden.', 'No matches.': 'Keine Treffer.',
  'Type a command or search…': 'Befehl eingeben oder suchen…',
  'Go to Dashboard': 'Zur Übersicht', 'Go to Pins': 'Zu den Pins',
  'Go to Strings': 'Zu Strings', 'Go to Cheat Database': 'Zur Cheat-Datenbank',
  'Go to Forensic Tools': 'Zu den Forensik-Tools', 'Go to Activity Log': 'Zum Aktivitätsprotokoll',
  'Go to Support': 'Zum Support', 'Go to Resources': 'Zu den Ressourcen',
  'Go to Settings': 'Zu den Einstellungen',

  // ---- Generic UI verbs / labels ----
  'Save': 'Speichern', 'Save changes': 'Änderungen speichern', 'Save All': 'Alle speichern',
  'Save Rule': 'Regel speichern', 'Save strings': 'Strings speichern', 'Saved': 'Gespeichert',
  'Cancel': 'Abbrechen', 'Close': 'Schließen', 'Delete': 'Löschen', 'Edit': 'Bearbeiten',
  'Add': 'Hinzufügen', 'Add Entry': 'Eintrag hinzufügen', 'Remove': 'Entfernen',
  'Removed': 'Entfernt', 'Copy': 'Kopieren', 'Copied': 'Kopiert', 'Copy code': 'Code kopieren',
  'Copy pin': 'Pin kopieren', 'Copy Pin': 'Pin kopieren', 'Export': 'Exportieren',
  'Import': 'Importieren', 'Submit': 'Absenden', 'Update': 'Aktualisieren',
  'Create': 'Erstellen', 'Clear': 'Leeren', 'Clear all': 'Alles leeren',
  'Clear data': 'Daten löschen', 'Reset': 'Zurücksetzen', 'Test': 'Testen',
  'Validate': 'Prüfen', 'Analyze': 'Analysieren', 'Scan': 'Scannen', 'Show': 'Anzeigen',
  'Done': 'Fertig', 'Add': 'Hinzufügen', 'Upload': 'Hochladen', 'Upload File': 'Datei hochladen',
  'Download': 'Herunterladen', 'Downloading': 'Wird heruntergeladen', 'Finished': 'Fertig',
  'Search...': 'Suchen...', 'Search…': 'Suchen…', 'Disconnect': 'Trennen',
  'Show more': 'Mehr anzeigen', 'Show less': 'Weniger anzeigen', 'View plans': 'Pläne ansehen',
  'Get Started': 'Loslegen', 'Mark all read': 'Alle als gelesen markieren',
  'Mark as resolved': 'Als gelöst markieren', 'Manage Access': 'Zugriff verwalten',
  'Recycle': 'Erneuern', 'Register': 'Registrieren', 'Purchase': 'Kaufen',
  'Checkout': 'Kasse', 'Run scan now': 'Scan jetzt ausführen',
  'Open full results': 'Vollständige Ergebnisse öffnen', 'View Results': 'Ergebnisse ansehen',
  'Look Results': 'Ergebnisse ansehen', 'Report Scan': 'Scan melden',
  'Revoke All Other': 'Alle anderen widerrufen', 'Back to Pins': 'Zurück zu den Pins',
  'Back to home': 'Zurück zur Startseite', 'Change Password': 'Passwort ändern',
  'Connect Discord': 'Discord verbinden', 'Setup 2FA': '2FA einrichten',
  'Enable 2FA': '2FA aktivieren', 'Disable 2FA': '2FA deaktivieren',
  'Import backup': 'Backup importieren', 'Export backup': 'Backup exportieren',
  'Factory reset': 'Werkseinstellungen', 'Reset to defaults': 'Auf Standard zurücksetzen',
  'New Rule': 'Neue Regel', 'New Ticket': 'Neues Ticket', 'New Support Ticket': 'Neues Support-Ticket',
  'Add Cheat Entry': 'Cheat-Eintrag hinzufügen', 'Claim license': 'Lizenz einlösen',
  'Claim it here': 'Hier einlösen', 'Contact support': 'Support kontaktieren',
  'View AI opinion': 'KI-Einschätzung ansehen', 'View Final GUI': 'Finale GUI ansehen',
  'Check Risk Score': 'Risikobewertung prüfen', 'Start Ocean': 'Ocean starten',
  'Start Swimming': 'Jetzt loslegen', 'See why': 'Erfahre warum',
  'Export .txt': '.txt exportieren', 'Export CSV': 'CSV exportieren',
  'Export Style': 'Stil exportieren', 'Import Style': 'Stil importieren',
  'Export Data': 'Daten exportieren', 'Import Result': 'Ergebnis importieren',
  'Import Scan Result': 'Scan-Ergebnis importieren', 'Defaults loaded': 'Standard geladen',
  'Use Ocean logo': 'Ocean-Logo verwenden', 'Connect third-party services': 'Drittanbieter-Dienste verbinden',
  'Restore from a JSON file': 'Aus einer JSON-Datei wiederherstellen',

  // ---- Dashboard ----
  'View statistics, events, and announcements on the Ocean.': 'Statistiken, Ereignisse und Ankündigungen im Überblick.',
  'Welcome back, Ham.': 'Willkommen zurück, Ham.', 'Welcome back': 'Willkommen zurück',
  'Welcome to Ocean': 'Willkommen bei Ocean',
  'Overview of your scan activity and detection results': 'Überblick über deine Scan-Aktivität und Erkennungsergebnisse',
  'Total Scans': 'Scans gesamt', 'Detections': 'Erkennungen', 'Unique Cheats': 'Einzigartige Cheats',
  'Games Tracked': 'Erfasste Spiele', 'Games Covered': 'Abgedeckte Spiele',
  'Total Pins': 'Pins gesamt', 'Total Events': 'Ereignisse gesamt', 'Total Entries': 'Einträge gesamt',
  'Active Users': 'Aktive Nutzer', 'Scans Today': 'Scans heute', 'Daily Pins': 'Pins pro Tag',
  'Cheating Rate': 'Cheating-Rate', 'Legit Rate': 'Legit-Rate', 'Suspicious Rate': 'Verdächtig-Rate',
  'Detection Rates': 'Erkennungsraten', 'Detection Results': 'Erkennungsergebnisse',
  'Results Distribution': 'Ergebnisverteilung', 'Detections by Game': 'Erkennungen nach Spiel',
  'Scans & Detections (last 14 days)': 'Scans & Erkennungen (letzte 14 Tage)',
  'No activity yet': 'Noch keine Aktivität', 'No data': 'Keine Daten',
  'Cheating': 'Cheating', 'Suspicious': 'Verdächtig', 'Legit': 'Legitim',
  'Detected': 'Erkannt', 'Verdict': 'Urteil', 'Risk Score': 'Risikobewertung',

  // ---- Pins ----
  'View and manage your scan pins and results': 'Scan-Pins und Ergebnisse anzeigen und verwalten',
  'My Pins': 'Meine Pins', 'Create Pin': 'Pin erstellen', 'Edit Pin': 'Pin bearbeiten',
  'Delete Pin': 'Pin löschen', 'Pin Details': 'Pin-Details', 'Pin Actions': 'Pin-Aktionen',
  'Pin Code': 'Pin-Code', 'Pin Code:': 'Pin-Code:', 'Pin Status': 'Pin-Status',
  'Pin Created': 'Pin erstellt', 'Pin Created Successfully': 'Pin erfolgreich erstellt',
  'Pin created': 'Pin erstellt', 'Pin updated': 'Pin aktualisiert', 'Pin deleted': 'Pin gelöscht',
  'Pin not found': 'Pin nicht gefunden', 'Client Name': 'Kundenname',
  'Client Name required': 'Kundenname erforderlich', 'Discord ID': 'Discord-ID',
  'Discord ID:': 'Discord-ID:', 'Discord ID required': 'Discord-ID erforderlich',
  'Discord ID of the scanned user. Saved with the results.': 'Discord-ID des gescannten Nutzers. Wird mit den Ergebnissen gespeichert.',
  'Create a pin for a scan. The scanned user’s Discord ID is required and stored with the result.':
    'Erstelle einen Pin für einen Scan. Die Discord-ID des gescannten Nutzers ist erforderlich und wird mit dem Ergebnis gespeichert.',
  'Share this pin with the user so they can run the scanner against it.':
    'Teile diesen Pin mit dem Nutzer, damit er den Scanner damit ausführen kann.',
  'This pin will be available for 24 hours. Make sure you use it before it expires.':
    'Dieser Pin ist 24 Stunden lang gültig. Stelle sicher, dass du ihn vor Ablauf verwendest.',
  'List and inspect scan pins. A pin is an 8-character code bound to a scanned user (Discord ID) and game.':
    'Scan-Pins auflisten und einsehen. Ein Pin ist ein 8-stelliger Code, der an einen gescannten Nutzer (Discord-ID) und ein Spiel gebunden ist.',
  'Information about the pin details': 'Informationen zu den Pin-Details',
  'Information about the users PC': 'Informationen über den PC des Nutzers',
  'No results yet — this pin has not been scanned.': 'Noch keine Ergebnisse — dieser Pin wurde noch nicht gescannt.',
  'Waiting to be scanned': 'Wartet auf Scan', 'Scan pending': 'Scan ausstehend',
  'Scan complete': 'Scan abgeschlossen', 'Scan finished': 'Scan abgeschlossen',
  'Scan reported': 'Scan gemeldet', 'Scan result imported': 'Scan-Ergebnis importiert',
  'User already scanned': 'Nutzer bereits gescannt', 'Search by pin or name...': 'Nach Pin oder Name suchen...',
  'Your pin is in queue and waiting to be scanned…': 'Dein Pin ist in der Warteschlange und wartet auf den Scan…',
  'Pin lifecycle: Pending → Finished (or Expired after 24h).': 'Pin-Lebenszyklus: Ausstehend → Abgeschlossen (oder nach 24 Std. abgelaufen).',

  // ---- Strings / extractor / tools ----
  'Upload and analyze files for string detection.': 'Dateien hochladen und auf String-Erkennung analysieren.',
  'String Analysis': 'String-Analyse', 'String Extractor': 'String-Extraktor',
  'String List': 'String-Liste', 'String deleted': 'String gelöscht',
  'Strings saved': 'Strings gespeichert', 'Saved strings cleared': 'Gespeicherte Strings gelöscht',
  'All saved strings cleared': 'Alle gespeicherten Strings gelöscht',
  'Saved signature strings': 'Gespeicherte Signatur-Strings',
  'Saved': 'Gespeichert', 'Filter saved strings...': 'Gespeicherte Strings filtern...',
  'Filter strings...': 'Strings filtern...', 'No strings match.': 'Keine Strings stimmen überein.',
  'No saved strings yet. Analyze a file and press “Save strings”.':
    'Noch keine gespeicherten Strings. Analysiere eine Datei und drücke „Strings speichern“.',
  'Tap the trash icon next to a string to delete it. These are matched on every file analysis.':
    'Tippe auf das Papierkorb-Symbol neben einem String, um ihn zu löschen. Diese werden bei jeder Dateianalyse abgeglichen.',
  'Delete this string': 'Diesen String löschen', 'Upload a file to extract printable strings':
    'Lade eine Datei hoch, um druckbare Strings zu extrahieren',
  'Drag and drop or click': 'Ziehen und ablegen oder klicken',
  'No analysis results yet.': 'Noch keine Analyseergebnisse.', 'My Files': 'Meine Dateien',
  'Scanned files': 'Gescannte Dateien', 'Stored detection files': 'Gespeicherte Erkennungsdateien',
  'No detection files uploaded.': 'Keine Erkennungsdateien hochgeladen.',
  'Detection file added': 'Erkennungsdatei hinzugefügt', 'No files scanned yet.': 'Noch keine Dateien gescannt.',
  'Scan a file against your rules': 'Eine Datei gegen deine Regeln scannen',
  'No rules matched — file looks clean.': 'Keine Regeln getroffen — Datei sieht sauber aus.',
  'No YARA rule configured': 'Keine YARA-Regel konfiguriert',
  'Configure a YARA rule first to start scanning.': 'Konfiguriere zuerst eine YARA-Regel, um mit dem Scannen zu beginnen.',
  'Write YARA Rules': 'YARA-Regeln schreiben', 'YARA Rules': 'YARA-Regeln',
  'Rule Editor': 'Regel-Editor', 'Rule saved': 'Regel gespeichert', 'Rule Changes': 'Regeländerungen',
  'Upload for presence detection': 'Für Präsenzerkennung hochladen',
  'Compute a cryptographic hash to verify a file against VirusTotal or known databases.':
    'Berechne einen kryptografischen Hash, um eine Datei mit VirusTotal oder bekannten Datenbanken abzugleichen.',
  'SHA-256 File Hash': 'SHA-256-Datei-Hash', 'File Hash': 'Datei-Hash', 'Hash copied': 'Hash kopiert',
  'Failed to hash file': 'Datei konnte nicht gehasht werden', 'Failed to read file': 'Datei konnte nicht gelesen werden',
  'Select File Mode': 'Dateimodus wählen', 'Working Mode': 'Arbeitsmodus',
  'Signatures (comma separated)': 'Signaturen (kommagetrennt)', 'Analyzer': 'Analyzer',
  'Extractor': 'Extraktor', 'Engines': 'Engines',

  // ---- Cheat Database ----
  'Known cheats, clients and signatures': 'Bekannte Cheats, Clients und Signaturen',
  'Searchable catalogue of known cheat clients with detection signatures.':
    'Durchsuchbarer Katalog bekannter Cheat-Clients mit Erkennungssignaturen.',
  'Cheat added': 'Cheat hinzugefügt', 'Category': 'Kategorie', 'Severity': 'Schweregrad',
  'Signatures (comma separated)': 'Signaturen (kommagetrennt)',
  'Search name, signature or notes...': 'Name, Signatur oder Notizen suchen...',
  'All Severity': 'Alle Schweregrade', 'All Status': 'Alle Status', 'All Games': 'Alle Spiele',
  'All Options': 'Alle Optionen', 'All Activity': 'Alle Aktivitäten', 'All Severity': 'Alle Schweregrade',
  'No entries match your filters.': 'Keine Einträge entsprechen deinen Filtern.',

  // ---- Forensic tools / scan results ----
  'Client-side analyzers for browser history, DNS cache, system artifacts and file integrity.':
    'Clientseitige Analyzer für Browserverlauf, DNS-Cache, Systemartefakte und Dateiintegrität.',
  'Scan Results': 'Scan-Ergebnisse', 'Scan Status': 'Scan-Status',
  'Here you can see the results of the scans you have done.': 'Hier siehst du die Ergebnisse der von dir durchgeführten Scans.',
  'Select a Detection Category': 'Eine Erkennungskategorie auswählen',
  'Choose a category from the sidebar to view detailed results':
    'Wähle eine Kategorie in der Seitenleiste, um detaillierte Ergebnisse zu sehen',
  'Nothing found in this category.': 'In dieser Kategorie nichts gefunden.',
  'Nothing found in this category': 'In dieser Kategorie nichts gefunden',
  'No detections in the previous scan.': 'Keine Erkennungen im vorherigen Scan.',
  'No screenshot available': 'Kein Screenshot verfügbar',
  'No screenshot available for this scan': 'Für diesen Scan ist kein Screenshot verfügbar',
  'Previous Scan Found': 'Vorheriger Scan gefunden',
  'This Discord ID was already scanned. Here are the results of the previous scan.':
    'Diese Discord-ID wurde bereits gescannt. Hier sind die Ergebnisse des vorherigen Scans.',
  'Location': 'Ort', 'Evidence': 'Beweis', 'Impact': 'Auswirkung', 'AI Opinion': 'KI-Einschätzung',
  'Automated assessment': 'Automatisierte Bewertung', 'Heuristic analysis text': 'Heuristische Analyse',
  'Detection guidance': 'Erkennungshinweise', 'Forensic Detections': 'Forensische Erkennungen',
  'Boot Time': 'Startzeit', 'Boot sequence': 'Startsequenz', 'No boot sequence recorded.': 'Keine Startsequenz aufgezeichnet.',
  'Measured Boot Chain': 'Gemessene Boot-Kette', 'Recorded boot sequence detail for this machine.':
    'Aufgezeichnete Startsequenz-Details für diesen Rechner.',
  'Executable List': 'Programmliste', 'Executed At': 'Ausgeführt am',
  'Executed applications Timestamps': 'Zeitstempel ausgeführter Anwendungen',
  'Execution activity': 'Ausführungsaktivität', 'Processes executed during the scan': 'Während des Scans ausgeführte Prozesse',
  'Admin-Executed Applications': 'Mit Admin-Rechten ausgeführte Anwendungen',
  'Applications launched with administrator privileges during the scan window':
    'Anwendungen, die während des Scan-Zeitfensters mit Administratorrechten gestartet wurden',
  'Last Computer Activity': 'Letzte Computeraktivität', 'Recent system file operations and executions':
    'Aktuelle Systemdatei-Operationen und -Ausführungen',
  'MFT Records': 'MFT-Einträge', 'Master File Table records & information': 'Master-File-Table-Einträge & -Informationen',
  'Compilation Dates': 'Kompilierungsdaten', 'Compilation dates': 'Kompilierungsdaten',
  'No Compilation dates data found': 'Keine Kompilierungsdaten gefunden',
  'Mods Logs': 'Mods-Protokolle', 'Mods detected in the system': 'Im System erkannte Mods',
  'No mods found': 'Keine Mods gefunden', 'Recording Software': 'Aufnahmesoftware',
  'Screen recording or capture software detected': 'Bildschirmaufnahme- oder Capture-Software erkannt',
  'No recording software found': 'Keine Aufnahmesoftware gefunden',
  'Discord Accounts': 'Discord-Konten', 'Discord accounts detected on this system': 'Auf diesem System erkannte Discord-Konten',
  'No Discord accounts found': 'Keine Discord-Konten gefunden',
  'Alternative accounts detected': 'Alternative Konten erkannt', 'No alternative accounts found': 'Keine alternativen Konten gefunden',
  'Browser History': 'Browserverlauf', 'DNS Cache': 'DNS-Cache', 'System Artifacts': 'Systemartefakte',
  'Suspicious Files': 'Verdächtige Dateien', 'Suspicious Files:': 'Verdächtige Dateien:',
  'Detection Files:': 'Erkennungsdateien:', 'File executions & obtained data': 'Dateiausführungen & gewonnene Daten',
  'Hardware Stats': 'Hardware-Statistiken', 'Device Info': 'Geräteinfo', 'PC Information': 'PC-Informationen',
  'User PC': 'Nutzer-PC', 'User': 'Nutzer', 'Install Date': 'Installationsdatum',
  'Presence Detection': 'Präsenzerkennung', 'Screenshare & forensic helpers': 'Screenshare- & Forensik-Helfer',
  'Screenshare Tool': 'Screenshare-Tool',
  'USB Activity': 'USB-Aktivität',
  'Removable / USB storage recently connected or removed, and what was on it':
    'Wechseldatenträger / USB-Speicher, der kürzlich angeschlossen oder entfernt wurde, und was darauf war',
  'No USB activity recorded.': 'Keine USB-Aktivität aufgezeichnet.',
  'Contents not recorded for this device.': 'Inhalt für dieses Gerät nicht aufgezeichnet.',
  'Connected': 'Angeschlossen', 'Mounted': 'Eingebunden', 'Seen': 'Gesehen',
  'Serial:': 'Seriennr.:', 'IP Address': 'IP-Adresse', 'Not available': 'Nicht verfügbar',
  'Discord Server': 'Discord-Server',
  'Servers the scanned Discord account is in — reselling and cheat servers are flagged':
    'Server, in denen der gescannte Discord-Account ist — Reselling- und Cheat-Server werden markiert',
  'No Discord servers found': 'Keine Discord-Server gefunden',
  'Cheat Discord': 'Cheat-Discord', 'Reselling Discord': 'Reselling-Discord',
  'Member': 'Mitglied', 'flagged ·': 'markiert ·', 'total': 'gesamt', 'suspicious ·': 'verdächtig ·',
  'Discord ID': 'Discord-ID', 'Discord ID Server Checker': 'Discord-ID-Server-Checker',
  'Enter only a Discord ID. Decodes the account creation date and aggregates the servers detected in past scans bound to this ID — reselling and cheat servers are flagged. Results are sent to the webhook configured in Settings.':
    'Gib nur eine Discord-ID ein. Dekodiert das Konto-Erstellungsdatum und fasst die in früheren Scans erkannten Server zusammen, die an diese ID gebunden sind — Reselling- und Cheat-Server werden markiert. Die Ergebnisse werden an den in den Einstellungen hinterlegten Webhook gesendet.',
  'Check & Send': 'Prüfen & Senden', 'Sending…': 'Senden…',
  'No webhook configured in Settings → Integrations.': 'Kein Webhook in Einstellungen → Integrationen konfiguriert.',
  'Account created': 'Konto erstellt', 'Scans on record': 'Scans im Verlauf',
  'Flagged servers': 'Markierte Server',
  'No server data on record for this ID. Run a scan with a pin bound to this Discord ID.':
    'Keine Server-Daten für diese ID vorhanden. Führe einen Scan mit einem Pin durch, der an diese Discord-ID gebunden ist.',
  'Sent to webhook': 'An Webhook gesendet', 'Webhook failed': 'Webhook fehlgeschlagen',
  'No webhook configured': 'Kein Webhook konfiguriert',
  'Add a Discord webhook in Settings → Integrations.': 'Füge in Einstellungen → Integrationen einen Discord-Webhook hinzu.',
  'Invalid Discord ID': 'Ungültige Discord-ID',
  'Enter a numeric Discord ID (17–20 digits).': 'Gib eine numerische Discord-ID ein (17–20 Ziffern).',

  // ---- Account / settings ----
  'Manage your account settings and preferences': 'Verwalte deine Kontoeinstellungen und Präferenzen',
  'General': 'Allgemein', 'Appearance': 'Darstellung', 'Security': 'Sicherheit',
  'Connections': 'Verbindungen', 'Sessions': 'Sitzungen', 'Billing': 'Abrechnung',
  'Integrations': 'Integrationen', 'Privacy & Data': 'Datenschutz & Daten',
  'Preferences & data': 'Präferenzen & Daten', 'Profile saved': 'Profil gespeichert',
  'Your account profile.': 'Dein Kontoprofil.', 'Your current plan.': 'Dein aktueller Plan.',
  'Display name': 'Anzeigename', 'Email': 'E-Mail', 'Country': 'Land',
  'Theme': 'Design', 'Theme and language settings.': 'Design- und Spracheinstellungen.',
  'Theme and language.': 'Design und Sprache.', 'Language': 'Sprache',
  'Interface language': 'Sprache der Oberfläche', 'Dark or light interface': 'Dunkle oder helle Oberfläche',
  'Default Game': 'Standardspiel', 'Pre-selected when creating pins': 'Beim Erstellen von Pins vorausgewählt',
  'Two-Factor Authentication': 'Zwei-Faktor-Authentifizierung', '2FA enabled': '2FA aktiviert',
  '2FA disabled': '2FA deaktiviert', 'Set up Two-Factor Authentication': 'Zwei-Faktor-Authentifizierung einrichten',
  'Add this secret to your authenticator app (TOTP):': 'Füge dieses Geheimnis zu deiner Authenticator-App hinzu (TOTP):',
  'Secret copied': 'Geheimnis kopiert', 'Passkeys': 'Passkeys', 'No Passkeys': 'Keine Passkeys',
  'Passkey': 'Passkey', 'Passkey added': 'Passkey hinzugefügt', 'Passkey removed': 'Passkey entfernt',
  'Add a passkey for faster sign-in.': 'Füge einen Passkey für schnellere Anmeldung hinzu.',
  'Passwordless authentication': 'Passwortlose Authentifizierung',
  'Change your password to keep your account secure': 'Ändere dein Passwort, um dein Konto sicher zu halten',
  'Current password': 'Aktuelles Passwort', 'New password': 'Neues Passwort',
  'Confirm new password': 'Neues Passwort bestätigen', 'Password changed': 'Passwort geändert',
  'Password reset': 'Passwort zurückgesetzt', 'Password too short': 'Passwort zu kurz',
  'Passwords do not match': 'Passwörter stimmen nicht überein', 'Password': 'Passwort',
  'Connected Accounts': 'Verbundene Konten', 'Connect your accounts to enable additional features and seamless integration.':
    'Verbinde deine Konten, um zusätzliche Funktionen und nahtlose Integration zu aktivieren.',
  'No accounts connected with Ocean yet.': 'Noch keine Konten mit Ocean verbunden.',
  'Discord connected': 'Discord verbunden', 'Disconnected': 'Getrennt', 'Connected': 'Verbunden',
  'Current Session': 'Aktuelle Sitzung', 'Other Sessions': 'Andere Sitzungen',
  'Session Details': 'Sitzungsdetails', 'Sessions, IPs, devices': 'Sitzungen, IPs, Geräte',
  'No other active sessions.': 'Keine anderen aktiven Sitzungen.',
  'Session revoked': 'Sitzung widerrufen', 'All other sessions revoked': 'Alle anderen Sitzungen widerrufen',
  'Current': 'Aktuell', 'Audit trail of everything you do': 'Prüfprotokoll all deiner Aktionen',
  'Your current plan.': 'Dein aktueller Plan.', 'Free plan': 'Kostenloser Plan',
  'API Integrations': 'API-Integrationen', 'API Key': 'API-Schlüssel', 'API key saved': 'API-Schlüssel gespeichert',
  'Discord Webhook': 'Discord-Webhook', 'Webhook URL': 'Webhook-URL', 'Webhook saved': 'Webhook gespeichert',
  'Webhook removed': 'Webhook entfernt', 'Discord notifications': 'Discord-Benachrichtigungen',
  'VirusTotal API': 'VirusTotal-API', 'VirusTotal intelligence': 'VirusTotal-Informationen',
  'Enter VirusTotal API key': 'VirusTotal-API-Schlüssel eingeben', 'Keys are encrypted.': 'Schlüssel sind verschlüsselt.',
  'Connect third-party services': 'Drittanbieter-Dienste verbinden',
  'Data Management': 'Datenverwaltung', 'Data to Export': 'Zu exportierende Daten',
  'Select data to export': 'Daten zum Export auswählen', 'Download all data as JSON': 'Alle Daten als JSON herunterladen',
  'Export your data. Everything is stored locally in your browser.':
    'Exportiere deine Daten. Alles wird lokal in deinem Browser gespeichert.',
  'Everything is stored locally in your browser.': 'Alles wird lokal in deinem Browser gespeichert.',
  'Include Security Data': 'Sicherheitsdaten einschließen', 'Account and Platform Data': 'Konto- und Plattformdaten',
  'Data exported': 'Daten exportiert', 'Data cleared': 'Daten gelöscht', 'Backup exported': 'Backup exportiert',
  'Backup restored': 'Backup wiederhergestellt', 'Invalid backup file': 'Ungültige Backup-Datei',
  'Report exported': 'Bericht exportiert', 'All changes saved': 'Alle Änderungen gespeichert',
  'Restore demo seed data': 'Demo-Beispieldaten wiederherstellen',
  'Wipe pins, scans and files (keeps settings)': 'Pins, Scans und Dateien löschen (Einstellungen bleiben)',
  'Reset complete': 'Zurücksetzen abgeschlossen', 'Visibility': 'Sichtbarkeit',
  'Public': 'Öffentlich', 'Private': 'Privat', 'Notes': 'Notizen', 'Status': 'Status',
  'Notifications': 'Benachrichtigungen', 'No notifications': 'Keine Benachrichtigungen',
  'Nothing new': 'Nichts Neues', 'Now': 'Jetzt', 'Online': 'Online', 'Active': 'Aktiv',
  'Storage': 'Speicher', 'Built-in': 'Integriert', 'Custom': 'Benutzerdefiniert',
  'System': 'System', 'Type': 'Typ', 'Name': 'Name', 'Name required': 'Name erforderlich',
  'Color': 'Farbe', 'Colours': 'Farben', 'Spacing': 'Abstand', 'Typography': 'Typografie',
  'Actions': 'Aktionen', 'Version': 'Version', 'Version label': 'Versionsbezeichnung',
  'Created': 'Erstellt', 'Used': 'Verwendet', 'Expired': 'Abgelaufen', 'Pending': 'Ausstehend',
  'Unknown': 'Unbekannt', 'About': 'Über', 'Product': 'Produkt', 'Build': 'Build',

  // ---- Login / landing / public ----
  'Login': 'Anmelden', 'Sign Up': 'Registrieren', 'Register': 'Registrieren',
  'Email or Username': 'E-Mail oder Benutzername', 'Forgot your password?': 'Passwort vergessen?',
  'Enter your credentials to access your account': 'Gib deine Anmeldedaten ein, um auf dein Konto zuzugreifen',
  'OR CONTINUE WITH': 'ODER FORTFAHREN MIT', 'Invalid credentials': 'Ungültige Anmeldedaten',
  'Registration closed': 'Registrierung geschlossen', 'Get Started': 'Loslegen',
  'A reliable solution against cheaters': 'Eine zuverlässige Lösung gegen Cheater',
  'How Ocean works': 'So funktioniert Ocean', 'Discover the key features of Ocean': 'Entdecke die wichtigsten Funktionen von Ocean',
  'Features': 'Funktionen', 'Community': 'Community', 'Team': 'Team', 'Docs': 'Doku',
  'Frequently Asked Questions': 'Häufig gestellte Fragen', 'Join our Community': 'Tritt unserer Community bei',
  'Growing Community': 'Wachsende Community', 'Privacy Focused': 'Datenschutzorientiert',
  'Complete Documentation': 'Vollständige Dokumentation', '24/7 Active Support': 'Aktiver Support rund um die Uhr',
  'Effortlessly scan suspects in seconds with two simple clicks that handle everything automatically.':
    'Scanne Verdächtige mühelos in Sekunden mit zwei einfachen Klicks, die alles automatisch erledigen.',
  'Analyze the results on our dashboard and reach a final verdict on the suspect with confidence!':
    'Analysiere die Ergebnisse in unserem Dashboard und fälle mit Sicherheit ein endgültiges Urteil über den Verdächtigen!',
  'Let Ocean take care of all the hard work for you. Simply wait a few seconds while our advanced technology processes everything and delivers accurate results quickly and effortlessly.':
    'Lass Ocean die ganze harte Arbeit für dich erledigen. Warte einfach ein paar Sekunden, während unsere fortschrittliche Technologie alles verarbeitet und schnell sowie mühelos präzise Ergebnisse liefert.',
  'Powered by cutting-edge AI and expert digital forensics, we provide precise, trustworthy cheat detection results.':
    'Angetrieben von modernster KI und Experten der digitalen Forensik liefern wir präzise, vertrauenswürdige Cheat-Erkennungsergebnisse.',
  'Our detections are powered by deep expertise in digital forensics and an advanced understanding of operating systems.':
    'Unsere Erkennungen basieren auf tiefem Fachwissen in digitaler Forensik und einem fortgeschrittenen Verständnis von Betriebssystemen.',
  'Ocean prioritizes completing scans within a strict time frame, averaging around 60 seconds for comprehensive cheat detection.':
    'Ocean priorisiert den Abschluss von Scans innerhalb eines strengen Zeitrahmens — im Schnitt rund 60 Sekunden für eine umfassende Cheat-Erkennung.',
  'Ocean is secured with military-grade encryption — because security comes first, and it':
    'Ocean ist mit Verschlüsselung auf Militärniveau gesichert — denn Sicherheit steht an erster Stelle, und sie',
  'With future-focused security, we ensure every trace of information remains completely protected and encrypted.':
    'Mit zukunftsorientierter Sicherheit stellen wir sicher, dass jede Spur von Informationen vollständig geschützt und verschlüsselt bleibt.',
  'Ocean offers customizations ranging from simple design tweaks to real-time threat detection — all as part of our service.':
    'Ocean bietet Anpassungen von einfachen Design-Optimierungen bis hin zur Echtzeit-Bedrohungserkennung — alles als Teil unseres Dienstes.',
  'Our community is constantly growing, with 500+ active servers and dedicated members ready to help you!':
    'Unsere Community wächst ständig — mit über 500 aktiven Servern und engagierten Mitgliedern, die dir gerne helfen!',
  'Join our Discord for support.': 'Tritt für Support unserem Discord bei.',
  'Link Discord for more': 'Discord für mehr verknüpfen', 'Answer your': 'Beantworte deine',
  'Think.': 'Denken.', 'Scan.': 'Scannen.', 'Find.': 'Finden.', 'Think. Scan. Find.': 'Denken. Scannen. Finden.',
  'Rise': 'Aufstieg', 'Most': 'Am meisten', 'More than': 'Mehr als', 'See why': 'Erfahre warum',
  'Let\'s solve that.': 'Lösen wir das.', 'Can\'t run Ocean?': 'Ocean lässt sich nicht starten?',
  'Need More Help?': 'Brauchst du mehr Hilfe?', 'Browse FAQs or open a support ticket.':
    'Durchsuche die FAQ oder eröffne ein Support-Ticket.',
  'A reliable solution against cheaters': 'Eine zuverlässige Lösung gegen Cheater',

  // ---- Support ----
  'Browse FAQs or open a support ticket.': 'Durchsuche die FAQ oder eröffne ein Support-Ticket.',
  'Get help & open tickets': 'Hilfe erhalten & Tickets eröffnen', 'New Support Ticket': 'Neues Support-Ticket',
  'No tickets yet': 'Noch keine Tickets', 'Subject': 'Betreff', 'Message': 'Nachricht',
  'Priority': 'Priorität', 'Describe your issue…': 'Beschreibe dein Problem…',
  'Short summary': 'Kurze Zusammenfassung', 'Subject and message required': 'Betreff und Nachricht erforderlich',
  'Ticket submitted': 'Ticket eingereicht', 'Contact support': 'Support kontaktieren',
  'Contact Information': 'Kontaktinformationen', 'Contact for Support': 'Kontakt für Support',

  // ---- Resources: hero subtitles & shared ----
  'Leaderboard': 'Bestenliste', 'Ranking is computed live from your own scan data.':
    'Das Ranking wird live aus deinen eigenen Scan-Daten berechnet.',
  'Games by Detections': 'Spiele nach Erkennungen', 'No scan data yet.': 'Noch keine Scan-Daten.',
  'Documentation': 'Dokumentation', 'Guides, references and API details for Ocean Anti-Cheat':
    'Anleitungen, Referenzen und API-Details für Ocean Anti-Cheat',
  'Pricing': 'Preise', 'Plans & limits — pick the plan that fits your community':
    'Pläne & Limits — wähle den Plan, der zu deiner Community passt',
  'Start Detecting': 'Jetzt erkennen', 'Download Ocean for your platform — available for Windows & Linux':
    'Lade Ocean für deine Plattform herunter — verfügbar für Windows & Linux',
  'Download Ocean': 'Ocean herunterladen', 'Changelog': 'Änderungsprotokoll', 'Changelogs': 'Änderungsprotokolle',
  'Stay up to date with the latest updates, improvements and new features of Ocean':
    'Bleibe auf dem Laufenden über die neuesten Updates, Verbesserungen und neuen Funktionen von Ocean',
  'Legal': 'Rechtliches', 'Legal Agreement': 'Rechtliche Vereinbarung',
  'Terms and conditions governing the use of Ocean Anti-Cheat services':
    'Geschäftsbedingungen für die Nutzung der Ocean-Anti-Cheat-Dienste',
  'Privacy Policy': 'Datenschutzerklärung', 'How Ocean Anti-Cheat collects, uses and protects data':
    'Wie Ocean Anti-Cheat Daten erhebt, verwendet und schützt',
  'Legal Notice': 'Impressum', 'Impressum, transparency & company information for Ocean Anti-Cheat':
    'Impressum, Transparenz & Unternehmensinformationen zu Ocean Anti-Cheat',
  'Terms of Service': 'Nutzungsbedingungen', 'Table of Contents': 'Inhaltsverzeichnis',
  'Versions': 'Versionen', 'PIN Required': 'PIN erforderlich', 'Enter your PIN code': 'Gib deinen PIN-Code ein',
  'Invalid PIN': 'Ungültige PIN', 'Session downloaded': 'Sitzung heruntergeladen',
  'Advanced cheat detection': 'Fortschrittliche Cheat-Erkennung',
  'Cheat detection for Linux systems': 'Cheat-Erkennung für Linux-Systeme',
  'Bypass blocks preventing Ocean from running': 'Umgeht Sperren, die Ocean am Ausführen hindern',
  'Have a pending license?': 'Hast du eine ausstehende Lizenz?',
  'Personal Plans': 'Privat-Pläne', 'Enterprise Plans': 'Unternehmens-Pläne',
  'Demo pricing — no payment processing is wired up.': 'Demo-Preise — es ist keine Zahlungsabwicklung angebunden.',
  'Specific license that supports scans for the game FiveM, including its respective detection modules.':
    'Spezielle Lizenz, die Scans für das Spiel FiveM einschließlich der zugehörigen Erkennungsmodule unterstützt.',
  'Team license for organisations. Supports FiveM scans across multiple operators.':
    'Team-Lizenz für Organisationen. Unterstützt FiveM-Scans über mehrere Operatoren hinweg.',
  'Troubleshooting': 'Fehlerbehebung', 'VC++ Runtime Error': 'VC++-Laufzeitfehler',
  'Download and install vcredist (x64)': 'vcredist (x64) herunterladen und installieren',
  'Restart your computer.': 'Starte deinen Computer neu.', 'Try running Ocean again.': 'Versuche, Ocean erneut zu starten.',
  'Contact support if persists.': 'Kontaktiere den Support, falls das Problem bestehen bleibt.',

  // Terms preface + sections
  'This Terms and Conditions of Use (“Agreement”) is a legally binding agreement between “us” or “we” and the entity or person (“you”, “your”, or “user”) that registered an account to receive cheat detection services (“Services”).':
    'Diese Nutzungsbedingungen („Vereinbarung“) sind eine rechtlich bindende Vereinbarung zwischen „uns“ bzw. „wir“ und der Einrichtung oder Person („du“, „dein“ oder „Nutzer“), die ein Konto registriert hat, um Cheat-Erkennungsdienste („Dienste“) zu erhalten.',
  'Ocean reserves the right to make modifications to this Agreement at any time. Unless otherwise specified, any modifications will take effect the day they are posted to this page.':
    'Ocean behält sich das Recht vor, diese Vereinbarung jederzeit zu ändern. Sofern nicht anders angegeben, treten Änderungen an dem Tag in Kraft, an dem sie auf dieser Seite veröffentlicht werden.',
  'By accessing or utilizing our Services, you acknowledge and agree to abide by these Terms. If you do not accept these Terms, we kindly ask that you refrain from using our Services.':
    'Durch den Zugriff auf oder die Nutzung unserer Dienste erkennst du diese Bedingungen an und stimmst zu, sie einzuhalten. Wenn du diese Bedingungen nicht akzeptierst, bitten wir dich, unsere Dienste nicht zu nutzen.',
  'Description of the Software': 'Beschreibung der Software', 'Use of Ocean': 'Nutzung von Ocean',
  'Intellectual Property': 'Geistiges Eigentum', 'Disclaimer of Warranty': 'Gewährleistungsausschluss',
  'Modification of Terms': 'Änderung der Bedingungen', 'Prohibited Activities and Enforcement': 'Verbotene Aktivitäten und Durchsetzung',
  'Appeals Process': 'Einspruchsverfahren', 'Data Collection and Privacy': 'Datenerhebung und Datenschutz',
  'Self-Scanning Limitations': 'Einschränkungen beim Selbst-Scan', 'Termination of Use': 'Beendigung der Nutzung',
  'Chargebacks and Reversals': 'Rückbuchungen und Stornierungen',
  'Ocean is a post-mortem anti-cheat and screenshare assistance framework. It inspects processes, modules, files and system artifacts on a consenting user’s machine and reports indicators of cheating to the operator who initiated the scan.':
    'Ocean ist ein Post-mortem-Anti-Cheat- und Screenshare-Hilfsframework. Es untersucht Prozesse, Module, Dateien und Systemartefakte auf dem Rechner eines einwilligenden Nutzers und meldet Indikatoren für Cheating an den Operator, der den Scan ausgelöst hat.',
  'The Ocean Monthly/Yearly/Lifetime License and the Ocean Enterprise License, collectively “The Licenses”, are classified as Products. A License can be a Personal Licence or an Enterprise Licence.':
    'Die Ocean-Monats-/Jahres-/Lifetime-Lizenz und die Ocean-Enterprise-Lizenz, zusammen „die Lizenzen“, werden als Produkte eingestuft. Eine Lizenz kann eine Privat-Lizenz oder eine Enterprise-Lizenz sein.',
  'Ocean may only be used to scan a device with the explicit, informed consent of that device’s owner. Operators are responsible for obtaining consent and for moderation decisions made from results.':
    'Ocean darf nur verwendet werden, um ein Gerät mit der ausdrücklichen, informierten Einwilligung des Geräteeigentümers zu scannen. Operatoren sind für das Einholen der Einwilligung und für Moderationsentscheidungen auf Basis der Ergebnisse verantwortlich.',
  'A Personal Licence is granted to an individual upon payment and may not be shared. An Enterprise Licence provides operator slots for an organisation.':
    'Eine Privat-Lizenz wird einer Einzelperson gegen Zahlung gewährt und darf nicht geteilt werden. Eine Enterprise-Lizenz stellt Operator-Slots für eine Organisation bereit.',
  'All Ocean software, branding, signatures and documentation are the intellectual property of Ocean and its licensors. Cheat client names are referenced solely for detection and education.':
    'Sämtliche Ocean-Software, -Branding, -Signaturen und -Dokumentation sind geistiges Eigentum von Ocean und seinen Lizenzgebern. Cheat-Client-Namen werden ausschließlich zur Erkennung und Aufklärung genannt.',
  'Scan data produced by the scanner is delivered to the operator who initiated the scan. This dashboard stores all data locally; no scan content is transmitted to Ocean unless the operator configures their own backend.':
    'Die vom Scanner erzeugten Scan-Daten werden an den Operator geliefert, der den Scan ausgelöst hat. Dieses Dashboard speichert alle Daten lokal; es werden keine Scan-Inhalte an Ocean übertragen, es sei denn, der Operator konfiguriert ein eigenes Backend.',
  'The Services are provided “as is” without warranty. Usermode scanning cannot detect kernel-mode, DMA or external (second-PC) cheats. Detection results are indicators and must not be treated as conclusive proof.':
    'Die Dienste werden „wie besehen“ ohne Gewährleistung bereitgestellt. Usermode-Scans können keine Kernel-Mode-, DMA- oder externen (Zweit-PC-)Cheats erkennen. Erkennungsergebnisse sind Indikatoren und dürfen nicht als endgültiger Beweis behandelt werden.',
  'Ocean reserves the right to modify this Agreement at any time. Modifications take effect the day they are posted. Continued use constitutes acceptance.':
    'Ocean behält sich das Recht vor, diese Vereinbarung jederzeit zu ändern. Änderungen treten am Tag ihrer Veröffentlichung in Kraft. Die fortgesetzte Nutzung gilt als Zustimmung.',
  'You may not scan devices without consent, harass individuals, reverse-engineer the software, or redistribute licenses. Violations may result in immediate termination without refund.':
    'Du darfst keine Geräte ohne Einwilligung scannen, keine Personen belästigen, die Software nicht zurückentwickeln und keine Lizenzen weiterverbreiten. Verstöße können zur sofortigen Kündigung ohne Rückerstattung führen.',
  'A user subjected to a scan may request a review through the operator. Operators may escalate disputed detections via Support; Ocean reviews evidence and methodology, not the moderation decision itself.':
    'Ein gescannter Nutzer kann über den Operator eine Überprüfung beantragen. Operatoren können strittige Erkennungen über den Support eskalieren; Ocean prüft Beweise und Methodik, nicht die Moderationsentscheidung selbst.',
  'A scanned user’s Discord ID is stored with the pin to correlate repeat scans. No analytics or third-party trackers are used by this dashboard.':
    'Die Discord-ID eines gescannten Nutzers wird mit dem Pin gespeichert, um wiederholte Scans zuzuordnen. Dieses Dashboard verwendet keine Analyse- oder Drittanbieter-Tracker.',
  'Scanning your own machine for testing is permitted, but results may differ from a genuine screenshare scenario and should not be used to certify third parties.':
    'Das Scannen des eigenen Rechners zu Testzwecken ist erlaubt, die Ergebnisse können jedoch von einem echten Screenshare-Szenario abweichen und sollten nicht zur Zertifizierung Dritter verwendet werden.',
  'Ocean may suspend or terminate access for breach of these Terms. Upon termination your right to use the Services ends immediately; locally stored data remains under your control.':
    'Ocean kann den Zugriff bei Verstoß gegen diese Bedingungen aussetzen oder beenden. Mit der Beendigung endet dein Recht zur Nutzung der Dienste sofort; lokal gespeicherte Daten bleiben unter deiner Kontrolle.',
  'Initiating a chargeback without first contacting support results in permanent termination of all associated licenses and accounts.':
    'Das Einleiten einer Rückbuchung, ohne zuvor den Support zu kontaktieren, führt zur dauerhaften Kündigung aller zugehörigen Lizenzen und Konten.',

  // Privacy sections + bodies
  'GDPR compliance verification:': 'DSGVO-Konformitätsnachweis:',
  'Types of Data we Collect': 'Arten der von uns erhobenen Daten',
  'Data Usage and Processing': 'Datennutzung und -verarbeitung', 'Data Retention': 'Datenaufbewahrung',
  'Data Security': 'Datensicherheit', 'Data Storage Location': 'Speicherort der Daten',
  'Links to Other Sites': 'Links zu anderen Seiten', "Children's Privacy": 'Datenschutz für Kinder',
  'Your Privacy Rights': 'Deine Datenschutzrechte', 'Legal Basis for Processing': 'Rechtsgrundlage der Verarbeitung',
  'International Data Protection': 'Internationaler Datenschutz', 'Data Protection Measures': 'Datenschutzmaßnahmen',
  'Data Breach Procedures': 'Verfahren bei Datenschutzverletzungen', 'Third-Party Service Providers': 'Drittanbieter-Dienstleister',
  'Business Transfers': 'Unternehmensübertragungen', 'COPPA Compliance': 'COPPA-Konformität',
  'Dispute Resolution': 'Streitbeilegung', 'Additional Rights and Questions': 'Weitere Rechte und Fragen',
  'Scanner Usage': 'Scanner-Nutzung', 'Security Research Program': 'Sicherheitsforschungsprogramm',
  'Service Improvements': 'Dienstverbesserungen', 'Account and Platform Data': 'Konto- und Plattformdaten',
  'User Registration Information:': 'Registrierungsinformationen des Nutzers:',
  'Authentication Data:': 'Authentifizierungsdaten:', 'Email address:': 'E-Mail-Adresse:',
  'Discord ID:': 'Discord-ID:', 'Nametag:': 'Nametag:', 'IP Addresses:': 'IP-Adressen:',
  'User Agent:': 'User-Agent:', 'Used for account verification': 'Wird zur Kontoverifizierung verwendet',
  'Required for communications': 'Erforderlich für die Kommunikation', 'Encrypted storage': 'Verschlüsselte Speicherung',
  'Retained for account duration': 'Wird für die Dauer des Kontos aufbewahrt',
  'Service integration': 'Dienst-Integration', 'Support communications': 'Support-Kommunikation',
  'Community features': 'Community-Funktionen', 'Public identification': 'Öffentliche Identifizierung',
  'Community interaction': 'Community-Interaktion', 'User recognition': 'Nutzererkennung',
  'Login security': 'Anmeldesicherheit', 'Fraud prevention': 'Betrugsprävention',
  '90-day retention': '90 Tage Aufbewahrung', 'Session integrity': 'Sitzungsintegrität',
  'Abuse detection': 'Missbrauchserkennung', 'Diagnostics': 'Diagnose',
  'Data is processed only to deliver cheat-detection services and account functions.':
    'Daten werden ausschließlich zur Bereitstellung von Cheat-Erkennungsdiensten und Kontofunktionen verarbeitet.',
  'Scan results are tied to the operator who initiated the scan.':
    'Scan-Ergebnisse sind an den Operator gebunden, der den Scan ausgelöst hat.',
  'No automated decision-making with legal effect is performed.':
    'Es findet keine automatisierte Entscheidungsfindung mit Rechtswirkung statt.',
  'Account data: retained for the lifetime of the account.':
    'Kontodaten: werden für die Lebensdauer des Kontos aufbewahrt.',
  'IP / authentication logs: 90 days.': 'IP-/Authentifizierungsprotokolle: 90 Tage.',
  'Scan results: retained by the operator on their own device (localStorage).':
    'Scan-Ergebnisse: werden vom Operator auf dem eigenen Gerät aufbewahrt (localStorage).',
  'Encryption in transit and at rest for account data.':
    'Verschlüsselung von Kontodaten bei Übertragung und Speicherung.',
  'Principle of least privilege for internal access.':
    'Prinzip der minimalen Rechtevergabe für internen Zugriff.',
  'This dashboard keeps all scan data client-side.': 'Dieses Dashboard hält alle Scan-Daten clientseitig.',
  'Account infrastructure is hosted within the EU/EEA where possible.':
    'Die Konto-Infrastruktur wird, wo möglich, innerhalb der EU/des EWR gehostet.',
  'Dashboard scan data never leaves the user’s browser.':
    'Dashboard-Scan-Daten verlassen niemals den Browser des Nutzers.',
  'Our services may link to third-party sites (e.g. Discord). We are not responsible for the privacy practices of external sites.':
    'Unsere Dienste können auf Drittanbieter-Seiten verlinken (z. B. Discord). Wir sind nicht für die Datenschutzpraktiken externer Seiten verantwortlich.',
  'Ocean is not directed to children under 16. We do not knowingly collect data from minors. See COPPA Compliance below.':
    'Ocean richtet sich nicht an Kinder unter 16 Jahren. Wir erheben nicht wissentlich Daten von Minderjährigen. Siehe COPPA-Konformität unten.',
  'Right of access, rectification and erasure.': 'Recht auf Auskunft, Berichtigung und Löschung.',
  'Right to restrict or object to processing.': 'Recht auf Einschränkung oder Widerspruch gegen die Verarbeitung.',
  'Right to data portability.': 'Recht auf Datenübertragbarkeit.',
  'Right to lodge a complaint with a supervisory authority.':
    'Recht auf Beschwerde bei einer Aufsichtsbehörde.',
  'Processing is based on contract performance, legitimate interest in fraud prevention, and consent where required.':
    'Die Verarbeitung beruht auf Vertragserfüllung, berechtigtem Interesse an der Betrugsprävention und, soweit erforderlich, auf Einwilligung.',
  'Where data is transferred outside the EEA, appropriate safeguards (SCCs) are applied.':
    'Werden Daten außerhalb des EWR übertragen, werden geeignete Garantien (SCCs) angewendet.',
  'Hardened infrastructure and monitoring.': 'Gehärtete Infrastruktur und Überwachung.',
  'Regular dependency and security review.': 'Regelmäßige Abhängigkeits- und Sicherheitsprüfung.',
  'Tamper-evident scan tokens.': 'Manipulationssichere Scan-Tokens.',
  'In the event of a breach affecting personal data, affected users and the competent authority will be notified within 72 hours where required by law.':
    'Im Falle einer Verletzung personenbezogener Daten werden betroffene Nutzer und die zuständige Behörde, sofern gesetzlich vorgeschrieben, innerhalb von 72 Stunden benachrichtigt.',
  'Payment processing via a Merchant of Record.': 'Zahlungsabwicklung über einen Merchant of Record.',
  'Discord for authentication & community.': 'Discord für Authentifizierung & Community.',
  'No advertising or analytics processors.': 'Keine Werbe- oder Analyse-Dienstleister.',
  'If Ocean is involved in a merger or acquisition, data may be transferred subject to this policy.':
    'Sollte Ocean an einer Fusion oder Übernahme beteiligt sein, können Daten gemäß dieser Richtlinie übertragen werden.',
  'We comply with the Children’s Online Privacy Protection Act. Accounts identified as belonging to children under 13 will be removed.':
    'Wir halten den Children’s Online Privacy Protection Act ein. Konten, die als zu Kindern unter 13 Jahren gehörig identifiziert werden, werden entfernt.',
  'Disputes are handled via the Support page first; unresolved matters are subject to the governing law stated in the Legal Agreement.':
    'Streitigkeiten werden zunächst über die Support-Seite behandelt; ungelöste Angelegenheiten unterliegen dem in der Rechtlichen Vereinbarung genannten geltenden Recht.',
  'For additional rights requests or questions, contact us through the Support page with your account details.':
    'Für weitere Rechteanfragen oder Fragen kontaktiere uns über die Support-Seite mit deinen Kontodaten.',
  'The scanner only runs after explicit consent.': 'Der Scanner läuft nur nach ausdrücklicher Einwilligung.',
  'It collects anti-cheat artifacts, not arbitrary personal files.':
    'Er erfasst Anti-Cheat-Artefakte, keine beliebigen persönlichen Dateien.',
  'Results are delivered only to the initiating operator.':
    'Ergebnisse werden nur an den auslösenden Operator geliefert.',
  'Security researchers may report vulnerabilities responsibly via Support. We do not pursue good-faith research.':
    'Sicherheitsforscher können Schwachstellen verantwortungsvoll über den Support melden. Wir verfolgen gutgläubige Forschung nicht.',
  'Aggregated, non-identifying signals may be used to improve detection quality.':
    'Aggregierte, nicht identifizierende Signale können zur Verbesserung der Erkennungsqualität verwendet werden.',
  'Questions about this policy? Open a ticket on the Support page.':
    'Fragen zu dieser Richtlinie? Eröffne ein Ticket auf der Support-Seite.',
  'Details for this section are available on request via Support.':
    'Details zu diesem Abschnitt sind auf Anfrage über den Support erhältlich.',

  // Legal Notice
  'Legal Notice / Impressum': 'Impressum',
  'Information provided strictly for transparency and regulatory compliance purposes (e.g., according to § 5 DDG).':
    'Diese Angaben dienen ausschließlich der Transparenz und der Einhaltung gesetzlicher Vorschriften (z. B. gemäß § 5 DDG).',
  'Operator': 'Betreiber', 'Service': 'Dienst', 'Represented by': 'Vertreten durch', 'Contact': 'Kontakt',
  'Online anti-cheat / screenshare service': 'Online-Anti-Cheat-/Screenshare-Dienst',
  'Ocean Operations': 'Ocean Operations', 'Via the Support page within the dashboard':
    'Über die Support-Seite im Dashboard',
  'Company Operations & Headquarters': 'Geschäftsbetrieb & Hauptsitz',
  'Ocean operates as an online service. Day-to-day operations are handled remotely; correspondence is processed through the in-dashboard Support channel.':
    'Ocean wird als Online-Dienst betrieben. Der laufende Betrieb erfolgt remote; die Korrespondenz wird über den Support-Kanal im Dashboard abgewickelt.',
  'For legal, billing or data-protection enquiries, open a ticket on the Support page including your account email and a description of your request.':
    'Für rechtliche, abrechnungsbezogene oder datenschutzbezogene Anfragen eröffne ein Ticket auf der Support-Seite mit deiner Konto-E-Mail und einer Beschreibung deines Anliegens.',
  'Merchant of Record': 'Merchant of Record',
  'Payments are processed by a third-party Merchant of Record who acts as the reseller of the Licenses and handles billing, tax and chargebacks on our behalf.':
    'Zahlungen werden von einem externen Merchant of Record abgewickelt, der als Wiederverkäufer der Lizenzen auftritt und Abrechnung, Steuern und Rückbuchungen in unserem Namen übernimmt.',
  'EU Privacy & GDPR (Art. 27)': 'EU-Datenschutz & DSGVO (Art. 27)',
  'For matters relating to the EU General Data Protection Regulation, requests can be submitted via Support and will be routed to the responsible representative under Art. 27 GDPR where applicable.':
    'Für Angelegenheiten im Zusammenhang mit der EU-Datenschutz-Grundverordnung können Anfragen über den Support eingereicht werden und werden, soweit zutreffend, an den verantwortlichen Vertreter gemäß Art. 27 DSGVO weitergeleitet.',

  // Changelog content
  'We’ve released a new update bringing general improvements and system enhancements across Ocean.':
    'Wir haben ein neues Update veröffentlicht, das allgemeine Verbesserungen und Systemoptimierungen in ganz Ocean bringt.',
  'New Scan Results layout with category drill-down': 'Neues Scan-Ergebnis-Layout mit Kategorie-Aufschlüsselung',
  'Repeat-scan detection via Discord ID': 'Erkennung wiederholter Scans über Discord-ID',
  'Tool Designer + style import/export': 'Tool-Designer + Stil-Import/-Export',
  'Numerous stability and UI fixes': 'Zahlreiche Stabilitäts- und UI-Korrekturen',
  'Release 0.2 expands detection coverage and adds the forensic toolset.':
    'Release 0.2 erweitert die Erkennungsabdeckung und fügt das Forensik-Toolset hinzu.',
  'Cheat Database & Forensic Tools': 'Cheat-Datenbank & Forensik-Tools',
  'String / YARA-lite analysis': 'String-/YARA-lite-Analyse', 'Activity log + CSV export': 'Aktivitätsprotokoll + CSV-Export',
  'First public beta of the Ocean dashboard and FiveM scanner.':
    'Erste öffentliche Beta des Ocean-Dashboards und des FiveM-Scanners.',
  'Dashboard, Pins and Strings': 'Dashboard, Pins und Strings',
  'C++ FiveM scanner with .ocean sessions': 'C++-FiveM-Scanner mit .ocean-Sitzungen',

  // Documentation content
  'Overview': 'Übersicht', 'Detects Logs': 'Erkennungsprotokolle', 'Warning Logs': 'Warnprotokolle',
  'Warnings Logs': 'Warnprotokolle', 'Suspicious Logs': 'Verdächtig-Protokolle',
  'Suspicious logs': 'Verdächtig-Protokolle', 'Integrity Logs': 'Integritätsprotokolle',
  'Detection Systems': 'Erkennungssysteme', 'Integrity Checks': 'Integritätsprüfungen',
  'Integrity': 'Integrität', 'Getting Started': 'Erste Schritte', 'Typical sources': 'Typische Quellen',
  'API — Overview': 'API — Übersicht', 'API — Scanned Users': 'API — Gescannte Nutzer',
  'API — User Risk Score': 'API — Nutzer-Risikobewertung', 'API — Pins': 'API — Pins',
  'API — Pin Status': 'API — Pin-Status', 'API — Create Pins': 'API — Pins erstellen',
  'Scanned Users': 'Gescannte Nutzer', 'User Risk Score': 'Nutzer-Risikobewertung',
  'Create Pins': 'Pins erstellen', 'Severity': 'Schweregrad',
  'Welcome to the official documentation of Ocean Anticheat Solutions, a post-mortem detection framework designed to identify and analyze cheating activity across multiple game environments including FiveM, Minecraft, and other supported platforms.':
    'Willkommen zur offiziellen Dokumentation von Ocean Anticheat Solutions, einem Post-mortem-Erkennungsframework, das entwickelt wurde, um Cheating-Aktivitäten über mehrere Spielumgebungen hinweg — darunter FiveM, Minecraft und andere unterstützte Plattformen — zu identifizieren und zu analysieren.',
  "This portal provides a complete reference for developers, partners, and server administrators who work with Ocean's detection systems. Here you will find detailed explanations of detection categories, integrity modules, logging schemas, and implementation details for the Ocean Dashboard and Ocean+ APIs.":
    'Dieses Portal bietet eine vollständige Referenz für Entwickler, Partner und Serveradministratoren, die mit den Erkennungssystemen von Ocean arbeiten. Hier findest du detaillierte Erläuterungen zu Erkennungskategorien, Integritätsmodulen, Logging-Schemata und Implementierungsdetails für das Ocean-Dashboard und die Ocean+-APIs.',
  'Use the navigation sidebar to explore categories such as Detections, Logs, and Integrity Systems.':
    'Nutze die Navigations-Seitenleiste, um Kategorien wie Erkennungen, Protokolle und Integritätssysteme zu erkunden.',
  'Read each section to understand how Ocean classifies detections, processes memory and file artifacts, and communicates results through the dashboard.':
    'Lies jeden Abschnitt, um zu verstehen, wie Ocean Erkennungen klassifiziert, Speicher- und Dateiartefakte verarbeitet und Ergebnisse über das Dashboard kommuniziert.',
  'Use the search bar to quickly locate specific detection signatures or log entries by name.':
    'Nutze die Suchleiste, um bestimmte Erkennungssignaturen oder Protokolleinträge schnell nach Namen zu finden.',
  'Generate a pin from the Pins page, run the scanner, and review the results on the Scan Results page.':
    'Erzeuge auf der Pins-Seite einen Pin, führe den Scanner aus und prüfe die Ergebnisse auf der Scan-Ergebnis-Seite.',
  'Detects Logs are high-confidence findings produced when Ocean matches a known cheat signature in memory, on disk, or in the loaded module list of the game process. Each entry includes the matched signature, severity (High/Critical), and the evidence (process, module or file path).':
    'Erkennungsprotokolle sind Funde mit hoher Zuverlässigkeit, die entstehen, wenn Ocean eine bekannte Cheat-Signatur im Speicher, auf der Festplatte oder in der geladenen Modulliste des Spielprozesses findet. Jeder Eintrag enthält die getroffene Signatur, den Schweregrad (Hoch/Kritisch) und den Beweis (Prozess-, Modul- oder Dateipfad).',
  'Critical — paid/native cheat clients and injectors': 'Kritisch — bezahlte/native Cheat-Clients und Injektoren',
  'High — known free clients, loaders and tooling': 'Hoch — bekannte kostenlose Clients, Loader und Tools',
  'Detects Logs alone are sufficient grounds for a moderation decision when corroborated by execution evidence.':
    'Erkennungsprotokolle allein sind eine ausreichende Grundlage für eine Moderationsentscheidung, sofern sie durch Ausführungsbeweise gestützt werden.',
  'Warning Logs are medium-severity indicators. They do not prove cheating on their own but raise the risk score and warrant manual review — e.g. analysis/debug tools, unsigned modules in unusual locations, or anti-forensic utilities.':
    'Warnprotokolle sind Indikatoren mittleren Schweregrads. Sie beweisen für sich allein kein Cheating, erhöhen aber die Risikobewertung und erfordern eine manuelle Überprüfung — z. B. Analyse-/Debug-Tools, unsignierte Module an ungewöhnlichen Orten oder Anti-Forensik-Werkzeuge.',
  'Cheat Engine, x64dbg, ReClass': 'Cheat Engine, x64dbg, ReClass',
  'Unsigned non-system DLLs': 'Unsignierte Nicht-System-DLLs',
  'File cleaners (BleachBit, CCleaner) run shortly before the scan':
    'Dateibereiniger (BleachBit, CCleaner), die kurz vor dem Scan ausgeführt wurden',
  'Suspicious Logs are low-severity, contextual findings used for timeline correlation. They become meaningful when combined with Detects or Warning logs.':
    'Verdächtig-Protokolle sind kontextbezogene Funde geringen Schweregrads zur Zeitachsen-Korrelation. Sie werden bedeutsam, wenn sie mit Erkennungs- oder Warnprotokollen kombiniert werden.',
  'Examples: short-lived processes from temp directories, renamed binaries, or gaps in the prefetch/USN journal.':
    'Beispiele: kurzlebige Prozesse aus Temp-Verzeichnissen, umbenannte Binärdateien oder Lücken im Prefetch-/USN-Journal.',
  'Ocean combines several engines to reach a verdict:': 'Ocean kombiniert mehrere Engines, um zu einem Urteil zu gelangen:',
  'Signature matching — strings & module names against the cheat database':
    'Signaturabgleich — Strings & Modulnamen gegen die Cheat-Datenbank',
  'Hashing — SHA-256 of files compared to known-bad sets':
    'Hashing — SHA-256 von Dateien im Vergleich zu bekannten Schad-Sets',
  'YARA-lite — string & hex pattern rules': 'YARA-lite — String- & Hex-Muster-Regeln',
  'Heuristics — suspicious JVM args, reflection, injection patterns':
    'Heuristik — verdächtige JVM-Argumente, Reflection, Injektionsmuster',
  'Correlation — artifacts merged into a single timeline':
    'Korrelation — Artefakte zu einer einzigen Zeitachse zusammengeführt',
  'Usermode scanning cannot detect kernel, DMA or external (second-PC) cheats — results are indicators, not absolute proof.':
    'Usermode-Scans können keine Kernel-, DMA- oder externen (Zweit-PC-)Cheats erkennen — Ergebnisse sind Indikatoren, kein absoluter Beweis.',
  'Integrity Checks validate that the system and the scanner itself were not tampered with: module signature verification, driver integrity, handle/hook table inspection and memory region scanning.':
    'Integritätsprüfungen stellen sicher, dass das System und der Scanner selbst nicht manipuliert wurden: Modul-Signaturprüfung, Treiberintegrität, Inspektion der Handle-/Hook-Tabellen und Scannen von Speicherbereichen.',
  'Passing integrity checks are logged as Integrity Logs and increase confidence in a Clean verdict.':
    'Bestandene Integritätsprüfungen werden als Integritätsprotokolle erfasst und erhöhen die Zuverlässigkeit eines „sauber“-Urteils.',
  'The Ocean+ API exposes scan sessions and results. All endpoints require a Bearer API key. Base URL: https://api.anticheat.ac/v1.':
    'Die Ocean+-API stellt Scan-Sitzungen und -Ergebnisse bereit. Alle Endpunkte erfordern einen Bearer-API-Schlüssel. Basis-URL: https://api.anticheat.ac/v1.',
  'This dashboard is client-side; the API reference here describes the schema the OCEAN1 token / .ocean session files follow.':
    'Dieses Dashboard ist clientseitig; die API-Referenz hier beschreibt das Schema, dem der OCEAN1-Token / die .ocean-Sitzungsdateien folgen.',
  'Returns users that have been scanned, keyed by Discord ID. Repeat scans of the same Discord ID are grouped so previous results can be retrieved.':
    'Gibt gescannte Nutzer zurück, indiziert nach Discord-ID. Wiederholte Scans derselben Discord-ID werden gruppiert, sodass frühere Ergebnisse abgerufen werden können.',
  'The risk score is computed from the scan result: detects × 8 + warnings × 2 + suspicious × 5, capped at 100.':
    'Die Risikobewertung wird aus dem Scan-Ergebnis berechnet: Erkennungen × 8 + Warnungen × 2 + Verdächtig × 5, begrenzt auf 100.',
  '0–29 — Low risk': '0–29 — Geringes Risiko', '30–59 — Medium risk': '30–59 — Mittleres Risiko',
  '60–100 — High risk': '60–100 — Hohes Risiko',
  'List and inspect scan pins. A pin is an 8-character code bound to a scanned user (Discord ID) and game.':
    'Scan-Pins auflisten und einsehen. Ein Pin ist ein 8-stelliger Code, der an einen gescannten Nutzer (Discord-ID) und ein Spiel gebunden ist.',
  'Pin lifecycle: Pending → Finished (or Expired after 24h).':
    'Pin-Lebenszyklus: Ausstehend → Abgeschlossen (oder nach 24 Std. abgelaufen).',
  'Pending — created, waiting to be scanned': 'Ausstehend — erstellt, wartet auf Scan',
  'Finished — scan completed, result available': 'Abgeschlossen — Scan abgeschlossen, Ergebnis verfügbar',
  'Expired — not used within 24 hours': 'Abgelaufen — nicht innerhalb von 24 Stunden verwendet',
  'Create a pin for a scan. The scanned user’s Discord ID is required and stored with the result.':
    'Erstelle einen Pin für einen Scan. Die Discord-ID des gescannten Nutzers ist erforderlich und wird mit dem Ergebnis gespeichert.',

  // ---- Tool Designer / branding ----
  'Configure the dashboard, manage data, and design the scanner GUI.':
    'Konfiguriere das Dashboard, verwalte Daten und gestalte die Scanner-GUI.',
  'Customize the look of the FiveM Scanner GUI. Changes save automatically and produce a style code the scanner can load.':
    'Passe das Aussehen der FiveM-Scanner-GUI an. Änderungen werden automatisch gespeichert und erzeugen einen Stil-Code, den der Scanner laden kann.',
  'Dashboard / Tool Designer': 'Dashboard / Tool-Designer', 'Style code copied': 'Stil-Code kopiert',
  'Style loaded': 'Stil geladen', 'Invalid style code': 'Ungültiger Stil-Code',
  'Paste a style code…': 'Stil-Code einfügen…', 'Unsaved changes — press Save All to apply':
    'Ungespeicherte Änderungen — drücke „Alle speichern“ zum Übernehmen',
  'Accent colour': 'Akzentfarbe', 'Background colour': 'Hintergrundfarbe', 'Text colour': 'Textfarbe',
  'Muted background colour': 'Gedämpfte Hintergrundfarbe', 'Muted text colour': 'Gedämpfte Textfarbe',
  'Titlebar colour': 'Titelleistenfarbe', 'Game background': 'Spielhintergrund',
  'Finished text': 'Abgeschlossen-Text', 'Scanning process text': 'Scan-Vorgangstext',
  'Scanning...': 'Scannen...', 'Scanning': 'Scannen', 'Text': 'Text', 'Logo': 'Logo',
  'Custom Logo URL (stretched to 600×300)': 'Eigene Logo-URL (auf 600×300 gestreckt)',
  'Custom logo is active in the preview.': 'Eigenes Logo ist in der Vorschau aktiv.',
  'Logo failed to load — check the URL': 'Logo konnte nicht geladen werden — prüfe die URL',
  'Branding': 'Branding', 'Wallpapers': 'Hintergrundbilder',
  'Official wallpapers for desktops and social media.': 'Offizielle Hintergrundbilder für Desktops und soziale Medien.',
  'Logo, color, type, and assets built with clarity and hierarchy in mind.':
    'Logo, Farbe, Typografie und Assets, mit Klarheit und Hierarchie gestaltet.',
  'Use the name consistently in communications and on products.':
    'Verwende den Namen einheitlich in der Kommunikation und auf Produkten.',
  'Minimum clearance around the symbol. Scales with the size of the logo.':
    'Mindestabstand um das Symbol. Skaliert mit der Größe des Logos.',
  'Fixed aspect ratio. No effects or distortion. Same geometry in both backgrounds.':
    'Festes Seitenverhältnis. Keine Effekte oder Verzerrungen. Gleiche Geometrie in beiden Hintergründen.',
  'A base of grays and black; blue as an accent.': 'Eine Basis aus Grautönen und Schwarz; Blau als Akzent.',
  'Geist Sans for interface and communication. Geist Mono for data. Plus Jakarta for brand accents.':
    'Geist Sans für Oberfläche und Kommunikation. Geist Mono für Daten. Plus Jakarta für Marken-Akzente.',
  'Naming': 'Namensgebung', 'Spacing': 'Abstände',

  // ---- Misc statuses / toasts ----
  'Saved': 'Gespeichert', 'Profile saved': 'Profil gespeichert', 'Cheat added': 'Cheat hinzugefügt',
  'Invalid token': 'Ungültiger Token', 'Paste data': 'Daten einfügen', 'Paste some data first': 'Füge zuerst Daten ein',
  'Fill in all fields': 'Fülle alle Felder aus', 'Invalid PIN': 'Ungültige PIN',
  'Scan complete': 'Scan abgeschlossen', 'Discord': 'Discord', 'Server': 'Server',
  'No tickets yet': 'Noch keine Tickets', 'No data': 'Keine Daten', 'Results': 'Ergebnisse',
  'Last Updated:': 'Zuletzt aktualisiert:',
}

// Dynamic patterns (computed strings)
const RULES = [
  [/^(\d[\d.,]*) scans · (\d[\d.,]*) detections$/, (m) => `${m[1]} Scans · ${m[2]} Erkennungen`],
  [/^(\d+) versions published$/, (m) => `${m[1]} Versionen veröffentlicht`],
  [/^(\d+) scans$/, (m) => `${m[1]} Scans`],
  [/^(\d+) detections$/, (m) => `${m[1]} Erkennungen`],
  [/^Shared with Me \((\d+)\)$/, (m) => `Mit mir geteilt (${m[1]})`],
  [/^Last updated\s+(\d{1,2})\s+([A-Z][a-z]+),?\s+(\d{4})$/, (m) =>
    `Zuletzt aktualisiert: ${m[1]}. ${MONTHS[m[2]] || m[2]} ${m[3]}`],
  [/^(\d{1,2})\s+([A-Z][a-z]+)\s+(\d{4})$/, (m) =>
    MONTHS[m[2]] ? `${m[1]}. ${MONTHS[m[2]]} ${m[3]}` : null],
  [/^\/year$/, () => '/Jahr'],
  [/^\/6 months$/, () => '/6 Monate'],
  [/^\/month$/, () => '/Monat'],
]

function translate(raw) {
  const key = raw.replace(/\s+/g, ' ').trim()
  if (!key) return null
  if (DE[key]) return DE[key]
  for (const [rx, fn] of RULES) {
    const m = key.match(rx)
    if (m) {
      const out = fn(m)
      if (out) return out
    }
  }
  return null
}

const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'CODE', 'PRE', 'svg', 'SVG'])
const ATTRS = ['placeholder', 'title', 'aria-label']
const ATTR_ORIG = new WeakMap() // element -> { [attr]: originalEnglishValue }

function applyToTree(root, toGerman) {
  // Text nodes
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(n) {
      const p = n.parentElement
      if (!p) return NodeFilter.FILTER_REJECT
      if (SKIP_TAGS.has(p.tagName) || p.closest('[data-no-i18n]')) return NodeFilter.FILTER_REJECT
      if (!n.nodeValue || !/\S/.test(n.nodeValue)) return NodeFilter.FILTER_REJECT
      return NodeFilter.FILTER_ACCEPT
    },
  })
  const nodes = []
  while (walker.nextNode()) nodes.push(walker.currentNode)
  for (const n of nodes) {
    const raw = n.nodeValue
    if (toGerman) {
      if (n.__i18nDe && n.nodeValue === n.__i18nDe) continue
      const de = translate(raw)
      if (de && de !== raw.trim()) {
        const lead = raw.match(/^\s*/)[0]
        const trail = raw.match(/\s*$/)[0]
        if (n.__i18nEn == null) n.__i18nEn = raw
        n.nodeValue = lead + de + trail
        n.__i18nDe = n.nodeValue
      }
    } else if (n.__i18nEn != null) {
      n.nodeValue = n.__i18nEn
      n.__i18nEn = null
      n.__i18nDe = null
    }
  }
  // Attributes (originals kept in a WeakMap — never touch dataset/DOM attrs)
  const els = root.querySelectorAll('[placeholder],[title],[aria-label]')
  for (const el of els) {
    if (el.closest('[data-no-i18n]')) continue
    const store = ATTR_ORIG.get(el)
    for (const a of ATTRS) {
      if (toGerman) {
        if (!el.hasAttribute(a)) continue
        const cur = el.getAttribute(a)
        const de = translate(cur)
        if (de && de !== cur) {
          const s = ATTR_ORIG.get(el) || {}
          if (s[a] == null) s[a] = cur
          ATTR_ORIG.set(el, s)
          el.setAttribute(a, de)
        }
      } else if (store && store[a] != null) {
        el.setAttribute(a, store[a])
        delete store[a]
      }
    }
  }
}

export function AutoI18n() {
  const { state } = useStore()
  const lang = state.settings.lang || 'en'

  useEffect(() => {
    const root = document.getElementById('root')
    if (!root) return
    const toGerman = lang === 'de'
    let raf = 0
    let observer

    const run = () => {
      if (observer) observer.disconnect()
      try {
        applyToTree(root, toGerman)
      } catch (err) {
        // Translation must never break the app
        console.error('[i18n]', err)
      } finally {
        if (observer) observer.observe(root, { childList: true, subtree: true, characterData: true })
      }
    }
    const schedule = () => {
      cancelAnimationFrame(raf)
      raf = requestAnimationFrame(run)
    }

    observer = new MutationObserver(schedule)
    run()
    observer.observe(root, { childList: true, subtree: true, characterData: true })

    return () => {
      cancelAnimationFrame(raf)
      observer.disconnect()
      // Restore English on unmount/lang change so a later toggle is clean
      try {
        if (toGerman) applyToTree(root, false)
      } catch (err) {
        console.error('[i18n]', err)
      }
    }
  }, [lang])

  return null
}
