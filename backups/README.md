# Projekt-Backups

Dieser Ordner enthält zeitgestempelte Backup-Archive des ZeroTrace-Projekts.

## Inhalt der Archive

Jedes `.tar.gz` enthält den vollständigen Projekt-Quellcode **ohne**:

- `node_modules/` (kann mit `npm install` wiederhergestellt werden)
- `.git/` (Versionsverlauf liegt im Repository)
- `dist/` (Build-Output)
- `backups/` (dieser Ordner selbst)

## Namensschema

```
zerotrace-backup-JJJJMMTT-HHMMSS.tar.gz
```

## Wiederherstellung

```bash
mkdir wiederherstellung && cd wiederherstellung
tar -xzf ../backups/zerotrace-backup-JJJJMMTT-HHMMSS.tar.gz
npm install
```
