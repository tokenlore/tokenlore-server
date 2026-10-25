# Changelog

Was sich für dich als Betreiber ändert, je Version. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [Semantic Versioning](https://semver.org/lang/de/). Wie du ein Update einspielst: [docs/betrieb.md](docs/betrieb.md#5-updates).

## Unveröffentlicht

## 0.2.0 – 2026-10-25

### Neu

- Erste Veröffentlichung: Server in reinem PHP mit SQLite für normalen Webspace; Dateien hochladen, Einrichtung im Browser, ohne SSH, Docker oder Composer auf dem Server. Jede Version liegt mit eigenem Tag auf GitHub in [tokenlore/tokenlore-server](https://github.com/tokenlore/tokenlore-server), als ZIP („Source code (zip)“) oder per Git beim Hoster.
- Die Einrichtungsseite prüft PHP-Version, Erweiterungen, SQLite, Datenordner, Grenzwerte, HTTPS, Umschreibregeln und den Authorization-Header und nennt, was zu tun ist. Ist der Datenordner von außen abrufbar, lässt sie sich erst abschließen, wenn das behoben ist.
- Besitznachweis bei der Einrichtung: eine Datei `setup-code.txt` mit dem angezeigten Code im Datenordner. Ohne sie kann niemand das erste Konto anlegen, auch nicht, wer die Adresse vor dir findet.
- Betrieb ohne Umschreibregeln über `…/index.php`, auch im Unterordner.
- Datenannahme vom tokenlore-Plugin unter `/api/plugin/pair`, `/api/plugin/ingest` und `/api/plugin/ca`, streng geprüft nach dem Protokoll des Plugins.
- Webseite mit Übersicht, Modellen, Konten mit Zuordnung und Geräten; Kopplungscode mit fertigem Befehl `/tokenlore:connect …`, bei eigener CA mit Fingerabdruck.
- Mehrere Konten mit den Rollen Admin und Mitglied, Team-Statistik und Server-Einstellungen.
- Notfall-Zugang über eine Datei im Datenordner, wenn kein Admin mehr Zugang hat.
- Sicherheitsprotokoll für Admin-Aktionen, Server-Einstellungen und Notfall-Zugang.
- Automatische Sicherung der Datenbank vor jeder Umstellung.
- Betriebsanleitung in `docs/betrieb.md`, mit Anleitung für einen zusätzlichen Passwortschutz der Webseite (Basic-Auth), bei dem die Plugins weiter liefern können.
- `SECURITY.md`: wie du eine Sicherheitslücke vertraulich meldest.
- Lizenz MIT (`LICENSE`); Lizenzen der mitgelieferten Schrift und Bibliotheken in `THIRD_PARTY_NOTICES`.
