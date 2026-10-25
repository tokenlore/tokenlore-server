# tokenlore-server

tokenlore zeigt, wie viel du mit Claude Code arbeitest: Token, Modelle, Konten und Geräte. Das tokenlore-Plugin schickt nur Zahlen und Metadaten, nie Inhalte, an diesen Server; der Server prüft sie streng, legt sie in SQLite ab und zeigt sie auf einer Webseite, auf Wunsch für ein ganzes Team mit Rollen. Er ist reines PHP und läuft auf normalem Webspace: Dateien hochladen, Einrichtung im Browser, ohne SSH, Docker oder Composer auf dem Server.

- Betrieb (Installation, Datenordner, Updates, Team, Notfall-Zugang, Fehlersuche): [docs/betrieb.md](docs/betrieb.md)
- Plugin für die Geräte: [tokenlore/tokenlore](https://github.com/tokenlore/tokenlore)
- Datenformat und Prüfregeln: [PROTOCOL.md im Plugin-Repo](https://github.com/tokenlore/tokenlore/blob/main/PROTOCOL.md)
- Änderungen: [CHANGELOG.md](CHANGELOG.md)
- Sicherheitslücke gefunden? Bitte vertraulich melden: [SECURITY.md](SECURITY.md)

**Inhalt:** [Voraussetzungen](#voraussetzungen) · [Installation](#installation) · [Benutzung](#benutzung) · [Lizenz](#lizenz)

## Voraussetzungen

| Was | Wozu | Prüfen |
|---|---|---|
| PHP 8.2 oder neuer mit `pdo_sqlite`, `json`, `openssl`, `mbstring`, `ctype` und Argon2id | Server ausführen | Einrichtungsseite, Teil „Prüfung des Servers“ |
| SQLite 3.27 oder neuer mit JSON1 | Datenbank | Einrichtungsseite |
| Schreibrechte für PHP im Ordner `data/` | Datenbank und Sicherungen | Einrichtungsseite, Teil „Prüfung des Servers“ |
| HTTPS mit gültigem Zertifikat | Anmeldung und Kopplung | `curl -s https://<server>/healthz` gibt `ok` aus |
| Apache mit `.htaccess` (nginx: eigene Regel) | Sperren und Umschreibregeln | Einrichtungsseite, Teil „Datenbank und Adressen“ |

Grenzwerte von PHP und Einzelheiten: [docs/betrieb.md](docs/betrieb.md#1-voraussetzungen).

## Installation

1. Eine Version als ZIP laden: auf GitHub unter „Tags“ bei der gewünschten Version „Source code (zip)“, oder die neueste Version unter `https://github.com/tokenlore/tokenlore-server/archive/refs/heads/main.zip`.
2. Entpacken. Im ZIP liegt ein Ordner (etwa `tokenlore-server-1.2.3`); hochgeladen wird sein Inhalt, nicht der Ordner selbst.
3. Den Inhalt per FTP in den Web-Ordner laden, auch die versteckten `.htaccess`-Dateien.
4. Die Adresse im Browser öffnen: Die Einrichtungsseite prüft den Server.
5. Den angezeigten Code als `setup-code.txt` per FTP in `data/` legen und das erste Konto anlegen; es wird Admin.
6. Prüfen: Die Bestätigung nennt die Serveradresse, und die Anmeldung klappt.

Ausführlich, auch per Git beim Hoster: [docs/betrieb.md](docs/betrieb.md#2-installation).

## Benutzung

- **Geräte koppeln:** Auf der Webseite unter „Einstellungen“, „Gerät hinzufügen“ einen Kopplungscode erzeugen und den angezeigten Befehl `/tokenlore:connect …` in Claude Code eingeben ([Anleitung](docs/betrieb.md#4-geräte-koppeln)).
- **Auswerten:** Übersicht, Modelle, Konten und Geräte auf der Webseite.
- **Team:** Mitglieder anlegen, Rollen Admin und Mitglied, Team-Statistik ([Anleitung](docs/betrieb.md#6-team)).
- **Updates:** neue Version einspielen, per ZIP und FTP oder per Git beim Hoster ([Anleitung](docs/betrieb.md#5-updates)).
- **Passwortschutz:** Die Webseite lässt sich zusätzlich per Basic-Auth schützen; die Adressen der Plugins bleiben frei ([Anleitung](docs/betrieb.md#passwortschutz-für-die-webseite-freiwillig)).
- **Admin-Zugang verloren:** [Notfall-Zugang](docs/betrieb.md#7-notfall-zugang).

## Lizenz

MIT, siehe [LICENSE](LICENSE). Die mitgelieferte Schrift und die Bibliotheken der Webseite stehen unter eigenen Lizenzen; deren Texte stehen in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

tokenlore ist kein Produkt von Anthropic und nicht mit Anthropic verbunden. „Claude“ und „Claude Code“ sind Marken von Anthropic.
