# tokenlore-server

tokenlore zeigt, wie viel du mit Claude Code arbeitest: Token, Modelle, Konten und Geräte. Das tokenlore-Plugin schickt nur Zahlen und Metadaten, nie Inhalte, an diesen Server; der Server prüft sie streng, legt sie in SQLite ab und zeigt sie auf einer Webseite, auf Wunsch für ein ganzes Team mit Rollen. Er ist reines PHP und läuft auf normalem Webspace: Dateien hochladen, Einrichtung im Browser, ohne SSH, Docker oder Composer auf dem Server.

- Betrieb (Installation, Datenordner, Updates, Team, Notfall-Zugang, Fehlersuche): [docs/betrieb.md](docs/betrieb.md) <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->
- Plugin für die Geräte: [tokenlore/tokenlore](https://github.com/tokenlore/tokenlore)
- Datenformat und Prüfregeln: [PROTOCOL.md im Plugin-Repo](https://github.com/tokenlore/tokenlore/blob/main/PROTOCOL.md)
- Änderungen: [CHANGELOG.md](CHANGELOG.md)
- Sicherheitslücke gefunden? Bitte vertraulich melden: [SECURITY.md](SECURITY.md)

**Inhalt:** [Voraussetzungen](#voraussetzungen) · [Installation](#installation) · [Benutzung](#benutzung) · [Lizenz](#lizenz)

## Voraussetzungen

| Was | Wozu | Prüfen |
|---|---|---|
| PHP 8.2 oder neuer mit `pdo_sqlite`, `json`, `openssl`, `mbstring`, `ctype`, `sodium` und Argon2id (fehlt `sodium`: im Hoster-Menü unter „PHP-Einstellungen“ anschalten) | Server ausführen | Einrichtungsseite, Teil „Prüfung des Servers“ |
| SQLite 3.27 oder neuer mit JSON1 | Datenbank | Einrichtungsseite |
| Schreibrechte für PHP im Ordner `data/` | Datenbank und Sicherungen | Einrichtungsseite, Teil „Prüfung des Servers“ |
| HTTPS mit gültigem Zertifikat | Anmeldung und Kopplung | `curl -s https://<server>/healthz` gibt `ok` aus |
| Apache mit `.htaccess` (nginx: eigene Regel) | Sperren und Umschreibregeln | Einrichtungsseite, Teil „Datenbank und Adressen“ |

Grenzwerte von PHP und Einzelheiten: [docs/betrieb.md](docs/betrieb.md#1-voraussetzungen). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->

## Installation

1. Eine Version als ZIP laden: auf GitHub unter „Tags“ bei der gewünschten Version „Source code (zip)“, oder die neueste Version unter `https://github.com/tokenlore/tokenlore-server/archive/refs/heads/main.zip`.
2. Entpacken. Im ZIP liegt ein Ordner (etwa `tokenlore-server-1.2.3`); hochgeladen wird sein Inhalt, nicht der Ordner selbst.
3. Den Inhalt per FTP in den Web-Ordner laden, auch die versteckten `.htaccess`-Dateien.
4. Die Adresse im Browser öffnen: Die Einrichtungsseite prüft den Server.
5. Den angezeigten Code als `setup-code.txt` per FTP in `data/` legen und das erste Konto anlegen; es wird Admin.
6. Prüfen: Die Bestätigung nennt die Serveradresse, und die Anmeldung klappt.

Ausführlich, auch per Git beim Hoster: [docs/betrieb.md](docs/betrieb.md#2-installation). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->

## Benutzung

- **Geräte koppeln:** Auf der Webseite unter „Einstellungen“, „Gerät hinzufügen“ einen Kopplungscode erzeugen und den angezeigten Befehl `/tokenlore:connect …` in Claude Code eingeben ([Anleitung](docs/betrieb.md#4-geräte-koppeln)). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->
- **Ein Rechner bleibt ein Gerät,** egal ob du ihn sperrst, neu koppelst oder das Plugin neu installierst. Neu koppeln sperrt den alten Schlüssel. Die älteren Zahlen des Rechners (Altbestand) kommen auf jedem Server an und zählen nie doppelt; einen Tag, den ein anderes Gerät schon mit genau denselben Werten hat, zählt nur dieses. Holst du `~/.claude` aus einer Sicherung zurück oder kopierst ihn auf einen weiteren Rechner, fragt `/tokenlore:connect`, ob es das alte Gerät ist, mit Empfehlung und den Folgen jeder Antwort; die Antwort lässt sich auch später auf der Geräteliste geben. Sieht ein Rechner doch wie zwei Geräte aus, schlägt die Geräteliste „Zusammenlegen?“ vor; zusammengelegt wird nur, wenn du es bestätigst ([Anleitung](docs/betrieb.md#ein-rechner-bleibt-ein-gerät)). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->
- **Plugin aktuell halten:** Zu alte Plugins nimmt der Server nicht an. Die Geräteliste zeigt dann „Plugin veraltet“; die Zahlen warten im Archiv auf dem Rechner und kommen nach dem Aktualisieren an ([Anleitung](docs/betrieb.md#4-geräte-koppeln)). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->
- **Auswerten:** Übersicht, Modelle, Konten und Geräte auf der Webseite.
- **Team:** Mitglieder anlegen, Rollen Admin und Mitglied, Team-Statistik ([Anleitung](docs/betrieb.md#6-team)). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->
- **Updates:** neue Version einspielen, per ZIP und FTP oder per Git beim Hoster ([Anleitung](docs/betrieb.md#5-updates)). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->
- **Passwortschutz:** Die Webseite lässt sich zusätzlich per Basic-Auth schützen; die Adressen der Plugins bleiben frei ([Anleitung](docs/betrieb.md#passwortschutz-für-die-webseite-freiwillig)). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->
- **Admin-Zugang verloren:** [Notfall-Zugang](docs/betrieb.md#7-notfall-zugang). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->

## Lizenz

MIT, siehe [LICENSE](LICENSE). Die mitgelieferte Schrift und die Bibliotheken der Webseite stehen unter eigenen Lizenzen; deren Texte stehen in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->

tokenlore ist kein Produkt von Anthropic und nicht mit Anthropic verbunden. „Claude“ und „Claude Code“ sind Marken von Anthropic.
