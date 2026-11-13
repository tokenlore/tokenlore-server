# Changelog

Was sich für dich als Betreiber ändert, je Version. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Versionen nach [Semantic Versioning](https://semver.org/lang/de/). Wie du ein Update einspielst: [docs/betrieb.md](docs/betrieb.md#5-updates). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->

## Unveröffentlicht

## 0.4.0 – 2026-11-13

### Neu

- Stellst du einen Rechner aus einer Sicherung wieder her oder kopierst seinen Konfigurationsordner auf einen neuen Rechner, fragt das Plugin beim Koppeln, ob er das alte Gerät ist. Es empfiehlt eine Antwort und warnt, wenn das alte Gerät vor Kurzem noch geliefert hat. Bei „Ja“ wird das alte Gerät neu gekoppelt, seine Zahlen bleiben, und der andere Rechner liefert nicht mehr, bis du ihn neu koppelst. Bei „Nein“ wird es ein neues Gerät, und die Frage kommt nicht wieder. Bei „Später“ wird es ein neues Gerät, und die Geräteliste fragt dich, sobald du entscheiden willst.
- Die Geräteliste zeigt bei so einem Gerät den Hinweis mit Empfehlung und den Folgen je Antwort; für dieses Paar fragt sie nicht zusätzlich „Zusammenlegen?“.

### Doku

- Die Betriebsanleitung erklärt die Frage nach dem alten Gerät beim Koppeln und auf der Seite „Geräte“.

## 0.3.0 – 2026-11-09

### Neu

- Ein Rechner bleibt ein Gerät: Koppelst du einen Rechner neu, etwa nach dem Sperren oder nach einer Neuinstallation des Plugins, bekommt sein bisheriges Gerät einen neuen Schlüssel. Seine Zahlen bleiben, der alte Schlüssel wird gesperrt.
- Ein neu gekoppeltes Gerät behält seinen Namen, auch einen, den du auf der Webseite vergeben hast; nur `--name` beim Koppeln ersetzt ihn.
- Im Geräte-Detail holst du mit „Code für dieses Gerät“ einen Kopplungscode für genau dieses Gerät.
- Zeigen zwei Geräte dieselben abgeschlossenen Tage, fragt die Geräteliste „Zusammenlegen?“. Erst nach deiner Bestätigung werden sie ein Gerät; nichts zählt doppelt.
- Der Altbestand (Zahlen von vor der Kopplung) kommt auf jedem Server an und wird nachgeführt, wenn er wächst.
- Jede Anfrage und jede Sitzung zählt auf deinem Server nur einmal, auch wenn zwei Benutzer sie liefern: Sie gehört dem, der sie zuerst geliefert hat; auch neue Anfragen in dieser Sitzung zählen nur bei ihm. Gleiche Tage aus dem Altbestand, etwa von einem kopierten Rechner, zählen ebenfalls nur einmal.
- Lag etwas, das ein Gerät geliefert hat, schon bei einem anderen Benutzer oder Gerät, zeigt die Geräteliste beim Gerät einen Hinweis mit der Anzahl. Wer oder welches Gerät das ist, siehst du nicht; der Hinweis verrät nur, dass genau diese Anfrage oder genau diese Tageswerte schon anderswo auf deinem Server liegen. Legst du zwei Geräte zusammen, verschwindet der Hinweis für Tage, die nur beim jeweils anderen der beiden lagen.
- Dein Server nimmt nur noch Zahlen an, die das Plugin auf dem Rechner unterschrieben hat. Jede Anfrage liegt zuerst im Archiv des Rechners; löscht Claude Code dort alte Sitzungsdateien, gehen ihre Zahlen trotzdem nicht verloren.
- Ist das Plugin eines Geräts zu alt, zeigen Geräteliste und Gerät „Plugin veraltet“. Dein Server nimmt von diesem Gerät dann nichts an; die Zahlen warten auf dem Rechner und kommen nach dem Aktualisieren an.
- Ziehst du deinen Server samt Datenordner auf eine andere Adresse um, bleibt jeder Rechner nach dem Neukoppeln sein bisheriges Gerät.
- Beim Koppeln beweist das Plugin, dass es den geheimen Teil seines Signaturschlüssels hat. Wer nur einen Kopplungscode erwischt, kann so keinen fremden Schlüssel an ein Gerät hängen, und wer einen fremden Schlüssel nur kennt, kann damit kein Gerät aussperren. Ein mitgelesener Nachweis gilt nur für deinen Server und nur einmal, auch wenn dein Server denselben Code später wieder vergibt. Koppelt jemand sein Plugin aus Versehen mit einem falschen Server, kann dieser den Schlüssel bei dir an ein anderes Gerät hängen; das echte Gerät holt ihn mit erneutem Koppeln zurück, denn der neueste Nachweis gewinnt. Das Plugin auf dem Gerät, das seinen Schlüssel verloren hat, sagt das beim Sitzungsstart und nennt die Schritte zum Neukoppeln.
- Ein Gerät hat höchstens 32 Signaturschlüssel, auch nach dem Zusammenlegen. Der zuletzt gemeldete bleibt immer; kommen beim Koppeln oder Zusammenlegen mehr zusammen, vergisst dein Server die ältesten. Legst du sehr viele Geräte zusammen, kann ein älteres davon so seinen Schlüssel verlieren; es bekommt ihn mit erneutem Koppeln zurück.
- Dein Server weist Zeilen ab, die nicht genau so aussehen, wie das Plugin sie unterschreibt (etwa doppelte Felder).
- Die Systemseite zeigt, ob die PHP-Erweiterung `sodium` angeschaltet ist.
- Die Seite „Datenschutz“ zeigt, wie eine unterschriebene Zeile aussieht und was das Plugin auf dem Rechner aufhebt.

### Geändert

- Braucht die Plugin-Version mit Gerätekennung; ältere Plugins können nicht mehr koppeln.
- Konten lassen sich nicht mehr von Hand zuordnen. Anfragen ohne Konto stehen in der Zeile „Ohne Konto“ und zählen in allen Summen mit.
- **Hast du Version 0.2.0 installiert, musst du die Datenbank löschen und tokenlore neu einrichten.** Der Server stellt sie nicht selbst um. Nach dem Update erkennt er sie, ändert nichts an ihr und zeigt dir auf der Webseite die Schritte: Kopiere zuerst deinen Datenordner auf deinen Rechner, lösche dann im Datenordner die Datei `tokenlore-….sqlite` (und, falls vorhanden, die Dateien gleichen Namens mit `-wal` und `-shm` am Ende) und lade die Seite neu. Du richtest tokenlore dann neu ein wie beim ersten Mal; Konten, Geräte und Zahlen sind danach auf dem Server weg, in deiner Sicherung bleiben sie. Koppel deine Rechner neu, das Plugin schickt dabei alles aus seinem Archiv erneut. Bis dahin meldet Claude Code beim Koppeln und Liefern, dass die Datenbank von einer älteren Version stammt.
- **Braucht die PHP-Erweiterung `sodium`.** Fehlt sie, bricht die Einrichtung mit einer Anleitung ab: im Hoster-Menü unter „PHP-Einstellungen“ die Erweiterung `sodium` anschalten (in Plesk im Bereich „Erweiterungen“).
- Braucht die Plugin-Version mit Archiv. Ältere Plugins können weder koppeln noch liefern; aktualisiere das Plugin auf jedem Rechner und koppele ihn danach einmal neu.
- Dein Server speichert kein Projekt mehr zu einer Sitzung.

### Doku

- Die Betriebsanleitung nennt unter „Bekannte Grenzen“, dass auf gemietetem Webspace auch dein Hoster die Datenbankdatei und die Logs lesen kann.
- Die Betriebsanleitung erklärt Neukoppeln, Altbestand und Zusammenlegen.
- Die Seite „Datenschutz“ und die Betriebsanleitung sagen genauer, wann nach dem Ende einer Sitzung gesendet wird: höchstens alle 5 Minuten; kam der letzte Abgleich vor weniger als 5 Minuten, kommt die letzte Anfrage der Sitzung mit dem ersten Abgleich, der mindestens 5 Minuten nach ihr läuft. Dabei geht nichts verloren, und nichts zählt doppelt.
- Die Betriebsanleitung erklärt die Seite „Die Datenbank stammt von einer älteren Version“.
- Die Betriebsanleitung erklärt den Hinweis „… ältere Archivzeilen gehen nicht an den Server …“: Hält ein anderes Gerät einen früheren Signaturschlüssel eines Rechners, liefert der Rechner neue Zahlen weiter, nur die älteren Zeilen mit diesem Schlüssel nicht. Ist das andere Gerät derselbe Rechner, legst du beide auf der Seite „Geräte“ zusammen und koppelst das Gerät danach neu; dann gehen auch die älteren Zeilen mit.
- Die Betriebsanleitung erklärt das Archiv auf dem Rechner, „Plugin veraltet“, den Umzug des Servers und die Meldungen „Signaturschlüssel fehlt“ und „Dieser Ordner stammt von einem anderen Rechner“.

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
