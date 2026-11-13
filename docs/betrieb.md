# tokenlore-Server betreiben

tokenlore zeigt dir, wie viel du mit Claude Code arbeitest: Token, Modelle, Konten, Geräte. Der Server läuft auf ganz
normalem Webspace mit PHP. Du brauchst dafür kein SSH, keine Kommandozeile, keine Datenbank, die du selbst anlegst, und
kein Docker. Alles geht per FTP und im Browser.

Diese Anleitung ist für Privatleute geschrieben. Gehe die Abschnitte der Reihe nach durch:

1. [Voraussetzungen](#1-voraussetzungen)
2. [Installation](#2-installation)
3. [Datenordner und Sicherheit](#3-datenordner-und-sicherheit)
4. [Geräte koppeln](#4-geräte-koppeln)
5. [Updates](#5-updates)
6. [Team](#6-team)
7. [Notfall-Zugang](#7-notfall-zugang)
8. [Bekannte Grenzen](#8-bekannte-grenzen)
9. [Fehlersuche](#9-fehlersuche)

---

## 1. Voraussetzungen

Dein Webspace braucht:

| Was | Wert |
|---|---|
| PHP | Version **8.2 oder neuer** |
| PHP-Erweiterungen | `pdo_sqlite`, `json`, `openssl`, `mbstring`, `ctype`, **`sodium`** für die Signaturen der Plugins und **Argon2id** für die Passwörter (bei den meisten Hostern kommt Argon2id mit `sodium`). Fehlt `sodium`: im Hoster-Menü unter „PHP-Einstellungen“ die Erweiterung `sodium` anschalten. |
| SQLite | Version **3.27 oder neuer** mit den JSON-Funktionen (JSON1). Beides gehört zu PHP; bei PHP 8.2 ist es fast immer dabei. |
| Adresse | **HTTPS** (ein gültiges Zertifikat, bei den meisten Hostern Let's Encrypt). Ohne HTTPS gibt es keine Anmeldung. |
| Schreibrechte | PHP muss im Ordner `data/` Dateien anlegen dürfen |
| Webserver | Apache mit `.htaccess` (der Normalfall, z. B. bei Plesk). Nur nginx? Siehe [Abschnitt 3](#nginx). |

**Grenzwerte von PHP.** Der Server ist darauf ausgelegt, dass dein Hoster mindestens diese Werte erlaubt:

| Einstellung | Mindestens |
|---|---|
| `max_execution_time` (Laufzeit) | 30 Sekunden (oder 0 = unbegrenzt) |
| `memory_limit` (Speicher) | 128 MB |
| `post_max_size` (Größe einer Anfrage) | 8 MB |

Du musst nichts davon vorher prüfen: Die Einrichtungsseite ([Abschnitt 2](#2-installation)) testet alles und sagt dir
klar, was fehlt. Fehlende Erweiterungen und ein nicht beschreibbarer Datenordner sind **Fehler** (dann geht es nicht
weiter). Zu kleine Grenzwerte und fehlendes HTTPS sind **Warnungen**. Grenzwerte und PHP-Version stellst du im Panel
deines Hosters ein (bei Plesk unter „Websites & Domains“, „PHP-Einstellungen“).

---

## 2. Installation

Es gibt zwei Wege: **per ZIP und FTP** (die Schritte hier) oder **per Git beim Hoster**, falls dein Panel das anbietet
(siehe [unten](#installation-und-update-per-git-beim-hoster)). Der Git-Weg macht spätere Updates einfacher.

**Schritt 1: ZIP herunterladen.** Die Versionen liegen im Repo
[tokenlore/tokenlore-server](https://github.com/tokenlore/tokenlore-server) auf GitHub. Unter „Tags“ findest du jede
Version mit „Source code (zip)“; die neueste bekommst du auch direkt unter
`https://github.com/tokenlore/tokenlore-server/archive/refs/heads/main.zip`. Entpacke die ZIP auf deinem Rechner. Darin
liegt ein Ordner wie `tokenlore-server-1.2.3`; hochgeladen wird sein **Inhalt**, nicht der Ordner selbst.

**Schritt 2: Ordner wählen.** Entscheide, wo tokenlore erreichbar sein soll:

- Im **Wurzelordner** einer Domain oder Subdomain, z. B. `https://tokenlore.example.de/`. Das ist der einfachste Weg.
- In einem **Unterordner**, z. B. `https://example.de/tokenlore/`. Lege dazu im Web-Ordner (bei Plesk `httpdocs`)
  einen Ordner `tokenlore` an.

> **Achtung:** Liegt im gewählten Ordner schon eine Webseite, werden deren `index.php` und `.htaccess` überschrieben.
> Nimm dann einen Unterordner.

**Schritt 3: Per FTP hochladen.** Lade den **Inhalt** des Ordners `tokenlore-server-…` in den gewählten Ordner. Es
müssen `index.php`, `.htaccess`, `app/`, `data/`, `docs/`, `_app/` und die übrigen Dateien nebeneinander liegen.

> **Wichtig: versteckte Dateien.** `.htaccess` beginnt mit einem Punkt, und viele FTP-Programme blenden solche Dateien
> aus und laden sie dann auch nicht hoch. Schalte „versteckte Dateien anzeigen“ ein (FileZilla: Menü „Server“,
> „Versteckte Dateien anzeigen erzwingen“) und prüfe nach dem Hochladen, dass `.htaccess` im Hauptordner sowie in
> `app/` und `data/` angekommen ist. Diese Dateien sperren die Ordner mit dem Programmcode und deinen Daten.

Hat dein Hoster einen Dateimanager im Browser, kannst du alternativ die ZIP-Datei hochladen und dort entpacken. Dann
liegt auf dem Server der Ordner `tokenlore-server-…`: Verschiebe seinen Inhalt (auch die versteckten Dateien) in den
gewählten Ordner und lösche den leeren Ordner.

**Schritt 4: Einrichtungsseite öffnen.** Rufe die Adresse im Browser auf, z. B. `https://example.de/tokenlore/`.
Du siehst die Seite „tokenlore einrichten“ in vier Teilen:

1. **Prüfung des Servers:** PHP-Version, Erweiterungen (darunter `sodium`), SQLite, Argon2id, Datenordner, Grenzwerte und HTTPS. Alles sollte
   „In Ordnung“ sein. Bei „Warnung“ oder „Fehler“ steht dabei, was zu tun ist.
2. **Datenbank und Adressen:**
   - **Datenordner:** Die Seite prüft mit einer Testdatei selbst, ob der Datenordner von außen abrufbar ist. Kommt die
     ernste Warnung „Die Datenbank ist von außen abrufbar“, mach [Abschnitt 3](#3-datenordner-und-sicherheit). Erst
     danach lässt sich die Einrichtung abschließen. Diese Sperre schützt dich vor einem Versehen; ob der Ordner
     wirklich geschützt ist, zeigt sie nur, wenn der Server sich selbst erreichen konnte. Steht dort „Bitte von Hand
     prüfen“, konnte der Server sich selbst nicht erreichen: Rufe dann die angezeigte Adresse des Datenordners im
     Browser auf. Es muss „Verboten“ (403) oder „Nicht gefunden“ (404) erscheinen.
   - **Umschreibregeln:** Wirken sie nicht, sagt die Seite es dir. Dann läuft alles über `…/index.php`
     (z. B. `https://example.de/tokenlore/index.php`), und die Adresse in den Kopplungsbefehlen enthält `index.php`.
     Das ist in Ordnung. Steht dort „Unklar“, prüfst du es selbst: Ruf `…/api/healthz` auf. Kommt eine kurze Meldung
     in geschweiften Klammern (`{"error":…}`), wirken die Regeln; zeigt der Webserver eine eigene Fehlerseite, trag
     unter Team → Server die Serveradresse mit `/index.php` am Ende ein.
   - **Authorization-Header:** Kommt der Header mit dem Geräteschlüssel der Plugins nicht bei PHP an (Apache mit
     CGI/FastCGI), warnt die Seite und nennt die Zeilen, die der Hoster erlauben muss (`CGIPassAuth On` oder
     `SetEnvIf Authorization …`). Ohne sie können die Plugins nichts liefern.
3. **Besitz nachweisen:** Die Seite zeigt einen Code. Lege auf deinem Rechner eine Textdatei `setup-code.txt` an, die
   nur diesen Code enthält, und lade sie per FTP in den Ordner `data` (dort liegen schon `.htaccess` und `index.html`).
   Nur wer Dateien auf den Server laden kann, kommt so weiter. Ein Fremder, der die Adresse vor dir findet, kann die
   Einrichtung also nicht an sich reißen. Achte darauf, dass die Datei nicht `setup-code.txt.txt` heißt (Windows
   blendet Endungen oft aus). Der Code gilt nur in dem Browser, in dem du die Seite geöffnet hast, und nur, solange
   du sie zwischendurch neu lädst (spätestens alle zwei Stunden). Sonst zeigt die Seite einen neuen Code, und du
   ersetzt den Inhalt der Datei. Nach der Einrichtung löscht der Server die Datei selbst.
4. **Administrator-Konto anlegen:** das Formular (Schritt 5).

**Schritt 5: Erstes Konto anlegen.** Gib Benutzername und Passwort (zweimal) ein (Benutzername: 3 bis 32 Zeichen aus
Kleinbuchstaben, Ziffern, Punkt, Unterstrich und Bindestrich; Passwort: mindestens 12 Zeichen). Den Schalter „Dieser
Server steht hinter einem Proxy“ lässt du aus, außer die Seite schlägt ihn vor („Proxy erkannt“) oder du weißt, dass
ein Proxy davor steht; er lässt sich später unter „Team“, „Server“ ändern. Dann klicke auf „Einrichtung abschließen“.
**Das erste Konto wird automatisch Admin.** Danach ist die Einrichtungsseite dauerhaft gesperrt.

> **Mach diesen Schritt bald nach dem Hochladen.** Ohne die Datei `setup-code.txt` kann zwar niemand das erste Konto
> anlegen, die Einrichtungsseite bleibt bis dahin aber für jeden sichtbar.

Die Bestätigung nennt die gespeicherte Serveradresse (sie steht später in den Kopplungsbefehlen) und prüft den
Datenordner noch einmal. Mit „Weiter zur Anmeldung“ meldest du dich an und kannst [Geräte koppeln](#4-geräte-koppeln).

### Installation und Update per Git beim Hoster

Viele Panels können ein Git-Repo selbst holen und in einen Ordner legen, bei Plesk unter „Websites & Domains“, „Git“.
Dann brauchst du für Installation und Updates kein FTP-Programm. So geht es bei Plesk:

1. „Git“ öffnen, „Remote-Git-Hosting“ wählen und als Adresse `https://github.com/tokenlore/tokenlore-server.git`
   eintragen. Das Repo ist öffentlich, Zugangsdaten brauchst du nicht.
2. **Bereitstellungsmodus „Manuell“** wählen. Dann kommt ein Update nur, wenn du es auslöst, und du kannst vorher den
   Datenordner sichern ([Abschnitt 5](#5-updates)).
3. **Bereitstellungspfad:** der Ordner, in dem tokenlore laufen soll, z. B. `httpdocs` oder `httpdocs/tokenlore`
   (siehe Schritt 2 oben). Zweig: `main`, dort liegt immer die neueste Version.
4. „Bereitstellen“ klicken. Danach geht es weiter mit Schritt 4 oben (Einrichtungsseite öffnen).

**Der Ordner `.git` gehört nicht in den Web-Ordner.** Er enthält das ganze Repo und hat im Web nichts zu suchen.
Prüfe nach dem ersten Bereitstellen per FTP (mit eingeblendeten versteckten Dateien), dass im Bereitstellungspfad
**kein** Ordner `.git` liegt. Liegt doch einer da, nimm den Weg über ZIP und FTP; die `.htaccess` sperrt ihn zwar, aber
nur, solange dein Webserver sie liest.

Ein automatisches Bereitstellen bei jeder neuen Version bräuchte einen Webhook im GitHub-Repo von tokenlore, den nur
dessen Betreuer einrichten können. Rufe neue Versionen deshalb selbst ab ([Abschnitt 5](#5-updates)).

Datenbank, Sicherungen und `config.local.php` gehören nicht zum Repo; beim Bereitstellen sollten sie deshalb
unberührt bleiben. Sichere den Datenordner trotzdem vor dem ersten Bereitstellen und vor jedem Update
([Abschnitt 5](#5-updates)), vor allem, wenn du von einer Installation per ZIP auf Git umsteigst.

Andere Panels (etwa cPanel mit „Git Version Control“) arbeiten ähnlich; wichtig ist dort genauso, dass das Repo selbst
außerhalb des Web-Ordners liegt.

---

## 3. Datenordner und Sicherheit

**Meldet die Einrichtungsseite beim Datenordner keine Warnung („Datenbank geschützt“ oder „Datenordner außerhalb des
Web-Ordners“), bist du hier fertig.** Lies dann nur noch „Sicherung von Hand“ am Ende dieses Abschnitts.

Im Ordner `data/` liegt alles, was du nicht verlieren willst: die Datenbank (eine Datei
`tokenlore-<32 zufällige Zeichen>.sqlite`, solange der Server arbeitet dazu `…-wal` und `…-shm`), die automatischen
Sicherungen (`backup-…sqlite`) und ab und zu kurzlebige Hilfsdateien (`setup-code.txt`, `reset-admin.txt`, Sperrdateien). **Aus dem
Internet darf davon nichts abrufbar sein.** Dafür sorgen mehrere Schichten:

1. `data/.htaccess` verbietet auf Apache jeden Abruf, und `data/index.html` ist eine leere Seite.
2. Die Datenbankdatei hat einen zufälligen Namen, den niemand erraten kann.
3. Die Einrichtungsseite prüft selbst, ob der Abruf von außen möglich wäre. Falls ja, lässt sie sich erst abschließen,
   wenn das behoben ist.

Versteckte Pfade (`.git/`, `.env`, alles mit führendem Punkt außer `.well-known`) sperrt die `.htaccess` im
Installationsordner. Ein Ordner wie `.git/` wäre allerdings offen, wenn dein Apache weder mod_rewrite noch mod_alias
hat (oder `.htaccess` ganz ignoriert); lade solche Ordner deshalb nie in den Web-Ordner hoch.

**Warum eine Warnung kommen kann:** Manche Hoster ignorieren `.htaccess` (Einstellung `AllowOverride None`), und
nginx kennt `.htaccess` gar nicht. Dann hilft eine der folgenden Möglichkeiten.

### Möglichkeit A (am sichersten): Datenordner außerhalb des Web-Ordners

Lege einen Ordner **neben** deinen Web-Ordner, den kein Browser erreicht. Bei Plesk liegt dein Web-Ordner z. B. in
`/var/www/vhosts/example.de/httpdocs`; der neue Ordner wäre `/var/www/vhosts/example.de/tokenlore-daten`.

Die Datei `config.local.php`, die dem Server den Ordner nennt, sieht immer so aus:

```php
<?php
return ['data_dir' => '/var/www/vhosts/example.de/tokenlore-daten'];
```

Statt des vollen Pfades geht auch ein Pfad ab dem Installationsordner. Liegt tokenlore in `httpdocs/tokenlore` und
der Datenordner neben `httpdocs`, ist das `'../../tokenlore-daten'`. Die Datei gehört **nicht** zu tokenlore, ein
Update (per ZIP oder Git) überschreibt sie also nie.

**Fall 1: Neue Installation (noch kein Konto angelegt).**

1. Lege den neuen Ordner per FTP an. PHP muss darin schreiben dürfen.
2. Lege auf deinem Rechner `config.local.php` mit dem Inhalt oben (mit deinem Pfad) an und lade sie in den
   Installationsordner, neben `index.php`.
3. Lade die Einrichtungsseite neu. Beim Datenordner steht jetzt „Datenordner außerhalb des Web-Ordners“. Lege dann das
   Konto an.

**Fall 2: Laufende Installation (es gibt schon Konten und Daten).**

1. Lege den neuen Ordner per FTP an. PHP muss darin schreiben dürfen.
2. **Benutze die Seite ab jetzt nicht mehr, bis du fertig bist**, und lass auch die Geräte ruhen, so gut es geht (ein
   Plugin, das gerade liefert, schreibt in die Datenbank). Sonst kopierst du eine halb geschriebene Datenbank.
3. Kopiere **alle Dateien `tokenlore-*.sqlite*`** (Datenbank, `-wal` und `-shm`, sofern vorhanden) aus `data/` in den
   neuen Ordner. Die Sicherungen `backup-*.sqlite` kannst du mitnehmen.
4. Lege `config.local.php` mit dem Inhalt oben an und lade sie in den Installationsordner, neben `index.php`. Ab jetzt
   nutzt der Server den neuen Ordner.
5. Melde dich an und prüfe, ob deine Zahlen da sind. Erst dann löschst du die Datenbankdateien aus dem alten
   Ordner `data/` (die Dateien `.htaccess` und `index.html` dort bleiben liegen).

Den vollen Pfad deines Webspace nennt dir das Panel oder die Hilfe deines Hosters. Manche Hoster erlauben PHP nur Pfade innerhalb des eigenen Webspace; ein Ordner neben `httpdocs`
liegt dort in der Regel noch drin.

### <a id="nginx"></a>Möglichkeit B: Regel für nginx

Läuft vor oder statt Apache ein nginx, der `.htaccess` nicht liest, sperre die Ordner mit einer Regel in der nginx-
Konfiguration. Bei Plesk trägst du sie unter „Websites & Domains“, „Apache & nginx-Einstellungen“ im Feld „Zusätzliche
nginx-Anweisungen“ ein. Beispiel für den Unterordner `/tokenlore/` (bei einer Installation im Wurzelordner entfällt
das Präfix):

```nginx
location ^~ /tokenlore/data/ { return 404; }
location ^~ /tokenlore/app/  { return 404; }
location ~* \.(sqlite3?|db)(-wal|-shm|-journal)?$ { return 404; }
```

Kennst du dich damit nicht aus, frag deinen Hoster oder nimm Möglichkeit A. Prüfe danach auf der Einrichtungsseite oder
im Browser, dass `https://example.de/tokenlore/data/index.html` **nicht** mehr erreichbar ist (die Datei soll ein
404 oder 403 liefern).

### Passwortschutz für die Webseite (freiwillig)

Wer die Adresse kennt, sieht die Anmeldeseite von tokenlore. Willst du, dass Fremde gar nichts sehen, schalte davor den
Passwortschutz deines Webservers (Basic-Auth): Der Browser fragt dann zuerst nach einem zweiten Benutzernamen und
Passwort. Die Webseite funktioniert dahinter ganz normal.

**Vier Adressen müssen frei bleiben:** `…/api/plugin/pair`, `…/api/plugin/ingest`, `…/api/plugin/ca` und `…/api/plugin/info`. Über sie
liefern die Plugins. Sie schicken ihren Geräteschlüssel im selben Header, den der Passwortschutz braucht, und können
kein zweites Passwort mitsenden. Die eingebaute Funktion „Passwortgeschützte Verzeichnisse“ von Plesk kann solche
Ausnahmen nicht. Nimm deshalb eine der Regeln unten. Sie lassen außerdem `/.well-known/acme-challenge/` frei, damit
die automatische Verlängerung deines Zertifikats (Let's Encrypt) weiter klappt.

**Erst nach der Einrichtung einschalten.** Die Einrichtungsseite ruft für ihre Prüfungen den eigenen Server ab, ohne
Passwort. Mit Passwortschutz meldet sie dann falsche Ergebnisse (etwa „Umschreibregeln wirken nicht“).

**Schritt 1: Passwortdatei anlegen.** Die Datei heißt meist `.htpasswd` und enthält je Person eine Zeile
`name:verschlüsseltes-passwort`. Lege sie **außerhalb** des Web-Ordners ab, bei Plesk z. B. in
`/var/www/vhosts/example.de/tokenlore-passwort/.htpasswd`.

Die Zeile erzeugst du auf deinem Rechner mit `openssl`. Unter Windows öffnest du dazu die „Git Bash“ (sie kommt mit
Git für Windows, das Claude Code unter Windows ohnehin braucht), unter macOS und Linux das Terminal:

```
openssl passwd -apr1
```

Der Befehl fragt zweimal nach dem Passwort (es erscheint dabei nicht auf dem Bildschirm) und gibt eine Zeile wie
`$apr1$…` aus. Die Zeile in der Passwortdatei ist dann `betreiber:` und direkt dahinter diese Ausgabe, also
`betreiber:$apr1$…`. Apache und nginx verstehen dieses Format beide.

**Schritt 2: Regel eintragen (Apache, der Normalfall auch bei Plesk).** Die Regel darf **nicht** in die `.htaccess`
von tokenlore: Die ersetzt jedes Update. Je nach Ort der Installation:

- **tokenlore liegt in einem Unterordner** (z. B. `httpdocs/tokenlore`): Lege die Regel in eine `.htaccess` im Ordner
  **darüber** (`httpdocs/.htaccess`, an den Anfang, falls es die Datei schon gibt):

  ```apache
  SetEnvIf Request_URI "^/tokenlore/(index\.php/)?api/plugin/(pair|ingest|ca|info)$" TL_FREI=1
  SetEnvIf Request_URI "^/\.well-known/acme-challenge/" TL_FREI=1
  AuthType Basic
  AuthName "tokenlore"
  AuthUserFile /var/www/vhosts/example.de/tokenlore-passwort/.htpasswd
  <RequireAny>
      Require env TL_FREI REDIRECT_TL_FREI
      Require valid-user
  </RequireAny>
  ```

  Ersetze `/tokenlore/` durch deinen Unterordner und den Pfad bei `AuthUserFile` durch deinen. Achtung: Die Regel
  schützt dann auch alles andere in `httpdocs`.

- **tokenlore liegt im Wurzelordner einer Domain**: Trag die Regel bei Plesk unter „Websites & Domains“, „Apache &
  nginx-Einstellungen“ in **beide** Felder „Zusätzliche Apache-Anweisungen“ (HTTP und HTTPS) ein:

  ```apache
  <Directory "/var/www/vhosts/example.de/httpdocs">
      SetEnvIf Request_URI "^/(index\.php/)?api/plugin/(pair|ingest|ca|info)$" TL_FREI=1
      SetEnvIf Request_URI "^/\.well-known/acme-challenge/" TL_FREI=1
      AuthType Basic
      AuthName "tokenlore"
      AuthUserFile /var/www/vhosts/example.de/tokenlore-passwort/.htpasswd
      <RequireAny>
          Require env TL_FREI REDIRECT_TL_FREI
          Require valid-user
      </RequireAny>
  </Directory>
  ```

Warum zwei Namen (`TL_FREI` und `REDIRECT_TL_FREI`)? Apache leitet `…/api/plugin/ingest` intern an `index.php` weiter
und prüft dabei ein zweites Mal; dann trägt die Markierung den Vorsatz `REDIRECT_`. Von außen lässt sie sich nicht
setzen.

**Plesk mit nginx davor:** Bei Plesk steht oft ein nginx vor Apache, der Dateien wie Bilder, Schriften und Skripte
selbst ausliefert, ohne Apache und damit ohne den Passwortschutz zu fragen. Diese Dateien sind die öffentlichen Teile
der Webseite (dieselben wie im Repo auf GitHub), deine Zahlen gehören nicht dazu. Willst du auch sie schützen, schalte
unter „Apache & nginx-Einstellungen“ „Statische Dateien direkt von nginx bereitstellen“ aus.

**Nur nginx (ohne Apache dahinter):** Die Regel kommt in die nginx-Konfiguration, in denselben `server { … }` wie die
Sperren aus [Möglichkeit B](#nginx), die du dort ebenfalls brauchst. Das Beispiel gilt für den Unterordner
`/tokenlore/` mit PHP-FPM; passe Pfade und `fastcgi_pass` an deine Konfiguration an. Im Wurzelordner entfällt überall
das `/tokenlore` (aus `/tokenlore/index.php` wird `/index.php`, aus `location /tokenlore/` wird `location /`). Der
Block mit `map` steht außerhalb von `server { … }`.

```nginx
map $request_uri $tl_auth {
    "~^/tokenlore/(index\.php/)?api/plugin/(pair|ingest|ca|info)(\?.*)?$" off;
    default "tokenlore";
}

server {
    # … deine übrigen Einstellungen und die Sperren aus Möglichkeit B …
    location /tokenlore/ {
        auth_basic $tl_auth;
        auth_basic_user_file /var/www/vhosts/example.de/tokenlore-passwort/.htpasswd;
        index index.php;
        try_files $uri $uri/ /tokenlore/index.php$is_args$args;

        # Versteckte Dateien (.htaccess, .gitattributes …) nie ausliefern.
        location ~ /\. { return 404; }
        # index.html nur über index.php (sie setzt die Sicherheits-Header der Seite).
        location = /tokenlore/index.html { rewrite ^ /tokenlore/index.php last; }

        location ~ ^/tokenlore/index\.php(/|$) {
            auth_basic $tl_auth;
            auth_basic_user_file /var/www/vhosts/example.de/tokenlore-passwort/.htpasswd;
            fastcgi_split_path_info ^(.+\.php)(/.*)$;
            include fastcgi_params;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param PATH_INFO $fastcgi_path_info;
            fastcgi_param HTTP_AUTHORIZATION $http_authorization;
            fastcgi_pass unix:/run/php/php-fpm.sock;
        }
    }
}
```

**Schritt 3: Prüfen.** Öffne in einem privaten Browserfenster:

- die Webseite: Erst kommt die Passwortabfrage, danach die Anmeldung von tokenlore;
- `…/favicon.svg`: Auch hier kommt die Passwortabfrage (sonst siehe „Plesk mit nginx davor“);
- `…/api/plugin/ca`: Diese Adresse antwortet **ohne** Passwortabfrage (ohne eigene CA mit der kurzen Meldung
  `{"error":"Nicht gefunden"}`).

Lass zum Schluss auf einem Gerät `/tokenlore:sync` laufen; auf der Seite „Geräte“ muss sich danach „Letzter Abgleich“
aktualisieren. Prüfungen von außen wie `curl …/healthz` brauchen dann das Passwort (`curl -u name …`).

### Sicherung von Hand

Der Server legt vor jeder Änderung am Datenbankaufbau selbst eine Sicherung an ([Abschnitt 5](#5-updates)). Das ersetzt
keine regelmäßige Kopie: Lade ab und zu **alle Dateien `tokenlore-*.sqlite*`** aus dem Datenordner herunter
(Datenbank, `-wal` und `-shm` immer zusammen; sie gehören zusammen).

---

## 4. Geräte koppeln

Ein „Gerät“ ist ein Rechner, auf dem Claude Code läuft. Dort schickt das tokenlore-**Plugin** nur Zahlen und
Metadaten an deinen Server, nie Inhalte. Was genau gesendet wird, zeigt die Seite „Datenschutz“. Jede Anfrage legt
das Plugin zuerst unterschrieben in einem Archiv auf dem Rechner ab und liefert dann daraus, beim Start und nach dem
Ende jeder Claude-Code-Sitzung. Nach dem Ende einer Sitzung höchstens alle 5 Minuten: Kam der letzte Abgleich vor
weniger als 5 Minuten, kommt die letzte Anfrage der Sitzung mit dem ersten Abgleich, der mindestens 5 Minuten nach
dieser Anfrage läuft; dabei geht nichts verloren, und nichts zählt doppelt. Ist dein Server mal nicht erreichbar, geht
ebenfalls nichts verloren; dein Server nimmt nur Zeilen mit gültiger Unterschrift des Geräts an.

**Halte das Plugin auf dem neuesten Stand.** Es prüft das Zertifikat deines Servers wie ein Browser und versteht
Adressen mit Pfad. Ein veraltetes Plugin koppelt und liefert nicht; aktualisiere es dann wie in Schritt 1. Hast du
schon einen anderen tokenlore-Server, koppelst du jedes Gerät hier zusätzlich; die älteren Zahlen schickt das Plugin
dabei auch an diesen Server ([siehe unten](#ein-rechner-bleibt-ein-gerät)).

**Schritt 1: Plugin installieren oder aktualisieren.** Auf dem Gerät in einer `claude`-Sitzung im Terminal:

```
/plugin marketplace add tokenlore/tokenlore
/plugin install tokenlore@tokenlore
```

Schon installiert? Dann aktualisieren (`claude plugin marketplace update tokenlore`, danach
`claude plugin update tokenlore@tokenlore`, dann `/reload-plugins`).

**Schritt 2: Kopplungszeile holen.** Melde dich auf deiner Webseite an, öffne „Einstellungen“ und dort „Gerät
hinzufügen“, dann „Code erzeugen“. Die Seite zeigt die fertige Zeile:

```
/tokenlore:connect https://example.de/tokenlore 123456
```

Der Code ist 6-stellig, gilt **10 Minuten** und **nur einmal**. Ein neuer Code macht den vorherigen von dir ungültig.

**Schritt 3: Zeile in Claude Code einfügen.** Füge die Zeile auf dem Gerät in Claude Code ein. Mit `--name "Mein Laptop"`
am Ende vergibst du einen Gerätenamen (sonst nimmt das Plugin den Rechnernamen).

> Füge nur Zeilen ein, die **dein eigener Server** angezeigt hat. Eine fremde Zeile koppelt dein Gerät mit einem fremden
> Server.

**Zu `--ca`.** Die Adresse ist normalerweise alles, was das Plugin braucht, weil dein Server ein normales Zertifikat des
Hosters hat. `--ca <Fingerabdruck>` steht nur dann in der Zeile, wenn du (als Admin) unter „Team“, „Server“ ein
Zertifikat einer **eigenen CA** hinterlegt hast, etwa für einen Server im Heimnetz mit selbst ausgestelltem Zertifikat.
Die Webseite fügt es dann selbst ein; du musst nichts tippen.

**Zur Adresse.** Die Adresse in der Zeile ermittelt der Server selbst. Stimmt sie nicht (etwa hinter einem Proxy),
korrigiere sie als Admin unter „Team“, „Server“, „Öffentliche Adresse“. Liegt der Server in einem Unterordner und die
Umschreibregeln fehlen, enthält sie `/index.php`. Auch das ist richtig.

**Zum Testen:** Das Plugin verbindet nur über HTTPS. Auf `http://localhost` lässt sich deshalb der Server selbst
ausprobieren, aber nicht mit dem echten Plugin koppeln. Teste die Kopplung auf deinem echten Webspace: Nach dem
Koppeln sollten auf der Seite „Geräte“ dein Gerät und nach kurzer Zeit die ersten Zahlen erscheinen.

### Ein Rechner bleibt ein Gerät

Ein Rechner bleibt auf deinem Server immer **ein** Gerät, egal ob du es sperrst, neu koppelst oder das Plugin neu
installierst. Das Plugin legt dafür beim ersten Koppeln eine kleine Datei `tokenlore-id` in den Claude-Ordner des
Rechners (meist `~/.claude`) und löscht sie nie. Daran erkennt der Server den Rechner wieder. Ein zweiter Rechner hat
seine eigene Datei und wird ein eigenes Gerät; seine Zahlen kommen zu denen des ersten hinzu.

**Neu koppeln.** Koppelst du einen Rechner, den der Server schon kennt, mit einem neuen Code, landet er beim selben
Gerät. Seine Zahlen bleiben, der alte Schlüssel wird gesperrt, und eine Sperre des Geräts ist aufgehoben. Claude Code
meldet dann „Bestehendes Gerät neu gekoppelt“. So holst du auch ein gesperrtes Gerät zurück. Der Name des Geräts
bleibt dabei, etwa einer, den du auf der Seite „Geräte“ vergeben hast. Nur mit `--name` bekommt es den neuen Namen.

**Code für ein bestimmtes Gerät.** Erkennt der Server den Rechner nicht wieder (etwa weil die Datei `tokenlore-id`
gelöscht wurde), öffne auf der Seite „Geräte“ das Gerät und dort unter „Neu koppeln“ den Knopf „Code für dieses
Gerät“. Die Kopplungsseite zeigt dann, für welches Gerät der Code gilt. Mit diesem Code koppelt genau dieses Gerät neu,
statt dass ein neues entsteht. Gehört der Rechner schon zu einem anderen deiner Geräte, lehnt der Server den Code ab,
und es ändert sich nichts.

**Ältere Zahlen (Altbestand).** Claude Code führt auf jedem Rechner eine Tagesübersicht, auch aus der Zeit vor
tokenlore. Das Plugin übernimmt sie einmal in sein Archiv und schickt sie nach jedem Koppeln an den Server, auf jedem
Server, mit dem du koppelst. Der Server behält für jeden Tag die zuerst angekommene Angabe und ändert sie nie. Deshalb
kommt der Altbestand überall an und zählt nie doppelt, auch wenn du dasselbe Gerät mehrmals koppelst. Einen Tag, den
ein anderes Gerät schon mit genau denselben Werten hat, zählt nur dieses.

**Zusammenlegen.** Zeigen zwei deiner Geräte dieselben abgeschlossenen Tage, ist es wahrscheinlich derselbe Rechner
(etwa nachdem die Datei `tokenlore-id` verloren ging). Die Seite „Geräte“ zeigt dann „… hat dieselben Tage wie …
Zusammenlegen?“. Erst wenn du auf „Zusammenlegen …“ klickst und bestätigst, wird aus beiden ein Gerät: Zahlen,
Schlüssel und Kennungen gehen auf das verbleibende Gerät über, nichts zählt doppelt, und das Plugin sendet ohne neue
Kopplung weiter. Das lässt sich nicht rückgängig machen. Ohne deine Bestätigung legt der Server nie Geräte zusammen.
Hast du bei der Frage nach dem Vorgänger (siehe unten) „Nein“ gewählt, schlägt die Seite diese beiden Geräte nie zum
Zusammenlegen vor.

**Claude-Ordner kopiert oder aus einer Sicherung geholt.** Hast du einen Rechner neu aufgesetzt und `~/.claude` aus
einer Sicherung zurückgeholt, oder den Ordner von einem anderen Rechner kopiert, liefert das Plugin dort nichts, bis
du neu koppelst. Gehört der ursprüngliche Rechner auf deinem Server zu deinen Geräten, fragt `/tokenlore:connect` in
Claude Code in einem Auswahlfenster, ob dieser Rechner das alte Gerät ist. Die Frage nennt das alte Gerät und seine
letzte Lieferung, jede Antwort sagt kurz, was danach passiert, und die empfohlene steht zuerst:

- Hat das alte Gerät in den letzten 24 Stunden geliefert, scheint es in Gebrauch zu sein. Die Frage warnt davor und
  empfiehlt „Nein“.
- Sonst empfiehlt sie „Ja“, etwa nach einem neu aufgesetzten Rechner.

Entscheiden musst du; der Server entscheidet nie allein. Was nach jeder Antwort passiert:

- **„Ja: dieser Rechner wird „…““:** Der Rechner macht als das alte Gerät weiter, mit allen Zahlen. Die älteren Tage
  aus dem zurückgeholten Ordner zählen nicht zusätzlich zu Tagen, an denen das alte Gerät schon einzelne Anfragen
  geliefert hat. Liefert ein anderer Rechner als dieses Gerät, liefert er danach nichts, bis du ihn neu koppelst.
- **„Nein: eigenes Gerät …“:** Der Rechner wird ein eigenes Gerät, das alte liefert unverändert weiter. Alte Tage, die
  beide aus demselben Ordner haben, können doppelt zählen. Für diese beiden Geräte kommt die Frage nie wieder, weder
  in Claude Code noch auf der Webseite.
- **„Später: eigenes Gerät, auf der Webseite entscheiden“:** Der Rechner wird ein eigenes Gerät und liefert. Die Seite „Geräte“ zeigt
  oben die Frage mit denselben Angaben, derselben Empfehlung und den Folgen je Antwort, dazu die Zahl gleicher Tage
  beider Geräte. „Ja, derselbe Rechner“ legt beide Geräte sofort zusammen und wirkt wie „Ja“ in Claude Code; das lässt
  sich nicht rückgängig machen. „Nein, ein anderer Rechner“ wirkt wie „Nein“ in Claude Code.

Schließt du das Fenster ohne Antwort, wird nichts gekoppelt; der Code bleibt bis zu seinem Ablauf gültig, und Claude
Code zeigt die drei fertigen Befehle zum Antworten. Die Antwort lässt sich auch gleich beim Koppeln mitgeben, etwa
`/tokenlore:connect … --vorgaenger gleich` (Ja), `--vorgaenger neu` (Nein) oder `--vorgaenger spaeter` (Später).

Keine Frage kommt, wenn der ursprüngliche Rechner auf deinem Server nicht zu deinen Geräten gehört, wenn du einen Code
für ein bestimmtes Gerät benutzt oder wenn der Server den Rechner schon kennt. Dann wird gekoppelt wie oben
beschrieben; Anfragen, die schon der ursprüngliche Rechner geliefert hat, zählen nicht doppelt. Ziehst du ganz auf
einen neuen Rechner um, ohne den Ordner mitzunehmen, sperre das alte Gerät auf der Seite „Geräte“.

**Hinweis „lag schon bei einem anderen Benutzer oder Gerät“.** Jede Anfrage und jede Sitzung zählt auf dem Server nur
einmal, bei dem Benutzer, der sie zuerst geliefert hat. Liefert ein anderer Benutzer dieselbe Anfrage oder arbeitet er
in derselben Sitzung weiter, zählt das nur beim ersten. Ebenso zählt ein Tag aus dem Altbestand, den ein anderes Gerät
schon mit genau denselben Werten hat, nur dort, etwa bei einem kopierten Claude-Ordner. Die Seite „Geräte“ zeigt dann
beim Gerät, wie viele Anfragen und Tage das betrifft. Das ist kein Fehler: Die Kopplung gilt, und alles andere zählt
normal.

---

## 5. Updates

Es gibt **kein automatisches Update**. Das ist Absicht, denn ein Server, der sich selbst Programme holt, wäre ein
Sicherheitsrisiko. Ein Update ist: neue Version einspielen, per ZIP und FTP oder per Git beim Hoster. Was sich je
Version ändert, steht in `CHANGELOG.md`.

**Per Git beim Hoster** (wenn du so installiert hast, [siehe Abschnitt 2](#installation-und-update-per-git-beim-hoster)):

1. **Kopiere zuerst deinen Datenordner auf deinen Rechner** (wie in Schritt 2 unten).
2. Klicke bei Plesk unter „Git“ auf „Abrufen“ und dann auf „Bereitstellen“.
3. Rufe die Seite einmal im Browser auf (wie in Schritt 5 unten). Die Datei `VERSION` im Installationsordner zeigt
   danach die neue Version.

**Per ZIP und FTP:**

1. Lade die neue Version als ZIP herunter ([Abschnitt 2](#2-installation), Schritt 1) und entpacke sie auf deinem
   Rechner.
2. **Kopiere zuerst deinen Datenordner auf deinen Rechner. Das ist Pflicht.** Gemeint ist `data/` im
   Installationsordner, oder der Ordner, der in deiner `config.local.php` steht (siehe „Sicherung von Hand“ in
   [Abschnitt 3](#3-datenordner-und-sicherheit)). Benutze die Seite währenddessen nicht.
3. Lösche auf dem Server den Ordner `app/` (er enthält nur Programmcode, keine Daten), damit keine veralteten Dateien
   übrig bleiben.

   > **Lösche nur `app/`, niemals `data/`.** Die Namen sehen sich ähnlich, und daneben liegt noch `_app/` (Dateien der
   > Webseite). In `data/` liegen deine Datenbank und die Sicherungen. Was dort gelöscht ist, ist weg.

4. Lade den Inhalt des Ordners `tokenlore-server-…` per FTP in denselben Ordner wie bei der Installation und
   überschreibe die vorhandenen Dateien. **Lade den Ordner `data/` dabei nicht mit hoch** (im FTP-Programm abwählen
   oder beim Nachfragen „Überspringen“ wählen). Er enthält ohnehin nur die zwei Sperrdateien `data/.htaccess` und
   `data/index.html`. Lädt dein FTP-Programm ihn doch mit, werden genau diese zwei Dateien ersetzt, **deine Daten
   nie**: Die ZIP enthält keine Datenbank, keine Sicherung und keine `config.local.php`.
5. Rufe die Seite einmal im Browser auf. Der Server bringt die Datenbank beim ersten Aufruf **selbst** auf den neuen
   Stand.

**Sicherungen entstehen automatisch.** Muss der Aufbau der Datenbank geändert werden, legt der Server **vorher** im
Datenordner eine Kopie an: `backup-<alter Stand>-<Zeitpunkt>-<Zufallszeichen>.sqlite`. Die fünf neuesten bleiben
liegen, ältere werden gelöscht. Geht bei der Umstellung etwas schief, bleibt die Datenbank unverändert.

**Manche Datenbanken lassen sich nicht umstellen.** Stammt deine Datenbank von einer Version, die die Zahlen
anders gespeichert hat, ändert der Server an ihr nichts. Die Webseite zeigt dann „Die Datenbank stammt von einer
älteren Version“ mit den Schritten: Datenordner sichern, die Datenbank löschen, tokenlore neu einrichten und die
Rechner neu koppeln. Die Plugins schicken danach alles aus ihrem Archiv erneut, auch die älteren Zahlen.

Die laufende Version steht in der Datei `VERSION` im Installationsordner.

**Eine Sicherung zurückspielen:** Lade die aktuelle Datenbank (`tokenlore-*.sqlite` samt `-wal` und `-shm`) aus dem
Datenordner herunter und lösche sie dort. Benenne dann die gewünschte Sicherung um in `tokenlore-<beliebige
Zeichen>.sqlite`. Im Datenordner darf immer nur **eine** Datenbank `tokenlore-*.sqlite` liegen.

---

## 6. Team

Eine Installation funktioniert wie ein Team-Konto bei Claude: Es gibt mehrere Konten, und Admins sehen die Nutzungsdaten
des Teams. Für dich allein reicht das erste Konto, das du bei der Einrichtung angelegt hast.

**Rollen**

- **Admin:** Sieht alle Zahlen des Teams, legt Konten an, vergibt und entzieht Admin-Rechte, setzt Passwörter zurück,
  beendet Sitzungen, sperrt Konten und ändert die Server-Einstellungen (Adresse, Zertifikat, Proxy). Das erste Konto ist
  Admin. Der **letzte** Admin kann sich die Rechte nicht selbst entziehen und nicht gesperrt werden.
- **Mitglied:** Sieht nur die eigenen Zahlen und koppelt die eigenen Geräte.

**Wo?** Admins finden den Bereich „Team“ in der Navigation. „Übersicht“ zeigt die Statistik jedes Mitglieds und die
Summe über das Team. Unter „Mitglieder“ legst du neue Konten an (Benutzername und Passwort geben Admins dem neuen
Mitglied auf einem sicheren Weg weiter; ändern kann es das Passwort selbst unter „Einstellungen“) und verwaltest
bestehende: Admin-Rechte vergeben oder entziehen, neues Passwort setzen, alle Sitzungen beenden, sperren und entsperren.
„Server“ enthält die Server-Einstellungen und zeigt oben, ob die PHP-Erweiterung `sodium` angeschaltet ist; fehlt sie,
steht dort, wo du sie anschaltest.

**Hinweis an Mitglieder.** Sag jedem Mitglied **vorher**, dass Admins seine Nutzungsdaten einsehen können. Gesehen wird
nur, was das Plugin ohnehin sendet: Zahlen und Metadaten wie Zeiten, Modelle, Werkzeugnamen und Geräte, nie Inhalte (je
nach gewählter E-Mail-Stufe des Geräts auch die E-Mail-Adresse des Claude-Kontos). Mitglieder sehen in ihrem Konto
selbst einen deutlichen Hinweis darauf: „Admins dieser Installation können deine Nutzungsdaten einsehen.“

---

## 7. Notfall-Zugang

Hat kein Admin mehr Zugang (Passwort vergessen), kommst du mit Zugriff auf den Datenordner per FTP wieder hinein. Ohne
diesen Zugriff geht es bewusst nicht.

1. Öffne die Anmeldeseite und klicke auf **„Kein Admin-Zugang mehr?“**. Du landest auf der Seite „Notfall-Zugang“.
2. Klicke auf **„Code anzeigen“**. Die Seite zeigt einen Code und den Dateinamen `reset-admin.txt`. Der Code steht nur
   auf dieser Seite. Lädst du sie neu, brauchst du einen neuen.
3. Lege auf deinem Rechner eine **frische** Textdatei mit dem Namen `reset-admin.txt` an, die nur den Code enthält
   (Leerraum am Rand stört nicht), und lade sie per FTP in den **Datenordner** hoch (`data/`, oder der Ordner aus deiner
   `config.local.php`).
   - Die Datei muss **neu** sein: Ihr Änderungsdatum darf nicht älter als eine Stunde sein. Manche FTP-Programme
     übernehmen das Datum von deinem Rechner. Speichere die Datei deshalb direkt vor dem Hochladen neu.
   - Klappt es nicht, prüfe, ob die Uhr deines Rechners ungefähr stimmt.
4. Klicke auf **„Die Datei liegt bereit“**. Trage dann den **Benutzernamen** des Kontos ein, das wieder Admin werden
   soll, und ein **neues Passwort** (mindestens 12 Zeichen), und klicke auf „Zugang zurücksetzen“.

Der Server ersetzt das Passwort, macht das Konto zum Admin, hebt eine Sperre auf, meldet es überall ab und löscht danach
die Datei und den Code. Danach meldest du dich normal an.

**Sicherheit:** Code und Datei gelten höchstens **eine Stunde**, danach werden beide gelöscht. Ohne Schreibzugriff auf
den Datenordner kann niemand die Datei anlegen. Ein Fremder kann den Ablauf deshalb nicht ausnutzen, auch nicht mit einer
liegengebliebenen Datei, denn die gehört zu einem Code, den nur du gesehen hast.

**Meldung „Die Notfall-Datei fehlt, ist älter als eine Stunde oder enthält einen anderen Code“:** Prüfe den Dateinamen (genau `reset-admin.txt`), den Ordner (der
Datenordner, in dem auch die Datenbank liegt), den Inhalt (nur der Code, der **aktuell** angezeigt wird) und das Alter
der Datei (unter einer Stunde).

---

## 8. Bekannte Grenzen

tokenlore ist für den privaten Gebrauch gedacht, also für dich und einen kleinen Kreis. Das ist bewusst so und wird
hier offen gesagt:

- **Fehlversuche beim Koppeln werden global gezählt.** Ein falscher Kopplungscode zählt gegen die aktuell offenen Codes
  aller Konten (ein Code trägt keinen Benutzernamen). Fünf Fehlversuche machen sie ungültig. Ein Angreifer, der die
  Adresse kennt, kann die Kopplung damit **zeitweise stören**: Dann hole einfach einen neuen Code. Er kann dadurch
  **keine Geräte übernehmen** und sieht keine Daten.
- **PHP-Warnungen bei `display_errors=On`.** In seltenen Fällen kann PHP dann Dateipfade in einer Antwort zeigen.
  Bitte deinen Hoster, `display_errors` auszuschalten (oder stelle es im Panel selbst auf `Off`).
- **Apache-Fehlerseiten haben keine Sicherheits-Header.** Seiten, die Apache selbst erzeugt (etwa die 403-Seite für
  gesperrte Ordner), tragen nicht die Sicherheits-Header, die der Server sonst setzt. Sie enthalten keine Daten.
- **Wer den Server betreibt, sieht alle Zahlen** (keine Inhalte, aber Zeiten, Modelle, Werkzeugnamen und je nach
  E-Mail-Stufe die Adresse). Das gilt auch für Admins ([Abschnitt 6](#6-team)). Auf gemietetem Webspace kann außerdem
  dein Hoster die Datenbankdatei im Datenordner und die Logs lesen.
- **Der Hinweis beim Gerät verrät etwas.** Zeigt ein Gerät, dass Anfragen oder Tage schon anderswo lagen, weiß sein
  Benutzer: Genau diese Anfrage oder genau diese Tageswerte liegen schon bei jemandem auf diesem Server. Wer, sieht er
  nicht.
- **Kein Betrieb für große Teams.** Gedacht ist der Server für wenige Personen und Geräte. Es gibt keine
  Echtheitsprüfung der Nutzungsdaten und keine Rangliste.
- **Kein automatisches Update und keine Übernahme alter Daten** aus dem früheren Go-Server ([Abschnitt 5](#5-updates)).
- **Neu eingerichteter Server heißt neue Geräte.** Das Plugin erkennt einen Rechner an der Kennung des Servers, die
  bei der Einrichtung entsteht und in der Datenbank steht. Ziehst du mit deinem Datenordner auf eine andere Adresse um,
  bleibt jeder Rechner nach dem Neukoppeln sein bisheriges Gerät. Richtest du den Server neu ein, erscheint jeder
  Rechner als neues Gerät.

---

## 9. Fehlersuche

**Die Einrichtungsseite meldet einen Fehler bei den Voraussetzungen.** Stelle im Panel deines Hosters PHP 8.2 oder neuer
ein und aktiviere die genannte Erweiterung (`pdo_sqlite`, `json`, `openssl`, `mbstring`, `ctype`, `sodium`). Für `sodium`
heißt das: im Hoster-Menü unter „PHP-Einstellungen“ die Erweiterung `sodium` anschalten (in Plesk im Bereich
„Erweiterungen“). Fehlt Argon2id, ist
SQLite älter als 3.27 oder fehlen ihm die JSON-Funktionen, wähle eine andere PHP-Version oder frag deinen Hoster. Ist der Datenordner nicht beschreibbar, setze im FTP-Programm die Rechte für
`data/` auf 755 oder 775 (je nach Hoster; im Zweifel in dessen Hilfe nachsehen).

**Die Einrichtungsseite lädt sehr langsam (mehrere Sekunden).** Die Seite ruft für ihre Prüfungen den eigenen Server
ab. Hat dein Webspace nur sehr wenige PHP-Prozesse frei, wartet dieser Abruf, bis die Seite selbst fertig ist, und
läuft erst nach einigen Sekunden ab. Dann steht bei den Prüfungen „Bitte von Hand prüfen“ bzw. „nicht geprüft“. Das
ist harmlos: Prüfe den Datenordner wie dort beschrieben selbst im Browser. Nach der Einrichtung passiert das nicht mehr.

**„Datei noch nicht gefunden“ bei der Einrichtung, obwohl `setup-code.txt` hochgeladen ist.** Prüfe der Reihe nach:
- Der Name ist genau `setup-code.txt` (nicht `setup-code.txt.txt`), und die Datei liegt im Datenordner (`data`),
  nicht im Installationsordner daneben.
- Sie enthält nur den Code, den die Seite **in diesem Browser** gerade zeigt. Hast du die Seite in einem anderen
  Browser geöffnet oder länger als zwei Stunden nicht neu geladen, gibt es einen neuen Code. Wechselt der Code bei
  jedem Neuladen, nimmt der Browser keine Cookies an (etwa in einem privaten Fenster): Erlaube sie für diese Seite.
- Sie ist als einfacher Text gespeichert (ASCII oder UTF-8), etwa mit dem Windows-Editor. Ein Textprogramm wie Word
  oder die Windows-PowerShell mit `>` speichern in einem anderen Format.
- Das Änderungsdatum der Datei liegt nicht mehr als fünf Minuten in der Zukunft und nicht mehr als einen Tag zurück.
  Weicht die Uhr deines Rechners stark ab, lege die Datei im Dateimanager des Hosters an.

**Ich sehe eine weiße Seite oder „Internal Server Error“.** Sieh in das Fehlerprotokoll deines Hosters (im Panel unter
„Logs“ oder „Fehlerprotokoll“). Häufige Ursachen: PHP-Version zu alt, `.htaccess` nur halb hochgeladen oder Dateien
unvollständig übertragen. Lade die Dateien noch einmal hoch.

**Die Einrichtungsseite warnt, dass die Datenbank von außen erreichbar ist.** Nimm
[Möglichkeit A oder B aus Abschnitt 3](#3-datenordner-und-sicherheit) und lege das Konto erst danach an.

**Nach der Anmeldung lande ich sofort wieder auf der Anmeldeseite.** Die Anmeldung braucht HTTPS. Rufe die Seite mit
`https://` auf. Steht vor deinem Server ein eigener Proxy, den du selbst betreibst, schalte als Admin unter „Team“,
„Server“ den Schalter „Hinter einem Proxy“ ein. Nur dann, denn sonst kann jeder die Angaben des Proxys fälschen. Bei
Plesk mit nginx vor Apache schlägt die Einrichtungsseite den Schalter vor.

**Der Kopplungsbefehl zeigt eine falsche Adresse.** Korrigiere sie als Admin unter „Team“, „Server“, „Öffentliche
Adresse“.

**`/tokenlore:connect` meldet, der Code sei falsch oder abgelaufen.** Hole einen neuen Code. Er gilt 10 Minuten und nur
einmal. Gib die Zeile genau so ein, wie die Seite sie zeigt. Beim Kopieren aus manchen Programmen schleichen sich
Zeilenumbrüche ein.

**Das Plugin meldet einen Zertifikatsfehler.** Stimmt das Zertifikat deines Hosters (Gültigkeit, Domain)? Prüfe es im
Browser. Hast du ein eigenes Zertifikat, hinterlege die CA unter „Team“, „Server“ und koppele mit der Zeile, die die
Webseite danach anzeigt (mit `--ca`).

**„Zu viele Versuche“ (Fehler 429).** Warte ein paar Sekunden bis Minuten und versuche es erneut. Anmeldung, Kopplung und
Notfall-Zugang haben eine Bremse gegen Raten.

**Ein Konto ist nach zu vielen Fehlversuchen gesperrt.** Zehn falsche Passwörter sperren ein Konto für 15 Minuten.
Warte, oder bitte einen Admin, unter „Team“, „Mitglieder“ ein neues Passwort zu setzen. Das hebt die Sperre auf.

**Die Seite zeigt „Interner Fehler“, und im Fehlerprotokoll steht „Im Datenordner liegt mehr als eine Datenbank“.** Es
darf nur **eine** Datei `tokenlore-*.sqlite` im Datenordner liegen. Verschiebe die andere (und deren `-wal`/`-shm`) aus
dem Ordner heraus.

**Nach einem Update zeigt die Seite „Interner Fehler“, und im Fehlerprotokoll steht „Datenbank ist neuer als diese
tokenlore-Version“.** Du hast eine ältere Version über eine neuere Installation gelegt. Spiel die neueste Version ein;
die Daten sind unversehrt.

**Die Webseite zeigt „Die Datenbank stammt von einer älteren Version“, und Claude Code meldet beim Koppeln oder
Liefern „Die Datenbank des Servers stammt von einer älteren Version“.** Folge den Schritten auf der Webseite: Lade den
Datenordner per FTP auf deinen Rechner, lösche auf dem Server die Datei `tokenlore-….sqlite` (samt `-wal` und `-shm`,
falls vorhanden), lade die Seite neu und richte tokenlore neu ein. Koppel danach jeden Rechner neu; das Plugin schickt
dann alles aus seinem Archiv erneut.

**Es kommen keine Zahlen von einem Gerät an.** Prüfe auf dem Gerät mit `/tokenlore:status`, ob es gekoppelt ist. Mit
`/tokenlore:sync` stößt du den Abgleich sofort an. Zeigt die Seite „Geräte“ beim Gerät „Plugin veraltet“, nimmt dein
Server von dieser Plugin-Version nichts an; Claude Code meldet dann „Bitte tokenlore auf mindestens … aktualisieren“.
Aktualisiere das Plugin wie in [Abschnitt 4](#4-geräte-koppeln), Schritt 1. Die Zahlen warten so lange im Archiv des
Rechners und kommen danach an.

**Claude Code meldet „Signaturschlüssel fehlt, bitte neu koppeln“.** Das Plugin unterschreibt jede Zeile mit einem
Schlüssel, der auf dem Rechner liegt. Fehlt er, liefert es nichts. Koppele das Gerät neu; es bleibt dasselbe Gerät, und
ältere Zeilen prüft der Server weiter mit dem Schlüssel, mit dem sie unterschrieben sind.

**Claude Code meldet „Der Server kennt den Signaturschlüssel dieses Geräts nicht mehr“.** Ein anderes Gerät hat beim <!-- doku-ok: Wortlaut der Meldung -->
Koppeln denselben Signaturschlüssel gemeldet und ihn damit übernommen, meist weil der Datenordner des Plugins samt
Schlüssel auf einen anderen Rechner kopiert wurde. Bis zum Neukoppeln liefert dieses Gerät nichts; nichts geht verloren.
Koppele es neu, dann holt es den Schlüssel zurück.

**Claude Code meldet „… ältere Archivzeilen gehen nicht an den Server …“.** Ein anderes Gerät hat einen früheren <!-- doku-ok: Fachbegriff früherer Signaturschlüssel -->
Signaturschlüssel dieses Rechners übernommen, und auf dem Rechner selbst fehlt dieser Schlüssel. Neue Zahlen
liefert das Gerät weiter. Die älteren Zeilen mit diesem Schlüssel hält das Plugin zurück; was davon nie geliefert
wurde, fehlt auf deinem Server. Ist das andere Gerät derselbe Rechner, lege beide auf der Seite „Geräte“ zusammen
([Abschnitt 4](#ein-rechner-bleibt-ein-gerät)) und koppele das Gerät danach neu. Dann schickt das Plugin die älteren
Zeilen mit, und nichts zählt doppelt. Nur neu koppeln, ohne zusammenzulegen, reicht dafür nicht.

**Claude Code meldet „Dieses Gerät wurde anderswo neu gekoppelt“.** Dasselbe Gerät wurde auf einem anderen Rechner
oder mit einem neueren Code gekoppelt, der Schlüssel auf diesem Rechner ist deshalb gesperrt. Soll dieser Rechner weiter
liefern, hol auf der Webseite einen Code und koppele ihn neu.

**Claude Code meldet „Dieses Gerät ist auf dem Server gesperrt“.** Du hast das Gerät auf der Webseite gesperrt. Soll es
wieder liefern, koppele es mit einem neuen Code neu; es bleibt dasselbe Gerät mit seinen Zahlen.

**Claude Code meldet „Dieser Ordner stammt von einem anderen Rechner oder einer anderen Kopplung“.** Die Datei
`tokenlore-id` im Claude-Ordner passt nicht zur Kopplung, etwa weil sie ersetzt oder der Ordner kopiert wurde. Bis zum
Neukoppeln geht nichts an den Server; nichts geht verloren. Koppele das Gerät neu; mit einem „Code für dieses Gerät“
landet es sicher beim richtigen Gerät.

**`/tokenlore:connect` meldet „Kopplung abgelehnt: Dieser Rechner ist auf dem Server schon ein anderes Gerät“.** Du hast einen „Code für dieses Gerät“
benutzt, aber der Rechner gehört schon zu einem anderen deiner Geräte. Es hat sich nichts geändert. Hol einen normalen
Code unter „Gerät hinzufügen“, dann landet der Rechner bei seinem eigenen Gerät; sind beide Geräte derselbe Rechner,
lege sie auf der Seite „Geräte“ zusammen.

**Ein Rechner steht zweimal in der Geräteliste.** Wahrscheinlich ging die Datei `tokenlore-id` verloren. Sobald beide Geräte drei gleiche abgeschlossene Tage haben, schlägt die Seite
„Geräte“ „Zusammenlegen?“ vor ([Abschnitt 4](#ein-rechner-bleibt-ein-gerät)).
