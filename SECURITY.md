# Sicherheit

## Unterstützte Versionen

Sicherheitskorrekturen gibt es nur für die jeweils neueste Version (der neueste Tag bzw. der Zweig `main`). Halte deine
Installation deshalb aktuell; wie, steht in [docs/betrieb.md](docs/betrieb.md#5-updates). <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->

## Eine Lücke melden

Bitte melde Sicherheitslücken **nicht** in einem öffentlichen Issue, sondern vertraulich über GitHub: Reiter
„Security“ dieses Repos, „Report a vulnerability“. Nur die Betreuer des Projekts sehen die Meldung.

Hilfreich sind:

- betroffene Version (Datei `VERSION`) und PHP-Version,
- Webserver (Apache, nginx, Hoster),
- die Schritte, mit denen sich die Lücke nachstellen lässt, und was ein Angreifer damit erreicht.

Du bekommst eine Rückmeldung, sobald die Meldung gesichtet ist. Ist die Lücke bestätigt, erscheint die Korrektur als
neue Version; im [CHANGELOG](CHANGELOG.md) steht dann, was zu tun ist.

## Was in den Bereich fällt

- der Server in diesem Repo: PHP-Code, `.htaccess`, die mitgelieferte Webseite,
- die Annahme der Daten vom Plugin (`/api/plugin/…`) und die Betriebsanleitung, soweit sie zu unsicheren Einstellungen
  rät.

Lücken im Plugin selbst meldest du im Repo [tokenlore/tokenlore](https://github.com/tokenlore/tokenlore). Fehler in
PHP, im Webserver oder beim Hoster gehören zu deren Betreibern.

## Was tokenlore bewusst nicht leistet

Die [Bekannten Grenzen](docs/betrieb.md#8-bekannte-grenzen) in der Betriebsanleitung (etwa: wer den Server betreibt, <!-- doku-ok: Ziel liegt im veröffentlichten Stand -->
sieht alle Zahlen) sind keine Lücken, sondern beschriebene Eigenschaften.
