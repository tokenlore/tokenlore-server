<?php

declare(strict_types=1);

// Seite der Einrichtung (siehe Handlers\SetupHandlers). Schlichtes HTML mit eigener CSS-Datei: kein Skript,
// kein style-Attribut, kein <style> (die CSP erlaubt nichts davon). Alle Werte laufen durch $e().
// Verfügbar ist nur $v (die Daten des Handlers).

/** @var array<string,mixed> $v */

$e = static fn(mixed $s): string => htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$done = $v['done'] === true;
$sb = (string) $v['scriptBase'];
$dataPath = $v['dataPath'] ?? null;
$exposure = (string) $v['exposure'];
$base = (string) $v['base'];
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= $done ? 'Einrichtung abgeschlossen' : 'tokenlore einrichten' ?></title>
<link rel="stylesheet" href="<?= $e($v['css']) ?>">
</head>
<body>
<main>
<?php
// Anleitung bei offener Datenbank, einmal geschrieben, an einer Stelle gezeigt (Formularseite und Abschluss).
$exposureBlock = static function () use ($e, $exposure, $sb, $dataPath, $base, $done): void {
    $dataUrl = $base . '/' . ($dataPath ?? 'data') . '/';
    if ($exposure === 'exposed') : ?>
<section class="alert alert-danger" role="alert" aria-labelledby="warn-data">
<h2 id="warn-data">Ernste Warnung: Die Datenbank ist von außen abrufbar</h2>
<p>Der Server hat soeben getestet: Eine Datei aus dem Datenordner lässt sich über das Internet abrufen. In diesem Ordner liegt die Datenbank mit allen Nutzungsdaten und den Passwort-Prüfwerten. Wer den Dateinamen kennt, könnte sie herunterladen. Der Name ist zufällig und schwer zu erraten, trotzdem darf das nicht so bleiben.</p>
<p>Der Schutz, der mitgeliefert wird (die Datei <code>.htaccess</code> im Ordner <code>data</code>), greift hier nicht. Das passiert, wenn der Webserver nginx ist, der solche Dateien ignoriert, oder wenn Apache die <code>.htaccess</code> nicht beachtet (Einstellung <code>AllowOverride None</code>).</p>
<h3>So behebst du das (eine der Möglichkeiten genügt)</h3>
<ol>
<li>
<p><strong>Datenordner außerhalb des Web-Ordners ablegen (empfohlen).</strong> Leg auf dem Server einen Ordner an, der nicht über das Internet erreichbar ist, zum Beispiel neben dem Web-Ordner statt darin. PHP muss in ihn schreiben dürfen. Leg dann im Installationsordner, dort wo <code>index.php</code> liegt, eine Datei <code>config.local.php</code> mit diesem Inhalt an (den Pfad ersetzt du durch deinen):</p>
<pre><code><?= $e("<?php\nreturn ['data_dir' => '/pfad/zum/ordner/ausserhalb'];") ?></code></pre>
<p>Lade danach diese Seite neu. Bei einer bestehenden Einrichtung verschiebst du die Datenbankdateien mit in den neuen Ordner.</p>
</li>
<li>
<p><strong>Zugriff in nginx sperren.</strong> Trag in der nginx-Konfiguration deiner Seite diese Regel ein (in Plesk: Domain, „Apache &amp; nginx-Einstellungen“, „Zusätzliche nginx-Anweisungen“):</p>
<pre><code><?= $e('location ^~ ' . $sb . '/' . ($dataPath ?? 'data') . "/ {\n    return 404;\n}") ?></code></pre>
</li>
<li>
<p><strong>Bei Apache:</strong> Bitte den Hoster, für den Ordner <code>AllowOverride All</code> zu erlauben, damit die mitgelieferte <code>.htaccess</code> wirkt.</p>
</li>
</ol>
<?php if ($done) : ?>
<p>Danach diese Seite neu laden: Verschwindet die Warnung, ist die Datenbank geschützt. Behebe das sofort.</p>
<?php else : ?>
<p>Danach diese Seite neu laden: Verschwindet die Warnung, ist die Datenbank geschützt. <strong>Vorher lässt sich die Einrichtung nicht abschließen.</strong></p>
<?php endif; ?>
</section>
<?php elseif ($exposure === 'unknown') : ?>
<section class="alert alert-note" aria-labelledby="note-data">
<h2 id="note-data">Datenordner: Bitte von Hand prüfen</h2>
<p>Ob der Datenordner von außen abrufbar ist, konnte nicht automatisch geprüft werden (zum Beispiel, weil der Server sich selbst nicht erreichen kann oder nur im lokalen Netz steht). Das ist wichtig, denn dort liegt die Datenbank.</p>
<p>Ruf bitte selbst im Browser <code><?= $e($dataUrl) ?></code> auf. Es sollte „Verboten“ (403) oder „Nicht gefunden“ (404) erscheinen. Wird stattdessen eine Dateiliste oder ein Inhalt angezeigt, ist der Ordner ungeschützt: Leg ihn dann per Datei <code>config.local.php</code> (Eintrag <code>data_dir</code>) außerhalb des Web-Ordners ab oder sperr ihn in der nginx-Konfiguration.</p>
</section>
<?php elseif ($exposure === 'protected') : ?>
<p class="line line-ok"><span class="badge badge-ok">In Ordnung</span> <strong>Datenbank geschützt.</strong> Der Datenordner ist nicht von außen abrufbar (mit einer Testdatei geprüft).</p>
<?php elseif ($exposure === 'outside') : ?>
<p class="line line-ok"><span class="badge badge-ok">In Ordnung</span> <strong>Datenordner außerhalb des Web-Ordners.</strong> Er liegt nicht unter der Adresse dieses Servers und ist darüber nicht abrufbar. Voraussetzung ist, dass er auch in keinem anderen öffentlichen Ordner liegt.</p>
<?php endif;
};
?>

<?php if ($done) : ?>
<h1>Einrichtung abgeschlossen</h1>
<p class="lead">Das Administrator-Konto <strong><?= $e($v['username']) ?></strong> wurde angelegt. Diese Einrichtungsseite ist jetzt dauerhaft gesperrt.</p>
<p><a class="button" href="<?= $e($v['next']) ?>">Weiter zur Anmeldung</a></p>

<?php $exposureBlock(); ?>

<h2>Nächste Schritte</h2>
<ol>
<li>Melde dich mit dem neuen Konto an.</li>
<li>Prüf unter Team → Server die Serveradresse. Sie steht in den Kopplungsbefehlen für die Plugins.</li>
<li>Kopple deine Geräte und leg bei Bedarf weitere Konten an.</li>
</ol>
<?php if ($v['storedUrl'] !== null) : ?>
<p class="muted">Als Serveradresse gespeichert: <code><?= $e($v['storedUrl']) ?></code>. Du kannst sie unter Team → Server ändern.</p>
<?php else : ?>
<p class="muted">Die erkannte Adresse wurde nicht gespeichert, weil sie nicht mit https beginnt. Du kannst sie später unter Team → Server eintragen.</p>
<?php endif; ?>
<?php if (($v['rewrite'] ?? null) === null) : ?>
<p class="muted">Ob die Umschreibregeln wirken, prüfst du von Hand: Ruf <code><?= $e($base) ?>/api/healthz</code> auf, und zeigt der Webserver dort statt einer kurzen tokenlore-Meldung (<code>{"error":…}</code>) eine eigene Fehlerseite, trag unter Team → Server die Serveradresse mit <code>/index.php</code> am Ende ein.</p>
<?php endif; ?>

<?php else : ?>
<h1>tokenlore einrichten</h1>
<p class="lead">Willkommen. Diese Seite richtet deinen tokenlore-Server ein: Sie prüft den Webspace und legt die Datenbank und dein Konto an. Das dauert etwa eine Minute.</p>

<section class="alert alert-important" aria-labelledby="first-account">
<h2 id="first-account">Wichtig: Das erste Konto wird Administrator</h2>
<p>Das erste Konto, das hier angelegt wird, ist Administrator und hat die volle Kontrolle über diesen Server. Damit das niemand vor dir tut, verlangt die Einrichtung eine kleine Datei, die nur du per FTP in den Datenordner legen kannst (Schritt 3).</p>
<p>Bist du nicht der Betreiber dieses Servers (hast du die Seite nur zufällig gefunden), schließ sie bitte. Nach dem Abschluss ist diese Seite dauerhaft gesperrt.</p>
</section>

<?php if ($v['errors'] !== []) : ?>
<section class="alert alert-danger" role="alert" aria-labelledby="form-errors">
<h2 id="form-errors">Das hat nicht geklappt</h2>
<ul>
<?php foreach ($v['errors'] as $error) : ?>
<li><?= $e($error) ?></li>
<?php endforeach; ?>
</ul>
</section>
<?php endif; ?>

<h2>1. Prüfung des Servers</h2>
<ul class="checks">
<?php foreach ($v['checks'] as $check) :
    $critical = in_array($check['name'], $v['critical'], true);
    [$class, $label] = $check['ok'] ? ['ok', 'In Ordnung'] : ($critical ? ['fail', 'Fehler'] : ['warn', 'Warnung']);
    ?>
<li class="check check-<?= $class ?>">
<p class="check-title"><span class="badge badge-<?= $class ?>"><?= $label ?></span> <strong><?= $e($check['name']) ?></strong></p>
<p class="check-hint"><?= $e($check['hint']) ?></p>
</li>
<?php endforeach; ?>
</ul>

<?php if ($v['blocking']) : ?>
<section class="alert alert-danger" role="alert">
<p><strong>Die Einrichtung ist erst möglich, wenn die als „Fehler“ markierten Punkte behoben sind.</strong> Behebe sie (die Hinweise stehen oben, im Zweifel hilft der Hoster) und lade diese Seite danach neu.</p>
</section>
<?php else : ?>

<h2>2. Datenbank und Adressen</h2>
<?php $exposureBlock(); ?>

<?php if ($v['rewrite'] === true) : ?>
<p class="line line-ok"><span class="badge badge-ok">In Ordnung</span> <strong>Umschreibregeln wirken.</strong> Adressen wie <code><?= $e($base) ?>/api/…</code> erreichen die Anwendung.</p>
<?php elseif ($v['rewrite'] === false) : ?>
<section class="alert alert-warn" aria-labelledby="note-rewrite">
<h2 id="note-rewrite">Umschreibregeln wirken nicht</h2>
<p>Der Server arbeitet trotzdem, aber alle Adressen müssen dann <code>/index.php</code> enthalten. Die Serveradresse für die Plugins wird deshalb so gespeichert:</p>
<p><code><?= $e($v['storedUrl']) ?></code></p>
<p>Für kürzere Adressen: Bei Apache müssen <code>mod_rewrite</code> und <code>AllowOverride All</code> erlaubt sein (der Hoster kann helfen), damit die mitgelieferte <code>.htaccess</code> wirkt. Bei nginx trägst du diese Regel ein (in Plesk bei „Zusätzliche nginx-Anweisungen“):</p>
<pre><code><?= $e('rewrite ^' . $sb . '/(api/.*|healthz)$ ' . $sb . '/index.php last;') ?></code></pre>
</section>
<?php else : ?>
<p class="line line-note"><span class="badge badge-note">Unklar</span> <strong>Umschreibregeln nicht geprüft.</strong> Der Server konnte sich selbst nicht erreichen. Prüf es nach der Einrichtung von Hand: Ruf <code><?= $e($base) ?>/api/healthz</code> im Browser auf. Antwortet tokenlore mit einer kurzen Meldung in geschweiften Klammern (<code>{"error":…}</code>), wirken die Regeln. Zeigt der Webserver stattdessen eine eigene Fehlerseite, wirken sie nicht. Trag dann unter Team → Server die Serveradresse mit <code>/index.php</code> am Ende ein.</p>
<?php endif; ?>

<?php if (($v['authorization'] ?? null) === false) : ?>
<section class="alert alert-warn" aria-labelledby="note-auth">
<h2 id="note-auth">Der Authorization-Header kommt nicht an</h2>
<p>Die Plugins melden sich mit ihrem Geräteschlüssel im Header <code>Authorization</code> an. Bei einer Probe hat der Webserver diesen Header nicht an PHP weitergegeben. So bleibt jede Lieferung der Plugins mit „nicht angemeldet“ hängen. Die Webseite selbst funktioniert trotzdem.</p>
<p>Das passiert bei Apache, wenn PHP über CGI oder FastCGI läuft. Die mitgelieferte <code>.htaccess</code> enthält dafür Regeln, die hier offenbar nicht wirken. Bitte den Hoster, eine dieser Zeilen für deine Seite zu erlauben oder einzutragen:</p>
<pre><code>CGIPassAuth On
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1</code></pre>
<p>Lade diese Seite danach neu. Verschwindet der Hinweis, ist alles in Ordnung.</p>
</section>
<?php endif; ?>

<?php if ($exposure === 'exposed') : ?>
<section class="alert alert-danger" role="alert">
<p><strong>Die Einrichtung ist erst möglich, wenn der Datenordner nicht mehr von außen abrufbar ist.</strong> Behebe das wie oben beschrieben und lade diese Seite danach neu.</p>
</section>
<?php else : ?>
<h2>3. Besitz nachweisen</h2>
<p>Damit nur du diesen Server einrichten kannst, legst du eine kleine Textdatei in den Datenordner. Das geht nur mit Zugang per FTP oder über den Dateimanager deines Hosters.</p>
<ol>
<li>Leg auf deinem Rechner eine Textdatei mit dem Namen <code><?= $e($v['proofFile']) ?></code> an.</li>
<li>Schreib genau diesen Code hinein und sonst nichts: <code><?= $e($v['proofCode']) ?></code></li>
<?php if ($dataPath !== null) : ?>
<li>Lade die Datei in den Ordner <code><?= $e(rawurldecode($dataPath)) ?></code> im Installationsordner (dort liegen schon <code>.htaccess</code> und <code>index.html</code>).</li>
<?php else : ?>
<li>Lade die Datei in deinen Datenordner (den Ordner, den du in <code>config.local.php</code> eingetragen hast).</li>
<?php endif; ?>
</ol>
<p class="hint">Windows blendet Dateiendungen oft aus. Heißt die Datei auf dem Server <code><?= $e($v['proofFile']) ?>.txt</code>, benenn sie um. Speichere sie als einfachen Text, etwa mit dem Windows-Editor. Der Code gilt nur in diesem Browser und nur, solange du die Seite spätestens alle zwei Stunden neu lädst; sonst bekommst du einen neuen. Wechselt der Code bei jedem Neuladen, nimmt der Browser keine Cookies an (etwa in einem privaten Fenster); erlaube sie für diese Seite. Nach der Einrichtung löscht der Server die Datei selbst.</p>
<?php if ($v['proofPresent']) : ?>
<p class="line line-ok"><span class="badge badge-ok">In Ordnung</span> <strong>Datei gefunden.</strong> Der Code stimmt.</p>
<?php else : ?>
<p class="line line-note"><span class="badge badge-note">Offen</span> <strong>Datei noch nicht gefunden.</strong> Lade sie hoch und schick danach das Formular ab (oder lade diese Seite neu, um es zu prüfen).</p>
<?php endif; ?>

<h2>4. Administrator-Konto anlegen</h2>
<?php if (!$v['https']) : ?>
<p class="alert alert-warn">Diese Seite wurde nicht verschlüsselt aufgerufen: Das Passwort würde im Klartext durchs Netz gehen. Richte besser zuerst https ein und ruf die Seite damit auf.</p>
<?php endif; ?>
<form method="post" action="<?= $e($v['action']) ?>">
<input type="hidden" name="csrf" value="<?= $e($v['csrf']) ?>">

<div class="field">
<label for="username">Benutzername</label>
<p class="hint" id="username-hint">3 bis 32 Zeichen: Kleinbuchstaben a bis z, Ziffern, Punkt, Unterstrich und Bindestrich.</p>
<input type="text" id="username" name="username" value="<?= $e($v['username']) ?>" required minlength="3" maxlength="32" pattern="[a-z0-9._\-]{3,32}" autocomplete="username" autocapitalize="none" spellcheck="false" aria-describedby="username-hint">
</div>

<div class="field">
<label for="password">Passwort</label>
<p class="hint" id="password-hint">Mindestens 12 Zeichen. Ein Satz aus mehreren Wörtern ist gut zu merken und schwer zu erraten.</p>
<input type="password" id="password" name="password" required minlength="12" autocomplete="new-password" aria-describedby="password-hint">
</div>

<div class="field">
<label for="password2">Passwort wiederholen</label>
<input type="password" id="password2" name="password2" required minlength="12" autocomplete="new-password">
</div>

<div class="field">
<p class="check-line">
<input type="checkbox" id="trust_proxy" name="trust_proxy" value="1"<?= $v['proxySuggested'] ? ' checked' : '' ?> aria-describedby="proxy-hint">
<label for="trust_proxy">Dieser Server steht hinter einem Proxy (zum Beispiel nginx vor Apache)</label>
</p>
<p class="hint" id="proxy-hint">
<?php if ($v['proxySuggested']) : ?>
<strong>Proxy erkannt:</strong> Die Anfrage kam über eine lokale Adresse mit dem Header <code>X-Forwarded-For</code>, wie es bei einem vorgeschalteten Proxy üblich ist (etwa in Plesk). Wir empfehlen, das einzuschalten. Dann gelten die Angaben des Proxys zu Adresse, https und Besucher.
<?php else : ?>
Nur einschalten, wenn vor dem Webserver ein Proxy steht, der die Header <code>X-Forwarded-*</code> setzt. Falsch eingeschaltet könnten Besucher ihre Adresse vortäuschen und Begrenzungen umgehen. Lässt sich später unter Team → Server ändern.
<?php endif; ?>
</p>
</div>

<p><button type="submit" class="button">Einrichtung abschließen</button></p>
<p class="muted">Mit dem Abschluss wird die Datenbank angelegt und das Konto erstellt. Danach ist diese Seite dauerhaft gesperrt.</p>
</form>
<?php endif; ?>
<?php endif; ?>
<?php endif; ?>
</main>
</body>
</html>
