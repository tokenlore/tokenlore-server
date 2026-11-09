<?php

declare(strict_types=1);

// Seite bei einer Datenbank vom Stand vor dem Plugin-Archiv (siehe Handlers\OldDatabaseHandlers). Schlichtes HTML mit
// setup.css, ohne Skript und ohne Inline-Stil (CSP). Alle Werte laufen durch $e(). Verfügbar ist nur $v.

/** @var array<string,mixed> $v */

$e = static fn(mixed $s): string => htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>tokenlore: Datenbank neu einrichten</title>
<link rel="stylesheet" href="<?= $e($v['css']) ?>">
</head>
<body>
<main>
<h1>Die Datenbank stammt von einer älteren Version</h1>
<section class="alert alert-important" role="alert" aria-labelledby="old-db">
<h2 id="old-db">Was los ist</h2>
<p>Diese tokenlore-Version speichert die Zahlen anders als die Version, mit der du deinen Server eingerichtet hast. Deine bisherige Datenbank kann sie nicht weiterbenutzen und stellt sie auch nicht selbst um. Damit nichts kaputtgeht, ändert der Server an ihr nichts und zeigt nur diese Seite.</p>
</section>
<h2>So geht es weiter</h2>
<ol>
<li><p><strong>Sichern:</strong> Lade per FTP den ganzen Datenordner auf deinen Rechner herunter. Das ist der Ordner <code>data</code> im Installationsordner oder der Ordner, der in deiner <code>config.local.php</code> steht. Darin liegt die Datenbank, eine Datei mit einem Namen wie <code>tokenlore-….sqlite</code>.</p></li>
<li><p><strong>Löschen:</strong> Lösche auf dem Server im Datenordner die Datei <code>tokenlore-….sqlite</code> und, falls vorhanden, die Dateien gleichen Namens mit <code>-wal</code> und <code>-shm</code> am Ende. Die übrigen Dateien im Datenordner lässt du liegen.</p></li>
<li><p><strong>Neu einrichten:</strong> Lade diese Seite neu. Es erscheint die Einrichtung wie beim ersten Mal; du legst dein Konto neu an. Konten, Geräte und Zahlen der alten Datenbank sind danach auf dem Server weg, in deiner Sicherung bleiben sie erhalten.</p></li>
<li><p><strong>Rechner neu koppeln:</strong> Hol auf der Webseite für jeden Rechner einen Kopplungscode und koppel ihn neu. Das Plugin schickt danach alles aus seinem Archiv auf dem Rechner erneut, auch die Zahlen von früher.</p></li>
</ol>
</main>
</body>
</html>
