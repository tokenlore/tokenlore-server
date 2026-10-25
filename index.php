<?php

declare(strict_types=1);

// Einstiegspunkt: Bootstrap → Kernel → Ausgabe. Die Routen stehen in app/routes.php.

// Fehlermeldungen gehören ins Protokoll, nicht in die Antwort (Pfade, SQL).
ini_set('display_errors', '0');

require __DIR__ . '/app/bootstrap.php';

use Tokenlore\Http\Kernel;
use Tokenlore\Http\Request;

$request = Request::fromGlobals();
$kernel = new Kernel(require __DIR__ . '/app/routes.php');
$kernel->handle($request)->send($request->method !== 'HEAD');
