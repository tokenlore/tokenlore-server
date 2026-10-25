<?php

declare(strict_types=1);

use Tokenlore\Audit;
use Tokenlore\Auth\Sessions;
use Tokenlore\Auth\Users;
use Tokenlore\Config\Paths;
use Tokenlore\Config\ServerSettings;
use Tokenlore\Db\Database;
use Tokenlore\Db\Migrator;
use Tokenlore\Devices\Devices;
use Tokenlore\Devices\Pairing;
use Tokenlore\Handlers\AdminHandlers;
use Tokenlore\Handlers\PluginHandlers;
use Tokenlore\Handlers\AuthHandlers;
use Tokenlore\Handlers\DeviceHandlers;
use Tokenlore\Handlers\IngestHandlers;
use Tokenlore\Handlers\ManageHandlers;
use Tokenlore\Handlers\RecoveryHandlers;
use Tokenlore\Handlers\SetupHandlers;
use Tokenlore\Handlers\StatsHandlers;
use Tokenlore\Handlers\WebHandlers;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\RateLimit\Limiter;
use Tokenlore\Setup\Recovery;
use Tokenlore\Setup\Setup;

// Verdrahtung der Routen. index.php übergibt diese Funktion an den Kern; sie läuft einmal je Anfrage, bevor
// verteilt wird: Dienste bauen, dann die register-Methoden der Handler aufrufen. /healthz liefert der Kern
// selbst, ohne Datenbank. $installDir, $audit und $setupFetch setzen nur Tests (Installation im Temp-Ordner,
// Protokoll-Fake, Abrufer für die Selbstprüfungen der Einrichtung).
//
// Ohne Datenbank oder ohne Konto fehlt die Einrichtung: die API antwortet 503, Seiten zeigen die Einrichtung.
return static function (
    Router $router,
    Request $request,
    ?string $installDir = null,
    ?Audit $audit = null,
    ?callable $setupFetch = null,
): void {
    $installDir ??= dirname(__DIR__);
    $audit ??= new Audit();
    $paths = Paths::fromInstallDir($installDir);

    $file = $paths->databaseFile();
    $db = $file === null ? null : Database::open($file);
    if ($db !== null) {
        (new Migrator($db, $paths))->migrate();
    }

    if ($db === null || (int) $db->pdo()->query('select exists (select 1 from users)')->fetchColumn() === 0) {
        // Rückfall für /api/-Pfade jenseits der Platzhalter der Einrichtung.
        $router->apiFallback(static fn(): Response => Response::error(503, Setup::NOT_READY));
        // Die Einrichtung öffnet die Datenbank selbst (und benennt eine ohne Konto um, unter Windows nur ohne
        // offene Verbindung).
        $db?->close();
        SetupHandlers::register($router, $paths, $setupFetch);
        return;
    }

    $nowMs = static fn(): int => (int) floor(microtime(true) * 1000);
    $settings = ServerSettings::load($db);
    $limiter = new Limiter($db, $nowMs);
    $sessions = new Sessions($db);
    $users = new Users($db);
    $pairing = new Pairing($db);
    $devices = new Devices($db);
    $mw = new Middleware($sessions, $limiter, null, $settings->trustProxy());

    AuthHandlers::register($router, $mw, $sessions, $users, null, $audit);
    DeviceHandlers::register($router, $mw, $pairing, $devices, $settings, null, $audit);
    PluginHandlers::register($router, $mw, $pairing, $settings, null, $audit);
    IngestHandlers::register($router, $mw, $db, $limiter, $nowMs, $audit);
    StatsHandlers::register($router, $mw, $db);
    ManageHandlers::register($router, $mw, $db, null, $audit);

    // Team-Verwaltung mit denselben Instanzen wie die Middleware (Uhr: Standard, wie dort).
    AdminHandlers::register($router, $mw, $db, $sessions, $users, $settings, null, $audit);
    // Notfall-Zugang: ohne Anmeldung erreichbar, nur mit der Login-Grenze je IP.
    RecoveryHandlers::register($router, $mw, new Recovery($db, $paths), $audit);

    // Als Letztes: die Webseite für alle übrigen Pfade außerhalb von /api/.
    WebHandlers::register($router, $installDir, $settings->publicUrl());
};
