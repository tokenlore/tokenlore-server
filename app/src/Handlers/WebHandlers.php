<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Web\SpaPage;

// Die Webseite als Rückfall für alle Pfade außerhalb von /api/ (und außer den eingetragenen Routen wie /healthz):
// Startseite, statische Dateien über index.php/… und Umleitungen alter Seitenadressen auf die Hash-Route.
final class WebHandlers
{
    /** Erste Pfadsegmente der Seiten, deren letztes Segment ein Name oder eine ID ist (web/src/routes/…/[id]). */
    private const NAMED_ROUTES = ['models', 'accounts', 'devices'];

    /**
     * Trägt den Rückfall ein. $installDir ist der Installationsordner mit index.html, _app/, favicon.svg und
     * theme-init.js (der Inhalt von web/build/ liegt dort neben index.php). $publicUrl ist die gespeicherte
     * Serveradresse: Endet sie auf /index.php (die Umschreibregeln wirken nicht), läuft die Seite nur über
     * index.php, sonst gingen ihre API-Aufrufe (…/api/…) ins Leere.
     */
    public static function register(Router $router, string $installDir, ?string $publicUrl = null): void
    {
        $router->fallback(static fn(Request $r): Response => self::handle($r, $installDir, $publicUrl));
    }

    public static function handle(Request $r, string $installDir, ?string $publicUrl = null): Response
    {
        if ($r->method !== 'GET' && $r->method !== 'HEAD') {
            return Response::text(405, 'Methode nicht erlaubt')->withHeader('Allow', 'GET, HEAD');
        }
        // Der Pfad der Anfrage ist dekodiert und ohne Schrägstrich am Ende von /sub; für Umleitungen zählt
        // die Adresse, wie sie ankam.
        [$rawPath, $query] = self::splitUri($r->rawUri);
        $name = substr($r->path, 1);
        $onlyIndexPhp = $publicUrl !== null && str_ends_with($publicUrl, '/index.php');

        if ($name === '' || $name === 'index.html') {
            // Das CSS der Einrichtung: Ihre Abschlussseite lädt es, wenn das Konto schon existiert.
            if ($name === '' && ($r->query['asset'] ?? null) === SetupHandlers::CSS_ASSET) {
                return SetupHandlers::stylesheet();
            }
            if ($onlyIndexPhp && !$r->viaIndexPhp) {
                return self::redirect(302, $r->scriptBase . '/index.php' . ($query === '' ? '' : '?' . $query));
            }
            // Startseite eines Unterordners ohne Schrägstrich am Ende (/sub): relative Pfade lösten falsch auf.
            if ($name === '' && $r->scriptBase !== '' && !$r->viaIndexPhp && rawurldecode($rawPath) === $r->scriptBase) {
                return self::redirect(301, $r->scriptBase . '/' . ($query === '' ? '' : '?' . $query));
            }
            return SpaPage::revalidate($r, SpaPage::render($installDir));
        }
        $asset = SpaPage::asset($installDir, $name);
        if ($asset !== null) {
            return SpaPage::revalidate($r, $asset);
        }
        // Fehlende Dateien unter _app/ bleiben 404, sonst käme statt eines Skripts die Seite zurück.
        if ($name === '_app' || str_starts_with($name, '_app/')) {
            return Response::text(404, 'Nicht gefunden');
        }
        // Eine fehlende Datei (/favicon.ico, /robots.txt, /.env) ist 404, nicht die Webseite: sonst bekäme jede
        // Suche nach Dateien eine Umleitung.
        if (self::looksLikeFile($r)) {
            return Response::text(404, 'Nicht gefunden');
        }
        // Alte Seitenadresse (/models, /devices/3): die Route steht jetzt im Fragment der Startseite,
        // die Abfrage gehört zur Route („#/models?range=7d“).
        $start = $r->scriptBase . ($r->viaIndexPhp || $onlyIndexPhp ? '/index.php' : '/');
        return self::redirect(302, $start . '#' . self::route($r, $rawPath) . ($query === '' ? '' : '?' . $query));
    }

    /**
     * Sieht der Pfad nach einer Datei aus: ein Punkt im letzten (nicht leeren) Segment (/favicon.ico) oder ein
     * Segment, das mit einem Punkt beginnt (/.git/config, /.well-known/…). Ausgenommen sind Adressen der Seiten
     * mit freiem Namen als letztem Segment (/models/gpt-4.1, /accounts/a.b, /devices/…): Modellnamen und
     * Konto-IDs dürfen Punkte enthalten (Limits::MODEL_PATTERN und ID_PATTERN), und ihre alten Adressen sollen
     * weiter auf die Hash-Route führen.
     */
    private static function looksLikeFile(Request $r): bool
    {
        $segments = $r->segments();
        while ($segments !== [] && end($segments) === '') {
            array_pop($segments);
        }
        if ($segments === []) {
            return false;
        }
        // Auch bei den benannten Seiten ist ein verstecktes letztes Segment (/models/.env) keine Adresse einer Seite.
        if (count($segments) >= 2 && in_array($segments[0], self::NAMED_ROUTES, true)) {
            return end($segments)[0] === '.';
        }
        foreach ($segments as $segment) {
            if ($segment !== '' && $segment[0] === '.') {
                return true;
            }
        }
        return str_contains(end($segments), '.');
    }

    private static function redirect(int $status, string $location): Response
    {
        return (new Response($status))->withHeader('Location', $location);
    }

    /**
     * Die Route für das Fragment: der Pfad hinter dem Installationspfad (und hinter index.php), Segment für
     * Segment am rohen Pfad getrennt. So bleibt %2F im Segment ("a%2Fb") statt zum Trenner zu werden. Jedes
     * Segment wird neu kodiert, damit nichts Unkodiertes (Steuerzeichen, Leerzeichen) in den Header kommt.
     * Ein Schrägstrich am Ende entfällt.
     */
    private static function route(Request $r, string $rawPath): string
    {
        $segments = explode('/', $rawPath);
        $skip = count(explode('/', $r->scriptBase)) + ($r->viaIndexPhp ? 1 : 0);
        $expected = $r->scriptBase . ($r->viaIndexPhp ? '/index.php' : '');
        if ($rawPath === '' || rawurldecode(implode('/', array_slice($segments, 0, $skip))) !== $expected) {
            // Ohne rohe Adresse (oder bei abweichender Schreibung des Installationspfads): dekodierter Pfad.
            $segments = explode('/', $r->path);
            $skip = 1;
        }
        $rest = array_slice($segments, $skip);
        while ($rest !== [] && end($rest) === '') {
            array_pop($rest);
        }
        return '/' . implode('/', array_map(static fn(string $s): string => rawurlencode(rawurldecode($s)), $rest));
    }

    /**
     * Pfad (nicht dekodiert) und Abfrage (unverändert) der Adresse, ohne Fragment und Host. Eine Abfrage mit
     * Zeichen außerhalb der ASCII-Druckzeichen kommt nicht in den Location-Header und entfällt.
     *
     * @return array{string, string}
     */
    private static function splitUri(string $uri): array
    {
        if (preg_match('#^[A-Za-z][A-Za-z0-9+.-]*://[^/?\#]*#', $uri, $m) === 1) {
            $uri = substr($uri, strlen($m[0]));
        }
        [$path, $query] = explode('?', explode('#', $uri, 2)[0], 2) + [1 => ''];
        return [$path, preg_match('/^[\x21-\x7E]*\z/', $query) === 1 ? $query : ''];
    }
}
