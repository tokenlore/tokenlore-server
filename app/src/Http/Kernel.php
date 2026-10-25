<?php

declare(strict_types=1);

namespace Tokenlore\Http;

use Closure;

// Kern des Servers: Anfrage → Router → Antwort, dazu Sicherheits-Header auf jeder Antwort
// (wie securityHeaders in internal/httpapi/middleware.go) und Fehlerbehandlung ohne Details nach außen.
final class Kernel
{
    // Grund-CSP wie web.BaseCSP im Go-Server: kein unsafe-inline; HTML-Antworten erweitern nur script-src um Hashes.
    public const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'";

    private const SECURITY_HEADERS = [
        'Content-Security-Policy' => self::CSP,
        'Strict-Transport-Security' => 'max-age=31536000',
        'X-Content-Type-Options' => 'nosniff',
        'Referrer-Policy' => 'no-referrer',
        'Cross-Origin-Opener-Policy' => 'same-origin',
        'Permissions-Policy' => 'camera=(), microphone=(), geolocation=()',
    ];

    private readonly Router $router;
    private readonly Closure $log;
    private ?Closure $routes;

    /**
     * @param (callable(Router, Request): void)|null $routes trägt die Routen ein; läuft einmal je Anfrage
     *        vor dem Verteilen (Datenbank, Sitzungen usw. werden dort verdrahtet, siehe app/routes.php)
     * @param (callable(string): void)|null $log Ziel für Fehlermeldungen (Standard: error_log)
     */
    public function __construct(?callable $routes = null, ?callable $log = null)
    {
        $this->routes = $routes === null ? null : Closure::fromCallable($routes);
        $this->log = $log === null ? static function (string $m): void {
            error_log($m);
        } : Closure::fromCallable($log);
        $this->router = new Router();
        // Ohne Datenbank und Sitzungen: sagt nur, dass PHP und der Kern laufen.
        $this->router->add('GET', '/healthz', static fn(): Response => Response::text(200, 'ok'));
    }

    public function router(): Router
    {
        return $this->router;
    }

    public function handle(Request $request): Response
    {
        try {
            if ($this->routes !== null) {
                $routes = $this->routes;
                $this->routes = null;
                $routes($this->router, $request);
            }
            $response = $this->router->dispatch($request);
        } catch (\Throwable $e) {
            // Nach außen keine Einzelheiten (Pfade, SQL); die Ursache steht im Fehlerprotokoll.
            ($this->log)(sprintf('%s: %s in %s:%d', $e::class, $e->getMessage(), $e->getFile(), $e->getLine()));
            $response = str_starts_with($request->path, '/api/')
                ? Response::error(500, 'Interner Fehler')
                : Response::text(500, 'Interner Fehler');
        }
        return $this->withSecurityHeaders($request, $response);
    }

    /** Setzt die Header, soweit der Handler sie nicht selbst gesetzt hat (die Webseite erweitert die CSP). */
    private function withSecurityHeaders(Request $request, Response $response): Response
    {
        $headers = self::SECURITY_HEADERS;
        if (str_starts_with($request->path, '/api/')) {
            $headers['Cache-Control'] = 'no-store';
        }
        foreach ($headers as $name => $value) {
            if ($response->header($name) === null) {
                $response = $response->withHeader($name, $value);
            }
        }
        return $response;
    }
}
