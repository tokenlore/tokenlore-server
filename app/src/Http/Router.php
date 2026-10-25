<?php

declare(strict_types=1);

namespace Tokenlore\Http;

// Verteilt Anfragen nach Methode und Pfadmuster ({id} steht für genau ein Pfadsegment).
// Ein Handler ist callable(Request, array<string,string> $params): Response.
final class Router
{
    /** @var list<array{string, list<string|array{string}>, callable}> Methode, Segmente (Text oder [Parametername]), Handler */
    private array $routes = [];
    /** @var callable|null */
    private $fallback = null;
    /** @var callable|null */
    private $apiFallback = null;

    public function add(string $method, string $pattern, callable $handler): void
    {
        if ($method !== strtoupper($method) || $pattern === '' || $pattern[0] !== '/') {
            throw new \InvalidArgumentException('Ungültige Route');
        }
        // Segmentweise wie der Mux des Go-Servers: Ein {name} ist ein ganzes Segment. Verglichen wird mit den einzeln
        // dekodierten Segmenten der Anfrage (Request::segments()), damit %2F in einem Segment bleibt und nicht zum
        // Trenner wird (/api/admin/users/1%2Fdisable ist kein /api/admin/users/1/disable).
        $segments = [];
        foreach (explode('/', substr($pattern, 1)) as $part) {
            if (preg_match('/^\{([A-Za-z_][A-Za-z0-9_]*)\}\z/', $part, $m) === 1) {
                $segments[] = [$m[1]];
            } elseif (str_contains($part, '{')) {
                throw new \InvalidArgumentException('Ungültige Route');
            } else {
                $segments[] = $part;
            }
        }
        $this->routes[] = [$method, $segments === [''] ? [] : $segments, $handler];
    }

    /**
     * Passt der Pfad zum Muster, kommen die Parameter heraus, sonst null.
     *
     * @param list<string|array{string}> $pattern
     * @param list<string> $segments
     * @return array<string,string>|null
     */
    private static function match(array $pattern, array $segments): ?array
    {
        if (count($pattern) !== count($segments)) {
            return null;
        }
        $params = [];
        foreach ($pattern as $i => $part) {
            if (is_array($part)) {
                if ($segments[$i] === '') {
                    return null;
                }
                $params[$part[0]] = $segments[$i];
            } elseif ($part !== $segments[$i]) {
                return null;
            }
        }
        return $params;
    }

    /** Handler für alle Pfade außerhalb von /api/, die keine Route treffen (z. B. die Webseite). */
    public function fallback(callable $handler): void
    {
        $this->fallback = $handler;
    }

    /** Handler für Pfade unter /api/ ohne passende Route (z. B. 503, solange die Einrichtung fehlt). */
    public function apiFallback(callable $handler): void
    {
        $this->apiFallback = $handler;
    }

    public function dispatch(Request $request): Response
    {
        $allowed = [];
        $segments = $request->segments();
        foreach ($this->routes as [$method, $pattern, $handler]) {
            $params = self::match($pattern, $segments);
            if ($params === null) {
                continue;
            }
            if ($method === $request->method || ($method === 'GET' && $request->method === 'HEAD')) {
                return $handler($request, $params);
            }
            $allowed[$method] = true;
        }
        $api = str_starts_with($request->path, '/api/');
        if ($allowed !== []) {
            $msg = 'Methode nicht erlaubt';
            $r = $api ? Response::error(405, $msg) : Response::text(405, $msg);
            return $r->withHeader('Allow', implode(', ', array_keys($allowed)));
        }
        if (!$api && $this->fallback !== null) {
            return ($this->fallback)($request, []);
        }
        if ($api && $this->apiFallback !== null) {
            return ($this->apiFallback)($request, []);
        }
        return $api ? Response::error(404, 'Nicht gefunden') : Response::text(404, 'Nicht gefunden');
    }
}
