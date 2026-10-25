<?php

declare(strict_types=1);

namespace Tokenlore\Http;

use Tokenlore\RateLimit\IpKey;

// Eingehende Anfrage. Der Pfad ist relativ zur Installation (z. B. /api/me), egal ob der Server in einem
// Unterordner liegt oder über index.php/… aufgerufen wird. Unveränderlich; die Middleware hängt per withAttr() an.
final class Request
{
    /** Obergrenze für den gelesenen Rumpf (post_max_size der Hoster liegt darunter oder gleich). */
    public const MAX_READ = 16 * 1024 * 1024;

    /** @var array<string, mixed> */
    private array $attrs = [];

    /**
     * @param array<string,string> $headers Namen klein geschrieben
     * @param array<string,string> $cookies
     * @param array<string,mixed> $query
     */
    public function __construct(
        public readonly string $method = 'GET',
        public readonly string $path = '/',
        public readonly array $headers = [],
        public readonly string $body = '',
        public readonly array $cookies = [],
        public readonly string $remoteAddr = '',
        public readonly bool $https = false,
        public readonly string $scriptBase = '',
        public readonly bool $viaIndexPhp = false,
        public readonly array $query = [],
        // Adresse genau wie vom Server geliefert (REQUEST_URI, mit Abfrage, nicht dekodiert). Der Pfad oben
        // verliert z. B. den Schrägstrich am Ende von /sub und macht aus %2F ein Segmenttrennzeichen.
        public readonly string $rawUri = '',
        // Eigene Adresse und eigener Port des Servers laut SERVER_ADDR und SERVER_PORT (nicht vom Client bestimmbar,
        // anders als der Host-Header). Die Einrichtung verbindet für ihre Selbstprüfung nur dorthin.
        public readonly string $serverAddr = '',
        public readonly int $serverPort = 0,
        // Die Segmente des Pfades (wie path relativ zur Installation), noch nicht dekodiert; null bei von Hand gebauten
        // Anfragen. Der Router verteilt danach, damit %2F im Segment bleibt, siehe segments().
        public readonly ?array $rawSegments = null,
    ) {
    }

    /**
     * Die Pfadsegmente, einzeln dekodiert: %2F bleibt Teil seines Segments und wird nicht zum Trenner (anders als in
     * path, wo alles dekodiert ist). "/" hat keine Segmente; ein Schrägstrich am Ende ergibt ein leeres letztes.
     *
     * @return list<string>
     */
    public function segments(): array
    {
        if ($this->rawSegments !== null) {
            $segments = array_map('rawurldecode', $this->rawSegments);
        } else {
            $segments = explode('/', substr($this->path, 1));
        }
        return $segments === [''] ? [] : $segments;
    }

    /**
     * Name des ausgeführten Skripts. Manche CGI-Setups hängen PATH_INFO an SCRIPT_NAME an
     * (/sub/index.php/api/me): Das wird erkannt, wenn PATH_INFO ein Suffix von SCRIPT_NAME ist (und davor ein
     * .php-Skript steht) oder SCRIPT_NAME nicht auf .php endet, aber /index.php/ enthält. Fehlt SCRIPT_NAME,
     * gilt PHP_SELF (SCRIPT_NAME plus PATH_INFO), zuletzt /index.php.
     *
     * @param array<string,mixed> $server
     */
    private static function scriptName(array $server): string
    {
        $script = (string) ($server['SCRIPT_NAME'] ?? '');
        if ($script === '') {
            $script = (string) ($server['PHP_SELF'] ?? '');
        }
        if ($script === '') {
            return '/index.php';
        }
        $info = (string) ($server['PATH_INFO'] ?? '');
        if ($info !== '' && str_ends_with($script, $info)) {
            $cut = substr($script, 0, -strlen($info));
            // Ein PATH_INFO wie /index.php hinter einem sauberen /index.php lässt nichts übrig, das ein Skript wäre.
            if (str_ends_with($cut, '.php')) {
                return $cut;
            }
        }
        if (!str_ends_with($script, '.php') && ($i = strpos($script, '/index.php/')) !== false) {
            return substr($script, 0, $i + strlen('/index.php'));
        }
        return $script;
    }

    /**
     * Die Abfrage wie url.ParseQuery im Go-Server: Namen und Werte nur prozent- und plus-dekodiert (kein
     * Feld-Syntax a[]=1, keine Umbenennung von Punkt und Leerzeichen wie bei parse_str); bei doppeltem Namen gilt
     * der erste Wert. Paare mit kaputter Kodierung oder Semikolon entfallen, wie in Go.
     *
     * @return array<string,string>
     */
    private static function parseQuery(string $qs): array
    {
        $out = [];
        foreach (explode('&', $qs) as $pair) {
            if ($pair === '' || str_contains($pair, ';') || preg_match('/%(?![0-9A-Fa-f]{2})/', $pair) === 1) {
                continue;
            }
            [$name, $value] = explode('=', $pair, 2) + [1 => ''];
            $name = urldecode($name);
            if (!array_key_exists($name, $out)) {
                $out[$name] = urldecode($value);
            }
        }
        return $out;
    }

    public static function fromGlobals(): self
    {
        $body = file_get_contents('php://input', false, null, 0, self::MAX_READ + 1);
        return self::fromServer($_SERVER, $body === false ? '' : $body);
    }

    /**
     * Baut die Anfrage aus einem $_SERVER-artigen Feld; der Pfad kommt aus REQUEST_URI, damit er vom
     * Umschreiben unabhängig ist (SCRIPT_NAME zeigt auf index.php, auch wenn api/… aufgerufen wurde).
     *
     * @param array<string,mixed> $server
     */
    public static function fromServer(array $server, string $body = ''): self
    {
        $uri = (string) ($server['REQUEST_URI'] ?? '/');
        // Absolute Form („GET http://host/pfad“) auf den Pfad kürzen, Fragment verwerfen.
        if (preg_match('#^[A-Za-z][A-Za-z0-9+.-]*://[^/?\#]*#', $uri, $m)) {
            $uri = substr($uri, strlen($m[0]));
        }
        $uri = explode('#', $uri, 2)[0];
        [$rawPath, $queryString] = explode('?', $uri, 2) + [1 => ''];
        if ($rawPath === '' || $rawPath[0] !== '/') {
            $rawPath = '/' . $rawPath;
        }
        $query = self::parseQuery($queryString);

        $script = self::scriptName($server);
        if ($script[0] !== '/') {
            $script = '/' . $script;
        }
        $base = substr($script, 0, (int) strrpos($script, '/'));

        // Segmentweise, damit %2F innerhalb eines Segments bleibt: erst am rohen Pfad trennen, dann dekodieren.
        // $all beginnt mit dem leeren Element vor dem ersten Schrägstrich.
        $all = explode('/', $rawPath);
        $decoded = array_map('rawurldecode', $all);
        $scriptSegs = explode('/', $script);
        $baseSegs = array_slice($scriptSegs, 0, -1);
        $viaIndexPhp = false;
        if ($decoded === $scriptSegs || (count($decoded) > count($scriptSegs) && array_slice($decoded, 0, count($scriptSegs)) === $scriptSegs)) {
            $viaIndexPhp = true;
            $skip = count($scriptSegs);
        } elseif ($base !== '' && array_slice($decoded, 0, count($baseSegs)) === $baseSegs) {
            $skip = count($baseSegs);
        } else {
            $skip = 1;
        }
        $path = '/' . implode('/', array_slice($decoded, $skip));
        $rawSegments = array_slice($all, $skip);

        $headers = [];
        foreach ($server as $key => $value) {
            if (!is_string($value)) {
                continue;
            }
            if (str_starts_with($key, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
            } elseif ($key === 'CONTENT_TYPE' || $key === 'CONTENT_LENGTH') {
                $headers[strtolower(str_replace('_', '-', $key))] ??= $value;
            }
        }
        // Apache gibt Authorization bei CGI/FastCGI nur über die umgeleitete Umgebungsvariable weiter.
        if (!isset($headers['authorization']) && is_string($server['REDIRECT_HTTP_AUTHORIZATION'] ?? null)) {
            $headers['authorization'] = $server['REDIRECT_HTTP_AUTHORIZATION'];
        }

        $httpsVar = strtolower((string) ($server['HTTPS'] ?? ''));
        $https = ($httpsVar !== '' && $httpsVar !== 'off') || (string) ($server['SERVER_PORT'] ?? '') === '443';

        return new self(
            method: strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET')),
            path: $path,
            headers: $headers,
            body: $body,
            cookies: self::parseCookies($headers['cookie'] ?? ''),
            remoteAddr: (string) ($server['REMOTE_ADDR'] ?? ''),
            https: $https,
            scriptBase: $base,
            viaIndexPhp: $viaIndexPhp,
            query: $query,
            rawUri: (string) ($server['REQUEST_URI'] ?? ''),
            serverAddr: (string) ($server['SERVER_ADDR'] ?? ''),
            serverPort: (int) ($server['SERVER_PORT'] ?? 0),
            rawSegments: $rawSegments,
        );
    }

    /** Wert eines Headers (Name ohne Beachtung der Schreibung) oder null. */
    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function cookie(string $name): ?string
    {
        return $this->cookies[$name] ?? null;
    }

    public function attr(string $name, mixed $default = null): mixed
    {
        return $this->attrs[$name] ?? $default;
    }

    public function withAttr(string $name, mixed $value): self
    {
        $c = clone $this;
        $c->attrs[$name] = $value;
        return $c;
    }

    /** HTTPS laut Server; mit trustProxy zählt X-Forwarded-Proto (rechter Eintrag, den setzt der eigene Proxy). */
    public function isHttps(bool $trustProxy): bool
    {
        if ($trustProxy) {
            $proto = strtolower(self::lastEntry($this->header('x-forwarded-proto') ?? ''));
            if ($proto === 'https' || $proto === 'http') {
                return $proto === 'https';
            }
        }
        return $this->https;
    }

    /**
     * Adresse des Clients wie ClientIP im Go-Server: mit trustProxy zählt der rechte Eintrag von
     * X-Forwarded-For (den setzt der eigene Proxy, links steht Fälschbares); ist er keine IP, oder
     * ohne trustProxy, gilt REMOTE_ADDR. IPv4-in-IPv6 wird IPv4, Zonen entfallen.
     */
    public function clientIp(bool $trustProxy): string
    {
        if ($trustProxy) {
            $ip = self::normalizeIp(self::lastEntry($this->header('x-forwarded-for') ?? ''));
            if ($ip !== null) {
                return $ip;
            }
        }
        $host = trim($this->remoteAddr);
        if (preg_match('/^\[([^\]]*)\](?::\d+)?\z/', $host, $m) || preg_match('/^([^:]+):\d+\z/', $host, $m)) {
            $host = $m[1];
        }
        return self::normalizeIp($host) ?? $host;
    }

    private static function lastEntry(string $list): string
    {
        $i = strrpos($list, ',');
        return trim($i === false ? $list : substr($list, $i + 1));
    }

    // Zone weg, IPv4-in-IPv6 als IPv4; null für Unlesbares. Die Regeln stehen nur in IpKey.
    private static function normalizeIp(string $ip): ?string
    {
        return IpKey::normalize($ip);
    }

    /** @return array<string,string> bei doppeltem Namen gilt der erste (wie net/http) */
    private static function parseCookies(string $header): array
    {
        $out = [];
        foreach (explode(';', $header) as $part) {
            $eq = strpos($part, '=');
            if ($eq === false) {
                continue;
            }
            $name = trim(substr($part, 0, $eq));
            $value = trim(substr($part, $eq + 1));
            if (strlen($value) >= 2 && $value[0] === '"' && str_ends_with($value, '"')) {
                $value = substr($value, 1, -1);
            }
            if ($name !== '' && !array_key_exists($name, $out)) {
                $out[$name] = $value;
            }
        }
        return $out;
    }
}
