<?php

declare(strict_types=1);

namespace Tokenlore\Http;

use Closure;
use Tokenlore\RateLimit\IpKey;
use Tokenlore\RateLimit\Limits;
use Tokenlore\Util\MediaType;

// Middleware wie im Go-Server (internal/httpapi/middleware.go und ratelimit.go).
// Jede Methode liefert eine Schicht: Closure(callable $next): Closure(Request, array $params): Response.
// Schichten setzt man mit Middleware::chain() um einen Handler; die erste Schicht läuft zuerst.
final class Middleware
{
    private readonly Closure $clock;

    /**
     * @param (callable(): int)|null $clock Unix-Sekunden (Standard: time())
     * @param bool $trustProxy X-Forwarded-For auswerten (Server-Einstellung „Hinter einem Proxy“)
     */
    public function __construct(
        private readonly SessionResolver $sessions,
        private readonly RateLimiter $limiter,
        ?callable $clock = null,
        private readonly bool $trustProxy = false,
    ) {
        $this->clock = $clock === null ? time(...) : Closure::fromCallable($clock);
    }

    /** Setzt die Schichten um den Handler; $layers[0] ist die äußerste. */
    public static function chain(callable $handler, callable ...$layers): callable
    {
        foreach (array_reverse($layers) as $layer) {
            $handler = $layer($handler);
        }
        return $handler;
    }

    /**
     * Lehnt Anfragen ohne Content-Type application/json ab (Parameter wie charset sind erlaubt): 415. Streng wie
     * mime.ParseMediaType im Go-Server: Auch ein kaputter Parameter ("application/json; charset") ergibt 415.
     */
    public function jsonOnly(): Closure
    {
        return static fn(callable $next): Closure => static function (Request $r, array $p) use ($next): Response {
            if (MediaType::parse($r->header('content-type') ?? '') !== 'application/json') {
                return Response::error(415, 'Content-Type muss application/json sein');
            }
            return $next($r, $p);
        };
    }

    /** Begrenzt den Rumpf auf $bytes Bytes: 413. */
    public function maxBody(int $bytes): Closure
    {
        return static fn(callable $next): Closure => static function (Request $r, array $p) use ($next, $bytes): Response {
            if (strlen($r->body) > $bytes) {
                return Response::error(413, 'Anfrage zu groß');
            }
            return $next($r, $p);
        };
    }

    /**
     * Begrenzt je Client-IP (IPv6 je /64, zusätzlich gesammelt je /48); läuft vor jeder teuren Arbeit.
     * $bucket: ein Name aus Limits::PER_IP (login, pair, recovery, ca, session, ingest_ip). Bei Ablehnung 429
     * mit Retry-After.
     */
    public function limitIp(string $bucket): Closure
    {
        if (!isset(Limits::PER_IP[$bucket])) {
            throw new \InvalidArgumentException('Unbekannte Ratengrenze: ' . $bucket);
        }
        return fn(callable $next): Closure => function (Request $r, array $p) use ($next, $bucket): Response {
            return $this->ipAllowed($r, $bucket) ? $next($this->withIp($r), $p) : $this->tooMany($bucket);
        };
    }

    /**
     * Prüft das Sitzungs-Cookie (SessionCookie; fehlt es oder kommt es doppelt vor: 401; Form zuerst, ohne
     * Datenbank) und legt uid, csrf und role als Request-Attribute ab. Wie im Go-Server steht die
     * Sitzungs-Grenze je IP davor: 429 oder 401.
     */
    public function requireSession(): Closure
    {
        return fn(callable $next): Closure => function (Request $r, array $p) use ($next): Response {
            if (!$this->ipAllowed($r, 'session')) {
                return $this->tooMany('session');
            }
            $token = SessionCookie::token($r);
            if ($token === null || !self::validSessionToken($token)) {
                return Response::error(401, 'Nicht angemeldet');
            }
            $user = $this->sessions->user($token, ($this->clock)());
            if ($user === null) {
                return Response::error(401, 'Nicht angemeldet');
            }
            return $next($this->withIp($r)->withAttr('uid', $user['uid'])->withAttr('csrf', $user['csrf'])->withAttr('role', $user['role']), $p);
        };
    }

    /** Legt die Client-IP als Attribut ip ab (für das Sicherheitsprotokoll; Proxy-Regel wie die Ratengrenze). */
    private function withIp(Request $r): Request
    {
        return $r->withAttr('ip', $r->clientIp($this->trustProxy));
    }

    /** Verlangt bei ändernden Methoden den passenden X-CSRF-Token: 403. Nach requireSession einzusetzen. */
    public function requireCsrf(): Closure
    {
        return static fn(callable $next): Closure => static function (Request $r, array $p) use ($next): Response {
            if (in_array($r->method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
                $want = (string) $r->attr('csrf', '');
                if ($want === '' || !hash_equals($want, $r->header('x-csrf-token') ?? '')) {
                    return Response::error(403, 'CSRF-Prüfung fehlgeschlagen');
                }
            }
            return $next($r, $p);
        };
    }

    /** Nur für Admins: 403. Nach requireSession einzusetzen. */
    public function requireAdmin(): Closure
    {
        return static fn(callable $next): Closure => static function (Request $r, array $p) use ($next): Response {
            if ($r->attr('role') !== 'admin') {
                return Response::error(403, 'Keine Berechtigung');
            }
            return $next($r, $p);
        };
    }

    /** Prüft die Form (base64url, 32 Bytes = 43 Zeichen), bevor die Datenbank gefragt wird. */
    public static function validSessionToken(string $v): bool
    {
        return preg_match('/^[A-Za-z0-9_-]{43}\z/', $v) === 1;
    }

    // Grenze je IP (IPv6 je /64), danach für IPv6 die Sammelgrenze je /48 mit Limits::AGGREGATE_FACTOR-
    // facher Rate und Burst (wie ipLimiter.allow im Go-Server). Die Kürzung der Adresse macht IpKey.
    //
    // Abweichung vom Go-Server: Die Sammelgrenze wird vorher ohne Verbrauch angesehen. Ist sie erschöpft,
    // lehnt das ab, ohne das /64 anzulegen oder zu belasten; sonst füllte ein Angreifer mit wechselnden
    // /64 aus einem /48 die Tabelle. Danach verbraucht wie in Go erst das /64, dann das /48.
    private function ipAllowed(Request $r, string $bucket): bool
    {
        [$perSecond, $burst] = Limits::PER_IP[$bucket];
        $ip = $r->clientIp($this->trustProxy);
        $aggregate = IpKey::aggregate($ip);
        $aggKey = 'ip48:' . $bucket . ':' . $aggregate;
        $aggPerSecond = $perSecond * Limits::AGGREGATE_FACTOR;
        $aggBurst = $burst * Limits::AGGREGATE_FACTOR;
        if ($aggregate !== null && !$this->limiter->peek($aggKey, $aggPerSecond, $aggBurst)) {
            return false;
        }
        if (!$this->limiter->allow('ip:' . $bucket . ':' . IpKey::perIp($ip), $perSecond, $burst)) {
            return false;
        }
        return $aggregate === null || $this->limiter->allow($aggKey, $aggPerSecond, $aggBurst);
    }

    private function tooMany(string $bucket): Response
    {
        $retry = Limits::retryAfter(Limits::PER_IP[$bucket][0]);
        return Response::error(429, 'Zu viele Anfragen')->withHeader('Retry-After', (string) $retry);
    }
}
