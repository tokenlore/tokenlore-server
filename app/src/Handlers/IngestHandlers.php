<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Audit;
use Tokenlore\Db\Database;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\RateLimiter;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Ingest\Decoder;
use Tokenlore\Ingest\DeviceRevoked;
use Tokenlore\Ingest\IngestError;
use Tokenlore\Ingest\Store;
use Tokenlore\Protocol\Limits;
use Tokenlore\RateLimit\Limits as RateLimits;

// Datenannahme vom Plugin: POST /api/plugin/ingest (ingest_handler.go). Reihenfolge wie im Go-Server: Grenze je IP,
// Geräteschlüssel, Grenze je Gerät, Content-Type, Sperre je Gerät, Rumpfgrenze, Dekodieren, Prüfen, Speichern.
// Die Gleichzeitigkeits-Grenzen des Go-Servers (globale Plätze, gelesene Rümpfe) entfallen laut Design;
// SQLite regelt die Last. Die Sperre je Gerät liegt in device_locks.
final class IngestHandlers
{
    /** Wie lange eine Sperre höchstens gilt. Nach einem Absturz läuft sie ab, statt das Gerät dauerhaft zu blockieren. */
    public const LOCK_TTL_MS = 120_000;

    private readonly Closure $nowMs;
    private readonly Audit $audit;

    /**
     * @param (callable(): int)|null $nowMs Uhr in Millisekunden (Standard: Systemzeit)
     * @param Audit|null $audit Sicherheitsprotokoll (Standard: error_log)
     */
    public function __construct(
        private readonly Database $db,
        private readonly RateLimiter $limiter,
        ?callable $nowMs = null,
        ?Audit $audit = null,
    ) {
        $this->nowMs = $nowMs === null
            ? static fn(): int => (int) floor(microtime(true) * 1000)
            : Closure::fromCallable($nowMs);
        $this->audit = $audit ?? new Audit();
    }

    /** Trägt die Route ein. */
    public static function register(Router $router, Middleware $mw, Database $db, RateLimiter $limiter, ?callable $nowMs = null, ?Audit $audit = null): void
    {
        $h = new self($db, $limiter, $nowMs, $audit);
        $router->add('POST', '/api/plugin/ingest', Middleware::chain(
            $h->handle(...),
            $mw->limitIp('ingest_ip'),
            $h->requireDeviceKey(),
            $h->limitDevice(),
            $mw->jsonOnly(),
            $h->lockDevice(),
            $mw->maxBody(Limits::MAX_BATCH_BYTES),
        ));
    }

    /** Liest den Geräteschlüssel aus "Authorization: Bearer <key>"; die Form wird vor der Datenbank geprüft. */
    public static function bearerKey(Request $r): ?string
    {
        $h = $r->header('authorization') ?? '';
        if (!str_starts_with($h, 'Bearer ')) {
            return null;
        }
        $key = substr($h, 7);
        return preg_match(Limits::DEVICE_KEY_PATTERN, $key) === 1 ? $key : null;
    }

    /**
     * Prüft den Geräteschlüssel vor allem anderen; Nutzer (uid) und Gerät (device) kommen nur von hier.
     * Gültig nur, wenn weder Schlüssel noch Gerät noch das Konto (users.disabled_at) gesperrt sind. Hash: rohe SHA-256-Bytes als BLOB (devices.hashOf).
     */
    private function requireDeviceKey(): Closure
    {
        return fn(callable $next): Closure => function (Request $r, array $p) use ($next): Response {
            $key = self::bearerKey($r);
            if ($key === null) {
                return Response::error(401, 'Nicht berechtigt');
            }
            $st = $this->db->pdo()->prepare(
                'select d.user_id, d.id from device_keys k join devices d on d.id = k.device_id join users u on u.id = d.user_id'
                . ' where k.key_hash = ? and k.revoked_at is null and d.revoked_at is null and u.disabled_at is null',
            );
            $st->bindValue(1, hash('sha256', $key, true), \PDO::PARAM_LOB);
            $st->execute();
            $row = $st->fetch(\PDO::FETCH_NUM);
            $st->closeCursor();
            if ($row === false) {
                return Response::error(401, 'Nicht berechtigt');
            }
            return $next($r->withAttr('uid', (int) $row[0])->withAttr('device', (int) $row[1]), $p);
        };
    }

    /** Ratengrenze je Gerät (IngestPerKey im Go-Server); nach requireDeviceKey. */
    private function limitDevice(): Closure
    {
        return fn(callable $next): Closure => function (Request $r, array $p) use ($next): Response {
            if (!$this->limiter->allow('ingest:dev:' . $r->attr('device'), RateLimits::INGEST_PER_KEY, RateLimits::INGEST_PER_KEY_BURST)) {
                $retry = RateLimits::retryAfter(RateLimits::INGEST_PER_KEY);
                return Response::error(429, 'Zu viele Anfragen')->withHeader('Retry-After', (string) $retry);
            }
            return $next($r, $p);
        };
    }

    /**
     * Höchstens eine Lieferung je Gerät gleichzeitig. Die Sperre ist eine Zeile in device_locks mit Ablaufzeit:
     * belegt wird sie nur, wenn keine da ist oder die vorhandene abgelaufen ist; freigegeben wird nur die eigene.
     * Belegt: 429 mit Retry-After 5, wie MaxPerDevice im Go-Server.
     */
    private function lockDevice(): Closure
    {
        return fn(callable $next): Closure => function (Request $r, array $p) use ($next): Response {
            $dev = (int) $r->attr('device');
            $now = ($this->nowMs)();
            $until = $now + self::LOCK_TTL_MS;
            $pdo = $this->db->pdo();
            $st = $pdo->prepare(
                'insert into device_locks (device_id, until_ms) values (:dev, :until)'
                . ' on conflict (device_id) do update set until_ms = excluded.until_ms where device_locks.until_ms <= :now',
            );
            $st->bindValue(':dev', $dev, \PDO::PARAM_INT);
            $st->bindValue(':until', $until, \PDO::PARAM_INT);
            $st->bindValue(':now', $now, \PDO::PARAM_INT);
            $st->execute();
            if ($st->rowCount() !== 1) {
                return Response::error(429, 'Zu viele gleichzeitige Lieferungen')->withHeader('Retry-After', '5');
            }
            try {
                return $next($r, $p);
            } finally {
                $del = $pdo->prepare('delete from device_locks where device_id = ? and until_ms = ?');
                $del->bindValue(1, $dev, \PDO::PARAM_INT);
                $del->bindValue(2, $until, \PDO::PARAM_INT);
                $del->execute();
            }
        };
    }

    /** Nimmt ein Lieferpaket an: Schlüssel, Typ und Größe sind schon geprüft. */
    private function handle(Request $r, array $p): Response
    {
        $now = ($this->nowMs)();
        try {
            $b = Decoder::decode($r->body);
            Decoder::validate($b, $now);
        } catch (IngestError $e) {
            // Nur Pfad und feste Meldung, nie Inhalte aus dem Paket (auch nicht im Protokoll).
            $this->audit->request($r, 'lieferung_abgelehnt', (int) $r->attr('uid'), [
                'geraet' => (int) $r->attr('device'), 'pfad' => $e->path, 'meldung' => $e->msg,
            ]);
            return Response::json($e->status, ['error' => $e->msg, 'path' => $e->path]);
        }
        try {
            $res = (new Store($this->db))->save((int) $r->attr('uid'), (int) $r->attr('device'), $b, $now);
        } catch (DeviceRevoked) {
            return Response::error(401, 'Nicht berechtigt');
        }
        // Schlüssel sortiert wie die Go-Map.
        return Response::json(200, [
            'accounts' => $res['accounts'],
            'flagged_sessions' => $res['flagged_sessions'],
            'requests' => $res['requests'],
            'sessions' => $res['sessions'],
        ]);
    }
}
