<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use Closure;
use Tokenlore\Audit;
use Tokenlore\Db\Database;
use Tokenlore\Devices\Devices;
use Tokenlore\Http\Middleware;
use Tokenlore\Http\RateLimiter;
use Tokenlore\Http\Request;
use Tokenlore\Http\Response;
use Tokenlore\Http\Router;
use Tokenlore\Ingest\Decoder;
use Tokenlore\Ingest\DeviceRevoked;
use Tokenlore\Ingest\IngestError;
use Tokenlore\Ingest\PluginOutdated;
use Tokenlore\Ingest\Store;
use Tokenlore\Protocol\Limits;
use Tokenlore\RateLimit\Limits as RateLimits;

// Datenannahme vom Plugin: POST /api/plugin/ingest (ingest_handler.go). Reihenfolge wie im Go-Server: Grenze je IP,
// Geräteschlüssel, Grenze je Gerät, Content-Type, Sperre je Gerät, Rumpfgrenze, Dekodieren mit Mindestversion,
// Prüfen samt Signatur je Zeile, Speichern.
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
     * Prüft den Geräteschlüssel vor allem anderen; Nutzer (uid), Gerät (device) und Schlüssel-Hash (key_hash) kommen
     * nur von hier. Gültig nur, wenn weder Schlüssel noch Gerät noch das Konto (users.disabled_at) gesperrt sind.
     * Sonst 401 mit Grund (siehe unauthorized). Hash: rohe SHA-256-Bytes als BLOB (Devices::hashKey).
     */
    private function requireDeviceKey(): Closure
    {
        return fn(callable $next): Closure => function (Request $r, array $p) use ($next): Response {
            $key = self::bearerKey($r);
            if ($key === null) {
                return self::unauthorized('unknown');
            }
            $hash = Devices::hashKey($key);
            [$row, $reason] = $this->keyState($hash);
            if ($row === null) {
                return self::unauthorized($reason);
            }
            return $next($r->withAttr('uid', $row[0])->withAttr('device', $row[1])->withAttr('key_hash', $hash), $p);
        };
    }

    /**
     * Zustand eines Schlüssels: [[uid, Gerät], ''] wenn er gilt, sonst [null, Grund]. Grund: 'unknown' (Schlüssel
     * unbekannt), 'repaired' (Schlüssel gesperrt, weil das Gerät neu gekoppelt wurde), 'revoked' (Schlüssel oder
     * Gerät in der Geräte-Ansicht gesperrt oder Konto gesperrt).
     *
     * @return array{0: array{0:int, 1:int}|null, 1: string}
     */
    private function keyState(string $hash): array
    {
        $st = $this->db->pdo()->prepare(
            'select d.user_id, d.id, k.revoked_at, k.revoked_reason, d.revoked_at, u.disabled_at'
            . ' from device_keys k join devices d on d.id = k.device_id join users u on u.id = d.user_id where k.key_hash = ?',
        );
        $st->bindValue(1, $hash, \PDO::PARAM_LOB);
        $st->execute();
        $row = $st->fetch(\PDO::FETCH_NUM);
        $st->closeCursor();
        if ($row === false) {
            return [null, 'unknown'];
        }
        if ($row[2] !== null) {
            return [null, $row[3] === 'repaired' ? 'repaired' : 'revoked'];
        }
        if ($row[4] !== null || $row[5] !== null) {
            return [null, 'revoked'];
        }
        return [[(int) $row[0], (int) $row[1]], ''];
    }

    /** 401 beim Liefern mit Grund, laut Protokoll {"error":"unauthorized","reason":…}. */
    private static function unauthorized(string $reason): Response
    {
        return Response::json(401, ['error' => 'unauthorized', 'reason' => $reason]);
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

    /**
     * Nimmt ein Lieferpaket an: Schlüssel, Typ und Größe sind schon geprüft. Danach Mindestversion (426), Paketform,
     * Signatur je Zeile gegen die Signaturschlüssel des Geräts (zuerst der am liefernden Geräteschlüssel) und
     * Inhaltszeilen (je 400 mit Pfad), dann Speichern.
     */
    private function handle(Request $r, array $p): Response
    {
        $now = ($this->nowMs)();
        $hash = (string) $r->attr('key_hash');
        try {
            $b = Decoder::decode($r->body);
            // Über den Schlüssel, nicht über das Gerät: wurde das Gerät inzwischen zusammengelegt, gelten die Schlüssel
            // des verbliebenen Geräts (dorthin speichert auch der Rückfall unten).
            $keys = (new Devices($this->db))->signKeysOfKey($hash);
            $b = Decoder::validate($b, $now, $keys);
        } catch (PluginOutdated) {
            return Response::json(426, ['error' => 'plugin_outdated', 'min_plugin_version' => Limits::MIN_PLUGIN_VERSION]);
        } catch (IngestError $e) {
            // Nur Pfad und feste Meldung, nie Inhalte aus dem Paket (auch nicht im Protokoll).
            $this->audit->request($r, 'lieferung_abgelehnt', (int) $r->attr('uid'), [
                'geraet' => (int) $r->attr('device'), 'pfad' => $e->path, 'meldung' => $e->msg,
            ]);
            $body = ['error' => $e->msg, 'path' => $e->path];
            if ($e->reason !== '') {
                $body['reason'] = $e->reason;
            }
            return Response::json($e->status, $body);
        }
        $store = new Store($this->db);
        try {
            $res = $store->save((int) $r->attr('uid'), (int) $r->attr('device'), $b, $now, $hash);
        } catch (DeviceRevoked) {
            // Zwischen Schlüsselprüfung und Speichern gesperrt oder neu gekoppelt; der Grund steht jetzt am Schlüssel.
            [$row, $reason] = $this->keyState($hash);
            if ($row === null || $row[1] === (int) $r->attr('device')) {
                return self::unauthorized($reason === '' ? 'revoked' : $reason);
            }
            // Der Schlüssel gilt, gehört aber inzwischen einem anderen Gerät (zusammengelegt): einmal dorthin speichern.
            try {
                $res = $store->save($row[0], $row[1], $b, $now, $hash);
            } catch (DeviceRevoked) {
                [, $reason] = $this->keyState($hash);
                return self::unauthorized($reason === '' ? 'revoked' : $reason);
            }
        }
        // Schlüssel sortiert wie die Go-Map.
        return Response::json(200, [
            'accounts' => $res['accounts'],
            'elsewhere_requests' => $res['elsewhere_requests'],
            'flagged_sessions' => $res['flagged_sessions'],
            'known_requests' => $res['known_requests'],
            'legacy_days' => $res['legacy_days'],
            'legacy_rejected_days' => $res['legacy_rejected_days'],
            'requests' => $res['requests'],
            'sessions' => $res['sessions'],
        ]);
    }
}
