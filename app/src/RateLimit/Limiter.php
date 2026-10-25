<?php

declare(strict_types=1);

namespace Tokenlore\RateLimit;

use Closure;
use Tokenlore\Db\Database;
use Tokenlore\Http\RateLimiter;

// Token-Bucket je Schlüssel in der Tabelle rate_limits (bucket, tokens, updated_ms), damit die
// Grenzen über PHP-Anfragen hinweg gelten. Rate und Burst gibt der Aufrufer je Anfrage mit
// (Werte siehe Limits); die Tabelle hält nur den Füllstand. Die Grenzen je Client-IP (mit der
// IPv6-Kürzung aus IpKey) setzt Http\Middleware::limitIp darauf.
final class Limiter implements RateLimiter
{
    // So lange ungenutzte Einträge werden entfernt (ratelimit.IdleTTL).
    public const IDLE_TTL_MS = 600_000;

    // allow() räumt bei jedem SWEEP_ONE_IN-ten Aufruf im Mittel auf (1 %).
    private const SWEEP_ONE_IN = 100;

    // Höchstzahl der Einträge (ratelimit.MaxEntries); sweep() löscht darüber die ältesten.
    public const MAX_ENTRIES = 100_000;

    // Längere Schlüssel landen nur als Hash in der Tabelle (beliebig lange Schlüssel blähen sie sonst auf).
    private const MAX_KEY_LENGTH = 64;

    // Rundungsspielraum: 6000 ms bei 1/6 je s ergeben in Gleitkomma knapp unter 1 Token.
    private const EPSILON = 1e-9;

    // Füllstand eines vorhandenen Buckets zum Zeitpunkt :now, höchstens :burst.
    private const REFILLED = 'min(:burst, tokens + max(0, :now - updated_ms) * cast(:per_ms as real))';

    // Bucket ist zum Zeitpunkt :now wieder voll (mit der gespeicherten Rate); Löschen ändert dann nichts.
    // Überlauf-Buckets sind ausgenommen: sie werden nie verdrängt.
    private const FULL = "(tokens + max(0, :now - updated_ms) * per_ms >= burst - " . self::EPSILON
        . " and bucket not like '" . self::OVERFLOW_PREFIX . "%')";

    // Präfix der Überlauf-Buckets je Route (siehe allow()).
    private const OVERFLOW_PREFIX = 'overflow:';

    private readonly Closure $nowMs;

    /**
     * @param callable():int $nowMs Uhr in Millisekunden (in Tests steuerbar)
     * @param int $maxEntries Höchstzahl der Einträge (in Tests klein)
     */
    public function __construct(
        private readonly Database $db,
        callable $nowMs,
        private readonly int $maxEntries = self::MAX_ENTRIES,
    ) {
        $this->nowMs = Closure::fromCallable($nowMs);
    }

    /**
     * Verbraucht ein Token des Buckets, wenn eines da ist. Der Bucket füllt sich mit $perSecond je
     * Sekunde bis höchstens $burst; ein neuer Bucket startet voll. Eine abgelehnte Anfrage schreibt
     * nichts, verschiebt also den Nachschub nicht. Rate und Burst stehen mit in der Zeile, damit
     * sweep() erkennt, welche Buckets wieder voll sind.
     *
     * Ist die Tabelle voll (maxEntries) und lässt sich kein voller Bucket verdrängen, bekommen neue
     * Schlüssel keine eigene Zeile, sondern teilen sich den Überlauf-Bucket ihrer Route. Erschöpfte
     * Buckets werden nie gelöscht: Sonst könnte ein Angreifer seinen eigenen mit einer Flut neuer
     * Schlüssel verdrängen.
     */
    public function allow(string $bucket, float $perSecond, int $burst): bool
    {
        if ($burst < 1) {
            return false;
        }
        if (is_infinite($perSecond) && $perSecond > 0) {
            return true;
        }
        if (random_int(1, self::SWEEP_ONE_IN) === 1) {
            $this->sweep();
        }

        // Vorhandener Bucket: nachfüllen und verbrauchen, wenn ein Token da ist.
        $pdo = $this->db->pdo();
        $st = $pdo->prepare(
            'update rate_limits set tokens = max(0.0, ' . self::REFILLED . ' - 1), updated_ms = :now,'
            . ' per_ms = :per_ms, burst = :burst'
            . ' where bucket = :bucket and ' . self::REFILLED . ' >= 1 - ' . self::EPSILON,
        );
        $this->bind($st, $bucket, $perSecond, $burst);
        $st->execute();
        if ($st->rowCount() === 1) {
            return true;
        }
        $st = $pdo->prepare('select 1 from rate_limits where bucket = ?');
        $st->execute([self::storageKey($bucket)]);
        if ($st->fetchColumn() !== false) {
            return false; // vorhanden, aber leer
        }

        // Neuer Bucket: Zählen, Verdrängen und Anlegen unter der Schreibsperre, damit das Maximum auch
        // bei gleichzeitigen Anfragen hält. Läuft schon eine Transaktion, gilt deren Sperre.
        $create = function () use ($bucket, $perSecond, $burst): bool {
            $excess = $this->count() - $this->maxEntries + 1;
            if ($excess > 0 && $this->evictFull($excess) < $excess) {
                // Kein Platz: alle neuen Schlüssel der Route teilen sich den Überlauf-Bucket mit
                // AGGREGATE_FACTOR-facher Rate und Burst. Er wird nie verdrängt; der eigene (vielleicht
                // erschöpfte) Bucket lässt sich so nicht zurücksetzen, und nicht alle sind ausgesperrt.
                return $this->upsert(
                    self::OVERFLOW_PREFIX . self::route($bucket),
                    $perSecond * Limits::AGGREGATE_FACTOR,
                    $burst * Limits::AGGREGATE_FACTOR,
                );
            }
            return $this->upsert($bucket, $perSecond, $burst);
        };
        return $this->db->inTransaction() ? $create() : (bool) $this->db->tx($create);
    }

    // Legt den Bucket an (voll, ein Token verbraucht) oder verbraucht wie oben, falls es ihn schon gibt.
    private function upsert(string $bucket, float $perSecond, int $burst): bool
    {
        $st = $this->db->pdo()->prepare(
            'insert into rate_limits (bucket, tokens, updated_ms, per_ms, burst)'
            . ' values (:bucket, :burst - 1, :now, :per_ms, :burst)'
            . ' on conflict (bucket) do update set'
            . ' tokens = max(0.0, ' . self::REFILLED . ' - 1), updated_ms = :now, per_ms = :per_ms, burst = :burst'
            . ' where ' . self::REFILLED . ' >= 1 - ' . self::EPSILON,
        );
        $this->bind($st, $bucket, $perSecond, $burst);
        $st->execute();
        return $st->rowCount() === 1;
    }

    // Route eines Schlüssels für den Überlauf: Schlüssel haben die Form <art>:<route>:<subjekt>
    // (z. B. "ip:login:192.0.2.7", das Subjekt darf Doppelpunkte enthalten) oder <route>:<subjekt>
    // (z. B. "ingest-key:7"); ohne Doppelpunkt ist die Route leer. So bleibt die Zahl der
    // Überlauf-Buckets klein.
    private static function route(string $bucket): string
    {
        $parts = explode(':', $bucket, 3);
        return match (count($parts)) {
            1 => '',
            2 => $parts[0],
            default => $parts[0] . ':' . $parts[1],
        };
    }

    /**
     * Wie allow(), aber ohne Verbrauch und ohne zu schreiben: true, wenn der Bucket gerade ein Token
     * hat. Ein unbekannter Bucket gilt als voll.
     */
    public function peek(string $bucket, float $perSecond, int $burst): bool
    {
        if ($burst < 1) {
            return false;
        }
        if (is_infinite($perSecond) && $perSecond > 0) {
            return true;
        }
        $st = $this->db->pdo()->prepare('select ' . self::REFILLED . ' from rate_limits where bucket = :bucket');
        $this->bind($st, $bucket, $perSecond, $burst);
        $st->execute();
        $tokens = $st->fetchColumn();
        return $tokens === false || (float) $tokens >= 1 - self::EPSILON;
    }

    private function bind(\PDOStatement $st, string $bucket, float $perSecond, int $burst): void
    {
        $st->bindValue(':bucket', self::storageKey($bucket));
        $st->bindValue(':burst', $burst, \PDO::PARAM_INT);
        $st->bindValue(':now', ($this->nowMs)(), \PDO::PARAM_INT);
        $st->bindValue(':per_ms', max(0.0, $perSecond) / 1000.0);
    }

    // Schlüssel, wie er in der Tabelle steht: bis MAX_KEY_LENGTH Zeichen unverändert, länger als
    // "sha256:<hex>". Ein kurzer Schlüssel kann so nie wie ein Hash aussehen (der ist 71 Zeichen lang).
    private static function storageKey(string $bucket): string
    {
        return strlen($bucket) > self::MAX_KEY_LENGTH ? 'sha256:' . hash('sha256', $bucket) : $bucket;
    }

    /**
     * Wartezeit für Retry-After, siehe Limits::retryAfter. $bucket ist unbenutzt und nur der Signatur
     * wegen da.
     */
    public function retryAfter(string $bucket, float $perSecond): int
    {
        return Limits::retryAfter($perSecond);
    }

    // Löscht Einträge, die seit IDLE_TTL_MS nicht mehr beschrieben wurden und wieder voll sind; ein
    // neuer Eintrag ändert dann nichts. Sind danach noch mehr als maxEntries übrig, gehen weitere volle
    // Buckets, die am längsten ungenutzten zuerst (wie MaxEntries im Go-Server, dort mit Stichprobe).
    // Erschöpfte Buckets löscht sweep() nie: das höbe eine Sperre auf (fail open).
    public function sweep(): void
    {
        $pdo = $this->db->pdo();
        $now = ($this->nowMs)();
        $st = $pdo->prepare('delete from rate_limits where updated_ms <= :cutoff and ' . self::FULL);
        $st->bindValue(':cutoff', $now - self::IDLE_TTL_MS, \PDO::PARAM_INT);
        $st->bindValue(':now', $now, \PDO::PARAM_INT);
        $st->execute();

        $excess = $this->count() - $this->maxEntries;
        if ($excess > 0) {
            $this->evictFull($excess);
        }
    }

    private function count(): int
    {
        return (int) $this->db->pdo()->query('select count(*) from rate_limits')->fetchColumn();
    }

    // Löscht bis zu $limit wieder volle Buckets, die am längsten ungenutzten zuerst; liefert die Anzahl.
    private function evictFull(int $limit): int
    {
        $st = $this->db->pdo()->prepare(
            'delete from rate_limits where bucket in (select bucket from rate_limits where ' . self::FULL
            . ' order by updated_ms, bucket limit :limit)'
        );
        $st->bindValue(':now', ($this->nowMs)(), \PDO::PARAM_INT);
        $st->bindValue(':limit', $limit, \PDO::PARAM_INT);
        $st->execute();
        return $st->rowCount();
    }
}
