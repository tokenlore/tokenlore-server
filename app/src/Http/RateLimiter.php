<?php

declare(strict_types=1);

namespace Tokenlore\Http;

// Schnittstelle zur Ratenbegrenzung; Umsetzung: RateLimit\Limiter (Token-Bucket in SQLite).
interface RateLimiter
{
    /** true: die Anfrage darf durch; verbraucht dabei einen Token des Buckets. */
    public function allow(string $bucket, float $perSecond, int $burst): bool;

    /** true: der Bucket hat gerade ein Token; verbraucht nichts und legt nichts an. */
    public function peek(string $bucket, float $perSecond, int $burst): bool;
}
