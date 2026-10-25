<?php

declare(strict_types=1);

namespace Tokenlore\Util;

// Zeitpunkte für JSON-Antworten: RFC 3339 in UTC wie Gos time.Time.
final class Time
{
    /** Aus Unix-Millisekunden; Sekundenbruchteile nur, wenn vorhanden, ohne Nullen am Ende. */
    public static function isoMs(int $ms): string
    {
        $frac = (($ms % 1000) + 1000) % 1000;
        $s = gmdate('Y-m-d\TH:i:s', intdiv($ms - $frac, 1000));
        return $s . ($frac === 0 ? '' : '.' . rtrim(sprintf('%03d', $frac), '0')) . 'Z';
    }

    /** Aus Unix-Sekunden. */
    public static function isoSec(int $sec): string
    {
        return gmdate('Y-m-d\TH:i:s', $sec) . 'Z';
    }
}
