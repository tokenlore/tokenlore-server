<?php

declare(strict_types=1);

namespace Tokenlore\Util;

// Eingaben aus Pfad und Abfrage lesen.
final class Parse
{
    /** Positive Ganzzahl wie strconv.ParseInt (Vorzeichen +, führende Nullen erlaubt, höchstens int64); sonst null. */
    public static function positiveInt(string $s): ?int
    {
        if (preg_match('/^\+?0*([0-9]+)\z/', $s, $m) !== 1) {
            return null;
        }
        $digits = $m[1];
        if (strlen($digits) > 19 || (strlen($digits) === 19 && strcmp($digits, '9223372036854775807') > 0)) {
            return null;
        }
        $v = (int) $digits;
        return $v > 0 ? $v : null;
    }
}
