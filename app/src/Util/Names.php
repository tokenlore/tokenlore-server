<?php

declare(strict_types=1);

namespace Tokenlore\Util;

use Tokenlore\Protocol\Validator;

// Vom Nutzer vergebene Anzeigenamen (Geräte, Konten) prüfen, wie names.Clean im Go-Server.
final class Names
{
    /** Leerraum wie unicode.IsSpace in Go (strings.TrimSpace). */
    private const SPACE = '[\t\n\x{0B}\f\r \x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]';

    /** Größte erlaubte Zahl aufeinanderfolgender Kombinationszeichen (Mn/Me). */
    private const MAX_MARKS = 2;

    /**
     * Trimmt den Namen und prüft ihn zusätzlich zu Validator::deviceName: mindestens ein Zeichen aus L, N, P
     * oder S, keine Hangul-Füllzeichen, höchstens zwei Kombinationszeichen hintereinander. null: unzulässig.
     */
    public static function clean(string $name): ?string
    {
        $n = self::trimSpace($name);
        if ($n === null || !Validator::deviceName($n)) {
            return null;
        }
        $visible = false;
        $marks = 0;
        foreach (mb_str_split($n, 1, 'UTF-8') as $ch) {
            if (preg_match('/^[\x{115F}\x{1160}\x{3164}\x{FFA0}]$/u', $ch) === 1) {
                return null;
            }
            if (preg_match('/^[\p{Mn}\p{Me}]$/u', $ch) === 1) {
                if (++$marks > self::MAX_MARKS) {
                    return null;
                }
                continue;
            }
            $marks = 0;
            if (preg_match('/^[\p{L}\p{N}\p{P}\p{S}]$/u', $ch) === 1) {
                $visible = true;
            }
        }
        return $visible ? $n : null;
    }

    /** Wie strings.TrimSpace; null bei ungültigem UTF-8. */
    public static function trimSpace(string $s): ?string
    {
        return preg_replace('/^' . self::SPACE . '+|' . self::SPACE . '+\z/u', '', $s);
    }
}
