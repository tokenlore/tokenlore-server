<?php

declare(strict_types=1);

namespace Tokenlore\Util;

// Content-Type lesen wie mime.ParseMediaType im Go-Server: Der Typ muss aus zwei Tokens bestehen, und die
// Parameter müssen als Ganzes stimmen. Ein kaputter Parameter ("application/json; charset", "…;;") macht den
// ganzen Wert ungültig, auch wenn der Typ stimmt. Die Werte der Parameter braucht niemand und werden nicht
// ausgegeben; die Fortsetzungs-Regeln nach RFC 2231 (name*0=…) können in Go nie einen Fehler auslösen.
final class MediaType
{
    // tspecials nach RFC 2045 (Go: isTSpecial).
    private const TSPECIAL = '()<>@,;:\\"/[]?=';

    // Leerraum wie unicode.IsSpace in Go (der Wert ist ein Bytestring): die ASCII-Zeichen \t \n \v \f \r und Leerzeichen
    // (im Code) sowie NEL, NBSP und die Z-Zeichen jenseits von ASCII als UTF-8-Bytes.
    private const UNICODE_SPACES = [
        "\xC2\x85", "\xC2\xA0", "\xE1\x9A\x80", "\xE2\x80\x80", "\xE2\x80\x81", "\xE2\x80\x82", "\xE2\x80\x83",
        "\xE2\x80\x84", "\xE2\x80\x85", "\xE2\x80\x86", "\xE2\x80\x87", "\xE2\x80\x88", "\xE2\x80\x89", "\xE2\x80\x8A",
        "\xE2\x80\xA8", "\xE2\x80\xA9", "\xE2\x80\xAF", "\xE2\x81\x9F", "\xE3\x80\x80",
    ];

    private function __construct()
    {
    }

    /**
     * Der Medientyp klein geschrieben ohne Parameter (z. B. "application/json"), oder null, wenn Go
     * ParseMediaType einen Fehler gäbe. Kleinschreibung nur für ASCII; Go bildet auch einzelne Unicode-Zeichen
     * (etwa İ) auf ASCII ab, das wäre ein Typ, den kein Client sendet.
     */
    public static function parse(string $v): ?string
    {
        $semi = strpos($v, ';');
        $base = $semi === false ? $v : substr($v, 0, $semi);
        $type = strtolower(self::trim($base));
        if (!self::validType($type)) {
            return null;
        }

        $seen = [];
        $v = substr($v, strlen($base));
        while ($v !== '') {
            $v = self::trimLeft($v);
            if ($v === '') {
                break;
            }
            [$key, $value, $rest] = self::consumeParam($v);
            if ($key === '') {
                // Ein einzelnes Semikolon am Ende ist erlaubt, alles andere ein Fehler.
                if (self::trim($rest) === ';') {
                    break;
                }
                return null;
            }
            // Doppelte Namen sind falsch, werden aber bei gleichem Wert hingenommen.
            if (array_key_exists($key, $seen) && $seen[$key] !== $value) {
                return null;
            }
            $seen[$key] = $value;
            $v = $rest;
        }
        return $type;
    }

    // checkMediaTypeDisposition: ein Token, oder zwei durch einen Schrägstrich getrennte, sonst nichts.
    private static function validType(string $s): bool
    {
        [$type, $rest] = self::consumeToken($s);
        if ($type === '') {
            return false;
        }
        if ($rest === '') {
            return true;
        }
        if ($rest[0] !== '/') {
            return false;
        }
        [$sub, $rest] = self::consumeToken(substr($rest, 1));
        return $sub !== '' && $rest === '';
    }

    /** @return array{string, string, string} Name (klein), Wert, Rest; Name leer bei Fehler (dann ist Rest der Eingang) */
    private static function consumeParam(string $v): array
    {
        $rest = self::trimLeft($v);
        if ($rest === '' || $rest[0] !== ';') {
            return ['', '', $v];
        }
        $rest = self::trimLeft(substr($rest, 1));
        [$param, $rest] = self::consumeToken($rest);
        $param = strtolower($param);
        if ($param === '') {
            return ['', '', $v];
        }
        $rest = self::trimLeft($rest);
        if ($rest === '' || $rest[0] !== '=') {
            return ['', '', $v];
        }
        $rest = self::trimLeft(substr($rest, 1));
        [$value, $rest2] = self::consumeValue($rest);
        if ($value === '' && $rest2 === $rest) {
            return ['', '', $v];
        }
        return [$param, $value, $rest2];
    }

    /** @return array{string, string} Wert (Token oder quoted-string) und Rest */
    private static function consumeValue(string $v): array
    {
        if ($v === '') {
            return ['', ''];
        }
        if ($v[0] !== '"') {
            return self::consumeToken($v);
        }
        $out = '';
        $n = strlen($v);
        for ($i = 1; $i < $n; $i++) {
            $c = $v[$i];
            if ($c === '"') {
                return [$out, substr($v, $i + 1)];
            }
            // Maskiertes Sonderzeichen; ein Backslash vor etwas anderem bleibt stehen (Pfade des MSIE).
            if ($c === '\\' && $i + 1 < $n && strpos(self::TSPECIAL, $v[$i + 1]) !== false) {
                $out .= $v[++$i];
                continue;
            }
            if ($c === "\r" || $c === "\n") {
                return ['', $v];
            }
            $out .= $c;
        }
        // Das schließende Anführungszeichen fehlt.
        return ['', $v];
    }

    /** @return array{string, string} das Token am Anfang und der Rest */
    private static function consumeToken(string $v): array
    {
        $n = strlen($v);
        for ($i = 0; $i < $n; $i++) {
            $c = ord($v[$i]);
            if ($c <= 0x20 || $c >= 0x7F || strpos(self::TSPECIAL, $v[$i]) !== false) {
                break;
            }
        }
        return [substr($v, 0, $i), substr($v, $i)];
    }

    // Von Hand statt mit Regex: Bei langen Leerzeichen-Folgen stößt PCRE an seine Grenzen oder rechnet quadratisch.
    private static function trimLeft(string $s): string
    {
        $i = 0;
        $n = strlen($s);
        while ($i < $n) {
            if (strpos("\t\n\v\f\r ", $s[$i]) !== false) {
                $i++;
                continue;
            }
            foreach (self::UNICODE_SPACES as $u) {
                if (substr_compare($s, $u, $i, strlen($u)) === 0) {
                    $i += strlen($u);
                    continue 2;
                }
            }
            break;
        }
        return $i === 0 ? $s : substr($s, $i);
    }

    private static function trim(string $s): string
    {
        $s = self::trimLeft($s);
        $end = strlen($s);
        while ($end > 0) {
            if (strpos("\t\n\v\f\r ", $s[$end - 1]) !== false) {
                $end--;
                continue;
            }
            foreach (self::UNICODE_SPACES as $u) {
                $len = strlen($u);
                if ($end >= $len && substr_compare($s, $u, $end - $len, $len) === 0) {
                    $end -= $len;
                    continue 2;
                }
            }
            break;
        }
        return substr($s, 0, $end);
    }
}
