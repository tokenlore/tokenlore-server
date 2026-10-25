<?php

declare(strict_types=1);

namespace Tokenlore\Util;

// JSON in der Schreibweise von Gos encoding/json (json.Marshal), wo PHP abweicht: Schlüssel von Objekten stehen
// sortiert, die Zeichen <, > und & sind mit kleinen Hex-Ziffern maskiert (Go: u003c, PHP: u003C), und Gleitkommazahlen
// stehen ohne ".0" und mit Go-Exponenten. Umlaute und Schrägstriche bleiben lesbar. Wert und Aufbau sind dieselben
// wie bei json_encode; nur die Schreibweise einzelner Teile (Reihenfolge der Schlüssel, Hex-Ziffern, Zahlen) ist die
// von Go.
final class GoJson
{
    private const FLAGS = JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP;

    private function __construct()
    {
    }

    /**
     * Wie json_encode, in Go-Schreibweise. Schlüssel sortiert nur mit $sortKeys (Go sortiert Map-Schlüssel immer;
     * die Antworten des Servers geben ihre Felder schon in der Reihenfolge der Go-Strukturen aus).
     */
    public static function encode(mixed $data, bool $sortKeys = false): string
    {
        if ($sortKeys) {
            $data = self::sorted($data);
        }
        return self::normalize(json_encode($data, self::FLAGS));
    }

    /**
     * Ordnet die Schlüssel aller Objekte (auch verschachtelter) bytegenau wie sort.Strings. Ein Array mit
     * Textschlüsseln, auch "0", "1", …, bleibt ein Objekt; eine Liste bleibt eine Liste.
     */
    private static function sorted(mixed $v): mixed
    {
        // Ein stdClass ist immer ein Objekt, auch mit den Schlüsseln "0", "1" (die als Array eine Liste wären).
        if ($v instanceof \stdClass) {
            $v = get_object_vars($v);
        } elseif (!is_array($v)) {
            return $v;
        } elseif (array_is_list($v)) {
            return array_map(self::sorted(...), $v);
        }
        ksort($v, SORT_STRING);
        return (object) array_map(self::sorted(...), $v);
    }

    /**
     * Ein Durchgang über den JSON-Text, ohne regulären Ausdruck (der bei langen Texten ohne JIT an PCRE-Grenzen
     * stößt und dann kein Ergebnis liefert): Texte (in Anführungszeichen) bekommen die kleinen Hex-Ziffern, Zahlen
     * in Exponentenschreibweise die Form von Go. PHP wechselt schon unter 1e-4 und ab 1e15 zum Exponenten und
     * schreibt "1.0e-7"; Go bleibt bis 1e-6 und unter 1e21 bei der Dezimalschreibweise (0.00001) und schreibt sonst
     * "1e-7" (Exponent ohne führende Null, Mantisse ohne ".0"). Ganzzahlige Gleitkommazahlen schreibt PHP wie Go
     * ohne ".0" (ohne JSON_PRESERVE_ZERO_FRACTION).
     */
    private static function normalize(string $json): string
    {
        // PHP schreibt die Maskierung der Zeichen < und > als Hex-Escape und Exponenten mit Vorzeichen (e-7, e+21);
        // ohne beides ist nichts umzuschreiben.
        $hex = '\\' . 'u003';
        if (!str_contains($json, $hex) && !str_contains($json, 'e-') && !str_contains($json, 'e+')) {
            return $json;
        }
        $out = [];
        $copied = 0; // bis hierhin ist der Text in $out übernommen
        $n = strlen($json);
        $i = 0;
        while (($i += strcspn($json, '"eE', $i)) < $n) {
            if ($json[$i] === '"') {
                // Ende des Textes: das nächste Anführungszeichen, das kein Backslash maskiert.
                $j = $i + 1;
                while (true) {
                    $j += strcspn($json, '"\\', $j);
                    if ($j >= $n || $json[$j] === '"') {
                        break;
                    }
                    $j += 2;
                }
                $text = substr($json, $i, $j - $i + 1);
                if (str_contains($text, $hex)) {
                    $out[] = substr($json, $copied, $i - $copied);
                    $out[] = self::lowerHex($text);
                    $copied = $j + 1;
                }
                $i = $j + 1;
                continue;
            }
            // e oder E außerhalb eines Textes: Exponent einer Zahl (und nicht true, false, null).
            $start = $i;
            while ($start > $copied && strpos('0123456789.-', $json[$start - 1]) !== false) {
                $start--;
            }
            $expStart = $i + 1;
            if ($expStart < $n && ($json[$expStart] === '+' || $json[$expStart] === '-')) {
                $expStart++;
            }
            $end = $expStart;
            while ($end < $n && $json[$end] >= '0' && $json[$end] <= '9') {
                $end++;
            }
            if ($start < $i && $end > $expStart && self::isMantissa(substr($json, $start, $i - $start), $sign, $digits)) {
                $out[] = substr($json, $copied, $start - $copied);
                $out[] = self::goExponent($sign, $digits, (int) substr($json, $i + 1, $end - $i - 1));
                $copied = $end;
            }
            $i = max($i + 1, $end);
        }
        $out[] = substr($json, $copied);
        return implode('', $out);
    }

    /** Die Maskierung der Zeichen < und > in einem Text mit kleinen Hex-Ziffern; ein maskierter Backslash bleibt, wie er ist. */
    private static function lowerHex(string $text): string
    {
        $out = '';
        $pos = 0;
        while (($b = strpos($text, '\\', $pos)) !== false) {
            $next = $text[$b + 1] ?? '';
            $code = substr($text, $b + 2, 4);
            if ($next === 'u' && ($code === '003C' || $code === '003E')) {
                $out .= substr($text, $pos, $b - $pos) . '\\' . 'u003' . strtolower($code[3]);
                $pos = $b + 6;
            } else {
                $out .= substr($text, $pos, $b + 2 - $pos);
                $pos = $b + 2;
            }
        }
        return $out . substr($text, $pos);
    }

    /**
     * Ist $m die Mantisse, wie PHP sie schreibt (-?, eine Ziffer, optional . und Ziffern)? Dann sind $sign ("-" oder "")
     * und $digits (alle Ziffern ohne Komma) gesetzt.
     */
    private static function isMantissa(string $m, ?string &$sign, ?string &$digits): bool
    {
        $sign = '';
        if ($m !== '' && $m[0] === '-') {
            $sign = '-';
            $m = substr($m, 1);
        }
        if ($m === '' || !ctype_digit($m[0]) || (strlen($m) > 1 && ($m[1] !== '.' || strlen($m) === 2 || !ctype_digit(substr($m, 2))))) {
            return false;
        }
        $digits = $m[0] . substr($m, 2);
        return true;
    }

    // $digits: die Ziffern der Mantisse ohne Komma (1 vor dem Komma), $exp: Zehnerpotenz.
    private static function goExponent(string $sign, string $digits, int $exp): string
    {
        $digits = rtrim($digits, '0');
        if ($digits === '') {
            return $sign . '0';
        }
        if ($exp < -6 || $exp >= 21) {
            $mant = $digits[0] . (strlen($digits) > 1 ? '.' . substr($digits, 1) : '');
            return $sign . $mant . 'e' . ($exp < 0 ? '-' : '+') . abs($exp);
        }
        $point = $exp + 1; // Stellen vor dem Komma
        if ($point <= 0) {
            return $sign . '0.' . str_repeat('0', -$point) . $digits;
        }
        if ($point >= strlen($digits)) {
            return $sign . $digits . str_repeat('0', $point - strlen($digits));
        }
        return $sign . substr($digits, 0, $point) . '.' . substr($digits, $point);
    }
}
