<?php

declare(strict_types=1);

namespace Tokenlore\Handlers;

use stdClass;

// Strenges Lesen eines JSON-Rumpfs wie decodeStrict im Go-Server (encoding/json mit DisallowUnknownFields):
// genau ein Objekt, nur bekannte Felder mit dem erwarteten Typ, kein Inhalt danach. Der einzige Leser
// dieser Art; alle Handler nutzen ihn.
final class StrictJson
{
    /**
     * Liest genau ein JSON-Objekt. Feldnamen ohne Beachtung der Schreibung (wie Go), null und fehlende
     * Felder bleiben weg, `null` als Rumpf ist ein leeres Objekt. Ungültiges UTF-8 wird wie in Go durch
     * U+FFFD ersetzt. Fehler: 'syntax' (kein JSON oder überzähliger Inhalt), 'unknown' (unbekanntes Feld)
     * oder 'type' (falscher Typ; $field ist das Feld oder '' für den ganzen Rumpf); der erste Fehler zählt.
     *
     * @param array<string,string> $spec Feld => 'string' | 'int' | 'bool' | 'string[]' (JSON-Liste nur aus Texten)
     * @return array{0: array<string,mixed>|null, 1: ?string, 2: string} Werte, Fehlerart, Feld
     */
    public static function decode(string $body, array $spec): array
    {
        try {
            // Ohne JSON_BIGINT_AS_STRING: zu große Zahlen werden float und damit ein Typfehler (wie Go), nie Text.
            $v = json_decode($body, false, 512, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE);
        } catch (\JsonException) {
            return [null, 'syntax', ''];
        }
        if ($v === null) {
            return [[], null, ''];
        }
        if (!$v instanceof stdClass) {
            return [null, 'type', ''];
        }
        $lower = [];
        foreach ($spec as $name => $_) {
            $lower[strtolower($name)] = $name;
        }
        $out = [];
        $err = null;
        foreach (get_object_vars($v) as $key => $value) {
            $name = isset($spec[$key]) ? $key : ($lower[strtolower((string) $key)] ?? null);
            if ($name === null) {
                $err ??= [null, 'unknown', ''];
                continue;
            }
            if ($value === null) {
                continue;
            }
            $ok = match ($spec[$name]) {
                'string' => is_string($value),
                'int' => is_int($value),
                'bool' => is_bool($value),
                'string[]' => is_array($value) && array_is_list($value) && $value === array_filter($value, 'is_string'),
                default => false,
            };
            if (!$ok) {
                $err ??= [null, 'type', $name];
                continue;
            }
            $out[$name] = $value;
        }
        return $err ?? [$out, null, ''];
    }

    /**
     * Kurzform für Rümpfe nur aus Text: liefert alle $fields (fehlend oder null: ''); null bei jedem Formfehler.
     *
     * @param list<string> $fields
     * @return array<string,string>|null
     */
    public static function strings(string $body, array $fields): ?array
    {
        [$v] = self::decode($body, array_fill_keys($fields, 'string'));
        return $v === null ? null : array_merge(array_fill_keys($fields, ''), $v);
    }
}
